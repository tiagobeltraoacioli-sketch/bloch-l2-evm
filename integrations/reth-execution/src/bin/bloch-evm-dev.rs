// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicitly synthetic, isolated developer service; no L1 derivation or P2P.
use alloy_consensus::Transaction;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256};
use bloch_l2_evm::{
    transactions::{MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    build_eth_api, chain_identity_rpc, chain_status_rpc, inspect_canonical_prefix, pool_maintenance, prepare_genesis,
    replay_canonical_prefix_with_limits, start_http_rpc, start_ws_rpc, BlochChainSpec, BlochEvmConfig,
    BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, BlochTransactionValidator, CanonicalCoordinator,
    ReplayFloor, ReplayLimits,
};
use eyre::{bail, ensure, Result};
use reth_db::mdbx::{init_db_for, open_db, open_db_read_only, DatabaseArguments};
use reth_network_api::noop::NoopNetwork;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    DBProvider, DatabaseProviderFactory, ProviderFactory,
};
use reth_rpc::{EthFilter, EthPubSub};
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, pubsub::EthPubSubApiServer, EthApiServer, EthFilterApiServer};
use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, maintain::MaintainPoolConfig, validate::EthTransactionValidatorBuilder,
    CoinbaseTipOrdering, EthPooledTransaction, Pool, PoolConfig, PoolTransaction, TransactionPool,
};
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    task::Poll,
    time::Duration,
};

const USAGE: &str = "bloch-evm-dev --synthetic-dev --data-dir PATH [--init] [--fund ADDRESS] [--replay-from SOURCE] [--replay-min-block NUMBER --replay-min-hash HASH] [--replay-max-blocks NUMBER] [--replay-max-bytes NUMBER] [--port 8545] [--ws-port PORT] [--block-interval-ms 1000]\n\
Isolated synthetic developer domain, loopback HTTP and optional WebSocket, no P2P/L1 derivation/finality.\n\
--ws-port enables a separate loopback listener; port 0 selects an available port.\n\
--init requires a nonexistent directory; --fund is init-only synthetic issuance (100,000,000 sats).\n\
--replay-from requires --init and forbids --fund; re-executes a stopped source into the new directory without writing the source.\n\
Replay limits default to 10000 blocks and 268435456 canonical bytes; the optional minimum block/hash must come from independently retained history.\n\
Without --init the existing archival database is validated and reopened. Partial initialization is never retried automatically.\n\
Pending block/state queries are unsupported. No private keys are generated or accepted. Ctrl-C stops the service.";

struct Options {
    path: PathBuf,
    init: bool,
    fund: Option<Address>,
    replay_from: Option<PathBuf>,
    replay_floor: Option<ReplayFloor>,
    replay_limits: ReplayLimits,
    port: u16,
    ws_port: Option<u16>,
    block_time: Duration,
}
impl Options {
    fn parse() -> Result<Option<Self>> {
        let mut args = std::env::args().skip(1);
        let (mut synthetic, mut path, mut init, mut fund) = (false, None, false, None);
        let mut replay_from = None;
        let (mut replay_min_block, mut replay_min_hash) = (None, None);
        let mut replay_limits = ReplayLimits::default();
        let (mut port, mut millis) = (8545, 1000u64);
        let mut ws_port = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(arg) = args.next() {
            ensure!(seen.insert(arg.clone()), "duplicate option {arg}");
            match arg.as_str() {
                "--help" | "-h" => {
                    println!("{USAGE}");
                    return Ok(None);
                }
                "--synthetic-dev" => synthetic = true,
                "--init" => init = true,
                "--data-dir" => path = Some(PathBuf::from(args.next().ok_or_else(|| eyre::eyre!("missing PATH"))?)),
                "--fund" => fund = Some(args.next().ok_or_else(|| eyre::eyre!("missing ADDRESS"))?.parse()?),
                "--replay-from" => {
                    replay_from = Some(PathBuf::from(args.next().ok_or_else(|| eyre::eyre!("missing SOURCE"))?))
                }
                "--replay-min-block" => {
                    replay_min_block = Some(
                        args.next()
                            .ok_or_else(|| eyre::eyre!("missing minimum block"))?
                            .parse()?,
                    );
                }
                "--replay-min-hash" => {
                    replay_min_hash = Some(
                        args.next()
                            .ok_or_else(|| eyre::eyre!("missing minimum hash"))?
                            .parse::<B256>()?,
                    );
                }
                "--replay-max-blocks" => {
                    replay_limits.blocks = args
                        .next()
                        .ok_or_else(|| eyre::eyre!("missing replay block limit"))?
                        .parse()?;
                }
                "--replay-max-bytes" => {
                    replay_limits.bytes = args
                        .next()
                        .ok_or_else(|| eyre::eyre!("missing replay byte limit"))?
                        .parse()?;
                }
                "--port" => port = args.next().ok_or_else(|| eyre::eyre!("missing port"))?.parse()?,
                "--ws-port" => ws_port = Some(args.next().ok_or_else(|| eyre::eyre!("missing WS port"))?.parse()?),
                "--block-interval-ms" => {
                    millis = args.next().ok_or_else(|| eyre::eyre!("missing interval"))?.parse()?
                }
                _ => bail!("unknown option {arg}\n{USAGE}"),
            }
        }
        ensure!(synthetic, "--synthetic-dev is mandatory\n{USAGE}");
        ensure!(fund.is_none() || init, "--fund is only allowed with --init");
        ensure!(
            replay_from.is_none() || (init && fund.is_none()),
            "--replay-from requires --init and forbids --fund"
        );
        let replay_floor = match (replay_min_block, replay_min_hash) {
            (None, None) => None,
            (Some(number), Some(hash)) => {
                ensure!(!hash.is_zero(), "minimum replay hash must be nonzero");
                Some(ReplayFloor { number, hash })
            }
            _ => bail!("--replay-min-block and --replay-min-hash must be supplied together"),
        };
        ensure!(
            replay_from.is_some() || !seen.iter().any(|name| name.starts_with("--replay-")),
            "replay bounds and floor require --replay-from"
        );
        ensure!(millis > 0, "block interval must be nonzero");
        ensure!(
            port == 0 || ws_port != Some(port),
            "HTTP and WebSocket need distinct fixed ports"
        );
        let block_time = Duration::from_millis(millis);
        ensure!(
            tokio::time::Instant::now().checked_add(block_time).is_some(),
            "block interval overflows the monotonic clock"
        );
        Ok(Some(Self {
            path: path.ok_or_else(|| eyre::eyre!("--data-dir is required"))?,
            init,
            fund,
            replay_from,
            replay_floor,
            replay_limits,
            port,
            ws_port,
            block_time,
        }))
    }
}

/// Resolve trusted parent directories before opening any storage. A replay
/// target must be new and disjoint from the source, including symlink aliases.
fn replay_paths(source: &Path, target: &Path) -> Result<(PathBuf, PathBuf)> {
    let source = source.canonicalize()?;
    ensure!(source.is_dir(), "replay source must be a directory");
    match std::fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => bail!("replay target must not already exist"),
    }
    let name = target
        .file_name()
        .ok_or_else(|| eyre::eyre!("replay target needs a directory name"))?;
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let target = parent.canonicalize()?.join(name);
    ensure!(
        !target.starts_with(&source) && !source.starts_with(&target),
        "replay source and target directories must not overlap"
    );
    Ok((source, target))
}

#[tokio::main]
async fn main() -> Result<()> {
    let Some(options) = Options::parse()? else {
        return Ok(());
    };
    let runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::ExistingHandle(tokio::runtime::Handle::current())),
    )
    .build()?;
    let outcome = run(options, runtime.clone()).await;
    let shutdown =
        tokio::task::spawn_blocking(move || runtime.graceful_shutdown_with_timeout(Duration::from_secs(10))).await;
    // Cleanup runs even when startup, binding, mining or server stop failed.
    outcome?;
    ensure!(shutdown?, "runtime graceful shutdown timed out");
    Ok(())
}

async fn run(mut options: Options, runtime: reth_tasks::Runtime) -> Result<()> {
    let first_tick = tokio::time::Instant::now()
        .checked_add(options.block_time)
        .ok_or_else(|| eyre::eyre!("block interval overflows the monotonic clock"))?;
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    // Poll once to install Tokio's portable signal handler before any readiness
    // announcement. Keep this same future alive for the whole service lifetime.
    let already_interrupted = std::future::poll_fn(|cx| {
        Poll::Ready(match shutdown.as_mut().poll(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(result) => result.map(|()| true),
        })
    })
    .await?;
    if already_interrupted {
        return Ok(());
    }
    let kernel = ChainSpec::testnet();
    // Stable synthetic identity, deliberately unrelated to native/L1 deployment.
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), B256::repeat_byte(0xd3), 0)?);
    // Inspect the read-only source before creating or opening a writable target.
    let replay_source = if let Some(source_path) = &options.replay_from {
        let (source_path, target_path) = replay_paths(source_path, &options.path)?;
        options.path = target_path;
        let source: BlochProviderFactory = ProviderFactory::new(
            Arc::new(open_db_read_only(source_path.join("db"), DatabaseArguments::default())?),
            spec.clone(),
            StaticFileProvider::read_only(source_path.join("static"))?,
            RocksDBBuilder::new(source_path.join("rocks"))
                .with_default_tables()
                .with_read_only(true)
                .build()?,
            runtime.clone(),
        )?;
        let inspected = inspect_canonical_prefix(&source, &spec, options.replay_floor, options.replay_limits)?;
        eprintln!(
            "Synthetic replay preflight: blocks={} canonical_bytes={} rollback_floor={}",
            inspected.blocks,
            inspected.bytes,
            if inspected.floor.is_some() {
                "supplied"
            } else {
                "not-supplied"
            }
        );
        Some(source)
    } else {
        None
    };
    if options.init {
        std::fs::create_dir(&options.path)?;
    } else {
        ensure!(
            options.path.is_dir(),
            "existing data directory required; use --init for a new directory"
        );
        for directory in ["db", "static", "rocks"] {
            ensure!(
                options.path.join(directory).is_dir(),
                "incomplete data directory: missing {directory}"
            );
        }
    }
    let db_path = options.path.join("db");
    let db = if options.init {
        init_db_for::<_, BlochTables>(db_path, DatabaseArguments::default())?
    } else {
        open_db(db_path, DatabaseArguments::default())?
    };
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(db),
        spec.clone(),
        StaticFileProvider::read_write(options.path.join("static"))?,
        RocksDBBuilder::new(options.path.join("rocks"))
            .with_default_tables()
            .build()?,
        runtime.clone(),
    )?;
    if let Some(source) = &replay_source {
        let recovered =
            replay_canonical_prefix_with_limits(source, &factory, options.replay_floor, options.replay_limits)?;
        eprintln!(
            "Replayed acknowledged synthetic prefix: block={} hash={} canonical_bytes={}; source opened read-only",
            recovered.head.0.number,
            recovered.head.hash(),
            recovered.bytes
        );
    } else if options.init {
        let genesis = prepare_genesis(&spec, factory.latest()?.as_ref())?;
        let writer = factory.database_provider_rw()?;
        writer.save_blocks(vec![genesis], SaveBlocksMode::Full)?;
        writer.commit()?;
    }
    let mut coordinator = CanonicalCoordinator::attach(factory)?;
    if let Some(recipient) = options.fund {
        eprintln!("SYNTHETIC funding recipient={recipient}, l1_sats=100000000; no real L1 deposit");
        coordinator.extend(
            coordinator.head().hash(),
            BlochNextBlockEnvCtx {
                timestamp: 1,
                prevrandao: B256::ZERO,
                anchor_root: B256::repeat_byte(0xd3),
                deposits: vec![DepositMint {
                    recipient,
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 1,
                        l1_tx_index: 0,
                        l1_txid: [0xd3; 32],
                        l1_vout: 0,
                        l1_sats: 100_000_000,
                    },
                }],
            },
            vec![],
        )?;
    }
    let provider = coordinator.provider();
    let config = BlochEvmConfig::new(&kernel, spec.domain());
    let blobs = InMemoryBlobStore::default();
    let inner = EthTransactionValidatorBuilder::new(provider.clone(), config.clone())
        .no_eip4844()
        .no_eip7702()
        .set_block_gas_limit(kernel.gas_limit)
        .build::<EthPooledTransaction, _>(blobs.clone());
    let pool = Pool::new(
        BlochTransactionValidator::new(&kernel, inner),
        CoinbaseTipOrdering::<EthPooledTransaction>::default(),
        blobs,
        PoolConfig::default(),
    );
    let maintenance_future = pool_maintenance(
        provider.clone(),
        pool.clone(),
        runtime.clone(),
        MaintainPoolConfig::default(),
    )?;
    let api = build_eth_api(
        RpcNodeCoreAdapter::new(
            provider.clone(),
            pool.clone(),
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config,
        ),
        runtime.clone(),
    );
    // Reth exposes logs and polling filters in a separate module from EthApi.
    // Share its real provider, receipt cache and runtime with ordinary queries.
    let filter = EthFilter::new(
        api.clone(),
        reth_rpc_eth_types::EthConfig::default().filter_config(),
        runtime.clone(),
    );
    let mut module = api.clone().into_rpc().remove_context();
    module.merge(filter.into_rpc())?;
    module.merge(chain_identity_rpc(spec.clone()))?;
    module.merge(chain_status_rpc(spec.clone(), provider))?;
    let ws_module = if options.ws_port.is_some() {
        let mut ws = module.clone();
        ws.merge(EthPubSub::new(api, runtime.clone()).into_rpc())?;
        Some(ws)
    } else {
        None
    };
    let server = start_http_rpc(module, options.port).await?;
    let ws_server = if let (Some(module), Some(port)) = (ws_module, options.ws_port) {
        Some(start_ws_rpc(module, port).await?)
    } else {
        None
    };
    let mut critical = runtime
        .take_task_manager_handle()
        .ok_or_else(|| eyre::eyre!("runtime task manager unavailable"))?;
    let mut maintenance = tokio::spawn(maintenance_future);
    println!(
        "SYNTHETIC DEV ONLY: HTTP={} chain_id={} domain={} head={} no P2P; pending block/state queries unsupported",
        server.http_url().unwrap_or_default(),
        kernel.chain_id,
        spec.domain(),
        coordinator.head().hash()
    );
    println!("RPC listening at {}", server.http_url().unwrap_or_default());
    if let Some(ws) = &ws_server {
        println!("WS listening at {}", ws.ws_url().unwrap_or_default());
    }
    let mut interval = tokio::time::interval_at(first_tick, options.block_time);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let outcome: Result<()> = async {
        loop {
            tokio::select! {
                signal = &mut shutdown => { signal?; break; }
                result = &mut maintenance => bail!("pool maintenance stopped unexpectedly: {result:?}"),
                result = &mut critical => bail!("critical runtime task stopped: {result:?}"),
                _ = interval.tick() => {
                    // Allow maintenance to apply the previous canonical event before selection.
                    if pool.block_info().last_seen_block_hash != coordinator.head().hash() { continue; }
                    let mut selected = Vec::new();
                    let (mut gas, mut bytes) = (0u64, 0usize);
                    for entry in pool.best_transactions() {
                        let tx = entry.transaction.clone_into_consensus().into_inner();
                        let size = tx.encode_2718_len();
                        if selected.len() == MAX_SIGNED_TRANSACTIONS || bytes + size > MAX_SIGNED_BLOCK_BYTES || tx.gas_limit() > kernel.gas_limit - gas { break; }
                        gas += tx.gas_limit(); bytes += size; selected.push(tx);
                    }
                    let timestamp = coordinator.head().0.timestamp.checked_add(1).ok_or_else(|| eyre::eyre!("timestamp exhausted"))?;
                    let head = coordinator.extend(coordinator.head().hash(), BlochNextBlockEnvCtx {
                        timestamp, prevrandao: B256::ZERO, anchor_root: B256::repeat_byte(0xd3), deposits: vec![],
                    }, selected)?;
                    println!("synthetic block={} hash={}", head.0.number, head.hash());
                }
            }
        }
        Ok(())
    }.await;
    let stopped = server.stop();
    let ws_stopped = ws_server.map(|server| server.stop()).transpose();
    maintenance.abort();
    // The handle may already have completed on the error branch above.
    if !maintenance.is_finished() {
        let _ = maintenance.await;
    }
    outcome?;
    stopped?;
    ws_stopped?;
    Ok(())
}

#[cfg(test)]
mod replay_path_tests {
    use super::replay_paths;

    #[test]
    fn rejects_same_existing_and_nested_targets_before_mutation() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        assert!(replay_paths(&source, &source).is_err());
        assert!(replay_paths(&source, &source.join("nested")).is_err());
        assert!(!source.join("nested").exists());
        let target = root.path().join("new");
        let (resolved_source, resolved_target) = replay_paths(&source, &target).unwrap();
        assert_eq!(resolved_source, source.canonicalize().unwrap());
        assert_eq!(resolved_target, root.path().canonicalize().unwrap().join("new"));
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_alias_overlap_and_dangling_target() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let alias = root.path().join("alias");
        std::fs::create_dir(&source).unwrap();
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(replay_paths(&source, &alias.join("nested")).is_err());
        assert!(replay_paths(&alias, &source.join("nested")).is_err());
        let dangling = root.path().join("dangling");
        std::os::unix::fs::symlink(root.path().join("absent"), &dangling).unwrap();
        assert!(replay_paths(&source, &dangling).is_err());
        assert!(!source.join("nested").exists());
    }
}
