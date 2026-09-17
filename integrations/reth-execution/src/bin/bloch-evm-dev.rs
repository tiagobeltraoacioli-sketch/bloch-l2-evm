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
    build_eth_api, pool_maintenance, prepare_genesis, replay_canonical_prefix, start_http_rpc, BlochChainSpec,
    BlochEvmConfig, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, BlochTransactionValidator,
    CanonicalCoordinator,
};
use eyre::{bail, ensure, Result};
use reth_db::mdbx::{init_db_for, open_db, open_db_read_only, DatabaseArguments};
use reth_network_api::noop::NoopNetwork;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    DBProvider, DatabaseProviderFactory, ProviderFactory,
};
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer};
use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, maintain::MaintainPoolConfig, validate::EthTransactionValidatorBuilder,
    CoinbaseTipOrdering, EthPooledTransaction, Pool, PoolConfig, PoolTransaction, TransactionPool,
};
use std::{future::Future, path::PathBuf, sync::Arc, task::Poll, time::Duration};

const USAGE: &str = "bloch-evm-dev --synthetic-dev --data-dir PATH [--init] [--fund ADDRESS] [--replay-from SOURCE] [--port 8545] [--block-interval-ms 1000]\n\
Isolated synthetic developer domain, loopback HTTP, no P2P/L1 derivation/finality.\n\
--init requires a nonexistent directory; --fund is init-only synthetic issuance (100,000,000 sats).\n\
--replay-from requires --init and forbids --fund; re-executes a stopped source into the new directory without writing the source.\n\
Without --init the existing archival database is validated and reopened. Partial initialization is never retried automatically.\n\
Pending RPC is unsupported. No private keys are generated or accepted. Ctrl-C stops the service.";

struct Options {
    path: PathBuf,
    init: bool,
    fund: Option<Address>,
    replay_from: Option<PathBuf>,
    port: u16,
    block_time: Duration,
}
impl Options {
    fn parse() -> Result<Option<Self>> {
        let mut args = std::env::args().skip(1);
        let (mut synthetic, mut path, mut init, mut fund) = (false, None, false, None);
        let mut replay_from = None;
        let (mut port, mut millis) = (8545, 1000u64);
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
                "--port" => port = args.next().ok_or_else(|| eyre::eyre!("missing port"))?.parse()?,
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
        ensure!(millis > 0, "block interval must be nonzero");
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
            port,
            block_time,
        }))
    }
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

async fn run(options: Options, runtime: reth_tasks::Runtime) -> Result<()> {
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
    if let Some(source) = &options.replay_from {
        let source: BlochProviderFactory = ProviderFactory::new(
            Arc::new(open_db_read_only(source.join("db"), DatabaseArguments::default())?),
            spec.clone(),
            StaticFileProvider::read_only(source.join("static"))?,
            RocksDBBuilder::new(source.join("rocks"))
                .with_default_tables()
                .with_read_only(true)
                .build()?,
            runtime.clone(),
        )?;
        let recovered = replay_canonical_prefix(&source, &factory)?;
        eprintln!(
            "Replayed acknowledged synthetic prefix: block={} hash={}; source opened read-only",
            recovered.0.number,
            recovered.hash()
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
            provider,
            pool.clone(),
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config,
        ),
        runtime.clone(),
    );
    let server = start_http_rpc(api.into_rpc().remove_context(), options.port).await?;
    let mut critical = runtime
        .take_task_manager_handle()
        .ok_or_else(|| eyre::eyre!("runtime task manager unavailable"))?;
    let mut maintenance = tokio::spawn(maintenance_future);
    println!(
        "SYNTHETIC DEV ONLY: HTTP={} chain_id={} domain={} head={} no P2P; pending unsupported",
        server.http_url().unwrap_or_default(),
        kernel.chain_id,
        spec.domain(),
        coordinator.head().hash()
    );
    println!("RPC listening at {}", server.http_url().unwrap_or_default());
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
    maintenance.abort();
    // The handle may already have completed on the error branch above.
    if !maintenance.is_finished() {
        let _ = maintenance.await;
    }
    outcome?;
    stopped?;
    Ok(())
}
