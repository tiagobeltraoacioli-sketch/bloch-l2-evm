// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only RPC for the natively settled development L2.
//!
//! Serves the canonical database written by the settlement worker, opened
//! read-only, and follows its head. `safe`/`finalized` are published only in
//! memory (never written to the database), from the native follower's status
//! (schema v2), with the levels of an Ethereum rollup:
//! - `finalized`: the highest L2 block whose settlement lies inside the
//!   natively FFG-finalized prefix that the follower verified by real replay
//!   from the pinned genesis, provided every listed settlement matches the local
//!   canonical header at its height;
//! - `safe`: the settlement the operator's own native node holds at its
//!   canonical head (accepted on L1, not yet finalized), when it matches the
//!   local canonical header; never below `finalized`.
//! No checkpoint signature is involved. Neither level regresses; any
//! inconsistency freezes it and is logged. `bloch_finality` reports both with
//! their L1 anchors.
//!
//! With `--txpool DIR` it is also the development sequencer's front door:
//! `eth_sendRawTransaction` authenticates the canonical signed bytes (EIP-2718
//! encoding, chain id, low-s ECDSA signature, size) and checks the nonce
//! against the head, then writes one `<hash>.tx` spool entry (hex) atomically
//! into the pool the settlement worker selects from. Inclusion, fees, balance
//! and gas are decided by the producer, which drops invalid entries with a
//! reason. Without `--txpool`, transactions are refused.
use alloy_primitives::B256;
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    build_eth_api, chain_identity_rpc, chain_status_rpc, start_http_rpc, BlochBlockchainProvider, BlochChainSpec,
    BlochEvmConfig, BlochProviderFactory,
};
use eyre::{bail, ensure, Result};
use reth_db::mdbx::{open_db_read_only, DatabaseArguments};
use reth_network_api::noop::NoopNetwork;
use reth_provider::{
    providers::{BlockchainProvider, RocksDBBuilder, StaticFileProvider},
    AccountReader, BlockNumReader, HeaderProvider, ProviderFactory, StateProviderFactory,
};
use reth_rpc::EthFilter;
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer, EthFilterApiServer};
use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_transaction_pool::noop::NoopTransactionPool;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const USAGE: &str = "bloch-l2-settled-rpc --data-dir CANONICAL --view-dir NEW_DIR --finality-status FILE --network HEX [--port 8546] [--poll-ms 2000] [--rules v3|v2] [--txpool DIR]\n\
Development RPC over the settled database; with --txpool, eth_sendRawTransaction spools authenticated\n\
transactions for the settlement worker (the sequencer). finalized comes only from verified native FFG finality of L2 settlements;\n\
safe from the settlement the local native node accepted at its head. --rules selects the settlement\n\
execution rules the canonical database was written under (default v3: ChainSpec::testnet_v3).\n";

struct Options {
    data_dir: PathBuf,
    view_dir: PathBuf,
    status: PathBuf,
    network: String,
    port: u16,
    poll: Duration,
    v3: bool,
    txpool: Option<PathBuf>,
}

/// Spool entries accepted while the producer has not yet consumed them; the
/// producer itself refuses a pool above 16,384 entries.
const MAX_SPOOL_ENTRIES: usize = 4_096;
/// Highest nonce gap accepted ahead of the head account nonce.
const MAX_NONCE_AHEAD: u64 = 64;

fn parse() -> Result<Options> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    ensure!(args.len() % 2 == 0, "options must be --name value pairs\n{USAGE}");
    let mut map = std::collections::BTreeMap::new();
    for pair in args.chunks(2) {
        ensure!(
            ["--data-dir", "--view-dir", "--finality-status", "--network", "--port", "--poll-ms", "--rules", "--txpool"].contains(&pair[0].as_str()),
            "unknown option {}\n{USAGE}",
            pair[0]
        );
        ensure!(map.insert(pair[0].clone(), pair[1].clone()).is_none(), "{} repeated", pair[0]);
    }
    let get = |k: &str| map.get(k).cloned().ok_or_else(|| eyre::eyre!("missing {k}\n{USAGE}"));
    let network = get("--network")?;
    ensure!(network.len() == 64 && network.bytes().all(|b| b.is_ascii_hexdigit()), "--network must be 64 hex characters");
    Ok(Options {
        data_dir: PathBuf::from(get("--data-dir")?),
        view_dir: PathBuf::from(get("--view-dir")?),
        status: PathBuf::from(get("--finality-status")?),
        network: network.to_lowercase(),
        port: map.get("--port").map_or(Ok(8546), |v| v.parse())?,
        poll: Duration::from_millis(map.get("--poll-ms").map_or(Ok(2000), |v| v.parse())?),
        v3: match map.get("--rules").map_or("v3", String::as_str) {
            "v3" => true,
            "v2" => false,
            other => bail!("--rules must be v3 or v2, not {other}"),
        },
        txpool: map.get("--txpool").map(PathBuf::from),
    })
}

fn rpc_error(message: impl Into<String>) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(-32000, message.into(), None::<()>)
}

/// `eth_sendRawTransaction` into the settlement worker's spool directory.
fn sequencer_rpc(spec: ChainSpec, pool: PathBuf, provider: BlochBlockchainProvider) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_blocking_method("eth_sendRawTransaction", move |params, _, _| {
            let raw: alloy_primitives::Bytes = params.one()?;
            let tx = bloch_l2_evm::decode_signed_transaction(&spec, &raw)
                .map_err(|e| rpc_error(format!("transaction rejected: {e:?}")))?;
            let hash = tx.hash();
            let name = format!("{}.tx", alloy_primitives::hex::encode(hash));
            if pool.join(&name).exists() {
                return Ok(hash); // already known, not yet consumed
            }
            let nonce = provider
                .latest()
                .and_then(|state| state.basic_account(&tx.sender()))
                .map_err(|e| rpc_error(format!("state unavailable: {e}")))?
                .map_or(0, |account| account.nonce);
            let sent = tx.environment().nonce;
            if sent < nonce {
                return Err(rpc_error(format!("nonce too low: next nonce is {nonce}")));
            }
            if sent > nonce + MAX_NONCE_AHEAD {
                return Err(rpc_error(format!("nonce too high: next nonce is {nonce}")));
            }
            let entries = std::fs::read_dir(&pool)
                .map_err(|e| rpc_error(format!("txpool unavailable: {e}")))?
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().extension().is_some_and(|x| x == "tx"))
                .count();
            if entries >= MAX_SPOOL_ENTRIES {
                return Err(rpc_error("txpool full"));
            }
            // Write beside, then rename: the producer only reads complete *.tx files.
            let partial = pool.join(format!(".{}.partial", alloy_primitives::hex::encode(hash)));
            let written = std::fs::write(&partial, format!("{}\n", alloy_primitives::hex::encode(tx.raw())))
                .and_then(|()| {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600))
                })
                .and_then(|()| std::fs::rename(&partial, pool.join(&name)));
            if let Err(error) = written {
                let _ = std::fs::remove_file(&partial);
                return Err(rpc_error(format!("txpool write failed: {error}")));
            }
            println!("spooled tx={hash} from={} nonce={sent}", tx.sender());
            Ok(hash)
        })
        .expect("the send method name is unique in a new module");
    module
}

/// RocksDB's read-only secondary needs a writable scratch directory beside
/// `rocks`; the view keeps it out of the writer's database directory.
fn create_view(data: &Path, view: &Path) -> Result<()> {
    std::fs::create_dir(view)?;
    for directory in ["db", "static", "rocks"] {
        let target = data.join(directory);
        ensure!(std::fs::symlink_metadata(&target)?.is_dir(), "{} is not a directory", target.display());
        std::os::unix::fs::symlink(target, view.join(directory))?;
    }
    Ok(())
}

type Header = reth_primitives_traits::SealedHeader<bloch_reth_execution::BlochNodeHeader>;

/// What the follower's status proves against the local canonical chain.
struct Levels {
    finalized: Option<Header>,
    /// `None` when the status has no safe settlement or it is not local yet.
    safe: Option<Header>,
    status: serde_json::Value,
}

/// The highest L2 header proven final by the follower's verified status, if
/// every listed settlement matches the local canonical chain, and the safe
/// header the local native node reports.
fn verified_levels(status_path: &Path, network: &str, provider: &BlochBlockchainProvider) -> Result<Option<Levels>> {
    let bytes = match std::fs::read(status_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(bytes.len() <= 16 * 1_048_576, "finality status too large");
    let status: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(status["schema"] == "bloch.l2.native-follower-status.v2", "unexpected status schema");
    ensure!(status["network"] == network, "status is for another native network");
    ensure!(status["production_finality"] == false, "status claims production finality");
    let settlements = status["finalized_settlements"].as_array().ok_or_else(|| eyre::eyre!("no settlement list"))?;
    let mut best = None;
    let mut expected_number = 1u64;
    for entry in settlements {
        let number = entry["l2_number"].as_u64().ok_or_else(|| eyre::eyre!("bad l2_number"))?;
        let hash: B256 = entry["l2_hash"].as_str().unwrap_or_default().parse()?;
        ensure!(number == expected_number, "finalized settlements are not contiguous from block 1");
        expected_number += 1;
        let local = provider
            .sealed_header(number)?
            .ok_or_else(|| eyre::eyre!("settled L2 block {number} is not in the local canonical chain yet"))?;
        ensure!(local.hash() == hash, "settled L2 block {number} differs from the local canonical header");
        best = Some(local);
    }
    let finalized_number = best.as_ref().map_or(0, |h: &Header| h.0.number);
    let safe = match status.get("safe_settlement").filter(|v| !v.is_null()) {
        None => None,
        Some(entry) => {
            let number = entry["l2_number"].as_u64().ok_or_else(|| eyre::eyre!("bad safe l2_number"))?;
            let hash: B256 = entry["l2_hash"].as_str().unwrap_or_default().parse()?;
            ensure!(number >= finalized_number, "safe settlement {number} is below finalized {finalized_number}");
            match provider.sealed_header(number)? {
                // Not produced locally yet: keep the previous safe level.
                None => None,
                Some(local) => {
                    ensure!(local.hash() == hash, "safe L2 block {number} differs from the local canonical header");
                    Some(local)
                }
            }
        }
    };
    Ok(Some(Levels { finalized: best, safe, status }))
}

fn level_json(header: &Option<Header>) -> serde_json::Value {
    header.as_ref().map_or(serde_json::Value::Null, |h| {
        serde_json::json!({"number": format!("0x{:x}", h.0.number), "hash": h.hash()})
    })
}

/// `bloch_finality`: the L2 levels and their L1 anchors, named like the native
/// node's `getchaininfo` finality fields.
fn finality_rpc(view: Arc<std::sync::RwLock<serde_json::Value>>) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("bloch_finality", move |_, _, _| {
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(view.read().map(|v| v.clone()).unwrap_or_default())
        })
        .expect("the finality method name is unique in a new module");
    module
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = parse()?;
    let runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::ExistingHandle(tokio::runtime::Handle::current())),
    )
    .build()?;
    create_view(&options.data_dir, &options.view_dir)?;
    // The rules the settlement worker executed under (bloch-l2-produce-dev
    // writes V3 blocks with ChainSpec::testnet_v3).
    let rules = || if options.v3 { ChainSpec::testnet_v3() } else { ChainSpec::testnet() };
    let spec = Arc::new(BlochChainSpec::new(rules(), B256::repeat_byte(0xd3), 0)?);
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(open_db_read_only(options.view_dir.join("db"), DatabaseArguments::default())?),
        spec.clone(),
        StaticFileProvider::read_only(options.view_dir.join("static"))?,
        RocksDBBuilder::new(options.view_dir.join("rocks")).with_default_tables().with_read_only(true).build()?,
        runtime.clone(),
    )?
    .with_read_only_sync(true);
    let provider: BlochBlockchainProvider = BlockchainProvider::new(factory.clone())?;
    let kernel = rules();
    let config = BlochEvmConfig::new(&kernel, spec.domain());
    let api = build_eth_api(
        RpcNodeCoreAdapter::new(
            provider.clone(),
            NoopTransactionPool::default(),
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config,
        ),
        runtime.clone(),
    );
    let filter = EthFilter::new(api.clone(), reth_rpc_eth_types::EthConfig::default().filter_config(), runtime.clone());
    let mut module = api.into_rpc().remove_context();
    if let Some(pool) = &options.txpool {
        ensure!(std::fs::symlink_metadata(pool)?.is_dir(), "--txpool {} is not a directory", pool.display());
        // Replace the no-pool method of the read-only API with the spooling one.
        ensure!(module.remove_method("eth_sendRawTransaction").is_some(), "eth API lacks eth_sendRawTransaction");
        module.merge(sequencer_rpc(rules(), pool.clone(), provider.clone()))?;
    }
    module.merge(filter.into_rpc())?;
    module.merge(chain_identity_rpc(spec.clone()))?;
    module.merge(chain_status_rpc(spec.clone(), provider.clone()))?;
    let finality = Arc::new(std::sync::RwLock::new(serde_json::Value::Null));
    module.merge(finality_rpc(finality.clone()))?;
    let server = start_http_rpc(module, options.port).await?;
    println!(
        "SETTLED DEV RPC at {}; finality only from verified native FFG settlement; {}",
        server.http_url().unwrap_or_default(),
        options.txpool.as_ref().map_or("transactions refused".to_string(), |p| format!("eth_sendRawTransaction spools to {}", p.display()))
    );
    let state = provider.canonical_in_memory_state();
    let mut head_number = u64::MAX;
    let mut finalized: Option<Header> = None;
    let mut safe: Option<Header> = None;
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    let mut interval = tokio::time::interval(options.poll);
    let result: Result<()> = async {
        loop {
            tokio::select! {
                signal = &mut shutdown => { signal?; break; }
                _ = interval.tick() => {
                    let number = factory.best_block_number()?;
                    if number != head_number {
                        let header = factory.sealed_header(number)?.ok_or_else(|| eyre::eyre!("head header missing"))?;
                        state.set_canonical_head(header.clone());
                        head_number = number;
                        println!("head block={} hash={}", number, header.hash());
                    }
                    let number_of = |h: &Option<Header>| h.as_ref().map_or(0, |h| h.0.number);
                    match verified_levels(&options.status, &options.network, &provider) {
                        Ok(Some(levels)) => {
                            match levels.finalized {
                                Some(header) if header.0.number > number_of(&finalized) => {
                                    state.set_finalized(header.clone());
                                    println!("finalized block={} hash={} (verified native FFG settlement)", header.0.number, header.hash());
                                    finalized = Some(header);
                                }
                                Some(header) if header.0.number < number_of(&finalized) => {
                                    println!("finality status regressed to {}; keeping {}", header.0.number, number_of(&finalized));
                                }
                                _ => {}
                            }
                            // safe follows the local node's accepted head, and is never below finalized.
                            let candidate = match levels.safe {
                                Some(h) if h.0.number >= number_of(&finalized) => Some(h),
                                _ => finalized.clone(),
                            };
                            match candidate {
                                Some(header) if header.0.number > number_of(&safe) => {
                                    state.set_safe(header.clone());
                                    println!("safe block={} hash={} (settlement accepted on the native head)", header.0.number, header.hash());
                                    safe = Some(header);
                                }
                                Some(header) if header.0.number < number_of(&safe) => {
                                    println!("safe settlement regressed to {}; keeping {}", header.0.number, number_of(&safe));
                                }
                                _ => {}
                            }
                            let s = &levels.status;
                            let latest = factory.sealed_header(head_number)?;
                            *finality.write().expect("finality lock") = serde_json::json!({
                                "latest": level_json(&latest),
                                "safe": level_json(&safe),
                                "finalized": level_json(&finalized),
                                "finalized_height": number_of(&finalized),
                                "l1": {
                                    "finalized": {"epoch": s["native_finalized_epoch"], "root": s["native_finalized_block"],
                                                  "slot": s["native_finalized_slot"]},
                                    "verified_tip": s["verified_tip"], "verified_blocks": s["verified_blocks"],
                                    "safe_settlement": s["safe_settlement"],
                                },
                                "trust": "finalized: native FFG replay from the pinned genesis; safe: the local native node's head; no checkpoint signatures",
                            });
                        }
                        Ok(None) => {}
                        Err(error) => println!("finality not advanced: {error}"),
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    let _ = server.stop();
    let _ = std::fs::remove_dir_all(&options.view_dir);
    if !runtime.graceful_shutdown_with_timeout(Duration::from_secs(10)) {
        bail!("runtime graceful shutdown timed out");
    }
    result
}
