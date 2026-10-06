// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only RPC for the natively settled development L2.
//!
//! Serves the canonical database written by the settlement worker, opened
//! read-only, and follows its head. `safe`/`finalized` are published only in
//! memory (never written to the database) and only from the native follower's
//! status: the highest L2 block whose settlement lies inside the natively
//! FFG-finalized prefix that the follower verified by real replay, provided that
//! every listed settlement matches the local canonical header at its height.
//! Finality never regresses; any inconsistency freezes it and is logged.
//! Transactions are refused: this node produces no blocks.
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
    BlockNumReader, HeaderProvider, ProviderFactory,
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

const USAGE: &str = "bloch-l2-settled-rpc --data-dir CANONICAL --view-dir NEW_DIR --finality-status FILE --network HEX [--port 8546] [--poll-ms 2000]\n\
Read-only development RPC. safe/finalized come only from verified native FFG finality of L2 settlements.\n";

struct Options {
    data_dir: PathBuf,
    view_dir: PathBuf,
    status: PathBuf,
    network: String,
    port: u16,
    poll: Duration,
}

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
            ["--data-dir", "--view-dir", "--finality-status", "--network", "--port", "--poll-ms"].contains(&pair[0].as_str()),
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
    })
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

/// The highest L2 header proven final by the follower's verified status, if
/// every listed settlement matches the local canonical chain.
fn verified_final_header(
    status_path: &Path,
    network: &str,
    provider: &BlochBlockchainProvider,
) -> Result<Option<reth_primitives_traits::SealedHeader<bloch_reth_execution::BlochNodeHeader>>> {
    let bytes = match std::fs::read(status_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(bytes.len() <= 16 * 1_048_576, "finality status too large");
    let status: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(status["schema"] == "bloch.l2.native-follower-status.v1", "unexpected status schema");
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
    Ok(best)
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = parse()?;
    let runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::ExistingHandle(tokio::runtime::Handle::current())),
    )
    .build()?;
    create_view(&options.data_dir, &options.view_dir)?;
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0)?);
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(open_db_read_only(options.view_dir.join("db"), DatabaseArguments::default())?),
        spec.clone(),
        StaticFileProvider::read_only(options.view_dir.join("static"))?,
        RocksDBBuilder::new(options.view_dir.join("rocks")).with_default_tables().with_read_only(true).build()?,
        runtime.clone(),
    )?
    .with_read_only_sync(true);
    let provider: BlochBlockchainProvider = BlockchainProvider::new(factory.clone())?;
    let kernel = ChainSpec::testnet();
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
    module.merge(filter.into_rpc())?;
    module.merge(chain_identity_rpc(spec.clone()))?;
    module.merge(chain_status_rpc(spec.clone(), provider.clone()))?;
    let server = start_http_rpc(module, options.port).await?;
    println!(
        "SETTLED DEV RPC (read-only) at {}; finality only from verified native FFG settlement",
        server.http_url().unwrap_or_default()
    );
    let state = provider.canonical_in_memory_state();
    let mut head_number = u64::MAX;
    let mut finalized_number = 0u64;
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
                    match verified_final_header(&options.status, &options.network, &provider) {
                        Ok(Some(header)) if header.0.number > finalized_number => {
                            finalized_number = header.0.number;
                            state.set_safe(header.clone());
                            state.set_finalized(header.clone());
                            println!("finalized block={} hash={} (verified native FFG settlement)", finalized_number, header.hash());
                        }
                        Ok(Some(header)) if header.0.number < finalized_number => {
                            println!("finality status regressed to {}; keeping {}", header.0.number, finalized_number);
                        }
                        Ok(_) => {}
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
