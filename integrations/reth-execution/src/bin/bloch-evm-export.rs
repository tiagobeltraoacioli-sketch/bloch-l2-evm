// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only proof-input export from a stopped synthetic developer node.
use alloy_primitives::B256;
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{proof_export::export_canonical_witness, BlochChainSpec, BlochProviderFactory};
use eyre::{ensure, Result};
use reth_db::mdbx::{open_db_read_only, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    ProviderFactory,
};
use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("bloch-evm-export --synthetic-dev SOURCE_DIRECTORY BLOCK_NUMBER NEW_ARTIFACT\nStop source writers first. Source is opened read-only; output must be outside it.\nLocal block selection is trusted. No native deposit/finality authentication or proof generation.");
        return Ok(());
    }
    ensure!(
        args.len() == 4 && args[0] == "--synthetic-dev",
        "use --help for the explicit synthetic export command"
    );
    let source = std::fs::canonicalize(PathBuf::from(&args[1]))?;
    let number: u64 = args[2]
        .to_str()
        .ok_or_else(|| eyre::eyre!("invalid block number"))?
        .parse()?;
    let output = PathBuf::from(&args[3]);
    let output_parent = std::fs::canonicalize(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new(".")),
    )?;
    ensure!(
        !output_parent.starts_with(&source),
        "artifact output must be outside the source directory"
    );
    ensure!(!output.try_exists()?, "artifact output already exists");
    for directory in ["db", "static", "rocks"] {
        ensure!(
            source.join(directory).is_dir(),
            "incomplete source: missing {directory}"
        );
    }
    let runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::ExistingHandle(tokio::runtime::Handle::current())),
    )
    .build()?;
    let result = (|| -> Result<()> {
        let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0)?);
        let factory: BlochProviderFactory = ProviderFactory::new(
            Arc::new(open_db_read_only(source.join("db"), DatabaseArguments::default())?),
            spec,
            StaticFileProvider::read_only(source.join("static"))?,
            RocksDBBuilder::new(source.join("rocks"))
                .with_default_tables()
                .with_read_only(true)
                .build()?,
            runtime.clone(),
        )?;
        let artifact = export_canonical_witness(&factory, number).map_err(|error| eyre::eyre!("{error}"))?;
        let bytes = artifact.encode().map_err(|error| eyre::eyre!("{error}"))?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(&output)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&output_parent)?.sync_all()?;
        println!("SYNTHETIC execution input exported: block={} header={} bytes={}; no native funding/finality authentication", number, artifact.header().hash(), bytes.len());
        Ok(())
    })();
    let shutdown =
        tokio::task::spawn_blocking(move || runtime.graceful_shutdown_with_timeout(Duration::from_secs(10))).await;
    result?;
    ensure!(shutdown?, "runtime graceful shutdown timed out");
    Ok(())
}
