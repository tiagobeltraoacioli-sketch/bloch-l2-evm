// SPDX-License-Identifier: AGPL-3.0-or-later
//! Development producer for the natively settled L2 canonical database.
//!
//! `init` creates a fresh database at L2 genesis. `extend` appends exactly one
//! EMPTY block anchored to the native-selected source block, refusing any parent
//! other than the one the caller names (the previously accepted native
//! settlement's L2 header). `export` writes the execution artifact of one block
//! for the settlement prover. Block attributes follow a fixed development rule
//! (timestamp = parent + 1, prevrandao 0x07..07), which reproduces the block the
//! `native-empty` qualification proves for block 1. No proof, settlement,
//! deposit or finality is produced or implied here.
#![cfg(unix)]

use alloy_primitives::{hex, B256};
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    prepare_genesis, proof_export::export_canonical_witness, BlochChainSpec, BlochNextBlockEnvCtx,
    BlochProviderFactory, BlochTables, CanonicalCoordinator,
};
use reth_db::mdbx::{init_db_for, open_db, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use reth_tasks::{Runtime, RuntimeBuilder, RuntimeConfig};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

const USAGE: &str = "\
usage:
  bloch-l2-produce-dev init   --target DIR
  bloch-l2-produce-dev extend --target DIR --parent HEX --anchor HEX
  bloch-l2-produce-dev export --target DIR --number N --out FILE
  bloch-l2-produce-dev head   --target DIR

extend appends one empty block (timestamp = parent + 1, prevrandao 0x07..07)
whose anchor is the native-selected source block. HEX is 64 lowercase hex
characters without 0x. Development only: no settlement or finality is implied.
";

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bloch-l2-produce-dev: refused: {error}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn option<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    let mut found = None;
    for pair in args.chunks(2) {
        if pair.len() != 2 || !pair[0].starts_with("--") {
            return Err("options must be --name value pairs".into());
        }
        if pair[0] == name {
            if found.is_some() {
                return Err(format!("{name} repeated"));
            }
            found = Some(pair[1].as_str());
        }
    }
    found.ok_or_else(|| format!("missing {name}"))
}

fn only(args: &[String], allowed: &[&str]) -> Result<(), String> {
    for pair in args.chunks(2) {
        if !allowed.contains(&pair[0].as_str()) {
            return Err(format!("unexpected option {}", pair[0]));
        }
    }
    Ok(())
}

fn hash(value: &str, name: &str) -> Result<B256, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("{name} must be 64 lowercase hex characters"));
    }
    let parsed: B256 = value.parse().map_err(|_| format!("{name} is not a hash"))?;
    if parsed.is_zero() {
        return Err(format!("{name} must not be zero"));
    }
    Ok(parsed)
}

fn spec() -> Result<Arc<BlochChainSpec>, String> {
    BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0)
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

fn open(path: &Path, runtime: &Runtime, create: bool) -> Result<BlochProviderFactory, String> {
    let db = if create {
        init_db_for::<_, BlochTables>(path.join("db"), DatabaseArguments::default())
    } else {
        for directory in ["db", "static", "rocks"] {
            if !fs::symlink_metadata(path.join(directory)).map(|m| m.is_dir()).unwrap_or(false) {
                return Err(format!("target is missing {directory}"));
            }
        }
        open_db(path.join("db"), DatabaseArguments::default())
    }
    .map_err(|e| e.to_string())?;
    ProviderFactory::new(
        Arc::new(db),
        spec()?,
        StaticFileProvider::read_write(path.join("static")).map_err(|e| e.to_string())?,
        RocksDBBuilder::new(path.join("rocks")).with_default_tables().build().map_err(|e| e.to_string())?,
        runtime.clone(),
    )
    .map_err(|e| e.to_string())
}

fn run(args: &[String]) -> Result<String, String> {
    let (command, rest) = args.split_first().ok_or("missing command")?;
    let target = PathBuf::from(option(rest, "--target")?);
    let runtime = RuntimeBuilder::new(RuntimeConfig::default()).build().map_err(|e| e.to_string())?;
    let result = (|| match command.as_str() {
        "init" => {
            only(rest, &["--target"])?;
            fs::create_dir(&target).map_err(|e| format!("create target: {e}"))?;
            let factory = open(&target, &runtime, true)?;
            let genesis = prepare_genesis(&*spec()?, factory.latest().map_err(|e| e.to_string())?.as_ref())
                .map_err(|e| e.to_string())?;
            let hash = genesis.recovered_block().hash();
            let writer = factory.database_provider_rw().map_err(|e| e.to_string())?;
            writer.save_blocks(vec![genesis], SaveBlocksMode::Full).map_err(|e| e.to_string())?;
            writer.commit().map_err(|e| e.to_string())?;
            Ok(json!({"number": 0, "hash": hex::encode(hash)}).to_string())
        }
        "extend" => {
            only(rest, &["--target", "--parent", "--anchor"])?;
            let parent = hash(option(rest, "--parent")?, "--parent")?;
            let anchor = hash(option(rest, "--anchor")?, "--anchor")?;
            let mut coordinator =
                CanonicalCoordinator::attach(open(&target, &runtime, false)?).map_err(|e| e.to_string())?;
            let head = coordinator.head().clone();
            if head.hash() != parent {
                return Err(format!(
                    "canonical head {} is not the expected parent {}",
                    hex::encode(head.hash()),
                    hex::encode(parent)
                ));
            }
            let timestamp = head.0.timestamp.checked_add(1).ok_or("timestamp overflow")?;
            let tip = coordinator
                .extend(
                    parent,
                    BlochNextBlockEnvCtx {
                        timestamp,
                        prevrandao: B256::repeat_byte(7),
                        anchor_root: anchor,
                        deposits: vec![],
                    },
                    vec![],
                )
                .map_err(|e| e.to_string())?;
            Ok(json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                      "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                      "anchor": hex::encode(anchor), "timestamp": timestamp})
            .to_string())
        }
        "export" => {
            only(rest, &["--target", "--number", "--out"])?;
            let number: u64 = option(rest, "--number")?.parse().map_err(|_| "--number must be decimal")?;
            let out = PathBuf::from(option(rest, "--out")?);
            let factory = open(&target, &runtime, false)?;
            let artifact = export_canonical_witness(&factory, number).map_err(|e| e.to_string())?;
            let bytes = artifact.encode().map_err(|e| e.to_string())?;
            let mut file = OpenOptions::new().write(true).create_new(true).open(&out).map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            File::open(out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))
                .and_then(|d| d.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(json!({"number": number, "hash": hex::encode(artifact.header().hash()),
                      "anchor": hex::encode(artifact.context().anchor_root), "bytes": bytes.len()})
            .to_string())
        }
        "head" => {
            only(rest, &["--target"])?;
            let factory = open(&target, &runtime, false)?;
            let number = factory.best_block_number().map_err(|e| e.to_string())?;
            let header = factory.sealed_header(number).map_err(|e| e.to_string())?.ok_or("missing head header")?;
            Ok(json!({"number": number, "hash": hex::encode(header.hash()),
                      "state_root": hex::encode(header.0.state_root)})
            .to_string())
        }
        other => Err(format!("unknown command {other}")),
    })();
    if !runtime.graceful_shutdown_with_timeout(Duration::from_secs(10)) {
        return Err("task runtime did not shut down".into());
    }
    result
}
