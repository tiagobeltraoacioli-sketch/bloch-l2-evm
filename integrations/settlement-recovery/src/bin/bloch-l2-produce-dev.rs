// SPDX-License-Identifier: AGPL-3.0-or-later
//! Development producer for the natively settled L2 canonical database.
//!
//! `init` creates a fresh database at L2 genesis. `da` prints the L1
//! data-availability batch of one block's user transactions (M3), and
//! `reconstruct` rebuilds a fresh database from native (L1) blocks only:
//! deposits, DA batches and settlements, checking every settled root. `extend` appends exactly one
//! block anchored to the native-selected source block, refusing any parent
//! other than the one the caller names (the previously accepted native
//! settlement's L2 header). Without `--txs` the block carries deposits only;
//! with `--txs` it also carries user transactions chosen deterministically by
//! `bloch_l2_evm::node_execution::select` within per-block gas/byte/count limits. `export` writes the execution artifact of one block
//! for the settlement prover. Block attributes follow a fixed development rule
//! (timestamp = parent + 1, prevrandao 0x07..07), which reproduces the block the
//! `native-empty` qualification proves for block 1. No proof, settlement,
//! deposit or finality is produced or implied here.
#![cfg(unix)]

use alloy_primitives::{hex, B256};
use bloch_l2_evm::{
    data_availability::{da_commitment, encode_da_payload},
    node_execution::select::SelectionLimits,
    ChainSpec,
};
use bloch_settlement_recovery::reconstruct::{derive_settled_blocks, NativeBlockTransactions};
use bloch_reth_execution::{
    prepare_genesis, proof_export::export_canonical_witness, BlochChainSpec, BlochNextBlockEnvCtx,
    BlochProviderFactory, BlochTables, CanonicalCoordinator,
};
use reth_db::mdbx::{init_db_for, open_db, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
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
  bloch-l2-produce-dev extend --target DIR --parent HEX --anchor HEX [--deposits FILE]
                              [--txs PATH] [--max-gas N] [--max-bytes N] [--max-txs N]
  bloch-l2-produce-dev export --target DIR --number N --out FILE
  bloch-l2-produce-dev head   --target DIR
  bloch-l2-produce-dev da     --target DIR --number N --out FILE
  bloch-l2-produce-dev reconstruct --target NEW_DIR (--l1 FILE | --l1-follower DIR) [--chain-id N]

extend appends one empty block (timestamp = parent + 1, prevrandao 0x07..07)
whose anchor is the native-selected source block. HEX is 64 lowercase hex
characters without 0x. --deposits is a JSON list of native inbox records
({height,tx_index,txid,vout,sats,recipient}) minted at block start, in order.
--txs is the pending pool: a JSON list of signed transaction hex strings, or a
spool directory of *.tx files (one hex transaction each). Deposits are minted
first; transactions are selected in a deterministic order within --max-gas
(declared gas), --max-bytes (encoded bytes) and --max-txs; overflow is left
pending and invalid transactions are dropped with a reason. With a spool
directory, files of included and dropped transactions are removed after the
block is durably committed. Without --txs the block has no user transactions.
da writes the canonical L1 data-availability batch (hex) of block N's user
transactions and prints its da_commitment; a block without user transactions
has nothing to publish. reconstruct creates NEW_DIR at L2 genesis and replays
every L2 block settled in the given native blocks, from native data only:
inbox deposits (0x14), DA batches (0x15) and settlements (0x12/0x13). --l1 is
a JSON object {blocks: [{height, transactions: [hex, ...]}, ...]} in height order;
--l1-follower is a native follower state directory (index + blocks/*.bin).
Each rebuilt block must reproduce the settled header hash and state root.
Development only: no settlement or finality is implied.
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
            only(
                rest,
                &["--target", "--parent", "--anchor", "--deposits", "--txs", "--max-gas", "--max-bytes", "--max-txs"],
            )?;
            let deposits = match rest.chunks(2).find(|p| p[0] == "--deposits") {
                Some(pair) => read_deposits(Path::new(&pair[1]))?,
                None => vec![],
            };
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
            let attributes = BlochNextBlockEnvCtx {
                timestamp,
                prevrandao: B256::repeat_byte(7),
                anchor_root: anchor,
                deposits: deposits.clone(),
            };
            let pool = match rest.chunks(2).find(|p| p[0] == "--txs") {
                Some(pair) => Some(read_pool(Path::new(&pair[1]))?),
                None => {
                    if rest.chunks(2).any(|p| p[0].starts_with("--max-")) {
                        return Err("--max-gas/--max-bytes/--max-txs require --txs".into());
                    }
                    None
                }
            };
            let Some(pool) = pool else {
                let tip = coordinator.extend(parent, attributes, vec![]).map_err(|e| e.to_string())?;
                return Ok(json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                          "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                          "anchor": hex::encode(anchor), "timestamp": timestamp, "deposits": deposits.len(),
                          "transactions": 0})
                .to_string());
            };
            let limits = limits(rest, SelectionLimits::protocol(&ChainSpec::testnet()))?;
            let candidates: Vec<_> = pool.iter().map(|(_, raw)| raw.clone()).collect();
            let (tip, selection) = coordinator
                .extend_with_pending(parent, attributes, &candidates, limits)
                .map_err(|e| e.to_string())?;
            // Committed: prune the spool of included and dropped entries.
            let mut pruned = 0usize;
            let finished = selection
                .dropped
                .iter()
                .map(|d| d.index)
                .chain(selection.hashes.iter().filter_map(|h| {
                    candidates.iter().position(|raw| alloy_primitives::keccak256(raw) == *h)
                }));
            for index in finished {
                if let Some(file) = &pool[index].0 {
                    fs::remove_file(file).map_err(|e| format!("prune {}: {e}", file.display()))?;
                    pruned += 1;
                }
            }
            Ok(json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                      "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                      "anchor": hex::encode(anchor), "timestamp": timestamp, "deposits": deposits.len(),
                      "transactions": selection.transactions.len(),
                      "declared_gas": selection.declared_gas, "bytes": selection.bytes,
                      "limits": {"max_gas": limits.max_gas, "max_bytes": limits.max_bytes,
                                 "max_txs": limits.max_transactions},
                      "included": selection.hashes.iter().map(hex::encode).collect::<Vec<_>>(),
                      "deferred": selection.deferred.iter().map(|d| json!({"hash": hex::encode(d.hash),
                                  "reason": d.reason.as_str()})).collect::<Vec<_>>(),
                      "dropped": selection.dropped.iter().map(|d| json!({"index": d.index,
                                  "hash": d.hash.map(hex::encode), "reason": d.reason.describe()}))
                                  .collect::<Vec<_>>(),
                      "pruned": pruned})
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
        "da" => {
            only(rest, &["--target", "--number", "--out"])?;
            let number: u64 = option(rest, "--number")?.parse().map_err(|_| "--number must be decimal")?;
            let out = PathBuf::from(option(rest, "--out")?);
            let factory = open(&target, &runtime, false)?;
            let block = factory
                .block_by_number(number)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("no block {number}"))?;
            let transactions = &block.body.as_core().transactions;
            if transactions.is_empty() {
                return Err(format!("block {number} has no user transactions: nothing to publish"));
            }
            let payload = encode_da_payload(transactions).map_err(|e| e.to_string())?;
            let chain_id = ChainSpec::testnet().chain_id;
            let commitment = da_commitment(chain_id, number, &payload);
            let mut file = OpenOptions::new().write(true).create_new(true).open(&out).map_err(|e| e.to_string())?;
            writeln!(file, "{}", hex::encode(&payload)).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            Ok(json!({"number": number, "hash": hex::encode(block.header.0.hash()), "chain_id": chain_id,
                      "transactions": transactions.len(), "bytes": payload.len(),
                      "da_commitment": hex::encode(commitment)})
            .to_string())
        }
        "reconstruct" => {
            only(rest, &["--target", "--l1", "--l1-follower", "--chain-id"])?;
            let blocks = match (option(rest, "--l1"), option(rest, "--l1-follower")) {
                (Ok(file), Err(_)) => read_l1_fixture(Path::new(file))?,
                (Err(_), Ok(dir)) => read_l1_follower(Path::new(dir))?,
                _ => return Err("exactly one of --l1 or --l1-follower is required".into()),
            };
            let chain_id = match option(rest, "--chain-id") {
                Ok(value) => value.parse().map_err(|_| "--chain-id must be decimal")?,
                Err(_) => ChainSpec::testnet().chain_id,
            };
            fs::create_dir(&target).map_err(|e| format!("create target: {e}"))?;
            let factory = open(&target, &runtime, true)?;
            let genesis = prepare_genesis(&*spec()?, factory.latest().map_err(|e| e.to_string())?.as_ref())
                .map_err(|e| e.to_string())?;
            let genesis_header = genesis.recovered_block().clone_sealed_header();
            let writer = factory.database_provider_rw().map_err(|e| e.to_string())?;
            writer.save_blocks(vec![genesis], SaveBlocksMode::Full).map_err(|e| e.to_string())?;
            writer.commit().map_err(|e| e.to_string())?;
            let settled = derive_settled_blocks(&blocks, chain_id, genesis_header.hash(), genesis_header.0.state_root)
                .map_err(|e| e.to_string())?;
            let mut coordinator = CanonicalCoordinator::attach(factory).map_err(|e| e.to_string())?;
            let mut report = Vec::new();
            for block in &settled {
                let head = coordinator.head().clone();
                if head.hash() != block.parent_hash || head.0.state_root != block.previous_state_root {
                    return Err(format!("L2 block {}: rebuilt parent differs from the settled parent", block.number));
                }
                let attributes = BlochNextBlockEnvCtx {
                    timestamp: head.0.timestamp.checked_add(1).ok_or("timestamp overflow")?,
                    prevrandao: B256::repeat_byte(7),
                    anchor_root: block.anchor,
                    deposits: block.deposits.clone(),
                };
                let tip = coordinator
                    .extend_raw(head.hash(), attributes, &block.transactions)
                    .map_err(|e| format!("L2 block {}: {e}", block.number))?;
                let mismatch = tip.hash() != block.header_hash
                    || tip.0.state_root != block.state_root
                    || block.transactions_root.is_some_and(|root| root != tip.0.transactions_root)
                    || block.deposits_hash.is_some_and(|hash| hash != tip.0.deposits_hash);
                if mismatch {
                    return Err(format!(
                        "L2 block {}: rebuilt hash {} / state root {} differ from settled {} / {}",
                        block.number,
                        hex::encode(tip.hash()),
                        hex::encode(tip.0.state_root),
                        hex::encode(block.header_hash),
                        hex::encode(block.state_root)
                    ));
                }
                report.push(json!({"number": block.number, "settled_at": block.settled_at,
                                   "hash": hex::encode(tip.hash()), "state_root": hex::encode(tip.0.state_root),
                                   "deposits": block.deposits.len(), "transactions": block.transactions.len(),
                                   "da_commitment": hex::encode(block.da_commitment)}));
            }
            Ok(json!({"genesis": hex::encode(genesis_header.hash()), "native_blocks": blocks.len(),
                      "settled": report.len(), "head": report.last().map(|b| b["hash"].clone()),
                      "blocks": report})
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

/// Native inbox records as L2 deposit mints. The native settlement rejects any
/// body that does not mint exactly these records, so no field is defaulted.
fn read_deposits(path: &Path) -> Result<Vec<bloch_l2_evm::DepositMint>, String> {
    let bytes = fs::read(path).map_err(|e| format!("deposits: {e}"))?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&bytes).map_err(|e| format!("deposits: {e}"))?;
    let num = |v: &serde_json::Value, k: &str| v[k].as_u64().ok_or_else(|| format!("deposit field {k} must be an integer"));
    let bytes_of = |v: &serde_json::Value, k: &str, n: usize| -> Result<Vec<u8>, String> {
        let b = hex::decode(v[k].as_str().unwrap_or_default().trim_start_matches("0x")).map_err(|_| format!("deposit field {k} must be hex"))?;
        if b.len() != n { return Err(format!("deposit field {k} must be {n} bytes")); }
        Ok(b)
    };
    list.iter()
        .map(|v| {
            Ok(bloch_l2_evm::DepositMint {
                recipient: alloy_primitives::Address::from_slice(&bytes_of(v, "recipient", 20)?),
                provenance: bloch_l2_evm::DepositProvenance::BridgedBlch {
                    l1_height: num(v, "height")?,
                    l1_tx_index: u32::try_from(num(v, "tx_index")?).map_err(|_| "tx_index too large")?,
                    l1_txid: bytes_of(v, "txid", 32)?.try_into().unwrap(),
                    l1_vout: u32::try_from(num(v, "vout")?).map_err(|_| "vout too large")?,
                    l1_sats: num(v, "sats")?,
                },
            })
        })
        .collect()
}

/// Pending pool entries: (spool file, if any; canonical signed bytes).
/// Bytes are not authenticated here; selection drops invalid ones with a reason.
fn read_pool(path: &Path) -> Result<Vec<(Option<PathBuf>, alloy_primitives::Bytes)>, String> {
    let decode = |text: &str| -> Result<alloy_primitives::Bytes, String> {
        hex::decode(text.trim().trim_start_matches("0x")).map(Into::into).map_err(|_| "--txs entry is not hex".to_string())
    };
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("--txs: {e}"))?;
    let entries = if metadata.is_dir() {
        let mut files = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| format!("--txs: {e}"))? {
            let file = entry.map_err(|e| format!("--txs: {e}"))?.path();
            if file.extension().is_some_and(|x| x == "tx") && fs::symlink_metadata(&file).map(|m| m.is_file()).unwrap_or(false) {
                files.push(file);
            }
        }
        // Order does not affect selection; sort only for stable reports.
        files.sort();
        files
            .into_iter()
            .map(|file| {
                let text = fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
                // Undecodable text still becomes a (dropped) candidate, so the file is pruned.
                Ok((Some(file), decode(&text).unwrap_or_default()))
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        let list: Vec<String> =
            serde_json::from_slice(&fs::read(path).map_err(|e| format!("--txs: {e}"))?).map_err(|e| format!("--txs: {e}"))?;
        list.iter().map(|text| Ok((None, decode(text)?))).collect::<Result<Vec<_>, String>>()?
    };
    if entries.len() > MAX_POOL_ENTRIES {
        return Err(format!("--txs holds more than {MAX_POOL_ENTRIES} entries"));
    }
    Ok(entries)
}

/// Native blocks as a JSON fixture: {"blocks":[{"height":H,"transactions":[HEX,...]}]}.
fn read_l1_fixture(path: &Path) -> Result<Vec<NativeBlockTransactions>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).map_err(|e| format!("--l1: {e}"))?).map_err(|e| format!("--l1: {e}"))?;
    let blocks = value["blocks"].as_array().ok_or("--l1 needs a blocks list")?;
    if blocks.len() > MAX_L1_BLOCKS {
        return Err(format!("--l1 holds more than {MAX_L1_BLOCKS} blocks"));
    }
    blocks
        .iter()
        .map(|block| {
            let height = block["height"].as_u64().ok_or("block height must be an integer")?;
            let transactions = block["transactions"]
                .as_array()
                .ok_or("block transactions must be a list")?
                .iter()
                .map(|tx| hex::decode(tx.as_str().unwrap_or_default()).map_err(|_| "transaction is not hex".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(NativeBlockTransactions { height, transactions })
        })
        .collect()
}

/// A native follower state directory: `index` lists verified block ids from
/// genesis (line i is height i), `blocks/<id>.bin` holds each envelope.
fn read_l1_follower(dir: &Path) -> Result<Vec<NativeBlockTransactions>, String> {
    let index = fs::read_to_string(dir.join("index")).map_err(|e| format!("--l1-follower index: {e}"))?;
    let mut blocks = Vec::new();
    for (i, line) in index.lines().enumerate() {
        if blocks.len() >= MAX_L1_BLOCKS {
            return Err(format!("--l1-follower holds more than {MAX_L1_BLOCKS} blocks"));
        }
        let id: B256 = line.trim().parse().map_err(|_| "corrupt follower index line")?;
        let bytes = fs::read(dir.join("blocks").join(format!("{}.bin", hex::encode(id)))).map_err(|e| e.to_string())?;
        let envelope = bloch_pos_node::codec::decode_envelope(&bytes).map_err(|_| "native envelope does not decode")?;
        if B256::from(*envelope.block_id().as_bytes()) != id {
            return Err("native envelope does not match its index id".into());
        }
        blocks.push(NativeBlockTransactions { height: i as u64 + 1, transactions: envelope.body.transactions });
    }
    Ok(blocks)
}

/// Upper bound on native blocks read by one reconstruction.
const MAX_L1_BLOCKS: usize = 1_000_000;

/// Upper bound on candidates read per block (selection cost is linear in it).
const MAX_POOL_ENTRIES: usize = 16_384;

fn limits(args: &[String], protocol: SelectionLimits) -> Result<SelectionLimits, String> {
    let value = |name: &str| -> Result<Option<u64>, String> {
        args.chunks(2)
            .find(|p| p[0] == name)
            .map(|p| p[1].parse::<u64>().map_err(|_| format!("{name} must be decimal")))
            .transpose()
    };
    let limits = SelectionLimits {
        max_gas: value("--max-gas")?.unwrap_or(protocol.max_gas),
        max_bytes: value("--max-bytes")?.map_or(Ok(protocol.max_bytes), |v| usize::try_from(v).map_err(|_| "--max-bytes too large".to_string()))?,
        max_transactions: value("--max-txs")?.map_or(Ok(protocol.max_transactions), |v| usize::try_from(v).map_err(|_| "--max-txs too large".to_string()))?,
    };
    if limits.max_gas > protocol.max_gas
        || limits.max_bytes > protocol.max_bytes
        || limits.max_transactions > protocol.max_transactions
    {
        return Err(format!(
            "limits exceed the protocol maxima (gas {}, bytes {}, txs {})",
            protocol.max_gas, protocol.max_bytes, protocol.max_transactions
        ));
    }
    Ok(limits)
}
