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
//! for the settlement prover. `withdrawal-proof` (M4) prints the Merkle proof
//! of one outbox withdrawal against the withdrawal root after a block, the
//! input of an L1 claim. Blocks execute under the settlement V3 rules
//! (`ChainSpec::testnet_v3`, withdrawal outbox). Block attributes follow a fixed development rule
//! (timestamp = parent + 1, prevrandao 0x07..07), which reproduces the block the
//! `native-empty` qualification proves for block 1. No proof, settlement,
//! deposit or finality is produced or implied here.
#![cfg(unix)]

use alloy_primitives::{hex, Address, B256, U256};
use bloch_l2_evm::forced_inclusion::{ForcedRecord, ForcedSelection, ForcedTransaction};
use bloch_l2_evm::{
    data_availability::{da_commitment, encode_da_payload},
    node_execution::select::SelectionLimits,
    proof_statement::configuration_commitment,
    withdrawal::{
        empty_withdrawal_root, verify_withdrawal_proof, Withdrawal, WithdrawalCommitment, WithdrawalTree,
        OUTBOX_NONCE_SLOT, OUTBOX_ROOT_SLOT,
    },
    ChainSpec,
};
use bloch_settlement_recovery::reconstruct::{
    derive_settled_blocks, flag_day_first_slot, l2_registry_blocks, NativeBlockTransactions,
};
use bloch_settlement_recovery::timestamp::{next_timestamp, TimestampRule};
use bloch_reth_execution::{
    canonical::rewind_canonical_head, prepare_genesis,
    proof_export::{export_forced_with_report, export_sparse_forced_with_report, export_with_report}, BlochChainSpec, BlochNextBlockEnvCtx,
    BlochProviderFactory, BlochTables, CanonicalCoordinator, L2Network,
};
use reth_db::mdbx::{init_db_for, open_db, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, BlockReader, ChainSpecProvider, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
    ReceiptProvider, StateProvider, StateProviderFactory,
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
usage (every command also takes [--rules v3|mainnet --domain HEX --genesis-time SECS]):
  bloch-l2-produce-dev init   --target DIR
  bloch-l2-produce-dev extend --target DIR --parent HEX --anchor HEX [--deposits FILE]
                              [--txs PATH] [--max-gas N] [--max-bytes N] [--max-txs N]
                              [--timestamp-rule FROM:GENESIS:SLOT_MS --anchor-slot N]
                              [--rule-set base|next] [--forced FILE]
  bloch-l2-produce-dev select ... as extend, with --txs and without --max-txs: reports the selection and commits nothing
  bloch-l2-produce-dev rewind --target DIR --number N --hash HEX [--respool DIR]
  bloch-l2-produce-dev export --target DIR --number N --out FILE [--witness complete|sparse]
  bloch-l2-produce-dev head   --target DIR
  bloch-l2-produce-dev da     --target DIR --number N --out FILE
  bloch-l2-produce-dev reconstruct --target NEW_DIR (--l1 FILE | --l1-follower DIR) [--chain-id N]
                                   [--timestamp-rule FROM:GENESIS:SLOT_MS]
  bloch-l2-produce-dev withdrawal-proof --target DIR --index I [--number N] [--root HEX --count N]
  bloch-l2-produce-dev account --target DIR --address HEX20
  bloch-l2-produce-dev address --key FILE
  bloch-l2-produce-dev sign-tx --key FILE --nonce N (--to HEX20 --value-wei N | --withdraw-to HEX32 --sats N)
                               [--gas N] [--max-fee-wei N] --out FILE

extend appends one empty block (timestamp = parent + 1, prevrandao 0x07..07)
whose anchor is the native-selected source block. With --timestamp-rule
FROM:L1_GENESIS_UNIX_SECS:L1_SLOT_MILLIS, blocks from L2 number FROM on take the
start time of the anchored native slot (--anchor-slot), never less than parent + 1;
reconstruct must be given the same rule. HEX is 64 lowercase hex
characters without 0x. --deposits is a JSON list of native inbox records
({height,tx_index,txid,vout,sats,recipient}) minted at block start, in order.
--forced (CANDIDATE, forced inclusion) is the JSON list getl2settlement.forced.due
gives ({height,l1_txid,envelope_hash,gas_limit,envelope}): after the deposits and
before the pool, each runs or is skipped by the forced rule, outside the limits;
a sidecar DIR/forced/NNNNNNNN.json lets export and da find them.
--txs is the pending pool: a JSON list of signed transaction hex strings, or a
spool directory of *.tx files (one hex transaction each). Deposits are minted
first; transactions are selected in a deterministic order within --max-gas
(declared gas), --max-bytes (encoded bytes) and --max-txs; overflow is left
pending and invalid transactions are dropped with a reason. With a spool
directory, files of included and dropped transactions are removed after the
block is durably committed. Without --txs the block has no user transactions.
--min-tip-wei N leaves pending the transactions whose effective priority fee at
this block's base fee is below N (default 0, no minimum); reported as below_min_tip.
--fresh-slot-price-wei N (with --txs; sequencer policy v2) leaves pending every
transaction whose gas used times effective tip is below N times the storage slots
it adds, measured on the block as it will be built: the first such transaction in
block order is taken out and the selection runs again, so a transaction is judged
after exactly the transactions it would run after. At most 8 such passes run: if the
last one still finds an unpaid transaction, the block keeps the transactions ahead of
it and everything else stays pending, reported as not_judged. --write-exempt A,B names
senders that pay no write price. Left transactions keep their spool files (unpaid).
select runs the same selection on the same parent, deposits and limits, and prints
the report extend would print (included, deferred, dropped, tx_stats with sender,
nonce, gas used, effective tip and storage slots added and cleared per account),
without committing a block or pruning the spool. It takes no --max-txs: a
sequencer policy applies its own count to its own order (sequencer policy v2).
da writes the canonical L1 data-availability batch (hex) of block N's user
transactions and prints its da_commitment; a block without user transactions
has nothing to publish. reconstruct creates NEW_DIR at L2 genesis and replays
every L2 block settled in the given native blocks, from native data only:
inbox deposits (0x14), DA batches (0x15) and settlements (0x12/0x13). --l1 is
a JSON object {blocks: [{height, transactions: [hex, ...]}, ...]} in height order;
--l1-follower is a native follower state directory (index + blocks/*.bin).
Each rebuilt block must reproduce the settled header hash and state root, and
a V3 settlement's withdrawal root and count.
withdrawal-proof rebuilds the withdrawal tree from the outbox events of blocks
1..=N (default: the head), checks it against the outbox root and count in the
state after block N (and against --root/--count, e.g. a settled statement),
and prints the 32 siblings of withdrawal I (bottom-up) with its leaf fields.
extend and head report the outbox withdrawal_root / withdrawal_count after the
block; extend also lists the withdrawals the block initiated.
account prints the balance (wei and whole sats) and nonce of an L2 address at
the head. address prints the L2 address of a development secp256k1 key FILE
(64 hex characters). sign-tx writes one signed EIP-1559 transaction (hex, a
txpool spool entry) from that key: a plain transfer, or with --withdraw-to an
outbox initiateWithdrawal(l1Recipient) carrying --sats (the L1 recipient is
the native owner script hash, SHA3-256 of the hybrid public key). The key
FILE is a development hot key: never use it for value.
--rules mainnet selects ChainSpec::mainnet_v1 switching to ChainSpec::mainnet (chain
id 700770) with the ceremony's --domain and wall-clock --genesis-time, and requires
extend/reconstruct to use a --timestamp-rule from L2 block 1 (wall-clock time from
genesis). Which rules a block runs: reconstruct reads each settlement's configuration
commitment; everything else derives the switch from the database, and extend switches
with --rule-set next, which the settler gives once L1 reports the next program. A
block under the next rules takes its timestamp and prevrandao from the compiled
derivation, and --rule-set base is refused after the switch. rewind removes the
head block, named by number and hash, when L1 replaced the program before it
settled; --respool writes its user transactions back to a spool directory. The default
(v3) keeps the devnet identity: ChainSpec::testnet_v3, domain d3..d3, genesis 0.
Development only: no settlement or finality is implied.
";

/// Network options accepted by every command.
const NETWORK_OPTIONS: [&str; 3] = ["--rules", "--domain", "--genesis-time"];

static NETWORK: std::sync::OnceLock<L2Network> = std::sync::OnceLock::new();

fn network() -> &'static L2Network {
    NETWORK.get_or_init(L2Network::devnet_v3)
}

/// Split the network options off the command's options and select the network.
fn select_network(rest: &[String]) -> Result<Vec<String>, String> {
    let mut kept = Vec::new();
    let mut found = std::collections::BTreeMap::new();
    for pair in rest.chunks(2) {
        if pair.len() == 2 && NETWORK_OPTIONS.contains(&pair[0].as_str()) {
            if found.insert(pair[0].clone(), pair[1].clone()).is_some() {
                return Err(format!("{} repeated", pair[0]));
            }
        } else {
            kept.extend_from_slice(pair);
        }
    }
    let rules = found.get("--rules").map_or("v3", String::as_str);
    if rules == "v2" {
        return Err("the producer writes settlement V3 blocks: --rules v3 or mainnet".into());
    }
    let selected = L2Network::parse(
        rules,
        found.get("--domain").map(String::as_str),
        found.get("--genesis-time").map(String::as_str),
    )?;
    if NETWORK.set(selected.clone()).is_err() && network() != &selected {
        return Err("network selected twice".into());
    }
    Ok(kept)
}

/// Timestamp and prevrandao of block `number`: from the derivation its rules
/// compile, or under rules without one from the configured development rule.
fn block_attributes(
    rules: &ChainSpec,
    rule: Option<&TimestampRule>,
    number: u64,
    parent_timestamp: u64,
    anchor_slot: Option<u64>,
) -> Result<(u64, B256), String> {
    if let Some(derivation) = rules.block_derivation {
        let slot = anchor_slot.ok_or("the next rules need --anchor-slot")?;
        let timestamp = derivation.timestamp(parent_timestamp, slot).ok_or("timestamp overflow")?;
        return Ok((timestamp, derivation.prevrandao));
    }
    let timestamp = next_timestamp(rule, number, parent_timestamp, anchor_slot)
        .ok_or("timestamp overflow, or --anchor-slot missing under --timestamp-rule")?;
    Ok((timestamp, B256::repeat_byte(7)))
}

/// On mainnet every block after genesis follows the wall-clock rule.
fn checked_rule(rule: Option<TimestampRule>) -> Result<Option<TimestampRule>, String> {
    if network().mainnet {
        rule.as_ref().ok_or("--rules mainnet requires --timestamp-rule 1:L1_GENESIS_UNIX_SECS:L1_SLOT_MILLIS")?
            .require_from_genesis()?;
    }
    Ok(rule)
}

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

/// `--timestamp-rule FROM:GENESIS:SLOT_MS`: L2 time follows the anchored L1 slot from
/// L2 block FROM on (see `timestamp.rs`); absent, every block is `parent + 1`.
fn timestamp_rule(args: &[String]) -> Result<Option<TimestampRule>, String> {
    option(args, "--timestamp-rule").ok().map(TimestampRule::parse).transpose()
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

/// The selected execution rules: by default the settlement V3 rules (testnet
/// parameters plus the withdrawal outbox; the `settlement_v3` guest compiles
/// the same `ChainSpec`), or `ChainSpec::mainnet` with `--rules mainnet`.
fn rules() -> ChainSpec {
    network().rules.clone()
}

fn outbox() -> Address {
    rules().withdrawal_outbox.expect("settlement V3 rules have the withdrawal outbox")
}

fn spec() -> Result<Arc<BlochChainSpec>, String> {
    network().chain_spec().map(Arc::new).map_err(|e| e.to_string())
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
    let factory = ProviderFactory::new(
        Arc::new(db),
        spec()?,
        StaticFileProvider::read_write(path.join("static")).map_err(|e| e.to_string())?,
        RocksDBBuilder::new(path.join("rocks")).with_default_tables().build().map_err(|e| e.to_string())?,
        runtime.clone(),
    )
    .map_err(|e| e.to_string())?;
    if !create {
        // A database opens only under the network (rules, domain, genesis) it was created for.
        let sealed = <BlochProviderFactory as HeaderProvider>::sealed_header(&factory, 0).map_err(|e| e.to_string())?.ok_or("target has no genesis header")?;
        let genesis: &bloch_reth_execution::BlochNodeHeader = sealed.header();
        let selected = network();
        if (genesis.0.chain_id, genesis.0.domain, genesis.0.timestamp)
            != (selected.rules.chain_id, selected.domain, selected.genesis_timestamp)
        {
            return Err(format!(
                "target was created for chain id {} domain {} genesis time {}, not the selected network (--rules)",
                genesis.0.chain_id,
                hex::encode(genesis.0.domain),
                genesis.0.timestamp
            ));
        }
    }
    if !create {
        factory.chain_spec().rules().discover(&factory).map_err(|e| e.to_string())?;
    }
    Ok(factory)
}

/// The name a report gives the rules of block `number`.
fn rule_set_name(factory: &BlochProviderFactory, number: u64) -> &'static str {
    if factory.chain_spec().rules().is_next(number) { "next" } else { "base" }
}

fn run(args: &[String]) -> Result<String, String> {
    let (command, rest) = args.split_first().ok_or("missing command")?;
    let rest = &select_network(rest)?[..];
    match command.as_str() {
        "address" => {
            only(rest, &["--key"])?;
            return Ok(json!({"address": format!("{:x}", key_address(&read_key(option(rest, "--key")?)?)) }).to_string());
        }
        "sign-tx" => return sign_tx(rest),
        _ => {}
    }
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
        "extend" | "select" => {
            let selecting = command == "select";
            let allowed: &[&str] = &[
                "--target", "--parent", "--anchor", "--anchor-slot", "--timestamp-rule", "--deposits", "--txs",
                "--max-gas", "--max-bytes", "--max-txs", "--min-tip-wei", "--rule-set", "--forced",
                "--fresh-slot-price-wei", "--write-exempt",
            ];
            if selecting && rest.iter().any(|a| a == "--max-txs") {
                // Sequencer policy v2: the policy applies its own count to its own try order.
                return Err("select runs without the per-block transaction cap: --max-txs is not accepted".into());
            }
            only(rest, allowed)?;
            // CANDIDATE (forced inclusion): the records L1 names for this block's settlement.
            let forced = match rest.chunks(2).find(|p| p[0] == "--forced") {
                Some(pair) => read_forced(Path::new(&pair[1]))?,
                None => vec![],
            };
            let deposits = match rest.chunks(2).find(|p| p[0] == "--deposits") {
                Some(pair) => read_deposits(Path::new(&pair[1]))?,
                None => vec![],
            };
            let parent = hash(option(rest, "--parent")?, "--parent")?;
            let anchor = hash(option(rest, "--anchor")?, "--anchor")?;
            let factory = open(&target, &runtime, false)?;
            let schedule = factory.chain_spec().rules().clone();
            let mut coordinator = CanonicalCoordinator::attach(factory).map_err(|e| e.to_string())?;
            let head = coordinator.head().clone();
            if head.hash() != parent {
                return Err(format!(
                    "canonical head {} is not the expected parent {}",
                    hex::encode(head.hash()),
                    hex::encode(parent)
                ));
            }
            let rule = checked_rule(timestamp_rule(rest)?)?;
            let anchor_slot = match option(rest, "--anchor-slot") {
                Ok(value) => Some(value.parse::<u64>().map_err(|_| "--anchor-slot must be decimal")?),
                Err(_) => None,
            };
            let number = head.0.number + 1;
            match option(rest, "--rule-set") {
                Ok("next") if !schedule.is_next(number) => schedule.switch_at(number).map_err(|e| e.to_string())?,
                Ok("next") | Err(_) => {}
                Ok("base") if schedule.is_next(number) => {
                    return Err(format!("block {number} is past the switch to the next rules"));
                }
                Ok("base") => {}
                Ok(other) => return Err(format!("--rule-set must be base or next, not {other}")),
            }
            let (timestamp, prevrandao) = block_attributes(schedule.at(number), rule.as_ref(), number, head.0.timestamp, anchor_slot)?;
            let attributes = BlochNextBlockEnvCtx {
                timestamp,
                prevrandao,
                anchor_root: anchor,
                deposits: deposits.clone(),
            };
            let pool = match rest.chunks(2).find(|p| p[0] == "--txs") {
                Some(pair) => Some(read_pool(Path::new(&pair[1]))?),
                None => {
                    if rest.chunks(2).any(|p| p[0].starts_with("--max-")) {
                        return Err("--max-gas/--max-bytes/--max-txs require --txs".into());
                    }
                    if rest.chunks(2).any(|p| p[0] == "--fresh-slot-price-wei" || p[0] == "--write-exempt") {
                        return Err("--fresh-slot-price-wei/--write-exempt require --txs".into());
                    }
                    None
                }
            };
            let Some(pool) = pool else {
                if command == "select" {
                    return Err("select needs --txs".into());
                }
                if !forced.is_empty() {
                    // Deposits and forced envelopes only.
                    let (selection, _) = coordinator
                        .select_pending_after_forced(&attributes, &forced, &[], SelectionLimits::protocol(&rules()))
                        .map_err(|e| e.to_string())?;
                    let tip = coordinator.extend_raw(parent, attributes, &selection.included).map_err(|e| e.to_string())?;
                    write_forced_sidecar(&target, tip.0.number, &forced, selection.included.len())?;
                    let mut out = json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                              "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                              "anchor": hex::encode(anchor), "timestamp": timestamp, "deposits": deposits.len(),
                              "transactions": selection.included.len(), "user_transactions": 0,
                              "forced": forced_report(&forced, &selection),
                              "rules": if schedule.is_next(number) { "next" } else { "base" }});
                    report_withdrawals(&mut out, &coordinator.provider(), tip.0.number, tip.hash())?;
                    return Ok(out.to_string());
                }
                let tip = coordinator.extend(parent, attributes, vec![]).map_err(|e| e.to_string())?;
                let mut out = json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                          "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                          "anchor": hex::encode(anchor), "timestamp": timestamp, "deposits": deposits.len(),
                          "transactions": 0, "rules": if schedule.is_next(number) { "next" } else { "base" }});
                report_withdrawals(&mut out, &coordinator.provider(), tip.0.number, tip.hash())?;
                return Ok(out.to_string());
            };
            let limits = limits(rest, SelectionLimits::protocol(&rules()))?;
            // Policy of this producer, not a block rule: replay never reads the pool.
            let min_tip = match option(rest, "--min-tip-wei") {
                Ok(text) => text.parse::<u128>().map_err(|_| "--min-tip-wei must be decimal")?,
                Err(_) => 0,
            };
            let next_base_fee = u128::from(rules().next_base_fee(head.0.base_fee_per_gas, head.0.gas_used));
            let (pool, below_min_tip) = hold_below_min_tip(&rules(), pool, next_base_fee, min_tip);
            // Policy of this producer, not a block rule: a transaction that does not pay the write price for
            // the storage slots it adds is left pending, so no block of this producer creates an unpaid slot.
            let price = write_price(rest)?;
            let (pool, unpaid) = match &price {
                Some(price) => leave_unpaid(&coordinator, &attributes, &forced, pool, limits, price)?,
                None => (pool, UnpaidReport::default()),
            };
            let candidates: Vec<_> = pool.iter().map(|(_, raw)| raw.clone()).collect();
            if !forced.is_empty() {
                let (forced_selection, selection) = coordinator
                    .select_pending_after_forced(&attributes, &forced, &candidates, limits)
                    .map_err(|e| e.to_string())?;
                if command == "select" {
                    let mut out = selection_report(&selection, below_min_tip);
                    out["forced"] = forced_report(&forced, &forced_selection);
                    out["committed"] = json!(false);
                    unpaid.report(&mut out, &price);
                    return Ok(out.to_string());
                }
                let body: Vec<_> = forced_selection.included.iter().chain(selection.transactions.iter()).cloned().collect();
                let tip = coordinator.extend_raw(parent, attributes, &body).map_err(|e| e.to_string())?;
                write_forced_sidecar(&target, tip.0.number, &forced, forced_selection.included.len())?;
                let pruned = prune_spool(&pool, &candidates, &selection)?;
                let mut out = json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                          "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                          "anchor": hex::encode(anchor), "timestamp": timestamp, "deposits": deposits.len(),
                          "rules": if schedule.is_next(number) { "next" } else { "base" },
                          "transactions": body.len(), "user_transactions": selection.transactions.len(),
                          "forced": forced_report(&forced, &forced_selection),
                          "declared_gas": selection.declared_gas, "bytes": selection.bytes,
                          "limits": {"max_gas": limits.max_gas, "max_bytes": limits.max_bytes,
                                     "max_txs": limits.max_transactions},
                          "pruned": pruned});
                if let (Some(fields), serde_json::Value::Object(report)) = (out.as_object_mut(), selection_report(&selection, below_min_tip)) {
                    fields.extend(report);
                }
                unpaid.report(&mut out, &price);
                report_withdrawals(&mut out, &coordinator.provider(), tip.0.number, tip.hash())?;
                return Ok(out.to_string());
            }
            if command == "select" {
                // What `extend` would select, per transaction: nothing is committed or pruned.
                let selection = coordinator.select_pending(&attributes, &candidates, limits).map_err(|e| e.to_string())?;
                let mut report = selection_report(&selection, below_min_tip);
                report["committed"] = json!(false);
                unpaid.report(&mut report, &price);
                return Ok(report.to_string());
            }
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
                    // The settled RPC may have evicted it meanwhile: gone is pruned.
                    match fs::remove_file(file) {
                        Ok(()) => pruned += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("prune {}: {e}", file.display())),
                    }
                }
            }
            let mut out = json!({"number": tip.0.number, "hash": hex::encode(tip.hash()),
                      "state_root": hex::encode(tip.0.state_root), "parent": hex::encode(parent),
                      "anchor": hex::encode(anchor), "timestamp": timestamp, "deposits": deposits.len(),
                      "rules": if schedule.is_next(number) { "next" } else { "base" },
                      "transactions": selection.transactions.len(),
                      "declared_gas": selection.declared_gas, "bytes": selection.bytes,
                      "limits": {"max_gas": limits.max_gas, "max_bytes": limits.max_bytes,
                                 "max_txs": limits.max_transactions},
                      "pruned": pruned});
            extend_report(&mut out, &selection, below_min_tip);
            unpaid.report(&mut out, &price);
            report_withdrawals(&mut out, &coordinator.provider(), tip.0.number, tip.hash())?;
            Ok(out.to_string())
        }
        "rewind" => {
            only(rest, &["--target", "--number", "--hash", "--respool"])?;
            let number: u64 = option(rest, "--number")?.parse().map_err(|_| "--number must be decimal")?;
            let expected = hash(option(rest, "--hash")?, "--hash")?;
            let factory = open(&target, &runtime, false)?;
            let head = factory.best_block_number().map_err(|e| e.to_string())?;
            if head != number {
                return Err(format!("the head is block {head}, not {number}"));
            }
            let block = factory.block_by_number(number).map_err(|e| e.to_string())?.ok_or("head block is missing")?;
            let mut respooled = 0usize;
            if let Ok(directory) = option(rest, "--respool") {
                for raw in block.body.as_core().transactions.iter() {
                    let name = format!("{}.tx", hex::encode(alloy_primitives::keccak256(raw)));
                    let path = Path::new(directory).join(&name);
                    if path.exists() {
                        continue;
                    }
                    let temporary = Path::new(directory).join(format!(".{name}.rewind"));
                    fs::write(&temporary, format!("{}\n", hex::encode(raw))).map_err(|e| format!("--respool: {e}"))?;
                    fs::rename(&temporary, &path).map_err(|e| format!("--respool: {e}"))?;
                    respooled += 1;
                }
            }
            let parent = rewind_canonical_head(&factory, expected).map_err(|e| e.to_string())?;
            match fs::remove_file(forced_sidecar(&target, number)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("forced sidecar: {e}")),
            }
            factory.chain_spec().rules().discover(&factory).map_err(|e| e.to_string())?;
            Ok(json!({"number": parent.0.number, "hash": hex::encode(parent.hash()),
                      "state_root": hex::encode(parent.0.state_root), "rewound": number,
                      "rewound_hash": hex::encode(expected), "respooled": respooled}).to_string())
        }
        "export" => {
            only(rest, &["--target", "--number", "--out", "--witness"])?;
            let sparse = match option(rest, "--witness") {
                Err(_) => false,
                Ok("complete") => false,
                Ok("sparse") => true,
                Ok(other) => return Err(format!("--witness must be complete or sparse, not {other}")),
            };
            let number: u64 = option(rest, "--number")?.parse().map_err(|_| "--number must be decimal")?;
            let out = PathBuf::from(option(rest, "--out")?);
            let factory = open(&target, &runtime, false)?;
            // CANDIDATE: `--witness sparse` writes the artifact of the sparse-witness guest.
            let forced = read_forced_sidecar(&target, number)?.map(|(forced, _)| forced).unwrap_or_default();
            let (bytes, hash, anchor, state_entries) = if sparse {
                let (artifact, state_entries) =
                    export_sparse_forced_with_report(&factory, number, &forced).map_err(|e| e.to_string())?;
                (artifact.encode().map_err(|e| e.to_string())?, artifact.header().hash(), artifact.context().anchor_root, state_entries)
            } else {
                // CANDIDATE: a block that consumed forced records exports the complete artifact of the
                // fallback guest, which carries them.
                let report = if forced.is_empty() {
                    export_with_report(&factory, number)
                } else {
                    export_forced_with_report(&factory, number, &forced)
                }
                .map_err(|e| e.to_string())?;
                let artifact = report.artifact;
                (artifact.encode().map_err(|e| e.to_string())?, artifact.header().hash(), artifact.context().anchor_root, report.state_entries)
            };
            let mut file = OpenOptions::new().write(true).create_new(true).open(&out).map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            File::open(out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))
                .and_then(|d| d.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(json!({"number": number, "hash": hex::encode(hash),
                      "anchor": hex::encode(anchor), "bytes": bytes.len(),
                      "state_entries": state_entries, "sparse": sparse})
            .to_string())
        }
        "hash" => {
            only(rest, &["--target", "--number"])?;
            let number: u64 = option(rest, "--number")?.parse().map_err(|_| "--number must be decimal")?;
            let factory = open(&target, &runtime, false)?;
            let header = <BlochProviderFactory as HeaderProvider>::sealed_header(&factory, number)
                .map_err(|e| e.to_string())?
                .ok_or("no such block")?;
            Ok(json!({"number": number, "hash": hex::encode(header.hash())}).to_string())
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
            // Forced envelopes are already on L1: the batch carries the sequencer's part only.
            let included = read_forced_sidecar(&target, number)?.map_or(0, |(_, included)| included);
            let transactions = block
                .body
                .as_core()
                .transactions
                .get(included..)
                .ok_or_else(|| format!("block {number} is shorter than its forced prefix"))?;
            if transactions.is_empty() {
                return Err(format!("block {number} has no user transactions: nothing to publish"));
            }
            let payload = encode_da_payload(transactions).map_err(|e| e.to_string())?;
            let chain_id = rules().chain_id;
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
            only(rest, &["--target", "--l1", "--l1-follower", "--chain-id", "--timestamp-rule"])?;
            let rule = checked_rule(timestamp_rule(rest)?)?;
            let blocks = match (option(rest, "--l1"), option(rest, "--l1-follower")) {
                (Ok(file), Err(_)) => read_l1_fixture(Path::new(file))?,
                (Err(_), Ok(dir)) => read_l1_follower(Path::new(dir))?,
                _ => return Err("exactly one of --l1 or --l1-follower is required".into()),
            };
            let chain_id = match option(rest, "--chain-id") {
                Ok(value) => value.parse().map_err(|_| "--chain-id must be decimal")?,
                Err(_) => rules().chain_id,
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
            let schedule = factory.chain_spec().rules().clone();
            let configurations = match schedule.next() {
                Some(next) => Some((
                    configuration_commitment(schedule.base()).map_err(|e| e.to_string())?,
                    configuration_commitment(next).map_err(|e| e.to_string())?,
                )),
                None => None,
            };
            let mut coordinator = CanonicalCoordinator::attach(factory).map_err(|e| e.to_string())?;
            let mut report = Vec::new();
            for block in &settled {
                let head = coordinator.head().clone();
                if head.hash() != block.parent_hash || head.0.state_root != block.previous_state_root {
                    return Err(format!("L2 block {}: rebuilt parent differs from the settled parent", block.number));
                }
                // The statement names the rules: L1 compared this field with its policy.
                if let Some((base, next)) = configurations {
                    if block.configuration == next {
                        if !schedule.is_next(block.number) {
                            schedule.switch_at(block.number).map_err(|e| e.to_string())?;
                        }
                    } else if block.configuration != base || schedule.is_next(block.number) {
                        return Err(format!("L2 block {}: settled under an unexpected configuration {}", block.number, hex::encode(block.configuration)));
                    }
                }
                let (timestamp, prevrandao) = block_attributes(schedule.at(block.number), rule.as_ref(), block.number, head.0.timestamp, Some(block.anchor_slot))?;
                let attributes = BlochNextBlockEnvCtx {
                    timestamp,
                    prevrandao,
                    anchor_root: block.anchor,
                    deposits: block.deposits.clone(),
                };
                // Forced inclusion: the consumed records run first, by the same rule as the producer and the guest.
                let mut body = Vec::new();
                if !block.forced.is_empty() {
                    let (selection, _) = coordinator
                        .select_pending_after_forced(&attributes, &block.forced, &[], SelectionLimits::protocol(&rules()))
                        .map_err(|e| format!("L2 block {}: forced: {e}", block.number))?;
                    body.extend(selection.included);
                }
                let forced_included = body.len();
                body.extend(block.transactions.iter().cloned());
                let tip = coordinator
                    .extend_raw(head.hash(), attributes, &body)
                    .map_err(|e| format!("L2 block {}: {e}", block.number))?;
                if !block.forced.is_empty() {
                    write_forced_sidecar(&target, tip.0.number, &block.forced, forced_included)?;
                }
                let withdrawals = outbox_commitment(
                    coordinator.provider().history_by_block_hash(tip.hash()).map_err(|e| e.to_string())?.as_ref(),
                )?;
                if block.withdrawals.is_some_and(|settled| settled != withdrawals) {
                    return Err(format!(
                        "L2 block {}: rebuilt withdrawal root {} / count {} differ from settled",
                        block.number,
                        hex::encode(withdrawals.root),
                        withdrawals.count
                    ));
                }
                let mismatch = tip.hash() != block.header_hash
                    || tip.0.state_root != block.state_root
                    || block.transactions_root.is_some_and(|root| root != tip.0.transactions_root)
                    || (block.forced.is_empty() && block.deposits_hash.is_some_and(|hash| hash != tip.0.deposits_hash));
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
                                   "rules": if schedule.is_next(block.number) { "next" } else { "base" },
                                   "deposits": block.deposits.len(), "transactions": block.transactions.len(),
                                   "forced": block.forced.len(), "forced_included": forced_included,
                                   "da_commitment": hex::encode(block.da_commitment),
                                   "withdrawal_root": hex::encode(withdrawals.root),
                                   "withdrawal_count": withdrawals.count}));
            }
            Ok(json!({"genesis": hex::encode(genesis_header.hash()), "native_blocks": blocks.len(),
                      "settled": report.len(), "head": report.last().map(|b| b["hash"].clone()),
                      "next_rules_from": schedule.next_from(), "blocks": report})
            .to_string())
        }
        "head" => {
            only(rest, &["--target"])?;
            let factory = open(&target, &runtime, false)?;
            let number = factory.best_block_number().map_err(|e| e.to_string())?;
            let header = factory.sealed_header(number).map_err(|e| e.to_string())?.ok_or("missing head header")?;
            let withdrawals = outbox_commitment(factory.latest().map_err(|e| e.to_string())?.as_ref())?;
            Ok(json!({"number": number, "hash": hex::encode(header.hash()),
                      "state_root": hex::encode(header.0.state_root),
                      "rules": rule_set_name(&factory, number),
                      "next_rules_from": factory.chain_spec().rules().next_from(),
                      "withdrawal_root": hex::encode(withdrawals.root), "withdrawal_count": withdrawals.count})
            .to_string())
        }
        "withdrawal-proof" => {
            only(rest, &["--target", "--index", "--number", "--root", "--count"])?;
            let index: u64 = option(rest, "--index")?.parse().map_err(|_| "--index must be decimal")?;
            let factory = open(&target, &runtime, false)?;
            let head = factory.best_block_number().map_err(|e| e.to_string())?;
            let number = match option(rest, "--number") {
                Ok(value) => value.parse().map_err(|_| "--number must be decimal")?,
                Err(_) => head,
            };
            if number > head {
                return Err(format!("no block {number} (head {head})"));
            }
            withdrawal_proof(&factory, number, index, settled_commitment(rest)?)
        }
        "account" => {
            only(rest, &["--target", "--address"])?;
            let address: Address = parse_address(option(rest, "--address")?)?;
            let factory = open(&target, &runtime, false)?;
            let state = factory.latest().map_err(|e| e.to_string())?;
            let account = state.basic_account(&address).map_err(|e| e.to_string())?.unwrap_or_default();
            let (sats, dust) = account.balance.div_rem(U256::from(bloch_l2_evm::ATOM_SCALE));
            Ok(json!({"address": format!("{address:x}"), "number": factory.best_block_number().map_err(|e| e.to_string())?,
                      "balance_wei": account.balance.to_string(), "balance_sats": sats.to_string(),
                      "dust_wei": dust.to_string(), "nonce": account.nonce})
            .to_string())
        }
        other => Err(format!("unknown command {other}")),
    })();
    if !runtime.graceful_shutdown_with_timeout(Duration::from_secs(10)) {
        return Err("task runtime did not shut down".into());
    }
    result
}

fn parse_address(text: &str) -> Result<Address, String> {
    let bytes = hex::decode(text.trim_start_matches("0x")).map_err(|_| "address must be hex")?;
    if bytes.len() != 20 {
        return Err("address must be 20 bytes".into());
    }
    Ok(Address::from_slice(&bytes))
}

/// Development secp256k1 key: one line of 64 hex characters, owner-only file.
fn read_key(path: &str) -> Result<k256::ecdsa::SigningKey, String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("--key: {e}"))?;
    if !metadata.is_file() || metadata.len() > 200 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("--key must be a regular file readable by its owner only".into());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("--key: {e}"))?;
    let bytes = hex::decode(text.trim().trim_start_matches("0x")).map_err(|_| "--key must be hex")?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| "--key must be 32 bytes")?;
    k256::ecdsa::SigningKey::from_bytes((&bytes).into()).map_err(|_| "--key is not a secp256k1 scalar".into())
}

fn key_address(key: &k256::ecdsa::SigningKey) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&alloy_primitives::keccak256(&point.as_bytes()[1..])[12..])
}

fn sign_tx(rest: &[String]) -> Result<String, String> {
    use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
    only(rest, &["--key", "--nonce", "--to", "--value-wei", "--withdraw-to", "--sats", "--gas", "--max-fee-wei", "--out"])?;
    let key = read_key(option(rest, "--key")?)?;
    let decimal = |name: &str| -> Result<u128, String> {
        option(rest, name)?.parse().map_err(|_| format!("{name} must be decimal"))
    };
    let nonce = u64::try_from(decimal("--nonce")?).map_err(|_| "--nonce too large")?;
    let (to, value, input, default_gas) = match (option(rest, "--to"), option(rest, "--withdraw-to")) {
        (Ok(to), Err(_)) => {
            if option(rest, "--sats").is_ok() {
                return Err("--sats goes with --withdraw-to".into());
            }
            (parse_address(to)?, U256::from(decimal("--value-wei")?), Vec::new(), 21_000)
        }
        (Err(_), Ok(recipient)) => {
            if option(rest, "--value-wei").is_ok() {
                return Err("--value-wei goes with --to".into());
            }
            let recipient = hash(recipient, "--withdraw-to")?;
            let sats = u64::try_from(decimal("--sats")?).map_err(|_| "--sats too large")?;
            if sats < bloch_l2_evm::withdrawal::MIN_WITHDRAWAL_SATS {
                return Err("--sats is below the minimum withdrawal (the outbox would revert)".into());
            }
            let mut data = bloch_l2_evm::withdrawal::INITIATE_WITHDRAWAL_SELECTOR.to_vec();
            data.extend_from_slice(recipient.as_slice());
            (outbox(), bloch_l2_evm::sats_to_wei(sats), data, 100_000)
        }
        _ => return Err("give exactly one of --to or --withdraw-to".into()),
    };
    let gas_limit = match option(rest, "--gas") {
        Ok(_) => u64::try_from(decimal("--gas")?).map_err(|_| "--gas too large")?,
        Err(_) => default_gas,
    };
    let max_fee_per_gas = match option(rest, "--max-fee-wei") {
        Ok(_) => decimal("--max-fee-wei")?,
        Err(_) => 2_000_000_000,
    };
    let tx = TxEip1559 {
        chain_id: rules().chain_id,
        nonce,
        to: alloy_primitives::TxKind::Call(to),
        value,
        input: input.into(),
        gas_limit,
        max_fee_per_gas,
        // The settled RPC's default minimum; set a lower --max-fee-wei only with care.
        max_priority_fee_per_gas: 100_000_000u128.min(max_fee_per_gas),
        ..Default::default()
    };
    let signature: alloy_primitives::Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .map_err(|e| e.to_string())?
        .into();
    let signed = tx.into_signed(signature);
    let hash = *signed.hash();
    let encoded = TxEnvelope::from(signed).encoded_2718();
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(option(rest, "--out")?)
        .map_err(|e| format!("--out: {e}"))?;
    writeln!(out, "{}", hex::encode(&encoded)).map_err(|e| format!("--out: {e}"))?;
    Ok(json!({"hash": hex::encode(hash), "from": format!("{:x}", key_address(&key)), "nonce": nonce,
              "to": format!("{to:x}"), "value_wei": value.to_string(), "gas_limit": gas_limit, "bytes": encoded.len()})
    .to_string())
}

/// The selection part of the extend and select reports. `tx_stats` is a report only: no block rule reads it.
fn extend_report(
    out: &mut serde_json::Value,
    selection: &bloch_l2_evm::node_execution::select::BlockSelection,
    below_min_tip: usize,
) {
    let slots = |items: &[(Address, u64)]| items.iter().map(|(a, n)| json!([hex::encode(a), n])).collect::<Vec<_>>();
    out["included"] = json!(selection.hashes.iter().map(hex::encode).collect::<Vec<_>>());
    out["deferred"] = json!(selection
        .deferred
        .iter()
        .map(|d| json!({"hash": hex::encode(d.hash), "reason": d.reason.as_str()}))
        .collect::<Vec<_>>());
    out["dropped"] = json!(selection
        .dropped
        .iter()
        .map(|d| json!({"index": d.index, "hash": d.hash.map(hex::encode), "reason": d.reason.describe()}))
        .collect::<Vec<_>>());
    out["below_min_tip"] = json!(below_min_tip);
    out["tx_stats"] = json!(selection
        .stats
        .iter()
        .map(|t| json!({"hash": hex::encode(t.hash), "sender": hex::encode(t.sender), "nonce": t.nonce,
                        "gas_used": t.gas_used, "effective_tip": t.effective_tip.to_string(),
                        "fresh_slots": slots(&t.fresh_slots), "cleared_slots": slots(&t.cleared_slots)}))
        .collect::<Vec<_>>());
}

/// Native inbox records as L2 deposit mints. The native settlement rejects any
/// body that does not mint exactly these records, so no field is defaulted.
fn selection_report(selection: &bloch_l2_evm::node_execution::select::BlockSelection, below_min_tip: usize) -> serde_json::Value {
    let mut report = json!({});
    extend_report(&mut report, selection, below_min_tip);
    report
}

/// CANDIDATE (forced inclusion): the due records as `getl2settlement.forced.due` lists them, each with its
/// envelope: `[{"height", "l1_txid", "envelope_hash", "gas_limit", "envelope"}]`, hex with or without 0x.
/// The forced rule checks each envelope against its hash and the list against the per-settlement bounds.
fn read_forced(path: &Path) -> Result<Vec<ForcedTransaction>, String> {
    let bytes = fs::read(path).map_err(|e| format!("forced: {e}"))?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&bytes).map_err(|e| format!("forced: {e}"))?;
    forced_from_json(&list)
}

fn forced_from_json(list: &[serde_json::Value]) -> Result<Vec<ForcedTransaction>, String> {
    let num = |v: &serde_json::Value, k: &str| v[k].as_u64().ok_or_else(|| format!("forced field {k} must be an integer"));
    let bytes_of = |v: &serde_json::Value, k: &str| -> Result<Vec<u8>, String> {
        hex::decode(v[k].as_str().unwrap_or_default().trim_start_matches("0x")).map_err(|_| format!("forced field {k} must be hex"))
    };
    let fixed = |v: &serde_json::Value, k: &str| -> Result<[u8; 32], String> {
        bytes_of(v, k)?.try_into().map_err(|_| format!("forced field {k} must be 32 bytes"))
    };
    list.iter()
        .map(|v| {
            Ok(ForcedTransaction {
                record: ForcedRecord {
                    l1_height: num(v, "height")?,
                    l1_txid: fixed(v, "l1_txid")?,
                    envelope_hash: B256::from(fixed(v, "envelope_hash")?),
                    gas_limit: num(v, "gas_limit")?,
                },
                envelope: bytes_of(v, "envelope")?.into(),
            })
        })
        .collect()
}

fn forced_json(forced: &[ForcedTransaction]) -> serde_json::Value {
    json!(forced
        .iter()
        .map(|f| json!({"height": f.record.l1_height, "l1_txid": hex::encode(f.record.l1_txid),
                        "envelope_hash": hex::encode(f.record.envelope_hash), "gas_limit": f.record.gas_limit,
                        "envelope": hex::encode(&f.envelope)}))
        .collect::<Vec<_>>())
}

fn forced_report(forced: &[ForcedTransaction], selection: &ForcedSelection) -> serde_json::Value {
    json!({"due": forced.len(), "included": selection.included.len(),
           "hashes": selection.included.iter().map(|raw| hex::encode(alloy_primitives::keccak256(raw))).collect::<Vec<_>>(),
           "skipped": selection.skipped.iter().map(|(index, reason)| json!([index, format!("{reason:?}")])).collect::<Vec<_>>(),
           "due_hash": hex::encode(bloch_l2_evm::forced_inclusion::forced_hash(
               &forced.iter().map(|f| f.record).collect::<Vec<_>>()))})
}

/// The forced records block `number` consumed and how many of its first transactions they are. Kept beside the
/// database (candidate tooling): `export` puts the records in the sparse witness and `da` leaves the prefix out.
fn forced_sidecar(target: &Path, number: u64) -> PathBuf {
    target.join("forced").join(format!("{number:08}.json"))
}

fn write_forced_sidecar(target: &Path, number: u64, forced: &[ForcedTransaction], included: usize) -> Result<(), String> {
    let path = forced_sidecar(target, number);
    fs::create_dir_all(path.parent().expect("sidecar has a parent")).map_err(|e| format!("forced sidecar: {e}"))?;
    let temporary = path.with_extension("json.tmp");
    let text = json!({"number": number, "included": included, "forced": forced_json(forced)}).to_string();
    let mut file = File::create(&temporary).map_err(|e| format!("forced sidecar: {e}"))?;
    file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| format!("forced sidecar: {e}"))?;
    fs::rename(&temporary, &path).map_err(|e| format!("forced sidecar: {e}"))
}

fn read_forced_sidecar(target: &Path, number: u64) -> Result<Option<(Vec<ForcedTransaction>, usize)>, String> {
    let bytes = match fs::read(forced_sidecar(target, number)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("forced sidecar: {e}")),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| format!("forced sidecar: {e}"))?;
    let list = value["forced"].as_array().ok_or("forced sidecar: no list")?;
    let included = value["included"].as_u64().ok_or("forced sidecar: no count")? as usize;
    Ok(Some((forced_from_json(list)?, included)))
}

/// Remove the spool files of included and dropped candidates.
fn prune_spool(
    pool: &[(Option<PathBuf>, alloy_primitives::Bytes)],
    candidates: &[alloy_primitives::Bytes],
    selection: &bloch_l2_evm::node_execution::select::BlockSelection,
) -> Result<usize, String> {
    let mut pruned = 0usize;
    let finished = selection
        .dropped
        .iter()
        .map(|d| d.index)
        .chain(selection.hashes.iter().filter_map(|h| candidates.iter().position(|raw| alloy_primitives::keccak256(raw) == *h)));
    for index in finished {
        if let Some(file) = &pool[index].0 {
            match fs::remove_file(file) {
                Ok(()) => pruned += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("prune {}: {e}", file.display())),
            }
        }
    }
    Ok(pruned)
}

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

/// Set aside entries whose effective tip at `next_base_fee` is below `min_tip`: they stay in the
/// spool, not selected and not pruned, until the fee allows them or the settled RPC evicts them.
/// Undecodable bytes pass through, for selection to drop them with a reason.
/// The producer's write price (sequencer policy v2): wei per added storage slot, and the senders exempt from it.
struct WritePrice {
    per_slot: u128,
    exempt: Vec<Address>,
}

fn write_price(args: &[String]) -> Result<Option<WritePrice>, String> {
    let exempt = match option(args, "--write-exempt") {
        Ok(text) => text
            .split(',')
            .filter(|a| !a.is_empty())
            .map(|a| a.trim_start_matches("0x").parse::<Address>().map_err(|_| format!("--write-exempt: {a} is not an address")))
            .collect::<Result<Vec<_>, _>>()?,
        Err(_) => vec![],
    };
    match option(args, "--fresh-slot-price-wei") {
        Ok(text) => {
            let per_slot = text.parse::<u128>().map_err(|_| "--fresh-slot-price-wei must be decimal")?;
            Ok((per_slot > 0).then_some(WritePrice { per_slot, exempt }))
        }
        Err(_) if exempt.is_empty() => Ok(None),
        Err(_) => Err("--write-exempt needs --fresh-slot-price-wei".into()),
    }
}

/// What [`leave_unpaid`] took out of the candidates.
#[derive(Default)]
struct UnpaidReport {
    entries: Vec<serde_json::Value>,
    not_judged: Vec<String>,
    passes: usize,
    capped: bool,
}

impl UnpaidReport {
    fn report(&self, out: &mut serde_json::Value, price: &Option<WritePrice>) {
        if let Some(price) = price {
            out["unpaid"] = json!(self.entries);
            out["not_judged"] = json!(self.not_judged);
            out["write_price"] = json!({"fresh_slot_price_wei": price.per_slot.to_string(), "passes": self.passes,
                                        "max_passes": WRITE_PRICE_MAX_PASSES, "capped": self.capped});
        }
    }
}

/// Hard cap on the selections one `select` or `extend` runs for the write price (review R308-2P-13). Each pass is
/// one selection over the whole pool, so the work of a call is at most this many selections whatever the pool holds.
const WRITE_PRICE_MAX_PASSES: usize = 8;

/// Take out of `pool` every candidate that would be included without paying the write price.
/// The slots a transaction adds depend on the transactions before it, so the selection runs on the candidates,
/// the FIRST unpaid transaction in block order leaves, and the selection runs again: every transaction is then
/// judged after exactly the transactions it runs after in the block that is built, and a transaction is never
/// refused for what an earlier refused one did.
///
/// The passes are capped. When the last allowed pass still finds an unpaid transaction, the block keeps only the
/// transactions AHEAD of it in block order: each of them ran after exactly the transactions it will run after, so
/// its count stands and nothing unpaid is built. The unpaid one is reported, and everything behind it is reported
/// as `not_judged` and stays pending for the next block (liveness first: the prefix is served, nobody is refused
/// for a count that was not measured, and a chain of non-payers of any length costs at most the cap).
fn leave_unpaid(
    coordinator: &CanonicalCoordinator,
    attributes: &BlochNextBlockEnvCtx,
    forced: &[ForcedTransaction],
    mut pool: Vec<(Option<PathBuf>, alloy_primitives::Bytes)>,
    limits: SelectionLimits,
    price: &WritePrice,
) -> Result<(Vec<(Option<PathBuf>, alloy_primitives::Bytes)>, UnpaidReport), String> {
    let mut report = UnpaidReport::default();
    loop {
        let candidates: Vec<_> = pool.iter().map(|(_, raw)| raw.clone()).collect();
        let selection = if forced.is_empty() {
            coordinator.select_pending(attributes, &candidates, limits).map_err(|e| e.to_string())?
        } else {
            coordinator.select_pending_after_forced(attributes, forced, &candidates, limits).map_err(|e| e.to_string())?.1
        };
        report.passes += 1;
        let unpaid = selection.stats.iter().position(|stats| {
            let slots = stats.fresh_slots.iter().fold(0u64, |total, (_, n)| total.saturating_add(*n));
            slots > 0
                && !price.exempt.contains(&stats.sender)
                && U256::from(stats.gas_used) * U256::from(stats.effective_tip) < U256::from(slots) * U256::from(price.per_slot)
        });
        let Some(at) = unpaid else {
            return Ok((pool, report));
        };
        let stats = &selection.stats[at];
        let slots = stats.fresh_slots.iter().fold(0u64, |total, (_, n)| total.saturating_add(*n));
        report.entries.push(json!({"hash": hex::encode(stats.hash), "sender": hex::encode(stats.sender), "nonce": stats.nonce,
                                   "gas_used": stats.gas_used, "effective_tip": stats.effective_tip.to_string(),
                                   "fresh_slots": slots,
                                   "owed_wei": (U256::from(slots) * U256::from(price.per_slot)).to_string()}));
        if report.passes < WRITE_PRICE_MAX_PASSES {
            let leaving = stats.hash;
            pool.retain(|(_, raw)| alloy_primitives::keccak256(raw) != leaving);
            continue;
        }
        // The cap: keep the measured prefix, leave everything else pending, unjudged.
        report.capped = true;
        let prefix: Vec<B256> = selection.stats[..at].iter().map(|stats| stats.hash).collect();
        let unpaid_hash = stats.hash;
        pool.retain(|(_, raw)| {
            let hash = alloy_primitives::keccak256(raw);
            if prefix.contains(&hash) {
                return true;
            }
            if hash != unpaid_hash {
                report.not_judged.push(hex::encode(hash));
            }
            false
        });
        return Ok((pool, report));
    }
}

fn hold_below_min_tip(
    spec: &bloch_l2_evm::ChainSpec,
    pool: Vec<(Option<PathBuf>, alloy_primitives::Bytes)>,
    next_base_fee: u128,
    min_tip: u128,
) -> (Vec<(Option<PathBuf>, alloy_primitives::Bytes)>, usize) {
    if min_tip == 0 {
        return (pool, 0);
    }
    let before = pool.len();
    let kept: Vec<_> = pool
        .into_iter()
        .filter(|(_, raw)| match bloch_l2_evm::decode_signed_transaction(spec, raw) {
            Err(_) => true,
            Ok(tx) => {
                let env = tx.environment();
                let priority = env.gas_priority_fee.unwrap_or(env.gas_price);
                priority.min(env.gas_price.saturating_sub(next_base_fee)) >= min_tip
            }
        })
        .collect();
    let held = before - kept.len();
    (kept, held)
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
        let mut entries = Vec::with_capacity(files.len());
        for file in files {
            let text = match fs::read_to_string(&file) {
                Ok(text) => text,
                // Evicted by the settled RPC between listing and reading.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", file.display())),
            };
            // Undecodable text still becomes a (dropped) candidate, so the file is pruned.
            entries.push((Some(file), decode(&text).unwrap_or_default()));
        }
        entries
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
/// native genesis, `blocks/<id>.bin` holds each envelope. Heights are the L2
/// registry's count: the mainnet L2 was installed by a flag day, every other
/// network this tool selects has it at genesis.
fn read_l1_follower(dir: &Path) -> Result<Vec<NativeBlockTransactions>, String> {
    let index = fs::read_to_string(dir.join("index")).map_err(|e| format!("--l1-follower index: {e}"))?;
    let mut blocks = Vec::new();
    for line in index.lines() {
        if blocks.len() >= MAX_L1_BLOCKS {
            return Err(format!("--l1-follower holds more than {MAX_L1_BLOCKS} blocks"));
        }
        let id: B256 = line.trim().parse().map_err(|_| "corrupt follower index line")?;
        let bytes = fs::read(dir.join("blocks").join(format!("{}.bin", hex::encode(id)))).map_err(|e| e.to_string())?;
        let envelope = bloch_pos_node::codec::decode_envelope(&bytes).map_err(|_| "native envelope does not decode")?;
        if B256::from(*envelope.block_id().as_bytes()) != id {
            return Err("native envelope does not match its index id".into());
        }
        blocks.push((envelope.header.slot, envelope.body.transactions));
    }
    Ok(l2_registry_blocks(blocks, network().mainnet.then(flag_day_first_slot)))
}

/// The outbox root and count in a state (the empty tree before the outbox
/// exists or before the first withdrawal), as settlement V3 publishes them.
fn outbox_commitment(state: &dyn StateProvider) -> Result<WithdrawalCommitment, String> {
    let slot = |key: U256| -> Result<U256, String> {
        Ok(state.storage(outbox(), B256::from(key)).map_err(|e| e.to_string())?.unwrap_or_default())
    };
    let count = u64::try_from(slot(OUTBOX_NONCE_SLOT)?).map_err(|_| "outbox counter exceeds u64")?;
    let root = if count == 0 { empty_withdrawal_root() } else { B256::from(slot(OUTBOX_ROOT_SLOT)?) };
    Ok(WithdrawalCommitment { root, count })
}

/// Outbox withdrawals initiated in block `number`, from its receipts' logs.
fn block_withdrawals(provider: &impl ReceiptProvider<Receipt = bloch_reth_execution::BlochRethReceipt>, number: u64)
    -> Result<Vec<Withdrawal>, String> {
    let receipts = provider
        .receipts_by_block(number.into())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no receipts for block {number}"))?;
    receipts
        .iter()
        .flat_map(|receipt| receipt.logs.iter())
        .filter_map(|log| Withdrawal::from_log(outbox(), log))
        .map(|w| w.map_err(|e| format!("block {number}: {e}")))
        .collect()
}

fn withdrawal_json(w: &Withdrawal, block: u64) -> serde_json::Value {
    json!({"nonce": w.nonce, "l1_recipient": hex::encode(w.l1_recipient), "sats": w.sats,
           "sender": hex::encode(w.sender), "l2_block": block,
           "leaf": hex::encode(w.leaf(rules().chain_id))})
}

/// Add the post-block outbox commitment and the block's withdrawals.
fn report_withdrawals(
    out: &mut serde_json::Value,
    provider: &bloch_reth_execution::BlochBlockchainProvider,
    number: u64,
    hash: B256,
) -> Result<(), String> {
    let state = provider.history_by_block_hash(hash).map_err(|e| e.to_string())?;
    let commitment = outbox_commitment(state.as_ref())?;
    let withdrawals = block_withdrawals(provider, number)?;
    out["withdrawal_root"] = json!(hex::encode(commitment.root));
    out["withdrawal_count"] = json!(commitment.count);
    out["withdrawals"] = json!(withdrawals.iter().map(|w| withdrawal_json(w, number)).collect::<Vec<_>>());
    Ok(())
}

/// `--root HEX --count N` (both or neither): a settled commitment to check.
fn settled_commitment(args: &[String]) -> Result<Option<WithdrawalCommitment>, String> {
    match (option(args, "--root"), option(args, "--count")) {
        (Err(_), Err(_)) => Ok(None),
        (Ok(root), Ok(count)) => {
            if root.len() != 64 || !root.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err("--root must be 64 lowercase hex characters".into());
            }
            Ok(Some(WithdrawalCommitment {
                root: root.parse().map_err(|_| "--root is not a hash")?,
                count: count.parse().map_err(|_| "--count must be decimal")?,
            }))
        }
        _ => Err("--root and --count go together".into()),
    }
}

/// Rebuild the withdrawal tree of blocks 1..=number from receipts, check it
/// against the outbox state after `number` (and a settled commitment, if
/// given), and print the proof of withdrawal `index`.
fn withdrawal_proof(
    factory: &BlochProviderFactory,
    number: u64,
    index: u64,
    settled: Option<WithdrawalCommitment>,
) -> Result<String, String> {
    if number > MAX_PROOF_BLOCKS {
        return Err(format!("withdrawal-proof scans at most {MAX_PROOF_BLOCKS} blocks"));
    }
    let chain_id = rules().chain_id;
    let mut withdrawals = Vec::new();
    for height in 1..=number {
        withdrawals.extend(block_withdrawals(factory, height)?.into_iter().map(|w| (w, height)));
    }
    if withdrawals.iter().enumerate().any(|(i, (w, _))| w.nonce != i as u64) {
        return Err("outbox events are not consecutive from nonce 0".into());
    }
    let tree = WithdrawalTree::new(withdrawals.iter().map(|(w, _)| w.leaf(chain_id)).collect())
        .map_err(|e| e.to_string())?;
    let hash = factory
        .sealed_header(number)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("missing header {number}"))?
        .hash();
    let state = factory.history_by_block_hash(hash).map_err(|e| e.to_string())?;
    let stored = outbox_commitment(state.as_ref())?;
    if tree.commitment() != stored {
        return Err(format!(
            "rebuilt tree ({} / {}) differs from the outbox state after block {number} ({} / {})",
            hex::encode(tree.root()), tree.count(), hex::encode(stored.root), stored.count
        ));
    }
    if let Some(settled) = settled {
        if settled != stored {
            return Err(format!(
                "settled withdrawal root {} / count {} differ from block {number} ({} / {})",
                hex::encode(settled.root), settled.count, hex::encode(stored.root), stored.count
            ));
        }
    }
    let (withdrawal, block) = withdrawals
        .get(usize::try_from(index).map_err(|_| "--index too large")?)
        .ok_or_else(|| format!("withdrawal {index} does not exist after block {number} (count {})", stored.count))?;
    let siblings = tree.proof(index).ok_or("no proof")?;
    let leaf = withdrawal.leaf(chain_id);
    if !verify_withdrawal_proof(leaf, index, &siblings, stored.root) {
        return Err("internal error: the proof does not verify".into());
    }
    Ok(json!({"chain_id": chain_id, "number": number, "withdrawal_root": hex::encode(stored.root),
              "withdrawal_count": stored.count, "index": index,
              "withdrawal": withdrawal_json(withdrawal, *block),
              "siblings": siblings.iter().map(hex::encode).collect::<Vec<_>>()})
    .to_string())
}

/// Upper bound on blocks scanned by one withdrawal proof (receipts of every
/// block since genesis; an indexer replaces this outside development).
const MAX_PROOF_BLOCKS: u64 = 1_000_000;

/// Upper bound on native blocks read by one reconstruction: the follower's default `--max-blocks`, the most a
/// follower store holds. Mainnet L1 grows about 2,800 blocks a day.
const MAX_L1_BLOCKS: usize = 5_000_000;

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
