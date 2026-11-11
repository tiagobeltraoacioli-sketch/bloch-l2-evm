// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-l2-produce-dev extend --txs`: user transactions from a spool
//! directory, deposits first, per-block limits, overflow kept for the next
//! block, invalid entries dropped with a reason and pruned after commit.
#![cfg(unix)]

use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Signature, TxKind, U256};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use std::{path::Path, process::Command};

const BIN: &str = env!("CARGO_BIN_EXE_bloch-l2-produce-dev");

fn produce(args: &[&str]) -> Result<Value, String> {
    let out = Command::new(BIN).args(args).output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn transfer(nonce: u64) -> String {
    let tx = TxEip1559 {
        chain_id: 700_771,
        nonce,
        to: TxKind::Call(Address::repeat_byte(0x55)),
        value: U256::from(1_000u64),
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

fn spool(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn extend_with_txs_selects_within_limits_defers_overflow_and_prunes() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("db");
    let pool = root.path().join("pool");
    std::fs::create_dir(&pool).unwrap();
    let db_s = db.to_str().unwrap();
    let pool_s = pool.to_str().unwrap();
    let genesis = produce(&["init", "--target", db_s]).unwrap();
    let parent = genesis["hash"].as_str().unwrap().to_string();
    let sender = Address::from_public_key(key().verifying_key());
    let deposits = root.path().join("deposits.json");
    std::fs::write(
        &deposits,
        serde_json::json!([{"height": 3, "tx_index": 0, "txid": "11".repeat(32), "vout": 0,
                            "sats": 100_000_000u64, "recipient": hex::encode(sender)}])
        .to_string(),
    )
    .unwrap();
    for nonce in 0..3 {
        std::fs::write(pool.join(format!("a{nonce}.tx")), transfer(nonce)).unwrap();
    }
    std::fs::write(pool.join("b-garbage.tx"), "02c0").unwrap();
    std::fs::write(pool.join("ignored.txt"), "not a pool entry").unwrap();
    let anchor = "ab".repeat(32);

    // Limits need --txs.
    let err = produce(&[
        "extend",
        "--target",
        db_s,
        "--parent",
        &parent,
        "--anchor",
        &anchor,
        "--max-gas",
        "1",
    ]);
    assert!(err.unwrap_err().contains("require --txs"));
    // Limits above the protocol maxima are refused.
    let err = produce(&[
        "extend",
        "--target",
        db_s,
        "--parent",
        &parent,
        "--anchor",
        &anchor,
        "--txs",
        pool_s,
        "--max-gas",
        "30000001",
    ]);
    assert!(err.unwrap_err().contains("protocol maxima"));

    // Block 1: the deposit is minted first and funds the sender; two of the
    // three transfers fit --max-txs 2; the garbage entry is dropped.
    let block = produce(&[
        "extend",
        "--target",
        db_s,
        "--parent",
        &parent,
        "--anchor",
        &anchor,
        "--deposits",
        deposits.to_str().unwrap(),
        "--txs",
        pool_s,
        "--max-txs",
        "2",
    ])
    .unwrap();
    assert_eq!(block["number"], 1);
    assert_eq!(block["deposits"], 1);
    assert_eq!(block["transactions"], 2);
    assert_eq!(block["declared_gas"], 42_000);
    assert_eq!(block["deferred"].as_array().unwrap().len(), 1);
    assert_eq!(block["deferred"][0]["reason"], "count-limit");
    assert_eq!(block["dropped"].as_array().unwrap().len(), 1);
    assert!(block["dropped"][0]["reason"]
        .as_str()
        .unwrap()
        .starts_with("authentication"));
    assert_eq!(block["pruned"], 3);
    assert_eq!(spool(&pool), vec!["a2.tx", "ignored.txt"]);

    // Block 2: the overflow is included; the spool is drained.
    let parent2 = block["hash"].as_str().unwrap().to_string();
    let block2 = produce(&[
        "extend",
        "--target",
        db_s,
        "--parent",
        &parent2,
        "--anchor",
        &anchor,
        "--txs",
        pool_s,
        "--max-gas",
        "21000",
    ])
    .unwrap();
    assert_eq!(block2["number"], 2);
    assert_eq!(block2["transactions"], 1);
    assert_eq!(block2["pruned"], 1);
    assert_eq!(spool(&pool), vec!["ignored.txt"]);

    // A resubmitted (already included) transaction is dropped as nonce-too-low;
    // a JSON list is accepted as the pool and nothing is pruned from it.
    let list = root.path().join("list.json");
    std::fs::write(&list, serde_json::json!([transfer(0)]).to_string()).unwrap();
    let parent3 = block2["hash"].as_str().unwrap().to_string();
    let block3 = produce(&[
        "extend",
        "--target",
        db_s,
        "--parent",
        &parent3,
        "--anchor",
        &anchor,
        "--txs",
        list.to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(block3["transactions"], 0);
    assert!(block3["dropped"][0]["reason"]
        .as_str()
        .unwrap()
        .starts_with("nonce-too-low"));
    assert_eq!(block3["pruned"], 0);

    // Without --txs, a block stays deposit-only and reports no transactions.
    let parent4 = block3["hash"].as_str().unwrap().to_string();
    let block4 = produce(&["extend", "--target", db_s, "--parent", &parent4, "--anchor", &anchor]).unwrap();
    assert_eq!(block4["transactions"], 0);
    assert!(block4.get("included").is_none());

    // The exported artifact of block 1 carries the two user transactions.
    let out = root.path().join("block1.artifact");
    let info = produce(&[
        "export",
        "--target",
        db_s,
        "--number",
        "1",
        "--out",
        out.to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(info["hash"], block["hash"]);
    let head = produce(&["head", "--target", db_s]).unwrap();
    assert_eq!(head["number"], 4);
}

/// `address`, `sign-tx` and `account`: the development key funds itself by a
/// deposit, then a transfer and an outbox withdrawal signed by the tool are
/// selected from the spool and leave one withdrawal leaf; the tool refuses a
/// group-readable key and a withdrawal the outbox would revert.
#[test]
fn sign_tx_transfers_and_withdraws_from_a_development_key() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("db");
    let pool = root.path().join("pool");
    std::fs::create_dir(&pool).unwrap();
    let (db_s, pool_s) = (db.to_str().unwrap(), pool.to_str().unwrap());
    let key_file = root.path().join("k.hex");
    std::fs::write(&key_file, hex::encode([7u8; 32]) + "\n").unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key_s = key_file.to_str().unwrap();
    let sender = Address::from_public_key(key().verifying_key());
    let address = produce(&["address", "--key", key_s]).unwrap();
    assert_eq!(address["address"], hex::encode(sender));

    let genesis = produce(&["init", "--target", db_s]).unwrap();
    let deposits = root.path().join("deposits.json");
    std::fs::write(
        &deposits,
        serde_json::json!([{"height": 3, "tx_index": 0, "txid": "11".repeat(32), "vout": 0,
                            "sats": 20_000_000_000u64, "recipient": hex::encode(sender)}])
        .to_string(),
    )
    .unwrap();
    let parent = genesis["hash"].as_str().unwrap();
    let one = produce(&["extend", "--target", db_s, "--parent", parent, "--anchor", &"ab".repeat(32),
                        "--deposits", deposits.to_str().unwrap()])
    .unwrap();
    let account = produce(&["account", "--target", db_s, "--address", &hex::encode(sender)]).unwrap();
    assert_eq!((account["balance_sats"].as_str(), account["nonce"].as_u64()), (Some("20000000000"), Some(0)));

    let out = |name: &str| pool.join(name).to_str().unwrap().to_string();
    let recipient = "cd".repeat(32);
    let transfer = produce(&["sign-tx", "--key", key_s, "--nonce", "0", "--to", &"55".repeat(20),
                             "--value-wei", "1000", "--out", &out("0.tx")])
    .unwrap();
    assert_eq!(transfer["from"], hex::encode(sender));
    produce(&["sign-tx", "--key", key_s, "--nonce", "1", "--withdraw-to", &recipient, "--sats", "5000000000",
              "--out", &out("1.tx")])
    .unwrap();
    // The outbox minimum and exclusive destinations are enforced before signing.
    assert!(produce(&["sign-tx", "--key", key_s, "--nonce", "2", "--withdraw-to", &recipient, "--sats", "10",
                      "--out", &out("2.tx")])
    .unwrap_err()
    .contains("minimum withdrawal"));
    assert!(produce(&["sign-tx", "--key", key_s, "--nonce", "2", "--to", &"55".repeat(20), "--value-wei", "1",
                      "--withdraw-to", &recipient, "--sats", "1000000", "--out", &out("2.tx")])
    .is_err());
    // An existing output is never overwritten.
    assert!(produce(&["sign-tx", "--key", key_s, "--nonce", "0", "--to", &"55".repeat(20), "--value-wei", "1",
                      "--out", &out("0.tx")])
    .is_err());

    let two = produce(&["extend", "--target", db_s, "--parent", one["hash"].as_str().unwrap(), "--anchor",
                        &"cd".repeat(32), "--txs", pool_s])
    .unwrap();
    assert_eq!((two["transactions"].as_u64(), two["withdrawal_count"].as_u64()), (Some(2), Some(1)));
    assert_eq!(two["withdrawals"][0]["l1_recipient"], recipient);
    assert_eq!(two["withdrawals"][0]["sats"], 5_000_000_000u64);
    let account = produce(&["account", "--target", db_s, "--address", &hex::encode(sender)]).unwrap();
    assert_eq!(account["nonce"].as_u64(), Some(2));
    let left: u64 = account["balance_sats"].as_str().unwrap().parse().unwrap();
    assert!(left < 15_000_000_000 && left > 14_999_000_000, "{account}");
    assert!(spool(&pool).is_empty());

    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(produce(&["address", "--key", key_s]).unwrap_err().contains("owner only"));
}

fn signed_by(seed: u8, nonce: u64, to: TxKind, input: Vec<u8>, tip: u128) -> String {
    let key = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
    let tx = TxEip1559 {
        chain_id: 700_771,
        nonce,
        to,
        input: input.into(),
        gas_limit: 200_000,
        max_fee_per_gas: 200_000_000_000,
        max_priority_fee_per_gas: tip,
        ..Default::default()
    };
    let signature: Signature = key.sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
    hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

fn address_of(seed: u8) -> Address {
    Address::from_public_key(SigningKey::from_bytes((&[seed; 32]).into()).unwrap().verifying_key())
}

/// Round 15 (agents/304 U3, F264-2 residual): the write price inside the producer's own selection. A chain of
/// senders that write the same slot at tips below the price for one new slot is taken out whole in one
/// `select`, however long, and `extend` builds no block with an unpaid slot.
#[test]
fn write_price_leaves_a_whole_chain_of_non_payers_pending() {
    const GWEI: u128 = 1_000_000_000;
    // One new slot costs 10^15 wei: about 23 gwei per gas for a 43.7k-gas store.
    const PRICE: &str = "1000000000000000";
    let root = tempfile::tempdir().unwrap();
    let (db, pool) = (root.path().join("db"), root.path().join("pool"));
    std::fs::create_dir(&pool).unwrap();
    let (db_s, pool_s) = (db.to_str().unwrap(), pool.to_str().unwrap());
    let genesis = produce(&["init", "--target", db_s]).unwrap();
    let parent = genesis["hash"].as_str().unwrap().to_string();
    let seeds: Vec<u8> = (21..=30).collect();
    let deposits = root.path().join("deposits.json");
    let mints: Vec<_> = seeds
        .iter()
        .enumerate()
        .map(|(i, seed)| {
            serde_json::json!({"height": 3, "tx_index": i, "txid": format!("{:064x}", i + 1), "vout": 0,
                               "sats": 100_000_000u64, "recipient": hex::encode(address_of(*seed))})
        })
        .collect();
    std::fs::write(&deposits, serde_json::Value::Array(mints).to_string()).unwrap();
    let anchor = "ab".repeat(32);
    // Block 1: the deposits, and a contract whose only code is SSTORE(calldata[32..64], calldata[0..32]).
    let init = hex::decode("67600035602035550060005260086018f3").unwrap();
    std::fs::write(pool.join("deploy.tx"), signed_by(seeds[0], 0, TxKind::Create, init, 30 * GWEI)).unwrap();
    let one = produce(&["extend", "--target", db_s, "--parent", &parent, "--anchor", &anchor, "--deposits", deposits.to_str().unwrap(), "--txs", pool_s]).unwrap();
    assert_eq!(one["transactions"], 1, "{one}");
    let head = one["hash"].as_str().unwrap().to_string();
    let contract = address_of(seeds[0]).create(0);
    let store = |value: u8, slot: u8| {
        let mut data = vec![0u8; 64];
        data[31] = value;
        data[63] = slot;
        data
    };
    let empty = root.path().join("empty.json");
    std::fs::write(&empty, "[]").unwrap();
    let select = |extra: &[&str]| {
        let mut args = vec!["select", "--target", db_s, "--parent", &head, "--anchor", &anchor, "--deposits", empty.to_str().unwrap(), "--txs", pool_s];
        args.extend_from_slice(extra);
        produce(&args).unwrap()
    };
    // Nine senders write slot 5, each at a lower tip, every tip below the price of one new slot.
    for (i, seed) in seeds[1..].iter().enumerate() {
        let raw = signed_by(*seed, 0, TxKind::Call(contract), store(1 + i as u8, 5), (9 - i as u128) * GWEI);
        std::fs::write(pool.join(format!("chain-{i}.tx")), raw).unwrap();
    }
    let unpriced = select(&[]);
    assert_eq!(unpriced["included"].as_array().unwrap().len(), 9);
    assert!(unpriced.get("unpaid").is_none());
    assert_eq!(unpriced["tx_stats"][0]["fresh_slots"][0][1], 1, "the first writer creates the slot");
    assert_eq!(unpriced["tx_stats"][1]["fresh_slots"].as_array().unwrap().len(), 0);
    // With the price, judged inside the selection: each writer would create the slot (the ones before it were
    // left out), none pays, all nine are left out in one pass.
    let priced = select(&["--fresh-slot-price-wei", PRICE]);
    assert_eq!(priced["included"].as_array().unwrap().len(), 0, "{priced}");
    assert_eq!(priced["unpaid"].as_array().unwrap().len(), 9);
    assert_eq!(priced["not_judged"].as_array().unwrap().len(), 0);
    assert_eq!(priced["write_price"]["passes"], 1);
    assert_eq!(priced["write_price"]["wasted_covered_gas"], 0);
    let mut left: Vec<&str> = priced["unpaid"].as_array().unwrap().iter().map(|t| t["hash"].as_str().unwrap()).collect();
    let mut chain: Vec<&str> = unpriced["included"].as_array().unwrap().iter().map(|t| t.as_str().unwrap()).collect();
    left.sort_unstable();
    chain.sort_unstable();
    assert_eq!(left, chain, "the nine writers, in the seed's order (senders without credit are not ordered by tip)");
    assert!(priced["unpaid"].as_array().unwrap().iter().all(|t| t["own_doing"] == true && t["covered"] == false));
    assert_eq!(priced["tx_stats"].as_array().unwrap().len(), 0);
    // An exempt sender pays no write price: it creates the slot and the eight behind it add none.
    let first = hex::encode(address_of(seeds[1]));
    let exempt = select(&["--fresh-slot-price-wei", PRICE, "--write-exempt", &first]);
    assert_eq!(exempt["included"].as_array().unwrap().len(), 9, "{exempt}");
    assert_eq!(exempt["unpaid"].as_array().unwrap().len(), 0);
    // A payer ahead of the chain creates the slot; nobody behind it owes anything. It is ahead because its sender
    // has paid fees before (credit); senders without credit are ordered by the block's seed, not by the tip they claim.
    std::fs::write(pool.join("payer.tx"), signed_by(seeds[0], 1, TxKind::Call(contract), store(77, 5), 30 * GWEI)).unwrap();
    let credits = root.path().join("credits.json");
    std::fs::write(&credits, serde_json::json!({hex::encode(address_of(seeds[0])): "1000000000000000000"}).to_string()).unwrap();
    let paid = select(&["--fresh-slot-price-wei", PRICE, "--write-credits", credits.to_str().unwrap()]);
    assert_eq!(paid["included"].as_array().unwrap().len(), 10, "{paid}");
    assert_eq!(paid["unpaid"].as_array().unwrap().len(), 0);
    assert_eq!(paid["write_price"]["passes"], 1);
    // Without credit the payer stands where the seed puts it: the writers ahead of it are left out, the ones
    // behind it add no slot, and the payer itself is always included.
    let seeded = select(&["--fresh-slot-price-wei", PRICE]);
    let included = seeded["included"].as_array().unwrap().len();
    assert_eq!(included + seeded["unpaid"].as_array().unwrap().len(), 10, "{seeded}");
    assert!(included >= 1 && seeded["unpaid"].as_array().unwrap().iter().all(|t| t["own_doing"] == true));
    std::fs::remove_file(pool.join("payer.tx")).unwrap();
    // A non-payer is not refused for what an earlier non-payer did: an unpaid creator of slot 6 goes first, and
    // the payer of slot 6 behind it is judged on the block without it.
    std::fs::write(pool.join("other-unpaid.tx"), signed_by(seeds[0], 1, TxKind::Call(contract), store(1, 6), 20 * GWEI)).unwrap();
    let mixed = select(&["--fresh-slot-price-wei", PRICE]);
    assert_eq!(mixed["unpaid"].as_array().unwrap().len(), 10, "{mixed}");
    assert_eq!(mixed["included"].as_array().unwrap().len(), 0);
    std::fs::remove_file(pool.join("other-unpaid.tx")).unwrap();
    // extend with the price builds the block without them and keeps their files; without --txs the flag is refused.
    let err = produce(&["extend", "--target", db_s, "--parent", &head, "--anchor", &anchor, "--fresh-slot-price-wei", PRICE]);
    assert!(err.unwrap_err().contains("require --txs"));
    let files_before = spool(&pool);
    let two = produce(&["extend", "--target", db_s, "--parent", &head, "--anchor", &anchor, "--deposits", empty.to_str().unwrap(),
                        "--txs", pool_s, "--fresh-slot-price-wei", PRICE]).unwrap();
    assert_eq!(two["transactions"], 0, "{two}");
    assert_eq!(two["unpaid"].as_array().unwrap().len(), 9);
    assert_eq!(two["not_judged"].as_array().unwrap().len(), 0);
    assert_eq!(two["pruned"], 0);
    assert_eq!(spool(&pool), files_before, "an unpaid transaction keeps its spool file");
}

/// Shared world of the adversarial tests: `non_payers` senders each call a contract in a way that adds one slot
/// below the price, at `tip` gwei; `honest` senders send one plain transfer and `honest_calls` one paid contract
/// call, at 3 gwei and below every non-payer. Returns (database, pool directory, head hash, temp dir guard).
struct Adversarial {
    _root: tempfile::TempDir,
    db: String,
    pool: String,
    head: String,
    empty: String,
}

const ADV_PRICE: &str = "200000000000000"; // the policy's 200 µBLCH per slot

fn adversarial(non_payers: usize, chain: bool, honest: usize, honest_calls: usize) -> Adversarial {
    const GWEI: u128 = 1_000_000_000;
    let root = tempfile::tempdir().unwrap();
    let (db, pool) = (root.path().join("db"), root.path().join("pool"));
    std::fs::create_dir(&pool).unwrap();
    let (db_s, pool_s) = (db.to_str().unwrap().to_string(), pool.to_str().unwrap().to_string());
    let parent = produce(&["init", "--target", &db_s]).unwrap()["hash"].as_str().unwrap().to_string();
    let key_of = |i: usize| {
        let mut seed = [9u8; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        SigningKey::from_bytes((&seed).into()).unwrap()
    };
    let sign = |i: usize, nonce: u64, to: TxKind, input: Vec<u8>, value: u64, gas: u64, tip: u128| {
        let tx = TxEip1559 { chain_id: 700_771, nonce, to, input: input.into(), value: U256::from(value), gas_limit: gas,
                             max_fee_per_gas: 200_000_000_000, max_priority_fee_per_gas: tip, ..Default::default() };
        let signature: Signature = key_of(i).sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
        hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
    };
    let address = |i: usize| Address::from_public_key(key_of(i).verifying_key());
    let total = non_payers + honest + honest_calls + 1;
    let deposits = root.path().join("deposits.json");
    let mints: Vec<_> = (0..total)
        .map(|i| serde_json::json!({"height": 3, "tx_index": i, "txid": format!("{:064x}", i + 1), "vout": 0,
                                    "sats": 100_000_000u64, "recipient": hex::encode(address(i))}))
        .collect();
    std::fs::write(&deposits, serde_json::Value::Array(mints).to_string()).unwrap();
    let anchor = "ab".repeat(32);
    let deployer = total - 1;
    // SSTORE(calldata[32..64], calldata[0..32])
    let init = hex::decode("67600035602035550060005260086018f3").unwrap();
    std::fs::write(pool.join("deploy.tx"), sign(deployer, 0, TxKind::Create, init, 0, 200_000, 30 * GWEI)).unwrap();
    let one = produce(&["extend", "--target", &db_s, "--parent", &parent, "--anchor", &anchor, "--deposits", deposits.to_str().unwrap(), "--txs", &pool_s]).unwrap();
    assert_eq!(one["transactions"], 1, "{one}");
    let head = one["hash"].as_str().unwrap().to_string();
    let contract = address(deployer).create(0);
    let store = |value: u64, slot: u64| {
        let mut data = vec![0u8; 64];
        data[24..32].copy_from_slice(&value.to_be_bytes());
        data[56..64].copy_from_slice(&slot.to_be_bytes());
        data
    };
    // Non-payers: one new slot each (their own, or the same one when `chain`), 3.9 gwei x about 43.7k gas < 2e14.
    for i in 0..non_payers {
        let slot = if chain { 1_000_000 } else { 1_000 + i as u64 };
        let tip = 3_900_000_000 - (i as u128);
        std::fs::write(pool.join(format!("np-{i}.tx")), sign(i, 0, TxKind::Call(contract), store(1 + i as u64, slot), 0, 60_000, tip)).unwrap();
    }
    // Honest users at the decided maximum tip, 3 gwei, behind every non-payer: plain transfers, and contract calls
    // that add no slot (they store zero) and so owe no write price.
    for i in 0..honest {
        std::fs::write(pool.join(format!("honest-{i}.tx")), sign(non_payers + i, 0, TxKind::Call(Address::repeat_byte(0x55)), vec![], 1_000, 21_000, 3 * GWEI)).unwrap();
    }
    for i in 0..honest_calls {
        std::fs::write(pool.join(format!("call-{i}.tx")), sign(non_payers + honest + i, 0, TxKind::Call(contract), store(0, 500 + i as u64), 0, 60_000, 3 * GWEI - 1 - i as u128)).unwrap();
    }
    let empty = root.path().join("empty.json");
    std::fs::write(&empty, "[]").unwrap();
    Adversarial { db: db_s, pool: pool_s, head, empty: empty.to_str().unwrap().to_string(), _root: root }
}

fn adversarial_select(world: &Adversarial, extra: &[&str]) -> (Value, std::time::Duration) {
    let anchor = "ab".repeat(32);
    let mut args = vec!["select", "--target", &world.db, "--parent", &world.head, "--anchor", &anchor, "--deposits", &world.empty, "--txs", &world.pool];
    args.extend_from_slice(extra);
    let started = std::time::Instant::now();
    let report = produce(&args).unwrap();
    (report, started.elapsed())
}

/// Review R308-3P-2, the reviewer's scenario on the real binary: eight funded senders spool one call each that
/// adds one own new slot at 3.9 gwei (below the write price), ahead in tip order of honest users at 3 gwei.
/// Before the fix (the 8-pass cap that kept only the transactions ahead of the eighth non-payer) the block took
/// no user transaction. A non-payer must never displace a payer.
#[test]
fn eight_non_payers_ahead_in_tip_order_do_not_empty_the_block() {
    let world = adversarial(8, false, 20, 10);
    let (priced, _) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE]);
    assert_eq!(priced["unpaid"].as_array().unwrap().len(), 8, "{}", priced["write_price"]);
    assert_eq!(priced["not_judged"].as_array().unwrap().len(), 0);
    assert_eq!(priced["included"].as_array().unwrap().len(), 30, "every honest transfer and paid call is in the block");
    // Nothing in the block adds a slot it does not pay for.
    for t in priced["tx_stats"].as_array().unwrap() {
        let fresh: u64 = t["fresh_slots"].as_array().unwrap().iter().map(|pair| pair[1].as_u64().unwrap()).sum();
        let paid = t["gas_used"].as_u64().unwrap() as u128 * t["effective_tip"].as_str().unwrap().parse::<u128>().unwrap();
        assert!(paid >= fresh as u128 * 200_000_000_000_000, "{t}");
    }
    // extend builds exactly that block and keeps the non-payers' files.
    let anchor = "ab".repeat(32);
    let block = produce(&["extend", "--target", &world.db, "--parent", &world.head, "--anchor", &anchor, "--deposits", &world.empty,
                          "--txs", &world.pool, "--fresh-slot-price-wei", ADV_PRICE]).unwrap();
    assert_eq!(block["transactions"], 30, "{block}");
    assert_eq!(block["included"], priced["included"]);
    assert_eq!(block["unpaid"].as_array().unwrap().len(), 8);
    assert_eq!(spool(Path::new(&world.pool)).iter().filter(|name| name.starts_with("np-")).count(), 8);
}

/// Review R308-3P-2, timed (the numbers are recorded in docs/SEQUENCER-POLICY-V2.md): 8, 64 and 400 non-payers
/// from as many keys at a tip above every honest user, as independent writers and as a chain in which each
/// refusal uncovers the next. Honest transactions are all included and the call stays far inside the plan's
/// allowance; with a small allowance for non-payers the plain transfers are still served.
#[test]
fn many_non_payers_at_a_high_tip_cost_one_pass_and_serve_every_payer() {
    for (count, chain) in [(8usize, false), (64, false), (400, false), (64, true), (400, true)] {
        let world = adversarial(count, chain, 20, 10);
        let (plain, plain_time) = adversarial_select(&world, &[]);
        // The honest senders have paid fees before (credit): they are covered and judged first, by tip.
        let honest: Vec<String> = plain["tx_stats"].as_array().unwrap().iter()
            .filter(|t| t["effective_tip"].as_str().unwrap().parse::<u128>().unwrap() < 3_800_000_000)
            .map(|t| t["sender"].as_str().unwrap().to_string()).collect();
        let entries: Vec<(&String, u128)> = honest.iter().map(|k| (k, 1_000_000_000_000_000u128)).collect();
        let file = credits_file(&world, &entries);
        let (priced, priced_time) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE, "--write-credits", &file]);
        eprintln!(
            "R308-3P-2 measured: {count} non-payers ({}), 30 honest: select without the price {:?} ({} included); with the price {:?}: included {}, unpaid {}, not judged {}, wasted gas {}",
            if chain { "chain on one slot" } else { "own slots" }, plain_time, plain["included"].as_array().unwrap().len(), priced_time,
            priced["included"].as_array().unwrap().len(), priced["unpaid"].as_array().unwrap().len(),
            priced["not_judged"].as_array().unwrap().len(), priced["write_price"]["wasted_uncovered_gas"]
        );
        assert_eq!(priced["included"].as_array().unwrap().len(), 30, "{count} {chain}");
        // Every non-payer is executed and left out while the uncovered pool (half a block) lasts; past it the rest
        // is not executed. Either way none is included and no honest transaction is touched.
        assert_eq!(priced["unpaid"].as_array().unwrap().len() + priced["not_judged"].as_array().unwrap().len(), count);
        assert!(priced["write_price"]["wasted_uncovered_gas"].as_u64().unwrap() <= 15_000_000 + 60_000);
        assert_eq!(priced["write_price"]["passes"], 1);
        assert!(priced_time < plain_time * 3 + std::time::Duration::from_secs(5), "{priced_time:?} against {plain_time:?}");
        if count == 400 && !chain {
            // A small pool for uncovered senders: about three non-payers use it up. Honest senders with credit are
            // covered and unaffected; without credit only their plain transfers are then still executed.
            let (covered, _) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE, "--write-uncovered-gas", "100000", "--write-credits", &file]);
            assert_eq!(covered["included"].as_array().unwrap().len(), 30, "covered senders do not depend on the uncovered pool");
            assert!(covered["unpaid"].as_array().unwrap().len() <= 4);
            let (tight, _) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE, "--write-uncovered-gas", "100000"]);
            assert!(tight["included"].as_array().unwrap().len() >= 20, "the plain transfers at least");
        }
    }
}

/// World of the fourth-pass tests (review R308-4P-1): `big` keys each send one writer that adds 200 slots with
/// about 4.45M gas at 7.9 gwei (unpaid: 3.5e16 wei against 4e16 owed); `calls` honest senders each send one
/// contract call at 3 gwei that adds no slot; `transfers` honest senders one plain transfer at 3 gwei.
/// Returns the world and the hex addresses of the big keys and of the honest callers.
fn large_non_payers(big: usize, calls: usize, transfers: usize, race: bool) -> (Adversarial, Vec<String>, Vec<String>) {
    const GWEI: u128 = 1_000_000_000;
    let root = tempfile::tempdir().unwrap();
    let (db, pool) = (root.path().join("db"), root.path().join("pool"));
    std::fs::create_dir(&pool).unwrap();
    let (db_s, pool_s) = (db.to_str().unwrap().to_string(), pool.to_str().unwrap().to_string());
    let parent = produce(&["init", "--target", &db_s]).unwrap()["hash"].as_str().unwrap().to_string();
    let key_of = |i: usize| {
        let mut seed = [11u8; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        SigningKey::from_bytes((&seed).into()).unwrap()
    };
    let sign = |i: usize, nonce: u64, to: TxKind, input: Vec<u8>, value: u64, gas: u64, tip: u128| {
        let tx = TxEip1559 { chain_id: 700_771, nonce, to, input: input.into(), value: U256::from(value), gas_limit: gas,
                             max_fee_per_gas: 200_000_000_000, max_priority_fee_per_gas: tip, ..Default::default() };
        let signature: Signature = key_of(i).sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
        hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
    };
    let address = |i: usize| Address::from_public_key(key_of(i).verifying_key());
    let total = big + calls + transfers + 1;
    let deployer = total - 1;
    let deposits = root.path().join("deposits.json");
    let mints: Vec<_> = (0..total + 2)
        .map(|i| serde_json::json!({"height": 3, "tx_index": i, "txid": format!("{:064x}", i + 1), "vout": 0,
                                    "sats": 1_000_000_000u64, "recipient": hex::encode(address(i))}))
        .collect();
    std::fs::write(&deposits, serde_json::Value::Array(mints).to_string()).unwrap();
    let anchor = "ab".repeat(32);
    // Contract 0: SSTORE(calldata[32..64], calldata[0..32]). Contract 1: for n in 200..=1 { SSTORE(calldata[0..32] + n, 1) }.
    let store_init = hex::decode("67600035602035550060005260086018f3").unwrap();
    let loop_init = hex::decode("7360c85b600181600035015560019003806002570060005260146000f3").unwrap();
    let mut loop_init_fixed = loop_init.clone();
    // RETURN(offset 12, size 20): the runtime is right-aligned in the 32-byte word.
    let n = loop_init_fixed.len();
    loop_init_fixed[n - 2] = 0x0c;
    std::fs::write(pool.join("deploy-0.tx"), sign(deployer, 0, TxKind::Create, store_init, 0, 200_000, 30 * GWEI)).unwrap();
    std::fs::write(pool.join("deploy-1.tx"), sign(deployer, 1, TxKind::Create, loop_init_fixed, 0, 200_000, 30 * GWEI)).unwrap();
    let (store, looper) = (address(deployer).create(0), address(deployer).create(1));
    let word = |value: u64| {
        let mut data = vec![0u8; 32];
        data[24..32].copy_from_slice(&value.to_be_bytes());
        data
    };
    let pair = |value: u64, slot: u64| {
        let mut data = word(value);
        data.extend(word(slot));
        data
    };
    // Slot 900 of the store contract holds 5 from block 1 on (the recipient's non-zero balance of R308-4P-2).
    std::fs::write(pool.join("deploy-2.tx"), sign(deployer, 2, TxKind::Call(store), pair(5, 900), 0, 100_000, 30 * GWEI)).unwrap();
    let one = produce(&["extend", "--target", &db_s, "--parent", &parent, "--anchor", &anchor, "--deposits", deposits.to_str().unwrap(), "--txs", &pool_s]).unwrap();
    assert_eq!(one["transactions"], 3, "{one}");
    let head = one["hash"].as_str().unwrap().to_string();
    if race {
        // The recipient empties slot 900 at 5 gwei (ahead); the user then writes it at 3 gwei: a new slot in this
        // block only. A third sender writes a slot nobody else touches at 3 gwei: unpaid on any state.
        std::fs::write(pool.join("race-clear.tx"), sign(total, 0, TxKind::Call(store), pair(0, 900), 0, 100_000, 5 * GWEI)).unwrap();
        std::fs::write(pool.join("race-user.tx"), sign(total + 1, 0, TxKind::Call(store), pair(7, 900), 0, 100_000, 3 * GWEI)).unwrap();
        std::fs::write(pool.join("race-own.tx"), sign(deployer, 3, TxKind::Call(store), pair(7, 901), 0, 100_000, 3 * GWEI)).unwrap();
    }
    for i in 0..big {
        std::fs::write(pool.join(format!("big-{i}.tx")), sign(i, 0, TxKind::Call(looper), word(1_000_000 * (i as u64 + 1)), 0, 5_000_000, 7_900_000_000 - i as u128)).unwrap();
    }
    for i in 0..calls {
        let mut data = word(0);
        data.extend(word(500 + i as u64));
        std::fs::write(pool.join(format!("call-{i}.tx")), sign(big + i, 0, TxKind::Call(store), data, 0, 60_000, 3 * GWEI - 1 - i as u128)).unwrap();
    }
    for i in 0..transfers {
        std::fs::write(pool.join(format!("honest-{i}.tx")), sign(big + calls + i, 0, TxKind::Call(Address::repeat_byte(0x55)), vec![], 1_000, 21_000, 3 * GWEI)).unwrap();
    }
    let empty = root.path().join("empty.json");
    std::fs::write(&empty, "[]").unwrap();
    let bigs = (0..big).map(|i| hex::encode(address(i))).collect();
    let callers = (big..big + calls).map(|i| hex::encode(address(i))).collect();
    (Adversarial { db: db_s, pool: pool_s, head, empty: empty.to_str().unwrap().to_string(), _root: root }, bigs, callers)
}

fn credits_file(world: &Adversarial, entries: &[(&String, u128)]) -> String {
    let path = Path::new(&world.db).parent().unwrap().join(format!("credits-{}.json", entries.len()));
    let map: serde_json::Map<String, Value> = entries.iter().map(|(sender, wei)| ((*sender).clone(), Value::String(wei.to_string()))).collect();
    std::fs::write(&path, Value::Object(map).to_string()).unwrap();
    path.to_str().unwrap().to_string()
}

/// Review R308-4P-1 on the real binary. On the third-pass producer (one shared 60M allowance, a standing list)
/// fourteen keys with standing, each wasting about 4.45M gas, left the ten honest contract calls behind them
/// not judged (recorded in agents/311-evidence/u3/). Now: what a key bought with one paid transfer is far from
/// covering a 5M-gas writer, so the writer is not executed at all; keys that really paid for that much gas before
/// are covered, waste their own pool and are debited, and still cannot touch the pool of the senders without
/// credit; nobody's honest call is left unjudged for somebody else's waste except by fees paid at a higher bid.
#[test]
fn large_non_payers_cannot_starve_contract_calls() {
    let (world, bigs, callers) = large_non_payers(14, 10, 10, false);
    // (a) Standing bought with one plain transfer at the floor: 21,000 gas x 0.1 gwei of credit per key.
    let cheap: Vec<(&String, u128)> = bigs.iter().map(|k| (k, 21_000u128 * 100_000_000)).collect();
    let file = credits_file(&world, &cheap);
    let (report, time) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE, "--write-credits", &file]);
    eprintln!("R308-4P-1 measured (a) 14 big writers with one-transfer credit: {time:?} included {} unpaid {} not judged {} {}",
              report["included"].as_array().unwrap().len(), report["unpaid"].as_array().unwrap().len(),
              report["not_judged"].as_array().unwrap().len(), report["write_price"]);
    assert_eq!(report["included"].as_array().unwrap().len(), 20, "ten honest calls and ten transfers");
    assert!(time < std::time::Duration::from_secs(30), "{time:?}");
    assert_eq!(report["unpaid"].as_array().unwrap().len(), 0, "an uncovered 5M-gas writer is not executed");
    assert_eq!(report["needs_credit"].as_array().unwrap().len(), 14);
    assert_eq!(report["not_judged"].as_array().unwrap().len(), 0);
    assert_eq!(report["write_price"]["wasted_covered_gas"], 0);
    assert_eq!(report["write_price"]["wasted_uncovered_gas"], 0);
    // (b) Keys that really paid before for as much gas as they now waste (5M x 7.9 gwei each) are covered and are
    // executed, ahead of everybody by tip, until the covered pool of 60M is used up (fourteen x 4.45M reach it).
    // The honest callers WITH credit sit behind them in the covered class: their small calls are then judged from
    // the other pool; the honest callers WITHOUT credit are judged from that pool whatever the covered class wasted.
    let mut rich: Vec<(&String, u128)> = bigs.iter().map(|k| (k, 5_000_000u128 * 7_900_000_000)).collect();
    rich.extend(callers.iter().take(5).map(|k| (k, 1_000_000_000_000_000u128)));
    let file = credits_file(&world, &rich);
    let (report, time) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE, "--write-credits", &file]);
    eprintln!("R308-4P-1 measured (b) 14 big writers that paid 3.95e16 wei each before: {time:?} included {} unpaid {} not judged {} {}",
              report["included"].as_array().unwrap().len(), report["unpaid"].as_array().unwrap().len(),
              report["not_judged"].as_array().unwrap().len(), report["write_price"]);
    let unpaid = report["unpaid"].as_array().unwrap();
    assert!(unpaid.iter().all(|t| t["covered"] == true && t["own_doing"] == true));
    assert!(report["write_price"]["wasted_covered_gas"].as_u64().unwrap() <= 60_000_000 + 5_000_000);
    assert_eq!(report["write_price"]["wasted_uncovered_gas"], 0);
    assert_eq!(report["not_judged"].as_array().unwrap().len(), 0);
    let included: Vec<&str> = report["tx_stats"].as_array().unwrap().iter().map(|t| t["sender"].as_str().unwrap()).collect();
    for caller in &callers {
        assert!(included.contains(&caller.as_str()), "every honest caller, with credit or without, is judged and included");
    }
    assert_eq!(included.len(), 20, "ten transfers and ten calls");
    assert!(time < std::time::Duration::from_secs(30), "65M gas of covered waste, each judged twice: {time:?}");
    // (c) With the per-transaction cap of the policy (5M is the default there; here 4M) the writers are not executed.
    let (report, _) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE, "--write-credits", &file, "--write-max-tx-gas", "4000000"]);
    assert_eq!(report["included"].as_array().unwrap().len(), 20);
    assert_eq!(report["unpaid"].as_array().unwrap().len(), 0);
    assert_eq!(report["over_gas_cap"].as_array().unwrap().len(), 14);
}

/// Review R308-4P-2 on the real binary: a transaction made unpaid by an earlier transaction of the same block
/// (the recipient empties the slot the user then writes) is left out but reported `own_doing: false`; one that
/// adds a slot on any state is `own_doing: true`. The policy gives the sender-wide wait only to the second.
#[test]
fn a_transaction_made_unpaid_by_an_earlier_one_is_not_its_senders_doing() {
    let (world, _, _) = large_non_payers(0, 0, 2, true);
    let (report, _) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE]);
    let unpaid = report["unpaid"].as_array().unwrap();
    assert_eq!(unpaid.len(), 2, "{report}");
    let by_doing: Vec<bool> = unpaid.iter().map(|t| t["own_doing"].as_bool().unwrap()).collect();
    assert_eq!(by_doing.iter().filter(|own| **own).count(), 1, "the writer of slot 901: unpaid on the start state too");
    assert_eq!(by_doing.iter().filter(|own| !**own).count(), 1, "the user racing the recipient: paid alone, unpaid here");
    assert_eq!(report["included"].as_array().unwrap().len(), 3, "the recipient's clearing transaction and two transfers");
    // Without the recipient's transaction the user's one is included: it adds no slot.
    std::fs::remove_file(Path::new(&world.pool).join("race-clear.tx")).unwrap();
    let (report, _) = adversarial_select(&world, &["--fresh-slot-price-wei", ADV_PRICE]);
    assert_eq!(report["unpaid"].as_array().unwrap().len(), 1);
    assert_eq!(report["included"].as_array().unwrap().len(), 3);
}
