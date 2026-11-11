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
    // With the price: the first writer leaves, the second becomes the creator and leaves, and so on, in one call.
    let priced = select(&["--fresh-slot-price-wei", PRICE]);
    assert_eq!(priced["included"].as_array().unwrap().len(), 0, "{priced}");
    assert_eq!(priced["unpaid"].as_array().unwrap().len(), 9);
    assert_eq!(priced["write_price"]["passes"], 10);
    assert_eq!(priced["write_price"]["conservative"], false);
    assert_eq!(priced["unpaid"][0]["hash"], unpriced["included"][0], "refused in block order, highest tip first");
    assert_eq!(priced["tx_stats"].as_array().unwrap().len(), 0);
    // An exempt sender pays no write price: it creates the slot and the eight behind it add none.
    let first = hex::encode(address_of(seeds[1]));
    let exempt = select(&["--fresh-slot-price-wei", PRICE, "--write-exempt", &first]);
    assert_eq!(exempt["included"].as_array().unwrap().len(), 9, "{exempt}");
    assert_eq!(exempt["unpaid"].as_array().unwrap().len(), 0);
    // A payer ahead of the chain creates the slot; nobody behind it owes anything.
    std::fs::write(pool.join("payer.tx"), signed_by(seeds[0], 1, TxKind::Call(contract), store(77, 5), 30 * GWEI)).unwrap();
    let paid = select(&["--fresh-slot-price-wei", PRICE]);
    assert_eq!(paid["included"].as_array().unwrap().len(), 10, "{paid}");
    assert_eq!(paid["unpaid"].as_array().unwrap().len(), 0);
    assert_eq!(paid["write_price"]["passes"], 1);
    std::fs::remove_file(pool.join("payer.tx")).unwrap();
    // A non-payer is not refused for what an earlier non-payer did: an unpaid creator of slot 6 goes first, and
    // the payer of slot 6 behind it is judged on the block without it.
    std::fs::write(pool.join("other-unpaid.tx"), signed_by(seeds[0], 1, TxKind::Call(contract), store(1, 6), 20 * GWEI)).unwrap();
    let mixed = select(&["--fresh-slot-price-wei", PRICE]);
    assert_eq!(mixed["unpaid"].as_array().unwrap().len(), 10, "{mixed}");
    std::fs::remove_file(pool.join("other-unpaid.tx")).unwrap();
    // extend with the price builds the block without them and keeps their files; without --txs the flag is refused.
    let err = produce(&["extend", "--target", db_s, "--parent", &head, "--anchor", &anchor, "--fresh-slot-price-wei", PRICE]);
    assert!(err.unwrap_err().contains("require --txs"));
    let files_before = spool(&pool);
    let two = produce(&["extend", "--target", db_s, "--parent", &head, "--anchor", &anchor, "--deposits", empty.to_str().unwrap(),
                        "--txs", pool_s, "--fresh-slot-price-wei", PRICE]).unwrap();
    assert_eq!(two["transactions"], 0, "{two}");
    assert_eq!(two["unpaid"].as_array().unwrap().len(), 9);
    assert_eq!(two["pruned"], 0);
    assert_eq!(spool(&pool), files_before, "an unpaid transaction keeps its spool file");
}
