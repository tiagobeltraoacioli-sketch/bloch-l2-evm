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
