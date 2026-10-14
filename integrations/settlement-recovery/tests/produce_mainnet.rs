// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-l2-produce-dev --rules mainnet`: chain id 700770, the ceremony's
//! domain and a wall-clock genesis, and wall-clock block timestamps from
//! block 1 (no `parent + 1` prefix as on devnet4).
#![cfg(unix)]

use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Signature, TxKind, U256};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_bloch-l2-produce-dev");
const DOMAIN: &str = "7070707070707070707070707070707070707070707070707070707070707070";
const GENESIS: &str = "1800000000";
const MAINNET: [&str; 6] = ["--rules", "mainnet", "--domain", DOMAIN, "--genesis-time", GENESIS];

fn produce(args: &[&str]) -> Result<Value, String> {
    let out = Command::new(BIN).args(args).output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn mainnet(args: &[&str]) -> Result<Value, String> {
    produce(&[args, &MAINNET[..]].concat())
}

fn key() -> SigningKey {
    SigningKey::from_bytes((&[9u8; 32]).into()).unwrap()
}

fn transfer(chain_id: u64, nonce: u64) -> String {
    let tx = TxEip1559 {
        chain_id,
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

#[test]
fn mainnet_profile_has_its_own_genesis_chain_id_and_wall_clock_blocks() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("mainnet");
    let db_s = db.to_str().unwrap();
    let devnet = root.path().join("devnet");

    // Mainnet knobs are refused without --rules mainnet, and mainnet needs them.
    assert!(produce(&["init", "--target", db_s, "--domain", DOMAIN])
        .unwrap_err()
        .contains("only to --rules mainnet"));
    assert!(
        produce(&["init", "--target", db_s, "--rules", "mainnet", "--domain", DOMAIN])
            .unwrap_err()
            .contains("--genesis-time")
    );
    assert!(produce(&["init", "--target", db_s, "--rules", "v2"])
        .unwrap_err()
        .contains("settlement V3"));

    let genesis = mainnet(&["init", "--target", db_s]).unwrap();
    let dev_genesis = produce(&["init", "--target", devnet.to_str().unwrap()]).unwrap();
    assert_ne!(
        genesis["hash"], dev_genesis["hash"],
        "mainnet genesis differs from the devnet one"
    );
    let parent = genesis["hash"].as_str().unwrap().to_string();
    let anchor = "ab".repeat(32);

    let sender = Address::from_public_key(key().verifying_key());
    let deposits = root.path().join("deposits.json");
    std::fs::write(
        &deposits,
        serde_json::json!([{"height": 3, "tx_index": 0, "txid": "11".repeat(32), "vout": 0,
                            "sats": 100_000_000u64, "recipient": hex::encode(sender)}])
        .to_string(),
    )
    .unwrap();
    let pool = root.path().join("pool");
    std::fs::create_dir(&pool).unwrap();
    std::fs::write(pool.join("a-mainnet.tx"), transfer(700_770, 0)).unwrap();
    std::fs::write(pool.join("b-devnet.tx"), transfer(700_771, 1)).unwrap();
    let extend = |rule: Option<&str>, slot: &str| {
        let mut args = vec!["extend", "--target", db_s, "--parent", &parent, "--anchor", &anchor];
        args.extend(["--anchor-slot", slot, "--deposits", deposits.to_str().unwrap()]);
        args.extend(["--txs", pool.to_str().unwrap()]);
        if let Some(rule) = rule {
            args.extend(["--timestamp-rule", rule]);
        }
        mainnet(&args)
    };
    // Every mainnet block follows the wall-clock rule from block 1.
    assert!(extend(None, "100").unwrap_err().contains("requires --timestamp-rule"));
    assert!(extend(Some("228:1800000000:2000"), "100")
        .unwrap_err()
        .contains("from L2 block 1"));

    // Block 1 is stamped with the start of its anchored native slot.
    let block = extend(Some("1:1800000000:2000"), "100").unwrap();
    assert_eq!(block["number"], 1);
    assert_eq!(block["timestamp"], 1_800_000_200u64);
    // Only the transaction signed for 700770 authenticates.
    assert_eq!(block["transactions"], 1);
    assert!(block["dropped"][0]["reason"]
        .as_str()
        .unwrap()
        .starts_with("authentication"));

    // The database only opens under the network it was created for.
    let head = mainnet(&["head", "--target", db_s]).unwrap();
    assert_eq!(head["hash"], block["hash"]);
    assert!(produce(&["head", "--target", db_s])
        .unwrap_err()
        .contains("not the selected network"));
    let devnet_s = devnet.to_str().unwrap();
    assert!(mainnet(&["head", "--target", devnet_s])
        .unwrap_err()
        .contains("not the selected network"));
    assert_eq!(
        produce(&["head", "--target", devnet_s]).unwrap()["hash"],
        dev_genesis["hash"]
    );
}
