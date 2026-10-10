// SPDX-License-Identifier: AGPL-3.0-or-later
//! M4 end to end, execution only (no proof): L2 blocks with outbox
//! withdrawals are produced by `bloch-l2-produce-dev`, exported, re-executed
//! statelessly into settlement V3 statements exactly as the guest does, framed
//! as native `0x13` transactions and checked against the native withdrawal
//! rule in sequence. The claim input from `withdrawal-proof` verifies with
//! the NATIVE leaf and proof code against the settled root.
#![cfg(unix)]

use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Signature, TxKind, B256, U256};
use bloch_execution_artifact::ExecutionArtifact;
use bloch_l2_evm::{
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2, SettlementStatementV3},
    sats_to_wei,
    withdrawal::{empty_withdrawal_root, INITIATE_WITHDRAWAL_SELECTOR, L2_TO_L1_MESSAGE_PASSER},
    ChainSpec,
};
use bloch_pos_committee::l2_settlement::{withdrawal, Reject, Transaction as Settlement};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_bloch-l2-produce-dev");
const CHAIN_ID: u64 = 700_771;

fn produce(args: &[&str]) -> Result<Value, String> {
    let out = Command::new(BIN).args(args).output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes((&[9u8; 32]).into()).unwrap()
}

fn sign(nonce: u64, to: Address, value: U256, input: Vec<u8>) -> String {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        to: TxKind::Call(to),
        value,
        input: input.into(),
        gas_limit: 100_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1,
        ..Default::default()
    };
    let signature: Signature = key().sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
    hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

fn withdraw(nonce: u64, l1_recipient: [u8; 32], sats: u64) -> String {
    let mut input = INITIATE_WITHDRAWAL_SELECTOR.to_vec();
    input.extend_from_slice(&l1_recipient);
    sign(nonce, L2_TO_L1_MESSAGE_PASSER, sats_to_wei(sats), input)
}

fn h(v: &Value) -> B256 {
    v.as_str().unwrap().parse().unwrap()
}

#[test]
fn produced_withdrawals_settle_under_the_native_rule_and_prove_natively() {
    let root = tempfile::tempdir().unwrap();
    let path = |name: &str| root.path().join(name).to_str().unwrap().to_string();
    let db = path("db");
    let genesis = produce(&["init", "--target", &db]).unwrap();
    let sender = Address::from_public_key(key().verifying_key());
    let (alice, bob) = ([0xa1u8; 32], [0xb2u8; 32]);
    let deposit = json!([{"height": 2, "tx_index": 0, "txid": "21".repeat(32), "vout": 1,
                          "sats": 1_000_000_000u64, "recipient": hex::encode(sender)}]);
    // Block 1: deposit only. Block 2: two withdrawals. Block 3: a transfer.
    let plan: Vec<(Value, Vec<String>)> = vec![
        (deposit, vec![]),
        (json!([]), vec![withdraw(0, alice, 2_000_000), withdraw(1, bob, 3_000_000)]),
        (json!([]), vec![sign(2, Address::repeat_byte(0x55), U256::from(1_000u64), vec![])]),
    ];
    let spec = ChainSpec::testnet_v3();
    let domain = B256::repeat_byte(0xd3);
    let mut parent = genesis["hash"].as_str().unwrap().to_string();
    let mut previous: Option<Vec<u8>> = None;
    let mut consumed = 0u64;
    let mut statements = Vec::new();
    for (i, (deposits, txs)) in plan.iter().enumerate() {
        let number = i as u64 + 1;
        let deposits_file = path(&format!("deposits-{number}.json"));
        std::fs::write(&deposits_file, deposits.to_string()).unwrap();
        let pool = path(&format!("pool-{number}.json"));
        std::fs::write(&pool, json!(txs).to_string()).unwrap();
        let anchor = hex::encode([0xa0 + number as u8; 32]);
        let block = produce(&["extend", "--target", &db, "--parent", &parent, "--anchor", &anchor,
                              "--deposits", &deposits_file, "--txs", &pool])
        .unwrap();
        assert_eq!(block["transactions"].as_u64().unwrap(), txs.len() as u64, "{block}");

        // Execution only, as the guest: the exported witness re-executed
        // under the V3 rules yields the statement the proof would carry.
        let artifact_path = path(&format!("block-{number}.artifact"));
        produce(&["export", "--target", &db, "--number", &number.to_string(), "--out", &artifact_path]).unwrap();
        let artifact = ExecutionArtifact::decode(&std::fs::read(&artifact_path).unwrap(), &spec, domain).unwrap();
        let minted = artifact.body().deposits.len() as u64;
        let context = SettlementContextV2 {
            network: B256::repeat_byte(0x41),
            genesis: B256::repeat_byte(0x42),
            program_elf_keccak: B256::repeat_byte(0x43),
            program_vkey_koalabear: B256::repeat_byte(0x44),
            program_vkey_bn254: B256::repeat_byte(0x45),
            previous_settlement: if number == 1 { B256::ZERO } else { B256::repeat_byte(0x48) },
            l1_slot: 10 + number,
            l1_height: 10 + number,
            source_commitment: B256::repeat_byte(0x46),
            inbox_root: B256::repeat_byte(0x47),
            inbox_count: 1,
            consumed_start: consumed,
            consumed_end: consumed + minted,
        };
        consumed += minted;
        let statement = execute_settlement_statement_v3(
            &spec,
            domain,
            artifact.witness(),
            artifact.context(),
            artifact.body(),
            context,
        )
        .unwrap();
        assert_eq!(statement.base.l2_header_hash, h(&block["hash"]));
        assert_eq!(statement.withdrawal_root, h(&block["withdrawal_root"]));
        assert_eq!(statement.withdrawal_count, block["withdrawal_count"].as_u64().unwrap());

        // Framed as the native async settlement and decoded by the native codec.
        let frame = Settlement { proof_policy: [3; 32], statement: statement.encode().to_vec(), proof: [1; 356] }
            .encode_async();
        let native = Settlement::decode_async(&frame).unwrap();
        let added = withdrawal::check_successor(previous.as_deref(), &native.statement).unwrap();
        assert_eq!(added.is_some(), number == 2, "block {number}");
        previous = Some(native.statement.clone());
        statements.push(statement);
        parent = block["hash"].as_str().unwrap().to_string();
    }
    let (s1, s2, s3) = (&statements[0], &statements[1], &statements[2]);
    assert_eq!((s1.withdrawal_root, s1.withdrawal_count), (empty_withdrawal_root(), 0));
    assert_eq!(s2.withdrawal_count, 2);
    assert_eq!((s3.withdrawal_root, s3.withdrawal_count), (s2.withdrawal_root, 2));
    assert_eq!(withdrawal::empty_root(), empty_withdrawal_root().0);

    // The native rule refuses a settled tree that shrinks or moves without leaves.
    let tampered = |statement: &SettlementStatementV3, root: B256, count: u64| {
        SettlementStatementV3 { withdrawal_root: root, withdrawal_count: count, ..*statement }.encode().to_vec()
    };
    let head = s2.encode().to_vec();
    for (root, count) in [(s2.withdrawal_root, 1), (B256::repeat_byte(7), 2), (s2.withdrawal_root, 3)] {
        assert_eq!(
            withdrawal::check_successor(Some(&head), &tampered(s3, root, count)),
            Err(Reject::Withdrawals),
            "{root} {count}"
        );
    }

    // The claim input for withdrawal 1 against the root settled for block 2,
    // checked with the native leaf and proof code.
    let proof = produce(&["withdrawal-proof", "--target", &db, "--index", "1", "--number", "2", "--root",
                          &hex::encode(s2.withdrawal_root), "--count", "2"])
    .unwrap();
    let siblings: Vec<[u8; 32]> =
        proof["siblings"].as_array().unwrap().iter().map(|v| h(v).0).collect();
    let leaf = withdrawal::leaf(CHAIN_ID, 1, &bob, 3_000_000);
    assert_eq!(h(&proof["withdrawal"]["leaf"]).0, leaf);
    assert_eq!(
        withdrawal::root_from_proof(&leaf, 1, &siblings.clone().try_into().unwrap()),
        Some(s2.withdrawal_root.0)
    );
    // Block 3 left the tree unchanged: the same proof holds against its root.
    let later = produce(&["withdrawal-proof", "--target", &db, "--index", "1"]).unwrap();
    assert_eq!(later["siblings"], proof["siblings"]);
    assert_eq!(later["number"], 3);
}
