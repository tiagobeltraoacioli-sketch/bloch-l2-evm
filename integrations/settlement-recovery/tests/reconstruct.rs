// SPDX-License-Identifier: AGPL-3.0-or-later
//! M3 end to end: an L2 chain produced with deposits and user transactions is
//! rebuilt from native (L1) block data only — deposits (0x14), DA batches
//! (0x15) and V3 settlements (0x13) — by `bloch-l2-produce-dev reconstruct`,
//! which must reproduce every settled header hash and state root. Missing,
//! tampered, same-block and foreign-chain batches, and a wrong settled root,
//! are refused.
#![cfg(unix)]

use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    data_availability::{da_commitment, decode_da_payload},
    deposits_hash,
    node_primitives::NodeBodyV2,
    proof_statement::{SettlementStatementV2, SettlementStatementV3},
    withdrawal::{verify_withdrawal_proof, withdrawal_leaf, INITIATE_WITHDRAWAL_SELECTOR, L2_TO_L1_MESSAGE_PASSER},
    DepositMint, DepositProvenance,
};
use bloch_pos_committee::{
    l2_settlement::Transaction as Settlement,
    transition::{
        funded::ADMISSION_PQ_KEY_BYTES, FundingInput, L2DataAvailability, L2Deposit, PosTransaction, TransferOutput,
    },
};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::{path::Path, process::Command};

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

fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes((&[i + 1; 32]).into()).unwrap()
}
fn sender(i: u8) -> Address {
    Address::from_public_key(key(i).verifying_key())
}
fn transfer(i: u8, nonce: u64) -> String {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        to: TxKind::Call(Address::repeat_byte(0x55)),
        value: U256::from(1_000u64 + nonce),
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1,
        ..Default::default()
    };
    let signature: Signature = key(i)
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

/// `initiateWithdrawal(l1_recipient)` with `sats` (M4 outbox).
fn withdraw(i: u8, nonce: u64, l1_recipient: B256, sats: u64) -> String {
    let mut input = INITIATE_WITHDRAWAL_SELECTOR.to_vec();
    input.extend_from_slice(l1_recipient.as_slice());
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        to: TxKind::Call(L2_TO_L1_MESSAGE_PASSER),
        value: bloch_l2_evm::sats_to_wei(sats),
        input: input.into(),
        gas_limit: 100_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1,
        ..Default::default()
    };
    let signature: Signature = key(i)
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

/// A canonically shaped native deposit. Reconstruction trusts finalized
/// native blocks, so the authorization bytes are placeholders.
fn deposit(seed: u8, to: Address, sats: u64) -> PosTransaction {
    PosTransaction::L2Deposit(L2Deposit {
        network_domain: [0x91; 32],
        funding_pubkey: vec![0x5a; ADMISSION_PQ_KEY_BYTES],
        inputs: vec![FundingInput {
            txid: [seed; 32],
            vout: 0,
        }],
        amount_sat: sats,
        recipient: to.into_array(),
        change: TransferOutput {
            value: 0,
            script_hash: [0; 32],
        },
        tx_bytes: 9_000,
        tip_millisat_per_gas: 0,
        signature: vec![1; 64],
    })
}
/// Inbox record JSON for the producer, as the native chain derives it.
fn record(tx: &PosTransaction, height: u64, tx_index: u32) -> Value {
    let PosTransaction::L2Deposit(d) = tx else {
        unreachable!()
    };
    json!({"height": height, "tx_index": tx_index, "txid": hex::encode(tx.txid()), "vout": 1,
           "sats": d.amount_sat, "recipient": hex::encode(d.recipient)})
}
fn mint(r: &Value) -> DepositMint {
    DepositMint {
        recipient: Address::from_slice(&hex::decode(r["recipient"].as_str().unwrap()).unwrap()),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: r["height"].as_u64().unwrap(),
            l1_tx_index: r["tx_index"].as_u64().unwrap() as u32,
            l1_txid: hex::decode(r["txid"].as_str().unwrap()).unwrap().try_into().unwrap(),
            l1_vout: 1,
            l1_sats: r["sats"].as_u64().unwrap(),
        },
    }
}
fn da(number: u64, payload: Vec<u8>, chain: u64) -> PosTransaction {
    PosTransaction::L2DataAvailability(L2DataAvailability {
        network_domain: [0x91; 32],
        funding_pubkey: vec![0x5a; ADMISSION_PQ_KEY_BYTES],
        inputs: vec![FundingInput {
            txid: [0xee; 32],
            vout: number as u32,
        }],
        l2_chain_id: chain,
        l2_block_number: number,
        payload,
        change: TransferOutput {
            value: 0,
            script_hash: [0; 32],
        },
        tx_bytes: 200_000,
        tip_millisat_per_gas: 0,
        signature: vec![1; 64],
    })
}
fn h(v: &Value, k: &str) -> B256 {
    v[k].as_str().unwrap().parse().unwrap()
}

/// One produced L2 block and what the native chain would settle for it.
struct Produced {
    number: u64,
    parent: B256,
    parent_root: B256,
    hash: B256,
    state_root: B256,
    anchor: B256,
    records: Vec<Value>,
    consumed: (u64, u64),
    payload: Option<Vec<u8>>,
    /// Outbox (root, count) after the block, as the producer reports it.
    withdrawals: (B256, u64),
}

fn settlement(block: &Produced, inbox_count: u64) -> PosTransaction {
    let deposits: Vec<DepositMint> = block.records.iter().map(mint).collect();
    let transactions: Vec<Bytes> = block
        .payload
        .as_deref()
        .map(|p| decode_da_payload(p).unwrap())
        .unwrap_or_default();
    let statement = SettlementStatementV3 {
        base: SettlementStatementV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            domain: B256::repeat_byte(0xd3),
            configuration: B256::repeat_byte(4),
            program_elf_keccak: B256::repeat_byte(5),
            program_vkey_koalabear: B256::repeat_byte(6),
            program_vkey_bn254: B256::repeat_byte(7),
            previous_settlement: B256::repeat_byte(8),
            chain_id: CHAIN_ID,
            l2_number: block.number,
            l2_parent_hash: block.parent,
            l2_previous_state_root: block.parent_root,
            l2_header_hash: block.hash,
            l2_state_root: block.state_root,
            l1_block: block.anchor,
            l1_slot: 10 + block.number,
            l1_height: 10 + block.number,
            source_commitment: B256::repeat_byte(9),
            inbox_root: B256::repeat_byte(10),
            inbox_count,
            consumed_start: block.consumed.0,
            consumed_end: block.consumed.1,
            body_commitment: B256::repeat_byte(11),
        },
        deposits_hash: deposits_hash(&deposits),
        transactions_root: NodeBodyV2 {
            deposits: vec![],
            transactions: transactions.clone(),
        }
        .transactions_root(),
        receipts_root: B256::repeat_byte(12),
        user_tx_count: transactions.len() as u64,
        withdrawal_root: block.withdrawals.0,
        withdrawal_count: block.withdrawals.1,
        da_commitment: block
            .payload
            .as_deref()
            .map_or(B256::ZERO, |p| da_commitment(CHAIN_ID, block.number, p)),
    };
    PosTransaction::L2SettlementAsync(Box::new(Settlement {
        proof_policy: [3; 32],
        statement: statement.encode().to_vec(),
        proof: [0; 356],
    }))
}

fn fixture(path: &Path, blocks: &[(u64, Vec<PosTransaction>)]) {
    let blocks: Vec<Value> = blocks
        .iter()
        .map(|(height, txs)| {
            json!({"height": height, "transactions": txs.iter().map(|t| hex::encode(t.canonical_bytes())).collect::<Vec<_>>()})
        })
        .collect();
    std::fs::write(path, json!({ "blocks": blocks }).to_string()).unwrap();
}

#[test]
fn l2_state_is_rebuilt_from_l1_deposits_da_batches_and_settlements() {
    let root = tempfile::tempdir().unwrap();
    let dir = |name: &str| root.path().join(name).to_str().unwrap().to_string();
    let db = dir("producer");
    let genesis = produce(&["init", "--target", &db]).unwrap();
    let genesis_head = produce(&["head", "--target", &db]).unwrap();

    // Native deposits: two in native block 2, one in native block 5.
    let d1 = deposit(0x11, sender(0), 100_000_000);
    let d2 = deposit(0x12, sender(1), 200_000_000);
    let d3 = deposit(0x13, sender(2), 300_000_000);
    let inbox = [record(&d1, 2, 0), record(&d2, 2, 1), record(&d3, 5, 0)];

    // L2 block 1: deposits only. L2 block 2: two user transfers. L2 block 3:
    // the third deposit funds a sender that spends it in the same block, and
    // two withdrawals go through the outbox (M4).
    let (l1_alice, l1_bob) = (B256::repeat_byte(0x77), B256::repeat_byte(0x78));
    type Step = (Vec<Value>, (u64, u64), Vec<String>); // inbox records, consumed range, user transactions
    let plan: Vec<Step> = vec![
        (inbox[..2].to_vec(), (0, 2), vec![]),
        (vec![], (2, 2), vec![transfer(0, 0), transfer(0, 1)]),
        (
            inbox[2..].to_vec(),
            (2, 3),
            vec![
                transfer(1, 0),
                transfer(2, 0),
                withdraw(0, 2, l1_alice, 5_000_000),
                withdraw(2, 1, l1_bob, 7_000_000),
            ],
        ),
    ];
    let mut produced = Vec::new();
    let (mut parent, mut parent_root) = (h(&genesis, "hash"), h(&genesis_head, "state_root"));
    for (i, (records, consumed, txs)) in plan.into_iter().enumerate() {
        let number = i as u64 + 1;
        let anchor = B256::repeat_byte(0xa0 + number as u8);
        let deposits = root.path().join(format!("deposits-{number}.json"));
        std::fs::write(&deposits, Value::from(records.clone()).to_string()).unwrap();
        let pool = root.path().join(format!("pool-{number}.json"));
        std::fs::write(&pool, json!(txs).to_string()).unwrap();
        let block = produce(&[
            "extend",
            "--target",
            &db,
            "--parent",
            &hex::encode(parent),
            "--anchor",
            &hex::encode(anchor),
            "--deposits",
            deposits.to_str().unwrap(),
            "--txs",
            pool.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(block["transactions"].as_u64().unwrap(), txs.len() as u64, "{block}");
        let payload = if txs.is_empty() {
            let out = root.path().join(format!("da-{number}.hex"));
            assert!(produce(&[
                "da",
                "--target",
                &db,
                "--number",
                &number.to_string(),
                "--out",
                out.to_str().unwrap()
            ])
            .unwrap_err()
            .contains("nothing to publish"));
            None
        } else {
            let out = root.path().join(format!("da-{number}.hex"));
            let info = produce(&[
                "da",
                "--target",
                &db,
                "--number",
                &number.to_string(),
                "--out",
                out.to_str().unwrap(),
            ])
            .unwrap();
            let payload = hex::decode(std::fs::read_to_string(&out).unwrap().trim()).unwrap();
            assert_eq!(h(&info, "da_commitment"), da_commitment(CHAIN_ID, number, &payload));
            assert_eq!(info["transactions"], txs.len());
            let decoded = decode_da_payload(&payload).unwrap();
            // Exactly the included transactions, in block (selection) order.
            let included: Vec<String> = decoded
                .iter()
                .map(|tx| hex::encode(alloy_primitives::keccak256(tx)))
                .collect();
            assert_eq!(
                Value::from(included),
                block["included"],
                "DA batch is the body, in order"
            );
            Some(payload)
        };
        let p = Produced {
            number,
            parent,
            parent_root,
            hash: h(&block, "hash"),
            state_root: h(&block, "state_root"),
            anchor,
            records,
            consumed,
            payload,
            withdrawals: (
                h(&block, "withdrawal_root"),
                block["withdrawal_count"].as_u64().unwrap(),
            ),
        };
        assert_eq!(
            block["withdrawals"].as_array().unwrap().len() as u64,
            if number == 3 { 2 } else { 0 }
        );
        (parent, parent_root) = (p.hash, p.state_root);
        produced.push(p);
    }

    // The native chain: deposits, DA one block before each user-tx settlement.
    let (b1, b2, b3) = (&produced[0], &produced[1], &produced[2]);
    let da2 = da(2, b2.payload.clone().unwrap(), CHAIN_ID);
    let da3 = da(3, b3.payload.clone().unwrap(), CHAIN_ID);
    let honest = vec![
        (2, vec![d1.clone(), d2.clone()]),
        (3, vec![settlement(b1, 2)]),
        (4, vec![da2.clone()]),
        (5, vec![d3.clone(), settlement(b2, 3)]),
        (6, vec![da3.clone()]),
        (7, vec![settlement(b3, 3)]),
        (8, vec![]),
    ];
    let l1 = root.path().join("l1.json");
    fixture(&l1, &honest);
    let report = produce(&["reconstruct", "--target", &dir("rebuilt"), "--l1", l1.to_str().unwrap()]).unwrap();
    assert_eq!(report["genesis"], genesis["hash"]);
    assert_eq!(report["settled"], 3, "{report}");
    assert_eq!(h(&report, "head"), b3.hash);
    for (rebuilt, original) in report["blocks"].as_array().unwrap().iter().zip(&produced) {
        assert_eq!(h(rebuilt, "hash"), original.hash);
        assert_eq!(h(rebuilt, "state_root"), original.state_root);
    }
    assert_eq!(report["blocks"][1]["transactions"], 2);
    assert_eq!(report["blocks"][2]["deposits"], 1);
    assert_eq!(report["blocks"][2]["withdrawal_count"], 2);
    assert_eq!(h(&report["blocks"][2], "withdrawal_root"), b3.withdrawals.0);
    // Blocks 1 and 2 have no withdrawal: the empty tree.
    assert_eq!(b1.withdrawals, (bloch_l2_evm::withdrawal::empty_withdrawal_root(), 0));
    assert_eq!(b2.withdrawals, b1.withdrawals);

    // Claim input: the proof of withdrawal 1 against the settled root of L2
    // block 3, rebuilt from receipts and checked against the outbox state.
    let (root3, count3) = (hex::encode(b3.withdrawals.0), b3.withdrawals.1.to_string());
    let proof = produce(&[
        "withdrawal-proof",
        "--target",
        &db,
        "--index",
        "1",
        "--number",
        "3",
        "--root",
        &root3,
        "--count",
        &count3,
    ])
    .unwrap();
    assert_eq!(proof["withdrawal"]["nonce"], 1);
    assert_eq!(proof["withdrawal"]["sats"], 7_000_000);
    assert_eq!(proof["withdrawal"]["l2_block"], 3);
    assert_eq!(h(&proof["withdrawal"], "l1_recipient"), l1_bob);
    let siblings: Vec<B256> = proof["siblings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    let leaf = withdrawal_leaf(CHAIN_ID, 1, l1_bob, 7_000_000);
    assert!(verify_withdrawal_proof(
        leaf,
        1,
        &siblings.try_into().unwrap(),
        b3.withdrawals.0
    ));
    let head = produce(&["head", "--target", &db]).unwrap();
    assert_eq!(
        (h(&head, "withdrawal_root"), head["withdrawal_count"].as_u64()),
        (b3.withdrawals.0, Some(2))
    );
    // Refused: a root the chain never had, a missing leaf, a block before it.
    let wrong = hex::encode(B256::repeat_byte(9));
    assert!(produce(&[
        "withdrawal-proof",
        "--target",
        &db,
        "--index",
        "0",
        "--root",
        &wrong,
        "--count",
        "2"
    ])
    .unwrap_err()
    .contains("differ"));
    assert!(produce(&["withdrawal-proof", "--target", &db, "--index", "2"])
        .unwrap_err()
        .contains("does not exist"));
    assert!(
        produce(&["withdrawal-proof", "--target", &db, "--index", "0", "--number", "2"])
            .unwrap_err()
            .contains("does not exist")
    );
    // The rebuilt database is a usable canonical L2 database.
    let head = produce(&["head", "--target", &dir("rebuilt")]).unwrap();
    assert_eq!(
        (head["number"].as_u64(), h(&head, "state_root")),
        (Some(3), b3.state_root)
    );

    // The same native blocks read from a native follower store (index +
    // blocks/<id>.bin, line i = height i) rebuild the same chain.
    let follower = root.path().join("follower");
    write_follower_store(&follower, &honest);
    let from_store = produce(&[
        "reconstruct",
        "--target",
        &dir("rebuilt-follower"),
        "--l1-follower",
        follower.to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(from_store["blocks"], report["blocks"]);

    // A prefix of L1 rebuilds only what was settled in it.
    fixture(&l1, &honest[..3]);
    let report = produce(&["reconstruct", "--target", &dir("prefix"), "--l1", l1.to_str().unwrap()]).unwrap();
    assert_eq!(report["settled"], 1);

    let refuse = |name: &str, blocks: Vec<(u64, Vec<PosTransaction>)>, needle: &str| {
        let path = root.path().join(format!("{name}.json"));
        fixture(&path, &blocks);
        let error = produce(&["reconstruct", "--target", &dir(name), "--l1", path.to_str().unwrap()]).unwrap_err();
        assert!(error.contains(needle), "{name}: {error}");
    };
    // Missing DA batch.
    let mut missing = honest.clone();
    missing[2].1.clear();
    refuse("missing-da", missing, "no L1 data-availability batch");
    // Tampered batch (reordered transactions): another commitment.
    let mut reordered = decode_da_payload(b2.payload.as_ref().unwrap()).unwrap();
    reordered.reverse();
    let tampered = bloch_l2_evm::data_availability::encode_da_payload(&reordered).unwrap();
    let mut wrong = honest.clone();
    wrong[2].1 = vec![da(2, tampered, CHAIN_ID)];
    refuse("tampered-da", wrong, "no L1 data-availability batch");
    // DA in the same native block as its settlement is not yet available.
    let mut same = honest.clone();
    same[2].1.clear();
    same[3].1.insert(0, da2.clone());
    refuse("same-block-da", same, "no L1 data-availability batch");
    // DA published for another L2 chain does not count.
    let mut foreign = honest.clone();
    foreign[2].1 = vec![da(2, b2.payload.clone().unwrap(), CHAIN_ID + 1)];
    refuse("foreign-chain-da", foreign, "no L1 data-availability batch");
    // A settled state root the L1 data does not produce is refused.
    let mut lie = clone_produced(b1);
    lie.state_root = B256::repeat_byte(0x66);
    let mut bad_root = honest.clone();
    bad_root[1].1 = vec![settlement(&lie, 2)];
    bad_root.truncate(2);
    refuse("wrong-root", bad_root, "differ from settled");
    // A settled withdrawal root the L1 data does not produce is refused.
    let mut lie = clone_produced(b3);
    lie.withdrawals.0 = B256::repeat_byte(0x67);
    let mut bad_withdrawals = honest.clone();
    bad_withdrawals[5].1 = vec![settlement(&lie, 3)];
    refuse("wrong-withdrawal-root", bad_withdrawals, "withdrawal root");
    // A settlement whose withdrawal root changes without new withdrawals.
    let mut lie = clone_produced(b2);
    lie.withdrawals.0 = B256::repeat_byte(0x68);
    let mut moved = honest.clone();
    moved[3].1 = vec![d3.clone(), settlement(&lie, 3)];
    refuse("moved-withdrawal-root", moved, "do not extend");
    // A deposit the settlement claims but L1 never carried.
    let mut no_deposit = honest.clone();
    no_deposit[0].1.pop();
    refuse("missing-deposit", no_deposit, "consumes unknown inbox records");
}

fn clone_produced(p: &Produced) -> Produced {
    Produced {
        number: p.number,
        parent: p.parent,
        parent_root: p.parent_root,
        hash: p.hash,
        state_root: p.state_root,
        anchor: p.anchor,
        records: p.records.clone(),
        consumed: p.consumed,
        payload: p.payload.clone(),
        withdrawals: p.withdrawals,
    }
}

/// A follower-shaped store of envelopes carrying `blocks` (empty blocks fill
/// the heights in between). Headers are not signed: the reconstruction reads
/// transactions from a store the follower already verified.
fn write_follower_store(dir: &Path, blocks: &[(u64, Vec<PosTransaction>)]) {
    use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body, VERSION_G4};
    std::fs::create_dir_all(dir.join("blocks")).unwrap();
    let mut index = String::new();
    let mut parent = [0u8; 32];
    let last = blocks.last().unwrap().0;
    for height in 1..=last {
        let transactions = blocks
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, txs)| txs.iter().map(PosTransaction::canonical_bytes).collect())
            .unwrap_or_default();
        let envelope = BlockEnvelope {
            header: BlockHeaderV4 {
                version: VERSION_G4,
                parent,
                state_root: [0; 32],
                body_root: [0; 32],
                slot: height,
                proposer_index: 0,
                randao_reveal: [0; 32],
                randao_mix: [0; 32],
                justified_root: [0; 32],
                finalized_root: [0; 32],
                attestation_root: [0; 32],
                coherence_root: [0; 32],
            },
            proposer_sig: vec![],
            body: Body {
                transactions,
                attestations: vec![],
            },
        };
        let id = *envelope.block_id().as_bytes();
        std::fs::write(
            dir.join("blocks").join(format!("{}.bin", hex::encode(id))),
            bloch_pos_node::codec::encode_envelope(&envelope),
        )
        .unwrap();
        index.push_str(&format!("{}\n", hex::encode(id)));
        parent = id;
    }
    std::fs::write(dir.join("index"), index).unwrap();
}
