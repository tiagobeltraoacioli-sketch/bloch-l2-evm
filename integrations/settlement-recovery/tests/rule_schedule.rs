// SPDX-License-Identifier: AGPL-3.0-or-later
//! Rule sets by height through the real database and the producer binary: blocks
//! under the activated rules, a block rewound when L1 replaced the program, the same
//! number under the next rules, an artifact of each side, and a rebuild from L1 data
//! alone that takes each block's rules from its settlement's configuration.
#![cfg(unix)]

use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::{MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP},
    data_availability::{da_commitment, decode_da_payload},
    deposits_hash,
    node_primitives::NodeBodyV2,
    proof_statement::{configuration_commitment, SettlementStatementV2, SettlementStatementV3},
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_pos_committee::{
    l2_settlement::Transaction as Settlement,
    transition::{funded::ADMISSION_PQ_KEY_BYTES, FundingInput, L2DataAvailability, L2Deposit, PosTransaction, TransferOutput},
};
use bloch_settlement_recovery::reconstruct::{derive_settled_blocks_with_reset, NativeBlockTransactions, ReconstructError};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_bloch-l2-produce-dev");
const CHAIN_ID: u64 = 700_770;
const RULE: &str = "1:1786656679:30000";

fn domain() -> String {
    hex::encode(MAINNET_DOMAIN)
}

fn produce(args: &[&str]) -> Result<Value, String> {
    let genesis = MAINNET_GENESIS_TIMESTAMP.to_string();
    let domain = domain();
    let out = Command::new(BIN)
        .args(args)
        .args(["--rules", "mainnet", "--domain", &domain, "--genesis-time", &genesis])
        .output()
        .unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes((&[9u8; 32]).into()).unwrap()
}

fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}

fn transfer(nonce: u64) -> String {
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
    let signature: Signature = key().sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
    hex::encode(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

fn deposit(seed: u8, to: Address, sats: u64) -> PosTransaction {
    PosTransaction::L2Deposit(L2Deposit {
        network_domain: [0x91; 32],
        funding_pubkey: vec![0x5a; ADMISSION_PQ_KEY_BYTES],
        inputs: vec![FundingInput { txid: [seed; 32], vout: 0 }],
        amount_sat: sats,
        recipient: to.into_array(),
        change: TransferOutput { value: 0, script_hash: [0; 32] },
        tx_bytes: 9_000,
        tip_millisat_per_gas: 0,
        signature: vec![1; 64],
    })
}

fn da(number: u64, payload: Vec<u8>) -> PosTransaction {
    PosTransaction::L2DataAvailability(L2DataAvailability {
        network_domain: [0x91; 32],
        funding_pubkey: vec![0x5a; ADMISSION_PQ_KEY_BYTES],
        inputs: vec![FundingInput { txid: [0xee; 32], vout: number as u32 }],
        l2_chain_id: CHAIN_ID,
        l2_block_number: number,
        payload,
        change: TransferOutput { value: 0, script_hash: [0; 32] },
        tx_bytes: 200_000,
        tip_millisat_per_gas: 0,
        signature: vec![1; 64],
    })
}

fn h(v: &Value, k: &str) -> B256 {
    v[k].as_str().unwrap_or_else(|| panic!("{k} in {v}")).parse().unwrap()
}

#[derive(Debug)]
struct Produced {
    number: u64,
    parent: B256,
    parent_root: B256,
    hash: B256,
    state_root: B256,
    anchor: B256,
    slot: u64,
    records: Vec<Value>,
    consumed: (u64, u64),
    payload: Option<Vec<u8>>,
    configuration: B256,
    withdrawals: (B256, u64),
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

fn settlement(block: &Produced, inbox_count: u64) -> PosTransaction {
    let deposits: Vec<DepositMint> = block.records.iter().map(mint).collect();
    let transactions: Vec<Bytes> = block.payload.as_deref().map(|p| decode_da_payload(p).unwrap()).unwrap_or_default();
    let statement = SettlementStatementV3 {
        base: SettlementStatementV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            domain: MAINNET_DOMAIN,
            configuration: block.configuration,
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
            l1_slot: block.slot,
            l1_height: 10 + block.number,
            source_commitment: B256::repeat_byte(9),
            inbox_root: B256::repeat_byte(10),
            inbox_count,
            consumed_start: block.consumed.0,
            consumed_end: block.consumed.1,
            body_commitment: B256::repeat_byte(11),
        },
        deposits_hash: deposits_hash(&deposits),
        transactions_root: NodeBodyV2 { deposits: vec![], transactions: transactions.clone() }.transactions_root(),
        receipts_root: B256::repeat_byte(12),
        user_tx_count: transactions.len() as u64,
        withdrawal_root: block.withdrawals.0,
        withdrawal_count: block.withdrawals.1,
        da_commitment: block.payload.as_deref().map_or(B256::ZERO, |p| da_commitment(CHAIN_ID, block.number, p)),
    };
    PosTransaction::L2SettlementAsync(Box::new(Settlement {
        proof_policy: [3; 32],
        statement: statement.encode().to_vec(),
        proof: [0; 356],
    }))
}

struct Chain {
    root: tempfile::TempDir,
    db: String,
    parent: B256,
    parent_root: B256,
}

impl Chain {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db").to_str().unwrap().to_string();
        let genesis = produce(&["init", "--target", &db]).unwrap();
        let head = produce(&["head", "--target", &db]).unwrap();
        assert_eq!(head["rules"], "base");
        Self { root, db, parent: h(&genesis, "hash"), parent_root: h(&head, "state_root") }
    }

    fn extend(&mut self, number: u64, rule_set: Option<&str>, records: Vec<Value>, consumed: (u64, u64), txs: &[String]) -> Result<Produced, String> {
        let anchor = B256::repeat_byte(0xa0 + number as u8);
        let deposits = self.root.path().join(format!("deposits-{number}-{rule_set:?}.json"));
        std::fs::write(&deposits, Value::from(records.clone()).to_string()).unwrap();
        let pool = self.root.path().join(format!("pool-{number}-{rule_set:?}.json"));
        std::fs::write(&pool, json!(txs).to_string()).unwrap();
        let slot = (100 * number).to_string();
        let (parent, anchor_hex) = (hex::encode(self.parent), hex::encode(anchor));
        let mut args = vec![
            "extend", "--target", &self.db, "--parent", &parent, "--anchor", &anchor_hex, "--deposits",
            deposits.to_str().unwrap(), "--txs", pool.to_str().unwrap(), "--timestamp-rule", RULE, "--anchor-slot", &slot,
        ];
        if let Some(rule_set) = rule_set {
            args.extend(["--rule-set", rule_set]);
        }
        let block = produce(&args)?;
        assert_eq!(block["number"], number);
        let next = rule_set == Some("next") || block["rules"] == "next";
        assert_eq!(block["rules"], if next { "next" } else { "base" });
        let spec = if next { ChainSpec::mainnet() } else { ChainSpec::mainnet_v1() };
        let payload = (!txs.is_empty()).then(|| {
            let out = self.root.path().join(format!("da-{number}-{}.hex", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            produce(&["da", "--target", &self.db, "--number", &number.to_string(), "--out", out.to_str().unwrap()]).unwrap();
            hex::decode(std::fs::read_to_string(&out).unwrap().trim()).unwrap()
        });
        let produced = Produced {
            number,
            parent: self.parent,
            parent_root: self.parent_root,
            hash: h(&block, "hash"),
            state_root: h(&block, "state_root"),
            anchor,
            slot: 100 * number,
            records,
            consumed,
            payload,
            configuration: configuration_commitment(&spec).unwrap(),
            withdrawals: (h(&block, "withdrawal_root"), block["withdrawal_count"].as_u64().unwrap()),
        };
        (self.parent, self.parent_root) = (produced.hash, produced.state_root);
        Ok(produced)
    }

    fn export(&self, number: u64, label: &str) -> Value {
        let out = self.root.path().join(format!("artifact-{number}-{label}"));
        produce(&["export", "--target", &self.db, "--number", &number.to_string(), "--out", out.to_str().unwrap()]).unwrap()
    }
}

fn l1_fixture(path: &std::path::Path, blocks: &[(u64, Vec<PosTransaction>)]) {
    let blocks: Vec<Value> = blocks
        .iter()
        .map(|(height, txs)| json!({"height": height, "transactions": txs.iter().map(|t| hex::encode(t.canonical_bytes())).collect::<Vec<_>>()}))
        .collect();
    std::fs::write(path, json!({ "blocks": blocks }).to_string()).unwrap();
}

#[test]
fn a_chain_crosses_the_swap_rewinds_the_unsettled_head_and_rebuilds_from_l1() {
    let mut chain = Chain::new();
    let d1 = deposit(0x11, sender(), 100_000_000);
    let d1_txid = d1.txid();
    let record = |height: u64, txid: [u8; 32]| json!({"height": height, "tx_index": 0, "txid": hex::encode(txid), "vout": 1,
        "sats": 100_000_000u64, "recipient": hex::encode(sender())});

    // Base rules: a deposit, then user transactions in the block before the swap.
    let b1 = chain.extend(1, Some("base"), vec![record(2, d1_txid)], (0, 1), &[]).unwrap();
    let b2 = chain.extend(2, None, vec![], (1, 1), &[transfer(0)]).unwrap();
    assert!(produce(&["head", "--target", &chain.db]).unwrap()["next_rules_from"].is_null());
    chain.export(2, "base");

    // Block 3 under the base rules is the block in flight when L1 replaces the program.
    let (parent, parent_root) = (chain.parent, chain.parent_root);
    let in_flight = chain.extend(3, Some("base"), vec![], (1, 1), &[transfer(1)]).unwrap();
    let spool = chain.root.path().join("spool");
    std::fs::create_dir(&spool).unwrap();
    assert!(
        produce(&["rewind", "--target", &chain.db, "--number", "2", "--hash", &hex::encode(in_flight.hash)]).unwrap_err().contains("not 2"),
        "a rewind names the head"
    );
    assert!(
        produce(&["rewind", "--target", &chain.db, "--number", "3", "--hash", &hex::encode(b2.hash)]).unwrap_err().contains("not the block"),
        "a rewind names the head's hash"
    );
    let rewound = produce(&[
        "rewind", "--target", &chain.db, "--number", "3", "--hash", &hex::encode(in_flight.hash), "--respool", spool.to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(rewound["number"], 2);
    assert_eq!(h(&rewound, "hash"), parent);
    assert_eq!(rewound["respooled"], 1);
    let entries: Vec<_> = std::fs::read_dir(&spool).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(std::fs::read_to_string(&entries[0]).unwrap().trim(), transfer(1));
    let head = produce(&["head", "--target", &chain.db]).unwrap();
    assert_eq!((head["number"].as_u64(), h(&head, "state_root")), (Some(2), parent_root));
    (chain.parent, chain.parent_root) = (parent, parent_root);

    // The same number under the next rules: another hash and state root, same receipts-relevant body.
    let b3 = chain.extend(3, Some("next"), vec![], (1, 1), &[transfer(1)]).unwrap();
    assert_ne!(b3.hash, in_flight.hash);
    assert_ne!(b3.state_root, in_flight.state_root);
    assert_eq!(produce(&["head", "--target", &chain.db]).unwrap()["next_rules_from"], 3);
    assert_eq!(produce(&["head", "--target", &chain.db]).unwrap()["rules"], "next");
    chain.export(3, "next");

    // The switch is one-way and every later process derives it from the database.
    assert!(chain.extend(4, Some("base"), vec![], (1, 1), &[]).unwrap_err().contains("past the switch"));
    let b4 = chain.extend(4, None, vec![], (1, 1), &[transfer(2)]).unwrap();
    chain.export(4, "next");
    chain.export(2, "base-again");

    // A rebuild from native data reproduces all of it, with no rule set given.
    let d = chain.root.path().join("l1.json");
    let blocks = vec![
        (2, vec![d1.clone()]),
        (3, vec![settlement(&b1, 1)]),
        (4, vec![da(2, b2.payload.clone().unwrap())]),
        (5, vec![settlement(&b2, 1)]),
        (6, vec![da(3, in_flight.payload.clone().unwrap())]),
        (7, vec![da(4, b4.payload.clone().unwrap())]),
        (8, vec![settlement(&b3, 1)]),
        (9, vec![settlement(&b4, 1)]),
    ];
    l1_fixture(&d, &blocks);
    let rebuilt = chain.root.path().join("rebuilt");
    let report = produce(&["reconstruct", "--target", rebuilt.to_str().unwrap(), "--l1", d.to_str().unwrap(), "--timestamp-rule", RULE]).unwrap();
    assert_eq!(report["settled"], 4, "{report}");
    assert_eq!(report["next_rules_from"], 3);
    assert_eq!(h(&report, "head"), b4.hash);
    let rules: Vec<_> = report["blocks"].as_array().unwrap().iter().map(|b| b["rules"].as_str().unwrap()).collect();
    assert_eq!(rules, ["base", "base", "next", "next"]);
    let rebuilt_head = produce(&["head", "--target", rebuilt.to_str().unwrap()]).unwrap();
    assert_eq!(h(&rebuilt_head, "hash"), b4.hash);
    assert_eq!(rebuilt_head["next_rules_from"], 3);

    // The rebuilt block's rules come from L1: another configuration does not rebuild.
    let mut wrong = settlement(&b3, 1);
    if let PosTransaction::L2SettlementAsync(tx) = &mut wrong {
        tx.statement[22 + 96..22 + 128].copy_from_slice(&[0x44; 32]);
    }
    let mut tampered = blocks.clone();
    tampered[6] = (8, vec![wrong]);
    l1_fixture(&d, &tampered);
    let bad = chain.root.path().join("rebuilt-bad");
    assert!(produce(&["reconstruct", "--target", bad.to_str().unwrap(), "--l1", d.to_str().unwrap(), "--timestamp-rule", RULE])
        .unwrap_err()
        .contains("unexpected configuration"));

    // A block under the base rules after the next rules does not rebuild either.
    let mut late_base = b4;
    late_base.configuration = configuration_commitment(&ChainSpec::mainnet_v1()).unwrap();
    let mut tampered = blocks.clone();
    tampered[7] = (9, vec![settlement(&late_base, 1)]);
    l1_fixture(&d, &tampered);
    let bad = chain.root.path().join("rebuilt-bad-2");
    assert!(produce(&["reconstruct", "--target", bad.to_str().unwrap(), "--l1", d.to_str().unwrap(), "--timestamp-rule", RULE])
        .unwrap_err()
        .contains("unexpected configuration"));

    // The next rule set's vaults hold the sweep code from the switch on.
    assert_eq!(in_flight.configuration, configuration_commitment(&ChainSpec::mainnet_v1()).unwrap());
    assert_eq!(b3.configuration, configuration_commitment(&ChainSpec::mainnet()).unwrap());
}

#[test]
fn a_rewound_chain_equals_a_chain_that_never_built_the_block() {
    let mut rewound = Chain::new();
    let mut straight = Chain::new();
    let d1 = deposit(0x21, sender(), 100_000_000);
    let record = json!({"height": 2, "tx_index": 0, "txid": hex::encode(d1.txid()), "vout": 1, "sats": 100_000_000u64, "recipient": hex::encode(sender())});
    for chain in [&mut rewound, &mut straight] {
        chain.extend(1, Some("base"), vec![record.clone()], (0, 1), &[]).unwrap();
        chain.extend(2, Some("base"), vec![], (1, 1), &[transfer(0)]).unwrap();
    }
    // Several rounds, so a leftover index or trie node from the removed block would show.
    for _ in 0..3 {
        let (parent, root) = (rewound.parent, rewound.parent_root);
        let doomed = rewound.extend(3, Some("base"), vec![], (1, 1), &[transfer(1), transfer(2)]).unwrap();
        produce(&["rewind", "--target", &rewound.db, "--number", "3", "--hash", &hex::encode(doomed.hash)]).unwrap();
        (rewound.parent, rewound.parent_root) = (parent, root);
    }
    let a = rewound.extend(3, Some("base"), vec![], (1, 1), &[transfer(1)]).unwrap();
    let b = straight.extend(3, Some("base"), vec![], (1, 1), &[transfer(1)]).unwrap();
    assert_eq!((a.hash, a.state_root), (b.hash, b.state_root));
    let a = rewound.extend(4, Some("next"), vec![], (1, 1), &[transfer(2)]).unwrap();
    let b = straight.extend(4, Some("next"), vec![], (1, 1), &[transfer(2)]).unwrap();
    assert_eq!((a.hash, a.state_root), (b.hash, b.state_root));
    assert_eq!(rewound.export(4, "a")["hash"], straight.export(4, "b")["hash"]);
    let address = hex::encode(sender());
    assert_eq!(
        produce(&["account", "--target", &rewound.db, "--address", &address]).unwrap(),
        produce(&["account", "--target", &straight.db, "--address", &address]).unwrap()
    );
}

#[test]
fn a_rewind_of_the_first_next_block_forgets_the_switch() {
    let mut chain = Chain::new();
    chain.extend(1, Some("base"), vec![], (0, 0), &[]).unwrap();
    let (parent, root) = (chain.parent, chain.parent_root);
    let first = chain.extend(2, Some("next"), vec![], (0, 0), &[]).unwrap();
    assert_eq!(produce(&["head", "--target", &chain.db]).unwrap()["next_rules_from"], 2);
    produce(&["rewind", "--target", &chain.db, "--number", "2", "--hash", &hex::encode(first.hash)]).unwrap();
    assert!(produce(&["head", "--target", &chain.db]).unwrap()["next_rules_from"].is_null());
    (chain.parent, chain.parent_root) = (parent, root);
    let again = chain.extend(2, Some("base"), vec![], (0, 0), &[]).unwrap();
    assert_ne!(again.hash, first.hash);
}

fn native(height: u64, txs: Vec<PosTransaction>) -> NativeBlockTransactions {
    NativeBlockTransactions { height, transactions: txs.iter().map(|t| t.canonical_bytes()).collect() }
}

fn bare(number: u64, parent: B256, root: B256, hash: u8) -> Produced {
    Produced {
        number,
        parent,
        parent_root: root,
        hash: B256::repeat_byte(hash),
        state_root: B256::repeat_byte(hash ^ 0xff),
        anchor: B256::repeat_byte(0xa0 + number as u8),
        slot: 100 * number,
        records: vec![],
        consumed: (0, 0),
        payload: None,
        configuration: configuration_commitment(&ChainSpec::mainnet_v1()).unwrap(),
        withdrawals: (bloch_l2_evm::withdrawal::empty_withdrawal_root(), 0),
    }
}

#[test]
fn a_head_reset_drops_the_discarded_tail_from_a_rebuild() {
    let (g_hash, g_root) = (B256::repeat_byte(0x10), B256::repeat_byte(0x20));
    let k = bare(1, g_hash, g_root, 0x31);
    let bad = bare(2, k.hash, k.state_root, 0x32);
    let bad_tail = bare(3, bad.hash, bad.state_root, 0x33);
    let new = bare(2, k.hash, k.state_root, 0x42);
    let blocks = vec![
        native(1, vec![settlement(&k, 0)]),
        native(2, vec![settlement(&bad, 0)]),
        native(3, vec![settlement(&bad_tail, 0)]),
        native(4, vec![settlement(&new, 0)]),
    ];
    // Without a reset, a settlement that does not extend the head is refused as ever.
    assert!(matches!(
        derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, None),
        Err(ReconstructError::Successor { number: 2, .. })
    ));
    let derived = derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, Some(1)).unwrap();
    assert_eq!(derived.iter().map(|b| (b.number, b.header_hash)).collect::<Vec<_>>(), [(1, k.hash), (2, new.hash)]);

    // Back to the genesis.
    let genesis_child = bare(1, g_hash, g_root, 0x51);
    let blocks = vec![native(1, vec![settlement(&k, 0)]), native(2, vec![settlement(&bad, 0)]), native(3, vec![settlement(&genesis_child, 0)])];
    let derived = derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, Some(0)).unwrap();
    assert_eq!(derived.iter().map(|b| b.header_hash).collect::<Vec<_>>(), [genesis_child.hash]);

    // A settlement that names another parent than the kept block is not a reset.
    let foreign = bare(2, B256::repeat_byte(0x77), k.state_root, 0x42);
    let blocks = vec![native(1, vec![settlement(&k, 0)]), native(2, vec![settlement(&bad, 0)]), native(3, vec![settlement(&foreign, 0)])];
    assert!(matches!(
        derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, Some(1)),
        Err(ReconstructError::Successor { number: 2, .. })
    ));
    // Nor is the normal next block at the kept height.
    let blocks = vec![native(1, vec![settlement(&k, 0)]), native(2, vec![settlement(&new, 0)])];
    assert_eq!(derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, Some(1)).unwrap().len(), 2);
}
