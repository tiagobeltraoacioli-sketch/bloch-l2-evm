// SPDX-License-Identifier: AGPL-3.0-or-later
//! Rule sets by height through the real database and the producer binary: blocks
//! under the activated rules, a block rewound when L1 replaced the program, the same
//! number under the next rules, an artifact of each side, and a rebuild from L1 data
//! alone that takes each block's rules from its settlement's configuration.
#![cfg(unix)]

use alloy_consensus::{private::alloy_eips::eip2718::Encodable2718, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::{MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP, MAINNET_NEXT_RULES_RELEASABLE},
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

/// The release rules once the owner has set the fee-sweep recipient; until then
/// the rehearsal network, whose next rules sweep to the placeholder (agent 163 B-1).
const RULES: &str = if MAINNET_NEXT_RULES_RELEASABLE { "mainnet" } else { "mainnet-rehearsal" };

fn produce(args: &[&str]) -> Result<Value, String> {
    let genesis = MAINNET_GENESIS_TIMESTAMP.to_string();
    let domain = domain();
    let out = Command::new(BIN)
        .args(args)
        .args(["--rules", RULES, "--domain", &domain, "--genesis-time", &genesis])
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
        // One repeated byte as ever for the short chains; the floor chains have several hundred blocks.
        let anchor = match u8::try_from(number).ok().and_then(|n| 0xa0u8.checked_add(n)) {
            Some(byte) => B256::repeat_byte(byte),
            None => {
                let mut bytes = [0xa5u8; 32];
                bytes[24..].copy_from_slice(&number.to_be_bytes());
                B256::from(bytes)
            }
        };
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
        let spec = if next { ChainSpec::mainnet_next_or_rehearsal() } else { ChainSpec::mainnet_v1() };
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

    /// The head's fees as the producer reports them (`fees`).
    fn fees(&self) -> Value {
        produce(&["fees", "--target", &self.db]).unwrap()
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
    assert_eq!(b3.configuration, configuration_commitment(&ChainSpec::mainnet_next_or_rehearsal()).unwrap());
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

// ── Forced inclusion (candidate): the rebuild mirrors the native forced queue ──

fn forced_tx(seed: u8, envelope: Vec<u8>) -> PosTransaction {
    PosTransaction::L2ForcedTransaction(bloch_pos_committee::transition::L2ForcedTransaction {
        network_domain: [0x91; 32],
        funding_pubkey: vec![0x5a; ADMISSION_PQ_KEY_BYTES],
        inputs: vec![FundingInput { txid: [seed; 32], vout: 0 }],
        l2_chain_id: CHAIN_ID,
        gas_limit: 21_000,
        max_surcharge_sat: 0,
        envelope,
        change: TransferOutput { value: 0, script_hash: [0; 32] },
        tx_bytes: 9_000,
        tip_millisat_per_gas: 0,
        signature: vec![1; 64],
    })
}

/// `settlement` with the deposits slot bound to these consumed forced records.
fn settlement_forced(block: &Produced, records: &[bloch_l2_evm::forced_inclusion::ForcedRecord]) -> PosTransaction {
    let PosTransaction::L2SettlementAsync(mut tx) = settlement(block, 0) else { unreachable!() };
    let mut statement = SettlementStatementV3::decode(&tx.statement).unwrap();
    statement.deposits_hash = bloch_l2_evm::forced_inclusion::inbox_hash(statement.deposits_hash, records);
    tx.statement = statement.encode().to_vec();
    PosTransaction::L2SettlementAsync(tx)
}

fn record_of(height: u64, tx: &PosTransaction) -> bloch_l2_evm::forced_inclusion::ForcedRecord {
    let PosTransaction::L2ForcedTransaction(forced) = tx else { unreachable!() };
    bloch_l2_evm::forced_inclusion::ForcedRecord {
        l1_height: height,
        l1_txid: tx.txid(),
        envelope_hash: alloy_primitives::keccak256(&forced.envelope),
        gas_limit: forced.gas_limit,
    }
}

#[test]
fn a_rebuild_finds_the_forced_records_each_settlement_consumed() {
    let (g_hash, g_root) = (B256::repeat_byte(0x10), B256::repeat_byte(0x20));
    let (a, b) = (forced_tx(1, vec![0x02, 0xaa]), forced_tx(2, vec![0x02, 0xbb]));
    let (ra, rb) = (record_of(1, &a), record_of(1, &b));
    let one = bare(1, g_hash, g_root, 0x31);
    let two = bare(2, one.hash, one.state_root, 0x32);
    let three = bare(3, two.hash, two.state_root, 0x33);
    // Both queued at height 1; the first settlement anchored before them consumes none, the second
    // consumes only the first record, the third the second.
    let blocks = vec![
        native(1, vec![a.clone(), b.clone(), settlement(&one, 0)]),
        native(2, vec![settlement_forced(&two, &[ra])]),
        native(3, vec![settlement_forced(&three, &[rb])]),
    ];
    let derived = derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, None).unwrap();
    let consumed: Vec<Vec<_>> = derived.iter().map(|d| d.forced.iter().map(|f| f.record).collect()).collect();
    assert_eq!(consumed, vec![vec![], vec![ra], vec![rb]]);
    assert_eq!(derived[1].forced[0].envelope.as_ref(), &[0x02, 0xaa]);
    // Both at once.
    let blocks = vec![native(1, vec![a.clone(), b.clone(), settlement_forced(&one, &[ra, rb])])];
    let derived = derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, None).unwrap();
    assert_eq!(derived[0].forced.len(), 2);
    // Out of queue order, or a record that was never queued: refused.
    let blocks = vec![native(1, vec![a.clone(), b.clone(), settlement_forced(&one, &[rb])])];
    assert!(matches!(derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, None), Err(ReconstructError::Deposits { number: 1 })));
    let blocks = vec![native(1, vec![settlement_forced(&one, &[ra])])];
    assert!(matches!(derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, None), Err(ReconstructError::Deposits { number: 1 })));
}

#[test]
fn a_head_reset_queues_again_the_forced_records_of_the_dropped_blocks() {
    let (g_hash, g_root) = (B256::repeat_byte(0x10), B256::repeat_byte(0x20));
    let a = forced_tx(1, vec![0x02, 0xaa]);
    let ra = record_of(1, &a);
    let k = bare(1, g_hash, g_root, 0x31);
    let bad = bare(2, k.hash, k.state_root, 0x32);
    let new = bare(2, k.hash, k.state_root, 0x42);
    // The dropped block 2 consumed the record; after the reset to block 1 the new block 2 must consume it again.
    let blocks = vec![
        native(1, vec![a.clone(), settlement(&k, 0)]),
        native(2, vec![settlement_forced(&bad, &[ra])]),
        native(3, vec![settlement_forced(&new, &[ra])]),
    ];
    let derived = derive_settled_blocks_with_reset(&blocks, CHAIN_ID, g_hash, g_root, Some(1)).unwrap();
    assert_eq!(derived.iter().map(|b| b.header_hash).collect::<Vec<_>>(), [k.hash, new.hash]);
    assert_eq!(derived[1].forced.iter().map(|f| f.record).collect::<Vec<_>>(), vec![ra]);
}

// ── F387-1 end to end: chains that cross the base-fee floor of the next rules ──
//
// Agent 387 found twice, on a real-proof net, that the settler's producer stops for ever at the first
// block whose EIP-1559 step falls under the next rules' base-fee floor (0.1 gwei): first the header was
// built on the base rules, then (after that was fixed) its parent link was still judged on them. A unit
// test of each call did not catch the next one. These two tests drive the producer binary itself across
// the floor (`extend`, as the settler does), then every other reader of the same chain: `fees`, `select`,
// `export` of the complete and the sparse artifact (the prover's input), and `reconstruct` (the follower's
// rebuild from L1 data alone). From 1 gwei the fee falls 0.4% per quiet block: about 575 blocks.

fn u(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or_else(|| panic!("{k} in {v}"))
}

/// What the kernel of each rule set computes: the expectation the chain is held to.
fn step(spec: &ChainSpec, fees: &Value) -> u64 {
    spec.next_base_fee(u(fees, "base_fee"), u(fees, "gas_used"))
}

/// The artifacts of block `number`, as the prover takes them: both witness forms export, decode under the
/// rules of that block and carry its base fee; the other rule set's configuration does not decode them.
fn check_artifacts(chain: &Chain, number: u64, own: &ChainSpec, other: &ChainSpec, base_fee: u64) {
    let complete = chain.root.path().join(format!("floor-artifact-{number}"));
    let sparse = chain.root.path().join(format!("floor-artifact-{number}-sparse"));
    let n = number.to_string();
    produce(&["export", "--target", &chain.db, "--number", &n, "--out", complete.to_str().unwrap()]).unwrap();
    produce(&["export", "--target", &chain.db, "--number", &n, "--out", sparse.to_str().unwrap(), "--witness", "sparse"]).unwrap();
    let bytes = std::fs::read(&complete).unwrap();
    let artifact = bloch_execution_artifact::ExecutionArtifact::decode(&bytes, own, MAINNET_DOMAIN).unwrap();
    assert_eq!((artifact.header().number, artifact.header().base_fee_per_gas), (number, base_fee));
    assert_eq!(artifact.context().base_fee_per_gas, base_fee);
    assert!(bloch_execution_artifact::ExecutionArtifact::decode(&bytes, other, MAINNET_DOMAIN).is_err(), "block {number}: the other rule set");
    let bytes = std::fs::read(&sparse).unwrap();
    let artifact = bloch_execution_artifact::SparseExecutionArtifact::decode(&bytes, own, MAINNET_DOMAIN).unwrap();
    assert_eq!((artifact.header().number, artifact.header().base_fee_per_gas), (number, base_fee));
    assert!(bloch_execution_artifact::SparseExecutionArtifact::decode(&bytes, other, MAINNET_DOMAIN).is_err(), "block {number}: the other rule set (sparse)");
}

/// Rebuild the chain from L1 data alone and compare the head and the switch.
fn check_rebuild(chain: &Chain, blocks: &[Produced], l1: Vec<(u64, Vec<PosTransaction>)>, next_from: u64) {
    let d = chain.root.path().join("floor-l1.json");
    l1_fixture(&d, &l1);
    let rebuilt = chain.root.path().join("floor-rebuilt");
    let report = produce(&["reconstruct", "--target", rebuilt.to_str().unwrap(), "--l1", d.to_str().unwrap(), "--timestamp-rule", RULE]).unwrap();
    let last = blocks.last().unwrap();
    assert_eq!(report["settled"], last.number, "every block rebuilds");
    assert_eq!(report["next_rules_from"], next_from);
    assert_eq!(h(&report, "head"), last.hash);
    let rebuilt_fees = produce(&["fees", "--target", rebuilt.to_str().unwrap()]).unwrap();
    assert_eq!(rebuilt_fees, chain.fees(), "the rebuilt head has the same fees");
}

/// Agent 387's case: the next rules from early on, the fee falls to the floor under them and stays there.
#[test]
fn f387_1_a_chain_under_the_next_rules_extends_across_the_base_fee_floor_and_rebuilds() {
    let (base, next) = (ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal());
    let floor = next.min_base_fee;
    assert!(floor > 0 && base.min_base_fee == 0, "the floor is a next-rules addition");
    let mut chain = Chain::new();
    let d1 = deposit(0x31, sender(), 100_000_000);
    let record = json!({"height": 2, "tx_index": 0, "txid": hex::encode(d1.txid()), "vout": 1, "sats": 100_000_000u64, "recipient": hex::encode(sender())});
    let mut blocks = vec![chain.extend(1, Some("base"), vec![record], (0, 1), &[]).unwrap()];
    let before = chain.fees();
    assert_eq!(before["rules"], "base");
    assert_eq!(u(&before, "next_base_fee"), step(&base, &before));
    assert_eq!(u(&before, "next_base_fee_if_switching"), step(&next, &before));
    blocks.push(chain.extend(2, Some("next"), vec![], (1, 1), &[]).unwrap());

    // Quiet blocks until the fee has been at the floor for a while. Each block's base fee is what the
    // NEXT rules compute from its parent; the producer's own report of the next fee agrees.
    let mut fees = chain.fees();
    assert_eq!((u(&fees, "number"), fees["rules"].as_str(), fees["next_rules_from"].as_u64()), (2, Some("next"), Some(2)));
    assert!(fees.get("next_base_fee_if_switching").is_none(), "{fees}");
    let (mut first_floored, mut first_clamped) = (None, None);
    let last = loop {
        let number = u(&fees, "number") + 1;
        let expected = step(&next, &fees);
        assert_eq!(u(&fees, "next_base_fee"), expected, "block {number}");
        assert_eq!(u(&fees, "next_min_base_fee"), floor);
        let clamped = step(&base, &fees) < floor;
        if clamped && first_clamped.is_none() {
            // The block 387's producer refused: the EIP-1559 step is under the floor.
            first_clamped = Some(number);
            assert_eq!(expected, floor);
        }
        if expected == floor && first_floored.is_none() {
            first_floored = Some(number);
        }
        let block = chain.extend(number, None, vec![], (1, 1), &[]).unwrap_or_else(|e| panic!("block {number} (base fee {expected}): {e}"));
        blocks.push(block);
        fees = chain.fees();
        assert_eq!((u(&fees, "number"), u(&fees, "base_fee"), u(&fees, "gas_used")), (number, expected, 0));
        if first_clamped.is_some_and(|first| number >= first + 3) {
            break number;
        }
        assert!(number < 700, "the fee reaches the floor in about 575 blocks");
    };
    let (first_floored, first_clamped) = (first_floored.unwrap(), first_clamped.unwrap());
    assert!(first_floored > 500 && first_clamped >= first_floored, "floor at {first_floored}, first clamped step at {first_clamped}");
    assert_eq!(u(&fees, "base_fee"), floor);

    // A user transaction at the floor: selected, included, and the fee stays at the floor after it.
    let pool = chain.root.path().join("floor-pool.json");
    std::fs::write(&pool, json!([transfer(0)]).to_string()).unwrap();
    let (parent, anchor) = (hex::encode(chain.parent), hex::encode(B256::repeat_byte(0x77)));
    let selected = produce(&[
        "select", "--target", &chain.db, "--parent", &parent, "--anchor", &anchor, "--txs", pool.to_str().unwrap(),
        "--timestamp-rule", RULE, "--anchor-slot", &(100 * (last + 1)).to_string(), "--min-tip-wei", "1",
    ])
    .unwrap();
    assert_eq!(selected["included"].as_array().unwrap().len(), 1, "{selected}");
    assert_eq!(selected["below_min_tip"], 0);
    let with_tx = chain.extend(last + 1, None, vec![], (1, 1), &[transfer(0)]).unwrap();
    assert!(with_tx.payload.is_some());
    blocks.push(with_tx);
    blocks.push(chain.extend(last + 2, None, vec![], (1, 1), &[]).unwrap());
    let end = chain.fees();
    assert_eq!((u(&end, "number"), u(&end, "base_fee"), u(&end, "next_base_fee")), (last + 2, floor, floor));

    // The prover's inputs: the last block above the floor, the first at it, the first clamped one,
    // the block with the transaction and the head.
    let above = blocks[(first_floored - 2) as usize].number;
    assert_eq!(above, first_floored - 1);
    let mut numbers = vec![first_floored, first_clamped, first_clamped + 1, last + 1, last + 2];
    numbers.dedup(); // the first block at the floor is usually the first clamped one
    for number in numbers {
        check_artifacts(&chain, number, &next, &base, floor);
    }
    let bytes = {
        let out = chain.root.path().join("floor-artifact-above");
        produce(&["export", "--target", &chain.db, "--number", &above.to_string(), "--out", out.to_str().unwrap()]).unwrap();
        std::fs::read(out).unwrap()
    };
    let artifact = bloch_execution_artifact::ExecutionArtifact::decode(&bytes, &next, MAINNET_DOMAIN).unwrap();
    assert!(artifact.header().base_fee_per_gas > floor);

    // The follower's rebuild from L1 data alone crosses the floor too.
    let mut l1 = vec![(2, vec![d1])];
    for block in &blocks {
        let mut txs = Vec::new();
        if let Some(payload) = &block.payload {
            txs.push(da(block.number, payload.clone()));
        }
        // The data of a block on L1 before its settlement, each in its own L1 block.
        if !txs.is_empty() {
            l1.push((10 + 2 * block.number, txs));
        }
        l1.push((11 + 2 * block.number, vec![settlement(block, 1)]));
    }
    check_rebuild(&chain, &blocks, l1, 2);
}

/// The launch chain's case: the BASE rules have no floor, so by the time L1 replaces the program the fee
/// is under 0.1 gwei. The first block of the next rules starts at the floor (a step up from its parent),
/// and the chain goes on from there.
#[test]
fn f387_1_a_chain_switches_to_the_next_rules_under_the_base_fee_floor_and_rebuilds() {
    let (base, next) = (ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal());
    let floor = next.min_base_fee;
    let mut chain = Chain::new();
    let d1 = deposit(0x41, sender(), 100_000_000);
    let record = json!({"height": 2, "tx_index": 0, "txid": hex::encode(d1.txid()), "vout": 1, "sats": 100_000_000u64, "recipient": hex::encode(sender())});
    let mut blocks = vec![chain.extend(1, Some("base"), vec![record], (0, 1), &[]).unwrap()];
    let mut fees = chain.fees();
    // Base rules until the fee is well under the floor: the unfloored step, block after block.
    while u(&fees, "base_fee") >= floor - floor / 50 {
        let number = u(&fees, "number") + 1;
        let expected = step(&base, &fees);
        assert_eq!(u(&fees, "next_base_fee"), expected);
        assert_eq!(u(&fees, "next_min_base_fee"), 0);
        assert_eq!(u(&fees, "next_base_fee_if_switching"), step(&next, &fees));
        blocks.push(chain.extend(number, None, vec![], (1, 1), &[]).unwrap_or_else(|e| panic!("base block {number}: {e}")));
        fees = chain.fees();
        assert_eq!((u(&fees, "number"), u(&fees, "base_fee"), fees["rules"].as_str()), (number, expected, Some("base")));
        assert!(number < 700, "the fee falls under the floor in about 580 blocks");
    }
    let under = u(&fees, "base_fee");
    assert!(under < floor && step(&base, &fees) < under);
    assert_eq!(u(&fees, "next_base_fee_if_switching"), floor);

    // L1 replaced the program: the next block is the first of the next rules, at the floor.
    let switch = u(&fees, "number") + 1;
    blocks.push(chain.extend(switch, Some("next"), vec![], (1, 1), &[transfer(0)]).unwrap_or_else(|e| panic!("the switch block {switch}: {e}")));
    assert!(blocks.last().unwrap().payload.is_some(), "the transaction is in the switch block");
    fees = chain.fees();
    assert_eq!((u(&fees, "base_fee"), fees["rules"].as_str(), fees["next_rules_from"].as_u64()), (floor, Some("next"), Some(switch)));
    for number in switch + 1..=switch + 3 {
        assert_eq!(u(&fees, "next_base_fee"), floor);
        blocks.push(chain.extend(number, None, vec![], (1, 1), &[]).unwrap_or_else(|e| panic!("block {number} after the switch: {e}")));
        fees = chain.fees();
        assert_eq!((u(&fees, "number"), u(&fees, "base_fee")), (number, floor));
    }

    // The base rules are refused after the switch, as ever; the switch block and its neighbours export.
    assert!(chain.extend(switch + 4, Some("base"), vec![], (1, 1), &[]).unwrap_err().contains("past the switch"));
    check_artifacts(&chain, switch - 1, &base, &next, under);
    for number in [switch, switch + 1, switch + 3] {
        check_artifacts(&chain, number, &next, &base, floor);
    }

    let mut l1 = vec![(2, vec![d1])];
    for block in &blocks {
        let mut txs = Vec::new();
        if let Some(payload) = &block.payload {
            txs.push(da(block.number, payload.clone()));
        }
        // The data of a block on L1 before its settlement, each in its own L1 block.
        if !txs.is_empty() {
            l1.push((10 + 2 * block.number, txs));
        }
        l1.push((11 + 2 * block.number, vec![settlement(block, 1)]));
    }
    check_rebuild(&chain, &blocks, l1, switch);
}
