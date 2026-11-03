// SPDX-License-Identifier: MIT OR Apache-2.0
//! Forced inclusion on the complete-witness path: the same rule as the sparse
//! guest (agent 137's tests on `sparse_witness`, repeated here on the complete
//! witness), and, with the sparse feature, the same statement byte for byte.

use super::*;
use crate::chainspec::MAINNET_DOMAIN;
use crate::forced_inclusion::{forced_hash, inbox_hash, ForcedRecord, ForcedTransaction};
use crate::node_execution::{execute_node_block, genesis_v2, node_head};
use crate::proof_statement::execute_settlement_statement_v3;
use crate::state::{DepositMint, DepositProvenance};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Bytes, Signature, TxKind};
use k256::ecdsa::SigningKey;

struct Chain {
    spec: ChainSpec,
    state: L2State,
    key: SigningKey,
    sender: Address,
    nonce: u64,
    deposits: u64,
}

impl Chain {
    fn new(spec: ChainSpec) -> Self {
        let mut state = genesis_v2(&spec, 0).unwrap();
        state.commit_root();
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let sender = Address::from_public_key(key.verifying_key());
        let mut chain = Self { spec, state, key, sender, nonce: 0, deposits: 0 };
        let body = chain.body(vec![]);
        chain.commit(&body);
        chain
    }

    fn deposit(&mut self) -> DepositMint {
        self.deposits += 1;
        DepositMint {
            recipient: self.sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: self.deposits,
                l1_tx_index: 0,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: 10_000_000_000,
            },
        }
    }

    fn body(&mut self, transactions: Vec<Bytes>) -> NodeBodyV2 {
        NodeBodyV2 { deposits: vec![self.deposit()], transactions }
    }

    fn tx(&mut self, to: TxKind, value: U256, gas_limit: u64) -> Bytes {
        let transaction = TxEip1559 {
            chain_id: self.spec.chain_id,
            nonce: self.nonce,
            to,
            value,
            gas_limit,
            max_fee_per_gas: 200_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            ..Default::default()
        };
        self.nonce += 1;
        let signature: Signature = self.key.sign_prehash_recoverable(transaction.signature_hash().as_slice()).unwrap().into();
        TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into()
    }

    fn context(&self) -> BlockContext {
        let parent = node_head(&self.spec, MAINNET_DOMAIN, &self.state).unwrap();
        BlockContext {
            number: parent.number + 1,
            timestamp: match self.spec.block_derivation {
                Some(rule) => rule.timestamp(parent.timestamp, 1).unwrap(),
                None => parent.timestamp + 1,
            },
            base_fee_per_gas: self.spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao: match self.spec.block_derivation {
                Some(rule) => rule.prevrandao,
                None => B256::repeat_byte(7),
            },
            anchor_root: B256::repeat_byte(8),
        }
    }

    fn commit(&mut self, body: &NodeBodyV2) -> NodeExecutionOutcome {
        let context = self.context();
        let outcome = execute_node_block(&self.spec, MAINNET_DOMAIN, &mut self.state, &context, body).unwrap();
        self.state.commit_root();
        outcome
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

fn signed(spec: &ChainSpec, key: &SigningKey, nonce: u64, to: Address, gas_limit: u64) -> Bytes {
    let transaction = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to: TxKind::Call(to),
        value: U256::from(1_000_000u64),
        gas_limit,
        max_fee_per_gas: 200_000_000_000,
        max_priority_fee_per_gas: 0,
        ..Default::default()
    };
    let signature: Signature = key.sign_prehash_recoverable(transaction.signature_hash().as_slice()).unwrap().into();
    TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into()
}

fn record(height: u64, envelope: Bytes, declared: u64) -> ForcedTransaction {
    ForcedTransaction {
        record: ForcedRecord {
            l1_height: height,
            l1_txid: [height as u8; 32],
            envelope_hash: keccak256(&envelope),
            gas_limit: declared,
        },
        envelope,
    }
}

fn settlement(deposits: u64) -> SettlementContextV2 {
    SettlementContextV2 {
        network: B256::repeat_byte(1),
        genesis: B256::repeat_byte(2),
        program_elf_keccak: B256::repeat_byte(3),
        program_vkey_koalabear: B256::repeat_byte(4),
        program_vkey_bn254: B256::repeat_byte(5),
        previous_settlement: B256::repeat_byte(6),
        l1_slot: 1,
        l1_height: 1,
        source_commitment: B256::repeat_byte(7),
        inbox_root: B256::repeat_byte(8),
        inbox_count: deposits,
        consumed_start: 0,
        consumed_end: deposits,
    }
}

/// A chain under the next rules (forced inclusion on), the censored user funded.
struct Fixture {
    chain: Chain,
    censored: SigningKey,
    unfunded: Address,
    queue: Vec<ForcedTransaction>,
}

fn fixture() -> Fixture {
    let mut chain = Chain::new(ChainSpec::mainnet());
    assert!(chain.spec.forced_inclusion);
    let censored = key(0x33);
    let censored_address = Address::from_public_key(censored.verifying_key());
    let fund = chain.tx(TxKind::Call(censored_address), U256::from(10u128.pow(18)), 21_000);
    let body = chain.body(vec![fund]);
    assert!(chain.commit(&body).transactions[0].success);
    let unfunded_key = key(0x44);
    let unfunded = Address::from_public_key(unfunded_key.verifying_key());
    let spec = chain.spec.clone();
    let to = Address::repeat_byte(0x55);
    let queue = vec![
        // Valid: included first.
        record(10, signed(&spec, &censored, 0, to, 21_000), 21_000),
        // Nonce gap: refused before execution, skipped.
        record(10, signed(&spec, &censored, 7, to, 21_000), 21_000),
        // Not a transaction: skipped.
        record(11, Bytes::from_static(&[0xde, 0xad]), 21_000),
        // An unfunded sender: skipped, and its account must be in the witness.
        record(11, signed(&spec, &unfunded_key, 0, to, 21_000), 21_000),
        // Gas above the declared gas: skipped.
        record(12, signed(&spec, &censored, 1, to, 50_000), 21_000),
        // Valid after the first.
        record(12, signed(&spec, &censored, 1, to, 21_000), 21_000),
    ];
    Fixture { chain, censored, unfunded, queue }
}

fn honest_body(f: &mut Fixture) -> NodeBodyV2 {
    let sequencer = f.chain.tx(TxKind::Call(Address::repeat_byte(0x66)), U256::from(5u64), 21_000);
    f.chain.body(vec![f.queue[0].envelope.clone(), f.queue[5].envelope.clone(), sequencer])
}

fn generate(f: &Fixture, body: &NodeBodyV2, forced: &[ForcedTransaction]) -> Result<(BatchWitness, NodeExecutionOutcome), NodeWitnessError> {
    generate_node_batch_witness_forced(&f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &f.chain.context(), body, forced)
}

fn statement(f: &Fixture, witness: &BatchWitness, body: &NodeBodyV2, forced: &[ForcedTransaction]) -> Result<SettlementStatementV3, SettlementStatementV2Error> {
    execute_settlement_statement_v3_forced(&f.chain.spec, MAINNET_DOMAIN, witness, &f.chain.context(), body, settlement(1), forced)
}

#[test]
fn forced_records_run_first_bind_the_statement_and_cover_skipped_senders() {
    let mut f = fixture();
    let body = honest_body(&mut f);
    let context = f.chain.context();
    let (witness, canonical) = generate(&f, &body, &f.queue).expect("an honest forced block generates and self-verifies");
    // The skipped unfunded sender was read only by the probe; the witness proves it absent.
    assert!(witness.absent_accounts.contains(&f.unfunded));
    let censored = Address::from_public_key(f.censored.verifying_key());
    assert!(witness.pre_accounts.iter().any(|a| a.address == censored));
    let (outcome, included) =
        verify_node_batch_forced(&f.chain.spec, MAINNET_DOMAIN, &witness, &context, &body, &f.queue).unwrap();
    assert_eq!(included, 2);
    assert_eq!(outcome.header, canonical.header);
    assert!(outcome.transactions.iter().all(|t| t.success));
    let mut full = f.chain.state.clone();
    assert_eq!(execute_node_block(&f.chain.spec, MAINNET_DOMAIN, &mut full, &context, &body).unwrap().header, canonical.header);

    let s = statement(&f, &witness, &body, &f.queue).unwrap();
    let records: Vec<ForcedRecord> = f.queue.iter().map(|q| q.record).collect();
    assert_eq!(s.deposits_hash, inbox_hash(body.deposits_hash(), &records));
    assert_ne!(s.deposits_hash, body.deposits_hash());
    assert_ne!(forced_hash(&records), forced_hash(&records[..5]));
    assert_eq!(s.user_tx_count, 1, "only the sequencer's transaction counts");
    assert_eq!(
        s.da_commitment,
        crate::data_availability::block_da_commitment(f.chain.spec.chain_id, context.number, &body.transactions[2..]).unwrap()
    );
    assert_eq!(configuration_commitment(&f.chain.spec).unwrap(), s.base.configuration);
    assert_eq!(
        format!("{:x}", s.base.configuration),
        "b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d",
        "the fallback names the forced next configuration (tag 4), the one PROGRAM_NEXT names"
    );
    // The plain complete statement of the same block differs: it does not bind the records.
    let plain = execute_settlement_statement_v3(&f.chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1)).unwrap();
    assert_ne!(plain.encode(), s.encode());
}

#[test]
fn a_body_that_omits_reorders_or_delays_a_due_forced_transaction_is_refused() {
    let mut f = fixture();
    let honest = honest_body(&mut f);
    let context = f.chain.context();
    let sequencer = honest.transactions[2].clone();
    let bodies = [
        vec![f.queue[5].envelope.clone(), sequencer.clone()],
        vec![sequencer.clone()],
        vec![f.queue[5].envelope.clone(), f.queue[0].envelope.clone(), sequencer.clone()],
        vec![sequencer.clone(), f.queue[0].envelope.clone(), f.queue[5].envelope.clone()],
    ];
    for transactions in bodies {
        let body = NodeBodyV2 { deposits: honest.deposits.clone(), transactions };
        assert!(generate(&f, &body, &f.queue).is_err(), "a body without the exact forced prefix must not generate");
    }
    let (witness, _) = generate(&f, &honest, &f.queue).unwrap();
    let dropped = NodeBodyV2 { deposits: honest.deposits.clone(), transactions: vec![sequencer] };
    assert!(verify_node_batch_forced(&f.chain.spec, MAINNET_DOMAIN, &witness, &context, &dropped, &f.queue).is_err());
    assert!(statement(&f, &witness, &dropped, &f.queue).is_err());
}

#[test]
fn a_witness_without_a_skipped_or_included_sender_fails_the_block() {
    let mut f = fixture();
    let body = honest_body(&mut f);
    let context = f.chain.context();
    let (witness, _) = generate(&f, &body, &f.queue).unwrap();
    // The unfunded (skipped) sender's absence proof removed: a database error, never a skip.
    let mut missing = witness.clone();
    missing.absent_accounts.retain(|a| *a != f.unfunded);
    assert!(verify_node_batch_forced(&f.chain.spec, MAINNET_DOMAIN, &missing, &context, &body, &f.queue).is_err());
    // The censored (included) sender removed: its forced transaction cannot become a skip.
    let censored = Address::from_public_key(f.censored.verifying_key());
    let mut missing = witness.clone();
    missing.pre_accounts.retain(|a| a.address != censored);
    let without_forced = NodeBodyV2 { deposits: body.deposits.clone(), transactions: vec![body.transactions[2].clone()] };
    assert!(verify_node_batch_forced(&f.chain.spec, MAINNET_DOMAIN, &missing, &context, &without_forced, &f.queue).is_err());
    assert!(verify_node_batch_forced(&f.chain.spec, MAINNET_DOMAIN, &missing, &context, &body, &f.queue).is_err());
}

#[test]
fn a_funded_skipped_sender_is_witnessed_and_cannot_be_left_out() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let other = key(0x77);
    let other_address = Address::from_public_key(other.verifying_key());
    let fund = chain.tx(TxKind::Call(other_address), U256::from(10u128.pow(18)), 21_000);
    let body = chain.body(vec![fund]);
    assert!(chain.commit(&body).transactions[0].success);
    // A nonce gap: skipped, but the sender's account decides it, and nothing else touches it.
    let forced = vec![record(5, signed(&chain.spec, &other, 9, Address::repeat_byte(0x55), 21_000), 21_000)];
    let body = chain.body(vec![]);
    let context = chain.context();
    let (witness, _) =
        generate_node_batch_witness_forced(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, &forced).unwrap();
    assert!(witness.pre_accounts.iter().any(|a| a.address == other_address), "the skipped sender is witnessed");
    let (_, included) = verify_node_batch_forced(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, &forced).unwrap();
    assert_eq!(included, 0);
    let mut missing = witness.clone();
    missing.pre_accounts.retain(|a| a.address != other_address);
    let result = verify_node_batch_forced(&chain.spec, MAINNET_DOMAIN, &missing, &context, &body, &forced);
    assert!(result.is_err(), "accepted: {:?}", result.map(|(o, n)| (o.header.state_root, n)));
    // The plain generator does not see the probe's read: its witness would fail the forced verifier.
    let (plain, _) = crate::node_execution::generate_node_batch_witness(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body).unwrap();
    assert!(!plain.pre_accounts.iter().any(|a| a.address == other_address));
    assert!(verify_node_batch_forced(&chain.spec, MAINNET_DOMAIN, &plain, &context, &body, &forced).is_err());
}

#[test]
fn a_tampered_forced_list_changes_the_statement_or_fails() {
    let mut f = fixture();
    let body = honest_body(&mut f);
    let (witness, _) = generate(&f, &body, &f.queue).unwrap();
    let honest = statement(&f, &witness, &body, &f.queue).unwrap();
    // A skipped record dropped: still executes, but the slot no longer matches L1's queue.
    let mut fewer = f.queue.clone();
    fewer.remove(3);
    let s = statement(&f, &witness, &body, &fewer).unwrap();
    assert_ne!(s.deposits_hash, honest.deposits_hash);
    // Every record dropped: the forced envelopes become sequencer transactions, the slot is the plain hash.
    let s = statement(&f, &witness, &body, &[]).unwrap();
    assert_eq!(s.deposits_hash, body.deposits_hash());
    assert_ne!(s.deposits_hash, honest.deposits_hash);
    // An envelope that does not hash to its record.
    let mut swapped = f.queue.clone();
    swapped[1].envelope = swapped[5].envelope.clone();
    assert!(statement(&f, &witness, &body, &swapped).is_err());
    // More than the per-settlement bounds.
    let mut many = f.queue.clone();
    while many.len() <= crate::forced_inclusion::MAX_PER_SETTLEMENT {
        many.push(many[2].clone());
    }
    assert!(statement(&f, &witness, &body, &many).is_err());
}

#[test]
fn forced_records_are_refused_under_rules_without_forced_inclusion_and_none_is_the_plain_path() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    assert!(!chain.spec.forced_inclusion);
    let tx = chain.tx(TxKind::Call(Address::repeat_byte(0x66)), U256::from(5u64), 21_000);
    let body = chain.body(vec![tx.clone()]);
    let context = chain.context();
    let queue = vec![record(3, tx, 21_000)];
    assert!(generate_node_batch_witness_forced(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, &queue).is_err());
    let (witness, _) =
        generate_node_batch_witness_forced(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, &[]).unwrap();
    let (plain, _) = crate::node_execution::generate_node_batch_witness(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body).unwrap();
    assert_eq!(witness, plain, "with no forced record the witness is the plain one");
    let forced = execute_settlement_statement_v3_forced(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1), &[]).unwrap();
    let plain = execute_settlement_statement_v3(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1)).unwrap();
    assert_eq!(forced.encode(), plain.encode());
    assert!(execute_settlement_statement_v3_forced(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1), &queue).is_err());
}

#[test]
fn with_nothing_due_the_next_rules_statement_is_the_plain_one() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let tx = chain.tx(TxKind::Call(Address::repeat_byte(0x66)), U256::from(5u64), 21_000);
    let body = chain.body(vec![tx]);
    let context = chain.context();
    let (witness, _) =
        generate_node_batch_witness_forced(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, &[]).unwrap();
    let forced = execute_settlement_statement_v3_forced(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1), &[]).unwrap();
    let plain = execute_settlement_statement_v3(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1)).unwrap();
    assert_eq!(forced.encode(), plain.encode());
    assert_eq!(forced.user_tx_count, 1);
}

#[test]
fn a_forced_only_block_has_no_user_transactions_and_no_da() {
    let mut f = fixture();
    let body = f.chain.body(vec![f.queue[0].envelope.clone(), f.queue[5].envelope.clone()]);
    let (witness, _) = generate(&f, &body, &f.queue).unwrap();
    let s = statement(&f, &witness, &body, &f.queue).unwrap();
    assert_eq!(s.user_tx_count, 0);
    assert_eq!(s.da_commitment, B256::ZERO);
}

/// The two guests of the next rules must agree byte for byte: the complete
/// fallback and the sparse `PROGRAM_NEXT`.
#[cfg(feature = "sparse-witness")]
mod against_sparse {
    use super::*;
    use crate::sparse_witness::{execute_settlement_statement_v3_sparse, generate_sparse_node_witness_forced, BlockHashes};

    fn sparse_statement(f: &Fixture, body: &NodeBodyV2, forced: &[ForcedTransaction]) -> SettlementStatementV3 {
        let context = f.chain.context();
        let (witness, _) = generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, body, BlockHashes::Lazy, forced,
        )
        .unwrap();
        execute_settlement_statement_v3_sparse(&f.chain.spec, MAINNET_DOMAIN, &witness, &context, body, settlement(1), BlockHashes::Lazy)
            .unwrap()
    }

    #[test]
    fn the_complete_and_sparse_statements_are_byte_identical() {
        let mut f = fixture();
        let honest = honest_body(&mut f);
        let forced_only = NodeBodyV2 {
            deposits: honest.deposits.clone(),
            transactions: vec![f.queue[0].envelope.clone(), f.queue[5].envelope.clone()],
        };
        let skips_only: Vec<ForcedTransaction> = [1usize, 2, 3, 4].iter().map(|i| f.queue[*i].clone()).collect();
        let sequencer_only = NodeBodyV2 { deposits: honest.deposits.clone(), transactions: vec![honest.transactions[2].clone()] };
        let cases: [(&NodeBodyV2, &[ForcedTransaction]); 4] =
            [(&honest, &f.queue), (&forced_only, &f.queue), (&sequencer_only, &skips_only), (&sequencer_only, &[])];
        for (body, forced) in cases {
            let (witness, _) = generate(&f, body, forced).unwrap();
            let complete = statement(&f, &witness, body, forced).unwrap();
            assert_eq!(complete.encode(), sparse_statement(&f, body, forced).encode());
        }
    }
}
