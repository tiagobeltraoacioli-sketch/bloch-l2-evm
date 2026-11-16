// SPDX-License-Identifier: MIT OR Apache-2.0
//! Forced inclusion (candidate): the deterministic selection of forced
//! envelopes at the start of a block, and the verifier's prefix check.
#![cfg(feature = "forced-inclusion")]
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::forced_inclusion::{
    check_forced_prefix, push_forced, statement_fields, ForcedInputError, ForcedRecord, ForcedSkip, ForcedTransaction,
    MAX_GAS, MAX_PER_SETTLEMENT,
};
use bloch_l2_evm::{
    execute_signed_block, BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State, SignedBlockBuilder,
    SignedBlockInput, TransactionAuthError,
};
use k256::ecdsa::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}
fn address(seed: u8) -> Address {
    Address::from_public_key(key(seed).verifying_key())
}
fn sign(chain_id: u64, seed: u8, nonce: u64, gas_limit: u64, max_fee: u128) -> Bytes {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        to: TxKind::Call(Address::repeat_byte(0x44)),
        value: U256::from(1_000),
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: 0,
        ..Default::default()
    };
    let signature: Signature = key(seed)
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}
fn transfer(spec: &ChainSpec, seed: u8, nonce: u64) -> Bytes {
    sign(spec.chain_id, seed, nonce, 21_000, 2_000_000_000)
}
fn forced(height: u64, envelope: Bytes, declared: u64) -> ForcedTransaction {
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
/// Accounts 1 and 2 funded; account 3 (the censored user's) funded too.
fn funded(spec: &ChainSpec) -> L2State {
    let mut state = L2State::genesis(spec);
    for (i, seed) in [1u8, 2, 3].into_iter().enumerate() {
        state
            .deposit_mint(
                spec,
                &DepositMint {
                    recipient: address(seed),
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 1,
                        l1_tx_index: i as u32,
                        l1_txid: [seed; 32],
                        l1_vout: 0,
                        l1_sats: 100_000_000,
                    },
                },
            )
            .unwrap();
    }
    state.commit_root();
    state
}

/// The mixed queue of the tests: two valid envelopes around every kind of skip.
fn queue(spec: &ChainSpec) -> Vec<ForcedTransaction> {
    vec![
        forced(10, transfer(spec, 3, 0), 21_000),
        // Nonce gap: revm refuses it before execution.
        forced(10, transfer(spec, 3, 5), 21_000),
        // Not a transaction at all.
        forced(11, Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]), 21_000),
        // Another chain.
        forced(11, sign(spec.chain_id + 1, 3, 1, 21_000, 2_000_000_000), 21_000),
        // Its own gas limit is above the declared one.
        forced(12, sign(spec.chain_id, 3, 1, 50_000, 2_000_000_000), 21_000),
        // Fee cap below the base fee.
        forced(12, sign(spec.chain_id, 3, 1, 21_000, 1), 21_000),
        // An unfunded sender.
        forced(13, transfer(spec, 9, 0), 21_000),
        // Valid after the first one.
        forced(13, transfer(spec, 3, 1), 21_000),
    ]
}

#[test]
fn forced_envelopes_run_first_and_invalid_ones_are_skipped_not_blocking() {
    let spec = ChainSpec::default();
    let state = funded(&spec);
    let root = state.clone().commit_root();
    let mut builder =
        SignedBlockBuilder::new(&spec, state.db(), root, BlockContext::next(&spec, &state), vec![]).unwrap();
    let queue = queue(&spec);
    let selection = push_forced(&spec, &mut builder, &queue).unwrap();
    assert_eq!(
        selection.included,
        vec![queue[0].envelope.clone(), queue[7].envelope.clone()]
    );
    let skipped: Vec<usize> = selection.skipped.iter().map(|(i, _)| *i).collect();
    assert_eq!(skipped, vec![1, 2, 3, 4, 5, 6]);
    assert!(matches!(selection.skipped[1].1, ForcedSkip::Authentication(_)));
    assert!(matches!(
        selection.skipped[2].1,
        ForcedSkip::Authentication(TransactionAuthError::WrongChain)
    ));
    assert_eq!(
        selection.skipped[3].1,
        ForcedSkip::GasAboveDeclared {
            envelope: 50_000,
            declared: 21_000
        }
    );
    assert!(matches!(selection.skipped[0].1, ForcedSkip::Execution(_)));
    assert!(matches!(selection.skipped[4].1, ForcedSkip::Execution(_)));
    assert!(matches!(selection.skipped[5].1, ForcedSkip::Execution(_)));

    // The sequencer's own transactions follow.
    let sequencer = [transfer(&spec, 1, 0), transfer(&spec, 2, 0)];
    for tx in &sequencer {
        builder.try_push(tx).unwrap();
    }
    let (input, _) = builder.finish().unwrap();
    let mut body = selection.included.clone();
    body.extend(sequencer.iter().cloned());
    assert_eq!(input.transactions, body);
    // The whole-block executor agrees with the incremental build.
    let mut replay = state.clone();
    let outcome = execute_signed_block(&spec, &mut replay, &input).unwrap();
    assert_eq!(outcome.tx_outcomes.len(), 4);
    // Statement fields: the slot binds all eight records; the count is the sequencer's two.
    let records: Vec<ForcedRecord> = queue.iter().map(|f| f.record).collect();
    let deposits = bloch_l2_evm::executor::deposits_hash(&[]);
    let (slot, users) = statement_fields(deposits, &records, body.len(), selection.included.len()).unwrap();
    assert_eq!(users, 2);
    assert_eq!(slot, bloch_l2_evm::forced_inclusion::inbox_hash(deposits, &records));
    assert_ne!(slot, deposits);
}

#[test]
fn the_verifier_accepts_exactly_the_forced_prefix() {
    let spec = ChainSpec::default();
    let state = funded(&spec);
    let root = state.clone().commit_root();
    let context = BlockContext::next(&spec, &state);
    let queue = queue(&spec);
    let sequencer = transfer(&spec, 1, 0);
    let good = vec![queue[0].envelope.clone(), queue[7].envelope.clone(), sequencer.clone()];
    let selection = check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], &queue, &good).unwrap();
    assert_eq!(selection.included.len(), 2);

    let cases: Vec<(&str, Vec<Bytes>, usize)> = vec![
        // The censoring body: the forced envelopes are left out.
        ("omitted", vec![sequencer.clone()], 0),
        // Only the first one.
        ("partial", vec![queue[0].envelope.clone(), sequencer.clone()], 1),
        // Reordered behind a sequencer transaction.
        (
            "behind",
            vec![sequencer.clone(), queue[0].envelope.clone(), queue[7].envelope.clone()],
            0,
        ),
        // Swapped.
        ("swapped", vec![queue[7].envelope.clone(), queue[0].envelope.clone()], 0),
        // A skipped envelope in place of an included one.
        (
            "skipped one",
            vec![queue[0].envelope.clone(), queue[1].envelope.clone()],
            1,
        ),
    ];
    for (name, body, position) in cases {
        assert_eq!(
            check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], &queue, &body),
            Err(ForcedInputError::Prefix { position }),
            "{name}"
        );
    }
    // Nothing forced: any body passes and the selection is empty.
    let none = check_forced_prefix(&spec, state.db(), root, context, vec![], &[], &[sequencer]).unwrap();
    assert!(none.included.is_empty() && none.skipped.is_empty());
}

#[test]
fn forced_input_must_match_its_records_and_the_cap() {
    let spec = ChainSpec::default();
    let state = funded(&spec);
    let root = state.clone().commit_root();
    let context = BlockContext::next(&spec, &state);
    let mut wrong = forced(1, transfer(&spec, 3, 0), 21_000);
    wrong.record.envelope_hash = B256::repeat_byte(1);
    assert_eq!(
        check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], &[wrong], &[]),
        Err(ForcedInputError::Envelope { index: 0 })
    );
    let empty = forced(1, Bytes::new(), 21_000);
    assert_eq!(
        check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], &[empty], &[]),
        Err(ForcedInputError::Envelope { index: 0 })
    );
    let many: Vec<ForcedTransaction> = (0..=MAX_PER_SETTLEMENT as u64)
        .map(|n| forced(1, transfer(&spec, 3, n), 21_000))
        .collect();
    assert_eq!(
        check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], &many, &[]),
        Err(ForcedInputError::TooMany)
    );
    // Declared gas: sixteen transfers (336k) cross the 300k cap; fourteen fit.
    let sixteen = &many[..MAX_PER_SETTLEMENT];
    assert_eq!(
        check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], sixteen, &[]),
        Err(ForcedInputError::Gas)
    );
    let over = forced(1, transfer(&spec, 3, 0), MAX_GAS + 1);
    assert_eq!(
        check_forced_prefix(&spec, state.db(), root, context.clone(), vec![], &[over], &[]),
        Err(ForcedInputError::Gas)
    );
    // Fourteen sequential envelopes of one sender all execute, in order.
    let fourteen = &many[..14];
    let body: Vec<Bytes> = fourteen.iter().map(|f| f.envelope.clone()).collect();
    let selection = check_forced_prefix(&spec, state.db(), root, context, vec![], fourteen, &body).unwrap();
    assert_eq!(selection.included.len(), 14);
}

#[test]
fn forced_envelopes_run_after_the_deposits_of_the_same_block() {
    // A user whose only funds arrive by deposit in this very block can force a
    // transaction spending them: deposits mint first.
    let spec = ChainSpec::default();
    let state = L2State::genesis(&spec);
    let root = state.clone().commit_root();
    let deposit = DepositMint {
        recipient: address(3),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 2,
            l1_tx_index: 0,
            l1_txid: [7; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    };
    let queue = vec![forced(2, transfer(&spec, 3, 0), 21_000)];
    let body = vec![queue[0].envelope.clone()];
    let context = BlockContext::next(&spec, &state);
    let selection =
        check_forced_prefix(&spec, state.db(), root, context.clone(), vec![deposit], &queue, &body).unwrap();
    assert_eq!(selection.included.len(), 1);
    let mut replay = state.clone();
    let input = SignedBlockInput {
        context,
        deposits: vec![deposit],
        transactions: body,
    };
    assert_eq!(
        execute_signed_block(&spec, &mut replay, &input)
            .unwrap()
            .tx_outcomes
            .len(),
        1
    );
    // Without the deposit the same envelope is skipped, not fatal.
    let context = BlockContext::next(&spec, &state);
    let alone = check_forced_prefix(&spec, state.db(), root, context, vec![], &queue, &[]).unwrap();
    assert!(alone.included.is_empty() && alone.skipped.len() == 1);
}
