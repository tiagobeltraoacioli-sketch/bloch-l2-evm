// SPDX-License-Identifier: MIT OR Apache-2.0
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::genesis4::{
    prepare_source_batch, source_prevrandao, verify_source_batch, ReportedSource, SourceError, GENESIS_ROOT, NETWORK_ID,
};
use bloch_l2_evm::{execute_signed_block, generate_signed_batch_witness, ChainSpec, L2State};

fn source() -> ReportedSource {
    ReportedSource {
        network_id: NETWORK_ID,
        genesis_root: GENESIS_ROOT,
        block_hash: B256::repeat_byte(7),
        slot: 80_000,
    }
}

#[test]
fn source_bound_execution_and_stateless_replay_agree() {
    let spec = ChainSpec::testnet();
    let mut state = L2State::genesis(&spec);
    let source = source();
    let root = state.state_root();
    let input = prepare_source_batch(&spec, &state, &source, vec![]).unwrap();
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
    let verified = verify_source_batch(&spec, &source, B256::ZERO, root, &witness, &input).unwrap();
    let result = execute_signed_block(&spec, &mut state, &input).unwrap();
    assert_eq!(result.state_root, verified.new_state_root);
    assert_eq!(state.head().unwrap().anchor_root, source.block_hash);
    assert_eq!(state.head().unwrap().timestamp, source.timestamp().unwrap());
    assert_ne!(root, state.state_root());
}

#[test]
fn wrong_source_and_parent_bindings_are_rejected() {
    let spec = ChainSpec::testnet();
    let state = L2State::genesis(&spec);
    let source = source();
    let input = prepare_source_batch(&spec, &state, &source, vec![]).unwrap();
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
    let mut forged = source.clone();
    forged.block_hash = B256::repeat_byte(9);
    assert_eq!(
        verify_source_batch(&spec, &forged, B256::ZERO, state.state_root(), &witness, &input).unwrap_err(),
        SourceError::BindingMismatch
    );
    assert_eq!(
        verify_source_batch(&spec, &source, B256::ZERO, B256::ZERO, &witness, &input).unwrap_err(),
        SourceError::BindingMismatch
    );
    assert_eq!(
        verify_source_batch(
            &spec,
            &source,
            B256::repeat_byte(8),
            state.state_root(),
            &witness,
            &input
        )
        .unwrap_err(),
        SourceError::BindingMismatch
    );
}

#[test]
fn regressed_or_conflicting_source_cannot_follow_committed_head() {
    let spec = ChainSpec::testnet();
    let mut state = L2State::genesis(&spec);
    let mut source = source();
    let input = prepare_source_batch(&spec, &state, &source, vec![]).unwrap();
    execute_signed_block(&spec, &mut state, &input).unwrap();
    let root = state.state_root();
    source.slot -= 1;
    assert_eq!(
        prepare_source_batch(&spec, &state, &source, vec![]).unwrap_err(),
        SourceError::SourceConflict
    );
    source.slot += 1;
    source.block_hash = B256::repeat_byte(8);
    assert_eq!(
        prepare_source_batch(&spec, &state, &source, vec![]).unwrap_err(),
        SourceError::SourceConflict
    );
    assert_eq!(root, state.state_root());
}

#[test]
fn invalid_network_clock_and_unsigned_wallet_bytes_fail_closed() {
    let spec = ChainSpec::testnet();
    let mut state = L2State::genesis(&spec);
    let mut source = source();
    source.network_id = 1;
    assert_eq!(source.timestamp(), Err(SourceError::WrongNetwork));
    source.network_id = NETWORK_ID;
    source.slot = u64::MAX;
    assert_eq!(source.timestamp(), Err(SourceError::InvalidSource));
    source.slot = 80_000;
    let root = state.state_root();
    let input = prepare_source_batch(&spec, &state, &source, vec![Bytes::from_static(b"unsigned")]).unwrap();
    assert!(execute_signed_block(&spec, &mut state, &input).is_err());
    assert_eq!(root, state.state_root());
}

#[test]
fn verifier_rejects_same_slot_conflict_even_if_host_bypasses_preparation() {
    let spec = ChainSpec::testnet();
    let mut state = L2State::genesis(&spec);
    let mut source = source();
    let first = prepare_source_batch(&spec, &state, &source, vec![]).unwrap();
    let parent = execute_signed_block(&spec, &mut state, &first).unwrap();
    let mut malicious = prepare_source_batch(&spec, &state, &source, vec![]).unwrap();
    source.block_hash = B256::repeat_byte(99);
    malicious.context.anchor_root = source.block_hash;
    malicious.context.prevrandao = source_prevrandao(parent.block_hash, source.block_hash);
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &malicious).unwrap();
    assert_eq!(
        verify_source_batch(
            &spec,
            &source,
            parent.block_hash,
            state.state_root(),
            &witness,
            &malicious
        )
        .unwrap_err(),
        SourceError::SourceConflict
    );
}
