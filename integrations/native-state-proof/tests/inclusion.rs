// SPDX-License-Identifier: AGPL-3.0-or-later
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{authenticate_body, AuthenticatedBody, FinalizedCheckpoint};
use bloch_native_state_proof::{evm_commitment_key, verify_evm_commitment, verify_utxo, StateProofError};
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
    state_root::{
        build_state_tree, eutxo_leaf, BaseFeeRecord, CheckpointRecord, ConsensusState, EutxoEntry, EvmCommitment,
        FinalityRecord, Smt,
    },
};
fn entries() -> Vec<EutxoEntry> {
    vec![
        EutxoEntry {
            txid: [7; 32],
            vout: 3,
            value: u64::MAX,
            script_hash: [8; 32],
        },
        EutxoEntry {
            txid: [9; 32],
            vout: 0,
            value: 600,
            script_hash: [10; 32],
        },
    ]
}
fn evm() -> EvmCommitment {
    EvmCommitment {
        account_root: [11; 32],
        receipts_root: [12; 32],
        gas_used: 21_000,
        base_fee_per_gas: 7,
    }
}
fn tree(outputs: &[EutxoEntry], evm: EvmCommitment) -> Smt {
    let cp = CheckpointRecord {
        epoch: 0,
        root: [0; 32],
    };
    let finality = FinalityRecord {
        justified: vec![],
        current_justified: cp,
        previous_justified: cp,
        finalized: cp,
        leaked: vec![],
        next_epoch: 1,
    };
    // The authoritative consensus builder performs the actual private leaf codecs.
    build_state_tree(&ConsensusState {
        written_off_sat: 0,
        funded_validators: &[],
        stake_low_water: &[],
        randao_generations: &[],
        eutxos: outputs,
        validators: &[],
        current_participation: &[],
        previous_participation: &[],
        randao_mixes: &[],
        finality: &finality,
        pending_votes: &[],
        fc_messages: &[],
        fc_equivocators: &[],
        fc_recent_votes: &[],
        deposit_queue: &[],
        delegations: &[],
        pending_fees: &[],
        taint_root: [13; 32],
        coherence_accumulator_root: [14; 32],
        coherence_nullifier_root: [15; 32],
        evm,
        issued_sat: u64::MAX as u128 + 600,
        applied_evidence: &[],
        slash_window: &[],
        delegator_slash_losses: &[],
        base_fee: BaseFeeRecord {
            base_fee_millisat_per_gas: 1000,
            gas_used: 0,
            tx_bytes: 0,
        },
        delegator_fee_rewards: &[],
        validator_fee_rewards: &[],
        delegator_issuance_rewards: &[],
        current_proposed: &[],
    })
}
fn body(root: [u8; 32]) -> AuthenticatedBody {
    let mut header = vec![0u8; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].copy_from_slice(&root);
    header[68..100].copy_from_slice(&body_root(&[]));
    header[100..108].copy_from_slice(&100u64.to_le_bytes());
    let first = BlockHeaderV4::canonical_deserialize(&header).unwrap();
    let mut headers = vec![Bytes::from(first.canonical_serialize())];
    header[4..36].copy_from_slice(BlockId::of(&first).as_bytes());
    header[36..68].fill(88); // Descendant state differs from observed historical state.
    header[100..108].copy_from_slice(&109u64.to_le_bytes());
    let checkpoint = BlockHeaderV4::canonical_deserialize(&header).unwrap();
    headers.push(Bytes::from(checkpoint.canonical_serialize()));
    authenticate_body(
        FinalizedCheckpoint {
            block: B256::from(*BlockId::of(&checkpoint).as_bytes()),
            slot: 109,
        },
        &headers,
        &[],
    )
    .unwrap()
}

#[test]
fn native_utxo_proofs_preserve_exact_value_and_authenticated_provenance() {
    let outputs = entries();
    let tree = tree(&outputs, evm());
    let body = body(tree.root());
    for entry in &outputs {
        let proof = tree.prove(&eutxo_leaf(entry).0).unwrap();
        let observed = verify_utxo(&body, entry, &proof.siblings).unwrap();
        assert_eq!(observed.value(), entry);
        assert_eq!(observed.slot(), 100);
        assert_eq!(observed.checkpoint().slot, 109);
        assert_eq!(observed.block(), body.block());
        assert_eq!(observed.state_root(), B256::from(tree.root()));
        assert_ne!(observed.block(), observed.checkpoint().block);
    }
}
#[test]
fn all_native_output_fields_are_bound() {
    let outputs = entries();
    let tree = tree(&outputs, evm());
    let body = body(tree.root());
    let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
    for field in 0..4 {
        let mut changed = outputs[0].clone();
        match field {
            0 => changed.txid[0] ^= 1,
            1 => changed.vout += 1,
            2 => changed.value -= 1,
            _ => changed.script_hash[0] ^= 1,
        }
        assert_eq!(
            verify_utxo(&body, &changed, &proof.siblings).unwrap_err(),
            StateProofError::Inclusion
        );
    }
}
#[test]
fn native_evm_leaf_matches_official_state_builder_and_binds_every_field() {
    let entry = evm();
    let tree = tree(&entries(), entry);
    let body = body(tree.root());
    let proof = tree.prove(&evm_commitment_key()).unwrap();
    assert_eq!(
        *verify_evm_commitment(&body, entry, &proof.siblings).unwrap().value(),
        entry
    );
    for field in 0..4 {
        let mut changed = entry;
        match field {
            0 => changed.account_root[0] ^= 1,
            1 => changed.receipts_root[0] ^= 1,
            2 => changed.gas_used += 1,
            _ => changed.base_fee_per_gas += 1,
        }
        assert_eq!(
            verify_evm_commitment(&body, changed, &proof.siblings).unwrap_err(),
            StateProofError::Inclusion
        );
    }
}
#[test]
fn malformed_paths_and_changed_siblings_are_rejected() {
    let outputs = entries();
    let tree = tree(&outputs, evm());
    let body = body(tree.root());
    let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
    for length in [0, 255, 257, 2048] {
        assert_eq!(
            verify_utxo(&body, &outputs[0], &vec![[0; 32]; length]).unwrap_err(),
            StateProofError::Length
        );
    }
    for index in [0, 127, 255] {
        let mut siblings = proof.siblings.clone();
        siblings[index][0] ^= 1;
        assert!(verify_utxo(&body, &outputs[0], &siblings).is_err());
    }
    let mut reversed = proof.siblings;
    reversed.reverse();
    assert!(verify_utxo(&body, &outputs[0], &reversed).is_err());
}
#[test]
fn proofs_cannot_move_between_components_or_block_states() {
    let outputs = entries();
    let tree = tree(&outputs, evm());
    let original = body(tree.root());
    let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
    assert!(verify_evm_commitment(&original, evm(), &proof.siblings).is_err());
    assert!(verify_utxo(&body([99; 32]), &outputs[0], &proof.siblings).is_err());
    let evm_proof = tree.prove(&evm_commitment_key()).unwrap();
    assert!(verify_utxo(&original, &outputs[0], &evm_proof.siblings).is_err());
}
#[test]
fn historical_membership_does_not_claim_current_unspentness() {
    let outputs = entries();
    let mut tree = tree(&outputs, evm());
    let original = body(tree.root());
    let key = eutxo_leaf(&outputs[0]).0;
    let proof = tree.prove(&key).unwrap();
    tree.remove(&key);
    assert!(tree.prove(&key).is_none());
    assert!(verify_utxo(&original, &outputs[0], &proof.siblings).is_ok());
    assert!(verify_utxo(&body(tree.root()), &outputs[0], &proof.siblings).is_err());
}
#[test]
fn zero_evm_commitment_is_observable_without_claiming_execution() {
    let entry = EvmCommitment {
        account_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        base_fee_per_gas: 0,
    };
    let tree = tree(&entries(), entry);
    let proof = tree.prove(&evm_commitment_key()).unwrap();
    let observed = verify_evm_commitment(&body(tree.root()), entry, &proof.siblings).unwrap();
    assert_eq!(observed.value().gas_used, 0);
}
