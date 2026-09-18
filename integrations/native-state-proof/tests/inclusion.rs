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

#[cfg(unix)]
mod checkpoint_pipeline {
    use super::*;
    use bloch_native_escrow_pq::{
        checkpoint::{CheckpointError, CheckpointPolicy, Phase},
        checkpoint_store::{CheckpointStore, StoreError},
    };
    use bloch_native_state_proof::checkpoint_reader::{
        read_evm_commitment, read_utxo, read_utxos, read_utxos_with_height, ReadError, UtxoRequest, MAX_UTXO_BATCH,
    };
    use bloch_pos_committee::ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint};
    use std::{
        fs,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            OnceLock,
        },
    };
    fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
        static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
        KEYS.get_or_init(|| (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
    }
    fn policy() -> CheckpointPolicy {
        CheckpointPolicy::new(
            7,
            [9; 32],
            SignerSet {
                id: 1,
                threshold: 2,
                min_external: 1,
                adopted_epoch: 0,
                signers: keys()
                    .iter()
                    .enumerate()
                    .map(|(i, key)| Signer {
                        pubkey: key.0[4..].try_into().unwrap(),
                        external: i == 2,
                    })
                    .collect(),
            },
            Phase::A,
        )
        .unwrap()
    }
    fn signed(root: [u8; 32], epoch: u64, parent: [u8; 32]) -> (CheckpointEnvelope, Vec<u8>) {
        signed_at_slot(root, epoch, parent, epoch * 120)
    }
    fn signed_at_slot(root: [u8; 32], epoch: u64, parent: [u8; 32], slot: u64) -> (CheckpointEnvelope, Vec<u8>) {
        let mut header = vec![0; 304];
        header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
        header[4..36].copy_from_slice(&parent);
        header[36..68].copy_from_slice(&root);
        header[68..100].copy_from_slice(&body_root(&[]));
        header[100..108].copy_from_slice(&slot.to_le_bytes());
        let native = BlockHeaderV4::canonical_deserialize(&header).unwrap();
        let cp = WeakSubjectivityCheckpoint {
            version: ws::WS_FORMAT_VERSION,
            network_id: 7,
            genesis_root: [9; 32],
            epoch,
            block_root: *BlockId::of(&native).as_bytes(),
            state_root: root,
            validator_set_root: [12; 32],
            issued_at: 1,
            signer_set_id: 1,
        };
        let signatures = [0u8, 2]
            .into_iter()
            .map(|i| {
                let signature = bloch_crypto::crypto::sign(&keys()[i as usize].1, &cp.ws_digest()).unwrap();
                (i, signature[4..].to_vec())
            })
            .collect();
        (
            CheckpointEnvelope {
                checkpoint: cp,
                signatures,
            },
            header,
        )
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let name = format!(
                "bloch-state-reader-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            Self(std::env::temp_dir().join(name))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn persisted_real_pq_checkpoint_authenticates_utxo_and_evm_state() {
        let outputs = entries();
        let tree = tree(&outputs, evm());
        let (env, header) = signed(tree.root(), 100, [0; 32]);
        let temp = Temp::new();
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let mark = store.accept(&env, &header, 100).unwrap();
        drop(store);
        let store = CheckpointStore::open(&temp.0, policy(), Some(mark)).unwrap();
        let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
        let observed = read_utxo(&store, 101, &header, &[], &outputs[0], &proof.siblings).unwrap();
        assert_eq!(observed.state().value(), &outputs[0]);
        assert_eq!(observed.state().block(), observed.state().checkpoint().block);
        assert_eq!(observed.checkpoint_epoch(), 100);
        assert_eq!(observed.checked_at_epoch(), 101);
        assert_eq!(observed.signed_digest(), mark.digest);
        assert!(!observed.arrangement_review_due());
        let proof = tree.prove(&evm_commitment_key()).unwrap();
        assert_eq!(
            *read_evm_commitment(&store, 101, &header, &[], evm(), &proof.siblings)
                .unwrap()
                .state()
                .value(),
            evm()
        );
        assert_eq!(store.mark(), Some(mark));
    }
    #[test]
    fn stale_future_and_empty_stores_never_return_state_observations() {
        let outputs = entries();
        let tree = tree(&outputs, evm());
        let temp = Temp::new();
        let (env, header) = signed(tree.root(), 100, [0; 32]);
        let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        assert!(matches!(
            read_utxo(&store, 100, &header, &[], &outputs[0], &proof.siblings),
            Err(ReadError::Checkpoint(StoreError::Empty))
        ));
        store.accept(&env, &header, 100).unwrap();
        assert!(matches!(
            read_utxo(&store, 99, &header, &[], &outputs[0], &proof.siblings),
            Err(ReadError::Checkpoint(StoreError::Verify(CheckpointError::Future)))
        ));
        assert!(matches!(
            read_utxo(
                &store,
                100 + ws::WS_PERIOD_EPOCHS,
                &header,
                &[],
                &outputs[0],
                &proof.siblings
            ),
            Err(ReadError::Checkpoint(StoreError::Verify(CheckpointError::Stale)))
        ));
    }
    #[test]
    fn old_header_and_pre_spend_proof_cannot_substitute_for_new_checkpoint_state() {
        let outputs = entries();
        let mut tree = tree(&outputs, evm());
        let temp = Temp::new();
        let (old, old_header) = signed(tree.root(), 100, [0; 32]);
        let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        store.accept(&old, &old_header, 100).unwrap();
        assert!(read_utxo(&store, 100, &old_header, &[], &outputs[0], &proof.siblings).is_ok());
        tree.remove(&eutxo_leaf(&outputs[0]).0);
        let (new, new_header) = signed(tree.root(), 101, old.checkpoint.block_root);
        store.accept(&new, &new_header, 101).unwrap();
        assert!(matches!(
            read_utxo(&store, 101, &old_header, &[], &outputs[0], &proof.siblings),
            Err(ReadError::Body(_))
        ));
        assert!(matches!(
            read_utxo(&store, 101, &new_header, &[], &outputs[0], &proof.siblings),
            Err(ReadError::State(_))
        ));
    }
    #[test]
    fn tampered_body_and_leaf_fail_without_mutating_checkpoint() {
        let outputs = entries();
        let tree = tree(&outputs, evm());
        let temp = Temp::new();
        let (env, header) = signed(tree.root(), 100, [0; 32]);
        let proof = tree.prove(&eutxo_leaf(&outputs[0]).0).unwrap();
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let mark = store.accept(&env, &header, 100).unwrap();
        assert!(matches!(
            read_utxo(
                &store,
                100,
                &header,
                &[Bytes::from_static(&[1])],
                &outputs[0],
                &proof.siblings
            ),
            Err(ReadError::Body(_))
        ));
        let mut changed = outputs[0].clone();
        changed.value -= 1;
        assert!(matches!(
            read_utxo(&store, 100, &header, &[], &changed, &proof.siblings),
            Err(ReadError::State(_))
        ));
        assert_eq!(store.mark(), Some(mark));
    }
    #[test]
    fn request_limits_are_checked_before_checkpoint_verification() {
        let temp = Temp::new();
        let store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let entry = entries().remove(0);
        assert!(matches!(
            read_utxo(&store, 100, &[], &[], &entry, &[]),
            Err(ReadError::Limit)
        ));
        assert!(matches!(
            read_utxo(
                &store,
                100,
                &[0; 304],
                &vec![Bytes::new(); 4097],
                &entry,
                &[[0; 32]; 256]
            ),
            Err(ReadError::Limit)
        ));
        assert!(matches!(
            read_utxo(&store, 100, &[0; 304], &[], &entry, &[[0; 32]; 257]),
            Err(ReadError::Limit)
        ));
    }

    #[test]
    fn batch_preserves_order_and_checkpoint_and_rejects_partial_success() {
        let outputs = entries();
        let tree = tree(&outputs, evm());
        let proofs: Vec<_> = outputs.iter().map(|e| tree.prove(&eutxo_leaf(e).0).unwrap()).collect();
        let temp = Temp::new();
        let (env, header) = signed(tree.root(), 100, [0; 32]);
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let mark = store.accept(&env, &header, 100).unwrap();
        let mut requests: Vec<_> = outputs
            .iter()
            .zip(&proofs)
            .rev()
            .map(|(entry, proof)| UtxoRequest {
                entry,
                siblings: &proof.siblings,
            })
            .collect();
        let observed = read_utxos(&store, 101, &header, &[], &requests).unwrap();
        for (observation, request) in observed.iter().zip(&requests) {
            assert_eq!(observation.state().value(), request.entry);
            assert_eq!(observation.signed_digest(), mark.digest);
            assert_eq!(observation.checked_at_epoch(), 101);
            assert_eq!(observation.state().block(), env.checkpoint.block_root);
        }
        let mut bad = requests[1].entry.clone();
        bad.value -= 1;
        requests[1].entry = &bad;
        assert!(matches!(
            read_utxos(&store, 101, &header, &[], &requests),
            Err(ReadError::State(_))
        ));
        assert_eq!(store.mark(), Some(mark));
        assert!(matches!(
            read_utxos(&store, 100 + ws::WS_PERIOD_EPOCHS, &header, &[], &requests),
            Err(ReadError::Checkpoint(StoreError::Verify(CheckpointError::Stale)))
        ));
    }

    #[test]
    fn batch_rejects_duplicate_outpoints_even_with_different_values_before_pq() {
        let temp = Temp::new();
        let store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let entry = entries().remove(0);
        let mut altered = entry.clone();
        altered.value -= 1;
        let siblings = [[0; 32]; 256];
        for second in [&entry, &altered] {
            let requests = [
                UtxoRequest {
                    entry: &entry,
                    siblings: &siblings,
                },
                UtxoRequest {
                    entry: second,
                    siblings: &siblings,
                },
            ];
            assert!(matches!(
                read_utxos(&store, 100, &[0; 304], &[], &requests),
                Err(ReadError::DuplicateOutput)
            ));
        }
    }

    #[test]
    fn batch_bounds_cover_empty_oversized_and_later_malformed_paths() {
        let temp = Temp::new();
        let store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let outputs = entries();
        let siblings = [[0; 32]; 256];
        assert!(matches!(
            read_utxos(&store, 100, &[0; 304], &[], &[]),
            Err(ReadError::Limit)
        ));
        let oversized: Vec<_> = (0..=MAX_UTXO_BATCH)
            .map(|_| UtxoRequest {
                entry: &outputs[0],
                siblings: &siblings,
            })
            .collect();
        assert!(matches!(
            read_utxos(&store, 100, &[0; 304], &[], &oversized),
            Err(ReadError::Limit)
        ));
        let malformed = [
            UtxoRequest {
                entry: &outputs[0],
                siblings: &siblings,
            },
            UtxoRequest {
                entry: &outputs[1],
                siblings: &siblings[..255],
            },
        ];
        assert!(matches!(
            read_utxos(&store, 100, &[0; 304], &[], &malformed),
            Err(ReadError::Limit)
        ));
    }

    #[test]
    fn height_annotated_reader_authenticates_whole_path_and_advances_only_after_all_proofs() {
        use bloch_l2_evm::l1::height::{HeightCursor, HeightError};
        let outputs = entries();
        let tree = tree(&outputs, evm());
        let proofs: Vec<_> = outputs
            .iter()
            .map(|entry| tree.prove(&eutxo_leaf(entry).0).unwrap())
            .collect();
        let (genesis, genesis_header) = signed_at_slot(tree.root(), 0, [0; 32], 0);
        let (middle, middle_header) = signed_at_slot(tree.root(), 0, genesis.checkpoint.block_root, 7);
        let (tip, tip_header) = signed_at_slot(tree.root(), 0, middle.checkpoint.block_root, 100);
        let headers = vec![
            Bytes::from(genesis_header),
            Bytes::from(middle_header),
            Bytes::from(tip_header.clone()),
        ];
        let mut cursor = HeightCursor::from_genesis(genesis.checkpoint.block_root.into(), &headers[0]).unwrap();
        let original = cursor.clone();
        let temp = Temp::new();
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let mark = store.accept(&tip, &tip_header, 0).unwrap();
        let requests: Vec<_> = outputs
            .iter()
            .zip(&proofs)
            .map(|(entry, proof)| UtxoRequest {
                entry,
                siblings: &proof.siblings,
            })
            .collect();

        let omitted = [headers[0].clone(), headers[2].clone()];
        assert!(matches!(
            read_utxos_with_height(&store, 0, &mut cursor, &omitted, &[], &requests),
            Err(ReadError::Height(_))
        ));
        assert_eq!(cursor, original);
        let mut changed = outputs[1].clone();
        changed.value -= 1;
        let forged = [
            UtxoRequest {
                entry: &outputs[0],
                siblings: &proofs[0].siblings,
            },
            UtxoRequest {
                entry: &changed,
                siblings: &proofs[1].siblings,
            },
        ];
        assert!(matches!(
            read_utxos_with_height(&store, 0, &mut cursor, &headers, &[], &forged),
            Err(ReadError::State(_))
        ));
        assert_eq!(cursor, original);
        assert!(matches!(
            read_utxos_with_height(&store, 0, &mut cursor, &headers, &[Bytes::from_static(&[1])], &requests),
            Err(ReadError::Body(_))
        ));
        assert_eq!(cursor, original);
        assert!(matches!(
            read_utxos_with_height(&store, ws::WS_PERIOD_EPOCHS, &mut cursor, &headers, &[], &requests),
            Err(ReadError::Checkpoint(_))
        ));
        assert_eq!(cursor, original);

        let observed = read_utxos_with_height(&store, 0, &mut cursor, &headers, &[], &requests).unwrap();
        assert_eq!(observed.len(), outputs.len());
        for (observed, entry) in observed.iter().zip(&outputs) {
            assert_eq!(observed.observation().state().value(), entry);
            assert_eq!(observed.observation().signed_digest(), mark.digest);
            assert_eq!(observed.position().block(), observed.observation().state().block());
            assert_eq!((observed.position().height(), observed.position().slot()), (2, 100));
        }
        let accepted = cursor.clone();
        assert!(matches!(
            read_utxos_with_height(&store, 0, &mut cursor, &headers[2..], &[], &requests),
            Err(ReadError::Height(HeightError::Replay))
        ));
        assert_eq!(cursor, accepted);
        assert_eq!(store.mark(), Some(mark));
        // A later, correctly signed checkpoint does not itself prove ancestry.
        // Its fork diverges before the accepted height-2 position.
        let (conflicting, conflicting_header) = signed_at_slot(tree.root(), 1, genesis.checkpoint.block_root, 120);
        let conflict_mark = store.accept(&conflicting, &conflicting_header, 1).unwrap();
        let conflicting_path = [headers[0].clone(), Bytes::from(conflicting_header)];
        assert!(matches!(
            read_utxos_with_height(&store, 1, &mut cursor, &conflicting_path, &[], &requests),
            Err(ReadError::Height(HeightError::Continuity))
        ));
        assert_eq!(cursor, accepted);
        assert_eq!(store.mark(), Some(conflict_mark));
    }
}
