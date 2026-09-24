// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution validity and source authorization are independent requirements.
mod support;

use alloy_primitives::{Address, Bytes, B256};
use bloch_l2_evm::{
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::TrustedLockLocation,
    l1::{FinalizedCheckpoint, TransactionInclusionEvidenceV1},
    native_settlement::{
        store::{SettlementStoreErrorV1, SettlementStoreMarkV1, SettlementStoreV1},
        SettlementError, SettlementPolicyV1, SettlementProofVerifierV1, SettlementRegistryV1, SettlementTransactionV1,
        SETTLEMENT_PROOF_V1_BYTES,
    },
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    proof_statement::execute_statement,
    scale::sats_to_wei,
    settlement_admission::{
        authenticate_settlement_inclusion, AuthenticatedSettlementInclusionV1, SettlementAdmissionExpectationV1,
    },
    BlockContext, ChainSpec, DepositMint, DepositPosition, DepositProvenance,
};
use bloch_native_domain_devnet::{
    SettlementPayload, SettlementSelectionCommitErrorV1, SourceAnchor, SourceBatch, SourceRegistry,
    ValidatedSettlementSelectionV1, MAX_LOCKS,
};
use sha3::{Digest, Sha3_256};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct ExactSettlementVerifier {
    policy: B256,
}

impl SettlementProofVerifierV1 for ExactSettlementVerifier {
    fn verify(&self, proof_policy: B256, _: &[u8], proof: &[u8]) -> bool {
        proof_policy == self.policy && proof == [0x5a; SETTLEMENT_PROOF_V1_BYTES]
    }
}

fn temporary_store() -> PathBuf {
    std::env::temp_dir().join(format!(
        "bloch-selection-store-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ))
}

fn native_hash(parts: &[&[u8]]) -> B256 {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    B256::from_slice(&hasher.finalize())
}

fn native_body_root(transactions: &[Bytes]) -> B256 {
    let tag = b"BLCH4:BODY\0\0\0\0\0\0";
    let mut level: Vec<B256> = transactions
        .iter()
        .map(|transaction| native_hash(&[tag, &[0, 1], &(transaction.len() as u64).to_le_bytes(), transaction]))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    native_hash(&[tag, &[1, 1], pair[0].as_slice(), pair[1].as_slice()])
                } else {
                    pair[0]
                }
            })
            .collect();
    }
    level[0]
}

fn authenticate_selection(
    selection: &ValidatedSettlementSelectionV1,
    proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
    containing_slot: u64,
) -> AuthenticatedSettlementInclusionV1 {
    authenticate_selection_with_evidence(selection, proof, containing_slot).0
}

fn authenticate_selection_with_evidence(
    selection: &ValidatedSettlementSelectionV1,
    proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
    containing_slot: u64,
) -> (AuthenticatedSettlementInclusionV1, TransactionInclusionEvidenceV1) {
    let transaction = selection.transaction(proof).unwrap().encode();
    let transactions = vec![
        Bytes::from_static(b"unrelated canonical native transaction"),
        Bytes::copy_from_slice(&transaction),
    ];
    let mut header = [0u8; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].copy_from_slice(B256::repeat_byte(0x90).as_slice());
    header[68..100].copy_from_slice(native_body_root(&transactions).as_slice());
    header[100..108].copy_from_slice(&containing_slot.to_le_bytes());
    let block = native_hash(&[b"BLCH4:BLOCK\0\0\0\0\0", &header]);
    let checkpoint = FinalizedCheckpoint {
        block,
        slot: containing_slot,
    };
    let evidence =
        TransactionInclusionEvidenceV1::new(checkpoint, vec![Bytes::copy_from_slice(&header)], transactions).unwrap();
    let inclusion = evidence.authenticate_exact(&transaction).unwrap();
    let authenticated = authenticate_settlement_inclusion(
        inclusion,
        &SettlementAdmissionExpectationV1 {
            settlement: selection.expectation(),
            block,
            slot: containing_slot,
            checkpoint,
            transaction_index: 1,
        },
    )
    .unwrap();
    (authenticated, evidence)
}

#[test]
fn valid_v2_execution_still_requires_exact_source_selected_deposits() {
    let network = B256::repeat_byte(1);
    let domain = B256::repeat_byte(0xd3);
    let owner = B256::repeat_byte(8);
    let recipient = Address::repeat_byte(7);
    let mut spec = ChainSpec::testnet();
    spec.deposit_gas = spec.gas_limit / 2;
    let mut source = SourceRegistry::new(network, domain, support::cursor()).unwrap();
    let mut ledger = EscrowLedger::new(
        network,
        domain,
        (0..3)
            .map(|vout| {
                (
                    Outpoint {
                        txid: B256::repeat_byte(9),
                        vout,
                    },
                    Coin { value: 101, owner },
                )
            })
            .collect(),
        MAX_LOCKS,
    )
    .unwrap();
    let position = support::position(1);
    let mut locations = vec![];
    let mut mints = vec![];
    for sequence in 0..3 {
        let lock = ledger
            .apply_authorized_lock(&LockIntent {
                network,
                domain,
                owner,
                inputs: vec![Outpoint {
                    txid: B256::repeat_byte(9),
                    vout: sequence as u32,
                }],
                recipient,
                amount: 100,
                fee: 1,
                change_owner: owner,
                nonce: sequence,
            })
            .unwrap();
        let transaction = B256::repeat_byte(20 + sequence as u8);
        locations.push(TrustedLockLocation {
            sequence,
            intent: lock.id,
            transaction,
            position: DepositPosition {
                l1_height: 1,
                l1_tx_index: sequence as u32,
                l1_vout: 0,
            },
        });
        mints.push(DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: sequence as u32,
                l1_txid: transaction.into(),
                l1_vout: 0,
                l1_sats: 100,
            },
        });
    }
    let inbox = ledger.inbox();
    let batch = SourceBatch {
        network,
        domain,
        genesis: position.genesis(),
        previous: source.commitment(),
        anchor: SourceAnchor {
            block: position.block(),
            slot: position.slot(),
            height: position.height(),
        },
        inbox_root: inbox.root(),
        count: 3,
        locations,
    };
    source
        .apply(
            batch.commitment().unwrap(),
            position,
            &support::headers(1),
            &batch,
            &inbox.proofs(0..3).unwrap(),
        )
        .unwrap();
    let accepted = source.clone();
    let mut state = genesis_v2(&spec, 0).unwrap();
    let initial_head = node_head(&spec, domain, &state).unwrap();
    let settlement_policy = SettlementPolicyV1 {
        network,
        genesis: position.genesis(),
        domain,
        configuration: bloch_l2_evm::proof_statement::configuration_commitment(&spec).unwrap(),
        program_elf_keccak: B256::repeat_byte(0xa1),
        program_vkey_koalabear: B256::repeat_byte(0xa2),
        program_vkey_bn254: B256::repeat_byte(0xa3),
        proof_policy: B256::repeat_byte(0xa4),
        chain_id: spec.chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: initial_head.hash(),
        initial_l2_state_root: initial_head.state_root,
    };
    let store_path = temporary_store();
    let mut settlement_store = SettlementStoreV1::create(&store_path, settlement_policy).unwrap();
    let initial_store_mark = settlement_store.mark();
    let mut store_mark = initial_store_mark;
    let settlement_verifier = ExactSettlementVerifier {
        policy: settlement_policy.proof_policy,
    };
    let mut consumed = 0;
    for end in [2, 3, 3] {
        let parent = node_head(&spec, domain, &state).unwrap();
        let context = BlockContext {
            number: parent.number + 1,
            timestamp: parent.timestamp + 1,
            base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao: B256::repeat_byte(6),
            anchor_root: position.block(),
        };
        let body = NodeBodyV2 {
            deposits: mints[consumed as usize..end as usize].to_vec(),
            transactions: vec![],
        };
        if consumed == 0 {
            for mode in 0..3 {
                let mut forged = body.clone();
                match mode {
                    0 => forged.deposits[0].recipient = Address::repeat_byte(99),
                    1 => {
                        let DepositProvenance::BridgedBlch { ref mut l1_sats, .. } = forged.deposits[0].provenance;
                        *l1_sats += 1;
                    }
                    _ => {
                        forged.deposits.pop();
                    }
                }
                let (witness, outcome) = generate_node_batch_witness(&state, &spec, domain, &context, &forged).unwrap();
                // A genuine successful stateless execution is insufficient to
                // authorize a wrong recipient/amount or omit the mandatory prefix.
                let statement = execute_statement(&spec, domain, &witness, &context, &forged).unwrap();
                assert_eq!(statement.header_hash, outcome.header.hash());
                assert!(source
                    .validate_v2_prefix(&spec, consumed, &outcome.header, &forged)
                    .is_err());
                assert_eq!(source, accepted);
                assert_eq!(state.total_minted_wei(), sats_to_wei(0));
            }
        }
        let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain, &context, &body).unwrap();
        let selected = source
            .validate_v2_prefix(&spec, consumed, &recorded.header, &body)
            .unwrap();
        let statement = execute_statement(&spec, domain, &witness, &context, &body).unwrap();
        assert_eq!(statement, selected.statement());
        assert_eq!(selected.range(), consumed..end);
        assert_eq!(selected.source_commitment(), source.commitment());
        assert_eq!(selected.inbox_count(), 3);
        assert_eq!(selected.anchor().block, position.block());
        assert_eq!(statement.header_hash, recorded.header.hash());
        if consumed == 0 {
            let mut wrong_policy = settlement_policy;
            wrong_policy.domain = B256::repeat_byte(0xee);
            assert_eq!(
                selected.select_settlement_v1(&recorded.header, wrong_policy, settlement_store.registry()),
                Err(bloch_native_domain_devnet::Error::Identity)
            );
        } else {
            let stale_registry = SettlementRegistryV1::new(settlement_policy).unwrap();
            assert_eq!(
                selected.select_settlement_v1(&recorded.header, settlement_policy, &stale_registry),
                Err(bloch_native_domain_devnet::Error::Replay)
            );
        }
        let selection = selected
            .select_settlement_v1(&recorded.header, settlement_policy, settlement_store.registry())
            .unwrap();
        let expectation = selection.expectation();
        assert_eq!(expectation.statement.l2_header_hash, recorded.header.hash());
        assert_eq!(
            expectation.statement.consumed_start..expectation.statement.consumed_end,
            consumed..end
        );
        assert_eq!(expectation.statement.source_commitment, source.commitment());
        assert!(selection.transaction([0; SETTLEMENT_PROOF_V1_BYTES]).is_err());
        let containing_slot = position.slot() + 1_000 + recorded.header.number;
        if consumed == 0 {
            let forged_mark = SettlementStoreMarkV1 {
                record_digest: B256::repeat_byte(0xff),
                ..store_mark
            };
            assert!(matches!(
                selection.verify_inclusion_and_commit(
                    &mut settlement_store,
                    forged_mark,
                    authenticate_selection(&selection, [0x5a; SETTLEMENT_PROOF_V1_BYTES], containing_slot,),
                    &settlement_verifier,
                ),
                Err(SettlementSelectionCommitErrorV1::Store(SettlementStoreErrorV1::Cas))
            ));
            assert_eq!(settlement_store.mark(), store_mark);
            assert!(matches!(
                selection.verify_inclusion_and_commit(
                    &mut settlement_store,
                    store_mark,
                    authenticate_selection(&selection, [0x5b; SETTLEMENT_PROOF_V1_BYTES], containing_slot,),
                    &settlement_verifier,
                ),
                Err(SettlementSelectionCommitErrorV1::Store(
                    SettlementStoreErrorV1::Settlement(SettlementError::Proof)
                ))
            ));
            assert_eq!(settlement_store.mark(), store_mark);
            let (included, _) =
                authenticate_selection_with_evidence(&selection, [0x5a; SETTLEMENT_PROOF_V1_BYTES], containing_slot);
            let (_, mismatched_evidence) =
                authenticate_selection_with_evidence(&selection, [0x5b; SETTLEMENT_PROOF_V1_BYTES], containing_slot);
            assert!(matches!(
                selection.verify_evidence_and_commit(
                    &mut settlement_store,
                    store_mark,
                    included,
                    mismatched_evidence,
                    &settlement_verifier,
                ),
                Err(SettlementSelectionCommitErrorV1::Store(
                    SettlementStoreErrorV1::Evidence
                ))
            ));
            assert_eq!(settlement_store.mark(), store_mark);
        }
        let (authenticated, evidence) =
            authenticate_selection_with_evidence(&selection, [0x5a; SETTLEMENT_PROOF_V1_BYTES], containing_slot);
        let evidence_commitment = evidence.commitment();
        let persisted = selection
            .verify_evidence_and_commit(
                &mut settlement_store,
                store_mark,
                authenticated,
                evidence,
                &settlement_verifier,
            )
            .unwrap();
        store_mark = persisted.mark();
        assert_eq!(persisted.accepted().l2_number, recorded.header.number);
        assert_eq!(persisted.accepted().consumed_end, end);
        assert_eq!(persisted.admission().transaction_index(), 1);
        assert_eq!(persisted.admission().slot(), containing_slot);
        assert_ne!(persisted.admission().admission_commitment(), B256::ZERO);
        assert_eq!(settlement_store.evidence().unwrap().commitment(), evidence_commitment);
        let settlement = SettlementPayload::from_validated_prefix(
            &selected,
            &recorded.header,
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0xa3),
            B256::repeat_byte(0xa4),
            B256::repeat_byte(0xa5),
        )
        .unwrap();
        assert_eq!(settlement.l2_header_hash, statement.header_hash);
        assert_eq!(settlement.l2_state_root, recorded.header.state_root);
        assert_eq!(settlement.chain_id, spec.chain_id);
        assert_eq!(settlement.l1_block, selected.anchor().block);
        assert_eq!(settlement.consumed_start..settlement.consumed_end, consumed..end);
        assert_eq!(
            SettlementPayload::decode(&settlement.encode().unwrap()).unwrap(),
            settlement
        );
        let mut mismatched = recorded.header.clone();
        mismatched.state_root[0] ^= 1;
        assert!(SettlementPayload::from_validated_prefix(
            &selected,
            &mismatched,
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0xa3),
            B256::repeat_byte(0xa4),
            B256::repeat_byte(0xa5),
        )
        .is_err());
        let outcome = execute_node_block(&spec, domain, &mut state, &context, &body).unwrap();
        assert_eq!(outcome.header, recorded.header);
        assert_eq!(state.balance_of(&recipient), sats_to_wei(end * 100));
        assert_eq!(state.total_minted_wei(), sats_to_wei(end * 100));
        assert_eq!(source, accepted);
        assert!(ledger.conserved());
        // The consuming coordinator owns advancement; validation never consumes.
        consumed = end;
    }
    drop(settlement_store);
    let recovered = SettlementStoreV1::open(&store_path, settlement_policy, initial_store_mark).unwrap();
    assert_eq!(recovered.mark(), store_mark);
    assert_eq!(recovered.registry().head().unwrap().l2_number, 3);
    assert_eq!(recovered.registry().head().unwrap().consumed_end, 3);
    let recovered_admission = recovered.admission().unwrap();
    assert_eq!(recovered_admission.transaction_index(), 1);
    assert!(recovered_admission.slot() > recovered.registry().head().unwrap().l1_slot);
    assert_ne!(recovered_admission.admission_commitment(), B256::ZERO);
    let recovered_transaction = SettlementTransactionV1::decode(recovered_admission.transaction()).unwrap();
    let recovered_inclusion = recovered
        .evidence()
        .unwrap()
        .authenticate_exact(recovered_admission.transaction())
        .unwrap();
    assert_eq!(recovered_inclusion.block(), recovered_admission.block());
    assert_eq!(recovered_inclusion.slot(), recovered_admission.slot());
    assert_eq!(recovered_inclusion.checkpoint(), recovered_admission.checkpoint());
    assert_eq!(
        recovered_inclusion.transaction_index(),
        recovered_admission.transaction_index()
    );
    assert_eq!(
        recovered_transaction.commitment(),
        recovered.registry().head().unwrap().commitment
    );
    drop(recovered);
    let last_record = store_path.join(format!("{:020}.sst", store_mark.generation));
    let canonical_record = fs::read(&last_record).unwrap();
    assert_eq!(&canonical_record[..8], b"BLSTRC03");
    let evidence_tag = b"BLOCH:L1:INCLUSION-EVIDENCE:1";
    let evidence_offset = canonical_record
        .windows(evidence_tag.len())
        .position(|window| window == evidence_tag)
        .unwrap();
    let evidence_length_offset = evidence_offset - 4;
    let retained_length = u32::from_le_bytes(
        canonical_record[evidence_length_offset..evidence_offset]
            .try_into()
            .unwrap(),
    ) as usize;
    assert_eq!(evidence_offset + retained_length, canonical_record.len());

    let mut length_bomb = canonical_record.clone();
    length_bomb[evidence_length_offset..evidence_offset].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&last_record, &length_bomb).unwrap();
    assert!(matches!(
        SettlementStoreV1::open(&store_path, settlement_policy, initial_store_mark),
        Err(SettlementStoreErrorV1::Format)
    ));

    let mut trailing_record = canonical_record.clone();
    trailing_record.push(0);
    fs::write(&last_record, &trailing_record).unwrap();
    assert!(matches!(
        SettlementStoreV1::open(&store_path, settlement_policy, initial_store_mark),
        Err(SettlementStoreErrorV1::Format)
    ));

    let mut corrupted_record = canonical_record.clone();
    *corrupted_record.last_mut().unwrap() ^= 1;
    fs::write(&last_record, &corrupted_record).unwrap();
    assert!(matches!(
        SettlementStoreV1::open(&store_path, settlement_policy, initial_store_mark),
        Err(SettlementStoreErrorV1::Evidence)
    ));
    fs::write(&last_record, canonical_record).unwrap();
    let recovered = SettlementStoreV1::open(&store_path, settlement_policy, store_mark).unwrap();
    assert_eq!(recovered.admission().unwrap().transaction_index(), 1);
    drop(recovered);
    fs::remove_dir_all(store_path).unwrap();
}
