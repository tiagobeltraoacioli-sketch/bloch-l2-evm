// SPDX-License-Identifier: AGPL-3.0-or-later
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    l1::{FinalizedCheckpoint, L1Error, TransactionInclusionEvidenceV1},
    native_settlement::{
        SettlementExpectationV1, SettlementPolicyV1, SettlementTransactionV1, SETTLEMENT_PROOF_V1_BYTES,
    },
    proof_statement::SettlementStatementV2,
    settlement_admission::{SettlementAdmissionErrorV1, SettlementAdmissionExpectationV1},
};
use bloch_native_escrow_pq::{
    checkpoint::{CheckpointPolicy, Phase},
    settlement_authority::{
        bind_settlement_checkpoint_authority, CheckpointAuthorityReceiptV1, SettlementAuthorityErrorV1,
        CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES,
    },
};
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
    ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint},
};
use std::sync::OnceLock;

fn h(value: u8) -> B256 {
    B256::repeat_byte(value)
}

fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}

fn signer_set() -> SignerSet {
    SignerSet {
        id: 1,
        signers: keys()
            .iter()
            .enumerate()
            .map(|(index, key)| Signer {
                pubkey: key.0[4..].try_into().unwrap(),
                external: index == 2,
            })
            .collect(),
        threshold: 2,
        min_external: 1,
        adopted_epoch: 50,
    }
}

fn checkpoint_policy() -> CheckpointPolicy {
    CheckpointPolicy::new(7, [9; 32], signer_set(), Phase::A).unwrap()
}

fn settlement_policy() -> SettlementPolicyV1 {
    SettlementPolicyV1 {
        network: h(1),
        genesis: h(2),
        domain: h(3),
        configuration: h(4),
        program_elf_keccak: h(5),
        program_vkey_koalabear: h(6),
        program_vkey_bn254: h(7),
        proof_policy: h(8),
        chain_id: 700_771,
        first_l2_number: 1,
        initial_l2_parent_hash: h(10),
        initial_l2_state_root: h(11),
    }
}

fn statement() -> SettlementStatementV2 {
    let policy = settlement_policy();
    SettlementStatementV2 {
        network: policy.network,
        genesis: policy.genesis,
        domain: policy.domain,
        configuration: policy.configuration,
        program_elf_keccak: policy.program_elf_keccak,
        program_vkey_koalabear: policy.program_vkey_koalabear,
        program_vkey_bn254: policy.program_vkey_bn254,
        previous_settlement: B256::ZERO,
        chain_id: policy.chain_id,
        l2_number: 1,
        l2_parent_hash: policy.initial_l2_parent_hash,
        l2_previous_state_root: policy.initial_l2_state_root,
        l2_header_hash: h(20),
        l2_state_root: h(21),
        l1_block: h(22),
        l1_slot: 80,
        l1_height: 70,
        source_commitment: h(23),
        inbox_root: h(24),
        inbox_count: 1,
        consumed_start: 0,
        consumed_end: 1,
        body_commitment: h(25),
    }
}

fn settlement_transaction() -> Bytes {
    SettlementTransactionV1::new(
        settlement_policy().proof_policy,
        statement(),
        [9; SETTLEMENT_PROOF_V1_BYTES],
    )
    .unwrap()
    .encode()
    .to_vec()
    .into()
}

fn signed_checkpoint(
    transactions: Vec<Bytes>,
) -> (
    bloch_native_escrow_pq::checkpoint::VerifiedCheckpoint,
    TransactionInclusionEvidenceV1,
) {
    let epoch = 100u64;
    let slot = epoch * 120;
    let mut header = vec![0; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].fill(11);
    let body_transactions = transactions
        .iter()
        .map(|transaction| transaction.to_vec())
        .collect::<Vec<_>>();
    header[68..100].copy_from_slice(&body_root(&body_transactions));
    header[100..108].copy_from_slice(&slot.to_le_bytes());
    let native = BlockHeaderV4::canonical_deserialize(&header).unwrap();
    let checkpoint = WeakSubjectivityCheckpoint {
        version: ws::WS_FORMAT_VERSION,
        network_id: 7,
        genesis_root: [9; 32],
        epoch,
        block_root: *BlockId::of(&native).as_bytes(),
        state_root: native.state_root,
        validator_set_root: [12; 32],
        issued_at: 12345,
        signer_set_id: 1,
    };
    let digest = checkpoint.ws_digest();
    let envelope = CheckpointEnvelope {
        checkpoint,
        signatures: [0u8, 2]
            .into_iter()
            .map(|index| {
                let signature = bloch_crypto::crypto::sign(&keys()[index as usize].1, &digest).unwrap();
                (index, signature[4..].to_vec())
            })
            .collect(),
    };
    let verified = checkpoint_policy().verify(&envelope, &header, 101, None).unwrap();
    let evidence =
        TransactionInclusionEvidenceV1::new(verified.anchor(), vec![Bytes::from(header)], transactions).unwrap();
    (verified, evidence)
}

fn expectation(checkpoint: FinalizedCheckpoint) -> SettlementAdmissionExpectationV1 {
    SettlementAdmissionExpectationV1 {
        settlement: SettlementExpectationV1 {
            statement: statement(),
            source_predecessor: B256::ZERO,
        },
        block: checkpoint.block,
        slot: checkpoint.slot,
        checkpoint,
        transaction_index: 1,
    }
}

#[test]
fn real_pq_checkpoint_binds_exact_settlement_body_and_authority_identity() {
    let transaction = settlement_transaction();
    let (checkpoint, evidence) = signed_checkpoint(vec![Bytes::from_static(b"unrelated"), transaction.clone()]);
    let expected = expectation(checkpoint.anchor());
    let bound = bind_settlement_checkpoint_authority(checkpoint, evidence, &expected).unwrap();

    assert_eq!(bound.inclusion().transaction(), transaction.as_ref());
    assert_eq!(bound.inclusion().checkpoint(), expected.checkpoint);
    assert_eq!(bound.inclusion().transaction_index(), 1);
    assert_eq!(bound.authority().checkpoint_epoch(), 100);
    assert_eq!(bound.authority().checked_at_epoch(), 101);
    assert_eq!(bound.authority().checkpoint_block(), expected.checkpoint.block);
    assert_eq!(bound.authority().checkpoint_slot(), expected.checkpoint.slot);
    assert_ne!(bound.authority().policy_identity(), B256::ZERO);
    assert_ne!(bound.authority().checkpoint_digest(), B256::ZERO);
    assert_ne!(bound.authority().commitment(), B256::ZERO);
    assert!(!bound.authority().arrangement_review_due());
    let encoded_authority = bound.authority().encode();
    assert_eq!(encoded_authority.len(), CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES);
    assert_eq!(
        CheckpointAuthorityReceiptV1::decode(&encoded_authority).unwrap(),
        *bound.authority()
    );
    for length in 0..encoded_authority.len() {
        assert!(CheckpointAuthorityReceiptV1::decode(&encoded_authority[..length]).is_err());
    }
    let mut wrong_tag = encoded_authority;
    wrong_tag[0] ^= 1;
    assert!(CheckpointAuthorityReceiptV1::decode(&wrong_tag).is_err());
    let mut wrong_review_flag = encoded_authority;
    wrong_review_flag[CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES - 1] = 2;
    assert!(CheckpointAuthorityReceiptV1::decode(&wrong_review_flag).is_err());
    let mut zero_policy = encoded_authority;
    zero_policy[8..40].fill(0);
    assert!(CheckpointAuthorityReceiptV1::decode(&zero_policy).is_err());
    let mut trailing = encoded_authority.to_vec();
    trailing.push(0);
    assert!(CheckpointAuthorityReceiptV1::decode(&trailing).is_err());

    let (inclusion, recovered_evidence, authority) = bound.into_parts();
    assert_eq!(
        recovered_evidence
            .authenticate_exact(inclusion.transaction())
            .unwrap()
            .transaction_index(),
        1
    );
    assert_eq!(authority.checkpoint_block(), inclusion.checkpoint().block);
}

#[test]
fn mismatched_checkpoint_index_statement_and_duplicate_bytes_fail_closed() {
    let transaction = settlement_transaction();
    let (checkpoint, evidence) = signed_checkpoint(vec![Bytes::from_static(b"unrelated"), transaction.clone()]);
    let mut wrong_checkpoint = expectation(checkpoint.anchor());
    wrong_checkpoint.checkpoint.block = h(0xee);
    assert!(matches!(
        bind_settlement_checkpoint_authority(checkpoint, evidence, &wrong_checkpoint),
        Err(SettlementAuthorityErrorV1::Checkpoint)
    ));

    let (checkpoint, evidence) = signed_checkpoint(vec![Bytes::from_static(b"unrelated"), transaction.clone()]);
    let mut wrong_index = expectation(checkpoint.anchor());
    wrong_index.transaction_index = 9;
    assert!(matches!(
        bind_settlement_checkpoint_authority(checkpoint, evidence, &wrong_index),
        Err(SettlementAuthorityErrorV1::TransactionIndex)
    ));

    let (checkpoint, evidence) = signed_checkpoint(vec![Bytes::from_static(b"unrelated"), transaction.clone()]);
    let mut wrong_statement = expectation(checkpoint.anchor());
    wrong_statement.settlement.statement.l2_state_root = h(0xef);
    assert!(matches!(
        bind_settlement_checkpoint_authority(checkpoint, evidence, &wrong_statement),
        Err(SettlementAuthorityErrorV1::Admission(
            SettlementAdmissionErrorV1::SettlementExpectation
        ))
    ));

    let (checkpoint, evidence) = signed_checkpoint(vec![transaction.clone(), transaction]);
    let expected = expectation(checkpoint.anchor());
    assert!(matches!(
        bind_settlement_checkpoint_authority(checkpoint, evidence, &expected),
        Err(SettlementAuthorityErrorV1::Inclusion(L1Error::TransactionAmbiguous))
    ));
}
