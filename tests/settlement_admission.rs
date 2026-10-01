use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{
    authenticate_body, authenticate_exact_transaction, AuthenticatedTransactionInclusion, FinalizedCheckpoint,
};
use bloch_l2_evm::native_settlement::{
    SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1, SettlementTransactionV1,
    SETTLEMENT_PROOF_V1_BYTES,
};
use bloch_l2_evm::proof_statement::SettlementStatementV2;
use bloch_l2_evm::settlement_admission::{
    authenticate_settlement_inclusion, SettlementAdmissionErrorV1, SettlementAdmissionExpectationV1,
    SettlementAdmissionRegistryV1,
};
use sha3::{Digest, Sha3_256};

fn h(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn policy() -> SettlementPolicyV1 {
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
    let policy = policy();
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
        // This is the earlier source anchor, not the later block that contains
        // the settlement transaction.
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

fn settlement_bytes() -> Vec<u8> {
    SettlementTransactionV1::new(policy().proof_policy, statement(), [9; SETTLEMENT_PROOF_V1_BYTES])
        .unwrap()
        .encode()
        .to_vec()
}

struct ExactVerifier;
impl SettlementProofVerifierV1 for ExactVerifier {
    fn verify(&self, proof_policy: B256, public_values: &[u8], proof: &[u8]) -> bool {
        proof_policy == policy().proof_policy
            && public_values == statement().encode()
            && proof == [9; SETTLEMENT_PROOF_V1_BYTES]
    }
}

struct RejectVerifier;
impl SettlementProofVerifierV1 for RejectVerifier {
    fn verify(&self, _: B256, _: &[u8], _: &[u8]) -> bool {
        false
    }
}

fn hash(parts: &[&[u8]]) -> B256 {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    B256::from_slice(&hasher.finalize())
}

fn body_root(transactions: &[Bytes]) -> B256 {
    let tag = b"BLCH4:BODY\0\0\0\0\0\0";
    let mut level: Vec<B256> = transactions
        .iter()
        .map(|transaction| hash(&[tag, &[0, 1], &(transaction.len() as u64).to_le_bytes(), transaction]))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    hash(&[tag, &[1, 1], pair[0].as_slice(), pair[1].as_slice()])
                } else {
                    pair[0]
                }
            })
            .collect();
    }
    level[0]
}

fn authenticate_at_index(
    exact_transaction: &[u8],
    transaction_index: usize,
) -> (AuthenticatedTransactionInclusion, FinalizedCheckpoint) {
    let settlement = Bytes::copy_from_slice(exact_transaction);
    let filler = Bytes::from_static(b"unrelated canonical native transaction");
    let transactions = if transaction_index == 0 {
        vec![settlement, filler]
    } else {
        vec![filler, settlement]
    };
    let mut header = [0u8; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].copy_from_slice(h(90).as_slice());
    header[68..100].copy_from_slice(body_root(&transactions).as_slice());
    header[100..108].copy_from_slice(&100u64.to_le_bytes());
    let block = hash(&[b"BLCH4:BLOCK\0\0\0\0\0", &header]);
    let checkpoint = FinalizedCheckpoint { block, slot: 100 };
    let body = authenticate_body(checkpoint, &[Bytes::copy_from_slice(&header)], &transactions).unwrap();
    (
        authenticate_exact_transaction(&body, exact_transaction).unwrap(),
        checkpoint,
    )
}

fn expectation(inclusion: &AuthenticatedTransactionInclusion) -> SettlementAdmissionExpectationV1 {
    SettlementAdmissionExpectationV1 {
        settlement: SettlementExpectationV1 {
            statement: statement(),
            source_predecessor: B256::ZERO,
        },
        block: inclusion.block(),
        slot: inclusion.slot(),
        checkpoint: inclusion.checkpoint(),
        transaction_index: inclusion.transaction_index(),
    }
}

#[test]
fn exact_inclusion_coordinates_are_bound_to_kernel_acceptance() {
    let transaction = settlement_bytes();
    let (inclusion, checkpoint) = authenticate_at_index(&transaction, 1);
    let expected = expectation(&inclusion);
    let mut registry = SettlementAdmissionRegistryV1::new(policy()).unwrap();
    let accepted = registry
        .verify_inclusion_and_apply(inclusion, &expected, &ExactVerifier)
        .unwrap();

    assert_eq!(accepted.block(), expected.block);
    assert_eq!(accepted.slot(), 100);
    assert_eq!(accepted.checkpoint(), checkpoint);
    assert_eq!(accepted.transaction_index(), 1);
    assert_eq!(accepted.settlement().l1_block, statement().l1_block);
    assert_ne!(accepted.settlement().l1_block, accepted.block());
    assert_ne!(accepted.admission_commitment(), B256::ZERO);
}

#[test]
fn generic_inclusion_refines_into_a_non_fungible_settlement_capability() {
    let transaction = settlement_bytes();
    let (inclusion, checkpoint) = authenticate_at_index(&transaction, 1);
    let expected = expectation(&inclusion);
    let authenticated = authenticate_settlement_inclusion(inclusion, &expected).unwrap();
    assert_eq!(authenticated.transaction(), transaction);
    assert_eq!(authenticated.statement(), &statement());
    assert_eq!(authenticated.block(), expected.block);
    assert_eq!(authenticated.slot(), expected.slot);
    assert_eq!(authenticated.checkpoint(), checkpoint);
    assert_eq!(authenticated.transaction_index(), 1);
    assert_ne!(authenticated.admission_commitment(), B256::ZERO);

    let (inclusion, _) = authenticate_at_index(&transaction, 1);
    let mut wrong = expectation(&inclusion);
    wrong.settlement.statement.l2_state_root = h(0xee);
    assert!(matches!(
        authenticate_settlement_inclusion(inclusion, &wrong),
        Err(SettlementAdmissionErrorV1::SettlementExpectation)
    ));
}

#[test]
fn every_mismatched_inclusion_coordinate_fails_before_mutating_kernel() {
    let transaction = settlement_bytes();
    let mut registry = SettlementAdmissionRegistryV1::new(policy()).unwrap();
    let before = registry.state_commitment();
    for coordinate in 0..5 {
        let (inclusion, _) = authenticate_at_index(&transaction, 1);
        let mut wrong = expectation(&inclusion);
        match coordinate {
            0 => wrong.block = h(200),
            1 => wrong.slot += 1,
            2 => wrong.checkpoint.block = h(201),
            3 => wrong.checkpoint.slot += 1,
            4 => wrong.transaction_index = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            registry.verify_inclusion_and_apply(inclusion, &wrong, &ExactVerifier),
            Err(SettlementAdmissionErrorV1::InclusionExpectation)
        ));
        assert!(registry.head().is_none());
        assert_eq!(registry.state_commitment(), before);
    }
}

#[test]
fn arbitrary_included_bytes_and_rejected_proofs_fail_closed() {
    let arbitrary = b"included but not a settlement";
    let (inclusion, _) = authenticate_at_index(arbitrary, 0);
    let expected = expectation(&inclusion);
    let mut registry = SettlementAdmissionRegistryV1::new(policy()).unwrap();
    let before = registry.state_commitment();
    assert!(matches!(
        registry.verify_inclusion_and_apply(inclusion, &expected, &ExactVerifier),
        Err(SettlementAdmissionErrorV1::Codec(_))
    ));
    assert_eq!(registry.state_commitment(), before);

    let transaction = settlement_bytes();
    let (inclusion, _) = authenticate_at_index(&transaction, 0);
    let expected = expectation(&inclusion);
    assert!(matches!(
        registry.verify_inclusion_and_apply(inclusion, &expected, &RejectVerifier),
        Err(SettlementAdmissionErrorV1::Settlement(_))
    ));
    assert!(registry.head().is_none());
    assert_eq!(registry.state_commitment(), before);
}

#[test]
fn source_anchor_must_strictly_precede_the_containing_block() {
    let mut self_anchored = statement();
    self_anchored.l1_slot = 100;
    let transaction =
        SettlementTransactionV1::new(policy().proof_policy, self_anchored, [9; SETTLEMENT_PROOF_V1_BYTES])
            .unwrap()
            .encode();
    let (inclusion, _) = authenticate_at_index(&transaction, 0);
    let mut expected = expectation(&inclusion);
    expected.settlement.statement = self_anchored;
    let mut registry = SettlementAdmissionRegistryV1::new(policy()).unwrap();
    assert!(matches!(
        registry.verify_inclusion_and_apply(inclusion, &expected, &ExactVerifier),
        Err(SettlementAdmissionErrorV1::SourceAnchor)
    ));
    assert!(registry.head().is_none());
}

#[test]
fn admission_identity_changes_with_authenticated_body_position() {
    let transaction = settlement_bytes();
    let (first_inclusion, _) = authenticate_at_index(&transaction, 0);
    let first_expected = expectation(&first_inclusion);
    let mut first_registry = SettlementAdmissionRegistryV1::new(policy()).unwrap();
    let first = first_registry
        .verify_inclusion_and_apply(first_inclusion, &first_expected, &ExactVerifier)
        .unwrap()
        .admission_commitment();

    let (second_inclusion, _) = authenticate_at_index(&transaction, 1);
    let second_expected = expectation(&second_inclusion);
    let mut second_registry = SettlementAdmissionRegistryV1::new(policy()).unwrap();
    let second = second_registry
        .verify_inclusion_and_apply(second_inclusion, &second_expected, &ExactVerifier)
        .unwrap()
        .admission_commitment();

    assert_ne!(first, second);
}
