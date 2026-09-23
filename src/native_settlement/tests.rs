use super::*;
use alloc::vec::Vec;

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

fn statement(previous: B256, number: u64, parent: B256, previous_root: B256, start: u64) -> SettlementStatementV2 {
    let p = policy();
    SettlementStatementV2 {
        network: p.network,
        genesis: p.genesis,
        domain: p.domain,
        configuration: p.configuration,
        program_elf_keccak: p.program_elf_keccak,
        program_vkey_koalabear: p.program_vkey_koalabear,
        program_vkey_bn254: p.program_vkey_bn254,
        previous_settlement: previous,
        chain_id: p.chain_id,
        l2_number: number,
        l2_parent_hash: parent,
        l2_previous_state_root: previous_root,
        l2_header_hash: h(20 + number as u8),
        l2_state_root: h(30 + number as u8),
        l1_block: h(40 + number as u8),
        l1_slot: 100 + number,
        l1_height: 90 + number,
        source_commitment: h(50 + number as u8),
        inbox_root: h(60 + number as u8),
        inbox_count: start + 2,
        consumed_start: start,
        consumed_end: start + 1,
        body_commitment: h(70 + number as u8),
    }
}

fn transaction(statement: SettlementStatementV2) -> SettlementTransactionV1 {
    SettlementTransactionV1::new(policy().proof_policy, statement, [9; SETTLEMENT_PROOF_V1_BYTES]).unwrap()
}

struct ExactVerifier;
impl SettlementProofVerifierV1 for ExactVerifier {
    fn verify(&self, proof_policy: B256, public_values: &[u8], proof: &[u8]) -> bool {
        proof_policy == policy().proof_policy
            && SettlementStatementV2::decode(public_values).is_ok()
            && proof == [9; SETTLEMENT_PROOF_V1_BYTES]
    }
}

struct Reject;
impl SettlementProofVerifierV1 for Reject {
    fn verify(&self, _: B256, _: &[u8], _: &[u8]) -> bool {
        false
    }
}

#[test]
fn canonical_codec_is_exact_and_domain_separated() {
    let tx = transaction(statement(B256::ZERO, 1, h(10), h(11), 0));
    let bytes = tx.encode();
    assert_eq!(SettlementTransactionV1::decode(&bytes).unwrap(), tx);
    assert_eq!(
        tx.commitment(),
        SettlementTransactionV1::decode(&bytes).unwrap().commitment()
    );
    for end in 0..bytes.len() {
        assert!(SettlementTransactionV1::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(SettlementTransactionV1::decode(&trailing).is_err());
    let mut wrong_tag = bytes;
    wrong_tag[0] ^= 1;
    assert!(SettlementTransactionV1::decode(&wrong_tag).is_err());
}

#[test]
fn first_and_contiguous_successor_advance_atomically() {
    let first_statement = statement(B256::ZERO, 1, h(10), h(11), 0);
    let first_tx = transaction(first_statement);
    let mut registry = SettlementRegistryV1::new(policy()).unwrap();
    let first = registry
        .verify_and_apply(
            &first_tx.encode(),
            &SettlementExpectationV1 {
                statement: first_statement,
                source_predecessor: B256::ZERO,
            },
            &ExactVerifier,
        )
        .unwrap();
    assert_eq!(first.consumed_end, 1);
    let first_state = registry.state_commitment();

    let second_statement = statement(first.commitment, 2, first.l2_header_hash, first.l2_state_root, 1);
    let second = registry
        .verify_and_apply(
            &transaction(second_statement).encode(),
            &SettlementExpectationV1 {
                statement: second_statement,
                source_predecessor: first.source_commitment,
            },
            &ExactVerifier,
        )
        .unwrap();
    assert_eq!(registry.head(), Some(&second));
    assert_eq!(second.l2_number, 2);
    assert_eq!(second.consumed_end, 2);
    assert_ne!(registry.state_commitment(), first_state);
}

#[test]
fn rejected_proof_and_expectation_leave_state_unchanged() {
    let statement = statement(B256::ZERO, 1, h(10), h(11), 0);
    let tx = transaction(statement);
    let mut registry = SettlementRegistryV1::new(policy()).unwrap();
    assert!(matches!(
        registry.verify_and_apply(
            &tx.encode(),
            &SettlementExpectationV1 {
                statement,
                source_predecessor: B256::ZERO
            },
            &Reject
        ),
        Err(SettlementError::Proof)
    ));
    assert!(registry.head().is_none());

    let mut other = statement;
    other.body_commitment = h(99);
    assert!(matches!(
        registry.verify_and_apply(
            &tx.encode(),
            &SettlementExpectationV1 {
                statement: other,
                source_predecessor: B256::ZERO
            },
            &ExactVerifier
        ),
        Err(SettlementError::Expectation)
    ));
    assert!(registry.head().is_none());
}

#[test]
fn replay_cross_domain_and_policy_substitution_fail_closed() {
    let statement = statement(B256::ZERO, 1, h(10), h(11), 0);
    let tx = transaction(statement);
    let expectation = SettlementExpectationV1 {
        statement,
        source_predecessor: B256::ZERO,
    };
    let mut registry = SettlementRegistryV1::new(policy()).unwrap();
    let accepted = registry
        .verify_and_apply(&tx.encode(), &expectation, &ExactVerifier)
        .unwrap();
    assert!(matches!(
        registry.verify_and_apply(&tx.encode(), &expectation, &ExactVerifier),
        Err(SettlementError::Transition)
    ));
    assert_eq!(registry.head(), Some(&accepted));

    let mut wrong_domain = statement;
    wrong_domain.domain = h(111);
    let mut fresh = SettlementRegistryV1::new(policy()).unwrap();
    assert!(matches!(
        fresh.verify_and_apply(
            &transaction(wrong_domain).encode(),
            &SettlementExpectationV1 {
                statement: wrong_domain,
                source_predecessor: B256::ZERO
            },
            &ExactVerifier
        ),
        Err(SettlementError::Policy)
    ));

    let substituted = SettlementTransactionV1::new(h(112), statement, [9; SETTLEMENT_PROOF_V1_BYTES]).unwrap();
    assert!(matches!(
        fresh.verify_and_apply(&substituted.encode(), &expectation, &ExactVerifier),
        Err(SettlementError::Policy)
    ));
}

#[test]
fn broken_parent_source_cursor_and_regressions_do_not_mutate_head() {
    let first_statement = statement(B256::ZERO, 1, h(10), h(11), 0);
    let mut registry = SettlementRegistryV1::new(policy()).unwrap();
    let first = registry
        .verify_and_apply(
            &transaction(first_statement).encode(),
            &SettlementExpectationV1 {
                statement: first_statement,
                source_predecessor: B256::ZERO,
            },
            &ExactVerifier,
        )
        .unwrap();

    let mut invalids = Vec::new();
    let base = statement(first.commitment, 2, first.l2_header_hash, first.l2_state_root, 1);
    let mut value = base;
    value.l2_parent_hash = h(120);
    invalids.push((value, first.source_commitment));
    value = base;
    value.previous_settlement = h(121);
    invalids.push((value, first.source_commitment));
    value = base;
    value.consumed_start = 0;
    invalids.push((value, first.source_commitment));
    value = base;
    value.l1_height = first.l1_height - 1;
    invalids.push((value, first.source_commitment));
    value = base;
    value.l1_height = first.l1_height + 1;
    value.l1_slot = first.l1_slot;
    invalids.push((value, first.source_commitment));
    value = base;
    value.l1_height = first.l1_height;
    value.l1_slot = first.l1_slot;
    value.l1_block = h(123);
    invalids.push((value, first.source_commitment));
    value = base;
    value.inbox_count = first.inbox_count - 1;
    value.consumed_end = value.inbox_count;
    invalids.push((value, first.source_commitment));
    invalids.push((base, h(122)));

    for (candidate, source_predecessor) in invalids {
        assert!(matches!(
            registry.verify_and_apply(
                &transaction(candidate).encode(),
                &SettlementExpectationV1 {
                    statement: candidate,
                    source_predecessor
                },
                &ExactVerifier
            ),
            Err(SettlementError::Transition)
        ));
        assert_eq!(registry.head(), Some(&first));
    }
}

#[test]
fn proof_and_every_committed_byte_affect_identity() {
    let statement = statement(B256::ZERO, 1, h(10), h(11), 0);
    let original = transaction(statement);
    let mut proof = [9; SETTLEMENT_PROOF_V1_BYTES];
    proof[200] ^= 1;
    let changed_proof = SettlementTransactionV1::new(policy().proof_policy, statement, proof).unwrap();
    assert_ne!(original.commitment(), changed_proof.commitment());

    let encoded = original.encode();
    for index in [0, EXPERIMENTAL_SETTLEMENT_TX_V1_TAG.len(), encoded.len() - 1] {
        let mut changed = encoded;
        changed[index] ^= 1;
        if let Ok(candidate) = SettlementTransactionV1::decode(&changed) {
            assert_ne!(candidate.commitment(), original.commitment());
        }
    }
}
