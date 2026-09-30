use super::*;
use crate::proof_statement::SettlementStatementV2;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

fn h(value: u8) -> B256 {
    B256::repeat_byte(value)
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

fn statement(number: u64, previous: B256, parent: B256, state: B256, cursor: u64) -> SettlementStatementV2 {
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
        l2_previous_state_root: state,
        l2_header_hash: h(20 + number as u8),
        l2_state_root: h(30 + number as u8),
        l1_block: h(40 + number as u8),
        l1_slot: 100 + number,
        l1_height: 90 + number,
        source_commitment: h(50 + number as u8),
        inbox_root: h(60 + number as u8),
        inbox_count: cursor + 2,
        consumed_start: cursor,
        consumed_end: cursor + 1,
        body_commitment: h(70 + number as u8),
    }
}

struct Accept;
impl SettlementProofVerifierV1 for Accept {
    fn verify(&self, policy: B256, _: &[u8], proof: &[u8]) -> bool {
        policy == h(8) && proof == [9; super::super::SETTLEMENT_PROOF_V1_BYTES]
    }
}

fn transaction(s: SettlementStatementV2) -> Vec<u8> {
    super::super::SettlementTransactionV1::new(h(8), s, [9; super::super::SETTLEMENT_PROOF_V1_BYTES])
        .unwrap()
        .encode()
        .to_vec()
}

fn directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "bloch-settlement-{label}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    path
}

#[test]
fn persists_recovers_and_enforces_cas_and_external_floor() {
    let path = directory("recover");
    let mut store = SettlementStoreV1::create(&path, policy()).unwrap();
    let zero = store.mark();
    assert_eq!(SettlementStoreMarkV1::decode(&zero.encode()).unwrap(), zero);
    assert!(SettlementStoreMarkV1::decode(&zero.encode()[..79]).is_err());
    let s = statement(1, B256::ZERO, h(10), h(11), 0);
    let (_, one) = store
        .verify_and_commit(
            zero,
            &transaction(s),
            &SettlementExpectationV1 {
                statement: s,
                source_predecessor: B256::ZERO,
            },
            &Accept,
        )
        .unwrap();
    assert!(store.admission().is_none());
    assert!(matches!(
        store.verify_and_commit(
            zero,
            &transaction(s),
            &SettlementExpectationV1 {
                statement: s,
                source_predecessor: B256::ZERO
            },
            &Accept
        ),
        Err(SettlementStoreErrorV1::Cas)
    ));
    drop(store);
    let mut recovered = SettlementStoreV1::open(&path, policy(), one).unwrap();
    assert_eq!(recovered.mark(), one);
    let first = *recovered.registry().head().unwrap();
    assert_eq!(first.l2_number, 1);
    let second_statement = statement(
        2,
        first.commitment,
        first.l2_header_hash,
        first.l2_state_root,
        first.consumed_end,
    );
    let (_, two) = recovered
        .verify_and_commit(
            one,
            &transaction(second_statement),
            &SettlementExpectationV1 {
                statement: second_statement,
                source_predecessor: first.source_commitment,
            },
            &Accept,
        )
        .unwrap();
    drop(recovered);
    let recovered = SettlementStoreV1::open(&path, policy(), one).unwrap();
    assert_eq!(recovered.mark(), two);
    assert_eq!(recovered.registry().head().unwrap().consumed_end, 2);
    assert!(recovered.admission().is_none());
    drop(recovered);
    let forged = SettlementStoreMarkV1 {
        record_digest: h(99),
        ..two
    };
    assert!(matches!(
        SettlementStoreV1::open(&path, policy(), forged),
        Err(SettlementStoreErrorV1::Rollback)
    ));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn policy_substitution_partial_record_and_crash_artifact_fail_closed() {
    let path = directory("tamper");
    let store = SettlementStoreV1::create(&path, policy()).unwrap();
    let floor = store.mark();
    drop(store);
    let mut other = policy();
    other.domain = h(88);
    assert!(matches!(
        SettlementStoreV1::open(&path, other, floor),
        Err(SettlementStoreErrorV1::Policy)
    ));
    fs::write(path.join("00000000000000000001.sst"), b"partial").unwrap();
    assert!(matches!(
        SettlementStoreV1::open(&path, policy(), floor),
        Err(SettlementStoreErrorV1::Format)
    ));
    fs::remove_file(path.join("00000000000000000001.sst")).unwrap();
    fs::write(path.join(".pending-crash"), b"evidence").unwrap();
    assert!(matches!(
        SettlementStoreV1::open(&path, policy(), floor),
        Err(SettlementStoreErrorV1::CrashEvidence)
    ));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn truncation_mutation_gap_and_missing_floor_are_rejected() {
    let path = directory("adversarial");
    let store = SettlementStoreV1::create(&path, policy()).unwrap();
    let zero = store.mark();
    drop(store);
    let record = path.join("00000000000000000000.sst");
    let mut bytes = fs::read(&record).unwrap();
    bytes[50] ^= 1;
    fs::write(&record, bytes).unwrap();
    assert!(SettlementStoreV1::open(&path, policy(), zero).is_err());
    fs::remove_dir_all(path).unwrap();

    let path = directory("floor");
    let store = SettlementStoreV1::create(&path, policy()).unwrap();
    let impossible = SettlementStoreMarkV1 {
        generation: 1,
        record_digest: h(1),
        state_commitment: h(2),
    };
    drop(store);
    assert!(matches!(
        SettlementStoreV1::open(&path, policy(), impossible),
        Err(SettlementStoreErrorV1::Rollback)
    ));
    fs::remove_dir_all(path).unwrap();

    let path = directory("gap");
    let store = SettlementStoreV1::create(&path, policy()).unwrap();
    let floor = store.mark();
    drop(store);
    fs::rename(
        path.join("00000000000000000000.sst"),
        path.join("00000000000000000001.sst"),
    )
    .unwrap();
    assert!(matches!(
        SettlementStoreV1::open(&path, policy(), floor),
        Err(SettlementStoreErrorV1::Format)
    ));
    fs::remove_dir_all(path).unwrap();
}

// Deliberately permissive test-only writer, used to retain a cryptographically
// invalid but structurally coherent record and exercise proof recovery refusal.
struct TestAcceptAll;
impl SettlementProofVerifierV1 for TestAcceptAll {
    fn verify(&self, _: B256, _: &[u8], _: &[u8]) -> bool {
        true
    }
}
struct CountingVerifier {
    calls: std::cell::Cell<usize>,
}
impl SettlementProofVerifierV1 for CountingVerifier {
    fn verify(&self, policy: B256, public: &[u8], proof: &[u8]) -> bool {
        self.calls.set(self.calls.get() + 1);
        Accept.verify(policy, public, proof)
    }
}
fn retained_chain(path: &Path, invalid_at: Option<u64>) -> (SettlementStoreMarkV1, SettlementStoreMarkV1) {
    let mut store = SettlementStoreV1::create(path, policy()).unwrap();
    let zero = store.mark();
    for number in 1..=2 {
        let previous = store.registry().head().copied();
        let s = statement(
            number,
            previous.map_or(B256::ZERO, |v| v.commitment),
            previous.map_or(h(10), |v| v.l2_header_hash),
            previous.map_or(h(11), |v| v.l2_state_root),
            previous.map_or(0, |v| v.consumed_end),
        );
        let proof = [if invalid_at == Some(number) { 8 } else { 9 }; super::super::SETTLEMENT_PROOF_V1_BYTES];
        let tx = SettlementTransactionV1::new(h(8), s, proof).unwrap().encode();
        store
            .verify_and_commit(
                store.mark(),
                &tx,
                &SettlementExpectationV1 {
                    statement: s,
                    source_predecessor: previous.map_or(B256::ZERO, |v| v.source_commitment),
                },
                &TestAcceptAll,
            )
            .unwrap();
    }
    (zero, store.mark())
}

#[test]
fn proof_recovery_reverifies_every_record_even_before_the_external_floor() {
    for invalid_at in [None, Some(1), Some(2)] {
        let path = directory("proof-replay");
        let (_, tip) = retained_chain(&path, invalid_at);
        let before: Vec<_> = (0..=2).map(|i| fs::read(path.join(record_name(i))).unwrap()).collect();
        // Structural recovery never claimed to authenticate execution proofs.
        drop(SettlementStoreV1::open(&path, policy(), tip).unwrap());
        let verifier = CountingVerifier {
            calls: std::cell::Cell::new(0),
        };
        let recovered = SettlementStoreV1::open_verified(&path, policy(), tip, 2, &verifier);
        if invalid_at.is_none() {
            assert_eq!(recovered.as_ref().unwrap().mark(), tip);
            assert_eq!(verifier.calls.get(), 2);
        } else {
            assert!(matches!(
                recovered,
                Err(SettlementStoreErrorV1::Settlement(SettlementError::Proof))
            ));
            assert_eq!(verifier.calls.get(), invalid_at.unwrap() as usize);
        }
        drop(recovered);
        // Failure must release the writer lock, expose no partial handle and
        // preserve every record; the independent floor is not rewritten.
        drop(SettlementStoreV1::open(&path, policy(), tip).unwrap());
        for i in 0..=2 {
            assert_eq!(fs::read(path.join(record_name(i))).unwrap(), before[i as usize]);
        }
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn proof_recovery_budget_precedes_crypto_and_zero_budget_accepts_only_empty_history() {
    let path = directory("proof-budget");
    let (zero, tip) = retained_chain(&path, None);
    let verifier = CountingVerifier {
        calls: std::cell::Cell::new(0),
    };
    for budget in [0, 1, MAX_RECORDS + 1] {
        assert!(matches!(
            SettlementStoreV1::open_verified(&path, policy(), zero, budget, &verifier),
            Err(SettlementStoreErrorV1::Limit)
        ));
        assert_eq!(verifier.calls.get(), 0);
    }
    let store = SettlementStoreV1::open_verified(&path, policy(), zero, 2, &verifier).unwrap();
    assert_eq!(store.mark(), tip);
    drop(store);
    let mut wrong = tip;
    wrong.record_digest = h(99);
    assert!(matches!(
        SettlementStoreV1::open_verified(&path, policy(), wrong, 2, &verifier),
        Err(SettlementStoreErrorV1::Rollback)
    ));
    fs::remove_dir_all(path).unwrap();
    let path = directory("proof-empty");
    let store = SettlementStoreV1::create(&path, policy()).unwrap();
    let zero = store.mark();
    drop(store);
    let verifier = CountingVerifier {
        calls: std::cell::Cell::new(0),
    };
    drop(SettlementStoreV1::open_verified(&path, policy(), zero, 0, &verifier).unwrap());
    assert_eq!(verifier.calls.get(), 0);
    fs::remove_dir_all(path).unwrap();
}
