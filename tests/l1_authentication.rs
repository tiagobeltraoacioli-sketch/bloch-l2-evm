use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{
    authenticate_ancestry, authenticate_body, authenticate_exact_transaction, FinalizedCheckpoint, L1Error,
    TransactionInclusionEvidenceV1, MAX_INCLUSION_EVIDENCE_V1_BYTES,
};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::str::FromStr;
fn decode(s: &str) -> Bytes {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .into()
}
fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/genesis4-bodies.json")).unwrap()
}
fn fixture(case: usize) -> (FinalizedCheckpoint, Vec<Bytes>, Vec<Bytes>) {
    let f = &fixtures()[case];
    (
        FinalizedCheckpoint {
            block: B256::from_str(f["checkpoint"].as_str().unwrap()).unwrap(),
            slot: 109,
        },
        f["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| decode(v.as_str().unwrap()))
            .collect(),
        f["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| decode(v.as_str().unwrap()))
            .collect(),
    )
}
#[test]
fn official_consensus_vectors_cover_empty_even_and_odd_trees() {
    for (case, f) in fixtures().iter().enumerate() {
        let (cp, headers, txs) = fixture(case);
        let verified = authenticate_body(cp, &headers, &txs).unwrap();
        assert_eq!(verified.block(), B256::from_str(f["target"].as_str().unwrap()).unwrap());
        assert_eq!(verified.slot(), 100);
        assert_eq!(verified.state_root(), B256::repeat_byte(11));
        assert_eq!(verified.checkpoint(), cp);
        assert_eq!(verified.transactions(), txs);
    }
}

#[test]
fn exact_unique_transaction_inclusion_is_position_bound() {
    let (checkpoint, headers, transactions) = fixture(4);
    let body = authenticate_body(checkpoint, &headers, &transactions).unwrap();
    let included = authenticate_exact_transaction(&body, &transactions[2]).unwrap();
    assert_eq!(included.block(), body.block());
    assert_eq!(included.slot(), body.slot());
    assert_eq!(included.checkpoint(), checkpoint);
    assert_eq!(included.transaction_index(), 2);
    assert_eq!(included.transaction(), transactions[2].as_ref());
}

#[test]
fn inclusion_evidence_round_trips_and_reauthenticates_after_restart() {
    let (checkpoint, headers, transactions) = fixture(4);
    let evidence = TransactionInclusionEvidenceV1::new(checkpoint, headers.clone(), transactions.clone()).unwrap();
    assert_eq!(evidence.checkpoint(), checkpoint);
    assert_eq!(evidence.headers(), headers);
    assert_eq!(evidence.transactions(), transactions);

    let encoded = evidence.encode();
    assert!(encoded.len() <= MAX_INCLUSION_EVIDENCE_V1_BYTES);
    let recovered = TransactionInclusionEvidenceV1::decode(&encoded).unwrap();
    assert_eq!(recovered, evidence);
    assert_eq!(recovered.commitment(), evidence.commitment());
    assert_ne!(recovered.commitment(), B256::ZERO);
    let mut expected_commitment = Sha3_256::new();
    expected_commitment.update(b"BLOCH:L1:INCLUSION-EVIDENCE-COMMITMENT:1");
    expected_commitment.update((encoded.len() as u64).to_le_bytes());
    expected_commitment.update(&encoded);
    assert_eq!(
        recovered.commitment(),
        B256::from_slice(&expected_commitment.finalize())
    );

    let (other_checkpoint, other_headers, other_transactions) = fixture(3);
    let other = TransactionInclusionEvidenceV1::new(other_checkpoint, other_headers, other_transactions).unwrap();
    assert_ne!(recovered.commitment(), other.commitment());

    let included = recovered.authenticate_exact(&transactions[2]).unwrap();
    assert_eq!(
        included.block(),
        B256::from_str(fixtures()[4]["target"].as_str().unwrap()).unwrap()
    );
    assert_eq!(included.slot(), 100);
    assert_eq!(included.checkpoint(), checkpoint);
    assert_eq!(included.transaction_index(), 2);
    assert_eq!(included.transaction(), transactions[2].as_ref());
}

#[test]
fn inclusion_evidence_rejects_noncanonical_or_corrupted_envelopes() {
    let (checkpoint, headers, transactions) = fixture(4);
    let header_count = headers.len();
    let encoded = TransactionInclusionEvidenceV1::new(checkpoint, headers, transactions)
        .unwrap()
        .encode();

    for length in 0..encoded.len() {
        assert!(TransactionInclusionEvidenceV1::decode(&encoded[..length]).is_err());
    }

    let mut wrong_tag = encoded.clone();
    wrong_tag[0] ^= 1;
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&wrong_tag).unwrap_err(),
        L1Error::Evidence
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&trailing).unwrap_err(),
        L1Error::Evidence
    );

    let header_count_offset = b"BLOCH:L1:INCLUSION-EVIDENCE:1".len() + 32 + 8;
    let mut no_headers = encoded.clone();
    no_headers[header_count_offset..header_count_offset + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&no_headers).unwrap_err(),
        L1Error::Evidence
    );

    let mut excessive_headers = encoded.clone();
    excessive_headers[header_count_offset..header_count_offset + 4].copy_from_slice(&2049u32.to_le_bytes());
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&excessive_headers).unwrap_err(),
        L1Error::Evidence
    );

    let transaction_count_offset = header_count_offset + 4 + header_count * 304;
    let mut excessive_transactions = encoded.clone();
    excessive_transactions[transaction_count_offset..transaction_count_offset + 4]
        .copy_from_slice(&4097u32.to_le_bytes());
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&excessive_transactions).unwrap_err(),
        L1Error::Evidence
    );

    let first_transaction_length_offset = transaction_count_offset + 4;
    let mut excessive_body = encoded.clone();
    excessive_body[first_transaction_length_offset..first_transaction_length_offset + 4]
        .copy_from_slice(&(16u32 * 1024 * 1024 + 1).to_le_bytes());
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&excessive_body).unwrap_err(),
        L1Error::Evidence
    );

    let mut changed_body = encoded;
    *changed_body.last_mut().unwrap() ^= 1;
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&changed_body).unwrap_err(),
        L1Error::BodyRoot
    );

    let oversized = vec![0; MAX_INCLUSION_EVIDENCE_V1_BYTES + 1];
    assert_eq!(
        TransactionInclusionEvidenceV1::decode(&oversized).unwrap_err(),
        L1Error::Evidence
    );
}

#[test]
fn transaction_selection_rejects_empty_and_missing_bytes() {
    let (checkpoint, headers, transactions) = fixture(4);
    let body = authenticate_body(checkpoint, &headers, &transactions).unwrap();
    assert_eq!(
        authenticate_exact_transaction(&body, &[]).unwrap_err(),
        L1Error::TransactionEmpty
    );
    assert_eq!(
        authenticate_exact_transaction(&body, b"not in the committed body").unwrap_err(),
        L1Error::TransactionMissing
    );
}
#[test]
fn ancestry_authenticates_the_anchor_without_claiming_body_or_finality() {
    let (cp, headers, _) = fixture(4);
    let verified = authenticate_ancestry(cp, &headers).unwrap();
    assert_eq!(
        verified.block(),
        B256::from_str(fixtures()[4]["target"].as_str().unwrap()).unwrap()
    );
    assert_eq!(verified.slot(), 100);
    assert_eq!(verified.state_root(), B256::repeat_byte(11));
    assert_eq!(verified.checkpoint(), cp);
}

#[test]
fn ancestry_rejects_incomplete_paths_and_false_checkpoints() {
    let (cp, headers, _) = fixture(4);
    assert_eq!(
        authenticate_ancestry(cp, &[headers[0].clone(), headers[2].clone()]).unwrap_err(),
        L1Error::Ancestry
    );
    assert_eq!(
        authenticate_ancestry(
            FinalizedCheckpoint {
                block: B256::repeat_byte(0xff),
                slot: cp.slot,
            },
            &headers,
        )
        .unwrap_err(),
        L1Error::Checkpoint
    );
}
#[test]
fn omission_reorder_duplication_and_byte_tampering_fail() {
    let (cp, headers, txs) = fixture(4);
    let mut cases = vec![txs[..4].to_vec()];
    let mut reordered = txs.clone();
    reordered.swap(0, 1);
    cases.push(reordered);
    let mut duplicated = txs.clone();
    duplicated.push(txs.last().unwrap().clone());
    cases.push(duplicated);
    let mut altered = txs.clone();
    altered[0] = vec![99].into();
    cases.push(altered);
    for changed in cases {
        assert_eq!(
            authenticate_body(cp, &headers, &changed).unwrap_err(),
            L1Error::BodyRoot
        );
    }
}
#[test]
fn untrusted_header_changes_break_checkpoint_ancestry() {
    let (cp, headers, txs) = fixture(3);
    for index in 0..headers.len() {
        let mut changed = headers.clone();
        let mut raw = changed[index].to_vec();
        raw[36] ^= 1;
        changed[index] = raw.into();
        assert!(matches!(
            authenticate_body(cp, &changed, &txs),
            Err(L1Error::Ancestry | L1Error::Checkpoint)
        ));
    }
}
#[test]
fn wrong_checkpoint_and_slot_are_rejected() {
    let (mut cp, headers, txs) = fixture(3);
    cp.slot += 1;
    assert_eq!(authenticate_body(cp, &headers, &txs).unwrap_err(), L1Error::Checkpoint);
    cp.block = B256::ZERO;
    assert_eq!(authenticate_body(cp, &headers, &txs).unwrap_err(), L1Error::Checkpoint);
}
#[test]
fn truncated_extended_or_wrong_version_headers_are_rejected() {
    let (cp, headers, txs) = fixture(3);
    let mut version = headers[0].to_vec();
    version[0] ^= 1;
    let mut extended = headers[0].to_vec();
    extended.push(0);
    for raw in [vec![], headers[0][..303].to_vec(), extended, version] {
        let mut changed = headers.clone();
        changed[0] = raw.into();
        assert_eq!(authenticate_body(cp, &changed, &txs).unwrap_err(), L1Error::Header);
    }
}
#[test]
fn skipped_intermediate_header_is_not_a_valid_proof() {
    let (cp, headers, txs) = fixture(2);
    assert_eq!(
        authenticate_body(cp, &[headers[0].clone(), headers[2].clone()], &txs).unwrap_err(),
        L1Error::Ancestry
    );
}
#[test]
fn checkpoint_body_needs_no_intermediate_path() {
    let (mut cp, headers, txs) = fixture(5);
    cp.block = B256::from_str(fixtures()[5]["target"].as_str().unwrap()).unwrap();
    cp.slot = 100;
    assert!(authenticate_body(cp, &headers[..1], &txs).is_ok());
}
#[test]
fn path_and_body_work_limits_fail_closed() {
    let (cp, headers, txs) = fixture(0);
    assert_eq!(authenticate_body(cp, &[], &txs).unwrap_err(), L1Error::PathLimit);
    assert_eq!(
        authenticate_body(cp, &vec![headers[0].clone(); 2049], &txs).unwrap_err(),
        L1Error::PathLimit
    );
    assert_eq!(
        authenticate_body(cp, &headers, &vec![Bytes::new(); 4097]).unwrap_err(),
        L1Error::BodyLimit
    );
    let oversized = vec![vec![0u8; 16 * 1024 * 1024 + 1].into()];
    assert_eq!(
        authenticate_body(cp, &headers, &oversized).unwrap_err(),
        L1Error::BodyLimit
    );
}
