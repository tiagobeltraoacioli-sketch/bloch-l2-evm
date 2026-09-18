use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    l1::{authenticate_body, AuthenticatedBody, FinalizedCheckpoint},
    l1_transfer::{observe_transfer, TransferObservationError as Error},
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
fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/genesis4-transfers.json")).unwrap()
}
fn fixture(i: usize) -> AuthenticatedBody {
    let v = &vectors()[i];
    authenticate_body(
        FinalizedCheckpoint {
            block: B256::from_str(v["checkpoint"].as_str().unwrap()).unwrap(),
            slot: 100,
        },
        &[decode(v["header"].as_str().unwrap())],
        &[decode(v["transaction"].as_str().unwrap())],
    )
    .unwrap()
}
// Synthetic trusted checkpoint for testing malformed transfer payloads. This is
// not a claim that the payload could pass live Genesis-4 consensus validation.
fn synthetic(raw: Vec<u8>) -> AuthenticatedBody {
    let mut leaf = Sha3_256::new();
    leaf.update(b"BLCH4:BODY\0\0\0\0\0\0");
    leaf.update([0, 1]);
    leaf.update((raw.len() as u64).to_le_bytes());
    leaf.update(&raw);
    let mut h = vec![0; 304];
    h[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    h[68..100].copy_from_slice(&leaf.finalize());
    h[100..108].copy_from_slice(&100u64.to_le_bytes());
    let mut id = Sha3_256::new();
    id.update(b"BLCH4:BLOCK\0\0\0\0\0");
    id.update(&h);
    authenticate_body(
        FinalizedCheckpoint {
            block: B256::from_slice(&id.finalize()),
            slot: 100,
        },
        &[h.into()],
        &[raw.into()],
    )
    .unwrap()
}
#[test]
fn official_txids_match_both_encodings_and_preserve_output_indices() {
    let a = observe_transfer(&fixture(0), 0).unwrap();
    let b = observe_transfer(&fixture(1), 0).unwrap();
    assert_eq!(a.txid(), b.txid());
    assert_eq!(
        a.txid(),
        B256::from_str(vectors()[0]["txid"].as_str().unwrap()).unwrap()
    );
    assert_eq!(a.outputs(), b.outputs());
    assert_eq!(a.outputs()[1].value_sat, 5);
    assert_eq!(a.transaction_index(), 0);
    assert_eq!(a.slot(), 100);
    assert_eq!(a.block(), fixture(0).block());
}
#[test]
fn sums_use_u128_without_rounding_or_overflow() {
    let observation = observe_transfer(&fixture(0), 0).unwrap();
    assert_eq!(observation.paid_to(B256::repeat_byte(11)), 2 * u64::MAX as u128);
    assert_eq!(observation.paid_to(B256::repeat_byte(22)), 5);
    assert_eq!(observation.paid_to(B256::ZERO), 0);
}
#[test]
fn every_truncation_and_trailing_data_are_rejected() {
    for i in 0..2 {
        let raw = fixture(i).transactions()[0].to_vec();
        for end in 0..raw.len() {
            assert!(observe_transfer(&synthetic(raw[..end].to_vec()), 0).is_err());
        }
        let mut extended = raw;
        extended.push(0);
        assert_eq!(observe_transfer(&synthetic(extended), 0).unwrap_err(), Error::Encoding);
    }
}
#[test]
fn invalid_witness_reference_and_count_bombs_are_rejected() {
    let mut raw = fixture(1).transactions()[0].to_vec();
    // tag + table count + two length-prefixed 2-byte blobs + input count + outpoint.
    raw[57..61].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(observe_transfer(&synthetic(raw), 0).unwrap_err(), Error::Encoding);
    for tag in [1, 6] {
        let mut raw = vec![tag];
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(observe_transfer(&synthetic(raw), 0).unwrap_err(), Error::Limit);
    }
}
#[test]
fn old_bridge_envelopes_and_unrelated_tags_never_become_native_transfers() {
    for raw in [b"L2D0".to_vec(), vec![11], vec![13]] {
        assert_eq!(observe_transfer(&synthetic(raw), 0).unwrap_err(), Error::Unsupported);
    }
    assert_eq!(observe_transfer(&fixture(0), 1).unwrap_err(), Error::Position);
}
#[test]
fn transport_bytes_are_not_used_as_transaction_identity() {
    let body = fixture(0);
    let original = observe_transfer(&body, 0).unwrap();
    let mut raw = body.transactions()[0].to_vec();
    // The fixture's last signature byte: witness changes must not alter txid.
    raw[52] ^= 1;
    let changed = observe_transfer(&synthetic(raw), 0).unwrap();
    assert_eq!(original.txid(), changed.txid());
    assert_ne!(original.block(), changed.block());
}
