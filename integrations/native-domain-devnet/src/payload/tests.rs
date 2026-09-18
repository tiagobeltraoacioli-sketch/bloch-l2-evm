// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::{
    tests::{fixture, support},
    SourceRegistry,
};
use bloch_l2_evm::l1::{height::HeightCursor, FinalizedCheckpoint};

fn vector() -> SourcePayload {
    SourcePayload {
        network: B256::repeat_byte(1),
        domain: B256::repeat_byte(2),
        genesis: B256::repeat_byte(3),
        previous: B256::repeat_byte(4),
        slot: 150,
        height: 1,
        inbox_root: B256::repeat_byte(5),
        count: 1,
        locations: vec![TrustedLockLocation {
            sequence: 0,
            intent: B256::repeat_byte(6),
            transaction: B256::repeat_byte(7),
            position: DepositPosition {
                l1_height: 1,
                l1_tx_index: 8,
                l1_vout: 9,
            },
        }],
    }
}

#[test]
fn canonical_golden_vector_and_exact_bounded_decode() {
    let payload = vector();
    let expected=alloy_primitives::hex::decode("424c4f43483a4558504552494d454e54414c3a534f555243452d5041594c4f41443a31010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040496000000000000000100000000000000050505050505050505050505050505050505050505050505050505050505050501000000000000000100000000000000000000000606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070701000000000000000800000009000000").unwrap();
    let bytes = payload.encode().unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(SourcePayload::decode(&bytes).unwrap(), payload);
    for end in 0..bytes.len() {
        assert!(SourcePayload::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SourcePayload::decode(&trailing).is_err());
    let mut wrong_tag = bytes.clone();
    wrong_tag[0] ^= 1;
    assert_eq!(SourcePayload::decode(&wrong_tag), Err(Error::Codec));
    assert_eq!(
        SourcePayload::decode(&vec![0; MAX_SOURCE_PAYLOAD_BYTES + 1]),
        Err(Error::Limit)
    );
    let mut wrong_count = bytes.clone();
    wrong_count[FIXED_BYTES - 12..FIXED_BYTES - 4].copy_from_slice(&4097u64.to_le_bytes());
    assert_eq!(SourcePayload::decode(&wrong_count), Err(Error::Limit));
    let mut wrong_records = bytes.clone();
    wrong_records[FIXED_BYTES - 4..FIXED_BYTES].copy_from_slice(&4097u32.to_le_bytes());
    assert_eq!(SourcePayload::decode(&wrong_records), Err(Error::Limit));
    let mut zero_height = bytes.clone();
    zero_height[TAG.len() + 32 * 4 + 8..TAG.len() + 32 * 4 + 16].fill(0);
    assert_eq!(SourcePayload::decode(&zero_height), Err(Error::Configuration));
    for identity in 0..3 {
        let mut zero_identity = bytes.clone();
        zero_identity[TAG.len() + identity * 32..TAG.len() + (identity + 1) * 32].fill(0);
        assert_eq!(SourcePayload::decode(&zero_identity), Err(Error::Configuration));
    }
    let mut incomplete = bytes.clone();
    incomplete[FIXED_BYTES - 12..FIXED_BYTES - 4].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(SourcePayload::decode(&incomplete), Err(Error::Incomplete));
    let mut out_of_order = bytes;
    out_of_order[FIXED_BYTES..FIXED_BYTES + 8].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(SourcePayload::decode(&out_of_order), Err(Error::Mapping));
}

#[test]
fn every_committed_field_changes_commitment_or_rejects_incomplete_mapping() {
    let original = vector();
    let expected = original.commitment().unwrap();
    for field in 0..13 {
        let mut changed = original.clone();
        match field {
            0 => changed.network[0] ^= 1,
            1 => changed.domain[0] ^= 1,
            2 => changed.genesis[0] ^= 1,
            3 => changed.previous[0] ^= 1,
            4 => changed.slot += 1,
            5 => changed.height += 1,
            6 => changed.inbox_root[0] ^= 1,
            7 => {
                changed.count = 0;
                changed.locations.clear();
            }
            8 => changed.locations[0].intent[0] ^= 1,
            9 => changed.locations[0].transaction[0] ^= 1,
            10 => changed.locations[0].position.l1_height += 1,
            11 => changed.locations[0].position.l1_tx_index += 1,
            12 => changed.locations[0].position.l1_vout += 1,
            _ => unreachable!(),
        }
        assert_ne!(changed.commitment().unwrap(), expected, "field {field}");
    }
    let mut changed = original.clone();
    changed.count = 2;
    assert_eq!(changed.encode(), Err(Error::Incomplete));
    let mut changed = original;
    changed.locations[0].sequence = 1;
    assert_eq!(changed.encode(), Err(Error::Mapping));
}

#[test]
fn current_anchor_hash_is_absent_but_binding_retains_exact_typed_position() {
    let (batch, proofs) = fixture(1);
    let payload = SourcePayload::from_batch(&batch).unwrap();
    assert_eq!(payload.bind(support::position(1)).unwrap(), batch);
    let mut other = batch.clone();
    other.anchor.block[0] ^= 1;
    assert_eq!(SourcePayload::from_batch(&other).unwrap(), payload);
    assert_ne!(payload.commitment().unwrap(), batch.commitment().unwrap());
    let mut headers = support::headers(1);
    let mut changed = headers[1].to_vec();
    changed[36] ^= 1;
    headers[1] = changed.into();
    let mut cursor = support::cursor();
    let position = cursor
        .advance(
            FinalizedCheckpoint {
                block: support::id(&headers[1]),
                slot: 150,
            },
            &headers,
        )
        .unwrap();
    let bound = payload.bind(position).unwrap();
    assert_ne!(bound.anchor.block, batch.anchor.block);
    assert_ne!(bound.commitment().unwrap(), batch.commitment().unwrap());
    assert_eq!(
        SourcePayload::from_batch(&bound).unwrap().commitment().unwrap(),
        payload.commitment().unwrap()
    );
    // Binding a position does not replace registry source authority.
    let mut registry = SourceRegistry::new(batch.network, batch.domain, support::cursor()).unwrap();
    let initial = registry.clone();
    assert_eq!(
        registry.apply(
            payload.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &batch,
            &proofs
        ),
        Err(Error::Authority)
    );
    assert_eq!(registry, initial);
    registry
        .apply(
            batch.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &batch,
            &proofs,
        )
        .unwrap();
}

#[test]
fn genesis_and_mismatched_position_never_bind() {
    let (batch, _) = fixture(1);
    let payload = SourcePayload::from_batch(&batch).unwrap();
    assert_eq!(payload.bind(support::position(0)), Err(Error::Mapping));
    assert_eq!(payload.bind(support::position(2)), Err(Error::Mapping));
    let mut changed = payload.clone();
    changed.slot += 1;
    assert_eq!(changed.bind(support::position(1)), Err(Error::Mapping));
    let mut headers = support::headers(1);
    let mut genesis = headers[0].to_vec();
    genesis[36] ^= 1;
    headers[0] = genesis.into();
    let id = support::id(&headers[0]);
    let mut next = headers[1].to_vec();
    next[4..36].copy_from_slice(id.as_slice());
    headers[1] = next.into();
    let mut cursor = HeightCursor::from_genesis(id, &headers[0]).unwrap();
    let position = cursor
        .advance(
            FinalizedCheckpoint {
                block: support::id(&headers[1]),
                slot: 150,
            },
            &headers,
        )
        .unwrap();
    assert_eq!(payload.bind(position), Err(Error::Identity));
    let mut genesis_batch = batch.clone();
    genesis_batch.anchor.height = 0;
    assert_eq!(SourcePayload::from_batch(&genesis_batch), Err(Error::Configuration));
    for field in 0..4 {
        let mut invalid = payload.clone();
        match field {
            0 => invalid.network = B256::ZERO,
            1 => invalid.domain = B256::ZERO,
            2 => invalid.genesis = B256::ZERO,
            3 => invalid.height = 0,
            _ => unreachable!(),
        }
        assert_eq!(invalid.encode(), Err(Error::Configuration));
    }
}
