use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{
    height::{HeightCursor, HeightError, MAX_HEIGHT_HEADERS},
    FinalizedCheckpoint, L1Error,
};
use sha3::{Digest, Sha3_256};

fn header(parent: B256, slot: u64) -> Bytes {
    let mut raw = vec![0; 304];
    raw[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    raw[4..36].copy_from_slice(parent.as_slice());
    raw[100..108].copy_from_slice(&slot.to_le_bytes());
    raw.into()
}
fn id(header: &[u8]) -> B256 {
    let mut hash = Sha3_256::new();
    hash.update(b"BLCH4:BLOCK\0\0\0\0\0");
    hash.update(header);
    B256::from_slice(&hash.finalize())
}
fn chain() -> (HeightCursor, Vec<Bytes>, FinalizedCheckpoint) {
    let genesis = header(B256::ZERO, 0);
    let middle = header(id(&genesis), 7);
    let tip = header(id(&middle), 100);
    let cursor = HeightCursor::from_genesis(id(&genesis), &genesis).unwrap();
    let checkpoint = FinalizedCheckpoint {
        block: id(&tip),
        slot: 100,
    };
    (cursor, vec![genesis, middle, tip], checkpoint)
}

#[test]
fn counts_parent_edges_instead_of_slot_gaps_and_matches_chunked_advancement() {
    let (mut cursor, headers, checkpoint) = chain();
    let genesis = cursor.position();
    assert_eq!((genesis.height(), genesis.slot()), (0, 0));
    let position = cursor.advance(checkpoint, &headers).unwrap();
    assert_eq!((position.height(), position.slot()), (2, 100));
    assert_eq!(position.block(), checkpoint.block);
    assert_eq!(position.genesis(), genesis.block());
    let mut chunked = HeightCursor::from_genesis(genesis.block(), &headers[0]).unwrap();
    let middle = chunked
        .advance(
            FinalizedCheckpoint {
                block: id(&headers[1]),
                slot: 7,
            },
            &headers[..2],
        )
        .unwrap();
    assert_eq!((middle.height(), middle.slot()), (1, 7));
    assert_eq!(chunked.advance(checkpoint, &headers[1..]).unwrap(), position);
}

#[test]
fn omission_alteration_conflict_and_replay_preserve_the_cursor() {
    let (mut cursor, headers, checkpoint) = chain();
    let original = cursor.clone();
    assert_eq!(
        cursor.advance(checkpoint, &[headers[0].clone(), headers[2].clone()]),
        Err(HeightError::Authentication(L1Error::Ancestry))
    );
    assert_eq!(cursor, original);
    let mut altered = headers.clone();
    let mut raw = altered[1].to_vec();
    raw[36] ^= 1;
    altered[1] = raw.into();
    assert!(cursor.advance(checkpoint, &altered).is_err());
    assert_eq!(cursor, original);
    let wrong_checkpoint = FinalizedCheckpoint {
        block: B256::repeat_byte(9),
        ..checkpoint
    };
    assert_eq!(
        cursor.advance(wrong_checkpoint, &headers),
        Err(HeightError::Authentication(L1Error::Checkpoint))
    );
    assert_eq!(cursor, original);
    let mut wrong_slot = checkpoint;
    wrong_slot.slot += 1;
    assert!(cursor.advance(wrong_slot, &headers).is_err());
    assert_eq!(cursor, original);
    cursor.advance(checkpoint, &headers).unwrap();
    let accepted = cursor.clone();
    assert_eq!(cursor.advance(checkpoint, &headers), Err(HeightError::Continuity));
    assert_eq!(cursor.advance(checkpoint, &headers[2..]), Err(HeightError::Replay));
    // A conflicting chain at the same height cannot restart from the old genesis.
    let other_middle = header(id(&headers[0]), 8);
    let other_tip = header(id(&other_middle), 101);
    let conflict = FinalizedCheckpoint {
        block: id(&other_tip),
        slot: 101,
    };
    assert_eq!(
        cursor.advance(conflict, &[headers[0].clone(), other_middle, other_tip]),
        Err(HeightError::Continuity)
    );
    assert_eq!(cursor, accepted);
}

#[test]
fn bounds_malformed_headers_nonincreasing_slots_and_genesis_mismatch_fail_closed() {
    let (mut cursor, headers, checkpoint) = chain();
    let original = cursor.clone();
    let cases = [
        vec![],
        vec![headers[0].clone(); MAX_HEIGHT_HEADERS + 1],
        vec![Bytes::new()],
    ];
    for path in cases {
        assert_eq!(cursor.advance(checkpoint, &path), Err(HeightError::Bounds));
        assert_eq!(cursor, original);
    }
    let same_slot = header(id(&headers[0]), 0);
    assert_eq!(
        cursor.advance(checkpoint, &[headers[0].clone(), same_slot]),
        Err(HeightError::Authentication(L1Error::Ancestry))
    );
    let mut bad = headers.clone();
    let mut raw = bad[1].to_vec();
    raw[0] ^= 1;
    bad[1] = raw.into();
    assert_eq!(
        cursor.advance(checkpoint, &bad),
        Err(HeightError::Authentication(L1Error::Header))
    );
    assert_eq!(cursor, original);
    assert_eq!(
        HeightCursor::from_genesis(B256::repeat_byte(9), &headers[0]),
        Err(HeightError::Genesis)
    );
    assert_eq!(
        HeightCursor::from_genesis(id(&headers[1]), &headers[1]),
        Err(HeightError::Genesis)
    );
    assert_eq!(
        HeightCursor::from_genesis(B256::ZERO, &headers[0]),
        Err(HeightError::Genesis)
    );
}
