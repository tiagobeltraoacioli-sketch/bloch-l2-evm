// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cross-repository conformance for the native settlement V3 transaction frame.
//!
//! The SAME vector is rebuilt independently by the native repository
//! (`bloch-pos-committee/tests/l2_settlement_v3_frame.rs`) from its own offsets
//! and tags, against an identical copy of
//! `tests/fixtures/native-settlement-v3/frame-async.hex`. A drift in the tag set,
//! the statement layout or the frame order on either side fails CI there or here.
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{
    native_settlement::{
        NativeSettlementFrameV3, NativeSettlementModeV3, NativeWireTags, SettlementTransactionV1,
        NATIVE_SETTLEMENT_BYTES, NATIVE_SETTLEMENT_TAG, NATIVE_SETTLEMENT_V3_BYTES,
    },
    proof_statement::{SettlementStatementV2, SettlementStatementV3, SETTLEMENT_STATEMENT_V3_LEN},
};

const FIXTURE: &str = include_str!("fixtures/native-settlement-v3/frame-async.hex");
/// keccak256 of the 1155-byte asynchronous (0x13) frame below.
const FRAME_ASYNC_KECCAK: &str = "b4a32832b08b2297693a9f6f1468d59301f13bdedd0af059d6054200147117d4";

fn golden_statement() -> SettlementStatementV3 {
    SettlementStatementV3 {
        base: SettlementStatementV2 {
            network: B256::repeat_byte(0x01),
            genesis: B256::repeat_byte(0x02),
            domain: B256::repeat_byte(0x03),
            configuration: B256::repeat_byte(0x04),
            program_elf_keccak: B256::repeat_byte(0x05),
            program_vkey_koalabear: B256::repeat_byte(0x06),
            program_vkey_bn254: B256::repeat_byte(0x07),
            previous_settlement: B256::repeat_byte(0x08),
            chain_id: 0x0102_0304_0506_0708,
            l2_number: 0x1112_1314_1516_1718,
            l2_parent_hash: B256::repeat_byte(0x09),
            l2_previous_state_root: B256::repeat_byte(0x0a),
            l2_header_hash: B256::repeat_byte(0x0b),
            l2_state_root: B256::repeat_byte(0x0c),
            l1_block: B256::repeat_byte(0x0d),
            l1_slot: 0x2122_2324_2526_2728,
            l1_height: 0x3132_3334_3536_3738,
            source_commitment: B256::repeat_byte(0x0e),
            inbox_root: B256::repeat_byte(0x0f),
            inbox_count: 0x4142_4344_4546_4748,
            consumed_start: 0x5152_5354_5556_5758,
            consumed_end: 0x6162_6364_6566_6768,
            body_commitment: B256::repeat_byte(0x10),
        },
        deposits_hash: B256::repeat_byte(0x11),
        transactions_root: B256::repeat_byte(0x12),
        receipts_root: B256::repeat_byte(0x13),
        user_tx_count: 0x7172_7374_7576_7778,
        withdrawal_root: B256::repeat_byte(0x14),
        withdrawal_count: 0x8182_8384_8586_8788,
        da_commitment: B256::repeat_byte(0x15),
    }
}

fn golden_frame(mode: NativeSettlementModeV3) -> NativeSettlementFrameV3 {
    NativeSettlementFrameV3 {
        mode,
        proof_policy: B256::repeat_byte(0xa5),
        statement: golden_statement(),
        proof: core::array::from_fn(|i| (i * 7 + 3) as u8),
    }
}

fn fixture_bytes() -> Vec<u8> {
    alloy_primitives::hex::decode(FIXTURE.trim()).expect("fixture is hex")
}

#[test]
fn v3_frame_matches_the_shared_cross_repository_vector() {
    let frame = golden_frame(NativeSettlementModeV3::Asynchronous).encode();
    assert_eq!(frame.len(), NATIVE_SETTLEMENT_V3_BYTES);
    assert_eq!(NATIVE_SETTLEMENT_V3_BYTES, 1155);
    assert_eq!(frame[0], 0x13);
    assert_eq!(&frame[1..33], &[0xa5; 32]);
    assert_eq!(&frame[33..33 + 22], b"BLOCH:EVM:SETTLEMENT:3");
    assert_eq!(
        &frame[33 + SETTLEMENT_STATEMENT_V3_LEN..33 + SETTLEMENT_STATEMENT_V3_LEN + 2],
        &[3, 10]
    );
    assert_eq!(frame, fixture_bytes(), "frame differs from the shared fixture");
    assert_eq!(format!("{:x}", keccak256(&frame)), FRAME_ASYNC_KECCAK);
    // The synchronous frame differs only in its first byte.
    let sync = golden_frame(NativeSettlementModeV3::Synchronous).encode();
    assert_eq!(sync[0], 0x12);
    assert_eq!(sync[1..], frame[1..]);
}

#[test]
fn v3_frame_round_trips_and_refuses_historical_tags_and_other_lengths() {
    for mode in [
        NativeSettlementModeV3::Synchronous,
        NativeSettlementModeV3::Asynchronous,
    ] {
        let frame = golden_frame(mode);
        let bytes = frame.encode();
        assert_eq!(NativeSettlementFrameV3::decode(&bytes).unwrap(), frame);
        for len in 0..bytes.len() {
            assert!(NativeSettlementFrameV3::decode(&bytes[..len]).is_err(), "prefix {len}");
        }
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(NativeSettlementFrameV3::decode(&suffix).is_err());
        // Every tag other than 0x12/0x13 is refused, including the historical
        // 0x0E/0x0F/0x10 and the renumbered deposit tag 0x14.
        for tag in 0..=u8::MAX {
            let mut retagged = bytes.clone();
            retagged[0] = tag;
            assert_eq!(
                NativeSettlementFrameV3::decode(&retagged).is_ok(),
                tag == 0x12 || tag == 0x13,
                "tag {tag:#x}"
            );
        }
        // A V2 statement tag inside a V3-length frame is refused.
        let mut v2_tag = bytes.clone();
        v2_tag[33 + 21] = b'2';
        assert!(NativeSettlementFrameV3::decode(&v2_tag).is_err());
    }
    // The V2 (979-byte, 0x0E) codec and the V3 codec never accept each other.
    let v2 = SettlementTransactionV1::new(B256::repeat_byte(0xa5), golden_statement().base, [9; 356])
        .unwrap()
        .encode_wire(bloch_l2_evm::native_settlement::SettlementWireFormat::NativeV1);
    assert_eq!(v2.len(), NATIVE_SETTLEMENT_BYTES);
    assert!(NativeSettlementFrameV3::decode(&v2).is_err());
    assert!(SettlementTransactionV1::decode_wire(&golden_frame(NativeSettlementModeV3::Synchronous).encode()).is_err());
}

#[test]
fn wire_tag_sets_are_versioned_and_v2_clears_the_mainnet_space() {
    assert_eq!(
        NativeWireTags::V1,
        NativeWireTags {
            settlement: 0x0e,
            settlement_async: 0x0f,
            deposit: 0x10
        }
    );
    assert_eq!(NativeWireTags::V1.settlement, NATIVE_SETTLEMENT_TAG);
    assert_eq!(
        NativeWireTags::V2,
        NativeWireTags {
            settlement: 0x12,
            settlement_async: 0x13,
            deposit: 0x14
        }
    );
    // Mainnet assigns 0x00..=0x11 (0x0E..=0x11: funded delegation). The
    // renumbered set must sit entirely above it; V1 does not.
    let v2 = [
        NativeWireTags::V2.settlement,
        NativeWireTags::V2.settlement_async,
        NativeWireTags::V2.deposit,
    ];
    assert!(v2.iter().all(|tag| *tag > 0x11));
    let v1 = [
        NativeWireTags::V1.settlement,
        NativeWireTags::V1.settlement_async,
        NativeWireTags::V1.deposit,
    ];
    assert!(v1.iter().all(|tag| !v2.contains(tag)));
    assert_eq!(NativeSettlementModeV3::Synchronous.tag(), NativeWireTags::V2.settlement);
    assert_eq!(
        NativeSettlementModeV3::Asynchronous.tag(),
        NativeWireTags::V2.settlement_async
    );
}
