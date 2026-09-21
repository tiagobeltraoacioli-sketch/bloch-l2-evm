// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;

fn vector() -> SettlementPayload {
    SettlementPayload {
        network: B256::repeat_byte(1),
        genesis: B256::repeat_byte(2),
        domain: B256::repeat_byte(3),
        configuration: B256::repeat_byte(4),
        program_elf_keccak: B256::repeat_byte(5),
        program_vkey_koalabear: B256::repeat_byte(6),
        program_vkey_bn254: B256::repeat_byte(7),
        proof_digest: B256::repeat_byte(8),
        previous_settlement: B256::repeat_byte(9),
        chain_id: 700_771,
        l2_number: 16,
        l2_parent_hash: B256::repeat_byte(10),
        l2_previous_state_root: B256::repeat_byte(11),
        l2_header_hash: B256::repeat_byte(12),
        l2_state_root: B256::repeat_byte(13),
        l1_block: B256::repeat_byte(14),
        l1_slot: 17,
        l1_height: 10,
        source_commitment: B256::repeat_byte(15),
        inbox_root: B256::repeat_byte(16),
        inbox_count: 20,
        consumed_start: 3,
        consumed_end: 5,
        body_commitment: B256::repeat_byte(17),
    }
}

#[test]
fn canonical_fixed_width_layout_and_strict_decode() {
    let payload = vector();
    let bytes = payload.encode().unwrap();
    assert_eq!(bytes.len(), SETTLEMENT_PAYLOAD_BYTES);
    let mut expected = Vec::from(CODEC_TAG);
    for byte in 1..=9 {
        expected.extend_from_slice(B256::repeat_byte(byte).as_slice());
    }
    expected.extend_from_slice(&700_771u64.to_le_bytes());
    expected.extend_from_slice(&16u64.to_le_bytes());
    for byte in 10..=14 {
        expected.extend_from_slice(B256::repeat_byte(byte).as_slice());
    }
    expected.extend_from_slice(&17u64.to_le_bytes());
    expected.extend_from_slice(&10u64.to_le_bytes());
    for byte in 15..=16 {
        expected.extend_from_slice(B256::repeat_byte(byte).as_slice());
    }
    expected.extend_from_slice(&20u64.to_le_bytes());
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(&5u64.to_le_bytes());
    expected.extend_from_slice(B256::repeat_byte(17).as_slice());
    assert_eq!(bytes.as_slice(), expected);
    assert_eq!(SettlementPayload::decode(&bytes).unwrap(), payload);

    for end in 0..bytes.len() {
        assert!(SettlementPayload::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(SettlementPayload::decode(&trailing), Err(Error::Codec));
    let mut wrong_tag = bytes;
    wrong_tag[0] ^= 1;
    assert_eq!(SettlementPayload::decode(&wrong_tag), Err(Error::Codec));
}

#[test]
fn every_field_is_committed() {
    let original = vector();
    let expected = original.commitment().unwrap();
    for field in 0..24 {
        let mut changed = original;
        match field {
            0 => changed.network[0] ^= 1,
            1 => changed.genesis[0] ^= 1,
            2 => changed.domain[0] ^= 1,
            3 => changed.configuration[0] ^= 1,
            4 => changed.program_elf_keccak[0] ^= 1,
            5 => changed.program_vkey_koalabear[0] ^= 1,
            6 => changed.program_vkey_bn254[0] ^= 1,
            7 => changed.proof_digest[0] ^= 1,
            8 => changed.previous_settlement[0] ^= 1,
            9 => changed.chain_id += 1,
            10 => changed.l2_number += 1,
            11 => changed.l2_parent_hash[0] ^= 1,
            12 => changed.l2_previous_state_root[0] ^= 1,
            13 => changed.l2_header_hash[0] ^= 1,
            14 => changed.l2_state_root[0] ^= 1,
            15 => changed.l1_block[0] ^= 1,
            16 => changed.l1_slot += 1,
            17 => changed.l1_height -= 1,
            18 => changed.source_commitment[0] ^= 1,
            19 => changed.inbox_root[0] ^= 1,
            20 => changed.inbox_count += 1,
            21 => changed.consumed_start -= 1,
            22 => changed.consumed_end += 1,
            23 => changed.body_commitment[0] ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(changed.commitment().unwrap(), expected, "field {field}");
    }
}

#[test]
fn zero_identities_and_impossible_cursors_are_rejected() {
    for field in 0..16 {
        let mut invalid = vector();
        match field {
            0 => invalid.network = B256::ZERO,
            1 => invalid.genesis = B256::ZERO,
            2 => invalid.domain = B256::ZERO,
            3 => invalid.configuration = B256::ZERO,
            4 => invalid.program_elf_keccak = B256::ZERO,
            5 => invalid.program_vkey_koalabear = B256::ZERO,
            6 => invalid.program_vkey_bn254 = B256::ZERO,
            7 => invalid.proof_digest = B256::ZERO,
            8 => invalid.l2_parent_hash = B256::ZERO,
            9 => invalid.l2_previous_state_root = B256::ZERO,
            10 => invalid.l2_header_hash = B256::ZERO,
            11 => invalid.l2_state_root = B256::ZERO,
            12 => invalid.l1_block = B256::ZERO,
            13 => invalid.source_commitment = B256::ZERO,
            14 => invalid.inbox_root = B256::ZERO,
            15 => invalid.body_commitment = B256::ZERO,
            _ => unreachable!(),
        }
        assert_eq!(invalid.encode(), Err(Error::Configuration), "field {field}");
    }
    let mut first = vector();
    first.previous_settlement = B256::ZERO;
    assert_eq!(SettlementPayload::decode(&first.encode().unwrap()).unwrap(), first);
    let mut invalid = vector();
    invalid.chain_id = 0;
    assert_eq!(invalid.encode(), Err(Error::Configuration));
    invalid = vector();
    invalid.l2_number = 0;
    assert_eq!(invalid.encode(), Err(Error::Configuration));
    invalid = vector();
    invalid.l1_height = 0;
    assert_eq!(invalid.encode(), Err(Error::Configuration));
    invalid = vector();
    invalid.l1_slot = invalid.l1_height - 1;
    assert_eq!(invalid.encode(), Err(Error::Configuration));
    invalid = vector();
    invalid.consumed_start = invalid.consumed_end + 1;
    assert_eq!(invalid.encode(), Err(Error::Mapping));
    invalid = vector();
    invalid.consumed_end = invalid.inbox_count + 1;
    assert_eq!(invalid.encode(), Err(Error::Mapping));

    let mut encoded = vector().encode().unwrap();
    let l2_number_offset = CODEC_TAG.len() + 9 * 32 + 8;
    encoded[l2_number_offset..l2_number_offset + 8].fill(0);
    assert_eq!(SettlementPayload::decode(&encoded), Err(Error::Configuration));
}

#[test]
fn proof_digest_is_exact_bounded_keccak_without_verification_claim() {
    let bytes = b"canonical verified proof bytes";
    assert_eq!(proof_digest(bytes).unwrap(), keccak256(bytes));
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    assert_ne!(proof_digest(&changed).unwrap(), proof_digest(bytes).unwrap());
    assert_eq!(proof_digest(&[]), Err(Error::Codec));
    assert_eq!(
        proof_digest(&vec![0; MAX_SETTLEMENT_PROOF_BYTES + 1]),
        Err(Error::Limit)
    );
}
