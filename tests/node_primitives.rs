// SPDX-License-Identifier: MIT OR Apache-2.0
//! V2 codec/commitment qualification only; no V2 execution or activation claim.
use alloy_consensus::{
    proofs::calculate_receipt_root, Eip658Value, Receipt, ReceiptEnvelope, SignableTransaction, TxEip1559, TxEnvelope,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, Address, Bloom, Bytes, Signature, TxKind, B256};
use alloy_rlp::{Decodable, Encodable, Header};
use bloch_l2_evm::{
    node_primitives::{NodeBodyV2, NodeHeaderError, NodeHeaderV2},
    ChainSpec, DepositMint, DepositProvenance, L2Header,
};
use k256::ecdsa::SigningKey;

fn golden_header() -> NodeHeaderV2 {
    NodeHeaderV2 {
        domain: B256::repeat_byte(1),
        chain_id: 1,
        number: 2,
        timestamp: 3,
        base_fee_per_gas: 4,
        gas_limit: 5,
        gas_used: 4,
        user_gas_used: 3,
        beneficiary: Address::repeat_byte(2),
        prevrandao: B256::repeat_byte(3),
        anchor_root: B256::repeat_byte(4),
        parent_hash: B256::repeat_byte(5),
        parent_state_root: B256::repeat_byte(6),
        transactions_root: B256::repeat_byte(7),
        receipts_root: B256::repeat_byte(8),
        deposits_hash: B256::repeat_byte(9),
        logs_bloom: Bloom::ZERO,
        state_root: B256::repeat_byte(10),
    }
}
#[test]
fn header_golden_encoding_hash_and_stream_roundtrip() {
    let header = golden_header();
    // Independently generated with a small canonical RLP encoder over the
    // documented field list, not the Rust header's fields()/encode methods.
    let golden = hex::decode(include_str!("fixtures/node_header_v2.hex").trim()).unwrap();
    assert_eq!(alloy_rlp::encode(&header), golden);
    assert_eq!(header.length(), golden.len());
    assert_eq!(
        header.hash(),
        alloy_primitives::b256!("a2aac0c50e8af78ca7781c6e7fcc62bdf2f85e9f5a3f656834aad348bed967e9")
    );
    let mut stream = golden.clone();
    stream.extend_from_slice(&golden);
    let mut bytes = stream.as_slice();
    assert_eq!(NodeHeaderV2::decode(&mut bytes).unwrap(), header);
    assert_eq!(bytes, golden);
    assert_eq!(NodeHeaderV2::decode(&mut bytes).unwrap(), header);
    assert!(bytes.is_empty());
}
#[test]
fn malformed_header_and_every_truncation_fail_without_consuming_input() {
    let encoded = alloy_rlp::encode(golden_header());
    for end in 0..encoded.len() {
        let mut input = &encoded[..end];
        let original = input;
        assert!(NodeHeaderV2::decode(&mut input).is_err());
        assert_eq!(input, original);
    }
    let mut input = encoded.as_slice();
    let payload = Header::decode_bytes(&mut input, true).unwrap();
    let mut wrong_version = payload.to_vec();
    wrong_version[18] = b'1';
    let mut extra = payload.to_vec();
    extra.push(0x80);
    // Locate chain_id after tag and domain, and encode one noncanonically.
    let mut fields = payload;
    Header::decode_bytes(&mut fields, false).unwrap();
    B256::decode(&mut fields).unwrap();
    let offset = payload.len() - fields.len();
    let mut noncanonical = payload[..offset].to_vec();
    noncanonical.extend_from_slice(&[0x81, 1]);
    noncanonical.extend_from_slice(&fields[1..]);
    for payload in [wrong_version, extra, noncanonical] {
        let mut encoded = Vec::new();
        Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut encoded);
        encoded.extend(payload);
        let mut input = encoded.as_slice();
        assert!(NodeHeaderV2::decode(&mut input).is_err());
        assert_eq!(input, encoded);
    }
}
#[test]
fn every_header_field_is_bound_and_v1_identity_remains_distinct() {
    let h = golden_header();
    let hash = h.hash();
    let mut variants = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut variant = h.clone();
            variant.$field = $value;
            variants.push(variant);
        }};
    }
    changed!(domain, B256::ZERO);
    changed!(chain_id, 2);
    changed!(number, 3);
    changed!(timestamp, 4);
    changed!(base_fee_per_gas, 5);
    changed!(gas_limit, 6);
    changed!(gas_used, 5);
    changed!(user_gas_used, 4);
    changed!(beneficiary, Address::ZERO);
    changed!(prevrandao, B256::ZERO);
    changed!(anchor_root, B256::ZERO);
    changed!(parent_hash, B256::ZERO);
    changed!(parent_state_root, B256::ZERO);
    changed!(transactions_root, B256::ZERO);
    changed!(receipts_root, B256::ZERO);
    changed!(deposits_hash, B256::ZERO);
    changed!(logs_bloom, Bloom::repeat_byte(1));
    changed!(state_root, B256::ZERO);
    for variant in variants {
        assert_ne!(variant.hash(), hash);
    }
    let legacy = L2Header {
        chain_id: h.chain_id,
        number: h.number,
        timestamp: h.timestamp,
        base_fee_per_gas: h.base_fee_per_gas,
        gas_used: h.gas_used,
        prevrandao: h.prevrandao,
        anchor_root: h.anchor_root,
        parent_hash: h.parent_hash,
        deposits_hash: h.deposits_hash,
        state_root: h.state_root,
    };
    assert_ne!(legacy.hash(), hash);
}
fn fixture() -> (ChainSpec, NodeHeaderV2, NodeBodyV2, Vec<ReceiptEnvelope>) {
    let spec = ChainSpec::testnet();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce: 0,
        gas_limit: 50_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to: TxKind::Call(Address::repeat_byte(0x22)),
        ..Default::default()
    };
    let sig: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    let body = NodeBodyV2 {
        transactions: vec![TxEnvelope::from(tx.into_signed(sig)).encoded_2718().into()],
        deposits: vec![DepositMint {
            recipient: Address::from_public_key(key.verifying_key()),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
    };
    // Synthetic receipt: consistency validation must not be described as execution.
    let receipts = vec![ReceiptEnvelope::Eip1559(
        Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 21_000,
            logs: vec![],
        }
        .with_bloom(),
    )];
    let header = NodeHeaderV2 {
        domain: B256::repeat_byte(0x44),
        chain_id: spec.chain_id,
        number: 1,
        timestamp: 1,
        base_fee_per_gas: spec.initial_base_fee,
        gas_limit: spec.gas_limit,
        gas_used: 21_000 + spec.deposit_gas,
        user_gas_used: 21_000,
        beneficiary: spec.coinbase(),
        transactions_root: body.transactions_root(),
        receipts_root: calculate_receipt_root(&receipts),
        deposits_hash: body.deposits_hash(),
        ..Default::default()
    };
    (spec, header, body, receipts)
}
#[test]
fn commitments_bind_body_receipts_domain_and_separate_deposit_gas() {
    let (spec, header, body, receipts) = fixture();
    header
        .validate_commitments(&spec, header.domain, &body, &receipts)
        .unwrap();
    let mut wrong = header.clone();
    wrong.gas_used = wrong.user_gas_used;
    assert!(matches!(
        wrong.validate_commitments(&spec, header.domain, &body, &receipts),
        Err(NodeHeaderError::GasAccounting)
    ));
    assert!(header
        .validate_commitments(&spec, B256::repeat_byte(0x45), &body, &receipts)
        .is_err());
    let mut changed = body.clone();
    changed.deposits[0].recipient = Address::ZERO;
    assert!(header
        .validate_commitments(&spec, header.domain, &changed, &receipts)
        .is_err());
    changed = body.clone();
    changed.transactions[0] = Bytes::from_static(&[0x02]);
    assert!(matches!(
        header.validate_commitments(&spec, header.domain, &changed, &receipts),
        Err(NodeHeaderError::Body(_))
    ));
    assert!(header.validate_commitments(&spec, header.domain, &body, &[]).is_err());
    let mut changed = receipts.clone();
    if let ReceiptEnvelope::Eip1559(receipt) = &mut changed[0] {
        receipt.receipt.status = Eip658Value::Eip658(false);
    }
    assert!(matches!(
        header.validate_commitments(&spec, header.domain, &body, &changed),
        Err(NodeHeaderError::ReceiptCommitment)
    ));
    changed = receipts.clone();
    if let ReceiptEnvelope::Eip1559(receipt) = &mut changed[0] {
        receipt.logs_bloom = Bloom::repeat_byte(1);
    }
    assert!(matches!(
        header.validate_commitments(&spec, header.domain, &body, &changed),
        Err(NodeHeaderError::Receipts)
    ));
    changed = receipts.clone();
    if let ReceiptEnvelope::Eip1559(receipt) = &mut changed[0] {
        receipt.receipt.cumulative_gas_used = 50_001;
    }
    assert!(matches!(
        header.validate_commitments(&spec, header.domain, &body, &changed),
        Err(NodeHeaderError::Receipts)
    ));
    let receipt = Receipt {
        status: Eip658Value::PostState(B256::ZERO),
        cumulative_gas_used: 21_000,
        logs: vec![],
    }
    .with_bloom();
    assert!(matches!(
        header.validate_commitments(&spec, header.domain, &body, &[ReceiptEnvelope::Eip1559(receipt)]),
        Err(NodeHeaderError::Receipts)
    ));
}
#[test]
fn parent_state_root_and_next_context_are_bound() {
    let (spec, parent, _, _) = fixture();
    let mut next = parent.clone();
    next.number += 1;
    next.parent_hash = parent.hash();
    next.parent_state_root = parent.state_root;
    next.base_fee_per_gas = spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used);
    next.validate_parent(&spec, &parent).unwrap();
    let mut wrong = next.clone();
    wrong.parent_state_root = B256::repeat_byte(9);
    assert!(wrong.validate_parent(&spec, &parent).is_err());
    wrong = next.clone();
    wrong.parent_hash = B256::ZERO;
    assert!(wrong.validate_parent(&spec, &parent).is_err());
    wrong = next.clone();
    wrong.number += 1;
    assert!(wrong.validate_parent(&spec, &parent).is_err());
    wrong = next.clone();
    wrong.timestamp = 0;
    assert!(wrong.validate_parent(&spec, &parent).is_err());
    wrong = next;
    wrong.base_fee_per_gas += 1;
    assert!(wrong.validate_parent(&spec, &parent).is_err());
}

#[test]
fn empty_and_deposit_only_blocks_need_no_fabricated_receipts() {
    let (spec, mut header, mut body, _) = fixture();
    body.transactions.clear();
    header.transactions_root = body.transactions_root();
    header.receipts_root = calculate_receipt_root::<ReceiptEnvelope>(&[]);
    header.user_gas_used = 0;
    header.gas_used = spec.deposit_gas;
    header.validate_commitments(&spec, header.domain, &body, &[]).unwrap();
    body.deposits.clear();
    header.deposits_hash = body.deposits_hash();
    header.gas_used = 0;
    header.validate_commitments(&spec, header.domain, &body, &[]).unwrap();
}

#[test]
fn receipt_type_and_real_log_bloom_are_checked_independently_of_roots() {
    let (spec, mut header, body, _) = fixture();
    let log = alloy_primitives::Log::new(
        Address::repeat_byte(0x22),
        vec![B256::repeat_byte(0x33)],
        Bytes::from_static(b"fixture"),
    )
    .unwrap();
    let receipt = Receipt {
        status: Eip658Value::Eip658(true),
        cumulative_gas_used: 21_000,
        logs: vec![log],
    }
    .with_bloom();
    let receipts = vec![ReceiptEnvelope::Eip1559(receipt.clone())];
    header.receipts_root = calculate_receipt_root(&receipts);
    header.logs_bloom = receipt.logs_bloom;
    header
        .validate_commitments(&spec, header.domain, &body, &receipts)
        .unwrap();
    let mut wrong = header.clone();
    wrong.logs_bloom = Bloom::ZERO;
    assert!(matches!(
        wrong.validate_commitments(&spec, header.domain, &body, &receipts),
        Err(NodeHeaderError::ReceiptCommitment)
    ));
    wrong = header.clone();
    wrong.transactions_root = B256::ZERO;
    assert!(matches!(
        wrong.validate_commitments(&spec, header.domain, &body, &receipts),
        Err(NodeHeaderError::BodyCommitment)
    ));
    wrong = header.clone();
    wrong.receipts_root = B256::ZERO;
    assert!(matches!(
        wrong.validate_commitments(&spec, header.domain, &body, &receipts),
        Err(NodeHeaderError::ReceiptCommitment)
    ));
    let wrong_type = vec![ReceiptEnvelope::Eip2930(receipt)];
    header.receipts_root = calculate_receipt_root(&wrong_type);
    assert!(matches!(
        header.validate_commitments(&spec, header.domain, &body, &wrong_type),
        Err(NodeHeaderError::Receipts)
    ));
}
