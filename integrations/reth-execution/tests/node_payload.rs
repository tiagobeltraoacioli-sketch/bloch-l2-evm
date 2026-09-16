// SPDX-License-Identifier: MIT OR Apache-2.0
//! Custom payload identity and bounded transport preserve tagged V2 blocks.
use alloy_primitives::{Address, Bytes, B256, U256};
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    BlochBuiltPayload, BlochExecutionPayload, BlochNodeBlock, BlochNodeBody, BlochNodeHeader, BlochPayloadAttributes,
    BlochPayloadTypes,
};
use reth_payload_primitives::{BuiltPayload, ExecutionPayload, PayloadAttributes, PayloadTypes};
use reth_primitives_traits::SealedBlock;
fn deposit() -> DepositMint {
    DepositMint {
        recipient: Address::repeat_byte(7),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 0,
            l1_sats: 9,
        },
    }
}
fn block() -> BlochNodeBlock {
    let spec = ChainSpec::testnet();
    let state = genesis_v2(&spec, 10).unwrap();
    let mut header = node_head(&spec, B256::repeat_byte(3), &state).unwrap();
    let body = NodeBodyV2 {
        deposits: vec![deposit()],
        transactions: vec![],
    };
    header.deposits_hash = body.deposits_hash();
    BlochNodeBlock {
        header: BlochNodeHeader(header),
        body: BlochNodeBody::try_from_core(body).unwrap(),
    }
}
#[test]
fn built_and_transport_payloads_keep_custom_hash_body_and_sidecar() {
    let block = block();
    let hash = block.header.0.hash();
    let built = BlochBuiltPayload::new(block.clone(), U256::from(123));
    assert_eq!(built.block().hash(), hash);
    assert_eq!(built.fees(), U256::from(123));
    assert!(built.requests().is_none());
    let payload: BlochExecutionPayload = built.into();
    assert_eq!(payload.block, block);
    assert_eq!(payload.block_hash(), hash);
    assert_eq!(payload.transaction_count(), 0);
    assert!(payload.withdrawals().is_none());
    let payload = BlochPayloadTypes::block_to_payload(
        SealedBlock::seal_slow(block.clone()),
        Some(Bytes::from_static(&[1, 2, 3])),
    );
    let decoded: BlochExecutionPayload = serde_json::from_slice(&serde_json::to_vec(&payload).unwrap()).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded.block_hash(), hash);
    assert_eq!(decoded.block.body.as_core().deposits, vec![deposit()]);
    assert_eq!(decoded.block_access_list().unwrap().as_ref(), &[1, 2, 3]);
    let mut malformed = serde_json::to_value(&payload).unwrap();
    malformed["block"] = serde_json::json!([255]);
    assert!(serde_json::from_value::<BlochExecutionPayload>(malformed).is_err());
}
#[test]
fn build_identity_binds_all_custom_attributes_and_parent() {
    let domain = B256::repeat_byte(3);
    let parent = B256::repeat_byte(4);
    let make = |domain, time, random, anchor, deposits| {
        BlochPayloadAttributes::try_new(domain, time, random, anchor, deposits).unwrap()
    };
    let attrs = make(domain, 10, B256::repeat_byte(5), B256::repeat_byte(6), vec![deposit()]);
    let id = attrs.payload_id(&parent);
    for alternate in [
        make(
            B256::repeat_byte(8),
            10,
            attrs.prevrandao(),
            attrs.anchor_root(),
            vec![deposit()],
        ),
        make(domain, 11, attrs.prevrandao(), attrs.anchor_root(), vec![deposit()]),
        make(domain, 10, B256::repeat_byte(9), attrs.anchor_root(), vec![deposit()]),
        make(domain, 10, attrs.prevrandao(), B256::repeat_byte(9), vec![deposit()]),
        make(domain, 10, attrs.prevrandao(), attrs.anchor_root(), vec![]),
    ] {
        assert_ne!(alternate.payload_id(&parent), id);
    }
    assert_ne!(attrs.payload_id(&B256::ZERO), id);
    let decoded: BlochPayloadAttributes = serde_json::from_slice(&serde_json::to_vec(&attrs).unwrap()).unwrap();
    assert_eq!(decoded, attrs);
    assert_eq!(decoded.payload_id(&parent), id);
    assert_eq!(decoded.deposits(), &[deposit()]);
    assert!(BlochPayloadAttributes::try_new(B256::ZERO, 10, B256::ZERO, B256::ZERO, vec![]).is_err());
    let mut invalid = serde_json::to_value(&attrs).unwrap();
    invalid["domain"] = serde_json::to_value(B256::ZERO).unwrap();
    assert!(serde_json::from_value::<BlochPayloadAttributes>(invalid).is_err());
}

#[test]
fn attributes_cannot_smuggle_user_transactions_in_deposit_body() {
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    let tx: bloch_reth_execution::BlochRethTransaction = TxEip1559::default()
        .into_signed(alloy_primitives::Signature::new(U256::from(1), U256::from(1), false))
        .into();
    let body = BlochNodeBody::try_from_core(NodeBodyV2 {
        deposits: vec![],
        transactions: vec![tx.encoded_2718().into()],
    })
    .unwrap();
    let attrs = BlochPayloadAttributes::try_new(B256::repeat_byte(3), 10, B256::ZERO, B256::ZERO, vec![]).unwrap();
    let mut value = serde_json::to_value(attrs).unwrap();
    value["deposits"] = serde_json::to_value(body).unwrap();
    assert!(serde_json::from_value::<BlochPayloadAttributes>(value).is_err());
}
