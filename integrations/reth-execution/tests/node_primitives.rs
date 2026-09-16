// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual Reth traits and bounded adapters retain the portable V2 wire identity.
use alloy_consensus::{BlockHeader as _, EthereumReceipt, ReceiptEnvelope, SignableTransaction, TxEip1559};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, Bytes, Sealable, Signature, TxKind, B256};
use alloy_rlp::{Decodable, Encodable};
use bloch_l2_evm::{
    node_primitives::{NodeBlockV2, NodeBodyV2, NodeHeaderV2},
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{BlochNodeBlock, BlochNodeBody, BlochNodeHeader, BlochNodePrimitives, BlochRethTransaction};
use k256::ecdsa::SigningKey;
use reth_codecs::{Compact, Compress, Decompress};
use reth_primitives_traits::{Block, BlockBody, NodePrimitives};

fn raw() -> Bytes {
    let tx = TxEip1559 {
        chain_id: ChainSpec::testnet().chain_id,
        nonce: 0,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(7)),
        max_fee_per_gas: 2_000_000_000,
        ..Default::default()
    };
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    BlochRethTransaction::from(tx.into_signed(signature))
        .encoded_2718()
        .into()
}
fn deposit() -> DepositMint {
    DepositMint {
        recipient: Address::repeat_byte(8),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 2,
            l1_txid: [3; 32],
            l1_vout: 4,
            l1_sats: 5,
        },
    }
}
fn body() -> NodeBodyV2 {
    NodeBodyV2 {
        deposits: vec![deposit()],
        transactions: vec![raw()],
    }
}
fn header() -> NodeHeaderV2 {
    let golden =
        alloy_primitives::hex::decode(include_str!("../../../tests/fixtures/node_header_v2.hex").trim()).unwrap();
    NodeHeaderV2::decode(&mut golden.as_slice()).unwrap()
}

#[test]
fn reth_traits_sealing_compact_and_serde_preserve_golden_identity() {
    fn assert_node<N: NodePrimitives>() {}
    assert_node::<BlochNodePrimitives>();
    let header = BlochNodeHeader(header());
    assert_eq!(header.hash_slow(), header.0.hash());
    assert_eq!(
        header.hash_slow(),
        alloy_primitives::b256!("a2aac0c50e8af78ca7781c6e7fcc62bdf2f85e9f5a3f656834aad348bed967e9")
    );
    assert_eq!(header.parent_beacon_block_root(), Some(header.0.anchor_root));
    assert_eq!(header.gas_used(), header.0.gas_used);
    assert_eq!(header.blob_gas_used(), None);
    let mut compact = vec![];
    let size = header.to_compact(&mut compact);
    assert_eq!(compact, alloy_rlp::encode(&header.0));
    assert_eq!(header.clone().compress(), compact);
    assert_eq!(BlochNodeHeader::decompress(&compact).unwrap(), header);
    compact.push(0xaa);
    let (decoded, tail) = BlochNodeHeader::from_compact(&compact, size);
    assert_eq!(decoded, header);
    assert_eq!(tail, &[0xaa]);
    let json = serde_json::to_vec(&header).unwrap();
    assert_eq!(serde_json::from_slice::<BlochNodeHeader>(&json).unwrap(), header);
    let body = BlochNodeBody::try_from_core(body()).unwrap();
    let block = BlochNodeBlock {
        header: header.clone(),
        body,
    };
    let core = block.clone().into_core();
    assert_eq!(alloy_rlp::encode(&block), alloy_rlp::encode(&core));
    assert_eq!(BlochNodeBlock::rlp_length(&block.header, &block.body), block.length());
    let sealed = block.clone().seal_slow();
    assert_eq!(sealed.hash(), header.0.hash());
    assert_eq!(sealed.body().as_core().deposits, core.body.deposits);
    let json = serde_json::to_vec(&block).unwrap();
    assert_eq!(serde_json::from_slice::<BlochNodeBlock>(&json).unwrap(), block);
    let mut encoded = alloy_rlp::encode(&block);
    encoded.push(0xbb);
    let mut input = encoded.as_slice();
    assert_eq!(BlochNodeBlock::decode(&mut input).unwrap(), block);
    assert_eq!(input, &[0xbb]);
}

#[test]
fn body_parsing_is_atomic_bounded_and_preserves_exact_signed_bytes() {
    let core = body();
    let body = BlochNodeBody::try_from_core(core.clone()).unwrap();
    assert_eq!(body.transactions()[0].encoded_2718(), core.transactions[0]);
    assert_eq!(body.calculate_tx_root(), core.transactions_root());
    assert_eq!(body.recover_signers().unwrap().len(), 1);
    assert_eq!(body.clone().into_core(), core);
    // This is only an Ethereum RPC projection; the original body retains deposits.
    assert_eq!(body.clone().into_ethereum_body().transactions, body.transactions());
    for raw in [Bytes::from_static(&[0xff]), {
        let mut raw = raw().to_vec();
        raw.push(0);
        raw.into()
    }] {
        let bad = NodeBodyV2 {
            deposits: vec![deposit()],
            transactions: vec![raw],
        };
        let encoded = alloy_rlp::encode(&bad);
        let mut input = encoded.as_slice();
        assert!(BlochNodeBody::decode(&mut input).is_err());
        assert_eq!(input, encoded);
        let block = NodeBlockV2 {
            header: header(),
            body: bad,
        };
        let encoded = alloy_rlp::encode(&block);
        let mut input = encoded.as_slice();
        assert!(BlochNodeBlock::decode(&mut input).is_err());
        assert_eq!(input, encoded);
    }
    let oversized = NodeBodyV2 {
        deposits: vec![],
        transactions: vec![Bytes::from(vec![
            0;
            bloch_l2_evm::transactions::MAX_RAW_TRANSACTION_BYTES
                + 1
        ])],
    };
    assert!(BlochNodeBody::try_from_core(oversized).is_err());
    let too_many = NodeBodyV2 {
        deposits: vec![],
        transactions: vec![Bytes::new(); bloch_l2_evm::transactions::MAX_SIGNED_TRANSACTIONS + 1],
    };
    assert!(BlochNodeBody::try_from_core(too_many).is_err());
}

#[test]
fn serde_rejects_trailing_or_oversized_header_bytes_and_compact_detects_corruption() {
    let header = BlochNodeHeader(header());
    let mut encoded = alloy_rlp::encode(&header);
    encoded.push(0);
    assert!(serde_json::from_value::<BlochNodeHeader>(serde_json::json!(encoded)).is_err());
    assert!(serde_json::from_value::<BlochNodeHeader>(serde_json::json!(vec![0u8; 1034])).is_err());
    assert!(std::panic::catch_unwind(|| BlochNodeHeader::from_compact(&[0xc0], 1)).is_err());
    assert!(std::panic::catch_unwind(|| BlochNodeHeader::from_compact(&[], 1)).is_err());
    assert!(BlochNodeHeader::decompress(&[0xc0]).is_err());
    assert!(BlochNodeHeader::decompress(&encoded).is_err());
}

#[test]
fn node_transaction_storage_and_receipt_conversion_keep_commitments() {
    let raw = raw();
    let transaction = BlochRethTransaction::decode_2718(&mut raw.as_ref()).unwrap();
    let mut compact = vec![];
    let len = transaction.to_compact(&mut compact);
    let (decoded, rest) = BlochRethTransaction::from_compact(&compact, len);
    assert!(rest.is_empty());
    assert_eq!(decoded.encoded_2718(), raw);
    let receipt = EthereumReceipt {
        tx_type: alloy_consensus::TxType::Eip1559,
        success: true,
        cumulative_gas_used: 21_000,
        logs: vec![alloy_primitives::Log::new_unchecked(
            Address::repeat_byte(9),
            vec![B256::repeat_byte(1)],
            Bytes::new(),
        )],
    };
    let envelope: ReceiptEnvelope = receipt.clone().into();
    let roundtrip: EthereumReceipt = envelope.clone().into();
    assert_eq!(roundtrip, receipt);
    assert_eq!(
        alloy_consensus::proofs::calculate_receipt_root(&[envelope]),
        EthereumReceipt::calculate_receipt_root_no_memo(&[receipt])
    );
    let mut header = BlochNodeHeader(NodeHeaderV2 {
        transactions_root: alloy_consensus::EMPTY_ROOT_HASH,
        deposits_hash: bloch_l2_evm::deposits_hash(&[]),
        ..Default::default()
    });
    assert!(header.is_empty());
    header.0.deposits_hash = bloch_l2_evm::deposits_hash(&[deposit()]);
    assert!(!header.is_empty());
}
