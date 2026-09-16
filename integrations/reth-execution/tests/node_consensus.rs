// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reth consensus traits validate actual V2 execution, not Ethereum projections.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bloom, Bytes, Signature, TxKind, B256};
use bloch_l2_evm::{
    node_execution::{execute_node_block, genesis_v2},
    node_primitives::NodeBodyV2,
    BlockContext, ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    BlochChainSpec, BlochConsensus, BlochNodeBlock, BlochNodeBody, BlochNodeHeader, BlochRethReceipt,
    BlochRethTransaction,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, FullConsensus, HeaderValidator};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn raw(spec: &ChainSpec, nonce: u64, input: Bytes) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to: TxKind::Create,
        input,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    let tx: BlochRethTransaction = tx.into_signed(signature).into();
    tx.encoded_2718().into()
}
fn fixture() -> (
    Arc<BlochChainSpec>,
    BlochNodeBlock,
    BlockExecutionResult<BlochRethReceipt>,
) {
    let kernel = ChainSpec::testnet();
    let domain = B256::repeat_byte(42);
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), domain, 10).unwrap());
    let mut state = genesis_v2(&kernel, 10).unwrap();
    let body = NodeBodyV2 {
        deposits: vec![DepositMint {
            recipient: Address::from_public_key(key().verifying_key()),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
        transactions: vec![
            raw(&kernel, 0, Bytes::from_static(&[0x60, 42, 0x60, 0, 0x60, 0, 0xa1, 0])),
            raw(&kernel, 1, Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd])),
        ],
    };
    let context = BlockContext {
        number: 1,
        timestamp: 11,
        base_fee_per_gas: kernel.next_base_fee(kernel.initial_base_fee, 0),
        prevrandao: B256::ZERO,
        anchor_root: B256::repeat_byte(1),
    };
    let outcome = execute_node_block(&kernel, domain, &mut state, &context, &body).unwrap();
    let result = BlockExecutionResult {
        receipts: outcome.receipts.into_iter().map(Into::into).collect(),
        gas_used: outcome.header.gas_used,
        blob_gas_used: 0,
        requests: Default::default(),
    };
    (
        spec,
        BlochNodeBlock {
            header: BlochNodeHeader(outcome.header),
            body: BlochNodeBody::try_from_core(body).unwrap(),
        },
        result,
    )
}
#[test]
fn genuine_execution_passes_all_traits_and_cached_hints_cannot_bypass_recomputation() {
    let (spec, block, result) = fixture();
    let validator = BlochConsensus::new(spec.clone());
    let parent = SealedHeader::seal_slow(spec.genesis_header().clone());
    let header = SealedHeader::seal_slow(block.header.clone());
    validator.validate_header(&parent).unwrap();
    validator.validate_header_against_parent(&header, &parent).unwrap();
    let sealed = SealedBlock::seal_slow(block.clone());
    validator
        .validate_block_pre_execution_with_tx_root(&sealed, Some(block.header.0.transactions_root))
        .unwrap();
    assert!(validator
        .validate_block_pre_execution_with_tx_root(&sealed, Some(B256::ZERO))
        .is_err());
    let recovered = RecoveredBlock::try_recover(block.clone()).unwrap();
    let correct = Some((block.header.0.receipts_root, block.header.0.logs_bloom));
    validator
        .validate_block_post_execution(&recovered, &result, correct, None)
        .unwrap();
    assert!(result.gas_used > result.receipts.last().unwrap().cumulative_gas_used);
    assert!(!result.receipts[1].success);
    assert_ne!(block.header.0.logs_bloom, Bloom::ZERO);
    assert!(validator
        .validate_block_post_execution(&recovered, &result, Some((B256::ZERO, block.header.0.logs_bloom)), None)
        .is_err());
    assert!(validator
        .validate_block_post_execution(
            &recovered,
            &result,
            Some((block.header.0.receipts_root, Bloom::ZERO)),
            None
        )
        .is_err());
    let mut corrupt = result.clone();
    corrupt.receipts[0].success = false;
    assert!(validator
        .validate_block_post_execution(&recovered, &corrupt, correct, None)
        .is_err());
    corrupt = result.clone();
    corrupt.receipts[0].cumulative_gas_used += 1;
    assert!(validator
        .validate_block_post_execution(&recovered, &corrupt, correct, None)
        .is_err());
    corrupt = result.clone();
    corrupt.gas_used += 1;
    assert!(validator
        .validate_block_post_execution(&recovered, &corrupt, None, None)
        .is_err());
    corrupt = result.clone();
    corrupt.receipts.push(corrupt.receipts[0].clone());
    assert!(validator
        .validate_block_post_execution(&recovered, &corrupt, correct, None)
        .is_err());
    corrupt = result.clone();
    corrupt.requests = alloy_eips::eip7685::Requests::new(vec![Bytes::from_static(&[0, 1])]);
    assert!(validator
        .validate_block_post_execution(&recovered, &corrupt, None, None)
        .is_err());
    corrupt = result.clone();
    corrupt.blob_gas_used = 1;
    assert!(validator
        .validate_block_post_execution(&recovered, &corrupt, None, None)
        .is_err());
    assert!(validator
        .validate_block_post_execution(&recovered, &result, None, Some(B256::ZERO))
        .is_err());
}
#[test]
fn configured_genesis_seals_parent_fields_and_signed_body_are_enforced() {
    let (spec, block, _) = fixture();
    let validator = BlochConsensus::new(spec.clone());
    let parent = SealedHeader::seal_slow(spec.genesis_header().clone());
    assert!(validator
        .validate_header(&SealedHeader::new(block.header.clone(), B256::ZERO))
        .is_err());
    let mut altered = spec.genesis_header().clone();
    altered.0.timestamp += 1;
    assert!(validator.validate_header(&SealedHeader::seal_slow(altered)).is_err());
    for field in 0..6 {
        let mut header = block.header.clone();
        match field {
            0 => header.0.parent_hash = B256::ZERO,
            1 => header.0.parent_state_root = B256::ZERO,
            2 => header.0.number += 1,
            3 => header.0.timestamp = 9,
            4 => header.0.base_fee_per_gas += 1,
            _ => header.0.domain = B256::repeat_byte(9),
        }
        assert!(validator
            .validate_header_against_parent(&SealedHeader::seal_slow(header), &parent)
            .is_err());
    }
    let mut wrong = block.clone();
    wrong.header.0.deposits_hash = B256::ZERO;
    assert!(validator
        .validate_block_pre_execution(&SealedBlock::seal_slow(wrong))
        .is_err());
    let mut wrong = block.clone();
    wrong.header.0.gas_used += 1;
    assert!(validator
        .validate_block_pre_execution(&SealedBlock::seal_slow(wrong))
        .is_err());
    let mut body = block.body.as_core().clone();
    let mut foreign = spec.execution().clone();
    foreign.chain_id += 1;
    body.transactions[0] = raw(&foreign, 0, Bytes::new());
    let mut wrong = block;
    wrong.header.0.transactions_root = body.transactions_root();
    wrong.body = BlochNodeBody::try_from_core(body).unwrap();
    assert!(validator
        .validate_block_pre_execution(&SealedBlock::seal_slow(wrong))
        .is_err());
}
