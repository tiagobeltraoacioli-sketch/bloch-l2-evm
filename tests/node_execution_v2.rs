// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit V2 execution uses authenticated envelopes and committed V2 parents.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bloom, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    executor::deposits_hash,
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, verify_node_batch, HeadRecordV2},
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, HeadRecord, L2State,
};
use k256::ecdsa::SigningKey;

fn domain() -> B256 {
    B256::repeat_byte(19)
}
fn genesis_header(spec: &ChainSpec, root: B256) -> NodeHeaderV2 {
    HeadRecordV2 {
        base: HeadRecord {
            number: 0,
            timestamp: 10,
            base_fee_per_gas: spec.initial_base_fee,
            gas_used: 0,
            prevrandao: B256::ZERO,
            anchor_root: B256::ZERO,
            parent_hash: B256::ZERO,
            deposits_hash: deposits_hash(&[]),
        },
        user_gas_used: 0,
        parent_state_root: alloy_trie::EMPTY_ROOT_HASH,
        transactions_root: alloy_trie::EMPTY_ROOT_HASH,
        receipts_root: alloy_trie::EMPTY_ROOT_HASH,
        logs_bloom: Bloom::ZERO,
    }
    .header(spec, domain(), root)
}
fn next(spec: &ChainSpec, parent: &NodeHeaderV2) -> BlockContext {
    BlockContext {
        number: parent.number + 1,
        timestamp: parent.timestamp + 1,
        base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
        prevrandao: B256::repeat_byte(7),
        anchor_root: B256::repeat_byte(8),
    }
}
#[test]
fn empty_blocks_link_to_explicit_genesis_and_actual_post_state() {
    let spec = ChainSpec::testnet();
    let mut state = genesis_v2(&spec, 10).unwrap();
    let mut parent = genesis_header(&spec, state.commit_root());
    for _ in 0..2 {
        let body = NodeBodyV2::default();
        let result = execute_node_block(&spec, domain(), &mut state, &next(&spec, &parent), &body).unwrap();
        result.header.validate_parent(&spec, &parent).unwrap();
        result
            .header
            .validate_commitments(&spec, domain(), &body, &result.receipts)
            .unwrap();
        assert_eq!(result.header.state_root, state.commit_root());
        assert_eq!(result.header.parent_state_root, parent.state_root);
        assert!(result.receipts.is_empty());
        parent = result.header;
    }
    assert_eq!(parent.number, 2);
}
#[test]
fn v1_genesis_wrong_context_and_zero_domain_are_atomic() {
    let spec = ChainSpec::testnet();
    let mut state = genesis_v2(&spec, 10).unwrap();
    let root = state.commit_root();
    let valid = next(&spec, &genesis_header(&spec, root));
    let mut v1 = L2State::genesis(&spec);
    let v1_root = v1.commit_root();
    assert!(execute_node_block(&spec, domain(), &mut v1, &valid, &NodeBodyV2::default()).is_err());
    assert_eq!(v1.commit_root(), v1_root);
    let mut wrong_number = valid.clone();
    wrong_number.number += 1;
    let mut wrong_time = valid.clone();
    wrong_time.timestamp = 9;
    let mut wrong_fee = valid.clone();
    wrong_fee.base_fee_per_gas += 1;
    for context in [wrong_number, wrong_time, wrong_fee] {
        assert!(execute_node_block(&spec, domain(), &mut state, &context, &NodeBodyV2::default()).is_err());
        assert_eq!(state.commit_root(), root);
    }
    assert!(execute_node_block(&spec, B256::ZERO, &mut state, &valid, &NodeBodyV2::default()).is_err());
    assert_eq!(state.commit_root(), root);
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sign(spec: &ChainSpec, nonce: u64, to: TxKind, value: U256, input: Bytes) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to,
        value,
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
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}
#[test]
fn signed_deposit_transfer_and_revert_commit_actual_receipts_into_parent() {
    let spec = ChainSpec::testnet();
    let sender = Address::from_public_key(key().verifying_key());
    let recipient = Address::repeat_byte(55);
    let mut state = genesis_v2(&spec, 10).unwrap();
    let genesis = genesis_header(&spec, state.commit_root());
    let body = NodeBodyV2 {
        deposits: vec![DepositMint {
            recipient: sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
        transactions: vec![
            sign(&spec, 0, TxKind::Call(recipient), U256::from(123), Bytes::new()),
            // A reverting CREATE is a valid included transaction, with no created account.
            sign(
                &spec,
                1,
                TxKind::Create,
                U256::ZERO,
                Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]),
            ),
        ],
    };
    let context = next(&spec, &genesis);
    let mut invalid = body.clone();
    invalid.transactions[1] = sign(&spec, 9, TxKind::Create, U256::ZERO, Bytes::from_static(&[0x30, 0xff]));
    let before_balance = state.balance_of(&sender);
    assert!(execute_node_block(&spec, domain(), &mut state, &context, &invalid).is_err());
    assert_eq!(state.commit_root(), genesis.state_root);
    assert_eq!(state.balance_of(&sender), before_balance);
    let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain(), &context, &body).unwrap();
    assert_eq!(state.commit_root(), genesis.state_root);
    let verified = verify_node_batch(&spec, domain(), &witness, &context, &body).unwrap();
    let mut omitted = witness.clone();
    omitted
        .pre_accounts
        .retain(|account| account.address != spec.block_info);
    assert!(verify_node_batch(&spec, domain(), &omitted, &context, &body).is_err());
    let mut tampered = witness.clone();
    tampered
        .pre_accounts
        .iter_mut()
        .find(|account| account.address == spec.block_info)
        .unwrap()
        .balance += U256::from(1);
    assert!(verify_node_batch(&spec, domain(), &tampered, &context, &body).is_err());
    let result = execute_node_block(&spec, domain(), &mut state, &context, &body).unwrap();
    assert_eq!(result.header, recorded.header);
    assert_eq!(result.header, verified.header);
    assert_eq!(result.receipts, recorded.receipts);
    assert_eq!(result.receipts, verified.receipts);
    assert!(result.transactions[0].success);
    assert!(!result.transactions[1].success);
    assert_eq!(result.receipts.len(), 2);
    assert_eq!(state.balance_of(&recipient), U256::from(123));
    assert!(state.account(&sender.create(1)).is_none());
    assert_eq!(result.header.state_root, state.commit_root());
    assert!(result.header.gas_used > result.header.user_gas_used);
    assert_ne!(result.header.receipts_root, alloy_trie::EMPTY_ROOT_HASH);
    result.header.validate_parent(&spec, &genesis).unwrap();
    result
        .header
        .validate_commitments(&spec, domain(), &body, &result.receipts)
        .unwrap();
    let empty = NodeBodyV2::default();
    let second = execute_node_block(&spec, domain(), &mut state, &next(&spec, &result.header), &empty).unwrap();
    second.header.validate_parent(&spec, &result.header).unwrap();
    second
        .header
        .validate_commitments(&spec, domain(), &empty, &second.receipts)
        .unwrap();
    assert_eq!(second.header.parent_hash, result.header.hash());
    let mut forged_parent = result.header.clone();
    forged_parent.receipts_root = alloy_trie::EMPTY_ROOT_HASH;
    assert_ne!(second.header.parent_hash, forged_parent.hash());
    assert_eq!(second.header.state_root, state.commit_root());
}

#[test]
fn blockhash_opcode_returns_committed_v2_parent_in_host_and_witness() {
    use revm::state::{AccountInfo, Bytecode};
    let spec = ChainSpec::testnet();
    let mut state = genesis_v2(&spec, 10).unwrap();
    let contract = Address::repeat_byte(66);
    // Return BLOCKHASH(NUMBER - 1), using the actual shared opcode implementation.
    let code = Bytecode::new_raw(Bytes::from_static(&[
        0x60, 1, 0x43, 0x03, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
    ]));
    state.db_mut().insert_account_info(
        contract,
        AccountInfo {
            nonce: 1,
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let genesis = genesis_header(&spec, state.commit_root());
    let sender = Address::from_public_key(key().verifying_key());
    let first_body = NodeBodyV2 {
        deposits: vec![DepositMint {
            recipient: sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
        transactions: vec![],
    };
    let first = execute_node_block(&spec, domain(), &mut state, &next(&spec, &genesis), &first_body).unwrap();
    let context = next(&spec, &first.header);
    let body = NodeBodyV2 {
        deposits: vec![],
        transactions: vec![sign(&spec, 0, TxKind::Call(contract), U256::ZERO, Bytes::new())],
    };
    let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain(), &context, &body).unwrap();
    let verified = verify_node_batch(&spec, domain(), &witness, &context, &body).unwrap();
    let actual = execute_node_block(&spec, domain(), &mut state, &context, &body).unwrap();
    for result in [&actual, &recorded, &verified] {
        assert_eq!(
            result.transactions[0].result.output().unwrap().as_ref(),
            first.header.hash().as_slice()
        );
        assert_eq!(result.header, actual.header);
        assert_eq!(result.receipts, actual.receipts);
    }
    assert_eq!(actual.header.state_root, state.commit_root());
}

#[test]
fn emitted_log_bloom_and_creation_burn_survive_committed_head_and_witness() {
    use revm::state::{AccountInfo, Bytecode};
    let spec = ChainSpec::testnet();
    let mut state = genesis_v2(&spec, 10).unwrap();
    let emitter = Address::repeat_byte(77);
    // LOG1(topic=42, empty data), then STOP.
    let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 42, 0x60, 0, 0x60, 0, 0xa1, 0x00]));
    state.db_mut().insert_account_info(
        emitter,
        AccountInfo {
            nonce: 1,
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let genesis = genesis_header(&spec, state.commit_root());
    assert_eq!(
        bloch_l2_evm::node_execution::node_head(&spec, domain(), &state).unwrap(),
        genesis
    );
    let sender = Address::from_public_key(key().verifying_key());
    let burned = U256::from(123);
    let body = NodeBodyV2 {
        deposits: vec![DepositMint {
            recipient: sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
        transactions: vec![
            sign(&spec, 0, TxKind::Call(emitter), U256::ZERO, Bytes::new()),
            // A newly created account self-destructs to itself, burning its value.
            sign(&spec, 1, TxKind::Create, burned, Bytes::from_static(&[0x30, 0xff])),
        ],
    };
    let context = next(&spec, &genesis);
    let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain(), &context, &body).unwrap();
    let verified = verify_node_batch(&spec, domain(), &witness, &context, &body).unwrap();
    let actual = execute_node_block(&spec, domain(), &mut state, &context, &body).unwrap();
    for result in [&actual, &recorded, &verified] {
        assert_eq!(result.header, actual.header);
        assert_eq!(result.receipts, actual.receipts);
        assert_eq!(result.transactions[1].burned_wei, burned);
        result
            .header
            .validate_commitments(&spec, domain(), &body, &result.receipts)
            .unwrap();
    }
    let logs = actual.transactions[0].result.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].address, emitter);
    assert_eq!(logs[0].data.topics(), &[B256::from(U256::from(42))]);
    assert_ne!(actual.header.logs_bloom, Bloom::ZERO);
    assert_ne!(actual.header.receipts_root, alloy_trie::EMPTY_ROOT_HASH);
    assert_eq!(state.total_burned_wei(), burned);
    assert_eq!(state.total_native_wei() + burned, state.total_minted_wei());
    assert!(state.account(&sender.create(1)).is_none());
    assert_eq!(actual.header.state_root, state.commit_root());
    assert_eq!(
        bloch_l2_evm::node_execution::node_head(&spec, domain(), &state).unwrap(),
        actual.header
    );
    // Reconstruct the nonempty bloom from committed storage in the next block.
    let empty = NodeBodyV2::default();
    let context = next(&spec, &actual.header);
    let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain(), &context, &empty).unwrap();
    let verified = verify_node_batch(&spec, domain(), &witness, &context, &empty).unwrap();
    let second = execute_node_block(&spec, domain(), &mut state, &context, &empty).unwrap();
    assert_eq!(second.header.parent_hash, actual.header.hash());
    assert_eq!(second.header, recorded.header);
    assert_eq!(second.header, verified.header);
    assert_eq!(second.header.logs_bloom, Bloom::ZERO);
}
