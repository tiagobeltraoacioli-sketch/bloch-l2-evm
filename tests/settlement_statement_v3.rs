// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement V3 derived from actual stateless re-execution of a block that
//! carries user transactions (a transfer and a reverting CREATE) plus a deposit.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bloom, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    executor::deposits_hash,
    node_execution::{generate_node_batch_witness, genesis_v2, HeadRecordV2},
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{
        execute_settlement_statement_v2, execute_settlement_statement_v3, settlement_v3_layout, SettlementContextV2,
        SettlementStatementV3, SETTLEMENT_STATEMENT_V3_TAG,
    },
    BlockContext, ChainSpec, DepositMint, DepositProvenance, HeadRecord,
};
use k256::ecdsa::SigningKey;

fn domain() -> B256 {
    B256::repeat_byte(0xd3)
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
fn v3_statement_settles_a_block_with_user_transactions() {
    let spec = ChainSpec::testnet();
    let sender = Address::from_public_key(key().verifying_key());
    let mut state = genesis_v2(&spec, 10).unwrap();
    let genesis = genesis_header(&spec, state.commit_root());
    let deposit = DepositMint {
        recipient: sender,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 7,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 1,
            l1_sats: 100_000_000,
        },
    };
    let body = NodeBodyV2 {
        deposits: vec![deposit],
        transactions: vec![
            sign(
                &spec,
                0,
                TxKind::Call(Address::repeat_byte(55)),
                U256::from(123),
                Bytes::new(),
            ),
            sign(
                &spec,
                1,
                TxKind::Create,
                U256::ZERO,
                Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]),
            ),
        ],
    };
    let context = BlockContext {
        number: 1,
        timestamp: 11,
        base_fee_per_gas: spec.next_base_fee(genesis.base_fee_per_gas, genesis.gas_used),
        prevrandao: B256::repeat_byte(7),
        anchor_root: B256::repeat_byte(8),
    };
    let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain(), &context, &body).unwrap();
    let settlement = SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: B256::repeat_byte(0x43),
        program_vkey_koalabear: B256::repeat_byte(0x44),
        program_vkey_bn254: B256::repeat_byte(0x45),
        previous_settlement: B256::ZERO,
        l1_slot: 9,
        l1_height: 8,
        source_commitment: B256::repeat_byte(0x46),
        inbox_root: B256::repeat_byte(0x47),
        inbox_count: 1,
        consumed_start: 0,
        consumed_end: 1,
    };
    let v3 = execute_settlement_statement_v3(&spec, domain(), &witness, &context, &body, settlement).unwrap();
    // The V2 statement for the same block is identical in every shared field.
    let v2 = execute_settlement_statement_v2(&spec, domain(), &witness, &context, &body, settlement).unwrap();
    assert_eq!(v3.base, v2);
    assert_eq!(v3.base.l2_header_hash, recorded.header.hash());
    assert_eq!(v3.user_tx_count, 2);
    assert_eq!(v3.transactions_root, recorded.header.transactions_root);
    assert_eq!(v3.receipts_root, recorded.header.receipts_root);
    assert_ne!(v3.receipts_root, alloy_trie::EMPTY_ROOT_HASH);
    assert_eq!(v3.deposits_hash, deposits_hash(&body.deposits));
    // Independent spelling of the deposits hash the native chain recomputes:
    // recipient || height BE8 || tx_index BE4 || txid || vout BE4 || sats BE8.
    let mut preimage = Vec::new();
    preimage.extend_from_slice(sender.as_slice());
    preimage.extend_from_slice(&7u64.to_be_bytes());
    preimage.extend_from_slice(&0u32.to_be_bytes());
    preimage.extend_from_slice(&[1; 32]);
    preimage.extend_from_slice(&1u32.to_be_bytes());
    preimage.extend_from_slice(&100_000_000u64.to_be_bytes());
    assert_eq!(v3.deposits_hash, keccak256(&preimage));
    assert_eq!(
        (v3.withdrawal_root, v3.withdrawal_count, v3.da_commitment),
        (B256::ZERO, 0, B256::ZERO)
    );
    let bytes = v3.encode();
    assert!(bytes.starts_with(SETTLEMENT_STATEMENT_V3_TAG));
    let t = SETTLEMENT_STATEMENT_V3_TAG.len();
    let o = settlement_v3_layout::DEPOSITS_HASH;
    assert_eq!(&bytes[t + o..t + o + 32], v3.deposits_hash.as_slice());
    assert_eq!(SettlementStatementV3::decode(&bytes).unwrap(), v3);

    // A body that differs from the witnessed execution is refused.
    let mut altered = body.clone();
    altered.transactions.pop();
    assert!(execute_settlement_statement_v3(&spec, domain(), &witness, &context, &altered, settlement).is_err());
    // The consumed range must still equal the deposit count.
    let wrong_range = SettlementContextV2 {
        consumed_end: 0,
        ..settlement
    };
    assert!(execute_settlement_statement_v3(&spec, domain(), &witness, &context, &body, wrong_range).is_err());
}

/// Golden deposits hash shared with the native verifier's conformance test
/// (`bloch-pos-committee` `l2_settlement::v3_tests`).
#[test]
fn deposits_hash_cross_repository_golden_vector() {
    let deposit = DepositMint {
        recipient: Address::repeat_byte(0x42),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 7,
            l1_tx_index: 3,
            l1_txid: [0x11; 32],
            l1_vout: 1,
            l1_sats: 5_000,
        },
    };
    assert_eq!(
        format!("{:x}", deposits_hash(&[deposit])),
        "0cbc6acc037c5bd96bf847b916a584239e9fa7c22afbf1a37703f4b13afbcfd3"
    );
    assert_eq!(deposits_hash(&[]), keccak256([]));
}
