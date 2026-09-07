// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adversarial regressions from the second-pass security audit.

use std::collections::BTreeMap;

use alloy_primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy_trie::nodes::LeafNode;
use alloy_trie::Nibbles;
use bloch_l2_evm::state::{BLOCK_INFO_FLAG_SLOT, BLOCK_INFO_NUMBER_SLOT};
use bloch_l2_evm::{
    execute_block, stateless_new_root, validate_block_input, BlockContext, BlockInput, ChainSpec, L2State, Mpt,
    SparseTrieView,
};
use revm::context::TxEnv;
use revm::context_interface::transaction::{AccessListItem, Authorization, RecoveredAuthority, RecoveredAuthorization};
use revm::primitives::hardfork::SpecId;
use revm::state::AccountInfo;

fn key(byte: u8) -> Nibbles {
    Nibbles::unpack(B256::repeat_byte(byte))
}

fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flatten().copied().collect();
    let mut out = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend(payload);
    out
}

fn opens(bytes: Vec<u8>) -> Result<SparseTrieView, bloch_l2_evm::WitnessError> {
    let root = keccak256(&bytes);
    SparseTrieView::from_proof(root, &BTreeMap::from([(Nibbles::default(), Bytes::from(bytes))]))
}

#[test]
fn deletion_requires_the_opaque_surviving_leaf() {
    let mut trie = Mpt::new();
    trie.insert(key(0x00), vec![1; 40]);
    trie.insert(key(0x11), vec![2; 40]);
    let root = trie.root();
    let partial = trie.proof([key(0x00)]).unwrap();
    let full = trie.proof([key(0x00), key(0x11)]).unwrap();
    let changes = BTreeMap::from([(key(0x00), None)]);

    // Inclusion of the deleted key alone does not disclose the sibling's
    // compact path. Its hash cannot be reused at a shorter path after collapse.
    assert!(stateless_new_root(root, &partial, &changes).is_err());
    trie.remove(&key(0x00));
    assert_eq!(stateless_new_root(root, &full, &changes).unwrap(), trie.root());
}

#[test]
fn deletion_requires_the_opaque_surviving_extension() {
    let mut trie = Mpt::new();
    let mut b = B256::repeat_byte(0x11);
    let mut c = b;
    b[31] = 0x12;
    c[31] = 0x13;
    let b = Nibbles::unpack(b);
    let c = Nibbles::unpack(c);
    trie.insert(key(0x00), vec![1; 40]);
    trie.insert(b, vec![2; 40]);
    trie.insert(c, vec![3; 40]);
    let root = trie.root();
    let partial = trie.proof([key(0x00)]).unwrap();
    let full = trie.proof([key(0x00), b, c]).unwrap();
    let changes = BTreeMap::from([(key(0x00), None)]);

    assert!(stateless_new_root(root, &partial, &changes).is_err());
    trie.remove(&key(0x00));
    assert_eq!(stateless_new_root(root, &full, &changes).unwrap(), trie.root());
}

#[test]
fn odd_compact_path_of_33_bytes_is_rejected_before_decoding() {
    // 33 compact bytes fit the old byte bound, but an odd flag means 65
    // nibbles. Reject before the dependency joins beyond its fixed capacity.
    for flag in [0x10, 0x30] {
        let mut compact = vec![0; 33];
        compact[0] = flag;
        let bytes = list(&[
            alloy_rlp::encode(compact.as_slice()),
            alloy_rlp::encode([1u8].as_slice()),
        ]);
        assert!(opens(bytes).is_err());
    }
}

#[test]
fn trailing_rlp_bytes_are_rejected() {
    let mut bytes = alloy_rlp::encode(LeafNode::new(key(0x11), vec![1]));
    bytes.push(0);
    assert!(opens(bytes).is_err());
}

#[test]
fn nonzero_even_compact_padding_is_rejected() {
    let mut compact = vec![0x11; 33];
    compact[0] = 0x21;
    let bytes = list(&[
        alloy_rlp::encode(compact.as_slice()),
        alloy_rlp::encode([1u8].as_slice()),
    ]);
    assert!(opens(bytes).is_err());
}

#[test]
fn only_the_audited_cancun_hardfork_is_accepted() {
    let mut spec = ChainSpec::testnet();
    assert!(spec.validate().is_ok());
    for fork in [SpecId::SHANGHAI, SpecId::PRAGUE] {
        spec.spec_id = fork;
        assert!(spec.validate().is_err());
        let mut state = L2State::new();
        let before = state.state_root();
        assert!(execute_block(&spec, &mut state, BlockInput::default()).is_err());
        assert_eq!(state.state_root(), before);
    }
}

fn legacy_tx(spec: &ChainSpec) -> TxEnv {
    TxEnv::builder()
        .caller(Address::repeat_byte(0xaa))
        .gas_limit(100_000)
        .gas_price(spec.initial_base_fee as u128)
        .chain_id(Some(spec.chain_id))
        .build()
        .unwrap()
}

#[test]
fn legacy_transactions_cannot_smuggle_an_access_list() {
    let spec = ChainSpec::testnet();
    let mut tx = legacy_tx(&spec);
    tx.access_list.0.push(AccessListItem {
        address: Address::repeat_byte(0xbb),
        storage_keys: vec![B256::ZERO],
    });
    let input = BlockInput {
        txs: vec![tx],
        ..Default::default()
    };
    assert!(validate_block_input(&spec, &input).is_err());
}

#[test]
fn supported_envelopes_cannot_smuggle_authorizations() {
    let spec = ChainSpec::testnet();
    for tx_type in [0, 1, 2] {
        let mut tx = legacy_tx(&spec);
        tx.tx_type = tx_type;
        tx.gas_priority_fee = (tx_type == 2).then_some(0);
        tx.set_recovered_authorization(vec![RecoveredAuthorization::new_unchecked(
            Authorization {
                chain_id: U256::from(spec.chain_id),
                address: Address::repeat_byte(0xbb),
                nonce: 0,
            },
            RecoveredAuthority::Valid(Address::repeat_byte(0xaa)),
        )]);
        let input = BlockInput {
            txs: vec![tx],
            ..Default::default()
        };
        assert!(validate_block_input(&spec, &input).is_err());
    }
}

#[test]
fn next_context_reads_the_configured_block_info_account() {
    let mut spec = ChainSpec::testnet();
    spec.block_info = address!("4200000000000000000000000000000000000201");
    let mut state = L2State::new();
    execute_block(&spec, &mut state, BlockInput::default()).unwrap();
    let context = BlockContext::next(&spec, &state);
    assert_eq!(context.number, 2);
    let input = BlockInput {
        context,
        ..Default::default()
    };
    execute_block(&spec, &mut state, input).unwrap();
}

#[test]
fn terminal_block_number_does_not_panic_or_wrap() {
    let spec = ChainSpec::testnet();
    let mut state = L2State::new();
    let db = state.db_mut();
    db.insert_account_info(
        spec.block_info,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    db.insert_account_storage(spec.block_info, BLOCK_INFO_FLAG_SLOT, U256::from(1))
        .unwrap();
    db.insert_account_storage(spec.block_info, BLOCK_INFO_NUMBER_SLOT, U256::from(u64::MAX))
        .unwrap();
    let context = BlockContext::next(&spec, &state);
    assert_eq!(context.number, u64::MAX);
    let before = state.state_root();
    let input = BlockInput {
        context,
        ..Default::default()
    };
    assert!(execute_block(&spec, &mut state, input).is_err());
    assert_eq!(state.state_root(), before);
}
