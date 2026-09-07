// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adversarial regressions from the second-pass security audit.

use std::collections::BTreeMap;

use alloy_primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy_trie::nodes::LeafNode;
use alloy_trie::{HashBuilder, Nibbles};
use bloch_l2_evm::state::{BLOCK_INFO_FLAG_SLOT, BLOCK_INFO_NUMBER_SLOT};
use bloch_l2_evm::{
    execute_block, generate_batch_witness, stateless_new_root, validate_block_input, verify_batch, BlockContext,
    BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State, Mpt, SparseTrieView,
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
fn malformed_node_corpus_never_panics() {
    for len in 0..=70 {
        for first in 0u8..=255 {
            let mut bytes = vec![0x80; len];
            if let Some(byte) = bytes.first_mut() {
                *byte = first;
            }
            let _ = opens(bytes);
        }
    }
    let canonical = alloy_rlp::encode(LeafNode::new(key(0x11), vec![1]));
    let view = opens(canonical.clone()).unwrap();
    assert_eq!(view.apply(&BTreeMap::new()).unwrap(), keccak256(canonical));
}

#[test]
fn noncanonical_branch_and_extension_shapes_are_rejected() {
    // A branch must have at least two children.
    let mut children = vec![alloy_rlp::encode(B256::repeat_byte(1))];
    children.extend((0..16).map(|_| vec![0x80]));
    assert!(opens(list(&children)).is_err());

    // An extension must terminate at a branch, not an inline leaf.
    let inline_leaf = alloy_rlp::encode(LeafNode::new(Nibbles::from_nibbles([1]), vec![1]));
    let prefix = Nibbles::from_nibbles(vec![1; 63]);
    let compact = alloy_trie::nodes::encode_path_leaf(&prefix, false);
    let extension = list(&[alloy_rlp::encode(compact.as_slice()), inline_leaf]);
    assert!(opens(extension).is_err());

    // Reject an oversized list before the dependency allocates its items.
    assert!(opens(list(&vec![vec![0x80]; 100])).is_err());
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

#[test]
fn every_accepted_sparse_deletion_matches_an_independent_full_rebuild() {
    let mut accepted = 0;
    let mut incomplete = 0;
    // Root branches, deep extensions, and inline children near the key limit.
    for shared in [0, 1, 31, 62, 63] {
        for value_len in [1, 31, 32, 40] {
            let keys: Vec<Nibbles> = (0..4)
                .map(|i| {
                    let mut path = vec![0; 64];
                    path[shared] = i;
                    Nibbles::from_nibbles(path)
                })
                .collect();
            let mut trie = Mpt::new();
            for (i, k) in keys.iter().enumerate() {
                trie.insert(*k, vec![i as u8 + 1; value_len]);
            }
            let root = trie.root();
            for exposed in 1u8..16 {
                let proof = trie
                    .proof(keys.iter().enumerate().filter_map(|(i, k)| ((exposed >> i) & 1 == 1).then_some(*k)))
                    .unwrap();
                for deleted in 0u8..16 {
                    if deleted & !exposed != 0 {
                        continue;
                    }
                    let changes: BTreeMap<_, _> = keys
                        .iter()
                        .enumerate()
                        .filter_map(|(i, k)| ((deleted >> i) & 1 == 1).then_some((*k, None)))
                        .collect();
                    match stateless_new_root(root, &proof, &changes) {
                        Ok(derived) => {
                            let mut reference = HashBuilder::default();
                            for (i, k) in keys.iter().enumerate() {
                                if (deleted >> i) & 1 == 0 {
                                    reference.add_leaf(*k, &vec![i as u8 + 1; value_len]);
                                }
                            }
                            assert_eq!(derived, reference.root());
                            accepted += 1;
                        }
                        Err(bloch_l2_evm::WitnessError::OpaqueChildNeedsExpansion { .. }) => incomplete += 1,
                        Err(e) => panic!("unexpected rejection: {e}"),
                    }
                }
            }
        }
    }
    assert!(accepted > 1_000);
    assert!(incomplete > 0);
}

#[test]
fn canonical_proofs_survive_insertions_and_updates_with_an_opaque_sibling() {
    let mut trie = Mpt::new();
    trie.insert(key(0x11), vec![1; 40]);
    trie.insert(key(0x22), vec![2; 40]);
    let root = trie.root();
    let proof = trie.proof([key(0x11), key(0x33)]).unwrap();
    let changes = BTreeMap::from([(key(0x11), Some(vec![9; 40])), (key(0x33), Some(vec![3; 40]))]);
    let derived = stateless_new_root(root, &proof, &changes).unwrap();
    let mut reference = HashBuilder::default();
    reference.add_leaf(key(0x11), &[9; 40]);
    reference.add_leaf(key(0x22), &[2; 40]);
    reference.add_leaf(key(0x33), &[3; 40]);
    assert_eq!(derived, reference.root());
}

#[test]
fn multi_block_witnesses_match_full_execution_with_custom_system_accounts() {
    let mut spec = ChainSpec::testnet();
    spec.block_info = address!("4200000000000000000000000000000000000201");
    spec.supply_ledger = address!("4200000000000000000000000000000000000200");
    let mut state = L2State::new();
    for height in 1..=8 {
        let input = BlockInput {
            context: BlockContext::next(&spec, &state),
            deposits: vec![DepositMint {
                recipient: Address::repeat_byte(0xaa),
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: height,
                    l1_tx_index: 0,
                    l1_txid: [height as u8; 32],
                    l1_vout: 0,
                    l1_sats: 1,
                },
            }],
            txs: vec![],
        };
        let before = state.state_root();
        let (witness, host) = generate_batch_witness(&state, &spec, input.clone()).unwrap();
        assert_eq!(state.state_root(), before);
        let guest = verify_batch(&spec, &witness, &input).unwrap();
        let full = execute_block(&spec, &mut state, input).unwrap();
        assert_eq!(host.state_root, full.state_root);
        assert_eq!(guest.new_state_root, full.state_root);
        assert_eq!(guest.block_hash, full.block_hash);
        assert_eq!(full.block_number, height);
        assert_eq!(state.total_native_wei(), state.total_minted_wei_at(spec.supply_ledger));
    }
}
