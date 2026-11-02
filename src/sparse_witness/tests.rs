// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adversarial and differential tests of the sparse witness.
//!
//! The property under test: an omitted or forged slot never reads as zero, and no
//! change to a witness can make the verifier accept a different outcome.

use super::*;
use crate::chainspec::MAINNET_DOMAIN;
use crate::mpt::Mpt;
use crate::node_execution::{execute_node_block, genesis_v2, node_head};
use crate::state::{DepositMint, DepositProvenance};
use crate::stateroot::SparseTrieView;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Signature, TxKind};
use k256::ecdsa::SigningKey;

const OP_WRITE: u64 = 0;
const OP_READ: u64 = 1;
const OP_UPDATE: u64 = 2;
const OP_ZERO: u64 = 3;

struct Chain {
    spec: ChainSpec,
    state: L2State,
    key: SigningKey,
    sender: Address,
    nonce: u64,
    deposits: u64,
}

fn word(value: u64) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

fn ops(op: u64, start: u64, count: u64) -> Bytes {
    [word(op), word(start), word(count)].concat().into()
}

impl Chain {
    fn new(spec: ChainSpec) -> Self {
        let mut state = genesis_v2(&spec, 0).unwrap();
        state.commit_root();
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let sender = Address::from_public_key(key.verifying_key());
        let mut chain = Self {
            spec,
            state,
            key,
            sender,
            nonce: 0,
            deposits: 0,
        };
        let body = chain.body(vec![]);
        chain.commit(&body);
        chain
    }

    fn deposit(&mut self) -> DepositMint {
        self.deposits += 1;
        DepositMint {
            recipient: self.sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: self.deposits,
                l1_tx_index: 0,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: 10_000_000_000,
            },
        }
    }

    fn body(&mut self, transactions: Vec<Bytes>) -> NodeBodyV2 {
        NodeBodyV2 {
            deposits: vec![self.deposit()],
            transactions,
        }
    }

    fn tx(&mut self, to: TxKind, value: U256, input: Bytes, gas_limit: u64) -> Bytes {
        let transaction = TxEip1559 {
            chain_id: self.spec.chain_id,
            nonce: self.nonce,
            to,
            value,
            input,
            gas_limit,
            max_fee_per_gas: 200_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            ..Default::default()
        };
        self.nonce += 1;
        let signature: Signature = self
            .key
            .sign_prehash_recoverable(transaction.signature_hash().as_slice())
            .unwrap()
            .into();
        TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into()
    }

    fn call(&mut self, to: Address, input: Bytes) -> Bytes {
        self.tx(TxKind::Call(to), U256::ZERO, input, 5_000_000)
    }

    fn context(&self) -> BlockContext {
        let parent = node_head(&self.spec, MAINNET_DOMAIN, &self.state).unwrap();
        BlockContext {
            number: parent.number + 1,
            timestamp: match self.spec.block_derivation {
                Some(rule) => rule.timestamp(parent.timestamp, 1).unwrap(),
                None => parent.timestamp + 1,
            },
            base_fee_per_gas: self.spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao: match self.spec.block_derivation {
                Some(rule) => rule.prevrandao,
                None => B256::repeat_byte(7),
            },
            anchor_root: B256::repeat_byte(8),
        }
    }

    fn commit(&mut self, body: &NodeBodyV2) -> NodeExecutionOutcome {
        let context = self.context();
        let outcome = execute_node_block(&self.spec, MAINNET_DOMAIN, &mut self.state, &context, body).unwrap();
        self.state.commit_root();
        outcome
    }

    fn deploy(&mut self, runtime: &[u8]) -> Address {
        let address = self.sender.create(self.nonce);
        let tx = self.tx(TxKind::Create, U256::ZERO, deploy_code(runtime).into(), 5_000_000);
        let body = self.body(vec![tx]);
        let outcome = self.commit(&body);
        assert!(outcome.transactions[0].success, "deployment failed");
        address
    }

    /// Witness, canonical outcome and context for `body` as the next block.
    fn witness(&self, body: &NodeBodyV2, mode: BlockHashes) -> (SparseBatchWitness, NodeExecutionOutcome, BlockContext) {
        let context = self.context();
        let (witness, canonical) =
            generate_sparse_node_witness(&self.state, &self.spec, MAINNET_DOMAIN, &context, body, mode)
                .expect("the sparse witness generates and self-verifies");
        (witness, canonical, context)
    }

    fn verify(
        &self,
        witness: &SparseBatchWitness,
        context: &BlockContext,
        body: &NodeBodyV2,
        mode: BlockHashes,
    ) -> Result<NodeExecutionOutcome, SparseNodeError> {
        verify_node_batch_sparse(&self.spec, MAINNET_DOMAIN, witness, context, body, mode)
    }

    fn slot(&self, address: Address, slot: u64) -> U256 {
        self.state.storage_of(&address, U256::from(slot))
    }
}

fn big_contract(chain: &mut Chain, slots: u64) -> Address {
    let contract = chain.deploy(&storage_ops_runtime());
    let tx = chain.tx(TxKind::Call(contract), U256::ZERO, ops(OP_WRITE, 0, slots), 25_000_000);
    let body = chain.body(vec![tx]);
    assert!(chain.commit(&body).transactions[0].success, "filling storage failed");
    contract
}

fn account(witness: &SparseBatchWitness, address: Address) -> usize {
    witness
        .pre_accounts
        .iter()
        .position(|account| account.address == address)
        .expect("account is in the witness")
}

/// Remove the proof nodes that open `slot`: everything at or below its first
/// position that is not shared with another exposed key.
fn omit_slot(witness: &mut SparseBatchWitness, address: Address, slot: u64) {
    let key = storage_key(&U256::from(slot));
    let index = account(witness, address);
    let proof = &mut witness.pre_accounts[index].storage_proof;
    let deepest = proof.keys().filter(|path| key.starts_with(path)).max_by_key(|path| path.len()).copied();
    let deepest = deepest.expect("the slot is covered");
    assert!(!deepest.is_empty(), "the test needs a slot below the root node");
    proof.remove(&deepest);
}

fn assert_not_covered(result: Result<NodeExecutionOutcome, SparseNodeError>) {
    match result {
        Err(SparseNodeError::Execution(error)) => {
            let text = error.to_string();
            assert!(
                text.contains("UnwitnessedStorage") || text.contains("UnwitnessedBlockHash") || text.contains("not covered"),
                "unexpected failure: {text}"
            );
        }
        Err(SparseNodeError::Verify(SparseVerifyError::Slot(SparseAccessError::UnwitnessedStorage(..)))) => {}
        Err(other) => panic!("unexpected failure: {other}"),
        Ok(outcome) => panic!("an uncovered read was accepted, root {}", outcome.header.state_root),
    }
}

fn both_rules() -> [ChainSpec; 2] {
    [ChainSpec::mainnet_v1(), ChainSpec::mainnet()]
}

#[test]
fn the_contract_does_what_the_benchmark_says() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 8);
    assert_eq!(chain.slot(contract, 3), U256::from(4));
    let tx = chain.call(contract, ops(OP_UPDATE, 3, 1));
    let body = chain.body(vec![tx]);
    assert!(chain.commit(&body).transactions[0].success);
    assert_eq!(chain.slot(contract, 3), U256::from(5));
    let tx = chain.call(contract, ops(OP_ZERO, 3, 1));
    let body = chain.body(vec![tx]);
    assert!(chain.commit(&body).transactions[0].success);
    assert_eq!(chain.slot(contract, 3), U256::ZERO);
    let tx = chain.call(contract, ops(OP_READ, 0, 8));
    let body = chain.body(vec![tx]);
    assert!(chain.commit(&body).transactions[0].success);
}

#[test]
fn honest_witness_matches_the_canonical_path_and_stays_sparse() {
    for spec in both_rules() {
        for mode in [BlockHashes::Eager, BlockHashes::Lazy] {
            let mut chain = Chain::new(spec.clone());
            let contract = big_contract(&mut chain, 500);
            let tx = chain.call(contract, ops(OP_UPDATE, 7, 2));
            let body = chain.body(vec![tx]);
            let (witness, canonical, context) = chain.witness(&body, mode);
            let verified = chain.verify(&witness, &context, &body, mode).unwrap();
            assert_eq!(verified.header, canonical.header);
            let index = account(&witness, contract);
            assert!(
                witness.pre_accounts[index].storage_proof.len() < 40,
                "2 slots of 500 need few nodes, got {}",
                witness.pre_accounts[index].storage_proof.len()
            );
            let mut full = chain.state.clone();
            let outcome = execute_node_block(&spec, MAINNET_DOMAIN, &mut full, &context, &body).unwrap();
            assert_eq!(outcome.header, verified.header);
            assert_eq!(full.commit_root(), witness.new_state_root);
        }
    }
}

#[test]
fn omitted_nonzero_slot_never_reads_as_zero() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    assert_eq!(chain.slot(contract, 42), U256::from(43));
    let tx = chain.call(contract, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx]);
    let (mut witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    omit_slot(&mut witness, contract, 42);
    assert_not_covered(chain.verify(&witness, &context, &body, BlockHashes::Lazy));
}

#[test]
fn omitted_exclusion_proof_does_not_prove_zero() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    // Slot 900 was never written: the honest witness proves its exclusion.
    assert_eq!(chain.slot(contract, 900), U256::ZERO);
    let tx = chain.call(contract, ops(OP_READ, 900, 1));
    let body = chain.body(vec![tx]);
    let (mut witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    chain.verify(&witness, &context, &body, BlockHashes::Lazy).unwrap();
    omit_slot(&mut witness, contract, 900);
    assert_not_covered(chain.verify(&witness, &context, &body, BlockHashes::Lazy));
}

#[test]
fn an_empty_storage_proof_opens_only_the_empty_root() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    let tx = chain.call(contract, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    let index = account(&witness, contract);

    // No proof at all against the real root.
    let mut stripped = witness.clone();
    stripped.pre_accounts[index].storage_proof.clear();
    assert!(matches!(
        chain.verify(&stripped, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::Storage(_, WitnessError::EmptyProofForNonEmptyRoot { .. })))
    ));

    // The claim "this account has no storage": the account leaf refuses it.
    let mut claim = stripped;
    claim.pre_accounts[index].storage_root = alloy_trie::EMPTY_ROOT_HASH;
    assert!(matches!(
        chain.verify(&claim, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProven(a))) if a == contract
    ));
}

/// A contract that makes an inner call and records whether it succeeded. If an
/// uncovered read were an inner failure, a prover could flip this record.
fn catcher_runtime(target: Address) -> Vec<u8> {
    let mut code = vec![
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // calldatacopy(0, 0, calldatasize)
        0x60, 0x00, 0x60, 0x00, // out 0, 0
        0x36, 0x60, 0x00, // in size, in offset
        0x60, 0x00, // value 0
        0x73, // PUSH20 target
    ];
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[
        0x5a, 0xf1, // gas; CALL -> success
        0x60, 0x63, 0x55, // sstore(99, success)
        0x00,
    ]);
    code
}

#[test]
fn an_uncovered_read_in_an_inner_call_fails_the_block_and_cannot_be_caught() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    let catcher = chain.deploy(&catcher_runtime(contract));
    let tx = chain.call(catcher, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx]);
    let (mut witness, canonical, context) = chain.witness(&body, BlockHashes::Lazy);
    assert!(canonical.transactions[0].success);
    omit_slot(&mut witness, contract, 42);
    assert_not_covered(chain.verify(&witness, &context, &body, BlockHashes::Lazy));
}

#[test]
fn a_read_in_a_reverted_transaction_is_still_covered_and_still_required() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    // Runtime: sload(calldata[0]) then revert. Its storage is the one under test.
    let reverter = chain.deploy(&[0x60, 0x00, 0x35, 0x54, 0x50, 0x60, 0x00, 0x60, 0x00, 0xfd]);
    let tx = chain.call(reverter, Bytes::copy_from_slice(&word(5)));
    let inner = chain.call(contract, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx, inner]);
    let (witness, canonical, context) = chain.witness(&body, BlockHashes::Lazy);
    assert!(!canonical.transactions[0].success, "the first transaction reverts");
    chain.verify(&witness, &context, &body, BlockHashes::Lazy).unwrap();

    // Out of gas in an inner frame is the same: omitting the read fails the block.
    let catcher = {
        let mut chain_b = Chain::new(ChainSpec::mainnet());
        let target = big_contract(&mut chain_b, 500);
        let catcher = chain_b.deploy(&catcher_runtime(target));
        let tx = chain_b.tx(TxKind::Call(catcher), U256::ZERO, ops(OP_READ, 0, 500), 120_000);
        let body = chain_b.body(vec![tx]);
        let (mut witness, _, context) = chain_b.witness(&body, BlockHashes::Lazy);
        let verified = chain_b.verify(&witness, &context, &body, BlockHashes::Lazy).unwrap();
        // The first slots were read before the gas ran out.
        omit_slot(&mut witness, target, 0);
        assert_not_covered(chain_b.verify(&witness, &context, &body, BlockHashes::Lazy));
        verified.header.state_root
    };
    assert_ne!(catcher, B256::ZERO);
}

#[test]
fn a_forged_slot_value_is_refused_at_every_level_of_the_chain_of_trust() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    let tx = chain.call(contract, ops(OP_UPDATE, 42, 1));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    let index = account(&witness, contract);
    let key = storage_key(&U256::from(42));
    let proof = &witness.pre_accounts[index].storage_proof;
    let leaf_path = *proof.keys().filter(|path| key.starts_with(path)).max_by_key(|p| p.len()).unwrap();
    let forged_leaf: Bytes = {
        let rest = key.slice(leaf_path.len()..);
        alloy_rlp::encode(&alloy_trie::nodes::LeafNode::new(rest, alloy_rlp::encode(U256::from(777)))).into()
    };
    assert_ne!(proof[&leaf_path], forged_leaf, "the honest leaf holds 43");

    // 1. The leaf alone: its parent's reference refuses it.
    let mut forged = witness.clone();
    forged.pre_accounts[index].storage_proof.insert(leaf_path, forged_leaf.clone());
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::Storage(_, WitnessError::UnanchoredNode { .. })))
    ));

    // 2. A whole valid trie holding the forged value: the account leaf refuses its root.
    let mut own = Mpt::new();
    own.insert(key, alloy_rlp::encode(U256::from(777)));
    let own_root = own.root();
    let own_proof = own.proof([key]).unwrap();
    let mut forged = witness.clone();
    forged.pre_accounts[index].storage_root = own_root;
    forged.pre_accounts[index].storage_proof = own_proof;
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProven(a))) if a == contract
    ));

    // 3. Another account's valid proof under this account's root: anchored to nothing.
    let mut forged = witness.clone();
    let info_index = account(&witness, chain.spec.block_info);
    forged.pre_accounts[index].storage_proof = witness.pre_accounts[info_index].storage_proof.clone();
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::Storage(_, WitnessError::RootMismatch { .. })))
    ));

    // 4. The account fields, and a wrong prev_state_root with an honest proof.
    let mut forged = witness.clone();
    forged.pre_accounts[index].balance += U256::from(1);
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProven(_)))
    ));
    let mut forged = witness.clone();
    forged.pre_accounts[index].code_hash = alloy_primitives::keccak256([0x00]);
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProven(_)))
    ));
    let mut forged = witness.clone();
    forged.prev_state_root = B256::repeat_byte(0x42);
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::Witness(WitnessError::RootMismatch { .. })))
    ));

    // 5. A wrong claim about the result.
    let mut forged = witness.clone();
    forged.new_state_root = B256::repeat_byte(0x42);
    assert!(matches!(
        chain.verify(&forged, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::ClaimedRootMismatch { .. }))
    ));
}

#[test]
fn a_forged_exclusion_is_refused() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    let tx = chain.call(contract, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    let index = account(&witness, contract);
    let key = storage_key(&U256::from(42));

    // A branch rebuilt without the child on the path would say "this key is absent".
    let proof = &witness.pre_accounts[index].storage_proof;
    for (path, node) in proof.iter().filter(|(path, _)| key.starts_with(path)) {
        let mut buf = node.as_ref();
        let Ok(alloy_trie::nodes::TrieNode::Branch(branch)) = alloy_trie::nodes::TrieNode::decode(&mut buf) else {
            continue;
        };
        let nibble = key.get_unchecked(path.len());
        if !branch.state_mask.is_bit_set(nibble) {
            continue;
        }
        let mut stack = Vec::new();
        let mut mask = alloy_trie::TrieMask::default();
        let mut rank = 0;
        for candidate in 0u8..16 {
            if branch.state_mask.is_bit_set(candidate) {
                if candidate != nibble {
                    stack.push(branch.stack[rank].clone());
                    mask |= alloy_trie::TrieMask::from_nibble(candidate);
                }
                rank += 1;
            }
        }
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&alloy_trie::nodes::BranchNodeRef::new(&stack, mask), &mut encoded);
        let mut forged = witness.clone();
        forged.pre_accounts[index].storage_proof.insert(*path, encoded.into());
        assert!(
            chain.verify(&forged, &context, &body, BlockHashes::Lazy).is_err(),
            "a branch without the child at {path:?} must not prove exclusion"
        );
    }
}

#[test]
fn accounts_cannot_be_omitted_or_claimed_absent() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    let tx = chain.call(contract, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);

    let mut omitted = witness.clone();
    omitted.pre_accounts.retain(|account| account.address != contract);
    assert!(chain.verify(&omitted, &context, &body, BlockHashes::Lazy).is_err());

    let mut lied = omitted.clone();
    lied.absent_accounts.push(contract);
    assert!(matches!(
        chain.verify(&lied, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProvenAbsent(a))) if a == contract
    ));

    let mut stripped = lied;
    let path = account_key(&contract);
    let deepest = *stripped
        .proof
        .keys()
        .filter(|p| path.starts_with(p))
        .max_by_key(|p| p.len())
        .unwrap();
    stripped.proof.remove(&deepest);
    assert!(chain.verify(&stripped, &context, &body, BlockHashes::Lazy).is_err());

    let mut dup = witness.clone();
    dup.pre_accounts.push(dup.pre_accounts[0].clone());
    assert!(matches!(
        chain.verify(&dup, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::DuplicateAccount(_)))
    ));
}

#[test]
fn a_blind_write_under_an_opaque_subtree_is_an_error_even_when_it_is_zero() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 500);
    let tx = chain.call(contract, ops(OP_READ, 42, 1));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    // Find a live slot the proof leaves opaque.
    let index = account(&witness, contract);
    let view = IndexedTrieView::from_proof(
        witness.pre_accounts[index].storage_root,
        &witness.pre_accounts[index].storage_proof,
    )
    .unwrap();
    let hidden = (0..500u64)
        .find(|slot| view.lookup(&storage_key(&U256::from(*slot))).is_err())
        .expect("most slots are opaque");

    for value in [U256::ZERO, U256::from(5)] {
        let hydrated = hydrate_sparse(&chain.spec, &witness, context.number).unwrap();
        let HydratedSparse {
            mut state,
            account_view,
            pre_leaves,
            pre_storage_roots,
        } = hydrated;
        state.insert_account_storage(contract, U256::from(hidden), value).unwrap();
        let result = derive_post_root(&witness, &account_view, &pre_leaves, &pre_storage_roots, &state);
        assert!(
            matches!(result, Err(SparseVerifyError::Slot(SparseAccessError::UnwitnessedStorage(..)))),
            "write of {value} under an opaque subtree: {result:?}"
        );
    }
}

#[test]
fn a_deletion_that_needs_an_opaque_sibling_is_an_error() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 2);
    let tx = chain.call(contract, ops(OP_ZERO, 0, 1));
    let body = chain.body(vec![tx]);
    let (witness, canonical, context) = chain.witness(&body, BlockHashes::Lazy);
    let verified = chain.verify(&witness, &context, &body, BlockHashes::Lazy).unwrap();
    assert_eq!(verified.header, canonical.header);
    let survivor = storage_key(&U256::from(1));
    let index = account(&witness, contract);
    let mut stripped = witness.clone();
    let before = stripped.pre_accounts[index].storage_proof.len();
    stripped.pre_accounts[index]
        .storage_proof
        .retain(|path, _| path.is_empty() || !survivor.starts_with(path));
    assert!(stripped.pre_accounts[index].storage_proof.len() < before);
    assert!(matches!(
        chain.verify(&stripped, &context, &body, BlockHashes::Lazy),
        Err(SparseNodeError::Verify(SparseVerifyError::Storage(_, WitnessError::OpaqueChildNeedsExpansion { .. })))
    ));
}

/// Trie leaves that are not canonical non-zero words, under a root we build
/// ourselves: a read is an error, not a zero. A real root cannot hold these; the
/// check stays so that a future bug in the writer fails closed here.
#[test]
fn a_malformed_or_zero_leaf_is_not_a_value() {
    let good = U256::from(9);
    for bad in [vec![0x80u8], vec![0x82, 0x00, 0x01], vec![0xc0], vec![0x09, 0x09], Vec::new()] {
        let mut trie = Mpt::new();
        let key = storage_key(&U256::from(1));
        trie.insert(key, bad.clone());
        trie.insert(storage_key(&U256::from(2)), alloy_rlp::encode(good));
        let root = trie.root();
        let view = IndexedTrieView::from_proof(root, &trie.proof([key]).unwrap()).unwrap();
        assert_eq!(
            read_slot(&view, Address::ZERO, U256::from(1)),
            Err(SparseAccessError::MalformedStorageValue(Address::ZERO, U256::from(1))),
            "leaf {bad:?}"
        );
    }
}

/// The contract that uses `BLOCKHASH`: stores the hash of block `number - 1 - x`.
fn blockhash_runtime() -> Vec<u8> {
    vec![
        0x60, 0x00, 0x35, // x
        0x60, 0x01, 0x01, // x + 1
        0x43, 0x03, // number - (x + 1)
        0x40, // BLOCKHASH
        0x60, 0x00, 0x55, // sstore(0, hash)
        0x00,
    ]
}

#[test]
fn lazy_blockhash_serves_the_canonical_value_and_refuses_an_uncovered_entry() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = chain.deploy(&blockhash_runtime());
    for _ in 0..300 {
        let body = chain.body(vec![]);
        chain.commit(&body);
    }
    // Every distance in and just beyond the window, including the parent.
    for distance in [0u64, 1, 2, 100, 254, 255, 256, 257, 400] {
        let tx = chain.call(contract, Bytes::copy_from_slice(&word(distance)));
        let body = chain.body(vec![tx]);
        for mode in [BlockHashes::Eager, BlockHashes::Lazy] {
            chain.witness(&body, mode);
        }
        let outcome = chain.commit(&body);
        assert!(outcome.transactions[0].success);
        if distance < 256 {
            assert_ne!(chain.slot(contract, 0), U256::ZERO, "distance {distance}");
        } else {
            assert_eq!(chain.slot(contract, 0), U256::ZERO, "distance {distance}");
        }
    }

    // The lazy read is a proof obligation like any other slot.
    let tx = chain.call(contract, Bytes::copy_from_slice(&word(100)));
    let body = chain.body(vec![tx]);
    let (mut witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    let info = chain.spec.block_info;
    let wanted = block_hash_slot(context.number - 101);
    let key = storage_key(&wanted);
    let index = account(&witness, info);
    let deepest = *witness.pre_accounts[index]
        .storage_proof
        .keys()
        .filter(|path| key.starts_with(path))
        .max_by_key(|path| path.len())
        .unwrap();
    witness.pre_accounts[index].storage_proof.remove(&deepest);
    assert_not_covered(chain.verify(&witness, &context, &body, BlockHashes::Lazy));

    // The backing itself refuses a number outside the window.
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    let hydrated = hydrate_sparse(&chain.spec, &witness, context.number).unwrap();
    let backing = &hydrated.state.db;
    assert!(backing.block_hash_ref(context.number).is_err());
    assert!(backing.block_hash_ref(context.number + 1).is_err());
    assert!(backing.block_hash_ref(context.number - 257).is_err());
}

/// The sweep. Every single node of an honest witness is removed in turn, then
/// corrupted in turn. The verifier must fail, or (for a node nothing needed) return
/// exactly the canonical outcome. It must never return anything else.
#[test]
fn no_single_node_removed_or_corrupted_changes_the_outcome() {
    for (mode, deletes) in [
        (BlockHashes::Lazy, false),
        (BlockHashes::Eager, false),
        (BlockHashes::Lazy, true),
    ] {
        let mut chain = Chain::new(ChainSpec::mainnet());
        let contract = big_contract(&mut chain, 300);
        let catcher = chain.deploy(&catcher_runtime(contract));
        let block_hash = chain.deploy(&blockhash_runtime());
        let last_op = if deletes { OP_ZERO } else { OP_READ };
        let body_txs = vec![
            chain.call(contract, ops(OP_READ, 10, 3)),
            chain.call(contract, ops(OP_READ, 700, 2)),
            chain.call(contract, ops(OP_UPDATE, 20, 2)),
            chain.call(contract, ops(last_op, 30, 2)),
            chain.call(contract, ops(OP_WRITE, 800, 2)),
            chain.call(catcher, ops(OP_READ, 40, 1)),
            chain.call(block_hash, Bytes::copy_from_slice(&word(0))),
            chain.tx(
                TxKind::Call(Address::repeat_byte(0x5a)),
                U256::from(1_000_000_000_000u64),
                Bytes::new(),
                21_000,
            ),
        ];
        let body = chain.body(body_txs);
        let (witness, canonical, context) = chain.witness(&body, mode);
        assert!(canonical.transactions.iter().all(|tx| tx.success));

        let mut failed = 0usize;
        let mut harmless = 0usize;
        let mut accepted: Vec<String> = Vec::new();
        let mut check = |forged: &SparseBatchWitness, what: String| match chain.verify(forged, &context, &body, mode) {
            Err(_) => failed += 1,
            Ok(outcome) => {
                assert_eq!(outcome.header, canonical.header, "{what} changed the outcome");
                assert_eq!(outcome.receipts, canonical.receipts, "{what} changed the receipts");
                harmless += 1;
                accepted.push(what);
            }
        };

        for path in witness.proof.keys() {
            let mut forged = witness.clone();
            forged.proof.remove(path);
            check(&forged, format!("removing account node {path:?}"));
            let mut forged = witness.clone();
            let mut node = forged.proof[path].to_vec();
            let last = node.len() - 1;
            node[last] ^= 1;
            forged.proof.insert(*path, node.into());
            check(&forged, format!("corrupting account node {path:?}"));
        }
        for (index, account) in witness.pre_accounts.iter().enumerate() {
            for path in account.storage_proof.keys() {
                let mut forged = witness.clone();
                forged.pre_accounts[index].storage_proof.remove(path);
                check(&forged, format!("removing storage node {path:?} of {}", account.address));
                let mut forged = witness.clone();
                let mut node = forged.pre_accounts[index].storage_proof[path].to_vec();
                node[0] ^= 1;
                forged.pre_accounts[index].storage_proof.insert(*path, node.into());
                check(&forged, format!("corrupting first byte {path:?} of {}", account.address));
                let mut forged = witness.clone();
                let mut node = forged.pre_accounts[index].storage_proof[path].to_vec();
                let last = node.len() - 1;
                node[last] ^= 1;
                forged.pre_accounts[index].storage_proof.insert(*path, node.into());
                check(&forged, format!("corrupting last byte {path:?} of {}", account.address));
            }
        }
        assert!(failed > 100, "{mode:?}: only {failed} forgeries failed");
        // No corruption is ever accepted. A removal may be, with the canonical outcome
        // (checked above), only for nodes that expose the neighbours of a deleted key:
        // the generator cannot know before hashing whether the branch collapses, and
        // when it does not, nothing needs them. Without a deletion, every node of the
        // witness lies on the path of a key the block reads or writes.
        assert!(
            accepted.iter().all(|what| what.starts_with("removing storage node")),
            "{mode:?}: accepted: {accepted:#?}"
        );
        if !deletes {
            assert_eq!(harmless, 0, "{mode:?}: accepted unchanged: {accepted:#?}");
        }
    }
}

#[test]
fn extra_unreachable_nodes_change_nothing() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 100);
    let tx = chain.call(contract, ops(OP_UPDATE, 42, 1));
    let body = chain.body(vec![tx]);
    let (witness, canonical, context) = chain.witness(&body, BlockHashes::Lazy);
    let index = account(&witness, contract);
    let mut padded = witness.clone();
    // Nothing hash-links this node, so a walk never reaches it.
    let path = Nibbles::from_nibbles([0xf; 40]);
    padded.pre_accounts[index].storage_proof.insert(path, vec![0xc0; 40].into());
    let outcome = chain.verify(&padded, &context, &body, BlockHashes::Lazy).unwrap();
    assert_eq!(outcome.header, canonical.header);
}

/// Differential: random blocks against the canonical path, in both modes. A
/// generation failure here is a liveness bug of the sparse witness; the generator
/// itself fails on any difference from the canonical outcome.
#[test]
fn random_blocks_match_the_canonical_path() {
    for (seed, spec) in [(1u8, ChainSpec::mainnet()), (2, ChainSpec::mainnet_v1()), (3, ChainSpec::mainnet())] {
        let mut chain = Chain::new(spec);
        let contract = chain.deploy(&storage_ops_runtime());
        let catcher = chain.deploy(&catcher_runtime(contract));
        let block_hash = chain.deploy(&blockhash_runtime());
        let mut rng = keccak256([seed]);
        let mut next = |bound: u64| {
            rng = keccak256(rng);
            u64::from_be_bytes(rng[..8].try_into().unwrap()) % bound
        };
        for block in 0..120u64 {
            let mut txs = Vec::new();
            for _ in 0..next(6) {
                let start = next(400);
                let count = 1 + next(40);
                let tx = match next(9) {
                    0 | 1 | 2 => chain.call(contract, ops(OP_WRITE, start, count)),
                    3 => chain.call(contract, ops(OP_READ, start, count)),
                    4 => chain.call(contract, ops(OP_UPDATE, start, count)),
                    5 | 6 => chain.call(contract, ops(OP_ZERO, start, count)),
                    7 => chain.call(catcher, ops(next(4), start, count)),
                    _ => chain.call(block_hash, Bytes::copy_from_slice(&word(next(280)))),
                };
                txs.push(tx);
            }
            if next(4) == 0 {
                let mut to = [0x77u8; 20];
                to[12..].copy_from_slice(&next(30).to_be_bytes());
                txs.push(chain.tx(TxKind::Call(Address::from(to)), U256::from(1u64), Bytes::new(), 21_000));
            }
            let body = chain.body(txs);
            for mode in [BlockHashes::Eager, BlockHashes::Lazy] {
                let (witness, canonical, context) = chain.witness(&body, mode);
                let verified = chain.verify(&witness, &context, &body, mode).unwrap();
                assert_eq!(verified.header, canonical.header, "seed {seed} block {block} {mode:?}");
            }
            chain.commit(&body);
        }
        assert!(chain.state.db().cache.accounts[&contract].storage.len() > 50);
    }
}

/// Deletion of most of a trie and rebuilding it, where collapses are many.
#[test]
fn draining_and_refilling_a_contract_matches_the_canonical_path() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 64);
    for (op, start, count) in [
        (OP_ZERO, 0, 10),
        (OP_ZERO, 10, 30),
        (OP_ZERO, 40, 23),
        (OP_ZERO, 63, 1),
        (OP_WRITE, 0, 3),
        (OP_ZERO, 1, 1),
        (OP_ZERO, 0, 1),
        (OP_ZERO, 2, 1),
        (OP_WRITE, 100, 40),
    ] {
        let tx = chain.call(contract, ops(op, start, count));
        let body = chain.body(vec![tx]);
        chain.witness(&body, BlockHashes::Lazy);
        chain.witness(&body, BlockHashes::Eager);
        assert!(chain.commit(&body).transactions[0].success);
    }
}

/// An account created in the block, and one created and destroyed in the same
/// transaction: revm's commit sets the wipe marker, and the root is from the cache.
#[test]
fn created_and_destroyed_accounts_match_the_canonical_path() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    // Initcode: sstore(1, 5), then return no code.
    let plain = vec![0x60, 0x05, 0x60, 0x01, 0x55, 0x60, 0x00, 0x60, 0x00, 0xf3];
    // Initcode: sstore(1, 5), then selfdestruct to address 0x77 (EIP-6780: same transaction).
    let destroyed = vec![0x60, 0x05, 0x60, 0x01, 0x55, 0x60, 0x77, 0xff];
    // Keep a value on the address the destroyed one was funded from.
    let a = chain.tx(TxKind::Create, U256::from(3u64), plain.into(), 500_000);
    let b = chain.tx(TxKind::Create, U256::from(3u64), destroyed.into(), 500_000);
    let c = chain.tx(TxKind::Call(Address::repeat_byte(0x77)), U256::from(1u64), Bytes::new(), 21_000);
    let body = chain.body(vec![a, b, c]);
    let (witness, canonical, context) = chain.witness(&body, BlockHashes::Lazy);
    assert!(canonical.transactions.iter().all(|tx| tx.success));
    chain.verify(&witness, &context, &body, BlockHashes::Lazy).unwrap();
    chain.commit(&body);

    // The same address again, in a later block: a call on the now-empty account.
    let after = chain.body(vec![]);
    chain.witness(&after, BlockHashes::Lazy);
}

#[test]
fn indexed_lookup_and_apply_agree_with_the_plain_view() {
    let mut trie = Mpt::new();
    let keys: Vec<Nibbles> = (0..2000u64).map(|slot| storage_key(&U256::from(slot))).collect();
    for (index, key) in keys.iter().enumerate() {
        trie.insert(*key, alloy_rlp::encode(U256::from(index as u64 + 1)));
    }
    let root = trie.root();
    let mut rng = keccak256(b"indexed");
    let mut next = |bound: usize| {
        rng = keccak256(rng);
        usize::from_be_bytes(rng[..8].try_into().unwrap()) % bound
    };
    for round in 0..30 {
        let targets: Vec<Nibbles> = (0..1 + next(40)).map(|_| keys[next(2000)]).collect();
        let proof = trie.proof(targets.iter().copied()).unwrap();
        let plain = SparseTrieView::from_proof(root, &proof).unwrap();
        let indexed = IndexedTrieView::from_proof(root, &proof).unwrap();
        // Positions on every side: live keys, absent keys, all of them.
        for slot in 0..4000u64 {
            let key = storage_key(&U256::from(slot));
            match (plain.contains_key(&key), indexed.lookup(&key)) {
                (Ok(true), Ok(Some(value))) => assert_eq!(plain.leaf(&key).map(Vec::as_slice), Some(value)),
                (Ok(false), Ok(None)) | (Err(_), Err(_)) => {}
                (a, b) => panic!("round {round} slot {slot}: {a:?} vs {b:?}"),
            }
        }
        let mut changes = BTreeMap::new();
        for key in &targets {
            changes.insert(*key, if next(3) == 0 { None } else { Some(vec![0x09]) });
        }
        changes.insert(storage_key(&U256::from(5000 + round as u64)), Some(vec![0x07]));
        let a = plain.apply(&changes);
        let b = indexed.apply(&changes);
        match (a, b) {
            (Ok(x), Ok(y)) => assert_eq!(x, y),
            (Err(x), Err(y)) => assert_eq!(x, y),
            (a, b) => panic!("round {round}: {a:?} vs {b:?}"),
        }
    }
}

#[cfg(feature = "serde")]
#[test]
fn the_witness_round_trips_and_a_huge_node_is_refused() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let contract = big_contract(&mut chain, 20);
    let tx = chain.call(contract, ops(OP_UPDATE, 3, 1));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.witness(&body, BlockHashes::Lazy);
    let json = serde_json::to_value(&witness).unwrap();
    let back: SparseBatchWitness = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, witness);
    chain.verify(&back, &context, &body, BlockHashes::Lazy).unwrap();
    let mut oversized = json;
    let index = account(&witness, contract);
    let first = oversized["pre_accounts"][index]["storage_proof"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    oversized["pre_accounts"][index]["storage_proof"][first] = serde_json::json!(vec![0u8; 1025]);
    assert!(serde_json::from_value::<SparseBatchWitness>(oversized).is_err());
}

/// The statement bytes are the complete witness's bytes for the same block.
#[test]
fn the_statement_is_byte_identical_to_the_complete_witness() {
    use crate::proof_statement::execute_settlement_statement_v3;
    for spec in both_rules() {
        let mut chain = Chain::new(spec.clone());
        let contract = big_contract(&mut chain, 50);
        let tx = chain.call(contract, ops(OP_UPDATE, 3, 2));
        let body = chain.body(vec![tx]);
        let context = chain.context();
        let settlement = SettlementContextV2 {
            network: B256::repeat_byte(0x41),
            genesis: B256::repeat_byte(0x42),
            program_elf_keccak: B256::repeat_byte(0x43),
            program_vkey_koalabear: B256::repeat_byte(0x44),
            program_vkey_bn254: B256::repeat_byte(0x45),
            previous_settlement: B256::ZERO,
            l1_slot: 1,
            l1_height: 1,
            source_commitment: B256::repeat_byte(0x46),
            inbox_root: B256::repeat_byte(0x47),
            inbox_count: 1,
            consumed_start: 0,
            consumed_end: 1,
        };
        let (complete, _) = generate_node_batch_witness(&chain.state, &spec, MAINNET_DOMAIN, &context, &body).unwrap();
        let expected =
            execute_settlement_statement_v3(&spec, MAINNET_DOMAIN, &complete, &context, &body, settlement).unwrap();
        for mode in [BlockHashes::Eager, BlockHashes::Lazy] {
            let (sparse, _, _) = chain.witness(&body, mode);
            let got =
                execute_settlement_statement_v3_sparse(&spec, MAINNET_DOMAIN, &sparse, &context, &body, settlement, mode)
                    .unwrap();
            assert_eq!(got.encode(), expected.encode(), "{mode:?}");
        }
    }
}

// ── Forced inclusion (candidate) on the sparse path ──────────────────────────

mod forced {
    use super::*;
    use crate::forced_inclusion::{forced_hash, inbox_hash, ForcedRecord, ForcedTransaction};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn signed(spec: &ChainSpec, key: &SigningKey, nonce: u64, to: Address, gas_limit: u64) -> Bytes {
        let transaction = TxEip1559 {
            chain_id: spec.chain_id,
            nonce,
            to: TxKind::Call(to),
            value: U256::from(1_000_000u64),
            gas_limit,
            max_fee_per_gas: 200_000_000_000,
            max_priority_fee_per_gas: 0,
            ..Default::default()
        };
        let signature: Signature = key.sign_prehash_recoverable(transaction.signature_hash().as_slice()).unwrap().into();
        TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into()
    }

    fn record(height: u64, envelope: Bytes, declared: u64) -> ForcedTransaction {
        ForcedTransaction {
            record: ForcedRecord {
                l1_height: height,
                l1_txid: [height as u8; 32],
                envelope_hash: keccak256(&envelope),
                gas_limit: declared,
            },
            envelope,
        }
    }

    fn settlement(deposits: u64) -> SettlementContextV2 {
        SettlementContextV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            program_elf_keccak: B256::repeat_byte(3),
            program_vkey_koalabear: B256::repeat_byte(4),
            program_vkey_bn254: B256::repeat_byte(5),
            previous_settlement: B256::repeat_byte(6),
            l1_slot: 1,
            l1_height: 1,
            source_commitment: B256::repeat_byte(7),
            inbox_root: B256::repeat_byte(8),
            inbox_count: deposits,
            consumed_start: 0,
            consumed_end: deposits,
        }
    }

    /// A chain under the next rules (forced inclusion on), the censored user funded.
    struct Fixture {
        chain: Chain,
        censored: SigningKey,
        unfunded: Address,
        queue: Vec<ForcedTransaction>,
    }

    fn fixture() -> Fixture {
        let mut chain = Chain::new(ChainSpec::mainnet());
        assert!(chain.spec.forced_inclusion);
        let censored = key(0x33);
        let censored_address = Address::from_public_key(censored.verifying_key());
        let fund = chain.tx(TxKind::Call(censored_address), U256::from(10u128.pow(18)), Bytes::new(), 21_000);
        let body = chain.body(vec![fund]);
        assert!(chain.commit(&body).transactions[0].success);
        let unfunded_key = key(0x44);
        let unfunded = Address::from_public_key(unfunded_key.verifying_key());
        let spec = chain.spec.clone();
        let to = Address::repeat_byte(0x55);
        let queue = vec![
            // Valid: included first.
            record(10, signed(&spec, &censored, 0, to, 21_000), 21_000),
            // Nonce gap: refused before execution, skipped.
            record(10, signed(&spec, &censored, 7, to, 21_000), 21_000),
            // Not a transaction: skipped.
            record(11, Bytes::from_static(&[0xde, 0xad]), 21_000),
            // An unfunded sender: skipped, and its account must be in the witness.
            record(11, signed(&spec, &unfunded_key, 0, to, 21_000), 21_000),
            // Gas above the declared gas: skipped.
            record(12, signed(&spec, &censored, 1, to, 50_000), 21_000),
            // Valid after the first.
            record(12, signed(&spec, &censored, 1, to, 21_000), 21_000),
        ];
        Fixture { chain, censored, unfunded, queue }
    }

    fn honest_body(f: &mut Fixture) -> NodeBodyV2 {
        let sequencer = f.chain.tx(TxKind::Call(Address::repeat_byte(0x66)), U256::from(5u64), Bytes::new(), 21_000);
        f.chain.body(vec![f.queue[0].envelope.clone(), f.queue[5].envelope.clone(), sequencer])
    }

    #[test]
    fn forced_records_run_first_bind_the_statement_and_cover_skipped_senders() {
        let mut f = fixture();
        let body = honest_body(&mut f);
        let context = f.chain.context();
        let (witness, canonical) = generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &f.queue,
        )
        .expect("an honest forced block generates and self-verifies");
        assert_eq!(witness.forced, f.queue);
        // The skipped unfunded sender was read, so the witness proves it absent.
        assert!(witness.absent_accounts.contains(&f.unfunded));
        let censored = Address::from_public_key(f.censored.verifying_key());
        assert!(witness.pre_accounts.iter().any(|a| a.address == censored));
        let (outcome, included) = verify_node_batch_sparse_forced(
            &f.chain.spec, MAINNET_DOMAIN, &witness, &context, &body, BlockHashes::Lazy,
        )
        .unwrap();
        assert_eq!(included, 2);
        assert_eq!(outcome.header, canonical.header);
        assert!(outcome.transactions.iter().all(|t| t.success));
        // The complete path executes the same body to the same header.
        let mut full = f.chain.state.clone();
        assert_eq!(execute_node_block(&f.chain.spec, MAINNET_DOMAIN, &mut full, &context, &body).unwrap().header, canonical.header);

        let statement = execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .unwrap();
        let records: Vec<ForcedRecord> = f.queue.iter().map(|q| q.record).collect();
        assert_eq!(statement.deposits_hash, inbox_hash(body.deposits_hash(), &records));
        assert_ne!(statement.deposits_hash, body.deposits_hash());
        assert_ne!(forced_hash(&records), forced_hash(&records[..5]));
        assert_eq!(statement.user_tx_count, 1, "only the sequencer's transaction counts");
        assert_eq!(
            statement.da_commitment,
            crate::data_availability::block_da_commitment(context_chain(&f), context.number, &body.transactions[2..]).unwrap()
        );
        assert_eq!(
            configuration_commitment(&f.chain.spec).unwrap(),
            statement.base.configuration,
            "the statement names the forced configuration (tag 4)"
        );
        assert_ne!(statement.base.configuration, {
            let mut plain = f.chain.spec.clone();
            plain.forced_inclusion = false;
            configuration_commitment(&plain).unwrap()
        });
    }

    fn context_chain(f: &Fixture) -> u64 {
        f.chain.spec.chain_id
    }

    #[test]
    fn a_body_that_omits_reorders_or_skips_a_due_forced_transaction_is_refused() {
        let mut f = fixture();
        let honest = honest_body(&mut f);
        let context = f.chain.context();
        let sequencer = honest.transactions[2].clone();
        let bodies = [
            // Omitted.
            vec![f.queue[5].envelope.clone(), sequencer.clone()],
            vec![sequencer.clone()],
            // Swapped.
            vec![f.queue[5].envelope.clone(), f.queue[0].envelope.clone(), sequencer.clone()],
            // Behind a sequencer transaction.
            vec![sequencer.clone(), f.queue[0].envelope.clone(), f.queue[5].envelope.clone()],
        ];
        for transactions in bodies {
            let body = NodeBodyV2 { deposits: honest.deposits.clone(), transactions };
            let result = generate_sparse_node_witness_forced(
                &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &f.queue,
            );
            assert!(result.is_err(), "a body without the exact forced prefix must not generate");
        }
        // The honest witness against a body that drops the forced prefix.
        let (witness, _) = generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &honest, BlockHashes::Lazy, &f.queue,
        )
        .unwrap();
        let dropped = NodeBodyV2 { deposits: honest.deposits.clone(), transactions: vec![sequencer] };
        assert!(verify_node_batch_sparse_forced(&f.chain.spec, MAINNET_DOMAIN, &witness, &context, &dropped, BlockHashes::Lazy).is_err());
    }

    #[test]
    fn a_witness_without_a_skipped_sender_cannot_turn_the_skip_into_a_pass_or_a_valid_one_into_a_skip() {
        let mut f = fixture();
        let body = honest_body(&mut f);
        let context = f.chain.context();
        let (witness, _) = generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &f.queue,
        )
        .unwrap();
        // Remove the unfunded (skipped) sender's absence proof: a database error, never a skip.
        let mut missing = witness.clone();
        missing.absent_accounts.retain(|a| *a != f.unfunded);
        assert!(verify_node_batch_sparse_forced(&f.chain.spec, MAINNET_DOMAIN, &missing, &context, &body, BlockHashes::Lazy).is_err());
        // Remove the censored (included) sender: the forced transaction cannot be skipped instead.
        let censored = Address::from_public_key(f.censored.verifying_key());
        let mut missing = witness.clone();
        missing.pre_accounts.retain(|a| a.address != censored);
        let without_forced = NodeBodyV2 { deposits: body.deposits.clone(), transactions: vec![body.transactions[2].clone()] };
        assert!(verify_node_batch_sparse_forced(&f.chain.spec, MAINNET_DOMAIN, &missing, &context, &without_forced, BlockHashes::Lazy).is_err());
        assert!(verify_node_batch_sparse_forced(&f.chain.spec, MAINNET_DOMAIN, &missing, &context, &body, BlockHashes::Lazy).is_err());
    }

    #[test]
    fn a_tampered_forced_list_changes_the_statement_or_fails() {
        let mut f = fixture();
        let body = honest_body(&mut f);
        let context = f.chain.context();
        let (witness, _) = generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &f.queue,
        )
        .unwrap();
        let honest = execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .unwrap();
        // Dropping a skipped record: still executes, but the slot no longer matches L1's queue.
        let mut fewer = witness.clone();
        fewer.forced.remove(3);
        let statement = execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &fewer, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .unwrap();
        assert_ne!(statement.deposits_hash, honest.deposits_hash);
        // Dropping every record: the forced envelopes become sequencer transactions and the slot is the plain hash.
        let mut none = witness.clone();
        none.forced.clear();
        let statement = execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &none, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .unwrap();
        assert_eq!(statement.deposits_hash, body.deposits_hash());
        assert_ne!(statement.deposits_hash, honest.deposits_hash);
        // An envelope that does not hash to its record.
        let mut swapped = witness.clone();
        swapped.forced[1].envelope = swapped.forced[5].envelope.clone();
        assert!(execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &swapped, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .is_err());
        // More than the per-settlement bounds.
        let mut many = witness.clone();
        while many.forced.len() <= crate::forced_inclusion::MAX_PER_SETTLEMENT {
            many.forced.push(many.forced[2].clone());
        }
        assert!(execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &many, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .is_err());
    }

    #[test]
    fn forced_records_are_refused_under_rules_without_forced_inclusion() {
        let mut chain = Chain::new(ChainSpec::mainnet_v1());
        assert!(!chain.spec.forced_inclusion);
        let tx = chain.tx(TxKind::Call(Address::repeat_byte(0x66)), U256::from(5u64), Bytes::new(), 21_000);
        let body = chain.body(vec![tx.clone()]);
        let context = chain.context();
        let queue = vec![record(3, tx, 21_000)];
        assert!(generate_sparse_node_witness_forced(
            &chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &queue,
        )
        .is_err());
        // And with none, the block is exactly the 115 path: an empty list in the witness.
        let (witness, _) = generate_sparse_node_witness_forced(
            &chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &[],
        )
        .unwrap();
        assert!(witness.forced.is_empty());
    }

    #[test]
    fn a_forced_only_block_has_no_user_transactions_and_no_da() {
        let mut f = fixture();
        let body = f.chain.body(vec![f.queue[0].envelope.clone(), f.queue[5].envelope.clone()]);
        let context = f.chain.context();
        let (witness, _) = generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &f.queue,
        )
        .unwrap();
        let statement = execute_settlement_statement_v3_sparse(
            &f.chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement(1), BlockHashes::Lazy,
        )
        .unwrap();
        assert_eq!(statement.user_tx_count, 0);
        assert_eq!(statement.da_commitment, B256::ZERO);
    }

    #[test]
    fn the_producer_selection_builds_the_body_the_guest_accepts() {
        let mut f = fixture();
        let context = f.chain.context();
        let deposits = vec![f.chain.deposit()];
        let sequencer = f.chain.tx(TxKind::Call(Address::repeat_byte(0x66)), U256::from(5u64), Bytes::new(), 21_000);
        // The censored user's own pool transaction duplicates its forced one: dropped there.
        let candidates = vec![f.queue[0].envelope.clone(), sequencer.clone()];
        let (forced, selection) = crate::node_execution::select::select_node_transactions_after_forced(
            &f.chain.spec,
            MAINNET_DOMAIN,
            f.chain.state.db(),
            f.chain.state.state_root(),
            &context,
            &deposits,
            &f.queue,
            &candidates,
            crate::node_execution::select::SelectionLimits::protocol(&f.chain.spec),
        )
        .unwrap();
        assert_eq!(forced.included, vec![f.queue[0].envelope.clone(), f.queue[5].envelope.clone()]);
        assert_eq!(forced.skipped.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
        assert_eq!(selection.transactions, vec![sequencer]);
        let body = NodeBodyV2 {
            deposits,
            transactions: forced.included.iter().chain(&selection.transactions).cloned().collect(),
        };
        generate_sparse_node_witness_forced(
            &f.chain.state, &f.chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &f.queue,
        )
        .expect("the producer's body is the one the verifier accepts");
    }
}

mod forced_funded_skip {
    use super::*;
    use crate::forced_inclusion::{ForcedRecord, ForcedTransaction};

    #[test]
    fn a_funded_skipped_sender_left_out_of_the_witness_fails_the_block() {
        let mut chain = Chain::new(ChainSpec::mainnet());
        let other = SigningKey::from_bytes((&[0x77u8; 32]).into()).unwrap();
        let other_address = Address::from_public_key(other.verifying_key());
        let fund = chain.tx(TxKind::Call(other_address), U256::from(10u128.pow(18)), Bytes::new(), 21_000);
        let body = chain.body(vec![fund]);
        assert!(chain.commit(&body).transactions[0].success);
        // A nonce gap: skipped, but its sender's account decides it.
        let transaction = TxEip1559 {
            chain_id: chain.spec.chain_id,
            nonce: 9,
            to: TxKind::Call(Address::repeat_byte(0x55)),
            value: U256::from(1u64),
            gas_limit: 21_000,
            max_fee_per_gas: 200_000_000_000,
            ..Default::default()
        };
        let signature: Signature = other.sign_prehash_recoverable(transaction.signature_hash().as_slice()).unwrap().into();
        let envelope: Bytes = TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into();
        let forced = vec![ForcedTransaction {
            record: ForcedRecord { l1_height: 5, l1_txid: [5; 32], envelope_hash: keccak256(&envelope), gas_limit: 21_000 },
            envelope,
        }];
        let body = chain.body(vec![]);
        let context = chain.context();
        let (witness, _) = generate_sparse_node_witness_forced(
            &chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body, BlockHashes::Lazy, &forced,
        )
        .unwrap();
        assert!(witness.pre_accounts.iter().any(|a| a.address == other_address), "the skipped sender is witnessed");
        let mut missing = witness.clone();
        missing.pre_accounts.retain(|a| a.address != other_address);
        let result = verify_node_batch_sparse_forced(&chain.spec, MAINNET_DOMAIN, &missing, &context, &body, BlockHashes::Lazy);
        assert!(result.is_err(), "accepted: {:?}", result.map(|(o, n)| (o.header.state_root, n)));
    }
}
