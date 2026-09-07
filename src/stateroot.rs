// SPDX-License-Identifier: MIT OR Apache-2.0
//! State-root commitment — keccak-256 hexary Merkle-Patricia trie — and the
//! **authenticated** sparse-trie view used by the stateless proving path.
//!
//! The design (BLOCH-L2-EVM-DESIGN §1) commits state as a **standard Ethereum
//! keccak-256 hexary Merkle-Patricia trie root** (account trie + per-account
//! storage tries) so `eth_getProof` and the Bloch-anchored root are
//! byte-compatible with Ethereum tooling. This module computes that root over
//! the scaffold's [`L2State`] via `alloy-trie`'s `HashBuilder` (the primitive
//! reth uses), with account and storage values RLP-encoded exactly as Ethereum
//! does.
//!
//! Correctness anchors (see the tests): an empty state hashes to the canonical
//! `EMPTY_ROOT_HASH`; an account with no storage carries an `EMPTY_ROOT_HASH`
//! storage root inside its RLP; the root is deterministic and insertion-order
//! independent; **empty accounts (EIP-161: nonce 0, balance 0, empty code) are
//! excluded** from the trie exactly as on Ethereum. Still **SCAFFOLD/UNAUDITED** —
//! this is the state-root primitive, not a node.
//!
//! [`SparseTrieView`] walks a multiproof **only after** checking that its root
//! node hashes to the expected state root and that every descended child node
//! hashes to the reference stored in its parent, so nothing a prover supplies
//! is trusted by structure alone. Every malformed or incomplete input is a
//! [`WitnessError`], never a panic.

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable, Header};
use alloy_trie::nodes::{RlpNode, TrieNode};
use alloy_trie::{HashBuilder, Nibbles, EMPTY_ROOT_HASH};
use revm::database::{AccountState, CacheDB};
use revm::primitives::KECCAK_EMPTY;

use crate::state::L2State;

/// Number of nibbles in a keccak-hashed trie key (32 bytes).
pub const KEY_NIBBLES: usize = 64;

/// Longest compact-encoded path a leaf or extension node may carry
/// (32 key bytes + 1 flag byte).
const MAX_COMPACT_KEY_BYTES: usize = 33;

/// RLP-encode one account as Ethereum does: a list `[nonce, balance,
/// storageRoot, codeHash]`. `nonce`/`balance` use minimal big-endian (RLP integer
/// form); the two roots are fixed 32-byte strings.
fn encode_account(nonce: u64, balance: U256, storage_root: B256, code_hash: B256, out: &mut Vec<u8>) {
    let payload_len =
        nonce.length() + balance.length() + storage_root.length() + code_hash.length();
    Header { list: true, payload_length: payload_len }.encode(out);
    nonce.encode(out);
    balance.encode(out);
    storage_root.encode(out);
    code_hash.encode(out);
}

/// Feed `(keccak-hashed key, rlp value)` leaves into a hexary MPT and return its
/// root. Leaves are sorted by hashed key (the order `HashBuilder` requires).
/// Empty input yields the canonical [`EMPTY_ROOT_HASH`].
fn trie_root(mut leaves: Vec<(B256, Vec<u8>)>) -> B256 {
    if leaves.is_empty() {
        return EMPTY_ROOT_HASH;
    }
    leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut hb = HashBuilder::default();
    for (hashed_key, value) in &leaves {
        hb.add_leaf(Nibbles::unpack(hashed_key), value);
    }
    hb.root()
}

/// The keccak-256 MPT storage root over one account's slots: key
/// `keccak256(slot)`, value `rlp(U256)` (leading zeros trimmed), **zero-valued
/// slots omitted** (Ethereum stores no zero slots). Empty storage →
/// [`EMPTY_ROOT_HASH`].
fn storage_root<'a>(slots: impl Iterator<Item = (&'a U256, &'a U256)>) -> B256 {
    let leaves: Vec<(B256, Vec<u8>)> = slots
        .filter(|(_, value)| !value.is_zero())
        .map(|(slot, value)| {
            let key = keccak256(slot.to_be_bytes::<32>());
            let mut buf = Vec::new();
            value.encode(&mut buf);
            (key, buf)
        })
        .collect();
    trie_root(leaves)
}

/// Compute the real keccak-256 MPT **state root** over the account and storage
/// tries of `state`.
///
/// Each existing, non-empty account contributes a leaf keyed by
/// `keccak256(address)` whose value is `rlp(nonce, balance, storageRoot,
/// codeHash)`, where `storageRoot` is that account's own storage-trie root.
/// Empty accounts (EIP-161) and non-existing accounts are excluded, matching
/// Ethereum's state trie.
///
/// Requires a **complete** cache (the `EmptyDB`-backed [`L2State`] holds every
/// live account and slot); a partially cached database would yield a root over
/// partial state.
pub fn compute_keccak_mpt_state_root(state: &L2State) -> B256 {
    trie_root(account_leaves(state))
}

/// The `(keccak256(address), rlp(account))` leaf set of the state trie — the
/// same leaves [`compute_keccak_mpt_state_root`] hashes. Unsorted.
pub(crate) fn account_leaves(state: &L2State) -> Vec<(B256, Vec<u8>)> {
    account_leaves_of(&state.db)
}

/// [`account_leaves`] over any `CacheDB` whose cache is complete for the
/// accounts it holds (the stateless guest's hydrated state qualifies: every
/// hydrated account carries its full non-zero storage).
pub(crate) fn account_leaves_of<ExtDB>(db: &CacheDB<ExtDB>) -> Vec<(B256, Vec<u8>)> {
    db.cache
        .accounts
        .iter()
        .filter(|(_, acc)| acc.account_state != AccountState::NotExisting)
        .filter_map(|(address, acc)| {
            let info = acc.info()?;
            let code_hash = if info.code_hash == B256::ZERO { KECCAK_EMPTY } else { info.code_hash };
            // EIP-161: an account with nonce 0, balance 0, and empty code is not
            // in the state trie.
            if info.nonce == 0 && info.balance.is_zero() && code_hash == KECCAK_EMPTY {
                return None;
            }
            let s_root = storage_root(acc.storage.iter());
            let mut value = Vec::new();
            encode_account(info.nonce, info.balance, s_root, code_hash, &mut value);
            Some((keccak256(address), value))
        })
        .collect()
}

/// Why a multiproof / change set cannot be turned into a state root.
///
/// Every variant is a **reject the witness** outcome for a verifier or guest;
/// none of them is reachable from an honest, complete witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// The proof is empty but the expected root is not the empty-trie root.
    EmptyProofForNonEmptyRoot {
        /// The state root the proof was supposed to open.
        expected: B256,
    },
    /// The proof has nodes but none at the root path.
    MissingRootNode,
    /// The root node does not hash to the expected state root.
    RootMismatch {
        /// The state root the proof was supposed to open.
        expected: B256,
        /// `keccak256` of the supplied root node.
        got: B256,
    },
    /// A node present in the proof does not hash to (or, for an embedded node,
    /// equal) the reference stored in its parent.
    UnanchoredNode {
        /// Trie path of the offending node.
        path: Nibbles,
    },
    /// A node's RLP is not a valid trie node (or carries an over-long key).
    MalformedNode {
        /// Trie path of the offending node.
        path: Nibbles,
    },
    /// An extension node with an empty key (would not advance the walk).
    EmptyExtensionKey {
        /// Trie path of the offending node.
        path: Nibbles,
    },
    /// A path would exceed the 64-nibble key length.
    PathTooLong {
        /// Trie path at which the overflow was detected.
        path: Nibbles,
    },
    /// Two leaves claim the same full key.
    DuplicateLeaf {
        /// The duplicated key.
        key: Nibbles,
    },
    /// A change key is not exactly 64 nibbles long.
    InvalidKeyLength {
        /// The offending key.
        key: Nibbles,
    },
    /// A change (or lookup) key lies inside a subtree the proof left opaque, so
    /// the proof cannot say whether the key exists — the witness is incomplete.
    KeyInOpaqueSubtree {
        /// The offending key.
        key: Nibbles,
        /// The opaque subtree's path.
        frontier: Nibbles,
    },
    /// A delete targets a key the proof proves absent.
    DeleteOfAbsentKey {
        /// The offending key.
        key: Nibbles,
    },
}

impl core::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WitnessError::EmptyProofForNonEmptyRoot { expected } => {
                write!(f, "empty proof cannot open non-empty state root {expected}")
            }
            WitnessError::MissingRootNode => write!(f, "proof has no node at the root path"),
            WitnessError::RootMismatch { expected, got } => {
                write!(f, "proof root node hashes to {got}, expected state root {expected}")
            }
            WitnessError::UnanchoredNode { path } => {
                write!(f, "proof node at {path:?} does not match its parent's reference")
            }
            WitnessError::MalformedNode { path } => write!(f, "malformed trie node at {path:?}"),
            WitnessError::EmptyExtensionKey { path } => {
                write!(f, "extension node with empty key at {path:?}")
            }
            WitnessError::PathTooLong { path } => write!(f, "trie path exceeds 64 nibbles at {path:?}"),
            WitnessError::DuplicateLeaf { key } => write!(f, "duplicate leaf for key {key:?}"),
            WitnessError::InvalidKeyLength { key } => {
                write!(f, "change key {key:?} is not 64 nibbles long")
            }
            WitnessError::KeyInOpaqueSubtree { key, frontier } => write!(
                f,
                "key {key:?} lies inside opaque subtree {frontier:?}: witness incomplete"
            ),
            WitnessError::DeleteOfAbsentKey { key } => {
                write!(f, "delete of key {key:?} which the proof proves absent")
            }
        }
    }
}

impl core::error::Error for WitnessError {}

/// An **authenticated** sparse view of a Merkle-Patricia trie, reconstructed
/// from a multiproof that was checked against a known root: the exposed leaves
/// (full key → current RLP value) and the opaque frontier (subtree path → hash)
/// of everything the proof did not expose.
///
/// Because every node was hash-linked to its parent down from the root, a key
/// is either an exposed leaf, provably absent (its position is exposed and
/// empty), or hidden inside an opaque subtree — in which case the view refuses
/// to answer ([`WitnessError::KeyInOpaqueSubtree`]) instead of guessing.
#[derive(Debug, Clone, Default)]
pub struct SparseTrieView {
    leaves: BTreeMap<Nibbles, Vec<u8>>,
    frontier: Vec<(Nibbles, B256)>,
}

impl SparseTrieView {
    /// Build the view from `proof` (trie path → node RLP), verifying that the
    /// node at the root path hashes to `state_root` and that every descended
    /// child matches the reference held by its parent. Embedded (< 32-byte)
    /// children are decoded in place. An empty proof is accepted only for the
    /// empty-trie root.
    pub fn from_proof(state_root: B256, proof: &BTreeMap<Nibbles, Bytes>) -> Result<Self, WitnessError> {
        let mut view = Self::default();
        if proof.is_empty() {
            if state_root == EMPTY_ROOT_HASH {
                return Ok(view);
            }
            return Err(WitnessError::EmptyProofForNonEmptyRoot { expected: state_root });
        }
        let root_path = Nibbles::default();
        let root = proof.get(&root_path).ok_or(WitnessError::MissingRootNode)?;
        let got = keccak256(root);
        if got != state_root {
            return Err(WitnessError::RootMismatch { expected: state_root, got });
        }
        view.walk(root_path, root, proof)?;
        Ok(view)
    }

    /// The current RLP value of an exposed leaf.
    pub fn leaf(&self, key: &Nibbles) -> Option<&Vec<u8>> {
        self.leaves.get(key)
    }

    /// Exposed leaves, ordered by key.
    pub fn leaves(&self) -> &BTreeMap<Nibbles, Vec<u8>> {
        &self.leaves
    }

    /// Opaque subtrees `(path, hash)` the proof did not expose.
    pub fn frontier(&self) -> &[(Nibbles, B256)] {
        &self.frontier
    }

    /// Whether `key` exists in the trie: `Ok(true)` if it is an exposed leaf,
    /// `Ok(false)` if the proof proves it absent, `Err` if it lies inside an
    /// opaque subtree (the proof cannot tell).
    pub fn contains_key(&self, key: &Nibbles) -> Result<bool, WitnessError> {
        if key.len() != KEY_NIBBLES {
            return Err(WitnessError::InvalidKeyLength { key: *key });
        }
        if self.leaves.contains_key(key) {
            return Ok(true);
        }
        if let Some((frontier, _)) = self.frontier.iter().find(|(p, _)| key.starts_with(p)) {
            return Err(WitnessError::KeyInOpaqueSubtree { key: *key, frontier: *frontier });
        }
        Ok(false)
    }

    /// Apply a change set (full key → `Some(new_rlp)` to set, `None` to delete)
    /// and return the resulting root. Untouched exposed leaves keep the value
    /// read from the proof; opaque subtrees enter as hashes. Fails if any change
    /// key is malformed, lands inside an opaque subtree, or deletes a key the
    /// proof proves absent.
    pub fn apply(&self, changes: &BTreeMap<Nibbles, Option<Vec<u8>>>) -> Result<B256, WitnessError> {
        // Validate the change set against the authenticated shape first.
        for (key, change) in changes {
            let exists = self.contains_key(key)?;
            if !exists && change.is_none() {
                return Err(WitnessError::DeleteOfAbsentKey { key: *key });
            }
        }

        let mut out: Vec<Emit> = Vec::with_capacity(self.leaves.len() + self.frontier.len() + changes.len());
        for (k, cur) in &self.leaves {
            match changes.get(k) {
                Some(None) => {}                                     // delete
                Some(Some(v)) => out.push(Emit::Leaf(*k, v.clone())), // update
                None => out.push(Emit::Leaf(*k, cur.clone())),       // unchanged
            }
        }
        for (k, change) in changes {
            if let Some(v) = change {
                if !self.leaves.contains_key(k) {
                    out.push(Emit::Leaf(*k, v.clone())); // insert into exposed free space
                }
            }
        }
        for (path, hash) in &self.frontier {
            out.push(Emit::Branch(*path, *hash));
        }
        if out.is_empty() {
            return Ok(EMPTY_ROOT_HASH);
        }
        // HashBuilder consumes keys in nibble-lexicographic order. No emitted path
        // is a prefix of another: leaves are 64 nibbles, frontier paths are
        // shorter, and no leaf or change lies under a frontier (checked above).
        out.sort_by_key(|e| e.path().to_vec());
        let mut hb = HashBuilder::default();
        for e in &out {
            match e {
                Emit::Leaf(k, v) => hb.add_leaf(*k, v),
                Emit::Branch(p, h) => hb.add_branch(*p, *h, false),
            }
        }
        Ok(hb.root())
    }

    /// Walk an authenticated node at `path`, recording exposed leaves and the
    /// opaque frontier. Every recursion strictly extends the path, so depth is
    /// bounded by [`KEY_NIBBLES`].
    fn walk(&mut self, path: Nibbles, bytes: &[u8], proof: &BTreeMap<Nibbles, Bytes>) -> Result<(), WitnessError> {
        match decode_node(&path, bytes)? {
            TrieNode::EmptyRoot => Ok(()),
            TrieNode::Leaf(leaf) => {
                if path.len() + leaf.key.len() != KEY_NIBBLES {
                    return Err(WitnessError::PathTooLong { path });
                }
                let full = path.join(&leaf.key);
                if self.leaves.insert(full, leaf.value).is_some() {
                    return Err(WitnessError::DuplicateLeaf { key: full });
                }
                Ok(())
            }
            TrieNode::Extension(ext) => {
                if ext.key.is_empty() {
                    return Err(WitnessError::EmptyExtensionKey { path });
                }
                // An extension's child is a branch, which needs at least one more
                // nibble below it, so the child path must stay below 64.
                if path.len() + ext.key.len() >= KEY_NIBBLES {
                    return Err(WitnessError::PathTooLong { path });
                }
                let cp = path.join(&ext.key);
                self.descend(cp, &ext.child, proof)
            }
            TrieNode::Branch(branch) => {
                if path.len() >= KEY_NIBBLES {
                    return Err(WitnessError::PathTooLong { path });
                }
                let mut rank = 0usize;
                for nibble in 0u8..16 {
                    if !branch.state_mask.is_bit_set(nibble) {
                        continue;
                    }
                    let child = branch.stack.get(rank).ok_or(WitnessError::MalformedNode { path })?;
                    rank += 1;
                    let mut cp = path;
                    cp.push(nibble);
                    self.descend(cp, child, proof)?;
                }
                Ok(())
            }
        }
    }

    /// Resolve a child reference at `cp`: a hash reference is followed only if the
    /// proof supplies a node that hashes to it (else it becomes opaque
    /// frontier); an embedded node is decoded in place (and must equal any copy
    /// the proof carries at that path).
    fn descend(&mut self, cp: Nibbles, child: &RlpNode, proof: &BTreeMap<Nibbles, Bytes>) -> Result<(), WitnessError> {
        match child.as_hash() {
            Some(h) => match proof.get(&cp) {
                Some(bytes) => {
                    if keccak256(bytes) != h {
                        return Err(WitnessError::UnanchoredNode { path: cp });
                    }
                    self.walk(cp, bytes, proof)
                }
                None => {
                    self.frontier.push((cp, h));
                    Ok(())
                }
            },
            None => {
                let inline: &[u8] = child.as_slice();
                if let Some(bytes) = proof.get(&cp) {
                    if bytes.as_ref() != inline {
                        return Err(WitnessError::UnanchoredNode { path: cp });
                    }
                }
                self.walk(cp, inline, proof)
            }
        }
    }
}

/// Decode a trie node, rejecting over-long compact keys **before** alloy-trie's
/// decoder (which asserts on them) sees the bytes.
fn decode_node(path: &Nibbles, bytes: &[u8]) -> Result<TrieNode, WitnessError> {
    let malformed = || WitnessError::MalformedNode { path: *path };
    let mut probe = bytes;
    let header = Header::decode(&mut probe).map_err(|_| malformed())?;
    if header.list {
        if header.payload_length > probe.len() {
            return Err(malformed());
        }
        let mut first = &probe[..header.payload_length];
        if !first.is_empty() {
            let item = Header::decode(&mut first).map_err(|_| malformed())?;
            // Leaf / extension nodes: the first item is the compact key (a string).
            if !item.list && item.payload_length > MAX_COMPACT_KEY_BYTES {
                return Err(malformed());
            }
        }
    }
    let mut buf = bytes;
    TrieNode::decode(&mut buf).map_err(|_| malformed())
}

/// One reconstruction step fed to `HashBuilder`, sorted by trie path.
enum Emit {
    /// A surviving leaf: full key + the value it should carry in the new trie.
    Leaf(Nibbles, Vec<u8>),
    /// An opaque untouched subtree hanging at `path`, known only by `hash`.
    Branch(Nibbles, B256),
}

impl Emit {
    fn path(&self) -> &Nibbles {
        match self {
            Emit::Leaf(p, _) | Emit::Branch(p, _) => p,
        }
    }
}

/// STATELESS state-root UPDATE — the SP1-guest's "compute `new_state_root`"
/// step, general over arbitrary trie shape and over insert / update / delete.
///
/// `proof` is a multiproof (path → node RLP, from a `ProofRetainer`) that must
/// open `prev_state_root`; `changes` maps full keys to `Some(new_rlp)` (update
/// an existing key or insert a new one) or `None` (delete). Untouched account
/// values are never needed: they enter as opaque subtree hashes, and the
/// current value of an exposed-but-unchanged leaf is read from the proof.
///
/// The proof is authenticated node by node (see [`SparseTrieView::from_proof`])
/// and the change set must be fully covered by it: a change inside an opaque
/// subtree or a delete of an absent key is an error, never a silently wrong
/// root.
pub fn stateless_new_root(
    prev_state_root: B256,
    proof: &BTreeMap<Nibbles, Bytes>,
    changes: &BTreeMap<Nibbles, Option<Vec<u8>>>,
) -> Result<B256, WitnessError> {
    SparseTrieView::from_proof(prev_state_root, proof)?.apply(changes)
}

/// Deduplicated, sorted keys — a small helper for witness builders.
pub(crate) fn sorted_unique_keys(keys: impl IntoIterator<Item = B256>) -> Vec<B256> {
    let set: BTreeSet<B256> = keys.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Address};
    use alloy_trie::proof::ProofRetainer;
    use revm::state::AccountInfo;

    /// Fund an account directly (these tests are about trie mechanics, not the
    /// deposit path, so they bypass the supply ledger).
    fn fund(state: &mut L2State, to: Address, wei: u64) {
        let mut info = state.db.cache.accounts.get(&to).map(|a| a.info.clone()).unwrap_or_default();
        info.balance += U256::from(wei);
        state.db.insert_account_info(to, info);
    }

    fn leaves_sorted(state: &L2State) -> Vec<(B256, Vec<u8>)> {
        let mut leaves = account_leaves(state);
        leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        leaves
    }

    /// Multiproof of `targets` against `state`'s account trie.
    fn multiproof(state: &L2State, targets: impl IntoIterator<Item = Nibbles>) -> (B256, BTreeMap<Nibbles, Bytes>) {
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets));
        for (k, v) in &leaves_sorted(state) {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        let root = hb.root();
        let proof = hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();
        (root, proof)
    }

    fn leaf_of(state: &L2State, addr: Address) -> Vec<u8> {
        let key = keccak256(addr);
        account_leaves(state).into_iter().find(|(k, _)| *k == key).expect("leaf").1
    }

    #[test]
    fn empty_state_is_the_canonical_empty_root() {
        // The well-known Ethereum empty-trie root keccak256(rlp("")).
        assert_eq!(compute_keccak_mpt_state_root(&L2State::new()), EMPTY_ROOT_HASH);
    }

    #[test]
    fn empty_storage_root_is_the_canonical_empty_root() {
        let none: Vec<(U256, U256)> = vec![];
        assert_eq!(storage_root(none.iter().map(|(k, v)| (k, v))), EMPTY_ROOT_HASH);
    }

    #[test]
    fn one_funded_account_yields_a_nonempty_deterministic_root() {
        let mut a = L2State::new();
        fund(&mut a, address!("00000000000000000000000000000000000000aa"), 5);
        let r1 = compute_keccak_mpt_state_root(&a);
        assert_ne!(r1, EMPTY_ROOT_HASH, "a funded account must change the root");
        assert_ne!(r1, B256::ZERO, "a real MPT root is never all-zeroes");
        assert_eq!(r1, compute_keccak_mpt_state_root(&a), "deterministic");
    }

    #[test]
    fn root_is_insertion_order_independent() {
        let x = address!("00000000000000000000000000000000000000aa");
        let y = address!("00000000000000000000000000000000000000bb");
        let mut a = L2State::new();
        fund(&mut a, x, 3);
        fund(&mut a, y, 7);
        let mut b = L2State::new();
        fund(&mut b, y, 7);
        fund(&mut b, x, 3);
        assert_eq!(
            compute_keccak_mpt_state_root(&a),
            compute_keccak_mpt_state_root(&b),
            "the state root is a set commitment — insertion order must not matter"
        );
    }

    #[test]
    fn different_balances_give_different_roots() {
        let who = address!("00000000000000000000000000000000000000aa");
        let mut a = L2State::new();
        fund(&mut a, who, 1);
        let mut b = L2State::new();
        fund(&mut b, who, 2);
        assert_ne!(compute_keccak_mpt_state_root(&a), compute_keccak_mpt_state_root(&b));
    }

    #[test]
    fn eip161_empty_account_is_excluded_but_nonempty_is_included() {
        let who = address!("00000000000000000000000000000000000000aa");

        // An account that EXISTS in the DB (account_state = None, not
        // NotExisting) but is empty per EIP-161 (nonce 0, balance 0, empty
        // code) must NOT appear in the state trie: the root stays the
        // canonical empty root even though the account is present in the cache.
        let mut empty = L2State::new();
        empty.db.insert_account_info(who, AccountInfo::default());
        assert!(empty.db.cache.accounts.contains_key(&who), "the empty account is present in the DB cache");
        assert_eq!(
            compute_keccak_mpt_state_root(&empty),
            EMPTY_ROOT_HASH,
            "an EIP-161 empty account must be excluded from the state trie"
        );

        // Nonce alone (nonce 1, balance 0, empty code) makes the account
        // non-empty, so it IS in the trie and moves the root.
        let mut with_nonce = L2State::new();
        with_nonce.db.insert_account_info(who, AccountInfo { nonce: 1, ..Default::default() });
        assert_ne!(compute_keccak_mpt_state_root(&with_nonce), EMPTY_ROOT_HASH);

        // Balance alone likewise makes it non-empty.
        let mut with_balance = L2State::new();
        with_balance.db.insert_account_info(who, AccountInfo { balance: U256::from(1u64), ..Default::default() });
        assert_ne!(compute_keccak_mpt_state_root(&with_balance), EMPTY_ROOT_HASH);
    }

    #[test]
    fn eip161_empty_accounts_are_invisible_to_the_root() {
        let funded = address!("00000000000000000000000000000000000000aa");
        let ghost = address!("00000000000000000000000000000000000000bb");

        let mut only_funded = L2State::new();
        fund(&mut only_funded, funded, 9);

        let mut with_ghost = L2State::new();
        fund(&mut with_ghost, funded, 9);
        // A touched-but-empty account alongside the funded one.
        with_ghost.db.insert_account_info(ghost, AccountInfo::default());

        assert_eq!(
            compute_keccak_mpt_state_root(&only_funded),
            compute_keccak_mpt_state_root(&with_ghost),
            "EIP-161 empty accounts do not perturb the state root"
        );
    }

    /// Stateless witness verification (guest step 3(a)) on the REAL account
    /// trie: a multiproof for a touched account opens against the state root
    /// via the authenticated [`SparseTrieView`], and is tamper-evident.
    #[test]
    fn p0_3_stateless_witness_verifies_touched_account_against_prev_state_root() {
        let addrs = [
            address!("00000000000000000000000000000000000000a1"),
            address!("00000000000000000000000000000000000000b2"),
            address!("00000000000000000000000000000000000000c3"),
            address!("00000000000000000000000000000000000000d4"),
        ];
        let mut state = L2State::new();
        for (i, a) in addrs.iter().enumerate() {
            fund(&mut state, *a, (i as u64 + 1) * 100);
        }
        let prev_root = compute_keccak_mpt_state_root(&state);
        let touched_key = Nibbles::unpack(keccak256(addrs[1]));
        let (root, proof) = multiproof(&state, [touched_key]);
        assert_eq!(root, prev_root, "the retained build reproduces the state root");

        // (a.i) The witness OPENS: the touched account's real value is exposed.
        let view = SparseTrieView::from_proof(prev_root, &proof).expect("anchored proof");
        assert_eq!(view.leaf(&touched_key), Some(&leaf_of(&state, addrs[1])));
        assert_eq!(view.contains_key(&touched_key), Ok(true));

        // (a.ii) Tamper-evident: a wrong root, or a modified node, is rejected.
        let mut wrong = prev_root;
        wrong.0[0] ^= 0xFF;
        assert!(matches!(
            SparseTrieView::from_proof(wrong, &proof),
            Err(WitnessError::RootMismatch { .. })
        ));
        let mut tampered = proof.clone();
        let (deepest, bytes) = tampered.iter().max_by_key(|(p, _)| p.len()).map(|(p, b)| (*p, b.clone())).unwrap();
        let mut b = bytes.to_vec();
        let last = b.len() - 1;
        b[last] ^= 0xFF;
        tampered.insert(deepest, b.into());
        let err = SparseTrieView::from_proof(prev_root, &tampered).unwrap_err();
        assert!(
            matches!(err, WitnessError::RootMismatch { .. } | WitnessError::UnanchoredNode { .. } | WitnessError::MalformedNode { .. }),
            "tampered node must be rejected, got {err:?}"
        );
    }

    /// Stateless root update over a nested (non-flat) trie: 40 accounts, 3
    /// touched, only the touched keys exposed.
    #[test]
    fn p0_3b_general_stateless_root_update_over_nested_branches() {
        let mut state = L2State::new();
        let mut addrs = Vec::new();
        for i in 0u8..40 {
            let mut b = [0u8; 20];
            b[19] = i;
            let a = Address::from(b);
            fund(&mut state, a, (i as u64 + 1) * 10);
            addrs.push(a);
        }
        let prev_root = compute_keccak_mpt_state_root(&state);

        let touched_addrs = [addrs[3], addrs[17], addrs[29]];
        let mut new_state = state.clone();
        for a in &touched_addrs {
            fund(&mut new_state, *a, 500);
        }
        let expected = compute_keccak_mpt_state_root(&new_state);

        let touched_keys: Vec<Nibbles> = touched_addrs.iter().map(|a| Nibbles::unpack(keccak256(a))).collect();
        let (root, proof) = multiproof(&state, touched_keys);
        assert_eq!(root, prev_root);

        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        for a in &touched_addrs {
            changes.insert(Nibbles::unpack(keccak256(a)), Some(leaf_of(&new_state, *a)));
        }
        let got = stateless_new_root(prev_root, &proof, &changes).expect("complete witness");
        assert_eq!(got, expected, "general sparse stateless root update must match the full rebuild");
        assert_ne!(got, prev_root, "the update moved the root");
    }

    /// INSERT — a new account splits the trie (a single-leaf root becomes a
    /// 2-leaf branch). The witness exposes the leaf the insert splits (a
    /// non-inclusion proof of the new key).
    #[test]
    fn p0_3b_stateless_insert_new_account() {
        let existing = address!("0000000000000000000000000000000000000001");
        let new_addr = address!("0000000000000000000000000000000000000018");
        let mut state = L2State::new();
        fund(&mut state, existing, 100);
        let prev_root = compute_keccak_mpt_state_root(&state);

        let mut new_state = state.clone();
        fund(&mut new_state, new_addr, 250); // INSERT
        let expected = compute_keccak_mpt_state_root(&new_state);

        let new_key = Nibbles::unpack(keccak256(new_addr));
        let (root, proof) = multiproof(&state, [new_key]);
        assert_eq!(root, prev_root);
        let view = SparseTrieView::from_proof(prev_root, &proof).unwrap();
        assert_eq!(view.contains_key(&new_key), Ok(false), "non-inclusion is provable");

        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(new_key, Some(leaf_of(&new_state, new_addr)));
        assert_eq!(stateless_new_root(prev_root, &proof, &changes), Ok(expected), "insert must match full rebuild");
    }

    /// DELETE — removing an account collapses a branch (a 2-leaf branch
    /// collapses to a single leaf). The witness exposes BOTH the deleted key
    /// and its surviving sibling.
    #[test]
    fn p0_3b_stateless_delete_account_collapses_branch() {
        let del = address!("0000000000000000000000000000000000000001");
        let keep = address!("0000000000000000000000000000000000000018");
        let mut state = L2State::new();
        fund(&mut state, del, 100);
        fund(&mut state, keep, 200);
        let prev_root = compute_keccak_mpt_state_root(&state);

        // DELETE: zero the account (EIP-161 empty ⇒ excluded from the trie).
        let mut new_state = state.clone();
        new_state.db.insert_account_info(del, AccountInfo::default());
        let expected = compute_keccak_mpt_state_root(&new_state);
        assert_ne!(expected, prev_root);

        let del_key = Nibbles::unpack(keccak256(del));
        let (root, proof) = multiproof(&state, [del_key, Nibbles::unpack(keccak256(keep))]);
        assert_eq!(root, prev_root);

        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(del_key, None);
        assert_eq!(stateless_new_root(prev_root, &proof, &changes), Ok(expected), "delete-with-collapse must match full rebuild");
    }

    /// First insert into an EMPTY trie: the proof is empty (or the single
    /// empty-root node) and the update is the trie of that one leaf.
    #[test]
    fn stateless_insert_into_empty_trie() {
        let who = address!("00000000000000000000000000000000000000aa");
        let mut new_state = L2State::new();
        fund(&mut new_state, who, 1);
        let expected = compute_keccak_mpt_state_root(&new_state);
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(Nibbles::unpack(keccak256(who)), Some(leaf_of(&new_state, who)));
        let empty_proof = BTreeMap::new();
        assert_eq!(stateless_new_root(EMPTY_ROOT_HASH, &empty_proof, &changes), Ok(expected));
        // Deleting the only account returns to the empty root.
        let (root, proof) = multiproof(&new_state, [Nibbles::unpack(keccak256(who))]);
        assert_eq!(root, expected);
        let mut del: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        del.insert(Nibbles::unpack(keccak256(who)), None);
        assert_eq!(stateless_new_root(expected, &proof, &del), Ok(EMPTY_ROOT_HASH));
    }

    #[test]
    fn unanchored_or_injected_proof_nodes_are_rejected() {
        let mut state = L2State::new();
        let mut addrs = Vec::new();
        for i in 0u8..20 {
            let mut b = [0u8; 20];
            b[19] = i;
            fund(&mut state, Address::from(b), (i as u64 + 1) * 10);
            addrs.push(Address::from(b));
        }
        let prev_root = compute_keccak_mpt_state_root(&state);
        let target = Nibbles::unpack(keccak256(addrs[5]));
        let (root, proof) = multiproof(&state, [target]);
        assert_eq!(root, prev_root);
        let view = SparseTrieView::from_proof(prev_root, &proof).unwrap();
        assert!(!view.frontier().is_empty(), "20 accounts leave opaque siblings");

        // An empty proof cannot open a non-empty root.
        assert!(matches!(
            SparseTrieView::from_proof(prev_root, &BTreeMap::new()),
            Err(WitnessError::EmptyProofForNonEmptyRoot { .. })
        ));

        // Inject a fabricated leaf at an opaque frontier path: the parent's hash
        // reference does not match, so the node is rejected instead of trusted.
        let (frontier_path, _) = view.frontier()[0];
        let mut injected = proof.clone();
        let rest = Nibbles::from_nibbles(vec![0u8; KEY_NIBBLES - frontier_path.len()]);
        let fake = alloy_trie::nodes::LeafNode::new(rest, vec![0xc0]);
        injected.insert(frontier_path, alloy_rlp::encode(&fake).into());
        assert_eq!(
            SparseTrieView::from_proof(prev_root, &injected).unwrap_err(),
            WitnessError::UnanchoredNode { path: frontier_path }
        );

        // Rewriting an exposed leaf's bytes breaks the chain up to the root.
        let mut tampered = proof.clone();
        let (deepest, bytes) = tampered.iter().max_by_key(|(p, _)| p.len()).map(|(p, b)| (*p, b.clone())).unwrap();
        let mut b = bytes.to_vec();
        let last = b.len() - 1;
        b[last] ^= 0x01;
        tampered.insert(deepest, b.into());
        assert!(SparseTrieView::from_proof(prev_root, &tampered).is_err());
    }

    #[test]
    fn changes_inside_opaque_subtrees_and_deletes_of_absent_keys_are_errors() {
        let mut state = L2State::new();
        let mut addrs = Vec::new();
        for i in 0u8..20 {
            let mut b = [0u8; 20];
            b[19] = i;
            fund(&mut state, Address::from(b), (i as u64 + 1) * 10);
            addrs.push(Address::from(b));
        }
        let prev_root = compute_keccak_mpt_state_root(&state);
        let target = Nibbles::unpack(keccak256(addrs[5]));
        let (_, proof) = multiproof(&state, [target]);
        let view = SparseTrieView::from_proof(prev_root, &proof).unwrap();
        let (frontier_path, _) = view.frontier()[0];

        // A key under the opaque subtree: cannot be inserted, updated or deleted.
        let mut hidden = frontier_path;
        while hidden.len() < KEY_NIBBLES {
            hidden.push(0);
        }
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(hidden, None);
        assert!(matches!(view.apply(&changes), Err(WitnessError::KeyInOpaqueSubtree { .. })));
        changes.insert(hidden, Some(vec![0xc0]));
        assert!(matches!(view.apply(&changes), Err(WitnessError::KeyInOpaqueSubtree { .. })));
        assert!(matches!(view.contains_key(&hidden), Err(WitnessError::KeyInOpaqueSubtree { .. })));

        // Deleting a provably absent key is a witness inconsistency.
        let absent = Nibbles::unpack(keccak256(address!("00000000000000000000000000000000deadbeef")));
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        match view.contains_key(&absent) {
            Ok(false) => {
                changes.insert(absent, None);
                assert_eq!(view.apply(&changes), Err(WitnessError::DeleteOfAbsentKey { key: absent }));
            }
            other => {
                // The key happens to fall under an opaque sibling; that is the
                // other error, equally a rejection.
                assert!(matches!(other, Err(WitnessError::KeyInOpaqueSubtree { .. })));
            }
        }

        // Malformed keys are rejected before anything is hashed.
        let mut short: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        short.insert(Nibbles::from_nibbles([1, 2, 3]), Some(vec![0xc0]));
        assert!(matches!(view.apply(&short), Err(WitnessError::InvalidKeyLength { .. })));
    }

    #[test]
    fn malformed_nodes_are_errors_not_panics() {
        // Garbage at the root: hash mismatch (never decoded).
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), Bytes::from_static(&[0xde, 0xad]));
        assert!(matches!(
            SparseTrieView::from_proof(keccak256([0xde, 0xad]), &proof),
            Err(WitnessError::MalformedNode { .. })
        ));

        // Zero-length extension key (compact 0x00): rejected, no recursion.
        let child = B256::repeat_byte(0x44);
        let mut payload = Vec::new();
        [0x00u8].as_slice().encode(&mut payload);
        child.encode(&mut payload);
        let mut rlp = Vec::new();
        Header { list: true, payload_length: payload.len() }.encode(&mut rlp);
        rlp.extend(payload);
        let root = keccak256(&rlp);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), rlp.into());
        assert_eq!(
            SparseTrieView::from_proof(root, &proof).unwrap_err(),
            WitnessError::EmptyExtensionKey { path: Nibbles::default() }
        );

        // Over-long compact key (34 bytes) in a leaf: rejected before decode.
        let mut payload = Vec::new();
        [0x20u8; 34].as_slice().encode(&mut payload);
        [0x01u8].as_slice().encode(&mut payload);
        let mut rlp = Vec::new();
        Header { list: true, payload_length: payload.len() }.encode(&mut rlp);
        rlp.extend(payload);
        let root = keccak256(&rlp);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), rlp.into());
        assert!(matches!(
            SparseTrieView::from_proof(root, &proof),
            Err(WitnessError::MalformedNode { .. })
        ));

        // A leaf whose key would make the full path longer than 64 nibbles.
        let long_leaf = alloy_trie::nodes::LeafNode::new(Nibbles::from_nibbles(vec![1u8; 64]), vec![0x01]);
        let mut branch_payload = Vec::new();
        let leaf_rlp = alloy_rlp::encode(&long_leaf);
        let leaf_hash = keccak256(&leaf_rlp);
        // Branch with one child (nibble 0) referencing the leaf by hash, 16 empty
        // slots otherwise + empty value.
        leaf_hash.encode(&mut branch_payload);
        for _ in 1..17 {
            [].as_slice().encode(&mut branch_payload);
        }
        let mut branch_rlp = Vec::new();
        Header { list: true, payload_length: branch_payload.len() }.encode(&mut branch_rlp);
        branch_rlp.extend(branch_payload);
        let root = keccak256(&branch_rlp);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), branch_rlp.into());
        proof.insert(Nibbles::from_nibbles([0]), leaf_rlp.into());
        assert!(matches!(
            SparseTrieView::from_proof(root, &proof),
            Err(WitnessError::PathTooLong { .. })
        ));
    }

    /// Inline (< 32-byte) children — the shape storage tries take with small
    /// values — are decoded in place, so the update matches a full rebuild.
    #[test]
    fn inline_children_are_handled() {
        // Three leaves sharing a 63-nibble prefix and differing in the last
        // nibble: extension -> branch -> three 0-nibble-key leaves with 1-byte
        // values, each leaf RLP well under 32 bytes, so the branch embeds them
        // inline (and the branch itself is embedded in the extension).
        let keys: Vec<Nibbles> = (0u8..3)
            .map(|i| {
                let mut k = vec![0u8; 63];
                k.push(i);
                Nibbles::from_nibbles(k)
            })
            .collect();
        let values: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i + 1]).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([keys[0]]));
        for (k, v) in keys.iter().zip(&values) {
            hb.add_leaf(*k, v);
        }
        let prev_root = hb.root();
        let proof: BTreeMap<Nibbles, Bytes> = hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();
        assert!(
            proof.values().any(|node| node.len() < 32) || proof.len() < 3,
            "test premise: small nodes are embedded, not separately hashed"
        );

        // Expected: update leaf 0, keep the two inline siblings.
        let mut hb2 = HashBuilder::default();
        let new_v0 = vec![0x7f];
        hb2.add_leaf(keys[0], &new_v0);
        hb2.add_leaf(keys[1], &values[1]);
        hb2.add_leaf(keys[2], &values[2]);
        let expected = hb2.root();

        let view = SparseTrieView::from_proof(prev_root, &proof).unwrap();
        assert_eq!(view.leaves().len(), 3, "inline siblings are exposed, not dropped");
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(keys[0], Some(new_v0));
        assert_eq!(view.apply(&changes), Ok(expected));
        // Deleting one inline leaf collapses correctly too.
        let mut hb3 = HashBuilder::default();
        hb3.add_leaf(keys[1], &values[1]);
        hb3.add_leaf(keys[2], &values[2]);
        let mut del: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        del.insert(keys[0], None);
        assert_eq!(view.apply(&del), Ok(hb3.root()));
    }
}
