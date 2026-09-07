// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owned, in-memory keccak-256 hexary Merkle-Patricia trie with **incremental**
//! root computation, for the committed L2 state (audit finding C27).
//!
//! `alloy-trie`'s `HashBuilder` is a *batch* builder: it re-hashes every leaf
//! on every call, so a state root over `n` accounts costs O(n) per block
//! whatever the block touched. This trie keeps the node structure in memory,
//! caches every node's RLP reference ([`RlpNode`]) and invalidates only the
//! nodes on the paths of the keys a block changed, so an update costs
//! O(changed keys × depth) and an untouched subtree is never re-hashed.
//!
//! Encoding is delegated to `alloy-trie`'s own node encoders
//! ([`LeafNodeRef`], [`ExtensionNodeRef`], [`BranchNodeRef`]), so the root is
//! byte-identical to `HashBuilder`'s (asserted by the tests against the
//! from-scratch [`crate::stateroot::compute_keccak_mpt_state_root`]) and the
//! proofs it emits ([`Mpt::proof`]) are node-for-node identical to
//! `ProofRetainer`'s, keyed by each node's position path.
//!
//! Keys are fixed-length (64 nibbles — `keccak256` of an address or slot), as
//! in every Ethereum state and storage trie; branch nodes therefore never
//! carry a value.

use alloc::collections::btree_map::Entry;
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::{Encodable, EMPTY_STRING_CODE};
use alloy_trie::nodes::{BranchNodeRef, ExtensionNodeRef, LeafNodeRef, RlpNode};
use alloy_trie::{Nibbles, TrieMask, EMPTY_ROOT_HASH};

/// Every key is exactly this many nibbles (a 32-byte hash).
pub const KEY_NIBBLES: usize = 64;

/// A trie node. `cache` is the node's RLP reference (`rlp(node)` if shorter
/// than 32 bytes, else `rlp(keccak(rlp(node)))`), valid while the subtree is
/// unchanged; `None` marks a node on a modified path.
#[derive(Debug, Clone)]
enum Node {
    Leaf {
        key: Nibbles,
        value: Vec<u8>,
        cache: Option<RlpNode>,
    },
    Extension {
        key: Nibbles,
        child: Box<Node>,
        cache: Option<RlpNode>,
    },
    Branch {
        children: Box<[Option<Box<Node>>; 16]>,
        cache: Option<RlpNode>,
    },
}

/// What an insertion did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// The key was absent and is now present.
    Inserted,
    /// The key was present with a different value.
    Replaced,
    /// The key was present with the same value; nothing changed.
    Unchanged,
}

/// An incremental Merkle-Patricia trie over fixed-length (64-nibble) keys.
#[derive(Debug, Clone, Default)]
pub struct Mpt {
    root: Option<Node>,
    len: usize,
}

fn leaf(key: Nibbles, value: Vec<u8>) -> Node {
    Node::Leaf {
        key,
        value,
        cache: None,
    }
}

fn empty_children() -> Box<[Option<Box<Node>>; 16]> {
    Box::default()
}

/// Wrap `node` in an extension with `key`, unless `key` is empty.
fn wrap_extension(key: Nibbles, node: Node) -> Node {
    if key.is_empty() {
        node
    } else {
        Node::Extension {
            key,
            child: Box::new(node),
            cache: None,
        }
    }
}

impl Node {
    fn cache(&self) -> Option<&RlpNode> {
        match self {
            Node::Leaf { cache, .. } | Node::Extension { cache, .. } | Node::Branch { cache, .. } => cache.as_ref(),
        }
    }

    /// The node's RLP reference, computing and caching it (and its children's)
    /// where missing.
    fn rlp(&mut self, buf: &mut Vec<u8>) -> RlpNode {
        if let Some(c) = self.cache() {
            return c.clone();
        }
        match self {
            Node::Leaf { key, value, cache } => {
                buf.clear();
                let r = LeafNodeRef::new(key, value).rlp(buf);
                *cache = Some(r.clone());
                r
            }
            Node::Extension { key, child, cache } => {
                let c = child.rlp(buf);
                buf.clear();
                let r = ExtensionNodeRef::new(key, &c).rlp(buf);
                *cache = Some(r.clone());
                r
            }
            Node::Branch { children, cache } => {
                let mut stack: Vec<RlpNode> = Vec::with_capacity(16);
                let mut mask = TrieMask::default();
                for (i, child) in children.iter_mut().enumerate() {
                    if let Some(child) = child {
                        stack.push(child.rlp(buf));
                        mask |= TrieMask::from_nibble(i as u8);
                    }
                }
                buf.clear();
                let r = BranchNodeRef::new(&stack, mask).rlp(buf);
                *cache = Some(r.clone());
                r
            }
        }
    }

    /// The node's full RLP encoding (what a proof carries). `None` if any
    /// child's cache is cold — callers warm the trie with [`Mpt::root`] first.
    fn encoding(&self) -> Option<Bytes> {
        let mut out = Vec::new();
        match self {
            Node::Leaf { key, value, .. } => LeafNodeRef::new(key, value).encode(&mut out),
            Node::Extension { key, child, .. } => ExtensionNodeRef::new(key, child.cache()?).encode(&mut out),
            Node::Branch { children, .. } => {
                let mut stack: Vec<RlpNode> = Vec::with_capacity(16);
                let mut mask = TrieMask::default();
                for (i, child) in children.iter().enumerate() {
                    if let Some(child) = child {
                        stack.push(child.cache()?.clone());
                        mask |= TrieMask::from_nibble(i as u8);
                    }
                }
                BranchNodeRef::new(&stack, mask).encode(&mut out);
            }
        }
        Some(out.into())
    }

    fn root_hash_of(rlp: &RlpNode) -> B256 {
        rlp.as_hash().unwrap_or_else(|| keccak256(rlp))
    }
}

fn insert_at(node: Option<Node>, key: &Nibbles, depth: usize, value: Vec<u8>) -> (Node, Insert) {
    let rest = key.slice(depth..);
    match node {
        None => (leaf(rest, value), Insert::Inserted),
        Some(Node::Leaf {
            key: lkey,
            value: lval,
            cache,
        }) => {
            if lkey == rest {
                if lval == value {
                    return (
                        Node::Leaf {
                            key: lkey,
                            value: lval,
                            cache,
                        },
                        Insert::Unchanged,
                    );
                }
                return (leaf(lkey, value), Insert::Replaced);
            }
            // Same-length keys that differ: split at the first differing nibble.
            let cp = rest.common_prefix_length(&lkey);
            let mut children = empty_children();
            children[lkey.get_unchecked(cp) as usize] = Some(Box::new(leaf(lkey.slice(cp + 1..), lval)));
            children[rest.get_unchecked(cp) as usize] = Some(Box::new(leaf(rest.slice(cp + 1..), value)));
            (
                wrap_extension(rest.slice(..cp), Node::Branch { children, cache: None }),
                Insert::Inserted,
            )
        }
        Some(Node::Extension {
            key: ekey,
            child,
            cache,
        }) => {
            let cp = rest.common_prefix_length(&ekey);
            if cp == ekey.len() {
                let (new_child, outcome) = insert_at(Some(*child), key, depth + cp, value);
                let cache = if outcome == Insert::Unchanged { cache } else { None };
                return (
                    Node::Extension {
                        key: ekey,
                        child: Box::new(new_child),
                        cache,
                    },
                    outcome,
                );
            }
            // The new key leaves the extension after `cp` nibbles: a branch
            // there, with the remainder of the extension (or its child) on one
            // side and the new leaf on the other.
            let mut children = empty_children();
            let existing = if cp + 1 < ekey.len() {
                Node::Extension {
                    key: ekey.slice(cp + 1..),
                    child,
                    cache: None,
                }
            } else {
                *child
            };
            children[ekey.get_unchecked(cp) as usize] = Some(Box::new(existing));
            children[rest.get_unchecked(cp) as usize] = Some(Box::new(leaf(rest.slice(cp + 1..), value)));
            (
                wrap_extension(ekey.slice(..cp), Node::Branch { children, cache: None }),
                Insert::Inserted,
            )
        }
        Some(Node::Branch { mut children, cache }) => {
            let idx = rest.get_unchecked(0) as usize;
            let (new_child, outcome) = insert_at(children[idx].take().map(|b| *b), key, depth + 1, value);
            children[idx] = Some(Box::new(new_child));
            let cache = if outcome == Insert::Unchanged { cache } else { None };
            (Node::Branch { children, cache }, outcome)
        }
    }
}

fn remove_at(node: Node, key: &Nibbles, depth: usize) -> (Option<Node>, bool) {
    let rest = key.slice(depth..);
    match node {
        Node::Leaf {
            key: lkey,
            value,
            cache,
        } => {
            if lkey == rest {
                (None, true)
            } else {
                (
                    Some(Node::Leaf {
                        key: lkey,
                        value,
                        cache,
                    }),
                    false,
                )
            }
        }
        Node::Extension {
            key: ekey,
            child,
            cache,
        } => {
            if !rest.starts_with(&ekey) {
                return (
                    Some(Node::Extension {
                        key: ekey,
                        child,
                        cache,
                    }),
                    false,
                );
            }
            let (new_child, removed) = remove_at(*child, key, depth + ekey.len());
            match (new_child, removed) {
                (Some(c), false) => (
                    Some(Node::Extension {
                        key: ekey,
                        child: Box::new(c),
                        cache,
                    }),
                    false,
                ),
                (None, _) => (None, true),
                // The child collapsed: merge keys so no extension ever points
                // at a leaf or another extension.
                (Some(Node::Leaf { key: k, value, .. }), true) => (Some(leaf(ekey.join(&k), value)), true),
                (Some(Node::Extension { key: k, child: c, .. }), true) => (
                    Some(Node::Extension {
                        key: ekey.join(&k),
                        child: c,
                        cache: None,
                    }),
                    true,
                ),
                (Some(b @ Node::Branch { .. }), true) => (
                    Some(Node::Extension {
                        key: ekey,
                        child: Box::new(b),
                        cache: None,
                    }),
                    true,
                ),
            }
        }
        Node::Branch { mut children, cache } => {
            let idx = rest.get_unchecked(0) as usize;
            let Some(child) = children[idx].take() else {
                return (Some(Node::Branch { children, cache }), false);
            };
            let (new_child, removed) = remove_at(*child, key, depth + 1);
            if let Some(c) = new_child {
                children[idx] = Some(Box::new(c));
            }
            if !removed {
                return (Some(Node::Branch { children, cache }), false);
            }
            let remaining = children.iter().filter(|c| c.is_some()).count();
            if remaining >= 2 {
                return (Some(Node::Branch { children, cache: None }), true);
            }
            if remaining == 0 {
                return (None, true);
            }
            // A branch with one child collapses into its child, prefixed by
            // the child's nibble.
            let (nibble, only) = children
                .iter_mut()
                .enumerate()
                .find_map(|(i, c)| c.take().map(|c| (i as u8, c)))
                .expect("one child remains");
            let prefix = Nibbles::from_nibbles([nibble]);
            let collapsed = match *only {
                Node::Leaf { key: k, value, .. } => leaf(prefix.join(&k), value),
                Node::Extension { key: k, child, .. } => Node::Extension {
                    key: prefix.join(&k),
                    child,
                    cache: None,
                },
                b @ Node::Branch { .. } => Node::Extension {
                    key: prefix,
                    child: Box::new(b),
                    cache: None,
                },
            };
            (Some(collapsed), true)
        }
    }
}

impl Mpt {
    /// An empty trie.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the trie holds no key.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert or replace `key → value`. Only the nodes on the key's path lose
    /// their cached hash; an identical value changes nothing.
    ///
    /// # Panics
    /// If `key` is not [`KEY_NIBBLES`] long.
    pub fn insert(&mut self, key: Nibbles, value: Vec<u8>) -> Insert {
        assert_eq!(key.len(), KEY_NIBBLES, "trie keys are 64 nibbles");
        let (root, outcome) = insert_at(self.root.take(), &key, 0, value);
        self.root = Some(root);
        if outcome == Insert::Inserted {
            self.len += 1;
        }
        outcome
    }

    /// Remove `key`; returns whether it was present.
    pub fn remove(&mut self, key: &Nibbles) -> bool {
        assert_eq!(key.len(), KEY_NIBBLES, "trie keys are 64 nibbles");
        let Some(root) = self.root.take() else {
            return false;
        };
        let (root, removed) = remove_at(root, key, 0);
        self.root = root;
        if removed {
            self.len -= 1;
        }
        removed
    }

    /// The value stored under `key`.
    pub fn get(&self, key: &Nibbles) -> Option<&[u8]> {
        let mut node = self.root.as_ref()?;
        let mut depth = 0;
        loop {
            match node {
                Node::Leaf { key: k, value, .. } => return (key.slice(depth..) == *k).then_some(value.as_slice()),
                Node::Extension { key: k, child, .. } => {
                    if !key.slice(depth..).starts_with(k) {
                        return None;
                    }
                    depth += k.len();
                    node = child;
                }
                Node::Branch { children, .. } => {
                    node = children[key.get_unchecked(depth) as usize].as_deref()?;
                    depth += 1;
                }
            }
        }
    }

    /// The root hash, re-hashing only the nodes changed since the last call
    /// (and every node the first time). Also warms the caches [`Self::proof`]
    /// and [`Self::root_cached`] rely on.
    pub fn root(&mut self) -> B256 {
        match &mut self.root {
            None => EMPTY_ROOT_HASH,
            Some(node) => {
                let mut buf = Vec::with_capacity(600);
                Node::root_hash_of(&node.rlp(&mut buf))
            }
        }
    }

    /// The root hash without hashing: `Some` only if the trie is warm (no
    /// change since the last [`Self::root`]).
    pub fn root_cached(&self) -> Option<B256> {
        match &self.root {
            None => Some(EMPTY_ROOT_HASH),
            Some(node) => node.cache().map(Node::root_hash_of),
        }
    }

    /// Every `(key, value)` in key order.
    pub fn leaves(&self) -> Vec<(Nibbles, &[u8])> {
        fn walk<'a>(node: &'a Node, pos: Nibbles, out: &mut Vec<(Nibbles, &'a [u8])>) {
            match node {
                Node::Leaf { key, value, .. } => out.push((pos.join(key), value)),
                Node::Extension { key, child, .. } => walk(child, pos.join(key), out),
                Node::Branch { children, .. } => {
                    for (i, child) in children.iter().enumerate() {
                        if let Some(child) = child {
                            let mut p = pos;
                            p.push(i as u8);
                            walk(child, p, out);
                        }
                    }
                }
            }
        }
        let mut out = Vec::with_capacity(self.len);
        if let Some(root) = &self.root {
            walk(root, Nibbles::default(), &mut out);
        }
        out
    }

    /// The greatest key strictly below `key` (in nibble order), if any.
    pub fn predecessor(&self, key: &Nibbles) -> Option<Nibbles> {
        self.root
            .as_ref()
            .and_then(|r| neighbour(r, Nibbles::default(), key, false))
    }

    /// The smallest key strictly above `key`, if any.
    pub fn successor(&self, key: &Nibbles) -> Option<Nibbles> {
        self.root
            .as_ref()
            .and_then(|r| neighbour(r, Nibbles::default(), key, true))
    }

    /// The multiproof for `targets` in `ProofRetainer` form: every node whose
    /// position path is a prefix of a target (the root always), keyed by that
    /// path, with its full RLP encoding; `{∅: 0x80}` for the empty trie. `None`
    /// if the trie is cold (call [`Self::root`] first).
    pub fn proof(&self, targets: impl IntoIterator<Item = Nibbles>) -> Option<BTreeMap<Nibbles, Bytes>> {
        let mut out = BTreeMap::new();
        let Some(root) = &self.root else {
            out.insert(Nibbles::default(), Bytes::from_static(&[EMPTY_STRING_CODE]));
            return Some(out);
        };
        out.insert(Nibbles::default(), root.encoding()?);
        for target in targets {
            let mut node = root;
            let mut pos = Nibbles::default();
            loop {
                match node {
                    Node::Leaf { .. } => break,
                    Node::Extension { key, child, .. } => {
                        if !target.slice(pos.len()..).starts_with(key) {
                            break;
                        }
                        pos = pos.join(key);
                        node = child;
                    }
                    Node::Branch { children, .. } => {
                        if pos.len() >= target.len() {
                            break;
                        }
                        let idx = target.get_unchecked(pos.len());
                        let Some(child) = children[idx as usize].as_deref() else {
                            break;
                        };
                        pos.push(idx);
                        node = child;
                    }
                }
                if let Entry::Vacant(slot) = out.entry(pos) {
                    slot.insert(node.encoding()?);
                }
            }
        }
        Some(out)
    }
}

/// Smallest (`min`) or greatest key in the subtree at `pos`.
fn extreme_leaf(node: &Node, pos: Nibbles, min: bool) -> Nibbles {
    match node {
        Node::Leaf { key, .. } => pos.join(key),
        Node::Extension { key, child, .. } => extreme_leaf(child, pos.join(key), min),
        Node::Branch { children, .. } => {
            let found = if min {
                children.iter().enumerate().find(|(_, c)| c.is_some())
            } else {
                children.iter().enumerate().rev().find(|(_, c)| c.is_some())
            };
            let (i, child) = found.expect("a branch has children");
            let mut p = pos;
            p.push(i as u8);
            extreme_leaf(child.as_deref().expect("present"), p, min)
        }
    }
}

/// Nearest key strictly after (`above`) or before `key` within the subtree
/// rooted at `node` (whose position is `pos`, a prefix of `key`).
fn neighbour(node: &Node, pos: Nibbles, key: &Nibbles, above: bool) -> Option<Nibbles> {
    match node {
        Node::Leaf { key: k, .. } => {
            let full = pos.join(k);
            let ok = if above { full > *key } else { full < *key };
            ok.then_some(full)
        }
        Node::Extension { key: k, child, .. } => {
            let sub = pos.join(k);
            let key_prefix = key.slice(..sub.len().min(key.len()));
            if key_prefix == sub {
                neighbour(child, sub, key, above)
            } else if (sub > key_prefix) == above {
                // The whole subtree lies on the wanted side of `key`.
                Some(extreme_leaf(child, sub, above))
            } else {
                None
            }
        }
        Node::Branch { children, .. } => {
            let idx = key.get_unchecked(pos.len()) as usize;
            if let Some(child) = children[idx].as_deref() {
                let mut p = pos;
                p.push(idx as u8);
                if let Some(found) = neighbour(child, p, key, above) {
                    return Some(found);
                }
            }
            let candidates: Vec<usize> = if above {
                (idx + 1..16).collect()
            } else {
                (0..idx).rev().collect()
            };
            for i in candidates {
                if let Some(child) = children[i].as_deref() {
                    let mut p = pos;
                    p.push(i as u8);
                    return Some(extreme_leaf(child, p, above));
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::HashBuilder;

    /// Deterministic pseudo-random 32-byte keys and small values.
    fn keys(seed: u8, n: usize) -> Vec<(Nibbles, Vec<u8>)> {
        let mut out = Vec::with_capacity(n);
        let mut h = B256::repeat_byte(seed);
        for i in 0..n {
            h = keccak256(h);
            let value = if i % 3 == 0 { alloc::vec![i as u8] } else { h.to_vec() };
            out.push((Nibbles::unpack(h), value));
        }
        out
    }

    fn reference_root(leaves: &[(Nibbles, Vec<u8>)]) -> B256 {
        let mut sorted: Vec<&(Nibbles, Vec<u8>)> = leaves.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hb = HashBuilder::default();
        for (k, v) in sorted {
            hb.add_leaf(*k, v);
        }
        hb.root()
    }

    fn reference_proof(leaves: &[(Nibbles, Vec<u8>)], targets: &[Nibbles]) -> BTreeMap<Nibbles, Bytes> {
        let mut sorted: Vec<&(Nibbles, Vec<u8>)> = leaves.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets.iter().copied()));
        for (k, v) in sorted {
            hb.add_leaf(*k, v);
        }
        hb.root();
        hb.take_proof_nodes().into_nodes_sorted().into_iter().collect()
    }

    #[test]
    fn empty_and_single_leaf() {
        let mut t = Mpt::new();
        assert_eq!(t.root(), EMPTY_ROOT_HASH);
        assert_eq!(t.root_cached(), Some(EMPTY_ROOT_HASH));
        let (k, v) = keys(1, 1).remove(0);
        assert_eq!(t.insert(k, v.clone()), Insert::Inserted);
        assert_eq!(t.root_cached(), None, "cold after a change");
        assert_eq!(t.root(), reference_root(&[(k, v.clone())]));
        assert_eq!(t.get(&k), Some(v.as_slice()));
        assert_eq!(t.insert(k, v.clone()), Insert::Unchanged);
        assert!(t.root_cached().is_some(), "an identical write keeps the cache warm");
        assert_eq!(t.insert(k, alloc::vec![9]), Insert::Replaced);
        assert_eq!(t.root(), reference_root(&[(k, alloc::vec![9])]));
        assert!(t.remove(&k));
        assert!(!t.remove(&k));
        assert_eq!(t.root(), EMPTY_ROOT_HASH);
        assert!(t.is_empty());
    }

    #[test]
    fn matches_hash_builder_for_random_sets_in_any_insertion_order() {
        for (seed, n) in [(2u8, 2usize), (3, 3), (4, 17), (5, 100), (6, 1_000), (7, 3_000)] {
            let leaves = keys(seed, n);
            let mut t = Mpt::new();
            // Reverse insertion order: nothing about the result may depend on it.
            for (k, v) in leaves.iter().rev() {
                assert_eq!(t.insert(*k, v.clone()), Insert::Inserted);
            }
            assert_eq!(t.len(), n);
            assert_eq!(t.root(), reference_root(&leaves), "seed {seed} n {n}");
            let listed = t.leaves();
            assert!(listed.windows(2).all(|w| w[0].0 < w[1].0), "leaves are in key order");
            assert_eq!(listed.len(), n);
        }
    }

    #[test]
    fn incremental_updates_match_from_scratch_at_every_step() {
        let mut live: Vec<(Nibbles, Vec<u8>)> = keys(11, 400);
        let mut t = Mpt::new();
        for (k, v) in &live {
            t.insert(*k, v.clone());
        }
        assert_eq!(t.root(), reference_root(&live));
        let extra = keys(12, 200);
        let mut rng = B256::repeat_byte(0x5a);
        for step in 0..600 {
            rng = keccak256(rng);
            let r = rng[0] as usize;
            match r % 4 {
                0 if !live.is_empty() => {
                    // remove a random live key
                    let i = (rng[1] as usize * 256 + rng[2] as usize) % live.len();
                    let (k, _) = live.swap_remove(i);
                    assert!(t.remove(&k), "step {step}: remove present key");
                    assert!(!t.remove(&k));
                }
                1 if !live.is_empty() => {
                    // replace a random live value
                    let i = (rng[1] as usize * 256 + rng[2] as usize) % live.len();
                    let new_v = alloc::vec![rng[3], rng[4]];
                    let outcome = t.insert(live[i].0, new_v.clone());
                    assert_eq!(
                        outcome,
                        if live[i].1 == new_v {
                            Insert::Unchanged
                        } else {
                            Insert::Replaced
                        }
                    );
                    live[i].1 = new_v;
                }
                _ => {
                    // insert a fresh key (or re-insert a removed one)
                    let (k, v) = &extra[(rng[1] as usize * 256 + rng[2] as usize) % extra.len()];
                    let outcome = t.insert(*k, v.clone());
                    if let Some(e) = live.iter().find(|(lk, _)| lk == k) {
                        assert_eq!(outcome, if e.1 == *v { Insert::Unchanged } else { Insert::Replaced });
                        live.iter_mut().find(|(lk, _)| lk == k).unwrap().1 = v.clone();
                    } else {
                        assert_eq!(outcome, Insert::Inserted);
                        live.push((*k, v.clone()));
                    }
                }
            }
            assert_eq!(t.len(), live.len(), "step {step}");
            if step % 7 == 0 {
                assert_eq!(t.root(), reference_root(&live), "step {step}");
                for (k, v) in &live {
                    assert_eq!(t.get(k), Some(v.as_slice()));
                }
            }
        }
        assert_eq!(t.root(), reference_root(&live));
        // Draining everything returns to the empty root.
        for (k, _) in live.clone() {
            assert!(t.remove(&k));
        }
        assert_eq!(t.root(), EMPTY_ROOT_HASH);
        assert!(t.leaves().is_empty());
    }

    #[test]
    fn inline_children_and_deep_shared_prefixes_match_hash_builder() {
        // Keys sharing 62 nibbles with 1-byte values: leaves and the branch
        // holding them are inline (< 32 bytes), extension keys are long.
        let base = keccak256(b"inline");
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let mut k = Nibbles::unpack(base);
            k.truncate(62);
            k.push(i);
            k.push(15 - i);
            leaves.push((k, alloc::vec![i + 1]));
        }
        // plus one far-away key so the root is a real branch
        leaves.push((Nibbles::unpack(keccak256(b"far")), alloc::vec![0xaa; 40]));
        let mut t = Mpt::new();
        for (k, v) in &leaves {
            t.insert(*k, v.clone());
        }
        assert_eq!(t.root(), reference_root(&leaves));
        let targets: Vec<Nibbles> = leaves.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            t.proof(targets.iter().copied()).unwrap(),
            reference_proof(&leaves, &targets)
        );
        // Removing three of the four clustered keys collapses branch → leaf
        // under the extension, merging keys.
        for (k, _) in &leaves[..3] {
            assert!(t.remove(k));
        }
        assert_eq!(t.root(), reference_root(&leaves[3..]));
    }

    #[test]
    fn proofs_match_proof_retainer_for_present_and_absent_targets() {
        for (seed, n) in [(21u8, 1usize), (22, 5), (23, 60), (24, 700)] {
            let leaves = keys(seed, n);
            let mut t = Mpt::new();
            for (k, v) in &leaves {
                t.insert(*k, v.clone());
            }
            if n > 1 {
                // A cold trie (children never hashed) cannot encode its root.
                assert!(t.proof(core::iter::empty()).is_none(), "cold trie has no proof");
            }
            t.root();
            let absent = keys(seed + 100, 5);
            let mut targets: Vec<Nibbles> = leaves.iter().step_by(3).map(|(k, _)| *k).collect();
            targets.extend(absent.iter().map(|(k, _)| *k));
            let mine = t.proof(targets.iter().copied()).unwrap();
            let theirs = reference_proof(&leaves, &targets);
            assert_eq!(mine.len(), theirs.len(), "seed {seed}: node count");
            assert_eq!(mine, theirs, "seed {seed}: proof nodes");
            // Root-only proof (no targets) is the retained root node.
            let root_only = t.proof(core::iter::empty()).unwrap();
            assert_eq!(root_only.len(), 1);
            assert_eq!(root_only, reference_proof(&leaves, &[]));
        }
        // The empty trie's proof is the empty-root marker, as ProofRetainer emits it.
        let empty = Mpt::new();
        let p = empty.proof(core::iter::empty()).unwrap();
        assert_eq!(p, reference_proof(&[], &[]));
        assert_eq!(keccak256(&p[&Nibbles::default()]), EMPTY_ROOT_HASH);
    }

    #[test]
    fn neighbours_match_sorted_order() {
        let leaves = keys(31, 300);
        let mut t = Mpt::new();
        for (k, v) in &leaves {
            t.insert(*k, v.clone());
        }
        let mut sorted: Vec<Nibbles> = leaves.iter().map(|(k, _)| *k).collect();
        sorted.sort();
        // Present keys.
        for (i, k) in sorted.iter().enumerate() {
            assert_eq!(t.predecessor(k), if i > 0 { Some(sorted[i - 1]) } else { None });
            assert_eq!(t.successor(k), sorted.get(i + 1).copied());
        }
        // Absent keys.
        for (k, _) in keys(32, 100) {
            let pos = sorted.partition_point(|s| *s < k);
            assert_eq!(t.predecessor(&k), if pos > 0 { Some(sorted[pos - 1]) } else { None });
            assert_eq!(t.successor(&k), sorted.get(pos).copied());
        }
        assert_eq!(Mpt::new().predecessor(&sorted[0]), None);
        assert_eq!(Mpt::new().successor(&sorted[0]), None);
    }

    #[test]
    #[should_panic(expected = "64 nibbles")]
    fn short_keys_are_rejected() {
        Mpt::new().insert(Nibbles::from_nibbles([1, 2, 3]), alloc::vec![1]);
    }
}
