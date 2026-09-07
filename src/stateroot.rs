// SPDX-License-Identifier: MIT OR Apache-2.0
//! State-root commitment — keccak-256 hexary Merkle-Patricia trie.
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

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable, Header};
use alloy_trie::nodes::TrieNode;
use alloy_trie::{HashBuilder, Nibbles, EMPTY_ROOT_HASH};
use revm::database::AccountState;
use revm::primitives::KECCAK_EMPTY;

use crate::state::L2State;

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
pub fn compute_keccak_mpt_state_root(state: &L2State) -> B256 {
    trie_root(account_leaves(state))
}

/// The `(keccak256(address), rlp(account))` leaf set of the state trie — the
/// same leaves [`compute_keccak_mpt_state_root`] hashes, exposed so the
/// stateless-proving path (witness generation / verification) can build the
/// trie with a proof retainer over the same inputs. Unsorted (the trie builder
/// sorts by hashed key).
pub(crate) fn account_leaves(state: &L2State) -> Vec<(B256, Vec<u8>)> {
    state
        .db
        .cache
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

// The stateless state-root updater below is the SP1-guest building block
// (BLOCH-L2-PROVER-SCOPE.md P0.3), used by the host witness generator
// [`crate::proving::generate_batch_witness`].

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

/// STATELESS state-root UPDATE — the SP1-guest's step 3(e), general over
/// arbitrary trie shape AND over insert / update / delete.
///
/// Inputs: (a) `proof` — a multiproof (path → node RLP, from a `ProofRetainer`)
/// exposing every node the change set can restructure; (b) `changes` — full key
/// → `Some(new_rlp)` to set (update an existing key OR insert a new one) or
/// `None` to delete. Returns the post-state root. **Untouched account values are
/// never used**: they enter as opaque subtree hashes; the CURRENT value of an
/// exposed-but-unchanged leaf (e.g. the surviving sibling of a delete that
/// collapses a branch) is read from the proof itself.
///
/// Contract: the witness must EXPOSE every leaf that a change can restructure —
/// the sibling of a delete-collapse and the leaf an insert splits — by having
/// the `ProofRetainer` target those keys too. A change landing inside a subtree
/// that stayed opaque is a witness-incompleteness (it is not emitted, so the
/// root would diverge — the STF's witness generator must prevent it).
pub fn stateless_new_root(
    proof: &BTreeMap<Nibbles, Bytes>,
    changes: &BTreeMap<Nibbles, Option<Vec<u8>>>,
) -> B256 {
    // Walk the proof: collect exposed leaves (key, current value) + the opaque
    // frontier (subtree path, hash).
    let mut leaves: Vec<(Nibbles, Vec<u8>)> = Vec::new();
    let mut frontier: Vec<(Nibbles, B256)> = Vec::new();
    if proof.contains_key(&Nibbles::default()) {
        collect_sparse(Nibbles::default(), proof, &mut leaves, &mut frontier);
    }
    let exposed: BTreeSet<&Nibbles> = leaves.iter().map(|(k, _)| k).collect();

    let mut out: Vec<Emit> = Vec::new();
    // Exposed leaves: apply the change (delete = drop; update = new value;
    // unchanged = keep the proof's current value).
    for (k, cur) in &leaves {
        match changes.get(k) {
            Some(None) => {}                                             // delete
            Some(Some(v)) => out.push(Emit::Leaf(k.clone(), v.clone())), // update
            None => out.push(Emit::Leaf(k.clone(), cur.clone())),        // unchanged
        }
    }
    // Inserts: change keys that did not exist as exposed leaves.
    for (k, chg) in changes {
        if let Some(v) = chg {
            if !exposed.contains(k) {
                out.push(Emit::Leaf(k.clone(), v.clone()));
            }
        }
    }
    // Opaque untouched subtrees — but only those NO change reaches into (a
    // change inside an opaque subtree means the witness was incomplete).
    for (path, hash) in &frontier {
        if !changes.keys().any(|ck| ck.starts_with(path)) {
            out.push(Emit::Branch(path.clone(), *hash));
        }
    }

    if out.is_empty() {
        return EMPTY_ROOT_HASH;
    }
    // HashBuilder consumes keys in nibble-lexicographic order.
    out.sort_by(|a, b| a.path().to_vec().cmp(&b.path().to_vec()));
    let mut hb = HashBuilder::default();
    for e in &out {
        match e {
            Emit::Leaf(k, v) => hb.add_leaf(k.clone(), v),
            Emit::Branch(p, h) => hb.add_branch(p.clone(), *h, false),
        }
    }
    hb.root()
}

/// Walk the proof from `path`: recurse into every child whose node is present
/// in the proof (exposed), and record each other child as an opaque frontier
/// subtree. Exposed leaves are recorded with their CURRENT value.
fn collect_sparse(
    path: Nibbles,
    proof: &BTreeMap<Nibbles, Bytes>,
    leaves: &mut Vec<(Nibbles, Vec<u8>)>,
    frontier: &mut Vec<(Nibbles, B256)>,
) {
    let bytes = proof.get(&path).expect("proof node missing at an exposed path");
    match TrieNode::decode(&mut bytes.as_ref()).expect("valid trie node RLP") {
        TrieNode::EmptyRoot => {}
        TrieNode::Leaf(leaf) => leaves.push((path.join(&leaf.key), leaf.value)),
        TrieNode::Extension(ext) => {
            let cp = path.join(&ext.key);
            if proof.contains_key(&cp) {
                collect_sparse(cp, proof, leaves, frontier);
            } else if let Some(h) = ext.child.as_hash() {
                frontier.push((cp, h));
            }
        }
        TrieNode::Branch(branch) => {
            let mask = branch.state_mask.get();
            let mut rank = 0usize;
            for nibble in 0u8..16 {
                if (mask >> nibble) & 1 == 0 {
                    continue;
                }
                let child = &branch.stack[rank];
                rank += 1;
                let mut cp = path.clone();
                cp.push(nibble);
                if proof.contains_key(&cp) {
                    collect_sparse(cp, proof, leaves, frontier); // exposed
                } else if let Some(h) = child.as_hash() {
                    frontier.push((cp, h)); // opaque sibling (account trie ≥32B)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::sats_to_wei;
    use crate::state::{DepositMint, DepositProvenance, L2State};
    use alloy_primitives::{address, Address};

    fn deposit(state: &mut L2State, to: Address, sats: u64) {
        state
            .deposit_mint(&DepositMint {
                recipient: to,
                mint_wei: sats_to_wei(sats),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
            })
            .expect("deposit");
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
        deposit(&mut a, address!("00000000000000000000000000000000000000aa"), 5);
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
        deposit(&mut a, x, 3);
        deposit(&mut a, y, 7);
        let mut b = L2State::new();
        deposit(&mut b, y, 7);
        deposit(&mut b, x, 3);
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
        deposit(&mut a, who, 1);
        let mut b = L2State::new();
        deposit(&mut b, who, 2);
        assert_ne!(compute_keccak_mpt_state_root(&a), compute_keccak_mpt_state_root(&b));
    }

    #[test]
    fn eip161_empty_account_is_excluded_but_nonempty_is_included() {
        use revm::state::AccountInfo;
        let who = address!("00000000000000000000000000000000000000aa");

        // An account that EXISTS in the DB (account_state = None, not
        // NotExisting) but is empty per EIP-161 (nonce 0, balance 0, empty
        // code) must NOT appear in the state trie: the root stays the
        // canonical empty root even though the account is present in the cache.
        let mut empty = L2State::new();
        empty.db.insert_account_info(who, AccountInfo::default());
        assert!(
            empty.db.cache.accounts.contains_key(&who),
            "the empty account is present in the DB cache"
        );
        assert_eq!(
            compute_keccak_mpt_state_root(&empty),
            EMPTY_ROOT_HASH,
            "an EIP-161 empty account must be excluded from the state trie"
        );

        // Nonce alone (nonce 1, balance 0, empty code) makes the account
        // non-empty, so it IS in the trie and moves the root.
        let mut with_nonce = L2State::new();
        with_nonce
            .db
            .insert_account_info(who, AccountInfo { nonce: 1, ..Default::default() });
        assert_ne!(
            compute_keccak_mpt_state_root(&with_nonce),
            EMPTY_ROOT_HASH,
            "a nonce-1 account is not EIP-161-empty and belongs in the trie"
        );

        // Balance alone likewise makes it non-empty.
        let mut with_balance = L2State::new();
        with_balance.db.insert_account_info(
            who,
            AccountInfo { balance: U256::from(1u64), ..Default::default() },
        );
        assert_ne!(
            compute_keccak_mpt_state_root(&with_balance),
            EMPTY_ROOT_HASH,
            "a positive-balance account is not EIP-161-empty and belongs in the trie"
        );
    }

    #[test]
    fn eip161_empty_accounts_are_invisible_to_the_root() {
        use revm::state::AccountInfo;
        let funded = address!("00000000000000000000000000000000000000aa");
        let ghost = address!("00000000000000000000000000000000000000bb");

        let mut only_funded = L2State::new();
        deposit(&mut only_funded, funded, 9);

        let mut with_ghost = L2State::new();
        deposit(&mut with_ghost, funded, 9);
        // A touched-but-empty account alongside the funded one.
        with_ghost.db.insert_account_info(ghost, AccountInfo::default());

        assert_eq!(
            compute_keccak_mpt_state_root(&only_funded),
            compute_keccak_mpt_state_root(&with_ghost),
            "EIP-161 empty accounts do not perturb the state root"
        );
    }


    /// P0.3 de-risking spike (real-prover scope, `BLOCH-L2-PROVER-SCOPE.md`).
    ///
    /// The stateless (SP1-guest) proving path has two trie steps: **(a) verify
    /// the ExecutionWitness opens against `prev_state_root`** and **(b)
    /// recompute the new root from touched leaves + witness sibling nodes.**
    ///
    /// This proves **(a)** end-to-end on the REAL account trie using
    /// `alloy-trie` 0.9's `ProofRetainer` + `verify_proof`: a multiproof for a
    /// touched account both (i) verifies its real value against the state root
    /// and (ii) is tamper-evident. Step (b) — the sparse-trie root update — is
    /// the remaining P0.3 engineering; the primitive it needs
    /// (`HashBuilder::add_branch` for opaque untouched subtrees) is confirmed
    /// present in this same library, and the reference assembly is
    /// `reth-trie-sparse`.
    #[test]
    fn p0_3_stateless_witness_verifies_touched_account_against_prev_state_root() {
        use alloy_primitives::Bytes;
        use alloy_trie::proof::{verify_proof, ProofRetainer};

        // Pre-state with several accounts.
        let addrs = [
            address!("00000000000000000000000000000000000000a1"),
            address!("00000000000000000000000000000000000000b2"),
            address!("00000000000000000000000000000000000000c3"),
            address!("00000000000000000000000000000000000000d4"),
        ];
        let mut state = L2State::new();
        for (i, a) in addrs.iter().enumerate() {
            deposit(&mut state, *a, (i as u64 + 1) * 100);
        }
        let prev_root = compute_keccak_mpt_state_root(&state);

        // Rebuild the SAME trie with a proof retainer over ONE touched account,
        // exactly as a host-side witness generator would.
        let touched_key = keccak256(addrs[1]);
        let target = Nibbles::unpack(touched_key);
        let mut leaves = account_leaves(&state);
        leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));

        let mut hb =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([target.clone()]));
        let mut touched_value: Option<Vec<u8>> = None;
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
            if *k == touched_key {
                touched_value = Some(v.clone());
            }
        }
        let root = hb.root();
        assert_eq!(root, prev_root, "the retained build reproduces the state root");

        let proof_nodes = hb.take_proof_nodes();
        let proof: Vec<Bytes> =
            proof_nodes.matching_nodes_sorted(&target).into_iter().map(|(_, n)| n).collect();

        // (a.i) The witness OPENS: the touched account's real value verifies
        //       against prev_state_root — the guest's witness-verification step.
        verify_proof(prev_root, target.clone(), touched_value.clone(), proof.iter())
            .expect("touched account must open against prev_state_root");

        // (a.ii) Tamper-evident: a wrong value for the same key must NOT verify.
        let mut tampered = touched_value.expect("touched value present");
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(
            verify_proof(prev_root, target, Some(tampered), proof.iter()).is_err(),
            "a tampered account value must fail verification against prev_state_root"
        );
    }

    /// P0.3b de-risking spike — **stateless state-root UPDATE**.
    ///
    /// Recomputes the post-state root from ONLY (i) the touched account's NEW
    /// leaf value and (ii) the untouched accounts' subtree hashes carried in
    /// the witness — never touching the untouched account VALUES. This is the
    /// second guest trie step (3(e), "compute `new_state_root`") done
    /// statelessly, via `HashBuilder::add_branch` for the opaque untouched
    /// subtrees.
    ///
    /// Scope of this spike: a **flat** account trie (keys diverge at the first
    /// nibble → one leaf per account at a 1-nibble path), which isolates the
    /// mechanism. The general case (shared prefixes / extension nodes) walks
    /// the same primitive over a decoded sparse trie — the `reth-trie-sparse`
    /// assembly noted in the scope; this proves the core update is sound.
    #[test]
    fn p0_3b_stateless_root_update_from_touched_leaf_and_untouched_subtree_hashes() {
        use alloy_trie::proof::ProofRetainer;

        // Three accounts whose keccak-hashed keys diverge at the FIRST nibble
        // (1, 3, 4 respectively — verified), so the state trie is flat.
        let addrs = [
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000018"),
            address!("0000000000000000000000000000000000000005"),
        ];
        let mut state = L2State::new();
        for (i, a) in addrs.iter().enumerate() {
            deposit(&mut state, *a, (i as u64 + 1) * 100);
        }
        let prev_root = compute_keccak_mpt_state_root(&state);

        // Host witness: full multiproof of all leaves against prev_root.
        let mut leaves = account_leaves(&state);
        leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        let targets: Vec<Nibbles> = leaves.iter().map(|(k, _)| Nibbles::unpack(k)).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        assert_eq!(hb.root(), prev_root);
        let nodes = hb.take_proof_nodes().nodes_sorted(); // (path, bytes)

        // Flat-trie precondition + witness map: first nibble -> (leaf path, leaf
        // node hash). Every non-root proof node sits at a 1-nibble path.
        use std::collections::BTreeMap;
        let mut subtree: BTreeMap<u8, (Nibbles, B256)> = BTreeMap::new();
        for (path, bytes) in &nodes {
            if path.len() == 1 {
                subtree.insert(path.first().expect("len 1"), (path.clone(), keccak256(bytes)));
            }
        }
        assert_eq!(subtree.len(), addrs.len(), "flat trie: one 1-nibble leaf per account");

        // The touched account changes (a further deposit bumps its balance).
        let touched_key = keccak256(addrs[1]);
        let mut new_state = state.clone();
        deposit(&mut new_state, addrs[1], 50);
        let expected_new_root = compute_keccak_mpt_state_root(&new_state);
        let mut new_leaves = account_leaves(&new_state);
        new_leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        let new_touched_value =
            new_leaves.iter().find(|(k, _)| *k == touched_key).expect("touched leaf").1.clone();

        // STATELESS recompute: touched account via add_leaf(NEW value); every
        // untouched account via add_branch(its subtree hash) — its VALUE is
        // never used. Fed in sorted (first-nibble) order.
        let mut hb2 = HashBuilder::default();
        for (k, _v) in &leaves {
            let nk = Nibbles::unpack(k);
            if *k == touched_key {
                hb2.add_leaf(nk, &new_touched_value);
            } else {
                let first = nk.first().expect("nonempty key");
                let (path, hash) = subtree.get(&first).expect("untouched subtree in witness");
                hb2.add_branch(path.clone(), *hash, false);
            }
        }
        let stateless_new_root = hb2.root();

        assert_eq!(
            stateless_new_root, expected_new_root,
            "new root recomputed from the touched leaf + untouched SUBTREE HASHES only \
             (untouched account values never used)"
        );
        assert_ne!(stateless_new_root, prev_root, "the update actually moved the root");
    }

    /// P0.3b GENERAL case — stateless root update over an arbitrary (non-flat)
    /// trie with nested branches / extension nodes, via the multiproof walk in
    /// [`stateless_new_root`]. Proves the flat-case mechanism generalizes.
    #[test]
    fn p0_3b_general_stateless_root_update_over_nested_branches() {
        use alloy_trie::proof::ProofRetainer;

        // 40 accounts → keccak-keyed trie develops nested branches (first-nibble
        // collisions force depth-2+ structure), exercising the general walk.
        let mut state = L2State::new();
        let mut addrs = Vec::new();
        for i in 0u8..40 {
            let mut b = [0u8; 20];
            b[19] = i;
            let a = Address::from(b);
            deposit(&mut state, a, (i as u64 + 1) * 10);
            addrs.push(a);
        }
        let prev_root = compute_keccak_mpt_state_root(&state);

        // Touch 3 accounts (bump balances via further deposits).
        let touched_addrs = [addrs[3], addrs[17], addrs[29]];
        let mut new_state = state.clone();
        for a in &touched_addrs {
            deposit(&mut new_state, *a, 500);
        }
        let expected = compute_keccak_mpt_state_root(&new_state);

        // Witness: multiproof of ONLY the touched keys against prev_root.
        let touched_keys: Vec<Nibbles> =
            touched_addrs.iter().map(|a| Nibbles::unpack(keccak256(a))).collect();
        let mut leaves = account_leaves(&state);
        leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        let mut hb =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(touched_keys));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        assert_eq!(hb.root(), prev_root);
        let proof: BTreeMap<Nibbles, Bytes> =
            hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();

        // changes map: full key -> Some(NEW rlp value) (updates).
        let mut new_leaves = account_leaves(&new_state);
        new_leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        for a in &touched_addrs {
            let key = keccak256(a);
            let val = new_leaves.iter().find(|(k, _)| *k == key).expect("touched leaf").1.clone();
            changes.insert(Nibbles::unpack(key), Some(val));
        }

        let got = stateless_new_root(&proof, &changes);
        assert_eq!(
            got, expected,
            "general sparse stateless root update must match the full rebuild"
        );
        assert_ne!(got, prev_root, "the update moved the root");
    }

    /// P0.3b INSERT — a new account splits the trie (here: a single-leaf root
    /// becomes a 2-leaf branch). The witness exposes the leaf the insert splits
    /// (a non-inclusion proof of the new key), and `stateless_new_root` rebuilds
    /// the new shape from it.
    #[test]
    fn p0_3b_stateless_insert_new_account() {
        use alloy_trie::proof::ProofRetainer;

        let existing = address!("0000000000000000000000000000000000000001"); // nibble 1
        let new_addr = address!("0000000000000000000000000000000000000018"); // nibble 3
        let mut state = L2State::new();
        deposit(&mut state, existing, 100);
        let prev_root = compute_keccak_mpt_state_root(&state);

        let mut new_state = state.clone();
        deposit(&mut new_state, new_addr, 250); // INSERT
        let expected = compute_keccak_mpt_state_root(&new_state);

        // Witness: non-inclusion proof of the new key (exposes the root leaf it
        // would split).
        let new_key = keccak256(new_addr);
        let mut hb = HashBuilder::default()
            .with_proof_retainer(ProofRetainer::from_iter([Nibbles::unpack(new_key)]));
        let mut leaves = account_leaves(&state);
        leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        assert_eq!(hb.root(), prev_root);
        let proof: BTreeMap<Nibbles, Bytes> =
            hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();

        let mut new_leaves = account_leaves(&new_state);
        new_leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        let val = new_leaves.iter().find(|(k, _)| *k == new_key).unwrap().1.clone();
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(Nibbles::unpack(new_key), Some(val));

        assert_eq!(stateless_new_root(&proof, &changes), expected, "insert must match full rebuild");
    }

    /// P0.3b DELETE — removing an account collapses a branch (here: a 2-leaf
    /// branch collapses to a single leaf). The witness exposes BOTH the deleted
    /// key and its surviving sibling; `stateless_new_root` reads the sibling's
    /// current value from the proof and re-collapses correctly.
    #[test]
    fn p0_3b_stateless_delete_account_collapses_branch() {
        use alloy_trie::proof::ProofRetainer;
        use revm::state::AccountInfo;

        let del = address!("0000000000000000000000000000000000000001"); // nibble 1
        let keep = address!("0000000000000000000000000000000000000018"); // nibble 3
        let mut state = L2State::new();
        deposit(&mut state, del, 100);
        deposit(&mut state, keep, 200);
        let prev_root = compute_keccak_mpt_state_root(&state);

        // DELETE: zero the account (EIP-161 empty ⇒ excluded from the trie).
        let mut new_state = state.clone();
        new_state.db.insert_account_info(del, AccountInfo::default());
        let expected = compute_keccak_mpt_state_root(&new_state);
        assert_ne!(expected, prev_root);

        // Witness exposes both the deleted key and its surviving sibling.
        let del_key = keccak256(del);
        let keep_key = keccak256(keep);
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([
            Nibbles::unpack(del_key),
            Nibbles::unpack(keep_key),
        ]));
        let mut leaves = account_leaves(&state);
        leaves.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        assert_eq!(hb.root(), prev_root);
        let proof: BTreeMap<Nibbles, Bytes> =
            hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();

        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(Nibbles::unpack(del_key), None); // delete

        assert_eq!(
            stateless_new_root(&proof, &changes),
            expected,
            "delete-with-collapse must match full rebuild"
        );
    }
}
