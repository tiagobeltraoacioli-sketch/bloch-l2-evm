// SPDX-License-Identifier: MIT OR Apache-2.0
//! Host-side batch witness generator (RSP pattern) — the SP1 prover's host
//! step (BLOCH-L2-PROVER-SCOPE.md W1/P1).
//!
//! **SCAFFOLD, UNAUDITED.** Ties together the pieces the P0 spikes proved:
//! execute the batch with the REAL [`execute_block`] (stateless-read property),
//! build a multiproof of the changed accounts against the prior state root
//! ([`ProofRetainer`]), and **self-verify** that the guest-side stateless
//! root-update ([`stateless_new_root`]) reproduces the post-state root. The
//! self-check makes generation *correct-or-error*: a witness that cannot
//! reconstruct the new root is rejected, never returned silently wrong.

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_trie::proof::{verify_proof, ProofRetainer};
use alloy_trie::{HashBuilder, Nibbles};
use revm::primitives::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};

use crate::chainspec::ChainSpec;
use crate::executor::{execute_block, BlockInput, ExecutionOutcome};
use crate::state::L2State;
use crate::stateroot::{account_leaves, compute_keccak_mpt_state_root, stateless_new_root};

/// Everything a guest needs to re-derive a batch's post-state root without the
/// full state: the prior/post roots, the multiproof of the changed accounts,
/// and the change set (`Some(new_rlp)` = set, `None` = delete).
#[derive(Debug, Clone)]
pub struct BatchWitness {
    /// keccak-MPT state root before the batch.
    pub prev_state_root: B256,
    /// keccak-MPT state root after the batch (the value the proof proves).
    pub new_state_root: B256,
    /// Multiproof (trie-node path → RLP) of the changed accounts + neighbours,
    /// against `prev_state_root`.
    pub proof: BTreeMap<Nibbles, Bytes>,
    /// full key → `Some(new rlp account)` / `None` (delete).
    pub changes: BTreeMap<Nibbles, Option<Vec<u8>>>,
    /// The touched PRE-state accounts keyed by ADDRESS. The trie stores only
    /// `keccak(address)`, so the guest needs the address preimages to hydrate a
    /// stateless state and re-execute; each is bound to `prev_state_root` by
    /// [`hydrate_and_verify`].
    pub pre_accounts: Vec<WitnessAccount>,
}

/// A touched pre-state account, in a serde-stable shape for the witness (the
/// fields a revm `AccountInfo` + its storage need to round-trip to the guest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessAccount {
    /// Account address (trie-key preimage).
    pub address: Address,
    /// Native balance (wei).
    pub balance: U256,
    /// Nonce.
    pub nonce: u64,
    /// Contract code (empty for EOAs).
    pub code: Vec<u8>,
    /// Non-zero storage slots.
    pub storage: Vec<(U256, U256)>,
}

/// Generate (and self-verify) the witness for executing `input` against `pre`.
///
/// Returns the witness plus the execution outcome. Errors if execution fails or
/// if the generated witness does NOT reproduce the post-state root (an
/// incomplete witness — e.g. a restructure whose sibling was not exposed).
pub fn generate_batch_witness(
    pre: &L2State,
    spec: &ChainSpec,
    input: BlockInput,
) -> Result<(BatchWitness, ExecutionOutcome), String> {
    let prev_state_root = compute_keccak_mpt_state_root(pre);

    // Execute on a clone (stateless-read: only touched accounts are needed, but
    // here the host holds full state and records the delta).
    let mut post = pre.clone();
    let outcome = execute_block(spec, &mut post, input).map_err(|e| e.to_string())?;
    let new_state_root = compute_keccak_mpt_state_root(&post);

    // Diff pre vs post account leaves → the change set.
    let pre_leaves: BTreeMap<B256, Vec<u8>> = account_leaves(pre).into_iter().collect();
    let post_leaves: BTreeMap<B256, Vec<u8>> = account_leaves(&post).into_iter().collect();

    let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
    let mut changed_hashes: BTreeSet<B256> = BTreeSet::new();
    for (k, v) in &post_leaves {
        if pre_leaves.get(k) != Some(v) {
            changes.insert(Nibbles::unpack(k), Some(v.clone())); // insert or update
            changed_hashes.insert(*k);
        }
    }
    for k in pre_leaves.keys() {
        if !post_leaves.contains_key(k) {
            changes.insert(Nibbles::unpack(k), None); // delete
            changed_hashes.insert(*k);
        }
    }

    // Proof targets: every changed key, plus its immediate key-order neighbours
    // (over pre ∪ post) so a leaf split (insert) or branch collapse (delete)
    // exposes the sibling it restructures.
    let mut all_keys: Vec<B256> = pre_leaves.keys().chain(post_leaves.keys()).copied().collect();
    all_keys.sort_unstable();
    all_keys.dedup();
    let mut targets: BTreeSet<Nibbles> = changes.keys().cloned().collect();
    for (i, k) in all_keys.iter().enumerate() {
        if changed_hashes.contains(k) {
            if i > 0 {
                targets.insert(Nibbles::unpack(all_keys[i - 1]));
            }
            if i + 1 < all_keys.len() {
                targets.insert(Nibbles::unpack(all_keys[i + 1]));
            }
        }
    }

    // Build the multiproof against the PRE-state trie.
    let mut leaves: Vec<(B256, Vec<u8>)> = account_leaves(pre);
    leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut hb =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets.into_iter()));
    for (k, v) in &leaves {
        hb.add_leaf(Nibbles::unpack(k), v);
    }
    let built_root = hb.root();
    if built_root != prev_state_root {
        return Err("witness build: retained root != prev_state_root".to_string());
    }
    let proof: BTreeMap<Nibbles, Bytes> =
        hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();

    // Self-verify: the guest-side stateless update must reproduce the post-root.
    let reconstructed = stateless_new_root(&proof, &changes);
    if reconstructed != new_state_root {
        return Err("witness incomplete: stateless root != post-state root".to_string());
    }

    // Address-keyed PRE-state of every account the batch CHANGED and that
    // existed before it — what the guest hydrates. (NOTE: pure-READ accounts a
    // contract touches without changing are the general RSP access-set; that
    // needs a tracing DB and is not covered here — value transfers, deposit
    // mints and fee routing only touch accounts they also change.)
    let mut pre_accounts = Vec::new();
    for (addr, post_acc) in &post.db.cache.accounts {
        let Some(pre_acc) = pre.db.cache.accounts.get(addr) else {
            continue; // created by the batch — the guest re-creates it
        };
        let changed = pre_acc.info != post_acc.info || pre_acc.storage != post_acc.storage;
        if !changed {
            continue;
        }
        if let Some(info) = pre_acc.info() {
            let code = info.code.as_ref().map(|c| c.original_bytes().to_vec()).unwrap_or_default();
            let storage: Vec<(U256, U256)> = pre_acc.storage.iter().map(|(k, v)| (*k, *v)).collect();
            pre_accounts.push(WitnessAccount {
                address: *addr,
                balance: info.balance,
                nonce: info.nonce,
                code,
                storage,
            });
        }
    }

    Ok((BatchWitness { prev_state_root, new_state_root, proof, changes, pre_accounts }, outcome))
}

/// Guest step 3(a): hydrate a stateless [`L2State`] from the witness's
/// address-keyed pre-state and VERIFY each account opens against
/// `prev_state_root` via the multiproof. Returns the hydrated state ready for
/// [`execute_block`]. Errors if any account fails to open (⇒ unprovable batch).
pub fn hydrate_and_verify(
    pre_accounts: &[WitnessAccount],
    proof: &BTreeMap<Nibbles, Bytes>,
    prev_state_root: B256,
) -> Result<L2State, String> {
    let mut state = L2State::new();
    for wa in pre_accounts {
        let code = if wa.code.is_empty() { None } else { Some(Bytecode::new_raw(wa.code.clone().into())) };
        let code_hash = code.as_ref().map(|c| c.hash_slow()).unwrap_or(KECCAK_EMPTY);
        state.db.insert_account_info(
            wa.address,
            AccountInfo { balance: wa.balance, nonce: wa.nonce, code_hash, code, ..Default::default() },
        );
        for (slot, val) in &wa.storage {
            let _ = state.db.insert_account_storage(wa.address, *slot, *val);
        }
    }

    // Bind every hydrated leaf to prev_state_root through the multiproof.
    for (key, value) in account_leaves(&state) {
        let target = Nibbles::unpack(key);
        let mut path_nodes: Vec<(&Nibbles, &Bytes)> =
            proof.iter().filter(|(p, _)| target.starts_with(p)).collect();
        path_nodes.sort_by_key(|(p, _)| p.len());
        let nodes: Vec<Bytes> = path_nodes.iter().map(|(_, b)| (*b).clone()).collect();
        verify_proof(prev_state_root, target, Some(value), nodes.iter())
            .map_err(|e| {
                let mut s = String::from("pre-account does not open against prev_state_root: ");
                s.push_str(&e.to_string());
                s
            })?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::BlockContext;
    use crate::scale::{sats_to_wei, SATS_PER_BLCH};
    use crate::state::{DepositMint, DepositProvenance};
    use alloy_primitives::{address, Address, TxKind};
    use revm::context::TxEnv;

    fn deposit(to: Address, sats: u64) -> DepositMint {
        DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
        }
    }

    /// End-to-end host witness generation for a REAL transfer batch: fund a
    /// pre-state, then execute Alice→Bob, generate the witness, and confirm it
    /// self-verifies (the guest would reproduce the post-state root from the
    /// multiproof alone).
    #[test]
    fn host_generates_self_verifying_witness_for_a_transfer_batch() {
        let spec = ChainSpec::testnet();

        // Pre-state: several funded accounts (so the witness is genuinely
        // sparse — most accounts are untouched by the transfer).
        let mut pre = L2State::new();
        for i in 1u8..=8 {
            let mut b = [0u8; 20];
            b[19] = i;
            execute_block(
                &spec,
                &mut pre,
                BlockInput {
                    context: BlockContext { number: 0, ..Default::default() },
                    deposits: vec![deposit(Address::from(b), 5 * SATS_PER_BLCH)],
                    txs: vec![],
                },
            )
            .unwrap();
        }
        let alice = address!("0000000000000000000000000000000000000001");
        let bob = address!("00000000000000000000000000000000000000bb"); // a NEW recipient (insert)

        let tx = TxEnv::builder()
            .caller(alice)
            .kind(TxKind::Call(bob))
            .value(sats_to_wei(SATS_PER_BLCH))
            .gas_limit(21_000)
            .max_fee_per_gas(spec.initial_base_fee as u128 + 1_000_000_000)
            .gas_priority_fee(Some(1_000_000_000))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();

        let batch = BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![],
            txs: vec![tx],
        };

        let (witness, outcome) =
            generate_batch_witness(&pre, &spec, batch).expect("witness generates and self-verifies");

        assert!(outcome.tx_outcomes[0].success);
        assert_ne!(witness.new_state_root, witness.prev_state_root);
        // The self-check inside generate_batch_witness already asserts the guest
        // reproduces the root; re-run it here to make the guarantee explicit.
        assert_eq!(
            stateless_new_root(&witness.proof, &witness.changes),
            witness.new_state_root,
            "guest reconstructs the post-state root from the witness alone"
        );
        // The witness is sparse: it did not need all 8+ accounts, only the
        // changed ones (Alice, Bob, the two fee vaults) plus a few neighbours.
        assert!(witness.changes.len() <= 4, "only touched accounts change");
    }

    /// The GUEST flow, host-tested: hydrate the stateless pre-state from the
    /// witness, VERIFY it opens against `prev_state_root`, re-execute with the
    /// real `execute_block`, and confirm it reproduces the full execution — plus
    /// a tampered pre-account is rejected.
    #[test]
    fn guest_hydrate_verify_and_reexecute_reproduces_the_batch() {
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        for i in 1u8..=8 {
            let mut b = [0u8; 20];
            b[19] = i;
            execute_block(
                &spec,
                &mut pre,
                BlockInput {
                    context: BlockContext { number: 0, ..Default::default() },
                    deposits: vec![deposit(Address::from(b), 5 * SATS_PER_BLCH)],
                    txs: vec![],
                },
            )
            .unwrap();
        }
        let alice = address!("0000000000000000000000000000000000000001");
        let bob = address!("00000000000000000000000000000000000000bb");
        let make_batch = || {
            let tx = TxEnv::builder()
                .caller(alice)
                .kind(TxKind::Call(bob))
                .value(sats_to_wei(SATS_PER_BLCH))
                .gas_limit(21_000)
                .max_fee_per_gas(spec.initial_base_fee as u128 + 1_000_000_000)
                .gas_priority_fee(Some(1_000_000_000))
                .nonce(0)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap();
            BlockInput {
                context: BlockContext { number: 1, ..Default::default() },
                deposits: vec![],
                txs: vec![tx],
            }
        };

        // Full execution (oracle).
        let mut full = pre.clone();
        let full_outcome = execute_block(&spec, &mut full, make_batch()).unwrap();
        let full_root = compute_keccak_mpt_state_root(&full);

        // Host generates the witness.
        let (w, _) = generate_batch_witness(&pre, &spec, make_batch()).unwrap();
        assert!(!w.pre_accounts.is_empty(), "touched pre-state recorded");

        // GUEST: hydrate + verify against prev_root, then re-execute.
        let mut guest =
            hydrate_and_verify(&w.pre_accounts, &w.proof, w.prev_state_root).expect("opens");
        let guest_outcome = execute_block(&spec, &mut guest, make_batch()).unwrap();

        assert_eq!(guest_outcome.tx_outcomes[0].success, full_outcome.tx_outcomes[0].success);
        assert_eq!(guest_outcome.tx_outcomes[0].gas_used, full_outcome.tx_outcomes[0].gas_used);
        // The guest's stateless post-root equals the full rebuild.
        assert_eq!(stateless_new_root(&w.proof, &w.changes), full_root);

        // Negative: a tampered pre-account must NOT open against prev_state_root.
        let mut bad = w.pre_accounts.clone();
        bad[0].balance += U256::from(1u64);
        assert!(
            hydrate_and_verify(&bad, &w.proof, w.prev_state_root).is_err(),
            "tampered pre-account must fail verification"
        );
    }
}
