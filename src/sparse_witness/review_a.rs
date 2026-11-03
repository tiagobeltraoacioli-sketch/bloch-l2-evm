// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent review, part A (agent 162, round 10): witness verification and
//! state reads of the sparse settlement witness.
//!
//! These tests aim at what the earlier suites leave implicit:
//!
//! * genuine trie nodes moved to another path, copied to a child path, or taken from
//!   another genuine trie (the earlier property test removes nodes but never moves
//!   them);
//! * degenerate tries: the empty root, a root that is a single leaf, a root that is
//!   an extension, and keys of the wrong length;
//! * the guest database itself (`SparseBacking` under the hydrated `CacheDB`),
//!   queried directly without the EVM: accounts, slots, codes and the lazy
//!   block-hash window, so that each read answers truly or refuses.
//!
//! Every test asserts "a true answer or a refusal, never a wrong answer and never a
//! panic".

use super::*;
use crate::mpt::Mpt;
use crate::stateroot::{SparseTrieView, WitnessError};
use alloy_primitives::keccak256;
use std::panic::{catch_unwind, AssertUnwindSafe};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct Rng(B256);

impl Rng {
    fn new(seed: &[u8]) -> Self {
        Self(keccak256(seed))
    }
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = keccak256(self.0);
        u64::from_be_bytes(self.0[..8].try_into().unwrap()) % bound
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next(100) < percent
    }
    fn word(&mut self) -> B256 {
        self.0 = keccak256(self.0);
        self.0
    }
}

fn nibbles_of(word: B256) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (index, nibble) in out.iter_mut().enumerate() {
        let byte = word[index / 2];
        *nibble = if index % 2 == 0 { byte >> 4 } else { byte & 0xf };
    }
    out
}

/// A key sharing `shared` nibbles with `base`, then random (and different at `shared`).
fn near(rng: &mut Rng, base: &[u8; 64], shared: usize) -> Nibbles {
    let mut nibbles = *base;
    let tail = nibbles_of(rng.word());
    nibbles[shared..].copy_from_slice(&tail[shared..]);
    if shared < 64 && nibbles[shared] == base[shared] {
        nibbles[shared] = (base[shared] + 1) & 0xf;
    }
    Nibbles::from_nibbles_unchecked(nibbles)
}

/// Random keys around one base, at depths that give extensions, short branches
/// and (at 62/63) inline nodes for small values.
fn key_set(rng: &mut Rng, count: u64) -> Vec<Nibbles> {
    const DEPTHS: [usize; 10] = [0, 1, 2, 5, 9, 30, 57, 61, 62, 63];
    let base = nibbles_of(rng.word());
    let mut keys = BTreeSet::new();
    for _ in 0..count {
        let shared = DEPTHS[rng.next(DEPTHS.len() as u64) as usize];
        keys.insert(near(rng, &base, shared));
    }
    keys.into_iter().collect()
}

fn value(rng: &mut Rng) -> Vec<u8> {
    let word = match rng.next(3) {
        0 => U256::from(1 + rng.next(100)),
        1 => U256::from(1 + rng.next(1 << 32)),
        _ => U256::from_be_bytes(rng.word().0) | U256::from(1),
    };
    alloy_rlp::encode(word)
}

/// A true answer or a refusal; never a wrong answer.
fn assert_truthful(view: &IndexedTrieView, truth: &BTreeMap<Nibbles, Vec<u8>>, keys: &[Nibbles], what: &str) {
    for key in keys {
        match view.lookup(key) {
            Ok(Some(found)) => assert_eq!(truth.get(key).map(Vec::as_slice), Some(found), "{what}: wrong value"),
            Ok(None) => assert!(!truth.contains_key(key), "{what}: a live key was proved absent"),
            Err(_) => {}
        }
    }
}

fn no_panic<T>(what: &str, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => panic!("{what}: panicked instead of refusing"),
    }
}

// ---------------------------------------------------------------------------
// Trie level
// ---------------------------------------------------------------------------

/// A malicious prover holds every genuine node of the trie, and of other tries. It
/// can place any of them at any path of the proof map. The verifier must still
/// answer every key truly or refuse.
#[test]
fn relocated_copied_and_foreign_nodes_never_give_a_wrong_answer() {
    let mut rng = Rng::new(b"review-a relocate");
    let mut views = 0u64;
    let mut refused = 0u64;
    for round in 0..40 {
        let count = 2 + rng.next(30);
        let keys = key_set(&mut rng, count);
        let mut truth = BTreeMap::new();
        let mut trie = Mpt::new();
        for key in &keys {
            let v = value(&mut rng);
            trie.insert(*key, v.clone());
            truth.insert(*key, v);
        }
        let root = trie.root();
        let absent = key_set(&mut rng, 10);
        let universe: Vec<Nibbles> = keys.iter().chain(&absent).copied().collect();
        let full = trie.proof(universe.iter().copied()).unwrap();

        // A foreign trie: same shape of keys, other values. Its nodes are genuine
        // nodes of some trie, at real paths.
        let mut foreign = Mpt::new();
        for key in &keys {
            foreign.insert(*key, value(&mut rng));
        }
        foreign.insert(absent[0], value(&mut rng));
        foreign.root();
        let foreign_proof = foreign.proof(universe.iter().copied()).unwrap();

        let paths: Vec<Nibbles> = full.keys().copied().collect();
        let mut candidates: Vec<BTreeMap<Nibbles, Bytes>> = Vec::new();
        // Move: the node of `from` placed at `to` (replacing what was there).
        for from in &paths {
            for to in &paths {
                if from == to || !rng.chance(15) {
                    continue;
                }
                let mut proof = full.clone();
                proof.insert(*to, full[from].clone());
                candidates.push(proof);
                let mut proof = full.clone();
                let node = proof.remove(from).unwrap();
                proof.insert(*to, node);
                candidates.push(proof);
            }
            // Copy to every child position.
            if from.len() < 64 {
                for nibble in 0u8..16 {
                    let mut child = *from;
                    child.push(nibble);
                    if full.contains_key(&child) {
                        continue;
                    }
                    let mut proof = full.clone();
                    proof.insert(child, full[from].clone());
                    candidates.push(proof);
                }
            }
        }
        // Foreign nodes, at their own paths and at ours.
        for (path, node) in &foreign_proof {
            let mut proof = full.clone();
            proof.insert(*path, node.clone());
            candidates.push(proof);
            if let Some(to) = paths.get(rng.next(paths.len() as u64) as usize) {
                let mut proof = full.clone();
                proof.insert(*to, node.clone());
                candidates.push(proof);
            }
        }

        for (index, proof) in candidates.iter().enumerate() {
            let what = format!("round {round} candidate {index}");
            let indexed = no_panic(&what, || IndexedTrieView::from_proof(root, proof));
            let plain = no_panic(&what, || SparseTrieView::from_proof(root, proof));
            match (indexed, plain) {
                (Ok(view), Ok(plain)) => {
                    views += 1;
                    assert_truthful(&view, &truth, &universe, &what);
                    for key in &universe {
                        match (view.lookup(key), plain.contains_key(key)) {
                            (Ok(Some(_)), Ok(true)) | (Ok(None), Ok(false)) | (Err(_), Err(_)) => {}
                            (a, b) => panic!("{what}: indexed {a:?} and plain {b:?} differ"),
                        }
                    }
                }
                (Err(_), Err(_)) => refused += 1,
                (a, b) => panic!("{what}: indexed {:?} and plain {:?} disagree on acceptance", a.is_ok(), b.is_ok()),
            }
        }
    }
    std::println!("relocation: {views} views answered truly, {refused} refused");
    assert!(views > 1000 && refused > 1000, "both outcomes must be exercised: {views} {refused}");
}

#[test]
fn degenerate_roots_answer_truly_or_refuse() {
    let mut rng = Rng::new(b"review-a degenerate");
    let probes: Vec<Nibbles> = (0..32).map(|_| Nibbles::from_nibbles_unchecked(nibbles_of(rng.word()))).collect();

    // Empty trie, empty proof: every key is absent.
    let empty = IndexedTrieView::from_proof(alloy_trie::EMPTY_ROOT_HASH, &BTreeMap::new()).unwrap();
    assert_truthful(&empty, &BTreeMap::new(), &probes, "empty");
    assert!(probes.iter().all(|key| matches!(empty.lookup(key), Ok(None))));

    // Empty trie, the root given as 0x80 plus junk elsewhere: still empty.
    let mut junk = BTreeMap::new();
    junk.insert(Nibbles::default(), Bytes::from_static(&[0x80]));
    junk.insert(Nibbles::from_nibbles_unchecked([1]), Bytes::from_static(&[0xc2, 0x01, 0x02]));
    let view = IndexedTrieView::from_proof(alloy_trie::EMPTY_ROOT_HASH, &junk).unwrap();
    assert!(probes.iter().all(|key| matches!(view.lookup(key), Ok(None))));

    // Empty root, junk but no root node: refused.
    junk.remove(&Nibbles::default());
    assert!(matches!(
        IndexedTrieView::from_proof(alloy_trie::EMPTY_ROOT_HASH, &junk),
        Err(WitnessError::MissingRootNode)
    ));

    // Non-empty root, empty proof: refused, never "everything absent".
    let mut one = Mpt::new();
    let key = probes[0];
    one.insert(key, alloy_rlp::encode(U256::from(7)));
    let root = one.root();
    assert!(matches!(
        IndexedTrieView::from_proof(root, &BTreeMap::new()),
        Err(WitnessError::EmptyProofForNonEmptyRoot { .. })
    ));

    // A root that is one leaf: the key, and its last-nibble neighbour, answered truly.
    let proof = one.proof([key]).unwrap();
    assert_eq!(proof.len(), 1, "a one-leaf trie is its root");
    let view = IndexedTrieView::from_proof(root, &proof).unwrap();
    assert_eq!(view.lookup(&key).unwrap(), Some(alloy_rlp::encode(U256::from(7)).as_slice()));
    let mut neighbour = nibbles_of(B256::ZERO);
    for (index, nibble) in neighbour.iter_mut().enumerate() {
        *nibble = key.get_unchecked(index);
    }
    neighbour[63] ^= 1;
    let neighbour = Nibbles::from_nibbles_unchecked(neighbour);
    assert!(matches!(view.lookup(&neighbour), Ok(None)));
    let mut truth = BTreeMap::new();
    truth.insert(key, alloy_rlp::encode(U256::from(7)));
    assert_truthful(&view, &truth, &probes, "one leaf");

    // Wrong key lengths refuse, never panic.
    for length in [0usize, 1, 32, 63] {
        let short = Nibbles::from_nibbles_unchecked(&nibbles_of(rng.word())[..length]);
        assert!(matches!(view.lookup(&short), Err(WitnessError::InvalidKeyLength { .. })));
        assert!(matches!(empty.lookup(&short), Err(WitnessError::InvalidKeyLength { .. })));
    }
}

/// All keys share their first nibbles, so the root is an extension. With only the
/// root exposed, a key that leaves the extension's path is truly absent; a key that
/// follows it lies under the opaque branch and must be refused.
#[test]
fn an_extension_root_proves_absence_only_off_its_path() {
    let mut rng = Rng::new(b"review-a extension");
    for shared in [1usize, 2, 7, 40, 61] {
        let base = nibbles_of(rng.word());
        let mut trie = Mpt::new();
        let mut truth = BTreeMap::new();
        for _ in 0..6 {
            let key = near(&mut rng, &base, shared);
            // Full words: every leaf is hashed, so no node below the root is inline.
            let v = alloy_rlp::encode(U256::from_be_bytes(rng.word().0) | (U256::from(1) << 255));
            trie.insert(key, v.clone());
            truth.insert(key, v);
        }
        let root = trie.root();
        let any = *truth.keys().next().unwrap();
        let full = trie.proof([any]).unwrap();
        let mut root_only = BTreeMap::new();
        root_only.insert(Nibbles::default(), full[&Nibbles::default()].clone());
        let view = IndexedTrieView::from_proof(root, &root_only).unwrap();

        let prefix = Nibbles::from_nibbles_unchecked(&base[..shared]);
        let mut on_path = 0;
        let mut off_path = 0;
        for attempt in 0..96 {
            let depth = if attempt % 3 == 0 { shared } else { rng.next(shared as u64 + 1) as usize };
            let probe = near(&mut rng, &base, depth);
            let result = view.lookup(&probe);
            if probe.starts_with(&prefix) {
                on_path += 1;
                assert!(
                    matches!(result, Err(WitnessError::KeyInOpaqueSubtree { .. })),
                    "shared {shared}: a key under the opaque branch answered {result:?}"
                );
            } else {
                off_path += 1;
                assert!(matches!(result, Ok(None)), "shared {shared}: a key off the extension: {result:?}");
                assert!(!truth.contains_key(&probe));
            }
        }
        for key in truth.keys() {
            assert!(view.lookup(key).is_err(), "shared {shared}: a live key under the opaque branch");
        }
        assert!(on_path > 0 && off_path > 0, "shared {shared}: {on_path} {off_path}");
    }
}

// ---------------------------------------------------------------------------
// The guest database, without the EVM
// ---------------------------------------------------------------------------

struct Built {
    witness: SparseBatchWitness,
}

struct World {
    accounts: BTreeMap<Address, (AccountInfo, Mpt)>,
    trie: Mpt,
}

fn info(balance: u64, nonce: u64, code_hash: B256) -> AccountInfo {
    AccountInfo {
        balance: U256::from(balance),
        nonce,
        code_hash,
        code: None,
        ..Default::default()
    }
}

impl World {
    fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
            trie: Mpt::new(),
        }
    }

    fn put(&mut self, address: Address, info: AccountInfo, slots: &[(U256, U256)]) {
        let mut storage = Mpt::new();
        for (slot, word) in slots {
            storage.insert(storage_key(slot), alloy_rlp::encode(*word));
        }
        let root = storage.root();
        self.trie.insert(account_key(&address), account_leaf_with_root(&info, root));
        self.accounts.insert(address, (info, storage));
    }

    /// A witness for `present` (with proofs of `slots`) and `absent`.
    fn witness(&mut self, present: &[(Address, Vec<U256>)], absent: &[Address], codes: Vec<Bytes>) -> Built {
        let prev_state_root = self.trie.root();
        let targets = present.iter().map(|(a, _)| account_key(a)).chain(absent.iter().map(account_key));
        let proof = self.trie.proof(targets).unwrap();
        let pre_accounts = present
            .iter()
            .map(|(address, slots)| {
                let (info, storage) = self.accounts.get_mut(address).unwrap();
                let storage_root = storage.root();
                let storage_proof = if storage.is_empty() {
                    BTreeMap::new()
                } else {
                    storage.proof(slots.iter().map(storage_key)).unwrap()
                };
                SparseWitnessAccount {
                    address: *address,
                    balance: info.balance,
                    nonce: info.nonce,
                    code_hash: info.code_hash,
                    storage_root,
                    storage_proof,
                }
            })
            .collect();
        Built {
            witness: SparseBatchWitness {
                prev_state_root,
                new_state_root: prev_state_root,
                proof,
                pre_accounts,
                absent_accounts: absent.to_vec(),
                codes,
            },
        }
    }
}

const CONTRACT: Address = Address::repeat_byte(0xc1);
const EOA: Address = Address::repeat_byte(0xe0);
const NOBODY: Address = Address::repeat_byte(0x0b);
const STRANGER: Address = Address::repeat_byte(0x5a);

fn runtime() -> Bytes {
    Bytes::from_static(&[0x60, 0x01, 0x60, 0x00, 0x55, 0x00])
}

fn world(spec: &ChainSpec, number: u64) -> World {
    let mut world = World::new();
    let code_hash = keccak256(runtime());
    let slots: Vec<(U256, U256)> = (1..=200u64).map(|slot| (U256::from(slot), U256::from(slot * 3))).collect();
    world.put(CONTRACT, info(5, 1, code_hash), &slots);
    world.put(EOA, info(1_000, 4, KECCAK_EMPTY), &[]);
    world.put(STRANGER, info(9, 0, KECCAK_EMPTY), &[]);
    // The block-info account with a full ring: slot of block n holds a word derived from n.
    let ring: Vec<(U256, U256)> = (number.saturating_sub(BLOCK_HASH_HISTORY)..number)
        .map(|n| (block_hash_slot(n), U256::from_be_bytes(keccak256(n.to_be_bytes()).0)))
        .collect();
    world.put(spec.block_info, info(0, 1, KECCAK_EMPTY), &ring);
    world
}

#[test]
fn the_guest_database_answers_every_read_truly_or_refuses() {
    let spec = ChainSpec::mainnet_next_or_rehearsal();
    let number = 1_000u64;
    let mut world = world(&spec, number);
    let exposed: Vec<U256> = vec![U256::from(1), U256::from(77), U256::from(5_000)];
    let ring_reads: Vec<U256> = vec![block_hash_slot(number - 1), block_hash_slot(number - 256), block_hash_slot(number - 100)];
    let built = world.witness(
        &[(CONTRACT, exposed.clone()), (EOA, vec![]), (spec.block_info, ring_reads)],
        &[NOBODY],
        vec![runtime()],
    );
    let hydrated = hydrate_sparse(&spec, &built.witness, number).expect("an honest witness hydrates");
    let db = &hydrated.state;

    // Accounts: hydrated ones as in the trie (without code), absent ones absent,
    // every other address an error, including one that exists in the trie.
    let contract = db.basic_ref(CONTRACT).unwrap().unwrap();
    assert_eq!((contract.balance, contract.nonce, contract.code_hash), (U256::from(5), 1, keccak256(runtime())));
    assert!(contract.code.is_none());
    assert_eq!(db.basic_ref(NOBODY).unwrap(), None);
    assert_eq!(db.basic_ref(STRANGER), Err(SparseAccessError::UnwitnessedAccount(STRANGER)));
    assert_eq!(
        db.basic_ref(Address::repeat_byte(0x77)),
        Err(SparseAccessError::UnwitnessedAccount(Address::repeat_byte(0x77)))
    );

    // Slots: exposed values, a proven-absent slot as zero, every other slot an error.
    assert_eq!(db.storage_ref(CONTRACT, U256::from(1)).unwrap(), U256::from(3));
    assert_eq!(db.storage_ref(CONTRACT, U256::from(77)).unwrap(), U256::from(231));
    assert_eq!(db.storage_ref(CONTRACT, U256::from(5_000)).unwrap(), U256::ZERO);
    let mut refused = 0;
    for slot in 1..=200u64 {
        let slot = U256::from(slot);
        match db.storage_ref(CONTRACT, slot) {
            Ok(word) => assert_eq!(word, slot * U256::from(3), "slot {slot}"),
            Err(error) => {
                assert_eq!(error, SparseAccessError::UnwitnessedStorage(CONTRACT, slot));
                refused += 1;
            }
        }
    }
    assert!(refused > 150, "most live slots are opaque: {refused}");
    assert_eq!(db.storage_ref(EOA, U256::from(1)).unwrap(), U256::ZERO, "an account with the empty storage root");
    assert_eq!(db.storage_ref(NOBODY, U256::from(1)).unwrap(), U256::ZERO, "a proven-absent account");
    assert_eq!(
        db.storage_ref(STRANGER, U256::from(1)),
        Err(SparseAccessError::UnknownStorageAccount(STRANGER, U256::from(1)))
    );

    // Code: served only for its own hash.
    let code = db.code_by_hash_ref(keccak256(runtime())).unwrap();
    assert_eq!(code.original_bytes(), runtime());
    let other = keccak256([0x00]);
    assert_eq!(db.code_by_hash_ref(other), Err(SparseAccessError::UnwitnessedCode(other)));

    // Block hashes: the window is [number - 256, number); inside it, exposed ring
    // slots only.
    let ring = |n: u64| B256::from(keccak256(n.to_be_bytes()).0);
    assert_eq!(db.db.block_hash_ref(number - 1).unwrap(), ring(number - 1));
    assert_eq!(db.db.block_hash_ref(number - 256).unwrap(), ring(number - 256));
    assert_eq!(db.db.block_hash_ref(number - 100).unwrap(), ring(number - 100));
    for n in [number, number + 1, number - 257, 0, u64::MAX] {
        assert_eq!(db.db.block_hash_ref(n), Err(SparseAccessError::UnwitnessedBlockHash(n)), "block {n}");
    }
    let mut ring_refused = 0;
    for n in number - 256..number {
        match db.db.block_hash_ref(n) {
            Ok(hash) => assert_eq!(hash, ring(n)),
            Err(error) => {
                assert_eq!(error, SparseAccessError::UnwitnessedBlockHash(n));
                ring_refused += 1;
            }
        }
    }
    assert!(ring_refused > 200, "most ring slots are opaque: {ring_refused}");
}

/// Each way a witness can lie about an account, applied to the guest's hydration
/// directly, refuses with the precise error and never panics.
#[test]
fn hydration_refuses_every_account_lie() {
    let spec = ChainSpec::mainnet_next_or_rehearsal();
    let number = 1_000u64;
    let mut world = world(&spec, number);
    let honest = world
        .witness(&[(CONTRACT, vec![U256::from(1)]), (EOA, vec![])], &[NOBODY], vec![runtime()])
        .witness;
    hydrate_sparse(&spec, &honest, number).unwrap();
    let refuse = |witness: &SparseBatchWitness, what: &str| -> SparseVerifyError {
        match no_panic(what, || hydrate_sparse(&spec, witness, number)) {
            Ok(_) => panic!("{what}: accepted"),
            Err(error) => error,
        }
    };

    // An existing account claimed absent.
    let mut w = honest.clone();
    w.absent_accounts.push(STRANGER);
    let stranger_proof = world.witness(&[], &[STRANGER], vec![]).witness.proof;
    w.proof.extend(stranger_proof);
    assert!(matches!(refuse(&w, "existing claimed absent"), SparseVerifyError::AccountNotProvenAbsent(a) if a == STRANGER));

    // An absent address claimed absent with no proof of its path: opaque, refused.
    let mut w = honest.clone();
    let mut probe = 0u8;
    let hidden = loop {
        let candidate = Address::repeat_byte(probe);
        let view = IndexedTrieView::from_proof(w.prev_state_root, &w.proof).unwrap();
        if view.lookup(&account_key(&candidate)).is_err() && !world.accounts.contains_key(&candidate) {
            break candidate;
        }
        probe += 1;
    };
    w.absent_accounts.push(hidden);
    assert!(matches!(refuse(&w, "absent under opaque"), SparseVerifyError::Witness(WitnessError::KeyInOpaqueSubtree { .. })));

    // A pre-account with one field changed, or listed with another's storage.
    for field in 0..4 {
        let mut w = honest.clone();
        let account = w.pre_accounts.iter_mut().find(|a| a.address == CONTRACT).unwrap();
        match field {
            0 => account.balance += U256::from(1),
            1 => account.nonce += 1,
            2 => account.code_hash = KECCAK_EMPTY,
            _ => {
                account.storage_root = alloy_trie::EMPTY_ROOT_HASH;
                account.storage_proof = BTreeMap::new();
            }
        }
        assert!(matches!(refuse(&w, "changed field"), SparseVerifyError::AccountNotProven(a) if a == CONTRACT), "field {field}");
    }

    // The storage root is bound, the storage proof is not: a proof of another trie.
    let mut w = honest.clone();
    let foreign = {
        let mut trie = Mpt::new();
        trie.insert(storage_key(&U256::from(1)), alloy_rlp::encode(U256::from(999)));
        trie.root();
        trie.proof([storage_key(&U256::from(1))]).unwrap()
    };
    w.pre_accounts.iter_mut().find(|a| a.address == CONTRACT).unwrap().storage_proof = foreign;
    assert!(matches!(refuse(&w, "foreign storage proof"), SparseVerifyError::Storage(a, WitnessError::RootMismatch { .. }) if a == CONTRACT));

    // A pre-account whose leaf is behind an opaque node of the account proof.
    let mut w = honest.clone();
    let path = account_key(&CONTRACT);
    let deepest = *w.proof.keys().filter(|p| path.starts_with(p) && !p.is_empty()).max_by_key(|p| p.len()).unwrap();
    w.proof.remove(&deepest);
    assert!(matches!(refuse(&w, "leaf behind opaque"), SparseVerifyError::Witness(WitnessError::KeyInOpaqueSubtree { .. })));

    // An address in both lists, and twice in one list.
    let mut w = honest.clone();
    w.absent_accounts.push(EOA);
    assert!(matches!(refuse(&w, "both lists"), SparseVerifyError::DuplicateAccount(a) if a == EOA));
    let mut w = honest.clone();
    w.absent_accounts.push(NOBODY);
    assert!(matches!(refuse(&w, "absent twice"), SparseVerifyError::DuplicateAccount(a) if a == NOBODY));

    // An invented account at an absent address (EIP-161 empty, zero code hash, or real-looking).
    for (balance, nonce, code_hash, expect) in [
        (0u64, 0u64, KECCAK_EMPTY, "empty"),
        (1, 1, B256::ZERO, "zero code hash"),
        (1, 1, KECCAK_EMPTY, "not proven"),
    ] {
        let mut w = honest.clone();
        w.absent_accounts.retain(|a| *a != NOBODY);
        w.pre_accounts.push(SparseWitnessAccount {
            address: NOBODY,
            balance: U256::from(balance),
            nonce,
            code_hash,
            storage_root: alloy_trie::EMPTY_ROOT_HASH,
            storage_proof: BTreeMap::new(),
        });
        let error = refuse(&w, expect);
        let ok = match expect {
            "empty" => matches!(error, SparseVerifyError::EmptyAccount(_)),
            "zero code hash" => matches!(error, SparseVerifyError::ZeroCodeHash(_)),
            _ => matches!(error, SparseVerifyError::AccountNotProven(_)),
        };
        assert!(ok, "{expect}: {error:?}");
    }

    // Codes: empty, duplicate. A wrong code cannot be served for a hash: it is keyed
    // by its own.
    let mut w = honest.clone();
    w.codes.push(Bytes::new());
    assert!(matches!(refuse(&w, "empty code"), SparseVerifyError::InvalidCode(_)));
    let mut w = honest.clone();
    w.codes.push(runtime());
    assert!(matches!(refuse(&w, "duplicate code"), SparseVerifyError::DuplicateCode(_)));
    let mut w = honest.clone();
    w.codes = vec![Bytes::from_static(&[0x60, 0x02, 0x60, 0x00, 0x55, 0x00])];
    let hydrated = hydrate_sparse(&spec, &w, number).unwrap();
    assert_eq!(
        hydrated.state.code_by_hash_ref(keccak256(runtime())),
        Err(SparseAccessError::UnwitnessedCode(keccak256(runtime())))
    );
}

/// The bounded decoders refuse each allocation guard and malformed path with an
/// error, not a panic. Human-readable (JSON) path only: the crate has no bincode
/// dev-dependency, so the guest's own wire format is not exercised here.
#[test]
fn the_guest_decoder_refuses_malformed_witnesses_without_panicking() {
    let spec = ChainSpec::mainnet_next_or_rehearsal();
    let mut world = world(&spec, 300);
    let honest = world.witness(&[(CONTRACT, vec![U256::from(1)])], &[NOBODY], vec![runtime()]).witness;
    let json = serde_json::to_value(&honest).unwrap();
    let back: SparseBatchWitness = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, honest);

    let decode = |value: serde_json::Value, what: &str| {
        no_panic(what, || serde_json::from_value::<SparseBatchWitness>(value)).is_err()
    };
    // A path of 65 nibbles, a non-hex path, a path without 0x.
    for bad in ["0x00000000000000000000000000000000000000000000000000000000000000000", "0xzz", "00"] {
        let mut value = json.clone();
        value["proof"].as_object_mut().unwrap().insert(bad.into(), serde_json::Value::String("0x80".into()));
        assert!(decode(value, bad), "path {bad} accepted");
    }
    // A node over 1,024 bytes.
    let mut value = json.clone();
    let big = format!("0x{}", "00".repeat(1025));
    value["proof"].as_object_mut().unwrap().insert("0x1".into(), serde_json::Value::String(big));
    assert!(decode(value, "big node"));
    // A code over EIP-170.
    let mut value = json.clone();
    let big = format!("0x{}", "00".repeat(24_577));
    value["codes"].as_array_mut().unwrap().push(serde_json::Value::String(big));
    assert!(decode(value, "big code"));
}

// ---------------------------------------------------------------------------
// The guest's own wire format (bincode 1.3.3, as `sp1_zkvm::io::read`)
// ---------------------------------------------------------------------------

/// bincode 1.x with default options, exactly what `sp1_lib::io::read` calls.
fn guest_decode(bytes: &[u8]) -> Result<SparseBatchWitness, bincode::Error> {
    bincode::deserialize::<SparseBatchWitness>(bytes)
}

/// bincode 1.x default framing, written by hand so a test can state shapes the
/// typed encoder cannot: a 65-nibble path, a duplicate key, a declared length with
/// nothing behind it.
fn wire_len(out: &mut Vec<u8>, len: u64) {
    out.extend_from_slice(&len.to_le_bytes());
}
fn wire_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    wire_len(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
fn wire_proof(out: &mut Vec<u8>, pairs: &[(String, Vec<u8>)]) {
    wire_len(out, pairs.len() as u64);
    for (path, node) in pairs {
        wire_bytes(out, path.as_bytes());
        wire_bytes(out, node);
    }
}
fn proof_pairs(proof: &BTreeMap<Nibbles, Bytes>) -> Vec<(String, Vec<u8>)> {
    proof
        .iter()
        .map(|(path, node)| {
            let text = serde_json::to_value(path).unwrap().as_str().unwrap().to_owned();
            (text, node.to_vec())
        })
        .collect()
}

struct WireWitness {
    head: Vec<u8>,
    proof: Vec<(String, Vec<u8>)>,
    accounts: Vec<(Vec<u8>, Vec<(String, Vec<u8>)>)>,
    absent: Vec<u8>,
    codes: Vec<Vec<u8>>,
}

impl WireWitness {
    fn of(witness: &SparseBatchWitness) -> Self {
        let mut head = bincode::serialize(&witness.prev_state_root).unwrap();
        head.extend(bincode::serialize(&witness.new_state_root).unwrap());
        let accounts = witness
            .pre_accounts
            .iter()
            .map(|account| {
                let mut fixed = bincode::serialize(&account.address).unwrap();
                fixed.extend(bincode::serialize(&account.balance).unwrap());
                fixed.extend(bincode::serialize(&account.nonce).unwrap());
                fixed.extend(bincode::serialize(&account.code_hash).unwrap());
                fixed.extend(bincode::serialize(&account.storage_root).unwrap());
                (fixed, proof_pairs(&account.storage_proof))
            })
            .collect();
        Self {
            head,
            proof: proof_pairs(&witness.proof),
            accounts,
            absent: bincode::serialize(&witness.absent_accounts).unwrap(),
            codes: witness.codes.iter().map(|code| code.to_vec()).collect(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = self.head.clone();
        wire_proof(&mut out, &self.proof);
        wire_len(&mut out, self.accounts.len() as u64);
        for (fixed, storage) in &self.accounts {
            out.extend_from_slice(fixed);
            wire_proof(&mut out, storage);
        }
        out.extend_from_slice(&self.absent);
        wire_len(&mut out, self.codes.len() as u64);
        for code in &self.codes {
            wire_bytes(&mut out, code);
        }
        out
    }
}

/// Agent 162's finding L1: the bounded decoders branch on `is_human_readable()`, and
/// every other test decodes JSON, while the guest decodes bincode. This repeats the
/// decoder test on the guest's wire format: the same refusals, no panic, and no
/// allocation driven by a declared length the input does not back.
#[test]
fn the_guest_wire_format_refuses_malformed_witnesses_without_panicking() {
    let spec = ChainSpec::mainnet_next_or_rehearsal();
    let mut world = world(&spec, 300);
    let honest = world.witness(&[(CONTRACT, vec![U256::from(1), U256::from(2)])], &[NOBODY], vec![runtime()]).witness;
    assert!(!honest.pre_accounts.is_empty() && !honest.codes.is_empty());

    // The hand-written framing is the guest's framing: byte-identical to bincode's
    // own encoding of the honest witness, and decoded back to it.
    let typed = bincode::serialize(&honest).unwrap();
    let wire = WireWitness::of(&honest);
    assert_eq!(wire.encode(), typed, "hand-written framing differs from bincode");
    assert_eq!(guest_decode(&typed).unwrap(), honest);

    let refused = |bytes: &[u8], what: &str| no_panic(what, || guest_decode(bytes)).is_err();

    // Paths: 65 nibbles, non-hex, no 0x prefix, a duplicate; in the account trie
    // proof and in a storage proof.
    let long_path = format!("0x{}", "0".repeat(65));
    for bad in [long_path.as_str(), "0xzz", "00"] {
        let mut w = WireWitness::of(&honest);
        w.proof.push((bad.into(), vec![0x80]));
        assert!(refused(&w.encode(), bad), "account proof path {bad} accepted");
        let mut w = WireWitness::of(&honest);
        w.accounts[0].1.push((bad.into(), vec![0x80]));
        assert!(refused(&w.encode(), bad), "storage proof path {bad} accepted");
    }
    let mut w = WireWitness::of(&honest);
    let first = w.proof[0].clone();
    w.proof.push(first);
    assert!(refused(&w.encode(), "duplicate path"), "duplicate account proof path accepted");

    // Node bytes: 1,024 is the limit, 1,025 is refused (both tries).
    let mut w = WireWitness::of(&honest);
    w.proof.push(("0x1".into(), vec![0u8; 1024]));
    assert!(no_panic("node at limit", || guest_decode(&w.encode())).is_ok(), "a 1,024-byte node was refused");
    let mut w = WireWitness::of(&honest);
    w.proof.push(("0x1".into(), vec![0u8; 1025]));
    assert!(refused(&w.encode(), "big node"), "a 1,025-byte node accepted");
    let mut w = WireWitness::of(&honest);
    w.accounts[0].1.push(("0x1".into(), vec![0u8; 1025]));
    assert!(refused(&w.encode(), "big storage node"), "a 1,025-byte storage node accepted");

    // Code: EIP-170 is the limit.
    let mut w = WireWitness::of(&honest);
    w.codes.push(vec![0u8; revm::primitives::eip170::MAX_CODE_SIZE]);
    assert!(no_panic("code at limit", || guest_decode(&w.encode())).is_ok(), "an EIP-170-size code was refused");
    let mut w = WireWitness::of(&honest);
    w.codes.push(vec![0u8; revm::primitives::eip170::MAX_CODE_SIZE + 1]);
    assert!(refused(&w.encode(), "big code"), "a code over EIP-170 accepted");

    // Declared lengths the input does not back: every length prefix in turn set to
    // u64::MAX and to 2^32, with the input cut right after it. Each must be refused
    // without a panic (an attempt to reserve 2^64 elements or bytes aborts the
    // process, which `catch_unwind` would not survive either).
    let w = WireWitness::of(&honest);
    let mut prefixes: Vec<(String, Vec<u8>)> = Vec::new();
    {
        let mut out = w.head.clone();
        prefixes.push(("proof count".into(), out.clone()));
        wire_len(&mut out, w.proof.len() as u64);
        prefixes.push(("proof path length".into(), out.clone()));
        wire_bytes(&mut out, w.proof[0].0.as_bytes());
        prefixes.push(("proof node length".into(), out.clone()));
        let mut out = w.head.clone();
        wire_proof(&mut out, &w.proof);
        prefixes.push(("account count".into(), out.clone()));
        wire_len(&mut out, w.accounts.len() as u64);
        out.extend_from_slice(&w.accounts[0].0);
        prefixes.push(("storage proof count".into(), out.clone()));
        let mut out = w.head.clone();
        wire_proof(&mut out, &w.proof);
        wire_len(&mut out, w.accounts.len() as u64);
        for (fixed, storage) in &w.accounts {
            out.extend_from_slice(fixed);
            wire_proof(&mut out, storage);
        }
        prefixes.push(("absent count".into(), out.clone()));
        out.extend_from_slice(&w.absent);
        prefixes.push(("code count".into(), out.clone()));
        wire_len(&mut out, 1);
        prefixes.push(("code length".into(), out));
    }
    for (what, prefix) in &prefixes {
        for declared in [u64::MAX, 1u64 << 32, (1u64 << 16) + 1] {
            let mut bytes = prefix.clone();
            wire_len(&mut bytes, declared);
            assert!(refused(&bytes, what), "{what} = {declared} with no data accepted");
        }
    }

    // Every truncation of the honest encoding is refused.
    for cut in 0..typed.len() {
        assert!(refused(&typed[..cut], "truncation"), "truncation at {cut} of {} accepted", typed.len());
    }

    // Random byte corruption: never a panic. A corrupted witness that still decodes
    // is only a different (unauthenticated) witness, which hydration then checks.
    let mut rng = Rng::new(b"review-a bincode corruption");
    for _ in 0..4_000 {
        let mut bytes = typed.clone();
        for _ in 0..1 + rng.next(3) {
            let at = rng.next(bytes.len() as u64) as usize;
            bytes[at] = rng.next(256) as u8;
        }
        let _ = no_panic("corruption", || guest_decode(&bytes));
    }

    // bincode::deserialize ignores trailing bytes. The guest reads each input as its
    // own length-framed buffer, and the witness is never committed, so this is
    // recorded rather than refused.
    let mut trailing = typed.clone();
    trailing.extend_from_slice(&[0xde, 0xad]);
    assert_eq!(guest_decode(&trailing).unwrap(), honest);
}
