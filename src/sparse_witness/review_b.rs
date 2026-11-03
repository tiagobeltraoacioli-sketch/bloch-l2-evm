// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent review, part B (agent 163): state writes, the derived post-state root
//! and the public values of the sparse witness guest at f6eb456.
//!
//! A child of `review`, so it reuses that harness. Tests named `gate_` encode a
//! release condition and are expected to FAIL until the owner acts; every other test
//! is expected to pass.

use super::*;
use crate::chainspec::fee_vault_sweep_code;

/// Fund `count` throwaway blocks so that the vaults and the system accounts exist.
fn warm(chain: &mut Chain, count: usize) {
    for _ in 0..count {
        let sender = chain.sender;
        let pay = chain.pay(sender, 1);
        let body = chain.body(vec![pay]);
        chain.commit(&body);
    }
}

/// First nibbles of every account key in the state.
fn used_first_nibbles(chain: &Chain) -> BTreeSet<u8> {
    chain
        .state
        .db()
        .cache
        .accounts
        .iter()
        .filter(|(_, account)| account_exists(account))
        .map(|(address, _)| keccak256(address)[0] >> 4)
        .collect()
}

/// Mine CREATE2 salts of `factory` for `initcode`: two salts whose account keys share
/// their first three bytes and start with nibble `x`, and a third salt whose key
/// starts with `x` but differs from the pair in the second nibble.
fn mine_cascade(factory: Address, initcode: &[u8], x: u8) -> (B256, B256, B256) {
    let hash = keccak256(initcode);
    let mut seen: BTreeMap<[u8; 3], B256> = BTreeMap::new();
    let mut pair = None;
    let mut index = 0u64;
    while pair.is_none() {
        let salt = keccak256(index.to_be_bytes());
        index += 1;
        let key = keccak256(factory.create2(salt, hash));
        if key[0] >> 4 != x {
            continue;
        }
        let prefix = [key[0], key[1], key[2]];
        if let Some(other) = seen.get(&prefix) {
            pair = Some((*other, salt));
        } else {
            seen.insert(prefix, salt);
        }
    }
    let (a, b) = pair.unwrap();
    let pair_second = keccak256(factory.create2(a, hash))[0] & 0x0f;
    loop {
        let salt = keccak256(index.to_be_bytes());
        index += 1;
        let key = keccak256(factory.create2(salt, hash));
        if key[0] >> 4 == x && key[0] & 0x0f != pair_second {
            return (a, b, salt);
        }
    }
}

fn destroy_call(chain: &mut Chain, factory: Address, salt: B256, initcode: &[u8]) -> Bytes {
    let mut data = entry(CREATE2, U256::from_be_bytes(salt.0), u(0));
    data.extend_from_slice(initcode);
    chain.call(factory, data.into())
}

// ---------------------------------------------------------------------------
// Account trie: removals that cascade over two levels in one block
// ---------------------------------------------------------------------------

/// Two funded, code-less leaves `a` and `b` meet in a branch at depth 6 under first
/// nibble `x`, and a third leaf `c` is their only other relative under `x`. One block
/// destroys both `a` and `b` (CREATE2 + SELFDESTRUCT in the constructor): the depth-6
/// branch disappears, and the depth-1 branch under `x` collapses onto the untouched
/// `c`, whose compact path must be merged. The generator exposes `c` only through the
/// key-order neighbours of the deleted keys, so this checks that the neighbours of a
/// run of deletions reach the survivor two levels up.
#[test]
fn b_two_account_removals_cascade_onto_an_untouched_account() {
    for spec in both_rules() {
        let mut chain = Chain::new(spec);
        let factory = chain.deploy_script();
        warm(&mut chain, 2);
        let initcode = destroying_initcode(0x77);
        let hash = keccak256(&initcode);
        let used = used_first_nibbles(&chain);
        // The beneficiary 0x77.. and the fee vaults may appear later; skip their nibbles.
        let mut reserved = used.clone();
        for extra in [Address::with_last_byte(0x77), chain.spec.base_fee_vault, chain.spec.sequencer_fee_vault] {
            reserved.insert(keccak256(extra)[0] >> 4);
        }
        let x = (0u8..16).find(|n| !reserved.contains(n)).expect("a free first nibble");
        let (salt_a, salt_b, salt_c) = mine_cascade(factory, &initcode, x);
        let (a, b, c) = (factory.create2(salt_a, hash), factory.create2(salt_b, hash), factory.create2(salt_c, hash));

        let pays = vec![chain.pay(a, 5), chain.pay(b, 6), chain.pay(c, 7)];
        let body = chain.body(pays);
        chain.check(&body, "fund the cascade");
        assert_eq!(
            chain
                .state
                .db()
                .cache
                .accounts
                .iter()
                .filter(|(address, account)| account_exists(account) && keccak256(address)[0] >> 4 == x)
                .count(),
            3,
            "exactly a, b and c live under nibble {x:x}"
        );

        let destroy_a = destroy_call(&mut chain, factory, salt_a, &initcode);
        let destroy_b = destroy_call(&mut chain, factory, salt_b, &initcode);
        let body = chain.body(vec![destroy_a, destroy_b]);
        let (witness, canonical, context) = chain.differential(&body, "two removals cascade onto c");
        assert!(canonical.transactions.iter().all(|tx| tx.success));

        // c must be exposed as a leaf of the account proof: the guest needs its path.
        let view = IndexedTrieView::from_proof(witness.prev_state_root, &witness.proof).unwrap();
        assert!(view.lookup(&account_key(&c)).unwrap().is_some(), "the survivor c is exposed");

        // A prover that hides c's node (keeping its hash in the parent) must be
        // refused, never given a root.
        let c_paths: Vec<Nibbles> = witness
            .proof
            .keys()
            .copied()
            .filter(|path| path.len() >= 2 && account_key(&c).starts_with(path))
            .collect();
        assert!(!c_paths.is_empty(), "c has a node of its own in the proof");
        for path in c_paths {
            let mut hidden = witness.clone();
            hidden.proof.remove(&path);
            match chain.verify(&hidden, &context, &body) {
                Err(_) => {}
                Ok(outcome) => assert_eq!(outcome.header, canonical.header, "hiding {path:?} changed the root"),
            }
        }
        chain.commit(&body);
        assert!(chain.state.account(&a).is_none() && chain.state.account(&b).is_none());
        assert_eq!(chain.state.balance_of(&c), u(7));

        // And c itself next, so that the whole subtree under x is gone.
        let destroy_c = destroy_call(&mut chain, factory, salt_c, &initcode);
        let body = chain.body(vec![destroy_c]);
        chain.check(&body, "the last leaf under x");
    }
}

// ---------------------------------------------------------------------------
// The post-state root claim cannot be steered by a deletion
// ---------------------------------------------------------------------------

/// On a block that deletes storage slots and an account, the claimed root of the
/// witness is replaced by the roots a cheating prover would want: the pre-state root
/// (deletions ignored), the root with the deleted account still present, and a root
/// off by one bit. All must be refused.
#[test]
fn b_a_deletion_block_cannot_claim_another_root() {
    let pair = &mined_slots(3, 1)[0];
    let mut chain = Chain::new(ChainSpec::mainnet_next_or_rehearsal());
    let factory = chain.deploy_script();
    let target = chain.deploy_script();
    let fill = vec![(SSTORE, u(pair[0]), u(1)), (SSTORE, u(pair[1]), u(2)), (SSTORE, u(77), u(3))];
    let tx = chain.call(target, script(&fill));
    let initcode = destroying_initcode(0x77);
    let salt = B256::repeat_byte(0x31);
    let doomed = factory.create2(salt, keccak256(&initcode));
    let pay = chain.pay(doomed, 5);
    let body = chain.body(vec![tx, pay]);
    chain.check(&body, "fill");

    let clear = chain.call(target, script(&[(SSTORE, u(pair[0]), u(0)), (SSTORE, u(77), u(0))]));
    let destroy = destroy_call(&mut chain, factory, salt, &initcode);
    let body = chain.body(vec![clear, destroy]);
    let (witness, canonical, context) = chain.differential(&body, "deletions");
    let honest = witness.new_state_root;
    assert_eq!(honest, canonical.header.state_root);
    for claim in [witness.prev_state_root, B256::ZERO, honest ^ B256::with_last_byte(1)] {
        let mut lying = witness.clone();
        lying.new_state_root = claim;
        match chain.verify(&lying, &context, &body) {
            Err(SparseNodeError::Verify(SparseVerifyError::ClaimedRootMismatch { derived, .. })) => {
                assert_eq!(derived, honest, "the guest derives the honest root regardless of the claim");
            }
            other => panic!("claim {claim} not refused as a mismatch: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The rule switch: the first next-rules block over a v1 state
// ---------------------------------------------------------------------------

/// A chain runs the pinned v1 rules, so its fee vaults are plain code-less accounts
/// with balances, then switches to the next rules. The first next-rules block installs
/// the sweep at both vaults, and in the same block users sweep both and pay a vault
/// again. The sparse statement must equal the complete one byte for byte, the vaults
/// keep their balance until swept, and their nonce becomes 1.
#[test]
fn b_the_first_next_rules_block_over_a_v1_state_installs_and_sweeps() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let script_address = chain.deploy_script();
    for _ in 0..3 {
        let tx = chain.call(script_address, script(&[(SSTORE, u(1), u(2)), (SLOAD, u(1), u(0))]));
        let body = chain.body(vec![tx]);
        chain.check(&body, "v1 fees");
    }
    let (base, sequencer) = (chain.spec.base_fee_vault, chain.spec.sequencer_fee_vault);
    let before: Vec<U256> = [base, sequencer].iter().map(|vault| chain.state.balance_of(vault)).collect();
    assert!(before.iter().any(|balance| !balance.is_zero()), "v1 fees reached a vault");
    for vault in [base, sequencer] {
        if let Some(account) = chain.state.account(&vault) {
            assert_eq!(account.code_hash, revm::primitives::KECCAK_EMPTY, "no code under v1");
        }
    }

    chain.spec = ChainSpec::mainnet_next_or_rehearsal();
    // The first next-rules block: a deposit, a sweep of each vault, and a payment to one.
    let a = chain.call(base, Bytes::new());
    let b = chain.call(sequencer, Bytes::new());
    let c = chain.call(script_address, script(&[(BALANCE, word_of(base), u(0)), (CALL, word_of(sequencer), u(5))]));
    let body = chain.body(vec![a, b, c]);
    let (witness, canonical, _) = chain.differential(&body, "first next-rules block");
    assert!(canonical.transactions.iter().all(|tx| tx.success), "every sweep succeeds in the install block");
    // The vault code is installed by the protocol, not loaded from the witness.
    let sweep_hash = keccak256(fee_vault_sweep_code(chain.spec.fee_vault_sweep.expect("the next rules sweep")));
    assert!(
        witness.codes.iter().all(|code| keccak256(code) != sweep_hash),
        "the install block needs no sweep code in the witness"
    );
    chain.commit(&body);
    for vault in [base, sequencer] {
        let account = chain.state.account(&vault).expect("vault exists");
        assert_eq!(account.code_hash, sweep_hash);
        assert_eq!(account.nonce, 1);
    }
    assert!(!chain.state.balance_of(&chain.spec.fee_vault_sweep.unwrap()).is_zero());

    // The second block loads the installed code from the witness's code list.
    let a = chain.call(base, Bytes::new());
    let body = chain.body(vec![a]);
    let (witness, _, _) = chain.differential(&body, "second next-rules block");
    assert!(witness.codes.iter().any(|code| keccak256(code) == sweep_hash), "the sweep code is witnessed by hash");
    chain.commit(&body);
}

// ---------------------------------------------------------------------------
// Release gates on the sweep recipient (expected to FAIL today)
// ---------------------------------------------------------------------------

/// GATE. The next mainnet rules compile the fee-sweep recipient into the program and
/// its configuration commitment. Today that recipient is the placeholder
/// `0x…000fee01`, an address nobody holds a key or code for. Because the sweep is
/// permissionless, anyone could move every accumulated fee there, irrecoverably, the
/// moment a program built with it is activated. Nothing in the crate fails closed on
/// it. This test fails until the owner sets the real recipient.
#[test]
fn gate_next_rules_do_not_carry_the_placeholder_sweep_recipient() {
    let placeholder = crate::chainspec::REHEARSAL_FEE_SWEEP_RECIPIENT; // 0x…000fee01
    assert_ne!(
        ChainSpec::mainnet().fee_vault_sweep,
        Some(placeholder),
        "ChainSpec::mainnet() still sweeps the fee vaults to the placeholder 0x...fee01 (TBD-owner)"
    );
}

/// GATE (hardening). `ChainSpec::validate` refuses a sweep recipient that collides with
/// a system address, but accepts one that burns: the zero address and the Cancun
/// precompiles 0x01 to 0x0a, where no one can ever spend what the sweep sends. The
/// configuration commitment then hashes such a recipient without complaint.
#[test]
fn gate_validate_refuses_a_burning_sweep_recipient() {
    let mut accepted = Vec::new();
    let candidates = core::iter::once(Address::ZERO).chain((1u8..=0x0a).map(Address::with_last_byte));
    for recipient in candidates {
        let spec = ChainSpec {
            fee_vault_sweep: Some(recipient),
            ..ChainSpec::mainnet()
        };
        if spec.validate().is_ok() {
            accepted.push(recipient);
        }
    }
    assert!(accepted.is_empty(), "validate accepts burning sweep recipients: {accepted:?}");
}

// ---------------------------------------------------------------------------
// Storage trie: the same two-level cascade
// ---------------------------------------------------------------------------

/// Slots `a`, `b` share three key bytes under first nibble `x`, `c` shares only `x`.
fn mine_storage_cascade(x: u8, avoid: &BTreeSet<u64>) -> (u64, u64, u64) {
    let mut seen: BTreeMap<[u8; 3], u64> = BTreeMap::new();
    let mut slot = 10_000_000u64;
    let (a, b) = loop {
        slot += 1;
        if avoid.contains(&slot) {
            continue;
        }
        let key = keccak256(U256::from(slot).to_be_bytes::<32>());
        if key[0] >> 4 != x {
            continue;
        }
        let prefix = [key[0], key[1], key[2]];
        if let Some(other) = seen.get(&prefix) {
            break (*other, slot);
        }
        seen.insert(prefix, slot);
    };
    let second = keccak256(U256::from(a).to_be_bytes::<32>())[0] & 0x0f;
    loop {
        slot += 1;
        let key = keccak256(U256::from(slot).to_be_bytes::<32>());
        if key[0] >> 4 == x && key[0] & 0x0f != second {
            return (a, b, slot);
        }
    }
}

/// Storage version of the account cascade: one block deletes `a` and `b`; the branch
/// under `x` collapses onto the untouched `c`. Hiding `c`'s node must be refused.
#[test]
fn b_two_slot_deletions_cascade_onto_an_untouched_slot() {
    for spec in both_rules() {
        let mut chain = Chain::new(spec);
        let target = chain.deploy_script();
        let filler: Vec<u64> = (1..=40).collect();
        let used: BTreeSet<u8> = filler.iter().map(|slot| keccak256(U256::from(*slot).to_be_bytes::<32>())[0] >> 4).collect();
        let x = (0u8..16).find(|n| !used.contains(n)).expect("40 slots leave a first nibble free");
        let (a, b, c) = mine_storage_cascade(x, &filler.iter().copied().collect());
        let mut fill: Vec<(u64, U256, U256)> = filler.iter().map(|slot| (SSTORE, u(*slot), u(9))).collect();
        fill.extend([(SSTORE, u(a), u(1)), (SSTORE, u(b), u(2)), (SSTORE, u(c), u(3))]);
        let tx = chain.call(target, script(&fill));
        let body = chain.body(vec![tx]);
        chain.check(&body, "fill the storage cascade");

        let first = chain.call(target, script(&[(SSTORE, u(a), u(0))]));
        let second = chain.call(target, script(&[(SSTORE, u(b), u(0))]));
        let body = chain.body(vec![first, second]);
        let (witness, canonical, context) = chain.differential(&body, "two slot deletions cascade onto c");
        let index = account(&witness, target);
        let storage = &witness.pre_accounts[index];
        let view = IndexedTrieView::from_proof(storage.storage_root, &storage.storage_proof).unwrap();
        assert!(view.lookup(&storage_key(&u(c))).unwrap().is_some(), "the surviving slot c is exposed");
        let c_key = storage_key(&u(c));
        let c_paths: Vec<Nibbles> =
            storage.storage_proof.keys().copied().filter(|path| path.len() >= 2 && c_key.starts_with(path)).collect();
        assert!(!c_paths.is_empty(), "c has a node of its own in the storage proof");
        for path in c_paths {
            let mut hidden = witness.clone();
            hidden.pre_accounts[index].storage_proof.remove(&path);
            match chain.verify(&hidden, &context, &body) {
                Err(_) => {}
                Ok(outcome) => assert_eq!(outcome.header, canonical.header, "hiding {path:?} changed the root"),
            }
        }
        chain.commit(&body);
        assert_eq!(chain.state.storage_of(&target, u(c)), u(3));
        assert_eq!(chain.state.storage_of(&target, u(a)), u(0));
    }
}

fn account(witness: &SparseBatchWitness, address: Address) -> usize {
    witness.pre_accounts.iter().position(|entry| entry.address == address).expect("account in the witness")
}

// ---------------------------------------------------------------------------
// The sweep's failure paths
// ---------------------------------------------------------------------------

/// The sweep with a recipient that always reverts (`PUSH0 PUSH0 REVERT`), reached by a
/// direct call, by STATICCALL (value in a static frame), and by DELEGATECALL (the
/// caller's own balance is sent). The vault keeps its balance on every failure, and
/// the sparse statement equals the complete one.
#[test]
fn b_sweep_failure_paths_agree() {
    let reverting = [0x5f, 0x5f, 0xfd];
    // The first contract the harness sender deploys: its nonce is 0 after genesis.
    let probe = Chain::new(ChainSpec::mainnet_next_or_rehearsal());
    let recipient = probe.sender.create(0);
    let spec = ChainSpec {
        fee_vault_sweep: Some(recipient),
        ..ChainSpec::mainnet_next_or_rehearsal()
    };
    spec.validate().unwrap();
    let mut chain = Chain::new(spec);
    let tx = chain.tx(TxKind::Create, U256::ZERO, deploy_code(&reverting).into(), 300_000);
    let body = chain.body(vec![tx]);
    let outcome = chain.check(&body, "deploy the reverting recipient");
    assert!(outcome.transactions[0].success);
    assert_eq!(chain.state.account(&recipient).unwrap().code_hash, keccak256(reverting));
    let script_address = chain.deploy_script();
    let (base, sequencer) = (chain.spec.base_fee_vault, chain.spec.sequencer_fee_vault);
    // A plain 21,000-gas payment cannot run the script's code; give it room.
    let funded = chain.tx(TxKind::Call(script_address), u(1_000), Bytes::new(), 100_000);
    let body = chain.body(vec![funded]);
    let outcome = chain.check(&body, "fees accrue");
    assert!(outcome.transactions[0].success);
    assert_eq!(chain.state.balance_of(&script_address), u(1_000));
    let before = chain.state.balance_of(&base);
    assert!(!before.is_zero());

    let direct = chain.call(base, Bytes::new());
    let via = chain.call(
        script_address,
        script(&[
            (STATICCALL, word_of(sequencer), u(0)),
            (DELEGATECALL, word_of(base), u(0)),
            (CALL, word_of(base), u(0)),
        ]),
    );
    let body = chain.body(vec![direct, via]);
    let (_, canonical, _) = chain.differential(&body, "sweep failures");
    assert!(!canonical.transactions[0].success, "a direct sweep to a reverting recipient reverts");
    assert!(canonical.transactions[1].success, "the script survives its inner failures");
    for log in 0..3 {
        assert_eq!(Chain::logged_word(&canonical, 1, log), u(0), "inner sweep {log} fails");
    }
    chain.commit(&body);
    assert!(chain.state.balance_of(&base) >= before, "the vault kept its balance");
    assert_eq!(chain.state.balance_of(&recipient), u(0));
    assert_eq!(chain.state.balance_of(&script_address), u(1_000));
}
