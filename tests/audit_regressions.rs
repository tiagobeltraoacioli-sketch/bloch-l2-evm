// SPDX-License-Identifier: MIT OR Apache-2.0
//! Testes de regressão da auditoria profunda (ver `AUDITORIA-L2.md`).
//!
//! Cada módulo corresponde a um achado (C01..C31). Os achados **corrigidos**
//! (P0 da seção 8: C01–C10, C12, C18–C25, C29, C30) têm testes ativos que
//! afirmam o comportamento correto e passam. Os achados ainda abertos (C11,
//! C13, C15, C16, C17, C26, C27, C28, C31) continuam marcados `#[ignore]`: seus
//! testes afirmam o comportamento esperado após a correção e falham hoje.
//!
//! ```sh
//! cargo test --test audit_regressions              # achados corrigidos
//! cargo test --test audit_regressions -- --ignored # achados ainda abertos (esperado: falhas)
//! ```
//!
//! Audit regression tests (see `AUDITORIA-L2.md`). Fixed findings have live
//! tests; open findings are `#[ignore]`d and fail until fixed.
#![allow(clippy::all)]

mod common {
    #![allow(dead_code)]
    use alloy_primitives::{address, Address, TxKind, U256};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::{execute_block, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State};
    use revm::context::TxEnv;
    use std::sync::atomic::{AtomicU32, Ordering};

    pub const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    pub const BOB: Address = address!("0000000000000000000000000000000000000b0b");
    pub const CAROL: Address = address!("00000000000000000000000000000000000ca201");
    pub const GWEI: u128 = 1_000_000_000;
    pub const BLCH: u64 = SATS_PER_BLCH;

    static NEXT_VOUT: AtomicU32 = AtomicU32::new(1);

    /// A deposit with a process-unique L1 outpoint.
    pub fn deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_txid: [0xAB; 32],
                l1_vout: NEXT_VOUT.fetch_add(1, Ordering::Relaxed),
                l1_sats,
            },
        }
    }

    pub fn addr(i: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = i;
        Address::from(b)
    }

    /// EIP-1559 transfer at basefee + 1 gwei.
    pub fn transfer(from: Address, to: Address, nonce: u64, value: U256, gas_limit: u64) -> TxEnv {
        let spec = ChainSpec::testnet();
        TxEnv::builder()
            .caller(from)
            .kind(TxKind::Call(to))
            .value(value)
            .gas_limit(gas_limit)
            .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx env")
    }

    pub fn call_data(from: Address, to: Address, nonce: u64, data: alloy_primitives::Bytes, gas_limit: u64) -> TxEnv {
        let spec = ChainSpec::testnet();
        TxEnv::builder()
            .caller(from)
            .kind(TxKind::Call(to))
            .data(data)
            .gas_limit(gas_limit)
            .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx env")
    }

    pub fn create(from: Address, nonce: u64, initcode: Vec<u8>, gas_limit: u64) -> TxEnv {
        let spec = ChainSpec::testnet();
        TxEnv::builder()
            .caller(from)
            .kind(TxKind::Create)
            .data(initcode.into())
            .gas_limit(gas_limit)
            .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx env")
    }

    /// Initcode that deploys `runtime` verbatim (CODECOPY + RETURN).
    pub fn deployer(runtime: &[u8]) -> Vec<u8> {
        let len = runtime.len() as u8;
        let mut initcode = vec![0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3];
        initcode.extend_from_slice(runtime);
        initcode
    }

    pub fn block(number: u64, deposits: Vec<DepositMint>, txs: Vec<TxEnv>) -> BlockInput {
        BlockInput { context: BlockContext { number, ..Default::default() }, deposits, txs }
    }

    /// Pre-state with accounts 0x..01 ..= 0x..n funded with 5 BLCH each (block 0).
    pub fn funded(n: u8) -> L2State {
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        execute_block(&spec, &mut pre, block(0, (1..=n).map(|i| deposit(addr(i), 5 * BLCH)).collect(), vec![])).unwrap();
        pre
    }

    /// Everything an error must leave untouched.
    pub fn fingerprint(state: &L2State) -> (alloy_primitives::B256, U256, U256, usize) {
        (
            bloch_l2_evm::compute_keccak_mpt_state_root(state),
            state.total_native_wei(),
            state.total_minted_wei(),
            state.db.cache.accounts.len(),
        )
    }

    pub fn wei(blch: u64) -> U256 {
        sats_to_wei(blch * BLCH)
    }
}

/// C01 [critical, FIXED] — execute_block used to erase the entire state on any
/// transaction error; now the caller's state is byte-identical after every `Err`.
mod c01 {
    use super::common::*;
    use alloy_primitives::U256;
    use alloy_trie::EMPTY_ROOT_HASH;
    use bloch_l2_evm::{execute_block, BlockExecutionError, ChainSpec, L2State};

    #[test]
    fn failed_block_leaves_state_unchanged() {
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        execute_block(&spec, &mut st, block(1, vec![deposit(ALICE, 10 * BLCH), deposit(CAROL, 5 * BLCH)], vec![])).unwrap();
        execute_block(&spec, &mut st, block(2, vec![], vec![transfer(ALICE, BOB, 0, wei(1), 21_000)])).unwrap();
        let before = fingerprint(&st);
        assert_ne!(before.0, EMPTY_ROOT_HASH);
        assert_eq!(st.nonce_of(&ALICE), 1);

        // Evm error at index 1 after a valid tx 0 and a deposit.
        let err = execute_block(
            &spec,
            &mut st,
            block(3, vec![deposit(BOB, BLCH)], vec![transfer(ALICE, BOB, 1, U256::ZERO, 21_000), transfer(ALICE, BOB, 7, U256::ZERO, 21_000)]),
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 1, .. }));
        assert_eq!(fingerprint(&st), before, "state must be untouched after an Evm error");
        assert_eq!(st.nonce_of(&ALICE), 1);
        assert_eq!(st.balance_of(&CAROL), wei(5), "untouched accounts survive");

        // Block gas limit exceeded at index 1.
        let err = execute_block(
            &spec,
            &mut st,
            block(3, vec![], vec![transfer(ALICE, BOB, 1, U256::ZERO, 21_000), transfer(ALICE, BOB, 2, U256::ZERO, spec.gas_limit)]),
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlockGasLimitExceeded { tx_index: 1 }));
        assert_eq!(fingerprint(&st), before);

        // Other revm pre-validation errors.
        for bad in [
            transfer(ALICE, BOB, 1, wei(100), 21_000), // insufficient funds
            {
                let mut t = transfer(ALICE, BOB, 1, U256::ZERO, 21_000);
                t.chain_id = Some(1);
                t
            },
            {
                let mut t = transfer(ALICE, BOB, 1, U256::ZERO, 21_000);
                t.gas_price = 1;
                t.gas_priority_fee = Some(0);
                t
            },
        ] {
            let err = execute_block(&spec, &mut st, block(3, vec![], vec![bad])).unwrap_err();
            assert!(matches!(err, BlockExecutionError::Evm { tx_index: 0, .. }), "{err}");
            assert_eq!(fingerprint(&st), before);
        }

        // The nonce-0 transfer already included in block 2 can never be replayed.
        let err = execute_block(&spec, &mut st, block(3, vec![], vec![transfer(ALICE, BOB, 0, wei(1), 21_000)])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 0, .. }));
        assert_eq!(fingerprint(&st), before);
        assert_eq!(st.total_native_wei(), st.total_minted_wei());
    }
}

/// C02 [high, FIXED] — deposits are no longer applied before validation; a
/// rejected block leaves nothing minted and cannot double-mint on retry.
mod c02 {
    use super::common::*;
    use alloy_primitives::{TxKind, B256, U256};
    use bloch_l2_evm::{execute_block, BlockExecutionError, ChainSpec, L2State};
    use revm::context::TxEnv;

    #[test]
    fn failed_block_is_atomic_and_never_double_mints_its_deposits() {
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        let before = fingerprint(&st);
        let dep = deposit(BOB, 3 * BLCH);

        let blob_tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(2 * GWEI)
            .gas_priority_fee(Some(GWEI))
            .blob_hashes(vec![B256::repeat_byte(1)])
            .max_fee_per_blob_gas(1)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build_fill();
        let err = execute_block(&spec, &mut st, block(1, vec![dep], vec![blob_tx])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlobTxRejected { tx_index: 0 }));
        assert_eq!(fingerprint(&st), before, "rejected block applied no deposit");
        assert_eq!(st.balance_of(&BOB), U256::ZERO);

        // Re-proposing the block without the offending tx mints exactly once.
        let out = execute_block(&spec, &mut st, block(1, vec![dep], vec![])).unwrap();
        assert_eq!(out.minted_wei, wei(3));
        assert_eq!(st.balance_of(&BOB), wei(3));
        assert_eq!(st.total_minted_wei(), wei(3));

        // A duplicate outpoint inside one block applies nothing at all.
        let after = fingerprint(&st);
        let d2 = deposit(ALICE, BLCH);
        let err = execute_block(&spec, &mut st, block(2, vec![d2, d2], vec![])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::DuplicateDeposit { first_index: 0, second_index: 1 }));
        assert_eq!(fingerprint(&st), after);
        assert_eq!(st.balance_of(&ALICE), U256::ZERO);

        // Gas-limit rejection after deposits: deposits rolled back, ledger too.
        let err = execute_block(&spec, &mut st, block(2, vec![d2], vec![transfer(BOB, ALICE, 0, U256::ZERO, spec.gas_limit + 1)])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::TxGasLimitExceedsBlock { tx_index: 0 }));
        assert_eq!(fingerprint(&st), after);
        assert_eq!(st.total_native_wei(), st.total_minted_wei());
    }
}

/// C03 [high, FIXED] — only tx types 0/1/2 reach revm; a zero-priced custom
/// type can neither execute nor mint an unpaid basefee into the vault.
mod c03 {
    use super::common::*;
    use alloy_primitives::U256;
    use bloch_l2_evm::{execute_block, BlockExecutionError, ChainSpec, L2State, SUPPORTED_TX_TYPES};

    #[test]
    fn c03_unsupported_tx_types_are_rejected_and_never_inflate_supply() {
        assert_eq!(SUPPORTED_TX_TYPES, [0, 1, 2]);
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        execute_block(&spec, &mut st, block(1, vec![deposit(ALICE, 10 * BLCH)], vec![])).unwrap();
        let before = fingerprint(&st);
        let minted = st.total_minted_wei();

        for tx_type in [3u8, 4, 5, 0x10, 0x7E, 0xFF] {
            let mut t = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
            t.tx_type = tx_type;
            t.gas_price = 0;
            t.gas_priority_fee = None;
            let res = execute_block(&spec, &mut st, block(2, vec![], vec![t]));
            assert!(res.is_err(), "zero-priced type {tx_type:#x} must be rejected");
            assert!(matches!(
                res.unwrap_err(),
                BlockExecutionError::UnsupportedTxType { .. } | BlockExecutionError::BlobTxRejected { .. }
            ));
            assert_eq!(fingerprint(&st), before);
        }
        assert_eq!(st.total_native_wei(), minted, "supply was not inflated");
        assert_eq!(st.balance_of(&spec.base_fee_vault), U256::ZERO, "BaseFeeVault received nothing");
    }
}

/// C04 [critical, FIXED] — the multiproof is authenticated against
/// prev_state_root node by node; injected or tampered nodes are rejected.
mod c04 {
    use super::common::*;
    use alloy_primitives::{keccak256, B256};
    use alloy_trie::nodes::LeafNode;
    use alloy_trie::{Nibbles, EMPTY_ROOT_HASH};
    use bloch_l2_evm::{
        generate_batch_witness, hydrate_and_verify, stateless_new_root, verify_batch, ChainSpec, SparseTrieView, VerifyError,
        WitnessError,
    };
    use std::collections::BTreeMap;

    #[test]
    fn injected_proof_node_must_not_forge_new_state_root() {
        let spec = ChainSpec::testnet();
        let pre = funded(12);
        let batch = block(1, vec![], vec![transfer(addr(1), addr(7), 0, wei(1), 21_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        verify_batch(&spec, &w, &batch).expect("honest witness verifies");

        let view = SparseTrieView::from_proof(w.prev_state_root, &w.proof).unwrap();
        let (frontier, _) = view.frontier().first().copied().expect("opaque siblings exist");

        // (a) phantom leaf injected at an opaque frontier path.
        let mut injected = w.clone();
        let rest = Nibbles::from_nibbles(vec![0u8; 64 - frontier.len()]);
        injected.proof.insert(frontier, alloy_rlp::encode(&LeafNode::new(rest, vec![0xc0])).into());
        assert!(matches!(hydrate_and_verify(&injected), Err(VerifyError::Witness(WitnessError::UnanchoredNode { .. }))));
        assert!(matches!(
            stateless_new_root(w.prev_state_root, &injected.proof, &BTreeMap::new()),
            Err(WitnessError::UnanchoredNode { .. })
        ));

        // (b) tampered exposed node bytes.
        let mut tampered = w.clone();
        let (deepest, bytes) = tampered.proof.iter().max_by_key(|(p, _)| p.len()).map(|(p, b)| (*p, b.clone())).unwrap();
        let mut b = bytes.to_vec();
        let last = b.len() - 1;
        b[last] ^= 0x01;
        tampered.proof.insert(deepest, b.into());
        assert!(hydrate_and_verify(&tampered).is_err());

        // (c) empty proof against a non-empty root; wrong root.
        let mut empty = w.clone();
        empty.proof.clear();
        assert!(matches!(
            hydrate_and_verify(&empty),
            Err(VerifyError::Witness(WitnessError::EmptyProofForNonEmptyRoot { .. }))
        ));
        assert!(matches!(
            stateless_new_root(B256::repeat_byte(0x77), &w.proof, &BTreeMap::new()),
            Err(WitnessError::RootMismatch { .. })
        ));
        assert_eq!(stateless_new_root(EMPTY_ROOT_HASH, &BTreeMap::new(), &BTreeMap::new()), Ok(EMPTY_ROOT_HASH));
        let _ = keccak256([0u8]);
    }
}

/// C05 [high, FIXED] — an omitted existing account fails the guest's read
/// instead of being read as empty; lying that it is absent is caught.
mod c05 {
    use super::common::*;
    use bloch_l2_evm::{generate_batch_witness, hydrate_and_verify, verify_batch, BlockExecutionError, ChainSpec, VerifyError};

    #[test]
    fn omitted_existing_touched_pre_account_must_be_rejected_or_not_change_execution() {
        let spec = ChainSpec::testnet();
        let pre = funded(30);
        let (alice, bob) = (addr(3), addr(7));
        let batch = block(1, vec![], vec![transfer(alice, bob, 0, wei(1), 21_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        assert!(w.pre_accounts.iter().any(|a| a.address == bob));

        let mut omitted = w.clone();
        omitted.pre_accounts.retain(|a| a.address != bob);
        match verify_batch(&spec, &omitted, &batch) {
            Err(VerifyError::Execution(BlockExecutionError::Evm { .. }))
            | Err(VerifyError::Execution(BlockExecutionError::Database { .. })) => {}
            other => panic!("guest must fail the unwitnessed read, got {other:?}"),
        }

        let mut lied = omitted.clone();
        lied.absent_accounts.push(bob);
        lied.absent_accounts.sort();
        assert!(matches!(hydrate_and_verify(&lied), Err(VerifyError::AccountNotProvenAbsent(a)) if a == bob));

        // Omitting the sender is equally rejected.
        let mut no_sender = w.clone();
        no_sender.pre_accounts.retain(|a| a.address != alice);
        assert!(verify_batch(&spec, &no_sender, &batch).is_err());
    }
}

/// C06 [high, FIXED] — read-only accounts are part of the witness access set,
/// so the guest replay matches the host bit for bit.
mod c06 {
    use super::common::*;
    use alloy_primitives::{Bytes, U256};
    use bloch_l2_evm::{compute_keccak_mpt_state_root, execute_block, generate_batch_witness, verify_batch, ChainSpec};

    #[test]
    fn witness_access_set_covers_read_only_accounts_so_guest_replay_matches_host() {
        let spec = ChainSpec::testnet();
        let mut pre = funded(20);
        let (alice, d) = (addr(1), addr(9));
        // runtime: PUSH20 D, BALANCE, PUSH1 0, SSTORE, STOP
        let mut runtime = vec![0x73u8];
        runtime.extend_from_slice(d.as_slice());
        runtime.extend_from_slice(&[0x31, 0x60, 0x00, 0x55, 0x00]);
        let out = execute_block(&spec, &mut pre, block(1, vec![], vec![create(alice, 0, deployer(&runtime), 200_000)])).unwrap();
        let contract = out.tx_outcomes[0].created_address.unwrap();

        let batch = block(2, vec![], vec![call_data(alice, contract, 1, Bytes::new(), 100_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).expect("generates");
        assert!(w.pre_accounts.iter().any(|a| a.address == d), "read-only BALANCE target is in the witness");
        let verified = verify_batch(&spec, &w, &batch).expect("guest verifies");
        let mut full = pre.clone();
        execute_block(&spec, &mut full, batch).unwrap();
        assert_eq!(verified.new_state_root, compute_keccak_mpt_state_root(&full));
        assert_eq!(full.db.cache.accounts[&contract].storage[&U256::ZERO], wei(5));
    }
}

/// C07 [high, FIXED] — honest witnesses for zero-value calls that SLOAD an
/// empty slot or SSTORE 0->0 are accepted by the guest.
mod c07 {
    use super::common::*;
    use alloy_primitives::Bytes;
    use bloch_l2_evm::{compute_keccak_mpt_state_root, execute_block, generate_batch_witness, verify_batch, ChainSpec};

    fn run(runtime: &[u8]) {
        let spec = ChainSpec::testnet();
        let mut pre = funded(60);
        let alice = addr(1);
        let out = execute_block(&spec, &mut pre, block(1, vec![], vec![create(alice, 0, deployer(runtime), 200_000)])).unwrap();
        let contract = out.tx_outcomes[0].created_address.unwrap();
        let batch = block(2, vec![], vec![call_data(alice, contract, 1, Bytes::new(), 100_000)]);
        let (w, outcome) = generate_batch_witness(&pre, &spec, batch.clone()).expect("generates");
        assert!(outcome.tx_outcomes[0].success);
        let verified = verify_batch(&spec, &w, &batch).expect("honest witness opens");
        let mut full = pre.clone();
        execute_block(&spec, &mut full, batch).unwrap();
        assert_eq!(verified.new_state_root, compute_keccak_mpt_state_root(&full));
    }

    #[test]
    fn c07_honest_witness_opens_for_sload_of_empty_slot() {
        run(&[0x60, 0x00, 0x54, 0x00]); // PUSH1 0 SLOAD STOP
    }

    #[test]
    fn c07_honest_witness_opens_for_sstore_zero_to_zero() {
        run(&[0x60, 0x00, 0x60, 0x00, 0x55, 0x00]); // PUSH1 0 PUSH1 0 SSTORE STOP
    }
}

/// C08 [high, FIXED] — a change inside an opaque subtree is an error, never a
/// silently wrong root; a proof stripped under a created account is rejected.
mod c08 {
    use super::common::*;
    use alloy_primitives::keccak256;
    use alloy_trie::Nibbles;
    use bloch_l2_evm::{generate_batch_witness, hydrate_and_verify, verify_batch, ChainSpec, SparseTrieView, WitnessError};
    use std::collections::BTreeMap;

    #[test]
    fn stateless_new_root_refuses_a_change_inside_an_opaque_subtree() {
        let spec = ChainSpec::testnet();
        let pre = funded(20);
        let bob = alloy_primitives::address!("000000000000000000000000000000000000bb11");
        let batch = block(1, vec![], vec![transfer(addr(2), bob, 0, wei(1), 21_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        verify_batch(&spec, &w, &batch).unwrap();

        // Strip every node under bob's root-child subtree.
        let bob_path = Nibbles::unpack(keccak256(bob));
        let mut stripped = w.clone();
        stripped.proof.retain(|p, _| p.is_empty() || !bob_path.starts_with(p));
        assert!(stripped.proof.len() < w.proof.len());
        assert!(hydrate_and_verify(&stripped).is_err(), "bob can no longer be proven absent");

        // Direct: a change key under an opaque frontier is an error.
        let view = SparseTrieView::from_proof(w.prev_state_root, &w.proof).unwrap();
        let (frontier, _) = view.frontier().first().copied().expect("opaque siblings");
        let mut hidden = frontier;
        while hidden.len() < 64 {
            hidden.push(0);
        }
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(hidden, None);
        assert!(matches!(view.apply(&changes), Err(WitnessError::KeyInOpaqueSubtree { .. })));
        changes.insert(hidden, Some(vec![0xc0]));
        assert!(matches!(view.apply(&changes), Err(WitnessError::KeyInOpaqueSubtree { .. })));
    }
}

/// C09 [high, FIXED] — the guest derives the change set itself; the host's
/// claimed root is checked, never trusted.
mod c09 {
    use super::common::*;
    use alloy_primitives::B256;
    use bloch_l2_evm::{compute_keccak_mpt_state_root, execute_block, generate_batch_witness, verify_batch, ChainSpec, VerifyError};

    #[test]
    fn c09_guest_post_root_must_not_depend_on_host_supplied_changes() {
        let spec = ChainSpec::testnet();
        let pre = funded(8);
        let batch = block(1, vec![], vec![transfer(addr(1), addr(5), 0, wei(2), 21_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        // The witness carries no host-asserted change set at all.
        let _: &[bloch_l2_evm::WitnessAccount] = &w.pre_accounts;
        let mut full = pre.clone();
        execute_block(&spec, &mut full, batch.clone()).unwrap();
        assert_eq!(verify_batch(&spec, &w, &batch).unwrap().new_state_root, compute_keccak_mpt_state_root(&full));

        // A forged claim is rejected because the guest derives its own root.
        let mut claim = w.clone();
        claim.new_state_root = B256::repeat_byte(0x42);
        assert!(matches!(verify_batch(&spec, &claim, &batch), Err(VerifyError::ClaimedRootMismatch { .. })));
    }
}

/// C10 [high, FIXED] — every L1 outpoint mints at most once, and the consumed
/// set is committed in the state root.
mod c10 {
    use super::common::*;
    use bloch_l2_evm::{compute_keccak_mpt_state_root, execute_block, BlockExecutionError, ChainSpec, DepositError, L2State};

    #[test]
    fn deposit_outpoint_cannot_be_minted_twice() {
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        let dep = deposit(ALICE, BLCH);
        assert!(matches!(
            execute_block(&spec, &mut st, block(1, vec![dep, dep], vec![])),
            Err(BlockExecutionError::DuplicateDeposit { .. })
        ));
        execute_block(&spec, &mut st, block(1, vec![dep], vec![])).unwrap();
        let root = compute_keccak_mpt_state_root(&st);
        for n in 2..5 {
            assert!(matches!(
                execute_block(&spec, &mut st, block(n, vec![dep], vec![])),
                Err(BlockExecutionError::Deposit(DepositError::Replay { .. }))
            ));
            assert_eq!(compute_keccak_mpt_state_root(&st), root);
        }
        assert_eq!(st.balance_of(&ALICE), wei(1));
        let (txid, vout) = dep.outpoint();
        assert!(st.is_deposit_consumed(&txid, vout));

        // The consumed set is committed: same balances, different outpoints -> different roots.
        let mut a = L2State::new();
        execute_block(&spec, &mut a, block(1, vec![deposit(ALICE, BLCH)], vec![])).unwrap();
        let mut b = L2State::new();
        execute_block(&spec, &mut b, block(1, vec![deposit(ALICE, BLCH)], vec![])).unwrap();
        assert_eq!(a.balance_of(&ALICE), b.balance_of(&ALICE));
        assert_ne!(compute_keccak_mpt_state_root(&a), compute_keccak_mpt_state_root(&b));
    }
}

/// C12 [high, FIXED] — EIP-161-empty pre-accounts (with or without planted
/// storage) are rejected; an empty witness only opens the empty root.
mod c12 {
    use super::common::*;
    use alloy_primitives::{address, B256, U256};
    use alloy_trie::Nibbles;
    use bloch_l2_evm::{generate_batch_witness, hydrate_and_verify, BatchWitness, ChainSpec, VerifyError, WitnessAccount, WitnessError};
    use std::collections::BTreeMap;

    #[test]
    fn hydrate_and_verify_rejects_unverified_eip161_empty_accounts_with_storage() {
        let spec = ChainSpec::testnet();
        let pre = funded(8);
        let batch = block(1, vec![], vec![transfer(addr(1), BOB, 0, wei(1), 21_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch).unwrap();

        let mut ghost = w.clone();
        ghost.pre_accounts.push(WitnessAccount {
            address: address!("00000000000000000000000000000000deadbeef"),
            balance: U256::ZERO,
            nonce: 0,
            code: vec![],
            storage: vec![(U256::from(1u64), U256::from(0xdead_u64))],
        });
        ghost.pre_accounts.sort_by(|a, b| a.address.cmp(&b.address));
        assert!(matches!(hydrate_and_verify(&ghost), Err(VerifyError::EmptyAccount(_))));

        let mut garbage: BTreeMap<Nibbles, alloy_primitives::Bytes> = BTreeMap::new();
        garbage.insert(Nibbles::default(), vec![0xde, 0xad].into());
        let empty = BatchWitness {
            prev_state_root: B256::repeat_byte(0x42),
            new_state_root: B256::ZERO,
            proof: garbage,
            pre_accounts: vec![],
            absent_accounts: vec![],
        };
        assert!(matches!(hydrate_and_verify(&empty), Err(VerifyError::Witness(WitnessError::RootMismatch { .. }))));
    }
}

/// C11 [medium] — EIP-6780 SELFDESTRUCT-to-self in the creating transaction burns bridged BLCH: the documented "never burned / total native supply == total minted / L1 escrow always balances" invariant is false under unmodified Cancun revm and is untested
mod c11 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // Fix-tracking test for C11. Asserts the invariant the crate documented
    // (bridged BLCH is never burned, so total native supply == total minted). It
    // FAILS under unmodified Cancun revm because EIP-6780 SELFDESTRUCT-to-self in
    // the creating tx zeroes the balance without crediting anyone. If the chosen
    // fix is to document the burn and add `L2State::total_burned_wei()` instead of
    // re-routing, change the final assertion to
    // `total_native_wei == total_minted_wei - total_burned_wei` and assert
    // `total_burned_wei == value`.
    use super::common::*;
    use alloy_primitives::{address, bytes, Address, TxKind, U256};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::{execute_block, BlockContext, BlockInput, ChainSpec, L2State};
    use revm::context::TxEnv;

    #[test]
    #[ignore = "C11: EIP-6780 selfdestruct-to-self burns bridged BLCH; 'never burn' invariant is false"]
    fn c11_selfdestruct_to_self_in_creating_tx_must_not_break_supply_invariant() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // Block 1: fund ALICE with 10 bridged BLCH.
        execute_block(&spec, &mut state, block(1, vec![deposit(ALICE, 10 * SATS_PER_BLCH)], vec![])).expect("funding block");
        assert_eq!(state.total_native_wei(), state.total_minted_wei());

        // Block 2: CREATE with initcode `ADDRESS SELFDESTRUCT` (0x30ff) and 1 BLCH of value.
        let value = sats_to_wei(SATS_PER_BLCH);
        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Create)
            .value(value)
            .data(bytes!("30ff"))
            .gas_limit(100_000)
            .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("tx");
        let out = execute_block(&spec, &mut state, block(2, vec![], vec![tx])).expect("block");
        assert!(out.tx_outcomes[0].success, "the selfdestruct-to-self CREATE is a valid, successful tx");
        assert!(state.account(&ALICE.create(0)).is_none(), "EIP-6780: account created in-tx is destroyed");

        let minted = state.total_minted_wei();
        let native = state.total_native_wei();
        assert_eq!(
            native, minted,
            "supply invariant broken: {} wei of bridged BLCH vanished (minted {minted}, native {native})",
            minted - native
        );
        let _ = U256::ZERO;
    }
}

/// C13 [medium] — Block environment (base fee, number, timestamp, prevrandao) is caller-trusted: execute_block never enforces ChainSpec::next_base_fee or parent-header monotonicity
mod c13 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use super::common::*;
    use alloy_primitives::{address, Address, TxKind, B256, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::L2State;
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    /// Header-validity rule tracker (finding C13): after a genesis block, `execute_block`
    /// must reject a child block whose base fee != `ChainSpec::next_base_fee(parent)`,
    /// whose number != parent + 1, or whose timestamp regresses, and must accept the
    /// rule-conforming header. Fails today because the block environment is never checked.
    #[test]
    #[ignore = "C13: block environment is not validated against the parent header"]
    fn block_header_fields_are_validated_against_parent_and_eip1559_rule() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        // Genesis: block 0, timestamp 1000, base fee = initial_base_fee, gas_used 0.
        execute_block(&spec, &mut state, BlockInput {
            context: BlockContext { number: 0, timestamp: 1_000, base_fee_per_gas: spec.initial_base_fee, prevrandao: B256::ZERO },
            deposits: vec![deposit(ALICE, 10 * SATS_PER_BLCH)],
            txs: vec![],
        }).expect("genesis executes");
        let expected_bf = spec.next_base_fee(spec.initial_base_fee, 0);
        let good = BlockContext { number: 1, timestamp: 1_002, base_fee_per_gas: expected_bf, prevrandao: B256::ZERO };
        let tx = |nonce: u64| TxEnv::builder().caller(ALICE).kind(TxKind::Call(BOB)).value(U256::from(1))
            .gas_limit(21_000).max_fee_per_gas(2 * GWEI).gas_priority_fee(Some(GWEI))
            .nonce(nonce).chain_id(Some(spec.chain_id)).build().unwrap();

        for bad_bf in [0u64, 5 * GWEI as u64] {
            let mut s = state.clone();
            let ctx = BlockContext { base_fee_per_gas: bad_bf, ..good.clone() };
            let res = execute_block(&spec, &mut s, BlockInput { context: ctx, deposits: vec![], txs: vec![tx(0)] });
            assert!(res.is_err(), "base fee {bad_bf} != next_base_fee {expected_bf} must be rejected");
            assert_eq!(s.balance_of(&BOB), U256::ZERO, "rejected block must not advance state");
        }
        for bad_number in [0u64, 2, 7] {
            let mut s = state.clone();
            let ctx = BlockContext { number: bad_number, ..good.clone() };
            assert!(execute_block(&spec, &mut s, BlockInput { context: ctx, deposits: vec![], txs: vec![] }).is_err(),
                "block number {bad_number} after parent 0 must be rejected");
        }
        {
            let mut s = state.clone();
            let ctx = BlockContext { timestamp: 999, ..good.clone() };
            assert!(execute_block(&spec, &mut s, BlockInput { context: ctx, deposits: vec![], txs: vec![] }).is_err(),
                "timestamp 999 < parent 1000 must be rejected");
        }
        let out = execute_block(&spec, &mut state, BlockInput { context: good, deposits: vec![], txs: vec![tx(0)] })
            .expect("conforming header executes");
        assert_eq!(out.base_fee_per_gas, expected_bf);
        assert_eq!(out.base_fee_routed_wei, U256::from(expected_bf) * U256::from(21_000u64));
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::from(expected_bf) * U256::from(21_000u64));
    }
}

/// C15 [medium] — Unprotected (pre-EIP-155, chain_id = None) legacy transactions are accepted by execute_block
mod c15 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use super::common::*;
    use alloy_primitives::{address, Address, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::L2State;
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    #[test]
    #[ignore = "C15: unprotected legacy txs are currently accepted by execute_block"]
    fn c15_unprotected_legacy_tx_is_rejected_at_stf_boundary() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(&spec, &mut state, block(0, vec![deposit(ALICE, 10 * SATS_PER_BLCH)], vec![])).expect("genesis deposit block");

        let unprotected: TxEnv = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .value(sats_to_wei(SATS_PER_BLCH))
            .gas_limit(21_000)
            .gas_price(2 * GWEI)
            .nonce(0)
            .chain_id(None)
            .build()
            .unwrap();
        assert_eq!(unprotected.tx_type, 0, "test constructs a legacy tx");

        let result = execute_block(&spec, &mut state, block(1, vec![], vec![unprotected]));
        assert!(result.is_err(), "STF must reject a legacy tx without EIP-155 chain id (cross-chain replay surface)");
        assert_eq!(state.balance_of(&BOB), U256::ZERO, "no value may move on a rejected tx");
        assert_eq!(state.nonce_of(&ALICE), 0, "sender nonce must not advance on a rejected tx");

        let protected: TxEnv = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .value(sats_to_wei(SATS_PER_BLCH))
            .gas_limit(21_000)
            .gas_price(2 * GWEI)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();
        let out = execute_block(&spec, &mut state, block(1, vec![], vec![protected])).expect("EIP-155-protected legacy tx for this chain is valid");
        assert!(out.tx_outcomes[0].success);
        assert_eq!(state.balance_of(&BOB), sats_to_wei(SATS_PER_BLCH));
    }
}

/// C16 [medium] — BLOCKHASH returns EmptyDB's keccak256(decimal block number) placeholder for the whole 256-block window
mod c16 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use super::common::*;
    use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256};
    use bloch_l2_evm::{execute_block, BlockContext, BlockInput, ChainSpec, DepositMint, L2State};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use revm::context::TxEnv;
    use revm::state::{AccountInfo, Bytecode};

    /// BLOCKHASH must return the hash of the actual L2 block: it must depend on
    /// chain history and must never be revm EmptyDB's `keccak256(decimal number)`
    /// placeholder. Fails today because `execute_block` never supplies block
    /// hashes to `CacheDB<EmptyDB>`.
    #[test]
    #[ignore = "AUDIT C16 (medium): fails until the finding is fixed"]
    fn blockhash_returns_real_l2_block_hash_not_emptydb_placeholder() {
        const PROBE: Address = address!("00000000000000000000000000000000000000c0");

        // Runtime: PUSH1 0 BLOCKHASH PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN -> returns blockhash(0)
        fn chain(deposits: Vec<DepositMint>) -> L2State {
            let spec = ChainSpec::testnet();
            let mut s = L2State::new();
            let code = Bytecode::new_raw(Bytes::from_static(&[
                0x60, 0x00, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            ]));
            s.db.insert_account_info(
                PROBE,
                AccountInfo { balance: U256::ZERO, nonce: 1, code_hash: code.hash_slow(), code: Some(code), ..Default::default() },
            );
            execute_block(&spec, &mut s, block(0, deposits, vec![])).unwrap();
            s
        }
        fn blockhash0_at_block1(s: &mut L2State) -> B256 {
            let spec = ChainSpec::testnet();
            let tx = TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(PROBE))
                .gas_limit(100_000)
                .max_fee_per_gas(2 * GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(0)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap();
            let out = execute_block(&spec, s, block(1, vec![], vec![tx])).unwrap();
            let o = &out.tx_outcomes[0];
            assert!(o.success, "probe call must succeed");
            B256::from_slice(o.result.output().unwrap())
        }

        let mut a = chain(vec![deposit(ALICE, 10 * SATS_PER_BLCH)]);
        let mut b = chain(vec![deposit(ALICE, 10 * SATS_PER_BLCH), deposit(Address::from([0x99; 20]), 5)]);
        assert_ne!(
            bloch_l2_evm::compute_keccak_mpt_state_root(&a),
            bloch_l2_evm::compute_keccak_mpt_state_root(&b),
            "precondition: the two block-0 states differ"
        );

        let ha = blockhash0_at_block1(&mut a);
        let hb = blockhash0_at_block1(&mut b);

        let placeholder = keccak256(b"0");
        assert_ne!(ha, placeholder, "BLOCKHASH(0) must not be revm EmptyDB's keccak256(\"0\") placeholder");
        assert_ne!(hb, placeholder, "BLOCKHASH(0) must not be revm EmptyDB's keccak256(\"0\") placeholder");
        assert_ne!(ha, hb, "BLOCKHASH(0) must differ between two chains whose block 0 differs");
        assert_ne!(a.db.cache.block_hashes.get(&U256::ZERO), Some(&placeholder));
    }
}

/// C17 [medium] — EIP-4788 beacon-roots block-start system call and predeploy are absent at SpecId::CANCUN
mod c17 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use super::common::*;
    use alloy_primitives::{address, bytes, keccak256, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::L2State;
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    /// EIP-4788 at Cancun: the beacon-roots predeploy exists from genesis and the
    /// block-start system call populates `timestamps[ts % 8191]` so that a user
    /// `get(block.timestamp)` returns a 32-byte root, while `get(other_ts)` reverts.
    /// Fails today: the predeploy is absent and no system call is performed.
    #[test]
    #[ignore = "C17: EIP-4788 beacon-roots system call / predeploy not implemented"]
    fn eip4788_beacon_roots_system_call_is_applied_at_block_start() {
        const BEACON_ROOTS_ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");
        let beacon_roots_code: Bytes = bytes!("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500");
        const T: u64 = 1_700_000_000;

        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        let acct = state
            .account(&BEACON_ROOTS_ADDRESS)
            .expect("EIP-4788 beacon-roots predeploy must exist at genesis");
        assert_eq!(acct.code_hash, keccak256(&beacon_roots_code), "canonical EIP-4788 bytecode");

        let get = |nonce: u64, ts: u64| {
            TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(BEACON_ROOTS_ADDRESS))
                .gas_limit(100_000)
                .data(Bytes::from(U256::from(ts).to_be_bytes::<32>().to_vec()))
                .max_fee_per_gas(2 * GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(nonce)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap()
        };

        let out = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 1, timestamp: T, ..BlockContext::default() },
                deposits: vec![deposit(ALICE, 10 * SATS_PER_BLCH)],
                txs: vec![get(0, T), get(1, T + 1)],
            },
        )
        .expect("block executes");

        let same_ts = &out.tx_outcomes[0];
        assert!(same_ts.success, "get(block.timestamp) must succeed after the EIP-4788 system call");
        assert_eq!(same_ts.result.output().map(|b| b.len()).unwrap_or(0), 32, "beacon-roots get() returns a 32-byte root, not empty output");
        let other_ts = &out.tx_outcomes[1];
        assert!(!other_ts.success, "get(unknown ts) must revert per EIP-4788");

        let slots = &state.db.cache.accounts[&BEACON_ROOTS_ADDRESS].storage;
        let ts_slot = U256::from(T % 8191);
        assert_eq!(slots.get(&ts_slot).copied().unwrap_or_default(), U256::from(T), "timestamps[ts % 8191] == ts");
    }
}

/// C18 [medium, FIXED] — the supply ledger is committed in the state root and
/// carried by the witness; the guest re-derives every deposit against it.
mod c18 {
    use super::common::*;
    use alloy_primitives::U256;
    use bloch_l2_evm::chainspec::SUPPLY_LEDGER;
    use bloch_l2_evm::state::SUPPLY_LEDGER_TOTAL_MINTED_SLOT;
    use bloch_l2_evm::{compute_keccak_mpt_state_root, execute_block, generate_batch_witness, verify_batch, ChainSpec, L2State};

    #[test]
    fn supply_ledger_is_committed_and_survives_stateless_hydration() {
        let spec = ChainSpec::testnet();
        // Not committed would mean: same accounts, different ledger, same root.
        let mut a = L2State::new();
        execute_block(&spec, &mut a, block(1, vec![deposit(ALICE, 5 * BLCH)], vec![])).unwrap();
        let root = compute_keccak_mpt_state_root(&a);
        a.db.insert_account_storage(SUPPLY_LEDGER, SUPPLY_LEDGER_TOTAL_MINTED_SLOT, U256::from(1u64)).unwrap();
        assert_ne!(compute_keccak_mpt_state_root(&a), root, "ledger total is part of the root");
        assert_eq!(a.total_minted_wei(), U256::from(1u64), "ledger is read from committed storage");

        // In the stateless path the ledger account is hydrated and the guest's
        // deposit accounting matches the host's.
        let pre = funded(4);
        let host_total = pre.total_minted_wei();
        let batch = block(1, vec![deposit(BOB, 2 * BLCH)], vec![]);
        let (w, outcome) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        let ledger = w.pre_accounts.iter().find(|a| a.address == spec.supply_ledger).expect("ledger hydrated");
        assert!(ledger.storage.iter().any(|(k, v)| *k == SUPPLY_LEDGER_TOTAL_MINTED_SLOT && *v == host_total));
        let verified = verify_batch(&spec, &w, &batch).unwrap();
        assert_eq!(verified.minted_wei, outcome.minted_wei);
        assert_eq!(verified.minted_wei, wei(2));
    }
}

/// C19 [medium, FIXED] — deposits are bounded by the L1 hard cap, per deposit
/// and cumulatively; the credited amount is derived from `l1_sats` alone.
mod c19 {
    use super::common::*;
    use bloch_l2_evm::{execute_block, BlockExecutionError, ChainSpec, DepositError, L2State};

    #[test]
    fn c19_deposit_above_any_possible_l1_supply_is_rejected() {
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        for sats in [spec.max_l1_sats + 1, u64::MAX] {
            let err = execute_block(&spec, &mut st, block(1, vec![deposit(ALICE, sats)], vec![])).unwrap_err();
            assert!(matches!(err, BlockExecutionError::Deposit(DepositError::ExceedsL1Supply { .. })), "{err}");
        }
        assert_eq!(fingerprint(&st), fingerprint(&L2State::new()));
        execute_block(&spec, &mut st, block(1, vec![deposit(ALICE, spec.max_l1_sats)], vec![])).unwrap();
        let err = execute_block(&spec, &mut st, block(2, vec![deposit(BOB, 1)], vec![])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::Deposit(DepositError::CumulativeSupplyExceeded { .. })));
        let d = deposit(BOB, 7);
        assert_eq!(d.mint_wei(), bloch_l2_evm::sats_to_wei(7), "credit is derived from l1_sats");
    }
}

/// C20 [low, FIXED] — the witness has a canonical byte form.
mod c20 {
    use super::common::*;
    use alloy_primitives::Bytes;
    use bloch_l2_evm::{execute_block, generate_batch_witness, ChainSpec};

    #[test]
    fn c20_batch_witness_pre_accounts_and_storage_have_canonical_order() {
        let spec = ChainSpec::testnet();
        let mut pre = funded(14);
        let alice = addr(1);
        // runtime: SSTORE slots 1..=8 then STOP
        let mut runtime = Vec::new();
        for i in 1u8..=8 {
            runtime.extend_from_slice(&[0x60, i, 0x60, i, 0x55]);
        }
        runtime.push(0x00);
        let out = execute_block(&spec, &mut pre, block(1, vec![], vec![create(alice, 0, deployer(&runtime), 400_000)])).unwrap();
        let contract = out.tx_outcomes[0].created_address.unwrap();
        execute_block(&spec, &mut pre, block(2, vec![], vec![call_data(alice, contract, 1, Bytes::new(), 400_000)])).unwrap();

        let batch = block(3, vec![], vec![call_data(alice, contract, 2, Bytes::new(), 400_000)]);
        let (w1, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        let (w2, _) = generate_batch_witness(&pre.clone(), &spec, batch).unwrap();
        assert_eq!(w1, w2);
        let c = w1.pre_accounts.iter().find(|a| a.address == contract).unwrap();
        assert_eq!(c.storage.len(), 8);
        assert!(c.storage.windows(2).all(|p| p[0].0 < p[1].0));
        assert!(w1.pre_accounts.windows(2).all(|p| p[0].address < p[1].address));
        assert!(w1.absent_accounts.windows(2).all(|p| p[0] < p[1]));
    }
}

/// C21 [medium, FIXED] — a zero-length extension key is a rejected witness, not
/// an infinite recursion.
mod c21 {
    use alloy_primitives::{keccak256, Bytes, B256};
    use alloy_rlp::Encodable;
    use alloy_trie::Nibbles;
    use bloch_l2_evm::{stateless_new_root, WitnessError};
    use std::collections::BTreeMap;

    #[test]
    fn zero_length_extension_key_must_not_hang_or_abort() {
        let child = B256::repeat_byte(0x44);
        let mut payload = Vec::new();
        [0x00u8].as_slice().encode(&mut payload);
        child.encode(&mut payload);
        let mut rlp = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut rlp);
        rlp.extend(payload);
        let root = keccak256(&rlp);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), rlp.into());
        assert_eq!(
            stateless_new_root(root, &proof, &BTreeMap::new()),
            Err(WitnessError::EmptyExtensionKey { path: Nibbles::default() })
        );
    }
}

/// C22 [medium, FIXED] — over-capacity paths in a crafted proof are errors, not
/// panics or undefined behaviour.
mod c22 {
    use alloy_primitives::{keccak256, Bytes, B256};
    use alloy_trie::nodes::LeafNode;
    use alloy_trie::Nibbles;
    use bloch_l2_evm::{stateless_new_root, WitnessError};
    use std::collections::BTreeMap;

    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.iter().flatten().copied().collect();
        let mut out = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
        out.extend(payload);
        out
    }

    #[test]
    fn stateless_new_root_rejects_over_capacity_proof_without_panicking() {
        // (a) root = extension with a 64-nibble key whose child is a branch.
        let branch_children: Vec<Vec<u8>> = (0..16).map(|_| alloy_rlp::encode(&[] as &[u8])).chain([alloy_rlp::encode(&[] as &[u8])]).collect();
        let branch = list(&branch_children);
        let mut ext_items = Vec::new();
        let key = Nibbles::from_nibbles(vec![1u8; 64]);
        let compact = alloy_trie::nodes::encode_path_leaf(&key, false);
        ext_items.push(alloy_rlp::encode(compact.as_slice()));
        ext_items.push(alloy_rlp::encode(keccak256(&branch)));
        let ext = list(&ext_items);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), ext.clone().into());
        proof.insert(key, branch.into());
        assert!(matches!(
            stateless_new_root(keccak256(&ext), &proof, &BTreeMap::new()),
            Err(WitnessError::PathTooLong { .. }) | Err(WitnessError::MalformedNode { .. })
        ));

        // (b) a leaf whose key joins to 65 nibbles under a 1-nibble path.
        let leaf = LeafNode::new(Nibbles::from_nibbles(vec![2u8; 64]), vec![0x01]);
        let leaf_rlp = alloy_rlp::encode(&leaf);
        let mut children: Vec<Vec<u8>> = vec![alloy_rlp::encode(keccak256(&leaf_rlp))];
        children.extend((0..16).map(|_| alloy_rlp::encode(&[] as &[u8])));
        let branch = list(&children);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), branch.clone().into());
        proof.insert(Nibbles::from_nibbles([0]), leaf_rlp.into());
        assert!(matches!(
            stateless_new_root(keccak256(&branch), &proof, &BTreeMap::new()),
            Err(WitnessError::PathTooLong { .. })
        ));

        // (c) compact key longer than 33 bytes: rejected before alloy-trie decodes.
        let node = list(&[alloy_rlp::encode([0x20u8; 34].as_slice()), alloy_rlp::encode([0x01u8].as_slice())]);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), node.clone().into());
        assert!(matches!(
            stateless_new_root(keccak256(&node), &proof, &BTreeMap::new()),
            Err(WitnessError::MalformedNode { .. })
        ));
        let _ = B256::ZERO;
    }
}

/// C23 [low, FIXED] — malformed witness input is rejected with an error
/// everywhere (proof bytes, change keys, bytecode).
mod c23 {
    use super::common::*;
    use alloy_primitives::{keccak256, Bytes, U256};
    use alloy_trie::Nibbles;
    use bloch_l2_evm::{generate_batch_witness, hydrate_and_verify, stateless_new_root, ChainSpec, VerifyError, WitnessError};
    use std::collections::BTreeMap;

    #[test]
    fn malformed_witness_input_is_rejected_without_panicking() {
        // Garbage root bytes.
        let garbage = vec![0xde, 0xad];
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), garbage.clone().into());
        assert!(matches!(
            stateless_new_root(keccak256(&garbage), &proof, &BTreeMap::new()),
            Err(WitnessError::MalformedNode { .. })
        ));
        // Truncated node.
        let truncated = vec![0xf8, 0x51, 0x80, 0x80];
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), truncated.clone().into());
        assert!(matches!(
            stateless_new_root(keccak256(&truncated), &proof, &BTreeMap::new()),
            Err(WitnessError::MalformedNode { .. })
        ));

        // Change keys that are not 64 nibbles.
        let spec = ChainSpec::testnet();
        let pre = funded(6);
        let batch = block(1, vec![], vec![transfer(addr(1), addr(2), 0, wei(1), 21_000)]);
        let (w, _) = generate_batch_witness(&pre, &spec, batch).unwrap();
        let mut short: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        short.insert(Nibbles::from_nibbles([1, 2, 3]), Some(vec![0xc0]));
        assert!(matches!(
            stateless_new_root(w.prev_state_root, &w.proof, &short),
            Err(WitnessError::InvalidKeyLength { .. })
        ));

        // EIP-7702 magic prefix in a pre-account's code: an error, not a panic.
        let mut bad_code = w.clone();
        bad_code.pre_accounts[0].code = vec![0xef, 0x01, 0x00];
        assert!(matches!(hydrate_and_verify(&bad_code), Err(VerifyError::InvalidCode(_))));

        // Zero-valued / unsorted storage entries are rejected.
        let mut bad_storage = w.clone();
        bad_storage.pre_accounts[0].storage = vec![(U256::from(1u64), U256::ZERO)];
        assert!(matches!(hydrate_and_verify(&bad_storage), Err(VerifyError::InvalidStorage(..))));
    }
}

/// C24 [low, FIXED] — inline (< 32-byte) children are decoded in place.
mod c24 {
    use alloy_primitives::Bytes;
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{HashBuilder, Nibbles};
    use bloch_l2_evm::{stateless_new_root, SparseTrieView};
    use std::collections::BTreeMap;

    #[test]
    fn c24_stateless_new_root_handles_inline_children() {
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
        let view = SparseTrieView::from_proof(prev_root, &proof).unwrap();
        assert_eq!(view.leaves().len(), 3, "inline siblings exposed");

        let mut hb2 = HashBuilder::default();
        hb2.add_leaf(keys[0], &[0x7f]);
        hb2.add_leaf(keys[1], &values[1]);
        hb2.add_leaf(keys[2], &values[2]);
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(keys[0], Some(vec![0x7f]));
        assert_eq!(stateless_new_root(prev_root, &proof, &changes), Ok(hb2.root()));
    }
}

/// C25 [low, FIXED] — fee routing uses revm's own type-aware effective gas
/// price; inconsistent TxEnvs are rejected at the boundary.
mod c25 {
    use super::common::*;
    use alloy_primitives::{TxKind, U256};
    use bloch_l2_evm::{execute_block, BlockExecutionError, ChainSpec, L2State};
    use revm::context::TxEnv;

    #[test]
    fn c25_priority_fee_routed_matches_revm_payment_for_legacy_and_2930_with_priority_field() {
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        execute_block(&spec, &mut st, block(1, vec![deposit(ALICE, 10 * BLCH)], vec![])).unwrap();

        // Inconsistent envs (type 0/1 carrying a tip) are rejected.
        for tx_type in [0u8, 1] {
            let mut t = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
            t.tx_type = tx_type;
            t.gas_price = 3 * GWEI;
            assert!(matches!(
                execute_block(&spec, &mut st, block(2, vec![], vec![t])),
                Err(BlockExecutionError::InconsistentTxEnv { tx_index: 0 })
            ));
        }
        // Consistent legacy and 1559 envs: reported tip == vault delta.
        let legacy = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .gas_price(3 * GWEI)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();
        let before = st.balance_of(&spec.sequencer_fee_vault);
        let out = execute_block(&spec, &mut st, block(2, vec![], vec![legacy])).unwrap();
        assert_eq!(out.priority_fee_routed_wei, st.balance_of(&spec.sequencer_fee_vault) - before);
        assert_eq!(out.priority_fee_routed_wei, U256::from(2 * GWEI) * U256::from(21_000u64));
        let before = st.balance_of(&spec.sequencer_fee_vault);
        let out = execute_block(&spec, &mut st, block(3, vec![], vec![transfer(ALICE, BOB, 1, U256::ZERO, 21_000)])).unwrap();
        assert_eq!(out.priority_fee_routed_wei, st.balance_of(&spec.sequencer_fee_vault) - before);
        assert_eq!(st.total_native_wei(), st.total_minted_wei());
    }
}

/// C26 [low] — L2State account views report EIP-161-empty (touched-empty) accounts as existing while the committed state root excludes them; touched-empty accounts and zero-valued storage slots are never pruned
mod c26 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use super::common::*;
    use alloy_primitives::{address, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::{execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, L2State};
    use revm::context::TxEnv;
    use revm::database::AccountState;

    /// C26: touched-empty (EIP-161-empty) accounts must not be reported as existing by the
    /// account views, must not be counted by `total_native_wei`, and must not persist in the
    /// live state after a block — exactly as the committed state root already treats them.
    #[test]
    #[ignore = "AUDIT C26 (low): fails until the finding is fixed"]
    fn c26_touched_empty_accounts_do_not_exist_in_views_and_are_pruned() {
        const GHOST: Address = address!("0000000000000000000000000000000000060057");
        const ECRECOVER: Address = address!("0000000000000000000000000000000000000001");

        let spec = ChainSpec::testnet();
        let call = |to: Address, nonce: u64, gas: u64| {
            TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(to))
                .value(U256::ZERO)
                .gas_limit(gas)
                .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(nonce)
                .chain_id(Some(spec.chain_id))
                .data(Bytes::new())
                .build()
                .unwrap()
        };

        let mut state = L2State::new();
        // A 0-sat deposit is exact but must not materialise BOB. (Fixed.)
        state.deposit_mint(&spec, &deposit(BOB, 0)).unwrap();
        assert!(state.account(&BOB).is_none(), "0-sat deposit must not create an account");

        // Zero-value CALLs to a fresh address and to a precompile (EIP-161 touches).
        let out = execute_block(
            &spec,
            &mut state,
            block(1, vec![deposit(ALICE, 1_000_000_000)], vec![call(GHOST, 0, 21_000), call(ECRECOVER, 1, 100_000)]),
        )
        .unwrap();
        assert!(out.tx_outcomes.iter().all(|t| t.success));

        assert!(state.account(&GHOST).is_none(), "touched-empty account reported as existing");
        assert!(state.account(&ECRECOVER).is_none(), "touched precompile reported as existing");
        assert!(state.account(&BOB).is_none());
        assert_eq!(state.balance_of(&GHOST), U256::ZERO);
        assert_eq!(state.nonce_of(&GHOST), 0);

        for a in [GHOST, ECRECOVER, BOB] {
            let persisted = state
                .db
                .cache
                .accounts
                .get(&a)
                .map_or(false, |acc| acc.account_state != AccountState::NotExisting);
            assert!(!persisted, "touched-empty account {a} persists in the live state");
        }
        for (addr, acc) in &state.db.cache.accounts {
            if let Some(view) = state.account(addr) {
                assert!(
                    view.nonce != 0 || !view.balance.is_zero() || view.code_hash != revm::primitives::KECCAK_EMPTY,
                    "view reports EIP-161-empty account {addr} as existing (state={:?})",
                    acc.account_state
                );
            }
        }
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }
}

/// C27 [low] — State root is rebuilt from scratch over the entire state on every block (and execute_block now also clones the state for atomicity)
mod c27 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use std::time::Instant;
    use alloy_primitives::{Address, U256};
    use bloch_l2_evm::scale::SATS_PER_BLCH;
    use bloch_l2_evm::{execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State};

    /// Fix-tracking (C27): sealing a block that touches nothing must NOT cost time
    /// proportional to the total state size. Threshold is deliberately loose
    /// (10x over a 160x size difference) to tolerate timing noise. Run in --release.
    #[test]
    #[ignore = "C27: per-block cost is O(total state)"]
    fn c27_empty_block_time_must_not_scale_with_total_state_size() {
        fn deposit(to: Address, sats: u64) -> DepositMint {
            let mut vout = [0u8; 4];
            vout.copy_from_slice(&to.as_slice()[16..20]);
            DepositMint {
                recipient: to,
                provenance: DepositProvenance::BridgedBlch { l1_txid: [1; 32], l1_vout: u32::from_be_bytes(vout), l1_sats: sats },
            }
        }
        fn addr(i: u64) -> Address {
            let mut b = [0u8; 20];
            b[0] = 0xAA;
            b[12..].copy_from_slice(&i.to_be_bytes());
            Address::from(b)
        }
        fn state_with(spec: &ChainSpec, n_accounts: u64, n_slots: u64) -> L2State {
            let mut s = L2State::new();
            let deposits = (0..n_accounts).map(|i| deposit(addr(i), SATS_PER_BLCH)).collect();
            execute_block(spec, &mut s, BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits, txs: vec![] }).unwrap();
            let c = Address::from([0xCC; 20]);
            s.deposit_mint(spec, &deposit(c, SATS_PER_BLCH)).unwrap();
            for k in 0..n_slots {
                s.db.insert_account_storage(c, U256::from(k), U256::from(k + 1)).unwrap();
            }
            s
        }
        fn empty_block_secs(spec: &ChainSpec, s: &mut L2State) -> f64 {
            let mut ts: Vec<f64> = (0..5)
                .map(|i| {
                    let t = Instant::now();
                    execute_block(spec, s, BlockInput { context: BlockContext { number: 10 + i, ..Default::default() }, deposits: vec![], txs: vec![] }).unwrap();
                    t.elapsed().as_secs_f64()
                })
                .collect();
            ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            ts[2]
        }

        let spec = ChainSpec::testnet();
        let mut small = state_with(&spec, 1_000, 0);
        let mut big = state_with(&spec, 160_000, 0);
        let t_small = empty_block_secs(&spec, &mut small);
        let t_big = empty_block_secs(&spec, &mut big);
        assert!(
            t_big < 10.0 * t_small.max(1e-4),
            "empty block against 160k accounts took {:.2} ms vs {:.2} ms against 1k accounts (x{:.1})",
            t_big * 1e3, t_small * 1e3, t_big / t_small
        );
        let mut small = state_with(&spec, 10, 1_000);
        let mut big = state_with(&spec, 10, 160_000);
        let t_small = empty_block_secs(&spec, &mut small);
        let t_big = empty_block_secs(&spec, &mut big);
        assert!(
            t_big < 10.0 * t_small.max(1e-4),
            "empty block with an untouched 160k-slot contract took {:.2} ms vs {:.2} ms with 1k slots (x{:.1})",
            t_big * 1e3, t_small * 1e3, t_big / t_small
        );
    }
}

/// C28 [low] — ChainSpec::gas_target / next_base_fee divide by the pub knobs without a zero check
mod c28 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use bloch_l2_evm::ChainSpec;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    #[ignore = "AUDIT C28 (low): fails until the finding is fixed"]
    fn c28_chainspec_fee_helpers_are_total_for_zero_knobs() {
        let parent_bf = 1_000_000_000u64;

        let mut s = ChainSpec::testnet();
        s.base_fee_elasticity = 0;
        let gt = catch_unwind(AssertUnwindSafe(|| s.gas_target()));
        assert!(gt.is_ok(), "gas_target() must not panic for elasticity 0");
        for used in [0u64, 1, s.gas_limit / 2, s.gas_limit] {
            let r = catch_unwind(AssertUnwindSafe(|| s.next_base_fee(parent_bf, used)));
            assert_eq!(r.ok(), Some(parent_bf), "next_base_fee must not panic for elasticity 0 (gas_used={used})");
        }

        let mut s = ChainSpec::testnet();
        s.base_fee_denominator = 0;
        for used in [0u64, s.gas_target() - 1, s.gas_target(), s.gas_target() + 1, s.gas_limit] {
            let r = catch_unwind(AssertUnwindSafe(|| s.next_base_fee(parent_bf, used)));
            assert_eq!(r.ok(), Some(parent_bf), "next_base_fee must not panic for denominator 0 (gas_used={used})");
        }

        let mut s = ChainSpec::testnet();
        s.gas_limit = 1;
        s.base_fee_elasticity = 2;
        assert_eq!(s.next_base_fee(parent_bf, 0), parent_bf);
        assert_eq!(s.next_base_fee(parent_bf, 1), parent_bf);
    }
}

/// C29 [low, partially FIXED] — a zero-sat deposit no longer materializes the
/// recipient account. (Deposit metering per block remains open.)
mod c29 {
    use super::common::*;
    use alloy_primitives::U256;
    use bloch_l2_evm::{compute_keccak_mpt_state_root, execute_block, ChainSpec, L2State};
    use alloy_trie::EMPTY_ROOT_HASH;

    #[test]
    fn zero_sat_deposit_does_not_create_an_account() {
        let spec = ChainSpec::testnet();
        let mut st = L2State::new();
        let out = execute_block(&spec, &mut st, block(1, (0..50).map(|_| deposit(BOB, 0)).collect(), vec![])).unwrap();
        assert_eq!(out.minted_wei, U256::ZERO);
        assert!(st.account(&BOB).is_none(), "zero credit must not materialize an account");
        assert!(!st.db.cache.accounts.contains_key(&BOB));
        // Only the ledger (consumed outpoints) exists.
        assert_eq!(st.db.cache.accounts.len(), 1);
        assert_ne!(compute_keccak_mpt_state_root(&st), EMPTY_ROOT_HASH, "the consumed outpoints are committed");
    }
}

/// C30 [low, FIXED] — the no_std configuration's test target compiles.
mod c30 {
    use std::process::Command;

    #[test]
    fn no_default_features_test_target_compiles() {
        let root = env!("CARGO_MANIFEST_DIR");
        let status = Command::new(env!("CARGO"))
            .args(["test", "--offline", "--no-default-features", "--lib", "--no-run"])
            .current_dir(root)
            .status()
            .expect("run cargo");
        assert!(status.success(), "cargo test --no-default-features --lib --no-run must compile");
    }
}

/// C31 [low] — Determinism contract is enforced only by the committed Cargo.lock
mod c31 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use std::fs;
    use std::path::Path;

    const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn manifest_line(manifest: &str, dep: &str) -> String {
        manifest
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(&format!("{dep} ")) || l.starts_with(&format!("{dep}=")))
            .unwrap_or_else(|| panic!("{dep} not declared in Cargo.toml"))
            .to_string()
    }

    fn locked_version(lock: &str, name: &str) -> String {
        let needle = format!("name = \"{name}\"\nversion = \"");
        let i = lock.find(&needle).unwrap_or_else(|| panic!("{name} not in Cargo.lock")) + needle.len();
        lock[i..].split('"').next().unwrap().to_string()
    }

    #[test]
    #[ignore = "C31: consensus-relevant crates are caret ranges pinned only by Cargo.lock"]
    fn consensus_relevant_crates_are_pinned_exactly_and_match_the_lock() {
        let root = Path::new(MANIFEST_DIR);
        let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let lock = fs::read_to_string(root.join("Cargo.lock")).unwrap();
        for dep in ["revm", "alloy-primitives", "alloy-trie", "alloy-rlp"] {
            let line = manifest_line(&manifest, dep);
            let req = line.split('"').nth(1).unwrap_or_else(|| panic!("no version string on `{line}`"));
            assert!(req.starts_with('='), "{dep}: Cargo.toml requirement `{req}` is a caret range, not an exact `=` pin");
            assert_eq!(&req[1..], locked_version(&lock, dep), "{dep}: exact pin does not match the committed Cargo.lock");
        }
    }

    #[test]
    #[ignore = "C31: no rust-version / rust-toolchain.toml pin"]
    fn toolchain_is_pinned_for_reproducible_builds() {
        let root = Path::new(MANIFEST_DIR);
        let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert!(
            manifest.lines().any(|l| l.trim_start().starts_with("rust-version")),
            "Cargo.toml has no `rust-version` (revm 41.0.0 requires rustc >= 1.91.0)"
        );
        let toolchain = root.join("rust-toolchain.toml");
        assert!(toolchain.exists(), "no committed rust-toolchain.toml (SP1 vkey depends on the exact compiler)");
        let tc = fs::read_to_string(&toolchain).unwrap();
        let channel = tc.lines().find(|l| l.trim_start().starts_with("channel")).expect("channel = ... in rust-toolchain.toml");
        assert!(
            !channel.contains("\"stable\"") && !channel.contains("\"nightly\"") && !channel.contains("\"beta\""),
            "rust-toolchain.toml channel must be a fixed version, not a moving channel: {channel}"
        );
    }
}
