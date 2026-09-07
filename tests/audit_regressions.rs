// SPDX-License-Identifier: MIT OR Apache-2.0
//! Testes de regressão da auditoria profunda (ver `AUDITORIA-L2.md`).
//!
//! Cada módulo corresponde a um achado (C01..C31) e afirma o comportamento
//! CORRETO esperado — por isso cada teste **falha hoje** e está marcado com
//! `#[ignore]` para que `cargo test` continue verde. Ao corrigir um achado,
//! remova o `#[ignore]` do módulo correspondente: o teste passa a proteger a
//! correção contra regressões.
//!
//! Executar todos (esperado: falhas = achados ainda abertos):
//!
//! ```sh
//! cargo test --test audit_regressions -- --ignored
//! ```
//!
//! Executar um achado específico:
//!
//! ```sh
//! cargo test --test audit_regressions c04 -- --ignored
//! ```
//!
//! Audit regression tests (see `AUDITORIA-L2.md`). One module per finding; each
//! test asserts the CORRECT behaviour and therefore fails today; all are
//! `#[ignore]`d so the default `cargo test` run stays green. Un-ignore a module
//! once its finding is fixed.
#![allow(clippy::all)]


/// C01 [critical] — execute_block erases the ENTIRE L2 state (db mem::take'n and never restored) on BlockGasLimitExceeded or any revm transaction error, while total_minted_wei keeps counting: empty state root, supply-invariant break, nonce reset enabling replay of already-included transactions
mod c01 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, TxKind, U256};
    use bloch_l2_evm::executor::BlockExecutionError;
    use bloch_l2_evm::{
        compute_keccak_mpt_state_root, execute_block, sats_to_wei, BlockContext, BlockInput,
        ChainSpec, DepositMint, DepositProvenance, L2State,
    };
    use revm::context::TxEnv;

    /// C01 fix-tracking test: a block that returns `Err` must leave `L2State`
    /// byte-identical to the pre-block state (db, nonces, balances, supply ledger,
    /// state root). Today `execute_block` `mem::take`s `state.db` and never restores
    /// it on the `BlockGasLimitExceeded` / `Evm` paths, so the db is EMPTY after the
    /// error while `total_minted_wei` still counts the failed block's deposits.
    #[test]
        #[ignore = "AUDIT C01 (critical): fails until the finding is fixed"]
    fn failed_block_leaves_state_unchanged() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BOB: Address = address!("0000000000000000000000000000000000000b0b");
        const CAROL: Address = address!("00000000000000000000000000000000000ca201");
        const GWEI: u128 = 1_000_000_000;
        const SATS_PER_BLCH: u64 = 100_000_000;

        let spec = ChainSpec::testnet();
        let deposit = |to: Address, sats: u64| DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [9; 32], l1_vout: 0, l1_sats: sats },
        };
        let tx = |nonce: u64, gas_limit: u64, value: U256| {
            TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(BOB))
                .value(value)
                .gas_limit(gas_limit)
                .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(nonce)
                .chain_id(Some(spec.chain_id))
                .build()
                .expect("valid tx env")
        };
        let block = |n: u64, deposits: Vec<DepositMint>, txs: Vec<TxEnv>| BlockInput {
            context: BlockContext { number: n, ..Default::default() },
            deposits,
            txs,
        };

        // Pre-state: two funded accounts, ALICE at nonce 1 after one transfer.
        let mut state = L2State::new();
        execute_block(&spec, &mut state, block(1, vec![deposit(ALICE, 10 * SATS_PER_BLCH), deposit(CAROL, 5 * SATS_PER_BLCH)], vec![])).unwrap();
        execute_block(&spec, &mut state, block(2, vec![], vec![tx(0, 21_000, sats_to_wei(SATS_PER_BLCH))])).unwrap();
        let pre = state.clone();
        let pre_root = compute_keccak_mpt_state_root(&pre);
        assert_eq!(pre.total_native_wei(), pre.total_minted_wei());

        let assert_unchanged = |label: &str, state: &L2State| {
            assert_eq!(state.db.cache.accounts.len(), pre.db.cache.accounts.len(), "{label}: account set changed");
            assert_eq!(state.balance_of(&ALICE), pre.balance_of(&ALICE), "{label}: ALICE balance changed");
            assert_eq!(state.balance_of(&BOB), pre.balance_of(&BOB), "{label}: BOB balance changed");
            assert_eq!(state.balance_of(&CAROL), pre.balance_of(&CAROL), "{label}: CAROL balance changed");
            assert_eq!(state.nonce_of(&ALICE), pre.nonce_of(&ALICE), "{label}: ALICE nonce changed");
            assert_eq!(state.total_minted_wei(), pre.total_minted_wei(), "{label}: supply ledger changed");
            assert_eq!(state.total_native_wei(), state.total_minted_wei(), "{label}: supply invariant broken");
            assert_eq!(compute_keccak_mpt_state_root(state), pre_root, "{label}: state root changed");
        };

        // (1) revm pre-validation error at index 1 (tx 0 valid, tx 1 stale nonce), with a deposit in the block.
        let mut s = pre.clone();
        let err = execute_block(&spec, &mut s, block(3, vec![deposit(BOB, SATS_PER_BLCH)], vec![tx(1, 21_000, U256::ZERO), tx(7, 21_000, U256::ZERO)])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 1, .. }));
        assert_unchanged("Evm error", &s);

        // (2) block gas limit exceeded at index 0.
        let mut s = pre.clone();
        let err = execute_block(&spec, &mut s, block(3, vec![], vec![tx(1, spec.gas_limit + 1, U256::ZERO)])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlockGasLimitExceeded { tx_index: 0 }));
        assert_unchanged("BlockGasLimitExceeded", &s);

        // (3) a sequencer-boundary rejection (blob tx) after a deposit in the same block:
        //     the deposit must not persist either — block application is all-or-nothing.
        let mut s = pre.clone();
        let blob = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(2 * GWEI)
            .gas_priority_fee(Some(GWEI))
            .blob_hashes(vec![alloy_primitives::B256::repeat_byte(1)])
            .max_fee_per_blob_gas(1)
            .nonce(1)
            .chain_id(Some(spec.chain_id))
            .build_fill();
        let err = execute_block(&spec, &mut s, block(3, vec![deposit(BOB, SATS_PER_BLCH)], vec![blob])).unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlobTxRejected { tx_index: 0 }));
        assert_unchanged("BlobTxRejected", &s);
    }
}


/// C02 [high] — execute_block applies deposit mints before any block-level validation and without rollback, so a rejected block leaves its deposits credited/counted and re-proposing the anchored deposits double-mints them
mod c02 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, TxKind, B256, U256};
    use bloch_l2_evm::executor::BlockExecutionError;
    use bloch_l2_evm::{
        compute_keccak_mpt_state_root, execute_block, sats_to_wei, BlockContext, BlockInput,
        ChainSpec, DepositMint, DepositProvenance, L2State,
    };
    use revm::context::TxEnv;

    /// C02 fix-tracking test: a block that fails ANY executor check must leave the
    /// caller's `L2State` (db, supply ledger, state root) exactly as it was, so
    /// the anchored deposits can be re-proposed in a corrected block without
    /// being minted twice.
    #[test]
        #[ignore = "AUDIT C02 (high): fails until the finding is fixed"]
    fn failed_block_is_atomic_and_never_double_mints_its_deposits() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BOB: Address = address!("0000000000000000000000000000000000000b0b");
        const GWEI: u128 = 1_000_000_000;
        const SATS_PER_BLCH: u64 = 100_000_000;

        fn deposit(recipient: Address, l1_sats: u64, l1_vout: u32) -> DepositMint {
            DepositMint {
                recipient,
                mint_wei: sats_to_wei(l1_sats),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [0xAB; 32], l1_vout, l1_sats },
            }
        }
        fn snapshot(state: &L2State) -> (U256, U256, B256) {
            (state.total_minted_wei(), state.total_native_wei(), compute_keccak_mpt_state_root(state))
        }

        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let context = BlockContext { number: 1, ..BlockContext::default() };
        let escrow = deposit(BOB, 3 * SATS_PER_BLCH, 1); // 3 BLCH escrowed ONCE on L1
        let pre = snapshot(&state);

        // (a) Blob-tx rejection AFTER the deposit list.
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
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: context.clone(), deposits: vec![escrow], txs: vec![blob_tx] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlobTxRejected { tx_index: 0 }));
        assert_eq!(state.balance_of(&BOB), U256::ZERO, "Err must not leave the deposit credited");
        assert_eq!(snapshot(&state), pre, "Err must leave db, ledger and root untouched");

        // (b) Block-gas-limit rejection AFTER the deposit list.
        let huge_tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(spec.gas_limit + 1)
            .max_fee_per_gas(2 * GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx");
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: context.clone(), deposits: vec![escrow], txs: vec![huge_tx] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlockGasLimitExceeded { tx_index: 0 }));
        assert_eq!(snapshot(&state), pre, "ledger must not count a deposit whose credit was dropped");

        // (c) A bad deposit later in the list must not leave earlier ones applied.
        let mut bad = deposit(ALICE, SATS_PER_BLCH, 2);
        bad.mint_wei += U256::from(1);
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: context.clone(), deposits: vec![escrow, bad], txs: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Deposit(_)));
        assert_eq!(state.balance_of(&BOB), U256::ZERO, "deposit 0 must not survive a failed block");
        assert_eq!(snapshot(&state), pre);

        // (d) Re-proposing the corrected block mints the escrow exactly once.
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput { context, deposits: vec![escrow], txs: vec![] },
        )
        .unwrap();
        assert_eq!(out.minted_wei, sats_to_wei(3 * SATS_PER_BLCH));
        assert_eq!(state.balance_of(&BOB), sats_to_wei(3 * SATS_PER_BLCH), "3 BLCH escrowed => 3 BLCH minted, not 6");
        assert_eq!(state.total_minted_wei(), sats_to_wei(3 * SATS_PER_BLCH));
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }
}


/// C03 [high] — Sequencer boundary only blacklists tx_type 3: any tx_type >= 5 (including the reserved OP deposit type 0x7E) reaches revm as `TransactionType::Custom`, skips all fee/chain-id validation, and the executor then credits basefee*gas_used to the BaseFeeVault that nobody paid (unbacked supply inflation, free gas)
mod c03 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    /// C03: transaction types outside {0,1,2} must be rejected at the sequencer
    /// boundary (CANCUN); in particular a Custom-type (>= 5, e.g. the reserved
    /// OP deposit byte 0x7E) tx with gas_price 0 must never execute and must
    /// never cause basefee*gas to be credited to the BaseFeeVault unbacked.
    #[test]
    #[ignore]
    fn c03_unsupported_tx_types_are_rejected_and_never_inflate_supply() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BOB: Address = address!("0000000000000000000000000000000000000b0b");
        const GWEI: u128 = 1_000_000_000;
        let spec = ChainSpec::testnet();

        let funded = || {
            let mut s = L2State::new();
            execute_block(&spec, &mut s, BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: vec![DepositMint {
                    recipient: ALICE,
                    mint_wei: sats_to_wei(10 * SATS_PER_BLCH),
                    provenance: DepositProvenance::BridgedBlch { l1_txid: [7; 32], l1_vout: 1, l1_sats: 10 * SATS_PER_BLCH },
                }],
                txs: vec![],
            }).unwrap();
            s
        };
        let tx = |tx_type: u8, gas_price: u128| TxEnv {
            tx_type,
            caller: ALICE,
            gas_limit: 21_000,
            gas_price,
            kind: TxKind::Call(BOB),
            value: U256::ZERO,
            data: Bytes::new(),
            nonce: 0,
            chain_id: Some(spec.chain_id),
            access_list: Default::default(),
            gas_priority_fee: None,
            blob_hashes: vec![],
            max_fee_per_blob_gas: 0,
            authorization_list: vec![],
        };

        // Well-priced txs of every unsupported type must be rejected before the EVM.
        for t in [4u8, 5, 0x10, 0x7E, 0xFE, 0xFF] {
            let mut s = funded();
            let res = execute_block(&spec, &mut s, BlockInput {
                context: BlockContext::default(), deposits: vec![], txs: vec![tx(t, 2 * GWEI)],
            });
            assert!(res.is_err(), "tx_type 0x{t:02x} must be rejected at CANCUN");
        }

        // A zero-priced Custom-type tx must not execute and must not create wei.
        // (`<=` rather than `==` keeps this test focused on C03: the executor
        // currently drops `state.db` on Err, which is tracked separately.)
        let mut s = funded();
        let minted = s.total_minted_wei();
        let res = execute_block(&spec, &mut s, BlockInput {
            context: BlockContext::default(), deposits: vec![], txs: vec![tx(0x7E, 0)],
        });
        assert!(res.is_err(), "zero-priced type-0x7E tx must be rejected");
        assert!(s.total_native_wei() <= minted, "supply was inflated by an unpaid basefee credit");
        assert_eq!(s.balance_of(&spec.base_fee_vault), U256::ZERO, "BaseFeeVault received wei nobody paid");
    }
}


/// C04 [critical] — Stateless post-state root is computed from an unauthenticated proof: stateless_new_root takes no prev_state_root and collect_sparse never hash-links descended nodes, so injected or tampered proof nodes forge the committed new state root while hydrate_and_verify still passes
mod c04 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // Place under tests/ with #[ignore]. Fails today: hydrate_and_verify accepts a
    // proof carrying an injected node that lies on no hydrated-account path, and
    // stateless_new_root then reconstructs a DIFFERENT (forged) post-state root.
    // After the fix (authenticate the proof against prev_state_root), a tampered
    // proof is rejected before it can change the committed root, and this passes.
    use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256};
    use alloy_trie::nodes::{LeafNode, TrieNode};
    use alloy_trie::{Nibbles, EMPTY_ROOT_HASH};
    use alloy_rlp::{Decodable, Encodable, Header};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify};
    use bloch_l2_evm::stateroot::stateless_new_root;
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint,
        DepositProvenance, L2State,
    };
    use revm::context::TxEnv;

    #[test]
    #[ignore = "fix-tracking: stateless proof path is not anchored to prev_state_root (C04)"]
    fn injected_proof_node_must_not_forge_new_state_root() {
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        for i in 1u8..=40 {
            let mut b = [0u8; 20];
            b[19] = i;
            let d = DepositMint {
                recipient: Address::from(b),
                mint_wei: sats_to_wei(5 * 100_000_000),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [9; 32], l1_vout: 0, l1_sats: 5 * 100_000_000 },
            };
            execute_block(&spec, &mut pre, BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: vec![d], txs: vec![],
            }).unwrap();
        }
        let alice = address!("0000000000000000000000000000000000000001");
        let bob = address!("0000000000000000000000000000000000000b0b");
        let tx = TxEnv::builder().caller(alice).kind(TxKind::Call(bob))
            .value(sats_to_wei(100_000_000)).gas_limit(21_000)
            .max_fee_per_gas(spec.initial_base_fee as u128 + 1_000_000_000)
            .gas_priority_fee(Some(1_000_000_000)).nonce(0).chain_id(Some(spec.chain_id))
            .build().unwrap();
        let (w, _) = generate_batch_witness(&pre, &spec, BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![], txs: vec![tx],
        }).unwrap();

        // Inject a fabricated leaf at an opaque branch child path that is absent
        // from the proof and lies on no hydrated/changed key path.
        let hydrated: Vec<Nibbles> = w.pre_accounts.iter().map(|a| Nibbles::unpack(keccak256(a.address))).collect();
        let mut inject_at: Option<Nibbles> = None;
        for (path, bytes) in &w.proof {
            if let TrieNode::Branch(b) = TrieNode::decode(&mut bytes.as_ref()).unwrap() {
                for nib in 0u8..16 {
                    if (b.state_mask.get() >> nib) & 1 == 0 { continue; }
                    let mut cp = path.clone(); cp.push(nib);
                    if !w.proof.contains_key(&cp)
                        && !hydrated.iter().any(|k| k.starts_with(&cp))
                        && !w.changes.keys().any(|k| k.starts_with(&cp)) {
                        inject_at = Some(cp); break;
                    }
                }
            }
            if inject_at.is_some() { break; }
        }
        let cp = inject_at.expect("an opaque sibling exists");
        let rest = Nibbles::from_nibbles(vec![0u8; 64 - cp.len()]);
        let mut val = Vec::new();
        {
            // rlp([nonce, balance, storageRoot, codeHash]) exactly as Ethereum encodes an account.
            let nonce: u64 = 0;
            let balance: U256 = U256::from(1u64) << 200;
            let storage_root: B256 = EMPTY_ROOT_HASH;
            let code_hash: B256 = revm::primitives::KECCAK_EMPTY;
            let payload = nonce.length() + balance.length() + storage_root.length() + code_hash.length();
            Header { list: true, payload_length: payload }.encode(&mut val);
            nonce.encode(&mut val);
            balance.encode(&mut val);
            storage_root.encode(&mut val);
            code_hash.encode(&mut val);
        }
        let mut tampered = w.proof.clone();
        tampered.insert(cp, Bytes::from(alloy_rlp::encode(&LeafNode::new(rest, val))));

        // CORRECT behaviour: an injected node not authenticated by prev_state_root
        // must be rejected before it can change the committed root -- so either the
        // guest anchor rejects the tampered proof, or the reconstructed root is
        // still exactly the honest new_state_root. Neither holds today.
        let anchored = hydrate_and_verify(&w.pre_accounts, &tampered, w.prev_state_root).is_err();
        let forged = stateless_new_root(&tampered, &w.changes);
        assert!(anchored || forged == w.new_state_root,
            "tampered proof must be rejected or must not change the committed new state root (got forged={forged:?}, honest={:?})", w.new_state_root);
        let _ = B256::ZERO;
    }
}


/// C05 [high] — hydrate_and_verify proves only inclusion of the host-chosen pre_accounts, never completeness: an existing, touched pre-state account can be omitted, the guest re-executes against a false empty account, and the honest multiproof then yields a derivable, wrong post-state root
mod c05 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // tests/c05_hydrate_omitted_account.rs
    // Fix-tracking test for C05: a witness whose `pre_accounts` omits an EXISTING
    // account the batch touches must be rejected by the guest-side verification, or
    // at minimum must not let the guest re-execute against a false empty account.
    // Today `hydrate_and_verify` returns Ok and the guest sees the recipient at 0.
    use alloy_primitives::{keccak256, Address, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify, WitnessAccount};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    fn deposit(to: Address, sats: u64) -> DepositMint {
        DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
        }
    }
    fn addr(i: u64) -> Address {
        Address::from_slice(&keccak256(i.to_be_bytes())[12..])
    }

    #[test]
    #[ignore = "C05: hydrate_and_verify has no completeness / non-inclusion check"]
    fn omitted_existing_touched_pre_account_must_be_rejected_or_not_change_execution() {
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        let deposits: Vec<_> = (0..30).map(|i| deposit(addr(i), 5 * SATS_PER_BLCH)).collect();
        execute_block(
            &spec,
            &mut pre,
            BlockInput { context: BlockContext { number: 0, ..Default::default() }, deposits, txs: vec![] },
        )
        .unwrap();
        let sender = addr(3);
        let recipient = addr(7); // EXISTING account holding 5 BLCH
        assert_eq!(pre.balance_of(&recipient), sats_to_wei(5 * SATS_PER_BLCH));

        let batch = || {
            let tx = TxEnv::builder()
                .caller(sender)
                .kind(TxKind::Call(recipient))
                .value(sats_to_wei(SATS_PER_BLCH))
                .gas_limit(21_000)
                .max_fee_per_gas(spec.initial_base_fee as u128 + 1_000_000_000)
                .gas_priority_fee(Some(1_000_000_000))
                .nonce(0)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap();
            BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits: vec![], txs: vec![tx] }
        };

        // Oracle: full execution.
        let mut full = pre.clone();
        execute_block(&spec, &mut full, batch()).unwrap();
        let honest_post_balance = full.balance_of(&recipient);
        assert_eq!(honest_post_balance, sats_to_wei(6 * SATS_PER_BLCH));

        let (w, _) = generate_batch_witness(&pre, &spec, batch()).unwrap();
        assert!(w.pre_accounts.iter().any(|a| a.address == recipient), "honest witness carries the recipient");

        // Malicious host: drop the touched, funded recipient; proof and roots untouched.
        let malicious: Vec<WitnessAccount> =
            w.pre_accounts.iter().filter(|a| a.address != recipient).cloned().collect();

        match hydrate_and_verify(&malicious, &w.proof, w.prev_state_root) {
            Err(_) => {} // correct: incomplete witness rejected
            Ok(mut guest) => {
                // If hydration is accepted, re-execution must still agree with the
                // full execution (i.e. the guest must not have read a false empty account).
                let out = execute_block(&spec, &mut guest, batch());
                assert!(out.is_err() || guest.balance_of(&recipient) == honest_post_balance,
                    "guest re-executed against a false empty recipient: saw {} wei, honest {} wei",
                    guest.balance_of(&recipient), honest_post_balance);
            }
        }

        // An EIP-161-empty WitnessAccount at an address that really holds 5 BLCH is
        // equivalent to omission and must not be accepted unverified either.
        let mut with_empty = w.pre_accounts.clone();
        with_empty.push(WitnessAccount { address: addr(11), balance: U256::ZERO, nonce: 0, code: vec![], storage: vec![] });
        assert!(
            hydrate_and_verify(&with_empty, &w.proof, w.prev_state_root).is_err(),
            "an unproven empty pre-account at a funded address must be rejected"
        );
    }
}


/// C06 [high] — Witness access set omits every read-only (touched-but-unchanged) account and the guest has no exclusion proofs: generate_batch_witness returns Ok, hydrate_and_verify passes, and guest re-execution silently diverges from the host post-state root
mod c06 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify};
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State,
    };
    use revm::context::TxEnv;

    /// C06 fix-tracking test: a batch that READS an unchanged account (BALANCE of a
    /// funded EOA `D`, written by contract `C` into its slot 0) must yield a witness
    /// the guest can replay faithfully. Correct behaviour is either (a) the
    /// generator rejects the batch as unprovable, or (b) `hydrate_and_verify` +
    /// `execute_block` on the guest reproduces the host's post-state for `C`.
    /// Today (a) does not happen and (b) fails: the guest reads BALANCE(D) = 0.
    #[test]
    #[ignore = "C06: read-only accounts are omitted from the witness access set"]
    fn witness_access_set_covers_read_only_accounts_so_guest_replay_matches_host() {
        const GWEI: u128 = 1_000_000_000;
        const BLCH: u64 = 100_000_000;
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const D: Address = address!("00000000000000000000000000000000000000d4");

        let spec = ChainSpec::testnet();
        let dep = |to: Address, sats: u64| DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [9; 32], l1_vout: 0, l1_sats: sats },
        };
        let tx = |nonce: u64, kind: TxKind, data: Vec<u8>, gas: u64| {
            TxEnv::builder()
                .caller(ALICE)
                .kind(kind)
                .data(Bytes::from(data))
                .gas_limit(gas)
                .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(nonce)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap()
        };
        let slot0 = |s: &L2State, a: Address| -> U256 {
            s.db.cache.accounts.get(&a).and_then(|acc| acc.storage.get(&U256::ZERO).copied()).unwrap_or_default()
        };

        // Pre-state: ALICE, read-only D (7 BLCH), 10 noise accounts, and contract C
        // with runtime `PUSH20 D; BALANCE; PUSH1 0; SSTORE; STOP`.
        let mut pre = L2State::new();
        let mut deps = vec![dep(ALICE, 100 * BLCH), dep(D, 7 * BLCH)];
        for i in 1u8..=10 {
            deps.push(dep(Address::from([i; 20]), 3 * BLCH));
        }
        let mut runtime = vec![0x73u8];
        runtime.extend_from_slice(D.as_slice());
        runtime.extend_from_slice(&[0x31, 0x60, 0x00, 0x55, 0x00]);
        let len = runtime.len() as u8;
        // PUSH1 len PUSH1 0x0c PUSH1 0 CODECOPY PUSH1 len PUSH1 0 RETURN <runtime>
        let mut init = vec![0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3];
        init.extend_from_slice(&runtime);
        let out = execute_block(
            &spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: deps,
                txs: vec![tx(0, TxKind::Create, init, 300_000)],
            },
        )
        .unwrap();
        assert!(out.tx_outcomes[0].success);
        let c = out.tx_outcomes[0].created_address.unwrap();

        let batch = || BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(1, TxKind::Call(c), vec![], 120_000)],
        };

        // Host oracle.
        let mut full = pre.clone();
        let full_out = execute_block(&spec, &mut full, batch()).unwrap();
        assert!(full_out.tx_outcomes[0].success);
        assert_eq!(slot0(&full, c), sats_to_wei(7 * BLCH));

        // Either the generator refuses (batch not provable with this witness
        // format), or the witness must let the guest reproduce the host exactly.
        let Ok((w, host_out)) = generate_batch_witness(&pre, &spec, batch()) else {
            return; // acceptable: generation rejected an incomplete access set
        };
        let mut guest = hydrate_and_verify(&w.pre_accounts, &w.proof, w.prev_state_root).expect("witness opens");
        let guest_out = execute_block(&spec, &mut guest, batch()).unwrap();

        assert_eq!(guest_out.tx_outcomes[0].success, host_out.tx_outcomes[0].success);
        assert_eq!(guest_out.tx_outcomes[0].gas_used, host_out.tx_outcomes[0].gas_used);
        assert_eq!(
            slot0(&guest, c),
            slot0(&full, c),
            "guest must observe BALANCE(D) exactly as the host did; the read-only account D must be provided (and provable) in the witness"
        );
        assert_eq!(guest.balance_of(&D), full.balance_of(&D), "read-only D is part of the guest's verified pre-state");
    }
}


/// C07 [high] — Honest witnesses are rejected by hydrate_and_verify for any zero-value call that SLOADs an empty slot or SSTOREs 0->0: pre_accounts is selected by raw CacheDB diff while proof targets are selected by trie-leaf diff, so the touched contract has no path in the multiproof
mod c07 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{bytes, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::{compute_keccak_mpt_state_root, sats_to_wei, ChainSpec};
    use revm::context::TxEnv;

    const GWEI: u128 = 1_000_000_000;
    const SATS_PER_BLCH: u64 = 100_000_000;

    fn deposit(to: Address, sats: u64) -> DepositMint {
        DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
        }
    }

    fn tx(spec: &ChainSpec, caller: Address, kind: TxKind, data: Bytes, nonce: u64) -> TxEnv {
        TxEnv::builder()
            .caller(caller)
            .kind(kind)
            .data(data)
            .value(U256::ZERO)
            .gas_limit(300_000)
            .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap()
    }

    /// 60 funded EOAs + one contract deployed in block 0; block 1 = a zero-value
    /// call to it. The witness the host produces MUST open in the guest and the
    /// guest re-execution MUST match the full execution.
    fn honest_witness_round_trips(initcode: Bytes) {
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        let addrs: Vec<Address> = (1..=60u8).map(|i| Address::from([i; 20])).collect();
        let alice = addrs[0];
        let out0 = execute_block(
            &spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: addrs.iter().map(|a| deposit(*a, 10 * SATS_PER_BLCH)).collect(),
                txs: vec![tx(&spec, alice, TxKind::Create, initcode, 0)],
            },
        )
        .unwrap();
        assert!(out0.tx_outcomes[0].success);
        let contract = out0.tx_outcomes[0].created_address.unwrap();

        let batch = || BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(&spec, alice, TxKind::Call(contract), Bytes::new(), 1)],
        };

        let mut full = pre.clone();
        let full_out = execute_block(&spec, &mut full, batch()).unwrap();
        assert!(full_out.tx_outcomes[0].success);
        let full_root = compute_keccak_mpt_state_root(&full);

        let (w, _) = generate_batch_witness(&pre, &spec, batch()).expect("host generates witness");
        assert_eq!(w.new_state_root, full_root);

        // CORRECT behaviour: an honest witness opens against prev_state_root.
        let mut guest = hydrate_and_verify(&w.pre_accounts, &w.proof, w.prev_state_root)
            .expect("honest witness for a zero-value contract call must open against prev_state_root");

        // And the guest, re-executing on the hydrated state, reproduces the batch.
        let g = execute_block(&spec, &mut guest, batch()).unwrap();
        assert_eq!(g.tx_outcomes[0].success, full_out.tx_outcomes[0].success);
        assert_eq!(g.tx_outcomes[0].gas_used, full_out.tx_outcomes[0].gas_used, "guest must see the contract code");
    }

    /// runtime `PUSH1 0 SLOAD STOP` — reads an empty slot, changes nothing.
    #[test]
        #[ignore = "AUDIT C07 (high): fails until the finding is fixed"]
    fn c07_honest_witness_opens_for_sload_of_empty_slot() {
        honest_witness_round_trips(bytes!("63600054006000526004601cf3"));
    }

    /// runtime `PUSH1 0 PUSH1 0 SSTORE STOP` — writes 0 to an empty slot.
    #[test]
        #[ignore = "AUDIT C07 (high): fails until the finding is fixed"]
    fn c07_honest_witness_opens_for_sstore_zero_to_zero() {
        honest_witness_round_trips(bytes!("656000600055006000526006601af3"));
    }
}


/// C08 [high] — stateless_new_root silently drops an entire opaque frontier subtree when a change key descends into it (and silently no-ops deletes of non-exposed keys) — wrong root, no error, even with an anchored proof and verified pre-state
mod c08 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    //! C08 fix-tracking test: `stateless_new_root` must REFUSE (abort / error) when a
    //! change key lands inside an opaque frontier subtree instead of silently emitting a
    //! partial trie. Today the primitive returns a wrong root, so this test FAILS.
    //! If the fix changes the signature to `Result<B256, _>`, replace the `catch_unwind`
    //! assertion with `.is_err()`.
    use alloy_primitives::{address, keccak256, Address, Bytes, TxKind};
    use alloy_trie::Nibbles;
    use std::collections::BTreeMap;

    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance};
    use bloch_l2_evm::stateroot::stateless_new_root;
    use bloch_l2_evm::{ChainSpec, L2State};
    use revm::context::TxEnv;

    #[test]
    #[ignore = "C08: stateless_new_root silently drops opaque subtrees a change reaches into"]
    fn stateless_new_root_refuses_a_change_inside_an_opaque_subtree() {
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        for i in 1u8..=20 {
            let mut b = [0u8; 20];
            b[19] = i;
            let a = Address::from(b);
            execute_block(
                &spec,
                &mut pre,
                BlockInput {
                    context: BlockContext { number: 0, ..Default::default() },
                    deposits: vec![DepositMint {
                        recipient: a,
                        mint_wei: sats_to_wei(5 * SATS_PER_BLCH),
                        provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: 5 * SATS_PER_BLCH },
                    }],
                    txs: vec![],
                },
            )
            .unwrap();
        }
        let alice = address!("0000000000000000000000000000000000000001");
        let batch = |to: Address| {
            let tx = TxEnv::builder()
                .caller(alice)
                .kind(TxKind::Call(to))
                .value(sats_to_wei(SATS_PER_BLCH))
                .gas_limit(21_000)
                .max_fee_per_gas(spec.initial_base_fee as u128 + 1_000_000_000)
                .gas_priority_fee(Some(1_000_000_000))
                .nonce(0)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap();
            BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits: vec![], txs: vec![tx] }
        };

        // Find a NEW recipient whose root-child subtree already holds untouched accounts
        // and none of the hydrated pre-accounts, then strip that subtree from the proof
        // (what a malicious prover can do while the proof stays anchored to prev_state_root
        // and every hydrated pre-account still opens).
        let mut found = None;
        for last in 0x10u8..=0xffu8 {
            let mut b = [0u8; 20];
            b[18] = 0xbb;
            b[19] = last;
            let bob = Address::from(b);
            let nib = keccak256(bob)[0] >> 4;
            if !pre.db.cache.accounts.keys().any(|a| keccak256(a)[0] >> 4 == nib) {
                continue;
            }
            let Ok((w, _)) = generate_batch_witness(&pre, &spec, batch(bob)) else { continue };
            let stripped: BTreeMap<Nibbles, Bytes> = w
                .proof
                .iter()
                .filter(|(p, _)| p.get(0) != Some(nib))
                .map(|(p, b)| (p.clone(), b.clone()))
                .collect();
            if stripped.len() == w.proof.len() {
                continue;
            }
            if hydrate_and_verify(&w.pre_accounts, &stripped, w.prev_state_root).is_err() {
                continue;
            }
            found = Some((w, stripped));
            break;
        }
        let (w, stripped) = found.expect("a recipient whose subtree holds only untouched accounts");
        assert_eq!(keccak256(stripped.get(&Nibbles::default()).unwrap()), w.prev_state_root, "proof stays anchored");
        assert_eq!(stateless_new_root(&w.proof, &w.changes), w.new_state_root, "honest witness reconstructs");

        // CORRECT behaviour: the insert key descends into an opaque subtree => the witness
        // is incomplete and the primitive must refuse, never return a root.
        let refused = std::panic::catch_unwind(|| stateless_new_root(&stripped, &w.changes)).is_err();
        assert!(
            refused,
            "stateless_new_root returned a root ({:#x}) for a change landing inside an opaque subtree; it must abort/error",
            stateless_new_root(&stripped, &w.changes)
        );
    }
}


/// C09 [high] — Guest post-state root is host-controlled: BatchWitness.changes is a trusted host input, the crate offers no guest-side change-set derivation (account_leaves is pub(crate)), and the shipped guest flow commits stateless_new_root(proof, witness.changes)
mod c09 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, keccak256, Address, TxKind, U256};
    use alloy_rlp::{Encodable, Header};
    use alloy_trie::{Nibbles, EMPTY_ROOT_HASH};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify};
    use bloch_l2_evm::stateroot::stateless_new_root;
    use bloch_l2_evm::{
        compute_keccak_mpt_state_root, execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec,
        DepositMint, DepositProvenance, L2State,
    };
    use revm::context::TxEnv;
    use revm::primitives::KECCAK_EMPTY;

    /// C09: the guest-attested post-root must be a function of the guest's OWN
    /// re-execution of the proven pre-state, never of a host-supplied change set.
    /// Today the only guest path is `stateless_new_root(proof, witness.changes)`
    /// (the pattern in proving.rs:343-350), so tampering with `changes` flips the
    /// attested root and this test fails.
    #[test]
        #[ignore = "AUDIT C09 (high): fails until the finding is fixed"]
    fn c09_guest_post_root_must_not_depend_on_host_supplied_changes() {
        const SATS_PER_BLCH: u64 = 100_000_000;
        let spec = ChainSpec::testnet();
        let mut pre = L2State::new();
        for i in 1u8..=8 {
            let mut b = [0u8; 20];
            b[19] = i;
            let dep = DepositMint {
                recipient: Address::from(b),
                mint_wei: sats_to_wei(5 * SATS_PER_BLCH),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: 5 * SATS_PER_BLCH },
            };
            execute_block(
                &spec,
                &mut pre,
                BlockInput { context: BlockContext { number: 0, ..Default::default() }, deposits: vec![dep], txs: vec![] },
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
            BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits: vec![], txs: vec![tx] }
        };

        // Oracle root from full execution.
        let mut full = pre.clone();
        execute_block(&spec, &mut full, make_batch()).unwrap();
        let honest_root = compute_keccak_mpt_state_root(&full);

        // Honest witness, then a malicious host tampers ONLY `changes`: Alice's
        // post-leaf is rewritten to rlp[nonce=1, balance=10^30, EMPTY_ROOT_HASH, KECCAK_EMPTY].
        let (mut w, _) = generate_batch_witness(&pre, &spec, make_batch()).unwrap();
        let mut leaf = Vec::new();
        let (nonce, bal) = (1u64, U256::from(10u128.pow(30)));
        Header {
            list: true,
            payload_length: nonce.length() + bal.length() + EMPTY_ROOT_HASH.length() + KECCAK_EMPTY.length(),
        }
        .encode(&mut leaf);
        nonce.encode(&mut leaf);
        bal.encode(&mut leaf);
        EMPTY_ROOT_HASH.encode(&mut leaf);
        KECCAK_EMPTY.encode(&mut leaf);
        w.changes.insert(Nibbles::unpack(keccak256(alice)), Some(leaf));

        // Guest flow as the crate demonstrates it: hydrate+verify, re-execute, commit.
        let mut guest = hydrate_and_verify(&w.pre_accounts, &w.proof, w.prev_state_root).unwrap();
        execute_block(&spec, &mut guest, make_batch()).unwrap();
        assert_eq!(guest.balance_of(&alice), full.balance_of(&alice), "re-execution is honest");

        // CORRECT behaviour: the guest's attested post-root is determined by its own
        // re-execution, so tampering with the witness's `changes` cannot move it.
        // (After the fix, replace this call with the guest-side root derivation that
        // consumes the hydrated pre-state + re-executed post-state and ignores
        // witness.changes — or expect it to return Err on the mismatch.)
        let attested = stateless_new_root(&w.proof, &w.changes);
        assert_eq!(
            attested, honest_root,
            "guest attested a host-chosen root: `changes` must be derived from re-execution, not trusted from the witness"
        );
    }
}


/// C10 [high] — No deposit replay protection: the same L1 escrow outpoint (l1_txid, l1_vout) mints repeatedly within a block, across blocks, and through the proving path, and consumed outpoints are not committed to state
mod c10 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, U256};
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance,
        L2State,
    };

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const SATS_PER_BLCH: u64 = 100_000_000;

    fn escrow_7_1(l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient: ALICE,
            mint_wei: sats_to_wei(l1_sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [7u8; 32], l1_vout: 1, l1_sats },
        }
    }

    fn block(number: u64, deposits: Vec<DepositMint>) -> BlockInput {
        BlockInput { context: BlockContext { number, ..Default::default() }, deposits, txs: vec![] }
    }

    /// C10: one L1 escrow output (l1_txid, l1_vout) must mint exactly once.
    /// A duplicate inside a block, a replay in a later block, and a re-use of the
    /// outpoint with a different amount must all be rejected without changing state.
    #[test]
        #[ignore = "AUDIT C10 (high): fails until the finding is fixed"]
    fn deposit_outpoint_cannot_be_minted_twice() {
        let spec = ChainSpec::testnet();
        let one_blch = escrow_7_1(SATS_PER_BLCH);

        // Intra-block duplicate: the whole block must be rejected and nothing minted.
        let mut state = L2State::new();
        assert!(
            execute_block(&spec, &mut state, block(1, vec![one_blch, one_blch])).is_err(),
            "same (l1_txid, l1_vout) twice in one block must be rejected"
        );
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert_eq!(state.total_minted_wei(), U256::ZERO);

        // Cross-block replay: first use is fine, second use must fail and be a no-op.
        let mut state = L2State::new();
        execute_block(&spec, &mut state, block(1, vec![one_blch])).expect("first use of the outpoint mints");
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(SATS_PER_BLCH));
        assert!(
            execute_block(&spec, &mut state, block(2, vec![one_blch])).is_err(),
            "replaying a consumed outpoint in a later block must be rejected"
        );
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(SATS_PER_BLCH));
        assert_eq!(state.total_minted_wei(), sats_to_wei(SATS_PER_BLCH));
        assert_eq!(state.total_native_wei(), state.total_minted_wei());

        // Same outpoint, different claimed amount: still the same consumed escrow.
        assert!(
            execute_block(&spec, &mut state, block(3, vec![escrow_7_1(10 * SATS_PER_BLCH)])).is_err(),
            "a consumed outpoint cannot be re-used with a different l1_sats"
        );
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(SATS_PER_BLCH));
    }
}


/// C11 [medium] — EIP-6780 SELFDESTRUCT-to-self in the creating transaction burns bridged BLCH: the documented "never burned / total native supply == total minted / L1 escrow always balances" invariant is false under unmodified Cancun revm and is untested
mod c11 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // tests/c11_selfdestruct_burn.rs
    // Fix-tracking test for C11. Asserts the invariant the crate documents today
    // (bridged BLCH is never burned, so total native supply == total minted). It
    // FAILS under unmodified Cancun revm because EIP-6780 SELFDESTRUCT-to-self in
    // the creating tx zeroes the balance without crediting anyone. If the chosen
    // fix is to document the burn and add `L2State::total_burned_wei()` instead of
    // re-routing, change the final assertion to
    // `total_native_wei == total_minted_wei - total_burned_wei` and assert
    // `total_burned_wei == value`.
    use alloy_primitives::{address, bytes, Address, TxKind, U256};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::{execute_block, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State};
    use revm::context::TxEnv;

    #[test]
    #[ignore = "C11: EIP-6780 selfdestruct-to-self burns bridged BLCH; 'never burn' invariant is false"]
    fn c11_selfdestruct_to_self_in_creating_tx_must_not_break_supply_invariant() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const GWEI: u128 = 1_000_000_000;
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // Block 1: fund ALICE with 10 bridged BLCH.
        let l1_sats = 10 * SATS_PER_BLCH;
        execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 1, ..Default::default() },
                deposits: vec![DepositMint {
                    recipient: ALICE,
                    mint_wei: sats_to_wei(l1_sats),
                    provenance: DepositProvenance::BridgedBlch { l1_txid: [7; 32], l1_vout: 1, l1_sats },
                }],
                txs: vec![],
            },
        )
        .expect("funding block");
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
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![], txs: vec![tx] },
        )
        .expect("block");
        assert!(out.tx_outcomes[0].success, "the selfdestruct-to-self CREATE is a valid, successful tx");
        assert!(state.account(&ALICE.create(0)).is_none(), "EIP-6780: account created in-tx is destroyed");

        // Documented invariant (src/state.rs:7-13, src/lib.rs:32-33): bridged BLCH is never
        // burned, so total native supply == total minted after any block. Fails today by
        // exactly `value`.
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


/// C12 [high] — hydrate_and_verify never binds EIP-161-empty pre-accounts to prev_state_root: host-planted storage under a code-less address is hydrated unverified and leaks into the guest's post-state leaf/root after a plain value transfer
mod c12 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use std::collections::BTreeMap;

    use alloy_primitives::{address, Address, TxKind, U256};
    use alloy_trie::EMPTY_ROOT_HASH;
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify, WitnessAccount};
    use bloch_l2_evm::{execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State};
    use revm::context::TxEnv;

    /// C12: every WitnessAccount must be bound to prev_state_root. An EIP-161-empty
    /// entry carrying storage cannot exist in a Cancun state trie and must be rejected,
    /// both when appended to an otherwise valid witness and against an empty proof.
    #[test]
    #[ignore = "C12 fix-tracking: hydrate_and_verify accepts unverified EIP-161-empty pre-accounts"]
    fn hydrate_and_verify_rejects_unverified_eip161_empty_accounts_with_storage() {
        const SATS_PER_BLCH: u64 = 100_000_000;
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
                    deposits: vec![DepositMint {
                        recipient: Address::from(b),
                        mint_wei: sats_to_wei(5 * SATS_PER_BLCH),
                        provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: 5 * SATS_PER_BLCH },
                    }],
                    txs: vec![],
                },
            )
            .unwrap();
        }
        let alice = address!("0000000000000000000000000000000000000001");
        let bob = address!("00000000000000000000000000000000000000bb"); // absent from the pre-state trie
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
        let batch = BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits: vec![], txs: vec![tx] };
        let (w, _) = generate_batch_witness(&pre, &spec, batch).unwrap();
        assert!(hydrate_and_verify(&w.pre_accounts, &w.proof, w.prev_state_root).is_ok(), "honest witness opens");

        let planted = WitnessAccount {
            address: bob,
            balance: U256::ZERO,
            nonce: 0,
            code: vec![],
            storage: vec![(U256::from(1), U256::from(0xdead))],
        };

        // (1) appended to a valid witness: the ghost has no leaf in prev_state_root and carries
        // storage no code-less account can have -> must be rejected.
        let mut bad = w.pre_accounts.clone();
        bad.push(planted.clone());
        assert!(
            hydrate_and_verify(&bad, &w.proof, w.prev_state_root).is_err(),
            "EIP-161-empty pre-account with host-planted storage must not be hydrated unverified"
        );

        // (2) the degenerate shape: empty-with-storage entry, empty proof, empty root.
        assert!(
            hydrate_and_verify(&[planted], &BTreeMap::new(), EMPTY_ROOT_HASH).is_err(),
            "storage-carrying EIP-161-empty account must be rejected even against the empty trie"
        );
    }
}


/// C13 [medium] — Block environment (base fee, number, timestamp, prevrandao) is caller-trusted: execute_block never enforces ChainSpec::next_base_fee or parent-header monotonicity, so fee routing and header fields are an operator choice and the witness path proves blocks under arbitrary headers
mod c13 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, TxKind, B256, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");
    const GWEI: u128 = 1_000_000_000;

    /// Header-validity rule tracker (finding C13): after a genesis block, `execute_block`
    /// must reject a child block whose base fee != `ChainSpec::next_base_fee(parent)`,
    /// whose number != parent + 1, or whose timestamp regresses, and must accept the
    /// rule-conforming header. Fails today because the block environment is never checked.
    #[test]
    #[ignore]
    fn block_header_fields_are_validated_against_parent_and_eip1559_rule() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let deposit = DepositMint {
            recipient: ALICE,
            mint_wei: sats_to_wei(10 * SATS_PER_BLCH),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [7; 32], l1_vout: 1, l1_sats: 10 * SATS_PER_BLCH },
        };
        // Genesis: block 0, timestamp 1000, base fee = initial_base_fee, gas_used 0.
        execute_block(&spec, &mut state, BlockInput {
            context: BlockContext { number: 0, timestamp: 1_000, base_fee_per_gas: spec.initial_base_fee, prevrandao: B256::ZERO },
            deposits: vec![deposit],
            txs: vec![],
        }).expect("genesis executes");
        let expected_bf = spec.next_base_fee(spec.initial_base_fee, 0);
        let good = BlockContext { number: 1, timestamp: 1_002, base_fee_per_gas: expected_bf, prevrandao: B256::ZERO };
        let tx = |nonce: u64| TxEnv::builder().caller(ALICE).kind(TxKind::Call(BOB)).value(U256::from(1))
            .gas_limit(21_000).max_fee_per_gas(2 * GWEI).gas_priority_fee(Some(GWEI))
            .nonce(nonce).chain_id(Some(spec.chain_id)).build().unwrap();

        // Wrong base fee (0 and 5 gwei) must be rejected before any state change.
        for bad_bf in [0u64, 5 * GWEI as u64] {
            let mut s = state.clone();
            let ctx = BlockContext { base_fee_per_gas: bad_bf, ..good.clone() };
            let res = execute_block(&spec, &mut s, BlockInput { context: ctx, deposits: vec![], txs: vec![tx(0)] });
            assert!(res.is_err(), "base fee {bad_bf} != next_base_fee {expected_bf} must be rejected");
            assert_eq!(s.balance_of(&BOB), U256::ZERO, "rejected block must not advance state");
        }
        // Block number regression / duplicate / skip must be rejected.
        for bad_number in [0u64, 2, 7] {
            let mut s = state.clone();
            let ctx = BlockContext { number: bad_number, ..good.clone() };
            assert!(execute_block(&spec, &mut s, BlockInput { context: ctx, deposits: vec![], txs: vec![] }).is_err(),
                "block number {bad_number} after parent 0 must be rejected");
        }
        // Timestamp regression must be rejected.
        {
            let mut s = state.clone();
            let ctx = BlockContext { timestamp: 999, ..good.clone() };
            assert!(execute_block(&spec, &mut s, BlockInput { context: ctx, deposits: vec![], txs: vec![] }).is_err(),
                "timestamp 999 < parent 1000 must be rejected");
        }
        // The rule-conforming header is accepted and routes fees per the 1559 split.
        let out = execute_block(&spec, &mut state, BlockInput { context: good, deposits: vec![], txs: vec![tx(0)] })
            .expect("conforming header executes");
        assert_eq!(out.base_fee_per_gas, expected_bf);
        assert_eq!(out.base_fee_routed_wei, U256::from(expected_bf) * U256::from(21_000u64));
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::from(expected_bf) * U256::from(21_000u64));
    }
}


/// C15 [medium] — Unprotected (pre-EIP-155, chain_id = None) legacy transactions are accepted by execute_block: the STF provides no cross-chain replay protection for type-0 transactions
mod c15 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    /// C15 fix-tracking test: an unprotected (pre-EIP-155, chain_id = None) legacy
    /// transaction MUST be rejected at the STF boundary, so a transaction signed
    /// for another EVM chain cannot be replayed on Bloch L2 (and vice versa).
    /// Today revm's mainnet rule accepts it, so this test fails until a
    /// `tx.chain_id == Some(spec.chain_id)` sequencer-boundary rule is added.
    #[test]
    #[ignore = "C15: unprotected legacy txs are currently accepted by execute_block"]
    fn c15_unprotected_legacy_tx_is_rejected_at_stf_boundary() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BOB: Address = address!("0000000000000000000000000000000000000b0b");
        const GWEI: u128 = 1_000_000_000;

        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: vec![DepositMint {
                    recipient: ALICE,
                    mint_wei: sats_to_wei(10 * SATS_PER_BLCH),
                    provenance: DepositProvenance::BridgedBlch {
                        l1_txid: [7; 32],
                        l1_vout: 1,
                        l1_sats: 10 * SATS_PER_BLCH,
                    },
                }],
                txs: vec![],
            },
        )
        .expect("genesis deposit block");

        // Legacy (type-0) value transfer with NO EIP-155 chain id.
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

        let result = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 1, ..Default::default() },
                deposits: vec![],
                txs: vec![unprotected],
            },
        );

        assert!(
            result.is_err(),
            "STF must reject a legacy tx without EIP-155 chain id (cross-chain replay surface)"
        );
        assert_eq!(state.balance_of(&BOB), U256::ZERO, "no value may move on a rejected tx");
        assert_eq!(state.nonce_of(&ALICE), 0, "sender nonce must not advance on a rejected tx");

        // Control: the same tx WITH the correct chain id must still be accepted.
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
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 1, ..Default::default() },
                deposits: vec![],
                txs: vec![protected],
            },
        )
        .expect("EIP-155-protected legacy tx for this chain is valid");
        assert!(out.tx_outcomes[0].success);
        assert_eq!(state.balance_of(&BOB), sats_to_wei(SATS_PER_BLCH));
    }
}


/// C16 [medium] — BLOCKHASH returns EmptyDB's keccak256(decimal block number) placeholder for the whole 256-block window — no L2 block hashes are ever supplied to the EVM or to the proving witness
mod c16 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256};
    use bloch_l2_evm::{execute_block, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State};
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
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const PROBE: Address = address!("00000000000000000000000000000000000000c0");
        const GWEI: u128 = 1_000_000_000;

        fn deposit(recipient: Address, l1_sats: u64) -> DepositMint {
            DepositMint {
                recipient,
                mint_wei: sats_to_wei(l1_sats),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [7; 32], l1_vout: 1, l1_sats },
            }
        }
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
            execute_block(
                &spec,
                &mut s,
                BlockInput { context: BlockContext { number: 0, ..Default::default() }, deposits, txs: vec![] },
            )
            .unwrap();
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
            let out = execute_block(
                &spec,
                s,
                BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits: vec![], txs: vec![tx] },
            )
            .unwrap();
            let o = &out.tx_outcomes[0];
            assert!(o.success, "probe call must succeed");
            B256::from_slice(o.result.output().unwrap())
        }

        // Two chains whose block 0 differs (different deposits => different post-state).
        let mut a = chain(vec![deposit(ALICE, 10 * SATS_PER_BLCH)]);
        let mut b = chain(vec![deposit(ALICE, 10 * SATS_PER_BLCH), deposit(Address::from([0x99; 20]), 5)]);
        assert_ne!(
            bloch_l2_evm::compute_keccak_mpt_state_root(&a),
            bloch_l2_evm::compute_keccak_mpt_state_root(&b),
            "precondition: the two block-0 states differ"
        );

        let ha = blockhash0_at_block1(&mut a);
        let hb = blockhash0_at_block1(&mut b);

        // Correct behaviour: BLOCKHASH is never the EmptyDB placeholder ...
        let placeholder = keccak256(b"0");
        assert_ne!(ha, placeholder, "BLOCKHASH(0) must not be revm EmptyDB's keccak256(\"0\") placeholder");
        assert_ne!(hb, placeholder, "BLOCKHASH(0) must not be revm EmptyDB's keccak256(\"0\") placeholder");
        // ... and it depends on the actual block that was produced.
        assert_ne!(ha, hb, "BLOCKHASH(0) must differ between two chains whose block 0 differs");
        // Nothing may leak a placeholder into persisted state either.
        assert_ne!(a.db.cache.block_hashes.get(&U256::ZERO), Some(&placeholder));
    }
}


/// C17 [medium] — EIP-4788 beacon-roots block-start system call and predeploy are absent at SpecId::CANCUN: reads of 0x000F...Beac02 return empty success instead of a root/revert (diverges from L1 Cancun and OP-Stack Ecotone)
mod c17 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, bytes, keccak256, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    /// EIP-4788 at Cancun: the beacon-roots predeploy exists from genesis and the
    /// block-start system call populates `timestamps[ts % 8191]` so that a user
    /// `get(block.timestamp)` returns a 32-byte root, while `get(other_ts)` reverts.
    /// Fails today: the predeploy is absent and no system call is performed, so the
    /// account has KECCAK_EMPTY code and the call succeeds with EMPTY output.
    #[test]
    #[ignore = "C17: EIP-4788 beacon-roots system call / predeploy not implemented"]
    fn eip4788_beacon_roots_system_call_is_applied_at_block_start() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BEACON_ROOTS_ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");
        let beacon_roots_code: Bytes = bytes!("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500");
        const GWEI: u128 = 1_000_000_000;
        const T: u64 = 1_700_000_000;

        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // Cancun-at-genesis: the EIP-4788 predeploy must exist in the genesis state.
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
                // If the fix adds `parent_beacon_block_root` to BlockContext, it is
                // taken from Default here; the assertions below are value-agnostic.
                context: BlockContext { number: 1, timestamp: T, ..BlockContext::default() },
                deposits: vec![DepositMint {
                    recipient: ALICE,
                    mint_wei: sats_to_wei(10 * SATS_PER_BLCH),
                    provenance: DepositProvenance::BridgedBlch { l1_txid: [7; 32], l1_vout: 1, l1_sats: 10 * SATS_PER_BLCH },
                }],
                txs: vec![get(0, T), get(1, T + 1)],
            },
        )
        .expect("block executes");

        // get(block.timestamp): the block-start system call stored this block's
        // entry, so the read succeeds with exactly 32 bytes.
        let same_ts = &out.tx_outcomes[0];
        assert!(same_ts.success, "get(block.timestamp) must succeed after the EIP-4788 system call");
        assert_eq!(
            same_ts.result.output().map(|b| b.len()).unwrap_or(0),
            32,
            "beacon-roots get() returns a 32-byte root, not empty output"
        );
        // get(unknown timestamp): the predeploy REVERTs (empty-account success is wrong).
        let other_ts = &out.tx_outcomes[1];
        assert!(!other_ts.success, "get(unknown ts) must revert per EIP-4788");

        // The ring-buffer slots written by the system call are present in post-state.
        let slots = &state.db.cache.accounts[&BEACON_ROOTS_ADDRESS].storage;
        let ts_slot = U256::from(T % 8191);
        assert_eq!(slots.get(&ts_slot).copied().unwrap_or_default(), U256::from(T), "timestamps[ts % 8191] == ts");
    }
}


/// C18 [medium] — Zero-issuance supply ledger (total_minted_wei) is not committed in the state root, is absent from the witness, and desynchronises in the stateless guest path — the prover cannot prove total supply and the ledger is forgeable via snapshot or direct db writes
mod c18 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, keccak256, Address, B256, U256};
    use alloy_rlp::{Encodable, Header};
    use alloy_trie::{HashBuilder, Nibbles, EMPTY_ROOT_HASH};
    use bloch_l2_evm::proving::{generate_batch_witness, hydrate_and_verify};
    use bloch_l2_evm::{
        compute_keccak_mpt_state_root, execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec,
        DepositMint, DepositProvenance, L2State,
    };
    use revm::primitives::KECCAK_EMPTY;

    const SATS_PER_BLCH: u64 = 100_000_000;

    fn deposit(to: Address, sats: u64) -> DepositMint {
        DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
        }
    }

    /// Root of a trie holding ONLY the given EOA leaves (nonce 0, no code, no
    /// storage) — what the state root is if nothing but raw balances is committed.
    fn bare_eoa_trie_root(accounts: &[(Address, U256)]) -> B256 {
        let mut leaves: Vec<(B256, Vec<u8>)> = accounts
            .iter()
            .map(|(addr, bal)| {
                let mut v = Vec::new();
                let len = 0u64.length() + bal.length() + EMPTY_ROOT_HASH.length() + KECCAK_EMPTY.length();
                Header { list: true, payload_length: len }.encode(&mut v);
                0u64.encode(&mut v);
                bal.encode(&mut v);
                EMPTY_ROOT_HASH.encode(&mut v);
                KECCAK_EMPTY.encode(&mut v);
                (keccak256(addr), v)
            })
            .collect();
        leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut hb = HashBuilder::default();
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        hb.root()
    }

    /// C18: the zero-issuance supply ledger (`total_minted_wei`) must be part of
    /// the committed state and must survive the stateless (guest) hydration.
    #[test]
    #[ignore = "C18: supply ledger is not committed in the state root / not carried by the witness"]
    fn supply_ledger_is_committed_and_survives_stateless_hydration() {
        let spec = ChainSpec::testnet();
        let alice = address!("0000000000000000000000000000000000000001");
        let bob = address!("00000000000000000000000000000000000000bb");

        // Part A: the state root must commit to more than the bare account set —
        // a state whose only mint is 5 BLCH to Alice must NOT hash identically to
        // a trie containing just Alice's balance leaf (that trie carries no supply).
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: vec![deposit(alice, 5 * SATS_PER_BLCH)],
                txs: vec![],
            },
        )
        .unwrap();
        assert_eq!(state.total_minted_wei(), sats_to_wei(5 * SATS_PER_BLCH));
        assert_ne!(
            compute_keccak_mpt_state_root(&state),
            bare_eoa_trie_root(&[(alice, sats_to_wei(5 * SATS_PER_BLCH))]),
            "state root does not commit the supply ledger (C18)"
        );

        // Part B: the stateless guest must see the same authorized supply as the
        // host after hydrating the witness against prev_state_root, and must stay
        // in sync with the host after re-executing a batch that mints.
        let mut pre = L2State::new();
        for i in 1u8..=4 {
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
        let batch = BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![deposit(bob, 2 * SATS_PER_BLCH)],
            txs: vec![],
        };
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        let mut guest = hydrate_and_verify(&w.pre_accounts, &w.proof, w.prev_state_root).unwrap();
        assert_eq!(
            guest.total_minted_wei(),
            pre.total_minted_wei(),
            "hydrated guest ledger must equal the host ledger (C18)"
        );
        let mut host = pre.clone();
        execute_block(&spec, &mut host, batch.clone()).unwrap();
        execute_block(&spec, &mut guest, batch).unwrap();
        assert_eq!(
            guest.total_minted_wei(),
            host.total_minted_wei(),
            "guest and host supply diverge after the batch (C18)"
        );
    }
}


/// C19 [medium] — Deposit escrow amount (`l1_sats`) is an unauthenticated caller claim: `deposit_mint` only checks `mint_wei == sats_to_wei(l1_sats)`, never reads `l1_txid`/`l1_vout`, and imposes no supply bound, while the docs describe the check as "enforced"
mod c19 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address};
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance,
        L2State,
    };

    /// C19 fix-tracking test: a deposit claiming more sats than the L1 can
    /// possibly have issued must be rejected by the STF (defence in depth against
    /// an unauthenticated `l1_sats` claim). u64::MAX sats is 184,467,440,737 BLCH,
    /// thousands of times any 8-decimal L1 supply cap; today it is minted in full.
    #[test]
    #[ignore = "C19: l1_sats is an unbounded caller claim; enable once a MAX_L1_SATS bound exists"]
    fn c19_deposit_above_any_possible_l1_supply_is_rejected() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let forged = DepositMint {
            recipient: ALICE,
            mint_wei: sats_to_wei(u64::MAX),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: u64::MAX },
        };
        let result = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![forged], txs: vec![] },
        );
        assert!(
            result.is_err(),
            "a u64::MAX-sat escrow claim exceeds any possible L1 supply and must be rejected"
        );
        assert!(state.balance_of(&ALICE).is_zero(), "nothing may be credited for a rejected deposit");
        assert!(state.total_minted_wei().is_zero(), "nothing may be counted for a rejected deposit");
    }
}


/// C20 [low] — BatchWitness.pre_accounts and WitnessAccount.storage are emitted in randomly-seeded HashMap iteration order — the witness has no canonical byte form (differs between processes and even between two identical states in one process)
mod c20 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    //! C20 fix-tracking test: `BatchWitness.pre_accounts` (and each account's
    //! `storage`) must have a canonical order — two identical pre-states built
    //! independently must yield identical witnesses. FAILS today (HashMap order).
    use alloy_primitives::{keccak256, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::executor::{execute_block, BlockContext, BlockInput};
    use bloch_l2_evm::proving::generate_batch_witness;
    use bloch_l2_evm::scale::{sats_to_wei, SATS_PER_BLCH};
    use bloch_l2_evm::state::{DepositMint, DepositProvenance, L2State};
    use bloch_l2_evm::ChainSpec;
    use revm::context::TxEnv;

    fn addr(i: u64) -> Address {
        Address::from_slice(&keccak256(i.to_be_bytes())[12..])
    }

    fn deposit(to: Address, sats: u64) -> DepositMint {
        DepositMint {
            recipient: to,
            mint_wei: sats_to_wei(sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
        }
    }

    /// Init code: SSTORE slots 1..=8, then return the runtime
    /// `PUSH1 0x2a PUSH1 0x09 SSTORE STOP` (any call writes slot 9).
    fn init_code() -> Bytes {
        let mut c = Vec::new();
        for s in 1u8..=8 {
            c.extend_from_slice(&[0x60, s * 0x11, 0x60, s, 0x55]);
        }
        let runtime: [u8; 6] = [0x60, 0x2a, 0x60, 0x09, 0x55, 0x00];
        let off = (c.len() + 12) as u8;
        c.extend_from_slice(&[0x60, 6, 0x60, off, 0x60, 0x00, 0x39, 0x60, 6, 0x60, 0x00, 0xf3]);
        c.extend_from_slice(&runtime);
        c.into()
    }

    fn tx(spec: &ChainSpec, from: Address, kind: TxKind, nonce: u64, value: U256, data: Bytes, gas: u64) -> TxEnv {
        TxEnv::builder()
            .caller(from)
            .kind(kind)
            .value(value)
            .data(data)
            .gas_limit(gas)
            .max_fee_per_gas(spec.initial_base_fee as u128 + 1)
            .gas_priority_fee(Some(1))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap()
    }

    /// Build the same pre-state from a fresh `L2State` (fresh HashMap seeds):
    /// 12 funded EOAs + one contract with 8 non-zero storage slots.
    fn build_pre(spec: &ChainSpec) -> (L2State, Address) {
        let mut pre = L2State::new();
        execute_block(
            spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: (0..12).map(|i| deposit(addr(i), 5 * SATS_PER_BLCH)).collect(),
                txs: vec![],
            },
        )
        .unwrap();
        let out = execute_block(
            spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 1, ..Default::default() },
                deposits: vec![],
                txs: vec![tx(spec, addr(0), TxKind::Create, 0, U256::ZERO, init_code(), 500_000)],
            },
        )
        .unwrap();
        assert!(out.tx_outcomes[0].success);
        (pre, out.tx_outcomes[0].created_address.unwrap())
    }

    /// 10 transfers from distinct senders + one call that changes the contract's storage.
    fn batch(spec: &ChainSpec, contract: Address) -> BlockInput {
        let mut txs: Vec<TxEnv> = (1..=10u64)
            .map(|i| tx(spec, addr(i), TxKind::Call(addr(100 + i)), 0, sats_to_wei(1), Bytes::new(), 21_000))
            .collect();
        txs.push(tx(spec, addr(11), TxKind::Call(contract), 0, U256::ZERO, Bytes::new(), 100_000));
        BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![], txs }
    }

    #[test]
        #[ignore = "AUDIT C20 (low): fails until the finding is fixed"]
    fn c20_batch_witness_pre_accounts_and_storage_have_canonical_order() {
        let spec = ChainSpec::testnet();
        let (pre_a, contract) = build_pre(&spec);
        let (pre_b, contract_b) = build_pre(&spec);
        assert_eq!(contract, contract_b);

        let (wa, oa) = generate_batch_witness(&pre_a, &spec, batch(&spec, contract)).unwrap();
        let (wb, _) = generate_batch_witness(&pre_b, &spec, batch(&spec, contract)).unwrap();
        assert!(oa.tx_outcomes.iter().all(|t| t.success));

        // The canonical parts already agree ...
        assert_eq!(wa.prev_state_root, wb.prev_state_root);
        assert_eq!(wa.new_state_root, wb.new_state_root);
        assert_eq!(wa.proof, wb.proof);
        assert_eq!(wa.changes, wb.changes);

        // ... and so must the address-keyed pre-state: same accounts in the same
        // order, each with its storage slots in the same order (Vec equality).
        let ca = wa.pre_accounts.iter().find(|a| a.address == contract).expect("contract is a changed pre-account");
        let cb = wb.pre_accounts.iter().find(|a| a.address == contract).expect("contract is a changed pre-account");
        assert_eq!(ca.storage.len(), 8);
        assert_eq!(ca.storage, cb.storage, "storage slot order must be canonical");
        assert_eq!(wa.pre_accounts, wb.pre_accounts, "pre_accounts order must be canonical");

        // A witness must also be reproducible from the same state object twice.
        let (wa2, _) = generate_batch_witness(&pre_a, &spec, batch(&spec, contract)).unwrap();
        assert_eq!(wa.pre_accounts, wa2.pre_accounts);
    }
}


/// C21 [medium] — stateless_new_root: infinite recursion (uncatchable stack-overflow abort) on a zero-length extension-node key in a host-supplied multiproof
mod c21 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // Fix-tracking regression test for cluster C21. Today `stateless_new_root`
    // recurses forever on a zero-length extension key and the process ABORTS via
    // stack overflow (SIGABRT, uncatchable by catch_unwind), which would tear down
    // the whole test binary. To fail gracefully, the vulnerable call runs in a
    // CHILD process (this same test binary, re-invoked with an env flag) and the
    // parent asserts the child exited normally. After the fix (reject empty
    // extension keys / require strictly-growing paths, ideally returning an
    // error), the child terminates and this test passes.
    use std::collections::BTreeMap;
    use std::process::Command;
    use alloy_primitives::{Bytes, B256};
    use alloy_rlp::Encodable;
    use alloy_trie::Nibbles;

    const CHILD_FLAG: &str = "AUDIT_C21_CHILD";
    const TEST_PATH: &str = "c21::zero_length_extension_key_must_not_hang_or_abort";

    fn call_stateless_new_root_on_zero_length_extension() {
        // Craft an extension node with a ZERO-nibble key: RLP list [ 0x00, child ].
        // 0x00 = EVEN flag + no nibbles => alloy-trie yields ext.key.len() == 0.
        let child = B256::repeat_byte(0x44);
        let mut payload = Vec::new();
        [0x00u8].as_slice().encode(&mut payload);
        child.encode(&mut payload);
        let mut rlp = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut rlp);
        rlp.extend(payload);

        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), rlp.into());
        let changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();

        // CORRECT behaviour: this call terminates (a fixed impl handles/rejects the
        // malformed node instead of recursing forever). The returned value is
        // irrelevant to the invariant under test.
        let _root = bloch_l2_evm::stateroot::stateless_new_root(&proof, &changes);
    }

    #[test]
    #[ignore = "AUDIT C21 (medium): fails until the finding is fixed"]
    fn zero_length_extension_key_must_not_hang_or_abort() {
        if std::env::var_os(CHILD_FLAG).is_some() {
            call_stateless_new_root_on_zero_length_extension();
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let status = Command::new(exe)
            .args(["--ignored", "--exact", TEST_PATH, "--nocapture", "--test-threads=1"])
            .env(CHILD_FLAG, "1")
            .status()
            .expect("spawn child test process");
        assert!(
            status.success(),
            "stateless_new_root did not terminate on a zero-length extension key: child exited with {status} (SIGABRT = stack overflow)"
        );
    }
}


/// C22 [medium] — stateless_new_root panics or (release) writes out of bounds on a crafted witness proof: collect_sparse extends Nibbles past its 64-nibble capacity with unchecked push/join and an unchecked TrieNode::decode
mod c22 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // tests/c22_nibbles_capacity.rs
    // Fix-tracking regression test for C22. Asserts the CORRECT behaviour: a
    // crafted witness proof that would drive a trie path past the 64-nibble
    // Nibbles capacity must be handled gracefully (no panic / no UB) by the
    // public stateless updater. FAILS today (stateless_new_root panics in debug
    // and performs an out-of-bounds write in release). Commit with #[ignore].
    use std::collections::BTreeMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use alloy_primitives::{Bytes, B256};
    use alloy_rlp::Encodable;
    use alloy_trie::nodes::{BranchNode, ExtensionNode, LeafNode, RlpNode};
    use alloy_trie::{Nibbles, TrieMask};
    use bloch_l2_evm::stateroot::stateless_new_root;

    fn crafted_proofs() -> Vec<(&'static str, BTreeMap<Nibbles, Bytes>)> {
        let h = B256::repeat_byte(0x22);

        // A: root extension with a 64-nibble key -> branch child at the 64-nibble
        //    path -> collect_sparse pushes a 65th nibble.
        let key64 = Nibbles::unpack([0x12u8; 32]);
        assert_eq!(key64.len(), 64);
        let mut ext_rlp = Vec::new();
        ExtensionNode::new(key64, RlpNode::word_rlp(&h)).encode(&mut ext_rlp);
        let mut br_rlp = Vec::new();
        BranchNode::new(vec![RlpNode::word_rlp(&h)], TrieMask::new(0b10)).encode(&mut br_rlp);
        let mut a: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        a.insert(Nibbles::default(), ext_rlp.into());
        a.insert(key64, br_rlp.into());

        // B: root branch -> leaf with a 64-nibble key at a 1-nibble path ->
        //    path.join(&leaf.key) = 65 nibbles.
        let mut leaf_rlp = Vec::new();
        LeafNode::new(Nibbles::unpack([0x34u8; 32]), vec![0x01]).encode(&mut leaf_rlp);
        let mut br2 = Vec::new();
        BranchNode::new(vec![RlpNode::word_rlp(&h)], TrieMask::new(0b10)).encode(&mut br2);
        let mut b: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        b.insert(Nibbles::default(), br2.into());
        b.insert(Nibbles::from_nibbles([1u8]), leaf_rlp.into());

        vec![("branch-push-65", a), ("leaf-join-65", b)]
    }

    #[test]
    #[ignore = "C22: fails until collect_sparse bounds path extensions and returns an error"]
    fn stateless_new_root_rejects_over_capacity_proof_without_panicking() {
        for (name, proof) in crafted_proofs() {
            let r = catch_unwind(AssertUnwindSafe(|| {
                stateless_new_root(&proof, &BTreeMap::new())
            }));
            assert!(
                r.is_ok(),
                "stateless_new_root panicked (or would be UB in release) on crafted proof '{name}'; \
                 an over-64-nibble path must be treated as an invalid witness, not a panic"
            );
        }
    }
}


/// C23 [low] — stateless_new_root / collect_sparse and hydrate_and_verify panic (no error channel) on malformed witness input: expect() on node RLP, assertions inside TrieNode::decode / Nibbles / HashBuilder, and Bytecode::new_raw on EIP-7702 magic
mod c23 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // tests/c23_malformed_witness_no_panic.rs
    // Correct behaviour: malformed witness input must be REJECTED (an error), never a panic.
    // The test compiles against both the current `-> B256` signature and a future
    // `-> Result<B256, _>` one (the return value is discarded); it FAILS today because
    // each of the calls below panics.
    use std::collections::BTreeMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use alloy_primitives::{address, keccak256, Bytes, B256, U256};
    use alloy_rlp::Encodable;
    use alloy_trie::nodes::{BranchNode, LeafNode, RlpNode};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{HashBuilder, Nibbles, TrieMask, EMPTY_ROOT_HASH};
    use bloch_l2_evm::proving::{hydrate_and_verify, WitnessAccount};
    use bloch_l2_evm::stateroot::stateless_new_root;

    fn no_panic<F: FnOnce() -> R, R>(what: &str, f: F) {
        assert!(
            catch_unwind(AssertUnwindSafe(|| { let _ = f(); })).is_ok(),
            "{what}: malformed witness input must be rejected with an error, not a panic"
        );
    }

    fn rlp_list(items: &[&[u8]]) -> Vec<u8> {
        let mut payload = Vec::new();
        for it in items { it.encode(&mut payload); }
        let mut out = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
        out.extend(payload);
        out
    }

    #[test]
    #[ignore = "C23: stateless_new_root / hydrate_and_verify panic on malformed witness input"]
    fn malformed_witness_input_is_rejected_without_panicking() {
        // 1. garbage bytes at the root path
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]));
        no_panic("garbage root node", || stateless_new_root(&proof, &BTreeMap::new()));

        // 2. truncated branch node
        let h = B256::repeat_byte(0x11);
        let branch = BranchNode::new(vec![RlpNode::word_rlp(&h), RlpNode::word_rlp(&h)], TrieMask::new(0b0110));
        let mut rlp = Vec::new();
        branch.encode(&mut rlp);
        rlp.truncate(rlp.len() - 5);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), rlp.into());
        no_panic("truncated branch node", || stateless_new_root(&proof, &BTreeMap::new()));

        // 3. leaf with a 40-byte compact key (TrieNode::decode asserts internally)
        let mut key = vec![0x20u8];
        key.extend(std::iter::repeat(0xab).take(40));
        let rlp = rlp_list(&[&key, &[0x01u8]]);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), rlp.into());
        no_panic("over-long leaf key", || stateless_new_root(&proof, &BTreeMap::new()));

        // 4. exposed leaf whose joined path exceeds 64 nibbles
        let leaf = LeafNode::new(Nibbles::unpack([0x34u8; 32]), vec![0x01]);
        let mut leaf_rlp = Vec::new();
        leaf.encode(&mut leaf_rlp);
        let branch = BranchNode::new(vec![RlpNode::word_rlp(&h)], TrieMask::new(0b10));
        let mut br_rlp = Vec::new();
        branch.encode(&mut br_rlp);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), br_rlp.into());
        proof.insert(Nibbles::from_nibbles([1u8]), leaf_rlp.into());
        no_panic("joined path > 64 nibbles", || stateless_new_root(&proof, &BTreeMap::new()));

        // 5. change key that is a 10-nibble prefix of a real account key, on a valid 2-leaf trie
        let n1 = Nibbles::unpack(keccak256(address!("00000000000000000000000000000000000000aa")));
        let n2 = Nibbles::unpack(keccak256(address!("00000000000000000000000000000000000000bb")));
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([n1, n2]));
        let mut leaves = vec![(n1, vec![0xc1u8]), (n2, vec![0xc2u8])];
        leaves.sort();
        for (k, v) in &leaves { hb.add_leaf(*k, v); }
        let _root = hb.root();
        let proof: BTreeMap<Nibbles, Bytes> = hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(n1.slice(..10), Some(vec![0xc0]));
        no_panic("short change key prefixing a leaf", || stateless_new_root(&proof, &changes));

        // 6. change key extending an exposed leaf key
        let leaf = LeafNode::new(Nibbles::from_nibbles([1u8]), vec![0x01]);
        let mut leaf_rlp = Vec::new();
        leaf.encode(&mut leaf_rlp);
        let mut proof: BTreeMap<Nibbles, Bytes> = BTreeMap::new();
        proof.insert(Nibbles::default(), leaf_rlp.into());
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        changes.insert(Nibbles::from_nibbles([1u8, 2u8]), Some(vec![0x02]));
        no_panic("change key extending an exposed leaf", || stateless_new_root(&proof, &changes));

        // 7. hydrate_and_verify with EIP-7702-magic-prefixed but invalid code: must be Err, not panic
        let wa = WitnessAccount {
            address: address!("00000000000000000000000000000000000000c0"),
            balance: U256::ZERO,
            nonce: 1,
            code: vec![0xef, 0x01, 0x00],
            storage: vec![],
        };
        let r = catch_unwind(AssertUnwindSafe(|| hydrate_and_verify(&[wa], &BTreeMap::new(), EMPTY_ROOT_HASH).map(|_| ())));
        match r {
            Err(_) => panic!("hydrate_and_verify panicked on 0xEF01-prefixed code; must return Err"),
            Ok(Ok(())) => panic!("hydrate_and_verify accepted invalid 7702-prefixed code at CANCUN"),
            Ok(Err(_)) => {}
        }
    }
}


/// C24 [low] — stateless_new_root / collect_sparse silently drops inline (<32-byte) child nodes, returning a wrong root with no error for any trie with small leaves (storage tries); the account trie is unaffected only because account leaves are always >=70 bytes
mod c24 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use std::collections::BTreeMap;

    use alloy_primitives::{Bytes, B256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{HashBuilder, Nibbles};
    use bloch_l2_evm::stateroot::stateless_new_root;

    /// C24: `stateless_new_root` must handle INLINE (<32-byte) child nodes that are
    /// not proof targets. Three 2-nibble keys with 2-byte values sit as inline
    /// children of the root branch; with a proof targeting only key 0, updating or
    /// deleting key 0 must reproduce the full-rebuild root. Today the two untouched
    /// inline siblings are silently dropped (update => root of {key0} only; delete
    /// => EMPTY_ROOT_HASH), so this test FAILS until collect_sparse decodes inline
    /// children (or the function returns an error instead of a wrong root).
    #[test]
    #[ignore]
    fn c24_stateless_new_root_handles_inline_children() {
        fn full_root(leaves: &BTreeMap<Nibbles, Vec<u8>>) -> B256 {
            let mut hb = HashBuilder::default();
            for (k, v) in leaves {
                hb.add_leaf(*k, v);
            }
            hb.root()
        }
        let keys: Vec<Nibbles> = (0u8..3).map(|i| Nibbles::unpack([i << 4, 0x00])).collect();
        let pre: BTreeMap<Nibbles, Vec<u8>> =
            keys.iter().enumerate().map(|(i, k)| (*k, vec![0x81, i as u8 + 1])).collect();

        // Multiproof against the pre-trie targeting ONLY key 0 (siblings stay inline, untargeted).
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([keys[0]]));
        for (k, v) in &pre {
            hb.add_leaf(*k, v);
        }
        let prev_root = hb.root();
        assert_eq!(prev_root, full_root(&pre));
        let proof: BTreeMap<Nibbles, Bytes> =
            hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();

        // UPDATE key 0.
        let mut post_upd = pre.clone();
        post_upd.insert(keys[0], vec![0x81, 0x77]);
        let mut changes = BTreeMap::new();
        changes.insert(keys[0], Some(vec![0x81u8, 0x77]));
        assert_eq!(
            stateless_new_root(&proof, &changes),
            full_root(&post_upd),
            "update: inline untouched siblings must survive the stateless update"
        );

        // DELETE key 0.
        let mut post_del = pre.clone();
        post_del.remove(&keys[0]);
        let mut changes = BTreeMap::new();
        changes.insert(keys[0], None);
        assert_eq!(
            stateless_new_root(&proof, &changes),
            full_root(&post_del),
            "delete: two inline leaves remain, the root must not collapse to EMPTY_ROOT_HASH"
        );
    }
}


/// C25 [low] — Executor re-derives the effective gas price without consulting tx_type; a legacy/EIP-2930 TxEnv carrying gas_priority_fee = Some(..) makes ExecutionOutcome::priority_fee_routed_wei under-report the tip revm actually paid to the SequencerFeeVault
mod c25 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, TxKind, U256};
    use bloch_l2_evm::scale::SATS_PER_BLCH;
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State,
    };
    use revm::context::TxEnv;

    /// C25: `ExecutionOutcome::priority_fee_routed_wei` must equal the tip revm actually
    /// paid to the SequencerFeeVault, for every tx_type -- including a legacy (type-0) or
    /// EIP-2930 (type-1) TxEnv that also carries `gas_priority_fee = Some(..)`, where revm
    /// ignores the priority field and pays `(gas_price - base_fee) * gas_used`.
    #[test]
    #[ignore = "C25: executor's effective-gas-price mirror ignores tx_type (fix-tracking)"]
    fn c25_priority_fee_routed_matches_revm_payment_for_legacy_and_2930_with_priority_field() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BOB: Address = address!("0000000000000000000000000000000000000b0b");
        const GWEI: u128 = 1_000_000_000;

        let spec = ChainSpec::testnet();
        let base_fee = spec.initial_base_fee;

        // (tx_type, gas_price, gas_priority_fee) shapes for which revm pays gas_price - base_fee.
        let cases: [(u8, u128, Option<u128>); 2] = [
            (0, 3 * GWEI, Some(GWEI)), // legacy carrying a priority field
            (1, 2 * GWEI, Some(0)),    // 2930 carrying a zero priority field
        ];

        for (tx_type, gas_price, prio) in cases {
            let mut state = L2State::new();
            execute_block(
                &spec,
                &mut state,
                BlockInput {
                    context: BlockContext { number: 1, ..Default::default() },
                    deposits: vec![DepositMint {
                        recipient: ALICE,
                        mint_wei: sats_to_wei(10 * SATS_PER_BLCH),
                        provenance: DepositProvenance::BridgedBlch {
                            l1_txid: [7; 32],
                            l1_vout: 1,
                            l1_sats: 10 * SATS_PER_BLCH,
                        },
                    }],
                    txs: vec![],
                },
            )
            .expect("funding block");

            let tx = TxEnv::builder()
                .tx_type(Some(tx_type))
                .caller(ALICE)
                .kind(TxKind::Call(BOB))
                .gas_limit(21_000)
                .gas_price(gas_price)
                .gas_priority_fee(prio)
                .nonce(0)
                .chain_id(Some(spec.chain_id))
                .build()
                .expect("legacy/2930 TxEnv with a priority field builds");
            assert_eq!(tx.tx_type, tx_type);

            let vault_before = state.balance_of(&spec.sequencer_fee_vault);
            let out = execute_block(
                &spec,
                &mut state,
                BlockInput {
                    context: BlockContext { number: 2, ..Default::default() },
                    deposits: vec![],
                    txs: vec![tx],
                },
            )
            .expect("block executes");
            assert!(out.tx_outcomes[0].success);

            let actually_paid = state.balance_of(&spec.sequencer_fee_vault) - vault_before;
            // revm: legacy/2930 pay their full gas_price; the tip is gas_price - base_fee.
            let expected = U256::from(gas_price - base_fee as u128) * U256::from(out.gas_used);
            assert_eq!(actually_paid, expected, "revm payment for tx_type {tx_type}");
            assert_eq!(
                out.priority_fee_routed_wei, actually_paid,
                "tx_type {tx_type}: outcome must report exactly what revm paid to the SequencerFeeVault"
            );
            assert_eq!(state.total_native_wei(), state.total_minted_wei());
        }
    }
}


/// C26 [low] — L2State account views report EIP-161-empty (touched-empty) accounts as existing while the committed state root excludes them; touched-empty accounts and zero-valued storage slots are never pruned and grow without bound
mod c26 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, Bytes, TxKind, U256};
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance,
        L2State,
    };
    use revm::context::TxEnv;
    use revm::database::AccountState;

    /// C26: touched-empty (EIP-161-empty) accounts must not be reported as existing by the
    /// account views, must not be counted by `total_native_wei`, and must not persist in the
    /// live state after a block — exactly as the committed state root already treats them.
    #[test]
        #[ignore = "AUDIT C26 (low): fails until the finding is fixed"]
    fn c26_touched_empty_accounts_do_not_exist_in_views_and_are_pruned() {
        const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
        const BOB: Address = address!("0000000000000000000000000000000000000b0b");
        const GHOST: Address = address!("0000000000000000000000000000000000060057");
        const ECRECOVER: Address = address!("0000000000000000000000000000000000000001");
        const GWEI: u128 = 1_000_000_000;

        let spec = ChainSpec::testnet();
        let deposit = |recipient: Address, l1_sats: u64| DepositMint {
            recipient,
            mint_wei: sats_to_wei(l1_sats),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [7; 32], l1_vout: 1, l1_sats },
        };
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
        // A 0-sat deposit is exact but must not materialise BOB.
        state.deposit_mint(&deposit(BOB, 0)).unwrap();
        assert!(state.account(&BOB).is_none(), "0-sat deposit must not create an account");

        // Zero-value CALLs to a fresh address and to a precompile (EIP-161 touches).
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, 1_000_000_000)],
                txs: vec![call(GHOST, 0, 21_000), call(ECRECOVER, 1, 100_000)],
            },
        )
        .unwrap();
        assert!(out.tx_outcomes.iter().all(|t| t.success));

        // Views must agree with the trie: these accounts do not exist.
        assert!(state.account(&GHOST).is_none(), "touched-empty account reported as existing");
        assert!(state.account(&ECRECOVER).is_none(), "touched precompile reported as existing");
        assert!(state.account(&BOB).is_none());
        assert_eq!(state.balance_of(&GHOST), U256::ZERO);
        assert_eq!(state.nonce_of(&GHOST), 0);

        // Ghosts must not persist in the live state (pruned, or at most marked NotExisting).
        for a in [GHOST, ECRECOVER, BOB] {
            let persisted = state
                .db
                .cache
                .accounts
                .get(&a)
                .map_or(false, |acc| acc.account_state != AccountState::NotExisting);
            assert!(!persisted, "touched-empty account {a} persists in the live state");
        }

        // Every surviving cache entry that the views call "existing" must be non-empty per EIP-161.
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


/// C27 [low] — State root is rebuilt from scratch over the entire state on every block, and generate_batch_witness deep-clones the state and rebuilds the full trie ~5 times per batch — per-block/per-batch cost is O(total accounts + total storage slots) regardless of what the block touched
mod c27 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use std::time::Instant;
    use alloy_primitives::{Address, U256};
    use bloch_l2_evm::scale::SATS_PER_BLCH;
    use bloch_l2_evm::{execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State};

    /// Fix-tracking (C27): sealing a block that touches nothing must NOT cost time
    /// proportional to the total state size. With the current full recompute the
    /// 160k-account empty block is ~200x slower than the 1k-account one; an
    /// incremental/cached root makes the ratio ~1. Threshold is deliberately loose
    /// (10x over a 160x size difference) to tolerate timing noise. Run in --release.
    #[test]
    #[ignore]
    fn c27_empty_block_time_must_not_scale_with_total_state_size() {
        fn deposit(to: Address, sats: u64) -> DepositMint {
            DepositMint {
                recipient: to,
                mint_wei: sats_to_wei(sats),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [1; 32], l1_vout: 0, l1_sats: sats },
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
            s.deposit_mint(&deposit(c, SATS_PER_BLCH)).unwrap();
            for k in 0..n_slots {
                s.db.insert_account_storage(c, U256::from(k), U256::from(k + 1)).unwrap();
            }
            s
        }
        /// Median of 5 timings of an empty block (0 txs, 0 deposits).
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
            "empty block against 160k accounts took {:.2} ms vs {:.2} ms against 1k accounts (x{:.1}): state root is recomputed over the whole account set",
            t_big * 1e3, t_small * 1e3, t_big / t_small
        );

        // Same property for storage: one untouched contract with many slots.
        let mut small = state_with(&spec, 10, 1_000);
        let mut big = state_with(&spec, 10, 160_000);
        let t_small = empty_block_secs(&spec, &mut small);
        let t_big = empty_block_secs(&spec, &mut big);
        assert!(
            t_big < 10.0 * t_small.max(1e-4),
            "empty block with an untouched 160k-slot contract took {:.2} ms vs {:.2} ms with 1k slots (x{:.1}): every account's storage root is rebuilt every block",
            t_big * 1e3, t_small * 1e3, t_big / t_small
        );
    }
}


/// C28 [low] — ChainSpec::gas_target / next_base_fee divide by the pub knobs base_fee_elasticity and base_fee_denominator without a zero check; the target == 0 guard cannot cover elasticity == 0
mod c28 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use bloch_l2_evm::ChainSpec;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// C28: degenerate EIP-1559 knobs (elasticity 0 / denominator 0) must not panic
    /// inside the fee helpers; the documented fallback for an unusable target is
    /// "base fee unchanged" (the existing `target == 0` guard), so the same result is
    /// expected here. Fails today with `attempt to divide by zero` at
    /// src/chainspec.rs:86 and :104/:109.
    #[test]
        #[ignore = "AUDIT C28 (low): fails until the finding is fixed"]
    fn c28_chainspec_fee_helpers_are_total_for_zero_knobs() {
        let parent_bf = 1_000_000_000u64;

        // elasticity == 0
        let mut s = ChainSpec::testnet();
        s.base_fee_elasticity = 0;
        let gt = catch_unwind(AssertUnwindSafe(|| s.gas_target()));
        assert!(gt.is_ok(), "gas_target() must not panic for elasticity 0");
        for used in [0u64, 1, s.gas_limit / 2, s.gas_limit] {
            let r = catch_unwind(AssertUnwindSafe(|| s.next_base_fee(parent_bf, used)));
            assert_eq!(
                r.ok(),
                Some(parent_bf),
                "next_base_fee must not panic and must leave the base fee unchanged for elasticity 0 (gas_used={used})"
            );
        }

        // denominator == 0
        let mut s = ChainSpec::testnet();
        s.base_fee_denominator = 0;
        for used in [0u64, s.gas_target() - 1, s.gas_target(), s.gas_target() + 1, s.gas_limit] {
            let r = catch_unwind(AssertUnwindSafe(|| s.next_base_fee(parent_bf, used)));
            assert_eq!(
                r.ok(),
                Some(parent_bf),
                "next_base_fee must not panic and must leave the base fee unchanged for denominator 0 (gas_used={used})"
            );
        }

        // gas_limit < elasticity (target == 0): existing guard, must keep working.
        let mut s = ChainSpec::testnet();
        s.gas_limit = 1;
        s.base_fee_elasticity = 2;
        assert_eq!(s.next_base_fee(parent_bf, 0), parent_bf);
        assert_eq!(s.next_base_fee(parent_bf, 1), parent_bf);
    }
}


/// C29 [low] — Deposits are unmetered and unbounded per block, and zero-sat deposits materialize permanent (EIP-161-empty) account entries: free state-growth / per-block cost amplification
mod c29 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    use alloy_primitives::{address, Address, U256};
    use alloy_trie::EMPTY_ROOT_HASH;
    use bloch_l2_evm::{
        execute_block, sats_to_wei, BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance,
        L2State,
    };

    /// C29: a zero-sat deposit must not materialize an account. EIP-161: a zero-value
    /// touch of a non-existing account never creates it, so after a block of zero-sat
    /// deposits the account must not exist in the L2 state (not only be excluded from
    /// the trie). FAILS today: `credit_balance` loads the account and marks it existing.
    #[test]
        #[ignore = "AUDIT C29 (low): fails until the finding is fixed"]
    fn zero_sat_deposit_does_not_create_an_account() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let recipient: Address = address!("00000000000000000000000000000000000c2900");
        let deposit = DepositMint {
            recipient,
            mint_wei: sats_to_wei(0),
            provenance: DepositProvenance::BridgedBlch { l1_txid: [0x29; 32], l1_vout: 0, l1_sats: 0 },
        };
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit], txs: vec![] },
        )
        .expect("block executes");
        assert_eq!(out.minted_wei, U256::ZERO);
        assert_eq!(out.state_root, EMPTY_ROOT_HASH);
        // Correct behaviour: nothing was created for a zero-value deposit.
        assert!(
            state.account(&recipient).is_none(),
            "a zero-sat deposit must not create an (EIP-161-empty) account"
        );
        assert!(
            !state.db.cache.accounts.contains_key(&recipient),
            "a zero-sat deposit must not leave a permanent cache entry"
        );
    }
}


/// C30 [low] — Advertised no_std path is untested and nominal: `cargo test --no-default-features` fails to compile (34 errors) and revm/alloy-trie are always built with their default `std` + C-backend feature set
mod c30 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    // tests/no_std_config_compiles.rs — fix-tracking test for finding C30.
    // Asserts the CORRECT behaviour: the crate's own test suite compiles in the
    // advertised `--no-default-features` (no_std) configuration. Fails today with
    // 34 compile errors (32x `vec!` not in scope, `use std::collections::BTreeMap`
    // at src/stateroot.rs:497, and the E0282 it causes at :527).
    // Spawns a nested cargo on this crate's own manifest; inherits CARGO_TARGET_DIR.
    use std::process::Command;

    #[test]
    #[ignore = "C30: `cargo test --no-default-features` does not compile yet"]
    fn no_default_features_test_target_compiles() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let cargo = env!("CARGO");

        let lib = Command::new(cargo)
            .args(["build", "--no-default-features", "--offline", "--manifest-path", manifest])
            .output()
            .expect("spawn cargo build");
        assert!(
            lib.status.success(),
            "library must build under --no-default-features:\n{}",
            String::from_utf8_lossy(&lib.stderr)
        );

        let tests = Command::new(cargo)
            .args(["test", "--no-default-features", "--no-run", "--offline", "--manifest-path", manifest])
            .output()
            .expect("spawn cargo test --no-run");
        let stderr = String::from_utf8_lossy(&tests.stderr);
        let n_errors = stderr.lines().filter(|l| l.starts_with("error")).count();
        assert!(
            tests.status.success(),
            "the crate's own test suite must compile under --no-default-features \
             (the advertised no_std path); got {n_errors} error lines:\n{stderr}"
        );
    }
}


/// C31 [low] — Determinism ("byte-identical node/guest") contract is enforced only by the committed Cargo.lock: alloy-primitives/alloy-trie/alloy-rlp are caret ranges, no rust-version or rust-toolchain pin, and the pinned tree carries C/asm precompile backends and duplicate crate versions
mod c31 {
    #![allow(unused_imports, dead_code, unused_variables, unused_mut, non_snake_case)]
    //! C31 fix-tracking test: the design's determinism contract ("node and SP1
    //! guest re-execute byte-identical code") must be enforced by the manifest and
    //! toolchain pins themselves, not only by the committed Cargo.lock (which a
    //! separately-resolved guest crate does not inherit).
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

        // Every crate whose bytes shape the state root / RLP / U256 arithmetic
        // must be an exact `=x.y.z` requirement, and that exact version must be
        // the one the committed lock resolved (so `cargo update` cannot drift).
        for dep in ["revm", "alloy-primitives", "alloy-trie", "alloy-rlp"] {
            let line = manifest_line(&manifest, dep);
            let req = line.split('"').nth(1).unwrap_or_else(|| panic!("no version string on `{line}`"));
            assert!(
                req.starts_with('='),
                "{dep}: Cargo.toml requirement `{req}` is a caret range, not an exact `=` pin"
            );
            assert_eq!(
                &req[1..],
                locked_version(&lock, dep),
                "{dep}: exact pin does not match the committed Cargo.lock"
            );
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
        let channel = tc
            .lines()
            .find(|l| l.trim_start().starts_with("channel"))
            .expect("channel = ... in rust-toolchain.toml");
        assert!(
            !channel.contains("\"stable\"") && !channel.contains("\"nightly\"") && !channel.contains("\"beta\""),
            "rust-toolchain.toml channel must be a fixed version, not a moving channel: {channel}"
        );
    }
}
