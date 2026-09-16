// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual Reth StateProviderDatabase differential tests; all snapshots and roots are local fixtures.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    execute_signed_block, stateroot::compute_keccak_mpt_state_root, BlockContext, ChainSpec, DepositMint,
    DepositProvenance, ExecutionOutcome, L2State, SignedBlockInput,
};
use bloch_reth_execution::execute_on_provider;
use k256::ecdsa::SigningKey;
use reth_primitives_traits::{Account, Bytecode};
use reth_revm::database::{EvmStateProvider, StateProviderDatabase};
use reth_revm::revm::{
    database::{CacheDB, InMemoryDB},
    DatabaseRef,
};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::{cell::Cell, collections::BTreeSet, rc::Rc};

#[derive(Default)]
struct Reads {
    accounts: Cell<usize>,
    storage: Cell<usize>,
    code: Cell<usize>,
    hashes: Cell<usize>,
}
struct Provider {
    db: InMemoryDB,
    reads: Rc<Reads>,
    fail: bool,
}
impl Provider {
    fn new(db: InMemoryDB) -> Self {
        Self {
            db,
            reads: Rc::new(Reads::default()),
            fail: false,
        }
    }
}
impl EvmStateProvider for Provider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.reads.accounts.set(self.reads.accounts.get() + 1);
        if self.fail {
            return Err(ProviderError::UnsupportedProvider);
        }
        Ok(self.db.basic_ref(*address).unwrap().map(Into::into))
    }
    fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
        self.reads.hashes.set(self.reads.hashes.get() + 1);
        // Deliberately different from Bloch's committed BLOCKHASH history.
        Ok(Some(B256::repeat_byte(99)))
    }
    fn bytecode_by_hash(&self, hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.reads.code.set(self.reads.code.get() + 1);
        Ok(self.db.cache.contracts.get(hash).cloned().map(Bytecode))
    }
    fn storage(&self, address: Address, key: B256) -> ProviderResult<Option<U256>> {
        self.reads.storage.set(self.reads.storage.get() + 1);
        Ok(Some(self.db.storage_ref(address, U256::from_be_bytes(key.0)).unwrap()))
    }
}

fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn signed(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    signed_with_value(spec, nonce, to, input, U256::ZERO)
}
fn signed_with_value(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes, value: U256) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to,
        input,
        value,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}
fn deploy(runtime: &[u8]) -> Bytes {
    let length = u8::try_from(runtime.len()).unwrap();
    let mut code = vec![0x60, length, 0x60, 12, 0x60, 0, 0x39, 0x60, length, 0x60, 0, 0xf3];
    code.extend_from_slice(runtime);
    code.into()
}
fn deposit() -> DepositMint {
    DepositMint {
        recipient: sender(),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    }
}
fn input(spec: &ChainSpec, state: &L2State, transactions: Vec<Bytes>, deposits: Vec<DepositMint>) -> SignedBlockInput {
    let mut context = BlockContext::next(spec, state);
    context.anchor_root = B256::repeat_byte(44);
    SignedBlockInput {
        context,
        transactions,
        deposits,
    }
}

/// Enumerate our complete fixture and query the resulting overlay through DatabaseRef.
/// Unlike CacheDB::flatten, this preserves untouched backing storage and respects clearing.
fn materialize(overlay: &CacheDB<StateProviderDatabase<Provider>>) -> L2State {
    let mut state = L2State::new();
    let addresses: BTreeSet<_> = overlay
        .cache
        .accounts
        .keys()
        .chain(overlay.db.0.db.cache.accounts.keys())
        .copied()
        .collect();
    for address in addresses {
        let Some(mut info) = overlay.basic_ref(address).unwrap() else {
            continue;
        };
        info.code = Some(overlay.code_by_hash_ref(info.code_hash).unwrap());
        state.db_mut().insert_account_info(address, info);
        let slots: BTreeSet<_> = overlay
            .cache
            .accounts
            .get(&address)
            .into_iter()
            .chain(overlay.db.0.db.cache.accounts.get(&address))
            .flat_map(|account| account.storage.keys())
            .copied()
            .collect();
        for slot in slots {
            state
                .db_mut()
                .insert_account_storage(address, slot, overlay.storage_ref(address, slot).unwrap())
                .unwrap();
        }
    }
    state
}

fn differential(
    spec: &ChainSpec,
    reference: &mut L2State,
    database: &mut L2State,
    input: &SignedBlockInput,
) -> ExecutionOutcome {
    let provider = Provider::new(database.db().clone());
    let reads = provider.reads.clone();
    let before = format!("{:?}", provider.db);
    let pending = execute_on_provider(spec, provider, database.commit_root(), input).unwrap();
    assert!(reads.accounts.get() > 0, "actual Reth basic_account reads");
    assert!(reads.storage.get() > 0, "actual Reth storage key conversion");
    assert_eq!(reads.hashes.get(), 0, "Bloch BLOCKHASH must ignore provider history");
    if input.context.number > 1 {
        assert!(reads.code.get() > 0, "actual Reth bytecode reads");
    }
    assert_eq!(
        format!("{:?}", pending.overlay().db.0.db),
        before,
        "provider snapshot is read-only"
    );
    let reconstructed = materialize(pending.overlay());
    let root = compute_keccak_mpt_state_root(&reconstructed);
    let (_, actual) = pending.finalize(root);
    let expected = execute_signed_block(spec, reference, input).unwrap();
    assert_eq!(actual.header, expected.header);
    assert_eq!(actual.block_hash, expected.block_hash);
    assert_eq!(actual.state_root, expected.state_root);
    assert_eq!(actual.gas_used, expected.gas_used);
    assert_eq!(actual.minted_wei, expected.minted_wei);
    assert_eq!(actual.burned_wei, expected.burned_wei);
    assert_eq!(actual.base_fee_routed_wei, expected.base_fee_routed_wei);
    assert_eq!(actual.priority_fee_routed_wei, expected.priority_fee_routed_wei);
    assert_eq!(actual.tx_outcomes.len(), expected.tx_outcomes.len());
    for (actual, expected) in actual.tx_outcomes.iter().zip(&expected.tx_outcomes) {
        assert_eq!(actual.success, expected.success);
        assert_eq!(actual.gas_used, expected.gas_used);
        assert_eq!(actual.created_address, expected.created_address);
        assert_eq!(actual.result, expected.result);
    }
    *database = reconstructed;
    for address in [sender(), spec.base_fee_vault, spec.sequencer_fee_vault] {
        assert_eq!(database.balance_of(&address), reference.balance_of(&address));
    }
    assert_eq!(database.head(), reference.head());
    assert_eq!(database.deposit_cursor(), reference.deposit_cursor());
    assert_eq!(database.total_minted_wei(), reference.total_minted_wei());
    assert_eq!(database.total_burned_wei(), reference.total_burned_wei());
    assert_eq!(database.total_native_wei(), reference.total_native_wei());
    expected
}

#[test]
fn generic_database_preserves_signed_contracts_deposits_fees_and_blockhash() {
    let spec = ChainSpec::default();
    let mut reference = L2State::genesis(&spec);
    let mut database = reference.clone();
    // Store calldata in slot 0, store BLOCKHASH(1) in slot 1, then stop.
    let runtime = [0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 1, 0x40, 0x60, 1, 0x55, 0];
    let first = input(
        &spec,
        &reference,
        vec![signed(&spec, 0, TxKind::Create, deploy(&runtime))],
        vec![deposit()],
    );
    let deployed = differential(&spec, &mut reference, &mut database, &first);
    assert!(deployed.tx_outcomes[0].success);
    assert_eq!(deployed.gas_used, spec.deposit_gas + deployed.tx_outcomes[0].gas_used);
    let contract = deployed.tx_outcomes[0].created_address.unwrap();
    let second = input(
        &spec,
        &reference,
        vec![signed(
            &spec,
            1,
            TxKind::Call(contract),
            U256::from(42).to_be_bytes::<32>().to_vec().into(),
        )],
        vec![],
    );
    let called = differential(&spec, &mut reference, &mut database, &second);
    assert!(called.tx_outcomes[0].success);
    assert_eq!(called.header.parent_hash, deployed.block_hash);
    let slots = &database.db().cache.accounts[&contract].storage;
    assert_eq!(slots[&U256::ZERO], U256::from(42));
    assert_eq!(slots[&U256::from(1)], U256::from_be_bytes(deployed.block_hash.0));

    // Another deployment must not lose the untouched first contract's storage.
    let third = input(
        &spec,
        &reference,
        vec![signed(&spec, 2, TxKind::Create, deploy(&[0x60, 0, 0x60, 0, 0xfd]))],
        vec![],
    );
    let reverter = differential(&spec, &mut reference, &mut database, &third).tx_outcomes[0]
        .created_address
        .unwrap();
    let fourth = input(
        &spec,
        &reference,
        vec![signed(&spec, 3, TxKind::Call(reverter), Bytes::new())],
        vec![],
    );
    let reverted = differential(&spec, &mut reference, &mut database, &fourth);
    assert!(!reverted.tx_outcomes[0].success);
    assert!(reverted.gas_used > 0);
    assert_eq!(database.nonce_of(&sender()), 4);
    // Shared fixture fingerprint for the portable and separately pinned Reth builds.
    assert_eq!(
        compute_keccak_mpt_state_root(&database),
        alloy_primitives::b256!("caa54b319b1297820f2e71093a55156bb19225c76eec4c9f40672c6b4e6453f3")
    );
    assert_eq!(
        database.db().cache.accounts[&contract].storage[&U256::ZERO],
        U256::from(42)
    );
}

#[test]
fn provider_errors_propagate_and_malformed_signatures_do_not_read_provider() {
    let spec = ChainSpec::default();
    let mut state = L2State::genesis(&spec);
    let root = state.commit_root();
    let valid = input(&spec, &state, vec![], vec![deposit()]);
    let mut provider = Provider::new(state.db().clone());
    provider.fail = true;
    let reads = provider.reads.clone();
    let error = execute_on_provider(&spec, provider, root, &valid)
        .err()
        .expect("provider failure");
    assert!(matches!(error, bloch_l2_evm::SignedInputError::Execution(_)));
    assert!(format!("{error:?}").contains("UnsupportedProvider"));
    assert!(reads.accounts.get() > 0);

    let malformed = input(&spec, &state, vec![Bytes::from_static(&[2])], vec![deposit()]);
    let provider = Provider::new(state.db().clone());
    let reads = provider.reads.clone();
    let error = execute_on_provider(&spec, provider, root, &malformed)
        .err()
        .expect("signature failure");
    assert!(matches!(error, bloch_l2_evm::SignedInputError::Authentication { .. }));
    assert_eq!(
        reads.accounts.get() + reads.storage.get() + reads.code.get() + reads.hashes.get(),
        0
    );
}

#[test]
fn same_transaction_selfdestruct_burns_value_and_deletes_prefunded_account() {
    let spec = ChainSpec::default();
    let mut reference = L2State::genesis(&spec);
    let mut database = reference.clone();
    let doomed = sender().create(0);
    // A committed balance already exists at the future CREATE address. This
    // exercises deletion of a backing account, not just a newly cached absence.
    let prefund = DepositMint {
        recipient: doomed,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 1,
            l1_txid: [2; 32],
            l1_vout: 0,
            l1_sats: 3,
        },
    };
    let funding = input(&spec, &reference, vec![], vec![deposit(), prefund]);
    differential(&spec, &mut reference, &mut database, &funding);
    assert!(database.account(&doomed).is_some());
    let prefunded_balance = database.balance_of(&doomed);
    assert_eq!(prefunded_balance, U256::from(30_000_000_000u64));

    // ADDRESS SELFDESTRUCT burns the entire account when it destroys itself
    // during its creating transaction under EIP-6780.
    let value = U256::from(1_000_000_000_000_000u64);
    let burn = input(
        &spec,
        &reference,
        vec![signed_with_value(
            &spec,
            0,
            TxKind::Create,
            Bytes::from_static(&[0x30, 0xff]),
            value,
        )],
        vec![],
    );
    let outcome = differential(&spec, &mut reference, &mut database, &burn);
    let expected_burn = value + prefunded_balance;
    assert!(outcome.tx_outcomes[0].success);
    assert_eq!(outcome.tx_outcomes[0].burned_wei, expected_burn);
    assert_eq!(outcome.burned_wei, expected_burn);
    assert_eq!(database.total_burned_wei(), expected_burn);
    assert!(database.account(&doomed).is_none());
    assert!(reference.account(&doomed).is_none());
    assert_eq!(database.balance_of(&doomed), U256::ZERO);
    assert_eq!(database.total_native_wei(), database.total_minted_wei() - expected_burn);
    assert_eq!(
        compute_keccak_mpt_state_root(&database),
        alloy_primitives::b256!("8d248f2fca24dad8c10537c898904ab52a031c765cb8e6a41f465dff2ef57873")
    );
}
