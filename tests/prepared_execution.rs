// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared accounting over a mutable-only database, as required by Alloy StateDB.
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use bloch_l2_evm::{prepare_transaction_effects, ChainSpec, DepositMint, DepositProvenance, L2State};
use revm::{
    bytecode::Bytecode,
    context::{result::ResultAndState, TxEnv},
    database::InMemoryDB,
    handler::ExecuteEvm,
    state::{AccountInfo, EvmState},
    Context, Database, DatabaseCommit, DatabaseRef, MainBuilder, MainContext,
};

const SENDER: Address = Address::repeat_byte(17);
const RECIPIENT: Address = Address::repeat_byte(18);

#[derive(Debug)]
struct ReadFailure;
impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixture read failure")
    }
}
impl std::error::Error for ReadFailure {}
impl revm::context::DBErrorMarker for ReadFailure {}

/// Deliberately implements Database and DatabaseCommit, but NOT DatabaseRef.
struct MutableOnly {
    inner: InMemoryDB,
    fail_address: Option<Address>,
    commits: usize,
}
impl Database for MutableOnly {
    type Error = ReadFailure;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if self.fail_address == Some(address) {
            return Err(ReadFailure);
        }
        Ok(self.inner.basic(address).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.inner.code_by_hash(hash).unwrap())
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        Ok(self.inner.storage(address, slot).unwrap())
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.inner.block_hash(number).unwrap())
    }
}
impl DatabaseCommit for MutableOnly {
    fn commit(&mut self, state: EvmState) {
        self.commits += 1;
        self.inner.commit(state);
    }
}
fn funded(spec: &ChainSpec) -> MutableOnly {
    let mut state = L2State::genesis(spec);
    state
        .deposit_mint(
            spec,
            &DepositMint {
                recipient: SENDER,
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: 1,
                    l1_tx_index: 0,
                    l1_txid: [1; 32],
                    l1_vout: 0,
                    l1_sats: 100_000_000,
                },
            },
        )
        .unwrap();
    MutableOnly {
        inner: state.db().clone(),
        fail_address: None,
        commits: 0,
    }
}
fn root(db: &MutableOnly) -> B256 {
    let mut state = L2State::new();
    *state.db_mut() = db.inner.clone();
    state.commit_root()
}
fn tx(spec: &ChainSpec) -> TxEnv {
    TxEnv {
        tx_type: 2,
        caller: SENDER,
        gas_limit: 200_000,
        gas_price: 2_000_000_000,
        gas_priority_fee: Some(100_000_000),
        kind: TxKind::Call(RECIPIENT),
        value: U256::from(123),
        chain_id: Some(spec.chain_id),
        nonce: 0,
        ..Default::default()
    }
}
fn execute(db: MutableOnly, spec: &ChainSpec, tx: &TxEnv) -> (MutableOnly, ResultAndState) {
    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = spec.chain_id;
            cfg.set_spec_and_mainnet_gas_params(spec.spec_id);
        })
        .modify_block_chained(|block| {
            block.number = U256::from(1);
            block.timestamp = U256::from(1);
            block.gas_limit = spec.gas_limit;
            block.basefee = spec.initial_base_fee;
            block.beneficiary = spec.coinbase();
            block.prevrandao = Some(B256::ZERO);
        })
        .build_mainnet();
    let result = evm.transact(tx.clone()).unwrap();
    (evm.ctx.journaled_state.database, result)
}

#[test]
fn prepare_drop_and_commit_work_with_mutable_only_database() {
    let spec = ChainSpec::default();
    let db = funded(&spec);
    let original_root = root(&db);
    let transaction = tx(&spec);
    let (mut db, result) = execute(db, &spec, &transaction);
    let prepared = prepare_transaction_effects(&spec, spec.initial_base_fee, &transaction, 0, result, &mut db).unwrap();
    assert!(prepared.outcome().success);
    assert_eq!(prepared.outcome().gas_used, 21_000);
    assert_eq!(db.commits, 0);
    assert_eq!(root(&db), original_root);
    drop(prepared);
    let (mut db, result) = execute(db, &spec, &transaction);
    let prepared = prepare_transaction_effects(&spec, spec.initial_base_fee, &transaction, 0, result, &mut db).unwrap();
    // Commitment must be infallible and perform no further database reads.
    db.fail_address = Some(spec.base_fee_vault);
    let committed = prepared.commit(&mut db);
    assert_eq!(
        committed.base_fee_routed_wei,
        U256::from(spec.initial_base_fee) * U256::from(21_000)
    );
    assert_eq!(
        committed.priority_fee_routed_wei,
        U256::from(100_000_000u64) * U256::from(21_000)
    );
    assert_eq!(db.inner.basic_ref(SENDER).unwrap().unwrap().nonce, 1);
    assert_eq!(db.inner.basic_ref(RECIPIENT).unwrap().unwrap().balance, U256::from(123));
    assert_eq!(
        db.inner.basic_ref(spec.base_fee_vault).unwrap().unwrap().balance,
        committed.base_fee_routed_wei
    );
    assert_eq!(
        db.inner.basic_ref(spec.coinbase()).unwrap().unwrap().balance,
        committed.priority_fee_routed_wei
    );
}

#[test]
fn late_provider_failure_returns_no_prepared_effects_and_performs_no_commits() {
    let spec = ChainSpec::default();
    let db = funded(&spec);
    let original_root = root(&db);
    let transaction = tx(&spec);
    let (mut db, result) = execute(db, &spec, &transaction);
    db.fail_address = Some(spec.base_fee_vault);
    assert!(prepare_transaction_effects(&spec, spec.initial_base_fee, &transaction, 0, result, &mut db).is_err());
    assert_eq!(db.commits, 0);
    assert_eq!(root(&db), original_root);
    db.fail_address = None;
    let (mut db, result) = execute(db, &spec, &transaction);
    let prepared = prepare_transaction_effects(&spec, spec.initial_base_fee, &transaction, 0, result, &mut db).unwrap();
    prepared.commit(&mut db);
    assert_eq!(db.inner.basic_ref(SENDER).unwrap().unwrap().nonce, 1);
}

#[test]
fn selfdestructed_fee_vault_is_recreated_after_wiping_old_storage() {
    let spec = ChainSpec {
        base_fee_vault: SENDER.create(0),
        ..Default::default()
    };
    spec.validate().unwrap();
    let mut db = funded(&spec);
    let vault = spec.base_fee_vault;
    db.inner.insert_account_info(
        vault,
        AccountInfo {
            balance: U256::from(777),
            ..Default::default()
        },
    );
    db.inner
        .insert_account_storage(vault, U256::from(9), U256::from(456))
        .unwrap();
    let transaction = TxEnv {
        kind: TxKind::Create,
        data: Bytes::from_static(&[0x30, 0xff]),
        ..tx(&spec)
    };
    let (mut db, result) = execute(db, &spec, &transaction);
    assert!(result.result.is_success());
    assert!(result.state[&vault].is_selfdestructed());
    let prepared = prepare_transaction_effects(&spec, spec.initial_base_fee, &transaction, 0, result, &mut db).unwrap();
    assert_eq!(prepared.outcome().burned_wei, U256::from(900));
    let committed = prepared.commit(&mut db);
    let restored = db.inner.basic_ref(vault).unwrap().unwrap();
    assert_eq!(restored.balance, committed.base_fee_routed_wei);
    assert_eq!(restored.nonce, 0);
    assert_eq!(db.inner.storage_ref(vault, U256::from(9)).unwrap(), U256::ZERO);
}

#[test]
fn fee_credit_preserves_storage_of_vault_created_by_the_transaction() {
    let spec = ChainSpec {
        base_fee_vault: SENDER.create(0),
        ..Default::default()
    };
    spec.validate().unwrap();
    let db = funded(&spec);
    let transaction = TxEnv {
        kind: TxKind::Create,
        data: Bytes::from_static(&[0x60, 42, 0x60, 0, 0x55, 0]),
        ..tx(&spec)
    };
    let (mut db, result) = execute(db, &spec, &transaction);
    assert!(result.result.is_success());
    assert!(result.state[&spec.base_fee_vault].is_created());
    let prepared = prepare_transaction_effects(&spec, spec.initial_base_fee, &transaction, 0, result, &mut db).unwrap();
    assert_eq!(prepared.outcome().burned_wei, U256::ZERO);
    let committed = prepared.commit(&mut db);
    assert_eq!(
        db.inner.storage_ref(spec.base_fee_vault, U256::ZERO).unwrap(),
        U256::from(42)
    );
    assert_eq!(
        db.inner.basic_ref(spec.base_fee_vault).unwrap().unwrap().balance,
        committed.base_fee_routed_wei + U256::from(123)
    );
}
