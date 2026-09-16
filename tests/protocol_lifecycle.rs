// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase atomicity on a mutable-only, caller-owned provisional database.
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::BEACON_ROOTS_ADDRESS,
    executor::lifecycle::prepare_block_start,
    state::{
        BLOCK_INFO_FLAG_SLOT, SUPPLY_LEDGER_BURNED_SLOT, SUPPLY_LEDGER_CURSOR_SLOT, SUPPLY_LEDGER_TOTAL_MINTED_SLOT,
    },
    BlockContext, BlockExecutionError, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use revm::{
    context::{result::ResultAndState, BlockEnv, CfgEnv, TxEnv},
    database::InMemoryDB,
    state::{AccountInfo, Bytecode, EvmState},
    Context, Database, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext, SystemCallEvm,
};

const SENDER: Address = Address::repeat_byte(11);
const OTHER: Address = Address::repeat_byte(12);
#[derive(Debug)]
struct Unavailable;
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("phase fixture unavailable")
    }
}
impl std::error::Error for Unavailable {}
impl revm::context::DBErrorMarker for Unavailable {}
struct MutableOnly {
    inner: InMemoryDB,
    commits: usize,
    fail: Option<Address>,
    reads: Vec<Address>,
}
impl Database for MutableOnly {
    type Error = Unavailable;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.reads.push(address);
        if self.fail == Some(address) {
            return Err(Unavailable);
        }
        Ok(self.inner.basic(address).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.inner.code_by_hash(hash).unwrap())
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.reads.push(address);
        if self.fail == Some(address) {
            return Err(Unavailable);
        }
        Ok(self.inner.storage(address, slot).unwrap())
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.inner.block_hash(number).unwrap())
    }
}
impl DatabaseCommit for MutableOnly {
    fn commit(&mut self, state: EvmState) {
        self.commits += 1;
        self.inner.commit(state)
    }
}
fn db() -> MutableOnly {
    MutableOnly {
        inner: InMemoryDB::default(),
        commits: 0,
        fail: None,
        reads: Vec::new(),
    }
}
fn root(db: &MutableOnly) -> B256 {
    let mut state = L2State::new();
    *state.db_mut() = db.inner.clone();
    state.commit_root()
}
fn deposit(recipient: Address, height: u64, sats: u64) -> DepositMint {
    DepositMint {
        recipient,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: height,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 0,
            l1_sats: sats,
        },
    }
}
fn input(deposits: Vec<DepositMint>) -> BlockInput {
    BlockInput {
        context: BlockContext::default(),
        deposits,
        txs: Vec::new(),
    }
}
fn context<'a>(
    db: &'a mut MutableOnly,
    spec: &ChainSpec,
    input: &BlockInput,
) -> Context<BlockEnv, TxEnv, CfgEnv, &'a mut MutableOnly> {
    Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = spec.chain_id;
            cfg.set_spec_and_mainnet_gas_params(spec.spec_id)
        })
        .modify_block_chained(|block| {
            block.number = U256::from(input.context.number);
            block.timestamp = U256::from(input.context.timestamp);
            block.basefee = input.context.base_fee_per_gas;
            block.gas_limit = spec.gas_limit;
            block.beneficiary = spec.coinbase();
            block.prevrandao = Some(input.context.prevrandao);
        })
}
fn system(db: &mut MutableOnly, spec: &ChainSpec, input: &BlockInput) -> ResultAndState {
    context(db, spec, input)
        .build_mainnet()
        .system_call(
            BEACON_ROOTS_ADDRESS,
            Bytes::copy_from_slice(input.context.anchor_root.as_slice()),
        )
        .unwrap()
}
#[test]
fn dropped_start_and_failed_start_never_commit() {
    let spec = ChainSpec::testnet();
    let mut db = db();
    let input = input(Vec::new());
    let before = root(&db);
    let prepared = prepare_block_start(&spec, &mut db, before, &input).unwrap();
    drop(prepared);
    assert_eq!(db.commits, 0);
    assert_eq!(root(&db), before);
    db.fail = Some(BEACON_ROOTS_ADDRESS);
    assert!(matches!(
        prepare_block_start(&spec, &mut db, before, &input),
        Err(BlockExecutionError::Database { .. })
    ));
    assert_eq!(db.commits, 0);
    assert_eq!(root(&db), before);
    db.fail = None;
    let mut invalid = input;
    invalid.context.base_fee_per_gas += 1;
    assert!(matches!(
        prepare_block_start(&spec, &mut db, before, &invalid),
        Err(BlockExecutionError::InvalidBaseFee { .. })
    ));
    assert_eq!(db.commits, 0);
    assert_eq!(root(&db), before);
}
#[test]
fn late_deposit_cap_failure_discards_entire_deposit_batch() {
    let spec = ChainSpec {
        max_l1_sats: 10,
        ..ChainSpec::testnet()
    };
    let mut db = db();
    let input = input(vec![deposit(SENDER, 1, 6), deposit(OTHER, 2, 6)]);
    let before = root(&db);
    let pending = prepare_block_start(&spec, &mut db, before, &input)
        .unwrap()
        .commit(&mut db);
    let commits = db.commits;
    let result = system(&mut db, &spec, &input);
    assert!(result.result.is_success());
    assert!(matches!(
        pending.complete(result, &mut db),
        Err(BlockExecutionError::Deposit(_))
    ));
    assert_eq!(db.commits, commits + 1, "only the system result committed after prefix");
    assert!(db.inner.basic(SENDER).unwrap().is_none());
    assert!(db.inner.basic(OTHER).unwrap().is_none());
    assert_eq!(
        db.inner.storage(spec.supply_ledger, SUPPLY_LEDGER_CURSOR_SLOT).unwrap(),
        U256::ZERO
    );
    assert_eq!(
        db.inner
            .storage(spec.supply_ledger, SUPPLY_LEDGER_TOTAL_MINTED_SLOT)
            .unwrap(),
        U256::ZERO
    );
    assert_ne!(
        root(&db),
        before,
        "earlier protocol prefix intentionally remains provisional"
    );
}
#[test]
fn unsuccessful_actual_system_call_is_not_committed() {
    let spec = ChainSpec::testnet();
    let mut db = db();
    let code = Bytecode::new_legacy(Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]));
    db.inner.insert_account_info(
        BEACON_ROOTS_ADDRESS,
        AccountInfo {
            nonce: 1,
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let input = input(Vec::new());
    let before = root(&db);
    let pending = prepare_block_start(&spec, &mut db, before, &input)
        .unwrap()
        .commit(&mut db);
    let result = system(&mut db, &spec, &input);
    assert!(!result.result.is_success());
    let commits = db.commits;
    let after_prefix = root(&db);
    assert!(matches!(
        pending.complete(result, &mut db),
        Err(BlockExecutionError::SystemCall { .. })
    ));
    assert_eq!(db.commits, commits);
    assert_eq!(root(&db), after_prefix);
}
#[test]
fn late_final_head_read_failure_does_not_publish_staged_burn() {
    let spec = ChainSpec::testnet();
    let mut db = db();
    let input = input(vec![deposit(SENDER, 1, 100_000_000)]);
    let before = root(&db);
    let pending = prepare_block_start(&spec, &mut db, before, &input)
        .unwrap()
        .commit(&mut db);
    let result = system(&mut db, &spec, &input);
    let mut active = pending.complete(result, &mut db).unwrap();
    let tx = TxEnv {
        tx_type: 2,
        caller: SENDER,
        gas_limit: 200_000,
        gas_price: 2_000_000_000,
        gas_priority_fee: Some(100_000_000),
        kind: TxKind::Create,
        value: U256::from(123),
        data: Bytes::from_static(&[0x30, 0xff]),
        chain_id: Some(spec.chain_id),
        nonce: 0,
        ..Default::default()
    };
    active.validate_transaction(&tx).unwrap();
    let result = context(&mut db, &spec, &input)
        .build_mainnet()
        .transact(tx.clone())
        .unwrap();
    let candidate = active.prepare_transaction(&tx, result, &mut db).unwrap();
    assert_eq!(candidate.outcome().burned_wei, U256::from(123));
    candidate.commit(&mut db);
    let commits = db.commits;
    let before_finish = root(&db);
    db.reads.clear();
    db.fail = Some(spec.block_info);
    assert!(matches!(
        active.prepare_finish(&mut db),
        Err(BlockExecutionError::Database { .. })
    ));
    assert!(
        db.reads.contains(&spec.supply_ledger),
        "burn preparation preceded head failure"
    );
    assert_eq!(db.commits, commits);
    assert_eq!(root(&db), before_finish);
    assert_eq!(
        db.inner.storage(spec.supply_ledger, SUPPLY_LEDGER_BURNED_SLOT).unwrap(),
        U256::ZERO
    );
    assert_eq!(
        db.inner.storage(spec.block_info, BLOCK_INFO_FLAG_SLOT).unwrap(),
        U256::ZERO
    );
}

#[test]
fn replayed_deposit_cursor_preserves_existing_supply_and_balances() {
    let spec = ChainSpec::testnet();
    let mut funded = L2State::genesis(&spec);
    funded.deposit_mint(&spec, &deposit(OTHER, 5, 100)).unwrap();
    let mut db = db();
    db.inner = funded.db().clone();
    let cursor = db.inner.storage(spec.supply_ledger, SUPPLY_LEDGER_CURSOR_SLOT).unwrap();
    let supply = db
        .inner
        .storage(spec.supply_ledger, SUPPLY_LEDGER_TOTAL_MINTED_SLOT)
        .unwrap();
    let balance = db.inner.basic(OTHER).unwrap().unwrap().balance;
    let input = input(vec![deposit(SENDER, 4, 10), deposit(OTHER, 6, 10)]);
    let before = root(&db);
    let pending = prepare_block_start(&spec, &mut db, before, &input)
        .unwrap()
        .commit(&mut db);
    let result = system(&mut db, &spec, &input);
    let commits = db.commits;
    assert!(matches!(
        pending.complete(result, &mut db),
        Err(BlockExecutionError::Deposit(_))
    ));
    assert_eq!(db.commits, commits + 1);
    assert!(db.inner.basic(SENDER).unwrap().is_none());
    assert_eq!(db.inner.basic(OTHER).unwrap().unwrap().balance, balance);
    assert_eq!(
        db.inner.storage(spec.supply_ledger, SUPPLY_LEDGER_CURSOR_SLOT).unwrap(),
        cursor
    );
    assert_eq!(
        db.inner
            .storage(spec.supply_ledger, SUPPLY_LEDGER_TOTAL_MINTED_SLOT)
            .unwrap(),
        supply
    );
}
