// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real MDBX/static-file commits coupled to the fail-closed lifecycle journal.
use alloy_primitives::B256;
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    initialize_runtime_record, prepare_genesis, runtime_receipt_tip, BlochChainSpec, BlochNextBlockEnvCtx,
    BlochProviderFactory, BlochTables, DurableCanonicalSupervisor, DurableHead, RuntimeIdentity, SettlementCursor,
};
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{path::Path, sync::Arc};

fn open(path: &Path, spec: Arc<BlochChainSpec>) -> BlochProviderFactory {
    ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(path.join("db"), DatabaseArguments::test()).unwrap()),
        spec,
        StaticFileProvider::read_write(path.join("static")).unwrap(),
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap()
}

fn cursor(height: u64) -> SettlementCursor {
    SettlementCursor {
        l1_height: height,
        l1_block_hash: B256::repeat_byte(height as u8),
        event_index: height as u32,
    }
}

fn attributes(timestamp: u64) -> BlochNextBlockEnvCtx {
    BlochNextBlockEnvCtx {
        timestamp,
        prevrandao: B256::ZERO,
        anchor_root: B256::ZERO,
        deposits: vec![],
    }
}

fn fixture() -> (
    tempfile::TempDir,
    Arc<BlochChainSpec>,
    BlochProviderFactory,
    std::path::PathBuf,
) {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0x91), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let header = genesis.recovered_block().clone_sealed_header();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let runtime = directory.path().join("runtime.state");
    initialize_runtime_record(
        &runtime,
        RuntimeIdentity {
            chain_id: spec.execution().chain_id,
            genesis_hash: spec.genesis_hash(),
        },
        DurableHead::from_header(&header, cursor(10)),
    )
    .unwrap();
    (directory, spec, factory, runtime)
}

#[test]
fn database_success_then_journal_failure_poisoned_without_retry() {
    let (directory, spec, factory, runtime) = fixture();
    let mut supervisor = DurableCanonicalSupervisor::attach(factory.clone(), &runtime, cursor(10)).unwrap();
    let receipts = directory.path().join("runtime.state.receipts");
    let extra_link = directory.path().join("receipts-hardlink");
    std::fs::hard_link(&receipts, &extra_link).unwrap();

    let error = supervisor
        .extend(spec.genesis_hash(), attributes(11), vec![], cursor(11))
        .expect_err("journal hardlink must reject after the database commit");
    assert!(error.to_string().contains("hard link"), "{error}");
    assert!(supervisor.is_poisoned());
    assert_eq!(factory.best_block_number().unwrap(), 1);
    let tip = factory.sealed_header(1).unwrap().unwrap();
    assert_eq!(tip, *supervisor.head());
    assert!(supervisor
        .extend(tip.hash(), attributes(12), vec![], cursor(12))
        .is_err());
    assert_eq!(
        factory.best_block_number().unwrap(),
        1,
        "poisoned wrapper must not commit twice"
    );
}

#[test]
fn stale_parent_or_settlement_cursor_poison_before_database_write() {
    let (_directory, _, factory, runtime) = fixture();
    let mut stale_parent = DurableCanonicalSupervisor::attach(factory.clone(), &runtime, cursor(10)).unwrap();
    assert!(stale_parent
        .extend(B256::repeat_byte(0xff), attributes(11), vec![], cursor(11))
        .is_err());
    assert!(stale_parent.is_poisoned());
    assert_eq!(factory.best_block_number().unwrap(), 0);

    // A poisoned lease remains running and cannot be silently reused. Use an
    // independent fixture to exercise cursor rejection before any DB mutation.
    let (_cursor_directory, spec, factory, runtime) = fixture();
    let mut stale_cursor = DurableCanonicalSupervisor::attach(factory.clone(), &runtime, cursor(10)).unwrap();
    assert!(stale_cursor
        .extend(spec.genesis_hash(), attributes(11), vec![], cursor(9))
        .is_err());
    assert!(stale_cursor.is_poisoned());
    assert_eq!(factory.best_block_number().unwrap(), 0);
}

#[test]
fn clean_restart_requires_exact_database_head_cursor_and_floor() {
    let (_directory, spec, factory, runtime) = fixture();
    let mut first = DurableCanonicalSupervisor::attach(factory.clone(), &runtime, cursor(10)).unwrap();
    let tip = first
        .extend(spec.genesis_hash(), attributes(11), vec![], cursor(11))
        .unwrap();
    first.shutdown().unwrap();
    let floor = runtime_receipt_tip(&runtime, None).unwrap();

    assert!(DurableCanonicalSupervisor::attach(factory.clone(), &runtime, cursor(10)).is_err());
    let resumed = DurableCanonicalSupervisor::attach_with_floor(factory.clone(), &runtime, cursor(11), floor).unwrap();
    assert_eq!(resumed.head(), &tip);
    assert_eq!(resumed.durable_head(), DurableHead::from_header(&tip, cursor(11)));
    resumed.shutdown().unwrap();
}
