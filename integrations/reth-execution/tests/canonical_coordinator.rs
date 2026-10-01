// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real persistence, publication and rejection boundaries of the canonical writer.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, Signature, TxKind, B256};
use bloch_l2_evm::{ChainSpec, DepositMint, DepositProvenance};
use bloch_reth_execution::{
    prepare_genesis, BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator,
};
use k256::ecdsa::SigningKey;
use reth_chain_state::{CanonStateNotification, CanonStateSubscriptions};
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::{
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, ChainSpecProvider, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
    ReceiptProvider, StaticFileProviderFactory, StaticFileWriter, TransactionsProvider,
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
fn attributes(timestamp: u64) -> BlochNextBlockEnvCtx {
    // Explicit local fixture inputs, not authenticated native derivation.
    BlochNextBlockEnvCtx {
        timestamp,
        prevrandao: B256::ZERO,
        anchor_root: B256::ZERO,
        deposits: vec![],
    }
}

#[test]
fn unverified_numeric_finality_markers_cannot_bootstrap_the_canonical_provider() {
    for key in [
        tables::ChainStateKey::LastSafeBlock,
        tables::ChainStateKey::LastFinalizedBlock,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(75), 10).unwrap());
        let factory = open(directory.path(), spec.clone());
        let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
        let writer = factory.database_provider_rw().unwrap();
        writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
        writer.tx_ref().put::<tables::ChainState>(key.clone(), 0).unwrap();
        writer.commit().unwrap();
        drop(factory);
        let factory = open(directory.path(), spec);
        assert!(CanonicalCoordinator::attach(factory.clone()).is_err());
        let reader = factory.database_provider_ro().unwrap();
        assert_eq!(reader.tx_ref().get::<tables::ChainState>(key).unwrap(), Some(0));
    }
}

#[test]
fn held_transaction_snapshot_does_not_follow_newer_static_file_tip() {
    snapshot_queries_survive_static_tip_advance(false);
}

#[test]
fn held_transaction_range_snapshot_does_not_follow_newer_static_file_tip() {
    snapshot_queries_survive_static_tip_advance(true);
}

fn snapshot_queries_survive_static_tip_advance(range: bool) {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(75), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
    let provider = coordinator.provider();
    assert!(provider.canonical_in_memory_state().head_state().is_none());
    // Hold a real MDBX read transaction while publishing a later static-file
    // header. No sleep or scheduler race is needed to expose this boundary.
    let snapshot = provider.consistent_provider().unwrap();
    coordinator.extend(spec.genesis_hash(), attributes(11), vec![]).unwrap();
    assert_eq!(factory.last_block_number().unwrap(), 1);
    if range {
        assert!(snapshot.transactions_by_tx_range(0..1).unwrap().is_empty());
        assert!(snapshot.receipts_by_tx_range(0..1).unwrap().is_empty());
    } else {
        assert!(snapshot.transaction_by_id(0).unwrap().is_none());
    }
    assert!(provider.transaction_by_id(0).unwrap().is_none());
}

#[test]
fn held_snapshot_preserves_old_transactions_and_excludes_later_transactions() {
    let directory = tempfile::tempdir().unwrap();
    let kernel = ChainSpec::testnet();
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), B256::repeat_byte(76), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(factory).unwrap();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let mut funding = attributes(11);
    funding.deposits.push(DepositMint {
        recipient: sender,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 0,
            l1_txid: [76; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    });
    coordinator.extend(spec.genesis_hash(), funding, vec![]).unwrap();
    let signed = |nonce| {
        let tx = TxEip1559 {
            chain_id: kernel.chain_id,
            nonce,
            to: TxKind::Call(sender),
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            ..Default::default()
        };
        let signature: Signature = key
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .unwrap()
            .into();
        bloch_reth_execution::BlochRethTransaction::from(tx.into_signed(signature))
    };
    let first = signed(0);
    coordinator
        .extend(coordinator.head().hash(), attributes(12), vec![first.clone()])
        .unwrap();
    let provider = coordinator.provider();
    let snapshot = provider.consistent_provider().unwrap();
    let second = signed(1);
    coordinator
        .extend(coordinator.head().hash(), attributes(13), vec![second.clone()])
        .unwrap();
    assert_eq!(snapshot.transaction_by_id(0).unwrap(), Some(first.clone()));
    assert!(snapshot.transaction_by_id(1).unwrap().is_none());
    assert_eq!(snapshot.transactions_by_tx_range(0..2).unwrap(), vec![first.clone()]);
    assert_eq!(snapshot.receipts_by_tx_range(0..2).unwrap().len(), 1);
    assert_eq!(provider.transactions_by_tx_range(0..2).unwrap(), vec![first, second]);
}

#[test]
fn publishes_only_committed_extensions_and_resumes_persisted_head() {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(71), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    assert!(CanonicalCoordinator::attach(factory.clone()).is_err());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
    let provider = coordinator.provider();
    let mut notifications = provider.subscribe_to_canonical_state();
    let genesis_hash = spec.genesis_hash();
    assert!(coordinator
        .extend(B256::repeat_byte(99), attributes(11), vec![])
        .is_err());
    assert!(coordinator.extend(genesis_hash, attributes(9), vec![]).is_err());
    assert!(!coordinator.is_poisoned());
    assert!(notifications.try_recv().is_err());
    assert_eq!(factory.best_block_number().unwrap(), 0);
    let first = coordinator.extend(genesis_hash, attributes(11), vec![]).unwrap();
    let notification = notifications.try_recv().unwrap();
    assert!(matches!(notification, CanonStateNotification::Commit { .. }));
    assert_eq!(factory.sealed_header(1).unwrap().unwrap(), first);
    assert_eq!(provider.best_block_number().unwrap(), 1);
    assert!(coordinator.extend(genesis_hash, attributes(12), vec![]).is_err());
    assert!(notifications.try_recv().is_err());
    drop(notifications);
    drop(provider);
    drop(coordinator);
    drop(factory);

    let reopened = open(directory.path(), spec);
    let mut resumed = CanonicalCoordinator::attach(reopened.clone()).unwrap();
    assert_eq!(resumed.head(), &first);
    let second = resumed.extend(first.hash(), attributes(12), vec![]).unwrap();
    assert_eq!(second.0.number, 2);
    assert_eq!(reopened.sealed_header(2).unwrap().unwrap(), second);
    drop(resumed);
    drop(reopened);
    let wrong_spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(99), 10).unwrap());
    let wrong_domain = open(directory.path(), wrong_spec);
    assert!(CanonicalCoordinator::attach(wrong_domain).is_err());
}

#[test]
fn rejects_external_canonical_change_before_writing_or_publishing() {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(72), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut stale = CanonicalCoordinator::attach(factory.clone()).unwrap();
    // Intentionally violate sole-writer ownership to exercise defensive rejection.
    let mut other = CanonicalCoordinator::attach(factory.clone()).unwrap();
    let mut notifications = stale.provider().subscribe_to_canonical_state();
    let tip = other.extend(spec.genesis_hash(), attributes(11), vec![]).unwrap();
    assert!(stale.extend(spec.genesis_hash(), attributes(12), vec![]).is_err());
    assert!(!stale.is_poisoned());
    assert!(notifications.try_recv().is_err());
    assert_eq!(factory.sealed_header(1).unwrap().unwrap(), tip);
    assert_eq!(factory.best_block_number().unwrap(), 1);
}

#[test]
fn missing_genesis_account_history_is_rejected_without_repairing_the_database() {
    assert_missing_history(true);
}

#[test]
fn missing_genesis_storage_history_is_rejected_without_repairing_the_database() {
    assert_missing_history(false);
}

fn assert_missing_history(accounts: bool) {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(73), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
    let tip = coordinator.extend(spec.genesis_hash(), attributes(11), vec![]).unwrap();
    drop(coordinator);
    // Reproduce a database with valid current state but missing genesis indices.
    let writer = factory.database_provider_rw().unwrap();
    if accounts {
        writer.tx_ref().clear::<tables::AccountsHistory>().unwrap();
    } else {
        writer.tx_ref().clear::<tables::StoragesHistory>().unwrap();
    }
    writer.commit().unwrap();
    let error = CanonicalCoordinator::attach(factory.clone())
        .err()
        .expect("missing history must fail closed");
    assert!(error.to_string().contains("historical genesis"), "{error}");
    let reader = factory.database_provider_ro().unwrap();
    if accounts {
        assert_eq!(reader.tx_ref().entries::<tables::AccountsHistory>().unwrap(), 0);
        assert!(reader.tx_ref().entries::<tables::StoragesHistory>().unwrap() > 0);
    } else {
        assert_eq!(reader.tx_ref().entries::<tables::StoragesHistory>().unwrap(), 0);
        assert!(reader.tx_ref().entries::<tables::AccountsHistory>().unwrap() > 0);
    }
    assert_eq!(factory.sealed_header(1).unwrap().unwrap(), tip);
    assert_eq!(factory.best_block_number().unwrap(), 1);
    let rebuilt_directory = tempfile::tempdir().unwrap();
    let rebuilt = open(rebuilt_directory.path(), spec);
    assert_eq!(
        bloch_reth_execution::replay_canonical_prefix(&factory, &rebuilt).unwrap(),
        tip
    );
    assert_eq!(CanonicalCoordinator::attach(rebuilt).unwrap().head(), &tip);
    if accounts {
        assert_eq!(reader.tx_ref().entries::<tables::AccountsHistory>().unwrap(), 0);
    } else {
        assert_eq!(reader.tx_ref().entries::<tables::StoragesHistory>().unwrap(), 0);
    }
}

#[test]
fn finalized_static_files_ahead_of_mdbx_are_rejected_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(74), 10).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut accepted = CanonicalCoordinator::attach(factory.clone()).unwrap();
    let parent = accepted.extend(spec.genesis_hash(), attributes(11), vec![]).unwrap();
    drop(accepted);
    let executed = bloch_reth_execution::execute_next_block(
        &bloch_reth_execution::BlochEvmConfig::new(spec.execution(), spec.domain()),
        factory.latest().unwrap().as_ref(),
        &parent,
        attributes(12),
        vec![],
    )
    .unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
    // Reproduce the durable boundary in DatabaseProvider::commit: static files
    // are finalized before MDBX commits. Abort MDBX after that boundary.
    factory.static_file_provider().finalize().unwrap();
    drop(writer);
    assert_eq!(factory.best_block_number().unwrap(), 1);
    assert_eq!(factory.last_block_number().unwrap(), 2);
    drop(factory);

    let reopened = open(directory.path(), spec.clone());
    let error = CanonicalCoordinator::attach(reopened.clone())
        .err()
        .expect("partial persistence must not serve a head");
    assert!(error.to_string().contains("checkpoints disagree"), "{error}");
    assert_eq!(reopened.best_block_number().unwrap(), 1);
    assert_eq!(reopened.last_block_number().unwrap(), 2);
    assert_eq!(reopened.sealed_header(1).unwrap().unwrap(), parent);
    let target_directory = tempfile::tempdir().unwrap();
    let target = open(target_directory.path(), spec);
    let recovered = bloch_reth_execution::replay_canonical_prefix(&reopened, &target).unwrap();
    assert_eq!(recovered, parent);
    assert_eq!(CanonicalCoordinator::attach(target.clone()).unwrap().head(), &parent);
    assert_eq!(target.last_block_number().unwrap(), 1);
    assert!(target.sealed_header(2).unwrap().is_none());
    // Recovery did not truncate or otherwise repair the source in place.
    assert_eq!(reopened.best_block_number().unwrap(), 1);
    assert_eq!(reopened.last_block_number().unwrap(), 2);
    assert!(bloch_reth_execution::replay_canonical_prefix(&reopened, &target).is_err());
    // Losing a required body is not recoverable by inventing an empty block.
    let writer = reopened.database_provider_rw().unwrap();
    writer
        .tx_ref()
        .delete::<bloch_reth_execution::BlochV2Deposits>(1, None)
        .unwrap();
    writer.commit().unwrap();
    let incomplete_directory = tempfile::tempdir().unwrap();
    let incomplete = open(incomplete_directory.path(), target.chain_spec());
    assert!(bloch_reth_execution::replay_canonical_prefix(&reopened, &incomplete).is_err());
    assert_eq!(incomplete.best_block_number().unwrap(), 0);
    assert!(incomplete.sealed_header(1).unwrap().is_none());
}
