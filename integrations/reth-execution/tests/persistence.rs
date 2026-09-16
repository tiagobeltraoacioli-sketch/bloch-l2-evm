// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual Reth storage/trie integration. No Ethereum headers or node are fabricated.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    execute_signed_block, BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State, SignedBlockInput,
};
use bloch_reth_execution::{begin_on_provider, execute_on_provider, execution_bundle};
use k256::ecdsa::SigningKey;
use reth_db::{mdbx::DatabaseArguments, test_utils::TempDatabase};
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    test_utils::{create_test_provider_factory, MockNodeTypesWithDB},
    ChainSpecProvider, ChangeSetReader, DBProvider, DatabaseProviderFactory, ExecutionOutcome, HashedPostStateProvider,
    ProviderFactory, StateProvider, StateWriteConfig, StateWriter, StorageChangeSetReader, TrieWriter,
};
use reth_revm::revm::{
    database::{states::AccountStatus, BundleState, OriginalValuesKnown},
    state::AccountInfo,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

type Factory = ProviderFactory<MockNodeTypesWithDB>;

fn sign(key: &SigningKey, chain_id: u64, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    sign_with_value(key, chain_id, nonce, to, input, U256::ZERO)
}

fn sign_with_value(key: &SigningKey, chain_id: u64, nonce: u64, to: TxKind, input: Bytes, value: U256) -> Bytes {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        to,
        input,
        value,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}

/// Restore a single block's storage state using only persisted before-values
/// and the current database. This deliberately neither removes canonical block
/// metadata nor prunes history, and is not Reth's canonical unwind operation.
fn restore_storage_from_changesets(factory: &Factory, block: u64) -> B256 {
    let reader = factory.database_provider_ro().unwrap();
    let accounts: BTreeMap<_, Option<AccountInfo>> = reader
        .account_block_changeset(block)
        .unwrap()
        .into_iter()
        .map(|change| (change.address, change.info.map(Into::into)))
        .collect();
    let storage = reader.storage_block_changeset(block).unwrap();
    let addresses: BTreeSet<_> = accounts
        .keys()
        .copied()
        .chain(storage.iter().map(|change| change.address))
        .collect();
    let snapshot = factory.latest().unwrap();
    let mut builder = BundleState::builder(0..=0);
    for address in addresses {
        let current: Option<AccountInfo> = snapshot.basic_account(&address).unwrap().map(Into::into);
        let original = accounts.get(&address).cloned().unwrap_or_else(|| current.clone());
        builder = builder.state_address(address);
        if let Some(current) = current {
            builder = builder.state_original_account_info(address, current);
        }
        if let Some(original) = original {
            builder = builder.state_present_account_info(address, original);
        }
        builder.set_state_storage(
            address,
            storage
                .iter()
                .filter(|change| change.address == address)
                .map(|change| {
                    let current = snapshot.storage(address, change.key).unwrap().unwrap_or_default();
                    (U256::from_be_bytes(change.key.0), (current, change.value))
                })
                .collect(),
        );
    }
    let mut inverse = builder.build();
    for account in inverse.state.values_mut() {
        account.status = match (&account.original_info, &account.info) {
            (_, None) => AccountStatus::Destroyed,
            (None, Some(_)) => AccountStatus::InMemoryChange,
            (Some(_), Some(_)) => AccountStatus::Changed,
        };
    }
    let hashed = factory.hashed_post_state(&inverse);
    let (root, updates) = snapshot.state_root_with_updates(hashed.clone()).unwrap();
    drop(snapshot);
    drop(reader);
    let writer = factory.database_provider_rw().unwrap();
    // Do not create a fictitious new block or overwrite the saved before-values.
    writer
        .write_state_changes(inverse.to_plain_state(OriginalValuesKnown::Yes))
        .unwrap();
    writer.write_hashed_state(&hashed.into_sorted()).unwrap();
    writer.write_trie_updates(updates).unwrap();
    writer.commit().unwrap();
    root
}

#[test]
fn persisted_wipe_restores_unread_storage_from_disk_changesets_after_reopen() {
    let factory = create_test_provider_factory();
    let spec = ChainSpec::default();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let doomed = sender.create(0);
    let old_slot = U256::from(123);
    let old_value = U256::from(456);
    let mut reference = L2State::genesis(&spec);
    // A synthetic prefunded initial fixture; deposits still use the real mint
    // ledger. The extra storage models an old slot never read by the constructor.
    for (index, recipient, amount) in [(0, sender, 100_000_000), (1, doomed, 3)] {
        reference
            .deposit_mint(
                &spec,
                &DepositMint {
                    recipient,
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 1,
                        l1_tx_index: index,
                        l1_txid: [1; 32],
                        l1_vout: index,
                        l1_sats: amount,
                    },
                },
            )
            .unwrap();
    }
    reference
        .db_mut()
        .insert_account_storage(doomed, old_slot, old_value)
        .unwrap();
    let before_root = reference.commit_root();
    persist(&factory, genesis_bundle(&reference), 0, before_root, false);
    let before = reference.clone();
    let value = U256::from(1_000_000_000_000_000u64);
    let mut context = BlockContext::next(&spec, &reference);
    context.anchor_root = B256::repeat_byte(44);
    let input = SignedBlockInput {
        context,
        transactions: vec![sign_with_value(
            &key,
            spec.chain_id,
            0,
            TxKind::Create,
            Bytes::from_static(&[0x30, 0xff]),
            value,
        )],
        deposits: vec![],
    };
    let pending = execute_on_provider(&spec, factory.latest().unwrap(), before_root, &input).unwrap();
    assert!(pending.overlay().cache.accounts[&doomed].storage.is_empty());
    let bundle = execution_bundle(&pending).unwrap();
    let (_, sparse_reverts) = bundle.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
    let wipe = sparse_reverts.storage[0]
        .iter()
        .find(|entry| entry.address == doomed)
        .unwrap();
    assert!(wipe.wiped);
    assert!(
        wipe.storage_revert.iter().all(|(slot, _)| *slot != old_slot),
        "the execution bundle itself does not know the deleted historical slot"
    );
    let hashed = factory.hashed_post_state(&bundle);
    let root = pending.overlay().db.0.state_root(hashed).unwrap();
    let (overlay, outcome) = pending.finalize(root);
    drop(overlay);
    let expected = execute_signed_block(&spec, &mut reference, &input).unwrap();
    assert_eq!(outcome.header, expected.header);
    assert_eq!(outcome.burned_wei, value + U256::from(30_000_000_000u64));
    persist(&factory, bundle, input.context.number, expected.state_root, false);
    let snapshot = factory.latest().unwrap();
    assert!(snapshot.basic_account(&doomed).unwrap().is_none());
    assert!(snapshot
        .storage(doomed, B256::from(old_slot.to_be_bytes::<32>()))
        .unwrap()
        .is_none());
    drop(snapshot);

    let factory = reopen(factory);
    let reader = factory.database_provider_ro().unwrap();
    assert_eq!(
        reader
            .get_storage_before_block(input.context.number, doomed, B256::from(old_slot.to_be_bytes::<32>()))
            .unwrap()
            .unwrap()
            .value,
        old_value,
        "the real Reth writer expanded the wipe marker into durable before-values"
    );
    drop(reader);
    let restored_root = restore_storage_from_changesets(&factory, input.context.number);
    assert_eq!(restored_root, before_root);
    assert_snapshot(factory.latest().unwrap().as_ref(), &before);

    let restored = reopen(factory);
    assert_snapshot(restored.latest().unwrap().as_ref(), &before);
    assert_eq!(
        restored
            .latest()
            .unwrap()
            .storage(doomed, B256::from(old_slot.to_be_bytes::<32>()))
            .unwrap(),
        Some(old_value)
    );
    let reader = restored.database_provider_ro().unwrap();
    assert_eq!(
        reader
            .get_storage_before_block(input.context.number, doomed, B256::from(old_slot.to_be_bytes::<32>()))
            .unwrap()
            .unwrap()
            .value,
        old_value,
        "storage restoration deliberately retains history and does not claim canonical unwind"
    );
}

fn genesis_bundle(state: &L2State) -> BundleState {
    let mut builder = BundleState::builder(0..=0);
    for (address, account) in &state.db().cache.accounts {
        if state.account(address).is_none() {
            continue;
        }
        builder = builder
            .state_address(*address)
            .state_present_account_info(*address, account.info.clone());
        builder.set_state_storage(
            *address,
            account
                .storage
                .iter()
                .map(|(slot, value)| (*slot, (U256::ZERO, *value)))
                .collect(),
        );
    }
    for (hash, code) in &state.db().cache.contracts {
        builder = builder.contract(*hash, code.clone());
    }
    builder.build()
}

/// Calculate the root through Reth's actual database trie, then persist all
/// hashed/plain state and trie updates through its writer and commit boundary.
fn persist(factory: &Factory, bundle: BundleState, block: u64, expected_root: B256, abort_first: bool) {
    let hashed = factory.hashed_post_state(&bundle);
    let snapshot = factory.latest().unwrap();
    let before = snapshot.state_root(Default::default()).unwrap();
    let (root, updates) = snapshot.state_root_with_updates(hashed.clone()).unwrap();
    assert_eq!(
        root, expected_root,
        "Reth independently computes the Bloch execution root"
    );
    drop(snapshot);
    let outcome = ExecutionOutcome::new(bundle, vec![], block, vec![]);
    let config = StateWriteConfig {
        write_receipts: false,
        ..Default::default()
    };
    let sorted = hashed.into_sorted();
    if abort_first {
        let writer = factory.database_provider_rw().unwrap();
        writer.write_state(&outcome, OriginalValuesKnown::Yes, config).unwrap();
        writer.write_hashed_state(&sorted).unwrap();
        writer.write_trie_updates(updates.clone()).unwrap();
        drop(writer);
        assert_eq!(
            factory.latest().unwrap().state_root(Default::default()).unwrap(),
            before,
            "dropping an uncommitted writer must preserve the previous root"
        );
    }
    let writer = factory.database_provider_rw().unwrap();
    writer.write_state(&outcome, OriginalValuesKnown::Yes, config).unwrap();
    writer.write_hashed_state(&sorted).unwrap();
    writer.write_trie_updates(updates).unwrap();
    writer.commit().unwrap();
    assert_eq!(factory.latest().unwrap().state_root(Default::default()).unwrap(), root);
}

fn assert_snapshot(snapshot: &dyn StateProvider, reference: &L2State) {
    assert_eq!(snapshot.state_root(Default::default()).unwrap(), reference.state_root());
    for (address, account) in &reference.db().cache.accounts {
        if reference.account(address).is_none() {
            continue;
        }
        let stored = snapshot.basic_account(address).unwrap().expect("persisted account");
        assert_eq!(stored.balance, account.info.balance);
        assert_eq!(stored.nonce, account.info.nonce);
        for (slot, value) in &account.storage {
            assert_eq!(
                snapshot
                    .storage(*address, B256::from(slot.to_be_bytes::<32>()))
                    .unwrap()
                    .unwrap_or_default(),
                *value
            );
        }
    }
}

/// Release the factory and actual MDBX/RocksDB handles, preserving its disposable
/// directory, then open new handles. No live reader or writer survives this call.
fn reopen(factory: Factory) -> Factory {
    let chain_spec = factory.chain_spec();
    let directory = factory.db_ref().path().to_path_buf();
    let temporary = Arc::try_unwrap(factory.into_db()).expect("all provider handles dropped");
    drop(temporary.into_inner_db());
    let db = reth_db::init_db(directory.join("db"), DatabaseArguments::test()).unwrap();
    ProviderFactory::new(
        Arc::new(TempDatabase::new(db, directory.clone())),
        chain_spec,
        StaticFileProvider::read_write(directory.join("static_files")).unwrap(),
        RocksDBBuilder::new(directory.join("rocksdb"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap()
}

#[test]
fn real_reth_storage_commits_roots_reopens_and_discards_uncommitted_writes() {
    // Upstream test factory supplies only storage plumbing. No mainnet genesis
    // or Ethereum block is inserted: the state below is exactly Bloch's genesis.
    let factory = create_test_provider_factory();
    let spec = ChainSpec::default();
    let mut reference = L2State::genesis(&spec);
    persist(&factory, genesis_bundle(&reference), 0, reference.commit_root(), false);
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    // Store calldata word in slot 0; return it. No external compiler required.
    let runtime = [
        0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 0, 0x54, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3,
    ];
    let length = u8::try_from(runtime.len()).unwrap();
    let mut creation = vec![0x60, length, 0x60, 12, 0x60, 0, 0x39, 0x60, length, 0x60, 0, 0xf3];
    creation.extend_from_slice(&runtime);
    let transactions = [
        sign(&key, spec.chain_id, 0, TxKind::Create, creation.into()),
        sign(
            &key,
            spec.chain_id,
            1,
            TxKind::Call(contract),
            U256::from(42).to_be_bytes::<32>().to_vec().into(),
        ),
        sign(
            &key,
            spec.chain_id,
            2,
            TxKind::Call(contract),
            U256::ZERO.to_be_bytes::<32>().to_vec().into(),
        ),
    ];
    for (index, raw) in transactions.into_iter().enumerate() {
        let mut context = BlockContext::next(&spec, &reference);
        context.anchor_root = B256::repeat_byte(44); // Synthetic L1 context.
        let input = SignedBlockInput {
            context,
            transactions: vec![raw],
            deposits: if index == 0 {
                vec![DepositMint {
                    recipient: sender,
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 1,
                        l1_tx_index: 0,
                        l1_txid: [1; 32],
                        l1_vout: 0,
                        l1_sats: 100_000_000,
                    },
                }]
            } else {
                vec![]
            },
        };
        let mut builder = begin_on_provider(
            &spec,
            factory.latest().unwrap(),
            reference.commit_root(),
            input.context.clone(),
            input.deposits.clone(),
        )
        .unwrap();
        assert!(builder
            .try_push_with_condition(&input.transactions[0], |_| false)
            .unwrap()
            .is_none());
        assert!(builder.input().transactions.is_empty());
        builder.try_push(&input.transactions[0]).unwrap();
        let (accepted, pending) = builder.finish().unwrap();
        assert_eq!(accepted.transactions, input.transactions);
        let bundle = execution_bundle(&pending).unwrap();
        let hashed = factory.hashed_post_state(&bundle);
        let reth_root = pending.overlay().db.0.state_root(hashed).unwrap();
        let (overlay, actual) = pending.finalize(reth_root);
        drop(overlay); // Close the execution snapshot before any database commit.
        let expected = execute_signed_block(&spec, &mut reference, &input).unwrap();
        assert!(expected.tx_outcomes[0].success);
        assert_eq!(actual.header, expected.header);
        assert_eq!(actual.block_hash, expected.block_hash);
        assert_eq!(actual.state_root, expected.state_root);
        persist(&factory, bundle, input.context.number, expected.state_root, index == 1);
        assert_snapshot(factory.latest().unwrap().as_ref(), &reference);
    }
    let snapshot = factory.latest().unwrap();
    assert_eq!(snapshot.account_nonce(&sender).unwrap(), Some(3));
    assert_eq!(
        snapshot.storage(contract, B256::ZERO).unwrap(),
        None,
        "zero storage is deleted on disk"
    );
    assert_eq!(
        snapshot
            .account_code(&contract)
            .unwrap()
            .unwrap()
            .0
            .original_bytes()
            .as_ref(),
        runtime
    );
    drop(snapshot);
    let reader = factory.database_provider_ro().unwrap();
    assert_eq!(
        reader
            .get_storage_before_block(3, contract, B256::ZERO)
            .unwrap()
            .unwrap()
            .value,
        U256::from(42)
    );
    assert_eq!(
        reader
            .get_account_before_block(2, sender)
            .unwrap()
            .unwrap()
            .info
            .unwrap()
            .nonce,
        1
    );
    drop(reader);

    let reopened = reopen(factory);
    assert_snapshot(reopened.latest().unwrap().as_ref(), &reference);
    assert_eq!(reopened.latest().unwrap().account_nonce(&sender).unwrap(), Some(3));
    assert_eq!(
        reopened
            .latest()
            .unwrap()
            .account_code(&contract)
            .unwrap()
            .unwrap()
            .0
            .original_bytes()
            .as_ref(),
        runtime,
        "contract bytecode survives closing and reopening the storage handles"
    );
    let reader = reopened.database_provider_ro().unwrap();
    assert_eq!(
        reader
            .get_storage_before_block(3, contract, B256::ZERO)
            .unwrap()
            .unwrap()
            .value,
        U256::from(42)
    );
}
