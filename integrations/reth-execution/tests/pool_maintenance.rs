// SPDX-License-Identifier: MIT OR Apache-2.0
//! Upstream maintenance consumes real canonical broadcasts and reinserts reorged transactions.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{ChainSpec, DepositMint, DepositProvenance};
use bloch_reth_execution::{
    execute_next_block, pool_maintenance, pooled_from_raw, prepare_genesis, BlochChainSpec, BlochEvmConfig,
    BlochNextBlockEnvCtx, BlochNodePrimitives, BlochNodeTypes, BlochTables, BlochTransactionValidator,
};
use futures_util::StreamExt;
use k256::ecdsa::SigningKey;
use reth_chain_state::{CanonStateNotification, ExecutedBlock};
use reth_chainspec::EthChainSpec;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    DatabaseEnv,
};
use reth_execution_types::{Chain, ExecutionOutcome};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    providers::{BlockchainProvider, RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockExecutionWriter, BlockReader, DBProvider, DatabaseProviderFactory, ProviderFactory, StateProvider,
};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, maintain::MaintainPoolConfig, validate::EthTransactionValidatorBuilder,
    CoinbaseTipOrdering, EthPooledTransaction, FullTransactionEvent, Pool, PoolConfig, PoolTransaction,
    TransactionOrigin, TransactionPool,
};
use std::sync::Arc;

type Factory = ProviderFactory<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;
fn raw(key: &SigningKey, spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to,
        input,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    let tx: bloch_reth_execution::BlochRethTransaction = tx.into_signed(signature).into();
    tx.encoded_2718().into()
}

fn chain(block: &ExecutedBlock<BlochNodePrimitives>) -> Arc<Chain<BlochNodePrimitives>> {
    Arc::new(Chain::from_block(
        block.recovered_block().clone(),
        ExecutionOutcome::from((block.execution_outcome().clone(), block.block_number())),
        block.trie_data_handle(),
    ))
}

#[tokio::test]
async fn maintenance_mines_and_reinserts_on_real_canonical_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = ChainSpec::testnet();
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), B256::repeat_byte(71), 10).unwrap());
    let factory: Factory = ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(dir.path().join("db"), DatabaseArguments::test()).unwrap()),
        spec.clone(),
        StaticFileProvider::read_write(dir.path().join("static")).unwrap(),
        RocksDBBuilder::new(dir.path().join("rocks"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap();
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let config = BlochEvmConfig::new(&kernel, spec.domain());
    let attrs = BlochNextBlockEnvCtx {
        timestamp: 11,
        prevrandao: B256::ZERO,
        anchor_root: B256::repeat_byte(1),
        deposits: vec![DepositMint {
            recipient: sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
    };
    let funded = execute_next_block(
        &config,
        factory.latest().unwrap().as_ref(),
        &SealedHeader::seal_slow(spec.genesis_header().clone()),
        attrs,
        vec![],
    )
    .unwrap();
    let funded_block = funded.recovered_block().sealed_block().clone();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![funded], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let blobs = InMemoryBlobStore::default();
    let provider = BlockchainProvider::new(factory.clone()).unwrap();
    let inner = EthTransactionValidatorBuilder::new(provider.clone(), config.clone())
        .no_eip4844()
        .no_eip7702()
        .set_block_gas_limit(kernel.gas_limit)
        .build::<EthPooledTransaction, _>(blobs.clone());
    let pool = Pool::new(
        BlochTransactionValidator::new(&kernel, inner),
        CoinbaseTipOrdering::<EthPooledTransaction>::default(),
        blobs,
        PoolConfig::default(),
    );
    let maintenance_future = pool_maintenance(
        provider.clone(),
        pool.clone(),
        reth_tasks::Runtime::test(),
        MaintainPoolConfig::default(),
    )
    .unwrap();
    let runtime = [0x60, 0, 0x35, 0x60, 0, 0x55, 0];
    let mut init = vec![0x60, 7, 0x60, 12, 0x60, 0, 0x39, 0x60, 7, 0x60, 0, 0xf3];
    init.extend(runtime);
    let raws = [
        raw(&key, &kernel, 0, TxKind::Create, init.into()),
        raw(
            &key,
            &kernel,
            1,
            TxKind::Call(sender.create(0)),
            U256::from(42).to_be_bytes::<32>().to_vec().into(),
        ),
    ];
    pool.add_transaction(TransactionOrigin::External, pooled_from_raw(&kernel, &raws[1]).unwrap())
        .await
        .unwrap();
    assert!(
        pool.best_transactions().next().is_none(),
        "future nonce waits for its predecessor"
    );
    let mut forged_cache = pooled_from_raw(&kernel, &raws[0]).unwrap();
    forged_cache.transaction = alloy_consensus::transaction::Recovered::new_unchecked(
        forged_cache.transaction.into_inner(),
        Address::repeat_byte(99),
    );
    forged_cache.cost = U256::ZERO;
    forged_cache.encoded_length = 0;
    pool.add_transaction(TransactionOrigin::External, forged_cache)
        .await
        .unwrap();
    let selected: Vec<_> = pool
        .best_transactions()
        .map(|tx| tx.transaction.clone_into_consensus().into_inner())
        .collect();
    assert_eq!(selected.len(), 2);
    assert_eq!(
        selected.iter().map(|tx| tx.encoded_2718()).collect::<Vec<_>>(),
        raws.iter().map(|raw| raw.to_vec()).collect::<Vec<_>>()
    );
    let unfunded = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    assert!(pool
        .add_transaction(
            TransactionOrigin::External,
            pooled_from_raw(&kernel, &raw(&unfunded, &kernel, 0, TxKind::Call(sender), Bytes::new())).unwrap()
        )
        .await
        .is_err());
    // Selected transactions are fixed; this later admission must survive mining.
    let retained_raw = raw(&key, &kernel, 2, TxKind::Call(sender), Bytes::new());
    let retained_hash = alloy_primitives::keccak256(&retained_raw);
    pool.add_transaction(
        TransactionOrigin::External,
        pooled_from_raw(&kernel, &retained_raw).unwrap(),
    )
    .await
    .unwrap();
    let executed = execute_next_block(
        &config,
        factory.latest().unwrap().as_ref(),
        funded_block.sealed_header(),
        BlochNextBlockEnvCtx {
            timestamp: 12,
            prevrandao: B256::ZERO,
            anchor_root: B256::repeat_byte(2),
            deposits: vec![DepositMint {
                recipient: Address::repeat_byte(90),
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: 2,
                    l1_tx_index: 0,
                    l1_txid: [2; 32],
                    l1_vout: 0,
                    l1_sats: 1,
                },
            }],
        },
        selected,
    )
    .unwrap();
    let tip = executed.recovered_block().sealed_block().clone();
    let old_chain = chain(&executed);
    let mut events = pool.all_transactions_event_listener();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    provider
        .canonical_in_memory_state()
        .set_canonical_head(tip.clone_sealed_header());
    provider
        .canonical_in_memory_state()
        .set_persisted(alloy_eips::BlockNumHash::new(2, tip.hash()));
    provider
        .canonical_in_memory_state()
        .notify_canon_state(CanonStateNotification::Commit { new: old_chain.clone() });
    // Subscription exists before the future is first polled: the commit must not be lost.
    let maintenance = tokio::spawn(maintenance_future);
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let mut mined = 0;
        while mined < 2 {
            if let FullTransactionEvent::Mined { block_hash, .. } = events.next().await.unwrap() {
                assert_eq!(block_hash, tip.hash());
                mined += 1;
            }
        }
    })
    .await
    .expect("maintenance must consume the commit");
    assert_eq!(pool.block_info().last_seen_block_hash, tip.hash());
    assert_eq!(
        pool.block_info().pending_basefee,
        kernel.next_base_fee(tip.header().0.base_fee_per_gas, tip.header().0.gas_used)
    );
    assert_ne!(
        pool.block_info().pending_basefee,
        kernel.next_base_fee(tip.header().0.base_fee_per_gas, tip.header().0.user_gas_used)
    );
    assert_eq!(pool.all_transaction_hashes(), vec![retained_hash]);
    assert_eq!(
        factory.latest().unwrap().storage(sender.create(0), B256::ZERO).unwrap(),
        Some(U256::from(42))
    );
    assert!(pool
        .add_transaction(TransactionOrigin::External, pooled_from_raw(&kernel, &raws[0]).unwrap())
        .await
        .is_err());
    let writer = factory.database_provider_rw().unwrap();
    writer.remove_block_and_execution_above(1).unwrap();
    writer.commit().unwrap();
    let replacement = execute_next_block(
        &config,
        factory.latest().unwrap().as_ref(),
        funded_block.sealed_header(),
        BlochNextBlockEnvCtx {
            timestamp: 13,
            prevrandao: B256::ZERO,
            anchor_root: B256::repeat_byte(3),
            deposits: vec![],
        },
        vec![],
    )
    .unwrap();
    let new_chain = chain(&replacement);
    let replacement_tip = replacement.recovered_block().sealed_block().clone();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![replacement], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    provider
        .canonical_in_memory_state()
        .set_canonical_head(replacement_tip.clone_sealed_header());
    provider
        .canonical_in_memory_state()
        .set_persisted(alloy_eips::BlockNumHash::new(2, replacement_tip.hash()));
    let mut pending = pool.pending_transactions_listener();
    provider
        .canonical_in_memory_state()
        .notify_canon_state(CanonStateNotification::Reorg {
            old: old_chain,
            new: new_chain,
        });
    let expected = raws
        .iter()
        .map(alloy_primitives::keccak256)
        .collect::<std::collections::BTreeSet<_>>();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let mut observed = std::collections::BTreeSet::new();
        while !expected.is_subset(&observed) {
            observed.insert(pending.recv().await.unwrap());
        }
    })
    .await
    .expect("maintenance must automatically reinsert both old transactions");
    assert_eq!(pool.best_transactions().count(), 3);
    assert!(pool.all_transaction_hashes().contains(&retained_hash));
    assert_eq!(pool.block_info().last_seen_block_hash, replacement_tip.hash());
    assert_eq!(
        factory.latest().unwrap().basic_account(&sender).unwrap().unwrap().nonce,
        0
    );
    assert!(factory
        .latest()
        .unwrap()
        .basic_account(&sender.create(0))
        .unwrap()
        .is_none());
    assert_eq!(
        factory.block_by_number(2).unwrap().unwrap().header.0,
        replacement_tip.header().0
    );
    maintenance.abort();
    assert!(maintenance.await.unwrap_err().is_cancelled());
}
