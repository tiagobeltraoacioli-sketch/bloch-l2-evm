// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual full persistence and canonical unwind of executed V2 blocks.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    node_execution::{execute_node_block, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    execute_next_block, BlochChainSpec, BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeBlock, BlochNodeBody,
    BlochNodeHeader, BlochNodeTypes, BlochRethTransaction, BlochTables,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    transaction::DbTx,
    DatabaseEnv,
};
use reth_evm::ConfigureEvm;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::{BlockBody, SealedHeader};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockExecutionWriter, BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
    ReceiptProvider, StateProvider, TransactionsProvider,
};
use std::{path::Path, sync::Arc};

type Factory = ProviderFactory<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;
fn open(directory: &Path, spec: Arc<BlochChainSpec>) -> Factory {
    ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(directory.join("db"), DatabaseArguments::test()).unwrap()),
        spec,
        StaticFileProvider::read_write(directory.join("static_files")).unwrap(),
        RocksDBBuilder::new(directory.join("rocksdb"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap()
}

fn seed_genesis(factory: &Factory, spec: &BlochChainSpec) {
    let executed = {
        let snapshot = factory.latest().unwrap();
        bloch_reth_execution::prepare_genesis(spec, snapshot.as_ref()).unwrap()
    };
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn signed(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes) -> BlochRethTransaction {
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
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    tx.into_signed(signature).into()
}
fn deposit(index: u32) -> DepositMint {
    DepositMint {
        recipient: sender(),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: index,
            l1_txid: [index as u8 + 1; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    }
}
#[test]
fn full_saved_v2_execution_unwinds_and_reopens_to_exact_previous_state() {
    let directory = tempfile::tempdir().unwrap();
    let kernel = ChainSpec::testnet();
    let domain = B256::repeat_byte(0x71);
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), domain, 17).unwrap());
    let factory = open(directory.path(), spec.clone());
    seed_genesis(&factory, &spec);
    let config = BlochEvmConfig::new(&kernel, domain);
    let mut reference = genesis_v2(&kernel, 17).unwrap();
    let runtime = [
        0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 42, 0x60, 0, 0x60, 0, 0xa1, 0x60, 1, 0x43, 0x03, 0x40, 0x60, 0, 0x52, 0x60,
        32, 0x60, 0, 0xf3,
    ];
    let len = runtime.len() as u8;
    let mut init = vec![0x60, len, 0x60, 12, 0x60, 0, 0x39, 0x60, len, 0x60, 0, 0xf3];
    init.extend(runtime);
    let blocks = [
        vec![signed(&kernel, 0, TxKind::Create, init.into())],
        vec![
            signed(
                &kernel,
                1,
                TxKind::Call(sender().create(0)),
                U256::from(42).to_be_bytes::<32>().to_vec().into(),
            ),
            signed(
                &kernel,
                2,
                TxKind::Create,
                Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]),
            ),
        ],
    ];
    let mut expected_blocks = Vec::new();
    let mut expected_receipts = Vec::new();
    let mut first_state = None;
    for (index, transactions) in blocks.into_iter().enumerate() {
        let parent = SealedHeader::seal_slow(BlochNodeHeader(node_head(&kernel, domain, &reference).unwrap()));
        let attributes = BlochNextBlockEnvCtx {
            timestamp: 18 + index as u64,
            prevrandao: B256::repeat_byte(3),
            anchor_root: B256::repeat_byte(index as u8 + 4),
            deposits: vec![deposit(index as u32)],
        };
        let context = config.context_for_next_block(&parent, attributes.clone()).unwrap();
        let body = NodeBodyV2 {
            deposits: attributes.deposits.clone(),
            transactions: transactions.iter().map(|tx| tx.encoded_2718().into()).collect(),
        };
        let executed = {
            let snapshot = factory.latest().unwrap();
            execute_next_block(&config, snapshot.as_ref(), &parent, attributes, transactions).unwrap()
        };
        let expected = execute_node_block(&kernel, domain, &mut reference, &context.context, &body).unwrap();
        assert_eq!(executed.recovered_block().header().0, expected.header);
        let receipts: Vec<alloy_consensus::ReceiptEnvelope> = executed
            .execution_output
            .result
            .receipts
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        assert_eq!(receipts, expected.receipts);
        if index == 1 {
            assert!(!expected.transactions[1].success);
            assert_ne!(expected.header.logs_bloom, alloy_primitives::Bloom::ZERO);
            assert_eq!(
                expected.transactions[0].result.output().unwrap().as_ref(),
                parent.hash().as_slice()
            );
        }
        expected_blocks.push(BlochNodeBlock {
            header: BlochNodeHeader(expected.header.clone()),
            body: BlochNodeBody::try_from_core(body).unwrap(),
        });
        expected_receipts.push(executed.execution_output.result.receipts.clone());
        let writer = factory.database_provider_rw().unwrap();
        writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
        writer.commit().unwrap();
        assert_eq!(
            factory.latest().unwrap().state_root(Default::default()).unwrap(),
            expected.header.state_root
        );
        if index == 0 {
            first_state = Some(reference.clone());
        }
    }
    drop(factory);
    let factory = open(directory.path(), spec.clone());
    assert_eq!(factory.block_by_number(2).unwrap(), Some(expected_blocks[1].clone()));
    assert_eq!(
        factory.receipts_by_block(2.into()).unwrap(),
        Some(expected_receipts[1].clone())
    );
    {
        let snapshot = factory.latest().unwrap();
        assert_eq!(snapshot.state_root(Default::default()).unwrap(), reference.state_root());
        assert_eq!(
            snapshot.storage(sender().create(0), B256::ZERO).unwrap(),
            Some(U256::from(42))
        );
        assert_eq!(snapshot.basic_account(&sender()).unwrap().unwrap().nonce, 3);
    }
    // The upstream canonical operation unwinds trie/state/history/receipts/body/header indices together.
    let writer = factory.database_provider_rw().unwrap();
    writer.remove_block_and_execution_above(1).unwrap();
    writer.commit().unwrap();
    drop(factory);
    let factory = open(directory.path(), spec);
    assert!(factory.block_by_number(2).unwrap().is_none());
    assert!(factory
        .block_by_hash(expected_blocks[1].header.0.hash())
        .unwrap()
        .is_none());
    assert!(factory.header(expected_blocks[1].header.0.hash()).unwrap().is_none());
    assert_eq!(
        factory.block_by_hash(expected_blocks[0].header.0.hash()).unwrap(),
        Some(expected_blocks[0].clone())
    );
    for transaction in expected_blocks[1].body.transactions() {
        assert!(factory.transaction_by_hash(*transaction.tx_hash()).unwrap().is_none());
    }
    for transaction in expected_blocks[0].body.transactions() {
        assert_eq!(
            factory.transaction_by_hash(*transaction.tx_hash()).unwrap(),
            Some(transaction.clone())
        );
    }
    assert!(factory.receipts_by_block(2.into()).unwrap().is_none());
    assert_eq!(factory.block_by_number(1).unwrap(), Some(expected_blocks[0].clone()));
    assert_eq!(
        factory.receipts_by_block(1.into()).unwrap(),
        Some(expected_receipts[0].clone())
    );
    let before = first_state.unwrap();
    let snapshot = factory.latest().unwrap();
    assert_eq!(snapshot.state_root(Default::default()).unwrap(), before.state_root());
    assert_eq!(snapshot.basic_account(&sender()).unwrap().unwrap().nonce, 1);
    assert_eq!(
        snapshot.basic_account(&sender()).unwrap().unwrap().balance,
        before.balance_of(&sender())
    );
    assert_eq!(
        snapshot
            .storage(sender().create(0), B256::ZERO)
            .unwrap()
            .unwrap_or_default(),
        U256::ZERO
    );
    let contract = snapshot.basic_account(&sender().create(0)).unwrap().unwrap();
    assert_eq!(
        snapshot
            .bytecode_by_hash(&contract.bytecode_hash.unwrap())
            .unwrap()
            .unwrap()
            .original_bytes()
            .as_ref(),
        &runtime
    );
    let head = bloch_l2_evm::node_execution::node_head_on_database(
        &kernel,
        domain,
        reth_revm::database::StateProviderDatabase::new(snapshot.as_ref()),
        before.state_root(),
    )
    .unwrap();
    assert_eq!(head, expected_blocks[0].header.0);
    let reader = factory.database_provider_ro().unwrap();
    assert!(reader
        .tx_ref()
        .get::<bloch_reth_execution::BlochV2Deposits>(2)
        .unwrap()
        .is_none());
    assert_eq!(
        reader
            .tx_ref()
            .get::<bloch_reth_execution::BlochV2Deposits>(1)
            .unwrap()
            .unwrap()
            .deposits(),
        &[deposit(0)]
    );
}

#[test]
fn execution_rejects_wrong_snapshot_and_late_nonce_without_provider_writes() {
    let directory = tempfile::tempdir().unwrap();
    let kernel = ChainSpec::testnet();
    let domain = B256::repeat_byte(0x71);
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), domain, 17).unwrap());
    let factory = open(directory.path(), spec.clone());
    seed_genesis(&factory, &spec);
    let config = BlochEvmConfig::new(&kernel, domain);
    let attributes = BlochNextBlockEnvCtx {
        timestamp: 18,
        prevrandao: B256::ZERO,
        anchor_root: B256::repeat_byte(4),
        deposits: vec![deposit(0)],
    };
    let parent = SealedHeader::seal_slow(spec.genesis_header().clone());
    let mut wrong = spec.genesis_header().clone();
    wrong.0.state_root = B256::repeat_byte(88);
    {
        let snapshot = factory.latest().unwrap();
        assert!(execute_next_block(
            &config,
            snapshot.as_ref(),
            &SealedHeader::new(spec.genesis_header().clone(), B256::repeat_byte(99)),
            attributes.clone(),
            vec![]
        )
        .is_err());
        assert!(execute_next_block(
            &config,
            snapshot.as_ref(),
            &SealedHeader::seal_slow(wrong),
            attributes.clone(),
            vec![]
        )
        .is_err());
        let transactions = vec![
            signed(&kernel, 0, TxKind::Call(Address::repeat_byte(22)), Bytes::new()),
            signed(&kernel, 9, TxKind::Call(Address::repeat_byte(22)), Bytes::new()),
        ];
        assert!(execute_next_block(&config, snapshot.as_ref(), &parent, attributes, transactions).is_err());
        assert_eq!(snapshot.state_root(Default::default()).unwrap(), parent.0.state_root);
        assert!(snapshot.basic_account(&sender()).unwrap().is_none());
        assert_eq!(
            snapshot
                .basic_account(&sender())
                .unwrap()
                .map(|account| account.nonce)
                .unwrap_or_default(),
            0
        );
        assert!(bloch_reth_execution::prepare_genesis(&spec, snapshot.as_ref()).is_err());
        assert!(snapshot.basic_account(&Address::repeat_byte(22)).unwrap().is_none());
    }
    drop(factory);
    let factory = open(directory.path(), spec);
    assert_eq!(
        factory.latest().unwrap().state_root(Default::default()).unwrap(),
        parent.0.state_root
    );
    assert!(factory.block_by_number(1).unwrap().is_none());
}
