// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real ProviderFactory with Bloch types, custom genesis, MDBX and static files.
use alloy_primitives::{B256, U256};
use bloch_l2_evm::{node_execution::genesis_v2, node_primitives::NodeBodyV2, ChainSpec};
use bloch_reth_execution::{BlochChainSpec, BlochNodeBlock, BlochNodeBody, BlochNodeTypes, BlochTables};
use reth_chainspec::{EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition};
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    DatabaseEnv,
};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    BlockReader, BlockWriter, DBProvider, DatabaseProviderFactory, ExecutionOutcome, HashedPostStateProvider,
    ProviderFactory, StateProvider, StateWriteConfig, StateWriter, TrieWriter,
};
use reth_revm::revm::{
    database::{BundleState, OriginalValuesKnown},
    state::{AccountInfo, Bytecode},
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

#[test]
fn configuration_preserves_kernel_genesis_identity_and_fee_rules() {
    let kernel = ChainSpec::testnet();
    let domain = B256::repeat_byte(0x71);
    let spec = BlochChainSpec::new(kernel.clone(), domain, 17).unwrap();
    assert_eq!(spec.chain_id(), kernel.chain_id);
    assert_eq!(spec.domain(), domain);
    assert_eq!(spec.execution(), &kernel);
    assert_eq!(
        spec.genesis_header().0.state_root,
        genesis_v2(&kernel, 17).unwrap().state_root()
    );
    assert_eq!(spec.genesis_hash(), spec.genesis_header().0.hash());
    assert!(spec.genesis().alloc.values().all(|account| account.balance.is_zero()));
    assert!(!spec.is_ethereum());
    assert!(!spec.is_optimism());
    assert!(spec.blob_params_at_timestamp(u64::MAX).is_none());
    assert!(spec.is_cancun_active_at_timestamp(0));
    assert!(!spec.is_prague_active_at_timestamp(u64::MAX));
    assert_eq!(
        spec.ethereum_fork_activation(EthereumHardfork::Dao),
        ForkCondition::Never
    );
    let mut parent = spec.genesis_header().clone();
    for base in [0, 1, kernel.initial_base_fee, u64::MAX] {
        for gas in [0, kernel.gas_target(), kernel.gas_limit] {
            parent.0.base_fee_per_gas = base;
            parent.0.gas_used = gas;
            assert_eq!(
                spec.next_block_base_fee(&parent, 18),
                Some(kernel.next_base_fee(base, gas))
            );
        }
    }
    assert!(BlochChainSpec::new(kernel.clone(), B256::ZERO, 17).is_err());
    let changed = BlochChainSpec::new(kernel.clone(), B256::repeat_byte(0x72), 17).unwrap();
    assert_eq!(
        changed.genesis_header().0.state_root,
        spec.genesis_header().0.state_root
    );
    assert_ne!(changed.genesis_hash(), spec.genesis_hash());
    let mut invalid = kernel;
    invalid.base_fee_denominator = 0;
    assert!(BlochChainSpec::new(invalid, domain, 17).is_err());
}

#[test]
fn complete_provider_persists_and_reopens_custom_genesis_and_its_state() {
    let directory = tempfile::tempdir().unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0x71), 17).unwrap());
    let factory = open(directory.path(), spec.clone());
    let mut builder = BundleState::builder(0..=0);
    // Load exactly the advertised allocation, not a separately constructed kernel state.
    for (address, allocation) in &spec.genesis().alloc {
        let code = Bytecode::new_raw(allocation.code.clone().unwrap_or_default());
        let code_hash = code.hash_slow();
        builder = builder
            .state_address(*address)
            .state_present_account_info(
                *address,
                AccountInfo {
                    balance: allocation.balance,
                    nonce: allocation.nonce.unwrap_or_default(),
                    code_hash,
                    code: Some(code.clone()),
                    ..Default::default()
                },
            )
            .contract(code_hash, code);
        builder.set_state_storage(
            *address,
            allocation
                .storage
                .iter()
                .flatten()
                .map(|(key, value)| (U256::from_be_bytes(key.0), (U256::ZERO, U256::from_be_bytes(value.0))))
                .collect(),
        );
    }
    let bundle = builder.build();
    let hashed = factory.hashed_post_state(&bundle);
    let (root, updates) = factory
        .latest()
        .unwrap()
        .state_root_with_updates(hashed.clone())
        .unwrap();
    assert_eq!(root, spec.genesis_header().0.state_root);
    let block = BlochNodeBlock {
        header: spec.genesis_header().clone(),
        body: BlochNodeBody::try_from_core(NodeBodyV2::default()).unwrap(),
    };
    let recovered = RecoveredBlock::try_recover(block.clone()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.insert_block(&recovered).unwrap();
    writer
        .write_state(
            &ExecutionOutcome::new(bundle, vec![], 0, vec![]),
            OriginalValuesKnown::Yes,
            StateWriteConfig {
                write_receipts: false,
                ..Default::default()
            },
        )
        .unwrap();
    writer.write_hashed_state(&hashed.into_sorted()).unwrap();
    writer.write_trie_updates(updates).unwrap();
    writer.commit().unwrap();
    assert_eq!(factory.block_by_number(0).unwrap(), Some(block.clone()));
    drop(factory);
    let factory = open(directory.path(), spec.clone());
    assert_eq!(factory.block_by_number(0).unwrap(), Some(block));
    let state = factory.latest().unwrap();
    assert_eq!(state.state_root(Default::default()).unwrap(), root);
    for (address, account) in &spec.genesis().alloc {
        let actual = state.basic_account(address).unwrap().unwrap();
        assert_eq!(actual.balance, account.balance);
        assert_eq!(actual.nonce, account.nonce.unwrap_or_default());
        if let Some(code) = account.code.as_ref().filter(|code| !code.is_empty()) {
            let stored = state.bytecode_by_hash(&actual.bytecode_hash.unwrap()).unwrap().unwrap();
            assert_eq!(stored.original_bytes(), *code);
        }
        for (key, value) in account.storage.iter().flatten() {
            assert_eq!(
                state.storage(*address, *key).unwrap().unwrap_or_default(),
                U256::from_be_bytes(value.0)
            );
        }
    }
}
