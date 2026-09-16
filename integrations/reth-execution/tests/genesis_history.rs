// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genesis allocation history survives full persistence, reopen and canonical unwind.
use alloy_primitives::{B256, KECCAK256_EMPTY, U256};
use bloch_l2_evm::{
    node_execution::{execute_node_block, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    ChainSpec, L2State,
};
use bloch_reth_execution::{
    execute_next_block, prepare_genesis, BlochChainSpec, BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeHeader,
    BlochNodeTypes, BlochTables,
};
use reth_chainspec::EthChainSpec;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    DatabaseEnv,
};
use reth_evm::ConfigureEvm;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockExecutionWriter, DBProvider, DatabaseProviderFactory, ProviderFactory, StateProvider,
};
use std::{collections::BTreeSet, path::Path, sync::Arc};

type Factory = ProviderFactory<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;
fn open(path: &Path, spec: Arc<BlochChainSpec>) -> Factory {
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

fn assert_allocation_history(provider: &dyn StateProvider, spec: &BlochChainSpec, expected: &L2State) {
    assert_eq!(provider.state_root(Default::default()).unwrap(), expected.state_root());
    for (address, allocation) in &spec.genesis().alloc {
        let account = provider
            .basic_account(address)
            .unwrap()
            .expect("genesis account must exist historically");
        let reference = expected.account(address).unwrap();
        assert_eq!(account.nonce, reference.nonce, "nonce {address}");
        assert_eq!(account.balance, reference.balance, "balance {address}");
        assert_eq!(
            account.bytecode_hash.unwrap_or(KECCAK256_EMPTY),
            reference.code_hash,
            "code hash {address}"
        );
        if let Some(code) = &allocation.code {
            if !code.is_empty() {
                assert_eq!(
                    provider
                        .bytecode_by_hash(&reference.code_hash)
                        .unwrap()
                        .unwrap()
                        .original_bytes(),
                    *code,
                    "genesis bytecode {address}"
                );
            }
        }
        let reference_account = &expected.db().cache.accounts[address];
        let mut slots: BTreeSet<U256> = allocation
            .storage
            .as_ref()
            .into_iter()
            .flat_map(|slots| slots.keys().map(|slot| U256::from_be_bytes(slot.0)))
            .collect();
        slots.extend(reference_account.storage.keys().copied());
        slots.insert(U256::MAX); // Absent slots remain zero; no blanket genesis fill.
        for slot in slots {
            let value = reference_account.storage.get(&slot).copied().unwrap_or_default();
            assert_eq!(
                provider
                    .storage(*address, B256::from(slot))
                    .unwrap()
                    .unwrap_or_default(),
                value,
                "storage {address}[{slot}]"
            );
        }
    }
}
fn assert_views(factory: &Factory, spec: &BlochChainSpec, states: &[L2State], hashes: &[B256]) {
    for (state, hash) in states.iter().zip(hashes) {
        let historic = factory.history_by_block_hash(*hash).unwrap();
        assert_allocation_history(historic.as_ref(), spec, state);
    }
    assert_allocation_history(factory.latest().unwrap().as_ref(), spec, states.last().unwrap());
}

#[test]
fn every_genesis_account_slot_and_code_survives_historical_queries_reopen_and_unwind() {
    let directory = tempfile::tempdir().unwrap();
    let kernel = ChainSpec::testnet();
    let domain = B256::repeat_byte(0x75);
    let spec = Arc::new(BlochChainSpec::new(kernel.clone(), domain, 17).unwrap());
    let factory = open(directory.path(), spec.clone());
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut reference = genesis_v2(&kernel, 17).unwrap();
    let mut states = vec![reference.clone()];
    let mut hashes = vec![spec.genesis_hash()];
    let config = BlochEvmConfig::new(&kernel, domain);
    for number in 1..=2 {
        let parent = SealedHeader::seal_slow(BlochNodeHeader(node_head(&kernel, domain, &reference).unwrap()));
        let attrs = BlochNextBlockEnvCtx {
            timestamp: 17 + number,
            prevrandao: B256::repeat_byte(number as u8),
            anchor_root: B256::repeat_byte(number as u8 + 10),
            deposits: vec![],
        };
        let context = config.context_for_next_block(&parent, attrs.clone()).unwrap();
        let expected = execute_node_block(
            &kernel,
            domain,
            &mut reference,
            &context.context,
            &NodeBodyV2::default(),
        )
        .unwrap();
        let executed = execute_next_block(&config, factory.latest().unwrap().as_ref(), &parent, attrs, vec![]).unwrap();
        assert_eq!(executed.recovered_block().header().0, expected.header);
        hashes.push(expected.header.hash());
        states.push(reference.clone());
        let writer = factory.database_provider_rw().unwrap();
        writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
        writer.commit().unwrap();
    }
    assert_views(&factory, &spec, &states, &hashes);
    drop(factory);
    let factory = open(directory.path(), spec.clone());
    assert_views(&factory, &spec, &states, &hashes);
    for target in [1usize, 0] {
        let writer = factory.database_provider_rw().unwrap();
        writer.remove_block_and_execution_above(target as u64).unwrap();
        writer.commit().unwrap();
        assert_views(&factory, &spec, &states[..=target], &hashes[..=target]);
    }
    drop(factory);
    let factory = open(directory.path(), spec.clone());
    assert_views(&factory, &spec, &states[..1], &hashes[..1]);
}
