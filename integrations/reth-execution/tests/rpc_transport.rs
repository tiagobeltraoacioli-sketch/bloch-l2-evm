// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real HTTP requests reach the upstream EthApi over a persisted Bloch genesis.
use alloy_primitives::{B256, U256};
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    build_eth_api, prepare_genesis, start_http_rpc, BlochChainSpec, BlochEvmConfig, BlochNodeTypes, BlochTables,
    BlochTransactionValidator,
};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_chainspec::EthChainSpec;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    DatabaseEnv,
};
use reth_network_api::noop::NoopNetwork;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    providers::{BlockchainProvider, RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    DBProvider, DatabaseProviderFactory, ProviderFactory,
};
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder, CoinbaseTipOrdering, EthPooledTransaction,
    Pool, PoolConfig,
};
use serde_json::Value;
use std::sync::Arc;

type Factory = ProviderFactory<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;
#[tokio::test]
async fn actual_http_queries_v2_genesis_and_releases_listener_on_shutdown() {
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

    let config = BlochEvmConfig::new(&kernel, spec.domain());
    let provider = BlockchainProvider::new(factory.clone()).unwrap();
    let blobs = InMemoryBlobStore::default();
    let validator = EthTransactionValidatorBuilder::new(provider.clone(), config.clone())
        .no_eip4844()
        .no_eip7702()
        .set_block_gas_limit(kernel.gas_limit)
        .build::<EthPooledTransaction, _>(blobs.clone());
    let pool = Pool::new(
        BlochTransactionValidator::new(&kernel, validator),
        CoinbaseTipOrdering::<EthPooledTransaction>::default(),
        blobs,
        PoolConfig::default(),
    );
    let api = build_eth_api(
        RpcNodeCoreAdapter::new(
            provider,
            pool,
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config,
        ),
        reth_tasks::Runtime::test(),
    );
    let handle = start_http_rpc(api.into_rpc().remove_context(), 0).await.unwrap();
    let address = handle.http_local_addr().unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let client = HttpClientBuilder::default()
        .request_timeout(std::time::Duration::from_secs(10))
        .build(handle.http_url().unwrap())
        .unwrap();
    let chain: U256 = client.request("eth_chainId", rpc_params![]).await.unwrap();
    assert_eq!(chain, U256::from(kernel.chain_id));
    let block: Value = client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .unwrap();
    assert_eq!(block["hash"], serde_json::json!(spec.genesis_hash()));
    assert_eq!(block["domain"], serde_json::json!(spec.domain()));
    let flag: B256 = client
        .request("eth_getStorageAt", rpc_params![kernel.block_info, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(flag, B256::from(U256::from(2)));
    handle.stop().unwrap();
    drop(client);
    // The public upstream stop is asynchronous. Observe actual listener release,
    // not merely successful submission of a stop request; no replacement server.
    let listener = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => break listener,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => tokio::task::yield_now().await,
                Err(error) => panic!("cannot verify listener shutdown: {error}"),
            }
        }
    })
    .await
    .expect("HTTP listener must close after stop");
    drop(listener);
}
