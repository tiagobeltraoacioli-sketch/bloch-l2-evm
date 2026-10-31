// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real HTTP requests reach the upstream EthApi over a persisted Bloch genesis.
use alloy_primitives::{B256, U256};
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    build_eth_api, chain_identity_rpc, chain_status_rpc, prepare_genesis, start_http_rpc, BlochChainIdentity,
    BlochChainSpec, BlochChainStatus, BlochEvmConfig, BlochNodeTypes, BlochTables, BlochTransactionValidator,
    CHAIN_IDENTITY_FORMAT, CHAIN_STATUS_FORMAT, HEADER_FORMAT, RPC_MAX_BATCH_CALLS, RPC_MAX_REQUEST_BYTES,
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            provider.clone(),
            pool,
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config,
        ),
        reth_tasks::Runtime::test(),
    );
    let mut module = api.into_rpc().remove_context();
    module.merge(chain_identity_rpc(spec.clone())).unwrap();
    module.merge(chain_status_rpc(spec.clone(), provider)).unwrap();
    let handle = start_http_rpc(module, 0).await.unwrap();
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
    let identity: BlochChainIdentity = client.request("bloch_chainIdentity", rpc_params![]).await.unwrap();
    assert_eq!(identity.format, CHAIN_IDENTITY_FORMAT);
    assert_eq!(identity.chain_id, format!("0x{:x}", kernel.chain_id));
    assert_eq!(identity.domain, spec.domain());
    assert_eq!(identity.genesis_hash, spec.genesis_hash());
    assert_eq!(identity.header_format, HEADER_FORMAT);
    assert!(client
        .request::<BlochChainIdentity, _>("bloch_chainIdentity", rpc_params!["unexpected"])
        .await
        .is_err());
    let challenge = B256::repeat_byte(0xa5);
    let status: BlochChainStatus = client
        .request("bloch_chainStatus", rpc_params![challenge])
        .await
        .unwrap();
    assert_eq!(status.format, CHAIN_STATUS_FORMAT);
    assert_eq!(status.challenge, challenge);
    assert_eq!(status.identity, identity);
    assert_eq!(status.head_number, "0x0");
    assert_eq!(status.head_hash, spec.genesis_hash());
    assert_eq!(status.state_root, spec.genesis_header().0.state_root);
    assert!(client
        .request::<BlochChainStatus, _>("bloch_chainStatus", rpc_params![B256::ZERO])
        .await
        .is_err());
    assert!(client
        .request::<BlochChainStatus, _>("bloch_chainStatus", rpc_params![])
        .await
        .is_err());
    let flag: B256 = client
        .request("eth_getStorageAt", rpc_params![kernel.block_info, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(flag, B256::from(U256::from(2)));

    // Transport preflight must reject a body over the explicit budget before
    // the RPC method receives or deserializes its attacker-sized parameter.
    let oversized_body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["{}"]}}"#,
        "x".repeat(RPC_MAX_REQUEST_BYTES as usize)
    );
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        oversized_body.len(),
        oversized_body
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            // macOS may reset a connection after rejecting an unread request
            // body. Keep the already received HTTP error for the assertion.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("failed to read oversized RPC response: {error}"),
        }
    }
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "oversized RPC response: {response}"
    );
    // A batch carries at most RPC_MAX_BATCH_CALLS calls: one HTTP request must
    // not become thousands of calls behind a per-request gateway rate limit.
    let batch = |calls: u32| async move {
        let body = format!(
            "[{}]",
            (0..calls).map(|i| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_chainId","params":[]}}"#)).collect::<Vec<_>>().join(",")
        );
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response).to_string();
        let json = response.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        serde_json::from_str::<Value>(&json).unwrap_or(Value::Null)
    };
    let within = batch(RPC_MAX_BATCH_CALLS).await;
    assert_eq!(within.as_array().map(Vec::len), Some(RPC_MAX_BATCH_CALLS as usize), "{within}");
    let over = batch(RPC_MAX_BATCH_CALLS + 1).await;
    assert!(over["error"]["message"].as_str().is_some_and(|m| m.contains("atch")), "over the batch limit: {over}");
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
