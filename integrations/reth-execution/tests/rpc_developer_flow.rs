// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed developer workflow over real loopback HTTP and upstream Reth handlers.
//! Funding is synthetic; the canonical coordinator persists blocks and notifies pool maintenance.
//! NoopNetwork is a test fixture; this does not claim an autonomous or P2P node.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{ChainSpec, DepositMint, DepositProvenance};
use bloch_reth_execution::{
    build_eth_api, pool_maintenance, prepare_genesis, start_http_rpc, BlochChainSpec, BlochEvmConfig,
    BlochNextBlockEnvCtx, BlochNodeTypes, BlochTables, BlochTransactionValidator, CanonicalCoordinator,
};
use futures_util::StreamExt;
use jsonrpsee::{
    core::{
        client::{ClientT, Error as ClientError},
        params::ArrayParams,
    },
    http_client::HttpClientBuilder,
};
use k256::ecdsa::SigningKey;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    DatabaseEnv,
};
use reth_network_api::noop::NoopNetwork;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    DBProvider, DatabaseProviderFactory, ProviderFactory,
};
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder, CoinbaseTipOrdering, EthPooledTransaction,
    Pool, PoolConfig, PoolTransaction, TransactionPool,
};
use serde_json::{json, Value};
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

#[tokio::test]
async fn http_signed_deployment_call_receipts_logs_and_state_use_real_reth_handlers() {
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
    let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
    coordinator.extend(coordinator.head().hash(), attrs, vec![]).unwrap();
    let blobs = InMemoryBlobStore::default();
    let provider = coordinator.provider();
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
    let maintenance = tokio::spawn(
        pool_maintenance(
            provider.clone(),
            pool.clone(),
            reth_tasks::Runtime::test(),
            reth_transaction_pool::maintain::MaintainPoolConfig::default(),
        )
        .unwrap(),
    );
    let network = NoopNetwork::default().with_chain_id(kernel.chain_id);
    let api = build_eth_api(
        RpcNodeCoreAdapter::new(provider.clone(), pool.clone(), network, config.clone()),
        reth_tasks::Runtime::test(),
    );
    let server = start_http_rpc(api.into_rpc().remove_context(), 0).await.unwrap();
    let endpoint = server.http_local_addr().unwrap();
    assert!(endpoint.ip().is_loopback());
    let client = HttpClientBuilder::default()
        .request_timeout(std::time::Duration::from_secs(20))
        .build(server.http_url().unwrap())
        .unwrap();
    macro_rules! request {
        ($method:expr, $params:expr) => {{
            let values: Value = $params;
            let mut params = ArrayParams::new();
            for value in values.as_array().expect("test parameters are arrays") {
                params.insert(value).unwrap();
            }
            // Normalize only the client's received result/error for assertions.
            // Every invocation crosses the real HTTP transport to upstream EthApi.
            match client.request::<Value,_>($method, params).await {
                Ok(result) => json!({"result": result}),
                Err(ClientError::Call(error)) => json!({"error": {"code": error.code(), "message": error.message()}}),
                Err(error) => panic!("HTTP RPC transport failed for {}: {error}", $method),
            }
        }};
    }
    assert_eq!(
        request!("eth_chainId", json!([]))["result"],
        format!("0x{:x}", kernel.chain_id)
    );
    assert_eq!(
        request!("eth_getTransactionCount", json!([sender, "latest"]))["result"],
        "0x0"
    );
    // Deploy a runtime that writes calldata into slot zero.
    let runtime = [0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 42, 0x60, 0, 0x60, 0, 0xa1, 0];
    let mut init = vec![
        0x60,
        runtime.len() as u8,
        0x60,
        12,
        0x60,
        0,
        0x39,
        0x60,
        runtime.len() as u8,
        0x60,
        0,
        0xf3,
    ];
    init.extend(runtime);
    let deploy = raw(&key, &kernel, 0, TxKind::Create, init.into());
    let send = request!("eth_sendRawTransaction", json!([deploy]));
    assert!(send.get("error").is_none(), "{send}");
    let deploy_hash: B256 = serde_json::from_value(send["result"].clone()).unwrap();
    let call = raw(
        &key,
        &kernel,
        1,
        TxKind::Call(sender.create(0)),
        U256::from(42).to_be_bytes::<32>().into(),
    );
    let send = request!("eth_sendRawTransaction", json!([call]));
    assert!(send.get("error").is_none(), "{send}");
    let call_hash: B256 = serde_json::from_value(send["result"].clone()).unwrap();
    assert!(request!("eth_sendRawTransaction", json!(["0x02deadbeef"]))
        .get("error")
        .is_some());
    let mut wrong_chain = kernel.clone();
    wrong_chain.chain_id += 1;
    let wrong = raw(&key, &wrong_chain, 2, TxKind::Call(sender), Bytes::new());
    assert!(request!("eth_sendRawTransaction", json!([wrong]))
        .get("error")
        .is_some());
    let pending = request!("eth_getBlockByNumber", json!(["pending", false]));
    assert!(pending.get("error").is_some(), "{pending}");
    let parent = provider.canonical_in_memory_state().get_canonical_head();
    let selected: Vec<_> = pool
        .best_transactions()
        .map(|tx| tx.transaction.clone_into_consensus().into_inner())
        .collect();
    assert_eq!(selected.len(), 2);
    let mut events = pool.all_transactions_event_listener();
    let block = coordinator
        .extend(
            parent.hash(),
            BlochNextBlockEnvCtx {
                timestamp: 12,
                prevrandao: B256::ZERO,
                anchor_root: B256::repeat_byte(2),
                deposits: vec![DepositMint {
                    recipient: Address::repeat_byte(99),
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 2,
                        l1_tx_index: 1,
                        l1_txid: [2; 32],
                        l1_vout: 0,
                        l1_sats: 90,
                    },
                }],
            },
            selected,
        )
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let mut mined = std::collections::BTreeSet::new();
        while mined.len() < 2 {
            if let reth_transaction_pool::FullTransactionEvent::Mined { tx_hash, block_hash } =
                events.next().await.unwrap()
            {
                assert_eq!(block_hash, block.hash());
                assert!([deploy_hash, call_hash].contains(&tx_hash));
                mined.insert(tx_hash);
            }
        }
    })
    .await
    .expect("canonical notification must remove both mined pool transactions");
    assert!(pool.best_transactions().next().is_none());
    let receipt = request!("eth_getTransactionReceipt", json!([deploy_hash]));
    assert!(receipt.get("error").is_none(), "{receipt}");
    assert_eq!(receipt["result"]["blockHash"], json!(block.hash()));
    assert_eq!(receipt["result"]["contractAddress"], json!(sender.create(0)));
    assert_eq!(receipt["result"]["status"], "0x1");
    let receipt = request!("eth_getTransactionReceipt", json!([call_hash]));
    assert_eq!(receipt["result"]["blockHash"], json!(block.hash()));
    assert_eq!(receipt["result"]["transactionIndex"], "0x1");
    assert_eq!(
        receipt["result"]["cumulativeGasUsed"],
        format!("0x{:x}", block.header().0.user_gas_used)
    );
    assert!(block.header().0.gas_used > block.header().0.user_gas_used);
    assert_eq!(receipt["result"]["logs"][0]["blockHash"], json!(block.hash()));
    assert_eq!(receipt["result"]["logs"][0]["transactionHash"], json!(call_hash));
    assert_eq!(receipt["result"]["logs"][0]["logIndex"], "0x0");
    assert_eq!(
        receipt["result"]["logs"][0]["topics"][0],
        json!(B256::from(U256::from(42)))
    );
    let balance = factory
        .latest()
        .unwrap()
        .basic_account(&sender)
        .unwrap()
        .unwrap()
        .balance;
    assert_eq!(
        request!("eth_getBalance", json!([sender, "latest"]))["result"],
        json!(balance)
    );
    assert_eq!(
        request!("eth_getTransactionCount", json!([sender, "latest"]))["result"],
        "0x2"
    );
    assert_eq!(
        request!("eth_getCode", json!([sender.create(0), "latest"]))["result"],
        json!(Bytes::copy_from_slice(&runtime))
    );
    assert_eq!(
        request!("eth_getStorageAt", json!([sender.create(0), "0x0", "latest"]))["result"],
        json!(B256::from(U256::from(42)))
    );
    let response = request!("eth_getBlockByNumber", json!(["0x2", true]));
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["hash"], json!(block.hash()));
    assert_eq!(response["result"]["domain"], json!(spec.domain()));
    assert_eq!(
        response["result"]["depositsHash"],
        json!(block.header().0.deposits_hash)
    );
    assert_eq!(
        response["result"]["gasUsed"],
        format!("0x{:x}", block.header().0.gas_used)
    );
    assert_eq!(response["result"]["transactions"][0]["hash"], json!(deploy_hash));
    assert_eq!(response["result"]["transactions"][1]["hash"], json!(call_hash));
    assert_eq!(
        request!("eth_getRawTransactionByBlockHashAndIndex", json!([block.hash(), "0x0"]))["result"],
        json!(deploy)
    );
    assert_eq!(
        request!("eth_getRawTransactionByBlockHashAndIndex", json!([block.hash(), "0x1"]))["result"],
        json!(call)
    );
    maintenance.abort();
    assert!(maintenance.await.unwrap_err().is_cancelled());
    server.stop().unwrap();
    drop(client);
    let released = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match tokio::net::TcpListener::bind(endpoint).await {
                Ok(listener) => break listener,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => tokio::task::yield_now().await,
                Err(error) => panic!("cannot verify HTTP shutdown: {error}"),
            }
        }
    })
    .await
    .expect("HTTP listener should stop");
    drop(released);
}
