// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real RPC BLOCKHASH context and explicit override regression; no genesis mutation.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{ChainSpec, DepositMint, DepositProvenance};
use bloch_reth_execution::{
    build_eth_api, execute_next_block, pooled_from_raw, prepare_genesis, BlochChainSpec, BlochEvmConfig,
    BlochNextBlockEnvCtx, BlochNodeTypes, BlochTables, BlochTransactionValidator,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    DatabaseEnv,
};
use reth_network_api::noop::NoopNetwork;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    providers::{BlockchainProvider, RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    DBProvider, DatabaseProviderFactory, ProviderFactory,
};
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder, CoinbaseTipOrdering, EthPooledTransaction,
    Pool, PoolConfig, PoolTransaction,
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
async fn rpc_blockhash_matches_selected_header_and_honors_explicit_overrides() {
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
    let network = NoopNetwork::default().with_chain_id(kernel.chain_id);
    let api = build_eth_api(
        RpcNodeCoreAdapter::new(provider.clone(), pool.clone(), network, config.clone()),
        reth_tasks::Runtime::test(),
    );
    let rpc = api.into_rpc();
    macro_rules! request {
        ($method:expr, $params:expr) => {{
            let input = json!({"jsonrpc":"2.0","id":1,"method":$method,"params":$params}).to_string();
            let (output, _) = tokio::time::timeout(std::time::Duration::from_secs(20), rpc.raw_json_request(&input, 1)).await.unwrap().unwrap();
            serde_json::from_str::<Value>(output.get()).unwrap()
        }};
    }
    let funded_header = provider.canonical_in_memory_state().get_canonical_head();
    let block_one_hash = funded_header.hash();
    // Runtime returns BLOCKHASH(calldata[0]) only when equal to calldata[32];
    // otherwise it reverts. Thus estimateGas also verifies the observed hash.
    // It writes that hash to slot 7: RPC calls must not persist these writes.
    let runtime = [
        0x60, 0, 0x35, 0x40, 0x80, 0x60, 7, 0x55, 0x80, 0x60, 0, 0x52, 0x60, 32, 0x35, 0x14, 0x60, 24, 0x57, 0x60, 0,
        0x60, 0, 0xfd, 0x5b, 0x60, 32, 0x60, 0, 0xf3,
    ];
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
    let contract = sender.create(0);
    let calldata = |number: u64, expected: B256| {
        let mut input = U256::from(number).to_be_bytes::<32>().to_vec();
        input.extend(expected.as_slice());
        Bytes::from(input)
    };
    let transactions = [
        raw(&key, &kernel, 0, TxKind::Create, init.into()),
        raw(&key, &kernel, 1, TxKind::Call(contract), calldata(1, block_one_hash)),
    ]
    .iter()
    .map(|raw| {
        pooled_from_raw(&kernel, raw)
            .unwrap()
            .clone_into_consensus()
            .into_inner()
    })
    .collect();
    let executed = execute_next_block(
        &config,
        factory.latest().unwrap().as_ref(),
        &funded_header,
        BlochNextBlockEnvCtx {
            timestamp: 12,
            prevrandao: B256::ZERO,
            anchor_root: B256::repeat_byte(2),
            deposits: vec![],
        },
        transactions,
    )
    .unwrap();
    // The actual signed call succeeds under the canonical kernel snapshot.
    assert!(executed
        .execution_outcome()
        .result
        .receipts
        .iter()
        .all(alloy_consensus::TxReceipt::status));
    let block_two = executed.recovered_block().sealed_block().clone();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let executed = execute_next_block(
        &config,
        factory.latest().unwrap().as_ref(),
        block_two.sealed_header(),
        BlochNextBlockEnvCtx {
            timestamp: 13,
            prevrandao: B256::ZERO,
            anchor_root: B256::repeat_byte(3),
            deposits: vec![],
        },
        vec![],
    )
    .unwrap();
    let block_three = executed.recovered_block().sealed_block().clone();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![executed], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    provider
        .canonical_in_memory_state()
        .set_canonical_head(block_three.clone_sealed_header());
    provider
        .canonical_in_memory_state()
        .set_persisted(BlockNumHash::new(3, block_three.hash()));
    let call = |number, expected| json!({"from":sender,"to":contract,"input":calldata(number,expected)});
    let historical = json!({"blockHash":block_two.hash(),"requireCanonical":true});
    // Genesis accounts/unchanged slots must remain visible historically; otherwise
    // an RPC BLOCKHASH adapter would conceal a broken state-provider history.
    let historic = factory.history_by_block_hash(block_two.hash()).unwrap();
    assert_eq!(
        historic.basic_account(&kernel.block_info).unwrap(),
        factory.latest().unwrap().basic_account(&kernel.block_info).unwrap()
    );
    assert_eq!(
        historic.storage(kernel.block_info, B256::ZERO).unwrap(),
        Some(U256::from(2))
    );
    for (at, number, expected) in [
        (json!("latest"), 1, block_one_hash),
        (json!("latest"), 2, block_two.hash()),
        (historical.clone(), 1, block_one_hash),
        (historical.clone(), 2, B256::ZERO),
    ] {
        let response = request!("eth_call", json!([call(number, expected), at]));
        assert_eq!(
            response["result"],
            json!(expected),
            "at={at} number={number}: {response}"
        );
        let estimate = request!("eth_estimateGas", json!([call(number, expected), at]));
        let gas: U256 =
            serde_json::from_value(estimate["result"].clone()).expect("matching BLOCKHASH estimate must succeed");
        assert!(gas >= U256::from(21_000));
    }
    let fake = B256::repeat_byte(0x99);
    // Explicit context overrides cannot extend the opcode's 256-block window.
    let boundary = json!({"number":"0x12c", "blockHash":{"43":fake,"44":fake}});
    for (number, expected) in [(43, B256::ZERO), (44, fake)] {
        let response = request!("eth_call", json!([call(number, expected), "latest", null, boundary]));
        assert_eq!(response["result"], json!(expected), "{response}");
    }
    let overrides = json!({"blockHash":{"1":fake,"3":fake,"4":fake}});
    for number in [3, 4] {
        let response = request!("eth_call", json!([call(number, B256::ZERO), "latest", null, overrides]));
        assert_eq!(
            response["result"],
            json!(B256::ZERO),
            "current/future bounds must precede overrides: {response}"
        );
    }
    // This is the advertised upstream block-context override, not modified
    // canonical state. Both real RPC entry points must honor it.
    let override_call = request!("eth_call", json!([call(1, fake), "latest", null, overrides]));
    let override_estimate = request!("eth_estimateGas", json!([call(1, fake), "latest", null, overrides]));
    let historical_override = request!("eth_call", json!([call(1, fake), historical, null, overrides]));
    // Conversely a state override changes storage, not selected-block ancestry.
    let ring_slot = B256::from(bloch_l2_evm::state::block_hash_slot(1));
    let ring_override = json!({kernel.block_info.to_string(): {"stateDiff":{ring_slot.to_string():fake,B256::ZERO.to_string():B256::ZERO}}});
    let state_override_call = request!("eth_call", json!([call(1, block_one_hash), "latest", ring_override]));
    // Access-list construction exercises Reth's inspector-enabled EVM hook.
    let access_list = request!(
        "eth_createAccessList",
        json!([call(1, block_one_hash), "latest", ring_override])
    );
    assert!(access_list.get("error").is_none(), "{access_list}");
    assert!(access_list["result"]["error"].is_null(), "{access_list}");
    assert!(access_list["result"]["accessList"].is_array(), "{access_list}");
    assert_eq!(
        factory.latest().unwrap().storage(kernel.block_info, ring_slot).unwrap(),
        Some(U256::from_be_bytes(block_one_hash.0))
    );
    assert_eq!(
        factory
            .latest()
            .unwrap()
            .storage(contract, B256::from(U256::from(7)))
            .unwrap(),
        Some(U256::from_be_bytes(block_one_hash.0)),
        "RPC writes must remain transient"
    );
    assert_eq!(
        factory.latest().unwrap().basic_account(&sender).unwrap().unwrap().nonce,
        2
    );
    assert_eq!(
        override_call["result"],
        json!(fake),
        "explicit BLOCKHASH override ignored: {override_call}; estimate: {override_estimate}"
    );
    assert!(override_estimate.get("error").is_none(), "{override_estimate}");
    assert_eq!(historical_override["result"], json!(fake), "{historical_override}");
    assert_eq!(
        state_override_call["result"],
        json!(block_one_hash),
        "ring state override must not replace context: {state_override_call}"
    );
}
