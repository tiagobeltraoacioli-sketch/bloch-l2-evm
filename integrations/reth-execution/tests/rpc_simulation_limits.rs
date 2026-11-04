// SPDX-License-Identifier: MIT OR Apache-2.0
//! The simulation gas cap holds on every gas path of `eth_call`, `eth_estimateGas` and
//! `eth_createAccessList` (explicit gas, caller allowance, block override of the gas limit), and
//! repeated EVM runs stop at the simulation time budget (reth snapshot patch, RETH-SNAPSHOT.md).
use alloy_primitives::B256;
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    build_eth_api, prepare_genesis, BlochChainSpec, BlochEvmConfig, BlochNodeTypes, BlochTables, PendingPolicy,
};
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
use reth_rpc_eth_api::{helpers::call::set_simulation_time_limit, node::RpcNodeCoreAdapter, EthApiServer};
use reth_transaction_pool::noop::NoopTransactionPool;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

#[path = "../src/bin/settled_rpc/capped_api.rs"]
mod capped_api;
use capped_api::build_eth_api_capped;

type Factory = ProviderFactory<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;

const CAP: u64 = 15_000_000;
/// Reverts unless GAS (at its first instruction) is at least 20,000,000:
/// GAS PUSH4 20M GT PUSH1 0x0b JUMPI STOP JUMPDEST PUSH1 0 PUSH1 0 REVERT.
const NEEDS_20M: &str = "0x5a6301312d0011600b57005b60006000fd";
/// Counts 200,000 down (26 gas a turn, about 5.2M gas), then stops:
/// PUSH3 200000 JUMPDEST PUSH1 1 SWAP1 SUB DUP1 PUSH1 4 JUMPI STOP.
const BURNS_5M: &str = "0x62030d405b600190038060045700";
const TARGET: &str = "0x00000000000000000000000000000000000c0de1";
const RICH: &str = "0x00000000000000000000000000000000000a11ce";

fn overrides(code: &str) -> Value {
    let mut accounts = serde_json::Map::new();
    accounts.insert(TARGET.to_string(), json!({ "code": code }));
    accounts.insert(
        RICH.to_string(),
        json!({ "balance": "0xffffffffffffffffffffffffffffffff" }),
    );
    Value::Object(accounts)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulations_stay_within_the_gas_cap_and_the_time_budget() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = ChainSpec::testnet();
    assert!(
        kernel.gas_limit >= 20_000_000,
        "the fixture needs a block gas limit above 20M"
    );
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
    let core = || {
        RpcNodeCoreAdapter::new(
            provider.clone(),
            NoopTransactionPool::<reth_transaction_pool::EthPooledTransaction>::default(),
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config.clone(),
        )
    };
    let capped = build_eth_api_capped(core(), reth_tasks::Runtime::test(), PendingPolicy::Unavailable, CAP).into_rpc();
    let block_limit = build_eth_api(core(), reth_tasks::Runtime::test()).into_rpc();
    async fn request(rpc: &jsonrpsee::RpcModule<()>, method: &str, params: Value) -> Value {
        let input = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let (output, _) = tokio::time::timeout(Duration::from_secs(120), rpc.raw_json_request(&input, 1))
            .await
            .expect("simulation answered")
            .unwrap();
        serde_json::from_str(output.get()).unwrap()
    }
    let capped = capped.remove_context();
    let block_limit = block_limit.remove_context();
    let succeeded = |answer: &Value| answer.get("result").is_some() && answer["result"].get("error").is_none();

    // The control: under the block gas limit (30M) the fixture runs.
    let explicit = json!({"to": TARGET, "gas": format!("{:#x}", 25_000_000u64)});
    let answer = request(
        &block_limit,
        "eth_call",
        json!([explicit, "latest", overrides(NEEDS_20M)]),
    )
    .await;
    assert!(succeeded(&answer), "control eth_call at 25M: {answer}");

    // 1. Explicit gas above the cap (upstream already caps this one).
    let answer = request(&capped, "eth_call", json!([explicit, "latest", overrides(NEEDS_20M)])).await;
    assert!(
        !succeeded(&answer),
        "eth_call with explicit 25M gas ran above the cap: {answer}"
    );

    // 2. No gas, a fee and a rich sender: the caller-allowance fallback took the block gas limit,
    //    which a block override raises without bound.
    let allowance = json!({"from": RICH, "to": TARGET, "maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x0"});
    let big_block = json!({"gasLimit": format!("{:#x}", 1_000_000_000u64)});
    let answer = request(
        &block_limit,
        "eth_call",
        json!([allowance, "latest", overrides(NEEDS_20M), big_block]),
    )
    .await;
    assert!(
        succeeded(&answer),
        "control: the allowance path runs above 20M without the patch cap: {answer}"
    );
    let answer = request(
        &capped,
        "eth_call",
        json!([allowance, "latest", overrides(NEEDS_20M), big_block]),
    )
    .await;
    assert!(
        !succeeded(&answer),
        "eth_call allowance path ran above the cap: {answer}"
    );

    // 3. eth_estimateGas takes the block gas limit (or its override) as its ceiling.
    let plain = json!({"to": TARGET});
    let answer = request(
        &block_limit,
        "eth_estimateGas",
        json!([plain, "latest", overrides(NEEDS_20M), big_block]),
    )
    .await;
    assert!(succeeded(&answer), "control estimate: {answer}");
    for block in [Value::Null, big_block.clone()] {
        let answer = request(
            &capped,
            "eth_estimateGas",
            json!([plain, "latest", overrides(NEEDS_20M), block]),
        )
        .await;
        assert!(!succeeded(&answer), "estimate found gas above the cap: {answer}");
    }

    // 4. eth_createAccessList runs an explicit gas with the block and EIP-7825 limits disabled.
    let huge = json!({"to": TARGET, "gas": format!("{:#x}", 1_000_000_000u64)});
    let answer = request(
        &block_limit,
        "eth_createAccessList",
        json!([huge, "latest", overrides(NEEDS_20M)]),
    )
    .await;
    assert!(succeeded(&answer), "control access list at 1e9 gas: {answer}");
    let answer = request(
        &capped,
        "eth_createAccessList",
        json!([huge, "latest", overrides(NEEDS_20M)]),
    )
    .await;
    assert!(!succeeded(&answer), "access list ran above the cap: {answer}");
    let answer = request(
        &capped,
        "eth_createAccessList",
        json!([huge, "latest", overrides(BURNS_5M)]),
    )
    .await;
    assert!(
        succeeded(&answer),
        "an access list within the cap still works: {answer}"
    );

    // 5. Under the cap, honest calls and estimates still work.
    let answer = request(&capped, "eth_call", json!([plain, "latest", overrides(BURNS_5M)])).await;
    assert!(succeeded(&answer), "{answer}");
    let answer = request(
        &capped,
        "eth_estimateGas",
        json!([plain, "latest", overrides(BURNS_5M)]),
    )
    .await;
    let estimate = u64::from_str_radix(answer["result"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert!((5_000_000..CAP).contains(&estimate), "estimate {estimate}");

    // 6. The time budget: a 1 ms budget ends the estimate before its second run.
    set_simulation_time_limit(Some(Duration::from_millis(1)));
    let answer = request(
        &capped,
        "eth_estimateGas",
        json!([plain, "latest", overrides(BURNS_5M)]),
    )
    .await;
    let message = answer["error"]["message"].as_str().unwrap_or_default().to_string();
    assert!(message.contains("execution aborted (timeout = 1ms)"), "{answer}");
    let answer = request(
        &capped,
        "eth_createAccessList",
        json!([plain, "latest", overrides(BURNS_5M)]),
    )
    .await;
    let message = answer["error"]["message"].as_str().unwrap_or_default().to_string();
    assert!(message.contains("execution aborted (timeout = 1ms)"), "{answer}");
    // A single run (eth_call) is never cut: it is bounded by the gas cap.
    let answer = request(&capped, "eth_call", json!([plain, "latest", overrides(BURNS_5M)])).await;
    assert!(succeeded(&answer), "{answer}");
    set_simulation_time_limit(None);
    let answer = request(
        &capped,
        "eth_estimateGas",
        json!([plain, "latest", overrides(BURNS_5M)]),
    )
    .await;
    assert!(succeeded(&answer), "without a budget the estimate completes: {answer}");
}
