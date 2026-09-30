// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exercise the isolated developer executable, including a real process restart.
#![cfg(unix)]
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
impl Node {
    fn stop(&mut self) {
        assert!(Command::new("kill")
            .args(["-INT", &self.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "developer node failed to stop: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "developer node did not shut down");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn launch(directory: &Path, fund: Option<Address>) -> (Node, HttpClient) {
    launch_at_interval(directory, fund, "50")
}

fn launch_at_interval(directory: &Path, fund: Option<Address>, interval: &str) -> (Node, HttpClient) {
    launch_options(directory, fund, interval, None, None)
}

fn launch_options(
    directory: &Path,
    fund: Option<Address>,
    interval: &str,
    replay: Option<&Path>,
    replay_floor: Option<(u64, B256)>,
) -> (Node, HttpClient) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-evm-dev"));
    command.args(["--synthetic-dev", "--data-dir"]).arg(directory).args([
        "--port",
        "0",
        "--block-interval-ms",
        interval,
    ]);
    if let Some(address) = fund {
        command.args(["--init", "--fund", &address.to_string()]);
    }
    if let Some(source) = replay {
        command.args(["--init", "--replay-from"]).arg(source);
    }
    if let Some((number, hash)) = replay_floor {
        command.args([
            "--replay-min-block",
            &number.to_string(),
            "--replay-min-hash",
            &hash.to_string(),
        ]);
    }
    let mut node = Node(command.stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
    let output = node.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    // Continue draining stdout after discovery so mining output cannot block the child.
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            if let Some(url) = line.strip_prefix("RPC listening at ") {
                let _ = sender.send(url.to_owned());
            }
        }
    });
    let url = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("node must publish its RPC endpoint");
    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(url)
        .unwrap();
    (node, client)
}

fn signed(key: &SigningKey, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    let tx = TxEip1559 {
        chain_id: bloch_l2_evm::ChainSpec::testnet().chain_id,
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
async fn send_and_mine(client: &HttpClient, transaction: Bytes) -> Value {
    let hash: String = client
        .request("eth_sendRawTransaction", rpc_params![transaction])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let receipt: Value = client
                .request("eth_getTransactionReceipt", rpc_params![&hash])
                .await
                .unwrap();
            if !receipt.is_null() {
                return receipt;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node must mine admitted transaction")
}

#[tokio::test]
async fn executable_mines_signed_contract_and_reopens_persisted_state() {
    contract_restart(false).await;
}

#[tokio::test]
async fn executable_replays_contract_into_fresh_storage_and_continues_mining() {
    contract_restart(true).await;
}

#[tokio::test]
async fn reverted_contract_preserves_error_fee_nonce_and_receipt_across_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("reverted-node");
    let key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    let (mut node, client) = launch(&directory, Some(sender));
    // Write slot zero and emit a log, then revert with exactly four bytes.
    // Neither the write nor the log may survive; nonce and gas payment must.
    let runtime = alloy_primitives::hex!("602a600055602a60006000a163deadbeef6000526004601cfd");
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
    let deployed = send_and_mine(&client, signed(&key, 0, TxKind::Create, init.into())).await;
    assert_eq!(deployed["status"], "0x1");
    assert_eq!(deployed["contractAddress"], serde_json::json!(contract));

    for method in ["eth_call", "eth_estimateGas"] {
        let error = client
            .request::<Value, _>(
                method,
                rpc_params![serde_json::json!({"from": sender, "to": contract}), "latest"],
            )
            .await
            .expect_err("simulation must expose the actual revert");
        let jsonrpsee::core::client::Error::Call(error) = error else {
            panic!("expected RPC execution error, got {error}");
        };
        assert_eq!(error.code(), 3, "{method}: {error}");
        assert_eq!(error.data().unwrap().get(), "\"0xdeadbeef\"", "{method}: {error}");
    }
    let balance_before: U256 = client
        .request("eth_getBalance", rpc_params![sender, "latest"])
        .await
        .unwrap();
    let failed = send_and_mine(&client, signed(&key, 1, TxKind::Call(contract), Bytes::new())).await;
    assert_eq!(failed["status"], "0x0");
    assert_eq!(failed["logs"], serde_json::json!([]));
    let gas: U256 = serde_json::from_value(failed["gasUsed"].clone()).unwrap();
    let price: U256 = serde_json::from_value(failed["effectiveGasPrice"].clone()).unwrap();
    assert!(gas > U256::from(21_000) && gas < U256::from(200_000));
    assert!(price > U256::ZERO);
    let balance_after: U256 = client
        .request("eth_getBalance", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_eq!(balance_before - balance_after, gas * price);
    let nonce: String = client
        .request("eth_getTransactionCount", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_eq!(nonce, "0x2");
    let stored: U256 = client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, U256::ZERO);
    let logs: Value = client
        .request(
            "eth_getLogs",
            rpc_params![serde_json::json!({"address": contract, "blockHash": failed["blockHash"]})],
        )
        .await
        .unwrap();
    assert_eq!(logs, serde_json::json!([]));
    // A revert is an included transaction, not a fatal block-production error.
    let next = send_and_mine(&client, signed(&key, 2, TxKind::Call(sender), Bytes::new())).await;
    assert_eq!(next["status"], "0x1");
    drop(client);
    node.stop();
    drop(node);

    let (mut reopened, client) = launch(&directory, None);
    let receipt: Value = client
        .request(
            "eth_getTransactionReceipt",
            rpc_params![failed["transactionHash"].clone()],
        )
        .await
        .unwrap();
    assert_eq!(receipt, failed);
    let stored: U256 = client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, U256::ZERO);
    let nonce: String = client
        .request("eth_getTransactionCount", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_eq!(nonce, "0x3");
    drop(client);
    reopened.stop();
}

async fn contract_restart(replay: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("node");
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    let (mut first, client) = launch(&directory, Some(sender));
    // Store calldata and emit its value as one topic with empty data.
    let runtime = alloy_primitives::hex!("60003560005560005460006000a100");
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
    let deployed = send_and_mine(&client, signed(&key, 0, TxKind::Create, init.into())).await;
    assert_eq!(deployed["status"], "0x1");
    assert_eq!(deployed["contractAddress"], serde_json::json!(contract));
    let filter: String = client
        .request(
            "eth_newFilter",
            // getFilterLogs re-evaluates the stored filter's block tags. Pin
            // the start so later empty blocks cannot move it past the event.
            rpc_params![serde_json::json!({"address": contract, "fromBlock": deployed["blockNumber"]})],
        )
        .await
        .unwrap();
    let called = send_and_mine(
        &client,
        signed(
            &key,
            1,
            TxKind::Call(contract),
            U256::from(42).to_be_bytes::<32>().into(),
        ),
    )
    .await;
    assert_eq!(called["status"], "0x1");
    assert_eq!(called["logs"].as_array().unwrap().len(), 1);
    assert_eq!(called["logs"][0]["topics"][0], format!("0x{:064x}", 42));
    let changes: Value = client
        .request("eth_getFilterChanges", rpc_params![&filter])
        .await
        .unwrap();
    assert_eq!(changes, called["logs"]);
    let changes: Value = client
        .request("eth_getFilterChanges", rpc_params![&filter])
        .await
        .unwrap();
    assert_eq!(changes, serde_json::json!([]));
    let filter_logs: Value = client.request("eth_getFilterLogs", rpc_params![&filter]).await.unwrap();
    assert_eq!(filter_logs, called["logs"]);
    let removed: bool = client
        .request("eth_uninstallFilter", rpc_params![&filter])
        .await
        .unwrap();
    assert!(removed);
    let removed: bool = client
        .request("eth_uninstallFilter", rpc_params![&filter])
        .await
        .unwrap();
    assert!(!removed);
    let stored: String = client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, format!("0x{:064x}", 42));
    drop(client);
    first.stop();
    drop(first);

    let (mut second, client) = if replay {
        // Retain the acknowledged receipt's exact block before closing the source.
        // The new CLI must preserve this supplied floor, even if later empty blocks exist.
        let number = u64::from_str_radix(called["blockNumber"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let hash: B256 = called["blockHash"].as_str().unwrap().parse().unwrap();
        launch_options(
            &temporary.path().join("replayed"),
            None,
            "50",
            Some(&directory),
            Some((number, hash)),
        )
    } else {
        launch(&directory, None)
    };
    let stored: String = client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, format!("0x{:064x}", 42));
    let nonce: String = client
        .request("eth_getTransactionCount", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_eq!(nonce, "0x2");
    let receipt: Value = client
        .request(
            "eth_getTransactionReceipt",
            rpc_params![called["transactionHash"].clone()],
        )
        .await
        .unwrap();
    assert_eq!(receipt, called);
    let logs: Value = client
        .request(
            "eth_getLogs",
            rpc_params![serde_json::json!({"address": contract, "blockHash": called["blockHash"]})],
        )
        .await
        .unwrap();
    assert_eq!(logs, called["logs"]);
    let no_logs: Value = client
        .request("eth_getLogs", rpc_params![serde_json::json!({"address": contract, "fromBlock": called["blockNumber"], "toBlock": called["blockNumber"], "topics": [format!("0x{:064x}", 43)]})])
        .await
        .unwrap();
    assert_eq!(no_logs, serde_json::json!([]));
    let block: Value = client
        .request(
            "eth_getBlockByNumber",
            rpc_params![called["blockNumber"].clone(), false],
        )
        .await
        .unwrap();
    assert_eq!(block["hash"], called["blockHash"]);
    let next = send_and_mine(
        &client,
        signed(
            &key,
            2,
            TxKind::Call(contract),
            U256::from(43).to_be_bytes::<32>().into(),
        ),
    )
    .await;
    assert_eq!(next["status"], "0x1");
    let stored: String = client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, format!("0x{:064x}", 43));
    drop(client);
    second.stop();
}

#[test]
fn executable_requires_synthetic_mode_and_refuses_existing_initialization() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("must-not-create");
    let existing = temporary.path().join("preserve");
    std::fs::create_dir(&existing).unwrap();
    let sentinel = existing.join("sentinel");
    std::fs::write(&sentinel, b"preserve original contents").unwrap();
    for (path, explicit) in [(&missing, false), (&existing, true)] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-evm-dev"));
        command.args(["--data-dir"]).arg(path).arg("--init");
        if explicit {
            command.arg("--synthetic-dev");
        }
        let mut node = Node(command.stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = node.0.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "invalid invocation must exit before serving RPC"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(!missing.exists());
    assert_eq!(std::fs::read(sentinel).unwrap(), b"preserve original contents");
    assert_eq!(std::fs::read_dir(existing).unwrap().count(), 1);
}

#[tokio::test]
async fn abrupt_exit_after_acknowledged_commit_preserves_funding_and_can_resume() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("node");
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    // Keep the process between writes. This tests SIGKILL after an acknowledged
    // commit, deliberately not interruption inside multi-backend persistence.
    let (mut first, client) = launch_at_interval(&directory, Some(sender), "60000");
    let acknowledged: Value = client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .unwrap();
    assert_eq!(acknowledged["number"], "0x1");
    let balance: String = client
        .request("eth_getBalance", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_ne!(balance, "0x0");
    drop(client);
    first.0.kill().unwrap();
    assert!(!first.0.wait().unwrap().success());
    drop(first);

    let (mut resumed, client) = launch(&directory, None);
    let stored: Value = client
        .request("eth_getBlockByNumber", rpc_params!["0x1", false])
        .await
        .unwrap();
    assert_eq!(stored, acknowledged);
    let restored: String = client
        .request("eth_getBalance", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_eq!(restored, balance);
    let receipt = send_and_mine(&client, signed(&key, 0, TxKind::Call(sender), Bytes::new())).await;
    assert_eq!(receipt["status"], "0x1");
    let nonce: String = client
        .request("eth_getTransactionCount", rpc_params![sender, "latest"])
        .await
        .unwrap();
    assert_eq!(nonce, "0x1");
    drop(client);
    resumed.stop();
}
