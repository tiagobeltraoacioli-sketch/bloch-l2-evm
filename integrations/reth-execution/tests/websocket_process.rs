// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual upstream WebSocket subscriptions against the isolated developer process.
#![cfg(unix)]
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, U256};
use jsonrpsee::{
    core::client::{ClientT, Subscription, SubscriptionClientT},
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
    ws_client::{WsClient, WsClientBuilder},
};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
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
                assert!(status.success(), "node shutdown: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "node shutdown timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
async fn connect(url: &str) -> WsClient {
    WsClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(url)
        .await
        .unwrap()
}
async fn launch(directory: &Path, fund: Option<Address>) -> (Node, HttpClient, WsClient, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-evm-dev"));
    command.args(["--synthetic-dev", "--data-dir"]).arg(directory).args([
        "--port",
        "0",
        "--ws-port",
        "0",
        "--block-interval-ms",
        "100",
    ]);
    if let Some(address) = fund {
        command.args(["--init", "--fund", &address.to_string()]);
    }
    let mut node = Node(command.stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
    let output = node.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            if let Some(url) = line.strip_prefix("RPC listening at ") {
                let _ = sender.send((false, url.to_owned()));
            }
            if let Some(url) = line.strip_prefix("WS listening at ") {
                let _ = sender.send((true, url.to_owned()));
            }
        }
    });
    let mut http = None;
    let mut ws = None;
    while http.is_none() || ws.is_none() {
        let (websocket, url) = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("node must expose both real transports");
        if websocket {
            ws = Some(url);
        } else {
            http = Some(url);
        }
    }
    let http = http.unwrap();
    let ws = ws.unwrap();
    assert_ne!(
        http.trim_start_matches("http://"),
        ws.trim_start_matches("ws://"),
        "ephemeral transports require separate ports"
    );
    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&http)
        .unwrap();
    let websocket = connect(&ws).await;
    (node, client, websocket, ws)
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
async fn next(subscription: &mut Subscription<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(20), subscription.next())
        .await
        .expect("upstream notification timed out")
        .expect("subscription closed")
        .expect("invalid notification")
}
async fn receipt(http: &HttpClient, hash: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let value: Value = http
                .request("eth_getTransactionReceipt", rpc_params![hash])
                .await
                .unwrap();
            if !value.is_null() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("admitted transaction must be mined")
}
async fn check_head(http: &HttpClient, heads: &mut Subscription<Value>) {
    let head = next(heads).await;
    let canonical: Value = http
        .request("eth_getBlockByNumber", rpc_params![head["number"].clone(), false])
        .await
        .unwrap();
    for field in ["hash", "parentHash", "stateRoot", "number"] {
        assert_eq!(head[field], canonical[field], "V2 header field {field}");
    }
}
async fn unsubscribe(subscription: Subscription<Value>) {
    tokio::time::timeout(Duration::from_secs(10), subscription.unsubscribe())
        .await
        .expect("unsubscribe timed out")
        .unwrap();
}

#[test]
fn invalid_websocket_ports_fail_before_creating_storage() {
    let temporary = tempfile::tempdir().unwrap();
    for (name, arguments) in [
        ("same-port", vec!["--port", "8545", "--ws-port", "8545"]),
        ("missing-port", vec!["--ws-port"]),
        ("oversized-port", vec!["--ws-port", "65536"]),
    ] {
        let directory = temporary.path().join(name);
        let rejected = Command::new(env!("CARGO_BIN_EXE_bloch-evm-dev"))
            .args(["--synthetic-dev", "--data-dir"])
            .arg(&directory)
            .arg("--init")
            .args(arguments)
            .output()
            .unwrap();
        assert!(!rejected.status.success(), "{name}");
        assert!(
            !directory.exists(),
            "invalid transport configuration created storage: {name}"
        );
    }
}

#[tokio::test]
async fn real_websocket_heads_pending_logs_and_restart_match_http_state() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("node");
    let key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    let (mut node, http, ws, url) = launch(&directory, Some(sender)).await;
    let mut heads = ws
        .subscribe("eth_subscribe", rpc_params!["newHeads"], "eth_unsubscribe")
        .await
        .unwrap();
    check_head(&http, &mut heads).await;
    let invalid = ws
        .subscribe::<Value, _>(
            "eth_subscribe",
            rpc_params!["not-a-real-subscription"],
            "eth_unsubscribe",
        )
        .await
        .expect_err("invalid subscription must fail");
    let jsonrpsee::core::client::Error::Call(error) = invalid else {
        panic!("expected JSON-RPC subscription error: {invalid}")
    };
    assert_eq!(error.code(), -32602);
    let mut pending = ws
        .subscribe(
            "eth_subscribe",
            rpc_params!["newPendingTransactions"],
            "eth_unsubscribe",
        )
        .await
        .unwrap();
    // Synthetic fixture code stores calldata[0] and logs it as one topic.
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
    let raw = signed(&key, 0, TxKind::Create, init.into());
    let expected = keccak256(&raw);
    let hash: String = http.request("eth_sendRawTransaction", rpc_params![raw]).await.unwrap();
    assert_eq!(hash, expected.to_string());
    assert_eq!(next(&mut pending).await, json!(expected));
    let deployed = receipt(&http, &hash).await;
    assert_eq!(deployed["status"], "0x1");
    assert_eq!(deployed["contractAddress"], json!(contract));
    let mut logs = ws
        .subscribe(
            "eth_subscribe",
            rpc_params!["logs", json!({"address":contract,"topics":[format!("0x{:064x}",42)]})],
            "eth_unsubscribe",
        )
        .await
        .unwrap();
    let hash: String = http
        .request(
            "eth_sendRawTransaction",
            rpc_params![signed(
                &key,
                1,
                TxKind::Call(contract),
                U256::from(42).to_be_bytes::<32>().to_vec().into()
            )],
        )
        .await
        .unwrap();
    assert_eq!(next(&mut pending).await, json!(&hash));
    let logged = next(&mut logs).await;
    let called = receipt(&http, &hash).await;
    assert_eq!(called["status"], "0x1");
    assert_eq!(called["logs"], json!([logged]));
    for subscription in [logs, pending, heads] {
        unsubscribe(subscription).await;
    }
    drop(ws);
    let ws = connect(&url).await;
    let mut heads = ws
        .subscribe("eth_subscribe", rpc_params!["newHeads"], "eth_unsubscribe")
        .await
        .unwrap();
    check_head(&http, &mut heads).await;
    unsubscribe(heads).await;
    drop(ws);
    let stored: U256 = http
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, U256::from(42));
    drop(http);
    node.stop();
    drop(node);

    let (mut reopened, http, ws, _) = launch(&directory, None).await;
    let stored: U256 = http
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, U256::from(42));
    let recovered: Value = http
        .request("eth_getTransactionReceipt", rpc_params![&hash])
        .await
        .unwrap();
    assert_eq!(recovered, called);
    let mut heads = ws
        .subscribe("eth_subscribe", rpc_params!["newHeads"], "eth_unsubscribe")
        .await
        .unwrap();
    check_head(&http, &mut heads).await;
    let mut logs = ws
        .subscribe(
            "eth_subscribe",
            rpc_params!["logs", json!({"address":contract,"topics":[format!("0x{:064x}",43)]})],
            "eth_unsubscribe",
        )
        .await
        .unwrap();
    let hash: String = http
        .request(
            "eth_sendRawTransaction",
            rpc_params![signed(
                &key,
                2,
                TxKind::Call(contract),
                U256::from(43).to_be_bytes::<32>().to_vec().into()
            )],
        )
        .await
        .unwrap();
    let logged = next(&mut logs).await;
    let called = receipt(&http, &hash).await;
    assert_eq!(called["logs"], json!([logged]));
    let stored: U256 = http
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(stored, U256::from(43));
    unsubscribe(logs).await;
    unsubscribe(heads).await;
    drop(ws);
    drop(http);
    reopened.stop();
}
