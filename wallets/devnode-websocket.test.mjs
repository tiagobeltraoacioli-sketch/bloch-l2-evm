// SPDX-License-Identifier: MIT OR Apache-2.0
// Real ethers WebSocket subscriptions and automatic signing; synthetic funds only.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { ContractFactory, JsonRpcProvider, WebSocketProvider, Wallet } from "ethers";
import { compileCounter } from "./contracts/compile.mjs";

const binary = process.env.BLOCH_DEVNODE_BIN ?? fileURLToPath(new URL(
  "../integrations/reth-execution/target/debug/bloch-evm-dev", import.meta.url,
));
// Public fixture, funded only through a new explicit synthetic domain.
const key = `0x${"12".repeat(32)}`;

async function bounded(promise, label, milliseconds = 30_000) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

async function launch(directory, account) {
  const child = spawn(binary, ["--synthetic-dev", "--data-dir", directory, "--init",
    "--fund", account, "--port", "0", "--ws-port", "0", "--block-interval-ms", "100"],
  { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-16_384); });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  exited.catch(() => {});
  const lines = createInterface({ input: child.stdout });
  try {
    const endpoints = await bounded(new Promise((resolve, reject) => {
      const endpoints = {};
      lines.on("line", line => {
        if (line.startsWith("RPC listening at ")) endpoints.http = line.slice(17);
        if (line.startsWith("WS listening at ")) endpoints.ws = line.slice(16);
        if (endpoints.http && endpoints.ws) resolve(endpoints);
      });
      exited.then(status => reject(new Error(`node exited: ${JSON.stringify(status)} ${stderr}`)), reject);
    }), "HTTP/WS startup");
    assert.match(endpoints.http, /^http:\/\/127\.0\.0\.1:\d+\/?$/);
    assert.match(endpoints.ws, /^ws:\/\/127\.0\.0\.1:\d+\/?$/);
    return { ...endpoints, async close() {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGINT");
      try {
        const status = await bounded(exited, "node shutdown", 20_000);
        assert.equal(status.code, 0, `${JSON.stringify(status)} ${stderr}`);
      } catch (error) {
        child.kill("SIGKILL"); await exited.catch(() => {}); throw error;
      } finally { lines.close(); }
    } };
  } catch (error) {
    child.kill("SIGKILL"); await exited.catch(() => {}); lines.close(); throw error;
  }
}

// Observe public ethers diagnostics only; never intercept/replace RPC responses.
// `on` starts an async eth_subscribe. Await its actual server acknowledgment,
// rather than sleeping and hoping the event subscription has become active.
async function nextSubscribedEvent(provider, event, kind) {
  let requestId;
  let resolveReady, rejectReady, resolveEvent;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const received = new Promise(resolve => { resolveEvent = resolve; });
  const diagnostics = info => {
    if (info.action === "sendRpcPayload") {
      for (const payload of Array.isArray(info.payload) ? info.payload : [info.payload]) {
        if (payload.method === "eth_subscribe" && payload.params[0] === kind) requestId = payload.id;
      }
    } else if (info.action === "receiveRpcResult") {
      for (const result of Array.isArray(info.result) ? info.result : [info.result]) {
        if (requestId !== undefined && result.id === requestId) {
          if (result.error) rejectReady(new Error(JSON.stringify(result.error)));
          else resolveReady(result.result);
        }
      }
    }
  };
  await provider.on("debug", diagnostics);
  try {
    await provider.once(event, value => resolveEvent(value));
    const id = await bounded(ready, `${kind} subscription acknowledgment`, 10_000);
    assert.equal(typeof id, "string");
    return { received };
  } finally { await provider.off("debug", diagnostics); }
}

test("ethers WebSocketProvider subscribes before automatic signed Solidity deploy/call", { timeout: 120_000 }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), "bloch-ethers-ws-"));
  let node, provider, http;
  try {
    const artifact = await compileCounter();
    node = await launch(join(temporary, "node"), new Wallet(key).address);
    provider = new WebSocketProvider(node.ws);
    http = new JsonRpcProvider(node.http);
    assert.equal((await provider.getNetwork()).chainId, 700771n);
    const block = await nextSubscribedEvent(provider, "block", "newHeads");
    const height = await bounded(block.received, "high-level block event");
    assert.equal(typeof height, "number");
    const [wsBlock, httpBlock] = await Promise.all([provider.getBlock(height), http.getBlock(height)]);
    assert.equal(wsBlock.hash, httpBlock.hash);
    assert.equal(wsBlock.stateRoot, httpBlock.stateRoot);
    const wallet = new Wallet(key, provider);
    const fees = await provider.getFeeData();
    assert.notEqual(fees.maxFeePerGas, null);
    assert.notEqual(fees.maxPriorityFeePerGas, null);
    const factory = new ContractFactory(artifact.abi, artifact.bytecode, wallet);
    // Automatic nonce, gas estimate and EIP-1559 fee population through real WS.
    const counter = await factory.deploy(7n);
    const deployed = await counter.deploymentTransaction().wait(1, 30_000);
    assert.equal(deployed.status, 1);
    assert.equal(counter.deploymentTransaction().nonce, 0);
    const address = await counter.getAddress();
    assert.equal(deployed.contractAddress, address);
    const filter = { address, topics: await counter.filters.ValueChanged(wallet.address).getTopicFilter() };
    const log = await nextSubscribedEvent(provider, filter, "logs");
    const transaction = await counter.setValue(42n);
    assert.equal(transaction.nonce, 1);
    const [receipt, event] = await Promise.all([
      transaction.wait(1, 30_000), bounded(log.received, "high-level Solidity log event"),
    ]);
    assert.equal(receipt.status, 1);
    assert.equal(event.transactionHash, receipt.hash);
    assert.equal(event.blockHash, receipt.blockHash);
    assert.equal(event.blockNumber, receipt.blockNumber);
    assert.equal(event.index, receipt.logs[0].index);
    assert.deepEqual(event.topics, receipt.logs[0].topics);
    assert.equal(event.data, receipt.logs[0].data);
    assert.deepEqual(counter.interface.parseLog(event).args.toArray(), [wallet.address, 7n, 42n]);
    assert.equal(await counter.value(), 42n);
    assert.equal(BigInt(await provider.getStorage(address, 0)), 42n);
    assert.equal(BigInt(await http.getStorage(address, 0)), 42n);
    const persisted = await http.getTransactionReceipt(receipt.hash);
    assert.equal(persisted.blockHash, receipt.blockHash);
  } finally {
    await provider?.removeAllListeners();
    provider?.destroy(); http?.destroy();
    try { await node?.close(); } finally { await rm(temporary, { recursive: true, force: true }); }
  }
});
