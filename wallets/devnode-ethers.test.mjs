// SPDX-License-Identifier: MIT OR Apache-2.0
// Real ethers signing against the explicitly synthetic developer executable.
// No injected EIP-1193 provider or browser/user-approval compatibility is claimed.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { JsonRpcProvider, Wallet, getCreateAddress, toBeHex, zeroPadValue } from "ethers";

const binary = process.env.BLOCH_DEVNODE_BIN ?? fileURLToPath(new URL(
  "../integrations/reth-execution/target/debug/bloch-evm-dev", import.meta.url,
));
// Public fixture only, matching a newly initialized synthetic domain; never real funds.
const key = `0x${"07".repeat(32)}`;

async function launch(directory, fund) {
  const args = ["--synthetic-dev", "--data-dir", directory, "--port", "0", "--block-interval-ms", "100"];
  if (fund) args.push("--init", "--fund", fund);
  const child = spawn(binary, args, { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-16_384); });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  // Register a rejection handler immediately, including startup failures.
  exited.catch(() => {});
  const lines = createInterface({ input: child.stdout });
  let timer;
  const ready = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`startup timeout: ${stderr}`)), 30_000);
    lines.on("line", line => {
      if (line.startsWith("RPC listening at ")) resolve(line.slice("RPC listening at ".length));
    });
    exited.then(status => reject(new Error(`node exited before ready: ${JSON.stringify(status)} ${stderr}`)), reject);
  });
  async function stop() {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGINT");
    let deadline;
    try {
      const status = await Promise.race([
        exited,
        new Promise((_, reject) => {
          deadline = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`shutdown timeout: ${stderr}`)); }, 20_000);
        }),
      ]);
      assert.equal(status.code, 0, `node shutdown: ${JSON.stringify(status)} ${stderr}`);
    } finally {
      clearTimeout(deadline);
      lines.close();
    }
  }
  try {
    const url = await ready;
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+\/?$/);
    return { url, stop };
  } catch (error) {
    child.kill("SIGKILL");
    await exited.catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

test("ethers wallet automatically populates, signs, mines and queries synthetic deploy/call across restart", { timeout: 120_000 }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), "bloch-ethers-"));
  const directory = join(temporary, "node");
  let node;
  let provider;
  try {
    node = await launch(directory, new Wallet(key).address);
    provider = new JsonRpcProvider(node.url);
    const wallet = new Wallet(key, provider);
    assert.equal((await provider.getNetwork()).chainId, 700771n);
    const fees = await provider.getFeeData();
    assert.notEqual(fees.gasPrice, null);
    assert.notEqual(fees.maxFeePerGas, null);
    assert.notEqual(fees.maxPriorityFeePerGas, null);
    assert.ok(fees.maxFeePerGas >= fees.maxPriorityFeePerGas);
    // The wallet still fills all fees, nonce and gas itself below.
    const runtime = "3615601257600035600055602a60006000a15b60005460005260206000f3";
    const length = (runtime.length / 2).toString(16).padStart(2, "0");
    const initcode = `0x60${length}600c60003960${length}6000f3${runtime}`;
    const deployment = await wallet.sendTransaction({ data: initcode });
    const deployed = await deployment.wait(1, 30_000);
    assert.equal(deployed.status, 1);
    assert.equal(deployment.nonce, 0);
    const contract = getCreateAddress({ from: wallet.address, nonce: 0 });
    assert.equal(deployed.contractAddress, contract);
    assert.equal(await provider.getCode(contract), `0x${runtime}`);
    const call = await wallet.sendTransaction({ to: contract, data: zeroPadValue(toBeHex(42), 32) });
    const receipt = await call.wait(1, 30_000);
    assert.equal(receipt.status, 1);
    assert.equal(call.nonce, 1);
    assert.equal(receipt.logs.length, 1);
    assert.equal(receipt.logs[0].topics[0], zeroPadValue(toBeHex(42), 32));
    assert.equal(await provider.getStorage(contract, 0), zeroPadValue(toBeHex(42), 32));
    assert.equal(await provider.call({ to: contract }), zeroPadValue(toBeHex(42), 32));
    const block = await provider.getBlock(receipt.blockNumber);
    assert.equal(block.hash, receipt.blockHash);
    assert.ok(block.transactions.includes(call.hash));
    assert.equal(await provider.getTransactionCount(wallet.address, "pending"), 2);
    await assert.rejects(provider.send("eth_getBlockByNumber", ["pending", false]));
    provider.destroy(); provider = undefined;
    await node.stop(); node = undefined;
    node = await launch(directory);
    provider = new JsonRpcProvider(node.url);
    assert.equal((await provider.getTransactionReceipt(call.hash)).blockHash, receipt.blockHash);
    assert.equal(await provider.getStorage(contract, 0), zeroPadValue(toBeHex(42), 32));
    assert.equal(await provider.getTransactionCount(wallet.address), 2);
  } finally {
    provider?.destroy();
    try { await node?.stop(); }
    finally { await rm(temporary, { recursive: true, force: true }); }
  }
});
