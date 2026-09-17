// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Contract, ContractFactory, JsonRpcProvider, Wallet, zeroPadValue, toBeHex } from "ethers";
import { startNode } from "./browser/services.mjs";
import { compileCounter, COMPILER_VERSION } from "./contracts/compile.mjs";

// Public test key; only this newly initialized synthetic domain is funded.
const key = `0x${"11".repeat(32)}`;

async function assertEvent(counter, provider, receipt, sender) {
  const address = await counter.getAddress();
  const event = counter.interface.getEvent("ValueChanged");
  const filter = counter.filters.ValueChanged(sender);
  const [decoded, raw, absent] = await Promise.all([
    counter.queryFilter(filter, receipt.blockNumber, receipt.blockNumber),
    provider.getLogs({
      address, fromBlock: receipt.blockNumber, toBlock: receipt.blockNumber,
      topics: [event.topicHash, zeroPadValue(sender, 32)],
    }),
    counter.queryFilter(counter.filters.ValueChanged(address), receipt.blockNumber, receipt.blockNumber),
  ]);
  assert.equal(decoded.length, 1);
  assert.equal(decoded[0].eventName, "ValueChanged");
  assert.deepEqual([...decoded[0].args], [sender, 7n, 42n]);
  assert.equal(decoded[0].transactionHash, receipt.hash);
  assert.equal(decoded[0].blockHash, receipt.blockHash);
  assert.equal(raw.length, 1);
  assert.equal(raw[0].address, address);
  assert.equal(raw[0].transactionHash, receipt.hash);
  assert.deepEqual(counter.interface.parseLog(raw[0]).args.toArray(), [sender, 7n, 42n]);
  assert.deepEqual(absent, []);
}

function isExpectedRevert(counter, error) {
  assert.equal(error.code, "CALL_EXCEPTION");
  assert.equal(error.data, counter.interface.encodeErrorResult("ValueTooLarge", [1001n, 1000n]));
  const decoded = counter.interface.parseError(error.data);
  assert.equal(decoded.name, "ValueTooLarge");
  assert.deepEqual([...decoded.args], [1001n, 1000n]);
  return true;
}

test("compiled Cancun Solidity deploy, ABI events, custom errors and state survive restart", { timeout: 120_000 }, async () => {
  const artifact = await compileCounter();
  console.log(`Compiler ${COMPILER_VERSION}; evmVersion=cancun; creation bytes=${(artifact.bytecode.length - 2) / 2}`);
  const temporary = await mkdtemp(join(tmpdir(), "bloch-solidity-"));
  const directory = join(temporary, "node");
  let node;
  let provider;
  try {
    const sender = new Wallet(key).address;
    node = await startNode(directory, sender);
    provider = new JsonRpcProvider(node.url);
    assert.equal((await provider.getNetwork()).chainId, 700771n);
    const wallet = new Wallet(key, provider);
    const factory = new ContractFactory(artifact.abi, artifact.bytecode, wallet);
    // No manual nonce, fee, gas limit or raw signed transaction overrides.
    const counter = await factory.deploy(7n);
    const deployment = counter.deploymentTransaction();
    const deployed = await deployment.wait(1, 30_000);
    assert.equal(deployed.status, 1);
    assert.equal(deployment.nonce, 0);
    const address = await counter.getAddress();
    assert.equal(deployed.contractAddress, address);
    assert.equal(await provider.getCode(address), artifact.deployedBytecode);
    assert.equal(await counter.value(), 7n);
    assert.equal(await counter.MAX_VALUE(), 1000n);

    const update = await counter.setValue(42n);
    const receipt = await update.wait(1, 30_000);
    assert.equal(receipt.status, 1);
    assert.equal(update.nonce, 1);
    assert.equal(await counter.value(), 42n);
    assert.equal(await provider.getStorage(address, 0), zeroPadValue(toBeHex(42), 32));
    await assertEvent(counter, provider, receipt, sender);

    await assert.rejects(counter.setValue.staticCall(1001n), error => isExpectedRevert(counter, error));
    await assert.rejects(counter.setValue.estimateGas(1001n), error => isExpectedRevert(counter, error));
    assert.equal(await counter.value(), 42n);
    assert.equal(await provider.getTransactionCount(sender, "pending"), 2);
    await assertEvent(counter, provider, receipt, sender);

    const endpoint = node.url;
    provider.destroy(); provider = undefined;
    await node.close(); node = undefined;
    node = await startNode(directory, undefined, Number(new URL(endpoint).port));
    assert.equal(node.url, endpoint);
    provider = new JsonRpcProvider(node.url);
    const reopened = new Contract(address, artifact.abi, provider);
    assert.equal(await reopened.value(), 42n);
    assert.equal(await provider.getCode(address), artifact.deployedBytecode);
    assert.equal(await provider.getStorage(address, 0), zeroPadValue(toBeHex(42), 32));
    assert.equal(await provider.getTransactionCount(sender), 2);
    assert.equal((await provider.getTransactionReceipt(receipt.hash)).blockHash, receipt.blockHash);
    await assertEvent(reopened, provider, receipt, sender);
    await assert.rejects(reopened.setValue.staticCall(1001n), error => isExpectedRevert(reopened, error));
  } finally {
    provider?.destroy();
    try { await node?.close(); }
    finally { await rm(temporary, { recursive: true, force: true }); }
  }
});
