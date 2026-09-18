// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { createBlochL2Wallet, BLOCH_L2_SECURITY } from "./bloch-l2.mjs";

const account = `0x${"11".repeat(20)}`;
const chainId = `0x${700771n.toString(16)}`;
const options = { rpcUrl: "http://127.0.0.1:8545" };
function mock(handlers = {}) {
  const calls = [];
  return { calls, request: async request => {
    calls.push(request);
    if (handlers[request.method]) return handlers[request.method](request);
    if (request.method === "eth_chainId") return chainId;
    if (["eth_requestAccounts", "eth_accounts"].includes(request.method)) return [account];
    if (request.method === "eth_sendTransaction") return `0x${"aa".repeat(32)}`;
    return null;
  } };
}

test("connects the selected EIP-1193 wallet with explicit classical L2 metadata", async () => {
  const provider = mock();
  const wallet = createBlochL2Wallet(provider, options);
  const session = await wallet.connect();
  assert.equal(session.chainId, chainId);
  assert.deepEqual(session.accounts, [account]);
  assert.equal(session.security, BLOCH_L2_SECURITY);
  assert.equal(session.security.postQuantumAccounts, false);
  assert.equal(wallet.network.chainName, "Bloch L2 (ECDSA)");
});

test("adds an unknown chain, then explicitly switches again", async () => {
  let switches = 0;
  const provider = mock({ wallet_switchEthereumChain: () => { if (++switches === 1) throw { code: 4902 }; } });
  const wallet = createBlochL2Wallet(provider, options);
  await wallet.connect();
  assert.deepEqual(provider.calls.slice(0, 3).map(call => call.method), ["wallet_switchEthereumChain", "wallet_addEthereumChain", "wallet_switchEthereumChain"]);
  const network = provider.calls[1].params[0];
  assert.equal(network.nativeCurrency.decimals, 18);
  assert.deepEqual(network.rpcUrls, ["http://127.0.0.1:8545/"]);
});

test("does not bypass user rejection or request accounts on the wrong chain", async () => {
  const rejection = { code: 4001 };
  const provider = mock({ wallet_switchEthereumChain: () => { throw rejection; } });
  await assert.rejects(createBlochL2Wallet(provider, options).connect(), error => error === rejection);
  assert.equal(provider.calls.length, 1);
  const wrong = mock({ eth_chainId: () => "0x1" });
  await assert.rejects(createBlochL2Wallet(wrong, options).connect(), /not connected/);
  assert.ok(!wrong.calls.some(call => call.method === "eth_requestAccounts"));
  const oversized = mock({ eth_chainId: () => `0x${"f".repeat(10_000)}` });
  await assert.rejects(createBlochL2Wallet(oversized, options).connect(), /not connected/);
  assert.ok(!oversized.calls.some(call => call.method === "eth_requestAccounts"));
});

test("requires a real configured endpoint and rejects unsafe chain IDs", () => {
  for (const rpcUrl of [undefined, "http://example.com", "https://user:pass@example.com", "https://example.com/#x", "https://" + "a".repeat(2048)]) {
    assert.throws(() => createBlochL2Wallet(mock(), { rpcUrl }));
  }
  for (const id of [0, -1, Number.MAX_SAFE_INTEGER + 1, 1n << 64n, " 700771 ", "9".repeat(10_000)]) {
    assert.throws(() => createBlochL2Wallet(mock(), { ...options, chainId: id }));
  }
});

test("sends via the wallet with an explicit chain domain and connected sender", async () => {
  const provider = mock();
  const wallet = createBlochL2Wallet(provider, options);
  await wallet.sendTransaction({ from: account, to: account, value: "0x1", type: "0x2" });
  const sent = provider.calls.at(-1);
  assert.equal(sent.method, "eth_sendTransaction");
  assert.equal(sent.params[0].chainId, chainId);
  assert.equal(sent.params[0].from, account);
});

test("chain/account changes and unsupported authorization cannot reach signing", async () => {
  const provider = mock();
  const wallet = createBlochL2Wallet(provider, options);
  for (const tx of [
    { from: account, chainId: "0x1" }, { from: account, type: "0x4" },
    { from: account, authorizationList: [] }, { from: account, value: "0x01" },
    { from: account, value: `0x${"f".repeat(65)}` },
    { from: account, data: "0x1" }, { from: `0x${"22".repeat(20)}` },
    { from: account, gasPrice: "0x1", maxFeePerGas: "0x2" },
    { from: account, type: "0x0", accessList: [] },
    { from: account, type: "0x1", maxFeePerGas: "0x2" },
    { from: account, type: "0x2", gasPrice: "0x1" },
    { from: account, maxFeePerGas: "0x1", maxPriorityFeePerGas: "0x2" },
  ]) await assert.rejects(wallet.sendTransaction(tx));
  assert.ok(!provider.calls.some(call => call.method === "eth_sendTransaction"));
  let reads = 0;
  const changed = mock({ eth_chainId: () => ++reads === 1 ? chainId : "0x1" });
  await assert.rejects(createBlochL2Wallet(changed, options).sendTransaction({ from: account }), /not connected/);
  assert.ok(!changed.calls.some(call => call.method === "eth_sendTransaction"));
});

test("bounds untrusted provider responses and transaction collections", async () => {
  const tooManyAccounts = mock({ eth_requestAccounts: () => Array(1025).fill(account) });
  await assert.rejects(createBlochL2Wallet(tooManyAccounts, options).connect(), /valid Ethereum accounts/);

  const wallet = createBlochL2Wallet(mock(), options);
  const addressLikeObject = { toString: () => account, toLowerCase: () => account };
  let oversizedStorageKeysInspected = false;
  const oversizedStorageKeys = new Proxy(Array(8193), { get(target, key, receiver) {
    if (key === "some") oversizedStorageKeysInspected = true;
    return Reflect.get(target, key, receiver);
  } });
  for (const tx of [
    { from: addressLikeObject },
    { from: account, to: addressLikeObject },
    { from: account, accessList: [{ address: addressLikeObject, storageKeys: [] }] },
    { from: account, data: `0x${"00".repeat(128 * 1024 + 1)}` },
    { from: account, accessList: Array(1025).fill({ address: account, storageKeys: [] }) },
    { from: account, accessList: [{ address: account, storageKeys: oversizedStorageKeys }] },
  ]) await assert.rejects(wallet.sendTransaction(tx));
  assert.equal(oversizedStorageKeysInspected, false);

  const invalidHash = mock({ eth_sendTransaction: () => "0x01" });
  await assert.rejects(createBlochL2Wallet(invalidHash, options).sendTransaction({ from: account }), /invalid transaction hash/);
});
