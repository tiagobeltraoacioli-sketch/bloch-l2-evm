// SPDX-License-Identifier: MIT OR Apache-2.0
// Reference EIP-1193 identity/status checks against the real synthetic devnode.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { createBlochL2Wallet } from "./bloch-l2.mjs";

const binary = process.env.BLOCH_DEVNODE_BIN ?? fileURLToPath(new URL(
  "../integrations/reth-execution/target/debug/bloch-evm-dev", import.meta.url,
));
const account = `0x${"11".repeat(20)}`;

async function launch(directory) {
  const child = spawn(binary, [
    "--synthetic-dev", "--data-dir", directory, "--init", "--port", "0", "--block-interval-ms", "1000",
  ], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-16_384); });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  exited.catch(() => {});
  const lines = createInterface({ input: child.stdout });
  let timer;
  try {
    const url = await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`startup timeout: ${stderr}`)), 30_000);
      lines.on("line", line => {
        if (line.startsWith("RPC listening at ")) resolve(line.slice("RPC listening at ".length));
      });
      exited.then(status => reject(new Error(`node exited before ready: ${JSON.stringify(status)} ${stderr}`)), reject);
    });
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+\/?$/);
    return { child, exited, lines, url, stderr: () => stderr };
  } catch (error) {
    child.kill("SIGKILL");
    await exited.catch(() => {});
    lines.close();
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function stop(node) {
  if (node.child.exitCode === null && node.child.signalCode === null) node.child.kill("SIGINT");
  let timer;
  try {
    const status = await Promise.race([
      node.exited,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          node.child.kill("SIGKILL");
          reject(new Error(`shutdown timeout: ${node.stderr()}`));
        }, 20_000);
      }),
    ]);
    assert.equal(status.code, 0, `node shutdown: ${JSON.stringify(status)} ${node.stderr()}`);
  } finally {
    clearTimeout(timer);
    node.lines.close();
  }
}

test("EIP-1193 adapter verifies fresh canonical status against the real devnode", { timeout: 60_000 }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), "bloch-status-"));
  let node;
  try {
    node = await launch(join(temporary, "node"));
    let id = 0;
    const challenges = [];
    const rpc = async (method, params) => {
      const request = { jsonrpc: "2.0", id: ++id, method };
      if (params !== undefined) request.params = params;
      const response = await fetch(node.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
      assert.equal(response.ok, true);
      const message = await response.json();
      if (message.error) throw new Error(`RPC ${method}: ${JSON.stringify(message.error)}`);
      return message.result;
    };
    const identity = await rpc("bloch_chainIdentity");
    const genesis = await rpc("eth_getBlockByNumber", ["0x0", false]);
    const provider = { request: async request => {
      if (request.method === "wallet_switchEthereumChain") return null;
      if (request.method === "eth_requestAccounts") return [account];
      if (request.method === "bloch_chainStatus") challenges.push(request.params[0]);
      return rpc(request.method, request.params);
    } };
    const wallet = createBlochL2Wallet(provider, {
      rpcUrl: node.url,
      chainId: identity.chainId,
      domain: identity.domain,
      genesisHash: genesis.hash,
    });
    const session = await wallet.connect();
    assert.deepEqual(session.accounts, [account]);
    assert.equal(challenges.length, 2);
    assert.notEqual(challenges[0], challenges[1]);
  } finally {
    try { if (node) await stop(node); }
    finally { await rm(temporary, { recursive: true, force: true }); }
  }
});
