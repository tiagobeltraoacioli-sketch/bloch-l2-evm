// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import {
  createBlochL2Wallet,
  BLOCH_L2_HEADER_FORMAT,
  BLOCH_L2_CHECKPOINT_FORMAT,
  BLOCH_L2_IDENTITY_FORMAT,
  BLOCH_L2_SECURITY,
  BLOCH_L2_STATUS_FORMAT,
} from "./bloch-l2.mjs";
import {
  BLOCH_L2_FINALITY_ATTESTATION_FORMAT,
  BLOCH_L2_FINALITY_ENVELOPE_FORMAT,
  blochL2FinalitySigningBytes,
  createEd25519FinalityVerifier,
} from "./finality-attestation.mjs";

const account = `0x${"11".repeat(20)}`;
const chainId = `0x${700771n.toString(16)}`;
const genesisHash = `0x${"42".repeat(32)}`;
const domain = `0x${"71".repeat(32)}`;
const stateRoot = `0x${"31".repeat(32)}`;
const identity = Object.freeze({
  format: BLOCH_L2_IDENTITY_FORMAT,
  chainId,
  domain,
  genesisHash,
  headerFormat: BLOCH_L2_HEADER_FORMAT,
});
const trustedFinalityVerifier = Object.freeze({ verify: async () => true });
const options = {
  rpcUrl: "http://127.0.0.1:8545", genesisHash, domain, trustedFinalityVerifier,
};
function mock(handlers = {}) {
  const calls = [];
  return { calls, request: async request => {
    calls.push(request);
    if (handlers[request.method]) return handlers[request.method](request);
    if (request.method === "eth_chainId") return chainId;
    if (request.method === "eth_getBlockByNumber") return { number: "0x0", hash: genesisHash, stateRoot };
    if (request.method === "bloch_chainIdentity") return { ...identity };
    if (request.method === "bloch_chainStatus") return {
      format: BLOCH_L2_STATUS_FORMAT,
      challenge: request.params[0],
      identity: { ...identity },
      headNumber: "0x0",
      headHash: genesisHash,
      stateRoot,
    };
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
  assert.equal(session.genesisHash, genesisHash);
  assert.deepEqual(session.identity, identity);
  assert.ok(Object.isFrozen(session.identity));
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
  const wrongGenesis = mock({ eth_getBlockByNumber: () => ({ number: "0x0", hash: `0x${"24".repeat(32)}` }) });
  await assert.rejects(createBlochL2Wallet(wrongGenesis, options).connect(), /configured Bloch L2 genesis/);
  assert.ok(!wrongGenesis.calls.some(call => call.method === "eth_requestAccounts"));
  for (const value of [null, [], { number: "0x1", hash: genesisHash }, { number: "0x0", hash: "0x1" }]) {
    const malformedGenesis = mock({ eth_getBlockByNumber: () => value });
    await assert.rejects(createBlochL2Wallet(malformedGenesis, options).connect());
    assert.ok(!malformedGenesis.calls.some(call => call.method === "eth_requestAccounts"));
  }
});

test("requires a real configured endpoint and rejects unsafe chain IDs", () => {
  for (const rpcUrl of [undefined, "http://example.com", "https://user:pass@example.com", "https://example.com/#x", "https://" + "a".repeat(2048)]) {
    assert.throws(() => createBlochL2Wallet(mock(), { rpcUrl, genesisHash }));
  }
  for (const id of [0, -1, Number.MAX_SAFE_INTEGER + 1, 1n << 64n, " 700771 ", "9".repeat(10_000)]) {
    assert.throws(() => createBlochL2Wallet(mock(), { ...options, chainId: id }));
  }
  for (const configuredGenesis of [undefined, "0x1", `0x${"g".repeat(64)}`, `0x${"00".repeat(33)}`]) {
    assert.throws(() => createBlochL2Wallet(mock(), { ...options, genesisHash: configuredGenesis }));
  }
  for (const configuredDomain of [undefined, "0x1", `0x${"g".repeat(64)}`, `0x${"00".repeat(33)}`]) {
    assert.throws(() => createBlochL2Wallet(mock(), { ...options, domain: configuredDomain }));
  }
  for (const trustedFinalityVerifier of [null, {}, { verify: true }]) {
    assert.throws(
      () => createBlochL2Wallet(mock(), { ...options, trustedFinalityVerifier }),
      /trusted finality verifier/i,
    );
  }
});

test("requires the exact versioned chain identity before requesting accounts", async () => {
  for (const changed of [
    null,
    [],
    { ...identity, format: "bloch-chain-identity-v2" },
    { ...identity, chainId: "0xAB163" },
    { ...identity, domain: `0x${"72".repeat(32)}` },
    { ...identity, genesisHash: `0x${"43".repeat(32)}` },
    { ...identity, headerFormat: "ethereum-rlp" },
    { ...identity, extra: true },
  ]) {
    const provider = mock({ bloch_chainIdentity: () => changed });
    await assert.rejects(createBlochL2Wallet(provider, options).connect(), /configured Bloch L2 identity/);
    assert.ok(!provider.calls.some(call => call.method === "eth_requestAccounts"));
  }
  for (const missing of Object.keys(identity)) {
    const changed = { ...identity };
    delete changed[missing];
    const provider = mock({ bloch_chainIdentity: () => changed });
    await assert.rejects(createBlochL2Wallet(provider, options).connect(), /configured Bloch L2 identity/);
    assert.ok(!provider.calls.some(call => call.method === "eth_requestAccounts"));
  }
});

test("does not execute identity accessors and rechecks identity immediately before signing", async () => {
  let getterCalls = 0;
  const accessor = { ...identity };
  Object.defineProperty(accessor, "domain", { get() { getterCalls += 1; return domain; }, enumerable: true });
  const accessorProvider = mock({ bloch_chainIdentity: () => accessor });
  await assert.rejects(createBlochL2Wallet(accessorProvider, options).connect(), /configured Bloch L2 identity/);
  assert.equal(getterCalls, 0);

  let reads = 0;
  const changed = mock({
    bloch_chainIdentity: () => ++reads === 1 ? { ...identity } : { ...identity, domain: `0x${"72".repeat(32)}` },
  });
  await assert.rejects(
    createBlochL2Wallet(changed, options).sendTransaction({ from: account }),
    /configured Bloch L2 identity/,
  );
  assert.ok(!changed.calls.some(call => call.method === "eth_sendTransaction"));
});

test("requires a fresh challenge-bound canonical status and cross-checks its selected block", async () => {
  const challenges = [];
  const provider = mock({ bloch_chainStatus: request => {
    challenges.push(request.params[0]);
    return {
      format: BLOCH_L2_STATUS_FORMAT,
      challenge: request.params[0],
      identity: { ...identity },
      headNumber: "0x0",
      headHash: genesisHash,
      stateRoot,
    };
  } });
  await createBlochL2Wallet(provider, options).connect();
  assert.equal(challenges.length, 2);
  assert.match(challenges[0], /^0x[0-9a-f]{64}$/);
  assert.notEqual(challenges[0], challenges[1]);

  for (const changed of [
    null,
    [],
    { format: BLOCH_L2_STATUS_FORMAT, challenge: `0x${"ff".repeat(32)}`, identity: { ...identity }, headNumber: "0x0", headHash: genesisHash, stateRoot },
    { format: "bloch-chain-status-v2", challenge: "dynamic", identity: { ...identity }, headNumber: "0x0", headHash: genesisHash, stateRoot },
    { format: BLOCH_L2_STATUS_FORMAT, challenge: "dynamic", identity: { ...identity }, headNumber: "0x00", headHash: genesisHash, stateRoot },
    { format: BLOCH_L2_STATUS_FORMAT, challenge: "dynamic", identity: { ...identity }, headNumber: "0x0", headHash: "0x1", stateRoot },
  ]) {
    const stale = mock({ bloch_chainStatus: request => changed && {
      ...changed,
      challenge: changed.challenge === "dynamic" ? request.params[0] : changed.challenge,
    } });
    await assert.rejects(createBlochL2Wallet(stale, options).connect(), /fresh canonical Bloch L2 status/);
    assert.ok(!stale.calls.some(call => call.method === "eth_requestAccounts"));
  }

  const mismatchedHead = mock({ eth_getBlockByNumber: request => request.params[0] === "0x0"
    ? { number: "0x0", hash: genesisHash, stateRoot: `0x${"32".repeat(32)}` }
    : null });
  await assert.rejects(createBlochL2Wallet(mismatchedHead, options).connect(), /status does not match/);
  assert.ok(!mismatchedHead.calls.some(call => call.method === "eth_requestAccounts"));

  let getterCalls = 0;
  const accessorHead = { number: "0x0", hash: genesisHash, stateRoot };
  Object.defineProperty(accessorHead, "stateRoot", {
    get() { getterCalls += 1; return stateRoot; },
    enumerable: true,
  });
  const accessorProvider = mock({ eth_getBlockByNumber: () => accessorHead });
  await assert.rejects(createBlochL2Wallet(accessorProvider, options).connect());
  assert.equal(getterCalls, 0);
});

test("rejects canonical head rollback and same-height equivocation within one wallet session", async () => {
  const headOne = `0x${"41".repeat(32)}`;
  const rootOne = `0x${"51".repeat(32)}`;
  let reads = 0;
  const rollback = mock({
    bloch_chainStatus: request => ++reads === 1 ? {
      format: BLOCH_L2_STATUS_FORMAT, challenge: request.params[0], identity: { ...identity },
      headNumber: "0x1", headHash: headOne, stateRoot: rootOne,
    } : {
      format: BLOCH_L2_STATUS_FORMAT, challenge: request.params[0], identity: { ...identity },
      headNumber: "0x0", headHash: genesisHash, stateRoot,
    },
    eth_getBlockByNumber: request => request.params[0] === "0x1"
      ? { number: "0x1", hash: headOne, stateRoot: rootOne }
      : { number: "0x0", hash: genesisHash, stateRoot },
  });
  await assert.rejects(createBlochL2Wallet(rollback, options).connect(), /rolled back/);

  const headTwo = `0x${"42".repeat(32)}`;
  const rootTwo = `0x${"52".repeat(32)}`;
  reads = 0;
  let selectedHash = headOne;
  let selectedRoot = rootOne;
  const equivocation = mock({
    bloch_chainStatus: request => {
      if (++reads === 2) {
        selectedHash = headTwo;
        selectedRoot = rootTwo;
      }
      return {
        format: BLOCH_L2_STATUS_FORMAT, challenge: request.params[0], identity: { ...identity },
        headNumber: "0x1", headHash: selectedHash, stateRoot: selectedRoot,
      };
    },
    eth_getBlockByNumber: request => request.params[0] === "0x1"
      ? { number: "0x1", hash: selectedHash, stateRoot: selectedRoot }
      : { number: "0x0", hash: genesisHash, stateRoot },
  });
  await assert.rejects(createBlochL2Wallet(equivocation, options).connect(), /equivocated/);
});

test("exports a verified checkpoint and imports it as a cross-session rollback floor", async () => {
  const headOne = `0x${"61".repeat(32)}`;
  const rootOne = `0x${"71".repeat(32)}`;
  const atOne = mock({
    bloch_chainStatus: request => ({
      format: BLOCH_L2_STATUS_FORMAT, challenge: request.params[0], identity: { ...identity },
      headNumber: "0x1", headHash: headOne, stateRoot: rootOne,
    }),
    eth_getBlockByNumber: request => request.params[0] === "0x1"
      ? { number: "0x1", hash: headOne, stateRoot: rootOne }
      : { number: "0x0", hash: genesisHash, stateRoot },
  });
  const first = createBlochL2Wallet(atOne, options);
  assert.equal(first.exportCheckpoint(), null);
  const session = await first.connect();
  const checkpoint = {
    format: BLOCH_L2_CHECKPOINT_FORMAT,
    headNumber: "0x1",
    headHash: headOne,
    stateRoot: rootOne,
  };
  assert.deepEqual(session.checkpoint, checkpoint);
  assert.deepEqual(first.exportCheckpoint(), checkpoint);
  assert.ok(Object.isFrozen(session.checkpoint));
  assert.ok(Object.isFrozen(first.exportCheckpoint()));

  const rollback = mock();
  const resumed = createBlochL2Wallet(rollback, { ...options, minimumCheckpoint: checkpoint });
  await assert.rejects(resumed.connect(), /rolled back/);
  assert.ok(!rollback.calls.some(call => call.method === "eth_requestAccounts"));

  const exact = createBlochL2Wallet(atOne, { ...options, minimumCheckpoint: checkpoint });
  assert.deepEqual((await exact.connect()).checkpoint, checkpoint);

  let getterCalls = 0;
  const accessor = { ...checkpoint };
  Object.defineProperty(accessor, "headHash", {
    get() { getterCalls += 1; return headOne; }, enumerable: true,
  });
  for (const invalid of [
    null, [], { ...checkpoint, format: "bloch-wallet-checkpoint-v2" },
    { ...checkpoint, headNumber: "0x01" }, { ...checkpoint, headHash: "0x1" },
    { ...checkpoint, extra: true }, accessor,
  ]) assert.throws(
    () => createBlochL2Wallet(mock(), { ...options, minimumCheckpoint: invalid }),
    /Invalid trusted Bloch L2 wallet checkpoint/,
  );
  assert.equal(getterCalls, 0);
});

test("loads and atomically advances a trusted checkpoint store before account access", async () => {
  const headOne = `0x${"61".repeat(32)}`;
  const rootOne = `0x${"71".repeat(32)}`;
  const checkpoint = Object.freeze({
    format: BLOCH_L2_CHECKPOINT_FORMAT,
    headNumber: "0x1",
    headHash: headOne,
    stateRoot: rootOne,
  });
  const events = [];
  const store = {
    async load(selectedIdentity) {
      events.push(["load", selectedIdentity]);
      return null;
    },
    async advance(selectedIdentity, previous, next) {
      events.push(["advance", selectedIdentity, previous, next]);
      return true;
    },
  };
  const provider = mock({
    bloch_chainStatus: request => ({
      format: BLOCH_L2_STATUS_FORMAT, challenge: request.params[0], identity: { ...identity },
      headNumber: "0x1", headHash: headOne, stateRoot: rootOne,
    }),
    eth_getBlockByNumber: request => request.params[0] === "0x1"
      ? { number: "0x1", hash: headOne, stateRoot: rootOne }
      : { number: "0x0", hash: genesisHash, stateRoot },
  });
  const originalRequest = provider.request;
  provider.request = async request => {
    assert.equal(events[0]?.[0], "load");
    return originalRequest(request);
  };
  const session = await createBlochL2Wallet(provider, {
    ...options, trustedCheckpointStore: store,
  }).connect();
  assert.equal(events.length, 2);
  assert.deepEqual(events[0][1], identity);
  assert.deepEqual(events[1][1], identity);
  assert.equal(events[1][2], null);
  assert.deepEqual(events[1][3], checkpoint);
  assert.ok(Object.isFrozen(events[1][3]));
  assert.deepEqual(session.checkpoint, checkpoint);
});

test("trusted checkpoint storage fails closed on rollback, malformed state or ambiguous advance", async () => {
  const headOne = `0x${"61".repeat(32)}`;
  const rootOne = `0x${"71".repeat(32)}`;
  const checkpoint = {
    format: BLOCH_L2_CHECKPOINT_FORMAT,
    headNumber: "0x1",
    headHash: headOne,
    stateRoot: rootOne,
  };
  for (const trustedCheckpointStore of [
    null, {}, { load() {}, advance: true }, { load: true, advance() {} },
  ]) assert.throws(
    () => createBlochL2Wallet(mock(), { ...options, trustedCheckpointStore }),
    /trusted checkpoint store/i,
  );

  let getterCalls = 0;
  const accessor = { ...checkpoint };
  Object.defineProperty(accessor, "stateRoot", {
    get() { getterCalls += 1; return rootOne; }, enumerable: true,
  });
  for (const loaded of [{ ...checkpoint, headNumber: "0x01" }, accessor]) {
    const provider = mock();
    const wallet = createBlochL2Wallet(provider, {
      ...options,
      trustedCheckpointStore: { load: async () => loaded, advance: async () => true },
    });
    await assert.rejects(wallet.connect(), /Invalid trusted Bloch L2 wallet checkpoint/);
    assert.equal(provider.calls.length, 0);
  }
  assert.equal(getterCalls, 0);

  const lower = { ...checkpoint, headNumber: "0x0", headHash: genesisHash, stateRoot };
  const rollbackProvider = mock();
  await assert.rejects(createBlochL2Wallet(rollbackProvider, {
    ...options,
    minimumCheckpoint: checkpoint,
    trustedCheckpointStore: { load: async () => lower, advance: async () => true },
  }).connect(), /store rolled back/);
  assert.ok(!rollbackProvider.calls.some(call => call.method === "eth_chainId"));

  for (const result of [false, undefined]) {
    const provider = mock();
    await assert.rejects(createBlochL2Wallet(provider, {
      ...options,
      trustedCheckpointStore: { load: async () => null, advance: async () => result },
    }).connect(), /did not durably advance/);
    assert.ok(!provider.calls.some(call => call.method === "eth_requestAccounts"));
  }
});

test("proves a higher canonical head retains the trusted checkpoint ancestry", async () => {
  const headOne = `0x${"61".repeat(32)}`;
  const rootOne = `0x${"71".repeat(32)}`;
  const headTwo = `0x${"62".repeat(32)}`;
  const rootTwo = `0x${"72".repeat(32)}`;
  const checkpoint = {
    format: BLOCH_L2_CHECKPOINT_FORMAT,
    headNumber: "0x1",
    headHash: headOne,
    stateRoot: rootOne,
  };
  const block = request => {
    if (request.params[0] === "0x0") return { number: "0x0", hash: genesisHash, stateRoot };
    if (request.params[0] === "0x1") return { number: "0x1", hash: headOne, stateRoot: rootOne };
    return { number: "0x2", hash: headTwo, stateRoot: rootTwo };
  };
  const status = request => ({
    format: BLOCH_L2_STATUS_FORMAT, challenge: request.params[0], identity: { ...identity },
    headNumber: "0x2", headHash: headTwo, stateRoot: rootTwo,
  });
  const provider = mock({ eth_getBlockByNumber: block, bloch_chainStatus: status });
  const session = await createBlochL2Wallet(provider, { ...options, minimumCheckpoint: checkpoint }).connect();
  assert.equal(session.checkpoint.headNumber, "0x2");
  assert.ok(provider.calls.some(call => call.method === "eth_getBlockByNumber" && call.params[0] === "0x1"));

  const foreign = mock({
    eth_getBlockByNumber: request => request.params[0] === "0x1"
      ? { number: "0x1", hash: `0x${"ff".repeat(32)}`, stateRoot: rootOne }
      : block(request),
    bloch_chainStatus: status,
  });
  await assert.rejects(
    createBlochL2Wallet(foreign, { ...options, minimumCheckpoint: checkpoint }).connect(),
    /does not descend from the trusted checkpoint/,
  );
  assert.ok(!foreign.calls.some(call => call.method === "eth_requestAccounts"));

  let statusReads = 0;
  const moving = mock({
    eth_getBlockByNumber: block,
    bloch_chainStatus: request => ++statusReads === 1 ? status(request) : {
      ...status(request), headNumber: "0x3", headHash: `0x${"63".repeat(32)}`,
    },
  });
  await assert.rejects(
    createBlochL2Wallet(moving, { ...options, minimumCheckpoint: checkpoint }).connect(),
    /changed while proving checkpoint ancestry/,
  );
  assert.ok(!moving.calls.some(call => call.method === "eth_requestAccounts"));
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

test("requires external finality for signing and verifies the exact fresh checkpoint", async () => {
  const withoutVerifier = mock();
  await assert.rejects(
    createBlochL2Wallet(withoutVerifier, {
      ...options, trustedFinalityVerifier: undefined,
    }).sendTransaction({ from: account }),
    /finality verifier is required/,
  );
  assert.equal(withoutVerifier.calls.length, 0);

  const verified = [];
  const provider = mock();
  await createBlochL2Wallet(provider, {
    ...options,
    trustedFinalityVerifier: { verify: async (selectedIdentity, checkpoint) => {
      verified.push([selectedIdentity, checkpoint]);
      return true;
    } },
  }).sendTransaction({ from: account });
  assert.equal(verified.length, 1);
  assert.deepEqual(verified[0][0], identity);
  assert.deepEqual(verified[0][1], {
    format: BLOCH_L2_CHECKPOINT_FORMAT,
    headNumber: "0x0",
    headHash: genesisHash,
    stateRoot,
  });
  assert.ok(Object.isFrozen(verified[0][0]));
  assert.ok(Object.isFrozen(verified[0][1]));

  for (const verify of [async () => false, async () => ({ verified: true }), async () => {
    throw new Error("offline");
  }]) {
    const rejected = mock();
    await assert.rejects(
      createBlochL2Wallet(rejected, {
        ...options, trustedFinalityVerifier: { verify },
      }).sendTransaction({ from: account }),
      /finality verification failed/,
    );
    assert.ok(!rejected.calls.some(call => call.method === "eth_sendTransaction"));
  }
});

test("verifies a pinned Ed25519 finality attestation for the exact checkpoint", async () => {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const publicKeyBase64Url = Buffer.from(rawPublicKey).toString("base64url");
  const finalityProtocol = "bloch-native-checkpoint-v1";
  const now = Math.floor(Date.now() / 1_000);
  const payload = {
    format: BLOCH_L2_FINALITY_ATTESTATION_FORMAT,
    identity: { ...identity },
    checkpoint: {
      format: BLOCH_L2_CHECKPOINT_FORMAT,
      headNumber: "0x0",
      headHash: genesisHash,
      stateRoot,
    },
    issuedAt: now,
    expiresAt: now + 300,
    finalityProtocol,
    finalityReference: `0x${"91".repeat(32)}`,
  };
  const signature = Buffer.from(await crypto.subtle.sign(
    { name: "Ed25519" }, keys.privateKey, blochL2FinalitySigningBytes(payload),
  )).toString("base64url");
  let request;
  let envelope;
  const verifier = await createEd25519FinalityVerifier({
    publicKeyBase64Url,
    finalityProtocol,
    getAttestation: async value => {
      request = value;
      return envelope;
    },
  });
  envelope = {
    format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT,
    keyId: verifier.keyId,
    payload,
    signature,
  };
  const provider = mock();
  await createBlochL2Wallet(provider, {
    ...options, trustedFinalityVerifier: verifier,
  }).sendTransaction({ from: account });
  assert.deepEqual({ ...request.identity }, identity);
  assert.deepEqual({ ...request.checkpoint }, payload.checkpoint);
  assert.equal(request.finalityProtocol, finalityProtocol);
  assert.equal(request.keyId, verifier.keyId);
  assert.ok(Object.isFrozen(request));
  assert.ok(provider.calls.some(call => call.method === "eth_sendTransaction"));
});

test("Ed25519 finality envelopes reject stale, foreign, malformed and tampered claims", async () => {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const publicKeyBase64Url = Buffer.from(rawPublicKey).toString("base64url");
  const finalityProtocol = "bloch-native-checkpoint-v1";
  const checkpoint = {
    format: BLOCH_L2_CHECKPOINT_FORMAT, headNumber: "0x0", headHash: genesisHash, stateRoot,
  };
  const signedEnvelope = async overrides => {
    const now = Math.floor(Date.now() / 1_000);
    const payload = {
      format: BLOCH_L2_FINALITY_ATTESTATION_FORMAT,
      identity: { ...identity }, checkpoint: { ...checkpoint }, issuedAt: now,
      expiresAt: now + 300, finalityProtocol, finalityReference: `0x${"92".repeat(32)}`,
      ...overrides,
    };
    const signature = Buffer.from(await crypto.subtle.sign(
      { name: "Ed25519" }, keys.privateKey, blochL2FinalitySigningBytes(payload),
    )).toString("base64url");
    return { payload, signature };
  };
  let envelope;
  const verifier = await createEd25519FinalityVerifier({
    publicKeyBase64Url, finalityProtocol, getAttestation: async () => envelope,
  });
  const verify = () => verifier.verify(identity, checkpoint);
  const staleNow = Math.floor(Date.now() / 1_000);
  let signed = await signedEnvelope({ issuedAt: staleNow - 600, expiresAt: staleNow - 300 });
  envelope = { format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT, keyId: verifier.keyId, ...signed };
  await assert.rejects(verify(), /not fresh/);

  signed = await signedEnvelope({ checkpoint: { ...checkpoint, headHash: `0x${"ff".repeat(32)}` } });
  envelope = { format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT, keyId: verifier.keyId, ...signed };
  await assert.rejects(verify(), /does not match/);

  signed = await signedEnvelope({});
  envelope = { format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT, keyId: verifier.keyId,
    ...signed, signature: `${signed.signature[0] === "A" ? "B" : "A"}${signed.signature.slice(1)}` };
  await assert.rejects(verify(), /signature verification failed/);
  envelope = { format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT, keyId: "00".repeat(32), ...signed };
  await assert.rejects(verify(), /untrusted key/);
  envelope = { format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT, keyId: verifier.keyId, ...signed, extra: true };
  await assert.rejects(verify(), /Invalid Bloch L2 finality envelope/);

  await assert.rejects(
    createEd25519FinalityVerifier({ publicKeyBase64Url: "bad", finalityProtocol, getAttestation() {} }),
    /Invalid Ed25519/,
  );
});

test("accepts transaction quantities exactly at the node field widths", async () => {
  const provider = mock();
  const wallet = createBlochL2Wallet(provider, options);
  await wallet.sendTransaction({
    from: account,
    type: "0x2",
    gas: `0x${"f".repeat(16)}`,
    nonce: `0x${"f".repeat(16)}`,
    maxFeePerGas: `0x${"f".repeat(32)}`,
    maxPriorityFeePerGas: `0x${"f".repeat(32)}`,
    value: `0x${"f".repeat(64)}`,
    data: `0x${"00".repeat(128 * 1024 - 256 - 62)}`,
    accessList: [{ address: account, storageKeys: [`0x${"00".repeat(32)}`] }],
  });
  assert.equal(provider.calls.at(-1).method, "eth_sendTransaction");
});

test("chain/account changes and unsupported authorization cannot reach signing", async () => {
  const provider = mock();
  const wallet = createBlochL2Wallet(provider, options);
  const symbolField = Symbol("provider-specific signing override");
  for (const tx of [
    { from: account, chainId: "0x1" }, { from: account, type: "0x4" },
    { from: account, authorizationList: [] }, { from: account, value: "0x01" },
    { from: account, value: `0x${"f".repeat(65)}` },
    { from: account, nonce: `0x1${"0".repeat(16)}` },
    { from: account, gas: `0x1${"0".repeat(16)}` },
    { from: account, gasPrice: `0x1${"0".repeat(32)}` },
    { from: account, maxFeePerGas: `0x1${"0".repeat(32)}` },
    { from: account, maxPriorityFeePerGas: `0x1${"0".repeat(32)}` },
    { from: account, data: "0x1" }, { from: `0x${"22".repeat(20)}` },
    { from: account, gasPrice: "0x1", maxFeePerGas: "0x2" },
    { from: account, type: "0x0", accessList: [] },
    { from: account, type: "0x1", maxFeePerGas: "0x2" },
    { from: account, type: "0x2", gasPrice: "0x1" },
    { from: account, maxFeePerGas: "0x1", maxPriorityFeePerGas: "0x2" },
    { from: account, [symbolField]: true },
  ]) await assert.rejects(wallet.sendTransaction(tx));
  assert.ok(!provider.calls.some(call => call.method === "eth_sendTransaction"));
  let reads = 0;
  const changed = mock({ eth_chainId: () => ++reads === 1 ? chainId : "0x1" });
  await assert.rejects(createBlochL2Wallet(changed, options).sendTransaction({ from: account }), /not connected/);
  assert.ok(!changed.calls.some(call => call.method === "eth_sendTransaction"));
  let genesisReads = 0;
  const changedGenesis = mock({
    eth_getBlockByNumber: () => ({
      number: "0x0",
      hash: ++genesisReads === 1 ? genesisHash : `0x${"24".repeat(32)}`,
    }),
  });
  await assert.rejects(
    createBlochL2Wallet(changedGenesis, options).sendTransaction({ from: account }),
    /configured Bloch L2 genesis|status does not match/,
  );
  assert.ok(!changedGenesis.calls.some(call => call.method === "eth_sendTransaction"));
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
    { from: account, data: `0x${"00".repeat(128 * 1024 - 255)}` },
    { from: account, accessList: Array(1025).fill({ address: account, storageKeys: [] }) },
    { from: account, accessList: [{ address: account, storageKeys: oversizedStorageKeys }] },
    { from: account, accessList: [{
      address: account, storageKeys: Array(3964).fill(`0x${"00".repeat(32)}`),
    }] },
  ]) await assert.rejects(wallet.sendTransaction(tx));
  assert.equal(oversizedStorageKeysInspected, false);

  const invalidHash = mock({ eth_sendTransaction: () => "0x01" });
  await assert.rejects(createBlochL2Wallet(invalidHash, options).sendTransaction({ from: account }), /invalid transaction hash/);

  const oversizedAuthorizedAccount = mock({ eth_accounts: () => ["A".repeat(1_000_000)] });
  await assert.rejects(
    createBlochL2Wallet(oversizedAuthorizedAccount, options).sendTransaction({ from: account }),
    /not an authorized/,
  );
  assert.ok(!oversizedAuthorizedAccount.calls.some(call => call.method === "eth_sendTransaction"));
});

test("does not trust array instance methods or iterators from provider data", async () => {
  const deceptiveConnectAccounts = [{}];
  deceptiveConnectAccounts.some = () => false;
  deceptiveConnectAccounts[Symbol.iterator] = function* () { yield account; };
  const connectProvider = mock({ eth_requestAccounts: () => deceptiveConnectAccounts });
  await assert.rejects(createBlochL2Wallet(connectProvider, options).connect(), /valid Ethereum accounts/);
  const sparseConnectProvider = mock({ eth_requestAccounts: () => Array(1) });
  await assert.rejects(createBlochL2Wallet(sparseConnectProvider, options).connect(), /valid Ethereum accounts/);

  const deceptiveAuthorizedAccounts = [`0x${"22".repeat(20)}`];
  deceptiveAuthorizedAccounts.some = () => true;
  const authorizationProvider = mock({ eth_accounts: () => deceptiveAuthorizedAccounts });
  await assert.rejects(createBlochL2Wallet(authorizationProvider, options).sendTransaction({ from: account }), /not an authorized/);
  assert.ok(!authorizationProvider.calls.some(call => call.method === "eth_sendTransaction"));

  const storageKeys = ["not-a-storage-key"];
  storageKeys.some = () => false;
  const accessList = [{ address: account, storageKeys }];
  accessList.map = () => [];
  await assert.rejects(createBlochL2Wallet(mock(), options).sendTransaction({ from: account, accessList }), /Invalid access list entry/);
  await assert.rejects(createBlochL2Wallet(mock(), options).sendTransaction({ from: account, accessList: Array(1) }), /Invalid access list entry/);
  await assert.rejects(createBlochL2Wallet(mock(), options).sendTransaction({
    from: account, accessList: [{ address: account, storageKeys: Array(1) }],
  }), /Invalid access list entry/);
});

test("snapshots collection lengths before validating and copying", async () => {
  let accessLengthReads = 0;
  let keyLengthReads = 0;
  const storageKeys = new Proxy([`0x${"00".repeat(32)}`], { get(target, key, receiver) {
    if (key === "length") { keyLengthReads += 1; return keyLengthReads === 1 ? 1 : 1_000_000; }
    return Reflect.get(target, key, receiver);
  } });
  const accessList = new Proxy([{ address: account, storageKeys }], { get(target, key, receiver) {
    if (key === "length") { accessLengthReads += 1; return accessLengthReads === 1 ? 1 : 1_000_000; }
    return Reflect.get(target, key, receiver);
  } });
  await createBlochL2Wallet(mock(), options).sendTransaction({ from: account, accessList });
  assert.equal(accessLengthReads, 1);
  assert.equal(keyLengthReads, 1);
});

test("keeps all requests on the provider implementation selected at construction", async () => {
  const provider = mock();
  provider.request.bind = () => async () => { throw new Error("instance bind hook ran"); };
  const wallet = createBlochL2Wallet(provider, options);
  provider.request = async () => { throw new Error("replacement request method ran"); };
  const session = await wallet.connect();
  assert.deepEqual(session.accounts, [account]);
  await wallet.sendTransaction({ from: account });
  assert.ok(provider.calls.some(call => call.method === "eth_sendTransaction"));
});
