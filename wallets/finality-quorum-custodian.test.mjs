// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  AuthenticatedFinalityQuorumCustodian,
  AuthenticatedFinalityQuorumCustodianServer,
  BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES,
} from "./finality-quorum-custodian.mjs";
import { advanceCustodiedFinalityQuorumCheckpoint } from "./finality-quorum-checkpoint.mjs";

const HASH_A = "a".repeat(64), HASH_B = "b".repeat(64), HASH_C = "c".repeat(64);

function authentication(byte = 0x41) {
  return { key: new Uint8Array(32).fill(byte), clientId: "wallet-finality",
    custodianId: "independent-finality" };
}

function checkpoint(nextSequence = "0") {
  return { session: Buffer.alloc(32, 0x71).toString("base64url"), nextSequence };
}

function memoryStore(initial = null) {
  let current = initial, casCalls = 0, loadCalls = 0, mode = "normal";
  return {
    get current() { return current; }, get casCalls() { return casCalls; },
    get loadCalls() { return loadCalls; }, set mode(value) { mode = value; },
    async load() { loadCalls += 1; return current; },
    async compareAndSwap(expected, replacement) {
      casCalls += 1;
      if (mode === "uncertain") return { status: "uncertain" };
      if (mode === "race") { current = HASH_C; return { status: "conflict", currentStateHash: current }; }
      if (current !== expected) return { status: "conflict", currentStateHash: current };
      current = replacement;
      return { status: "committed" };
    },
  };
}

function pair(store, transportFactory = server => ({ exchange: bytes => server.handle(bytes) })) {
  const server = new AuthenticatedFinalityQuorumCustodianServer({ authentication: authentication(), store });
  const transport = transportFactory(server);
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(), transport,
    checkpoint: checkpoint() });
  return { client, server, transport };
}

test("authenticated custodian integrates with external-first L2 checkpoint commit", async t => {
  const directory = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = memoryStore(), { client } = pair(store), statePath = join(directory, "state.json");
  const state = await advanceCustodiedFinalityQuorumCheckpoint({ storePath: statePath,
    expectedStateHash: null, quorumId: HASH_A, threshold: 2,
    finalityProtocol: "bloch-native-checkpoint-v1",
    identity: { format: "bloch-chain-identity-v1", chainId: "0xab163", domain: `0x${"71".repeat(32)}`,
      genesisHash: `0x${"42".repeat(32)}`, headerFormat: "bloch-node-header-v2-fixed-width" },
    checkpoint: { format: "bloch-wallet-checkpoint-v1", headNumber: "0x2",
      headHash: `0x${"62".repeat(32)}`, stateRoot: `0x${"72".repeat(32)}` },
    bundleHash: HASH_B, custodian: client });
  assert.equal(store.current, state.stateHash);
  assert.equal(JSON.parse(await readFile(statePath, "utf8")).stateHash, state.stateHash);
  assert.deepEqual(client.checkpoint(), { session: checkpoint().session, nextSequence: "3" });
  client.close();
  await assert.rejects(client.load(), /closed/);
});

test("exact duplicate delivery is idempotent and executes one backing CAS", async () => {
  const store = memoryStore(null);
  const { client } = pair(store, server => ({ async exchange(bytes) {
    await server.handle(bytes);
    return server.handle(bytes);
  } }));
  assert.deepEqual(await client.compareAndSwap(null, HASH_A), { status: "committed" });
  assert.equal(store.current, HASH_A);
  assert.equal(store.casCalls, 1);
});

test("tamper, replay and wrong keys fail while consuming the request sequence", async () => {
  const store = memoryStore(null), base = new AuthenticatedFinalityQuorumCustodianServer({
    authentication: authentication(), store });
  const tampered = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(),
    checkpoint: checkpoint(), transport: { async exchange(bytes) {
      const response = Buffer.from(await base.handle(bytes)); response[response.length - 3] ^= 1; return response;
    } } });
  await assert.rejects(tampered.load());
  assert.equal(tampered.checkpoint().nextSequence, "1");

  let cached;
  const replayed = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(),
    checkpoint: checkpoint("8"), transport: { async exchange(bytes) {
      if (!cached) cached = await base.handle(bytes);
      return cached;
    } } });
  assert.equal(await replayed.load(), null);
  await assert.rejects(replayed.load(), /does not match/);
  assert.equal(replayed.checkpoint().nextSequence, "10");

  const wrong = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(0x42),
    checkpoint: checkpoint(), transport: { exchange: bytes => base.handle(bytes) } });
  await assert.rejects(wrong.load(), /authentication failed/);
  assert.equal(wrong.checkpoint().nextSequence, "1");
});

test("bounded malformed requests never touch the backing store", async () => {
  const store = memoryStore(null), server = new AuthenticatedFinalityQuorumCustodianServer({
    authentication: authentication(), store });
  for (const length of [0, 1, 2, 31, 255, 1024, BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES,
    BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES + 1]) {
    await assert.rejects(server.handle(Buffer.alloc(length, 0x41)));
  }
  assert.equal(store.loadCalls, 0);
  assert.equal(store.casCalls, 0);
});

test("conflict and uncertainty are authenticated without retry", async () => {
  const conflicting = memoryStore(null); conflicting.mode = "race";
  const conflictClient = pair(conflicting).client;
  assert.deepEqual(await conflictClient.compareAndSwap(null, HASH_A),
    { status: "conflict", currentStateHash: HASH_C });
  assert.equal(conflicting.casCalls, 1);

  const uncertain = memoryStore(null); uncertain.mode = "uncertain";
  const uncertainClient = pair(uncertain).client;
  assert.deepEqual(await uncertainClient.compareAndSwap(null, HASH_A), { status: "uncertain" });
  assert.equal(uncertain.casCalls, 1);
  assert.equal(uncertainClient.checkpoint().nextSequence, "1");
});

test("invalid transitions and exhausted checkpoints fail before transport", async () => {
  let calls = 0;
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(),
    checkpoint: checkpoint(), transport: { async exchange() { calls += 1; throw new Error("unexpected"); } } });
  await assert.rejects(client.compareAndSwap(HASH_A, HASH_A), /not an advance/);
  assert.equal(calls, 0);
  assert.equal(client.checkpoint().nextSequence, "0");

  const exhausted = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(),
    checkpoint: checkpoint("18446744073709551615"), transport: { async exchange() { calls += 1; } } });
  await assert.rejects(exhausted.load(), /exhausted/);
  assert.equal(calls, 0);
});
