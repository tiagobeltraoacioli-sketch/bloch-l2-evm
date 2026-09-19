// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { chmod, link, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthenticatedFinalityQuorumCustodianServer,
} from "./finality-quorum-custodian.mjs";
import {
  createFilesystemFinalityCustodian,
  createInitialFinalityCustodianCheckpoint,
  initializeFinalityCustodianCheckpoint,
  inspectFinalityCustodianCheckpoint,
} from "./finality-quorum-custodian-checkpoint.mjs";

const HASH_A = "a".repeat(64), HASH_B = "b".repeat(64);

function authentication() {
  return { key: new Uint8Array(32).fill(0x41), clientId: "wallet-finality",
    custodianId: "independent-finality" };
}

function initial() {
  return createInitialFinalityCustodianCheckpoint({ clientId: "wallet-finality",
    custodianId: "independent-finality", session: Buffer.alloc(32, 0x71).toString("base64url") });
}

function memoryAnchor(value) {
  let current = value, mode = "normal";
  return { get current() { return current; }, set mode(value) { mode = value; },
    async load() { return current; },
    async compareAndSwap(expected, replacement) {
      if (mode === "throw") throw new Error("anchor unavailable");
      if (mode === "uncertain") return { status: "uncertain" };
      if (mode === "conflict" || current !== expected) return { status: "conflict", currentStateHash: current };
      current = replacement;
      return { status: "committed" };
    } };
}

function memoryCustody(initialState = null) {
  let current = initialState, mode = "normal", calls = 0;
  return { get current() { return current; }, get calls() { return calls; }, set mode(value) { mode = value; },
    async load() { return current; },
    async compareAndSwap(expected, replacement) {
      calls += 1;
      if (mode === "uncertain") return { status: "uncertain" };
      if (current !== expected) return { status: "conflict", currentStateHash: current };
      current = replacement;
      return { status: "committed" };
    } };
}

function transport(store) {
  const server = new AuthenticatedFinalityQuorumCustodianServer({ authentication: authentication(), store });
  return { exchange: frame => server.handle(frame) };
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-checkpoint-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const checkpoint = initial(), storePath = join(root, "client.json");
  await initializeFinalityCustodianCheckpoint({ storePath, checkpoint,
    expectedStateHash: checkpoint.stateHash });
  return { root, checkpoint, storePath };
}

test("durable lifecycle anchors consumed sequence before I/O and survives restart", async t => {
  const f = await fixture(t), anchor = memoryAnchor(f.checkpoint.stateHash), custody = memoryCustody();
  let observedPending = false;
  const base = transport(custody);
  const guarded = { async exchange(frame) {
    const retained = await inspectFinalityCustodianCheckpoint(f.storePath);
    observedPending = retained.status === "pending" && anchor.current === retained.stateHash;
    return base.exchange(frame);
  } };
  let client = await createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: f.checkpoint.stateHash, authentication: authentication(), transport: guarded, anchor });
  assert.equal(await client.load(), null);
  assert.equal(observedPending, true);
  assert.deepEqual(await client.compareAndSwap(null, HASH_A), { status: "committed" });
  const retained = await inspectFinalityCustodianCheckpoint(f.storePath);
  assert.equal(retained.status, "ready");
  assert.equal(retained.nextSequence, "2");
  assert.equal(retained.generation, "4");
  assert.equal(anchor.current, retained.stateHash);
  client.close();

  client = await createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: retained.stateHash, authentication: authentication(), transport: base, anchor });
  assert.equal(await client.load(), HASH_A);
  assert.equal(client.checkpoint().nextSequence, "3");
});

test("transport failure and authenticated uncertainty retain pending state across restart", async t => {
  const first = await fixture(t), firstAnchor = memoryAnchor(first.checkpoint.stateHash);
  const failed = await createFilesystemFinalityCustodian({ storePath: first.storePath,
    expectedStateHash: first.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange() { throw new Error("connection lost"); } }, anchor: firstAnchor });
  await assert.rejects(failed.load(), /connection lost/);
  const pending = await inspectFinalityCustodianCheckpoint(first.storePath);
  assert.equal(pending.status, "pending");
  assert.equal(pending.nextSequence, "1");
  assert.equal(firstAnchor.current, pending.stateHash);
  await assert.rejects(createFilesystemFinalityCustodian({ storePath: first.storePath,
    expectedStateHash: pending.stateHash, authentication: authentication(), transport: {}, anchor: firstAnchor }),
  /unresolved pending/);

  const second = await fixture(t), secondAnchor = memoryAnchor(second.checkpoint.stateHash);
  const custody = memoryCustody(); custody.mode = "uncertain";
  const uncertain = await createFilesystemFinalityCustodian({ storePath: second.storePath,
    expectedStateHash: second.checkpoint.stateHash, authentication: authentication(),
    transport: transport(custody), anchor: secondAnchor });
  assert.deepEqual(await uncertain.compareAndSwap(null, HASH_B), { status: "uncertain" });
  assert.equal((await inspectFinalityCustodianCheckpoint(second.storePath)).status, "pending");
});

test("anchor failure occurs before transport and ambiguous anchor outcome retains the lock", async t => {
  const definite = await fixture(t), definiteAnchor = memoryAnchor(definite.checkpoint.stateHash);
  definiteAnchor.mode = "conflict";
  let calls = 0;
  const client = await createFilesystemFinalityCustodian({ storePath: definite.storePath,
    expectedStateHash: definite.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange() { calls += 1; } }, anchor: definiteAnchor });
  await assert.rejects(client.load(), /CAS conflict/);
  assert.equal(calls, 0);
  assert.equal((await inspectFinalityCustodianCheckpoint(definite.storePath)).lockPresent, false);

  const ambiguous = await fixture(t), ambiguousAnchor = memoryAnchor(ambiguous.checkpoint.stateHash);
  ambiguousAnchor.mode = "throw";
  const blocked = await createFilesystemFinalityCustodian({ storePath: ambiguous.storePath,
    expectedStateHash: ambiguous.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange() { calls += 1; } }, anchor: ambiguousAnchor });
  await assert.rejects(blocked.load(), /requires inspection/);
  assert.equal(calls, 0);
  assert.equal((await inspectFinalityCustodianCheckpoint(ambiguous.storePath)).lockPresent, true);
});

test("rollback, concurrent exchange, unsafe files, links and TOFU fail closed", async t => {
  const f = await fixture(t), anchor = memoryAnchor(f.checkpoint.stateHash), custody = memoryCustody();
  await assert.rejects(createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: "0".repeat(64), authentication: authentication(), transport: transport(custody), anchor }),
  /independent anchor/);
  await assert.rejects(initializeFinalityCustodianCheckpoint({ storePath: join(f.root, "tofu.json"),
    checkpoint: f.checkpoint, expectedStateHash: "0".repeat(64) }), /externally approved/);

  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const base = transport(custody);
  const client = await createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: f.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange(frame) { await gate; return base.exchange(frame); } }, anchor });
  const inFlight = client.load();
  await assert.rejects(client.load(), /already has an exchange/);
  release(); await inFlight;

  const retained = await inspectFinalityCustodianCheckpoint(f.storePath);
  await chmod(f.storePath, 0o644);
  await assert.rejects(inspectFinalityCustodianCheckpoint(f.storePath), /file is unsafe/);
  await chmod(f.storePath, 0o600);
  const hardlink = join(f.root, "hardlink.json"); await link(f.storePath, hardlink);
  await assert.rejects(inspectFinalityCustodianCheckpoint(f.storePath), /file is unsafe/);
  await rm(hardlink);
  const symlinkPath = join(f.root, "symlink.json"); await symlink(f.storePath, symlinkPath);
  await assert.rejects(inspectFinalityCustodianCheckpoint(symlinkPath));
  assert.equal(retained.status, "ready");
});
