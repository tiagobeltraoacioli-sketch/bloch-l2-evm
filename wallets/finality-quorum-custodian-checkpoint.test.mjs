// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile }
  from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
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
const execute = promisify(execFile);

function supportsModuleRegister(version) {
  const match = /^(\d+)\.(\d+)\./.exec(version);
  if (!match) return false;
  const major = Number(match[1]), minor = Number(match[2]);
  return major >= 21 || major === 20 && minor >= 6 || major === 18 && minor >= 19;
}

function checkpointRaceLoaderArguments() {
  if (supportsModuleRegister(process.versions.node)) {
    const registerLoader = new URL("./fixtures/register-custodian-checkpoint-race-loader.mjs",
      import.meta.url);
    return ["--import", registerLoader.href];
  }
  const loader = new URL("./fixtures/custodian-checkpoint-race-loader.mjs", import.meta.url);
  return ["--experimental-loader", loader.href];
}

function authentication() {
  return { key: new Uint8Array(32).fill(0x41), clientId: "wallet-finality",
    custodianId: "independent-finality" };
}

function initial() {
  return createInitialFinalityCustodianCheckpoint({ clientId: "wallet-finality",
    custodianId: "independent-finality", session: Buffer.alloc(32, 0x71).toString("base64url") });
}

function memoryAnchor(value, beforeCommit = null) {
  let current = value, mode = "normal";
  return { get current() { return current; }, set mode(value) { mode = value; },
    async load() { return current; },
    async compareAndSwap(expected, replacement) {
      if (mode === "throw") throw new Error("anchor unavailable");
      if (mode === "uncertain") return { status: "uncertain" };
      if (mode === "conflict" || current !== expected) return { status: "conflict", currentStateHash: current };
      await beforeCommit?.();
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
  const ambiguousNames = await readdir(ambiguous.root);
  assert.ok(ambiguousNames.some(name => name.startsWith("client.json.tmp-")));
  assert.ok(ambiguousNames.some(name => name.startsWith("client.json.previous-")));
});

test("anchor commit cannot overwrite a substituted predecessor", async t => {
  const f = await fixture(t), displaced = `${f.storePath}.displaced`;
  const original = await readFile(f.storePath);
  let calls = 0;
  const anchor = memoryAnchor(f.checkpoint.stateHash, async () => {
    await rename(f.storePath, displaced);
    await writeFile(f.storePath, original, { mode: 0o600, flag: "wx" });
  });
  const client = await createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: f.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange() { calls += 1; } }, anchor });
  await assert.rejects(client.load(), /requires inspection/);
  assert.equal(calls, 0);
  assert.deepEqual(await readFile(displaced), original);
  assert.deepEqual(await readFile(f.storePath), original);
  const names = await readdir(f.root);
  assert.ok(names.some(name => name.startsWith("client.json.tmp-")));
  assert.ok(names.some(name => name.startsWith("client.json.previous-")));
});

test("anchor commit cannot mutate through a replaced lock pathname", async t => {
  const f = await fixture(t), displaced = `${f.storePath}.lock.displaced`;
  let calls = 0;
  const anchor = memoryAnchor(f.checkpoint.stateHash, async () => {
    await rename(`${f.storePath}.lock`, displaced);
    await writeFile(`${f.storePath}.lock`, "replacement lock\n", { mode: 0o600, flag: "wx" });
  });
  const client = await createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: f.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange() { calls += 1; } }, anchor });
  await assert.rejects(client.load(), /requires inspection/);
  assert.equal(calls, 0);
  const names = await readdir(f.root);
  assert.ok(names.includes("client.json"));
  assert.ok(names.includes("client.json.lock"));
  assert.ok(names.includes("client.json.lock.displaced"));
  assert.ok(names.some(name => name.startsWith("client.json.tmp-")));
  assert.ok(names.some(name => name.startsWith("client.json.previous-")));
});

test("anchor commit cannot mutate through a displaced checkpoint directory", async t => {
  const f = await fixture(t), moved = `${f.root}.displaced`;
  t.after(() => rm(moved, { recursive: true, force: true }));
  let calls = 0;
  const anchor = memoryAnchor(f.checkpoint.stateHash, async () => {
    await rename(f.root, moved);
    await mkdir(f.root, { mode: 0o700 });
  });
  const client = await createFilesystemFinalityCustodian({ storePath: f.storePath,
    expectedStateHash: f.checkpoint.stateHash, authentication: authentication(),
    transport: { async exchange() { calls += 1; } }, anchor });
  await assert.rejects(client.load(), /requires inspection/);
  assert.equal(calls, 0);
  assert.deepEqual(await readdir(f.root), []);
  const names = await readdir(moved);
  assert.ok(names.includes("client.json"));
  assert.ok(names.includes("client.json.lock"));
  assert.ok(names.some(name => name.startsWith("client.json.tmp-")));
  assert.ok(names.some(name => name.startsWith("client.json.previous-")));
});

test("anchor commit cannot overwrite a final-window checkpoint substitution", async t => {
  const f = await fixture(t);
  const runner = new URL("./fixtures/mutate-custodian-checkpoint.mjs", import.meta.url);
  const result = await execute(process.execPath,
    [...checkpointRaceLoaderArguments(), fileURLToPath(runner), f.storePath], {
      env: { ...process.env, BLOCH_CHECKPOINT_RACE_TARGET: f.storePath,
        BLOCH_CHECKPOINT_RACE_ATTACK: "post-rename-pathname-replacement" },
      timeout: 10_000, killSignal: "SIGKILL", maxBuffer: 64 * 1024,
    });
  assert.equal(result.stdout, "rejected final-window checkpoint substitution\n");
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

for (const attack of ["same-inode-rewrite", "pathname-replacement", "parent-directory-replacement",
  "parent-directory-metadata-change", "growth", "post-read-parent-directory-replacement"]) {
  test(`client checkpoint rejects ${attack} during its bounded pinned read`, async t => {
    const f = await fixture(t);
    if (["parent-directory-replacement", "post-read-parent-directory-replacement"].includes(attack)) {
      t.after(() => rm(`${f.root}.race-moved`, { recursive: true, force: true }));
    }
    const runner = new URL("./fixtures/inspect-custodian-checkpoint.mjs", import.meta.url);
    const result = await execute(process.execPath,
      [...checkpointRaceLoaderArguments(), fileURLToPath(runner), f.storePath], {
        env: { ...process.env, BLOCH_CHECKPOINT_RACE_TARGET: f.storePath,
          BLOCH_CHECKPOINT_RACE_ATTACK: attack },
        timeout: 10_000,
        killSignal: "SIGKILL",
        maxBuffer: 64 * 1024,
      });
    assert.equal(result.stdout, "rejected custodian checkpoint mutation\n");
  });
}

test("client startup binds checkpoint and lock inspection to one directory snapshot", async t => {
  const f = await fixture(t);
  t.after(() => rm(`${f.root}.race-moved`, { recursive: true, force: true }));
  const runner = new URL("./fixtures/open-custodian-checkpoint.mjs", import.meta.url);
  const result = await execute(process.execPath,
    [...checkpointRaceLoaderArguments(), fileURLToPath(runner), f.storePath, f.checkpoint.stateHash], {
      env: { ...process.env, BLOCH_CHECKPOINT_RACE_TARGET: f.storePath,
        BLOCH_CHECKPOINT_RACE_ATTACK: "post-read-parent-directory-replacement" },
      timeout: 10_000,
      killSignal: "SIGKILL",
      maxBuffer: 64 * 1024,
    });
  assert.equal(result.stdout, "rejected custodian checkpoint startup race\n");
});

test("client startup revalidates checkpoint and lock after independent anchor I/O", async t => {
  const locked = await fixture(t);
  await assert.rejects(createFilesystemFinalityCustodian({ storePath: locked.storePath,
    expectedStateHash: locked.checkpoint.stateHash, authentication: authentication(),
    transport: transport(memoryCustody()), anchor: {
      async load() {
        await writeFile(`${locked.storePath}.lock`, "raced\n", { mode: 0o600, flag: "wx" });
        return locked.checkpoint.stateHash;
      },
      async compareAndSwap() { throw new Error("unexpected anchor mutation"); },
    } }), /changed during independent anchor verification/);

  const replaced = await fixture(t), bytes = await readFile(replaced.storePath);
  await assert.rejects(createFilesystemFinalityCustodian({ storePath: replaced.storePath,
    expectedStateHash: replaced.checkpoint.stateHash, authentication: authentication(),
    transport: transport(memoryCustody()), anchor: {
      async load() {
        await rename(replaced.storePath, `${replaced.storePath}.during-anchor`);
        await writeFile(replaced.storePath, bytes, { mode: 0o600, flag: "wx" });
        return replaced.checkpoint.stateHash;
      },
      async compareAndSwap() { throw new Error("unexpected anchor mutation"); },
    } }), /changed during independent anchor verification/);

  const rewritten = await fixture(t), rewrittenBytes = await readFile(rewritten.storePath);
  await assert.rejects(createFilesystemFinalityCustodian({ storePath: rewritten.storePath,
    expectedStateHash: rewritten.checkpoint.stateHash, authentication: authentication(),
    transport: transport(memoryCustody()), anchor: {
      async load() {
        await writeFile(rewritten.storePath, rewrittenBytes, { flag: "r+" });
        return rewritten.checkpoint.stateHash;
      },
      async compareAndSwap() { throw new Error("unexpected anchor mutation"); },
    } }), /changed during independent anchor verification/);
});
