// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { chmod, link, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFilesystemFinalityCustodianStore,
  createInitialFinalityCustodianStoreRecord,
  initializeFilesystemFinalityCustodianStore,
  inspectFilesystemFinalityCustodianStore,
} from "./finality-quorum-custodian-store.mjs";

const HASH_A = "a".repeat(64), HASH_B = "b".repeat(64);

async function fixture(t, stateHash = null) {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-store-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const storePath = join(root, "store.json");
  const record = createInitialFinalityCustodianStoreRecord({ stateHash });
  await initializeFilesystemFinalityCustodianStore({ storePath, record,
    expectedRecordHash: record.recordHash });
  return { root, storePath, record };
}

test("durable custodian store advances atomically and survives restart", async t => {
  const f = await fixture(t);
  let store = await createFilesystemFinalityCustodianStore({ storePath: f.storePath,
    expectedRecordHash: f.record.recordHash });
  assert.equal(await store.load(), null);
  assert.deepEqual(await store.compareAndSwap(null, HASH_A), { status: "committed" });
  const first = store.record();
  assert.equal(first.generation, "1");
  assert.equal(first.previousRecordHash, f.record.recordHash);
  store = await createFilesystemFinalityCustodianStore({ storePath: f.storePath,
    expectedRecordHash: first.recordHash });
  assert.equal(await store.load(), HASH_A);
  assert.deepEqual(await store.compareAndSwap(HASH_A, HASH_B), { status: "committed" });
  assert.equal((await inspectFilesystemFinalityCustodianStore(f.storePath)).stateHash, HASH_B);
});

test("store refuses TOFU, rollback, conflict and concurrent instances", async t => {
  const f = await fixture(t, HASH_A);
  await assert.rejects(initializeFilesystemFinalityCustodianStore({ storePath: join(f.root, "tofu.json"),
    record: f.record, expectedRecordHash: "0".repeat(64) }), /externally approved/);
  await assert.rejects(createFilesystemFinalityCustodianStore({ storePath: f.storePath,
    expectedRecordHash: "0".repeat(64) }), /externally retained/);
  const first = await createFilesystemFinalityCustodianStore({ storePath: f.storePath,
    expectedRecordHash: f.record.recordHash });
  const stale = await createFilesystemFinalityCustodianStore({ storePath: f.storePath,
    expectedRecordHash: f.record.recordHash });
  assert.deepEqual(await first.compareAndSwap(HASH_B, "c".repeat(64)),
    { status: "conflict", currentStateHash: HASH_A });
  await first.compareAndSwap(HASH_A, HASH_B);
  await assert.rejects(stale.compareAndSwap(HASH_A, "c".repeat(64)), /outside this process/);
});

test("store rejects corruption, exposed files, links and orphan locks", async t => {
  const exposed = await fixture(t);
  await chmod(exposed.storePath, 0o644);
  await assert.rejects(inspectFilesystemFinalityCustodianStore(exposed.storePath), /file is unsafe/);

  const linked = await fixture(t);
  const hardlink = join(linked.root, "hardlink.json");
  await link(linked.storePath, hardlink);
  await assert.rejects(inspectFilesystemFinalityCustodianStore(linked.storePath), /file is unsafe/);
  await rm(hardlink);
  const symlinkPath = join(linked.root, "symlink.json");
  await symlink(linked.storePath, symlinkPath);
  await assert.rejects(inspectFilesystemFinalityCustodianStore(symlinkPath));

  const locked = await fixture(t);
  await writeFile(`${locked.storePath}.lock`, "orphan\n", { mode: 0o600, flag: "wx" });
  const inspected = await inspectFilesystemFinalityCustodianStore(locked.storePath);
  assert.equal(inspected.lockPresent, true);
  await assert.rejects(createFilesystemFinalityCustodianStore({ storePath: locked.storePath,
    expectedRecordHash: locked.record.recordHash }), /locked/);

  const corrupt = await fixture(t);
  await writeFile(corrupt.storePath, "{}\n", { mode: 0o600 });
  await assert.rejects(inspectFilesystemFinalityCustodianStore(corrupt.storePath), /record is invalid/);
});
