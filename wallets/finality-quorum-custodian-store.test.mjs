// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, link, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  approveFinalityCustodianStoreRecord,
  assembleFinalityCustodianStoreContinuity,
  createApprovedFilesystemFinalityCustodianStore,
  createContinuityApprovedFilesystemFinalityCustodianStore,
  createFilesystemFinalityCustodianStore,
  createFinalityCustodianStoreContinuityTransition,
  createInitialFinalityCustodianStoreRecord,
  initializeApprovedFilesystemFinalityCustodianStore,
  initializeFilesystemFinalityCustodianStore,
  inspectFilesystemFinalityCustodianStore,
  signFinalityCustodianStoreContinuity,
} from "./finality-quorum-custodian-store.mjs";

const HASH_A = "a".repeat(64), HASH_B = "b".repeat(64);
const DEPLOYMENT = "d".repeat(64);

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
  await assert.rejects(stale.load(), /outside this process/);
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

  const live = await fixture(t);
  const store = await createFilesystemFinalityCustodianStore({ storePath: live.storePath,
    expectedRecordHash: live.record.recordHash });
  await writeFile(`${live.storePath}.lock`, "held\n", { mode: 0o600, flag: "wx" });
  await assert.rejects(store.load(), /locked/);
  await rm(`${live.storePath}.lock`);

  const corrupt = await fixture(t);
  await writeFile(corrupt.storePath, "{}\n", { mode: 0o600 });
  await assert.rejects(inspectFilesystemFinalityCustodianStore(corrupt.storePath), /record is invalid/);
});

test("offline approval binds deployment, authority and exact store record", async t => {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-approved-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const storePath = join(root, "store.json"), record = createInitialFinalityCustodianStoreRecord();
  const authority = generateKeyPairSync("ed25519"), other = generateKeyPairSync("ed25519");
  const approval = approveFinalityCustodianStoreRecord({ deploymentId: DEPLOYMENT, record,
    privateKey: authority.privateKey });
  await initializeApprovedFilesystemFinalityCustodianStore({ storePath, approval,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: authority.publicKey });
  let store = await createApprovedFilesystemFinalityCustodianStore({ storePath, approval,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: authority.publicKey });
  assert.equal(await store.load(), null);
  await assert.rejects(createApprovedFilesystemFinalityCustodianStore({ storePath, approval,
    expectedDeploymentId: "e".repeat(64), authorityPublicKey: authority.publicKey }), /approval/);
  await assert.rejects(createApprovedFilesystemFinalityCustodianStore({ storePath, approval,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: other.publicKey }), /signature/);
  const tampered = { ...approval, record: { ...approval.record, stateHash: HASH_A } };
  await assert.rejects(createApprovedFilesystemFinalityCustodianStore({ storePath, approval: tampered,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: authority.publicKey }), /record|signature/);

  await store.compareAndSwap(null, HASH_A);
  const current = store.record();
  await assert.rejects(createApprovedFilesystemFinalityCustodianStore({ storePath, approval,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: authority.publicKey }), /externally retained/);
  const currentApproval = approveFinalityCustodianStoreRecord({ deploymentId: DEPLOYMENT,
    record: current, privateKey: authority.privateKey });
  store = await createApprovedFilesystemFinalityCustodianStore({ storePath,
    approval: currentApproval, expectedDeploymentId: DEPLOYMENT,
    authorityPublicKey: authority.publicKey });
  assert.equal(await store.load(), HASH_A);
});

test("dual-signed continuity binds prior authority, next authority and exact records", async t => {
  const f = await fixture(t), prior = generateKeyPairSync("ed25519"), next = generateKeyPairSync("ed25519");
  let store = await createFilesystemFinalityCustodianStore({ storePath: f.storePath,
    expectedRecordHash: f.record.recordHash });
  await store.compareAndSwap(null, HASH_A);
  const advanced = store.record();
  const transition = createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: f.record, nextRecord: advanced, previousAuthorityPublicKey: prior.publicKey,
    nextAuthorityPublicKey: next.publicKey });
  const authorization = signFinalityCustodianStoreContinuity(transition, "authorization",
    prior.privateKey);
  const acceptance = signFinalityCustodianStoreContinuity(transition, "acceptance", next.privateKey);
  const continuity = assembleFinalityCustodianStoreContinuity({ transition,
    previousAuthorityPublicKey: prior.publicKey, nextAuthorityPublicKey: next.publicKey,
    authorization, acceptance });
  store = await createContinuityApprovedFilesystemFinalityCustodianStore({ storePath: f.storePath,
    continuity, expectedDeploymentId: DEPLOYMENT, expectedPreviousRecord: f.record,
    previousAuthorityPublicKey: prior.publicKey, nextAuthorityPublicKey: next.publicKey });
  assert.equal(await store.load(), HASH_A);

  await assert.rejects(createContinuityApprovedFilesystemFinalityCustodianStore({ storePath: f.storePath,
    continuity, expectedDeploymentId: "e".repeat(64), expectedPreviousRecord: f.record,
    previousAuthorityPublicKey: prior.publicKey, nextAuthorityPublicKey: next.publicKey }), /retained/);
  const substituted = generateKeyPairSync("ed25519");
  await assert.rejects(createContinuityApprovedFilesystemFinalityCustodianStore({ storePath: f.storePath,
    continuity, expectedDeploymentId: DEPLOYMENT, expectedPreviousRecord: f.record,
    previousAuthorityPublicKey: prior.publicKey, nextAuthorityPublicKey: substituted.publicKey }), /share/);
  assert.throws(() => signFinalityCustodianStoreContinuity(transition, "acceptance", prior.privateKey),
    /does not match/);
  const tampered = { ...continuity, transition: { ...continuity.transition,
    deploymentId: "e".repeat(64) } };
  await assert.rejects(createContinuityApprovedFilesystemFinalityCustodianStore({ storePath: f.storePath,
    continuity: tampered, expectedDeploymentId: DEPLOYMENT, expectedPreviousRecord: f.record,
    previousAuthorityPublicKey: prior.publicKey, nextAuthorityPublicKey: next.publicKey }), /retained/);

  const keyOnly = createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: advanced, nextRecord: advanced, previousAuthorityPublicKey: prior.publicKey,
    nextAuthorityPublicKey: next.publicKey });
  assert.equal(keyOnly.nextRecord.recordHash, advanced.recordHash);
  assert.throws(() => createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: advanced, nextRecord: advanced, previousAuthorityPublicKey: prior.publicKey,
    nextAuthorityPublicKey: prior.publicKey }), /not an advance/);
});
