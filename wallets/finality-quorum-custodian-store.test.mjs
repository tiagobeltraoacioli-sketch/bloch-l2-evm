// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, link, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  approveFinalityCustodianStoreRecord,
  advanceFinalityCustodianAuthorityCheckpoint,
  assembleFinalityCustodianStoreContinuity,
  createApprovedFilesystemFinalityCustodianStore,
  createContinuityApprovedFilesystemFinalityCustodianStore,
  createAuthorityCheckpointFilesystemFinalityCustodianStore,
  createFilesystemFinalityCustodianStore,
  createFinalityCustodianStoreContinuityTransition,
  createInitialFinalityCustodianStoreRecord,
  createInitialFinalityCustodianAuthorityCheckpoint,
  finalityCustodianAuthorityReconciliationSha256,
  initializeApprovedFilesystemFinalityCustodianStore,
  initializeFilesystemFinalityCustodianStore,
  inspectFilesystemFinalityCustodianStore,
  reconcileFinalityCustodianAuthorityStoreRecord,
  signFinalityCustodianStoreContinuity,
  verifyFinalityCustodianAuthorityStoreReconciliation,
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

test("one canonical authority checkpoint retains deployment key and record continuity", async t => {
  const f = await fixture(t), prior = generateKeyPairSync("ed25519"),
    next = generateKeyPairSync("ed25519"), substituted = generateKeyPairSync("ed25519");
  const approval = approveFinalityCustodianStoreRecord({ deploymentId: DEPLOYMENT,
    record: f.record, privateKey: prior.privateKey });
  const initial = createInitialFinalityCustodianAuthorityCheckpoint({ approval,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: prior.publicKey });
  assert.equal(initial.transitionIndex, "0");
  assert.equal(initial.previousCheckpointHash, null);
  assert.equal(initial.record.recordHash, f.record.recordHash);

  const transition = createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: f.record, nextRecord: f.record, previousAuthorityPublicKey: prior.publicKey,
    nextAuthorityPublicKey: next.publicKey });
  const continuity = assembleFinalityCustodianStoreContinuity({ transition,
    previousAuthorityPublicKey: prior.publicKey, nextAuthorityPublicKey: next.publicKey,
    authorization: signFinalityCustodianStoreContinuity(transition, "authorization", prior.privateKey),
    acceptance: signFinalityCustodianStoreContinuity(transition, "acceptance", next.privateKey) });
  const rotated = advanceFinalityCustodianAuthorityCheckpoint({ checkpoint: initial, continuity,
    nextAuthorityPublicKey: next.publicKey });
  assert.equal(rotated.transitionIndex, "1");
  assert.equal(rotated.previousCheckpointHash, initial.checkpointHash);
  assert.equal(rotated.record.recordHash, initial.record.recordHash);
  const store = await createAuthorityCheckpointFilesystemFinalityCustodianStore({
    storePath: f.storePath, checkpoint: rotated });
  assert.equal(await store.load(), null);
  await assert.rejects(reconcileFinalityCustodianAuthorityStoreRecord({
    storePath: f.storePath, checkpoint: initial, continuity,
    nextAuthorityPublicKey: next.publicKey }), /key-only/);

  assert.throws(() => advanceFinalityCustodianAuthorityCheckpoint({ checkpoint: initial, continuity,
    nextAuthorityPublicKey: substituted.publicKey }), /share/);
  assert.throws(() => advanceFinalityCustodianAuthorityCheckpoint({
    checkpoint: { ...initial, deploymentId: "e".repeat(64) }, continuity,
    nextAuthorityPublicKey: next.publicKey }), /checkpoint/);
  assert.throws(() => advanceFinalityCustodianAuthorityCheckpoint({
    checkpoint: { ...initial, authorityPublicKeyBase64Url:
      rotated.authorityPublicKeyBase64Url }, continuity, nextAuthorityPublicKey: next.publicKey }),
  /checkpoint/);
});

test("authority reconciliation classifies only the exact prior or approved successor record", async t => {
  const priorStore = await fixture(t), successorStore = await fixture(t);
  const previousAuthority = generateKeyPairSync("ed25519"),
    nextAuthority = generateKeyPairSync("ed25519");
  const approval = approveFinalityCustodianStoreRecord({ deploymentId: DEPLOYMENT,
    record: priorStore.record, privateKey: previousAuthority.privateKey });
  const checkpoint = createInitialFinalityCustodianAuthorityCheckpoint({ approval,
    expectedDeploymentId: DEPLOYMENT, authorityPublicKey: previousAuthority.publicKey });
  const writable = await createFilesystemFinalityCustodianStore({
    storePath: successorStore.storePath, expectedRecordHash: successorStore.record.recordHash });
  await writable.compareAndSwap(null, HASH_A);
  const successor = writable.record();
  const transition = createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: priorStore.record, nextRecord: successor,
    previousAuthorityPublicKey: previousAuthority.publicKey,
    nextAuthorityPublicKey: nextAuthority.publicKey });
  const continuity = assembleFinalityCustodianStoreContinuity({ transition,
    previousAuthorityPublicKey: previousAuthority.publicKey,
    nextAuthorityPublicKey: nextAuthority.publicKey,
    authorization: signFinalityCustodianStoreContinuity(
      transition, "authorization", previousAuthority.privateKey),
    acceptance: signFinalityCustodianStoreContinuity(
      transition, "acceptance", nextAuthority.privateKey) });

  const before = await reconcileFinalityCustodianAuthorityStoreRecord({
    storePath: priorStore.storePath, checkpoint, continuity,
    nextAuthorityPublicKey: nextAuthority.publicKey });
  assert.equal(before.status, "prior-record-observed");
  assert.equal(before.observedRecordHash, priorStore.record.recordHash);
  const after = await reconcileFinalityCustodianAuthorityStoreRecord({
    storePath: successorStore.storePath, checkpoint, continuity,
    nextAuthorityPublicKey: nextAuthority.publicKey });
  assert.equal(after.status, "successor-record-observed");
  assert.equal(after.observedRecordHash, successor.recordHash);
  assert.deepEqual(verifyFinalityCustodianAuthorityStoreReconciliation({ receipt: after,
    checkpoint, continuity, nextAuthorityPublicKey: nextAuthority.publicKey }), after);
  assert.match(finalityCustodianAuthorityReconciliationSha256(after), /^[0-9a-f]{64}$/);
  assert.throws(() => verifyFinalityCustodianAuthorityStoreReconciliation({
    receipt: { ...after, observedRecordHash: priorStore.record.recordHash },
    checkpoint, continuity, nextAuthorityPublicKey: nextAuthority.publicKey }), /does not match/);
  assert.throws(() => finalityCustodianAuthorityReconciliationSha256({
    ...after, unexpected: true }), /receipt is invalid/);

  await writable.compareAndSwap(HASH_A, HASH_B);
  await assert.rejects(reconcileFinalityCustodianAuthorityStoreRecord({
    storePath: successorStore.storePath, checkpoint, continuity,
    nextAuthorityPublicKey: nextAuthority.publicKey }), /neither/);
  await writeFile(`${priorStore.storePath}.lock`, "orphan\n", { mode: 0o600, flag: "wx" });
  await assert.rejects(reconcileFinalityCustodianAuthorityStoreRecord({
    storePath: priorStore.storePath, checkpoint, continuity,
    nextAuthorityPublicKey: nextAuthority.publicKey }), /locked/);
});
