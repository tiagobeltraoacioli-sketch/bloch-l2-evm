// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  approveFinalityCustodianStoreRecord,
  assembleFinalityCustodianStoreContinuity,
  createFinalityCustodianStoreContinuityTransition,
  createFilesystemFinalityCustodianStore,
  createInitialFinalityCustodianStoreRecord,
  finalityCustodianAuthorityReconciliationSha256,
  initializeFilesystemFinalityCustodianStore,
  signFinalityCustodianStoreContinuity,
} from "./finality-quorum-custodian-store.mjs";

const execute = promisify(execFile);
const CLI = join(import.meta.dirname, "finality-quorum-custodian-authority-cli.mjs");
const DEPLOYMENT = "d".repeat(64);

function artifactSha256(value) {
  return createHash("sha256").update(`${JSON.stringify(value)}\n`).digest("hex");
}

async function json(path, value, mode = 0o444) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode });
  await chmod(path, mode);
}

async function publicKey(path, key) {
  await writeFile(path, key.export({ format: "pem", type: "spki" }), { mode: 0o444 });
  await chmod(path, 0o444);
}

async function privateKey(path, key) {
  await writeFile(path, key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-authority-cli-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const previous = generateKeyPairSync("ed25519"), next = generateKeyPairSync("ed25519");
  const record = createInitialFinalityCustodianStoreRecord();
  const approval = approveFinalityCustodianStoreRecord({ deploymentId: DEPLOYMENT, record,
    privateKey: previous.privateKey });
  const approvalPath = join(root, "approval.json"), previousKey = join(root, "previous.pem"),
    nextKey = join(root, "next.pem"), previousPrivateKey = join(root, "previous-private.pem"),
    nextPrivateKey = join(root, "next-private.pem"), recordPath = join(root, "record.json");
  await json(approvalPath, approval); await publicKey(previousKey, previous.publicKey);
  await publicKey(nextKey, next.publicKey);
  await privateKey(previousPrivateKey, previous.privateKey);
  await privateKey(nextPrivateKey, next.privateKey); await json(recordPath, record);
  return { root, previous, next, record, approvalPath,
    approvalSha256: artifactSha256(approval), previousKey, nextKey,
    previousPrivateKey, nextPrivateKey, recordPath };
}

test("offline CLI creates approval, role-separated shares, and canonical continuity", async t => {
  const f = await fixture(t), approval = join(f.root, "cli-approval.json"),
    transition = join(f.root, "transition.json"), authorization = join(f.root, "authorization.json"),
    acceptance = join(f.root, "acceptance.json"), continuity = join(f.root, "continuity.json");
  const approvalResult = await execute(process.execPath, [CLI, "approve", "--record", f.recordPath,
    "--deployment-id", DEPLOYMENT, "--private-key", f.previousPrivateKey, "--output", approval]);
  const transitionResult = await execute(process.execPath,
    [CLI, "transition", "--previous-record", f.recordPath,
    "--next-record", f.recordPath, "--deployment-id", DEPLOYMENT,
    "--previous-authority-public-key", f.previousKey,
    "--next-authority-public-key", f.nextKey, "--output", transition]);
  const transitionBytes = await readFile(transition);
  const transitionSha256 = createHash("sha256").update(transitionBytes).digest("hex");
  assert.equal(JSON.parse(transitionResult.stdout).transitionSha256, transitionSha256);
  await assert.rejects(execute(process.execPath, [CLI, "sign-continuity",
    "--transition", transition, "--expected-transition-sha256", "0".repeat(64),
    "--role", "authorization", "--private-key", join(f.root, "must-not-be-read.pem"),
    "--output", join(f.root, "never-authorization.json")]),
  error => /externally approved/.test(error.stderr));
  await execute(process.execPath, [CLI, "sign-continuity", "--transition", transition,
    "--expected-transition-sha256", transitionSha256,
    "--role", "authorization", "--private-key", f.previousPrivateKey,
    "--output", authorization]);
  await execute(process.execPath, [CLI, "sign-continuity", "--transition", transition,
    "--expected-transition-sha256", transitionSha256,
    "--role", "acceptance", "--private-key", f.nextPrivateKey, "--output", acceptance]);
  await assert.rejects(execute(process.execPath,
    [CLI, "assemble-continuity", "--transition", transition,
    "--expected-transition-sha256", "bad",
    "--previous-authority-public-key", f.previousKey,
    "--next-authority-public-key", f.nextKey, "--authorization", authorization,
    "--acceptance", acceptance, "--output", join(f.root, "never-continuity.json")]),
  error => /externally approved/.test(error.stderr));
  const continuityResult = await execute(process.execPath,
    [CLI, "assemble-continuity", "--transition", transition,
    "--expected-transition-sha256", transitionSha256,
    "--previous-authority-public-key", f.previousKey,
    "--next-authority-public-key", f.nextKey, "--authorization", authorization,
    "--acceptance", acceptance, "--output", continuity]);
  const assembled = JSON.parse(await readFile(continuity, "utf8"));
  assert.equal(assembled.authorization.role, "authorization");
  assert.equal(assembled.acceptance.role, "acceptance");
  assert.equal(assembled.transition.previousRecord.recordHash, f.record.recordHash);
  assert.equal(assembled.transition.nextRecord.recordHash, f.record.recordHash);
  assert.equal(JSON.parse(continuityResult.stdout).continuitySha256,
    createHash("sha256").update(await readFile(continuity)).digest("hex"));
  const approvalBytes = await readFile(approval);
  const generatedApproval = JSON.parse(approvalBytes.toString("utf8"));
  assert.equal(generatedApproval.deploymentId, DEPLOYMENT);
  assert.equal(generatedApproval.record.recordHash, f.record.recordHash);
  assert.equal(JSON.parse(approvalResult.stdout).approvalSha256,
    createHash("sha256").update(approvalBytes).digest("hex"));
});

test("offline CLI creates the exact initial checkpoint and advances key-only continuity", async t => {
  const f = await fixture(t), initial = join(f.root, "initial.json"),
    continuityPath = join(f.root, "continuity.json"), advanced = join(f.root, "advanced.json");
  await execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", initial]);
  const retained = JSON.parse(await readFile(initial, "utf8"));
  assert.equal(retained.transitionIndex, "0");
  assert.equal(retained.deploymentId, DEPLOYMENT);
  const transition = createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: f.record, nextRecord: f.record,
    previousAuthorityPublicKey: f.previous.publicKey, nextAuthorityPublicKey: f.next.publicKey });
  const continuity = assembleFinalityCustodianStoreContinuity({ transition,
    previousAuthorityPublicKey: f.previous.publicKey, nextAuthorityPublicKey: f.next.publicKey,
    authorization: signFinalityCustodianStoreContinuity(
      transition, "authorization", f.previous.privateKey),
    acceptance: signFinalityCustodianStoreContinuity(
      transition, "acceptance", f.next.privateKey) });
  await json(continuityPath, continuity);
  const continuitySha256 = artifactSha256(continuity);
  await assert.rejects(execute(process.execPath, [CLI, "advance", "--checkpoint", initial,
    "--expected-checkpoint-hash", retained.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", "0".repeat(64),
    "--next-authority-public-key", f.nextKey,
    "--output", join(f.root, "never-advanced.json")]),
  error => /externally approved/.test(error.stderr));
  await execute(process.execPath, [CLI, "advance", "--checkpoint", initial,
    "--expected-checkpoint-hash", retained.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", continuitySha256,
    "--next-authority-public-key", f.nextKey,
    "--output", advanced]);
  const next = JSON.parse(await readFile(advanced, "utf8"));
  assert.equal(next.transitionIndex, "1");
  assert.equal(next.previousCheckpointHash, retained.checkpointHash);
  assert.equal(next.record.recordHash, retained.record.recordHash);
});

test("offline CLI writes a canonical record reconciliation receipt", async t => {
  const f = await fixture(t), storePath = join(f.root, "store.json"),
    checkpointPath = join(f.root, "initial.json"), continuityPath = join(f.root, "continuity.json"),
    receiptPath = join(f.root, "reconciliation.json");
  await initializeFilesystemFinalityCustodianStore({ storePath, record: f.record,
    expectedRecordHash: f.record.recordHash });
  const store = await createFilesystemFinalityCustodianStore({ storePath,
    expectedRecordHash: f.record.recordHash });
  await store.compareAndSwap(null, "a".repeat(64));
  const transition = createFinalityCustodianStoreContinuityTransition({ deploymentId: DEPLOYMENT,
    previousRecord: f.record, nextRecord: store.record(),
    previousAuthorityPublicKey: f.previous.publicKey,
    nextAuthorityPublicKey: f.next.publicKey });
  const continuity = assembleFinalityCustodianStoreContinuity({ transition,
    previousAuthorityPublicKey: f.previous.publicKey, nextAuthorityPublicKey: f.next.publicKey,
    authorization: signFinalityCustodianStoreContinuity(
      transition, "authorization", f.previous.privateKey),
    acceptance: signFinalityCustodianStoreContinuity(
      transition, "acceptance", f.next.privateKey) });
  await json(continuityPath, continuity);
  const continuitySha256 = artifactSha256(continuity);
  await execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", checkpointPath]);
  const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
  const result = await execute(process.execPath, [CLI, "reconcile-record", "--store", storePath,
    "--checkpoint", checkpointPath, "--expected-checkpoint-hash", checkpoint.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", continuitySha256,
    "--next-authority-public-key", f.nextKey, "--output", receiptPath]);
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  assert.equal(receipt.status, "successor-record-observed");
  assert.equal(receipt.observedRecordHash, store.record().recordHash);
  assert.equal(JSON.parse(result.stdout).status, receipt.status);
  const receiptSha256 = finalityCustodianAuthorityReconciliationSha256(receipt);
  const verified = await execute(process.execPath, [CLI, "verify-reconciliation",
    "--receipt", receiptPath, "--expected-receipt-sha256", receiptSha256,
    "--checkpoint", checkpointPath, "--expected-checkpoint-hash", checkpoint.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", continuitySha256,
    "--next-authority-public-key", f.nextKey]);
  assert.equal(JSON.parse(verified.stdout).receiptSha256, receiptSha256);
  await assert.rejects(execute(process.execPath, [CLI, "verify-reconciliation",
    "--receipt", receiptPath, "--expected-receipt-sha256", receiptSha256,
    "--checkpoint", checkpointPath, "--expected-checkpoint-hash", checkpoint.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", "bad",
    "--next-authority-public-key", f.nextKey]),
  error => /externally approved/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [CLI, "verify-reconciliation",
    "--receipt", receiptPath, "--expected-receipt-sha256", "0".repeat(64),
    "--checkpoint", checkpointPath, "--expected-checkpoint-hash", checkpoint.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", continuitySha256,
    "--next-authority-public-key", f.nextKey]),
  error => /externally approved/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [CLI, "reconcile-record", "--store", storePath,
    "--checkpoint", checkpointPath, "--expected-checkpoint-hash", "e".repeat(64),
    "--continuity", continuityPath, "--expected-continuity-sha256", continuitySha256,
    "--next-authority-public-key", f.nextKey,
    "--output", join(f.root, "never-reconciled.json")]),
  error => /externally retained hash/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [CLI, "reconcile-record", "--store", storePath,
    "--checkpoint", checkpointPath, "--expected-checkpoint-hash", checkpoint.checkpointHash,
    "--continuity", continuityPath, "--expected-continuity-sha256", "f".repeat(64),
    "--next-authority-public-key", f.nextKey,
    "--output", join(f.root, "never-substituted.json")]),
  error => /externally approved/.test(error.stderr));
});

test("offline CLI refuses substitution, unsafe input and output overwrite", async t => {
  const f = await fixture(t), output = join(f.root, "checkpoint.json");
  await chmod(f.previousPrivateKey, 0o644);
  await assert.rejects(execute(process.execPath, [CLI, "approve", "--record", f.recordPath,
    "--deployment-id", DEPLOYMENT, "--private-key", f.previousPrivateKey,
    "--output", join(f.root, "unsafe-approval.json")]), error => /unsafe/.test(error.stderr));
  await chmod(f.previousPrivateKey, 0o600);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", "e".repeat(64),
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]), error => /externally approved/.test(error.stderr));
  for (const digest of ["0".repeat(64), "E".repeat(64), "e".repeat(63)]) {
    await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
      "--expected-approval-sha256", digest,
      "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
      "--output", output]), error => /externally approved/.test(error.stderr));
  }
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]), error => /Usage/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", "e".repeat(64), "--authority-public-key", f.previousKey,
    "--output", output]), error => /approval/.test(error.stderr));
  await chmod(f.previousKey, 0o666);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]), error => /unsafe/.test(error.stderr));
  await chmod(f.previousKey, 0o444);
  await execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]), error => /EEXIST|exist/.test(error.stderr));
});

test("offline CLI requires canonical owned absolute inputs", async t => {
  const f = await fixture(t), noncanonical = join(f.root, "pretty.json");
  await writeFile(noncanonical, JSON.stringify(JSON.parse(await readFile(f.approvalPath, "utf8")),
    null, 2), { mode: 0o444 });
  await chmod(noncanonical, 0o444);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", noncanonical,
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", join(f.root, "never.json")]), error => /not canonical/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", "relative.json",
    "--expected-approval-sha256", f.approvalSha256,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", join(f.root, "never-either.json")]), error => /absolute/.test(error.stderr));
});
