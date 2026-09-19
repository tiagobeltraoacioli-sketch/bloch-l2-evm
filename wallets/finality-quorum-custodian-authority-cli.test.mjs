// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
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
  initializeFilesystemFinalityCustodianStore,
  signFinalityCustodianStoreContinuity,
} from "./finality-quorum-custodian-store.mjs";

const execute = promisify(execFile);
const CLI = join(import.meta.dirname, "finality-quorum-custodian-authority-cli.mjs");
const DEPLOYMENT = "d".repeat(64);

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
  return { root, previous, next, record, approvalPath, previousKey, nextKey,
    previousPrivateKey, nextPrivateKey, recordPath };
}

test("offline CLI creates approval, role-separated shares, and canonical continuity", async t => {
  const f = await fixture(t), approval = join(f.root, "cli-approval.json"),
    transition = join(f.root, "transition.json"), authorization = join(f.root, "authorization.json"),
    acceptance = join(f.root, "acceptance.json"), continuity = join(f.root, "continuity.json");
  await execute(process.execPath, [CLI, "approve", "--record", f.recordPath,
    "--deployment-id", DEPLOYMENT, "--private-key", f.previousPrivateKey, "--output", approval]);
  await execute(process.execPath, [CLI, "transition", "--previous-record", f.recordPath,
    "--next-record", f.recordPath, "--deployment-id", DEPLOYMENT,
    "--previous-authority-public-key", f.previousKey,
    "--next-authority-public-key", f.nextKey, "--output", transition]);
  await execute(process.execPath, [CLI, "sign-continuity", "--transition", transition,
    "--role", "authorization", "--private-key", f.previousPrivateKey,
    "--output", authorization]);
  await execute(process.execPath, [CLI, "sign-continuity", "--transition", transition,
    "--role", "acceptance", "--private-key", f.nextPrivateKey, "--output", acceptance]);
  await execute(process.execPath, [CLI, "assemble-continuity", "--transition", transition,
    "--previous-authority-public-key", f.previousKey,
    "--next-authority-public-key", f.nextKey, "--authorization", authorization,
    "--acceptance", acceptance, "--output", continuity]);
  const assembled = JSON.parse(await readFile(continuity, "utf8"));
  assert.equal(assembled.authorization.role, "authorization");
  assert.equal(assembled.acceptance.role, "acceptance");
  assert.equal(assembled.transition.previousRecord.recordHash, f.record.recordHash);
  assert.equal(assembled.transition.nextRecord.recordHash, f.record.recordHash);
  const generatedApproval = JSON.parse(await readFile(approval, "utf8"));
  assert.equal(generatedApproval.deploymentId, DEPLOYMENT);
  assert.equal(generatedApproval.record.recordHash, f.record.recordHash);
});

test("offline CLI creates the exact initial checkpoint and advances key-only continuity", async t => {
  const f = await fixture(t), initial = join(f.root, "initial.json"),
    continuityPath = join(f.root, "continuity.json"), advanced = join(f.root, "advanced.json");
  await execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
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
  await execute(process.execPath, [CLI, "advance", "--checkpoint", initial,
    "--continuity", continuityPath, "--next-authority-public-key", f.nextKey,
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
  await execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", checkpointPath]);
  const result = await execute(process.execPath, [CLI, "reconcile-record", "--store", storePath,
    "--checkpoint", checkpointPath, "--continuity", continuityPath,
    "--next-authority-public-key", f.nextKey, "--output", receiptPath]);
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  assert.equal(receipt.status, "successor-record-observed");
  assert.equal(receipt.observedRecordHash, store.record().recordHash);
  assert.equal(JSON.parse(result.stdout).status, receipt.status);
});

test("offline CLI refuses substitution, unsafe input and output overwrite", async t => {
  const f = await fixture(t), output = join(f.root, "checkpoint.json");
  await chmod(f.previousPrivateKey, 0o644);
  await assert.rejects(execute(process.execPath, [CLI, "approve", "--record", f.recordPath,
    "--deployment-id", DEPLOYMENT, "--private-key", f.previousPrivateKey,
    "--output", join(f.root, "unsafe-approval.json")]), error => /unsafe/.test(error.stderr));
  await chmod(f.previousPrivateKey, 0o600);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--deployment-id", "e".repeat(64), "--authority-public-key", f.previousKey,
    "--output", output]), error => /approval/.test(error.stderr));
  await chmod(f.previousKey, 0o666);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]), error => /unsafe/.test(error.stderr));
  await chmod(f.previousKey, 0o444);
  await execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", f.approvalPath,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", output]), error => /EEXIST|exist/.test(error.stderr));
});

test("offline CLI requires canonical owned absolute inputs", async t => {
  const f = await fixture(t), noncanonical = join(f.root, "pretty.json");
  await writeFile(noncanonical, JSON.stringify(JSON.parse(await readFile(f.approvalPath, "utf8")),
    null, 2), { mode: 0o444 });
  await chmod(noncanonical, 0o444);
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", noncanonical,
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", join(f.root, "never.json")]), error => /not canonical/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [CLI, "initial", "--approval", "relative.json",
    "--deployment-id", DEPLOYMENT, "--authority-public-key", f.previousKey,
    "--output", join(f.root, "never-either.json")]), error => /absolute/.test(error.stderr));
});
