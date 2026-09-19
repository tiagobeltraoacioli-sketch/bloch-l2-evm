// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { dirname, resolve } from "node:path";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";

export const BLOCH_L2_FINALITY_CUSTODIAN_STORE_FORMAT =
  "bloch-l2-finality-custodian-store-v1";
export const BLOCH_L2_FINALITY_CUSTODIAN_STORE_APPROVAL_FORMAT =
  "bloch-l2-finality-custodian-store-approval-v1";
export const BLOCH_L2_FINALITY_CUSTODIAN_STORE_CONTINUITY_FORMAT =
  "bloch-l2-finality-custodian-store-continuity-v1";
export const BLOCH_L2_FINALITY_CUSTODIAN_AUTHORITY_CHECKPOINT_FORMAT =
  "bloch-l2-finality-custodian-authority-checkpoint-v1";

const HASH = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_FILE_BYTES = 16 * 1024;
const FIELDS = ["format", "generation", "stateHash", "previousRecordHash", "recordHash"];
const APPROVAL_FIELDS = ["format", "deploymentId", "authorityKeyId", "record", "signature"];
const CONTINUITY_TRANSITION_FIELDS = ["format", "deploymentId", "previousAuthorityKeyId",
  "nextAuthorityKeyId", "previousRecord", "nextRecord"];
const CONTINUITY_SHARE_FIELDS = ["role", "keyId", "signature"];
const CONTINUITY_FIELDS = ["format", "transition", "authorization", "acceptance"];
const AUTHORITY_CHECKPOINT_FIELDS = ["format", "transitionIndex", "deploymentId", "authorityKeyId",
  "authorityPublicKeyBase64Url", "record", "previousCheckpointHash", "checkpointHash"];
const APPROVAL_DOMAIN = "BLOCH-L2-FINALITY-CUSTODIAN-STORE-APPROVAL-v1\0";
const AUTHORITY_CHECKPOINT_DOMAIN = "BLOCH-L2-FINALITY-CUSTODIAN-AUTHORITY-CHECKPOINT-v1\0";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function exact(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) {
    throw new Error(message);
  }
  return value;
}

function checkedHash(value, nullable, message) {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(message);
  return value;
}

function body(value) {
  return Object.fromEntries(FIELDS.slice(0, -1).map(field => [field, value[field]]));
}

function digest(value) {
  return createHash("sha256").update("BLOCH-L2-FINALITY-CUSTODIAN-STORE-v1\0")
    .update(JSON.stringify(value)).digest("hex");
}

function checkedRecord(value) {
  exact(value, FIELDS, "Finality custodian store record is invalid");
  if (value.format !== BLOCH_L2_FINALITY_CUSTODIAN_STORE_FORMAT ||
      typeof value.generation !== "string" || !U64.test(value.generation) ||
      BigInt(value.generation) > 0xffffffffffffffffn ||
      value.stateHash !== null && !HASH.test(value.stateHash) ||
      (value.generation === "0") !== (value.previousRecordHash === null) ||
      value.previousRecordHash !== null && !HASH.test(value.previousRecordHash) ||
      typeof value.recordHash !== "string" || !HASH.test(value.recordHash) ||
      digest(body(value)) !== value.recordHash) {
    throw new Error("Finality custodian store record is invalid");
  }
  return Object.freeze({ ...value });
}

function approvalKey(value, privateKey) {
  let key;
  try {
    if (value?.type === (privateKey ? "private" : "public")) key = value;
    else if (value?.type) throw new Error("wrong key type");
    else key = privateKey ? createPrivateKey(value) : createPublicKey(value);
  }
  catch (cause) { throw new Error("Finality custodian store approval key is invalid", { cause }); }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("Finality custodian store approval key must be Ed25519");
  }
  const publicKey = privateKey ? createPublicKey(key) : key;
  const encoded = publicKey.export({ format: "der", type: "spki" });
  return { key, keyId: createHash("sha256").update(encoded).digest("hex") };
}

function authorityPublicKey(value) {
  const authority = approvalKey(value, false);
  const encoded = authority.key.export({ format: "der", type: "spki" });
  if (encoded.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !encoded.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("Finality custodian authority public key encoding is invalid");
  }
  return { ...authority,
    publicKeyBase64Url: encoded.subarray(ED25519_SPKI_PREFIX.length).toString("base64url") };
}

function authorityPublicKeyFromRaw(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error("Finality custodian authority checkpoint public key is invalid");
  }
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== value) {
    throw new Error("Finality custodian authority checkpoint public key is invalid");
  }
  try {
    return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der", type: "spki" });
  } catch (cause) {
    throw new Error("Finality custodian authority checkpoint public key is invalid", { cause });
  }
}

function approvalBytes(deploymentId, authorityKeyId, record) {
  return Buffer.from(APPROVAL_DOMAIN + JSON.stringify({ deploymentId, authorityKeyId, record }), "utf8");
}

function decodedSignature(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) {
    throw new Error("Finality custodian store approval signature is invalid");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 64 || decoded.toString("base64url") !== value) {
    throw new Error("Finality custodian store approval signature is invalid");
  }
  return decoded;
}

export function approveFinalityCustodianStoreRecord({ deploymentId, record, privateKey } = {}) {
  if (typeof deploymentId !== "string" || !HASH.test(deploymentId) || deploymentId === "0".repeat(64)) {
    throw new Error("Finality custodian store approval deployment is invalid");
  }
  const approved = checkedRecord(record), authority = approvalKey(privateKey, true);
  return Object.freeze({ format: BLOCH_L2_FINALITY_CUSTODIAN_STORE_APPROVAL_FORMAT,
    deploymentId, authorityKeyId: authority.keyId, record: approved,
    signature: sign(null, approvalBytes(deploymentId, authority.keyId, approved), authority.key)
      .toString("base64url") });
}

export function verifyFinalityCustodianStoreApproval({ approval, expectedDeploymentId,
  authorityPublicKey } = {}) {
  exact(approval, APPROVAL_FIELDS, "Finality custodian store approval is invalid");
  if (typeof expectedDeploymentId !== "string" || !HASH.test(expectedDeploymentId) ||
      expectedDeploymentId === "0".repeat(64) || approval.format !==
      BLOCH_L2_FINALITY_CUSTODIAN_STORE_APPROVAL_FORMAT || approval.deploymentId !==
      expectedDeploymentId || typeof approval.authorityKeyId !== "string" ||
      !HASH.test(approval.authorityKeyId)) {
    throw new Error("Finality custodian store approval is invalid");
  }
  const record = checkedRecord(approval.record), authority = approvalKey(authorityPublicKey, false);
  if (authority.keyId !== approval.authorityKeyId || !verify(null,
    approvalBytes(approval.deploymentId, approval.authorityKeyId, record), authority.key,
    decodedSignature(approval.signature))) {
    throw new Error("Finality custodian store approval signature is invalid");
  }
  return record;
}

function checkedContinuityTransition(value) {
  exact(value, CONTINUITY_TRANSITION_FIELDS,
    "Finality custodian store continuity transition is invalid");
  if (value.format !== BLOCH_L2_FINALITY_CUSTODIAN_STORE_CONTINUITY_FORMAT ||
      typeof value.deploymentId !== "string" || !HASH.test(value.deploymentId) ||
      value.deploymentId === "0".repeat(64) ||
      typeof value.previousAuthorityKeyId !== "string" || !HASH.test(value.previousAuthorityKeyId) ||
      typeof value.nextAuthorityKeyId !== "string" || !HASH.test(value.nextAuthorityKeyId)) {
    throw new Error("Finality custodian store continuity transition is invalid");
  }
  const previousRecord = checkedRecord(value.previousRecord), nextRecord = checkedRecord(value.nextRecord);
  const sameRecord = previousRecord.recordHash === nextRecord.recordHash;
  if (sameRecord && value.previousAuthorityKeyId === value.nextAuthorityKeyId ||
      !sameRecord && BigInt(nextRecord.generation) <= BigInt(previousRecord.generation)) {
    throw new Error("Finality custodian store continuity transition is not an advance");
  }
  return Object.freeze({ format: value.format, deploymentId: value.deploymentId,
    previousAuthorityKeyId: value.previousAuthorityKeyId, nextAuthorityKeyId: value.nextAuthorityKeyId,
    previousRecord, nextRecord });
}

function continuityBytes(transition, role) {
  return Buffer.from(`BLOCH-L2-FINALITY-CUSTODIAN-STORE-CONTINUITY-${role}-v1\0` +
    JSON.stringify(transition), "utf8");
}

export function createFinalityCustodianStoreContinuityTransition({ deploymentId, previousRecord,
  nextRecord, previousAuthorityPublicKey, nextAuthorityPublicKey } = {}) {
  const previous = approvalKey(previousAuthorityPublicKey, false);
  const next = approvalKey(nextAuthorityPublicKey, false);
  return checkedContinuityTransition({ format: BLOCH_L2_FINALITY_CUSTODIAN_STORE_CONTINUITY_FORMAT,
    deploymentId, previousAuthorityKeyId: previous.keyId, nextAuthorityKeyId: next.keyId,
    previousRecord, nextRecord });
}

export function signFinalityCustodianStoreContinuity(transitionValue, role, privateKey) {
  const transition = checkedContinuityTransition(transitionValue);
  if (!['authorization', 'acceptance'].includes(role)) {
    throw new Error("Finality custodian store continuity role is invalid");
  }
  const authority = approvalKey(privateKey, true);
  const expected = role === "authorization" ? transition.previousAuthorityKeyId :
    transition.nextAuthorityKeyId;
  if (authority.keyId !== expected) {
    throw new Error("Finality custodian store continuity signer does not match its role");
  }
  return Object.freeze({ role, keyId: authority.keyId,
    signature: sign(null, continuityBytes(transition, role), authority.key).toString("base64url") });
}

function checkedContinuityShare(value, role, keyId, publicKey, transition) {
  exact(value, CONTINUITY_SHARE_FIELDS, "Finality custodian store continuity share is invalid");
  const authority = approvalKey(publicKey, false);
  if (value.role !== role || value.keyId !== keyId || authority.keyId !== keyId ||
      !verify(null, continuityBytes(transition, role), authority.key, decodedSignature(value.signature))) {
    throw new Error("Finality custodian store continuity share is invalid");
  }
  return Object.freeze({ role: value.role, keyId: value.keyId, signature: value.signature });
}

export function assembleFinalityCustodianStoreContinuity({ transition: transitionValue,
  previousAuthorityPublicKey, nextAuthorityPublicKey, authorization, acceptance } = {}) {
  const transition = checkedContinuityTransition(transitionValue);
  return Object.freeze({ format: BLOCH_L2_FINALITY_CUSTODIAN_STORE_CONTINUITY_FORMAT, transition,
    authorization: checkedContinuityShare(authorization, "authorization",
      transition.previousAuthorityKeyId, previousAuthorityPublicKey, transition),
    acceptance: checkedContinuityShare(acceptance, "acceptance",
      transition.nextAuthorityKeyId, nextAuthorityPublicKey, transition) });
}

export function verifyFinalityCustodianStoreContinuity({ continuity, expectedDeploymentId,
  expectedPreviousRecord, previousAuthorityPublicKey, nextAuthorityPublicKey } = {}) {
  exact(continuity, CONTINUITY_FIELDS, "Finality custodian store continuity is invalid");
  if (continuity.format !== BLOCH_L2_FINALITY_CUSTODIAN_STORE_CONTINUITY_FORMAT) {
    throw new Error("Finality custodian store continuity is invalid");
  }
  const transition = checkedContinuityTransition(continuity.transition);
  const previous = checkedRecord(expectedPreviousRecord);
  if (transition.deploymentId !== expectedDeploymentId ||
      transition.previousRecord.recordHash !== previous.recordHash) {
    throw new Error("Finality custodian store continuity does not match retained authority state");
  }
  const checked = assembleFinalityCustodianStoreContinuity({ transition,
    previousAuthorityPublicKey, nextAuthorityPublicKey,
    authorization: continuity.authorization, acceptance: continuity.acceptance });
  if (JSON.stringify(checked) !== JSON.stringify(continuity)) {
    throw new Error("Finality custodian store continuity is not canonical");
  }
  return transition.nextRecord;
}

function authorityCheckpointBody(value) {
  return Object.fromEntries(AUTHORITY_CHECKPOINT_FIELDS.slice(0, -1)
    .map(field => [field, value[field]]));
}

function authorityCheckpointDigest(value) {
  return createHash("sha256").update(AUTHORITY_CHECKPOINT_DOMAIN)
    .update(JSON.stringify(value)).digest("hex");
}

function checkedAuthorityCheckpoint(value) {
  exact(value, AUTHORITY_CHECKPOINT_FIELDS,
    "Finality custodian authority checkpoint is invalid");
  if (value.format !== BLOCH_L2_FINALITY_CUSTODIAN_AUTHORITY_CHECKPOINT_FORMAT ||
      typeof value.transitionIndex !== "string" || !U64.test(value.transitionIndex) ||
      BigInt(value.transitionIndex) > 0xffffffffffffffffn ||
      typeof value.deploymentId !== "string" || !HASH.test(value.deploymentId) ||
      value.deploymentId === "0".repeat(64) || typeof value.authorityKeyId !== "string" ||
      !HASH.test(value.authorityKeyId) ||
      value.previousCheckpointHash !== null && !HASH.test(value.previousCheckpointHash) ||
      typeof value.checkpointHash !== "string" || !HASH.test(value.checkpointHash)) {
    throw new Error("Finality custodian authority checkpoint is invalid");
  }
  const record = checkedRecord(value.record);
  const authority = authorityPublicKey(authorityPublicKeyFromRaw(value.authorityPublicKeyBase64Url));
  if (authority.keyId !== value.authorityKeyId ||
      authorityCheckpointDigest(authorityCheckpointBody(value)) !== value.checkpointHash ||
      (value.transitionIndex === "0") !== (value.previousCheckpointHash === null)) {
    throw new Error("Finality custodian authority checkpoint is invalid");
  }
  return Object.freeze({ format: value.format, transitionIndex: value.transitionIndex,
    deploymentId: value.deploymentId,
    authorityKeyId: value.authorityKeyId,
    authorityPublicKeyBase64Url: value.authorityPublicKeyBase64Url, record,
    previousCheckpointHash: value.previousCheckpointHash, checkpointHash: value.checkpointHash });
}

function buildAuthorityCheckpoint(transitionIndex, deploymentId, publicKey, record,
  previousCheckpointHash) {
  const authority = authorityPublicKey(publicKey);
  const body = { format: BLOCH_L2_FINALITY_CUSTODIAN_AUTHORITY_CHECKPOINT_FORMAT, transitionIndex,
    deploymentId, authorityKeyId: authority.keyId,
    authorityPublicKeyBase64Url: authority.publicKeyBase64Url, record: checkedRecord(record),
    previousCheckpointHash };
  return checkedAuthorityCheckpoint({ ...body,
    checkpointHash: authorityCheckpointDigest(body) });
}

/** Creates the first independently retainable authority tuple after verifying
 * the offline approval. The returned public checkpoint contains no secret. */
export function createInitialFinalityCustodianAuthorityCheckpoint({ approval,
  expectedDeploymentId, authorityPublicKey: publicKey } = {}) {
  const record = verifyFinalityCustodianStoreApproval({ approval, expectedDeploymentId,
    authorityPublicKey: publicKey });
  if (record.generation !== "0") {
    throw new Error("Finality custodian initial authority checkpoint is not generation zero");
  }
  return buildAuthorityCheckpoint("0", expectedDeploymentId, publicKey, record, null);
}

/** Verifies a dual-signed transition against one exact retained tuple and
 * derives its only canonical successor. */
export function advanceFinalityCustodianAuthorityCheckpoint({ checkpoint, continuity,
  nextAuthorityPublicKey } = {}) {
  const previous = checkedAuthorityCheckpoint(checkpoint);
  const previousPublicKey = authorityPublicKeyFromRaw(previous.authorityPublicKeyBase64Url);
  const nextRecord = verifyFinalityCustodianStoreContinuity({ continuity,
    expectedDeploymentId: previous.deploymentId, expectedPreviousRecord: previous.record,
    previousAuthorityPublicKey: previousPublicKey, nextAuthorityPublicKey });
  const nextIndex = BigInt(previous.transitionIndex) + 1n;
  if (nextIndex > 0xffffffffffffffffn) {
    throw new Error("Finality custodian authority checkpoint transition index exhausted");
  }
  return buildAuthorityCheckpoint(nextIndex.toString(), previous.deploymentId,
    nextAuthorityPublicKey, nextRecord, previous.checkpointHash);
}

/** Opens the local durability store only after validating the complete
 * independently retained authority tuple. */
export async function createAuthorityCheckpointFilesystemFinalityCustodianStore({ storePath,
  checkpoint } = {}) {
  const retained = checkedAuthorityCheckpoint(checkpoint);
  return createFilesystemFinalityCustodianStore({ storePath,
    expectedRecordHash: retained.record.recordHash });
}

export function createInitialFinalityCustodianStoreRecord({ stateHash = null } = {}) {
  checkedHash(stateHash, true, "Finality custodian initial state hash is invalid");
  const initial = { format: BLOCH_L2_FINALITY_CUSTODIAN_STORE_FORMAT, generation: "0",
    stateHash, previousRecordHash: null };
  return checkedRecord({ ...initial, recordHash: digest(initial) });
}

async function protectedDirectory(path) {
  if (typeof path !== "string" || !path) throw new Error("Finality custodian store path is invalid");
  const directoryPath = resolve(dirname(path)), before = await lstat(directoryPath);
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o022) !== 0 ||
      typeof process.getuid === "function" && before.uid !== process.getuid() ||
      await realpath(directoryPath) !== directoryPath) {
    throw new Error("Finality custodian store directory is unsafe");
  }
  const handle = await open(directoryPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0));
  const after = await handle.stat();
  if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino ||
      (after.mode & 0o022) !== 0 || typeof process.getuid === "function" && after.uid !== process.getuid()) {
    await handle.close();
    throw new Error("Finality custodian store directory changed");
  }
  return handle;
}

async function readRecord(path) {
  const directory = await protectedDirectory(path);
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o077) !== 0 || before.size < 2 ||
        before.size > MAX_FILE_BYTES || typeof process.getuid === "function" && before.uid !== process.getuid()) {
      throw new Error("Finality custodian store file is unsafe");
    }
    const encoded = await handle.readFile("utf8"), after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev || after.ino !== before.ino ||
        after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs ||
        (after.mode & 0o077) !== 0 || typeof process.getuid === "function" && after.uid !== process.getuid()) {
      throw new Error("Finality custodian store changed while being read");
    }
    let parsed;
    try { parsed = JSON.parse(encoded); } catch (cause) {
      throw new Error("Finality custodian store is not valid JSON", { cause });
    }
    if (encoded !== `${JSON.stringify(parsed)}\n`) throw new Error("Finality custodian store is not canonical");
    return checkedRecord(parsed);
  } finally {
    await handle?.close();
    await directory.close();
  }
}

async function lockPresent(path) {
  return lstat(`${path}.lock`).then(() => true, error => {
    if (error?.code === "ENOENT") return false;
    throw error;
  });
}

async function readUnderLock(path) {
  const lockPath = `${path}.lock`, directory = await protectedDirectory(path);
  let lock, lockStat, result, failure = null;
  try {
    try {
      lock = await open(lockPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    } catch (cause) {
      throw new Error("Finality custodian store is locked; inspect before retrying", { cause });
    }
    await lock.writeFile(`${JSON.stringify({ format: "bloch-l2-finality-custodian-store-lock-v1",
      token: randomBytes(32).toString("hex") })}\n`);
    await lock.sync(); await directory.sync();
    lockStat = await lock.stat();
    if (!lockStat.isFile() || lockStat.nlink !== 1 || (lockStat.mode & 0o077) !== 0) {
      throw new Error("Finality custodian store lock is unsafe");
    }
    result = await readRecord(path);
  } catch (error) { failure = error; }
  let cleanup = null;
  if (lock && lockStat) {
    try {
      const linked = await lstat(lockPath), actual = await lock.stat();
      if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 ||
          linked.dev !== lockStat.dev || linked.ino !== lockStat.ino ||
          actual.dev !== lockStat.dev || actual.ino !== lockStat.ino) {
        throw new Error("Finality custodian store lock changed; refusing removal");
      }
      await unlink(lockPath); await directory.sync();
    } catch (error) { cleanup = error; }
  }
  await lock?.close().catch(error => { cleanup ??= error; });
  await directory.close().catch(error => { cleanup ??= error; });
  if (cleanup) throw new Error("Finality custodian store requires inspection before retrying", { cause: cleanup });
  if (failure) throw failure;
  return result;
}

export async function initializeFilesystemFinalityCustodianStore({ storePath, record,
  expectedRecordHash } = {}) {
  const initial = checkedRecord(record);
  if (initial.generation !== "0" || initial.recordHash !== expectedRecordHash) {
    throw new Error("Finality custodian store does not match its externally approved initial record");
  }
  const directory = await protectedDirectory(storePath);
  try {
    const output = await open(storePath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try { await output.writeFile(`${JSON.stringify(initial)}\n`); await output.sync(); }
    finally { await output.close(); }
    await directory.sync();
  } finally { await directory.close(); }
  return initial;
}

export async function initializeApprovedFilesystemFinalityCustodianStore({ storePath, approval,
  expectedDeploymentId, authorityPublicKey } = {}) {
  const record = verifyFinalityCustodianStoreApproval({ approval, expectedDeploymentId,
    authorityPublicKey });
  if (record.generation !== "0") {
    throw new Error("Finality custodian initial store approval is not generation zero");
  }
  return initializeFilesystemFinalityCustodianStore({ storePath, record,
    expectedRecordHash: record.recordHash });
}

export async function inspectFilesystemFinalityCustodianStore(storePath) {
  const record = await readRecord(storePath);
  return Object.freeze({ ...record, lockPresent: await lockPresent(storePath) });
}

function nextRecord(current, stateHash) {
  const generation = BigInt(current.generation) + 1n;
  if (generation > 0xffffffffffffffffn) throw new Error("Finality custodian store generation exhausted");
  const next = { format: BLOCH_L2_FINALITY_CUSTODIAN_STORE_FORMAT,
    generation: generation.toString(), stateHash, previousRecordHash: current.recordHash };
  return checkedRecord({ ...next, recordHash: digest(next) });
}

async function replaceRecord(path, current, next) {
  const lockPath = `${path}.lock`, temporary = `${path}.tmp-${process.pid}-${randomBytes(12).toString("hex")}`;
  const directory = await protectedDirectory(path);
  let lock, lockStat, temporaryStat, replacementVerified = false, safeFailure = false;
  try {
    try {
      lock = await open(lockPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    } catch (cause) {
      throw new Error("Finality custodian store is locked; inspect before retrying", { cause });
    }
    await lock.writeFile(`${JSON.stringify({ format: "bloch-l2-finality-custodian-store-lock-v1",
      token: randomBytes(32).toString("hex") })}\n`);
    await lock.sync(); await directory.sync();
    lockStat = await lock.stat();
    if (!lockStat.isFile() || lockStat.nlink !== 1 || (lockStat.mode & 0o077) !== 0) {
      throw new Error("Finality custodian store lock is unsafe");
    }
    const observed = await readRecord(path);
    if (observed.recordHash !== current.recordHash) {
      safeFailure = true;
      throw new Error("Finality custodian store changed before CAS");
    }
    const output = await open(temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try {
      await output.writeFile(`${JSON.stringify(next)}\n`); await output.sync();
      temporaryStat = await output.stat();
      if (!temporaryStat.isFile() || temporaryStat.nlink !== 1 || (temporaryStat.mode & 0o077) !== 0) {
        throw new Error("Finality custodian store temporary file is unsafe");
      }
    } finally { await output.close(); }
    await rename(temporary, path); await directory.sync();
    if ((await readRecord(path)).recordHash !== next.recordHash) {
      throw new Error("Finality custodian store readback is ambiguous");
    }
    replacementVerified = true;
  } finally {
    let cleanup = null;
    try {
      const linked = await lstat(temporary);
      if (!temporaryStat || !linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 ||
          linked.dev !== temporaryStat.dev || linked.ino !== temporaryStat.ino) {
        throw new Error("Finality custodian store temporary path changed; refusing removal");
      }
      await unlink(temporary);
    } catch (error) { if (error?.code !== "ENOENT") cleanup = error; }
    if (lock && lockStat && (replacementVerified || safeFailure)) {
      try {
        const linked = await lstat(lockPath), actual = await lock.stat();
        if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 ||
            linked.dev !== lockStat.dev || linked.ino !== lockStat.ino ||
            actual.dev !== lockStat.dev || actual.ino !== lockStat.ino) {
          throw new Error("Finality custodian store lock changed; refusing removal");
        }
        await unlink(lockPath); await directory.sync();
      } catch (error) { cleanup ??= error; }
    } else if (lock) {
      cleanup ??= new Error("Finality custodian store transition is ambiguous; lock retained");
    }
    await lock?.close().catch(error => { cleanup ??= error; });
    await directory.close().catch(error => { cleanup ??= error; });
    if (cleanup) throw new Error("Finality custodian store requires inspection before retrying", { cause: cleanup });
  }
}

export async function createFilesystemFinalityCustodianStore({ storePath, expectedRecordHash } = {}) {
  checkedHash(expectedRecordHash, false, "Finality custodian externally retained record hash is invalid");
  if (await lockPresent(storePath)) throw new Error("Finality custodian store is locked; inspect before retrying");
  let retained = await readRecord(storePath);
  if (retained.recordHash !== expectedRecordHash) {
    throw new Error("Finality custodian store does not match its externally retained record hash");
  }
  let busy = false;
  return Object.freeze({
    async load() {
      if (busy) throw new Error("Finality custodian store already has an operation in progress");
      busy = true;
      try {
        const observed = await readUnderLock(storePath);
        if (observed.recordHash !== retained.recordHash) {
          throw new Error("Finality custodian store changed outside this process");
        }
        return observed.stateHash;
      } finally { busy = false; }
    },
    async compareAndSwap(expected, replacement) {
      checkedHash(expected, true, "Finality custodian store expected hash is invalid");
      checkedHash(replacement, false, "Finality custodian store replacement hash is invalid");
      if (expected === replacement) throw new Error("Finality custodian store CAS is not an advance");
      if (busy) throw new Error("Finality custodian store already has an operation in progress");
      busy = true;
      try {
        const observed = await readUnderLock(storePath);
        if (observed.recordHash !== retained.recordHash) {
          throw new Error("Finality custodian store changed outside this process");
        }
        if (retained.stateHash !== expected) {
          return Object.freeze({ status: "conflict", currentStateHash: retained.stateHash });
        }
        const next = nextRecord(retained, replacement);
        await replaceRecord(storePath, retained, next);
        retained = next;
        return Object.freeze({ status: "committed" });
      } finally { busy = false; }
    },
    record: () => retained,
  });
}

export async function createApprovedFilesystemFinalityCustodianStore({ storePath, approval,
  expectedDeploymentId, authorityPublicKey } = {}) {
  const record = verifyFinalityCustodianStoreApproval({ approval, expectedDeploymentId,
    authorityPublicKey });
  return createFilesystemFinalityCustodianStore({ storePath, expectedRecordHash: record.recordHash });
}

export async function createContinuityApprovedFilesystemFinalityCustodianStore({ storePath,
  continuity, expectedDeploymentId, expectedPreviousRecord, previousAuthorityPublicKey,
  nextAuthorityPublicKey } = {}) {
  const record = verifyFinalityCustodianStoreContinuity({ continuity, expectedDeploymentId,
    expectedPreviousRecord, previousAuthorityPublicKey, nextAuthorityPublicKey });
  return createFilesystemFinalityCustodianStore({ storePath, expectedRecordHash: record.recordHash });
}
