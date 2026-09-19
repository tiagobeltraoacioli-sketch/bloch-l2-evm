// SPDX-License-Identifier: MIT OR Apache-2.0

import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { basename, dirname, resolve } from "node:path";
import { canonicalBlochL2FinalityPayloadJson } from "./finality-attestation.mjs";

const FORMAT = "bloch-l2-finality-quorum-checkpoint-state-v1";
const HASH = /^[0-9a-f]{64}$/;
const PROTOCOL = /^[a-z0-9._:-]{1,128}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_FILE_BYTES = 64 * 1024;
const FIELDS = ["format", "quorumId", "threshold", "finalityProtocol", "identity", "checkpoint",
  "generation", "previousStateHash", "bundleHash", "stateHash"];

export class FinalityQuorumCustodianError extends Error {
  constructor(message, { uncertain = false, currentStateHash = undefined, cause = undefined } = {}) {
    super(message, { cause });
    this.name = "FinalityQuorumCustodianError";
    this.uncertain = uncertain;
    this.currentStateHash = currentStateHash;
  }
}

function exact(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) throw new Error(message);
  return value;
}

function hashBody(body) {
  return createHash("sha256").update("BLOCH-L2-FINALITY-QUORUM-CHECKPOINT-v1\0")
    .update(JSON.stringify(body)).digest("hex");
}

function canonicalIdentityCheckpoint(identity, checkpoint, finalityProtocol) {
  const payload = JSON.parse(canonicalBlochL2FinalityPayloadJson({
    format: "bloch-l2-finality-attestation-v1", identity, checkpoint, issuedAt: 0, expiresAt: 1,
    finalityProtocol, finalityReference: `0x${"00".repeat(32)}`,
  }));
  return { identity: payload.identity, checkpoint: payload.checkpoint };
}

function body(value) {
  return { format: value.format, quorumId: value.quorumId, threshold: value.threshold,
    finalityProtocol: value.finalityProtocol, identity: value.identity, checkpoint: value.checkpoint,
    generation: value.generation, previousStateHash: value.previousStateHash, bundleHash: value.bundleHash };
}

function checkedState(value) {
  exact(value, FIELDS, "Finality quorum checkpoint state is invalid");
  if (value.format !== FORMAT || !HASH.test(value.quorumId) || !Number.isSafeInteger(value.threshold) ||
      value.threshold < 2 || !PROTOCOL.test(value.finalityProtocol) || !U64.test(value.generation) ||
      BigInt(value.generation) < 1n || BigInt(value.generation) > 0xffffffffffffffffn ||
      (value.previousStateHash !== null && !HASH.test(value.previousStateHash)) ||
      (value.generation === "1") !== (value.previousStateHash === null) || !HASH.test(value.bundleHash) ||
      !HASH.test(value.stateHash) || hashBody(body(value)) !== value.stateHash) {
    throw new Error("Finality quorum checkpoint state is invalid");
  }
  const canonical = canonicalIdentityCheckpoint(value.identity, value.checkpoint, value.finalityProtocol);
  return Object.freeze({ ...value, ...canonical });
}

async function protectedDirectory(path) {
  path = absoluteCheckpointPath(path);
  const directoryPath = dirname(path), before = await lstat(directoryPath, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o022n) !== 0n ||
      typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) {
    throw new Error("Finality quorum checkpoint directory is unsafe");
  }
  if (await realpath(directoryPath) !== directoryPath) {
    throw new Error("Finality quorum checkpoint directory traverses a symlink");
  }
  const handle = await open(directoryPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0));
  const after = await handle.stat({ bigint: true });
  if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino || (after.mode & 0o022n) !== 0n ||
      typeof process.getuid === "function" && after.uid !== BigInt(process.getuid())) {
    await handle.close();
    throw new Error("Finality quorum checkpoint directory changed");
  }
  return handle;
}

async function readState(path) {
  path = absoluteCheckpointPath(path);
  const directory = await protectedDirectory(path);
  let handle;
  try {
    const directoryPath = dirname(path), directoryBefore = await directory.stat({ bigint: true });
    try { handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW); } catch (error) {
      if (error?.code === "ENOENT") {
        await validateDirectoryName(path, directory);
        return null;
      }
      throw error;
    }
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n ||
        typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()) ||
        before.size <= 0n || before.size > BigInt(MAX_FILE_BYTES)) {
      throw new Error("Finality quorum checkpoint file is unsafe");
    }
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_FILE_BYTES) throw new Error("Finality quorum checkpoint exceeds its size limit");
    const after = await handle.stat({ bigint: true });
    const namedAfter = await lstat(path, { bigint: true });
    const directoryAfter = await directory.stat({ bigint: true });
    const namedDirectoryAfter = await lstat(directoryPath, { bigint: true });
    if (!after.isFile() || after.nlink !== 1n || (after.mode & 0o077n) !== 0n ||
        typeof process.getuid === "function" && after.uid !== BigInt(process.getuid()) ||
        !sameIntegralSnapshot(before, after) || !sameIntegralSnapshot(after, namedAfter) ||
        BigInt(offset) !== after.size || !sameIntegralSnapshot(directoryBefore, directoryAfter) ||
        !sameIntegralSnapshot(directoryAfter, namedDirectoryAfter) ||
        await realpath(directoryPath) !== directoryPath) {
      throw new Error("Finality quorum checkpoint changed while being read");
    }
    const encoded = buffer.subarray(0, offset).toString("utf8");
    let parsed;
    try { parsed = JSON.parse(encoded); }
    catch (cause) { throw new Error("Finality quorum checkpoint is not valid JSON", { cause }); }
    if (encoded !== `${JSON.stringify(parsed)}\n`) throw new Error("Finality quorum checkpoint is not canonical");
    return checkedState(parsed);
  } finally {
    await handle?.close();
    await directory.close();
  }
}

function sameIntegralSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function absoluteCheckpointPath(path) {
  if (typeof path !== "string" || !path) throw new Error("Finality quorum checkpoint path is invalid");
  return resolve(path);
}

async function validateDirectoryName(path, directory) {
  const directoryPath = dirname(absoluteCheckpointPath(path));
  const actual = await directory.stat({ bigint: true });
  const named = await lstat(directoryPath, { bigint: true });
  if (!actual.isDirectory() || !named.isDirectory() || named.isSymbolicLink() ||
      actual.dev !== named.dev || actual.ino !== named.ino ||
      (actual.mode & 0o022n) !== 0n || (named.mode & 0o022n) !== 0n ||
      typeof process.getuid === "function" &&
        (actual.uid !== BigInt(process.getuid()) || named.uid !== BigInt(process.getuid())) ||
      await realpath(directoryPath) !== directoryPath) {
    throw new Error("Finality quorum checkpoint directory changed");
  }
}

function anchoredChild(directory, path) {
  if (process.platform !== "linux" || !Number.isSafeInteger(directory.fd) || directory.fd < 0) {
    throw new Error("Finality quorum checkpoint mutations require Linux descriptor-relative paths");
  }
  return `/proc/self/fd/${directory.fd}/${basename(path)}`;
}

async function readExactHandle(handle, bytes) {
  const buffer = Buffer.alloc(bytes.length + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return offset === bytes.length && buffer.subarray(0, offset).equals(bytes);
}

async function validateMutationAuthority(path, directory, lock, lockStat, lockBytes) {
  await validateDirectoryName(path, directory);
  const linked = await lstat(anchoredChild(directory, `${path}.lock`), { bigint: true });
  const actual = await lock.stat({ bigint: true });
  if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1n ||
      (linked.mode & 0o077n) !== 0n || !sameIntegralSnapshot(lockStat, actual) ||
      !sameIntegralSnapshot(actual, linked) || !await readExactHandle(lock, lockBytes)) {
    throw new Error("Finality quorum checkpoint lock changed; refusing mutation");
  }
}

async function validateReleasedLock(lock, lockStat, lockBytes) {
  const actual = await lock.stat({ bigint: true });
  if (actual.dev !== lockStat.dev || actual.ino !== lockStat.ino || actual.mode !== lockStat.mode ||
      actual.uid !== lockStat.uid || actual.gid !== lockStat.gid || actual.size !== lockStat.size ||
      actual.mtimeNs !== lockStat.mtimeNs || actual.nlink !== 0n ||
      !await readExactHandle(lock, lockBytes)) {
    throw new Error("Finality quorum checkpoint lock removal is ambiguous");
  }
}

async function validateTemporary(path, handle, snapshot, bytes, named = true, renamed = false) {
  const actual = await handle.stat({ bigint: true });
  if (renamed ? actual.dev !== snapshot.dev || actual.ino !== snapshot.ino ||
      actual.mode !== snapshot.mode || actual.uid !== snapshot.uid || actual.gid !== snapshot.gid ||
      actual.nlink !== snapshot.nlink || actual.size !== snapshot.size || actual.mtimeNs !== snapshot.mtimeNs
    : !sameIntegralSnapshot(snapshot, actual)) {
    throw new Error("Finality quorum checkpoint temporary file changed; refusing mutation");
  }
  if (named) {
    const linked = await lstat(path, { bigint: true });
    if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1n ||
        !sameIntegralSnapshot(actual, linked)) {
      throw new Error("Finality quorum checkpoint temporary path changed; refusing mutation");
    }
  }
  const buffer = Buffer.alloc(bytes.length + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== bytes.length || !buffer.subarray(0, offset).equals(bytes)) {
    throw new Error("Finality quorum checkpoint temporary bytes changed; refusing mutation");
  }
}

async function pinPredecessor(path, expectedStateHash) {
  if (expectedStateHash === null) {
    try {
      await lstat(path);
      throw new Error("Finality quorum checkpoint appeared before CAS");
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n ||
        before.size <= 0n || before.size > BigInt(MAX_FILE_BYTES) ||
        typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) {
      throw new Error("Finality quorum checkpoint predecessor is unsafe");
    }
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_FILE_BYTES) throw new Error("Finality quorum checkpoint predecessor exceeds its size limit");
    const after = await handle.stat({ bigint: true });
    const named = await lstat(path, { bigint: true });
    if (!sameIntegralSnapshot(before, after) || !sameIntegralSnapshot(after, named) ||
        BigInt(offset) !== after.size) {
      throw new Error("Finality quorum checkpoint predecessor changed while being pinned");
    }
    const bytes = Buffer.from(buffer.subarray(0, offset));
    let parsed;
    try { parsed = JSON.parse(bytes.toString("utf8")); } catch (cause) {
      throw new Error("Finality quorum checkpoint predecessor is not valid JSON", { cause });
    }
    if (bytes.toString("utf8") !== `${JSON.stringify(parsed)}\n` ||
        checkedState(parsed).stateHash !== expectedStateHash) {
      throw new Error("Finality quorum checkpoint predecessor does not match the authorized state");
    }
    return { handle, snapshot: after, bytes };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function retainPredecessorEvidence(evidencePath, predecessor) {
  if (!predecessor) return;
  const handle = await open(evidencePath,
    fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(predecessor.bytes); await handle.sync();
    const snapshot = await handle.stat({ bigint: true });
    const named = await lstat(evidencePath, { bigint: true });
    if (!snapshot.isFile() || snapshot.nlink !== 1n || (snapshot.mode & 0o077n) !== 0n ||
        !sameIntegralSnapshot(snapshot, named)) {
      throw new Error("Finality quorum checkpoint predecessor evidence is ambiguous");
    }
    predecessor.evidence = { handle, path: evidencePath, snapshot };
  } catch (error) {
    await handle.close();
    throw new Error("Finality quorum checkpoint predecessor evidence is ambiguous");
  }
}

async function validatePredecessorEvidence(predecessor) {
  if (!predecessor) return;
  const actual = await predecessor.evidence.handle.stat({ bigint: true });
  const named = await lstat(predecessor.evidence.path, { bigint: true });
  if (!sameIntegralSnapshot(predecessor.evidence.snapshot, actual) ||
      !sameIntegralSnapshot(actual, named)) {
    throw new Error("Finality quorum checkpoint predecessor evidence changed");
  }
  const buffer = Buffer.alloc(predecessor.bytes.length + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await predecessor.evidence.handle.read(
      buffer, offset, buffer.length - offset, offset,
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== predecessor.bytes.length || !buffer.subarray(0, offset).equals(predecessor.bytes)) {
    throw new Error("Finality quorum checkpoint predecessor evidence changed");
  }
}

async function validatePredecessor(path, predecessor) {
  if (!predecessor) {
    try {
      await lstat(path);
      throw new Error("Finality quorum checkpoint appeared before replacement");
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
  }
  const actual = await predecessor.handle.stat({ bigint: true });
  const named = await lstat(path, { bigint: true });
  if (!sameIntegralSnapshot(predecessor.snapshot, actual) || !sameIntegralSnapshot(actual, named)) {
    throw new Error("Finality quorum checkpoint predecessor changed; refusing replacement");
  }
  await validatePredecessorEvidence(predecessor);
}

async function validateDisplacedPredecessor(predecessor) {
  if (!predecessor) return;
  const actual = await predecessor.handle.stat({ bigint: true });
  if (actual.dev !== predecessor.snapshot.dev || actual.ino !== predecessor.snapshot.ino ||
      actual.mode !== predecessor.snapshot.mode || actual.uid !== predecessor.snapshot.uid ||
      actual.gid !== predecessor.snapshot.gid || actual.size !== predecessor.snapshot.size ||
      actual.mtimeNs !== predecessor.snapshot.mtimeNs || actual.nlink !== 0n) {
    throw new Error("Finality quorum checkpoint displaced predecessor changed");
  }
  await validatePredecessorEvidence(predecessor);
  const buffer = Buffer.alloc(predecessor.bytes.length + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await predecessor.handle.read(buffer, offset, buffer.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== predecessor.bytes.length || !buffer.subarray(0, offset).equals(predecessor.bytes)) {
    throw new Error("Finality quorum checkpoint displaced predecessor bytes changed");
  }
}

async function releasePredecessorEvidence(predecessor) {
  if (!predecessor) return;
  await validatePredecessorEvidence(predecessor);
  await unlink(predecessor.evidence.path);
  const actual = await predecessor.evidence.handle.stat({ bigint: true });
  if (actual.dev !== predecessor.evidence.snapshot.dev || actual.ino !== predecessor.evidence.snapshot.ino ||
      actual.mode !== predecessor.evidence.snapshot.mode || actual.uid !== predecessor.evidence.snapshot.uid ||
      actual.gid !== predecessor.evidence.snapshot.gid || actual.size !== predecessor.evidence.snapshot.size ||
      actual.mtimeNs !== predecessor.evidence.snapshot.mtimeNs || actual.nlink !== 0n) {
    throw new Error("Finality quorum checkpoint predecessor evidence cleanup is ambiguous");
  }
}

async function replaceState(path, state, expectedHash, retainExternally = null) {
  path = absoluteCheckpointPath(path);
  const token = randomBytes(12).toString("hex");
  const lockPath = `${path}.lock`, temporary = `${path}.tmp-${process.pid}-${token}`;
  const evidencePath = `${path}.previous-${process.pid}-${token}`;
  const directory = await protectedDirectory(path);
  const anchoredState = anchoredChild(directory, path);
  const anchoredLock = anchoredChild(directory, lockPath);
  const anchoredTemporary = anchoredChild(directory, temporary);
  const anchoredEvidence = anchoredChild(directory, evidencePath);
  let lock, lockStat, lockBytes, temporaryHandle, temporaryStat, temporaryBytes, predecessor,
    authorityDirectoryStat, lockInitialized = false, replacementAttempted = false,
    replacementVerified = false, externalAttempted = false, externalCommitConfirmed = false,
    externalOutcomeUncertain = false, safeFailure = false;
  try {
    try {
      await validateDirectoryName(path, directory);
      lock = await open(anchoredLock,
        fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    } catch (cause) {
      throw new Error("Finality quorum checkpoint is locked; inspect before retrying", { cause });
    }
    lockBytes = Buffer.from(`${JSON.stringify({ format: "bloch-l2-finality-quorum-checkpoint-lock-v1",
      pid: process.pid, token: randomBytes(32).toString("hex") })}\n`, "utf8");
    await lock.writeFile(lockBytes);
    await lock.sync(); await directory.sync();
    lockStat = await lock.stat({ bigint: true });
    if (!lockStat.isFile() || lockStat.nlink !== 1n || (lockStat.mode & 0o077n) !== 0n ||
        typeof process.getuid === "function" && lockStat.uid !== BigInt(process.getuid())) {
      throw new Error("Finality quorum checkpoint lock is unsafe");
    }
    lockInitialized = true;
    const observed = await readState(path);
    if ((observed?.stateHash ?? null) !== expectedHash) {
      safeFailure = true;
      throw new Error("Finality quorum checkpoint changed before CAS");
    }
    temporaryBytes = Buffer.from(`${JSON.stringify(state)}\n`, "utf8");
    if (temporaryBytes.length > MAX_FILE_BYTES) {
      safeFailure = true;
      throw new Error("Finality quorum checkpoint candidate exceeds its size limit");
    }
    predecessor = await pinPredecessor(anchoredState, expectedHash);
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    await retainPredecessorEvidence(anchoredEvidence, predecessor);
    temporaryHandle = await open(anchoredTemporary,
      fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    await temporaryHandle.writeFile(temporaryBytes); await temporaryHandle.sync();
    temporaryStat = await temporaryHandle.stat({ bigint: true });
    if (!temporaryStat.isFile() || temporaryStat.nlink !== 1n || (temporaryStat.mode & 0o077n) !== 0n ||
        typeof process.getuid === "function" && temporaryStat.uid !== BigInt(process.getuid())) {
      throw new Error("Finality quorum checkpoint temporary file is unsafe");
    }
    await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
    await validatePredecessor(anchoredState, predecessor);
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    await directory.sync();
    await validateDirectoryName(path, directory);
    await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
    await validatePredecessor(anchoredState, predecessor);
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    authorityDirectoryStat = await directory.stat({ bigint: true });
    if (retainExternally) {
      try {
        externalAttempted = true;
        await retainExternally();
        externalCommitConfirmed = true;
      } catch (error) {
        externalOutcomeUncertain = error instanceof FinalityQuorumCustodianError && error.uncertain;
        safeFailure = error instanceof FinalityQuorumCustodianError && !error.uncertain;
        throw error;
      }
    }
    replacementAttempted = true;
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    const directoryBeforeReplacement = await directory.stat({ bigint: true });
    if (!sameIntegralSnapshot(authorityDirectoryStat, directoryBeforeReplacement)) {
      throw new Error("Finality quorum checkpoint directory changed during external CAS");
    }
    await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
    await validatePredecessor(anchoredState, predecessor);
    await rename(anchoredTemporary, anchoredState);
    await directory.sync();
    await validateDirectoryName(path, directory);
    await validateTemporary(anchoredState, temporaryHandle, temporaryStat, temporaryBytes, true, true);
    await validateDisplacedPredecessor(predecessor);
    const retained = await readState(path);
    if (retained.stateHash !== state.stateHash) throw new Error("Finality quorum checkpoint readback is ambiguous");
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    await validateDirectoryName(path, directory);
    replacementVerified = true;
    await releasePredecessorEvidence(predecessor);
    await directory.sync();
  } finally {
    let cleanup = null;
    if (lockInitialized && !replacementVerified &&
        (!externalAttempted || safeFailure && !externalCommitConfirmed)) {
      try {
        if (!temporaryStat || !temporaryHandle || !temporaryBytes) {
          await lstat(anchoredTemporary);
          throw new Error("Finality quorum checkpoint temporary path is unverified");
        }
        await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
        await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
        await unlink(anchoredTemporary);
        await releasePredecessorEvidence(predecessor);
        await directory.sync();
      } catch (error) { if (error?.code !== "ENOENT") cleanup = error; }
    }
    if (lock && !lockInitialized) cleanup ??= new Error("Finality quorum checkpoint lock initialization is ambiguous");
    if (replacementAttempted && !replacementVerified) {
      cleanup ??= new Error("Finality quorum checkpoint replacement is ambiguous");
    }
    if (externalOutcomeUncertain || externalCommitConfirmed && !replacementVerified) {
      cleanup ??= new Error("External checkpoint custody outcome requires reconciliation");
    }
    if (!cleanup && lockInitialized &&
        (replacementVerified || safeFailure && !externalCommitConfirmed && !replacementAttempted)) {
      try {
        await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
        await unlink(anchoredLock);
        await validateReleasedLock(lock, lockStat, lockBytes);
        await directory.sync();
        await validateReleasedLock(lock, lockStat, lockBytes);
        await validateDirectoryName(path, directory);
      } catch (error) { cleanup ??= error; }
    } else if (!cleanup && lockInitialized) {
      cleanup = new Error("Finality quorum checkpoint transition is ambiguous; lock retained");
    }
    await temporaryHandle?.close().catch(error => { cleanup ??= error; });
    await predecessor?.evidence?.handle.close().catch(error => { cleanup ??= error; });
    await predecessor?.handle.close().catch(error => { cleanup ??= error; });
    await lock?.close().catch(error => { cleanup ??= error; });
    await directory.close().catch(error => { cleanup ??= error; });
    if (cleanup) throw new Error("Finality quorum checkpoint cleanup is ambiguous; inspect before retrying", { cause: cleanup });
  }
}

function deriveNextState({ current, quorumId, threshold, finalityProtocol, identity, checkpoint, bundleHash }) {
  const canonical = canonicalIdentityCheckpoint(identity, checkpoint, finalityProtocol);
  if (current) {
    if (current.quorumId !== quorumId || current.threshold !== threshold ||
        current.finalityProtocol !== finalityProtocol || JSON.stringify(current.identity) !== JSON.stringify(canonical.identity)) {
      throw new Error("Finality quorum checkpoint authority or chain identity changed");
    }
    const oldHeight = BigInt(current.checkpoint.headNumber), nextHeight = BigInt(canonical.checkpoint.headNumber);
    if (nextHeight <= oldHeight) throw new Error(nextHeight === oldHeight
      ? "Finality quorum checkpoint replay or same-height equivocation" : "Finality quorum checkpoint rollback");
  }
  const generation = current ? BigInt(current.generation) + 1n : 1n;
  if (generation > 0xffffffffffffffffn) throw new Error("Finality quorum checkpoint generation exhausted");
  const nextBody = { format: FORMAT, quorumId, threshold, finalityProtocol, identity: canonical.identity,
    checkpoint: canonical.checkpoint, generation: generation.toString(), previousStateHash: current?.stateHash ?? null,
    bundleHash };
  return Object.freeze({ ...nextBody, stateHash: hashBody(nextBody) });
}

function validateAdvance({ storePath, expectedStateHash, quorumId, threshold, finalityProtocol, bundleHash }) {
  if (typeof storePath !== "string" || !storePath || expectedStateHash !== null && !HASH.test(expectedStateHash) ||
      !HASH.test(quorumId) || !Number.isSafeInteger(threshold) || threshold < 2 || !PROTOCOL.test(finalityProtocol) ||
      !HASH.test(bundleHash)) throw new Error("Finality quorum checkpoint advance is invalid");
}

function checkedCustodian(custodian) {
  if (!custodian || typeof custodian !== "object" || Array.isArray(custodian) ||
      typeof custodian.load !== "function" || typeof custodian.compareAndSwap !== "function") {
    throw new TypeError("Finality quorum checkpoint custodian is invalid");
  }
  return custodian;
}

function checkedCustodianHash(value) {
  if (value !== null && (typeof value !== "string" || !HASH.test(value))) {
    throw new FinalityQuorumCustodianError("External checkpoint custodian returned an invalid state");
  }
  return value;
}

async function loadCustodian(custodian, message, uncertain = false) {
  try { return checkedCustodianHash(await custodian.load()); }
  catch (cause) {
    if (cause instanceof FinalityQuorumCustodianError && !uncertain) throw cause;
    throw new FinalityQuorumCustodianError(message, { uncertain, cause });
  }
}

async function retainWithCustodian(custodian, expectedStateHash, nextStateHash) {
  let outcome;
  try { outcome = await custodian.compareAndSwap(expectedStateHash, nextStateHash); }
  catch (cause) {
    throw new FinalityQuorumCustodianError(
      "External checkpoint custody outcome is uncertain; inspect before retrying", { uncertain: true, cause });
  }
  let status, keys;
  try {
    if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)) throw new Error("invalid outcome");
    keys = Object.keys(outcome);
    if (!Object.hasOwn(outcome, "status") || keys.some(key => !["status", "currentStateHash"].includes(key))) {
      throw new Error("invalid outcome");
    }
    status = outcome.status;
  } catch (cause) {
    throw new FinalityQuorumCustodianError(
      "External checkpoint custodian returned an ambiguous outcome", { uncertain: true, cause });
  }
  if (status === "conflict") {
    if (!Object.hasOwn(outcome, "currentStateHash")) {
      throw new FinalityQuorumCustodianError(
        "External checkpoint custodian returned an ambiguous conflict", { uncertain: true });
    }
    let currentStateHash;
    try { currentStateHash = checkedCustodianHash(outcome.currentStateHash); }
    catch (cause) {
      throw new FinalityQuorumCustodianError(
        "External checkpoint custodian returned an ambiguous conflict", { uncertain: true, cause });
    }
    throw new FinalityQuorumCustodianError("External checkpoint custodian CAS conflict", { currentStateHash });
  }
  if (status === "uncertain") {
    throw new FinalityQuorumCustodianError(
      "External checkpoint custody outcome is uncertain; inspect before retrying", { uncertain: true });
  }
  if (status !== "committed" || Object.hasOwn(outcome, "currentStateHash")) {
    throw new FinalityQuorumCustodianError(
      "External checkpoint custodian returned an ambiguous outcome", { uncertain: true });
  }
  const retained = await loadCustodian(custodian,
    "External checkpoint custody readback is uncertain; inspect before retrying", true);
  if (retained !== nextStateHash) {
    throw new FinalityQuorumCustodianError(
      "External checkpoint custodian did not retain the committed state exactly", { uncertain: true,
        currentStateHash: retained });
  }
}

export async function advanceFinalityQuorumCheckpoint({ storePath, expectedStateHash, quorumId, threshold,
  finalityProtocol, identity, checkpoint, bundleHash } = {}) {
  validateAdvance({ storePath, expectedStateHash, quorumId, threshold, finalityProtocol, bundleHash });
  const directory = await protectedDirectory(storePath); await directory.close();
  const current = await readState(storePath);
  if ((current?.stateHash ?? null) !== expectedStateHash) {
    throw new Error("Finality quorum checkpoint does not match the externally retained state hash");
  }
  const next = deriveNextState({ current, quorumId, threshold, finalityProtocol, identity, checkpoint, bundleHash });
  await replaceState(storePath, next, current?.stateHash ?? null);
  return next;
}

export async function inspectFinalityQuorumCheckpoint(storePath) {
  return readState(absoluteCheckpointPath(storePath));
}

export async function advanceCustodiedFinalityQuorumCheckpoint({ custodian, ...options } = {}) {
  validateAdvance(options);
  const external = checkedCustodian(custodian);
  const retained = await loadCustodian(external, "External checkpoint custodian could not be read");
  if (retained !== options.expectedStateHash) {
    throw new FinalityQuorumCustodianError(
      "External checkpoint custodian does not match the trusted state hash", { currentStateHash: retained });
  }
  const directory = await protectedDirectory(options.storePath); await directory.close();
  const current = await readState(options.storePath);
  if ((current?.stateHash ?? null) !== options.expectedStateHash) {
    throw new Error("Finality quorum checkpoint does not match the externally retained state hash");
  }
  const next = deriveNextState({ current, quorumId: options.quorumId, threshold: options.threshold,
    finalityProtocol: options.finalityProtocol, identity: options.identity, checkpoint: options.checkpoint,
    bundleHash: options.bundleHash });
  await replaceState(options.storePath, next, current?.stateHash ?? null,
    () => retainWithCustodian(external, current?.stateHash ?? null, next.stateHash));
  return next;
}

export const BLOCH_L2_FINALITY_QUORUM_CHECKPOINT_FORMAT = FORMAT;
