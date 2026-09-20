// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { link, lstat, open, realpath, rename, unlink } from "node:fs/promises";
import { AuthenticatedFinalityQuorumCustodian } from "./finality-quorum-custodian.mjs";

export const BLOCH_L2_FINALITY_CUSTODIAN_CHECKPOINT_FORMAT =
  "bloch-l2-finality-custodian-client-checkpoint-v1";

const HASH = /^[0-9a-f]{64}$/;
const ID = /^[a-z][a-z0-9-]{0,62}$/;
const SESSION = /^[A-Za-z0-9_-]{43}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_FILE_BYTES = 64 * 1024;
const STATE_FIELDS = ["format", "clientId", "custodianId", "session", "generation", "nextSequence",
  "status", "pendingRequestHash", "pendingOperation", "previousStateHash", "lastOutcome", "stateHash"];

function exact(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) throw new Error(message);
  return value;
}

function checkedSession(value) {
  if (typeof value !== "string" || !SESSION.test(value)) {
    throw new Error("Finality custodian checkpoint session is invalid");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32 || decoded.equals(Buffer.alloc(32)) || decoded.toString("base64url") !== value) {
    throw new Error("Finality custodian checkpoint session is invalid");
  }
  return value;
}

function checkedU64(value, message) {
  if (typeof value !== "string" || !U64.test(value) || BigInt(value) > 0xffffffffffffffffn) {
    throw new Error(message);
  }
  return value;
}

function checkedOutcome(value) {
  if (value === null) return null;
  exact(value, ["requestHash", "status", "currentStateHash"],
    "Finality custodian checkpoint outcome is invalid");
  if (!HASH.test(value.requestHash) || !["current", "committed", "conflict"].includes(value.status) ||
      value.currentStateHash !== null && !HASH.test(value.currentStateHash)) {
    throw new Error("Finality custodian checkpoint outcome is invalid");
  }
  return Object.freeze({ ...value });
}

function stateBody(value) {
  return Object.fromEntries(STATE_FIELDS.slice(0, -1).map(field => [field, value[field]]));
}

function stateHash(body) {
  return createHash("sha256").update("BLOCH-L2-FINALITY-CUSTODIAN-CLIENT-CHECKPOINT-v1\0")
    .update(JSON.stringify(body)).digest("hex");
}

function checkedState(value) {
  exact(value, STATE_FIELDS, "Finality custodian checkpoint state is invalid");
  checkedSession(value.session);
  checkedU64(value.generation, "Finality custodian checkpoint generation is invalid");
  checkedU64(value.nextSequence, "Finality custodian checkpoint sequence is invalid");
  const pending = value.status === "pending";
  if (value.format !== BLOCH_L2_FINALITY_CUSTODIAN_CHECKPOINT_FORMAT || !ID.test(value.clientId) ||
      !ID.test(value.custodianId) || value.clientId === value.custodianId ||
      !["ready", "pending"].includes(value.status) ||
      pending !== (typeof value.pendingRequestHash === "string" && HASH.test(value.pendingRequestHash)) ||
      pending !== ["load", "compare-and-swap"].includes(value.pendingOperation) ||
      (!pending && (value.pendingRequestHash !== null || value.pendingOperation !== null)) ||
      (value.generation === "0") !== (value.previousStateHash === null) ||
      value.previousStateHash !== null && !HASH.test(value.previousStateHash) ||
      !HASH.test(value.stateHash) || stateHash(stateBody(value)) !== value.stateHash) {
    throw new Error("Finality custodian checkpoint state is invalid");
  }
  const outcome = checkedOutcome(value.lastOutcome);
  if (value.generation === "0" && (value.nextSequence !== "0" || value.status !== "ready" || outcome !== null)) {
    throw new Error("Finality custodian initial checkpoint is invalid");
  }
  return Object.freeze({ ...value, lastOutcome: outcome });
}

export function createInitialFinalityCustodianCheckpoint({ clientId, custodianId, session } = {}) {
  const body = { format: BLOCH_L2_FINALITY_CUSTODIAN_CHECKPOINT_FORMAT, clientId, custodianId,
    session: checkedSession(session), generation: "0", nextSequence: "0", status: "ready",
    pendingRequestHash: null, pendingOperation: null, previousStateHash: null, lastOutcome: null };
  return checkedState({ ...body, stateHash: stateHash(body) });
}

async function protectedDirectory(path) {
  path = absoluteCheckpointPath(path);
  const directoryPath = dirname(path), before = await lstat(directoryPath);
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o022) !== 0 ||
      typeof process.getuid === "function" && before.uid !== process.getuid() ||
      await realpath(directoryPath) !== directoryPath) {
    throw new Error("Finality custodian checkpoint directory is unsafe");
  }
  const handle = await open(directoryPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0));
  const after = await handle.stat();
  if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino ||
      (after.mode & 0o022) !== 0 || typeof process.getuid === "function" && after.uid !== process.getuid()) {
    await handle.close();
    throw new Error("Finality custodian checkpoint directory changed");
  }
  return handle;
}

async function readState(path, retainedDirectory = null, retainedEvidence = null) {
  path = absoluteCheckpointPath(path);
  const directory = retainedDirectory ?? await protectedDirectory(path);
  const ownsDirectory = retainedDirectory === null;
  let handle;
  try {
    const directoryPath = dirname(path);
    const directoryBefore = await directory.stat({ bigint: true });
    handle = await open(process.platform === "linux" ? anchoredChild(directory, path) : path,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n || before.size < 2n ||
        before.size > BigInt(MAX_FILE_BYTES) || typeof process.getuid === "function" &&
        before.uid !== BigInt(process.getuid())) {
      throw new Error("Finality custodian checkpoint file is unsafe");
    }
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_FILE_BYTES) throw new Error("Finality custodian checkpoint exceeds its size limit");
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
      throw new Error("Finality custodian checkpoint changed while being read");
    }
    const encoded = buffer.subarray(0, offset).toString("utf8");
    let parsed;
    try { parsed = JSON.parse(encoded); } catch (cause) {
      throw new Error("Finality custodian checkpoint is not valid JSON", { cause });
    }
    if (encoded !== `${JSON.stringify(parsed)}\n`) {
      throw new Error("Finality custodian checkpoint is not canonical");
    }
    if (retainedEvidence) {
      retainedEvidence.snapshot = after;
      retainedEvidence.bytes = Buffer.from(buffer.subarray(0, offset));
    }
    return checkedState(parsed);
  } finally {
    await handle?.close();
    if (ownsDirectory) await directory.close();
  }
}

function sameIntegralSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function absoluteCheckpointPath(path) {
  if (typeof path !== "string" || !path) throw new Error("Finality custodian checkpoint path is invalid");
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
    throw new Error("Finality custodian checkpoint directory changed");
  }
}

function anchoredChild(directory, path) {
  if (process.platform !== "linux" || !Number.isSafeInteger(directory.fd) || directory.fd < 0) {
    throw new Error("Finality custodian checkpoint mutations require Linux descriptor-relative paths");
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
      (linked.mode & 0o077n) !== 0n || linked.dev !== lockStat.dev || linked.ino !== lockStat.ino ||
      actual.dev !== lockStat.dev || actual.ino !== lockStat.ino ||
      !sameIntegralSnapshot(lockStat, actual) || !sameIntegralSnapshot(actual, linked) ||
      !await readExactHandle(lock, lockBytes)) {
    throw new Error("Finality custodian checkpoint lock changed; refusing mutation");
  }
}

async function validateReleasedLock(lock, lockStat, lockBytes) {
  const actual = await lock.stat({ bigint: true });
  if (actual.dev !== lockStat.dev || actual.ino !== lockStat.ino || actual.mode !== lockStat.mode ||
      actual.uid !== lockStat.uid || actual.gid !== lockStat.gid || actual.size !== lockStat.size ||
      actual.mtimeNs !== lockStat.mtimeNs || actual.nlink !== 0n ||
      !await readExactHandle(lock, lockBytes)) {
    throw new Error("Finality custodian checkpoint lock removal is ambiguous");
  }
}

async function validateTemporary(path, handle, temporaryStat, bytes, renamed = false) {
  const actual = await handle.stat({ bigint: true });
  const linked = await lstat(path, { bigint: true });
  if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1n ||
      (renamed ? actual.dev !== temporaryStat.dev || actual.ino !== temporaryStat.ino ||
        actual.mode !== temporaryStat.mode || actual.uid !== temporaryStat.uid ||
        actual.gid !== temporaryStat.gid || actual.nlink !== temporaryStat.nlink ||
        actual.size !== temporaryStat.size || actual.mtimeNs !== temporaryStat.mtimeNs
        : !sameIntegralSnapshot(temporaryStat, actual)) ||
      !sameIntegralSnapshot(actual, linked) || !await readExactHandle(handle, bytes)) {
    throw new Error("Finality custodian checkpoint temporary path changed; refusing mutation");
  }
}

async function pinPredecessor(path, expectedStateHash) {
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n ||
        before.size < 2n || before.size > BigInt(MAX_FILE_BYTES) ||
        typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) {
      throw new Error("Finality custodian checkpoint predecessor is unsafe");
    }
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_FILE_BYTES) {
      throw new Error("Finality custodian checkpoint predecessor exceeds its size limit");
    }
    const after = await handle.stat({ bigint: true });
    const named = await lstat(path, { bigint: true });
    if (!sameIntegralSnapshot(before, after) || !sameIntegralSnapshot(after, named) ||
        BigInt(offset) !== after.size) {
      throw new Error("Finality custodian checkpoint predecessor changed while being pinned");
    }
    const encoded = buffer.subarray(0, offset).toString("utf8");
    let parsed;
    try { parsed = JSON.parse(encoded); } catch (cause) {
      throw new Error("Finality custodian checkpoint predecessor is not valid JSON", { cause });
    }
    if (encoded !== `${JSON.stringify(parsed)}\n` || checkedState(parsed).stateHash !== expectedStateHash) {
      throw new Error("Finality custodian checkpoint predecessor does not match the authorized state");
    }
    return { handle, snapshot: after, bytes: Buffer.from(buffer.subarray(0, offset)) };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function retainPredecessorEvidence(path, predecessor) {
  const handle = await open(path,
    fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(predecessor.bytes); await handle.sync();
    const snapshot = await handle.stat({ bigint: true });
    const named = await lstat(path, { bigint: true });
    if (!snapshot.isFile() || snapshot.nlink !== 1n || (snapshot.mode & 0o077n) !== 0n ||
        !sameIntegralSnapshot(snapshot, named) || !await readExactHandle(handle, predecessor.bytes)) {
      throw new Error("Finality custodian checkpoint predecessor evidence is ambiguous");
    }
    predecessor.evidence = { handle, path, snapshot };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function validatePredecessorEvidence(predecessor) {
  const actual = await predecessor.evidence.handle.stat({ bigint: true });
  const named = await lstat(predecessor.evidence.path, { bigint: true });
  if (!sameIntegralSnapshot(predecessor.evidence.snapshot, actual) ||
      !sameIntegralSnapshot(actual, named) ||
      !await readExactHandle(predecessor.evidence.handle, predecessor.bytes)) {
    throw new Error("Finality custodian checkpoint predecessor evidence changed");
  }
}

async function validatePredecessor(path, predecessor) {
  const actual = await predecessor.handle.stat({ bigint: true });
  const named = await lstat(path, { bigint: true });
  if (!sameIntegralSnapshot(predecessor.snapshot, actual) ||
      !sameIntegralSnapshot(actual, named)) {
    throw new Error("Finality custodian checkpoint predecessor changed; refusing replacement");
  }
  await validatePredecessorEvidence(predecessor);
}

async function validateDisplacedPredecessor(path, predecessor) {
  const actual = await predecessor.handle.stat({ bigint: true });
  if (actual.dev !== predecessor.snapshot.dev || actual.ino !== predecessor.snapshot.ino ||
      actual.mode !== predecessor.snapshot.mode || actual.uid !== predecessor.snapshot.uid ||
      actual.gid !== predecessor.snapshot.gid || actual.size !== predecessor.snapshot.size ||
      actual.mtimeNs !== predecessor.snapshot.mtimeNs || actual.nlink !== 1n) {
    throw new Error("Finality custodian checkpoint displaced predecessor changed");
  }
  const named = await lstat(path, { bigint: true });
  if (!sameIntegralSnapshot(actual, named)) {
    throw new Error("Finality custodian checkpoint displaced predecessor changed");
  }
  await validatePredecessorEvidence(predecessor);
  const buffer = Buffer.alloc(predecessor.bytes.length + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await predecessor.handle.read(
      buffer, offset, buffer.length - offset, offset,
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== predecessor.bytes.length ||
      !buffer.subarray(0, offset).equals(predecessor.bytes)) {
    throw new Error("Finality custodian checkpoint displaced predecessor bytes changed");
  }
}

async function releaseDisplacedPredecessor(path, predecessor) {
  await validateDisplacedPredecessor(path, predecessor);
  await unlink(path);
  const actual = await predecessor.handle.stat({ bigint: true });
  if (actual.dev !== predecessor.snapshot.dev || actual.ino !== predecessor.snapshot.ino ||
      actual.mode !== predecessor.snapshot.mode || actual.uid !== predecessor.snapshot.uid ||
      actual.gid !== predecessor.snapshot.gid || actual.size !== predecessor.snapshot.size ||
      actual.mtimeNs !== predecessor.snapshot.mtimeNs || actual.nlink !== 0n ||
      !await readExactHandle(predecessor.handle, predecessor.bytes)) {
    throw new Error("Finality custodian checkpoint predecessor cleanup is ambiguous");
  }
}

async function releasePredecessorEvidence(predecessor) {
  await validatePredecessorEvidence(predecessor);
  await unlink(predecessor.evidence.path);
  const actual = await predecessor.evidence.handle.stat({ bigint: true });
  if (actual.dev !== predecessor.evidence.snapshot.dev || actual.ino !== predecessor.evidence.snapshot.ino ||
      actual.mode !== predecessor.evidence.snapshot.mode || actual.uid !== predecessor.evidence.snapshot.uid ||
      actual.gid !== predecessor.evidence.snapshot.gid || actual.size !== predecessor.evidence.snapshot.size ||
      actual.mtimeNs !== predecessor.evidence.snapshot.mtimeNs || actual.nlink !== 0n ||
      !await readExactHandle(predecessor.evidence.handle, predecessor.bytes)) {
    throw new Error("Finality custodian checkpoint predecessor evidence cleanup is ambiguous");
  }
}

function checkedAnchor(anchor) {
  if (!anchor || typeof anchor !== "object" || Array.isArray(anchor)) {
    throw new Error("Finality custodian checkpoint anchor is invalid");
  }
  const load = anchor.load, compareAndSwap = anchor.compareAndSwap;
  if (typeof load !== "function" || typeof compareAndSwap !== "function") {
    throw new Error("Finality custodian checkpoint anchor is invalid");
  }
  return Object.freeze({
    load: (...args) => Reflect.apply(load, anchor, args),
    compareAndSwap: (...args) => Reflect.apply(compareAndSwap, anchor, args),
  });
}

function snapshotClientConfiguration(authentication, transport) {
  if (!authentication || typeof authentication !== "object" || Array.isArray(authentication) ||
      Object.keys(authentication).length !== 3 ||
      !["key", "clientId", "custodianId"].every(field => Object.hasOwn(authentication, field))) {
    throw new Error("Finality custodian authentication is invalid");
  }
  const key = authentication?.key;
  const configuredAuthentication = { key: key instanceof Uint8Array ? new Uint8Array(key) : key,
    clientId: authentication.clientId, custodianId: authentication.custodianId };
  const exchange = transport?.exchange;
  const configuredTransport = transport && typeof transport === "object" && typeof exchange === "function"
    ? Object.freeze({ exchange: (...args) => Reflect.apply(exchange, transport, args) }) : transport;
  return { authentication: configuredAuthentication, transport: configuredTransport };
}

async function anchorLoad(anchor) {
  const retained = await anchor.load();
  if (retained !== null && (typeof retained !== "string" || !HASH.test(retained))) {
    throw new Error("Finality custodian checkpoint anchor returned an invalid hash");
  }
  return retained;
}

async function anchorAdvance(anchor, expected, replacement) {
  let outcome;
  try { outcome = await anchor.compareAndSwap(expected, replacement); }
  catch (cause) {
    throw new Error("Finality custodian checkpoint anchor outcome is uncertain", { cause });
  }
  if (!outcome || typeof outcome !== "object" || Array.isArray(outcome) ||
      !["committed", "conflict", "uncertain"].includes(outcome.status)) {
    throw new Error("Finality custodian checkpoint anchor outcome is uncertain");
  }
  if (outcome.status === "uncertain") throw new Error("Finality custodian checkpoint anchor outcome is uncertain");
  if (outcome.status === "conflict") throw new Error("Finality custodian checkpoint anchor CAS conflict");
  if (Object.keys(outcome).length !== 1) throw new Error("Finality custodian checkpoint anchor outcome is uncertain");
}

async function replaceState(path, current, next, anchor) {
  path = absoluteCheckpointPath(path);
  const token = randomBytes(12).toString("hex");
  const lockPath = `${path}.lock`, temporary = `${path}.tmp-${process.pid}-${token}`;
  const evidence = `${path}.previous-${process.pid}-${token}`;
  const displaced = `${path}.displaced-${process.pid}-${token}`;
  const directory = await protectedDirectory(path);
  const anchoredState = anchoredChild(directory, path), anchoredLock = anchoredChild(directory, lockPath);
  const anchoredTemporary = anchoredChild(directory, temporary);
  const anchoredEvidence = anchoredChild(directory, evidence);
  const anchoredDisplaced = anchoredChild(directory, displaced);
  let lock, lockStat, lockBytes, temporaryHandle, temporaryStat, temporaryBytes, predecessor,
    authorityDirectoryStat, replacementAttempted = false, replacementVerified = false,
    anchorAttempted = false, anchorCommitted = false, safeFailure = false;
  try {
    try {
      await validateDirectoryName(path, directory);
      lock = await open(anchoredLock,
        fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    } catch (cause) {
      throw new Error("Finality custodian checkpoint is locked; inspect before retrying", { cause });
    }
    lockBytes = Buffer.from(`${JSON.stringify({ format: "bloch-l2-finality-custodian-client-lock-v1",
      token: randomBytes(32).toString("hex") })}\n`);
    await lock.writeFile(lockBytes);
    await lock.sync(); await directory.sync();
    lockStat = await lock.stat({ bigint: true });
    if (!lockStat.isFile() || lockStat.nlink !== 1n || (lockStat.mode & 0o077n) !== 0n) {
      throw new Error("Finality custodian checkpoint lock is unsafe");
    }
    const observed = await readState(path);
    if (observed.stateHash !== current.stateHash) {
      safeFailure = true;
      throw new Error("Finality custodian checkpoint changed before CAS");
    }
    temporaryBytes = Buffer.from(`${JSON.stringify(next)}\n`);
    if (temporaryBytes.length > MAX_FILE_BYTES) {
      safeFailure = true;
      throw new Error("Finality custodian checkpoint candidate exceeds its size limit");
    }
    predecessor = await pinPredecessor(anchoredState, current.stateHash);
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    await retainPredecessorEvidence(anchoredEvidence, predecessor);
    temporaryHandle = await open(anchoredTemporary,
      fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    await temporaryHandle.writeFile(temporaryBytes); await temporaryHandle.sync();
    temporaryStat = await temporaryHandle.stat({ bigint: true });
    if (!temporaryStat.isFile() || temporaryStat.nlink !== 1n || (temporaryStat.mode & 0o077n) !== 0n) {
      throw new Error("Finality custodian checkpoint temporary file is unsafe");
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
    try {
      anchorAttempted = true;
      await anchorAdvance(anchor, current.stateHash, next.stateHash);
      anchorCommitted = true;
    } catch (error) {
      safeFailure = /CAS conflict/.test(error.message);
      throw error;
    }
    replacementAttempted = true;
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    if (!sameIntegralSnapshot(authorityDirectoryStat, await directory.stat({ bigint: true }))) {
      throw new Error("Finality custodian checkpoint directory changed during anchor CAS");
    }
    await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
    await validatePredecessor(anchoredState, predecessor);
    await rename(anchoredState, anchoredDisplaced); await directory.sync();
    await validateDisplacedPredecessor(anchoredDisplaced, predecessor);
    await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
    await link(anchoredTemporary, anchoredState); await directory.sync();
    await validateDirectoryName(path, directory);
    const installed = await temporaryHandle.stat({ bigint: true });
    const namedInstalled = await lstat(anchoredState, { bigint: true });
    const namedTemporary = await lstat(anchoredTemporary, { bigint: true });
    if (installed.dev !== temporaryStat.dev || installed.ino !== temporaryStat.ino ||
        installed.nlink !== 2n || !sameIntegralSnapshot(installed, namedInstalled) ||
        !sameIntegralSnapshot(installed, namedTemporary) ||
        !await readExactHandle(temporaryHandle, temporaryBytes)) {
      throw new Error("Finality custodian checkpoint replacement is ambiguous");
    }
    await validateDisplacedPredecessor(anchoredDisplaced, predecessor);
    await unlink(anchoredTemporary); await directory.sync();
    const installedAfterUnlink = await temporaryHandle.stat({ bigint: true });
    const namedAfterUnlink = await lstat(anchoredState, { bigint: true });
    if (installedAfterUnlink.nlink !== 1n ||
        !sameIntegralSnapshot(installedAfterUnlink, namedAfterUnlink) ||
        !await readExactHandle(temporaryHandle, temporaryBytes)) {
      throw new Error("Finality custodian checkpoint replacement is ambiguous");
    }
    await validateDisplacedPredecessor(anchoredDisplaced, predecessor);
    const retained = await readState(path);
    if (retained.stateHash !== next.stateHash) throw new Error("Finality custodian checkpoint readback is ambiguous");
    await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
    await validateDirectoryName(path, directory);
    replacementVerified = true;
    await releaseDisplacedPredecessor(anchoredDisplaced, predecessor);
    await releasePredecessorEvidence(predecessor);
    await directory.sync();
  } finally {
    let cleanup = null;
    if (!anchorAttempted || safeFailure && !anchorCommitted) {
      try {
        if (!temporaryStat) {
          await lstat(anchoredTemporary);
          throw new Error("Finality custodian checkpoint temporary path is unverified");
        }
        await validateTemporary(anchoredTemporary, temporaryHandle, temporaryStat, temporaryBytes);
        await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
        await unlink(anchoredTemporary);
        await releasePredecessorEvidence(predecessor);
        await directory.sync();
      } catch (error) { if (error?.code !== "ENOENT") cleanup = error; }
    }
    if (lock && lockStat && (replacementVerified || safeFailure && !anchorCommitted && !replacementAttempted)) {
      try {
        await validateMutationAuthority(path, directory, lock, lockStat, lockBytes);
        await unlink(anchoredLock);
        await validateReleasedLock(lock, lockStat, lockBytes);
        await directory.sync();
        await validateReleasedLock(lock, lockStat, lockBytes);
        await validateDirectoryName(path, directory);
      } catch (error) { cleanup ??= error; }
    } else if (lock) {
      cleanup ??= new Error("Finality custodian checkpoint transition is ambiguous; lock retained");
    }
    await temporaryHandle?.close().catch(error => { cleanup ??= error; });
    await predecessor?.evidence?.handle.close().catch(error => { cleanup ??= error; });
    await lock?.close().catch(error => { cleanup ??= error; });
    await predecessor?.handle.close().catch(error => { cleanup ??= error; });
    await directory.close().catch(error => { cleanup ??= error; });
    if (cleanup) throw new Error("Finality custodian checkpoint requires inspection before retrying", { cause: cleanup });
  }
}

export async function initializeFinalityCustodianCheckpoint({ storePath, checkpoint,
  expectedStateHash } = {}) {
  storePath = absoluteCheckpointPath(storePath);
  const initial = checkedState(checkpoint);
  if (initial.generation !== "0" || expectedStateHash !== initial.stateHash) {
    throw new Error("Finality custodian checkpoint does not match its externally approved initial hash");
  }
  const directory = await protectedDirectory(storePath);
  const anchoredState = anchoredChild(directory, storePath);
  let output;
  try {
    await validateDirectoryName(storePath, directory);
    const bytes = Buffer.from(`${JSON.stringify(initial)}\n`);
    if (bytes.length > MAX_FILE_BYTES) throw new Error("Finality custodian checkpoint exceeds its size limit");
    output = await open(anchoredState,
      fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    await output.writeFile(bytes); await output.sync();
    let actual = await output.stat({ bigint: true });
    let named = await lstat(anchoredState, { bigint: true });
    await validateDirectoryName(storePath, directory);
    if (!actual.isFile() || actual.nlink !== 1n || (actual.mode & 0o077n) !== 0n ||
        !sameIntegralSnapshot(actual, named) || !await readExactHandle(output, bytes)) {
      throw new Error("Finality custodian checkpoint initialization is ambiguous");
    }
    await directory.sync();
    await validateDirectoryName(storePath, directory);
    actual = await output.stat({ bigint: true });
    named = await lstat(anchoredState, { bigint: true });
    if (!sameIntegralSnapshot(actual, named) || !await readExactHandle(output, bytes)) {
      throw new Error("Finality custodian checkpoint initialization is ambiguous");
    }
  } finally {
    await output?.close();
    await directory.close();
  }
  return initial;
}

function nextState(current, fields) {
  const generation = BigInt(current.generation) + 1n;
  if (generation > 0xffffffffffffffffn) throw new Error("Finality custodian checkpoint generation exhausted");
  const body = { ...stateBody(current), ...fields, generation: generation.toString(),
    previousStateHash: current.stateHash };
  return checkedState({ ...body, stateHash: stateHash(body) });
}

async function readCheckpointSnapshot(storePath) {
  storePath = absoluteCheckpointPath(storePath);
  const directory = await protectedDirectory(storePath);
  try {
    const before = await directory.stat({ bigint: true });
    const evidence = {};
    const state = await readState(storePath, directory, evidence);
    const lockPath = process.platform === "linux"
      ? anchoredChild(directory, `${storePath}.lock`) : `${storePath}.lock`;
    const lock = await lstat(lockPath).then(() => true, error => {
      if (error?.code === "ENOENT") return false;
      throw error;
    });
    const after = await directory.stat({ bigint: true });
    if (!sameIntegralSnapshot(before, after)) {
      throw new Error("Finality custodian checkpoint directory changed during inspection");
    }
    await validateDirectoryName(storePath, directory);
    return { state, lockPresent: lock, directorySnapshot: after,
      stateSnapshot: evidence.snapshot, stateBytes: evidence.bytes };
  } finally {
    await directory.close();
  }
}

export async function inspectFinalityCustodianCheckpoint(storePath) {
  const { state, lockPresent } = await readCheckpointSnapshot(storePath);
  return Object.freeze({ ...state, lockPresent });
}

export async function createFilesystemFinalityCustodian({ storePath, expectedStateHash, authentication,
  transport, anchor } = {}) {
  storePath = absoluteCheckpointPath(storePath);
  if (typeof expectedStateHash !== "string" || !HASH.test(expectedStateHash)) {
    throw new Error("Finality custodian externally retained checkpoint hash is invalid");
  }
  const configured = snapshotClientConfiguration(authentication, transport);
  const retainedAnchor = checkedAnchor(anchor);
  const snapshot = await readCheckpointSnapshot(storePath);
  const { lockPresent } = snapshot;
  if (lockPresent) throw new Error("Finality custodian checkpoint is locked; inspect before retrying");
  let retained = snapshot.state;
  const anchoredStateHash = await anchorLoad(retainedAnchor);
  const confirmed = await readCheckpointSnapshot(storePath);
  if (confirmed.lockPresent || !sameIntegralSnapshot(snapshot.directorySnapshot,
    confirmed.directorySnapshot) || !sameIntegralSnapshot(snapshot.stateSnapshot,
    confirmed.stateSnapshot) || !snapshot.stateBytes.equals(confirmed.stateBytes)) {
    throw new Error("Finality custodian checkpoint changed during independent anchor verification");
  }
  retained = confirmed.state;
  if (retained.stateHash !== expectedStateHash || anchoredStateHash !== expectedStateHash) {
    throw new Error("Finality custodian checkpoint does not match the independent anchor");
  }
  if (retained.status !== "ready") {
    throw new Error("Finality custodian checkpoint has an unresolved pending exchange");
  }
  if (configured.authentication?.clientId !== retained.clientId ||
      configured.authentication?.custodianId !== retained.custodianId) {
    throw new Error("Finality custodian checkpoint identity does not match authentication");
  }
  const lifecycle = {
    async begin(event) {
      exact(event, ["requestHash", "operation", "checkpoint"],
        "Finality custodian lifecycle begin event is invalid");
      if (retained.status !== "ready" || !HASH.test(event.requestHash) ||
          !["load", "compare-and-swap"].includes(event.operation) ||
          event.checkpoint?.session !== retained.session ||
          BigInt(event.checkpoint?.nextSequence ?? "-1") !== BigInt(retained.nextSequence) + 1n) {
        throw new Error("Finality custodian checkpoint cannot begin this exchange");
      }
      const next = nextState(retained, { nextSequence: event.checkpoint.nextSequence, status: "pending",
        pendingRequestHash: event.requestHash, pendingOperation: event.operation });
      await replaceState(storePath, retained, next, retainedAnchor);
      retained = next;
    },
    async complete(event) {
      exact(event, ["requestHash", "operation", "checkpoint", "response"],
        "Finality custodian lifecycle completion event is invalid");
      if (retained.status !== "pending" || retained.pendingRequestHash !== event.requestHash ||
          retained.pendingOperation !== event.operation || event.checkpoint?.session !== retained.session ||
          event.checkpoint?.nextSequence !== retained.nextSequence) {
        throw new Error("Finality custodian checkpoint cannot complete this exchange");
      }
      if (event.response?.status === "uncertain") return;
      const outcome = checkedOutcome({ requestHash: event.requestHash, status: event.response?.status,
        currentStateHash: event.response?.currentStateHash ?? null });
      const next = nextState(retained, { status: "ready", pendingRequestHash: null,
        pendingOperation: null, lastOutcome: outcome });
      await replaceState(storePath, retained, next, retainedAnchor);
      retained = next;
    },
  };
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication: configured.authentication,
    transport: configured.transport,
    checkpoint: { session: retained.session, nextSequence: retained.nextSequence }, lifecycle });
  return Object.freeze({
    load: () => client.load(),
    compareAndSwap: (expected, replacement) => client.compareAndSwap(expected, replacement),
    checkpoint: () => client.checkpoint(),
    retainedState: () => retained,
    close: () => client.close(),
  });
}
