// SPDX-License-Identifier: MIT OR Apache-2.0

import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { canonicalBlochL2FinalityPayloadJson } from "./finality-attestation.mjs";

const FORMAT = "bloch-l2-finality-quorum-checkpoint-state-v1";
const HASH = /^[0-9a-f]{64}$/;
const PROTOCOL = /^[a-z0-9._:-]{1,128}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_FILE_BYTES = 64 * 1024;
const FIELDS = ["format", "quorumId", "threshold", "finalityProtocol", "identity", "checkpoint",
  "generation", "previousStateHash", "bundleHash", "stateHash"];

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
  const directoryPath = resolve(dirname(path)), before = await lstat(directoryPath);
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o022) !== 0 ||
      typeof process.getuid === "function" && before.uid !== process.getuid()) {
    throw new Error("Finality quorum checkpoint directory is unsafe");
  }
  if (await realpath(directoryPath) !== directoryPath) {
    throw new Error("Finality quorum checkpoint directory traverses a symlink");
  }
  const handle = await open(directoryPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0));
  const after = await handle.stat();
  if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino || (after.mode & 0o022) !== 0 ||
      typeof process.getuid === "function" && after.uid !== process.getuid()) {
    await handle.close();
    throw new Error("Finality quorum checkpoint directory changed");
  }
  return handle;
}

async function readState(path) {
  let handle;
  try { handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW); } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o077) !== 0 ||
        typeof process.getuid === "function" && before.uid !== process.getuid() ||
        before.size <= 0 || before.size > MAX_FILE_BYTES) {
      throw new Error("Finality quorum checkpoint file is unsafe");
    }
    let parsed, encoded;
    try { encoded = await handle.readFile("utf8"); parsed = JSON.parse(encoded); }
    catch (cause) { throw new Error("Finality quorum checkpoint is not valid JSON", { cause }); }
    const after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev || after.ino !== before.ino ||
        after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs ||
        (after.mode & 0o077) !== 0 || typeof process.getuid === "function" && after.uid !== process.getuid()) {
      throw new Error("Finality quorum checkpoint changed while being read");
    }
    if (encoded !== `${JSON.stringify(parsed)}\n`) throw new Error("Finality quorum checkpoint is not canonical");
    return checkedState(parsed);
  } finally { await handle.close(); }
}

async function replaceState(path, state, expectedHash) {
  const lockPath = `${path}.lock`, temporary = `${path}.tmp-${process.pid}-${randomBytes(12).toString("hex")}`;
  const directory = await protectedDirectory(path);
  let lock, lockStat, temporaryStat, lockInitialized = false, replacementAttempted = false,
    replacementVerified = false;
  try { lock = await open(lockPath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600); }
  catch (cause) { await directory.close(); throw new Error("Finality quorum checkpoint is locked; inspect before retrying", { cause }); }
  try {
    await lock.writeFile(`${JSON.stringify({ format: "bloch-l2-finality-quorum-checkpoint-lock-v1",
      pid: process.pid, token: randomBytes(32).toString("hex") })}\n`, "utf8");
    await lock.sync(); await directory.sync();
    lockStat = await lock.stat();
    if (!lockStat.isFile() || lockStat.nlink !== 1 || (lockStat.mode & 0o077) !== 0 ||
        typeof process.getuid === "function" && lockStat.uid !== process.getuid()) {
      throw new Error("Finality quorum checkpoint lock is unsafe");
    }
    lockInitialized = true;
    const observed = await readState(path);
    if ((observed?.stateHash ?? null) !== expectedHash) throw new Error("Finality quorum checkpoint changed before CAS");
    const output = await open(temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try {
      await output.writeFile(`${JSON.stringify(state)}\n`, "utf8"); await output.sync();
      const stat = await output.stat();
      if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 ||
          typeof process.getuid === "function" && stat.uid !== process.getuid()) {
        throw new Error("Finality quorum checkpoint temporary file is unsafe");
      }
      temporaryStat = stat;
    }
    finally { await output.close(); }
    replacementAttempted = true;
    await rename(temporary, path);
    await directory.sync();
    const retained = await readState(path);
    if (retained.stateHash !== state.stateHash) throw new Error("Finality quorum checkpoint readback is ambiguous");
    replacementVerified = true;
  } finally {
    let cleanup = null;
    try {
      const linked = await lstat(temporary);
      if (!temporaryStat || !linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 ||
          linked.dev !== temporaryStat.dev || linked.ino !== temporaryStat.ino ||
          typeof process.getuid === "function" && linked.uid !== process.getuid()) {
        throw new Error("Finality quorum checkpoint temporary path changed; refusing removal");
      }
      await unlink(temporary);
    } catch (error) { if (error?.code !== "ENOENT") cleanup = error; }
    try {
      if (lockInitialized) {
        const pathStat = await lstat(lockPath), handleStat = await lock.stat();
        if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.nlink !== 1 ||
            pathStat.dev !== lockStat.dev || pathStat.ino !== lockStat.ino ||
            handleStat.dev !== lockStat.dev || handleStat.ino !== lockStat.ino ||
            (pathStat.mode & 0o077) !== 0 ||
            typeof process.getuid === "function" && pathStat.uid !== process.getuid()) {
          throw new Error("Finality quorum checkpoint lock changed; refusing removal");
        }
      }
    } catch (error) { cleanup ??= error; }
    if (!lockInitialized) cleanup ??= new Error("Finality quorum checkpoint lock initialization is ambiguous");
    if (replacementAttempted && !replacementVerified) {
      cleanup ??= new Error("Finality quorum checkpoint replacement is ambiguous");
    }
    if (!cleanup) {
      try { await unlink(lockPath); await directory.sync(); } catch (error) { cleanup ??= error; }
    }
    try { await lock.close(); } catch (error) { cleanup ??= error; }
    await directory.close().catch(error => { cleanup ??= error; });
    if (cleanup) throw new Error("Finality quorum checkpoint cleanup is ambiguous; inspect before retrying", { cause: cleanup });
  }
}

export async function advanceFinalityQuorumCheckpoint({ storePath, expectedStateHash, quorumId, threshold,
  finalityProtocol, identity, checkpoint, bundleHash } = {}) {
  if (typeof storePath !== "string" || !storePath || expectedStateHash !== null && !HASH.test(expectedStateHash) ||
      !HASH.test(quorumId) || !Number.isSafeInteger(threshold) || threshold < 2 || !PROTOCOL.test(finalityProtocol) ||
      !HASH.test(bundleHash)) throw new Error("Finality quorum checkpoint advance is invalid");
  const canonical = canonicalIdentityCheckpoint(identity, checkpoint, finalityProtocol);
  const directory = await protectedDirectory(storePath); await directory.close();
  const current = await readState(storePath);
  if ((current?.stateHash ?? null) !== expectedStateHash) {
    throw new Error("Finality quorum checkpoint does not match the externally retained state hash");
  }
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
  const next = Object.freeze({ ...nextBody, stateHash: hashBody(nextBody) });
  await replaceState(storePath, next, current?.stateHash ?? null);
  return next;
}

export const BLOCH_L2_FINALITY_QUORUM_CHECKPOINT_FORMAT = FORMAT;
