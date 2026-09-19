// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { dirname, resolve } from "node:path";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";
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
  if (typeof path !== "string" || !path) throw new Error("Finality custodian checkpoint path is invalid");
  const directoryPath = resolve(dirname(path)), before = await lstat(directoryPath);
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

async function readState(path) {
  const directory = await protectedDirectory(path);
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o077) !== 0 || before.size < 2 ||
        before.size > MAX_FILE_BYTES || typeof process.getuid === "function" && before.uid !== process.getuid()) {
      throw new Error("Finality custodian checkpoint file is unsafe");
    }
    const encoded = await handle.readFile("utf8"), after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev || after.ino !== before.ino ||
        after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs ||
        (after.mode & 0o077) !== 0 || typeof process.getuid === "function" && after.uid !== process.getuid()) {
      throw new Error("Finality custodian checkpoint changed while being read");
    }
    let parsed;
    try { parsed = JSON.parse(encoded); } catch (cause) {
      throw new Error("Finality custodian checkpoint is not valid JSON", { cause });
    }
    if (encoded !== `${JSON.stringify(parsed)}\n`) {
      throw new Error("Finality custodian checkpoint is not canonical");
    }
    return checkedState(parsed);
  } finally {
    await handle?.close();
    await directory.close();
  }
}

function checkedAnchor(anchor) {
  if (!anchor || typeof anchor !== "object" || Array.isArray(anchor) || typeof anchor.load !== "function" ||
      typeof anchor.compareAndSwap !== "function") throw new Error("Finality custodian checkpoint anchor is invalid");
  return anchor;
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
  const lockPath = `${path}.lock`, temporary = `${path}.tmp-${process.pid}-${randomBytes(12).toString("hex")}`;
  const directory = await protectedDirectory(path);
  let lock, lockStat, temporaryStat, replacementAttempted = false, replacementVerified = false,
    anchorCommitted = false, safeFailure = false;
  try {
    try {
      lock = await open(lockPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    } catch (cause) {
      throw new Error("Finality custodian checkpoint is locked; inspect before retrying", { cause });
    }
    await lock.writeFile(`${JSON.stringify({ format: "bloch-l2-finality-custodian-client-lock-v1",
      token: randomBytes(32).toString("hex") })}\n`);
    await lock.sync(); await directory.sync();
    lockStat = await lock.stat();
    if (!lockStat.isFile() || lockStat.nlink !== 1 || (lockStat.mode & 0o077) !== 0) {
      throw new Error("Finality custodian checkpoint lock is unsafe");
    }
    const observed = await readState(path);
    if (observed.stateHash !== current.stateHash) {
      safeFailure = true;
      throw new Error("Finality custodian checkpoint changed before CAS");
    }
    const output = await open(temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try {
      await output.writeFile(`${JSON.stringify(next)}\n`); await output.sync();
      temporaryStat = await output.stat();
      if (!temporaryStat.isFile() || temporaryStat.nlink !== 1 || (temporaryStat.mode & 0o077) !== 0) {
        throw new Error("Finality custodian checkpoint temporary file is unsafe");
      }
    } finally { await output.close(); }
    try {
      await anchorAdvance(anchor, current.stateHash, next.stateHash);
      anchorCommitted = true;
    } catch (error) {
      safeFailure = /CAS conflict/.test(error.message);
      throw error;
    }
    replacementAttempted = true;
    await rename(temporary, path); await directory.sync();
    const retained = await readState(path);
    if (retained.stateHash !== next.stateHash) throw new Error("Finality custodian checkpoint readback is ambiguous");
    replacementVerified = true;
  } finally {
    let cleanup = null;
    try {
      const linked = await lstat(temporary);
      if (!temporaryStat || !linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 ||
          linked.dev !== temporaryStat.dev || linked.ino !== temporaryStat.ino) {
        throw new Error("Finality custodian checkpoint temporary path changed; refusing removal");
      }
      await unlink(temporary);
    } catch (error) { if (error?.code !== "ENOENT") cleanup = error; }
    if (lock && lockStat && (replacementVerified || safeFailure && !anchorCommitted && !replacementAttempted)) {
      try {
        const linked = await lstat(lockPath), actual = await lock.stat();
        if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 || linked.dev !== lockStat.dev ||
            linked.ino !== lockStat.ino || actual.dev !== lockStat.dev || actual.ino !== lockStat.ino) {
          throw new Error("Finality custodian checkpoint lock changed; refusing removal");
        }
        await unlink(lockPath); await directory.sync();
      } catch (error) { cleanup ??= error; }
    } else if (lock) {
      cleanup ??= new Error("Finality custodian checkpoint transition is ambiguous; lock retained");
    }
    await lock?.close().catch(error => { cleanup ??= error; });
    await directory.close().catch(error => { cleanup ??= error; });
    if (cleanup) throw new Error("Finality custodian checkpoint requires inspection before retrying", { cause: cleanup });
  }
}

export async function initializeFinalityCustodianCheckpoint({ storePath, checkpoint,
  expectedStateHash } = {}) {
  const initial = checkedState(checkpoint);
  if (initial.generation !== "0" || expectedStateHash !== initial.stateHash) {
    throw new Error("Finality custodian checkpoint does not match its externally approved initial hash");
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

function nextState(current, fields) {
  const generation = BigInt(current.generation) + 1n;
  if (generation > 0xffffffffffffffffn) throw new Error("Finality custodian checkpoint generation exhausted");
  const body = { ...stateBody(current), ...fields, generation: generation.toString(),
    previousStateHash: current.stateHash };
  return checkedState({ ...body, stateHash: stateHash(body) });
}

export async function inspectFinalityCustodianCheckpoint(storePath) {
  const state = await readState(storePath);
  const lock = await lstat(`${storePath}.lock`).then(() => true, error => {
    if (error?.code === "ENOENT") return false;
    throw error;
  });
  return Object.freeze({ ...state, lockPresent: lock });
}

export async function createFilesystemFinalityCustodian({ storePath, expectedStateHash, authentication,
  transport, anchor } = {}) {
  if (typeof expectedStateHash !== "string" || !HASH.test(expectedStateHash)) {
    throw new Error("Finality custodian externally retained checkpoint hash is invalid");
  }
  const retainedAnchor = checkedAnchor(anchor);
  const lockPresent = await lstat(`${storePath}.lock`).then(() => true, error => {
    if (error?.code === "ENOENT") return false;
    throw error;
  });
  if (lockPresent) throw new Error("Finality custodian checkpoint is locked; inspect before retrying");
  let retained = await readState(storePath);
  if (retained.stateHash !== expectedStateHash || await anchorLoad(retainedAnchor) !== expectedStateHash) {
    throw new Error("Finality custodian checkpoint does not match the independent anchor");
  }
  if (retained.status !== "ready") {
    throw new Error("Finality custodian checkpoint has an unresolved pending exchange");
  }
  if (authentication?.clientId !== retained.clientId || authentication?.custodianId !== retained.custodianId) {
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
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication, transport,
    checkpoint: { session: retained.session, nextSequence: retained.nextSequence }, lifecycle });
  return Object.freeze({
    load: () => client.load(),
    compareAndSwap: (expected, replacement) => client.compareAndSwap(expected, replacement),
    checkpoint: () => client.checkpoint(),
    retainedState: () => retained,
    close: () => client.close(),
  });
}
