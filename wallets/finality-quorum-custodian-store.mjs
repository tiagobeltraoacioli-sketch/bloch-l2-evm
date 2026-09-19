// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { dirname, resolve } from "node:path";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";

export const BLOCH_L2_FINALITY_CUSTODIAN_STORE_FORMAT =
  "bloch-l2-finality-custodian-store-v1";

const HASH = /^[0-9a-f]{64}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_FILE_BYTES = 16 * 1024;
const FIELDS = ["format", "generation", "stateHash", "previousRecordHash", "recordHash"];

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
    async load() { return retained.stateHash; },
    async compareAndSwap(expected, replacement) {
      checkedHash(expected, true, "Finality custodian store expected hash is invalid");
      checkedHash(replacement, false, "Finality custodian store replacement hash is invalid");
      if (expected === replacement) throw new Error("Finality custodian store CAS is not an advance");
      if (busy) throw new Error("Finality custodian store already has an operation in progress");
      busy = true;
      try {
        const observed = await readRecord(storePath);
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
