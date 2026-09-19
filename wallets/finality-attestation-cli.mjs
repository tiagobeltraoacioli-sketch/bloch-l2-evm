#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile, rename, unlink } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { dirname } from "node:path";
import {
  BLOCH_L2_FINALITY_ENVELOPE_FORMAT,
  blochL2FinalitySigningBytes,
  canonicalBlochL2FinalityPayloadJson,
  createEd25519FinalityVerifier,
} from "./finality-attestation.mjs";

const MAX_JSON_BYTES = 64 * 1024;
const MAX_KEY_BYTES = 64 * 1024;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CHECKPOINT_STORE_FORMAT = "bloch-l2-finality-checkpoint-state-v1";
const HASH = /^[0-9a-f]{64}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const STORE_FIELDS = ["format", "keyId", "finalityProtocol", "identity", "checkpoint",
  "finalityReference", "generation", "previousStateHash", "envelopeHash", "stateHash"];

function usage() {
  return `Usage:
  node wallets/finality-attestation-cli.mjs sign --private-key <ed25519-private.pem> --input <payload.json> --output <envelope.json>
  node wallets/finality-attestation-cli.mjs verify --public-key <ed25519-public.pem> --protocol <finality-protocol> --input <envelope.json>
  node wallets/finality-attestation-cli.mjs verify-advance --public-key <ed25519-public.pem> --protocol <finality-protocol> --input <envelope.json> --store <state.json> --expected-state-hash <none|sha256>`;
}

function parse(args, expected) {
  if (args.length !== expected.length * 2) throw new Error(usage());
  const result = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!expected.includes(name) || Object.hasOwn(result, name) || typeof value !== "string" || !value) {
      throw new Error(usage());
    }
    result[name] = value;
  }
  if (expected.some(name => !Object.hasOwn(result, name))) throw new Error(usage());
  return result;
}

async function readBounded(path, maximum) {
  const value = await readFile(path);
  if (!value.length || value.length > maximum) throw new Error("Input file has an invalid size");
  return value;
}

async function readJson(path) {
  let value;
  try {
    value = JSON.parse((await readBounded(path, MAX_JSON_BYTES)).toString("utf8"));
  } catch (cause) {
    throw new Error("Input is not bounded valid JSON", { cause });
  }
  return value;
}

async function readPrivateKey(path) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o077) !== 0 ||
      before.size <= 0 || before.size > MAX_KEY_BYTES) {
    throw new Error("Private key must be a private, single-link regular file");
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev || after.ino !== before.ino ||
        (after.mode & 0o077) !== 0 || after.size <= 0 || after.size > MAX_KEY_BYTES) {
      throw new Error("Private key changed or has unsafe permissions");
    }
    const key = createPrivateKey(await handle.readFile());
    if (key.asymmetricKeyType !== "ed25519") throw new Error("Private key must be Ed25519");
    return key;
  } finally {
    await handle.close();
  }
}

function rawPublicKey(key) {
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Public key must be Ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  if (spki.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("Public key has an unexpected Ed25519 encoding");
  }
  return spki.subarray(ED25519_SPKI_PREFIX.length);
}

function describeKey(key) {
  const raw = rawPublicKey(key);
  return {
    rawBase64Url: raw.toString("base64url"),
    keyId: createHash("sha256").update(raw).digest("hex"),
  };
}

async function writeNewJson(path, value) {
  const encoded = `${JSON.stringify(value)}\n`;
  const handle = await open(path, "wx", 0o444);
  try {
    await handle.writeFile(encoded, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function exactJson(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) throw new Error(message);
  return value;
}

function hashJson(domain, value) {
  return createHash("sha256").update(domain).update(JSON.stringify(value)).digest("hex");
}

function stateBody(value) {
  return {
    format: value.format,
    keyId: value.keyId,
    finalityProtocol: value.finalityProtocol,
    identity: value.identity,
    checkpoint: value.checkpoint,
    finalityReference: value.finalityReference,
    generation: value.generation,
    previousStateHash: value.previousStateHash,
    envelopeHash: value.envelopeHash,
  };
}

function checkedStoredState(value) {
  exactJson(value, STORE_FIELDS, "Checkpoint store has an invalid state");
  if (value.format !== CHECKPOINT_STORE_FORMAT || !HASH.test(value.keyId) ||
      typeof value.finalityProtocol !== "string" || !/^[a-z0-9._:-]{1,128}$/.test(value.finalityProtocol) ||
      typeof value.generation !== "string" || !U64.test(value.generation) || BigInt(value.generation) < 1n ||
      BigInt(value.generation) > 0xffffffffffffffffn ||
      (value.previousStateHash !== null && !HASH.test(value.previousStateHash)) ||
      (value.generation === "1") !== (value.previousStateHash === null) ||
      !HASH.test(value.envelopeHash) || !HASH.test(value.stateHash) ||
      hashJson("BLOCH-L2-FINALITY-CHECKPOINT-STATE-v1\0", stateBody(value)) !== value.stateHash) {
    throw new Error("Checkpoint store has an invalid state");
  }
  const payload = JSON.parse(canonicalBlochL2FinalityPayloadJson({
    format: "bloch-l2-finality-attestation-v1",
    identity: value.identity,
    checkpoint: value.checkpoint,
    issuedAt: 0,
    expiresAt: 1,
    finalityProtocol: value.finalityProtocol,
    finalityReference: value.finalityReference,
  }));
  return Object.freeze({ ...value, identity: payload.identity, checkpoint: payload.checkpoint });
}

async function readStoredState(path) {
  let before;
  try { before = await lstat(path); } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o022) !== 0 ||
      before.size <= 0 || before.size > MAX_JSON_BYTES) throw new Error("Checkpoint store is not a protected regular file");
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev || after.ino !== before.ino ||
        (after.mode & 0o022) !== 0 || after.size <= 0 || after.size > MAX_JSON_BYTES) {
      throw new Error("Checkpoint store changed or is unsafe");
    }
    return checkedStoredState(JSON.parse((await handle.readFile()).toString("utf8")));
  } catch (cause) {
    if (cause instanceof SyntaxError) throw new Error("Checkpoint store is not valid JSON", { cause });
    throw cause;
  } finally { await handle.close(); }
}

async function openProtectedStoreDirectory(path) {
  const directoryPath = dirname(path);
  const before = await lstat(directoryPath);
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o022) !== 0) {
    throw new Error("Checkpoint store directory must not be group/world writable or a symlink");
  }
  const directory = await open(directoryPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0));
  const after = await directory.stat();
  if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino || (after.mode & 0o022) !== 0) {
    await directory.close();
    throw new Error("Checkpoint store directory changed or is unsafe");
  }
  return directory;
}

async function replaceState(path, state, expectedStateHash) {
  const lockPath = `${path}.lock`;
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(12).toString("hex")}`;
  let lock;
  try {
    lock = await open(lockPath, "wx", 0o600);
  } catch (cause) {
    throw new Error("Checkpoint store is locked; inspect before retrying", { cause });
  }
  try {
    const observed = await readStoredState(path);
    if ((observed?.stateHash ?? null) !== expectedStateHash) {
      throw new Error("Checkpoint store changed before durable advance");
    }
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(state)}\n`, "utf8");
      await handle.sync();
    } finally { await handle.close(); }
    await rename(temporary, path);
    const directory = await openProtectedStoreDirectory(path);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    let cleanupFailure = null;
    try { await unlink(temporary); } catch (error) { if (error?.code !== "ENOENT") cleanupFailure = error; }
    try { await lock.close(); } catch (error) { cleanupFailure ??= error; }
    try { await unlink(lockPath); } catch (error) { if (error?.code !== "ENOENT") cleanupFailure ??= error; }
    if (cleanupFailure) throw new Error("Checkpoint store cleanup failed; inspect state before retrying", {
      cause: cleanupFailure,
    });
  }
}

async function verifierFor(publicKeyPath, finalityProtocol, envelope) {
  const publicKey = createPublicKey(await readBounded(publicKeyPath, MAX_KEY_BYTES));
  const key = describeKey(publicKey);
  const verifier = await createEd25519FinalityVerifier({
    publicKeyBase64Url: key.rawBase64Url,
    finalityProtocol,
    getAttestation: async () => envelope,
  });
  if (!envelope || typeof envelope !== "object" || !envelope.payload || typeof envelope.payload !== "object") {
    throw new Error("Finality envelope has no payload");
  }
  await verifier.verify(envelope.payload.identity, envelope.payload.checkpoint);
  return { key, verifier, payload: JSON.parse(canonicalBlochL2FinalityPayloadJson(envelope.payload)) };
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "sign") {
    const values = parse(args, ["--private-key", "--input", "--output"]);
    const privateKey = await readPrivateKey(values["--private-key"]);
    const payload = JSON.parse(canonicalBlochL2FinalityPayloadJson(await readJson(values["--input"])));
    const key = describeKey(privateKey);
    const signature = sign(null, blochL2FinalitySigningBytes(payload), privateKey).toString("base64url");
    await writeNewJson(values["--output"], {
      format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT,
      keyId: key.keyId,
      payload,
      signature,
    });
    console.log(JSON.stringify({ signed: true, keyId: key.keyId }));
    return;
  }
  if (command === "verify") {
    const values = parse(args, ["--public-key", "--protocol", "--input"]);
    const envelope = await readJson(values["--input"]);
    const { verifier } = await verifierFor(values["--public-key"], values["--protocol"], envelope);
    console.log(JSON.stringify({ verified: true, keyId: verifier.keyId }));
    return;
  }
  if (command === "verify-advance") {
    const values = parse(args, ["--public-key", "--protocol", "--input", "--store", "--expected-state-hash"]);
    const expected = values["--expected-state-hash"];
    if (expected !== "none" && !HASH.test(expected)) throw new Error("Expected state hash must be none or SHA-256");
    const storeDirectory = await openProtectedStoreDirectory(values["--store"]);
    await storeDirectory.close();
    const envelope = await readJson(values["--input"]);
    const { verifier, payload } = await verifierFor(values["--public-key"], values["--protocol"], envelope);
    const current = await readStoredState(values["--store"]);
    if ((current === null) !== (expected === "none") || current && current.stateHash !== expected) {
      throw new Error("Checkpoint store does not match the externally retained state hash");
    }
    if (current) {
      if (current.keyId !== verifier.keyId || current.finalityProtocol !== payload.finalityProtocol ||
          JSON.stringify(current.identity) !== JSON.stringify(payload.identity)) {
        throw new Error("Finality checkpoint authority or chain identity changed");
      }
      const oldHeight = BigInt(current.checkpoint.headNumber), newHeight = BigInt(payload.checkpoint.headNumber);
      if (newHeight <= oldHeight) throw new Error(newHeight === oldHeight
        ? "Finality checkpoint replay or same-height equivocation" : "Finality checkpoint rollback");
    }
    const generation = current ? BigInt(current.generation) + 1n : 1n;
    if (generation > 0xffffffffffffffffn) throw new Error("Finality checkpoint generation exhausted");
    const canonicalEnvelope = {
      format: BLOCH_L2_FINALITY_ENVELOPE_FORMAT,
      keyId: verifier.keyId,
      payload,
      signature: envelope.signature,
    };
    const body = {
      format: CHECKPOINT_STORE_FORMAT,
      keyId: verifier.keyId,
      finalityProtocol: payload.finalityProtocol,
      identity: payload.identity,
      checkpoint: payload.checkpoint,
      finalityReference: payload.finalityReference,
      generation: generation.toString(),
      previousStateHash: current?.stateHash ?? null,
      envelopeHash: hashJson("BLOCH-L2-FINALITY-ENVELOPE-v1\0", canonicalEnvelope),
    };
    const state = Object.freeze({ ...body,
      stateHash: hashJson("BLOCH-L2-FINALITY-CHECKPOINT-STATE-v1\0", body) });
    await replaceState(values["--store"], state, current?.stateHash ?? null);
    console.log(JSON.stringify({ advanced: true, keyId: verifier.keyId, generation: state.generation,
      stateHash: state.stateHash, headNumber: state.checkpoint.headNumber }));
    return;
  }
  throw new Error(usage());
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
