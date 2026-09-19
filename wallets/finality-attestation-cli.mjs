#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import {
  BLOCH_L2_FINALITY_ENVELOPE_FORMAT,
  blochL2FinalitySigningBytes,
  canonicalBlochL2FinalityPayloadJson,
  createEd25519FinalityVerifier,
} from "./finality-attestation.mjs";

const MAX_JSON_BYTES = 64 * 1024;
const MAX_KEY_BYTES = 64 * 1024;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function usage() {
  return `Usage:
  node wallets/finality-attestation-cli.mjs sign --private-key <ed25519-private.pem> --input <payload.json> --output <envelope.json>
  node wallets/finality-attestation-cli.mjs verify --public-key <ed25519-public.pem> --protocol <finality-protocol> --input <envelope.json>`;
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
    const publicKey = createPublicKey(await readBounded(values["--public-key"], MAX_KEY_BYTES));
    const key = describeKey(publicKey);
    const envelope = await readJson(values["--input"]);
    const verifier = await createEd25519FinalityVerifier({
      publicKeyBase64Url: key.rawBase64Url,
      finalityProtocol: values["--protocol"],
      getAttestation: async () => envelope,
    });
    if (!envelope || typeof envelope !== "object" || !envelope.payload || typeof envelope.payload !== "object") {
      throw new Error("Finality envelope has no payload");
    }
    await verifier.verify(envelope.payload.identity, envelope.payload.checkpoint);
    console.log(JSON.stringify({ verified: true, keyId: verifier.keyId }));
    return;
  }
  throw new Error(usage());
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
