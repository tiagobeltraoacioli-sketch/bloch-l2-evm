#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { canonicalBlochL2FinalityPayloadJson } from "./finality-attestation.mjs";
import {
  BLOCH_L2_FINALITY_QUORUM_ENVELOPE_FORMAT,
  BLOCH_L2_FINALITY_QUORUM_PAYLOAD_FORMAT,
  blochL2FinalityQuorumSigningBytes,
  canonicalBlochL2FinalityQuorumConfig,
  canonicalBlochL2FinalityQuorumPayloadJson,
  createEd25519FinalityQuorumVerifier,
} from "./finality-quorum.mjs";

const MAX_JSON_BYTES = 512 * 1024;
const MAX_KEY_BYTES = 64 * 1024;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function usage() {
  return `Usage:
  node wallets/finality-quorum-cli.mjs sign --config <quorum.json> --signer-id <id> --private-key <ed25519-private.pem> --input <payload.json> --output <envelope.json>
  node wallets/finality-quorum-cli.mjs verify --config <quorum.json> --protocol <protocol> --expected <payload.json> --input <bundle.json>`;
}

function parse(args, expected) {
  if (args.length !== expected.length * 2) throw new Error(usage());
  const values = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    if (!expected.includes(args[index]) || Object.hasOwn(values, args[index]) || !args[index + 1]) {
      throw new Error(usage());
    }
    values[args[index]] = args[index + 1];
  }
  if (expected.some(name => !Object.hasOwn(values, name))) throw new Error(usage());
  return values;
}

async function readBounded(path, maximum) {
  const value = await readFile(path);
  if (!value.length || value.length > maximum) throw new Error("Input file has an invalid size");
  return value;
}

async function readJson(path) {
  try { return JSON.parse((await readBounded(path, MAX_JSON_BYTES)).toString("utf8")); }
  catch (cause) { throw new Error("Input is not bounded valid JSON", { cause }); }
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
  } finally { await handle.close(); }
}

function describeKey(key) {
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Public key must be Ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  if (spki.length !== SPKI_PREFIX.length + 32 || !spki.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
    throw new Error("Public key has an unexpected Ed25519 encoding");
  }
  const raw = spki.subarray(SPKI_PREFIX.length);
  return { publicKeyBase64Url: raw.toString("base64url"), keyId: createHash("sha256").update(raw).digest("hex") };
}

async function writeNewJson(path, value) {
  const handle = await open(path, "wx", 0o444);
  try { await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "sign") {
    const values = parse(args, ["--config", "--signer-id", "--private-key", "--input", "--output"]);
    const quorum = await canonicalBlochL2FinalityQuorumConfig(await readJson(values["--config"]));
    const signer = quorum.signers.find(candidate => candidate.signerId === values["--signer-id"]);
    if (!signer) throw new Error("Signer is not in the pinned finality quorum");
    const privateKey = await readPrivateKey(values["--private-key"]);
    const key = describeKey(privateKey);
    if (key.keyId !== signer.keyId || key.publicKeyBase64Url !== signer.publicKeyBase64Url) {
      throw new Error("Private key does not match the configured finality signer");
    }
    const base = JSON.parse(canonicalBlochL2FinalityPayloadJson(await readJson(values["--input"])));
    const payload = JSON.parse(canonicalBlochL2FinalityQuorumPayloadJson({
      format: BLOCH_L2_FINALITY_QUORUM_PAYLOAD_FORMAT, quorumId: quorum.quorumId,
      signerId: signer.signerId, identity: base.identity, checkpoint: base.checkpoint,
      issuedAt: base.issuedAt, expiresAt: base.expiresAt, finalityProtocol: base.finalityProtocol,
      finalityReference: base.finalityReference,
    }));
    await writeNewJson(values["--output"], {
      format: BLOCH_L2_FINALITY_QUORUM_ENVELOPE_FORMAT, quorumId: quorum.quorumId,
      signerId: signer.signerId, keyId: signer.keyId, payload,
      signature: sign(null, blochL2FinalityQuorumSigningBytes(payload), privateKey).toString("base64url"),
    });
    console.log(JSON.stringify({ signed: true, quorumId: quorum.quorumId, signerId: signer.signerId,
      keyId: signer.keyId }));
    return;
  }
  if (command === "verify") {
    const values = parse(args, ["--config", "--protocol", "--expected", "--input"]);
    const config = await readJson(values["--config"]);
    const expected = JSON.parse(canonicalBlochL2FinalityPayloadJson(await readJson(values["--expected"])));
    if (expected.finalityProtocol !== values["--protocol"]) throw new Error("Expected payload protocol mismatch");
    const bundle = await readJson(values["--input"]);
    const verifier = await createEd25519FinalityQuorumVerifier({ config,
      finalityProtocol: values["--protocol"], getBundle: async () => bundle });
    await verifier.verify(expected.identity, expected.checkpoint);
    console.log(JSON.stringify({ verified: true, quorumId: verifier.quorumId, threshold: verifier.threshold }));
    return;
  }
  throw new Error(usage());
}

main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
