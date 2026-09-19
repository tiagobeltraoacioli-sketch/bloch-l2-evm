#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createPrivateKey, createPublicKey } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  advanceFinalityCustodianAuthorityCheckpoint,
  approveFinalityCustodianStoreRecord,
  assembleFinalityCustodianStoreContinuity,
  createFinalityCustodianStoreContinuityTransition,
  createInitialFinalityCustodianAuthorityCheckpoint,
  reconcileFinalityCustodianAuthorityStoreRecord,
  signFinalityCustodianStoreContinuity,
} from "./finality-quorum-custodian-store.mjs";

const MAX_JSON_BYTES = 64 * 1024;
const MAX_KEY_BYTES = 64 * 1024;
const HASH = /^[0-9a-f]{64}$/;
const NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;

function usage() {
  return `Usage:
  node wallets/finality-quorum-custodian-authority-cli.mjs approve --record <record.json> --deployment-id <sha256> --private-key <ed25519-private.pem> --output <approval.json>
  node wallets/finality-quorum-custodian-authority-cli.mjs transition --previous-record <record.json> --next-record <record.json> --deployment-id <sha256> --previous-authority-public-key <ed25519-public.pem> --next-authority-public-key <ed25519-public.pem> --output <transition.json>
  node wallets/finality-quorum-custodian-authority-cli.mjs sign-continuity --transition <transition.json> --role <authorization|acceptance> --private-key <ed25519-private.pem> --output <share.json>
  node wallets/finality-quorum-custodian-authority-cli.mjs assemble-continuity --transition <transition.json> --previous-authority-public-key <ed25519-public.pem> --next-authority-public-key <ed25519-public.pem> --authorization <share.json> --acceptance <share.json> --output <continuity.json>
  node wallets/finality-quorum-custodian-authority-cli.mjs initial --approval <approval.json> --deployment-id <sha256> --authority-public-key <ed25519-public.pem> --output <checkpoint.json>
  node wallets/finality-quorum-custodian-authority-cli.mjs advance --checkpoint <checkpoint.json> --continuity <continuity.json> --next-authority-public-key <ed25519-public.pem> --output <next-checkpoint.json>
  node wallets/finality-quorum-custodian-authority-cli.mjs reconcile-record --store <store.json> --checkpoint <checkpoint.json> --continuity <continuity.json> --next-authority-public-key <ed25519-public.pem> --output <reconciliation.json>`;
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

async function readSafe(path, maximum, description, privateFile = false) {
  if (typeof path !== "string" || resolve(path) !== path) {
    throw new Error(`${description} path must be absolute`);
  }
  if (await realpath(path) !== path) throw new Error(`${description} path must not traverse links`);
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
      before.size < 1 || before.size > maximum ||
      (privateFile ? (before.mode & 0o077) !== 0 : (before.mode & 0o022) !== 0) ||
      typeof process.getuid === "function" && before.uid !== process.getuid()) {
    throw new Error(`${description} file is unsafe`);
  }
  const handle = await open(path, fsConstants.O_RDONLY | NOFOLLOW);
  try {
    const actual = await handle.stat();
    if (!actual.isFile() || actual.dev !== before.dev || actual.ino !== before.ino ||
        actual.nlink !== 1 || actual.size !== before.size || actual.mode !== before.mode ||
        actual.uid !== before.uid || actual.gid !== before.gid) {
      throw new Error(`${description} file changed`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.dev !== actual.dev || after.ino !== actual.ino || after.size !== actual.size ||
        after.mtimeMs !== actual.mtimeMs || after.ctimeMs !== actual.ctimeMs ||
        bytes.length !== after.size) {
      throw new Error(`${description} file changed`);
    }
    return bytes;
  } finally { await handle.close(); }
}

async function readCanonicalJson(path, description) {
  const encoded = (await readSafe(path, MAX_JSON_BYTES, description)).toString("utf8");
  let value;
  try { value = JSON.parse(encoded); }
  catch (cause) { throw new Error(`${description} is not valid JSON`, { cause }); }
  if (encoded !== `${JSON.stringify(value)}\n`) throw new Error(`${description} is not canonical JSON`);
  return value;
}

async function readEd25519PublicKey(path, description) {
  const encoded = await readSafe(path, MAX_KEY_BYTES, description);
  let key;
  try { key = createPublicKey(encoded); }
  catch (cause) { throw new Error(`${description} is invalid`, { cause }); }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${description} must be Ed25519`);
  return key;
}

async function readEd25519PrivateKey(path, description) {
  const encoded = await readSafe(path, MAX_KEY_BYTES, description, true);
  let key;
  try { key = createPrivateKey(encoded); }
  catch (cause) { throw new Error(`${description} is invalid`, { cause }); }
  finally { encoded.fill(0); }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${description} must be Ed25519`);
  return key;
}

function deploymentId(value) {
  if (!HASH.test(value) || value === "0".repeat(64)) {
    throw new Error("Deployment ID must be a nonzero SHA-256 value");
  }
  return value;
}

async function writeNewCanonicalJson(path, value) {
  if (typeof path !== "string" || resolve(path) !== path) {
    throw new Error("Output path must be absolute");
  }
  const parent = dirname(path), parentReal = await realpath(parent), metadata = await lstat(parent);
  if (parentReal !== resolve(parent) || !metadata.isDirectory() || metadata.isSymbolicLink() ||
      (metadata.mode & 0o022) !== 0 ||
      typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error("Output directory is unsafe");
  }
  const directory = await open(parent,
    fsConstants.O_RDONLY | NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0));
  let output;
  try {
    const actual = await directory.stat();
    if (!actual.isDirectory() || actual.dev !== metadata.dev || actual.ino !== metadata.ino ||
        (actual.mode & 0o022) !== 0) throw new Error("Output directory changed");
    output = await open(path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NOFOLLOW, 0o444);
    await output.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await output.sync();
    await directory.sync();
  } finally {
    await output?.close();
    await directory.close();
  }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  let output, path;
  if (command === "approve") {
    const values = parse(args, ["--record", "--deployment-id", "--private-key", "--output"]);
    output = approveFinalityCustodianStoreRecord({
      deploymentId: deploymentId(values["--deployment-id"]),
      record: await readCanonicalJson(values["--record"], "Custodian store record"),
      privateKey: await readEd25519PrivateKey(values["--private-key"], "Authority private key"),
    });
    path = values["--output"];
  } else if (command === "transition") {
    const values = parse(args, ["--previous-record", "--next-record", "--deployment-id",
      "--previous-authority-public-key", "--next-authority-public-key", "--output"]);
    output = createFinalityCustodianStoreContinuityTransition({
      deploymentId: deploymentId(values["--deployment-id"]),
      previousRecord: await readCanonicalJson(values["--previous-record"], "Previous record"),
      nextRecord: await readCanonicalJson(values["--next-record"], "Next record"),
      previousAuthorityPublicKey: await readEd25519PublicKey(
        values["--previous-authority-public-key"], "Previous authority public key"),
      nextAuthorityPublicKey: await readEd25519PublicKey(
        values["--next-authority-public-key"], "Next authority public key"),
    });
    path = values["--output"];
  } else if (command === "sign-continuity") {
    const values = parse(args, ["--transition", "--role", "--private-key", "--output"]);
    if (!["authorization", "acceptance"].includes(values["--role"])) {
      throw new Error("Continuity role must be authorization or acceptance");
    }
    output = signFinalityCustodianStoreContinuity(
      await readCanonicalJson(values["--transition"], "Continuity transition"),
      values["--role"],
      await readEd25519PrivateKey(values["--private-key"], "Authority private key"),
    );
    path = values["--output"];
  } else if (command === "assemble-continuity") {
    const values = parse(args, ["--transition", "--previous-authority-public-key",
      "--next-authority-public-key", "--authorization", "--acceptance", "--output"]);
    output = assembleFinalityCustodianStoreContinuity({
      transition: await readCanonicalJson(values["--transition"], "Continuity transition"),
      previousAuthorityPublicKey: await readEd25519PublicKey(
        values["--previous-authority-public-key"], "Previous authority public key"),
      nextAuthorityPublicKey: await readEd25519PublicKey(
        values["--next-authority-public-key"], "Next authority public key"),
      authorization: await readCanonicalJson(values["--authorization"], "Authorization share"),
      acceptance: await readCanonicalJson(values["--acceptance"], "Acceptance share"),
    });
    path = values["--output"];
  } else if (command === "initial") {
    const values = parse(args,
      ["--approval", "--deployment-id", "--authority-public-key", "--output"]);
    output = createInitialFinalityCustodianAuthorityCheckpoint({
      approval: await readCanonicalJson(values["--approval"], "Approval"),
      expectedDeploymentId: deploymentId(values["--deployment-id"]),
      authorityPublicKey: await readEd25519PublicKey(
        values["--authority-public-key"], "Authority public key"),
    });
    path = values["--output"];
  } else if (command === "advance") {
    const values = parse(args,
      ["--checkpoint", "--continuity", "--next-authority-public-key", "--output"]);
    output = advanceFinalityCustodianAuthorityCheckpoint({
      checkpoint: await readCanonicalJson(values["--checkpoint"], "Authority checkpoint"),
      continuity: await readCanonicalJson(values["--continuity"], "Continuity approval"),
      nextAuthorityPublicKey: await readEd25519PublicKey(
        values["--next-authority-public-key"], "Next authority public key"),
    });
    path = values["--output"];
  } else if (command === "reconcile-record") {
    const values = parse(args, ["--store", "--checkpoint", "--continuity",
      "--next-authority-public-key", "--output"]);
    if (resolve(values["--store"]) !== values["--store"]) {
      throw new Error("Custodian store path must be absolute");
    }
    output = await reconcileFinalityCustodianAuthorityStoreRecord({
      storePath: values["--store"],
      checkpoint: await readCanonicalJson(values["--checkpoint"], "Authority checkpoint"),
      continuity: await readCanonicalJson(values["--continuity"], "Continuity approval"),
      nextAuthorityPublicKey: await readEd25519PublicKey(
        values["--next-authority-public-key"], "Next authority public key"),
    });
    path = values["--output"];
  } else throw new Error(usage());
  await writeNewCanonicalJson(path, output);
  console.log(JSON.stringify(command === "reconcile-record" ? {
    created: true, status: output.status, observedRecordHash: output.observedRecordHash,
    nextCheckpointHash: output.nextCheckpointHash,
  } : { created: true, transitionIndex: output.transitionIndex,
    checkpointHash: output.checkpointHash, authorityKeyId: output.authorityKeyId }));
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
