// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { canonicalBlochL2FinalityQuorumConfig } from "./finality-quorum.mjs";

const execute = promisify(execFile);
const cli = new URL("./finality-quorum-cli.mjs", import.meta.url).pathname;
const protocol = "bloch-native-checkpoint-v1";
const spkiPrefixBytes = 12;

function payload(headHash = "62", headNumber = "0x2") {
  const now = Math.floor(Date.now() / 1_000);
  return { format: "bloch-l2-finality-attestation-v1",
    identity: { format: "bloch-chain-identity-v1", chainId: "0xab163", domain: `0x${"71".repeat(32)}`,
      genesisHash: `0x${"42".repeat(32)}`, headerFormat: "bloch-node-header-v2-fixed-width" },
    checkpoint: { format: "bloch-wallet-checkpoint-v1", headNumber,
      headHash: `0x${headHash.repeat(32)}`, stateRoot: `0x${"72".repeat(32)}` },
    issuedAt: now, expiresAt: now + 300, finalityProtocol: protocol,
    finalityReference: `0x${"91".repeat(32)}` };
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "bloch-finality-quorum-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const signers = [];
  for (const signerId of ["settlement-a", "settlement-b", "settlement-c"]) {
    const keys = generateKeyPairSync("ed25519");
    const privateKey = join(directory, `${signerId}.private.pem`);
    await writeFile(privateKey, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const der = keys.publicKey.export({ type: "spki", format: "der" });
    signers.push({ signerId, publicKeyBase64Url: der.subarray(spkiPrefixBytes).toString("base64url"), privateKey });
  }
  const config = { format: "bloch-l2-finality-quorum-config-v1", threshold: 2,
    signers: signers.map(({ signerId, publicKeyBase64Url }) => ({ signerId, publicKeyBase64Url })) };
  const configPath = join(directory, "config.json"), expected = join(directory, "payload.json");
  await writeFile(configPath, JSON.stringify(config));
  await writeFile(expected, JSON.stringify(payload()));
  return { directory, signers, config, configPath, expected };
}

async function signEnvelope(files, index, input = files.expected, suffix = "") {
  const output = join(files.directory, `envelope-${index}${suffix}.json`);
  const signer = files.signers[index];
  const result = await execute(process.execPath, [cli, "sign", "--config", files.configPath,
    "--signer-id", signer.signerId, "--private-key", signer.privateKey,
    "--input", input, "--output", output]);
  return { output, result: JSON.parse(result.stdout), envelope: JSON.parse(await readFile(output, "utf8")) };
}

async function bundle(files, envelopes, name = "bundle.json") {
  const quorum = await canonicalBlochL2FinalityQuorumConfig(files.config);
  const path = join(files.directory, name);
  await writeFile(path, JSON.stringify({ format: "bloch-l2-finality-quorum-bundle-v1",
    quorumId: quorum.quorumId, envelopes }));
  return path;
}

async function verify(files, input, expected = files.expected, config = files.configPath) {
  return execute(process.execPath, [cli, "verify", "--config", config, "--protocol", protocol,
    "--expected", expected, "--input", input]);
}

async function advance(files, input, store, retained, expected = files.expected) {
  return execute(process.execPath, [cli, "verify-advance", "--config", files.configPath,
    "--protocol", protocol, "--expected", expected, "--input", input, "--store", store,
    "--expected-state-hash", retained]);
}

test("offline finality quorum signs with independent pinned keys and verifies threshold", async t => {
  const files = await fixture(t);
  const a = await signEnvelope(files, 0), b = await signEnvelope(files, 1);
  assert.equal(a.result.signed, true);
  assert.equal(a.result.quorumId, b.result.quorumId);
  assert.notEqual(a.result.keyId, b.result.keyId);
  assert.equal((await stat(a.output)).mode & 0o777, 0o444);
  const input = await bundle(files, [a.envelope, b.envelope]);
  const result = JSON.parse((await verify(files, input)).stdout);
  assert.deepEqual(result, { verified: true, quorumId: a.result.quorumId, threshold: 2 });
});

test("quorum rejects insufficient, duplicate, tampered, substituted and foreign claims", async t => {
  const files = await fixture(t);
  const a = await signEnvelope(files, 0), b = await signEnvelope(files, 1);
  await assert.rejects(verify(files, await bundle(files, [a.envelope], "insufficient.json")),
    error => /threshold is not met/.test(error.stderr));
  await assert.rejects(verify(files, await bundle(files, [a.envelope, a.envelope], "duplicate.json")),
    error => /duplicate signer/.test(error.stderr));
  const tampered = structuredClone(b.envelope);
  tampered.signature = `${tampered.signature[0] === "A" ? "B" : "A"}${tampered.signature.slice(1)}`;
  await assert.rejects(verify(files, await bundle(files, [a.envelope, tampered], "tampered.json")),
    error => /signature verification failed/.test(error.stderr));
  const substituted = structuredClone(b.envelope);
  substituted.signerId = "settlement-c";
  await assert.rejects(verify(files, await bundle(files, [a.envelope, substituted], "substituted.json")),
    error => /untrusted or duplicate signer/.test(error.stderr));

  const foreignConfig = join(files.directory, "foreign-config.json");
  await writeFile(foreignConfig, JSON.stringify({ ...files.config, threshold: 3 }));
  await assert.rejects(verify(files, await bundle(files, [a.envelope, b.envelope], "foreign.json"),
    files.expected, foreignConfig), error => /untrusted quorum/.test(error.stderr));
  const foreignExpected = join(files.directory, "foreign-payload.json");
  await writeFile(foreignExpected, JSON.stringify(payload("ff")));
  await assert.rejects(verify(files, await bundle(files, [a.envelope, b.envelope], "wrong-head.json"),
    foreignExpected), error => /does not match/.test(error.stderr));
});

test("quorum config and signer key handling fail closed", async t => {
  const files = await fixture(t);
  const duplicate = { ...files.config, signers: [files.config.signers[0],
    { ...files.config.signers[1], publicKeyBase64Url: files.config.signers[0].publicKeyBase64Url },
    files.config.signers[2]] };
  await assert.rejects(canonicalBlochL2FinalityQuorumConfig(duplicate), /not independent/);
  let getterCalls = 0;
  const hostileSigner = { signerId: "settlement-a" };
  Object.defineProperty(hostileSigner, "publicKeyBase64Url", { enumerable: true,
    get() { getterCalls += 1; return files.config.signers[0].publicKeyBase64Url; } });
  await assert.rejects(canonicalBlochL2FinalityQuorumConfig({ ...files.config,
    signers: [hostileSigner, ...files.config.signers.slice(1)] }), /signer/);
  assert.equal(getterCalls, 0);
  await chmod(files.signers[0].privateKey, 0o644);
  await assert.rejects(execute(process.execPath, [cli, "sign", "--config", files.configPath,
    "--signer-id", files.signers[0].signerId, "--private-key", files.signers[0].privateKey,
    "--input", files.expected, "--output", join(files.directory, "unsafe.json")]),
  error => /private, single-link/.test(error.stderr));
  await chmod(files.signers[0].privateKey, 0o600);
  await assert.rejects(execute(process.execPath, [cli, "sign", "--config", files.configPath,
    "--signer-id", files.signers[0].signerId, "--private-key", files.signers[1].privateKey,
    "--input", files.expected, "--output", join(files.directory, "wrong-key.json")]),
  error => /does not match/.test(error.stderr));
});

test("verified quorum durably advances a checkpoint chained to an external state hash", async t => {
  const files = await fixture(t), store = join(files.directory, "quorum-state.json");
  const a = await signEnvelope(files, 0), b = await signEnvelope(files, 1);
  const firstBundle = await bundle(files, [a.envelope, b.envelope], "first-bundle.json");
  const first = JSON.parse((await advance(files, firstBundle, store, "none")).stdout);
  assert.equal(first.advanced, true);
  assert.equal(first.generation, "1");
  assert.equal(first.headNumber, "0x2");
  assert.match(first.stateHash, /^[0-9a-f]{64}$/);
  assert.match(first.bundleHash, /^[0-9a-f]{64}$/);
  assert.equal((await stat(store)).mode & 0o777, 0o600);
  const firstState = JSON.parse(await readFile(store, "utf8"));
  assert.equal(firstState.previousStateHash, null);
  assert.equal(firstState.stateHash, first.stateHash);

  const nextExpected = join(files.directory, "next-payload.json");
  await writeFile(nextExpected, JSON.stringify(payload("63", "0x3")));
  const nextA = await signEnvelope(files, 0, nextExpected, "-next");
  const nextB = await signEnvelope(files, 1, nextExpected, "-next");
  const nextBundle = await bundle(files, [nextB.envelope, nextA.envelope], "next-bundle.json");
  const second = JSON.parse((await advance(files, nextBundle, store, first.stateHash, nextExpected)).stdout);
  assert.equal(second.generation, "2");
  assert.equal(second.headNumber, "0x3");
  const secondState = JSON.parse(await readFile(store, "utf8"));
  assert.equal(secondState.previousStateHash, first.stateHash);
  assert.equal(secondState.stateHash, second.stateHash);
});

test("quorum checkpoint rejects stale anchor, replay, corruption and an orphan lock", async t => {
  const files = await fixture(t), store = join(files.directory, "quorum-state.json");
  const a = await signEnvelope(files, 0), b = await signEnvelope(files, 1);
  const input = await bundle(files, [a.envelope, b.envelope]);
  const first = JSON.parse((await advance(files, input, store, "none")).stdout);
  await assert.rejects(advance(files, input, store, "0".repeat(64)),
    error => /externally retained state hash/.test(error.stderr));
  await assert.rejects(advance(files, input, store, first.stateHash),
    error => /replay or same-height equivocation/.test(error.stderr));

  const retained = JSON.parse(await readFile(store, "utf8"));
  await writeFile(store, `${JSON.stringify({ ...retained, bundleHash: "f".repeat(64) })}\n`, { mode: 0o600 });
  await assert.rejects(advance(files, input, store, first.stateHash),
    error => /state is invalid/.test(error.stderr));
  await writeFile(store, `${JSON.stringify(retained)}\n`, { mode: 0o600 });
  await writeFile(`${store}.lock`, "operator inspection required\n", { mode: 0o600 });
  const higherExpected = join(files.directory, "higher-payload.json");
  await writeFile(higherExpected, JSON.stringify(payload("64", "0x4")));
  const higherA = await signEnvelope(files, 0, higherExpected, "-higher");
  const higherB = await signEnvelope(files, 1, higherExpected, "-higher");
  const higherBundle = await bundle(files, [higherA.envelope, higherB.envelope], "higher-bundle.json");
  await assert.rejects(advance(files, higherBundle, store, first.stateHash, higherExpected),
    error => /locked; inspect before retrying/.test(error.stderr));
  assert.equal(JSON.parse(await readFile(store, "utf8")).stateHash, first.stateHash);
});
