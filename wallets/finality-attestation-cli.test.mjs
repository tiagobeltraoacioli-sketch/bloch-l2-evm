// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const execute = promisify(execFile);
const cli = new URL("./finality-attestation-cli.mjs", import.meta.url).pathname;
const protocol = "bloch-native-checkpoint-v1";

function fixture(now = Math.floor(Date.now() / 1_000), headNumber = "0x2", headByte = "62") {
  return {
    format: "bloch-l2-finality-attestation-v1",
    identity: {
      format: "bloch-chain-identity-v1",
      chainId: "0xab163",
      domain: `0x${"71".repeat(32)}`,
      genesisHash: `0x${"42".repeat(32)}`,
      headerFormat: "bloch-node-header-v2-fixed-width",
    },
    checkpoint: {
      format: "bloch-wallet-checkpoint-v1",
      headNumber,
      headHash: `0x${headByte.repeat(32)}`,
      stateRoot: `0x${"72".repeat(32)}`,
    },
    issuedAt: now,
    expiresAt: now + 300,
    finalityProtocol: protocol,
    finalityReference: `0x${"91".repeat(32)}`,
  };
}

async function files(t) {
  const directory = await mkdtemp(join(tmpdir(), "bloch-finality-cli-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keys = generateKeyPairSync("ed25519");
  const privateKey = join(directory, "private.pem");
  const publicKey = join(directory, "public.pem");
  const input = join(directory, "payload.json");
  const output = join(directory, "envelope.json");
  await writeFile(privateKey, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  await writeFile(publicKey, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  await writeFile(input, `${JSON.stringify(fixture())}\n`);
  return { directory, privateKey, publicKey, input, output };
}

test("offline CLI signs canonically, creates once and verifies through the wallet verifier", async t => {
  const paths = await files(t);
  const signed = await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", paths.input, "--output", paths.output]);
  const signingResult = JSON.parse(signed.stdout);
  assert.equal(signingResult.signed, true);
  assert.match(signingResult.keyId, /^[0-9a-f]{64}$/);
  assert.equal((await stat(paths.output)).mode & 0o777, 0o444);
  const envelope = JSON.parse(await readFile(paths.output, "utf8"));
  assert.deepEqual(Object.keys(envelope), ["format", "keyId", "payload", "signature"]);
  assert.deepEqual(Object.keys(envelope.payload), [
    "format", "identity", "checkpoint", "issuedAt", "expiresAt", "finalityProtocol", "finalityReference",
  ]);
  const verified = await execute(process.execPath, [cli, "verify", "--public-key", paths.publicKey,
    "--protocol", protocol, "--input", paths.output]);
  assert.deepEqual(JSON.parse(verified.stdout), { verified: true, keyId: signingResult.keyId });
  await assert.rejects(
    execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
      "--input", paths.input, "--output", paths.output]),
    error => error.code === 1,
  );
});

test("offline CLI rejects unsafe keys, tampering, wrong protocol and stale attestations", async t => {
  const paths = await files(t);
  await chmod(paths.privateKey, 0o644);
  await assert.rejects(
    execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
      "--input", paths.input, "--output", paths.output]),
    error => /private, single-link/.test(error.stderr),
  );
  await chmod(paths.privateKey, 0o600);
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", paths.input, "--output", paths.output]);
  const envelope = JSON.parse(await readFile(paths.output, "utf8"));
  const tampered = join(paths.directory, "tampered.json");
  await writeFile(tampered, JSON.stringify({ ...envelope, signature:
    `${envelope.signature[0] === "A" ? "B" : "A"}${envelope.signature.slice(1)}` }));
  await assert.rejects(
    execute(process.execPath, [cli, "verify", "--public-key", paths.publicKey,
      "--protocol", protocol, "--input", tampered]),
    error => /signature verification failed/.test(error.stderr),
  );
  await assert.rejects(
    execute(process.execPath, [cli, "verify", "--public-key", paths.publicKey,
      "--protocol", "foreign-finality-v1", "--input", paths.output]),
    error => /Invalid Bloch L2 finality attestation/.test(error.stderr),
  );

  const stalePayload = join(paths.directory, "stale.json");
  const staleEnvelope = join(paths.directory, "stale-envelope.json");
  const now = Math.floor(Date.now() / 1_000);
  await writeFile(stalePayload, JSON.stringify(fixture(now - 600)));
  // fixture(now - 600) expires at now - 300 and is structurally signable.
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", stalePayload, "--output", staleEnvelope]);
  await assert.rejects(
    execute(process.execPath, [cli, "verify", "--public-key", paths.publicKey,
      "--protocol", protocol, "--input", staleEnvelope]),
    error => /not fresh/.test(error.stderr),
  );
});

test("verify-advance durably chains a checkpoint to an externally retained state hash", async t => {
  const paths = await files(t);
  const store = join(paths.directory, "checkpoint-state.json");
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", paths.input, "--output", paths.output]);
  const first = JSON.parse((await execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", "none"])).stdout);
  assert.equal(first.advanced, true);
  assert.equal(first.generation, "1");
  assert.equal(first.headNumber, "0x2");
  assert.match(first.stateHash, /^[0-9a-f]{64}$/);
  assert.equal((await stat(store)).mode & 0o777, 0o600);
  const firstState = JSON.parse(await readFile(store, "utf8"));
  assert.equal(firstState.previousStateHash, null);
  assert.equal(firstState.stateHash, first.stateHash);

  const nextPayload = join(paths.directory, "next.json");
  const nextEnvelope = join(paths.directory, "next-envelope.json");
  await writeFile(nextPayload, JSON.stringify(fixture(Math.floor(Date.now() / 1_000), "0x3", "63")));
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", nextPayload, "--output", nextEnvelope]);
  const second = JSON.parse((await execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", nextEnvelope,
    "--store", store, "--expected-state-hash", first.stateHash])).stdout);
  assert.equal(second.generation, "2");
  assert.equal(second.headNumber, "0x3");
  const secondState = JSON.parse(await readFile(store, "utf8"));
  assert.equal(secondState.previousStateHash, first.stateHash);
  assert.equal(secondState.stateHash, second.stateHash);
});

test("verify-advance rejects stale anchors, replay, rollback, equivocation and a locked store", async t => {
  const paths = await files(t);
  const store = join(paths.directory, "checkpoint-state.json");
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", paths.input, "--output", paths.output]);
  const first = JSON.parse((await execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", "none"])).stdout);

  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", "0".repeat(64)]),
  error => /externally retained state hash/.test(error.stderr));
  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", first.stateHash]),
  error => /replay or same-height equivocation/.test(error.stderr));

  const equivocalPayload = join(paths.directory, "equivocal.json");
  const equivocalEnvelope = join(paths.directory, "equivocal-envelope.json");
  await writeFile(equivocalPayload, JSON.stringify(fixture(Math.floor(Date.now() / 1_000), "0x2", "ff")));
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", equivocalPayload, "--output", equivocalEnvelope]);
  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", equivocalEnvelope,
    "--store", store, "--expected-state-hash", first.stateHash]),
  error => /replay or same-height equivocation/.test(error.stderr));

  const higherPayload = join(paths.directory, "higher.json");
  const higherEnvelope = join(paths.directory, "higher-envelope.json");
  await writeFile(higherPayload, JSON.stringify(fixture(Math.floor(Date.now() / 1_000), "0x4", "64")));
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", higherPayload, "--output", higherEnvelope]);
  await writeFile(`${store}.lock`, "operator-held\n", { mode: 0o600 });
  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", higherEnvelope,
    "--store", store, "--expected-state-hash", first.stateHash]),
  error => /store is locked/.test(error.stderr));
  assert.equal(JSON.parse(await readFile(store, "utf8")).stateHash, first.stateHash);
});

test("verify-advance rejects corrupted or writable checkpoint state", async t => {
  const paths = await files(t);
  const store = join(paths.directory, "checkpoint-state.json");
  await execute(process.execPath, [cli, "sign", "--private-key", paths.privateKey,
    "--input", paths.input, "--output", paths.output]);
  const first = JSON.parse((await execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", "none"])).stdout);
  const state = JSON.parse(await readFile(store, "utf8"));
  await writeFile(store, JSON.stringify({ ...state, envelopeHash: "f".repeat(64) }), { mode: 0o600 });
  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", first.stateHash]),
  error => /invalid state/.test(error.stderr));
  await writeFile(store, JSON.stringify(state), { mode: 0o666 });
  await chmod(store, 0o666);
  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", store, "--expected-state-hash", first.stateHash]),
  error => /protected regular file/.test(error.stderr));

  const unsafeDirectory = join(paths.directory, "writable");
  await mkdir(unsafeDirectory, { mode: 0o777 });
  await chmod(unsafeDirectory, 0o777);
  await assert.rejects(execute(process.execPath, [cli, "verify-advance",
    "--public-key", paths.publicKey, "--protocol", protocol, "--input", paths.output,
    "--store", join(unsafeDirectory, "state.json"), "--expected-state-hash", "none"]),
  error => /directory must not be group\/world writable/.test(error.stderr));
});
