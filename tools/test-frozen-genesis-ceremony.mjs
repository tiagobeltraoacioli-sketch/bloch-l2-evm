#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmod, copyFile, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalBytes, validate } from "./check-frozen-genesis-admission.mjs";
import {
  assembleApprovals, createSignatureRequests, createTemplate, derivePackage,
  freezeTemplate, wrapResponse,
} from "./frozen-genesis-ceremony.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function digest(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
async function secureWrite(file, bytes) {
  await writeFile(file, bytes, { mode: 0o600 });
  await chmod(file, 0o600);
}

async function setup() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bloch-genesis-ceremony-"));
  const sourceRevision = "c".repeat(40);
  const build = (await import("node:child_process")).spawnSync(
    "cargo",
    ["build", "--quiet", "--locked", "--features", "serde", "--example", "bloch-genesis-identity"],
    { cwd: ROOT, encoding: "utf8", env: { ...process.env, BLOCH_L2_SOURCE_REVISION: sourceRevision } },
  );
  assert.equal(build.status, 0, build.stderr || build.error?.message);
  const verifier = path.join(directory, "bloch-genesis-identity");
  await copyFile(path.join(ROOT, "target/debug/examples/bloch-genesis-identity"), verifier);
  await chmod(verifier, 0o500);
  const verifierSha256 = digest(await readFile(verifier));
  const keys = [0, 1, 2].map(() => generateKeyPairSync("ed25519"));
  const roots = {
    chainId: 700771,
    network: "bloch-l2-testnet",
    roots: keys.map(({ publicKey }, index) => ({
      organizationId: `independent-organization-${index + 1}`,
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
      rootId: `trust-root-${index + 1}`,
    })),
    schema: "bloch.l2.genesis-trust-roots.v1",
    threshold: 2,
  };
  await secureWrite(path.join(directory, "roots.json"), canonicalBytes(roots));
  const contract = {
    chainId: 700771,
    classification: "external-approval-required-non-authorizing",
    genesisAdmitted: false,
    inputArtifacts: {
      approvals: null, approvalsSha256: null, genesisPackage: null, genesisPackageSha256: null,
      identityVerifier: "bloch-genesis-identity", identityVerifierSha256: verifierSha256,
      identityVerifierSourceRevision: sourceRevision, trustRoots: "roots.json",
      trustRootsSha256: digest(canonicalBytes(roots)),
    },
    network: "bloch-l2-testnet",
    permissions: { admitGenesis: false, bindRpc: false, publishFinalized: false, startNode: false },
    schema: "bloch.l2.frozen-genesis-admission.v1",
    status: "roots-pinned",
  };
  const contractPath = path.join(directory, "admission.json");
  await secureWrite(contractPath, canonicalBytes(contract));
  return { directory, keys, contractPath };
}

async function prepare(value) {
  const template = path.join(value.directory, "genesis.template.json");
  const genesis = path.join(value.directory, "genesis.json");
  const packagePath = path.join(value.directory, "package.json");
  await createTemplate(template);
  await freezeTemplate(template, `0x${"d3".repeat(32)}`, 1770000000, genesis);
  const derived = await derivePackage(value.contractPath, genesis, "ceremony-2026-001", "decision-2026-001", packagePath);
  const requestDirectory = path.join(value.directory, "requests");
  const requests = await createSignatureRequests(value.contractPath, packagePath, requestDirectory);
  return { template, genesis, packagePath, requestDirectory, requests, derived };
}

async function signedResponses(value, prepared, count = 2, start = 0) {
  const outputs = [];
  for (let index = start; index < start + count; index += 1) {
    const entry = prepared.requests.outputs[index];
    const payload = await readFile(entry.payload);
    const signaturePath = path.join(value.directory, `root-${index + 1}.sig`);
    await secureWrite(signaturePath, sign(null, payload, value.keys[index].privateKey));
    const responsePath = path.join(value.directory, `root-${index + 1}.response.json`);
    await wrapResponse(value.contractPath, entry.request, signaturePath, responsePath);
    outputs.push(responsePath);
  }
  return outputs;
}

test("full identity-free ceremony produces a gate-compatible 2-of-3 envelope", async () => {
  const value = await setup();
  const prepared = await prepare(value);
  assert.equal(prepared.derived.derivedIdentityVerified, true);
  assert.equal(prepared.derived.nodeStartPermitted, false);
  assert.equal(prepared.requests.requestsCreated, 3);
  const template = JSON.parse(await readFile(prepared.template, "utf8"));
  assert.equal(template.domain, null);
  assert.equal(template.timestamp, null);
  assert.equal(JSON.stringify(template).includes("private"), false);

  const responses = await signedResponses(value, prepared, 2);
  const approvals = path.join(value.directory, "approvals.json");
  const assembled = await assembleApprovals(value.contractPath, prepared.packagePath, responses, approvals);
  assert.equal(assembled.approvalsVerified, 2);
  assert.equal(assembled.nodeStartPermitted, false);
  const gate = await validate({ contract: value.contractPath, package: prepared.packagePath, approvals });
  assert.equal(gate.genesisAdmitted, true);
  assert.equal(gate.nodeStartPermitted, false);
});

test("every ceremony output is create-once", async () => {
  const value = await setup();
  const prepared = await prepare(value);
  const templateBefore = await readFile(prepared.template);
  await assert.rejects(createTemplate(prepared.template), /refusing to overwrite/);
  assert.deepEqual(await readFile(prepared.template), templateBefore);
  const packageBefore = await readFile(prepared.packagePath);
  await assert.rejects(derivePackage(value.contractPath, prepared.genesis, "ceremony-2026-001", "decision-2026-001", prepared.packagePath), /refusing to overwrite/);
  assert.deepEqual(await readFile(prepared.packagePath), packageBefore);
  await assert.rejects(createSignatureRequests(value.contractPath, prepared.packagePath, prepared.requestDirectory), /EEXIST|exist/);
  const responses = await signedResponses(value, prepared, 2);
  const approvals = path.join(value.directory, "approvals.json");
  await assembleApprovals(value.contractPath, prepared.packagePath, responses, approvals);
  await assert.rejects(assembleApprovals(value.contractPath, prepared.packagePath, responses, approvals), /refusing to overwrite/);
});

test("one response, wrong signer and tampered response fail closed", async () => {
  const value = await setup();
  const prepared = await prepare(value);
  const one = await signedResponses(value, prepared, 1);
  await assert.rejects(assembleApprovals(value.contractPath, prepared.packagePath, one, path.join(value.directory, "one.json")), /insufficient detached responses/);

  const secondRequest = prepared.requests.outputs[1];
  const wrongSignature = path.join(value.directory, "wrong.sig");
  await secureWrite(wrongSignature, sign(null, await readFile(secondRequest.payload), value.keys[2].privateKey));
  await assert.rejects(wrapResponse(value.contractPath, secondRequest.request, wrongSignature, path.join(value.directory, "wrong.json")), /detached signature is invalid/);

  const second = await signedResponses(value, prepared, 1, 1);
  const two = [one[0], second[0]];
  const response = JSON.parse(await readFile(two[1], "utf8"));
  response.packageSha256 = "0".repeat(64);
  const tampered = path.join(value.directory, "tampered.response.json");
  await secureWrite(tampered, canonicalBytes(response));
  await assert.rejects(assembleApprovals(value.contractPath, prepared.packagePath, [two[0], tampered], path.join(value.directory, "tampered.json")), /targets another package/);
});
