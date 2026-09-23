#!/usr/bin/env node

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmod, copyFile, link, mkdtemp, readFile, rename, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { AdmissionError, canonicalBytes, validate } from "./check-frozen-genesis-admission.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DOMAIN = Buffer.from("BLOCH-L2-FROZEN-GENESIS-V1\0", "ascii");

async function writeCanonical(file, value) {
  await writeFile(file, canonicalBytes(value), { mode: 0o600 });
  await chmod(file, 0o600);
}
async function sha256(bytes) { return (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex"); }

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bloch-genesis-admission-"));
  const genesis = { chainId: 700771, domain: `0x${"d3".repeat(32)}`, executionProfile: "bloch-l2-cancun-zero-issuance-v1", schema: "bloch.l2.frozen-genesis.v1", timestamp: 1770000000 };
  const genesisPath = path.join(directory, "genesis.json");
  await writeCanonical(genesisPath, genesis);
  const genesisDigest = await sha256(canonicalBytes(genesis));
  const genesisPackage = {
    ceremonyId: "ceremony-2026-001",
    chainId: 700771,
    classification: "externally-reviewed-production-candidate",
    decisionId: "decision-2026-001",
    genesis: { blockHash: "DERIVE", path: "genesis.json", sha256: genesisDigest, stateRoot: "DERIVE" },
    network: "bloch-l2-testnet",
    schema: "bloch.l2.frozen-genesis-package.v1",
  };
  const sourceRevision = "a".repeat(40);
  const build = (await import("node:child_process")).spawnSync("cargo", ["build", "--quiet", "--locked", "--features", "serde", "--example", "bloch-genesis-identity"], { cwd: ROOT, encoding: "utf8", env: { ...process.env, BLOCH_L2_SOURCE_REVISION: sourceRevision } });
  assert.equal(build.status, 0, build.stderr);
  const verifierPath = path.join(directory, "bloch-genesis-identity");
  await copyFile(path.join(ROOT, "target/debug/examples/bloch-genesis-identity"), verifierPath);
  await chmod(verifierPath, 0o500);
  const verifierDigest = await sha256(await readFile(verifierPath));
  const derived = JSON.parse((await import("node:child_process")).spawnSync(verifierPath, [genesisPath], { encoding: "utf8" }).stdout);
  genesisPackage.genesis.blockHash = derived.blockHash;
  genesisPackage.genesis.stateRoot = derived.stateRoot;
  const packagePath = path.join(directory, "package.json");
  await writeCanonical(packagePath, genesisPackage);
  const packageDigest = await sha256(canonicalBytes(genesisPackage));
  const keys = [0, 1, 2].map(() => generateKeyPairSync("ed25519"));
  const roots = {
    chainId: 700771,
    network: "bloch-l2-testnet",
    roots: keys.map(({ publicKey }, index) => ({ organizationId: `organization-${index + 1}`, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }), rootId: `root-${index + 1}` })),
    schema: "bloch.l2.genesis-trust-roots.v1",
    threshold: 2,
  };
  const rootsPath = path.join(directory, "roots.json");
  await writeCanonical(rootsPath, roots);
  const rootsDigest = await sha256(canonicalBytes(roots));
  const contract = {
    chainId: 700771,
    classification: "external-approval-required-non-authorizing",
    genesisAdmitted: false,
    inputArtifacts: { approvals: null, approvalsSha256: null, genesisPackage: null, genesisPackageSha256: null, identityVerifier: "bloch-genesis-identity", identityVerifierSha256: verifierDigest, identityVerifierSourceRevision: sourceRevision, trustRoots: "roots.json", trustRootsSha256: rootsDigest },
    network: "bloch-l2-testnet",
    permissions: { admitGenesis: false, bindRpc: false, publishFinalized: false, startNode: false },
    schema: "bloch.l2.frozen-genesis-admission.v1",
    status: "roots-pinned",
  };
  const contractPath = path.join(directory, "admission.json");
  await writeCanonical(contractPath, contract);
  const message = Buffer.concat([DOMAIN, Buffer.from(packageDigest, "hex")]);
  const approvals = {
    approvals: keys.slice(0, 2).map(({ privateKey }, index) => ({ organizationId: `organization-${index + 1}`, rootId: `root-${index + 1}`, signatureBase64: sign(null, message, privateKey).toString("base64") })),
    chainId: 700771,
    decision: "approve-frozen-production-genesis",
    genesisSha256: genesisDigest,
    network: "bloch-l2-testnet",
    packageSha256: packageDigest,
    schema: "bloch.l2.frozen-genesis-approvals.v1",
  };
  const approvalsPath = path.join(directory, "approvals.json");
  await writeCanonical(approvalsPath, approvals);
  return { directory, genesis, genesisPath, genesisPackage, packagePath, roots, rootsPath, rootsDigest, contract, contractPath, approvals, approvalsPath };
}

function options(value) {
  return { contract: value.contractPath, package: value.packagePath, approvals: value.approvalsPath };
}

test("checked-in contract remains pending and grants no permission", async () => {
  const report = await validate({ contract: path.join(ROOT, "deployment/frozen-genesis-admission.json") });
  assert.equal(report.genesisAdmitted, false);
  assert.equal(report.nodeStartPermitted, false);
  assert.equal(report.sideEffects, false);
});

test("canonical package with two independent Ed25519 approvals is admitted offline", async () => {
  const value = await fixture();
  const report = await validate(options(value));
  assert.equal(report.chainId, 700771);
  assert.equal(report.genesisAdmitted, true);
  assert.equal(report.approvalsVerified, 2);
  assert.equal(report.nodeStartPermitted, false);
  assert.equal(report.sideEffects, false);
});

test("wrong trust-root pin and one approval fail closed", async () => {
  const value = await fixture();
  value.contract.inputArtifacts.trustRootsSha256 = "0".repeat(64);
  await writeCanonical(value.contractPath, value.contract);
  await assert.rejects(validate(options(value)), /reviewed contract pin/);
  value.contract.inputArtifacts.trustRootsSha256 = value.rootsDigest;
  await writeCanonical(value.contractPath, value.contract);
  value.approvals.approvals.pop();
  await writeCanonical(value.approvalsPath, value.approvals);
  await assert.rejects(validate(options(value)), /insufficient independent approvals/);
});

test("unreviewed verifier bytes and source revision fail closed", async () => {
  const value = await fixture();
  value.contract.inputArtifacts.identityVerifierSha256 = "0".repeat(64);
  await writeCanonical(value.contractPath, value.contract);
  await assert.rejects(validate(options(value)), /identity verifier does not match/);

  const value2 = await fixture();
  value2.contract.inputArtifacts.identityVerifierSourceRevision = "b".repeat(40);
  await writeCanonical(value2.contractPath, value2.contract);
  await assert.rejects(validate(options(value2)), /source revision does not match/);
});

test("symlink, hardlink and writable verifier files fail closed", async () => {
  const value = await fixture();
  const original = path.join(value.directory, "verifier-original");
  await rename(path.join(value.directory, "bloch-genesis-identity"), original);
  await symlink(original, path.join(value.directory, "bloch-genesis-identity"));
  await assert.rejects(validate(options(value)), /non-symlink/);

  const value2 = await fixture();
  await link(path.join(value2.directory, "bloch-genesis-identity"), path.join(value2.directory, "verifier-hardlink"));
  await assert.rejects(validate(options(value2)), /hard-linked/);

  const value3 = await fixture();
  await chmod(path.join(value3.directory, "bloch-genesis-identity"), 0o666);
  await assert.rejects(validate(options(value3)), /group\/world writable/);
});

test("tampered package, genesis and signature are rejected", async () => {
  const value = await fixture();
  value.genesisPackage.decisionId = "decision-tampered";
  await writeCanonical(value.packagePath, value.genesisPackage);
  await assert.rejects(validate(options(value)), /approvals do not bind/);

  const value2 = await fixture();
  value2.genesis.chainId = 84001;
  await writeCanonical(value2.genesisPath, value2.genesis);
  await assert.rejects(validate(options(value2)), /sha256 mismatch/);

  const value3 = await fixture();
  value3.approvals.approvals[0].signatureBase64 = Buffer.alloc(64, 7).toString("base64");
  await writeCanonical(value3.approvalsPath, value3.approvals);
  await assert.rejects(validate(options(value3)), /invalid signature/);
});

test("noncanonical input and incomplete option set are rejected", async () => {
  const value = await fixture();
  await writeFile(value.packagePath, JSON.stringify(value.genesisPackage, null, 2));
  await assert.rejects(validate(options(value)), /must use canonical JSON/);
  await assert.rejects(validate({ contract: options(value).contract, package: value.packagePath }), /supplied together/);
});

test("three roots must represent distinct ids, organizations and keys", async () => {
  for (const mutate of [
    (roots) => { roots.roots[1].rootId = roots.roots[0].rootId; },
    (roots) => { roots.roots[1].organizationId = roots.roots[0].organizationId; },
    (roots) => { roots.roots[1].publicKeyPem = roots.roots[0].publicKeyPem; },
  ]) {
    const value = await fixture();
    mutate(value.roots);
    await writeCanonical(value.rootsPath, value.roots);
    value.rootsDigest = await sha256(canonicalBytes(value.roots));
    value.contract.inputArtifacts.trustRootsSha256 = value.rootsDigest;
    await writeCanonical(value.contractPath, value.contract);
    await assert.rejects(validate(options(value)), AdmissionError);
  }
});

test("package cannot self-supply or bypass a previously reviewed roots pin", async () => {
  const value = await fixture();
  await assert.rejects(validate({
    contract: path.join(ROOT, "deployment/frozen-genesis-admission.json"),
    package: value.packagePath,
    approvals: value.approvalsPath,
  }), /must be pinned in the reviewed admission contract/);
});

test("genesis path traversal and zero reviewed roots are rejected", async () => {
  const value = await fixture();
  value.genesisPackage.genesis.path = "../genesis.json";
  await writeCanonical(value.packagePath, value.genesisPackage);
  await assert.rejects(validate(options(value)), /cannot escape/);

  const value2 = await fixture();
  value2.genesisPackage.genesis.stateRoot = `0x${"00".repeat(32)}`;
  await writeCanonical(value2.packagePath, value2.genesisPackage);
  await assert.rejects(validate(options(value2)), /nonzero/);
});

test("signed but falsely declared derived identities are rejected", async () => {
  const value = await fixture();
  value.genesisPackage.genesis.stateRoot = `0x${"44".repeat(32)}`;
  await writeCanonical(value.packagePath, value.genesisPackage);
  const packageDigest = await sha256(canonicalBytes(value.genesisPackage));
  value.approvals.packageSha256 = packageDigest;
  await writeCanonical(value.approvalsPath, value.approvals);
  await assert.rejects(validate(options(value)), /reviewed state root does not match/);
});
