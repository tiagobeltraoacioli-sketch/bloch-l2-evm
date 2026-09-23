#!/usr/bin/env node
/** Offline, fail-closed admission gate for an externally approved L2 genesis. */

import { createHash, createPublicKey, verify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants as FS, lstat, mkdtemp, open, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HEX64 = /^[0-9a-f]{64}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const SIGNATURE_DOMAIN = Buffer.from("BLOCH-L2-FROZEN-GENESIS-V1\0", "ascii");

export class AdmissionError extends Error {}

function requireCondition(condition, message) {
  if (!condition) throw new AdmissionError(message);
}

function exactObject(value, fields, label) {
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  requireCondition(JSON.stringify(actual) === JSON.stringify(expected), `${label} fields must be exactly ${expected.join(", ")}`);
  return value;
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    requireCondition(Number.isSafeInteger(value), "canonical JSON numbers must be safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  requireCondition(typeof value === "object", "unsupported canonical JSON value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`).join(",")}}`;
}

export function canonicalBytes(value) {
  return Buffer.from(`${canonicalValue(value)}\n`, "utf8");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function regularFile(file, label, maximum = 16 * 1024 * 1024) {
  const before = await lstat(file).catch((error) => { throw new AdmissionError(`cannot stat ${label}: ${error.message}`); });
  requireCondition(before.isFile() && !before.isSymbolicLink(), `${label} must be a regular non-symlink file`);
  requireCondition(before.nlink === 1, `${label} must not be hard-linked`);
  requireCondition((before.mode & 0o022) === 0, `${label} must not be group/world writable`);
  requireCondition(before.size <= maximum, `${label} exceeds the size limit`);
  let handle;
  try {
    handle = await open(file, FS.O_RDONLY | FS.O_NOFOLLOW);
    const opened = await handle.stat();
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeMs", "ctimeMs"]) {
      requireCondition(opened[field] === before[field], `${label} changed while it was opened`);
    }
    const bytes = await handle.readFile();
    const afterRead = await handle.stat();
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeMs", "ctimeMs"]) {
      requireCondition(afterRead[field] === opened[field], `${label} changed while it was read`);
    }
    const afterPath = await lstat(file);
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeMs", "ctimeMs"]) {
      requireCondition(afterPath[field] === opened[field], `${label} pathname changed while it was read`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof AdmissionError) throw error;
    throw new AdmissionError(`cannot securely read ${label}: ${error.message}`);
  } finally {
    await handle?.close();
  }
}

async function jsonDocument(file, label, requireCanonical = true) {
  const bytes = await regularFile(file, label);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch (error) { throw new AdmissionError(`${label} is not valid JSON: ${error.message}`); }
  if (requireCanonical) requireCondition(bytes.equals(canonicalBytes(value)), `${label} must use canonical JSON (sorted keys, compact form, trailing newline)`);
  return { value, bytes, sha256: sha256(bytes) };
}

function validateContract(value) {
  const contract = exactObject(value, ["schema", "network", "chainId", "classification", "status", "inputArtifacts", "permissions", "genesisAdmitted"], "admission contract");
  requireCondition(contract.schema === "bloch.l2.frozen-genesis-admission.v1", "unsupported admission contract schema");
  requireCondition(contract.network === "bloch-l2-testnet" && contract.chainId === 700771, "admission contract must target bloch-l2-testnet chain 700771");
  requireCondition(contract.classification === "external-approval-required-non-authorizing", "admission contract classification changed");
  requireCondition(["pending", "roots-pinned"].includes(contract.status) && contract.genesisAdmitted === false, "admission contract has an invalid status");
  const inputs = exactObject(contract.inputArtifacts, ["trustRoots", "trustRootsSha256", "identityVerifier", "identityVerifierSha256", "identityVerifierSourceRevision", "genesisPackage", "genesisPackageSha256", "approvals", "approvalsSha256"], "inputArtifacts");
  if (contract.status === "pending") {
    requireCondition(Object.values(inputs).every((item) => item === null), "pending admission contract cannot claim external artifacts");
  } else {
    requireCondition(typeof inputs.trustRoots === "string" && inputs.trustRoots.length > 0 && !path.isAbsolute(inputs.trustRoots) && !inputs.trustRoots.split(/[\\/]/).includes(".."), "pinned trust roots path must be relative and contained");
    requireCondition(typeof inputs.trustRootsSha256 === "string" && HEX64.test(inputs.trustRootsSha256), "pinned trust roots sha256 is invalid");
    requireCondition(typeof inputs.identityVerifier === "string" && inputs.identityVerifier.length > 0 && !path.isAbsolute(inputs.identityVerifier) && !inputs.identityVerifier.split(/[\\/]/).includes(".."), "pinned identity verifier path must be relative and contained");
    requireCondition(typeof inputs.identityVerifierSha256 === "string" && HEX64.test(inputs.identityVerifierSha256), "pinned identity verifier sha256 is invalid");
    requireCondition(typeof inputs.identityVerifierSourceRevision === "string" && /^[0-9a-f]{40}$/.test(inputs.identityVerifierSourceRevision), "pinned identity verifier source revision is invalid");
    requireCondition(inputs.genesisPackage === null && inputs.genesisPackageSha256 === null && inputs.approvals === null && inputs.approvalsSha256 === null, "roots-pinned contract cannot claim unverified genesis artifacts");
  }
  const permissions = exactObject(contract.permissions, ["admitGenesis", "startNode", "bindRpc", "publishFinalized"], "permissions");
  requireCondition(Object.values(permissions).every((item) => item === false), "pending admission contract cannot grant permissions");
  return contract;
}

function validateTrustRoots(value) {
  const registry = exactObject(value, ["schema", "network", "chainId", "threshold", "roots"], "trust root registry");
  requireCondition(registry.schema === "bloch.l2.genesis-trust-roots.v1", "unsupported trust root registry schema");
  requireCondition(registry.network === "bloch-l2-testnet" && registry.chainId === 700771, "trust roots target the wrong chain");
  requireCondition(registry.threshold === 2, "trust root threshold must be 2 of 3");
  requireCondition(Array.isArray(registry.roots) && registry.roots.length === 3, "exactly three trust roots are required");
  const ids = new Set();
  const organizations = new Set();
  const keyHashes = new Set();
  const roots = new Map();
  for (const item of registry.roots) {
    const root = exactObject(item, ["rootId", "organizationId", "publicKeyPem"], "trust root");
    requireCondition(typeof root.rootId === "string" && ID.test(root.rootId), "invalid trust root id");
    requireCondition(typeof root.organizationId === "string" && ID.test(root.organizationId), "invalid trust root organization id");
    requireCondition(typeof root.publicKeyPem === "string" && root.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n") && root.publicKeyPem.endsWith("-----END PUBLIC KEY-----\n"), "trust root must contain one PEM public key");
    let publicKey;
    try { publicKey = createPublicKey(root.publicKeyPem); }
    catch (error) { throw new AdmissionError(`invalid public key for ${root.rootId}: ${error.message}`); }
    requireCondition(publicKey.asymmetricKeyType === "ed25519", `${root.rootId} must use Ed25519`);
    const keyHash = sha256(publicKey.export({ type: "spki", format: "der" }));
    requireCondition(!ids.has(root.rootId), "trust root ids must be unique");
    requireCondition(!organizations.has(root.organizationId), "trust root organizations must be distinct");
    requireCondition(!keyHashes.has(keyHash), "trust root public keys must be distinct");
    ids.add(root.rootId); organizations.add(root.organizationId); keyHashes.add(keyHash);
    roots.set(root.rootId, { ...root, publicKey });
  }
  return { registry, roots };
}

async function executePinnedVerifier(verifierBytes, artifactPath) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bloch-genesis-verifier-"));
  const executable = path.join(directory, "bloch-genesis-identity");
  try {
    await writeFile(executable, verifierBytes, { mode: 0o500, flag: "wx" });
    return spawnSync(executable, [artifactPath], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function validatePackage(document, packagePath, verifier) {
  const value = exactObject(document.value, ["schema", "network", "chainId", "classification", "ceremonyId", "decisionId", "genesis"], "genesis package");
  requireCondition(value.schema === "bloch.l2.frozen-genesis-package.v1", "unsupported genesis package schema");
  requireCondition(value.network === "bloch-l2-testnet" && value.chainId === 700771, "genesis package targets the wrong chain");
  requireCondition(value.classification === "externally-reviewed-production-candidate", "genesis package classification is not reviewable");
  requireCondition(typeof value.ceremonyId === "string" && ID.test(value.ceremonyId), "invalid ceremony id");
  requireCondition(typeof value.decisionId === "string" && ID.test(value.decisionId), "invalid decision id");
  const genesis = exactObject(value.genesis, ["path", "sha256", "stateRoot", "blockHash"], "genesis descriptor");
  requireCondition(typeof genesis.path === "string" && genesis.path.length > 0 && !path.isAbsolute(genesis.path), "genesis path must be relative");
  requireCondition(!genesis.path.split(/[\\/]/).includes(".."), "genesis path cannot escape its package directory");
  requireCondition(HEX64.test(genesis.sha256), "invalid genesis sha256");
  requireCondition(HASH.test(genesis.stateRoot) && !/^0x0+$/.test(genesis.stateRoot), "genesis state root must be a nonzero 32-byte hash");
  requireCondition(HASH.test(genesis.blockHash) && !/^0x0+$/.test(genesis.blockHash), "genesis block hash must be a nonzero 32-byte hash");
  const base = await realpath(path.dirname(packagePath));
  const artifactPath = path.resolve(base, genesis.path);
  const resolved = await realpath(artifactPath).catch((error) => { throw new AdmissionError(`cannot resolve genesis artifact: ${error.message}`); });
  requireCondition(resolved === base || resolved.startsWith(`${base}${path.sep}`), "genesis artifact escapes its package directory");
  const artifact = await jsonDocument(artifactPath, "genesis artifact");
  requireCondition(artifact.sha256 === genesis.sha256, "genesis artifact sha256 mismatch");
  exactObject(artifact.value, ["chainId", "domain", "executionProfile", "schema", "timestamp"], "genesis artifact");
  requireCondition(artifact.value.schema === "bloch.l2.frozen-genesis.v1", "unsupported frozen genesis artifact schema");
  requireCondition(artifact.value.chainId === 700771, "genesis artifact chainId must be 700771");
  requireCondition(artifact.value.executionProfile === "bloch-l2-cancun-zero-issuance-v1", "genesis artifact uses an unsupported execution profile");
  requireCondition(typeof artifact.value.domain === "string" && HASH.test(artifact.value.domain) && !/^0x0+$/.test(artifact.value.domain), "genesis domain must be a nonzero 32-byte hash");
  requireCondition(Number.isSafeInteger(artifact.value.timestamp) && artifact.value.timestamp > 0, "genesis timestamp must be a positive safe integer");
  const result = await executePinnedVerifier(verifier.bytes, resolved);
  requireCondition(!result.error, `cannot execute compiled genesis identity verifier: ${result.error?.message}`);
  requireCondition(result.status === 0, `compiled genesis identity verifier rejected the artifact: ${(result.stderr || "no diagnostic").trim()}`);
  let derived;
  try { derived = JSON.parse(result.stdout); }
  catch (error) { throw new AdmissionError(`compiled genesis identity verifier returned invalid JSON: ${error.message}`); }
  exactObject(derived, ["blockHash", "buildSourceRevision", "chainId", "domain", "executionProfile", "stateRoot", "timestamp"], "derived genesis identity");
  requireCondition(derived.buildSourceRevision === verifier.sourceRevision, "compiled genesis verifier source revision does not match the reviewed contract pin");
  requireCondition(derived.chainId === 700771 && derived.domain === artifact.value.domain && derived.executionProfile === artifact.value.executionProfile && derived.timestamp === artifact.value.timestamp, "compiled genesis identity does not bind the complete artifact");
  requireCondition(derived.stateRoot === genesis.stateRoot, "reviewed state root does not match the compiled genesis derivation");
  requireCondition(derived.blockHash === genesis.blockHash, "reviewed block hash does not match the compiled genesis derivation");
  return { value, artifact, derived };
}

function validateApprovals(value, packageDigest, genesisDigest, trustRoots) {
  const envelope = exactObject(value, ["schema", "network", "chainId", "packageSha256", "genesisSha256", "decision", "approvals"], "approval envelope");
  requireCondition(envelope.schema === "bloch.l2.frozen-genesis-approvals.v1", "unsupported approval envelope schema");
  requireCondition(envelope.network === "bloch-l2-testnet" && envelope.chainId === 700771, "approvals target the wrong chain");
  requireCondition(envelope.packageSha256 === packageDigest && envelope.genesisSha256 === genesisDigest, "approvals do not bind the supplied package and genesis");
  requireCondition(envelope.decision === "approve-frozen-production-genesis", "approval decision is not affirmative");
  requireCondition(Array.isArray(envelope.approvals), "approvals must be an array");
  const message = Buffer.concat([SIGNATURE_DOMAIN, Buffer.from(packageDigest, "hex")]);
  const seen = new Set();
  for (const item of envelope.approvals) {
    const approval = exactObject(item, ["rootId", "organizationId", "signatureBase64"], "approval");
    const root = trustRoots.roots.get(approval.rootId);
    requireCondition(root !== undefined, `approval uses unknown trust root: ${approval.rootId}`);
    requireCondition(approval.organizationId === root.organizationId, `approval organization mismatch: ${approval.rootId}`);
    requireCondition(!seen.has(approval.rootId), `duplicate approval: ${approval.rootId}`);
    requireCondition(typeof approval.signatureBase64 === "string" && /^[A-Za-z0-9+/]{86}==$/.test(approval.signatureBase64), `invalid signature encoding: ${approval.rootId}`);
    const signature = Buffer.from(approval.signatureBase64, "base64");
    requireCondition(signature.length === 64 && verify(null, message, root.publicKey, signature), `invalid signature: ${approval.rootId}`);
    seen.add(approval.rootId);
  }
  requireCondition(seen.size >= trustRoots.registry.threshold, `insufficient independent approvals: ${seen.size}/${trustRoots.registry.threshold}`);
  return seen.size;
}

export async function validate(options) {
  const contractDocument = await jsonDocument(options.contract, "admission contract", false);
  const contract = validateContract(contractDocument.value);
  const supplied = [options.package, options.approvals];
  if (supplied.every((item) => item === undefined)) {
    return { chainId: 700771, status: contract.status, trustRootsPinned: contract.status === "roots-pinned", genesisAdmitted: false, approvalsVerified: 0, threshold: 2, nodeStartPermitted: false, sideEffects: false };
  }
  requireCondition(supplied.every((item) => item !== undefined), "package and approvals must be supplied together");
  requireCondition(contract.status === "roots-pinned", "trust roots must be pinned in the reviewed admission contract before a package can be evaluated");
  const contractDirectory = await realpath(path.dirname(options.contract));
  const rootsPath = path.resolve(contractDirectory, contract.inputArtifacts.trustRoots);
  const resolvedRoots = await realpath(rootsPath).catch((error) => { throw new AdmissionError(`cannot resolve pinned trust roots: ${error.message}`); });
  requireCondition(resolvedRoots === contractDirectory || resolvedRoots.startsWith(`${contractDirectory}${path.sep}`), "pinned trust roots escape the contract directory");
  const rootsDocument = await jsonDocument(rootsPath, "trust root registry");
  requireCondition(rootsDocument.sha256 === contract.inputArtifacts.trustRootsSha256, "trust root registry does not match the reviewed contract pin");
  const roots = validateTrustRoots(rootsDocument.value);
  const verifierPath = path.resolve(contractDirectory, contract.inputArtifacts.identityVerifier);
  const resolvedVerifier = await realpath(verifierPath).catch((error) => { throw new AdmissionError(`cannot resolve pinned identity verifier: ${error.message}`); });
  requireCondition(resolvedVerifier === contractDirectory || resolvedVerifier.startsWith(`${contractDirectory}${path.sep}`), "pinned identity verifier escapes the contract directory");
  const verifierBytes = await regularFile(verifierPath, "identity verifier", 128 * 1024 * 1024);
  requireCondition(sha256(verifierBytes) === contract.inputArtifacts.identityVerifierSha256, "identity verifier does not match the reviewed contract pin");
  const verifier = { bytes: verifierBytes, sourceRevision: contract.inputArtifacts.identityVerifierSourceRevision };
  const packageDocument = await jsonDocument(options.package, "genesis package");
  const genesisPackage = await validatePackage(packageDocument, options.package, verifier);
  const approvalsDocument = await jsonDocument(options.approvals, "approval envelope");
  const approvalsVerified = validateApprovals(approvalsDocument.value, packageDocument.sha256, genesisPackage.artifact.sha256, roots);
  return {
    chainId: 700771,
    status: "externally-approved",
    genesisAdmitted: true,
    packageSha256: packageDocument.sha256,
    genesisSha256: genesisPackage.artifact.sha256,
    genesisStateRoot: genesisPackage.value.genesis.stateRoot,
    genesisBlockHash: genesisPackage.value.genesis.blockHash,
    trustRootsSha256: rootsDocument.sha256,
    identityVerifierSha256: contract.inputArtifacts.identityVerifierSha256,
    identityVerifierSourceRevision: contract.inputArtifacts.identityVerifierSourceRevision,
    approvalsVerified,
    threshold: roots.registry.threshold,
    nodeStartPermitted: false,
    sideEffects: false,
  };
}

function parseArguments(argv) {
  const options = { contract: path.join(ROOT, "deployment/frozen-genesis-admission.json") };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--require-admitted") options.requireAdmitted = true;
    else if (["--contract", "--package", "--approvals"].includes(argument)) {
      requireCondition(index + 1 < argv.length, `${argument} requires a value`);
      const key = { "--contract": "contract", "--package": "package", "--approvals": "approvals" }[argument];
      options[key] = path.resolve(argv[++index]);
    } else throw new AdmissionError(`unknown argument: ${argument}`);
  }
  return options;
}

async function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const report = await validate(options);
    if (options.requireAdmitted && !report.genesisAdmitted) throw new AdmissionError("frozen production genesis is not admitted");
    console.log(JSON.stringify({ ok: true, ...report }));
  } catch (error) {
    console.log(JSON.stringify({ ok: false, error: error.message, sideEffects: false }));
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
