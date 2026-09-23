#!/usr/bin/env node
/** Offline create-once ceremony tooling. Never generates or reads private keys. */

import { verify } from "node:crypto";
import { constants as FS, lstat, mkdir, open, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  AdmissionError, canonicalBytes, executePinnedVerifier, jsonDocument,
  regularFile, sha256, validateContract, validateTrustRoots,
} from "./check-frozen-genesis-admission.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HASH = /^0x[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const DOMAIN = Buffer.from("BLOCH-L2-FROZEN-GENESIS-V1\0", "ascii");

function requireCondition(condition, message) {
  if (!condition) throw new AdmissionError(message);
}

function exactObject(value, fields, label) {
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  requireCondition(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort()), `${label} has unexpected or missing fields`);
  return value;
}

async function secureDirectory(directory, label) {
  const metadata = await lstat(directory).catch((error) => { throw new AdmissionError(`cannot stat ${label}: ${error.message}`); });
  requireCondition(metadata.isDirectory() && !metadata.isSymbolicLink(), `${label} must be a non-symlink directory`);
  requireCondition((metadata.mode & 0o022) === 0, `${label} must not be group/world writable`);
}

async function syncDirectory(directory, label) {
  let handle;
  try {
    handle = await open(directory, FS.O_RDONLY | FS.O_DIRECTORY | FS.O_NOFOLLOW);
    await handle.sync();
  } catch (error) {
    throw new AdmissionError(`cannot durably publish ${label}: ${error.message}`);
  } finally {
    await handle?.close();
  }
}

export async function writeOnce(file, bytes, mode = 0o600) {
  const parent = path.dirname(file);
  await secureDirectory(parent, "output directory");
  let handle;
  try {
    handle = await open(file, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | FS.O_NOFOLLOW, mode);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    if (error?.code === "EEXIST") throw new AdmissionError(`refusing to overwrite existing output: ${file}`);
    if (error instanceof AdmissionError) throw error;
    throw new AdmissionError(`cannot create output ${file}: ${error.message}`);
  } finally {
    await handle?.close();
  }
  await syncDirectory(parent, "create-once output");
}

async function containedFile(directory, relative, label) {
  requireCondition(typeof relative === "string" && relative.length > 0 && !path.isAbsolute(relative) && !relative.split(/[\\/]/).includes(".."), `${label} path must be relative and contained`);
  const base = await realpath(directory);
  const candidate = path.resolve(base, relative);
  const resolved = await realpath(candidate).catch((error) => { throw new AdmissionError(`cannot resolve ${label}: ${error.message}`); });
  requireCondition(resolved === base || resolved.startsWith(`${base}${path.sep}`), `${label} escapes its trusted directory`);
  return candidate;
}

export async function loadPinnedContext(contractPath) {
  const contractDocument = await jsonDocument(contractPath, "admission contract", false);
  const contract = validateContract(contractDocument.value);
  requireCondition(contract.status === "roots-pinned", "ceremony requires a prior reviewed roots-pinned contract");
  const directory = path.dirname(contractPath);
  const rootsPath = await containedFile(directory, contract.inputArtifacts.trustRoots, "trust roots");
  const rootsDocument = await jsonDocument(rootsPath, "trust root registry");
  requireCondition(rootsDocument.sha256 === contract.inputArtifacts.trustRootsSha256, "trust roots do not match the reviewed contract pin");
  const roots = validateTrustRoots(rootsDocument.value);
  const verifierPath = await containedFile(directory, contract.inputArtifacts.identityVerifier, "identity verifier");
  const verifierBytes = await regularFile(verifierPath, "identity verifier", 128 * 1024 * 1024);
  requireCondition(sha256(verifierBytes) === contract.inputArtifacts.identityVerifierSha256, "identity verifier does not match the reviewed contract pin");
  return {
    contract, roots, verifier: {
      bytes: verifierBytes,
      sha256: contract.inputArtifacts.identityVerifierSha256,
      sourceRevision: contract.inputArtifacts.identityVerifierSourceRevision,
    },
  };
}

export async function createTemplate(output) {
  const template = {
    chainId: 700771,
    domain: null,
    executionProfile: "bloch-l2-cancun-zero-issuance-v1",
    schema: "bloch.l2.frozen-genesis-template.v1",
    timestamp: null,
  };
  await writeOnce(output, canonicalBytes(template));
  return { output, identityAssigned: false, privateKeysHandled: false };
}

export async function freezeTemplate(templatePath, domain, timestamp, output) {
  const document = await jsonDocument(templatePath, "frozen genesis template");
  const template = exactObject(document.value, ["chainId", "domain", "executionProfile", "schema", "timestamp"], "frozen genesis template");
  requireCondition(template.schema === "bloch.l2.frozen-genesis-template.v1" && template.chainId === 700771 && template.executionProfile === "bloch-l2-cancun-zero-issuance-v1", "template profile changed");
  requireCondition(template.domain === null && template.timestamp === null, "template must remain identity-free");
  requireCondition(HASH.test(domain) && !/^0x0+$/.test(domain), "--domain must be a nonzero lowercase 32-byte hash");
  requireCondition(Number.isSafeInteger(timestamp) && timestamp > 0, "--timestamp must be a positive safe integer");
  const artifact = { chainId: 700771, domain, executionProfile: template.executionProfile, schema: "bloch.l2.frozen-genesis.v1", timestamp };
  await writeOnce(output, canonicalBytes(artifact));
  return { output, domain, timestamp, privateKeysHandled: false };
}

async function deriveArtifact(context, artifactPath) {
  const document = await jsonDocument(artifactPath, "frozen genesis artifact");
  const artifact = exactObject(document.value, ["chainId", "domain", "executionProfile", "schema", "timestamp"], "frozen genesis artifact");
  requireCondition(artifact.schema === "bloch.l2.frozen-genesis.v1" && artifact.chainId === 700771 && artifact.executionProfile === "bloch-l2-cancun-zero-issuance-v1", "frozen genesis artifact profile changed");
  const result = await executePinnedVerifier(context.verifier.bytes, artifactPath);
  requireCondition(!result.error && result.status === 0, `pinned verifier rejected frozen genesis: ${result.error?.message || result.stderr?.trim()}`);
  let derived;
  try { derived = JSON.parse(result.stdout); }
  catch (error) { throw new AdmissionError(`pinned verifier returned invalid JSON: ${error.message}`); }
  exactObject(derived, ["blockHash", "buildSourceRevision", "chainId", "domain", "executionProfile", "stateRoot", "timestamp"], "derived identity");
  requireCondition(derived.buildSourceRevision === context.verifier.sourceRevision, "pinned verifier reported a different source revision");
  requireCondition(derived.chainId === artifact.chainId && derived.domain === artifact.domain && derived.executionProfile === artifact.executionProfile && derived.timestamp === artifact.timestamp, "derived identity does not bind the frozen artifact");
  requireCondition(HASH.test(derived.stateRoot) && HASH.test(derived.blockHash), "pinned verifier returned malformed roots");
  return { artifact: document, derived };
}

export async function derivePackage(contractPath, artifactPath, ceremonyId, decisionId, output) {
  requireCondition(ID.test(ceremonyId) && ID.test(decisionId), "ceremony and decision ids must use lowercase stable identifiers");
  const outputDirectory = await realpath(path.dirname(output));
  const resolvedArtifact = await realpath(artifactPath);
  requireCondition(resolvedArtifact.startsWith(`${outputDirectory}${path.sep}`), "frozen genesis artifact must be inside the package output directory");
  const relative = path.relative(outputDirectory, resolvedArtifact);
  requireCondition(relative && !relative.split(path.sep).includes(".."), "frozen genesis artifact path is not package-contained");
  const context = await loadPinnedContext(contractPath);
  const { artifact, derived } = await deriveArtifact(context, artifactPath);
  const genesisPackage = {
    ceremonyId,
    chainId: 700771,
    classification: "externally-reviewed-production-candidate",
    decisionId,
    genesis: { blockHash: derived.blockHash, path: relative.split(path.sep).join("/"), sha256: artifact.sha256, stateRoot: derived.stateRoot },
    network: "bloch-l2-testnet",
    schema: "bloch.l2.frozen-genesis-package.v1",
  };
  await writeOnce(output, canonicalBytes(genesisPackage));
  return { output, packageSha256: sha256(canonicalBytes(genesisPackage)), genesisSha256: artifact.sha256, derivedIdentityVerified: true, nodeStartPermitted: false };
}

async function verifiedPackage(context, packagePath) {
  const document = await jsonDocument(packagePath, "genesis package");
  const value = exactObject(document.value, ["schema", "network", "chainId", "classification", "ceremonyId", "decisionId", "genesis"], "genesis package");
  requireCondition(value.schema === "bloch.l2.frozen-genesis-package.v1" && value.network === "bloch-l2-testnet" && value.chainId === 700771 && value.classification === "externally-reviewed-production-candidate", "genesis package profile changed");
  const descriptor = exactObject(value.genesis, ["path", "sha256", "stateRoot", "blockHash"], "genesis descriptor");
  requireCondition(HEX64.test(descriptor.sha256), "genesis descriptor sha256 is invalid");
  const artifactPath = await containedFile(path.dirname(packagePath), descriptor.path, "genesis artifact");
  const { artifact, derived } = await deriveArtifact(context, artifactPath);
  requireCondition(artifact.sha256 === descriptor.sha256, "genesis artifact digest mismatch");
  requireCondition(derived.stateRoot === descriptor.stateRoot && derived.blockHash === descriptor.blockHash, "package identity differs from pinned verifier derivation");
  return { document, value, descriptor, artifact, derived };
}

export async function createSignatureRequests(contractPath, packagePath, outputDirectory) {
  const context = await loadPinnedContext(contractPath);
  const checked = await verifiedPackage(context, packagePath);
  await mkdir(outputDirectory, { mode: 0o700 });
  await syncDirectory(path.dirname(outputDirectory), "request directory");
  await secureDirectory(outputDirectory, "request output directory");
  const payload = Buffer.concat([DOMAIN, Buffer.from(checked.document.sha256, "hex")]);
  const outputs = [];
  for (const root of context.roots.registry.roots) {
    const request = {
      chainId: 700771,
      decision: "approve-frozen-production-genesis",
      genesisSha256: checked.artifact.sha256,
      network: "bloch-l2-testnet",
      organizationId: root.organizationId,
      packageSha256: checked.document.sha256,
      payloadSha256: sha256(payload),
      rootId: root.rootId,
      schema: "bloch.l2.frozen-genesis-signature-request.v1",
      signingPayloadBase64: payload.toString("base64"),
    };
    const requestPath = path.join(outputDirectory, `${root.rootId}.request.json`);
    const payloadPath = path.join(outputDirectory, `${root.rootId}.payload.bin`);
    await writeOnce(requestPath, canonicalBytes(request));
    await writeOnce(payloadPath, payload);
    outputs.push({ rootId: root.rootId, request: requestPath, payload: payloadPath });
  }
  return { outputs, requestsCreated: outputs.length, threshold: context.roots.registry.threshold, privateKeysHandled: false, nodeStartPermitted: false };
}

function validateRequest(value) {
  const request = exactObject(value, ["schema", "network", "chainId", "decision", "genesisSha256", "packageSha256", "payloadSha256", "signingPayloadBase64", "rootId", "organizationId"], "signature request");
  requireCondition(request.schema === "bloch.l2.frozen-genesis-signature-request.v1" && request.network === "bloch-l2-testnet" && request.chainId === 700771 && request.decision === "approve-frozen-production-genesis", "signature request profile changed");
  requireCondition(HEX64.test(request.genesisSha256) && HEX64.test(request.packageSha256) && HEX64.test(request.payloadSha256), "signature request digest is invalid");
  const payload = Buffer.from(request.signingPayloadBase64, "base64");
  requireCondition(payload.equals(Buffer.concat([DOMAIN, Buffer.from(request.packageSha256, "hex")])) && sha256(payload) === request.payloadSha256, "signature request payload is inconsistent");
  return { request, payload };
}

export async function wrapResponse(contractPath, requestPath, signaturePath, output) {
  const context = await loadPinnedContext(contractPath);
  const requestDocument = await jsonDocument(requestPath, "signature request");
  const { request, payload } = validateRequest(requestDocument.value);
  const root = context.roots.roots.get(request.rootId);
  requireCondition(root && root.organizationId === request.organizationId, "signature request signer is not a pinned trust root");
  const signature = await regularFile(signaturePath, "detached Ed25519 signature", 1024);
  requireCondition(signature.length === 64 && verify(null, payload, root.publicKey, signature), "detached signature is invalid for the requested root");
  const response = {
    chainId: 700771,
    genesisSha256: request.genesisSha256,
    network: "bloch-l2-testnet",
    organizationId: request.organizationId,
    packageSha256: request.packageSha256,
    rootId: request.rootId,
    schema: "bloch.l2.frozen-genesis-signature-response.v1",
    signatureBase64: signature.toString("base64"),
  };
  await writeOnce(output, canonicalBytes(response));
  return { output, rootId: request.rootId, signatureVerified: true, privateKeysHandled: false, nodeStartPermitted: false };
}

export async function assembleApprovals(contractPath, packagePath, responsePaths, output) {
  const context = await loadPinnedContext(contractPath);
  const checked = await verifiedPackage(context, packagePath);
  const payload = Buffer.concat([DOMAIN, Buffer.from(checked.document.sha256, "hex")]);
  const approvals = [];
  const seen = new Set();
  for (const responsePath of responsePaths) {
    const document = await jsonDocument(responsePath, "signature response");
    const response = exactObject(document.value, ["schema", "network", "chainId", "genesisSha256", "packageSha256", "rootId", "organizationId", "signatureBase64"], "signature response");
    requireCondition(response.schema === "bloch.l2.frozen-genesis-signature-response.v1" && response.network === "bloch-l2-testnet" && response.chainId === 700771, "signature response profile changed");
    requireCondition(response.packageSha256 === checked.document.sha256 && response.genesisSha256 === checked.artifact.sha256, "signature response targets another package");
    const root = context.roots.roots.get(response.rootId);
    requireCondition(root && root.organizationId === response.organizationId && !seen.has(response.rootId), "signature response signer is unknown, mismatched or duplicated");
    const signature = Buffer.from(response.signatureBase64, "base64");
    requireCondition(signature.length === 64 && verify(null, payload, root.publicKey, signature), `invalid response signature: ${response.rootId}`);
    seen.add(response.rootId);
    approvals.push({ organizationId: response.organizationId, rootId: response.rootId, signatureBase64: response.signatureBase64 });
  }
  requireCondition(seen.size >= context.roots.registry.threshold, `insufficient detached responses: ${seen.size}/${context.roots.registry.threshold}`);
  approvals.sort((left, right) => left.rootId.localeCompare(right.rootId));
  const envelope = {
    approvals,
    chainId: 700771,
    decision: "approve-frozen-production-genesis",
    genesisSha256: checked.artifact.sha256,
    network: "bloch-l2-testnet",
    packageSha256: checked.document.sha256,
    schema: "bloch.l2.frozen-genesis-approvals.v1",
  };
  await writeOnce(output, canonicalBytes(envelope));
  return { output, approvalsVerified: approvals.length, threshold: context.roots.registry.threshold, genesisAdmitted: true, nodeStartPermitted: false, privateKeysHandled: false };
}

function argumentsFor(argv) {
  requireCondition(argv.length > 0, "a ceremony command is required");
  const command = argv[0];
  const options = {};
  for (let index = 1; index < argv.length; index += 1) {
    const name = argv[index];
    requireCondition(name.startsWith("--") && index + 1 < argv.length, `invalid argument: ${name}`);
    const key = name.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (key === "response") (options.responses ||= []).push(path.resolve(argv[++index]));
    else options[key] = argv[++index];
  }
  return { command, options };
}

async function main() {
  try {
    const { command, options } = argumentsFor(process.argv.slice(2));
    const contract = path.resolve(options.contract || path.join(ROOT, "deployment/frozen-genesis-admission.json"));
    let report;
    if (command === "template") report = await createTemplate(path.resolve(options.out));
    else if (command === "freeze") report = await freezeTemplate(path.resolve(options.template), options.domain, Number(options.timestamp), path.resolve(options.out));
    else if (command === "derive") report = await derivePackage(contract, path.resolve(options.genesis), options.ceremonyId, options.decisionId, path.resolve(options.out));
    else if (command === "requests") report = await createSignatureRequests(contract, path.resolve(options.package), path.resolve(options.outDir));
    else if (command === "respond") report = await wrapResponse(contract, path.resolve(options.request), path.resolve(options.signature), path.resolve(options.out));
    else if (command === "assemble") report = await assembleApprovals(contract, path.resolve(options.package), options.responses || [], path.resolve(options.out));
    else throw new AdmissionError(`unknown ceremony command: ${command}`);
    console.log(JSON.stringify({ ok: true, command, ...report }));
  } catch (error) {
    console.log(JSON.stringify({ ok: false, error: error.message, sideEffectsAuthorized: false }));
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
