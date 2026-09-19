// SPDX-License-Identifier: MIT OR Apache-2.0

const ATTESTATION_FORMAT = "bloch-l2-finality-attestation-v1";
const ENVELOPE_FORMAT = "bloch-l2-finality-envelope-v1";
const SIGNING_DOMAIN = "BLOCH-L2-FINALITY-ATTESTATION-v1\0";
const MAX_VALIDITY_SECONDS = 15 * 60;
const MAX_CLOCK_SKEW_SECONDS = 5 * 60;
const PROTOCOL = /^[a-z0-9._:-]{1,128}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const identityFields = ["format", "chainId", "domain", "genesisHash", "headerFormat"];
const checkpointFields = ["format", "headNumber", "headHash", "stateRoot"];
const payloadFields = [
  "format", "identity", "checkpoint", "issuedAt", "expiresAt", "finalityProtocol", "finalityReference",
];
const envelopeFields = ["format", "keyId", "payload", "signature"];
const ownKeys = Reflect.ownKeys;
const descriptor = Object.getOwnPropertyDescriptor;
const encoder = new TextEncoder();

function exactRecord(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(message);
  const keys = ownKeys(value);
  if (keys.length !== fields.length || keys.some(key => typeof key !== "string" || !fields.includes(key))) {
    throw new TypeError(message);
  }
  const result = Object.create(null);
  for (const field of fields) {
    const fieldDescriptor = descriptor(value, field);
    if (!fieldDescriptor || !("value" in fieldDescriptor)) throw new TypeError(message);
    result[field] = fieldDescriptor.value;
  }
  return result;
}

function checkedIdentity(value) {
  const identity = exactRecord(value, identityFields, "Invalid finality attestation identity");
  if (identity.format !== "bloch-chain-identity-v1" ||
      typeof identity.chainId !== "string" || identity.chainId.length > 66 ||
      !QUANTITY.test(identity.chainId) || BigInt(identity.chainId) >= (1n << 256n) ||
      !HASH.test(identity.domain) || !HASH.test(identity.genesisHash) ||
      identity.headerFormat !== "bloch-node-header-v2-fixed-width") {
    throw new TypeError("Invalid finality attestation identity");
  }
  return Object.freeze(identity);
}

function checkedCheckpoint(value) {
  const checkpoint = exactRecord(value, checkpointFields, "Invalid finality attestation checkpoint");
  if (checkpoint.format !== "bloch-wallet-checkpoint-v1" ||
      typeof checkpoint.headNumber !== "string" || checkpoint.headNumber.length > 18 ||
      !QUANTITY.test(checkpoint.headNumber) || BigInt(checkpoint.headNumber) > 0xffffffffffffffffn ||
      !HASH.test(checkpoint.headHash) || !HASH.test(checkpoint.stateRoot)) {
    throw new TypeError("Invalid finality attestation checkpoint");
  }
  return Object.freeze(checkpoint);
}

function checkedPayload(value, expectedProtocol) {
  const payload = exactRecord(value, payloadFields, "Invalid Bloch L2 finality attestation");
  payload.identity = checkedIdentity(payload.identity);
  payload.checkpoint = checkedCheckpoint(payload.checkpoint);
  if (payload.format !== ATTESTATION_FORMAT || !Number.isSafeInteger(payload.issuedAt) ||
      !Number.isSafeInteger(payload.expiresAt) || payload.expiresAt <= payload.issuedAt ||
      payload.expiresAt - payload.issuedAt > MAX_VALIDITY_SECONDS ||
      typeof payload.finalityProtocol !== "string" || !PROTOCOL.test(payload.finalityProtocol) ||
      (expectedProtocol !== undefined && payload.finalityProtocol !== expectedProtocol) ||
      !HASH.test(payload.finalityReference)) {
    throw new TypeError("Invalid Bloch L2 finality attestation");
  }
  return Object.freeze(payload);
}

function canonicalPayload(payload) {
  return JSON.stringify({
    format: payload.format,
    identity: {
      format: payload.identity.format,
      chainId: payload.identity.chainId,
      domain: payload.identity.domain,
      genesisHash: payload.identity.genesisHash,
      headerFormat: payload.identity.headerFormat,
    },
    checkpoint: {
      format: payload.checkpoint.format,
      headNumber: payload.checkpoint.headNumber,
      headHash: payload.checkpoint.headHash,
      stateRoot: payload.checkpoint.stateRoot,
    },
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    finalityProtocol: payload.finalityProtocol,
    finalityReference: payload.finalityReference,
  });
}

function decodeBase64Url(value, bytes, message) {
  if (typeof value !== "string" || !BASE64URL.test(value) || value.includes("=") ||
      value.length !== Math.ceil(bytes * 4 / 3)) throw new TypeError(message);
  let decoded;
  try {
    decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  } catch {
    throw new TypeError(message);
  }
  if (decoded.length !== bytes) throw new TypeError(message);
  const canonical = btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== value) throw new TypeError(message);
  const result = new Uint8Array(bytes);
  for (let index = 0; index < bytes; index += 1) result[index] = decoded.charCodeAt(index);
  return result;
}

function equalsExpected(actual, expected, fields) {
  return fields.every(field => actual[field] === expected[field]);
}

/** Canonical, domain-separated bytes used by an offline Ed25519 attestor. */
export function blochL2FinalitySigningBytes(value) {
  const payload = checkedPayload(value);
  return encoder.encode(SIGNING_DOMAIN + canonicalPayload(payload));
}

/** Canonical JSON retained inside signed envelopes and audit archives. */
export function canonicalBlochL2FinalityPayloadJson(value) {
  return canonicalPayload(checkedPayload(value));
}

/**
 * Build the trusted boundary consumed by `createBlochL2Wallet`.
 * `getAttestation` may use any transport, but the returned object is untrusted
 * until its exact payload and Ed25519 signature pass verification here.
 */
export async function createEd25519FinalityVerifier({
  publicKeyBase64Url,
  finalityProtocol,
  getAttestation,
} = {}) {
  if (!PROTOCOL.test(finalityProtocol) || typeof getAttestation !== "function") {
    throw new TypeError("Finality verifier configuration is invalid");
  }
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto is required for Bloch L2 finality verification");
  const rawKey = decodeBase64Url(publicKeyBase64Url, 32, "Invalid Ed25519 finality public key");
  const digest = new Uint8Array(await subtle.digest("SHA-256", rawKey));
  const keyId = Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
  const key = await subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, ["verify"]);

  return Object.freeze({
    keyId,
    async verify(identityValue, checkpointValue) {
      const identity = checkedIdentity(identityValue);
      const checkpoint = checkedCheckpoint(checkpointValue);
      const request = Object.freeze({ identity, checkpoint, finalityProtocol, keyId });
      const envelope = exactRecord(
        await getAttestation(request),
        envelopeFields,
        "Invalid Bloch L2 finality envelope",
      );
      if (envelope.format !== ENVELOPE_FORMAT || envelope.keyId !== keyId) {
        throw new Error("Bloch L2 finality envelope uses an untrusted key");
      }
      const payload = checkedPayload(envelope.payload, finalityProtocol);
      if (!equalsExpected(payload.identity, identity, identityFields) ||
          !equalsExpected(payload.checkpoint, checkpoint, checkpointFields)) {
        throw new Error("Bloch L2 finality attestation does not match the requested checkpoint");
      }
      const now = Math.floor(Date.now() / 1_000);
      if (payload.issuedAt > now + MAX_CLOCK_SKEW_SECONDS || payload.expiresAt <= now) {
        throw new Error("Bloch L2 finality attestation is not fresh");
      }
      const signature = decodeBase64Url(envelope.signature, 64, "Invalid Ed25519 finality signature");
      if (!await subtle.verify({ name: "Ed25519" }, key, signature, blochL2FinalitySigningBytes(payload))) {
        throw new Error("Bloch L2 finality signature verification failed");
      }
      return true;
    },
  });
}

export const BLOCH_L2_FINALITY_ATTESTATION_FORMAT = ATTESTATION_FORMAT;
export const BLOCH_L2_FINALITY_ENVELOPE_FORMAT = ENVELOPE_FORMAT;
