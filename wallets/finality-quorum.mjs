// SPDX-License-Identifier: MIT OR Apache-2.0

import { canonicalBlochL2FinalityPayloadJson } from "./finality-attestation.mjs";

const CONFIG_FORMAT = "bloch-l2-finality-quorum-config-v1";
const PAYLOAD_FORMAT = "bloch-l2-finality-quorum-attestation-v1";
const ENVELOPE_FORMAT = "bloch-l2-finality-quorum-envelope-v1";
const BUNDLE_FORMAT = "bloch-l2-finality-quorum-bundle-v1";
const SIGNING_DOMAIN = "BLOCH-L2-FINALITY-QUORUM-ATTESTATION-v1\0";
const CONFIG_DOMAIN = "BLOCH-L2-FINALITY-QUORUM-CONFIG-v1\0";
const HASH = /^[0-9a-f]{64}$/;
const BASE64URL_KEY = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SIGNER_ID = /^[a-z][a-z0-9-]{0,62}$/;
const PROTOCOL = /^[a-z0-9._:-]{1,128}$/;
const configFields = ["format", "threshold", "signers"];
const signerFields = ["signerId", "publicKeyBase64Url"];
const payloadFields = ["format", "quorumId", "signerId", "identity", "checkpoint", "issuedAt",
  "expiresAt", "finalityProtocol", "finalityReference"];
const envelopeFields = ["format", "quorumId", "signerId", "keyId", "payload", "signature"];
const bundleFields = ["format", "quorumId", "envelopes"];
const encoder = new TextEncoder();

function exactRecord(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(message);
  let keys;
  try { keys = Reflect.ownKeys(value); } catch { throw new TypeError(message); }
  if (keys.length !== fields.length || keys.some(key => typeof key !== "string" || !fields.includes(key))) {
    throw new TypeError(message);
  }
  const copy = Object.create(null);
  for (const field of fields) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, field); } catch { throw new TypeError(message); }
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new TypeError(message);
    copy[field] = descriptor.value;
  }
  return copy;
}

function exactArray(value, maximum, message) {
  if (!Array.isArray(value)) throw new TypeError(message);
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 1 || length > maximum ||
      Reflect.ownKeys(value).some(key => key !== "length" &&
        (!/^(?:0|[1-9][0-9]*)$/.test(String(key)) || Number(key) >= length))) throw new TypeError(message);
  const copy = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new TypeError(message);
    copy.push(descriptor.value);
  }
  return copy;
}

function decodeBase64Url(value, bytes, pattern, message) {
  if (typeof value !== "string" || !pattern.test(value)) throw new TypeError(message);
  let decoded;
  try {
    decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  } catch { throw new TypeError(message); }
  if (decoded.length !== bytes) throw new TypeError(message);
  const canonical = btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== value) throw new TypeError(message);
  const result = new Uint8Array(bytes);
  for (let index = 0; index < bytes; index += 1) result[index] = decoded.charCodeAt(index);
  return result;
}

function hex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function basePayload(payload) {
  const parsed = JSON.parse(canonicalBlochL2FinalityPayloadJson({
    format: "bloch-l2-finality-attestation-v1",
    identity: payload.identity,
    checkpoint: payload.checkpoint,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    finalityProtocol: payload.finalityProtocol,
    finalityReference: payload.finalityReference,
  }));
  parsed.identity = Object.freeze(parsed.identity);
  parsed.checkpoint = Object.freeze(parsed.checkpoint);
  return Object.freeze(parsed);
}

function checkedPayload(value, expected = {}) {
  const payload = exactRecord(value, payloadFields, "Invalid Bloch L2 finality quorum payload");
  if (payload.format !== PAYLOAD_FORMAT || !HASH.test(payload.quorumId) || !SIGNER_ID.test(payload.signerId) ||
      expected.quorumId !== undefined && payload.quorumId !== expected.quorumId ||
      expected.signerId !== undefined && payload.signerId !== expected.signerId) {
    throw new TypeError("Invalid Bloch L2 finality quorum payload");
  }
  const base = basePayload(payload);
  if (expected.finalityProtocol !== undefined && base.finalityProtocol !== expected.finalityProtocol) {
    throw new TypeError("Invalid Bloch L2 finality quorum payload");
  }
  return Object.freeze({ format: PAYLOAD_FORMAT, quorumId: payload.quorumId, signerId: payload.signerId,
    identity: base.identity, checkpoint: base.checkpoint, issuedAt: base.issuedAt, expiresAt: base.expiresAt,
    finalityProtocol: base.finalityProtocol, finalityReference: base.finalityReference });
}

function canonicalPayload(payload) {
  return JSON.stringify({ format: payload.format, quorumId: payload.quorumId, signerId: payload.signerId,
    identity: payload.identity, checkpoint: payload.checkpoint, issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt, finalityProtocol: payload.finalityProtocol,
    finalityReference: payload.finalityReference });
}

/** Validate a public quorum configuration and derive its domain-separated identity. */
export async function canonicalBlochL2FinalityQuorumConfig(value) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto is required for Bloch L2 finality quorum verification");
  const config = exactRecord(value, configFields, "Invalid Bloch L2 finality quorum config");
  const signers = exactArray(config.signers, 32, "Invalid Bloch L2 finality quorum signers");
  if (config.format !== CONFIG_FORMAT || signers.length < 2 || !Number.isSafeInteger(config.threshold) ||
      config.threshold < 2 || config.threshold > signers.length) throw new TypeError("Invalid Bloch L2 finality quorum config");
  const ids = new Set(), keyIds = new Set();
  let prior = null;
  const checked = [];
  for (const value of signers) {
    const signer = exactRecord(value, signerFields, "Invalid Bloch L2 finality quorum signer");
    if (!SIGNER_ID.test(signer.signerId) || prior !== null && signer.signerId <= prior) {
      throw new TypeError("Bloch L2 finality quorum signers must have unique sorted IDs");
    }
    const raw = decodeBase64Url(signer.publicKeyBase64Url, 32, BASE64URL_KEY,
      "Invalid Bloch L2 finality quorum public key");
    const keyId = hex(new Uint8Array(await subtle.digest("SHA-256", raw)));
    if (ids.has(signer.signerId) || keyIds.has(keyId)) throw new TypeError("Bloch L2 finality quorum signers are not independent");
    ids.add(signer.signerId); keyIds.add(keyId); prior = signer.signerId;
    checked.push(Object.freeze({ signerId: signer.signerId, publicKeyBase64Url: signer.publicKeyBase64Url, keyId, raw }));
  }
  const publicConfig = { format: CONFIG_FORMAT, threshold: config.threshold,
    signers: checked.map(({ signerId, publicKeyBase64Url, keyId }) => ({ signerId, publicKeyBase64Url, keyId })) };
  const quorumId = hex(new Uint8Array(await subtle.digest("SHA-256", encoder.encode(CONFIG_DOMAIN + JSON.stringify(publicConfig)))));
  return Object.freeze({ format: CONFIG_FORMAT, threshold: config.threshold,
    signers: Object.freeze(checked), quorumId });
}

export function canonicalBlochL2FinalityQuorumPayloadJson(value) {
  return canonicalPayload(checkedPayload(value));
}

export function blochL2FinalityQuorumSigningBytes(value) {
  return encoder.encode(SIGNING_DOMAIN + canonicalBlochL2FinalityQuorumPayloadJson(value));
}

/** Build a wallet-compatible threshold verifier over independently pinned Ed25519 keys. */
export async function createEd25519FinalityQuorumVerifier({ config, finalityProtocol, getBundle } = {}) {
  if (!PROTOCOL.test(finalityProtocol) || typeof getBundle !== "function") {
    throw new TypeError("Finality quorum verifier configuration is invalid");
  }
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto is required for Bloch L2 finality quorum verification");
  const quorum = await canonicalBlochL2FinalityQuorumConfig(config);
  const byKey = new Map();
  for (const signer of quorum.signers) {
    const key = await subtle.importKey("raw", signer.raw, { name: "Ed25519" }, false, ["verify"]);
    byKey.set(signer.keyId, { signer, key });
  }
  return Object.freeze({ quorumId: quorum.quorumId, threshold: quorum.threshold,
    signerKeyIds: Object.freeze(quorum.signers.map(signer => signer.keyId)),
    async verify(identity, checkpoint) {
      const expected = basePayload({ identity, checkpoint, issuedAt: 0, expiresAt: 1, finalityProtocol,
        finalityReference: `0x${"00".repeat(32)}` });
      const request = Object.freeze({ identity: expected.identity, checkpoint: expected.checkpoint,
        finalityProtocol, quorumId: quorum.quorumId,
        threshold: quorum.threshold });
      const bundle = exactRecord(await getBundle(request), bundleFields, "Invalid Bloch L2 finality quorum bundle");
      if (bundle.format !== BUNDLE_FORMAT || bundle.quorumId !== quorum.quorumId) {
        throw new Error("Bloch L2 finality bundle uses an untrusted quorum");
      }
      const envelopes = exactArray(bundle.envelopes, quorum.signers.length,
        "Invalid Bloch L2 finality quorum envelopes");
      const seen = new Set();
      for (const value of envelopes) {
        const envelope = exactRecord(value, envelopeFields, "Invalid Bloch L2 finality quorum envelope");
        const configured = byKey.get(envelope.keyId);
        if (envelope.format !== ENVELOPE_FORMAT || envelope.quorumId !== quorum.quorumId || !configured ||
            envelope.signerId !== configured.signer.signerId || seen.has(envelope.keyId)) {
          throw new Error("Bloch L2 finality quorum envelope has an untrusted or duplicate signer");
        }
        const payload = checkedPayload(envelope.payload, { quorumId: quorum.quorumId,
          signerId: envelope.signerId, finalityProtocol });
        if (JSON.stringify(payload.identity) !== JSON.stringify(expected.identity) ||
            JSON.stringify(payload.checkpoint) !== JSON.stringify(expected.checkpoint)) {
          throw new Error("Bloch L2 finality quorum attestation does not match the requested checkpoint");
        }
        const now = Math.floor(Date.now() / 1_000);
        if (payload.issuedAt > now + 300 || payload.expiresAt <= now) throw new Error("Bloch L2 finality quorum attestation is not fresh");
        const signature = decodeBase64Url(envelope.signature, 64, BASE64URL_SIGNATURE,
          "Invalid Bloch L2 finality quorum signature");
        if (!await subtle.verify({ name: "Ed25519" }, configured.key, signature,
          blochL2FinalityQuorumSigningBytes(payload))) {
          throw new Error("Bloch L2 finality quorum signature verification failed");
        }
        seen.add(envelope.keyId);
      }
      if (seen.size < quorum.threshold) throw new Error("Bloch L2 finality quorum threshold is not met");
      return true;
    },
  });
}

export const BLOCH_L2_FINALITY_QUORUM_CONFIG_FORMAT = CONFIG_FORMAT;
export const BLOCH_L2_FINALITY_QUORUM_PAYLOAD_FORMAT = PAYLOAD_FORMAT;
export const BLOCH_L2_FINALITY_QUORUM_ENVELOPE_FORMAT = ENVELOPE_FORMAT;
export const BLOCH_L2_FINALITY_QUORUM_BUNDLE_FORMAT = BUNDLE_FORMAT;
