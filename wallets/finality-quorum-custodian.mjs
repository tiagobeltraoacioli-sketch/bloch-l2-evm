// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const BLOCH_L2_FINALITY_CUSTODIAN_FORMAT = "bloch-l2-finality-custodian-v1";
export const BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES = 4096;

const DOMAIN = "BLOCH-L2-FINALITY-CUSTODIAN-AUTH-v1\0";
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[a-z][a-z0-9-]{0,62}$/;
const U64 = /^(?:0|[1-9][0-9]{0,19})$/;
const SESSION = /^[A-Za-z0-9_-]{43}$/;

function exact(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) throw new Error(message);
  return value;
}

function stateHash(value, nullable, message) {
  if (value === null && nullable) return null;
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(message);
  return value;
}

function sessionNonce(value) {
  if (typeof value !== "string" || !SESSION.test(value)) throw new Error("Finality custodian session is invalid");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.equals(Buffer.alloc(32)) || bytes.toString("base64url") !== value) {
    throw new Error("Finality custodian session is invalid");
  }
  return value;
}

function sequence(value) {
  if (typeof value !== "string" || !U64.test(value) || BigInt(value) > 0xffffffffffffffffn) {
    throw new Error("Finality custodian sequence is invalid");
  }
  return value;
}

function authentication(value) {
  const config = exact(value, ["key", "clientId", "custodianId"],
    "Finality custodian authentication is invalid");
  if (!(config.key instanceof Uint8Array) || config.key.byteLength !== 32 ||
      Buffer.from(config.key).equals(Buffer.alloc(32)) || !ID.test(config.clientId) ||
      !ID.test(config.custodianId) || config.clientId === config.custodianId) {
    throw new Error("Finality custodian authentication is invalid");
  }
  return { key: Buffer.from(config.key), clientId: config.clientId, custodianId: config.custodianId };
}

function mac(key, body) {
  return createHmac("sha256", key).update(DOMAIN).update(JSON.stringify(body)).digest("base64url");
}

function authenticated(body, key) {
  return { ...body, mac: mac(key, body) };
}

function verifyMac(value, body, key) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error("Finality custodian authentication failed");
  }
  const actual = Buffer.from(value, "base64url"), expected = Buffer.from(mac(key, body), "base64url");
  if (actual.length !== 32 || actual.toString("base64url") !== value || !timingSafeEqual(actual, expected)) {
    throw new Error("Finality custodian authentication failed");
  }
}

function encode(value) {
  const encoded = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  if (encoded.length > BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES) {
    throw new Error("Finality custodian frame exceeds its size limit");
  }
  return encoded;
}

function decode(encoded) {
  if (!(encoded instanceof Uint8Array) || encoded.byteLength < 2 ||
      encoded.byteLength > BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES) {
    throw new Error("Finality custodian frame has an invalid size");
  }
  const text = Buffer.from(encoded).toString("utf8");
  let parsed;
  try { parsed = JSON.parse(text); } catch (cause) {
    throw new Error("Finality custodian frame is not valid JSON", { cause });
  }
  if (`${JSON.stringify(parsed)}\n` !== text) throw new Error("Finality custodian frame is not canonical");
  return parsed;
}

function requestBody({ clientId, custodianId, session, sequence: requestSequence, operation,
  expectedStateHash, nextStateHash }) {
  return { format: BLOCH_L2_FINALITY_CUSTODIAN_FORMAT, direction: "request", clientId, custodianId,
    session, sequence: requestSequence, operation, expectedStateHash, nextStateHash };
}

function checkedRequest(value, auth) {
  const frame = exact(value, ["format", "direction", "clientId", "custodianId", "session", "sequence",
    "operation", "expectedStateHash", "nextStateHash", "mac"], "Finality custodian request is invalid");
  if (frame.format !== BLOCH_L2_FINALITY_CUSTODIAN_FORMAT || frame.direction !== "request" ||
      frame.clientId !== auth.clientId || frame.custodianId !== auth.custodianId ||
      !["load", "compare-and-swap"].includes(frame.operation)) {
    throw new Error("Finality custodian request is invalid");
  }
  sessionNonce(frame.session); sequence(frame.sequence);
  if (frame.operation === "load") {
    if (frame.expectedStateHash !== null || frame.nextStateHash !== null) {
      throw new Error("Finality custodian load request is invalid");
    }
  } else {
    stateHash(frame.expectedStateHash, true, "Finality custodian CAS request is invalid");
    stateHash(frame.nextStateHash, false, "Finality custodian CAS request is invalid");
    if (frame.expectedStateHash === frame.nextStateHash) throw new Error("Finality custodian CAS is not an advance");
  }
  const body = requestBody(frame);
  verifyMac(frame.mac, body, auth.key);
  return Object.freeze(body);
}

function requestHash(body) {
  return createHash("sha256").update("BLOCH-L2-FINALITY-CUSTODIAN-REQUEST-v1\0")
    .update(JSON.stringify(body)).digest("hex");
}

function responseBody(request, status, currentStateHash) {
  return { format: BLOCH_L2_FINALITY_CUSTODIAN_FORMAT, direction: "response",
    clientId: request.clientId, custodianId: request.custodianId, session: request.session,
    sequence: request.sequence, operation: request.operation, requestHash: requestHash(request),
    status, currentStateHash };
}

function checkedResponse(value, request, auth) {
  const frame = exact(value, ["format", "direction", "clientId", "custodianId", "session", "sequence",
    "operation", "requestHash", "status", "currentStateHash", "mac"],
  "Finality custodian response is invalid");
  const body = responseBody(request, frame.status, frame.currentStateHash);
  if (frame.format !== body.format || frame.direction !== body.direction || frame.clientId !== body.clientId ||
      frame.custodianId !== body.custodianId || frame.session !== body.session || frame.sequence !== body.sequence ||
      frame.operation !== body.operation || frame.requestHash !== body.requestHash ||
      !["current", "committed", "conflict", "uncertain"].includes(frame.status)) {
    throw new Error("Finality custodian response does not match its request");
  }
  const current = stateHash(frame.currentStateHash, true, "Finality custodian response state is invalid");
  if (request.operation === "load" && frame.status !== "current" ||
      request.operation === "compare-and-swap" && frame.status === "current" ||
      frame.status === "committed" && current !== request.nextStateHash) {
    throw new Error("Finality custodian response status is invalid");
  }
  verifyMac(frame.mac, body, auth.key);
  return Object.freeze({ status: frame.status, currentStateHash: current });
}

function checkedCheckpoint(value) {
  const checkpoint = exact(value, ["session", "nextSequence"], "Finality custodian checkpoint is invalid");
  sessionNonce(checkpoint.session); sequence(checkpoint.nextSequence);
  return checkpoint;
}

export class AuthenticatedFinalityQuorumCustodian {
  #auth; #transport; #lifecycle; #session; #nextSequence; #closed = false; #busy = false;

  constructor({ authentication: configured, transport, checkpoint, lifecycle = null } = {}) {
    this.#auth = authentication(configured);
    if (!transport || typeof transport !== "object" || typeof transport.exchange !== "function") {
      this.#auth.key.fill(0);
      throw new Error("Finality custodian transport is invalid");
    }
    if (lifecycle !== null && (!lifecycle || typeof lifecycle !== "object" ||
        typeof lifecycle.begin !== "function" || typeof lifecycle.complete !== "function")) {
      this.#auth.key.fill(0);
      throw new Error("Finality custodian lifecycle is invalid");
    }
    let retained;
    try { retained = checkedCheckpoint(checkpoint); }
    catch (error) { this.#auth.key.fill(0); throw error; }
    this.#transport = transport;
    this.#lifecycle = lifecycle;
    this.#session = retained.session;
    this.#nextSequence = BigInt(retained.nextSequence);
  }

  checkpoint() {
    return Object.freeze({ session: this.#session, nextSequence: this.#nextSequence.toString() });
  }

  close() { if (!this.#closed) { this.#auth.key.fill(0); this.#closed = true; } }

  async #exchange(operation, expectedStateHash, nextStateHash) {
    if (this.#closed) throw new Error("Finality custodian client is closed");
    if (this.#busy) throw new Error("Finality custodian client already has an exchange in progress");
    if (this.#nextSequence === 0xffffffffffffffffn) throw new Error("Finality custodian sequence exhausted");
    this.#busy = true;
    try {
      const body = requestBody({ clientId: this.#auth.clientId, custodianId: this.#auth.custodianId,
        session: this.#session, sequence: this.#nextSequence.toString(), operation,
        expectedStateHash, nextStateHash });
      const encoded = encode(authenticated(body, this.#auth.key));
      const digest = requestHash(body);
      this.#nextSequence += 1n;
      await this.#lifecycle?.begin(Object.freeze({ requestHash: digest, operation,
        checkpoint: this.checkpoint() }));
      const response = checkedResponse(decode(await this.#transport.exchange(encoded)), body, this.#auth);
      await this.#lifecycle?.complete(Object.freeze({ requestHash: digest, operation,
        checkpoint: this.checkpoint(), response }));
      return response;
    } finally {
      this.#busy = false;
    }
  }

  async load() {
    const response = await this.#exchange("load", null, null);
    if (response.status !== "current") throw new Error("Finality custodian load response is invalid");
    return response.currentStateHash;
  }

  async compareAndSwap(expectedStateHash, nextStateHash) {
    stateHash(expectedStateHash, true, "Finality custodian CAS input is invalid");
    stateHash(nextStateHash, false, "Finality custodian CAS input is invalid");
    if (expectedStateHash === nextStateHash) throw new Error("Finality custodian CAS is not an advance");
    const response = await this.#exchange("compare-and-swap", expectedStateHash, nextStateHash);
    if (response.status === "committed") return Object.freeze({ status: "committed" });
    if (response.status === "conflict") return Object.freeze({ status: "conflict",
      currentStateHash: response.currentStateHash });
    if (response.status === "uncertain") return Object.freeze({ status: "uncertain" });
    throw new Error("Finality custodian CAS response is invalid");
  }
}

export class AuthenticatedFinalityQuorumCustodianServer {
  #auth; #store; #closed = false;

  constructor({ authentication: configured, store } = {}) {
    this.#auth = authentication(configured);
    if (!store || typeof store !== "object" || typeof store.load !== "function" ||
        typeof store.compareAndSwap !== "function") {
      this.#auth.key.fill(0);
      throw new Error("Finality custodian store is invalid");
    }
    this.#store = store;
  }

  close() { if (!this.#closed) { this.#auth.key.fill(0); this.#closed = true; } }

  async handle(encoded) {
    if (this.#closed) throw new Error("Finality custodian server is closed");
    const request = checkedRequest(decode(encoded), this.#auth);
    let status, current;
    if (request.operation === "load") {
      current = stateHash(await this.#store.load(), true, "Finality custodian retained state is invalid");
      status = "current";
    } else {
      current = stateHash(await this.#store.load(), true, "Finality custodian retained state is invalid");
      if (current === request.nextStateHash) {
        status = "committed";
      } else if (current !== request.expectedStateHash) {
        status = "conflict";
      } else {
        const outcome = await this.#store.compareAndSwap(request.expectedStateHash, request.nextStateHash);
        if (outcome?.status === "conflict") {
          exact(outcome, ["status", "currentStateHash"], "Finality custodian store outcome is invalid");
          current = stateHash(outcome.currentStateHash, true, "Finality custodian store outcome is invalid");
          status = "conflict";
        } else {
          exact(outcome, ["status"], "Finality custodian store outcome is invalid");
          if (!["committed", "uncertain"].includes(outcome.status)) {
            throw new Error("Finality custodian store outcome is invalid");
          }
          status = outcome.status;
        }
        if (status === "committed") {
          current = stateHash(await this.#store.load(), true, "Finality custodian retained state is invalid");
          if (current !== request.nextStateHash) throw new Error("Finality custodian commit readback failed");
        }
      }
    }
    return encode(authenticated(responseBody(request, status, current), this.#auth.key));
  }
}
