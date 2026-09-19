// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  AuthenticatedFinalityQuorumCustodian,
  AuthenticatedFinalityQuorumCustodianServer,
} from "./finality-quorum-custodian.mjs";
import {
  createMtlsFinalityCustodianServer,
  createMtlsFinalityCustodianTransport,
  FinalityCustodianTransportUncertainError,
} from "./finality-quorum-custodian-mtls.mjs";

const execute = promisify(execFile);
const HASH_A = "a".repeat(64);

function authentication(byte = 0x41) {
  return { key: new Uint8Array(32).fill(byte), clientId: "wallet-finality",
    custodianId: "independent-finality" };
}

function checkpoint() {
  return { session: Buffer.alloc(32, 0x71).toString("base64url"), nextSequence: "0" };
}

function memoryStore() {
  let current = null, casCalls = 0;
  return { get current() { return current; }, get casCalls() { return casCalls; },
    async load() { return current; },
    async compareAndSwap(expected, replacement) {
      casCalls += 1;
      if (current !== expected) return { status: "conflict", currentStateHash: current };
      current = replacement;
      return { status: "committed" };
    } };
}

async function certificate(root, name) {
  const keyPath = join(root, `${name}.key`), certificatePath = join(root, `${name}.crt`);
  await execute("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
    "-out", certificatePath, "-subj", `/CN=${name}`, "-addext", name === "server" ?
      "subjectAltName=IP:127.0.0.1" : `subjectAltName=DNS:${name}`, "-days", "1"]);
  await chmod(keyPath, 0o600);
  const certificate = await readFile(certificatePath), key = await readFile(keyPath);
  return { certificate, key, fingerprint: new X509Certificate(certificate).fingerprint256
    .replaceAll(":", "").toLowerCase() };
}

async function availablePort() {
  const server = createNetServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const { port } = server.address();
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function listen(server, port) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}

async function close(server) {
  await new Promise(resolve => server.close(resolve));
}

function endpoint(port, path = "/v1/finality-custodian") {
  return { host: "127.0.0.1", port, path, timeoutMs: 3000, maxFrameBytes: 4096 };
}

function serverConfig(at, serverTls, clientTls) {
  return { endpoint: at, clientCertificateSha256: clientTls.fingerprint,
    serverCertificate: serverTls.certificate, serverPrivateKey: serverTls.key,
    clientCaCertificate: clientTls.certificate, maxConnections: 4 };
}

function clientConfig(at, serverTls, clientTls) {
  return { endpoint: at, serverCertificateSha256: serverTls.fingerprint,
    serverCaCertificate: serverTls.certificate, clientCertificate: clientTls.certificate,
    clientPrivateKey: clientTls.key };
}

test("pinned TLS 1.3 carrier performs exactly one authenticated custody exchange", async t => {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-mtls-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const [serverTls, clientTls] = await Promise.all([certificate(root, "server"), certificate(root, "client")]);
  const port = await availablePort(), at = endpoint(port), store = memoryStore();
  const handler = new AuthenticatedFinalityQuorumCustodianServer({ authentication: authentication(), store });
  const server = createMtlsFinalityCustodianServer(serverConfig(at, serverTls, clientTls), handler);
  await listen(server, port);
  t.after(() => close(server));
  const transport = createMtlsFinalityCustodianTransport(clientConfig(at, serverTls, clientTls));
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(), checkpoint: checkpoint(),
    transport });
  assert.equal(await client.load(), null);
  assert.deepEqual(await client.compareAndSwap(null, HASH_A), { status: "committed" });
  assert.equal(await client.load(), HASH_A);
  assert.equal(store.current, HASH_A);
  assert.equal(store.casCalls, 1);
  assert.deepEqual(client.checkpoint(), { session: checkpoint().session, nextSequence: "3" });
});

test("wrong server pin, client identity and route fail closed as uncertain without retry", async t => {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-mtls-adversarial-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const [serverTls, clientTls, rogueTls] = await Promise.all([
    certificate(root, "server"), certificate(root, "client"), certificate(root, "rogue")]);
  const port = await availablePort(), at = endpoint(port), store = memoryStore();
  const handler = new AuthenticatedFinalityQuorumCustodianServer({ authentication: authentication(), store });
  const server = createMtlsFinalityCustodianServer(serverConfig(at, serverTls, clientTls), handler);
  await listen(server, port);
  t.after(() => close(server));

  for (const config of [
    { ...clientConfig(at, serverTls, clientTls), serverCertificateSha256: "0".repeat(64) },
    { ...clientConfig(at, serverTls, rogueTls) },
    clientConfig(endpoint(port, "/v1/wrong"), serverTls, clientTls),
  ]) {
    const client = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(), checkpoint: checkpoint(),
      transport: createMtlsFinalityCustodianTransport(config) });
    await assert.rejects(client.load(), error => error instanceof FinalityCustodianTransportUncertainError &&
      /do not retry before reconciliation/.test(error.message));
    assert.equal(client.checkpoint().nextSequence, "1");
  }
  assert.equal(store.casCalls, 0);
});

test("truncated authenticated HTTP response is uncertain and malformed config fails before I/O", async t => {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-mtls-truncated-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const [serverTls, clientTls] = await Promise.all([certificate(root, "server"), certificate(root, "client")]);
  const port = await availablePort(), at = endpoint(port);
  const server = createHttpsServer({ cert: serverTls.certificate, key: serverTls.key,
    ca: clientTls.certificate, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3" }, (request, response) => {
    request.resume();
    response.writeHead(200, { "content-type": "application/octet-stream", "content-length": 32,
      connection: "close" });
    response.end(Buffer.from("{}\n"));
  });
  await listen(server, port);
  t.after(() => close(server));
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(), checkpoint: checkpoint(),
    transport: createMtlsFinalityCustodianTransport(clientConfig(at, serverTls, clientTls)) });
  await assert.rejects(client.load(), error => error instanceof FinalityCustodianTransportUncertainError);
  assert.equal(client.checkpoint().nextSequence, "1");

  assert.throws(() => createMtlsFinalityCustodianTransport(clientConfig({ ...at, host: "localhost" },
    serverTls, clientTls)), /endpoint is invalid/);
  const transport = createMtlsFinalityCustodianTransport(clientConfig(at, serverTls, clientTls));
  await assert.rejects(transport.exchange(Buffer.alloc(4097)), /outbound frame is invalid/);
});

test("absolute client deadline bounds a peer that never starts its response", async t => {
  const root = await mkdtemp(join(tmpdir(), "bloch-l2-custodian-mtls-deadline-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const [serverTls, clientTls] = await Promise.all([certificate(root, "server"), certificate(root, "client")]);
  const port = await availablePort(), at = { ...endpoint(port), timeoutMs: 500 };
  let responded = false;
  const server = createHttpsServer({ cert: serverTls.certificate, key: serverTls.key,
    ca: clientTls.certificate, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3" }, (request, response) => {
    request.resume();
    setTimeout(() => {
      responded = true;
      response.writeHead(200, { "content-type": "application/octet-stream", "content-length": 3,
        connection: "close" });
      response.end(Buffer.from("{}\n"));
    }, 1000);
  });
  await listen(server, port);
  t.after(() => close(server));
  const client = new AuthenticatedFinalityQuorumCustodian({ authentication: authentication(), checkpoint: checkpoint(),
    transport: createMtlsFinalityCustodianTransport(clientConfig(at, serverTls, clientTls)) });
  await assert.rejects(client.load(), error => error instanceof FinalityCustodianTransportUncertainError &&
    /deadline|timed out/.test(`${error.message} ${error.cause?.message ?? ""}`));
  assert.equal(responded, false);
  assert.equal(client.checkpoint().nextSequence, "1");
});
