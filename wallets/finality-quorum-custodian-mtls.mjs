// SPDX-License-Identifier: MIT OR Apache-2.0

import { X509Certificate } from "node:crypto";
import { createServer, request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { checkServerIdentity } from "node:tls";
import { BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES } from "./finality-quorum-custodian.mjs";

const SHA256 = /^[0-9a-f]{64}$/;
const REQUEST_PATH = /^\/[A-Za-z0-9/_-]{1,127}$/;
const MAX_TLS_BYTES = 64 * 1024;

function exact(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  const keys = Object.keys(value).sort(), expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(message);
  }
  return value;
}

function boundedInteger(value, minimum, maximum, message) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(message);
  return value;
}

function bytes(value, message) {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > MAX_TLS_BYTES) {
    throw new Error(message);
  }
  return Buffer.from(value);
}

function fingerprint(value, message) {
  if (typeof value !== "string") throw new Error(message);
  const normalized = value.replaceAll(":", "").toLowerCase();
  if (!SHA256.test(normalized)) throw new Error(message);
  return normalized;
}

function endpoint(value) {
  exact(value, ["host", "port", "path", "timeoutMs", "maxFrameBytes"],
    "Finality custodian mTLS endpoint is invalid");
  if (typeof value.host !== "string" || isIP(value.host) === 0 || value.host === "0.0.0.0" ||
      value.host === "::" || typeof value.path !== "string" || !REQUEST_PATH.test(value.path)) {
    throw new Error("Finality custodian mTLS endpoint is invalid");
  }
  boundedInteger(value.port, 1, 65535, "Finality custodian mTLS port is invalid");
  boundedInteger(value.timeoutMs, 500, 30000, "Finality custodian mTLS timeout is invalid");
  boundedInteger(value.maxFrameBytes, 2, BLOCH_L2_FINALITY_CUSTODIAN_MAX_BYTES,
    "Finality custodian mTLS frame limit is invalid");
  return Object.freeze({ ...value });
}

function clientConfig(value) {
  exact(value, ["endpoint", "serverCertificateSha256", "serverCaCertificate", "clientCertificate",
    "clientPrivateKey"], "Finality custodian mTLS client config is invalid");
  return Object.freeze({ endpoint: endpoint(value.endpoint),
    serverCertificateSha256: fingerprint(value.serverCertificateSha256,
      "Finality custodian server certificate pin is invalid"),
    serverCaCertificate: bytes(value.serverCaCertificate, "Finality custodian server CA is invalid"),
    clientCertificate: bytes(value.clientCertificate, "Finality custodian client certificate is invalid"),
    clientPrivateKey: bytes(value.clientPrivateKey, "Finality custodian client key is invalid") });
}

function serverConfig(value) {
  exact(value, ["endpoint", "clientCertificateSha256", "serverCertificate", "serverPrivateKey",
    "clientCaCertificate", "maxConnections"], "Finality custodian mTLS server config is invalid");
  return Object.freeze({ endpoint: endpoint(value.endpoint),
    clientCertificateSha256: fingerprint(value.clientCertificateSha256,
      "Finality custodian client certificate pin is invalid"),
    serverCertificate: bytes(value.serverCertificate, "Finality custodian server certificate is invalid"),
    serverPrivateKey: bytes(value.serverPrivateKey, "Finality custodian server key is invalid"),
    clientCaCertificate: bytes(value.clientCaCertificate, "Finality custodian client CA is invalid"),
    maxConnections: boundedInteger(value.maxConnections, 1, 64,
      "Finality custodian maximum connections is invalid") });
}

function certificateFingerprint(certificate, message) {
  if (!certificate?.raw) throw new Error(message);
  return fingerprint(new X509Certificate(certificate.raw).fingerprint256, message);
}

function contentLength(value, maximum) {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
    throw new Error("Finality custodian content length is invalid");
  }
  const parsed = Number(value);
  return boundedInteger(parsed, 2, maximum, "Finality custodian content length is invalid");
}

export class FinalityCustodianTransportUncertainError extends Error {
  constructor(message, options) {
    super(`Finality custodian transport outcome is uncertain: ${message}; do not retry before reconciliation`,
      options);
    this.name = "FinalityCustodianTransportUncertainError";
  }
}

export function createMtlsFinalityCustodianTransport(input) {
  const config = clientConfig(input);
  return Object.freeze({
    async exchange(frame) {
      if (!(frame instanceof Uint8Array) || frame.byteLength < 2 ||
          frame.byteLength > config.endpoint.maxFrameBytes) {
        throw new Error("Finality custodian outbound frame is invalid");
      }
      const payload = Buffer.from(frame);
      return new Promise((resolve, reject) => {
        let settled = false, deadline;
        const uncertain = (message, cause) => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          reject(new FinalityCustodianTransportUncertainError(message, cause ? { cause } : undefined));
        };
        const request = httpsRequest({
          host: config.endpoint.host,
          port: config.endpoint.port,
          path: config.endpoint.path,
          method: "POST",
          ca: config.serverCaCertificate,
          cert: config.clientCertificate,
          key: config.clientPrivateKey,
          rejectUnauthorized: true,
          minVersion: "TLSv1.3",
          maxVersion: "TLSv1.3",
          agent: false,
          timeout: config.endpoint.timeoutMs,
          headers: { "content-type": "application/octet-stream", "content-length": payload.length,
            connection: "close" },
          checkServerIdentity(host, certificate) {
            const identityError = checkServerIdentity(host, certificate);
            if (identityError) return identityError;
            return certificateFingerprint(certificate, "Finality custodian server certificate is invalid") ===
              config.serverCertificateSha256 ? undefined :
              new Error("Finality custodian server certificate pin does not match");
          },
        }, response => {
          const chunks = [];
          let received = 0, expected;
          try {
            if (response.statusCode !== 200 || response.headers["content-type"] !== "application/octet-stream" ||
                response.headers.connection?.toLowerCase() !== "close") {
              throw new Error("response status or headers are invalid");
            }
            expected = contentLength(response.headers["content-length"], config.endpoint.maxFrameBytes);
          } catch (error) {
            response.resume();
            uncertain(error.message, error);
            return;
          }
          response.on("data", chunk => {
            received += chunk.length;
            if (received > expected || received > config.endpoint.maxFrameBytes) {
              response.destroy(new Error("response exceeds its declared or configured limit"));
            } else chunks.push(chunk);
          });
          response.once("error", error => uncertain("response failed", error));
          response.once("end", () => {
            if (settled) return;
            if (received !== expected) {
              uncertain("response is truncated");
              return;
            }
            settled = true;
            clearTimeout(deadline);
            resolve(Buffer.concat(chunks));
          });
        });
        deadline = setTimeout(() => request.destroy(new Error("absolute exchange deadline exceeded")),
          config.endpoint.timeoutMs);
        request.once("timeout", () => request.destroy(new Error("exchange timed out")));
        request.once("error", error => uncertain("request failed", error));
        request.end(payload);
      });
    },
  });
}

async function readRequest(request, maximum, timeoutMs) {
  if (request.headers["content-type"] !== "application/octet-stream" ||
      request.headers.connection?.toLowerCase() !== "close" || request.headers["transfer-encoding"] !== undefined) {
    throw new Error("Finality custodian request headers are invalid");
  }
  const expected = contentLength(request.headers["content-length"], maximum);
  const chunks = [];
  let received = 0;
  const deadline = setTimeout(() => request.destroy(new Error("absolute request deadline exceeded")), timeoutMs);
  request.setTimeout(timeoutMs, () => request.destroy(new Error("request timed out")));
  try {
    for await (const chunk of request) {
      received += chunk.length;
      if (received > expected || received > maximum) {
        throw new Error("Finality custodian request exceeds its declared or configured limit");
      }
      chunks.push(chunk);
    }
  } finally {
    clearTimeout(deadline);
  }
  if (received !== expected) throw new Error("Finality custodian request is truncated");
  return Buffer.concat(chunks);
}

function send(response, status, frame) {
  const payload = frame ?? Buffer.alloc(0);
  response.writeHead(status, { "content-type": status === 200 ? "application/octet-stream" : "text/plain",
    "content-length": payload.length, "cache-control": "no-store", connection: "close" });
  response.end(payload);
}

export function createMtlsFinalityCustodianServer(input, handler) {
  const config = serverConfig(input);
  if (!handler || typeof handler !== "object" || typeof handler.handle !== "function") {
    throw new Error("Finality custodian mTLS handler is invalid");
  }
  const server = createServer({ cert: config.serverCertificate, key: config.serverPrivateKey,
    ca: config.clientCaCertificate, requestCert: true, rejectUnauthorized: true,
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3", handshakeTimeout: config.endpoint.timeoutMs },
  async (request, response) => {
    const deadline = setTimeout(() => {
      request.destroy(new Error("absolute server exchange deadline exceeded"));
      response.destroy();
    }, config.endpoint.timeoutMs);
    try {
      if (request.method !== "POST" || request.url !== config.endpoint.path || !request.socket.authorized) {
        throw new Error("Finality custodian request target or TLS authorization is invalid");
      }
      if (certificateFingerprint(request.socket.getPeerCertificate(true),
        "Finality custodian client certificate is invalid") !== config.clientCertificateSha256) {
        throw new Error("Finality custodian client certificate pin does not match");
      }
      const requestFrame = await readRequest(request, config.endpoint.maxFrameBytes,
        config.endpoint.timeoutMs);
      const responseFrame = await handler.handle(requestFrame);
      if (!(responseFrame instanceof Uint8Array) || responseFrame.byteLength < 2 ||
          responseFrame.byteLength > config.endpoint.maxFrameBytes) {
        throw new Error("Finality custodian handler response is invalid");
      }
      send(response, 200, Buffer.from(responseFrame));
    } catch {
      if (!response.headersSent) send(response, 400);
      else response.destroy();
    } finally {
      clearTimeout(deadline);
    }
  });
  server.maxConnections = config.maxConnections;
  server.requestTimeout = config.endpoint.timeoutMs;
  server.headersTimeout = config.endpoint.timeoutMs;
  server.keepAliveTimeout = 1;
  return server;
}
