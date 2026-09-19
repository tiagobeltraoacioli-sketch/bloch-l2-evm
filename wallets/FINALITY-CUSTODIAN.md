<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Finality custodian transport

The wallet finality checkpoint can use an independent custodian before writing
its local checkpoint. `finality-quorum-custodian.mjs` defines the bounded,
authenticated request/response protocol. `finality-quorum-custodian-mtls.mjs`
provides its concrete one-exchange HTTPS transport.

This is an integration boundary, not a deployed service. The module creates a
client adapter and an unbound server; an operator must still supply process
isolation, firewall policy, secret custody, monitoring, and independently
retained client checkpoints. No repository command starts the server.

`finality-quorum-custodian-store.mjs` provides the server-side durable CAS
store. Its canonical records form a hash chain, updates use a create-once lock,
temporary-file `fsync`, atomic rename, directory `fsync`, and readback. Opening
the store requires its independently retained exact record hash, so a restored
or replaced file cannot silently become trusted. An orphan lock or ambiguous
write blocks reopening for operator inspection; the module never removes one
based on age. This is a local durability boundary, not a substitute for an
independent backup or replicated witness of the retained record hash.
Loads and conflict observations take the same interprocess lock as transitions
and compare the exact retained record hash; a stale process therefore fails
closed instead of returning a cached custodian head.

`finality-quorum-custodian-checkpoint.mjs` supplies the filesystem-backed
client lifecycle. It writes a hash-chained `pending` state and advances an
independent CAS anchor before the transport receives a frame. Only a valid,
authenticated, non-uncertain response advances both anchor and local state back
to `ready`. A crash, malformed response, transport error, authenticated
`uncertain` result, ambiguous anchor update, or ambiguous local replacement
leaves a pending state or a retained lock and blocks restart.

## Transport invariants

- Both endpoints require TLS 1.3, CA validation, and an explicit SHA-256 leaf
  certificate pin. A valid CA chain alone is insufficient.
- The endpoint is a numeric IP address. The carrier does not perform DNS,
  redirect, proxy, fallback, reconnect, or automatic retry.
- One protocol frame is one POST and one response. Both directions require a
  canonical content length, `application/octet-stream`, `Connection: close`,
  and a configured limit no larger than the protocol's 4096-byte limit.
- Handshake, headers, request, and response share the configured deadline. The
  server limits simultaneous connections and rejects unpinned client leaves.
- Once the client starts the exchange, every TLS, HTTP, timeout, truncation,
  pin, or response failure is reported as uncertain. The caller must retain
  the already-consumed protocol sequence and reconcile the custodian state;
  it must not retry the CAS blindly.

TLS credentials are byte arrays supplied by the embedding process. Production
integration must load them without following links, require single-link files
owned by the service identity, require mode `0600` for private keys, and keep
the keys in a dedicated secret store or HSM where available. Certificate pins
and the authenticated protocol key are separate controls and must be rotated
through an offline, independently approved procedure.

## Required operational sequence

1. Provision distinct client and custodian identities and exchange CA roots and
   leaf pins out of band.
2. Build the initial filesystem checkpoint with a fresh random protocol session,
   approve its deterministic state hash out of band, create it once, and
   provision that same hash into an independent CAS anchor. This explicit hash
   is required at every client open; there is no trust on first use.
3. Start the custodian behind a firewall that permits only the pinned client IP
   and bind the returned server explicitly; the library never calls `listen`.
   Create the server-side store once from an externally approved initial record
   and require its latest record hash on every restart.
4. Use `createFilesystemFinalityCustodian` so each consumed sequence is first
   committed locally and to the independent anchor. Do not use the in-memory
   client directly in a restartable process.
5. On an uncertain result or retained lock, freeze checkpoint advancement and compare the
   independently retained custodian head. Resume only through a documented
   reconciliation decision.

The module deliberately does not automate pending-state reconciliation or
session replacement. Those actions require independently authenticated
evidence from the custodian and an approved session-rotation procedure; blindly
clearing the file or lock would reintroduce sequence reuse after a crash.

The HMAC protocol protects request identity and replay ordering even inside the
mTLS channel. mTLS protects the carrier and peer endpoints. Neither control
turns the experimental L2 into a production settlement system, and this code
must not be used with real funds until the native escrow, derivation, proof, and
settlement boundaries are independently completed and audited.
