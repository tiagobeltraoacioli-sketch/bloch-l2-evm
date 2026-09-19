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

For machine-checked startup approval, the store also supports an Ed25519-signed
envelope over the complete canonical record, an independently assigned 32-byte
deployment ID and the approver key ID. `initializeApproved...` verifies that
envelope before creating anything and accepts only generation zero;
`createApproved...` requires a fresh approval matching the exact current record
on each restart. The server receives only the pinned public key. The private key
belongs on an offline/HSM review path, and the deployment ID and public key must
not arrive with the local store. This approval authenticates operator intent;
it does not make ordinary disk or colocated backups rollback-resistant.

Approval-authority continuity is dual-signed and role-separated. A canonical
transition binds the deployment, independently retained prior record and key,
next record and next key. The prior key signs `authorization`; the next key
signs `acceptance`; both are mandatory and use distinct signing domains. This
supports a monotonic record advance, a key rotation at the exact same record,
or both, while rejecting a no-op, downgrade, key substitution or stale prior
record. The verified next record and public key must then be retained in the
independent operator control plane; the local file remains only a durability
mechanism, not the anti-rollback authority.

`createInitialFinalityCustodianAuthorityCheckpoint` and
`advanceFinalityCustodianAuthorityCheckpoint` make that retained input one
canonical public object instead of two loosely associated values. It binds the
deployment ID, exact Ed25519 public key, exact store record, a separate
monotonic transition index, the previous checkpoint hash and its own hash.
The separate index means a key-only rotation at an unchanged store record is
still an observable authority transition. Opening through
`createAuthorityCheckpointFilesystemFinalityCustodianStore` validates the
whole object before trusting its record hash. The checkpoint must be committed
atomically in an independent monotonic or append-only control plane before the
new authority is accepted; keeping it beside the store is not rollback
protection, and supplying an older internally valid checkpoint validates the
older state by design.

The offline CLI creates these objects without loading private material:

```sh
node wallets/finality-quorum-custodian-authority-cli.mjs approve \
  --record <initial-record.json> \
  --expected-record-hash <hash-retained-out-of-band> \
  --deployment-id <64-hex> \
  --private-key <current-ed25519-private.pem> --output <approval.json>

node wallets/finality-quorum-custodian-authority-cli.mjs transition \
  --previous-record <prior-record.json> --next-record <next-record.json> \
  --deployment-id <64-hex> \
  --previous-authority-public-key <current-ed25519-public.pem> \
  --next-authority-public-key <next-ed25519-public.pem> \
  --output <transition.json>

# Run separately under the retiring and incoming authorities:
node wallets/finality-quorum-custodian-authority-cli.mjs sign-continuity \
  --transition <transition.json> \
  --expected-transition-sha256 <hash-retained-out-of-band> \
  --role <authorization|acceptance> \
  --private-key <role-ed25519-private.pem> --output <role-share.json>

node wallets/finality-quorum-custodian-authority-cli.mjs assemble-continuity \
  --transition <transition.json> \
  --expected-transition-sha256 <hash-retained-out-of-band> \
  --previous-authority-public-key <current-ed25519-public.pem> \
  --next-authority-public-key <next-ed25519-public.pem> \
  --authorization <authorization-share.json> --acceptance <acceptance-share.json> \
  --output <continuity.json>

node wallets/finality-quorum-custodian-authority-cli.mjs initial \
  --approval <approved-initial-record.json> \
  --expected-approval-sha256 <hash-retained-out-of-band> \
  --deployment-id <64-hex> \
  --authority-public-key <current-ed25519-public.pem> \
  --output <new-authority-checkpoint.json>

node wallets/finality-quorum-custodian-authority-cli.mjs advance \
  --checkpoint <independently-retained-prior-checkpoint.json> \
  --expected-checkpoint-hash <hash-retained-out-of-band> \
  --continuity <dual-signed-continuity.json> \
  --expected-continuity-sha256 <hash-retained-out-of-band> \
  --next-authority-public-key <next-ed25519-public.pem> \
  --output <new-authority-checkpoint.json>

# With the custodian stopped, classify an ambiguous record-advancing operation:
node wallets/finality-quorum-custodian-authority-cli.mjs reconcile-record \
  --store <custodian-store.json> \
  --checkpoint <independently-retained-prior-checkpoint.json> \
  --expected-checkpoint-hash <hash-retained-out-of-band> \
  --continuity <dual-signed-continuity.json> \
  --expected-continuity-sha256 <hash-retained-out-of-band> \
  --next-authority-public-key <next-ed25519-public.pem> \
  --output <new-reconciliation-receipt.json>

# On an independent review host, require the receipt digest received out of band:
node wallets/finality-quorum-custodian-authority-cli.mjs verify-reconciliation \
  --receipt <reconciliation-receipt.json> \
  --expected-receipt-sha256 <externally-approved-sha256> \
  --checkpoint <independently-retained-prior-checkpoint.json> \
  --expected-checkpoint-hash <hash-retained-out-of-band> \
  --continuity <dual-signed-continuity.json> \
  --expected-continuity-sha256 <hash-retained-out-of-band> \
  --next-authority-public-key <next-ed25519-public.pem>
```

Inputs must be absolute, canonical, owned, single-link files without
group/world write permission. Output uses exclusive creation, is synced before
success and is never overwritten. Private keys additionally require owner-only
permissions and are opened only by the `approve` or `sign-continuity` process.
Before opening the authority private key, `approve` requires the record's exact
`recordHash` from the independent control plane. This prevents a different
internally valid store record from being substituted at the signing boundary.
The command then prints the SHA-256 of the exact canonical approval file,
including its terminating newline, so the value matches `sha256sum approval.json`;
transfer and retain that digest through an authenticated independent channel.
The `initial` command requires this digest, so a different old but valid
approval cannot silently become the bootstrap record. The CLI verifies the
initial signature or both continuity roles before
producing a successor, but moving that output to the independent control plane
remains an explicit operator action.
This file-byte convention is intentionally different from the reconciliation
receipt digest, which is the protocol's SHA-256 of the canonical JSON value
without the file newline.
Likewise, `transition` prints the SHA-256 of its exact canonical output file.
Each authority must receive that digest independently and supply it through
`--expected-transition-sha256` when signing. Assembly requires the same digest,
so a different well-formed transition cannot be inserted before either signing
or final continuity construction.
The `advance`, `reconcile-record`, and `verify-reconciliation` commands also
require the exact `checkpointHash` retained in the independent control plane.
An internally valid checkpoint file is not accepted as its own rollback floor;
the expected hash must arrive over an authenticated channel and must not be
copied from that file during the command invocation.
`assemble-continuity` prints the SHA-256 of the exact canonical continuity file,
including its terminating newline. Retain that digest independently as well;
all three commands require it through `--expected-continuity-sha256`. This
prevents a different internally valid, dual-signed transition from being
silently substituted for the transition approved by the operator.

`reconcile-record` takes the same exact retained checkpoint and dual-signed
transition, derives the only valid successor, and reads the filesystem store
under its create-once lock. It emits a canonical receipt only when the complete
observed record is exactly the retained prior record or the approved successor;
an orphan lock or any third state fails closed. Run it only while the custodian
is quiescent. The receipt classifies the local store at one instant; it does not
prove that the independent checkpoint control plane committed either value and
must not be used to adopt a value discovered from disk. A key-only authority
rotation cannot be distinguished from the store record and is therefore
rejected by this command. The command prints the canonical receipt SHA-256;
transfer that digest over an authenticated channel. `verify-reconciliation`
strictly rederives both checkpoint hashes and the only record hash permitted by
the claimed status, then requires that external digest instead of trusting the
receipt file. Verification authenticates consistency with the approved
transition, not the truth or freshness of the original filesystem observation.

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
