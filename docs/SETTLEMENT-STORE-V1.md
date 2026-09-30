# Settlement store V1

`native_settlement::store` is a dormant, Unix-only, single-writer recovery
primitive for `SettlementRegistryV1`. It does not activate native settlement.

The store creates a private `0700` directory and `0600` files without replacing
an existing path. Generation zero records the empty registry. Each later,
`BLSTRC02` record binds the exact settlement policy commitment,
previous record digest, registry state commitment, accepted L2 head, native
anchor, inbox cursor and canonical settlement transaction. Records committed
through `verify_inclusion_and_commit` additionally retain the containing block,
slot, checkpoint, transaction index and admission commitment. Publication writes
and fsyncs a private temporary inode, links it to a
create-once generation name, removes the temporary name and fsyncs the directory.
The in-memory head changes only after that sequence succeeds.

Every write is a CAS over `SettlementStoreMarkV1`. An I/O error after publication
starts poisons the handle and requires close/reopen; it must not be retried
blindly. Recovery rejects partial records, gaps, unknown files, leftover
`.pending-*` crash evidence, non-private files, policy substitution, broken hash
chains and noncanonical head/cursor progress.

Recovery decodes and round-trips every stored transaction, checks its commitment
and statement against the accepted head, and recomputes every stored admission
commitment from the exact transaction and coordinates. `BLSTRC01` is deliberately
not accepted by this implementation: an operator must explicitly replay trusted
source artifacts into a new store and establish a new independently retained
floor rather than silently reinterpret an old record layout.

`open` requires an exact independently retained rollback floor. A floor copied
from the directory under inspection provides no rollback protection. Operators
must durably acknowledge and retain each returned mark in a separate trust
domain before treating it as their new floor.
`SettlementStoreMarkV1::encode` provides its exact fixed-width transport, but
encoding alone does not authenticate a mark or make its retention independent.

`verify_evidence_and_commit` publishes a bounded variable-length `BLSTRC03`
record. Its prefix uses the V2 field layout under a distinct V3 tag, and its
length-prefixed suffix is the canonical `TransactionInclusionEvidenceV1`. The
store reauthenticates the
exact stored transaction, index, block, slot and checkpoint from that envelope
both before publication and during recovery. V2 and V3 records may coexist in
one hash-chained history; only V3 exposes recoverable evidence. The envelope and
accepted head share one create-once inode and record digest, avoiding a
cross-file crash window.

`BLSTRC04` extends V3 with a length-prefixed, bounded opaque authority-audit
suffix in that same inode. The portable store binds the bytes into its record
digest but deliberately does not interpret them as authority. The native-PQ
integration writes its canonical 129-byte receipt through this path and, after
restart, compares it with the exact independently retained PQ record reverified
at the receipt's historical freshness epoch. The returned audit type cannot be
used as a current checkpoint capability. A V4 record without that external
recheck is audit data, not a finality capability.

The native-PQ integration's coordinated open requires the external settlement
floor and checkpoint floor together, holds both single-writer locks, and returns
the stores only after V4 authority recovery succeeds. The compatibility opener
`open_authority_bound_stores` checks the latest authority receipt only; it is
not complete proof/authority replay. A failure drops both handles. This does
not merge or replace the two independently retained floors.

`open_verified` repeats the pinned execution proof and predecessor/cursor checks
for every retained settlement, including entries before the rollback floor.
`open_verified_with_audit` adds a caller-selected audit for each nonempty record
after those checks, its state commitment and its complete inclusion envelope
have passed. Its borrowed `SettlementReplayRecordV1` contains the exact record
mark, accepted head, transaction, inclusion, evidence and opaque authority bytes.
Generation zero is not audited. The callback must only validate: later history
or floor checks can still fail, so observing a record is not permission to
acknowledge or publish it. Audits run in order under the same writer lock, with
no second directory scan or retained copy of the entire history.

The native-PQ `open_proof_verified_authority_stores` uses this boundary to audit
**every** historical receipt against its independently pinned, locked checkpoint
store. V2/V3 records without an authority receipt are refused even when a later
V4 record is legitimate. Changed policy/digest/anchor/review claims, missing
signed checkpoints, malformed receipts, future acceptance epochs and authority
that was already stale at acceptance also fail. `History { generation, error }`
identifies the first failing authority record. Storage/proof errors retain their
original error category. Neither kind returns handles or rewrites records.

The `maximum_proofs` bound (`0..=10_000`) is checked before any settlement proof
or record audit. Checkpoint-store opening separately reverifies its own bounded
history. Legitimate historical receipts may be old at restart; their original
freshness is checked, while `CheckpointStore::current` still independently
refuses an expired current anchor. No recovered receipt is promoted to current
authority, validator execution or a finalized RPC tag.

This module does **not** provide distributed availability, hardware-backed WORM,
host-compromise resistance, proof that validators ran the transition, consensus,
or L2 finality. `registry()` exposes local recovered state only and must never be
published as `finalized`. Filesystem power-loss guarantees still depend on the
host, filesystem and storage hardware honoring `fsync` and hard-link semantics.
The inclusion receipt is replayable audit data, not an authentication capability;
the complete body, header/ancestry path and checkpoint-authority artifact remain
external and must be retained independently. `l1::TransactionInclusionEvidenceV1`
provides a bounded canonical envelope for independently retaining and
reauthenticating the complete body and ancestry path. The V3 path retains it
atomically, but the envelope does not authenticate checkpoint authority.
