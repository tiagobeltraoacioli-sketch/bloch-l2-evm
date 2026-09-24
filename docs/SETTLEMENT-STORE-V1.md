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
