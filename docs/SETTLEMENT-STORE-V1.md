# Settlement store V1

`native_settlement::store` is a dormant, Unix-only, single-writer recovery
primitive for `SettlementRegistryV1`. It does not activate native settlement.

The store creates a private `0700` directory and `0600` files without replacing
an existing path. Generation zero records the empty registry. Each later,
fixed-width record binds the exact settlement policy commitment, previous record
digest, registry state commitment, accepted L2 head, native anchor and inbox
cursor. Publication writes and fsyncs a private temporary inode, links it to a
create-once generation name, removes the temporary name and fsyncs the directory.
The in-memory head changes only after that sequence succeeds.

Every write is a CAS over `SettlementStoreMarkV1`. An I/O error after publication
starts poisons the handle and requires close/reopen; it must not be retried
blindly. Recovery rejects partial records, gaps, unknown files, leftover
`.pending-*` crash evidence, non-private files, policy substitution, broken hash
chains and noncanonical head/cursor progress.

`open` requires an exact independently retained rollback floor. A floor copied
from the directory under inspection provides no rollback protection. Operators
must durably acknowledge and retain each returned mark in a separate trust
domain before treating it as their new floor.
`SettlementStoreMarkV1::encode` provides its exact fixed-width transport, but
encoding alone does not authenticate a mark or make its retention independent.

This module does **not** provide distributed availability, hardware-backed WORM,
host-compromise resistance, proof that validators ran the transition, consensus,
or L2 finality. `registry()` exposes local recovered state only and must never be
published as `finalized`. Filesystem power-loss guarantees still depend on the
host, filesystem and storage hardware honoring `fsync` and hard-link semantics.
