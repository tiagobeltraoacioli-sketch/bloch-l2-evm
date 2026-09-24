# Durable checkpoint history and freshness-safe recovery

The Unix `checkpoint_store` module persists accepted signed checkpoints and
their exact headers. It uses the real hybrid quorum verifier from `checkpoint`.
It is a separate experimental library: it does not overwrite the native node's
`ws_latest.bin`, publish envelopes or change any running validator.

## API and acceptance

* `CheckpointStore::create(path, policy)` creates a new private directory and
  holds an exclusive OS writer lock. Existing directories are never replaced.
* `open(path, policy, minimum)` rechecks the exact pinned policy and verifies
  every stored envelope/header. `minimum` is an independently retained
  `(epoch, checkpoint digest)` watermark.
* `accept(envelope, header, current_epoch)` checks freshness, signatures, quorum,
  header binding and the previous checkpoint before writing. Identical fresh
  checkpoints are idempotent; older epochs or conflicting digests are refused.
* `current(current_epoch)` rechecks freshness and cryptographic validity before
  returning a usable `VerifiedCheckpoint`. An empty or poisoned store refuses.
* `historical_audit(epoch, checked_at_epoch, observed_current_epoch)` rereads and
  reverifies one exact retained record at its original freshness epoch. It
  rejects future-dated audits, records absent from the opened history and any
  changed predecessor link, and returns an audit-only type that cannot be used
  as a current checkpoint capability.
* `mark()` reports the stored rollback floor. It is not a fresh anchor and cannot
  be passed to the header verifier as one.

Settlement startup should use the sibling authority module's
`open_authority_bound_stores` facade. It requires this checkpoint floor and the
settlement floor, and releases both locks without exposing a handle if joint
recovery fails. Direct `open` remains the lower-level checkpoint-only primitive.

## Historical validity is not freshness

A store may contain a validly signed checkpoint that has aged beyond the
weak-subjectivity window. Reopening must preserve its rollback floor without
making it current. Historical replay therefore verifies each signature,
arrangement validity and header against that checkpoint's own epoch. Settlement
recovery may request an exact retained record at the freshness epoch recorded in
its V4 receipt, but receives `HistoricalCheckpointAuditV1`, not
`VerifiedCheckpoint`.

Only `current` applies the caller's trusted present epoch before returning an
anchor. Stale or future anchors are refused. The store can still accept a newer,
fresh checkpoint that advances beyond an old floor. Callers must recheck
freshness as time passes; an object obtained earlier does not stay fresh forever.
The clock and chain schedule remain trusted inputs, not values learned from the
artifact. A bootstrap checkpoint cannot override a running node's local finality.

## Durability and limits

Directories are created with mode 0700 and files with mode 0600, subject to
umask. Paths are resolved to absolute canonical paths before retaining the lock.
Each acceptance writes an exclusive temporary file, synchronizes it, renames it
to the epoch's final file and synchronizes the directory. The in-memory floor
advances only after success. A publication error poisons the instance: close and
reopen to resolve whether the record became visible before the failure.

The `POLICY` file pins a domain-separated SHA3 hash of network, genesis, signer
set ID, adoption epoch, phase shape, ordered public keys and external flags.
Silently changing keys, phase or policy is refused. Explicit signer rotation
and migration between stores remain unimplemented; do not edit `POLICY` to
bypass this binding.

Files named with 20 decimal epoch digits plus `.ckp` contain `BLCHCP01`, the
previous checkpoint digest (or policy identity for the first entry), canonical
native checkpoint bytes, the 304-byte header, a u8 signature count, and entries
of u8 signer index plus little-endian u32 length plus raw signature bytes.
The checkpoint decoder reserializes against the official encoder on every read.
Trailing bytes are rejected. The private store format is not the native node's
distribution-envelope file format.

Reads are capped at 64 KiB per file, five signatures per record, 8,192 bytes per
signature and 10,000 committed checkpoints. Every record must pass signatures
and header checks; corrupted files are never silently truncated or discarded.
Incomplete `.pending-*` files are ignored and retained. There is no automatic
cleanup, compaction or fast checkpoint-import path. Recovery cost grows with
history, including real PQ signature verification.

Retain the last acknowledged `CheckpointMark` independently. It detects removal
or replacement of that acknowledged checkpoint on reopen. With no independent
minimum, a valid older prefix cannot reveal that a newer suffix was deleted.
Previous-digest links detect structural omissions but do not make the local
history an independently signed append-only log: a file editor can relink valid
signed artifacts. The security floor is the externally retained epoch/digest
plus reverified signer assertions, not unsigned filesystem metadata.

Use trusted private parent directories and a local filesystem whose sync and
rename guarantees are appropriate. Locks are advisory; concurrent hostile path
replacement and hardware power-loss qualification are outside these tests.
This library does not replace the operator CLI's trusted inbox derivation files
or supply a native escrow activation.

## Validation

Persistence tests use real signatures from disposable test keys. They cover
restart and writer exclusion, idempotence, rollback and conflict refusal, stale
historical recovery with fresh replacement, exact historical audit after the
latest checkpoint advances, future audit claims, changed predecessor links,
signature corruption, truncation, acknowledged-tail deletion, immutable policy,
oversized input, publication-error poisoning and incomplete temporary files.

```sh
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-escrow-pq/Cargo.toml
```
