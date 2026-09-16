# Durable experimental escrow batches (Unix)

`lock_store::LockStore` records complete signed lock batches and reconstructs the
ledger by verifying every hybrid authorization and replaying every transition.
It is a local prototype, not a Genesis-4 transaction format or an activated bridge.
No private key or wallet password is stored; public keys, signatures and full lock
intents are stored, so treat the directory as sensitive transaction metadata.

## Lifecycle and trust

Create with `LockStore::create(path, trusted_baseline)` and retain `mark()` outside
the directory. Submit with `submit_batch(&[SignedLock { ... }])`, then independently
retain the new mark after success. Reopen with the same trusted baseline and the
last independently retained `LockMark`. Recovery accepts a later valid history
containing that exact mark and refuses loss or alteration of the acknowledged
prefix. An old minimum cannot detect loss of later unacknowledged batches.

`escrow()` is read-only: all mutations must use durable submission. Invalid
requests leave disk and memory unchanged. Recovery reproduces spent outputs,
change, fees, deposits and inbox sequence; replay protection is not reset.
Baseline allocations remain external trusted input, never imported from a wallet
balance or a historical checkpoint proof. The baseline commitment binds network,
domain, allocations, accounting, capacity and any pre-existing local history.

## Publication and recovery

The directory is created with mode 0700, files with 0600. An OS file lock on
`LOCK` is held for the writer lifetime; paths are canonicalized. Each batch is
validated on a private candidate before a new pending file is written and synced.
Publication renames it to its final sequence name and syncs the directory before
publishing memory. Any publication I/O failure poisons the handle: reads and
writes refuse service until it is closed and recovered. The batch may have reached
disk despite the error, so do not blindly resubmit it.

Recovery keeps the exclusive writer lock while it validates the entire history,
checks the retained minimum and synchronizes the directory. Only then does it
return a usable handle or mark. This completes publication when an earlier
process stopped after rename but before directory sync. If recovery sync fails,
`open` returns an I/O error, releases the lock and exposes no recovered state;
retry recovery rather than treating that failure as proof the batch was absent.
The same synchronization step applies to an empty history.

Committed files are `00000000000000000001.locks`, etc. Gaps, unexpected filenames,
non-regular committed files, malformed JSON, wrong baseline, invalid signatures,
wrong prior digest and incorrect resulting state commitments fail closed. Pending
files are ignored and retained. The format is version 1 JSON containing the prior
record digest, expected resulting ledger commitment and ordered signed intents.
SHA3-256 with `BLOCH:EXPERIMENTAL:LOCK:JOURNAL:1` commits the exact record bytes.
The first previous digest is the baseline ledger commitment. This is a local
hash chain, not a signed consensus ordering certificate: the independently held
mark protects acknowledged ordering against history replacement.

Limits are 8 MiB per serialized record and 10,000 committed batches, plus the
64-lock/4,096-input limits per batch. Disk reads are capped before JSON decoding;
decoding can allocate additional memory proportional to the capped payload.
Nested JSON sequences are also bounded during decoding: at most 64 locks,
4,096 inputs per intent, 3,749 public-key bytes and 8,192 signature bytes. The
decoder refuses an excess element before decoding its contents, rather than
building an oversized vector and rejecting it afterward. Intent objects reject
unknown fields. The existing aggregate 4,096-input budget across all locks is
still checked after decoding and before signatures or candidate-state cloning.
These are allocation defenses, not authorization: exact suite/key lengths,
ownership, signatures and transition rules still undergo their normal checks.
The emitted version-1 format is unchanged; previously accepted hand-edited
records with unknown intent fields now fail closed.

Recovery is linear in retained history and redoes PQ work. There is no pruning,
snapshot migration or total disk quota. Candidate construction clones the ledger
once per batch. Operators must separately budget disk, memory and concurrency.

The directory must be protected from concurrent filesystem modification by other
processes. Advisory locking and regular-file checks do not defend against a
hostile process with access to replace paths or the lock inode. Durability depends
on the filesystem's rename/fsync semantics; hardware power-loss behavior is not
qualified here.

Tests use disposable keys and temporary directories. They exercise reopen/replay,
exclusive locking, older and newer retained floors, ignored pending files,
repeated spend rejection, signature tampering, wrong baseline, publication
collision with poisoning, and rejection of a later invalid lock without any write.

## Publication fault matrix

Private test instrumentation injects both an I/O error and immediate child-process
exit (without running Rust destructors) after each boundary below. Production
calls use a no-op hook; no environment variable enables faults in the library.

| Boundary reached | State recovered after process exit or injected error |
| --- | --- |
| Pending file created | Previous complete state |
| Payload written | Previous complete state |
| Pending file synced | Previous complete state |
| File renamed to committed sequence | Complete new batch |
| Directory synced | Complete new batch |

Each case contains two signed locks, with the second spending the first lock's
change. Tests compare the entire recovered ledger commitment, verify conservation,
retry an unpublished batch, reject replay of a published batch and reopen again
with the new externally retained mark. Injected I/O errors additionally verify
that memory has not advanced and every subsequent read/write is refused until
recovery. Child-process exit verifies that the OS releases the writer lock even
without destructor cleanup.

Recovery-specific tests inject a directory-sync failure after an interrupted
rename, verify the writer lock remains held during synchronization and is released
on failure, then successfully reopen and reject replay. Additional checks cover
sync on empty and populated histories and rejection of malformed history or an
absent retained minimum before attempting synchronization.

Decoder tests cover exact field limits, the first excess element (including
nested malformed content), deserializers with known sequence lengths, unchanged
intent round trips and unknown intent fields. Full recovery and publication
failure tests continue to exercise actual hybrid signatures.

This matrix tests process failure on the host filesystem, not hardware power loss.
In particular, rename-before-directory-sync may recover differently after power
loss. The pending filename includes process ID, time and a counter to reduce
collisions with retained files across process-ID reuse; creation is still exclusive.

## Recovery resource budgets

`open_with_limits` takes `RecoveryLimits { batches, bytes }`, checked over all
committed record files before any JSON decoding, signature verification or replay.
Actual reads are additionally capped against the remaining byte budget. Baseline,
lock and pending files are excluded from that total. Exceeding a limit returns
`StoreError::Limit`, releases the lock and leaves history unchanged. Exact limits
are accepted, and a zero budget can recover an empty journal. The existing `open`
retains the original format ceilings through default limits.

The recovered writer retains these limits for new batches and tracks actual
committed bytes. Batch count is checked before signature work; the resulting
byte total is checked after candidate verification/serialization and before
creating pending files. Rejection leaves the ledger, inbox, fees and disk unchanged
and does not poison the handle. A larger history requires explicitly reopening
with a larger budget. Plain `create` and `open` retain the format ceilings.

These are journal-history budgets, not filesystem quotas, decoded-memory limits
or time limits. Pending files and metadata remain excluded. Tests
cover cumulative bytes over two signed batches, exact boundaries, zero budgets,
unchanged files after rejection and refusal before malformed JSON is decoded.
Write tests also cover repeatable rejection without poisoning, unchanged accounting,
exact-limit publication, restart and continuation after explicitly raising limits.
