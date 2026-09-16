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

This matrix tests process failure on the host filesystem, not hardware power loss.
In particular, rename-before-directory-sync may recover differently after power
loss. The pending filename includes process ID, time and a counter to reduce
collisions with retained files across process-ID reuse; creation is still exclusive.
