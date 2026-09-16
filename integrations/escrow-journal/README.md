# Experimental durable escrow execution journal

This Unix host library persists the inputs needed to recover `EscrowEvmDomain`
by verified replay. It is separate from the portable/no_std execution core.
It does not deploy a service, activate a bridge or authenticate L1 finality.

The [local operator CLI](CLI.md) provides bounded `init`, `status` and `apply`
commands with separate operator-supplied L1 derivation files.

## Commit and recovery

1. Create a new directory with mode 0700 and files with mode 0600, subject to
   the process umask. Existing directories are never implicitly reinitialized.
   Hold an exclusive OS file lock for the lifetime of the journal.
   Creation and reopening resolve the directory to an absolute canonical path
   before retaining the writer. Later process working-directory changes cannot
   redirect commits to an unrelated directory while the original lock is held.
2. Clone the private verification cursor and validate inclusion, deposit order,
   exact EVM mint data and the full EVM execution witness on that candidate.
   Rejected execution produces no committed file and does not poison the writer.
3. Serialize one bounded record containing the domain, sequential block number,
   previous record digest, inclusion proofs, signed block input, execution witness
   and composite receipt commitment. Add a length frame and Keccak-256 checksum.
4. Write an exclusively created temporary file, call `sync_all`, rename it to
   its final sequence name, then sync the directory. Only after these succeed
   publish the candidate in memory and return the accepted receipt.
5. Any publication I/O error poisons the writer. The rename may have succeeded
   even if directory sync failed; retrying from the old in-memory cursor would
   be unsafe. Close and reopen to resolve the visible committed history.

`Journal::open` requires a fresh trusted genesis domain, an independent minimum
`JournalHead` watermark and a host derivation function. For every committed block
the function must return its independently authenticated `TrustedEscrowBatch`.
No trusted-finality field is loaded from disk. Recovery checks the hash chain,
re-executes inclusion and EVM verification, and matches the composite receipt.
Both execution and inbox cursors are reconstructed together. If derivation is
unavailable or a committed record is invalid, opening fails without returning a
partially usable journal.

An older minimum watermark permits recovery of an extra complete commit whose
acknowledgment was lost. A missing or conflicting minimum watermark fails closed.
After each acknowledged commit, retain `journal.head()` independently using a
durable mechanism appropriate to the host. Storing it only beside the journal
does not protect against rollback of that entire directory. With only the
genesis watermark, deletion of a complete suffix is inherently undetectable;
checksums and hash chains alone cannot establish the latest accepted height.

## On-disk version 1

* `LOCK`: lifetime writer lock; never replace/delete this file while operating.
* `MANIFEST`: eight ASCII bytes `BLOCHM01`, followed by the 32-byte domain ID.
  The genesis head digest is Keccak-256 of these exact 40 bytes.
* `00000000000000000001.blj`, etc.: `BLOCHJ01`, little-endian u64 JSON payload
  length, payload bytes, 32-byte Keccak-256 payload digest. The payload includes
  the previous digest. JSON is a local storage encoding, not a consensus codec.
* `.pending-*`: unpublished temporary files, ignored during recovery and never
  interpreted as committed records. They are retained for operator inspection;
  automatic cleanup and garbage collection are not implemented.

Final records must form a contiguous sequence starting at one. Missing middle
records, truncated/corrupted committed files, unsupported filenames and symlink
records are rejected. A malformed committed tail is never silently discarded.
Payloads are bounded to 64 MiB before reading/decoding, and serialization uses a
bounded writer. Decoded objects can use more memory than their serialized size.
The prototype permits at most one million records and does not compact history.

## Operational limits

Use a local filesystem and a private directory with trusted parent directories.
The OS lock is advisory: all writers must cooperate. Checks reject ordinary
symlinks, but this is not a filesystem sandbox against an attacker concurrently
replacing directory entries, parents or the lock inode. Durability relies on the
filesystem/device honoring `sync_all` and atomic same-directory rename. The tests
exercise process failure and malformed disk state, not hardware power-loss
qualification or network-filesystem semantics.

Recovery is O(history): every witness is re-executed. It recovers the verifier's
state commitment, deposit cursor and accepted anchor, not a sequencer's complete
account database or the native escrow ledger. Atomic snapshots/checkpoints,
compaction, migrations, external watermark storage and a long-running service
remain unimplemented. Cloning the portable domain enables speculative local
verification; it does not authenticate genesis or authorize competing writers.

L1 roots, source mappings, append-only ancestry and finality remain host trust
boundaries. There is no mainnet inbox activation, withdrawal proof or SVM runtime.

## Validation

Run from the modular execution repository root with Rust 1.94.1:

```sh
cargo +1.94.1 test --offline --locked --manifest-path integrations/escrow-journal/Cargo.toml
```

Eighteen tests, including two child-process helpers, passed. They cover restart
after a real local deposit, duplicate-credit refusal, lock exclusion, incomplete
temporary files, recovery after a lost acknowledgment, publication-error
poisoning, corrupted/truncated/gapped journals, independently pinned rollback
detection, wrong domains, missing L1 derivation, symlinks, oversized files and
tampering with a recomputed checksum. A child process commits and exits without
destructors; the parent recovers the accepted deposit and lock. Fixtures use
synthetic L1 trust inputs and real local EVM witness verification.

### Publication fault matrix

The private publication path exposes test hooks at five boundaries. Tests inject
an I/O error and separately terminate a child process without destructors at
each boundary. For I/O errors, the writer remains at its old in-memory root and
cursors and refuses subsequent commits until recovery. The same production
write/sync/rename path is used; hooks are private and there is no public or
environment-controlled production fault switch.

| Interruption after | Visible final record in process-exit tests | Recovery |
| --- | --- | --- |
| Temporary file creation | No | Previous state; retry can credit once |
| Complete temporary write | No | Previous state; retry can credit once |
| Temporary file synchronization | No | Previous state; retry can credit once |
| Rename to final sequence name | Yes | Re-execute committed record; refuse replay |
| Directory synchronization | Yes | Re-execute committed record; refuse replay |

The checks compare execution roots, block numbers, deposit cursors and committed
heads, rather than merely checking file existence. They require one fresh L1
derivation for each recovered record. A separate child-process regression test
changes working directory after both relative creation and relative reopening,
then commits to the original journal successfully.

These tests simulate errors at operation boundaries and process termination.
They do not establish which unsynchronized directory entries survive hardware
power loss. Actual filesystem/device synchronization guarantees still apply.
