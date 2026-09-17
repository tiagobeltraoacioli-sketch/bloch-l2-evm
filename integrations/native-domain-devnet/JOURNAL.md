# Durable experimental source journal

`journal::SourceJournal` stores the accepted source registry in a private Unix
single-writer directory. It is separate from EVM/SP1 settlement persistence and
never serializes a `ValidatedV2Prefix` into an authority token.

`create(path, network, domain, genesis_cursor, limits)` requires a nonexistent
path. It writes and fsyncs the genesis-bound file header, lock, directory and
parent directory. Existing or partially initialized paths are never overwritten.
`append(expected_source_commitment, position, headers, batch, full_proofs)` first
checks bounded input and validates a cloned registry. Only after writing the
entire frame and successfully calling `sync_all` does it publish the registry and
return its new `SourceMark`.

Keep that mark **independently and durably**. `open(..., exact_mark, limits)`
replays privately from the configured genesis, verifies complete native header
paths, derives each height again, verifies the inbox/proofs/mapping and checks
all source hash links. It returns a journal only when the reconstructed mark is
exactly the expected externally trusted mark. A minimum watermark is deliberately
not accepted. Even a valid extra suffix is refused if it was not acknowledged by
that external authority. A missing prefix/suffix, changed valid root, divergent
native branch, claimed-height substitution, corrupt checksum or truncated frame
fails closed without repair or exposure of intermediate state.

The exact tip's source commitment recursively binds previous source batches;
the externally retained anchor/root/count/record-count are also compared.
Computing a frame's own commitment during private replay is not a new trust
source. Native finality and experimental escrow authority remain external.

## Failure behavior

A write or fsync error poisons the live journal. Its registry and mark accessors
then fail, and append cannot be retried. A changed file length also poisons the
journal before publication. Close it and recover only against independently
established exact trust. No API truncates an incomplete suffix or silently
promotes an unacknowledged record into a trusted tip. If the independent mark
was not retained after successful fsync, operator reconciliation is required;
this component does not pretend those two stores form one atomic transaction.

Tests inject partial writes and full writes followed by an fsync-style error;
these establish software failure behavior, not physical power-loss guarantees.
Files use `O_NOFOLLOW`/`O_NONBLOCK`, directory checks, regular-file checks and an
exclusive advisory file lock. A second writer is refused. These controls do not
make a hostile owner unable to replace/rewrite the directory or ignore advisory
locks; the directory must remain exclusively controlled. Same-length malicious
concurrent writes are outside that model. Existing processes changing file
length are detected before appending and after replay.

## Bounded canonical format

The `SOURCE` file begins with eight bytes `BLSRCJ01` and the 32-byte genesis source
commitment. Each frame contains:

1. Eight-byte `BLSRCF01` tag and little-endian u32 payload length.
2. Payload: u32 canonical source-message length and those source bytes; u32
   header count and each exact 304-byte native header; u32 proof count and the
   ordered proofs.
3. Keccak-256 of the frame tag, encoded length and payload.

Each proof is deposit ID (32), domain (32), recipient (20), amount/sequence/inbox
count (three little-endian u64), one-byte sibling count, then 32-byte siblings.
All counts are checked before allocation. The full inbox remains capped at
4096, proof depth at 12, headers per frame at the core's 2048 limit. The frame
bound is derived from these maxima. Defaults and hard journal bounds are 10,000
records and 64 MiB total file bytes; callers may lower either budget. Byte totals
include file header and frame envelopes. No unbounded serde decoder is exposed.

`SourceMark` has its own exact tag `BLOCH:SOURCE:MARK:1`, then record count u64,
source commitment and anchor block (two 32-byte values), slot/height/inbox count
(three u64), and inbox root (32 bytes). Integers are little-endian. Its codec
provides transport only; decoding an attacker-selected mark grants no trust.

## Native activation seam

A `SourceBatch` is a **host envelope** anchored to an already identified native
header. Its commitment includes that header's block hash, which itself includes
the native state root. Storing this exact envelope as a leaf in that same state
would create a hash cycle. A future native lock/inbox commitment must be defined
independently of the enclosing header; authenticated inclusion can then derive
the host envelope after header verification. This crate assigns no such native
leaf, transaction tag, authority policy or activation epoch.

Run all registry, V2 and journal tests with the commands in [README.md](README.md).
The journal tests use actual temporary files and real core ancestry/inbox
verification, with synthetic checkpoint/source authority explicitly supplied.

## Historical source snapshots

`snapshot_at(&mut self, requested_mark)` reconstructs a historical source
registry only if that exact mark occurs in the journal's history **and the
entire file still validates through the instance's independently trusted current
tip**. It shares the same replay implementation as `open`; it does not open a
second writer, trust a requested prefix in isolation, or alter the live source
cursor. The mutable borrow serializes file seeks, and subsequent writes retain
`O_APPEND` behavior.

An absent/forged requested mark returns `SnapshotMissing` after confirming the
file is otherwise valid; it does not poison an intact journal. Corruption,
changed length, a different final tip, or replay I/O failure does poison the
instance. Even a valid alternate prefix with recomputed checksums is never
returned if the final trusted tip differs. This API supports later combined
settlement recovery, but does not itself persist or restore EVM consumption.
