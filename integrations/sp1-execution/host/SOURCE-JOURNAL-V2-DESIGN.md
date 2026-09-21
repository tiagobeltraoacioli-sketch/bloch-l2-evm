# Source settlement V2 journal design

## Status: implemented locally, not qualified — activation blocker

This document specifies the separate durable journal for source-bound settlement
V2 implemented in `src/source_journal_v2.rs`. The implementation coordinates a
V2 execution head, consumed source cursor and settlement predecessor as one
fsync-before-publication transition, but it is not qualified for activation.
The repository still lacks the mandatory genuine nonempty source-bound Groth16
artifact and the complete crash/fault-injection qualification matrix below.

The existing `SourceSettlementJournal` and its version-1 file format remain
legacy Core-proof infrastructure. They must not be reinterpreted, migrated in
place or presented as V2 settlement evidence. DEX, bridge, mint, release and L2
finality activation must remain fail-closed until the design below is
implemented, independently reviewed and qualified with genuine source-bound SP1
Groth16 artifacts.

## Security objective

One durable record must establish exactly one successor of all coordinated
state:

- the verified L2 execution head;
- the exclusive next source sequence;
- the exact authenticated source-journal snapshot used by the proof;
- the preceding accepted V2 settlement commitment; and
- the newly reconstructed `SettlementPayloadV2` and its commitment.

The predecessor, proof digest and proof-policy commitment must never be
caller-selected. The predecessor is derived from retained state. The digest is
Keccak-256 of the exact canonical 356-byte Groth16 verifier input exported by a
private `QualifiedGroth16SettlementV2` capability. The proof policy is also
derived from that same capability and the pinned SDK/verifier constants. Append
and replay must require exact equality with the locally recomputed policy; a
nonzero or caller-supplied policy is not sufficient.

All validation, proof verification, payload construction, commitment derivation
and frame encoding must complete before a write begins. In-memory state may be
published only after the complete record and checksum have been synchronized.

## Separate version and policy

The implementation uses the new `source_journal_v2.rs` module under the
existing Unix and `source-settlement` feature gates. It uses tags distinct from
every legacy format:

```text
BLOCH:LOCAL:SP1:SOURCE:SETTLEMENT:2
BLOCH:LOCAL:SP1:SOURCE:SETTLEMENT:MARK:2
```

The V2 policy and immutable file prefix must bind:

- the complete `ChainSpec` commitment;
- native network and native genesis identities;
- execution domain;
- canonical zero-funded V2 genesis header;
- Keccak-256 of the exact guest ELF;
- the SP1 KoalaBear verifying-key digest;
- the distinct SP1 BN254 program-key projection; and
- a nonzero, independently accepted proof-policy commitment.

The proof-policy commitment must ultimately cover the proof scheme and transport
version, SP1 circuit version, full Groth16 wrapper verifying-key commitment,
canonical proof length, and public-statement codec/hash policy. A four-byte
wrapper-key prefix is a selector, not a sufficient verifier identity. A local
journal policy does not replace the required versioned commitment in a future
consensus payload.

The payload codec accepted by this journal is fixed to
`BLOCH:EXPERIMENTAL:SETTLEMENT-PAYLOAD:2` and
`SETTLEMENT_PAYLOAD_V2_BYTES` (currently exactly 671 bytes). Version 2 is the
39-byte tag, one 32-byte proof-policy commitment and the canonical 600-byte V1
field suffix. The journal must reject the 639-byte V1 codec, any other tag or
size, and any V2 value whose policy differs from the capability-derived policy.
V1/V2 conversion, prefix matching or best-effort decoding is forbidden.

Opening a file under any different policy must fail. The legacy version-1 tag
must never be accepted as version 2.

## Retained state and rollback floor

The live journal state should contain:

- the exclusively locked regular file;
- immutable policy;
- `SettlementCursor`;
- `next_sequence`;
- the last exact `SourceMark`;
- `last_payload: Option<SettlementPayloadV2>`;
- expected file length and record count; and
- a poisoned-state flag.

`last_settlement` must be derived from the complete V2
`last_payload.commitment()` so two independent retained values cannot diverge
and a V1 payload can never become a V2 predecessor.

The independently stored rollback floor should contain the complete execution
mark, next sequence, exact source mark and optional settlement commitment. Its
fixed-width codec must use an explicit `has_settlement` byte:

- only `0` and `1` are valid;
- `0` requires a zero commitment and is valid only for the genesis state;
- `1` requires a nonzero commitment; and
- unknown tags, truncation and trailing bytes are rejected.

Floor fields should be private with read-only accessors. The floor is trusted
application input retained outside the journal. A mark read from the same file
cannot establish rollback protection.

At journal genesis, `last_payload` is `None`, the floor settlement commitment is
zero, the execution cursor is the exact canonical zero-funded L2 genesis and
`next_sequence` is zero. The L2 genesis is not itself a
`SettlementPayloadV2`. A
zero `previous_settlement` is valid only for the first accepted V2 record in
this journal; after that record, every successor must use the commitment of the
immediately preceding `SettlementPayloadV2`. The initial source journal may
already contain pending deposits, but none are consumed until a verified V2
record advances the cursor. Importing an arbitrary non-genesis execution head or
switching from a legacy journal in place is forbidden.

## Record framing

Each record should contain one canonical frame:

```text
SourceMark
header_length: u32 big-endian
body_length: u32 big-endian
NodeHeaderV2 canonical RLP
NodeBodyV2 canonical RLP
exact SDK fixed-integer Groth16 V2 artifact
```

The record envelope should reuse the reviewed legacy shape:

```text
frame_length: u32 big-endian
frame
keccak256(frame)
```

The payload should not be duplicated in the frame. Replay reconstructs it from
the cryptographically verified public statement and the digest of the canonical
356-byte proof. Avoiding duplicated statement, digest or payload bytes removes a
second representation that could disagree with the proof.

The exact source `SourceMark` in the frame authenticates which historical
`SourceRegistry` snapshot is selected. It is not interchangeable with the
statement's `source_commitment`, `inbox_root`, `inbox_count` or consumed range.
Those values are projections recomputed from the authenticated snapshot by
`validate_v2_prefix`; replay must compare the proof statement with those derived
projections and may not copy them from the frame or payload.

Required bounds include:

- header at most 2,048 bytes;
- body at most `MAX_NODE_BODY_BYTES`;
- Groth16 artifact at most `MAX_GROTH16_ARTIFACT_BYTES`;
- Groth16 artifact at least four bytes before strict decoding;
- both declared RLP lengths nonzero;
- V2 frame maximum exactly
  `MARK_BYTES + 8 + 2_048 + MAX_NODE_BODY_BYTES +
  MAX_GROTH16_ARTIFACT_BYTES`;
- outer record overhead exactly 36 bytes: four-byte length plus 32-byte
  checksum;
- checked arithmetic for all offsets and aggregate lengths;
- at most `MAX_JOURNAL_RECORDS`; and
- cumulative file size at most `MAX_JOURNAL_BYTES`.

RLP and fixed-integer bincode decoding must be exact and reject trailing data.
The verification module needs a fixed crate-private wrapper such as
`pub(crate) fn decode_groth16_settlement_v2_proof(bytes: &[u8])`, which delegates
only to the strict decoder with `SETTLEMENT_STATEMENT_V2_LEN`. It must not expose
an arbitrary public-length argument. The legacy Groth16 decoder for the short
execution statement is not interchangeable.

## Checked transition

Append and replay should share one pure preparation routine. Its trusted inputs
are the immutable policy, current cursor, authenticated source snapshot, current
next sequence, retained predecessor, selected header/body and verified program.
It must:

1. Validate the exact source prefix at `next_sequence`.
2. Derive the complete `SettlementStatementV2`, including predecessor, from
   retained state and the selected source snapshot.
3. Decode and cryptographically verify an SP1 Groth16 settlement V2 artifact
   under the exact trusted program.
4. Compare every public statement byte with the independently derived
   expectation.
5. Export and bound the canonical 356-byte verifier input.
6. Require the proof's complete Groth16 wrapper-key hash to equal SHA-256 of the
   complete pinned `GROTH16_VK_BYTES`, not merely its four-byte selector.
7. Compute Keccak-256 of the exact 356 bytes as `proof_digest`.
8. Derive the proof-policy commitment from the capability and pinned constants,
   then require exact equality with the configured journal policy.
9. Construct the inert `SettlementPayloadV2`, decode/encode it under the fixed
   V2 tag and size, and derive its commitment.
10. Advance a clone of the execution cursor.
11. Return the complete candidate state without mutating the live journal.

No public API may accept a predecessor, proof digest, proof policy, payload or
expected statement as authority. A caller may select a header/body and present a
private verified capability, but retained policy, pinned verifier constants and
state determine the accepted expectation.

## Creation, append and recovery

Creation must validate the current exact source-journal tip and policy, require
canonical unconsumed EVM genesis, then exclusively create the destination with
mode `0600`, `O_NOFOLLOW`, `O_NONBLOCK` and `create_new`. It must verify that the
opened object is a regular file, take an exclusive lock, write the immutable
prefix plus initial source mark, synchronize the file and then synchronize its
containing directory. Existing files must never be overwritten. The path and
parent directory remain trusted operator configuration; ancestor symlinks are
outside the final-component `O_NOFOLLOW` guarantee.

Failure during creation is fail-closed. The implementation must close and
unlock the handle without publishing a journal object. A partially created file
must not be deleted, truncated, resumed or treated as genesis automatically;
`create_new` must continue to refuse it, and a later `open` must reject its
truncated or unsynchronized manifest. Operator inspection and explicit removal
are required before retrying creation.

Append must:

1. Refuse a poisoned journal.
2. Confirm the on-disk length is unchanged.
3. Check record and cumulative byte limits.
4. Authenticate both the current source mark and the previously used exact
   source mark in the same independently opened source history.
5. Prepare the entire candidate transition and encoded frame without writing.
6. Recheck file length immediately before I/O.
7. Mark the object poisoned before seeking or writing.
8. Append length, frame and checksum, then call `sync_all`.
9. Publish cursor, next sequence, source mark, last `SettlementPayloadV2`,
   expected length and record count only after successful synchronization.
10. Clear the poisoned flag only after publication completes.

Any error after write initiation leaves the object poisoned. A poisoned object
must reject state getters and future appends.

Recovery must open read/write with `O_NOFOLLOW | O_NONBLOCK`, reject non-regular
files, and reject a file whose Unix permission bits grant any group/other access
instead of the required owner-private `0600` policy. It must enforce the
cumulative size bound before allocation and take an exclusive lock. It then
authenticates the immutable prefix and initial source snapshot and replays every
record from genesis. Every frame must repeat source ordering and
historical-snapshot checks, real Groth16 verification, exact public expectation
and proof-policy comparison, and complete candidate derivation. Stored source
marks cannot bootstrap source trust: the source journal must already be open
against an independently accepted exact tip.

Recovery succeeds only if:

- the complete external rollback floor is encountered exactly at genesis or a
  replayed state;
- the final file length is unchanged from the initially observed length;
- every record is complete, canonical and cryptographically valid; and
- all coordinated state is derived from the same sequence of accepted frames.

A completely synchronized suffix beyond an older floor may be recovered. A
partial write, bad checksum, trailing garbage or invalid proof must fail closed.
There is no automatic truncation, salvage, downgrade or rollback.

## Mandatory qualification tests

No implementation is complete without all of the following.

### Codec and bounds

- Mark round trip, every truncated prefix and trailing bytes.
- Unknown tag, invalid option flag, `None` with nonzero commitment and `Some`
  with zero commitment.
- Frame truncation at every boundary, zero and oversized lengths, integer
  overflow, trailing RLP and trailing bincode.
- Exact V2 payload tag and 671-byte size; V1-as-V2, V2-as-V1 and unknown-size
  cross-decoding all fail.
- Wrong proof mode and wrong public-statement length.
- Record-count and cumulative-byte limits.

### Genuine proof and state binding

- A genuine source-bound settlement V2 Groth16 proof with at least one deposit.
- Exact 356-byte proof digest, fixed digest golden vector and exact reconstructed
  `SettlementPayloadV2` commitment.
- Fixed proof-policy preimage/commitment golden vector covering scheme,
  transport length, circuit version, complete wrapper-key hash, statement codec
  and hash-policy labels.
- Full proof wrapper-key hash equals SHA-256 of the pinned complete verifier key;
  a matching four-byte prefix with a different full hash is rejected.
- Random nonzero policy values may be structurally decoded only by the inert
  codec and are rejected by the journal's exact capability-derived policy gate.
- Successful append consumes the source range exactly once.
- The same capability cannot be replayed.
- Zero, stale, sibling-fork and future predecessors are rejected.
- Source mutation after proof creation invalidates the stale expectation.
- Network, genesis, domain, ELF, both SP1 key representations and proof-policy
  mutations are rejected.

### Atomicity and failure behavior

- Every pre-write failure leaves file bytes, execution head, next sequence,
  source mark and last `SettlementPayloadV2` unchanged.
- Injected short write, write error and synchronization error poison the object
  and never publish candidate in-memory state.
- Partial creation at each write/sync boundary leaves no usable journal object;
  the leftover path cannot be resumed, truncated or overwritten implicitly.
- External file-length mutation poisons the live object.
- A fully synchronized record is recoverable after simulated process loss.
- Partial record, partial checksum and garbage suffix fail without repair.

### Replay and rollback resistance

- Reopening from the genesis floor recovers a complete valid suffix.
- Reopening from an accepted later floor recovers the same final state.
- Floors differing in execution number/hash/root, next sequence, source mark or
  settlement commitment are rejected.
- A source journal advanced beyond the selected snapshot can authenticate that
  historical snapshot.
- Another source handle with matching network/genesis/domain but conflicting
  history cannot replace the previously used exact source history.
- Concurrent/open-lock exclusion, final-component symlink/FIFO rejection,
  nonblocking behavior, mode `0600` and `create_new` refusal are exercised.

The proof used by these tests must not be a mock, digest echo or empty synthetic
envelope. A retained nonempty-deposit Groth16 settlement V2 artifact tied to the
source fixture is a prerequisite for qualification.

## Non-goals

This local journal does not create a native transaction, provide proof data
availability, authenticate a native checkpoint authority, establish native
finality, authorize bridge mint/release, enable DEX liquidity or satisfy the
future consensus proof-policy commitment. Completing this design removes only
the local durable-state gap; all other activation gates remain independent and
fail-closed.
