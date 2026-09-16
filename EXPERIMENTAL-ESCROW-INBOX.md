# Experimental ordered escrow inclusion

The `experimental-escrow` feature now provides immutable `InboxSnapshot` values
from the kernel and from the authenticated `PqEscrow` facade. Records are ordered
by their original zero-based lock sequence, not by the intent hash used as the
kernel's lookup key. A snapshot can generate an `InboxProof` for each position.

This is an inclusion primitive, not finalized deposit derivation or EVM minting.
It does not add a consensus transaction or modify the live chain.

## Commitment format, version 1

All hashes are SHA3-256. Literal ASCII tags below have no trailing terminator.
Integers are little-endian, fixed-width u64. Fixed-width IDs are 32 bytes and
EVM recipients are 20 bytes. Concatenation follows the order shown:

* Leaf: `BLOCH:EXPERIMENTAL:INBOX:LEAF:1 || intent_id || domain || recipient || amount_sat || sequence`.
* Pair: `BLOCH:EXPERIMENTAL:INBOX:NODE:1 || left_hash || right_hash`.
* Empty tree: hash of `BLOCH:EXPERIMENTAL:INBOX:EMPTY:1` alone.
* Wrapped root: `BLOCH:EXPERIMENTAL:INBOX:ROOT:1 || network || domain || count || tree_hash`.

Each odd final node is promoted unchanged. The root binds the exact record count
so shape/count substitution cannot share the same wrapped root. Proof siblings
are bottom-up, omit promoted levels and contain no direction flags: directions
are derived from the authenticated sequence and count. Extra or missing siblings,
out-of-range positions and paths longer than 64 hashes are rejected. Count
reduction avoids overflow even for adversarial u64 counts.

## Trust boundary

`proof.verify(network, domain, expected_root)` requires the expected root from
an independent trusted source. Taking it from the proof sender proves nothing
about canonical chain state. The existing experimental state commitment remains
unchanged and is **not** this inbox root. No current Genesis-4 header commits this
new inbox format. Consensus integration must explicitly authenticate the inbox
root, network/domain and snapshot position before using inclusion for credit.

Membership is intentionally repeatable: calling `verify` twice does not consume
the deposit. Exactly-once EVM credit still requires an authenticated contiguous
derivation cursor committed atomically with execution. Inclusion of a single
record does not establish complete inbox delivery or prevent a sequencer from
omitting another record. Sequence numbers are not L1 heights or slots and must
not be substituted into the existing EVM deposit provenance fields.

Snapshot/proof construction copies the bounded local journal and costs O(n)
memory and hashing; proof verification costs O(log n), at most 64 levels. This
prototype is not a persistent incremental Merkle accumulator. A future transport
must bound decoding before allocation. Withdrawal authorization remains disabled.

## Validation

The [execution facade](EXPERIMENTAL-ESCROW-EXECUTION.md) now checks mandatory
contiguous inclusion and advances its local consumption cursor only after EVM
verification. It still requires host-authenticated L1 roots and source mappings;
the standalone membership API remains repeatable.

Four new tests exercise every position in trees of 0, 1, 2, 3, 5, 17, 32 and 65
records, all deposit fields, root/network/domain/count changes, malformed paths,
extreme counts and snapshot isolation. The real hybrid PQ funding test also
checks that its accepted lock produces a valid inclusion proof. These tests
exercise local correctness, not network finality or production bridge safety.

```sh
cargo +1.94.1 test --offline --locked --features experimental-escrow
cargo +1.94.1 check --offline --locked --no-default-features --features experimental-escrow
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-escrow-pq/Cargo.toml
```

## Reusable immutable proof index

Snapshots cache their wrapped root and all non-root Merkle levels at construction.
After the existing sequence sort, building those levels requires linear hashing
and retains O(n) hashes. Reading the root is O(1); producing a proof requires
O(log n) sibling lookups and output storage, with no reconstruction or rehashing
of the full tree. Reuse one snapshot for multiple proof requests; calling
`ledger.inbox()` again still constructs a new snapshot. Cloning a snapshot copies
its records and cached levels, so it is also O(n), not a cheap shared handle.

This changes local computation and memory use only. Domain separation, odd-node
promotion, count binding and proof serialization are unchanged. Compatibility
tests pin roots and odd-tail paths captured from the previous implementation,
while existing tests cover every position in even/odd trees, mutation rejection
and snapshot independence after new deposits. Cached roots remain local escrow
commitments and do not establish native finality or mint permission.

## Exact execution-prefix preparation

A producer can call `domain.required_deposit_range(snapshot.len() as u64)` and
pass the result to `snapshot.proofs(range)`. The domain uses the same mandatory
prefix rule as `verify_and_advance`: start at its next unconsumed deposit and take
up to the gas-derived limit (maximum 4,096). Shrinking known counts are rejected.
The snapshot returns the exact ordered set of independent inclusion proofs, with
no silent truncation; reversed, out-of-bounds or over-4,096 ranges are refused.
An empty range at the snapshot end is valid.

Both calls are read-only and allocate no reservation or consumption cursor.
This removes duplicated producer chunk arithmetic, not the trust boundary:
the verifier still requires independently authenticated root/count, real L1
locations and valid execution. A preview of a count alone never authenticates
the corresponding snapshot. These are ordinary proofs sharing a cached tree,
not a compressed Merkle multiproof.
