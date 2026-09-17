# Native Genesis-4 state inclusion adapter

This experimental AGPL-3.0-or-later integration verifies typed state observations
with the actual `bloch-pos-committee::state_root::verify_inclusion` implementation.
It is read-only and separate from the portable EVM crate's dependencies/license.
It does not activate consensus rules or make the experimental inbox native.

## Authenticated path

```text
Externally trusted finalized checkpoint
  → authenticated Genesis-4 header ancestry and complete target body
  → target header's state root
  → official 256-level SHA3 sparse Merkle inclusion verification
  → typed native-state observation with block, slot, root and checkpoint
```

Both APIs require an existing `AuthenticatedBody`, whose fields are private and
which can only be produced through the header/body verifier. They do not accept
an arbitrary RPC state root as a replacement for that provenance. The checkpoint
itself is still externally authenticated; this integration does not verify FFG
votes, validator-set evolution or weak-subjectivity bootstrap.

The [hybrid checkpoint adapter](../native-escrow-pq/CHECKPOINTS.md) can now supply
that anchor after checking a native envelope against independently trusted
signers and the exact checkpoint header. This replaces unchecked signer claims
with real signature verification, while retaining weak-subjectivity trust.

## Persisted checkpoint reader (Unix)

`checkpoint_reader::read_utxo` and `read_evm_commitment` compose the complete
read-only path rather than requiring callers to assemble its trust boundary:

```text
CheckpointStore + caller-supplied current epoch
  → recheck real ML-DSA-65 + Falcon-1024 signatures and WS freshness
  → authenticate the exact checkpoint header and complete transaction body
  → verify native state inclusion using the official consensus implementation
  → CheckpointObservation<T>
```

The reader accepts exactly one header, which must be the latest stored signed
checkpoint block. It does not accept an ancestor's state as the checkpoint's
state. The observation exposes the typed state, checkpoint epoch, epoch at which
freshness was checked, signed digest and signer-arrangement review flag. Its
fields are private. Reads do not advance or mutate the checkpoint store.

Before cryptographic work, requests must have a 304-byte header, exactly 256
siblings, at most 4,096 transactions and at most 16 MiB of transaction bytes.
Transport decoders must independently enforce these bounds before allocating.
Empty, poisoned, future or stale stores cannot supply observations. Store
recovery and rollback protection are documented in
[CHECKPOINT-STORE.md](../native-escrow-pq/CHECKPOINT-STORE.md); callers must retain
an independent minimum checkpoint mark when reopening to detect acknowledged
history loss.

The current epoch and signer policy remain trusted inputs. A checkpoint within
the 2,016-epoch weak-subjectivity window can still lag the network head; that
window is not a deposit-crediting freshness policy. The result proves state at
the named checkpoint, not present unspentness, independently verified FFG,
agreement between independent operators or permission to mint. Revalidate for
each decision and apply the application's separate freshness/finality policy.

### Genesis-derived height identification

`checkpoint_reader::read_utxos_with_height` adds a block-height annotation to
the existing authenticated batch reader. Its `HeightCursor` is initialized with
an independently configured **genesis block hash** and the exact genesis header;
that hash is not the checkpoint policy's genesis/state root. There is no input
for a claimed starting height. The configured genesis starts at height zero.

Each call supplies a complete forward header chain including the cursor's
previous block and ending at the latest stored PQ-signed checkpoint. Every
parent link and increasing slot is verified. Height increases by the number of
parent edges, not by slot differences: slots `0 → 7 → 100` give heights
`0 → 1 → 2`. At most 2,048 exact 304-byte headers are accepted per call; empty,
oversized or incorrectly sized paths fail before signature work. As elsewhere,
transport must enforce limits before allocation.

The reader authenticates the checkpoint's complete body and every requested
UTXO proof through `read_utxos`, then publishes the candidate cursor only after
the full path check succeeds. Omitted ancestors, conflicting forks, repeats,
stale checkpoints, body tampering and a later invalid UTXO proof leave the cursor
unchanged. The checkpoint store remains read-only. The result retains the
existing state observation and signed checkpoint provenance alongside a private
height position bound to the same block and configured genesis.

This is a concrete consumer for identifying native observations by block height
without inventing a slot-to-height conversion. It does **not** turn the observed
UTXO into a lock, derive an intent-to-transaction mapping, produce
`TrustedEscrowBatch`, prove completeness of all deposits or authorize an EVM
mint. Those consensus/inbox/source-mapping requirements remain open.

The cursor is in-memory and monotonic, with no arbitrary-height deserialization
or checkpoint import. It is not a durable rollback-protected index. Repeated
queries at the same checkpoint use the existing `read_utxos` API; the annotated
variant requires forward progress. Starting from a fresh genesis cursor cannot
skip to a checkpoint more than 2,047 blocks away, and missing intermediate
authenticated checkpoints are not bypassed. Catch-up requires an available
sequence of authenticated advances satisfying both the path bounds and the
checkpoint reader's freshness policy; supplying a historical epoch as though
it were the current epoch is not an authorized bootstrap shortcut.
Durable bootstrap/recovery of this
identification cursor remains a separate task; no persisted height is silently
trusted.

### Atomic UTXO batches

`checkpoint_reader::read_utxos` accepts 1–256 borrowed `UtxoRequest` entries.
It authenticates the checkpoint signatures and complete block body once for the
whole batch, then verifies each independent native SMT path against that same
state root. Results preserve request order and carry the same checkpoint digest
and checked epoch. If any proof fails, the call returns an error without exposing
partial results or mutating the store.

Duplicate outpoints are rejected even when the claimed values differ. Batch size
and every path length are checked before PQ verification; the maximum sibling
payload is 2 MiB, in addition to the existing body limit. This is a bounded list
of ordinary inclusion proofs, not a compressed Merkle multiproof. Each call
rechecks checkpoint freshness. The API neither enumerates all wallet outputs
nor proves a complete balance, and does not turn verified outputs into escrow
funding or mint authority.

`verify_utxo` uses the official `eutxo_leaf` codec to authenticate the native
transaction ID, output index, exact u64 value and script hash. It proves that
the output belongs to the committed unspent set **at the observed block**.
It does not prove current unspentness, key possession, noncustodial escrow or
eligibility for an EVM mint. Invalid inclusion is not an absence/spent proof.

`verify_evm_commitment` authenticates the already-existing native singleton
component `0x10`. Its canonical value is exactly 80 bytes:

| Offset | Field | Encoding |
| --- | --- | --- |
| 0 | Account trie root | 32 bytes, Keccak-MPT root |
| 32 | Receipts trie root | 32 bytes, Keccak-MPT root |
| 64 | Gas used | u64 little-endian |
| 72 | Base fee | u64 little-endian, native field documented in satoshi/gas |

The key is SHA3-256 of `DS_STATE || 0x03 || 0x10`; the value hash is SHA3-256
of `DS_STATE || 0x04 || canonical_value`. `DS_STATE` comes from the official
crate. The adapter implements only this fixed value/key encoding; the actual
leaf/path verification is delegated to consensus. Tests compare this encoding
against the official full `build_state_tree` builder, which uses its own private
EVM serializer. The native fee field must not be confused with the modular EVM
header's wei/gas field or the native fee-market singleton's millisatoshi/gas.

## Existing EVM leaf is not the experimental inbox

At the inspected native revision, `state_root.rs` commits this EVM leaf and
`genesis.rs` initializes its four fields to zero. Inclusion proves what the
chain commits; it does not establish that an EVM segment actually executed.
A valid all-zero commitment remains observable without being called active EVM.

The experimental escrow inbox has no assigned native state component, consensus
codec or activation rule. It must not be placed into the existing EVM singleton
or treated as equivalent to an account/receipts root. An ordinary UTXO payment
likewise must not be promoted to `TrustedEscrowBatch` just because its membership
verifies. The adapter deliberately returns no mint authorization or withdrawal
permission, and does not modify the local operator CLI's L1 trust boundary.

Native integration still needs consensus-enforced lock transitions, a committed
domain/inbox record, source mapping and authenticated ancestry/finality before
the external trust files can be replaced by independently verified derivation.
Slots remain slots; no L1 height mapping is invented here.

## Bounds, reproducibility and validation

Paths require exactly 256 siblings in root-to-leaf order. Wrong lengths are
rejected before allocating the native proof object. Each sibling is 32 bytes;
leaf data is fixed-size. Future transport must enforce bounds before allocation.
Observation fields are private and expose only read-only accessors.

Use Rust 1.94.1, the committed lockfile and a sibling `bloch-validator-payout`
checkout at revision:

```text
5af78a04a27dcb2c2253c32134fca888a8a965f9
```

The Cargo path dependency does not pin the checkout automatically. Verify it
before building. From the modular execution repository root:

```sh
git -C ../bloch-validator-payout rev-parse HEAD
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-state-proof/Cargo.toml
```

Fifteen integration tests use the official full consensus state builder and native
header codec with synthetic states/checkpoints. They cover exact UTXO values
including u64::MAX, every UTXO/EVM field, malformed/reversed/corrupted paths,
cross-component and cross-state substitution, historical inclusion after a spend
and a zero EVM commitment. Five end-to-end cases additionally use disposable real
hybrid signing keys and a persisted/reopened checkpoint store: successful typed
reads and provenance, empty/stale/future rejection, pre-spend state substitution
after a newer checkpoint, body/value tampering and early request bounds.
Three batch cases additionally cover request order and shared provenance,
failure after a valid first entry, expiry, duplicate outpoints with altered values,
empty/oversized batches and malformed later paths.
These are state-proof correctness tests, not live
network finality or protocol-activation evidence. No wallet or network is used.
