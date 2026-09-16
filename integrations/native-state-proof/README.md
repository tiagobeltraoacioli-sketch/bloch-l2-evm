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

Seven integration tests use the official full consensus state builder and native
header codec with synthetic states/checkpoints. They cover exact UTXO values
including u64::MAX, every UTXO/EVM field, malformed/reversed/corrupted paths,
cross-component and cross-state substitution, historical inclusion after a spend
and a zero EVM commitment. These are state-proof correctness tests, not live
network finality or protocol-activation evidence. No wallet or network is used.
