# Experimental native-domain source mapping

This standalone crate joins an **explicitly trusted experimental source
commitment** with real existing escrow inbox membership proofs and a
Genesis-4 ancestry-derived block position. It does not assign a native lock
transaction, activate consensus, authenticate finality, infer mint authority
from UTXOs, or change the native repository. No service here observes transfers
and turns them into EVM credits.

## Implemented boundary

`SourceRegistry::new(network, domain, HeightCursor)` starts with the canonical
empty experimental inbox at the configured native genesis. The cursor position must
be height zero and identify that genesis. `HeightPosition` has no public
claimed-height constructor: the existing `l1::height::HeightCursor` derives it
from complete parent-linked headers under an externally trusted checkpoint.
The PQ checkpoint reader can supply the same type. This proves identification
relative to the checkpoint authority, not finality itself.

`SourceRegistry::apply(expected_commitment, position, headers, batch, proofs)` checks:

- Network, execution domain, native genesis, and the exact derived
  `(block, slot, height)` position. Slot is never substituted for height.
- The independently authenticated source commitment, previous accepted source
  commitment, strictly advancing height and slot, and nonshrinking inbox.
- A complete native header path from the retained cursor to the supplied
  position. A valid position on a divergent branch of the same genesis is
  rejected; source hash chaining alone is not native ancestry verification.
- Complete ordered source locations and real inclusion proofs for **every**
  retained inbox leaf, including historical leaves.
- Exact equality of the historical location/deposit prefix. Valid inclusion
  proofs under a different tree cannot rewrite old locks.
- Intent/leaf identity, positive amounts, unique intent/output identities,
  lexicographic native positions, and a consistent transaction-ID-to-position
  mapping. New locations must belong to the current source anchor's height.

The authority must authenticate a complete experimental source record, including
its inbox root/count and native transaction locations. Passing the proposal's
own hash as `expected_commitment` is not authentication. Native header ancestry
and existing eUTXO proofs do not currently establish that experimental source
record or its escrow semantics. This missing native consensus/authority gate
remains explicit.

All rejection paths leave the registry unchanged. Accepted source progress does
not consume EVM deposits. `execution_batch(trusted_execution, range)` joins an
accepted source snapshot to a separately trusted `TrustedL1Batch`, checks exact
domain/anchor identity, and returns the existing `TrustedEscrowBatch` with only
the requested locations. It neither creates `DepositMint` nor authenticates
transaction DA. The existing escrow execution verifier still requires the exact
mandatory prefix and atomic EVM/witness verification before its cursor advances.
Source and EVM persistence are not implemented by this in-memory registry.

## Canonical codec

The byte message is exactly:

| Field | Encoding |
| --- | --- |
| Tag | ASCII `BLOCH:EXPERIMENTAL:SOURCE:1`, no terminator |
| network, domain, genesis, previous source commitment, anchor block | Five 32-byte hashes |
| anchor slot, derived height | Two little-endian u64 |
| inbox root | 32 bytes |
| inbox count | Little-endian u64 |
| location count | Little-endian u32 |
| each location | sequence u64, intent 32 bytes, native txid 32 bytes, height u64, transaction index u32, output index u32 |

All integers in a location are little-endian. The local commitment is Keccak-256
of this entire tagged message, not a native transaction ID. The decoder requires
one complete message, rejects unknown tags, truncation and trailing bytes, and
checks size/count bounds before allocation. There is no serde escape hatch.
Semantic verification remains separate from decoding.

The experimental lifetime inbox cap is **4096 locks**; every snapshot re-proves
the full prefix. This bounded O(n log n) policy avoids claiming an unimplemented
Merkle consistency proof. It is not a production capacity solution. Authorities
must publish each lock-bearing source height in order; newly adding a historical
location at a later anchor is rejected. Changing these rules requires a new
version/domain policy.

## Validation

```sh
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-domain-devnet/Cargo.toml
cargo +1.94.1 clippy --offline --locked --manifest-path integrations/native-domain-devnet/Cargo.toml --all-targets -- -D warnings
```

Validation on 2026-09-17: **10 unit tests and 2 execution integration tests passed**,
with no ignored cases; all-target Clippy with warnings denied also passed.

The standalone lockfile starts from the portable core's dependency versions;
no native/Reth checkout is required. Tests use synthetic funding and checkpoint
trust explicitly, but real `EscrowLedger`, inbox proofs, `HeightCursor`, and
source validation. They cover canonical codec limits, every truncated prefix,
identity/authority/ancestry, replay, incomplete snapshots, changed historical
leaves with otherwise valid proofs, slot/height confusion and unchanged state
on rejection, including a valid height position on a divergent native branch.
The integration test additionally joins source mapping to actual escrow/EVM
execution, exercises mandatory prefix chunks and invalid-witness atomic retry,
and compares minted balances and independently computed state roots. No mainnet funds, wallet keys or consensus rules are modified.

Remaining gates: native consensus-enforced locks and source commitment
inclusion, independently authenticated finalized checkpoint policy, durable
source replay with retained rollback protection, transaction DA derivation,
atomic integration with execution persistence, and withdrawal/release proofs.

## V2 selection for an independently verified execution

`validate_v2_prefix(spec, next_sequence, header, body)` returns a private-field
`ValidatedV2Prefix`. It requires exactly the next mandatory range, capped by
`min(gas_limit / deposit_gas, 4096)`, with each mint's recipient, amount, native
transaction and position equal to the accepted source mapping. It validates
canonical signed body bytes, header configuration/domain, transaction/deposit
roots, deposit gas accounting and the exact source anchor block.

The token binds source commitment, network/genesis/domain, inbox root/count,
anchor, range, canonical body commitment and an `ExecutionStatement` containing
configuration, parent state root and the complete V2 header hash. The existing
SP1 guest need not change: a host can compare authenticated proof public values
to `token.statement()`. This does not by itself verify a proof, receipt execution,
parent canonicality, native finality or source authority.

`next_sequence` must come from a separately retained settlement cursor. Selection
is deliberately read-only and repeatable; possession of a token is not a
single-use permit. A settlement host must atomically verify proof identity and
public values, ensure that token source/configuration/parent/cursor still match
its own state, and advance consumption exactly once. No such persistent host is
implemented by this module.

The V2 integration test demonstrates why the distinction matters: altered
recipient, amount and omitted deposits can produce valid real EVM/witness
execution statements, but this source selector rejects them. Successful chunks
and an empty suffix match actual V2 execution statements and conserved minted
balances. Unit negatives also bind header/post-state changes, malformed signed
bytes, domain/anchor, cursor bounds and unchanged registry state.
