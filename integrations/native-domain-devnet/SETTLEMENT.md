# Dormant native settlement payload

`SettlementPayload` is the canonical, fixed-width candidate message for a
future native settlement transition. It implements no transition. In particular,
it assigns no native transaction tag, state-component key, activation epoch,
proof verifier, authority or finality rule. Its ASCII prefix distinguishes this
experimental codec only; it is not a reserved native consensus tag.

The payload closes the data-shape gap identified by the
[native-domain activation proposal](../../docs/NATIVE-DOMAIN-ACTIVATION-PROPOSAL.md):
one message binds native network/genesis, execution domain/configuration and
chain ID, both program identities and the proof digest, settlement and L2
predecessors, the complete L2 head result, native anchor, authenticated source
snapshot, inbox cursor range and body commitment. Hashing or decoding that
message authenticates none of those inputs.

## Canonical format

The byte sequence starts with ASCII
`BLOCH:EXPERIMENTAL:SETTLEMENT-PAYLOAD:1`, with no terminator, followed by:

| Field | Encoding |
| --- | --- |
| native network, native genesis | Two raw 32-byte identities |
| execution domain, configuration commitment | Two raw 32-byte commitments |
| program ELF Keccak, KoalaBear verifying-key hash, BN254 verifying-key projection | Three raw 32-byte commitments |
| verified-proof digest | Raw 32 bytes |
| previous settlement commitment | Raw 32 bytes |
| EVM chain ID | Little-endian u64 |
| L2 number | Little-endian u64 |
| L2 parent header, previous state, full header, post-state | Four raw 32-byte commitments |
| native anchor block | Raw 32 bytes |
| native anchor slot, derived height | Two little-endian u64 values |
| accepted source commitment, inbox root | Two raw 32-byte commitments |
| inbox count, consumed start, consumed end | Three little-endian u64 values |
| canonical V2 body commitment | Raw 32 bytes |

The format has exactly `SETTLEMENT_PAYLOAD_BYTES` bytes. The decoder accepts
only that size and version, has no allocation or serde path, and rejects every
truncated prefix and all trailing data. Every identity/commitment except the
previous-settlement field must be nonzero; zero in that field is the sole codec
representation of no accepted predecessor. Chain ID, L2 number and native
height must be nonzero, native slot must not be below derived height, and the cursor must satisfy
`start <= end <= inbox_count`. An empty consumed range is valid because
a block with no newly available deposits can still be an execution successor.

`commitment()` is Keccak-256 over the complete tagged encoding. It is a candidate
payload commitment, not a native transaction ID, proof receipt or finality
certificate. `previous_settlement` makes succession explicit and permits zero
only so the first accepted settlement can represent the native state's `None`;
this dormant codec has no retained state and cannot determine whether that use
of zero is valid, whether a nonzero predecessor is the accepted tip, or whether
a payload is a replay.

## Construction boundary

`from_validated_prefix(selected, header, program_elf_keccak,
program_vkey_koalabear, program_vkey_bn254, proof_digest,
previous_settlement)` copies the
existing read-only source selection and checks:

- the full canonical V2 header hash equals the selected execution statement;
- the header domain and previous state root equal that statement;
- the header's native anchor equals the selected source anchor; and
- the explicit nonzero chain ID is copied from that same validated header;
- all payload structural and cursor invariants hold.

The three program identities match the current SP1 host policy: Keccak-256 of
the complete selected ELF, the SDK `HashableKey::hash_bytes` KoalaBear digest,
and the separate `HashableKey::bytes32_raw` BN254 projection required by the
Groth16 verifier. Those two verifying-key values are not interchangeable. The
proof digest algorithm is exactly
`Keccak-256(canonical_proof_bytes)`. `proof_digest(bytes)` rejects empty input and
input above 32 MiB before hashing. Legacy Core prototypes retain strict SDK
fixed-integer bincode bytes. Settlement V2 Groth16 uses the SDK's exact 356-byte
on-chain verifier encoding. This crate deliberately does not parse, canonicalize
or verify either representation.

Both program hashes and the proof digest must therefore come from a future
verifier operating under independently accepted policy. The payload constructor
does not accept proof bytes and cannot verify a proof merely because its digest
is supplied. Likewise,
`ValidatedV2Prefix` establishes exact source/body selection under the current
experimental registry; it is not a single-use authorization token.

`ValidatedV2Prefix::select_settlement_v1` is the stricter bridge to the dormant
native kernel. It derives the complete `SettlementStatementV2` from the selected
source, exact L2 header, immutable `SettlementPolicyV1` and the supplied
`SettlementRegistryV1`; callers cannot inject individual statement or accepted
head fields. The registry's policy commitment must match. For the first settlement it
requires the configured initial L2 parent/state and cursor zero. For successors
it derives both predecessor commitments and requires contiguous L2 height,
parent header/state, consumed cursor, nonregressing inbox and native anchor.
Only then does it return a private-field `ValidatedSettlementSelectionV1`, which
can frame exact proof bytes for the kernel. The kernel still independently
repeats policy, successor and cryptographic proof verification.

This composer does not strengthen the authority behind `ValidatedV2Prefix` and
does not make a proof valid. It assigns no Genesis-4 wire tag or state component,
and cannot replace checkpoint/source authentication or validator execution.
On Unix, `ValidatedSettlementSelectionV1::verify_and_commit` frames the exact
proof bytes and sends the matching transaction/expectation directly through
`SettlementStoreV1`'s CAS and durable publication path. The returned mark must
be retained independently for rollback detection. This persists the local
settlement head, consumed cursor and exact transaction; it does not persist the
source registry, authenticated body artifacts or checkpoint authority, and it
provides no atomic transaction spanning the separate source journal.

The stricter `verify_inclusion_and_commit` path accepts no free proof bytes. It
consumes an `AuthenticatedSettlementInclusionV1` previously refined from a
complete authenticated Genesis-4 body, requires its statement to equal this
selection and passes those exact included bytes to the same store/kernel. Its
`PersistedSettlementAdmissionV1` result keeps the accepted head, new external
mark and durable admission receipt together. The same create-once record stores
the exact transaction, containing block/slot, checkpoint, transaction index and
admission commitment and validates their cross-links on recovery. The complete
body, header/ancestry path and authenticated checkpoint-authority artifact must
still be retained independently; stored coordinates are not a finality
capability. The core `TransactionInclusionEvidenceV1` format can canonically
retain and reauthenticate that body and ancestry path, but it is not atomically
stored here and deliberately does not authenticate checkpoint authority.

The existing SP1 host permits Core artifacts up to 32 MiB, while the audited
native block limit is 512 KiB; current Core artifacts are approximately 2.8 MiB.
The isolated settlement V2 harness can generate and reverify the smaller
Groth16 wrapper offline, and its capability exports the exact 356-byte verifier
input. Native consensus still has no activated transaction, retained state or
qualified verifier path. This payload embeds only the 32-byte proof digest and
makes no claim that proof bytes are transported in a native transaction or
block. Proof data availability and validator-side deterministic verification
still require separate reviewed integration before activation.

A native implementation must still verify the configured program and proof,
authenticate source/state inclusion and native ancestry, check the exact
accepted predecessor and parent, enforce replay protection, then atomically
publish the L2 head and consumed cursor. Only a reviewed consensus transition
can give this payload settlement effect. A later checkpoint/finality policy must
separately prove what accepted settlements qualify; this codec never labels an
L2 block safe or finalized.

The legacy SP1 guest statement remains the 149-byte `ExecutionStatement` and is
insufficient for native settlement. The separate settlement guest publishes the
fixed-width, version-tagged `SettlementStatementV2`. It binds every payload field
except `proof_digest`, which cannot be included in the proof's own public input
without a circular dependency. `SettlementPayload::from_unverified_statement_v2`
is deliberately named as a low-level value conversion: it does not establish
that either the public statement or digest was verified. The SP1 host's
aggregated V2 transition is the safe composition boundary and derives the digest
from its private Groth16 capability.

`BLOCH:EXPERIMENTAL:SETTLEMENT-PAYLOAD:2` is now a separate inert codec; V1 is
unchanged. V2 adds a proof-policy commitment fixing `SP1_GROTH16`, the exact
356-byte verifier input, the SP1 circuit-version string, SHA-256 of the complete
wrapper verifying key, the settlement-statement V2 tag and Keccak-256 of its
canonical bytes. The host derives the version and full 492-byte key directly
from the pinned SP1 6.8.0 crates. The four-byte wrapper-key prefix remains only
a selector and is not accepted as the full key identity.

This closes the codec/composition gap only. Consensus activation still requires
the native verifier, authenticated inputs, durable atomic cursor and retained
qualification evidence described above.

The settlement V2 guest commits, but does not authenticate, native-origin
network/genesis, anchor, source snapshot, inbox and cursor inputs. The host must
compare all public bytes with an independently selected expectation, and native
consensus must authenticate those same inputs and enforce predecessor continuity.
The Core and Groth16 verification capabilities are distinct; only the dedicated
Groth16 settlement V2 capability exports the exact 356-byte verifier input. None
of these additions assigns a native tag, activates settlement or establishes
native finality.

## Conformance

Tests cover the canonical field order, exact round trip, every truncated prefix,
unknown prefix, trailing bytes, mutation of every committed field, all three program
identities, explicit chain ID, exact proof hashing and byte bound, zero identity,
invalid slot/cursor ranges, and construction from an actually validated V2
source prefix. The integration path composes three consecutive selected L2
blocks through the actual settlement registry, including an empty deposit
suffix, and rejects cross-domain policy, a stale registry and empty proof
transport. The Unix path also rejects a forged CAS mark and a verifier-rejected
proof without advancing, durably commits all three valid successors, then
reopens from an independently retainable earlier floor and recovers the exact
tip. Each valid successor uses exact bytes at index one of a complete synthetic
Genesis-4 body whose containing slot strictly follows the source anchor. A
mutated header is rejected even when all caller-supplied identities remain unchanged.

```sh
cargo +1.94.1 test --locked --offline \
  --manifest-path integrations/native-domain-devnet/Cargo.toml
cargo +1.94.1 clippy --locked --offline \
  --manifest-path integrations/native-domain-devnet/Cargo.toml \
  --all-targets -- -D warnings
```
