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
| program ELF Keccak, raw verifying-key hash | Two raw 32-byte commitments |
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
program_verifying_key_hash, proof_digest, previous_settlement)` copies the
existing read-only source selection and checks:

- the full canonical V2 header hash equals the selected execution statement;
- the header domain and previous state root equal that statement;
- the header's native anchor equals the selected source anchor; and
- the explicit nonzero chain ID is copied from that same validated header;
- all payload structural and cursor invariants hold.

The two program identities match the current SP1 host policy: Keccak-256 of the
complete selected ELF and the SDK `HashableKey::hash_bytes` digest of its
verifying key. The proof digest algorithm is exactly
`Keccak-256(canonical_proof_bytes)`. `proof_digest(bytes)` rejects empty input and
input above 32 MiB before hashing. Canonical proof bytes are the strict SDK 6.8.0
fixed-integer bincode bytes retained by the verifier; this crate deliberately
does not parse, canonicalize or verify them.

Both program hashes and the proof digest must therefore come from a future
verifier operating under independently accepted policy. The payload constructor
does not accept proof bytes and cannot verify a proof merely because its digest
is supplied. Likewise,
`ValidatedV2Prefix` establishes exact source/body selection under the current
experimental registry; it is not a single-use authorization token.

The existing SP1 host permits proof artifacts up to 32 MiB, while the audited
native block limit is 512 KiB. Its current Core artifacts are approximately 2.8
MiB. The pinned SDK also exposes a much smaller Groth16 wrapper, but the host
does not currently generate it and the native consensus path has no qualified
verifier for it. This payload embeds only the 32-byte proof digest and makes no
claim that any proof bytes are transported in a native transaction or block.
Proof data availability and validator-side deterministic verification need a
separate reviewed implementation before activation.

A native implementation must still verify the configured program and proof,
authenticate source/state inclusion and native ancestry, check the exact
accepted predecessor and parent, enforce replay protection, then atomically
publish the L2 head and consumed cursor. Only a reviewed consensus transition
can give this payload settlement effect. A later checkpoint/finality policy must
separately prove what accepted settlements qualify; this codec never labels an
L2 block safe or finalized.

## Conformance

Tests cover the canonical field order, exact round trip, every truncated prefix,
unknown prefix, trailing bytes, mutation of every committed field, both program
identities, explicit chain ID, exact proof hashing and byte bound, zero identity,
invalid slot/cursor ranges, and construction from an actually validated V2
source prefix. A mutated header is rejected even when all caller-supplied
identities remain unchanged.

```sh
cargo +1.94.1 test --locked --offline \
  --manifest-path integrations/native-domain-devnet/Cargo.toml
cargo +1.94.1 clippy --locked --offline \
  --manifest-path integrations/native-domain-devnet/Cargo.toml \
  --all-targets -- -D warnings
```
