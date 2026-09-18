# Experimental source payload without a self-header hash

`SourcePayload` is a bounded **post-genesis** codec for a possible future native
state integration. No native state-component key, transaction tag or activation
rule is assigned. It neither verifies state inclusion nor authorizes a mint.

An anchored `SourceBatch` contains its current native block hash. Inserting that
entire envelope into the state root of the same block would make the header hash
depend on itself. The payload therefore retains the complete source data but
omits **only the current anchor's block hash**. The prior source commitment is
allowed: it identifies a previous source whose block hash is already known.

Network and native genesis identities must already exist. Height zero is rejected
by encoding, decoding, `from_batch` and binding. This format cannot be included
in the genesis header that defines its own `genesis` field, which would introduce
another circular dependency. Genesis activation requires a separately specified
policy; this codec does not invent one.

## Exact format

The canonical byte sequence starts with ASCII
`BLOCH:EXPERIMENTAL:SOURCE-PAYLOAD:1`, followed by:

| Field | Encoding |
| --- | --- |
| network, domain, genesis, previous anchored source commitment | Four raw 32-byte hashes |
| slot, height | Two little-endian u64 values |
| inbox root | Raw 32-byte hash |
| total inbox count | Little-endian u64 |
| mapping record count | Little-endian u32 |
| each complete mapping record | Sequence u64, intent hash32, native transaction hash32, height u64, transaction index u32, output index u32; all integers little-endian |

The two counts must agree, cannot exceed 4096, and sequences must be exactly
`0..count`. Byte length and record counts are checked before allocating decoded
records; trailing bytes, unknown tags and truncated input fail. There is no
unbounded serde decoding path. Network/domain/genesis must be nonzero, matching
the registry's existing identity requirements. Further mapping validity, inbox
proofs, source ancestry and conservation remain in their existing validators.

`commitment()` is Keccak-256 of the tagged bytes. It is intentionally different
from `SourceBatch::commitment()` and cannot be substituted for the registry's
externally authenticated anchored source commitment.

## Bind only after the native header is identified

`SourcePayload::from_batch(&batch)` strips the current block hash, preserving the
other fields. `payload.bind(position: HeightPosition)` checks the independently
derived position's genesis, slot and nonzero height, then inserts its block hash
to reconstruct `SourceBatch`. A position identifies ancestry; it does not prove
that a payload is included in that header's state or that the checkpoint is final.

Two valid competing block positions with the same genesis/slot/height therefore
produce the same payload commitment but different anchored batch commitments.
Binding alone permits this transport operation. The existing `SourceRegistry`
still requires its trusted expected anchored commitment, retained native ancestry
and full inbox proofs, and rejects an unauthorized or divergent branch.

The remaining native seam is an authenticated state-inclusion path for this
payload under the selected header, tied to a reviewed domain/escrow component and
source authority. No API here labels a bare payload hash or position as such a
proof. Existing synthetic tests and source journals retain their explicit trust.

## Conformance

Unit tests include a fixed byte vector, every truncated prefix, count/byte bounds,
mutations of every committed field, current-block-hash invariance, typed position
mismatches, height-zero rejection and a real registry/inbox proof check showing
that the payload commitment does not replace the anchored authority.

```sh
cargo +1.94.1 test --locked --offline \
  --manifest-path integrations/native-domain-devnet/Cargo.toml
```

Observed on 2026-09-17 with Rust 1.94.1: the complete crate passed 25 unit tests
(including all four payload cases) and both real execution integration tests,
27/27 total with none ignored. All-target Clippy with warnings denied and package
formatting checks passed. This qualifies the experimental codec and its existing
registry boundary, not native consensus activation or state inclusion.
