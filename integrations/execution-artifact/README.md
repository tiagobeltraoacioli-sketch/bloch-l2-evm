# Execution witness transport

This small standalone crate transports a selected V2 block and sparse witness
between the isolated Reth and SP1 host dependency graphs. It does not include
either SDK and does not change the guest or execution statement format.

`ExecutionArtifact::new` and `decode` require independently selected chain
configuration and domain. They check canonical parent/header/body RLP, header
continuity, witness pre/post roots, then run the real stateless executor and
compare its full V2 header hash with the selected header. Context is derived
from that header; no second, inconsistent context object is accepted.

The private artifact exposes read-only header, body, witness, context and expected
statement accessors. It is checked execution input, **not** a cryptographic proof
capability. A receiver cannot use an arbitrary artifact as evidence that its
parent was selected, deposits were authorized, or an anchor was finalized. The
operator must independently choose the local canonical export; settlement still
requires its configured parent/program and actual proof verification.

## Envelope

The JSON envelope rejects unknown fields and requires format
`BLOCH:EVM:EXECUTION-ARTIFACT:1`. It contains configuration/domain commitments,
canonical RLP bytes for parent/header/body, and the core's serde `BatchWitness`.
JSON field ordering and whitespace are transport details, not consensus rules.
All RLP objects must consume their entire byte string and re-encode identically.

Input and serialized output are limited to 64 MiB; headers to 2048 bytes, and
the existing V2 body codec applies its own limits. Output writing stops at the
byte cap. The outer input cap is checked before JSON decoding; nested witness
vectors/strings are decoded within that input budget, not independently bounded
before each allocation. This is not a complete hostile-input memory/CPU sandbox.
Callers reading files must enforce the input cap before allocating the file.

## Reproduce

```sh
cargo +1.94.1 test --locked --offline --manifest-path integrations/execution-artifact/Cargo.toml
```

The transport tests exercise actual sparse-witness re-execution, round trips,
wrong configured identities, root corruption, RLP trailing bytes and malformed
envelopes. Reth export is documented in
[PROOF-EXPORT.md](../reth-execution/PROOF-EXPORT.md).

Local qualification on 2026-09-17 with Rust 1.94.1: all three transport tests
passed; all-target Clippy with `-D warnings` and package formatting passed.
This is host execution/transport evidence, not SP1 proof verification.
