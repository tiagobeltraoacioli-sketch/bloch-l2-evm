# Cancun KZG backend selection

The execution core keeps the exact `revm = 41.0.0` pin and Cancun rules in
both builds. Its default `host-kzg` feature enables `revm/c-kzg` and
`revm/portable`, preserving the previous native host backend. Disable default
features for the pure-Rust build. In revm 41, omitting both `c-kzg` and `blst`
selects the built-in arkworks KZG verifier. There is no `kzg-rs` feature in
this version. The Cancun point-evaluation precompile at `0x0a` remains
registered; absence of the C backend does not remove it.

`std` and `serde` are independent of backend selection. A guest dependency
should use `default-features = false, features = ["serde"]`. A native
comparison build can use `--no-default-features --features std,serde`.
Cargo features are additive: build the guest in an isolated workspace and
inspect its resolved feature graph. Any dependency that enables revm
`c-kzg` or `blst` overrides the arkworks selection. `--all-features` is a
host build, not a pure-Rust guest qualification.

The backend is a deliberate compiled-code difference, not a claim that host
and guest binaries are byte-identical. Both must implement the same Cancun
transition. Record the compiler, target, complete lockfile, resolved features,
guest source and ELF digest with the proving program identity. Backend or
compiler changes require rebuilding and qualifying the guest and updating its
verification key; they must not silently reuse an earlier program identity.
This change alone does not provide a zkVM entrypoint, proof verifier or proof
of native L1 provenance.

Run the same registered-precompile vectors in both configurations:

```sh
cargo test --locked --test kzg_backends
cargo test --locked --no-default-features --test kzg_backends
cargo check --locked --no-default-features --features serde --lib
```

The tests include all 122 point-proof verification cases from the pinned
[official Ethereum corpus](../tests/fixtures/kzg/README.md), including valid
proofs, false proofs and invalid encodings. They also cover the zero polynomial,
tampered proof and evaluation, out-of-field scalars, mismatched versioned
hash, input length, gas threshold and the exact successful return bytes.
They establish targeted backend parity; they are not a complete differential
audit or proof that the whole guest compiles for a particular zkVM target.
