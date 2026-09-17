# SP1 compiler qualification

This records the experimental compiler qualification for the V2 execution guest.
It does not establish a working prover, accepted proof, or production program
identity. Native node compilation remains pinned by its existing toolchain files.

The SP1 CLI under evaluation is **v6.8.0**, with the
`riscv64im-succinct-zkvm-elf` guest target. The older `riscv32im` placeholder in
`src/stubs.rs` is not a deployed program or a compatibility commitment.

## Verified macOS x86_64 artifacts

Downloads were checked against the SHA-256 digests returned by the official
GitHub release API. These checks establish correspondence with those release
assets, not an independent signature or source reproducibility audit.

| Artifact | Release | SHA-256 |
|---|---|---|
| `cargo_prove_v6.8.0_darwin_amd64.tar.gz` | [SP1 v6.8.0](https://github.com/succinctlabs/sp1/releases/tag/v6.8.0) | `7c585d641be8b380db919a64f82c99bf932223cef3bf155f48b279c408a249d5` |
| `rust-toolchain-x86_64-apple-darwin.tar.gz` | [succinct-1.94.0-64bit](https://github.com/succinctlabs/rust/releases/tag/succinct-1.94.0-64bit) | `2fdc61cb2a3984a0ec45beac9fff173dfdbc15c282cd2d08ab4ee7ec475a9b1a` |
| `rust-toolchain-x86_64-apple-darwin.tar.gz` | [succinct-1.96.0-64bit-v2 (prerelease)](https://github.com/succinctlabs/rust/releases/tag/succinct-1.96.0-64bit-v2) | `a5909912d18c076677a130aeb1cabff07e2302fa6e9c0b4b085da28207eb5228` |

`cargo-prove prove --version` reports
`cargo-prove sp1 (58c4aea 2026-09-11T06:26:56.604139000Z)`.
The 1.94 compiler reports `rustc 1.94.0-dev` / LLVM 21.1.8;
the prerelease reports `rustc 1.96.0-dev` / LLVM 22.1.2. Both report an unknown
Rust commit hash, making the release archive digest particularly important.

## Minimum compiler compatibility

The core, Alloy consensus 2.2.0, Alloy EIPs 2.2.0 and the resolved Alloy
transaction macros require Rust 1.94.1. The official 1.94.0-dev compiler rejects
the locked core before compilation. Do not lower package requirements or use
`--ignore-rust-version` to describe this compiler as supported.

The separately extracted 1.96 prerelease passed the locked core cross-target
check with `serde` and no default features on 2026-09-17 (1m 13s), without
replacing the user's default Rust installation. To reproduce the check,
set `BLOCH_SP1_RUSTC` to its extracted `bin/rustc` and run from the core root:

```sh
RUSTC="$BLOCH_SP1_RUSTC" \
CARGO_TARGET_DIR=target/sp1-core-preflight \
CARGO_BUILD_JOBS=2 \
cargo +1.94.1 check --locked --offline --no-default-features --features serde \
  --target riscv64im-succinct-zkvm-elf
```

This checks target compatibility only. A successful check does not link a guest
ELF, establish compatibility with the SP1 runtime/prover, or validate a proof.
The guest must retain an isolated workspace to prevent native `host-kzg`
feature unification; see [KZG backends](KZG-BACKENDS.md). Its eventual program
identity must bind its exact lockfile, compiler, features and ELF, with real
execution and accepted/rejected proof tests before any verifier is trusted.
