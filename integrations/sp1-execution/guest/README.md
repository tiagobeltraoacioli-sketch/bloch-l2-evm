# Synthetic developer SP1 guest

This isolated workspace defines an experimental **synthetic-dev** SP1 6.8.0
program. It compiles `ChainSpec::testnet()` (chain ID 700771) and the domain
`0xd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3`
into the program. There is no input for an arbitrary trusted configuration.
Changing the core source, configuration, domain, dependencies, features or
compiler changes the program that a verifier must identify and trust.

The guest linked successfully on 2026-09-17 using SP1 CLI 6.8.0 and the
checksum-verified `succinct-1.96.0-64bit-v2` compiler. The initial release build
took 3m 08s with two build jobs. After the core's height-identification module
was added, the guest was rebuilt successfully in 17.07s; its current local
ELF SHA-256 is
`39d78301107d0b2550355894dff4ce57e5762c7e6ed72fbb1766d9b6af80cbf2`.
The local SDK subsequently executed both the empty and signed-contract fixtures
successfully and rejected false post-state roots and trailing body bytes.
The release CPU host also generated and independently verified a real core
proof for both the empty and signed-contract fixtures, rejecting tampered proofs
and mismatched expected statements.
See the [host qualification results](../host/README.md) for proof checks and
measured costs. These runs do not establish bit-for-bit reproducibility on
other machines or authenticate native L1 deposits.
Compiler qualification and artifact checks are recorded in
[SP1-TOOLCHAIN.md](../../../docs/SP1-TOOLCHAIN.md).

The CLI expects a `succinct` rustup toolchain alias. After verifying and
extracting the compiler archive, link that alias to its extracted directory
without changing the default toolchain, then run from this directory:

```sh
CARGO_BUILD_JOBS=2 cargo prove build --locked
```

The executable is produced at
`target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest`.
Build output is ignored by version control; the source and lockfile are tracked.

The same build also produces the separate settlement program at
`target/elf-compilation/riscv64im-succinct-zkvm-elf/release/settlement_v2`.
These are different programs with different verification keys. A proof or key
for one must never be accepted for the other.

## Input frames

The caller supplies exactly these three SP1 input frames in order:

1. `BatchWitness`, using SP1 6.8.0's `SP1Stdin::write(&witness)` serialization
   (bincode as consumed by `sp1_zkvm::io::read`).
2. `BlockContext`, using `SP1Stdin::write(&context)` in the same format.
3. Canonical `NodeBodyV2` RLP bytes, produced by `alloy_rlp::encode(&body)` and
   supplied with `SP1Stdin::write_vec(body_bytes)`. This frame is raw bytes,
   **not** bincode serialization of a vector. The guest reads `io::read_vec`,
   runs the bounded V2 decoder and rejects trailing bytes within this frame.

The core's locked serde types define the first two private input formats;
they are not a stable independent network protocol. The body uses the tagged
`BLOCH:EVM:BODY:2` format. Its decoder applies count and byte bounds before
execution. Witness deserialization is not a separately bounded network ingress;
prover services must enforce resource limits before accepting untrusted jobs.
Unused extra SP1 input frames are not public commitments or authorization.

### Settlement V2 program

`src/bin/settlement_v2.rs` is a separate four-frame guest. Its first three
frames are identical to those above; frame four is the serde encoding of
`SettlementContextV2`. The context carries native network/genesis, exact ELF
and both SP1 key identities, predecessor, native anchor metadata, source/inbox
commitments and the consumed cursor range.

The guest checks the range shape and deposit count, re-executes the block, and
publishes the fixed 590-byte `SettlementStatementV2`. That statement binds all
settlement payload fields except `proof_digest`: a proof cannot include a digest
of its own final bytes without a circular dependency. The host adds that digest
only after successful verification.

Native-origin context remains prover input until a verifier compares every
public byte with an independently authorized expectation. The guest does not
prove native ancestry, checkpoint finality, source-state inclusion, custody or
single-use consumption merely by committing those values.

The guest runs the actual `execute_statement` / `verify_node_batch` path:
authenticate sparse pre-state, authenticate signed transactions, re-execute,
verify the resulting state root, and derive the complete V2 header hash.
Any decode or execution failure aborts before committing public bytes.

## Public bytes and trust boundary

The guest calls `commit_slice` exactly once with `ExecutionStatement::encode()`.
The public stream therefore contains the ASCII tag `BLOCH:EVM:EXECUTION:1`
followed by four raw 32-byte commitments: complete chain configuration,
execution domain, previous state root, and full V2 header hash. It contains no
bincode length prefix. See the core's `proof_statement` module for exact layout.

A verifier must first verify an actual proof against an independently
trusted key for this exact program, then compare the authenticated public bytes
with an expected statement constructed from trusted configuration, parent state
and canonical block selection. Comparing public bytes alone is not a proof.
Prover-selected context or deposit provenance does not establish native Bloch
finality, authorized deposits, escrow conservation or settlement. This guest
only covers execution under the explicitly synthetic developer domain.

The isolated workspace disables the core's default `std` and `host-kzg`
features and retains Cancun's pure-Rust arkworks point-evaluation precompile.
It does not disable the precompile or enable a native C backend. The SP1 runtime
itself supplies its guest runtime support with its explicit `lib` feature.
SP1 still enables `std` and auxiliary features on some shared dependencies
(including rand, SHA-2 and tracing); disabling the core's `std` feature does not
mean the entire guest dependency graph is `no_std`.
Proof mode is selected by the host, not by either guest. The legacy local
journal continues to accept Core proofs only. The isolated settlement V2 host
harness can request and verify a Groth16 wrapper for offline qualification;
Plonk remains unsupported and no proof mode activates native consensus.

The committed guest lockfile was seeded from the core lockfile before resolving
SP1. Target-filtered metadata confirmed that every package identity/version in
the core's non-development dependency closure remains present in the guest's
core closure. SP1 adds packages and enables shared features; this is not a
claim of an identical feature graph. Future updates must preserve this version
check and requalify the resulting program, rather than regenerate an unrelated
lockfile with newer transitive execution dependencies.

API references are pinned to the upstream
[SP1 6.8.0 example](https://github.com/succinctlabs/sp1/blob/v6.8.0/examples/fibonacci/program/src/main.rs)
and [SP1 6.8.0 I/O implementation](https://github.com/succinctlabs/sp1/blob/v6.8.0/crates/zkvm/lib/src/io.rs).

## Reproducible build and pinned identity (M3, 2026-10-10)

Build the programs with `scripts/build-reproducible.sh` (not a bare
`cargo prove build`). Without it the ELF embeds absolute source paths (panic
locations, tracing call sites): the same commit built at two worktree paths
produced two ELFs (`6dd5f5a3…` at the M1 path, `a80aa3a5…` at the M2 path),
hence two SP1 key pairs and two genesis policies. The script passes
`--remap-path-prefix` for the repository root (`/bloch-l2-evm`) and for
`$CARGO_HOME` (`/cargo`, registry sources and the git patches), refuses to
finish if either absolute prefix still appears in an ELF, and prints the
SHA-256 of each program.

`scripts/verify-reproducible.sh [COMMIT]` exports the commit twice with
`git archive` into two differently named directories, builds both from clean
targets and compares every ELF hash; it exits non-zero on any difference.

The pinned identity is derived only from that ELF:

1. `settlement_v3` ELF bytes → SHA-256 (settler `guest_sha256`) and Keccak-256
   (statement `program_elf_keccak`);
2. `bloch-evm-sp1-settlement-v3 identity ELF` (SP1 setup, no proof) → the
   KoalaBear and BN254 verifying keys (statement fields; the BN254 key is
   identity 5 of `l2-config.bin`);
3. `proof_policy_v3` does not depend on the ELF (wrapper VK, tag, public-value
   rule) and must equal the native `policy_commitment_v3()`.

Inputs that still change the ELF and must be pinned with it: the commit
(sources and `Cargo.lock`, including the patch commits), SP1 CLI 6.8.0, the
`succinct-1.96.0-64bit-v2` compiler, and the compiler host platform (only
macOS x86_64 was measured; a Linux host build must be compared separately or
built in SP1's Docker image).

## SP1 precompiles (M3.0b)

The guest enables `alloy-primitives/tiny-keccak` and patches `tiny-keccak`
(`sp1-patches/tiny-keccak`, tag `patch-2.0.2-sp1-6.2.0`) and `k256`
(`sp1-patches/elliptic-curves`, tag `patch-k256-13.4-sp1-6.2.0`, which also
pulls `sp1-patches/signatures` tag `sp1-skip-verify-on-recovery` for `ecdsa`).
Keccak-f and secp256k1 then run as SP1 syscalls instead of plain RISC-V. The
patched `ecdsa` skips the redundant re-verification after public-key recovery
(the recovered key verifies by construction). Results are unchanged: the
execution benchmark checks the committed statement byte-for-byte against host
execution, which uses the unpatched crates. The k256/tiny-keccak versions are
the core's; only their sources (git, pinned by commit in `Cargo.lock`) differ.
Precompile soundness is SP1's; these patches are not independently audited here.
