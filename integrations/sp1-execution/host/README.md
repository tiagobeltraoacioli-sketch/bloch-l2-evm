# Local SP1 execution and proof qualification

This executable is an experimental acceptance harness for the fixed
[synthetic developer guest](../guest/README.md). It does not authenticate native
Bloch deposits, run a sequencer, or settle a proof on either chain. The fixture
uses a public signing key and synthetic funds only.

The SDK is pinned to 6.8.0 without `network`, `cuda`, `native-gnark` or
`experimental` features. Proof generation constructs the CPU prover explicitly;
execution and standalone verification use the SDK's `LightProver`, which performs
real execution and full cryptographic verification without initializing the
proof-generation engine. `SP1_PROVER` cannot switch these explicit constructors
to a remote or mock prover. Only `SP1Proof::Core`
is accepted. No Groth16, Plonk or compressed proof is requested or accepted.

## Commands

Build the guest first. Run these from this directory, setting `BLOCH_GUEST_ELF`
to the trusted ELF produced by that build:

```sh
CARGO_BUILD_JOBS=2 cargo build --release --locked
target/release/bloch-evm-sp1-host fixture contract
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host execute empty "$BLOCH_GUEST_ELF"
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host execute contract "$BLOCH_GUEST_ELF"
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host prove empty "$BLOCH_GUEST_ELF" target/empty.proof
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host verify empty "$BLOCH_GUEST_ELF" target/empty.proof
```

The SDK also needs a protobuf compiler. Put `protoc` on `PATH` or set `PROTOC`
to its executable before building. Local qualification uses the official
[protoc 36.2 macOS x86_64 asset](https://github.com/protocolbuffers/protobuf/releases/tag/v36.2),
extracted in a separate cache without a global installation. Its ZIP SHA-256,
checked against the official release API, is
`228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078`.
The executable reports `libprotoc 36.2`.

Use `contract` instead of `empty` for the signed deploy/call proof qualification.
Use the optimized release build for proof qualification; the debug executor
measurements below do not qualify debug proving performance.
Proof creation refuses an existing output path. The `fixture` command executes
the native kernel only; it is useful for diagnosing fixture construction but
does not exercise the zkVM or prove anything.

`execute` compares real guest output with the independently executed native
fixture, reports instruction count and elapsed time, then requires guest failure
for a false post-state root and trailing body bytes. `prove` creates a core
proof, verifies it, rejects a missing final shard, changed public values and a changed trusted
expectation, persists it, reloads it and verifies it again. `verify` independently
rebuilds the fixture expectation and verification key from the trusted ELF.
These describe the implemented checks, not successful run evidence; validation
results must be recorded after running them.

## Qualification results

On 2026-09-17, the debug host built successfully with Rust 1.98.1, and both
native fixtures passed. The real SDK `LightProver` then executed the guest ELF
with SHA-256 `39d78301107d0b2550355894dff4ce57e5762c7e6ed72fbb1766d9b6af80cbf2`:

| Fixture | Guest instructions | Successful execution time | Negative guest inputs |
|---|---:|---:|---|
| Empty V2 block | 950,085 | 1.180s | False post-state and trailing body bytes rejected |
| Signed deposit/deploy/call storing 42 | 7,113,088 | 4.922s | False post-state and trailing body bytes rejected |

Both returned exactly the independently executed native statement. Times cover
the successful execution request only, excluding client initialization and
negative cases, on macOS x86_64 with `RAYON_NUM_THREADS=2`. They are execution
times, not proving costs. The expected guest panics in the negative cases are
checked as nonzero guest exits; each complete acceptance command exited zero.

An initial attempt initialized the full CPU proving engine for execution and
was interrupted after 101s without a result; it is not counted as a passing
run. Execution and verification now use the official light client.

The optimized host subsequently built successfully in 20m 07s with two build
jobs, reusing dependencies from the earlier interrupted release build. The
release `execute` commands also passed for the same ELF:

| Fixture | Guest instructions | Successful execution time | Negative guest inputs |
|---|---:|---:|---|
| Empty V2 block | 950,085 | 0.237s | False post-state and trailing body bytes rejected |
| Signed deposit/deploy/call storing 42 | 7,113,088 | 0.619s | False post-state and trailing body bytes rejected |

These are successful execution-request timings with `RAYON_NUM_THREADS=2`,
not proof costs.

The release CPU prover subsequently generated and cryptographically verified
**real core proofs for both fixtures**. The driver rejected a changed trusted
expectation, tampered public values and removal of the final proof shard. It
saved and reloaded each proof and verified it again. Separate `verify empty`
and `verify contract` processes also succeeded with exit code zero against the
trusted ELF and locally recomputed expectation.

The separate command `verify contract <TRUSTED_ELF>
target/qualification-empty.proof` rejected that same cryptographically valid
proof with `Error: Mismatch` and exit code 1: an empty-block proof cannot satisfy
the independently derived signed-contract header commitment. The original proof
file was not modified. The reverse combination, `verify empty` with the valid
contract proof, also failed with `Error: Mismatch` and exit code 1.

| Fixture | Core proving request | Complete proving command | Proof bytes |
|---|---:|---:|---:|
| Empty V2 block | 226.115s | 360.51s | 2,812,364 |
| Signed deposit/deploy/call storing 42 | 640.465s | 777.10s | 2,885,716 |

The complete command includes CPU engine initialization, key setup, verification
and negative checks. For the empty run, `/usr/bin/time -l` reported the elapsed time, then failed
to query `kern.clockrate` under the sandbox and returned exit 1 after the
successful driver. Consequently no peak-memory result is claimed for that run;
the separate successful verifier confirms the persisted proof independently.
The local artifact is `target/qualification-empty.proof`, SHA-256
`9b5a0dfee75a42a63b0b05262620e5b956da9c9afbd820edba8347d32db19db4`.
This digest identifies that particular proof file, not a deterministic proof
encoding. The signed-contract artifact is `target/qualification-contract.proof`,
SHA-256 `46f0530b2408d0dd6f98038c8b144670a84670c06bbf6df1a7050c9c58f75dc4`.
Both use the same guest ELF recorded above and host executable SHA-256
`a671c72be68fcde13f715a2ec137d5143a1768e1def8687f8567e6c02f45adc6`.

The contract proving command and resource wrapper both exited zero. macOS
`time -l` reported maximum resident set size of **10,636,984,320 bytes** and
peak memory footprint of **32,160,780,288 bytes**. These are different OS
accounting metrics; neither is a memory cap or a prediction for larger blocks.
The standalone contract verification took **15.26s** for the entire command,
including light-client initialization, trusted-key setup, native fixture
execution and proof verification. It reported maximum RSS **841,494,528 bytes**
and peak memory footprint **732,143,616 bytes**. All runs used two Rayon threads.
These single-machine measurements do not establish production throughput or
economically viable proving costs.

`cargo clippy --release --locked --offline -- -D warnings` passed for the host
in 2m 35s. Cargo still reports the upstream `proc-macro-error2` future-compatibility
notice; that is separate from the host's Clippy result.

## Trust and resource boundaries

Acceptance qualifies local execution and verification under the pinned SP1
6.8.0 implementation, qualified compiler and trusted guest ELF. It relies on
the upstream proof system, its implementation and cryptographic assumptions;
these runs are not an independent soundness audit or a privacy assessment.
Generating a `Core` proof does not establish that private inputs remain hidden,
and this harness makes no zero-knowledge or quantified security-level claim.
The pinned CPU core uses the Basefold/FRI verifier configured by
[`CoreProver::verifier`](https://github.com/succinctlabs/sp1/blob/v6.8.0/crates/prover/src/components.rs)
and [`core_fri_config`](https://github.com/succinctlabs/sp1/blob/v6.8.0/crates/primitives/src/fri_params.rs),
with `CORE_LOG_BLOWUP = 2` and the upstream query-count/grinding configuration.
Its inner context is
[`KoalaBearDegree4Duplex`](https://github.com/succinctlabs/sp1/blob/v6.8.0/crates/primitives/src/lib.rs).
Those are implementation parameters, not security guarantees derived by this
project. No recursion, compressed proof or pairing-based wrapper is accepted.

The operator supplies the trusted ELF, not the prover. A different arbitrary
program could simply publish a claimed statement, so an ELF obtained alongside
an untrusted proof is not a trusted program identity. Record and check the guest
source, lockfile, compiler and ELF digest before using this harness. Verification
requires a successful guest exit and compares all canonical public bytes only
after the cryptographic check. Expectations come from the local configured
fixture execution, not bytes packaged with a proof.

The signed fixture starts at V2 genesis, deposits synthetic funds, deploys with
nonce 0 and calls with nonce 1 to store 42 in slot 0. Native execution checks
runtime code, storage, receipts, outcomes and nonce 2 before yielding expected
commitments. The empty fixture performs one empty V2 transition.

This is a local development executable, not a resource-bounded service for
untrusted serialized proof files or witnesses. The SP1 serialization format and
dependency graph are version-specific. Proving cost and memory must be measured
on the actual machine; a successful build is not accepted-proof evidence.

SP1's executor runner also builds an internal helper crate with its own shipped
lockfile. The SDK's build script does not pass `--locked` to that nested build.
`CARGO_BUILD_JOBS=2` is inherited by the helper, unlike an outer-only `--jobs`
argument. Qualification must inspect any nested dependency changes and record
the resulting helper alongside the host lockfile. On macOS the SDK selects its
portable executor rather than the Linux x86_64 native executor.

The shipped internal lockfile SHA-256 digests recorded for qualification are
`09dee55211d0db320555ea9f63edb415ce4c2756e99bfc6b8fbdd38f69bb158e`
for `sp1-core-executor-runner` and
`a6ed816e8cf096498253a7b2200ffc0b17bd2ca5319eb76544ed461432c221e1`
for `sp1-core-executor-runner-binary`, both version 6.8.0. Their dependencies
were fetched with `cargo fetch --locked --manifest-path ...` before resuming
the outer build with `CARGO_NET_OFFLINE=true`.

The host lockfile was seeded from the native core lockfile. A target-filtered
metadata comparison confirmed that all 268 package identities in the native
core's resolved non-development dependency closure remain present in the SDK
host's core closure. SP1 adds packages and unifies additional features; this is
not a claim that the complete host and guest dependency graphs are identical.
