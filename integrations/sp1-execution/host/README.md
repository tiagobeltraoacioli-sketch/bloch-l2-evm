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
CARGO_BUILD_JOBS=2 cargo build --locked
target/debug/bloch-evm-sp1-host fixture contract
target/debug/bloch-evm-sp1-host execute empty "$BLOCH_GUEST_ELF"
target/debug/bloch-evm-sp1-host execute contract "$BLOCH_GUEST_ELF"
target/debug/bloch-evm-sp1-host prove empty "$BLOCH_GUEST_ELF" target/empty.proof
target/debug/bloch-evm-sp1-host verify empty "$BLOCH_GUEST_ELF" target/empty.proof
```

The SDK also needs a protobuf compiler. Put `protoc` on `PATH` or set `PROTOC`
to its executable before building. Local qualification uses the official
[protoc 36.2 macOS x86_64 asset](https://github.com/protocolbuffers/protobuf/releases/tag/v36.2),
extracted in a separate cache without a global installation. Its ZIP SHA-256,
checked against the official release API, is
`228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078`.
The executable reports `libprotoc 36.2`.

Use `contract` instead of `empty` for the signed deploy/call proof qualification.
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
run. Execution and verification now use the official light client. Optimized
host compilation and actual core-proof acceptance remain in progress; no proof
generation, persisted-proof verification or proof-cost result is claimed yet.

## Trust and resource boundaries

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
