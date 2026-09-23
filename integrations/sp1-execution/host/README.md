# Local SP1 execution and proof qualification

This executable is an experimental acceptance harness for the fixed
[synthetic developer guest](../guest/README.md). It does not authenticate native
Bloch deposits, run a sequencer, or settle a proof on either chain. The fixture
uses a public signing key and synthetic funds only.

The [local settlement library and journal](SETTLEMENT.md) bind verified proof
capabilities to a V2 cursor and independently retained recovery floor. They do
not activate native settlement or release funds. The optional `source-settlement`
feature also connects the exact mandatory deposit prefix to the verified V2
transition: see [source coordinator commands](SETTLEMENT.md#optional-source-selection-coordinator)
and the [combined local source/proof journal](SOURCE-JOURNAL.md).

The optional `node-artifact` feature accepts independently selected sparse
block exports from the developer node through a separate CLI; see
[ARTIFACT.md](ARTIFACT.md). It retains the same pinned guest and proof verifier.

The SDK is pinned to 6.8.0 without `network`, `cuda`, `native-gnark` or
`experimental` features. Proof generation constructs the CPU prover explicitly;
execution and standalone verification use the SDK's `LightProver`, which performs
real execution and full cryptographic verification without initializing the
proof-generation engine. `SP1_PROVER` cannot switch these explicit constructors
to a remote or mock prover. Core remains the only proof type accepted by the
legacy execution journal. Separate `prove-groth16` and `verify-groth16`
commands admit only a bounded SP1 6.8.0 Groth16 wrapper and return a distinct
offline-qualification capability that settlement cannot consume. Plonk,
compressed and TEE-attached proofs remain rejected.

The separate `settlement_v2` guest and
`bloch-evm-sp1-settlement-v2` CLI exercise the complete settlement statement.
Its Groth16 capability is type-distinct from both the legacy Core token and the
legacy Groth16 qualification token. It may advance only an explicitly supplied
local V2 cursor after exact expectation and header-continuity checks; it does
not write the legacy journal or any native consensus state.

With `source-settlement`, `Sp1SettlementProofVerifierV1` is the concrete,
fail-closed implementation of the dormant native kernel's proof-verifier
boundary. It accepts only the fixed 356-byte SP1 Groth16 transport, exact
590-byte settlement V2 public values, the program identity derived from the
trusted ELF, and the proof-policy commitment derived from SP1 6.8.0 plus the
SHA-256 digest of the complete compiled-in wrapper verification key. It invokes
`sp1_verifier::Groth16Verifier` directly; malformed inputs and cryptographic
failure return `false`. This adapter does not authenticate
`SettlementExpectationV1`, assign consensus tags or state keys, persist a
registry, or enable any RPC or production gate.

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
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host prove-groth16 empty "$BLOCH_GUEST_ELF" target/empty.groth16.proof
target/release/bloch-evm-sp1-host verify-groth16 empty "$BLOCH_GUEST_ELF" target/empty.groth16.proof
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
The Groth16 modes apply the same independent expectation and program identity,
require a real SDK verification, reject other proof variants, trailing data,
TEE attachments, noncanonical public inputs and an encoded proof other than
352 bytes, and cap the complete artifact at 64 KiB. They never return the Core
capability used by settlement.
These describe the implemented checks, not successful run evidence; validation
results must be recorded after running them.

### Settlement V2 offline harness

Build the separate `settlement_v2` guest ELF first, then use:

```sh
SETTLEMENT_V2_ELF=../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/settlement_v2
target/release/bloch-evm-sp1-settlement-v2 execute empty "$SETTLEMENT_V2_ELF"
SP1_GNARK_IMAGE=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d \
  RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-settlement-v2 prove-groth16 \
  empty "$SETTLEMENT_V2_ELF" target/settlement-v2.groth16.proof
target/release/bloch-evm-sp1-settlement-v2 verify-groth16 empty "$SETTLEMENT_V2_ELF" target/settlement-v2.groth16.proof

# Build the host with --features source-settlement before this qualification.
SP1_GNARK_IMAGE=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d \
  RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-settlement-v2 prove-groth16 \
  source-contract "$SETTLEMENT_V2_ELF" target/settlement-v2.source-contract.groth16.proof
target/release/bloch-evm-sp1-settlement-v2 verify-groth16 source-contract \
  "$SETTLEMENT_V2_ELF" target/settlement-v2.source-contract.groth16.proof
```

The fixture-less form remains an alias for `empty`. A separate build with
`--features source-settlement` accepts `source-contract` in the same position.
That fixture applies a synthetic escrow batch and inbox proof to its retained
source registry, derives a mandatory `0..1` prefix, and independently compares
the coordinator's V2 statement with host execution. After cryptographic
verification, the same coordinator derives the inert settlement payload and
checks that its consumption remains nonempty. This is source binding for an
offline synthetic qualification, not native source authentication.

Proof generation is release-circuit-only. The harness rejects
`SP1_CIRCUIT_MODE=dev`, an unpinned/tag-only Gnark image and an unavailable
Docker daemon before the expensive setup begins. The harness accepts only the
reviewed Gnark image digest shown above; qualification evidence must also record
and independently inspect that exact image identity.

The default harness uses the empty synthetic execution fixture and fixed
non-production network, genesis, anchor, source and inbox values. The optional
`source-contract` fixture uses a synthetic but internally authenticated batch,
inbox proof, deposit and source cursor. Both validate the four guest frames,
exact program identities, full 590-byte public statement, real SDK
Groth16 verification, expectation tampering, public-value tampering, persistence
and the canonical 356-byte minimal-verifier representation. It does not read a
native RPC, authenticate an inbox, establish finality, activate settlement or
authorize deposits, withdrawals or liquidity. Proof generation can be long and
resource intensive. Source code and successful compilation are not evidence of
a completed proving run; record artifact hashes, timings and negative-test
results separately after the command finishes.

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

The Groth16 routes have compile-time and adversarial codec coverage. The
settlement V2 guest and isolated offline harness are now present, but their
existence does not itself record a completed proving run or satisfy the
production proof-transport gate. Only retained artifact hashes, timing/resource
measurements and successful replay/tamper verification may be cited as run
evidence.

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
Both proof-generation runs used the same guest ELF recorded above and host executable SHA-256
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

The subsequent reusable verifier/local-settlement increment passed all three
`settlement_proofs` integration tests (228.84s, zero ignored), reusing those exact
proof artifacts and the unchanged guest ELF. This includes strict bounded file
admission, real capability/program/header/cursor binding and durable recovery,
and independent CLI processes for both fixtures. Replay/fork attempts, altered
ELF identity with the same VM key, wrong recovery floors, truncation, tampered
proofs with recomputed journal checksums, lock contention and external length
changes were rejected. Both `settle`/`verify-settlement` workflows passed; wrong
fixture, existing-target, corrupt and truncated journal commands failed without
repairing their inputs. Release Clippy with `--all-targets -- -D warnings`,
format checking and `git diff --check` passed. The host was rebuilt for this
increment; the preceding executable digest identifies the earlier measured
proof-generation binary, not every later host build.

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
project. No compressed or Plonk proof is accepted. A Groth16 wrapper is
accepted only by the separate offline-qualification path described above; it
is not a native consensus verifier or settlement capability.

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

## Source-bound contract qualification

On 2026-09-17, the optional `source-settlement` build passed in 4m 12s. The
`source-contract` fixture binds the signed deposit/deploy/call to canonical
synthetic native ancestry and a complete locally allocated escrow inbox. The
unchanged guest ELF shown above executed 7,113,088 instructions in 0.428440s,
matched the independently executed host statement, and rejected both false
post-state and trailing-body inputs. The expected V2 header hash is
`422676f406aa4cee089aff87b5a55c9f1e61faa9a47419ffc4e8e0b2dcdfa02a`.

A real local CPU core proof then passed generation, cryptographic verification,
wrong-expectation/public-value/final-shard rejection, save, reload and verification:

| Core proving request | Complete command | Proof bytes | Exit |
|---:|---:|---:|---:|
| 621.834817s | 773.086562s | 2,885,716 | 0 |

The proof is `target/qualification-source-contract.proof`, SHA-256
`5b7bb456ac487aaf385650a99687aff845135c83bf6acb0d5cfa89c43348b099`.
A Python subprocess wrapper measured elapsed time and Darwin
`getrusage(RUSAGE_CHILDREN).ru_maxrss`: 10,189,324,288 bytes. This is the child
maximum RSS metric, not peak memory footprint. The wrapper and prover both
returned zero. These are local observations with `RAYON_NUM_THREADS=2`, not
isolated-machine throughput guarantees. Raw metrics are retained in
`target/qualification-source-contract.metrics.json`.

The feature's bootstrap/source-policy test passed using the prior genuine
contract proof: altered source commitment, repeated source updates, legacy
synthetic anchor, mismatched verified statement, precredited/altered genesis,
wrong native identity and pre-advanced registry all failed without advancing
execution or deposit consumption. Commands, authority boundaries and artifact
overrides are in [SETTLEMENT.md](SETTLEMENT.md).

The source coordinator's real-proof acceptance test also passed (28.90s):
missing source and omitted/altered deposits or transaction bodies were rejected;
the valid transition advanced execution and consumption exactly once; replay
left both unchanged. A separate `verify-source source-contract` process repeated
real cryptographic verification against the trusted ELF and independently
executed fixture, accepted the coupled transition and rejected replay. Both
source coordinator tests passed individually, with no mocks or ignored tests.
This qualifies one source-bound first execution block. It does not qualify a
long consecutive chain of proven execution blocks or native consensus inclusion
of the source commitment.

The combined source/proof journal integration suite passed 3/3 tests in 29.65s
with the same genuine source proof. Recovery re-derived the consumed cursor,
reverified historical source selection beneath an independently trusted exact
source tip, and rejected conflicting native identity, corrupted/truncated
frames and inconsistent retained floors. Details and separate-file durability
semantics are documented in [SOURCE-JOURNAL.md](SOURCE-JOURNAL.md).
