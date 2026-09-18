# Selected node execution artifacts

The optional `node-artifact` feature builds `bloch-evm-sp1-artifact`, a separate
local acceptance CLI for V2 blocks exported by the Reth developer node. It uses
[execution-artifact](../../execution-artifact/README.md) to re-execute the sparse
witness, derives the expected statement from the selected header, and sends the
same witness/context/canonical-body frames to the unchanged pinned guest.
The operator independently selects the artifact, its parent and the ELF.
An execution proof does not authenticate native deposits, checkpoint finality,
canonical selection or withdrawal authority.

The guest policy remains `ChainSpec::testnet()` with domain `0xd3` repeated 32
times. Another configuration/domain fails artifact admission. The loader opens
only regular files with final-component no-follow and nonblocking flags, checks
a 64 MiB metadata cap before allocation, reads at most cap+1 bytes, and rejects
changed file length. Ancestor directories and artifact selection remain trusted;
this is not a hostile-filesystem or nested-allocation sandbox. JSON/RLP/witness
checks are provided by the shared transport before calling SP1.

From this host directory, after setting the `PROTOC` environment described in
the main README:

```sh
CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true cargo build --release --locked --offline --features node-artifact --bin bloch-evm-sp1-artifact
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-artifact execute "$TRUSTED_ARTIFACT" "$BLOCH_GUEST_ELF"
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-artifact prove "$TRUSTED_ARTIFACT" "$BLOCH_GUEST_ELF" target/node-block.proof
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-artifact verify "$TRUSTED_ARTIFACT" "$BLOCH_GUEST_ELF" target/node-block.proof
```

`execute` uses the real SDK light executor and checks exact public output plus
rejection of an altered claimed root and trailing body bytes. `prove` constructs
an explicit local CPU prover and requests only Core mode. The reusable
`TrustedProgram` verifies the proof with the selected ELF and exact expectation;
changed expected header, public bytes and a missing final core shard must fail.
Proof creation refuses an existing path, synchronizes the saved file, reloads it
through the bounded strict decoder, and verifies it again. Standalone `verify`
uses the light verifier, re-executes the selected artifact and verifies the full
core proof. Both successful proof paths advance a `SettlementCursor` from the
independently selected artifact parent to the verified successor, reject an
altered full header, and reject replay without changing that cursor. No environment variable chooses a mock or network prover.

The file/admission tests also use an existing genuine contract proof to accept
its matching exported input and reject the same proof for another selected
header. They do not generate a replacement proof or skip missing artifacts:

```sh
CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true RAYON_NUM_THREADS=2 cargo test --release --locked --offline --features node-artifact --test artifact_files -- --test-threads=1
```

A block exported at height three can be executed and proven against its selected
parent without proving the earlier blocks. This qualifies that selected sparse
transition; it does not qualify a consecutive chain of settled proofs. Use the
source-selection coordinator only with independently authenticated source
history and the correct configured execution cursor.

## Actual node execution qualification

On 2026-09-17, the Reth export test retained the actual canonical deposit,
deployment and contract-call blocks in `target/qualification-chain/block-N.json`.
The Reth test checked persisted storage slot 0 equals 42 after the call. Each
selected artifact then passed real execution in the unchanged SP1 guest:

| Canonical block | Guest instructions | Successful execute request |
|---:|---:|---:|
| 1: synthetic developer deposit | 1,090,300 | 0.123770s |
| 2: signed deployment | 4,384,309 | 0.272983s |
| 3: signed call storing 42 | 4,637,700 | 0.327738s |

All three guest commands also rejected an altered claimed post-state and trailing
body bytes, with exit zero for the complete acceptance command. Timings exclude
client initialization and negative cases, with `RAYON_NUM_THREADS=2` on macOS
x86_64; they are execution costs, not proving costs.

The artifact admission/standalone verification suite passed 2/2 tests in 30.12s
without mocks or skipped artifacts. It rejected oversized, empty, truncated,
trailing, symlink, directory and FIFO inputs, accepted a matching genuine saved
contract proof and rejected that same proof under another selected header.
The feature release build took 8m 23s, including dependencies newly compiled under
the transport's feature combination. All dependency versions and the guest ELF
remained unchanged.

A second retained sequence, `target/qualification-source-chain/block-N.json`,
uses the exact synthetic native anchor/mapping from `source_fixture`. This is
the selected sequence for proof generation and combined source-consumption
qualification; no replacement proofs are generated for the preceding generic
sequence. All three source-selected artifacts passed the same real guest checks:

| Source-selected block | Guest instructions | Successful execute request |
|---:|---:|---:|
| 1 | 1,090,300 | 0.134860s |
| 2 | 4,384,309 | 0.301525s |
| 3 | 4,637,700 | 0.303840s |

The selected final header is
`27344355005c7b69e96b6a3505e73fdfb1e11ce6af9828ef926a0e592794e5ec`,
and its state root is
`a25ec0910af766018f17c5c7dd8bca91b8528af7cf7022fa0b67e5fe26e6190b`.
These execution runs include changed-root and trailing-body rejection for every
block; cryptographic proving is a separate qualification step.

Retained source-selected JSON identities:

| Block | Bytes | SHA-256 |
|---:|---:|---|
| 1 | 4,720 | `f1d05a30f121ee535adefc133c049e15724b74c55209bd370c517aef5b38034b` |
| 2 | 5,958 | `c98eac0ab100caa804cd135df2f87b55ff02208b5c4f21a8052bb39a46bed1dc` |
| 3 | 7,221 | `9afa1f56e1c7062a2ae5d17cfacb603ebe3dd170c2da0446c34e102026e18a6e` |

Before proving the selected source sequence, the combined
`node-artifact,source-settlement` matrix passed all-target release Clippy with
`-D warnings` (10.08s). Its release build completed in 9m 39s. The source-prefix
preflight then passed in 0.01s: each exact selected statement matched the actual
export, parents were consecutive, and consumption advanced `0 → 1 → 1 → 1`.
