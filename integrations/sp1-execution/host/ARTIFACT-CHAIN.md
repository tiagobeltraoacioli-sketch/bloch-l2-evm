# Settle a selected persisted developer chain

`bloch-evm-sp1-chain` connects actual Reth-exported execution artifacts and actual
SP1 proofs to the existing local `SettlementJournal`. It does not synthesize
proofs, deserialize a trusted cursor, or authorize native deposits or finality.
The operator independently selects the ELF and complete input chain. The fixed
policy is testnet execution parameters and V2 domain `0xd3…d3`, matching the guest.

The first artifact must have the exact canonical `genesis_v2` parent for its
timestamp. Every subsequent artifact must contain the previous complete header
as its parent. The loader re-executes each sparse witness, and `TrustedProgram`
verifies each proof against that artifact's exact execution statement. All chain
and proof validation finishes **before creating the journal**. Existing output
is refused, including symlinks. Each accepted block is then appended using the
existing checksummed journal and synchronized before its cursor is published.

`verify` reconstructs the genesis cursor and retained floor from the independently
selected inputs, reopens the journal and re-verifies its proofs. The complete
recovered header must equal the last selected artifact. Although the underlying
journal supports recovery of valid successors after an older retained floor,
this CLI refuses such a suffix unless those successors are also selected inputs.

## Commands

Use the pinned guest and real proofs produced by `bloch-evm-sp1-artifact` (see
[ARTIFACT.md](ARTIFACT.md)). Source
artifacts are exported through the real Reth CLI described in
[PROOF-EXPORT.md](../../reth-execution/PROOF-EXPORT.md).

```sh
RAYON_NUM_THREADS=2 CARGO_BUILD_JOBS=2 cargo +1.98.1 build --release --offline --locked \
  --manifest-path integrations/sp1-execution/host/Cargo.toml \
  --features node-artifact --bin bloch-evm-sp1-chain

integrations/sp1-execution/host/target/release/bloch-evm-sp1-chain settle \
  /trusted/guest.elf /new/chain.journal \
  /trusted/block-1.json /trusted/block-1.proof \
  /trusted/block-2.json /trusted/block-2.proof \
  /trusted/block-3.json /trusted/block-3.proof

integrations/sp1-execution/host/target/release/bloch-evm-sp1-chain verify \
  /trusted/guest.elf /new/chain.journal \
  /trusted/block-1.json /trusted/block-1.proof \
  /trusted/block-2.json /trusted/block-2.proof \
  /trusted/block-3.json /trusted/block-3.proof
```

Use the host README's `PROTOC` setup when compiling. No build, download or CPU
proof generation is implicitly started by this command.

## Scope and failure semantics

This local prototype accepts at most 16 blocks and 128 MiB of combined artifact
and proof file lengths. Inputs must be regular files; source writers must be
stopped. The metadata budget is an admission check, not an atomic multi-file
snapshot. Per-file loaders retain their own byte limits and checks. Each witness
is released after validation; headers and verified proof tokens are retained
until preflight completes. These bounds do not establish a hostile-proof CPU or
decoded-memory sandbox. The explicitly trusted ELF has no new size policy here.

An invalid chain or invalid proof leaves no journal. An I/O failure during the
subsequent append sequence may leave a synchronized prefix or corrupt tail. The
CLI never overwrites, truncates or silently repairs it. Verification with a floor
beyond that prefix fails closed; a later retained input selection is still
external authority. No claim of cross-file transactions or physical power-loss
testing is made. `verify` uses the existing journal's exclusive writable handle
for cooperation, but does not append or repair content.

The synthetic funding block in the qualification chain is execution input, not
native authorization. Native-source-bound consumption uses the separate
[SOURCE-JOURNAL.md](SOURCE-JOURNAL.md) interface and authenticated source history;
this CLI deliberately does not substitute execution proofs for that authority.

## Acceptance

Place actual exported artifacts and generated proofs at
`target/qualification-source-chain/block-{1,2,3}.{json,proof}` under the host directory,
or set `BLOCH_SP1_CHAIN_DIR`. `BLOCH_SP1_ELF` overrides the pinned guest ELF path.

```sh
RAYON_NUM_THREADS=2 CARGO_BUILD_JOBS=2 cargo +1.98.1 test --release --offline --locked \
  --manifest-path integrations/sp1-execution/host/Cargo.toml \
  --features node-artifact --test artifact_chain -- --test-threads=1
```

The test runs actual separate CLI processes for settlement and recovery, requires
all real proof files, and has no ignored/mock acceptance path. It exercises exact
tip selection, no overwrite, reordered/omitted/repeated parents, a late wrong
proof before creation, truncation without repair and successful recovery after
restoring the original bytes. Missing proof artifacts fail explicitly.

## Qualification result

On 2026-09-17, `tools/proof-chain-rehearsal.py prove` completed against the
retained three-block source-selected Reth chain and the pinned guest ELF with
SHA-256
`39d78301107d0b2550355894dff4ce57e5762c7e6ed72fbb1766d9b6af80cbf2`.
The actual Core proof files were:

| Block | Proof bytes | SHA-256 | Complete proving step |
|---:|---:|---|---:|
| 1 | 2,813,900 | `b62fc96ea8c39a4bfc52ac84d8de5ef42cb3aac1e47fb3da3b15e0b2cc8abd14` | 350.285s |
| 2 | 2,853,244 | `0280304e06aca176f7b21b90ec4e62d22989ae9442adfb667c73aea5d5007f50` | 559.214s |
| 3 | 2,856,316 | `245f5a043807b541d89be87904941aaf08fc5c42ee9fbe391d7912b220191a14` | 573.104s |

Each proving command reloaded and verified its saved proof and rejected a changed
header, changed public bytes and missing final Core shard. The chain then settled
in 16.118s and reopened in a separate process in 16.833s at header
`27344355005c7b69e96b6a3505e73fdfb1e11ce6af9828ef926a0e592794e5ec`
and state root
`a25ec0910af766018f17c5c7dd8bca91b8528af7cf7022fa0b67e5fe26e6190b`.
The aggregate adversarial chain suite passed 2/2 tests in 123.15s; the combined
source-selection/source-consumption suite passed 2/2 in 13.92s, including exact
once-only consumption across all three proofs. These are local synthetic
qualification results, not native consensus authorization or production proving
capacity.
