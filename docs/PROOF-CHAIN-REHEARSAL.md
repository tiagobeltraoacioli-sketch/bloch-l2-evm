# Rehearse a persisted developer chain with real SP1 proofs

`tools/proof-chain-rehearsal.py` runs the selected Reth artifacts through the
actual SP1 artifact CLI, settles the complete chain into a new local journal,
then reopens it through a separate process. It writes a success report only
after every subprocess succeeds. It does not build binaries, download tools,
activate native consensus, or authenticate synthetic backing funds.

## Prepare independently selected inputs

Build the pinned unchanged guest and the host's `node-artifact` binaries using
the [SP1 host instructions](../integrations/sp1-execution/host/README.md). Select
the trusted ELF independently of the artifact/proof proposer.

Export a stopped local node with
[the Reth exporter](../integrations/reth-execution/PROOF-EXPORT.md), or run its
documented synthetic contract integration test with
`BLOCH_SOURCE_QUALIFICATION_CHAIN_DIRECTORY` set to a new directory. That fixture
contains a funding block, signed contract deployment and signed call setting
storage to `42`. Name the selected files `block-1.json` through `block-3.json`.
The chain must start at canonical V2 genesis under the fixed testnet/D3 policy.

For `verify` mode, provide matching, already generated `block-N.proof` files in
the same input directory. Missing proofs fail; there is no mock fallback or
implicit proof generation. `prove` mode explicitly performs the CPU-intensive
proof generation. Proofs are then cryptographically verified by the existing
host and again during journal recovery.

```sh
python3 tools/proof-chain-rehearsal.py verify \
  --chain-dir /absolute/path/to/selected-chain \
  --elf /absolute/path/to/trusted-guest.elf \
  --output /absolute/path/to/new-rehearsal
```

Use `prove` instead of `verify` to create new proofs. The default is three
blocks; `--blocks` permits 1 through 16. `--artifact-bin` and `--chain-bin` can
select independently built executables; otherwise the host's release binaries
are used. The script checks the chain CLI's 128 MiB aggregate input bound before
running commands. In prove mode, proof sizes are only known after generation;
the total is checked again after each proof, before starting further work.

## Output and trust boundary

The output directory must not exist and its parent must already exist. It is
created with mode `0700`. Selected artifacts, proofs in verify mode, and the
trusted ELF are copied to fixed names before any subprocess starts. Input
snapshots reject final symlinks/special files, cap bytes before and during
copying, and reject observed size/mtime changes. Stop input writers and use
trusted parent directories; these checks do not authenticate an adversarial
filesystem or choose the canonical chain for the operator.

Each step streams stdout/stderr to its own log rather than retaining unbounded
output in memory. The final `report.json` records input snapshot SHA-256 hashes,
proof hashes, commands, exit codes and elapsed wall time. Files are synchronized before
success. A failed step leaves its logs and any partial outputs for inspection;
it produces no success report and never overwrites an earlier run. Use a new
output directory for retry.

The underlying [chain journal CLI](../integrations/sp1-execution/host/ARTIFACT-CHAIN.md)
requires the complete selected chain, valid real proofs and the exact selected
tip on reopen. Its acknowledgement floor comes from those independently
selected inputs, not a cursor claimed by the journal. This establishes local
proof-backed execution and recovery. Native source authority, DA/finality,
consensus escrow and withdrawals remain separate release gates.
