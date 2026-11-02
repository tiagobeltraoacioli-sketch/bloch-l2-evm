# Fee-sweep recipient: one-pass procedure (December fork candidate)

Status: candidate procedure. It edits source trees only. Building, qualifying, signing and publishing stay
with the owner's release process.

## What the sweep is

- L2 fees never leave the L2 today. Base fees accrue at `0x4200…0019` and priority fees at `0x4200…0011`
  (also COINBASE). Both accounts are codeless and keyless, so nobody can spend them. The balances stay part
  of the L2 supply and stay backed by the L1 escrow.
- The next rules (`ChainSpec::mainnet()`, native `PROGRAM_NEXT`, gate `L2_NEXT_PROGRAM_EPOCH`) add the sweep.
  The first L2 block under those rules installs 37 bytes of code at both vaults, and their balances are kept.
  The code does `CALL(gas, RECIPIENT, selfbalance)` and reverts if that call fails.
- After that block, any transaction to a vault, from anyone and for any value (0 works), sends that vault's
  whole balance to `RECIPIENT`. Measured gas is 55,334 for the first sweep and 30,334 after that. There is
  no owner, setter, storage or selector.
- `RECIPIENT` is compiled into the guest and committed in the configuration (`BLOCH:EVM:CONFIG:3:CANCUN`,
  identity 3). Changing it later takes another L1 hard fork with a new ELF and new keys.
- The block derivation rule ships with it. The configuration code refuses one rule without the other
  (`PartialNextRules`), so "no sweep" is not an option without a code change.

**Funds that flow:** every base fee and tip since L2 block 1, plus every later fee, swept whenever someone
calls a vault. The funds arrive as L2 BLCH at `RECIPIENT`. To bring them to L1, the recipient makes an
ordinary L2 withdrawal (minimum 0.01 BLCH) followed by an L1 claim.

## Constraints on the address (enforced by `check`)

- It must be 20 bytes of hex, with a valid EIP-55 checksum if mixed case.
- It must not be a system account: either vault, the supply ledger, block info, the outbox or EIP-4788.
- It must not be in the `0x4200…` predeploy range or the precompile range. Precompile `0x09` reverts on an
  empty call, which would make every sweep fail forever.
- It must not be the placeholder `0x…0fee01`.
- A burn address needs `--allow-burn`.
- **It must be an address on L2 700770 that someone can spend from.** A Safe deployed on Ethereum or on
  another chain is not deployed here. A copied address would strand the fees. Run `onchain` against your own
  L2 node, at `finalized`, before `apply`.

## Steps

`S` below stands for `deployment/mainnet/set-sweep-recipient.py` in the L2 tree. `L2` is a new branch from
the fork-candidate L2 tip, and `N` is a new branch from the fork-candidate native tip.

1. Validate the address and print the new configuration commitment. Nothing is written.
   `python3 S check 0xADDRESS`
2. Read only: check the Safe on L2 (code, owners, threshold) at `finalized`.
   `python3 S onchain 0xADDRESS --rpc http://127.0.0.1:18955`
3. Phase 1 edits, with a dry run first. They cover the recipient constant (`src/chainspec.rs`), the two
   crossing `SWEEP_RECIPIENT`s and the configuration commitment everywhere it is pinned. That is native
   `PROGRAM_NEXT` / `PROGRAM_FALLBACK` identity 3, settler `MAINNET_NEXT*`, the prover installer, the
   crossings, `test_make_native_program.py` and `AUDIT-SCOPE-SPARSE.md`.
   `python3 S apply 0xADDRESS --l2 L2 --native N --dry-run`
   `python3 S apply 0xADDRESS --l2 L2 --native N`
4. Commit the L2 tree. Build both guests in the pinned container on two Linux x86_64 hosts and compare the
   `SHA256SUMS` files:
   - `integrations/sp1-execution/guest-sparse/build-container.sh OUT REV` builds
     `settlement_v3_mainnet_sparse`, the `PROGRAM_NEXT` guest.
   - `integrations/sp1-execution/guest/build-container.sh OUT REV` builds `settlement_v3_mainnet`, the
     `PROGRAM_FALLBACK` guest.

   `settlement_v3_mainnet_v1_sparse` runs the activated rules and has no recipient, so it should keep
   `b1b09c1f`. If it changes, stop and investigate.
5. Print the identities with the host built from the same commit:
   - `bloch-evm-sp1-settlement-v3 --mainnet --sparse identity OUT/settlement_v3_mainnet_sparse > sparse.json`
   - `bloch-evm-sp1-settlement-v3 --mainnet identity OUT/settlement_v3_mainnet > complete.json`
6. Phase 2 edits. `pins` refuses an identity whose configuration, domain, chain or proof policy differs. It
   moves the ELF SHA-256, the ELF Keccak and both vkey hashes of both guests in both trees, including the
   short `xxxxxxxx…yyyy` forms in comments and the ELF size in the native doc.
   `python3 S pins --l2 L2 --native N --sparse-identity sparse.json --sparse-elf OUT/settlement_v3_mainnet_sparse --complete-identity complete.json --complete-elf OUT2/settlement_v3_mainnet`
7. Commit the native tree. Phase 3 then moves `build-release.sh` `CANDIDATE_NATIVE_COMMIT`, and refuses if a
   native `Cargo.lock`, `Cargo.toml` or toolchain file changed. If one did, a new pinned lock is needed.
   `python3 S native-commit --l2 L2 --native N`
8. Audit. It exits non-zero while the placeholder, the old configuration or any `--old` value is still
   present, or while native and L2 disagree. It also prints the rebuild list.
   `python3 S audit --l2 L2 --native N --old OLD_SPARSE_SHA --old OLD_SPARSE_KECCAK --old OLD_COMPLETE_SHA --old OLD_COMPLETE_KECCAK`
9. Review the changed lines. Short-hash comments still name the commit they were built from, so update that
   provenance text by hand.

`PROGRAM_NEXT_FINAL` is not touched. It is the owner's sign-off that the guests are final, and
`hard_forks.rs` has a test asserting it is false while the recipient is a placeholder.

## What must be rebuilt after the edits

- **Guests:** `settlement_v3_mainnet_sparse`, `settlement_v3_mainnet` (complete, next rules) and the
  measurement-only `_eager`.
- **Native release:** `bloch-pos`, with `PROGRAM_NEXT` and `PROGRAM_FALLBACK` moved. Run the qualify
  build with a fresh context, the `l2_tests` and `hard_forks` suites, and the real-proof Groth16 check under
  the new program key.
- **L2 kit (`build-release.sh`):** follower, produce-dev and settled RPC. They link the chainspec and detect
  the switch by the vault code, which contains the recipient. Also the prover host
  (`bloch-evm-sp1-settlement-v3`), the settlement-recovery tools, the attestor package and the `GO-LIVE-PINS*`
  files.
- **Rehearsals:** the crossing (`rehearsal/next-consensus/sparse/crossing.py`, including a real sweep to the
  new recipient), the rollback crossing and run B.
- **Operator configuration:** the sequencer's `next_elf_keccak`, and the settler's `next_program` /
  `fallback_program` written by `install-settler-mainnet.py`.
- **Documents:** the fork notice (the recipient becomes public), the exchange guide ("vault balances can be
  swept to RECIPIENT after the gate") and `SETTLER-RUNBOOK.md`.

Unchanged: identities 0 to 2, the proof policy `15486996…`, the L2 genesis `632e45ae…`, the attestor set and
limits, the activated program (`8ec1c804…`, `203114bf…`), and every DEX and bridge contract.
