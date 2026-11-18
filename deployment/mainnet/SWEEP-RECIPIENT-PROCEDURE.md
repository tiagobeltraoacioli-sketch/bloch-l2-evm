# Fee-sweep recipient: one-pass procedure (December fork candidate)

Status: candidate procedure. It edits source trees only. Building, qualifying, signing and publishing stay
with the owner's release process.

## Release gate (agents 163 B-1, 217)

The fork-candidate L2 tree ships with `MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> = None` in
`src/chainspec.rs`. While it is unset, or holds an address the release check refuses:

- the three next-rules guests (`settlement_v3_mainnet_sparse`, `_sparse_eager`, `settlement_v3_mainnet`)
  fail to compile on a const assert of `MAINNET_NEXT_RULES_RELEASABLE`;
- both guest `build-container.sh` scripts refuse the commit before any download (`S gate --chainspec -`);
- `build-release.sh` refuses the next-rules (candidate native) kit build (`S gate --l2`);
- `ChainSpec::mainnet()` fails `validate` and the configuration commitment, `ChainSpec::mainnet_next()` is
  `None`, the follower and RPC follow the activated rules only, and the host refuses `--mainnet`.

`ChainSpec::validate` also refuses the zero address and the precompiles `0x01`-`0x0a` as a recipient (B-2),
for every rule set. The old placeholder `0x…000fee01` survives only as `REHEARSAL_FEE_SWEEP_RECIPIENT`
(`ChainSpec::mainnet_rehearsal`, `--rules mainnet-rehearsal`) for native tests. No guest and no L1 pin carries
it, so nothing built with it can settle. The flag `--rules mainnet-rehearsal` is compiled only with the cargo
feature `rehearsal-rules` (`integrations/reth-execution`, forwarded by `integrations/settlement-recovery`), which
`build-release.sh` never enables: from the round-19 December build on, a release producer or settled RPC refuses
the flag by name (review R335-5; the round-17 and round-18 December binaries still accepted it with the mainnet
domain, and a process started that way looked correct until the first block under the next rules).
A private crossing rehearsal that needs a next-rules ELF runs `set` with a throwaway address on a
throwaway branch.

## The owner's one command

`S` is `deployment/mainnet/set-sweep-recipient.py` in the L2 tree; `L2` and `N` are clean checkouts of new
branches from the fork-candidate L2 and native tips.

If the Safe is already deployed on L2 700770 (the address holds code at `finalized` on your own L2 node):

    python3 S set 0xADDRESS --l2 L2 --native N --rpc http://127.0.0.1:18955 --dry-run
    python3 S set 0xADDRESS --l2 L2 --native N --rpc http://127.0.0.1:18955

If it is not deployed yet (the counterfactual plan address), the address is given twice:

    python3 S set 0xADDRESS --l2 L2 --native N --confirm 0xADDRESS --dry-run
    python3 S set 0xADDRESS --l2 L2 --native N --confirm 0xADDRESS

`0xADDRESS` is the EIP-55 mixed-case checksum form, with its `0x`, exactly as the Safe shows it. An
all-lowercase, all-uppercase or prefix-less address is refused in every step: it carries no checksum, so one
wrong character could not be seen, and the recipient cannot be changed after the fork without a new program.
The tool never prints the checksum form of an address it refused.

`set` validates the address (as `check`) and then wants proof that it is the intended one: either `--rpc URL`
(the address must hold code on the L2 at `finalized`, as `onchain`), or the address a second time in
`--confirm` (on a terminal `set` asks for it when the flag is absent). Type the second one from the Safe's own
screen or from the plan file; do not paste the first. `--rpc URL --allow-codeless` (a counterfactual address
read on-chain) needs `--confirm` too. It then applies phase 1 to both trees (as `apply`),
re-checks the gate and commits both trees. Steps 4 to 9 below then follow from that commit. The next
configuration includes the 0.1 gwei base-fee floor (`MAINNET_MIN_BASE_FEE`, agent 197), which the script
reads from `src/chainspec.rs`; Rust test `rehearsal_configuration_matches_the_sweep_script` pins the
script's layout.

The individual steps remain available:

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

- It must be `0x` and 20 bytes of hex in the EIP-55 mixed-case checksum form. Single-case and prefix-less
  input is refused (`check`, `onchain`, `apply`, `set`).
- The release gate (`gate`, called by the build scripts, and `pins`, `audit`) reads the constant from
  `src/chainspec.rs` in the one-line form or the two-line form `rustfmt` keeps, at the start of a line only,
  and refuses a file that defines it twice. It also requires the doc line `apply` writes above the constant,
  ``/// rules, fixed by the owner: `0x…`.``, to carry the EIP-55 form of that same constant: a constant
  edited by hand, or with one wrong digit, does not match and is refused. Only `set`/`apply` should write it.
- It must not be a system account: either vault, the supply ledger, block info, the outbox or EIP-4788.
- It must not be in the `0x4200…` predeploy range or the precompile range. Precompile `0x09` reverts on an
  empty call, which would make every sweep fail forever.
- It must not be the rehearsal placeholder `0x…0fee01`.
- It must not be a burn address (`0x0`, `0x…dead`, `0xdead…`): every step and the release gate refuse it and
  there is no override (owner decision: never a burn address). The same holds for hand-made values nobody
  holds a key for: a run of 16 or more equal hex digits (`0xff…ff`, `0xff…fe`, `0x…0fee02`) or a short
  repeated pattern (`0xdeadbeef…`). The Rust check in `src/chainspec.rs` is narrower (it knows the zero
  address, the precompiles, the placeholder, the system accounts); this script is the stricter of the two.
- **It must be an address on L2 700770 that someone can spend from.** A Safe deployed on Ethereum or on
  another chain is not deployed here. A copied address would strand the fees. `set --rpc` runs `onchain`
  against your own L2 node, at `finalized`, and refuses an address without code; without it the address
  must be typed twice.

## Steps

`S` below stands for `deployment/mainnet/set-sweep-recipient.py` in the L2 tree. `L2` is a new branch from
the fork-candidate L2 tip, and `N` is a new branch from the fork-candidate native tip.

1. Validate the address and print the new configuration commitment. Nothing is written.
   `python3 S check 0xADDRESS`
2. Check that the address is spendable on L2. Do this read-only.
   - **If the Safe is already deployed on L2**, read its code, owners and threshold at `finalized`:
     `python3 S onchain 0xADDRESS --rpc http://127.0.0.1:18955`
   - **If it is not deployed yet** (the usual case while user transactions are off, because deploying a
     Safe is a user transaction), the address is counterfactual. It must equal the plan of the DEX kit,
     from postern-dex `deploy-safe.mjs`:
     `node scripts/staging/deploy-safe.mjs blochinc --plan deployments/mainnet/700770/safe.plan.json`
     That address follows from the bootstrap address and start nonce, the owners, the threshold and the
     salt nonce. Fix all of them before `apply`. Then keep the bootstrap key unused on L2 700770, and safe,
     until the Safe is deployed: without it, the address can never get code and every swept fee is
     stranded there. Owners can still be rotated after deployment without moving the address.
3. Phase 1 edits, with a dry run first. They cover the recipient constant (`src/chainspec.rs`), the two
   crossing `SWEEP_RECIPIENT`s and the configuration commitment everywhere it is pinned. That is native
   `PROGRAM_NEXT` / `PROGRAM_FALLBACK` identity 3, settler `MAINNET_NEXT*`, the prover installer, the
   crossings, `test_make_native_program.py` and `AUDIT-SCOPE-SPARSE.md`.
   `python3 S apply 0xADDRESS --l2 L2 --native N --dry-run`
   `python3 S apply 0xADDRESS --l2 L2 --native N`
   `apply` also moves the short forms of the configuration in comments (`b4663ab8`), and on a second run
   with another address every text that names the previous recipient. It writes every file under a temporary
   name and renames them at the end, `src/chainspec.rs` last, so an interrupted run leaves the gate closed
   and can simply be run again. (`apply` alone does not ask for the second typing or the on-chain read;
   `set` does.)
4. Commit the L2 tree. Build both guests in the pinned container on two Linux x86_64 hosts and compare the
   `SHA256SUMS` files:
   - `integrations/sp1-execution/guest-sparse/build-container.sh OUT REV` builds
     `settlement_v3_mainnet_sparse`, the `PROGRAM_NEXT` guest.
   - `integrations/sp1-execution/guest/build-container.sh OUT REV` builds `settlement_v3_mainnet`, the
     `PROGRAM_FALLBACK` guest.

   `settlement_v3_mainnet_v1_sparse` runs the activated rules and has no recipient. It no longer keeps
   `b1b09c1f`: the floor (agent 197) and the `validate` hardening (B-2) change shared code. Its identity
   under `--mainnet-v1 --sparse` must still reproduce the activated configuration `8ec1c804…`.
5. Print the identities with the host built from the same commit. `identity` now executes the ELF on an
   empty block under the selected rules and witness (SP1 execute, no proof) and refuses an ELF that commits
   another statement, so a mismatched flag or ELF stops here (B-3):
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
   present, or while native and L2 disagree; after a correct run of steps 3 to 7 it exits zero. The
   monitor's own constant `PLACEHOLDER_SWEEP_RECIPIENT` (`revenue_monitor.py`, the value it alarms on) is
   exempt. It also prints the rebuild list. The `GO-LIVE-PINS*` files are not touched by this tool and are
   stale from step 3 until they are rebuilt (see below), so `test_kit_source_pins.py` fails in between.
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
