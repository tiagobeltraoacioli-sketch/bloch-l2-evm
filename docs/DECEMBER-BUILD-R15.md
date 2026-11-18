# December build, round 15: recipients, identities, how to reproduce

Candidate only. Host names: the build hosts are named A and B here; the operator's records hold their addresses.
The deposit-only launch kit (`codex/l2-release-r15-20261110` 2de669e, release 926d2cf, signing
target `6d3bd628…9c19`) is not touched by anything here.

## 1. Owner decisions this build carries (2026-11-16)

| Decision | Value | Where it is compiled |
|---|---|---|
| L1 protocol treasury | `bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073` | native `params::PROTOCOL_TREASURY_SCRIPT_HASH` = the 20-byte key hash, then twelve zero bytes (the carried form) |
| L2 fee-sweep recipient | `0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544` (an externally owned address; confirmed by the owner) | `src/chainspec.rs` `MAINNET_FEE_SWEEP_RECIPIENT`; it enters the configuration commitment of the next rules |

Checks made before anything was written:
- The BLCH address has the mainnet prefix `bloch1q`, 48 hex characters, and its checksum
  (`SHA3-256(SHA3-256(hash20))[..4]` = `84242073`) verifies. It is a key-hash address (`SHA3-256(pubkey)[..20]`), the
  address of `tokenomics_v4::FOUNDER_WITHDRAWAL_H160`. A 32-byte script hash represents it in the carried form,
  which `transition::owns` opens for the holder of that key (the rule of every carried Genesis-3 balance; 160 bits
  of preimage resistance). A spend from a treasury output was not exercised on a rehearsal net.
- The EVM address has a valid EIP-55 checksum exactly as given, is not zero, not in the precompile range and not a
  known burn address; `set-sweep-recipient.py set … --confirm …` accepted it. The owner states it is an externally
  owned address; code at it on the L2 could not be checked (no L2 at that state yet) and is to be confirmed on
  chain at the first sweep. For an externally owned address the tool's Safe checks do not apply (review R335-6).

Naming the treasury arms nothing: `L2_NEXT_PROGRAM_EPOCH`, `L2_REVENUE_EPOCH`, `L2_FORCED_INCLUSION_EPOCH` and
`L2_PROGRAM_ROLLBACK_EPOCH` stay `u64::MAX`, and `PROGRAM_NEXT_FINAL` stays false. With the treasury named the
compile-time rule now ALLOWS arming forced inclusion and the revenue fee at or after the swap; setting the fork
epoch remains an owner input.

## 2. Branches and tips

| Repo | Branch | Tip | From |
|---|---|---|---|
| bloch-sis-pow | `codex/native-l2-dec-merge-r17-20261117` | `711e60ba` | the released node `906336fd` merged with `codex/l2-r17-20261117` `189f3178` (= `0861278c` plus scripts and a runbook), section 11; then bloch-sis-pow `main` `857a10ac` (the deployed release `0067547f`) merged in, section 12 |
| bloch-l2-evm | `codex/l2-dec-merge-r17-20261117` | see `git log` (this file is in the tip; the follower, producer and settled RPC were built at `904e6d4` against native `711e60ba`, the later commits move pins and documents only) | `codex/l2-r17-pins-20261117` `99da262` |

Before the merge (rounds 15 to 17, sections 3 to 8 where they say so): native `codex/l2-r15-recipients-20261116`
`0861278c` (from a2fc3d0f) and bloch-l2-evm `codex/l2-r15-recipients-20261116` (binaries built at c2938be).

Native commits: 1650b36d treasury; 36885a1a `set` (configuration); 613ba4d0 one test; 0861278c `pins`.
L2 commits: f32d400 `set`; b635566 root crate rustfmt and clippy clean (item U5; the guests were built here);
f482f92 planner reserve (F317-3); afb75e2 `pins` and `native-commit`; 59f4899 prover profile, shadow and forced
records, binary pins (F317-1, F317-2, F317-4); ade9c59 path prefixes remapped; 91dbd30 reviews R308-7P-2 and
R308-7P-3 (Python); c2938be the fixed build directory and `build-prover-host.sh` (the build commit).

## 3. Identities

Configuration commitment of the next rules: `27d6ce9f3ef204207ed089a4ba2593e4d45b9bc25242d3de32e2a3dea1a12783`
(before: `b4663ab8…a29d`). Unchanged: proof policy `154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d`,
L2 genesis `632e45ae…f468`, the activated program and its configuration `8ec1c804…8f2b`, SP1 circuit `v6.1.0`.

| Artifact | SHA-256 | Other identities |
|---|---|---|
| `settlement_v3_mainnet_sparse` (native `PROGRAM_NEXT`), 3,274,936 bytes | `81813124c19b1a9bfe5755fc742fa36a48420134b71e18ef355e26e1c5f1b6d9` | ELF Keccak `d6b33a99dc9329b2ca75aa0b4b7b3116e5334ee9edc9cb5e20491eaa926ceb74`; vkey `5dc306572d2df6a31f8c59c3114859500ba2af783ffaca8e473258c273d98584`; vkey bn254 `00bb860caeb4b7da8cfc62ce19148595017455ef0ffeb2a3a3992c6173d98584` |
| `settlement_v3_mainnet` of `guest-fallback` (native `PROGRAM_FALLBACK`), 3,141,328 bytes | `7528e26da4076499e0fabcc621836aae396d0ddcb1cbf567436273c820c7c3e1` | ELF Keccak `b6d6d128b0585ec6b24cec3261ccca348ee8e7cbc3e15eb51ed5fd838ac9baf1`; vkey `020138086276433f0bfc354c43e493a50400999706ba3ca061ae34d4162f4765`; vkey bn254 `000402701189d90cfc5fe1aa643e493a50801332e1ae8f2830d71a6a162f4765` |
| `settlement_v3_mainnet_v1_sparse` (activated rules, no recipient) | `ff34a548bc6d2632761dd53ab10e8462c88f7137f9606480fd4a2ccbf8da7098` | its identity reproduces the activated configuration `8ec1c804…` |
| `settlement_v3_mainnet_sparse_eager` (measurement only) | `84adfc2ca90dbc8d3f2fb010d89c4a98a618e587b5cc5efb5c3c39c29dfd45e4` | |
| `bloch-evm-sp1-settlement-v3` (SP1 host; features `source-settlement,node-artifact,sparse-witness`) | `3d89f5c3f5d8f8453eb38983d273feab0001c965a1c2c4206a06ef5b24d2c849` | `CANDIDATE_HOST_PIN` (settler installer), `PROVER_SHA256` (prover installer) |
| `bloch-l2-produce-dev` | `779850edebbbb6033266909170c8e17f62b2b47d7c360f29426175e2d1cb7f75` (native `711e60ba`, section 12; native `19aa156d` gave `c6b7ce1b…4d61`, before the merge `63c9cdf8…5a23`) | settler installer `PINS`, `install-shadow.sh` `PRODUCE_SHA256` |
| `bloch-l2-native-follower` | `989bae69debf8e0cac0962594c13dbd41f4a4e6d78453b66ea5fb0db5b81fc3e` (native `711e60ba`, section 12; native `19aa156d` gave `ee1b2c8a…d581`, before the merge `051ebfe5…0ee3`) | |
| `bloch-l2-settled-rpc` | `3d116e378616ee8c88e8a93d97514df745ef23ba323040ebefe4f5d54c91351d` | |
| `sequencer_mainnet.py` (shadow) | `1ff6349bc57e407003810c354ff811600fc29727dfd5e1670765da907895a8ae` | `install-shadow.sh` `SEQUENCER_SHA256` |
| `remote_prover.py` | `40f954601a94d9ce2f237af37211cbba1c3e0e0c0a4944cc2ad40714584381c5` | prover installer `REMOTE_PROVER_SHA256` |

The candidate's `GO-LIVE-PINS.sha256` is printed by `python3 deployment/mainnet/refresh_kit_pins.py`.

**`GO-LIVE-PINS.sha256` and `GO-LIVE-PINS-PROVER.sha256` of this branch are the December pin lists (review
R335-4, round 17).** Their binary lines are the build of section 12 (round 18): `artifacts/` (follower, producer,
settled RPC, `build.json` `ed14d087…3d5a`, the build's `SHA256SUMS` `f7451834…b23d`), the settler's producer and SP1
host, the prover's SP1 host, and one line for each December guest (`settlement_v3_mainnet_sparse`,
`settlement_v3_mainnet_fallback`) beside the activated guest, which the settler proves with until the swap.
`release-settler-v2/bloch-pos` stays the released node binary the settler host uses as DA key tool (the
installer's pin). `test_install_settler_mainnet` and `test_prover_mainnet` compare every installer pin with its
line. What is still the launch's on this branch:
- `follower-rpc/install.sh` accepts only the signed launch release (`RELEASE_SHA256SUMS_SHA256` `6d3bd628…`).
  A December release folder (the build output plus manifest, carryover and `build.json`, as
  `docs/RELEASE-SIGNING.md` assembles it) and its signing target do not exist; until they do, the
  `artifacts/SHA256SUMS` line holds the BUILD's `SHA256SUMS`, and the follower installer refuses the December
  artifacts.
- `docs/L2-MAINNET-GO-LIVE.md` is the launch plan with this tree's hashes in its table; a December plan
  section is not written.

**How far each identity is reproduced.**
- The four guest ELFs: built from b635566 in the pinned container on **two hosts** (build host A, image
  `sha256:b2badcc6…45ca`, twice in separate scratch directories with an empty crate registry; build host B, image
  `sha256:4cec7b91…a83b`, once): the three `SHA256SUMS` files are identical.
- After the merge with `main` (native `711e60ba`, round 18): see section 12.
- After the merge (native `19aa156d`): the SP1 host and the three binaries were built ONCE more from nothing on
  build host A (`build-prover-host.sh`, `build-release.sh`, L2 `3cbc421`). The SP1 host and the settled RPC came
  out as before the merge; the follower and the producer are new and are **not yet reproduced on a second host**.
- Before the merge, the SP1 host and the three L2 binaries (follower, producer, settled RPC): **reproduced on two
  hosts and two paths.** Four builds of c2938be, each compiled from nothing (`/var/tmp/bloch-l2-build` removed first), with
  `build-prover-host.sh` and `build-release.sh`: build host A from the source directories `…/l2-r15/dec` and
  `…/l2-r15/p2/another-place`, build host B from `…/l2-r15/dec-b1` and `…/l2-r15/elsewhere/dec-b2` (2026-11-16,
  21:06 to 21:43 UTC). The four SP1 hosts are one file and the four `SHA256SUMS` of `build-release.sh` are
  identical (`build.json` too). The binaries contain no build path (`strings`: no `/home`, no `/var/tmp`).
- **The earlier pins are withdrawn** (SP1 host `04fc2d32…8439`, producer `96b09d1a…87a3`, follower
  `76c14194…eae3`, settled RPC `1cfbe6e5…de2c`): they reproduce only in the directory
  `/home/ubuntu/l2dexbridge-20261030/l2-r15/dec` (a second host gave them there and three other hashes in a
  directory of another name). Three things tied the binaries to the directory, found one after the other:
  1. They embedded the paths of the sources, the cargo registry and the target directory (panic locations).
     Remedy: `--remap-path-prefix` for the three prefixes (ade9c59).
  2. The SP1 host embeds a runner binary that a build script builds with a nested cargo after removing
     `RUSTFLAGS`: 152 paths stayed. Remedy: the flags go as `CARGO_BUILD_RUSTFLAGS`, which the nested cargo
     inherits; the runner binary is then one file in every directory.
  3. With 1 and 2 no path was left in any binary, and still four directories gave four SP1 hosts
     (`11d9df08…`, `3e838973…`, `b8d45615…`, `f02ef8ae…`) and four sets of the three binaries: cargo names a
     crate by a hash that takes in the absolute path of each path dependency outside the workspace (the L2 root
     crate, the native crates, the reth snapshot), and every symbol carries it. No flag reaches that. Remedy:
     the two build scripts copy `WORK/src` to one fixed directory, `/var/tmp/bloch-l2-build`
     (`deployment/mainnet/build-root.sh`), and build there, whatever `WORK` is.
- Limits of this reproduction: both build hosts run Ubuntu 24.04.5 with gcc 13.3.0 and build as the same user
  name with the cargo home in the same place. The cargo home is remapped and no trace of it is in the binaries,
  but a build by another user, or on another distribution, was not made. `protoc` differs between the two hosts
  (the system's on A, a downloaded one on B) and does not change the result.
- No real proof was made under the new program keys. The native Groth16 fixture test and the crossing rehearsal
  with a real sweep to the recipient are part of the next real-proof run.

## 4. How to reproduce

`S` is `deployment/mainnet/set-sweep-recipient.py`; the full procedure is `deployment/mainnet/SWEEP-RECIPIENT-PROCEDURE.md`.

1. Guests, from a git checkout of this branch, in the pinned container:
   `DOCKER=… DOWNLOADS=… WORK=/tmp/x integrations/sp1-execution/guest-sparse/build-container.sh OUT b635566`
   and the same with `guest-fallback`. Compare `OUT/SHA256SUMS` with section 3.
2. SP1 host, with the sibling layout `WORK/src/{bloch-l2-evm,bloch-validator-payout,reth-bloch-rpc-snapshot}`:
   The sibling `reth-bloch-rpc-snapshot` is the pinned commit `8eb21017` PLUS the recorded patch: after cloning
   it, run `python3 integrations/reth-execution/prepare-reth.py` once in the L2 tree (it applies
   `reth-snapshot.patch` to the sibling; `--check` then passes). With a clean clone of the pinned commit alone
   `build-release.sh` stops at once with "Prepared Reth differs from the recorded patch" (agent 333, F333-1).
   `bloch-validator-payout` is bloch-sis-pow at exactly the native commit of section 2, clean.
   `JOBS=6 deployment/mainnet/build-prover-host.sh WORK OUT-HOST` (features
   `source-settlement,node-artifact,sparse-witness`). Compare `OUT-HOST/SHA256SUMS` with section 3.
3. Identities: `bloch-evm-sp1-settlement-v3 --mainnet --sparse identity OUT/settlement_v3_mainnet_sparse` and
   `--mainnet identity OUT2/settlement_v3_mainnet`; they must print the values of section 3.
4. Binaries: `JOBS=6 deployment/mainnet/build-release.sh WORK OUT` with native at `711e60ba` (the script checks
   the sources, applies the inert feature shim and refuses another native commit or lock).

`WORK` may be any directory and the builder any user: steps 2 and 4 copy `WORK/src` to `/var/tmp/bloch-l2-build`
and build there (section 3 says why), one build at a time per machine; the trees under `WORK` are not modified.
Each run of either script empties `/var/tmp/bloch-l2-build` first, target directories included, so everything is
compiled every time (review R335-2: until round 17 this was a sentence here, and a build after another tree's
build could reuse that tree's compiled crates). `RUSTFLAGS` must be unset.
The machine: x86_64 Linux with the toolchains of `rust-toolchain` files (rustup 1.98.1), `protoc`, and the C
toolchain of Ubuntu 24.04 (gcc 13.3.0; its start files and the C code some crates compile are part of the
binaries). Another distribution is not expected to give the same bytes and was not tried.
5. `python3 S audit --l2 L2 --native N` exits 0; `python3 deployment/mainnet/refresh_kit_pins.py` reports no
   difference.

Times on build host A (32 threads, builds at `-j 6`, niced): each guest crate 1 to 2 minutes; SP1 host 6 minutes;
identities under 1 minute; `build-release.sh` 12 minutes; root crate checks and tests 5 minutes; native committee
and node suites about 15 minutes.

## 5. If the owner picks another fee-sweep recipient (or another treasury)

Another **fee-sweep recipient** moves the configuration and with it every guest identity; no source logic changes.
Steps that run again, in order, and what they took here:
1. `python3 S set NEW --confirm NEW --l2 L2 --native N` (seconds; it rewrites every text naming the old recipient).
2. Both guest crates on two hosts (2 x 2 builds of 1 to 2 minutes).
3. The SP1 host (6 minutes): it links the chain specification, so it is rebuilt and its new hash is the pin; then
   the identities with it (under 1 minute).
4. `python3 S pins …`, commit native, `python3 S native-commit …`, `python3 S audit …` (seconds).
   Between step 1 and `pins` the trees pin the new configuration beside the identities of the guests built for
   the old one. Step 1 records that in `deployment/mainnet/SWEEP-PINS-PENDING.json` (committed with its edits);
   while the record is there `native-commit`, `audit` and the kit build's gate (`gate --l2`, called by
   `build-release.sh`) refuse, in whatever order they are run; the guest builds are not held; `pins` with
   identities made for the new configuration removes it (review R335-1).
5. `build-release.sh` on two hosts (12 minutes each), then the pins of the SP1 host, `bloch-l2-produce-dev` and
   `refresh_kit_pins.py --write` (seconds).
6. Suites: native committee and node (15 minutes), L2 clean export (about 40 minutes with a cold cache).
About one and a half hours of machine time on one host, plus the second host (`build-prover-host.sh` 6 minutes
and `build-release.sh` 12 minutes, one after the other: they share the fixed build directory). Item U5 (formatting) does not
run again.

Another **treasury** changes one native constant (`PROTOCOL_TREASURY_SCRIPT_HASH`). The guest ELFs, their keys
and the configuration do not move. The three L2 binaries link the native transition and are built against a named
native commit, so `build-release.sh` runs again against the new commit and their hashes and pins move; the SP1
host did not change with the native program pins here and is expected to stay, to be confirmed by its rebuild.
Steps: edit, native suites (15 minutes), native commit, `python3 S native-commit …`, `build-release.sh` (12
minutes per host), binary pins, `refresh_kit_pins.py --write`.

## 6. Tests on these tips

Clean `git archive` exports on build host A, own build directories (2026-11-16, after the rebuild):
- Rust, at the build commit c2938be (no Rust source, manifest or lock changed since b635566): root crate
  `cargo fmt --all -- --check` 0, `cargo clippy --all-targets -D warnings` 0, the same with `--all-features` 0;
  tests 282 / 287 (serde) / 282 (no default features), 2 ignored; release tests 24; reth-execution 223 passed,
  1 ignored; settlement-recovery 66 (with the pinned native lock); escrow-journal 29; entrypoint API 2; SP1 host 37.
- Python, at 9abc423 (the pins): devnet 529; mainnet 520 (33 skipped: the real-binary tests, run apart, and the
  sweep tests that start from the unset tree); public-rpc 19; attestor 93 (35 skipped); withdraw 44.
  `refresh_kit_pins.py` reports no difference.
- With the December producer `63c9cdf8…`: `test_shadow_settler_real_binary` 5 of 5 (settler and shadow on one
  pool, a reordered block, the full block with newcomers, a forced-only block and a forced-plus-user block under
  the next rules).
- `build-prover-host.sh` and `build-release.sh`: four times each (section 3), one result.

Native 0861278c (unchanged since the first build of this document), clean export, same host:
`cargo test -p bloch-pos-committee`: 1,007 passed, 0 failed, 15 ignored; `-p bloch-pos-node`: 842 passed, 0
failed, 31 ignored (one of them, `native_passphrase_tty`, needs a terminal and was run in a foreground `ssh -tt`
session).

## 7. Fixed in this build from the real-proof drills (agent 317, on e8f40c2) and the seventh review pass

| Finding | Fix | Test |
|---|---|---|
| F317-1 (High): the prover profile never reached the remote prover; a full block of 64 plain transfers was killed at 64 GiB and proved again for ever | The job frame carries the block's settings (version 2); a killed proof falls back to the two-core-worker settings, is logged `prover-oom`, and three kills at the safest settings halt the worker | `test_settler_policy_v2.Profiles` (frame, fallback, bound). **Not yet proven with a real proof.** |
| F317-2 (Low): four setting names lacked `SP1_WORKER_` | Renamed; a test ties them to the remote prover's allowed names | same |
| F317-3 (Medium): the one-eighth reserve was not delivered on a full block of 64 | The planner's reserved places go to senders without credit first | `test_round15_producer_write_price.ReserveHoldsOnAFullBlock`; on the real producer `test_shadow_settler_real_binary.ReserveOnAFullBlock` (56 covered, 8 newcomers) |
| R308-7P-2 (Low): a proof that fails every time in another way than a kill of the SP1 host was retried without a bound | Every failed proof of a block that took a minute or more is counted, whatever the exit code; five halt the worker (`prove_failed_max_attempts`, `prove_failed_min_seconds`); a failure that cost no proving stays with the retry | `test_settler_policy_v2.Profiles` (three tests). Python only |
| R308-7P-3 (Low): the planner called a transaction covered by its gas used, the producer by its gas limit | The planner reads the declared gas limit from the signed bytes | `test_round15_producer_write_price.CoveredIsTheProducersRule` (three tests; the first fails without the fix). Python only |
| F317-4 (High, operations): the shadow halted after a block whose only transaction is a forced record | The shadow reads the due forced records from L1 and passes them to the producer; the DA batch counts user transactions only | `test_sequencer_mainnet` (three tests); on the real producer under the next rules `test_shadow_settler_real_binary.ForcedBlocksUnderTheNextRules` |

The launch kit: F317-1 needs user transactions (a full block of 64 transfers); the deposit-only kit's largest
block is 64 deposits, which proves inside the 64 GiB scope with the installed settings (agent 312: prover slice
peak 20.7 GiB on a deposit-only block, SP1 host RSS 22.0 GiB at most; agent 317: 64 deposits plus 18 transactions
proved in 370.7 s with the fast settings). F317-4 needs L1 forced inclusion, which the launch release does not
have (the gate is in the December fork). Neither is a launch-line item.

## 8. Not yet proven (for the next real-proof run on this build)

**Round 17 update (2026-11-17).** The first real-proof run on this build exists: agent 317, Part B, continued by
agent 333 (`agents/317-l2-proof-drills-r15.md`, `agents/333-l2-proof-drills-r17.md` in the coordination folder),
on a private net with the real SP1 host, settled RPC and both guests of section 3 and the compiled recipients;
the L1 node, follower and producer there are forced builds (gate epochs and a throwaway attestor set only).
Proven there so far: a real Groth16 proof under the new `PROGRAM_NEXT` key and the swap; the documented install
with user transactions; the full block of 64 transfers with the profile reaching the remote prover (439.0 s, SP1
host peak 39.9 GiB, no rig workaround); the bound on memory kills (three kills, halt); the reserve on a full
block (56 covered, 8 newcomers); the crossing fee and a forced surcharge paid to the treasury script; a
forced-only block matched by the shadow. One defect seen there is fixed on `codex/l2-r17-pins-20261117` (the
local proof after a remote memory kill used the killed settings). The list below is what was open before that
run; the items it does not name above are still open.


- A real Groth16 proof under the new program keys; the native fixture test under them.
- The memory fallback of F317-1 on a real proof, and the full block of 64 transfers without the rig's workaround.
- S7 on the sparse guest; the clock and step-restart spool drills.
- The positive attested claim (3 of 5) and the sweep to the recipient in the fork crossing; the base-fee floor.
- The 96 GiB block (`mandatory-heavy`).
- A spend from the treasury output; the DEX and bridge flows of task 268.
- The binaries built by another user name, with another cargo home, or on another distribution (section 3).

## 9. Still owner inputs

The fork epoch (every L2 gate is inert until it is set), `PROGRAM_NEXT_FINAL` (the sign-off of the final guests),
the exempt sender list, the form of the rollback reset and who covers a forfeit shortfall, the signature on the
release.

## 10. The launch release 926d2cf and the build path

The launch release (`SHA256SUMS` `6d3bd628…9c19`) has the same dependence on the build directory and is NOT
rebuilt: its `build-release.sh` has neither the remapping nor the fixed directory. It was built by agent 195 from
fresh clones on both build hosts at one reference `WORK` path, `/home/ubuntu/hf-release-kit-20261020/l2-78d4921c-v2`
(a bind mount in a private mount namespace), byte-identical; agent 312 did not rebuild it (it checked the files
on the host against `SHA256SUMS`). The kit's plan names that path (`docs/L2-MAINNET-GO-LIVE.md` section 3.1,
"To reproduce"). Documentation item for the launch release notes: state that the release reproduces only when
built at exactly that path, as user `ubuntu` with the cargo home `/home/ubuntu/.cargo` (the registry path is
embedded too), on Ubuntu 24.04; the public copy of the plan replaces the user name by a placeholder
(`/home/<operator>/…`), so a third party cannot read the path from it and the release notes must give it literally.

## 11. The native line merged onto the released node (round 17)

The December native line branched from the release line at `4f34d87e`. The node the fleet was given is
`release/node-906336fd-20261113`, 117 commits further on that line: the security fixes of 2026-11-10 to 11-13,
the vote slot-epoch binding and the KES first-key floor armed at epoch 8620, and the state preflight of L2
deposits, DA batches and claims in the mempool. A December fork node must be that node plus the L2 changes.

**Native `codex/native-l2-dec-merge-r17-20261117` `19aa156d`** = merge `a49c5bbb` of `906336fd` and `189f3178`,
plus one test and two notes. Every L2 gate is still `u64::MAX`: `scripts/hf-release/hf-gates.py discover --base
906336fd --candidate 19aa156d` lists exactly the five L2 gates, all inert, and no other difference. What the
merge decided, file by file, is in the merge commit's message and in `docs/L2-MEMPOOL-ADMISSION.md` of the
native tree (the mempool door: the released preflight judges the deposit, the DA batch and the claim; the
fork's own check remains for the forced envelope).

**What moved in this tree.** Only what links the native transition:

| Artifact | Before the merge (native `0861278c`) | After (native `19aa156d`) |
|---|---|---|
| `bloch-l2-native-follower` | `051ebfe5…0ee3` | `ee1b2c8ac780c0803dcdeda97ce143627c7c3b4556334f44588080bd3c1fd581` |
| `bloch-l2-produce-dev` | `63c9cdf8…5a23` | `c6b7ce1b921134b73da4a85d0944e630f26e44dce604a4e10f2c0db7622e4d61` |
| `bloch-l2-settled-rpc` | `3d116e37…351d` | the same |
| `bloch-evm-sp1-settlement-v3` (SP1 host) | `3d89f5c3…c849` | the same |
| `sequencer_mainnet.py`, `remote_prover.py` | | the same |
| Guest ELFs, their keys, the configuration `27d6ce9f…2783`, the proof policy | | the same: no file a guest is built from changed (the guests do not link the native crates), so they were not rebuilt |
| Build `SHA256SUMS` / `build.json` | `22a662e9…0729` (reviewer 335's build) | `b89b58791506835579fcfd59464a73eef9081edb40372920d02928545ea3957f` / `e88a0836526b74be97fa62b059ed72c114aaa0552be979e75e44ead0c43def05` (`l2_commit` `3cbc421`) |
| Source pins | `install-settler-mainnet.py` `a31bdb83…96bb`, `install-shadow.sh` `a7276be6…5e7e`, `build-release.sh` `87d0ce99…7482`, `GO-LIVE-PINS.sha256` `4a6a0b61…f738`, `GO-LIVE-PINS-PROVER.sha256` `149189a6…0cde` | `136a081a…df76`, `0c630ba3…b07d`, `135ff8f0…8555`, `741828a328c3835980b8acf563128b5cfbf6f469bfbb3d252b94ac38058bf00e`, `b974e5cf…2ee7`; `follower-rpc/install.sh` `d2a41ac1…8ab1` (was `3984e0ed…5854`: the tip floor of 2026-11-17, `docs/MAINNET-RPC-READINESS.md`) |

The settlement-recovery lock is unchanged (`ab7b3a09…`): between `0861278c` and `19aa156d` three native
`Cargo.toml` files differ in comments and in two features without dependencies, and the native `Cargo.lock`
does not; `cargo build --locked` accepted it. `set-sweep-recipient.py native-commit` refuses any native
`Cargo.toml` difference, so the two commit pins were moved by hand to what it writes.

**What the followers gain.** The follower and the producer verify L1 blocks with the native code they link.
Built against `19aa156d` they carry the two rules the released node arms at epoch 8620; the build against
`0861278c` did not (open item N2). No follower of this build was run against a chain across 8620.

**Real-proof drills.** Agent 333's results of round 17 are for the identities before the merge. The guests and
the SP1 host are the same files, so its proving results stand for them; every result that ran the follower or
the producer of `0861278c` must be repeated with the two new binaries (list in the coordination folder's
cross-area log, 2026-11-17).

## 12. The merged line brought up to date with `main` (round 18)

bloch-sis-pow `main` moved after section 11 was written: `857a10ac` is PR #35, the deployed node release
`0067547f` (= `906336fd` + 49 node commits: the KES half of the block door, the Sentinel hooks, mempool source
budgets for funded delegation and commission updates, the `--reject-block-root` residues, supply-chain bumps)
merged into `main`. The native line took it by a merge commit, so nothing published was rewritten:

**Native `codex/native-l2-dec-merge-r17-20261117` `711e60ba`** = `f596fb78` (merge of `main` `857a10ac` into
`19aa156d`) + `8ba38c14` (a restated test, test-only) + `711e60ba` (notes). Of the files changed on either side
since `906336fd`, the 132 only `main` changed are byte-equal to `main`, the 39 only the L2 line changed are
byte-equal to `19aa156d`, and of the 6 both changed only `bloch-pos-node/src/rpc/tests.rs` conflicted (both
appended tests; both kept). `hf-gates.py discover --repo . --base 857a10ac --candidate 711e60ba` lists exactly the
five L2 gates, all inert. The suites, the CI-equivalent run and the mainnet replay of both trees are in the
coordination report of agent 382 (`agents/339-l2-native-merge-r17.md`, section R18).

| Artifact | Native `19aa156d` (section 11) | Native `711e60ba` |
|---|---|---|
| `bloch-l2-native-follower` | `ee1b2c8a…d581` | `989bae69debf8e0cac0962594c13dbd41f4a4e6d78453b66ea5fb0db5b81fc3e` |
| `bloch-l2-produce-dev` | `c6b7ce1b…4d61` | `779850edebbbb6033266909170c8e17f62b2b47d7c360f29426175e2d1cb7f75` |
| `bloch-l2-settled-rpc` | `3d116e37…351d` | the same |
| `bloch-evm-sp1-settlement-v3` (SP1 host) | `3d89f5c3…c849` | the same (rebuilt) |
| `sequencer_mainnet.py` | `1ff6349b…a8ae` | the same |
| Guest ELFs, keys, configuration `27d6ce9f…2783`, proof policy | | the same, not rebuilt (no guest input changed; the guests do not link the native crates) |
| Build `SHA256SUMS` / `build.json` | `b89b5879…957f` / `e88a0836…ef05` (`l2_commit` `3cbc421`) | `f7451834c7fa19635586a38b2718d7ce0a90525d66943b13470dfc9fe759b23d` / `ed14d087360f9f6738fef400420c3a95a8b1913e44c9db81ea650c0f39ae3d5a` (`l2_commit` `904e6d4`) |
| `GO-LIVE-PINS.sha256` | `741828a3…f00e` | `6b0dbee2fdc995fcaf664f2b408656359831fd9a117c645c4e353124028a030b` |

**The lock.** The settlement-recovery lock is unchanged (`ab7b3a09…`). Between `19aa156d` and `711e60ba` no
`Cargo.toml` of a native crate this tree builds changed; the native ROOT `Cargo.lock` moved (gossipsub 0.49.5,
tokio 1.53.3, rustix 1.1.6, the release's supply-chain fix L1M-17) and so did `services/pq-shield-api`. This tree
builds with its own lock, so **those bumps do not reach the three L2 binaries**: they keep the versions of
`ab7b3a09…`. Taking them would be a new lock and a new identity of every binary, the settled RPC included; it is
listed as open, not done. `set-sweep-recipient.py native-commit` refuses by rule ("native lock inputs changed")
and was not weakened; the two commit pins were moved by hand to what it writes (`build-release.sh` header).

**What the followers gain.** Built against `711e60ba` the follower and the producer link the deployed release's
native code (`0067547f`), including its KES attribution change (`kes.rs`, audit L1-17). Not run: a follower of
this build against a chain across epoch 8620 or across a late KES registration (agent 340's case).

**Reproduction.** Built three times from nothing on build host A, each byte-equal (all of `SHA256SUMS`, and
`build.json` between the two builds of the same commit): agent 382 from `…/l2-merge-r18/work` and from
`…/l2-merge-r18/p2/elsewhere` (L2 `904e6d4`), and reviewer 384 independently (`rel-dec71`). Not on a second host.

**Superseded by section 13** (the F387-1 fix moves the producer and the settled RPC).

## 13. Native `b7cd752b` and the F387-1 fix (round 18)

The native pin is `b7cd752b` (= `711e60ba` + test-only commits; bloch-sis-pow PR #37 merged it into `main` as
`c8a088cb`). The L2 tree carries the fix of agent 387's F387-1 (High): the producer's next header, reth's
`next_block_base_fee`, the settled RPC's spool head and `eth_gasPrice` floor, and the producer's tip hold take the
base fee of the rules of the block being built (`RuleSchedule::at`), so the next rules' base-fee floor (0.1 gwei)
is applied where the executor requires it. Under the base rules nothing changes. Build commit `7a3b695`:

| Artifact | Section 12 (native `711e60ba`, no fix) | Native `b7cd752b`, F387-1 fixed |
|---|---|---|
| `bloch-l2-native-follower` | `989bae69…fc3e` | `c4bf512e5ad0f5ef4ab8c132c6dc2d6e7a23a1e21dcaee6b232fa1e70ea79e28` |
| `bloch-l2-produce-dev` | `779850ed…7f75` | `364df3a3e5cb991f87d614676675448b08456ad8ad4bbd9af1425a3a925e0bc0` |
| `bloch-l2-settled-rpc` | `3d116e37…351d` | `304a9f5823bfae7cc59ff3799a7c4131c008f2c57255bfe9a49bf3aae07c898f` |
| SP1 host, `sequencer_mainnet.py`, guests, keys, configuration | | unchanged (`3d89f5c3…c849`, `1ff6349b…a8ae`; the guests do not link the changed crates) |
| Build `SHA256SUMS` / `build.json` | `f7451834…b23d` / `ed14d087…3d5a` | `27cfa4a34f9abcc68e47795b63f386e705b84747908a37e358415a2c677da2cf` / `94c3e3d2b005b3ff56573b93be6811eb940979754c3fc9355e10bfaa4daf688e` |

Also in this tree since section 12: every settled-RPC unit passes the 1 gwei tip floor (review R384-2); the
monitor carries agent 340's fix (an armed L1 gate missing from the L2 build is critical) and its build constants
name this build (review R384-6: `V2_BUILD`, `V2_SHA256`, the two 8620 gates in `V2_COMPILED_GATES`).

Reproduction: built twice from nothing on build host A from two directories (`…/l2-merge-r18/work3` and
`…/l2-merge-r18/p3/elsewhere`): every file of the two release outputs is byte-equal, `build.json` included.
Python suites at `161553e` (host, clean clone): devnet 531, mainnet 527 (33 skipped), gateway 19, attestor 93
(35 skipped), withdraw 44, replica 46 (16 skipped), follower-rpc 21, publish-safety 18; `refresh_kit_pins.py` exit 0.

Not done: a second host; the end-to-end `extend` across the floor with the rebuilt producer (agent 387's D1 rig);
the real-proof drills on these binaries.

## 14. The parent link on the next rules (round 18, third launch of agent 382; superseded by section 15)

Agent 387 re-tested section 13 on the real-proof net: the producer built the floored block, but the next block
was refused with "V2 parent linkage or context mismatch": three validators of the parent link still judged the
base fee on the base rules (`BlochConsensus::validate_header_against_parent`, the block assembler, the canonical
settlement audit). `6a0cc18` (failing-first `d4a6759`) made them use the rules of the child block. That launch
built `6a0cc18` twice (`…/l2-merge-r18/out5-release`, `out6-release`, byte-equal: follower `3d3d913c…127e`,
producer `aef978a6…1944`, settled RPC `8dc40b05…4b43`, `SHA256SUMS` `7b0ca1d5…ce0e`) but stopped before it
committed or posted those pins; they were never in a pin list and are recorded here only so that a binary with
one of these hashes can be named.

## 15. One source of the per-block rules; the round-19 December build (agent 404)

**F387-1 closed, end to end.** Two tests drive the producer binary across the base-fee floor
(`integrations/settlement-recovery/tests/rule_schedule.rs`, `f387_1_*`): the next rules from block 2 until the fee
has been at the floor for four blocks (agent 387's case), and the base rules until the fee is under the floor,
then the switch (the launch chain's case: the base rules have no floor, so about 580 quiet blocks after genesis
every program swap happens under the floor, and the first next-rules block starts at 0.1 gwei, a step up from its
parent). Each then runs `select`, exports the complete and the sparse artifact of the blocks at the floor, decodes
them under the block's rules (and is refused under the other rule set), and rebuilds the whole chain from L1 data
alone (`reconstruct`). On `f694f88` both fail ("block 575 … V2 parent linkage or context mismatch"; "the switch
block 581 … V2 parent linkage or context mismatch"); on `6a0cc18` and after, both pass.

**One source (`fadb157`, `3cd05e2`, `08b3a61`).** `RuleSchedule` (`integrations/reth-execution/src/rules.rs`)
answers the base fee of the block after a parent and the link of a header to its parent, on the rules of the
block in question; the 13 callers that used to pick a rule set themselves call it; a test reads the sources of
`reth-execution` and `settlement-recovery` and fails on any other call of the kernel's `next_base_fee` or
`validate_parent`. Where each check runs:

| Site | Side | Rules it uses |
|---|---|---|
| producer: next header, tip hold, `fees` (`bloch-l2-produce-dev`, `BlochEvmConfig::next_context`) | host | `RuleSchedule` (block being built) |
| block assembler, `BlochConsensus` (header against parent, body), `context_for_block` | host (producer, follower, settled RPC, shadow) | `RuleSchedule` (the block) |
| canonical settlement audit (`settlement_binding.rs`) | host (follower, audit tool) | `RuleSchedule` |
| proof export (`proof_export.rs`, both exports) | host (settler, shadow) | `RuleSchedule`; the artifact is built with the block's rules |
| reth `next_block_base_fee`, pool maintenance, settled RPC spool head, `eth_gasPrice` floor, admission context | host (settled RPC) | `RuleSchedule` (block after the head) |
| `execution-artifact` (`new`, `decode`: `validate_parent`) | host library (exporter and SP1 host) | the ONE rule set its caller passes; the artifact carries that rule set's configuration commitment and `decode` refuses another. Unchanged |
| SP1 host `bloch-evm-sp1-settlement-v3` (`artifact.rs`, `fixture.rs`, `settlement.rs` cursor) | host (prover) | the rule set of the program being proven (`--mainnet` or `--mainnet-v1`, chosen by the settler from the program L1 reports); the cursor holds one program identity and one configuration. Unchanged |
| guests (`settlement_v3_mainnet_sparse`, `settlement_v3_mainnet` fallback, `…_v1_sparse`) and the kernel they compile (`src/`: `executor.rs`, `node_execution`, `sparse_witness.rs`) | guest | the one rule set compiled into the program; the next-rules guests have had the floor since agent 197. Unchanged |

**No guest identity moves.** No file of the root crate, of the three guest crates, of `execution-artifact` or
of the SP1 host changed since the guests' build commit `b635566` (`git diff b635566 f349f65 -- src Cargo.toml
Cargo.lock integrations/sp1-execution integrations/execution-artifact` prints nothing). Proven by rebuild: both guest
crates built from `f349f65` in the pinned container (build host A, image `sha256:3aaa355d…6316`) give
`81813124…b6d9`, `ff34a548…7098`, `84adfc2c…45e4` and `7528e26d…c3e1`, the values of section 3; the SP1 host
rebuilt from `f349f65` is `3d89f5c3…c849`, as before. Equal ELFs have equal verification keys. The launch line is
not involved.

**The guests accept the floor blocks.** `deployment/mainnet/rehearsal/base-fee-floor/floor_drill.py` (no
network, no key, no proof) on build host A, 2026-11-18: the release producer of this build extends both chains
from a fresh mainnet genesis, and the release SP1 host executes the December guests (SP1 executor) on the
artifacts the producer exports. 16 of 16 steps pass. Chain 1 (next rules from block 2): first block at the floor
575, head 580; the sparse `PROGRAM_NEXT` guest matches the host statement on blocks 574, 575, 576 and 580, the
complete fallback guest on 575 and 576; the activated-rules program refuses block 575 (configuration mismatch).
Chain 2 (base rules to block 580, base fee 97,817,550; switch at 581): block 581 is at 100,000,000 and the chain
goes on there; the activated-rules guest executes block 580, the sparse next guest 581 and 582, the fallback
guest 581, and the activated-rules program refuses 581. Usage:
`floor_drill.py RELEASE_DIR SP1_HOST SPARSE_ELF FALLBACK_ELF V1_SPARSE_ELF NEW_OUT_DIR`.

**Also in this build:** `--rules mainnet-rehearsal` is compiled only with the cargo feature `rehearsal-rules`
(review R335-5; the release producer refuses the flag by name); the shadow makes the settler's three checks on the
due forced records (review R335-8; moves `sequencer_mainnet.py`); the producer has a read-only `fees` command.

Build commit `f349f65`, native `b7cd752b`, lock `ab7b3a09…` (unchanged); supersedes sections 13 and 14:

| Artifact | Section 13 (`7a3b695`) | Round 19 (`f349f65`) |
|---|---|---|
| `bloch-l2-native-follower` | `c4bf512e…7e28` | `301e37306f4624b7d7d2171e6c27d0ecca702d446fd1ff8d742f0d63bd741a8a` |
| `bloch-l2-produce-dev` | `364df3a3…0bc0` | `99c65c2ec23777f060edf93c532d2e7f34a17b2e246de8a050d316d90a8c458c` |
| `bloch-l2-settled-rpc` | `304a9f58…898f` | `cd7ffda73e461592f0b06f17a88c7defee84ac6c7e2759c3c8d37b3f958fb818` |
| `sequencer_mainnet.py` | `1ff6349b…a8ae` | `3ed3b67b44cf26b4e2ad8c9ff850c241a01e12147d2ee5ee6e69fbe34bba132c` |
| SP1 host, guest ELFs, keys, configuration `27d6ce9f…2783`, proof policy, L2 genesis `632e45ae…f468` | | unchanged (host and guests rebuilt) |
| Build `SHA256SUMS` / `build.json` | `27cfa4a3…a2cf` / `94c3e3d2…688e` | `8496a3386e0de0831c7acc9b94e3511168f2d93304281179138fea74b5d5ab50` / `d9dcac1bcbaab2d0ea47cbc048d44e5ed9e055643c7f1b275801bdb6a236e32f` |

The follower moves although its behaviour on a chain is the one of `6a0cc18`: it links `reth-execution`.
`GO-LIVE-PINS.sha256` is printed by `python3 deployment/mainnet/refresh_kit_pins.py`.

Not done: a second host; a real proof of a block at the floor (agent 405's D1 on these binaries); a follower of
this build across L1 epoch 8620.

