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
  known burn address; `set-sweep-recipient.py set … --confirm …` accepted it. It holds no code (an EOA), so the
  tool's Safe checks do not apply.

Naming the treasury arms nothing: `L2_NEXT_PROGRAM_EPOCH`, `L2_REVENUE_EPOCH`, `L2_FORCED_INCLUSION_EPOCH` and
`L2_PROGRAM_ROLLBACK_EPOCH` stay `u64::MAX`, and `PROGRAM_NEXT_FINAL` stays false. With the treasury named the
compile-time rule now ALLOWS arming forced inclusion and the revenue fee at or after the swap; setting the fork
epoch remains an owner input.

## 2. Branches and tips

| Repo | Branch | Tip | From |
|---|---|---|---|
| bloch-sis-pow | `codex/l2-r15-recipients-20261116` | `0861278c` | a2fc3d0f |
| bloch-l2-evm | `codex/l2-r15-recipients-20261116` | see `git log` (this file is in the tip; the binaries were built at 59f4899) | e8f40c2 |

Native commits: 1650b36d treasury; 36885a1a `set` (configuration); 613ba4d0 one test; 0861278c `pins`.
L2 commits: f32d400 `set`; b635566 root crate rustfmt and clippy clean (item U5; the guests were built here);
f482f92 planner reserve (F317-3); afb75e2 `pins` and `native-commit`; 59f4899 prover profile, shadow and forced
records, binary pins (F317-1, F317-2, F317-4).

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
| `bloch-evm-sp1-settlement-v3` (SP1 host; features `source-settlement,node-artifact,sparse-witness`) | `04fc2d32992ef7c9ada906542953b816c73968b31d44976835fe9b3e4c928439` | `CANDIDATE_HOST_PIN` (settler installer), `PROVER_SHA256` (prover installer) |
| `bloch-l2-produce-dev` | `96b09d1a6bb934af11c144abeec62d4c248704fd00d278cd0b324f4f491687a3` | settler installer `PINS`, `install-shadow.sh` `PRODUCE_SHA256` |
| `bloch-l2-native-follower` | `76c14194e9f5ed95a0ba4623f0588643a679e39d0ee751523411c5409c30eae3` | |
| `bloch-l2-settled-rpc` | `1cfbe6e52428cf1575733988d977517a69e71ec9ccf1e34bba6e98971b72de2c` | |
| `sequencer_mainnet.py` (shadow) | `1ff6349bc57e407003810c354ff811600fc29727dfd5e1670765da907895a8ae` | `install-shadow.sh` `SEQUENCER_SHA256` |
| `remote_prover.py` | `40f954601a94d9ce2f237af37211cbba1c3e0e0c0a4944cc2ad40714584381c5` | prover installer `REMOTE_PROVER_SHA256` |

The candidate's `GO-LIVE-PINS.sha256` is printed by `python3 deployment/mainnet/refresh_kit_pins.py`.

**How far each identity is reproduced.**
- The four guest ELFs: built from b635566 in the pinned container on **two hosts** (build host A, image
  `sha256:b2badcc6…45ca`, twice in separate scratch directories with an empty crate registry; build host B, image
  `sha256:4cec7b91…a83b`, once): the three `SHA256SUMS` files are identical.
- The SP1 host: built twice on ONE host (build host A) in separate target directories, once at b635566 with the
  native tree before the pins and once at afb75e2 with native 0861278c: one hash. It does not depend on the native
  program pins.
- `build-release.sh` (follower, producer, settled RPC): run twice on ONE host in separate target directories at
  afb75e2 with native 0861278c: identical `SHA256SUMS`; a third run at 59f4899 (the Python changes) is recorded in
  section 6.
- **Not done: a second host for the SP1 host and for `build-release.sh`.** a third build host did not answer SSH on
  2026-11-16; build host B was used only for the two short guest builds. Before the release is signed, a second
  host must reproduce these three binaries and the SP1 host; if a hash differs, the pins of section 3 move.
- No real proof was made under the new program keys. The native Groth16 fixture test and the crossing rehearsal
  with a real sweep to the recipient are part of the next real-proof run.

## 4. How to reproduce

`S` is `deployment/mainnet/set-sweep-recipient.py`; the full procedure is `deployment/mainnet/SWEEP-RECIPIENT-PROCEDURE.md`.

1. Guests, from a git checkout of this branch, in the pinned container:
   `DOCKER=… DOWNLOADS=… WORK=/tmp/x integrations/sp1-execution/guest-sparse/build-container.sh OUT b635566`
   and the same with `guest-fallback`. Compare `OUT/SHA256SUMS` with section 3.
2. SP1 host, with the sibling layout `WORK/src/{bloch-l2-evm,bloch-validator-payout,reth-bloch-rpc-snapshot}`:
   `cargo +1.98.1 build --release --locked --manifest-path integrations/sp1-execution/host/Cargo.toml --features source-settlement,node-artifact,sparse-witness --bin bloch-evm-sp1-settlement-v3`
   with `VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1`.
3. Identities: `bloch-evm-sp1-settlement-v3 --mainnet --sparse identity OUT/settlement_v3_mainnet_sparse` and
   `--mainnet identity OUT2/settlement_v3_mainnet`; they must print the values of section 3.
4. Binaries: `JOBS=6 deployment/mainnet/build-release.sh WORK OUT` with native at `0861278c` (the script checks
   the sources, applies the inert feature shim and refuses another native commit or lock).
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
5. `build-release.sh` on two hosts (12 minutes each), then the pins of the SP1 host, `bloch-l2-produce-dev` and
   `refresh_kit_pins.py --write` (seconds).
6. Suites: native committee and node (15 minutes), L2 clean export (about 40 minutes with a cold cache).
About one and a half hours of machine time on one host, plus the second host. Item U5 (formatting) does not
run again.

Another **treasury** changes one native constant (`PROTOCOL_TREASURY_SCRIPT_HASH`). The guest ELFs, their keys
and the configuration do not move. The three L2 binaries link the native transition and are built against a named
native commit, so `build-release.sh` runs again against the new commit and their hashes and pins move; the SP1
host did not change with the native program pins here and is expected to stay, to be confirmed by its rebuild.
Steps: edit, native suites (15 minutes), native commit, `python3 S native-commit …`, `build-release.sh` (12
minutes per host), binary pins, `refresh_kit_pins.py --write`.

## 6. Tests on these tips

L2 59f4899, clean `git archive` export, build host A, own build directories (2026-11-16):
- Root crate: `cargo fmt --all -- --check` 0; `cargo clippy --all-targets -D warnings` 0; the same with
  `--all-features` 0; tests 282 / 287 (serde) / 282 (no default features), 2 ignored; release tests 24.
- reth-execution 223 passed, 1 ignored; settlement-recovery 66; escrow-journal 29; entrypoint API 2; SP1 host 37.
- Python: devnet 523; mainnet 520 (33 skipped: the real-binary tests, run apart, and the sweep tests that start
  from the unset tree); public-rpc 19; attestor 93 (35 skipped); withdraw 44.
- With the December producer `96b09d1a…`: `test_shadow_settler_real_binary` 5 of 5 (settler and shadow on one
  pool, a reordered block, the full block with newcomers, a forced-only block and a forced-plus-user block under
  the next rules).
- `build-release.sh` at afb75e2 (twice) and at 59f4899: the same three binaries; `set-sweep-recipient.py audit`
  exit 0.

Native 0861278c, clean export, same host: `cargo test -p bloch-pos-committee`: 1,007 passed, 0 failed, 15
ignored; `-p bloch-pos-node`: 842 passed, 0 failed, 31 ignored (one of them, `native_passphrase_tty`, needs a
terminal and was run in a foreground `ssh -tt` session).

## 7. Fixed in this build from the real-proof drills (agent 317, on e8f40c2)

| Finding | Fix | Test |
|---|---|---|
| F317-1 (High): the prover profile never reached the remote prover; a full block of 64 plain transfers was killed at 64 GiB and proved again for ever | The job frame carries the block's settings (version 2); a killed proof falls back to the two-core-worker settings, is logged `prover-oom`, and three kills at the safest settings halt the worker | `test_settler_policy_v2.Profiles` (frame, fallback, bound). **Not yet proven with a real proof.** |
| F317-2 (Low): four setting names lacked `SP1_WORKER_` | Renamed; a test ties them to the remote prover's allowed names | same |
| F317-3 (Medium): the one-eighth reserve was not delivered on a full block of 64 | The planner's reserved places go to senders without credit first | `test_round15_producer_write_price.ReserveHoldsOnAFullBlock`; on the real producer `test_shadow_settler_real_binary.ReserveOnAFullBlock` (56 covered, 8 newcomers) |
| F317-4 (High, operations): the shadow halted after a block whose only transaction is a forced record | The shadow reads the due forced records from L1 and passes them to the producer; the DA batch counts user transactions only | `test_sequencer_mainnet` (three tests); on the real producer under the next rules `test_shadow_settler_real_binary.ForcedBlocksUnderTheNextRules` |

The launch kit: F317-1 needs user transactions (a full block of 64 transfers); the deposit-only kit's largest
block is 64 deposits, which proves inside the 64 GiB scope with the installed settings (agent 312: prover slice
peak 20.7 GiB on a deposit-only block, SP1 host RSS 22.0 GiB at most; agent 317: 64 deposits plus 18 transactions
proved in 370.7 s with the fast settings). F317-4 needs L1 forced inclusion, which the launch release does not
have (the gate is in the December fork). Neither is a launch-line item.

## 8. Not yet proven (for the next real-proof run on this build)

- A real Groth16 proof under the new program keys; the native fixture test under them.
- The memory fallback of F317-1 on a real proof, and the full block of 64 transfers without the rig's workaround.
- S7 on the sparse guest; the clock and step-restart spool drills.
- The positive attested claim (3 of 5) and the sweep to the recipient in the fork crossing; the base-fee floor.
- The 96 GiB block (`mandatory-heavy`).
- A spend from the treasury output; the DEX and bridge flows of task 268.
- The SP1 host and `build-release.sh` on a second host (section 3).

## 9. Still owner inputs

The fork epoch (every L2 gate is inert until it is set), `PROGRAM_NEXT_FINAL` (the sign-off of the final guests),
the exempt sender list, the form of the rollback reset and who covers a forfeit shortfall, the signature on the
release.
