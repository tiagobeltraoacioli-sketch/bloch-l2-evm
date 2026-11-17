# The L2 follower and producer against node release 906336fd

Status: **released as the launch build (round 18):** release `bloch-l2-2026-11-17-launch-native-906336fd`, build commit
`3d35a0f`, signing target `4039f26a…` (unsigned; plan §3.1). Below is the original text of agent 340, kept as written.

Original status: **prepared, not released.** This branch (`codex/l2-follower-8620-r17-20261117`, from the launch kit
`2de669e`) holds what a next L2 release needs; it builds no release and moves no binary pin. Rebuilding the L2
binaries moves the launch identity (release 926d2cf, signing target `SHA256SUMS` `6d3bd628…9c19`): that is a
decision of the coordinator and the owner.

## 1. What changed on the L1

Node release `906336fd35f157dac380523b59dee8a5a325175a` (`release/node-906336fd-20261113`) arms two consensus
rules at epoch 8620, together with KES enforcement:

| Rule | Constant | `getchaininfo.hard_forks` name |
|---|---|---|
| A vote's target epoch is the epoch of its slot, and its KES key is the slot epoch's | `ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH` | `hf3_kes_vote_slot_epoch_binding` |
| KES first-key floor: for a KES period before a validator's first KES key there is no KES key; its static key signs | `KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH` | `hf3_kes_first_key_floor` |

Native `78d4921c`, which release 926d2cf links, declares neither constant. The follower and the producer replay
every L1 block with the native code they link (`docs/L2-HARD-FORK-OPERATOR-STEPS.md`: every L1 hard fork is also
an L2 upgrade), so they judge by the rules of 78d4921c.

## 2. What happens to release 926d2cf

- At epoch 8620 itself: nothing. KES enforcement is in 78d4921c, and the slot-epoch binding only refuses votes
  that the older code admits; on one canonical branch of honest blocks both codes select the same key.
- Once KES binds on chain (90% of stake registered; two epochs after the boundary that sees it): **the first
  validator that registers its FIRST KES key after the bind halts every follower and producer of 926d2cf.** Its
  key starts with the next KES period (90 epochs, one day). For the rest of the current period the node release
  lets it sign with its static key (the floor). Native 78d4921c resolves the not-yet-started KES key for that
  period, whose leaf bounds refuse it: the vote, and so the block that carries it, is refused. The follower exits
  3 (`halted: native block …: native finality replay refused: Transition { … }`) and stays halted on every
  restart, because it replays from genesis.
- Who can cause it: any validator that had no KES key at the bind (a late registrant, every validator admitted
  later). It needs no intent, and it costs one registration.
- Effect: L2 finality as the follower reports it stops at that L1 block; the settler (its producer replays L1
  through the same code), the settled RPC's `safe` and `finalized`, the shadow and the attestor feeds stop with
  it. L1 keeps accepting settlements by its own rules; no funds move wrongly. Recovery is a release built against
  906336fd.

Reproduced on 2026-11-17 on a private chain of 906336fd with the gates rescheduled (rehearsal builds; 12
validators, KES enforcement and the two rules at epoch 44, bind at 46, a validator's first registration included
at slot 1730): the followers of 926d2cf / 78d4921c and of the December build / 0861278c had finalized past the
enforcement epoch and the bind, then both exited 3 at the block of slot 1731, the first to carry that validator's
static-key vote: `halted: native block 8be0c1db…04d4: native finality replay refused: Transition { block: 1730,
reason: "Attestation(0)" }`. The follower of the same L2 sources linked against 906336fd kept following.

## 3. The fix

The L2 sources of 926d2cf compile against 906336fd **unchanged** (no Rust source, no manifest). Only the native
commit and the lock differ:

- `deployment/mainnet/follower-rpc/settlement-recovery.native-906336fd.Cargo.lock`, sha256
  `ab7b3a0901f142d5e2a3905c68cf97eb69eb5cc968407621e55f21f14668cafa`: byte for byte the lock the December line pins
  as `settlement-recovery.native-27f195d7.Cargo.lock` (the 78d4921c lock plus `pqcrypto-mlkem` and the mesh
  transport's dependencies). A build without `--locked` against 906336fd leaves it unchanged, so it is the lock
  resolved against that commit.
- `build-release.sh`: `NATIVE_COMMIT=906336fd35f157dac380523b59dee8a5a325175a` selects that lock and refuses any
  other for the commit. The default is still 78d4921c, so the recipe of the signed release is as it was.
- `l2_monitor.py`: an L1 gate with an epoch that the L2 build's gate list does not have is CRIT under
  `l1_gates_vs_l2_build`. Before, the check skipped every gate it had no name for and answered "every L1 gate
  epoch matches the L2 build" for exactly this case.

Build (on each of the two build hosts, in the release's build directory layout; `WORK/src` holds `bloch-l2-evm`
at the release commit, `bloch-validator-payout` at 906336fd, `reth-bloch-rpc-snapshot` at 8eb21017 plus the
recorded patch):

```
NATIVE_COMMIT=906336fd35f157dac380523b59dee8a5a325175a deployment/mainnet/build-release.sh WORK OUT
```

`OUT/build.json` then lists `ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH` and
`KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH` at 8620 under `l1_activation_epochs`. Check it against the fleet:

```
python3 deployment/mainnet/l2_monitor.py --profile mainnet --phase live --build-json OUT/build.json
```

## 4. What moves with a release built this way (the identity batch; not done here)

- The three binaries (follower, producer, settled RPC as far as it links the native crates), `SHA256SUMS`, the
  signing target and its signature; `build.json`.
- Every pin of them: `GO-LIVE-PINS.sha256` (binary lines), `keykit/operator-pins-v2.sha256`,
  `follower-rpc/install.sh --expect-sha256`, `install-shadow.sh` (`NATIVE_LOCK_SHA256`, the producer hash and the
  `build.json` line it prints), `install-settler-mainnet.py`, `prover/install-prover-mainnet.py`,
  `attestor/install-attestor.sh`, `replica/PINS.sha256`, the plan's section 3.2 and its public copies.
- `l2_monitor.py` `V2_COMPILED_GATES` (add the two constants at 8620) and `native_lock_sha256`.
- The attestor operator bundles cut from the kit.

Not moved: the guest programs and their verification keys, the settlement policy, the L2 genesis, the proving
host, the DA signer's wire format.

## 5. Which node commit

The public RPC nodes of the fleet report commit `0067547f…` on 2026-11-17 (906336fd plus 49 commits). In the crates
the L2 links, `git diff 906336fd 0067547f` is one function of node-local relay policy
(`kes::failure_is_attributable`) and a comment, so a build against 906336fd follows that fleet. If a later node
release is published before the L2 release is built, repeat the comparison of `crates/bloch-pos-committee`,
`crates/bloch-crypto`, `crates/bloch-l2-proof` and `crates/bloch-pos-node/src/{lib,codec,genesis,genesis_l2}.rs`
and build against the newest release whose diff there is not empty.

`l1_gates.py` reads the constants named `*_ACTIVATION_EPOCH` and `HF<n>_*_EPOCH`. The third new gate,
`KES_REGISTER_EPOCH_BINDING_EPOCH` (inert in 906336fd), has neither form: when a node release arms it, teach
`l1_gates.py` the name in the same L2 release, or the monitor reports a correct build as not having it.

## 6. The rule for every later node release

A node release that changes any file of that list, or arms a gate, needs an L2 build against it before the gate's
epoch. The monitor now says so (`l1_gates_vs_l2_build`) as soon as an L1 endpoint runs the release; the comparison
of section 5 is the check to run before that, when the release is announced.
