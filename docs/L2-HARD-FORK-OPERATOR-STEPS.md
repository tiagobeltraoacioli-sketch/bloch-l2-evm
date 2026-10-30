# Bloch L2 (chain 700770) across the L1 hard forks HF1, HF2, HF3: operator steps

Status: **armed release 78d4921c (2026-10-26); L1 fleet on fa980367 = 78d4921c + mesh transport
(2026-10-28), see §0.** Written 2026-10-20 (mainnet epoch ~6090)
as a plan with every gate inert; §0 records the armed release and the L2 build that follows it. Read
this document with the epochs from the release notice. The epoch numbers are binding.
`epoch_start_utc(E) = 2026-08-13 21:31:19 + E × 960 s` (1 epoch = 16 min, 90 epochs/day).

The L2 activated natively at L1 epoch 5850. Its follower, producer and attestor hosts run the L1
transition themselves, so **every L1 hard fork is also an L2 upgrade**. An L2 binary built against the
old native release halts at the first block it judges differently.

**Owner decision (2026-10-20): deposits and withdrawals are not touched.** The L2 bridge deposit (0x14)
and withdrawal-claim (0x16) formats, their signing, the deposit/withdraw tooling (`bloch-pos l2-deposit`,
`l2-claim`, the attestor kit, `bloch-l2-bridge.py`) and the user-visible flow stay exactly as today.
Nothing in this plan changes them. §5 lists precisely where an L1 fork as currently drafted would still
reach them, so the owner can decide.

## 0. Armed release: native 78d4921c (HF1 + HF2 + HF3)

The L1 release `78d4921c3ec6ba41829f3878eed47f8d3bb96230` arms HF1 (claim finality and frozen set at
7180, own-target votes at 7186), HF2 (slashing v2, growth cap, `SIG_CANONICAL` and `MLDSA_PIN` at
7270), HF3 (PQ migration, suite 0x0003 for spends, KES registration at 7360) and KES enforcement at
8620. `LATTICE` and `SLASHING_ECONOMICS_V2` stay inert. Every L2 follower and producer must run a build
against it **before epoch 7178** (2026-11-01 15:39 UTC).

**L1 fleet on fa980367 (same L2 build).** The L1 fleet runs native
`fa9803671dbf426228a7ded5f569cfcad7b299c2` with `--mesh-security offer`. It is 78d4921c plus two
commits: `0b239d52` ("net: post-quantum mesh security for the devnet transport (--mesh-security)")
and `fa980367` (a rehearsal script). **The L2 build against 78d4921c is the correct build for an L1
running fa980367. Do not rebuild the L2 against fa980367.** Evidence (`git diff 78d4921c fa980367`):

- Changed files: `crates/bloch-pos-node/{Cargo.toml, src/mesh_pq.rs (new), src/net.rs, src/main.rs,
  src/engine.rs (Config: `MeshPlan`), src/engine/replay_bench.rs}`, `Cargo.lock` and
  `scripts/mesh-pq-rehearsal.py`. `params.rs` is unchanged, so the activation epochs are identical.
- No crate the L2 links changed: `bloch-pos-committee`, `bloch-crypto`, `bloch-finality-cert`,
  `bloch-mldsa-clean` and `bloch-l2-proof` have an empty diff. The L2 also links `bloch-pos-node`,
  but only its library target (`src/lib.rs` = `codec` + `genesis`, incl. `genesis_l2.rs`), and none of
  those files changed. All changed node files belong to the `bloch-pos` binary.
- `Cargo.lock`: only the `bloch-pos-node` dependency list (+ `getrandom 0.2.17`, `hkdf`,
  `pqcrypto-mlkem`, `rand_core 0.6.4`, `x25519-dalek`) and one new package, `pqcrypto-mlkem 0.1.1`.
  The settlement-recovery `NATIVE_LOCK` resolved against 78d4921c stays the correct lock for the
  78d4921c build. Do **not** point `NATIVE_COMMIT` at fa980367: `build-release.sh` would refuse the
  checkout, and with a 78d4921c lock `cargo --locked` would fail, because the node package's
  manifest now declares those new dependencies. The L2 binaries would not change anyway.
- Qualification of fa980367 on L1: full-history replay identical to 78d4921c, 0 gates changed.
  The new transport is the L1 nodes' peer-to-peer mesh. The L2 reads L1 only over RPC.

**Status 2026-10-28.** The L1 fleet, including the RPC endpoints the L2 reads (80.240.16.185,
199.247.22.8, 45.77.67.251, port 8080), runs fa980367. The T−2 requirement (§4) is met. Remaining:
every L2 follower and producer on the 78d4921c build before epoch 7178 (2026-11-01 15:39 UTC).

- **Build commit:** the tip of bloch-l2-evm `codex/hf-l2-native-verifier-78d4921c-20261026`. Its
  verifier code is commit `a776134` (on top of `0044697`); the tip adds only this document. `0044697`
  alone does **not** build against 78d4921c (it called a `bloch_crypto` function the release does not
  have and missed the `CompatiblePinned` policy), and even patched to compile it would have **halted at
  the first KES-signed block**, because `verify_kes_leaf` stayed on the trait default (v1 form).
- **Build:** `NATIVE_COMMIT=78d4921c3ec6ba41829f3878eed47f8d3bb96230
  NATIVE_LOCK=<settlement-recovery lock resolved against 78d4921c> build-release.sh WORK OUT`. The lock
  differs from the mainnet lock only by `bloch-finality-cert`, `bloch-mldsa-clean` (native path
  crates) and `fips205 0.4.1` (crates.io).
- **Check `OUT/build.json`:** `l2_tracked_changes` = 0, the pinned L2 genesis reproduced, and
  `l1_activation_epochs` = 7180, 7180, 7186, 7270 ×4, 7360 ×3, 8620, with `"inert"` only for
  `LATTICE` and `SLASHING_ECONOMICS_V2`.
- **Verifier parity with the node:** `NativeConsensusVerifierV1` overrides exactly what the node's
  `HybridVerifier` (bloch-pos-node `src/keys.rs`) overrides, with the same `bloch_crypto` call:

  | Native `SignatureVerifier` method | Node `HybridVerifier` | L2 `NativeConsensusVerifierV1` |
  | --- | --- | --- |
  | `verify_with_key` | `crypto::verify` | `crypto::verify` |
  | `verify_with_key_under` | `crypto::verify_with_policy(crypto_policy(p))`, 4 policies | same, 4 policies (`CompatiblePinned` behind `bloch_native_mldsa_pin`) |
  | `verify_spend_at_epoch` | `crypto::verify_spend(.., params::hf3_slh_suite_active(epoch))` | same |
  | `verify_kes` | trait default (`kes::verify` → `verify_kes_leaf`) | trait default |
  | `verify_kes_leaf` | `crypto::verify_bound` | `crypto::verify_bound` (`bloch_native_kes_leaf`) |
  | `verify_l2_settlement` | `bloch_l2_proof::verify` | `bloch_l2_proof::verify` |

  `build.rs` now fails the build if the native trait gains a method not in this table, so a new
  default can no longer be inherited silently.
- **Tests** (`integrations/settlement-recovery`, against the 78d4921c checkout, with the lock above):
  `cargo test --locked --lib node_parity` must run 4 tests (KES leaf in bound form, the 4-policy
  mapping incl. `CompatiblePinned`, `verify_spend_at_epoch` across the HF3 gate, KES size bound), and
  `cargo test --locked --lib sig_policy` 1 test.

## 1. The forks, as they touch the L2

| Fork | L1 gates (`bloch-pos-committee/src/params.rs`) | Branch (2026-10-20) | L2-relevant change |
| --- | --- | --- | --- |
| **HF1** | `HF1_CLAIM_FINALITY_EPOCH` (CF), `HF1_FROZEN_FINALITY_SET_EPOCH` (p1a), `HF1_OWN_TARGET_VOTES_EPOCH` (p2a) | `codex/hf1-core-20261020`, `codex/hf1-owntarget-20261020` | CF adds a committed `CHECKPOINT-ROOTS` section to the L2 settlement leaf, so state roots differ from the CF epoch on. p1a and p2a change the finality leaf and the FFG tally. Finality can now **halt** (more than 1/3 of the frozen set gone), where the inactivity leak used to restore it. |
| **HF2** | `SIG_CANONICAL_ACTIVATION_EPOCH` (sigdet), `HF2_SLASHING_V2_EPOCH`, `HF2_GROWTH_CAP_EPOCH` | `codex/hf2-sigdet-20261020`, `codex/hf2-slashing-20261020`, `codex/hf2-growthcap-20261020` | From `SIG_CANONICAL` (`A` below) every signature in a block is judged in the **v2 form**: canonical bytes, suite-bound context. A v1 signature is refused. Slashing and the growth cap change state. |
| **HF3** | `HF3_PQ_MIGRATION_EPOCH`, `HF3_SLH_SUITE_EPOCH`, KES (tx 0x17, state 0x22) and LC roster (state 0x23) ported to mainnet | `codex/hf3-tags-20261020`, `codex/hf3-slhdsa-20261020` (uncommitted), KES/LC devnet line | New tx tags 0x17–0x1B and state tags 0x22–0x24. Suite 0x0003 for **eUTXO spends only** (`verify_spend_at_epoch`). KES-signed votes. |

## 2. Component by component (operator side)

| Component | HF1 | HF2 | HF3 |
| --- | --- | --- | --- |
| **Native follower** (`bloch-l2-native-follower`: settler host, attestor hosts, settled-RPC source) | **Rebuild** against the HF1 native release. Otherwise a state-root mismatch at the CF epoch halts it. Its own-chain finality check (`checkpoint(chain, finalized.epoch) == finalized.root`) already matches CF and p2a. | **Rebuild + code change (done):** `NativeConsensusVerifierV1` overrides `verify_with_key_under`. The trait default applies the pre-fork rule and would halt the follower at `A`. | **Rebuild + code change (done, tested against 78d4921c, §0):** override `verify_spend_at_epoch` (fail-closed default would halt at the first 0x0003 spend) and `verify_kes_leaf` (v1 default would halt at the first KES-signed block). The build shim accepts a tree that defines `devnet-kes`/`devnet-lc-roster` itself (done). |
| **Producer / settler** (`bloch-l2-produce-dev`, `settler_v3.py`) | Rebuild: `reconstruct --l1-follower` decodes L1 blocks. The settlement 0x13 is unchanged. | 0x13 carries no signature, so it is unchanged. **DA batch 0x15** (only with `user_transactions`, off on mainnet today): signed `--for-epoch <head>` and **paused during epoch `A−1`** (done). | Rebuild. |
| **Prover** (SP1 `settlement_v3_mainnet`, gnark; host 136) | **No change.** The guest does not link the L1 consensus crate, so program vkey and proof policy `154869964f…` are unchanged. Do not rebuild the guest. | No change. | No change. |
| **Attestor hosts** (3-of-5, set `1c06adbb…`) | Rebuild their follower and producer and update the SHA-256 pins in `config.json`. The signing kit is unchanged. | Rebuild. Signing is unchanged by owner decision. See §5.2 for what HF2 as drafted would do to it. | Not affected by suite 0x0003 (§6). |
| **Light client** (step/release SP1 programs, roster 0x23; not on mainnet yet) | **Required at the LC mainnet port (not implemented):** the roster snapshot (`lc_snapshot`) uses leak-adjusted weights. Under p1a, finality is 2/3 of the frozen set `C`, unleaked, so the roster must be taken from `C`. CF and p2a need nothing (the LC counts votes for the exact link). | **Done (inert):** pure-Rust `verify_bound` and `EpochVerifier`. Votes are judged in the form of their target epoch (v1 below `A`, v2 from `A−1`), for static keys and KES leaves. | The LC reaches mainnet with KES and roster 0x23. Any program change means new vkeys and a **vault re-anchor** (§4.4). |
| **Settled RPC** (`bloch-l2-settled-rpc`) | No native dependency, no code change. L2 `safe`/`finalized` follow L1 finality: under p1a they **stall** during a finality halt. | — | — |
| **Shadow producer, monitor** | No change. | — | — |

## 3. Code prepared (local branches, nothing pushed or deployed)

| Repo / branch | Content |
| --- | --- |
| bloch-l2-evm `codex/hf-l2-compat-20261020` (from 79f5f66) | `settlement-recovery`: `build.rs` probes the native tree and turns on the `verify_with_key_under` (HF2) and `verify_spend_at_epoch` (HF3) overrides, plus a unit test. Settler DA form/pause. `build-release.sh` with `NATIVE_COMMIT`/`NATIVE_LOCK` and `l1_activation_epochs` in `build.json` (`l1_gates.py`). The shim accepts KES/LC trees. This document. |
| bloch-l2-evm `codex/hf-l2-native-verifier-78d4921c-20261026` (from 0044697) | `settlement-recovery` against the armed release 78d4921c: `verify_spend_at_epoch` via `verify_spend` + `hf3_slh_suite_active`, the `CompatiblePinned` arm, the `verify_kes_leaf` override, the trait-method guard in `build.rs`, and node-parity tests (§0). **The L2 build commit for 78d4921c.** |
| bloch-sis-pow `codex/hf-l2-compat-20261020` (from `codex/hf2-sigdet-20261020`) | `l2-da sign --for-epoch/--sig-policy`, `l2-da signature-forms`. **Deposit and claim CLIs untouched.** |
| bloch-sis-pow `codex/hf-l2-compat-lc-20261020` (from `codex/bloch-lc-20261014`) | LC `verify_bound`, `EpochVerifier`, and a mirrored `SIG_CANONICAL_ACTIVATION_EPOCH` (to be replaced by a re-export at the mainnet port). |

While the gates are inert, all of it behaves as before: same command lines, same outputs, same verdicts.

## 4. Steps at each activation

Common to every fork. The L2 roles are: the settler host (follower, producer, settler), the five
attestor hosts, the settled-RPC host, and the L1 RPCs the L2 reads.

- **T−14 (notice):** take the native release commit `N` and its activation epochs from the L1 notice.
- **T−10:** build `NATIVE_COMMIT=N NATIVE_LOCK=<lock resolved against N> build-release.sh WORK OUT`.
  `OUT/build.json` → `l1_activation_epochs` must list exactly the notice's epochs. If it shows
  `"inert"` where the notice has a number, the build is wrong: do not install it.
- **T−7 to T−2:** install on every L2 host. On start, the follower re-verifies retained history from
  Genesis-4, which takes **30–60 min** per host (longer as L1 grows). Upgrade one attestor host at a
  time, keeping ≥ 3 of 5 up. On an attestor host use `install-attestor.sh upgrade --artifacts DIR`
  (`deployment/mainnet/attestor/README.md`, "Upgrade"): it pins the follower as well as the producer
  in `config.json` and runs the checks below itself. Then check:
  - `attestor_agent.py check` prints `check-ok`;
  - the follower's `native_finalized_epoch` advances;
  - `rebuild-check-ok` appears in the logs.
- **T−2:** the L1 RPC endpoints the L2 reads (`--l1-rpc-url`, settler and attestor `rpc_urls`) must
  run `N`. A follower behind an un-upgraded L1 node stalls at the fork. A later L1 commit on top of `N`
  also qualifies when it leaves the consensus transition identical and changes no crate the L2 links
  (§0). For the HF1–HF3 release: `N` = 78d4921c, and the L1 RPCs (80.240.16.185, 199.247.22.8,
  45.77.67.251, port 8080) run fa980367 = 78d4921c + mesh transport. **Met (2026-10-28).** The L2
  build stays the one against 78d4921c.
- **T0:** watch the follower (`verified_slot` advances), settler acceptance and attestor logs. If an L2
  follower halts at the gate with `Transition` or `StateRootMismatch`, it is not running `N`: stop it
  and reinstall. Never skip a block.

### 4.1 HF1

1. Do the common steps with the HF1 release. **Every follower must be on HF1 before the CF epoch `E1`.**
2. At `E1`: claims pause until the first checkpoint recorded under CF finalizes, about `E1+2` (§5.1).
   Deposits, settlements and L2 blocks continue. Post a status note.
3. At the frozen-set and own-target gates: no L2 action. If L1 finality halts, the L2 keeps producing
   and settling but `finalized` stops: no claims, and attestor agents log `awaiting-own-finality`.
   Recovery comes as an L1 release (`NATIVE_FINALITY_SET_RECOVERY_EPOCHS`). Rebuild against it.

### 4.2 HF2 (`SIG_CANONICAL` at `A`)

1. Do the common steps with the HF2 release. The follower must carry the `verify_with_key_under`
   override. `build.rs` sets `bloch_native_sig_policy` when the native tree has the method. Check that
   `cargo test --lib sig_policy` in `integrations/settlement-recovery` runs one test rather than
   filtering it out.
2. Settler (only with `user_transactions` on): pin a `bloch-pos` built from
   `codex/hf-l2-compat-20261020` as the DA signer. It pauses itself during `A−1`. Expect up to one
   epoch of settlement delay at `A`.
3. Light client (once deployed): rebuild the step and release programs with
   `SIG_CANONICAL_ACTIVATION_EPOCH = A` and re-anchor (§4.4) **before `A−1`**. Otherwise step proofs
   stop at the first v2-signed epoch and vault releases halt.
4. Deposits and claims: see §5.2. **Open owner decision before HF2 can be armed.**

### 4.3 HF3

1. Do the common steps with the HF3 release. The follower must carry the `verify_spend_at_epoch`
   (`bloch_native_spend_at_epoch`) and `verify_kes_leaf` (`bloch_native_kes_leaf`) overrides. Check
   `l1_activation_epochs` for the KES and LC gates.
2. HF2+HF3 composition (resolved in 78d4921c): the native `PolicyVerifier` forwards
   `verify_kes`/`verify_kes_leaf` unchanged and routes only suite-0x0003 spends to
   `verify_spend_at_epoch`; the follower's overrides mirror the node's `HybridVerifier` (§0 table).
3. Light client mainnet launch:
   - port the LC to the HF line and use the re-exported constant;
   - take roster weights from the frozen finality set;
   - rebuild the programs, prove a fresh anchor and re-anchor (§4.4).

### 4.4 Light-client program change

The vault's `trustAnchor = SHA256("BLOCH-LC-TRUST-v1" ‖ anchor digest ‖ step vkey)` binds the step
program, so a new step program cannot extend the old proof chain:

1. Build both programs reproducibly and record their vkeys.
2. Prove a new anchor at a recent finalized checkpoint.
3. Update the vault's trust anchor through its guardian or governance path (an Ethereum-side action,
   outside this repo). Rehearse on devnet4 first.
4. Run the old and new provers in shadow, then switch before the fork epoch.

## 5. Deposits and withdrawals: exactly what the forks change

### 5.1 HF1 claim finality (CF): what a depositor, withdrawer or exchange does or sees

- **Deposits (0x14): nothing changes.** Format, signing, timing, fields and tooling are all as today.
- **Claim format and signing (0x16): unchanged.** The same `l2-claim prepare/sign`, the same attestor
  partials, the same bytes.
- **Validity:** a claim already requires the settled root to be in the FFG-finalized prefix, from
  `finalized_claims_from_height` on (today's `NotFinalized`). CF adds one condition: the finalized
  checkpoint must be **this chain's own** checkpoint at its epoch.
  - On a healthy chain this always holds, so nothing changes.
  - It fails only on a branch that finalized another branch's checkpoint during a split. That is the
    double-payout case it exists for (reproduced by
    `split_claim_releases_on_a_branch_that_finalized_the_other_branchs_checkpoint`).
- **Timing, once:** own roots are recorded only from `E1`. Claims therefore wait until a checkpoint of
  epoch ≥ `E1` finalizes, about 2 epochs (~32 min).
  - A claim broadcast in that window is dropped by block producers (`NotFinalized`, same handling as
    today's not-yet-final claims) and has to be broadcast again afterwards.
  - Exchanges: do not broadcast claims from `E1` until finality passes `E1` (or simply retry).
- **RPC (`getl2settlement`), additive, ships with the HF1 release and not gated:** commit d086b133 on
  `codex/hf1-core-20261020` adds `withdrawals.claimable`, `claimable_large`, `finalized_checkpoint`
  (`epoch`, `root`, `own_root`, `own_chain_rule_active`), and a `finalized` flag on `matured` /
  `matured_large`.
  - Existing fields keep their names and meanings.
  - `roots[].finalized` becomes the full consensus predicate, which is identical to today's on a
    healthy chain.
  - The `l2-claim` help text mentions `claimable`. Text only.
  - Tooling that proves against `matured[_large]` keeps working whenever that root is finalized, which
    is already required today.
- **Is CF needed for safety?**
  - Before HF1: yes. The double payout is live today.
  - Inside HF1, as drafted: own-target votes (`HF1_OWN_TARGET_VOTES_EPOCH`, p2a) count only votes for
    the chain's own checkpoints, from a record p2a keeps in the finality state. So once p2a is active,
    a branch cannot finalize a foreign checkpoint, and CF's extra condition is always true.
  - With p2a armed, CF is therefore **defense in depth only**. Its sole user-visible effect is the
    one-time ~2-epoch claim pause.
  - Between `E1` and the p2a gate (≤ 16 epochs) CF is what closes the gap.
- **Gating for the owner's decision:**
  - CF has its own constant, `HF1_CLAIM_FINALITY_EPOCH`.
  - But `codex/hf1-core-20261020` 4ee09f42 now **couples it** to the frozen set: a const assertion
    (`hf1_gates_coherent`) requires both armed together, CF first, ≤ 16 epochs apart. Its stated
    reason is that the frozen set alone still pays a split claim.
  - To let the owner arm HF1 without CF, the HF1 owners would have to allow "CF inert iff own-target
    armed at or before the frozen set" in that assertion. That is not changed here.

### 5.2 HF2 `SIG_CANONICAL`, as drafted, DOES reach deposits and claims (decision needed)

**Superseded in the armed release 78d4921c:** `apply_transaction` judges every transaction witness
(including 0x14 and 0x16 with the attestor partials) under `SignaturePolicy::transaction(epoch)`, which
is `Compatible`/`CompatiblePinned` and never a canonical policy, so v1 signatures stay valid before and
after `A`. Only consensus messages (votes, proposer signatures, slashing evidence, KES leaves) move to
the bound form. The text below describes the 2026-10-20 sigdet branch and is kept for the record.

`codex/hf2-sigdet-20261020` wraps the verifier for every transaction in a block
(`apply_transaction` → `PolicyVerifier::consensus(epoch)`). After `A`, consensus would refuse:

- a 0x14 deposit signed by today's `l2-deposit sign` (v1);
- a 0x16 claim whose funding signature (`l2-claim sign`) or attestor partials (`l2-claim attest`, the
  attestor agent) are v1;
- any deposit or claim signed before `A` but broadcast after it.

That contradicts "signing stays as today". The two options, for the owner and the HF2 owners:

1. **Exempt L2 bridge transactions:** judge the 0x14 and 0x16 signatures (funding and attestations)
   under `Compatible` at every epoch, so today's tools and partials stay valid. This is a small
   consensus change on the sigdet branch. The cost is that these signatures keep the v1 malleability
   the audit closes elsewhere. That is harmless for them, since the txid and nullifier do not depend on
   the signature bytes, but it needs the HF2 owners' review.
2. **Accept the change:** the deposit/claim tools and the attestor kit then need a `--for-epoch` signing
   option and v2 partials. A prototype was written on 2026-10-20 and **withdrawn by the owner decision**;
   it is not on any branch.

Until this is decided, `SIG_CANONICAL` must not be armed on mainnet.

### 5.3 HF3

Deposits and claims are not affected. HF3 opens suite 0x0003 only for eUTXO spends. Funding keys of
0x14/0x15/0x16 stay suite-0x0001 (3,749 B key, signature ≤ 4,593 B) as today. A user whose wallet moved
to 0x0003 still funds deposits and claims from a 0x0001 key.

## 6. HF3 suite 0x0003 and p9g (`codex/bloch-p9g-l2slh-20261019`, c981a331)

**Conclusion: HF3's suite 0x0003 does not affect L2 attestor or withdrawal verification.**

- The attestor set is pinned in consensus as five suite-0x0001 keys
  (`l2_settlement::mainnet::ATTESTOR_SET`, `1c06adbb…`). The claim decoder requires every key to be
  3,749 B and every signature ≤ 4,593 B. A 0x0003 key (1,829 B) or signature (~9.1 KB) is refused
  before any verification. HF3 routes 0x0003 only through `verify_spend_at_epoch`. Claims, deposits
  and DA keep `verify_with_key`.
- The withdrawal proof (a Merkle path to a root the L1 retains), the settlement Groth16 check and the
  SP1 settlement guest contain no attestor or user signature. Nothing changes there.
- Moving attestors to an SLH suite is a separate hard fork, out of scope here (p9g §2):
  - claim version 3 with per-suite lengths;
  - set-hash domain `BLOCH:L2:ATTESTOR-SET:2` including the suite;
  - a gated rewrite of the 0x21 policy leaf;
  - SHA2-128s ‖ ML-DSA-65 recommended over p9a's SHAKE-128s ‖ Falcon.

  That fork would change the claim format, so the owner decision above applies to it.
- SP1 cost (p9g, execute mode): a 0x0003 pair costs ~8.66 M gas, against 2.74 M for 0x0001. This only
  matters if attestations were ever checked in-circuit, which no current program does. For the LC,
  keep validator votes and KES leaves on 0x0001 (~43 verifications per finalization).

## 7. Not done here (owners: L1 HF integration)

- §5.2 decision (exempt 0x14/0x16 from `SIG_CANONICAL`, or not).
- §5.1: CF's coupling in `hf1_gates_coherent`, if the owner wants CF optional.
- LC roster derived from the frozen finality set, at the LC mainnet port.
- The committed tip of `codex/hf2-sigdet-20261020` (2e7cb51b) does not compile: `bloch-crypto`
  `verify_bound` lacks a `pqcrypto_traits::sign::DetachedSignature` import. A fix is in progress in
  that worktree. The branches here were tested with a local, uncommitted import.
- A `settlement-recovery.mainnet.Cargo.lock` resolved against each later HF release (`NATIVE_LOCK`;
  the 78d4921c one exists on the build host, §0).
- SP1 builds of the LC programs with the new verifier (not run here).
