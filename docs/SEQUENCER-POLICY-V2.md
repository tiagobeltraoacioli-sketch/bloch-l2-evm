# Sequencer policy v2: design specification

Status: design and reference planning core, 2026-11-02 (round 10, agent 166). **Not integrated, not built, not run with
real binaries, no proof.** Branch `codex/policy-v2-spec-r10-20261102`, from the user-transaction candidate
`codex/usertx-build-r8-20261102` 4b984af, which no longer carries agent 90's policy.

Reference code: `deployment/devnet/sequencer_policy_v2.py` (pure planner) and
`deployment/devnet/test_sequencer_policy_v2.py` (unit tests named after the review findings).

## 1. Scope

After the December fork, user transactions on L2 700770 need a sequencer policy: rules the settler applies when it
picks spooled transactions for a block. Agent 90's policy (`codex/policy-fixes-r7-20261102` 042cad6) was pulled from the
user-transaction build after agent 135's round-9 re-review (agents/135-policy-rereview.md: U1 and U2 High, U3-U6
Medium). This document specifies the rebuilt policy: every limit, why it exists, the measured number it rests on, how
each finding of reviews r7 (agent 121), r8 and r9 (agent 135) is closed, and the test plan.

The policy is sequencer policy only:

- No block rule. Replay, the guest, the follower and L1 never read it. The guest ELF and the program pins do not move.
- A foreign settler is not bound by it. Forced inclusion (agents 122, 137) is the censorship backstop, not this policy.
- What it moves: the settler's Python (`settler_v3.py`, a new policy module), the producer (`produce-dev select` with a
  per-transaction report), the SP1 host binary (a preflight cycle limit), and one RPC flag (agent 118's
  `--required-tip-file`). Section 8 lists the pins this moves.

## 2. Mandatory items and what the sequencer controls

| Item | Who decides | Bound | Source |
|---|---|---|---|
| Deposits | L1: `min(inbox at the anchor, consumed + 64)`, in order | 64 per settlement (`MAX_INBOX_PER_SETTLEMENT`) | agent 90, native `l2_settlement.rs:728` |
| Forced envelopes (after the fork, if 122/137 ship) | L1: the due records at the anchor | 16 records, 300k declared gas per settlement | agents 122, 137 |
| User transactions from the spool | The sequencer: this policy | Section 3 | |

The sequencer cannot defer, skip or reorder a mandatory item. So the mandatory-only block (deposits plus forced
envelopes) is always measured first, and its cost is the floor of every block.

Measured worst mandatory loads on the sparse guest:
- Deposits: **50.1M SP1 gas** for 64 deposits to 64 contracts with 24,576 bytes of code each (agent 90, sparse ELF
  `75b9c635`).
- Forced: **64.25M SP1 gas, 76.2M instructions** for a 300k-gas modexp record (agent 137).
- Both together: about 114M SP1 gas by addition. **Not measured as one block.**

## 3. The limits

All values are defaults in `sequencer_policy_v2.DEFAULTS`. Every window is in **seconds**, never blocks. Block times
range from minutes to about an hour with pacing (`--min-block-interval 1800`, D15) and proof time (agent 93: up to
3,474 s at height 8191). Block-counted windows were the root of r7 F6 and r8 N9.

### 3.1 Block SP1-gas budget, instruction budget, transactions per block, prover profiles

| Setting | Value | Was (agent 90) |
|---|---|---|
| `max_block_sp1_gas` | **90,000,000** | 150,000,000 |
| `max_block_instructions` | **90,000,000** | optional |
| `max_block_txs` | 64 | 64 |
| `fast_profile_max_sp1_gas` | 10,500,000 | none |

**Why.** A block the prover cannot prove stops settlement. The budget must be a block size that the planned prover
(32 vCPU, 128 GB) has proved, with a memory margin.

**Measured basis (agent 113, sparse guest `75b9c635`, real Groth16 proofs, all verified):**

| Block | SP1 gas | Instructions | Fast settings (32 threads, `ELEMENT_THRESHOLD=2^28`) | Low-memory "2c" settings |
|---|---:|---:|---|---|
| Settled blocks 1-15 of the DEX launch | 0.7-10.2M | 0.5-9.1M | **proved, 291-449 s, 27-41.2 GiB** | |
| 64 swaps, 64 users, seeded pool | 65.1M | 62.8M | **OOM at 48 GiB (75 s) and at 64 GiB (130 s, peak 63.0 GiB)** | proved, 1,007 s, 47.2 GiB |
| 64 swaps, 100k `approve` slots in bUSDC and the pair | 93.8M | 91.4M | not tried | proved at 64 GiB, 1,743 s, 54.8 GiB (host load about 34) |

Consequences:
- **Memory binds, not SP1 gas** (X17). Agent 90's 150M rested on complete-guest proofs at a 92 GiB scope (157M at
  h4097 in 1,772 s). The sparse guest has not been proved above 93.8M.
- **90M** is the largest round figure under the largest proved sparse block (93.8M at 54.8 GiB). Fitting the two 2c
  points gives about 30 GiB + 0.265 GiB per million SP1 gas, so about 54 GiB at 90M: 10 GiB under the 64 GiB scope.
  This is extrapolation between two points, not a measurement.
- The instruction budget is the same number, because memory follows instructions (agents 44, 82) and the sparse guest
  runs at about 0.97 instructions per SP1 gas on swaps and 1.19 on modexp (agent 137).
- `max_block_txs` stays at 64. Agent 113 estimates that about 110 swaps fit 150M. At 90M the budget and the cap bind
  at about the same point (64 swaps: 65-94M).
- **Prover profile by preflight SP1 gas** (`Policy.profile_for`):
  - up to 10.5M: `fast` at a 48 GiB scope (measured up to 10.2M);
  - up to the budget: `lowmem-2c` at a 64 GiB scope (measured 65.1M and 93.8M);
  - above the budget (only a mandatory-only block can be): `mandatory-heavy`, 2c at a 96 GiB scope on the dedicated
    prover. **Unmeasured.** If it fails, the block goes to the operator's exit (`deposits-over-budget.json`, the stuck
    block runbook's export-job).
  - The settler has no per-size switch today (agent 113). Section 8 lists the change.
- Cost of the lower budget: full blocks prove in 1,000-1,750 s with 2c, so about 50-86 full blocks a day (3,200-5,500
  swaps a day), as agent 113 measured. Small blocks keep the fast profile, about 220 a day.

### 3.2 Per-transaction gas cap

| Setting | Value |
|---|---|
| `max_tx_gas` | 5,000,000 |
| `exempt_max_tx_gas` | 15,000,000 (block gas limit) |

**Why.** The cap bounds one transaction's share of the 15M block gas and its native selection time. **It does not bound
proving cost:** a 14.5M-gas read of bUSDC costs 313M SP1 gas, and a modexp runs at about 216-304 SP1 gas per gas
(agents 90, 137). The SP1-gas budget does that. Exempt operator deployments get the block gas limit instead, and are
still measured against the budget.

**Integration:** the RPC admits up to 15M today (`SPOOL_LIMITS.max_tx_gas`). It should admit up to `max_tx_gas`
(exempt senders aside), so that an entry over the cap is refused at admission instead of sitting in the spool.

### 3.3 New storage slots: price and rates

| Setting | Value | Was |
|---|---|---|
| `fresh_slot_price_wei` | 200 µBLCH per new slot, met from the tip: `gas_used × tip ≥ new slots × price` (see A243-11: wallets need a write-aware tip) | same |
| `fresh_slots_per_block` | 128 | same |
| `fresh_slots_per_sender` per `fresh_sender_window_seconds` | 256 per 48 h | 256 per 96 blocks |
| `max_account_slots`, `max_deposit_exposure_slots` | none | none on the sparse guest (D6) |

**Why on the sparse guest.** Storage no longer costs proving time on the sparse guest: 100k slots per contract add
about 0.4M SP1 gas to a swap (agent 113). The rates exist for two other reasons:
- **The fallback guest is complete.** Agent 142 re-pinned the complete `settlement_v3_mainnet` (`3ad3a4f0`) as the
  fallback. If the chain ever falls back, every touched account's full storage is witnessed again, at 17.4-18.1k SP1
  gas per non-zero slot (agent 82), and the 128 GB prover carries about 8k slots per block. Unbounded slot growth
  before a fallback makes the fallback unprovable. Past about 870k slots in one account, even the operator's exit
  refuses the artifact (64 MiB limit, agent 82).
- **State growth is a cost to every node**, and `approve` griefing grows it cheaply: about 0.21 BLCH buys the proven
  class against the pair, WBLCH or bUSDC in 14 blocks (agent 96).

**Numbers.** Honest growth is 200-2,000 new slots a day (agent 96). 128 per block at 48 paced blocks a day allows
6,144 a day. 256 per sender per 48 h is far above any honest wallet. 200 µBLCH per slot makes an honest first
`approve` cost about 0.2 mBLCH more, and puts 100k slots at 20 BLCH (agent 90's D6 numbers).

The 48 h window replaces "96 blocks", which agent 90 calibrated at about 30 min per block.

### 3.4 Metering: how a candidate block is measured

| Setting | Value | Was |
|---|---|---|
| Host cycle limit for preflight | 2 × `max_block_instructions` = **180M instructions** | none |
| `preflight_execute_seconds` | 90 (wall-clock backstop only; agent 223 measured over-limit verdicts at 35-47 s under load 30-45, so 60 s left a 1.3x margin) | 30 recommended, 120 installer |
| `preflight_max_runs`, `preflight_max_seconds` | 24 runs, 180 s per block | 16, 180 s |
| Control run | an empty block without mandatory items, once per block, only when needed | `measure_empty` probe (r8 N6 only) |
| `unmeasured_retry_seconds` | retry after 10 min, then 30 min; quarantine at the 3rd failure | after 1, then 2 blocks |
| `sender_ban_seconds` | 24 h | `strike_cooldown_blocks`, unset by the installer |
| `standing_seconds` | 7 days | none |
| `band_max_wait_seconds` | 2 h | 16 blocks |
| `failure_memory_seconds` | 7 days | until quarantine |

**Why a cycle limit.** Every r7-r9 High finding about measuring (F1, F2, N3, N6, U1, U2) comes from one ambiguity: a
run that times out could be a heavy transaction or a slow host. Agent 90's policy had to guess, and each guess was
exploitable. With a cycle limit, a heavy transaction stops the run itself, quickly, and says so:
- SP1 6.8/6.9 honours `cycle_limit` on execute: `sp1-prover-6.9.0/src/worker/prover/execute.rs:248` returns
  `ExecutionError::ExceededCycleLimit` once the instruction count passes it, checked per gas chunk. The settlement host
  already calls `executor.execute(...).calculate_gas(true)` (`integrations/sp1-execution/host/src/bin/bloch-evm-sp1-settlement-v3.rs:281`).
- Host change: read `BLOCH_PREFLIGHT_CYCLE_LIMIT`, call `.cycle_limit(n)`, and on that error print
  `Settlement V3 over cycle limit: limit=<n>` and exit 3. The guest and its ELF do not change.
- **The limit is at least twice the instruction budget.** The mandatory base is measured first and fits the budget. So
  a block of the base plus one transaction that hits the limit has a transaction share above the instruction budget:
  that transaction is over the budget in any block, deposits or not. Quarantine on that verdict is a measured fact,
  not a guess.
- Time per run. Agent 135's S5 executed 920M SP1 gas in 37-44 s on 45.77 at load 30-50, about 21-25M per second. So
  a run that stops at 180M instructions should take about 8-10 s plus the database copy and export. **Not measured
  with the limit (test H1).**
- **A run without cost and without the cycle-limit verdict** is a host failure (OOM, crash, wall-clock backstop,
  missing cost line). It never quarantines anything by itself. The planner then runs the control. If the control has no
  cost either, the host is unavailable: the block takes no user transaction and nothing is quarantined or counted. If
  the control measures, the transaction gets two more tries, 10 and 40 minutes later, inside the RPC's 3 h TTL whatever
  the pace, and is quarantined at the third failure. Gas used plays no part (r9 U2).
- The settler refuses to start with a budget configured when an empty-block probe gives no cost
  (`check_cost_line`). A prover without the cost line can then never starve users silently (r7 F2).

**Try order** (`Policy.try_order`; agents/223 F223-4 and agents/243 A243-1..3):
1. **First group, by tip, all senders together:** small transactions (gas used below `large_gas`, state, initially
   `max_tx_gas`) of any sender, and every transaction of a sender with standing or an exempt sender. Ordered by
   effective tip, highest first: a higher tip buys room in a full block and a place under the transaction cap whoever
   sends it (r8 N2). Standing only breaks ties. (In 166's first order the tier came before the tip, so senders with
   standing at the capped tip could keep every new sender out for about 0.07 BLCH a day: A243-1, A243-2.)
2. **Then large transactions of fresh senders**, which cannot be told from offenders before they are measured
   (r9 U1). By tip until a quarantine or a run without cost in this block, then by ascending gas used (F223-4). A
   fresh sender whose first transaction is large waits behind the first group; any small paid transaction (an
   approve) gives it standing. After a verdict in the block, large transactions of senders with standing (exempt
   senders aside) join this group too, ahead of the fresh ones (A243-9).
   Measured sizes (agents/243-evidence/gstar.out, mainnet guest 203114bf): the worst instructions per gas is a KZG
   point-evaluation loop, about 460 instructions and 390 SP1 gas per gas. A transaction alone over the 90M budget
   needs about 245-280k gas used, and one over the 180M cycle limit about 440k. So `large_gas` cannot fall below
   about 120k: transfers and ordinary swaps stay small.
3. **`large_gas`** is half the gas used of the smallest offender that counted as small, set on a measured verdict
   (over the cycle limit, or over the budget alone) and persisted. An offender must use at least some G* gas, fixed by
   the guest's worst instructions per gas, so `large_gas` never falls below G*/2, and each offender small enough to go
   before small honest transactions halves it. It doubles back once per week without such an offender
   (`large_gas_recovery_seconds`) and never falls below `large_gas_floor` (120k, half the smallest measured
   offender), so one odd verdict (the complete fallback guest witnesses whole accounts, so a small transaction can be
   over there) cannot move every transaction into the large group, where standing comes first again. A run without
   cost lowers it for its block only, never for good.
4. **After an offender in a block** the rest is re-ordered and searched from the front without a full run, since the
   full run would only hit the offenders at the end again (35-40 s per verdict inside the settler, agents/223 F223-3).
5. **Nonce.** Each sender's transactions stay in nonce order, so every prefix holds nonce n before n+1 (r8 N1); a
   sender's place follows its next transaction.
6. The producer's native selection (`dry`) runs without the block's transaction cap, and the planner applies
   `max_block_txs` to the try order. Otherwise the producer's tip order alone would drop a sender with standing behind
   64 high-tip entries before the tiers apply. The first reference test run found this.
7. **Places by tip** (round 14, F264-5). The last `tip_reserved_txs` (8) of the `max_block_txs` places go to the
   highest tips among everything behind the first 56 of the try order, whatever the group, and are tried last. Without
   them, once a verdict has lowered `large_gas`, 64 small transfers at the floor tip per block kept a fresh sender's
   large transaction out for good, whatever its tip.
8. **Exempt offender** (round 14, F264-4). An exempt sender is never banned, but after a verdict on one of its
   transactions, its transactions of at least half that one's gas used wait `sender_ban_seconds` unmeasured
   (`exempt-offender-wait`). Smaller ones (bridge mints) go on as before. A resent offender no longer costs two
   cycle-limit verdicts ahead of every user in every block.

**Search** (`Policy.plan`, `_first_misfit`):
1. Measure the mandatory-only block (twice at most). Over the budget or over the limit: the block carries its mandatory
   items only, writes `deposits-over-budget.json` (renamed `mandatory-over-budget` in the plan) and takes the
   `mandatory-heavy` profile. No cost even for the control: no user transaction.
2. Gate the spool with native facts (section 3.3, 3.5, bans and waits), repeating the native selection until nothing is
   refused, at most 6 times. New-slot counts depend on the transactions before, so a refusal can uncover another one
   (A243-12): a refusal from the second pass on also waits 1 h by sender and nonce (`gate-dependent`), and a gate that
   has not settled after 6 passes uses its last passing set rather than none. The price of that fallback is that one
   transaction behind the last refusal may create a slot it did not pay for; the measurement bounds the block and the
   sender's 48 h rate books the slots from the block's own report.
3. Measure the mandatory block plus every candidate in try order. **If it fits, that is the block: one run.** This is
   the honest common case: two runs per block in all.
4. Otherwise find the first misfit by **exponential then binary search from the front**: prefixes of 1, 2, 4… on top of
   what already fits, then bisection. An offender at position p costs about 2·log2(p+1) runs, and one at the front
   costs exactly one, which is then also its alone run. Tip order puts an unpaid high tip at the front, where it is now
   cheapest to find (r9 U1).
5. Classify the offender by its alone run: fits alone → `block-full`, a later block. Over the cycle limit → quarantine.
   Measured over, but its share fits without this block's mandatory items → wait up to 2 h for a block without them
   (`band`). Measured over without them → quarantine. No cost → the control, as above.
6. Drop the offender and its sender's later nonces from this block, measure the rest again (step 3), until it fits or
   the allowance (24 runs, 180 s) runs out. Whatever is not reached waits.

**Quarantine binds the sender** (r9 U1, U3): a quarantine bans the sender for 24 h and removes its standing. Sending
the same nonce again, a replacement or a later nonce from that sender is refused by the gate (`sender-banned`) without
a run. Failure counts follow sender and nonce for 7 days, so the same nonce sent again after the ban goes to
quarantine at its first failure.

**Bound on measuring per block.** Honest block: 2 runs. Each offender at the front of a tier: 2 runs (the full run and
its alone run), about 20 s with the cycle limit. Each offender behind p fitting candidates: about 2·log2(p+1) + 1 runs.

### 3.5 Congestion tip

| Setting | Value | Was |
|---|---|---|
| `min_tip_wei` | 0.1 gwei (the RPC floor) | same |
| `congestion_max_tip_wei` | 100 gwei | same |
| `congestion_target_share` | 0.5 of the room above the mandatory base (and of the write rate) | same |
| Step per committed block | up by at most 1/8 when over the target (ratio capped at 2); down by (1 − ratio)/16 otherwise | up by ≤ 1/8 per block; down by time (half-life 1,800 s) |
| `congestion_idle_grace_seconds` | 4,500 | none |
| `congestion_idle_half_life_seconds` | 1,200 | none |
| Mandatory-only or host-unavailable blocks | the tip holds | (decayed) |

**Why.** The protocol base fee reacts only above 15M gas, and the settler never builds blocks that large. Without a
sequencer tip that follows SP1-gas use, 0.056 BLCH kept a floor-tip honest transfer out for 120 blocks at the floor base
fee. With it, saturating the budget for 200 blocks cost the attacker 70.8 BLCH (agent 90, D5 against D6).

**Why these steps.** Growth and decay must use the same unit, or the attacker picks the unit that favours it:
- Per-block growth with per-block halving: 5-of-6 saturation stays at the floor (r8 N7).
- Per-block growth with per-second decay: slow blocks decay the tip between congested blocks (r9 U6). A 1,772 s block
  is about one half-life at 1,800 s.

So both busy steps are per block, and the down step is half the up step. Per cycle:
- 5-of-6 saturation: 1.125^5 × 15/16 = 1.69, so the tip rises;
- 1-of-2: 1.125 × 15/16 = 1.055, so it rises;
- 1-of-3: 0.989, so it decays slowly. That is a third of the blocks at the budget, below the 0.5 target on average.

Time decay applies **only after an idle gap** longer than the grace (4,500 s). That is more than the slowest measured
proof (3,474 s at h8191 with 2c, agent 93), so busy blocks never decay the tip. It decays by half every 1,200 s after
the grace:
- 1 gwei back to the 0.1 gwei floor: 4,500 + 1,200 × log2(10) ≈ 8,500 s (2.4 h). That is inside the RPC's 3 h TTL
  (r7 F6).
- 100 gwei back to the floor: about 16,500 s (4.6 h). A floor-tip wallet transaction sent at the peak expires first.
  Wallets that read the published tip (below) are not affected.

`required_tip(now)` applies the idle decay at read time. The gate, the demand check and the RPC's published tip all
read it, so an idle chain admits a floor-tip transaction without first having to build a block (r9 U5).

The quiet interval also spans consecutive measured blocks with no user cost or
fresh writes. Their first commit records `idle_since`; later mandatory-only
commits preserve it across restarts. This fixes the r7 paced-deposit case where
every deposit renewed the grace and a floor-tip transaction waited 18 hours.
Elapsed decay already incorporated into the stored tip is not applied again.
Actual user load, an unmeasurable host, or a mandatory-over-budget block ends the
quiet interval; a single empty block among busy blocks does not bypass the grace.

**Published tip.** The state file carries `required_tip_wei`, decayed to the time of writing. Agent 118's
`--required-tip-file` on the settled RPC serves it through `eth_maxPriorityFeePerGas`, `eth_feeHistory` and
`eth_gasPrice` (+25% headroom). The settler must rewrite the file on idle-hold cycles too (`Policy.save(now)`), not only
on commits.

### 3.6 Exempt addresses

`write_limit_exempt_senders`: the operator's deployer and the bridge mint signers or relayers. **Addresses: TBD-owner.**

- Exempt from: the write price, the write rates, and the per-transaction gas cap, which becomes the block gas limit.
  Always tried among the small transactions, by tip.
- Exempt from the 24 h sender ban (agents/243 A243-5): a quarantine moves only the transaction, and the sender keeps
  its standing. Otherwise one over-budget deployment, or three runs without cost of a 15M-gas transaction (the 60 s
  backstop, agents/223 F223-3), would stop that address's bridge mints for a day.
- Not exempt from: the SP1-gas budget, the measurement, quarantine of the transaction, the congestion tip, or the
  producer's own rules. A compromised exempt key can make the planner measure one offender per block; rotation as below.
- Sender identity is the recovered signature, so the exemption cannot be claimed by another key. A compromised exempt
  key can grow state without the write price, still within 64 transactions per block and the SP1 budget. Rotation
  means changing the settler config, with no consensus change.

## 4. Per-block flow in the settler (integration)

1. `hold_block` with `skip_idle_blocks`: a block is due for deposits, for forced records, for `max_idle_seconds`, or
   when `Policy.demand(select-report, now, next_has_mandatory)` is true.
   - `next_has_mandatory` is whether L1 holds unconsumed deposits or due forced records for the next block (r9 U4).
   - The gate applies waits, bans and the decayed tip, so an entry that only waits is no demand (r8 N8).
2. `spool_open` (agent 92): with a stale source the spool is closed, and the budget path must honour it (r7 F4, already
   in 4b984af).
3. `plan = Policy.plan(spool, dry=produce-dev select, measure=preflight, measure_empty=control, has_mandatory)`.
   - Every producer call goes through `pool_arguments`, so `--min-tip-wei` and `--forced` reach the selection, the
     measurement and the final extend (r7 I1; agent 137).
4. Final `extend --txs selected.json` with `plan.raws`. Then:
   - `Policy.committed(plan, final_report)` returns the entries to unlink: exactly what that block included or the
     producer dropped (r8 N1).
   - The settler moves `plan.quarantine` to `txpool-quarantine`.
5. Prove with `PROFILES[plan.profile]`: the prover environment comes from the closed allowlist of agent 93's
   `prover_env`, and the memory scope comes from the profile.
6. Every preflight and proof run uses `run_bounded` with process-group kill and SP1 segment cleanup (r7 F8). That is
   already on 4b984af, and agent 135 re-checked it with real binaries in r8 §5.
7. On every hold cycle, `Policy.save(now)` refreshes `required_tip_wei`.

### Candidate preflight integration

The integrated candidate uses a two-stage execute path whenever
`BLOCH_PREFLIGHT_CYCLE_LIMIT` is set. First the pinned SP1 minimal executor runs
the same guest and input without gas tracing. A successful guest exit at or above
the instruction limit produces the stage-1 verdict and skips the gas run. Below
the limit, the gas run must finish successfully, match the independently computed
statement, and count exactly the same instructions. A guest error, a disagreement,
or a timeout supplies no cost and cannot by itself classify a transaction as an
over-limit offender. The first stage runs to completion; `run_bounded` remains the
external wall-clock and process-group backstop.

The settler requires one ordered stage-1 record and either one matching over-limit
verdict or one cost/statement pair. Duplicate, contradictory, out-of-order, and
oversized counters are refused. Each scheduled prover/guest/witness combination
and instruction limit gets its own empty-control check before selection. Changing
from the active program to the sparse candidate or complete fallback cannot reuse
the previous program's capability result.

The control block has a separate temporary directory with no forced-record
sidecar. Actual due forced records remain in every real selection and measurement;
they count as mandatory work and may settle alone above the optional transaction
budget. Source integration and unit tests do not establish a release binary,
production activation, or a new benchmark measurement. The candidate SP1 host
remains unpinned until its release build is qualified.

**Measured (round 15, execute-only, no proof).** Agent 243's precompile offenders, one transaction per
block, the mainnet guest `203114bf…`, limit 180M instructions (factor 2 on the 90M budget), on the shared
build host under a 24 GiB scope with another build running. "Before" is the single-stage host with the
cycle limit (`853c7e20…`), "after" the candidate's two-stage host built from this line (`5b6d2459…`,
unpinned, run with `--mainnet-v1`). Wall seconds of the whole host process:

| Transaction | Gas used | Instructions | Before: verdict or cost | After: verdict or cost | Stage 1 alone |
| --- | --- | --- | --- | --- | --- |
| KZG, 200k gas (fits) | 156,453 | 48.5M | cost in 9.0 s | cost in 9.1 s | 0.30 s |
| KZG, 450k gas (under the limit, over the budget) | 407,158 | 164.7M | cost in 13.2 s | cost in 13.5 s | 0.36 s |
| KZG, 700k gas | 657,863 | 280.8M | over limit in 17.0 s | over limit in 6.3 s | 0.47 s |
| KZG, 1.5M gas | 1,460,119 | 652.5M | over limit in 27.9 s | over limit in 6.9 s | 0.85 s |
| modexp 512 bytes, 450k gas (under the limit) | 391,779 | 91.3M | cost in 7.1 s | cost in 8.7 s | 0.47 s |
| modexp 512 bytes, 1.5M gas | 1,440,819 | 374.6M | over limit in 16.9 s | over limit in 3.5 s | 0.54 s |
| modexp 512 bytes, 3M gas | 2,941,839 | 779.8M | over limit in 28.8 s | over limit in 5.5 s | 0.93 s |

An over-limit verdict costs 3.5 to 6.9 s instead of 17 to 29 s, and the count itself stays under one
second up to 780M instructions; most of what is left is process start and input loading. A block under
the limit pays the count once more: 0.1 to 1.6 s. Stage 1 and the gas run counted the same instructions
in every row. Not measured here: the sparse and fallback candidate guests (they need the recipient
rebuild), the settler's own work around the host (database copy, extend, export), and a second host for
a reproducible build of the SP1 host.

## 5. Measured numbers this rests on

| Number | Value | Source |
|---|---|---|
| Fast settings, largest proved sparse block | 10.2M SP1 gas, ≤ 41.2 GiB | agent 113 |
| Fast settings, 64-swap block | OOM at 48 and 64 GiB (peak 63.0 GiB) | agent 113 (X17) |
| 2c settings, 64 swaps | 65.1M, 1,007 s, 47.2 GiB | agent 113 |
| 2c settings, 64 swaps at 100k slots | 93.8M, 1,743 s, 54.8 GiB | agent 113 |
| Worst deposit block, sparse | 50.1M | agent 90 |
| Worst forced record (300k-gas modexp) | 64.25M SP1 gas, 76.2M instructions | agent 137 |
| SP1 gas per new slot, complete guest | 17.4-18.1k | agent 82 |
| Slots per block on the 128 GB prover, complete guest | about 8k | agent 82 |
| bUSDC 14.5M-gas read, sparse | 313M SP1 gas | agent 90 |
| Execute speed under load | 920M SP1 gas in 37-44 s | agent 135, S5 |
| Slowest measured proof, 2c, h8191 | 3,474 s | agent 93 |
| Honest new slots | 200-2,000 a day | agent 96 |
| `approve` griefing to the proven class | about 0.21 BLCH, 14 blocks | agent 96 |
| Congestion tip D6 against saturation | 70.8 BLCH over 200 blocks; honest 200/200 | agent 90 |
| RPC spool | 4,096 entries, 16 per sender, nonce gap 16, TTL 3 h, replacement +10% | `bloch-l2-settled-rpc.rs:157` |

## 6. Closure of the review findings

"Unit" means a test in `test_sequencer_policy_v2.py` that passes on this branch. A mutation that removes the rule makes
it fail (section 9.1). "Integration" means a requirement on the settler, producer, host or RPC, not yet built.

| Finding | Severity | Closed by | Evidence |
|---|---|---|---|
| r7 F1 over-budget held for ever behind a deposit | High | The alone run classifies against the mandatory base: over without the base → quarantine with deposits too. Only a share that fits without them waits, by time, at most once per 2 h | Unit `F1…`, `N5…` |
| r7 F2 no cost means quarantine | Medium | No cost never quarantines without a control that measures. A host failure takes no user transaction and decides nothing. Start-up refuses a prover without the cost line | Unit `N9U2…`, `F2F7…start_up…` |
| r7 F3 pilot quarantines on deposits | High | The pilot path is not part of v2. If a pilot returns, it must call this planner | Integration |
| r7 F4 budget path ignores `spool_open` | High | Already fixed in 4b984af (`extend_within_budget` honours it); the v2 integration keeps it | Integration, existing test (`test_settler_f5`/`r7`) |
| r7 F5 undeliverable entries are demand | Medium | `demand` uses the full gate (waits, bans, decayed tip, mandatory items of the next block). Nonce gaps are already handled by 132's fix | Unit `N8…`, `U4…`; integration |
| r7 F6 tip decays per block under pacing | Medium | Idle-only time decay, read at `now`; windows in seconds | Unit `U5U6F6…`, `Limits…window_is_in_seconds` |
| r7 F7 torn state file | Low | Tolerant load, fsync on save | Unit `F2F7…torn_state…` |
| r7 F8 orphaned runner and `/dev/shm` leak | High | `run_bounded` group kill and segment cleanup (agent 90, re-checked by 135 S5); not in this module | Integration (already on 4b984af) |
| r7 I1 pool arguments | Integration | Every producer call through `pool_arguments` | Integration |
| r8 N1 deferred nonce deleted | High | Nonce-ordered prefixes; removal only from the final report | Unit `N1…` (4 tests) |
| r8 N2 tip ignored in a full block | High | Tip order within a tier | Unit `N2…` |
| r8 N3 replacement restarts the wait | High | Over-budget is a measured verdict (cycle limit) followed by a sender ban; a no-cost wait is keyed by sender and nonce | Unit `N3…`, `N3b…` |
| r8 N4 8 timeouts per sender | Medium | A heavy transaction costs 2 cycle-limited runs and no timeout | Unit `N4…` |
| r8 N5 band measured every block | Medium | Band wait by time, demand-aware | Unit `N5…` |
| r8 N6 timed-out deposit block takes unmeasured users | High | No unmeasured path at all. Mandatory over the limit, or without cost while the control measures: mandatory-only with record. Control fails: no user transaction | Unit `N6…` (3 tests) |
| r8 N7 5-of-6 attacker keeps the floor | Medium | Per-block up 1/8, down ≤ 1/16 | Unit `N7…` (2 tests) |
| r8 N8 waiting entry is demand | Medium | Gate includes waits | Unit `N8…` |
| r8 N9 block-counted wait under pacing | Low | Waits, bans, windows in seconds | Unit `N9U2…` |
| r9 U1 unpaid tip buys measuring time | High | Cycle limit (2 short runs per offender, no timeout); 24 h sender ban; standing tier; galloping search from the front | Unit `U1…` (3 tests), `U1Residual…` (2) |
| r9 U2 300k cutoff loses honest large transactions | High | No gas cutoff. No cost → control → retries at +10 and +40 min | Unit `N9U2…` (3 tests) |
| r9 U3 quarantined nonce sent again | Medium | Sender ban; failure count by sender and nonce for 7 days | Unit `U3…` |
| r9 U4 band demand ignores the next block | Medium | `demand(..., next_has_mandatory)` | Unit `U4…` |
| r9 U5 tip read without decay | Medium | `required_tip(now)` everywhere | Unit `U5U6F6…` |
| r9 U6 slow blocks decay the tip | Medium | No time decay while busy; grace 4,500 s above the slowest proof | Unit `U5U6F6…slow_blocks…` |

### Round 14 (agent 264's review 2, closed by agent 304)

| Finding | Severity | Closure | Test (`test_review_r12_policy_v2.py`) |
|---|---|---|---|
| F264-1 the allowance running out inside the search dropped the prefix already measured as fitting: one unpaid offender at the back of 64 emptied every block | High | `_first_misfit` returns the measured prefix with `complete = False`; `plan` commits it and leaves the rest `not-reached` | `F264_1…`, `F264_1b…` |
| F264-2 the unsettled-gate fallback let a transaction behind the last refusal create unpaid slots, above the per-block limit too | Medium | `_final_gate`: the gate runs again on the selection report of the block as chosen; refused ones leave and the rest is measured again (one run per pass); else the block-order prefix before the first refusal when it keeps at least half; else the measured block stands and `final-gate-unsettled` is logged | `F264_2…` |
| F264-3 a gate-dependent wait outlived a replacement that pays | Low | the wait names the refused hash; another hash at the same nonce is judged on its own payment | `F264_3…` |
| F264-4 a resent exempt offender was measured first in every block | Low | 3.4 rule 8 | `F264_4…` |
| F264-5 a fresh sender's large transaction never got under the transaction cap | Low | 3.4 rule 7 | `F264_5…` |
| F264-6 every preflight run copied the whole database | Medium (scaling) | one copy per block plan, rewound to the parent after each run and checked with `head`; a copy that does not read back as the parent is discarded (`preflight_database`, default `rewind`; `copy` is the old behaviour) | `F264_6…` (two tests) |

Residual of F264-2: closed in round 15, in the form agents/304 named as the complete remedy. The write price is
judged INSIDE the producer's selection (`produce-dev select|extend --fresh-slot-price-wei N`, turned on by
`producer_write_price`): after a transaction ran, if it would add storage slots it does not pay for, its changes are
dropped and the selection goes on with the next candidate on the block without it. One pass; no transaction is
refused for what a refused one did; **a non-payer never displaces a payer**, wherever it stands in tip order
(review R308-3P-2 replaced the capped re-selection of the second pass, which kept only the transactions ahead of
the eighth non-payer). `extend` builds exactly the judged block, so no block of this producer holds an unpaid slot.
The work spent on non-payers is bounded: `--write-wasted-gas` (default twice the block gas limit) is the gas that
may go to transactions that are then left out; past it only plain transfers, which add no slot whatever ran before
them, are still executed and the rest is reported `not_judged` (held `unpaid-allowance-exhausted`, no wait).
Non-paying is self-limiting: the SENDER of an unpaid transaction waits `unpaid_first_wait_seconds` (2,400 s, longer
than a block interval), twice as long after each further report, up to a day, whatever bytes or nonce it sends
next; while it waits the producer does not execute anything of that sender (`--write-waiting`, the demand check
included). Senders with standing (they have paid before) are selected ahead of all others, then by tip
(`--write-standing`), so keys that never paid, funded or not, are judged after every sender that has, and the
allowance they can burn is spent behind those. A fresh key gets one judged attempt per 40 minutes; its funding
transfer is a paying transaction. A producer call that times out is a producer refusal, so the deposits-only
block is still built, as the last resort only. Measured on the real binary (debug build, shared build host),
30 honest transactions at 3 gwei behind N non-payers at 3.9 gwei from N keys: N = 8: 0.17 s, N = 64: 0.22 s,
N = 400: 0.52 s as independent writers; N = 64: 0.40 s, N = 400: 0.49 s as a chain on one slot (each refusal
uncovers the next); in every run all 30 honest transactions are included, all N are reported unpaid, one pass;
the unpriced selection of the same pools takes 0.20 to 0.84 s. With a 100,000-gas allowance the 20 plain transfers
are still served, and with the honest senders in the standing list all 30. The plan's allowance is 180 s.
Tests: `tests/produce_txs.rs` (`eight_non_payers_ahead_in_tip_order_do_not_empty_the_block`, which fails on the
capped producer with the 30 honest transactions not judged; `many_non_payers_at_a_high_tip_cost_one_pass_and_serve_every_payer`;
`write_price_leaves_a_whole_chain_of_non_payers_pending`), `test_round15_producer_write_price.py`,
`review_r15_308_2p_u3_waits.py`, `review_r15_308_3p_cap_starves_users.py`.

## 7. Residual risks (accepted or open)

| # | Risk | Bound | Mitigation |
|---|---|---|---|
| R1 | Fresh, funded senders at the top tip, each over the cycle limit, delay **new** senders (no standing) | Each costs about 20 s and a 24 h ban. Eight per block leave a new sender served; nine delay it one block (unit `U1Residual…`). Keeping new senders out costs ≥ 9 fresh senders per block, about 430 a day at 48 blocks a day, each holding `gas_limit × max_fee`, which it gets back. Senders with standing are never behind them | Forced inclusion (≤ 2 settlements, about 3.2k sat) for a censored new user. Optional: the RPC reads `bans` from the state file and refuses banned senders at admission |
| R2 | An attacker with a deposit in every block (0.01 BLCH, credited back) keeps a band transaction (share within budget minus base) waiting | A band transaction is tried once every 2 h | Band transactions are about the size of the whole budget; accepted |
| R3 | Foreign settlers are not bound | Their own blocks only, on the sparse guest | Consensus repricing only (agent 90): not proposed |
| R4 | A mandatory-only block above the budget (deposits plus forced, about 114M by addition) | Commits alone with its record; `mandatory-heavy` profile unmeasured | Test P3; operator exit |
| R5 | The cycle limit is checked per gas chunk, so a run overshoots by up to one chunk | Time not measured | Test H1 |
| R6 | Standing is cheap (one paid transaction) | It only moves a sender ahead of fresh ones among large transactions and breaks tip ties among small ones (A243-1, A243-2); a quarantine removes it and bans the sender | Accepted |
| R7 | Spool flooding at the RPC (4,096 entries, 16 per sender, eviction by fee) | Pre-existing; the planner reads at most 16,384 | RPC refusal of banned senders (R1); admission at `max_tx_gas` (3.2) |
| R8 | The budget's memory margin rests on two 2c points and on load-noisy times | | Tests P1, P2 |
| R9 | The sparse guest's empty-block cost at height 8191 is not measured | Complete guest: +37k SP1 gas per block of height (agent 82) | Test H3 |

## 8. Integration and pins

| Component | Change | Moves |
|---|---|---|
| Producer | Re-land `produce-dev select` and `tx_stats` with `nonce` (agent 90's e49a380, c5f341e, f6ac754 producer part). Not flagged by reviews 121 or 135 | produce-dev hash (not the guest ELF: agent 90 checked `b21e83a8…` at both commits) |
| SP1 host | `BLOCH_PREFLIGHT_CYCLE_LIMIT`, over-limit line, exit 3 | prover host hash; not the ELF, not the vkey |
| Settler | Replace the old `extend_within_budget` with the v2 planner; control run; `check_cost_line` at start; `demand` in `hold_block`; profile per block; `save(now)` on hold cycles | `settler_v3.py`, new `sequencer_policy_v2.py`, installer FILES and pins |
| Installer | Defaults from section 3; exempt addresses TBD-owner; prover profiles; scopes 48/64/96 GiB | kit pins |
| RPC | Unit flag `--required-tip-file <workdir>/sequencer-policy.json` (agent 118, built; round 14: `follower-rpc/install.sh --required-tip-file PATH` writes it into the unit, only with `--rpc-user/--read-group`, and without the option the unit's command line is the deposit-only one). Optional: admission at `max_tx_gas`, refuse banned senders | RPC unit; the optional parts move the RPC hash |

The deposit-only launch build `116bfaba…` and its kit are not affected: user transactions stay off there.

## 9. Test plan

### 9.1 Done (this branch, Mac, no proof)

- `python3 -B -m unittest -v test_sequencer_policy_v2`: 39 tests pass. Each review scenario of agents 121 and 135 at
  policy level (N1-N9, U1-U6, F1, F2, F6, F7) plus the limits.
- Mutation check. Each rule was removed in turn from a copy of the module, and the suite must fail. See agents/166 for
  the table.

### 9.2 Before user transactions (in order)

| # | Test | Where | Pass criterion |
|---|---|---|---|
| I1 | Port the v2 planner into `settler_v3.py`. Run agent 121's and agent 135's settler-level suites (r7, r8, r9), adapted only where an assertion encodes the old schedule, each change noted | Mac | All finding tests pass; adapted assertions listed |
| H1 | Host cycle limit, execute-only on a private DB: S3's 4.9M-gas modexp, the 1.5M modexp, an empty block, the 64-swap artifact of agent 113 | 45.77 or 209 after 01:00 UTC, 12 GiB scope | Over-limit verdict in ≤ 15 s at load ≤ 40; no orphan, no `/dev/shm` left; the 64-swap block measures normally |
| H2 | Agent 135's driver S1, S2, S3, S5, S6 against the integrated v2 settler, real binaries | same | S1: both nonces served. S2: the honest transaction served. S3/S6: one block of measuring, then nothing; no timeout. S5: no segment leaks |
| H3 | Empty sparse block cost at heights 4097 and 8191 | execute-only | Recorded; budget re-checked |
| P1 | Prove fast-profile blocks at about 20M, 30M and 45M SP1 gas, 48 GiB scope | prover host, lock | Raise `fast_profile_max_sp1_gas` to the largest that proves with ≥ 4 GiB headroom |
| P2 | Prove a 90M-SP1-gas block with 2c at 64 GiB on the dedicated 32 vCPU / 128 GB host, no other load | dedicated prover | Peak ≤ 58 GiB, otherwise lower the budget |
| P3 | Prove a deposits + forced worst-case block (about 114M) with `mandatory-heavy` at 96 GiB | dedicated prover | Proves; otherwise the exit path is the plan, written in the runbook |
| R1 | Paced rehearsal (`--min-block-interval 1800`), 24 h, private crossing net: honest load plus the U1 pool attack, the congestion spike and idle decay | 209 | No honest sender with standing delayed more than 1 block; new senders per R1; tip within ±10% of the model; RPC publishes the tip |
| V1 | Independent review of the integrated diff, code before reports | | No High open |

## 10. Owner decisions

1. **Budget 90M SP1 gas and 90M instructions** (this spec) or 150M (agents 82 and 90, X12). 150M is above every
   sparse proof made so far.
2. **The host cycle limit:** a new prover host hash, while the ELF and vkey stay the same.
3. **Sender ban of 24 h and the standing tier.** They decide who waits under attack: new senders, with forced
   inclusion as their escape.
4. **Congestion tip on, with agent 118's published tip.** Or keep it off for the first weeks, with the floor only.
5. **Exempt addresses** (TBD-owner): deployer and bridge mint signers or relayers.
6. **The 96 GiB scope** for mandatory-heavy blocks on the dedicated prover.
