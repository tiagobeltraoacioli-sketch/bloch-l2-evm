# L2 open items for the external audit (round 15)

One index of what the internal review of round 15 left open. The full text of every item (defect, scenario, how to
reproduce, direction) is the section "Open items for the external audit (final, self-contained)" of the reviewer's
report, `agents/308-l2-review-r15.md` (agent 308, sixth pass). This file does not restate it: it names each item,
says which line it belongs to, and where the developer's own record of it is. Nothing here is closed by this file; the section "Status after round 17" below says what has been closed since.

Tips the items refer to: launch kit bloch-l2-evm `codex/l2-release-r15-20261110` 2de669e (deposit-only launch,
release 926d2cf); December candidate bloch-l2-evm `codex/l2-r15-20261110` (this branch; the review read 1b55ce1);
native bloch-sis-pow `codex/l2-r15-20261110` a2fc3d0f.

Lines: **launch** = the deposit-only launch kit, listed in `deployment/mainnet/KNOWN-ISSUES.md` of that line;
**candidate** = this branch (sequencer policy, producer, RPC; none of it consensus); **fork** = L1 consensus of
the December fork in the native tree; **node** = L1 node policy and release tooling (mempool, brake, build checks).

| Item | Line | What | Developer's record |
|---|---|---|---|
| A1 | fork | Withdrawal roots are not tied to each other; `PaidLeaves` is the compensating control (R308-7) | agents/311-l2-r15.md sections 12, 13 |
| A2 | fork, owner decision | Form of the rollback reset: a plain reset refuses itself on one claim against the tail (R308-2P-3) | native `docs/L2-FORFEIT-ONLY-RESET.md` on `codex/l2-r15-forfeit-only-reset-20261110` (not merged) |
| A3 | fork | What a forfeit reset costs beyond the escrow; no tool sums the shortfall (R308-4P-5) | same note; agents/311 section 15.2 item 5 |
| A4 | fork, accepted | Forced records beyond the 1,024-record log are not executed again (R308-8) | same note |
| A5 | fork | The paid-leaf record only grows (R308-2P-5) | agents/311 section 13.4 |
| A6 | fork, owner input | Treasury and fee-sweep recipient checks that code cannot make | agents/311 section 10 |
| A7 | fork | Not examined: fallback guest equivalence, rebuilt guest identity, parts of `l2_settlement.rs`, reorgs across a reset | agents/311 sections 13.4, 16.3 |
| B1 | node (**released node too**) | L2 kinds enter the mempool on a signature alone (R308-3) | below |
| B2 | node, accepted | Entries sharing one funding output compete by tip | agents/311 section 13 |
| B3 | node | The brake file can be replayed (R308-11) | agents/311 section 12 |
| B4 | node | `qualify.sh` sees an armed L2 gate only as a decimal literal (R308-10) | agents/311 section 12 |
| B5 | node, open by decision | The build check trusts git and the ambient Cargo configuration (R308-19) | `deployment/mainnet/review-r15-308/demo5_build_sources.py` (fails on purpose) |
| C1 | candidate | New senders under a paid full block (R308-6P-1, R15) | `docs/SEQUENCER-POLICY-V2.md` section 6 ("What a new sender gets"), section 7 R15 |
| C2 | candidate | Paid waste is not a congestion signal (R10) | section 7 R10 |
| C3 | candidate, accepted | The sender wait after three reports made by others (R12) | section 7 R12 |
| C4 | candidate | Credit of a dropped block is kept (R11) | section 7 R11 |
| C5 | candidate | What the shadow does not check (R13, R308-6P-2) | section 6 ("Rebuilds"), section 7 R13 |
| C6 | candidate | The reserve does not cover the proof budget; the figures are settings (R14, R16) | section 7 R14, R16 |
| C7 | candidate | What the RPC does not mirror (pools, waits, queued nonces, tip at the next base fee) | `docs/MAINNET-RPC-READINESS.md` |
| C8 | candidate | Never run on real binaries: one-copy preflight with user transactions, final-gate fallbacks, the settled stack with a prover | agents/312 (task 263) |
| C9 | candidate | The older residuals R1 to R9 | section 7 |
| D1 | launch (fixed on the candidate) | Launch settler edge cases (R308-24, 25, 26) | `KNOWN-ISSUES.md` |
| D2 | launch (F312-5 fixed on the candidate) | The shadow stops after a foreign settlement (F312-4); spool mode (F312-5) | `KNOWN-ISSUES.md` |
| D3 | launch | Gateway pool of eight (R308-27 residual) | `KNOWN-ISSUES.md` issue 7 |
| D4 | launch | Installers: upgrade order, resume, signing memory, host names (R308-21, 2P-9, 2P-12) | `KNOWN-ISSUES.md` issues 8 to 10 |
| D5 | launch | Not examined: `prover/`, `withdraw/`, `replica/`, `keykit/`, parts of the monitors | reviewer's report |

Changed on this branch after the review's last read (1b55ce1): R308-6P-2 (the monitor grades
`shadow-order-unchecked`: a warning, critical when it repeats), R308-6P-3 (the seed goes to the producer in a
0600 file), and for C1 the quote and the refusal name the plain transfer that buys the credit
(`first_transfer_priority_fee_wei`). C5 stands otherwise: blocks with forced records are still not order-checked.

## Status after round 17 (2026-11-17)

The table above is the list as the review wrote it (26 items) and is kept unchanged. The seventh review pass added
C10, C11 and D6. This section says, for each of the 29, what round 17 found or did. "Closes it" names the one
thing still missing. Tips of round 17: bloch-l2-evm `codex/l2-r17-20261117` (documents only on top of f73131f;
binaries of build commit c2938be) and `codex/l2-r17-pins-20261117` (Python and build-script fixes and their pins; no
binary pin); native
bloch-sis-pow `codex/l2-r17-20261117` (scripts and one runbook on top of 0861278c; no crate source changed);
native `codex/native-l2-admission-r17-20261117` (the released node line 906336fd plus one test and one note).

**No item below was closed by moving a December identity.** The guest ELFs, their keys, the configuration
`27d6ce9f…2783` and the four binaries are those of `docs/DECEMBER-BUILD-R15.md`. The launch kit 2de669e is untouched.

| Item | State | What round 17 found or did | Closes it |
|---|---|---|---|
| A1 | open (design fact) | Nothing changed. `PaidLeaves` stays the compensating control | The auditors' reading; a root link in the guest statement if a stronger rule is wanted (moves every guest identity) |
| A2 | owner decision | Two options on one page: `docs/L2-ROLLBACK-RESET-OPTIONS.md` | The owner's choice; then one consensus change in the native tree (moves the three L2 binaries) |
| A3 | open, follows A2 | Not built. The record holds leaf hashes, so a sum needs either the amounts stored with the leaf (a state-format change of the fork) or an indexer that reads the claims from blocks | With forfeit chosen: store the amount with the paid leaf and expose the sum per root in `getl2settlement`; without forfeit: not needed |
| A4 | accepted | Unchanged | Nothing (accepted); a longer consumed log if wanted |
| A5 | open | Not built: a prune point is a consensus rule of the fork and moves the three L2 binaries; it is batched with A2/A3 so the native side moves once | A committed prune point at the oldest retained withdrawal record, in the same native change as A2/A3 |
| A6 | partly closed | On a private net with real proofs (agent 317, Part B) the crossing fee of four deposits and a forced surcharge were paid to the treasury script as compiled. A spend FROM a treasury output needs the owner's key | Owner: one spend from a treasury output on a rehearsal net; the sweep to the recipient is in agent 333's run |
| A7 | partly closed | Identities reproduced on two hosts and two paths by the developer (c2938be); an independent rebuild is agent 333's step 1. Fallback-guest equivalence and the forced-prefix rule are still unexamined | The reviewer's or an auditor's own rebuild; an equivalence review of the two guests |
| B1 | **closed on the released node line**; open on the December native line | Releases `node-7f1c116e-20261112` and `node-906336fd-20261113` already carry a state preflight of deposits, DA batches and claims that uses the transition's own checks (commit 9cbd441f and followers). The statement below ("nothing closes it without a release") was true of 78d4921c only. Note and test: native `codex/native-l2-admission-r17-20261117`, `docs/L2-MEMPOOL-ADMISSION.md` | Every node on release 7f1c116e or later. For the fork: item N1 |
| B2 | **closed on the released node line** | The same releases refuse a second pending entry that spends an output a backed entry already spends (`plan_input_conflicts`) | As B1 |
| B3 | open, documented | Not built: the proposed fix (a sequence in the signed body, the highest seen persisted) keeps its mark in the directory the attacker of this item can write. Runbook now says how to lift a brake so that no copy remains, and to sign the shortest `until_epoch` (native 189f3178) | A mark kept outside the data directory (an operator-visible path), if wanted; low value: a replayed brake is node-local, fail-open and self-expiring |
| B4 | **closed** | `qualify.sh` asks `hf-gates.py status`, which evaluates the constant (literals, other constants, arithmetic); a value it cannot evaluate counts as armed. Native 6653540b, self-test `scripts/hf-release/hf-gates.selftest.py` | Done. Scripts only |
| B5 | open by decision | Unchanged | Build from a fresh `git archive` under `env -i` in the release procedure |
| C1 | open (stated) | Unchanged since `first_transfer_priority_fee_wei` | A measurement with real traffic |
| C2 | open | Not built: it changes the published tip, which every wallet pays; it needs a measured rule, not a guess | Traffic data, then one planner change (Python, pins only) |
| C3 | accepted | Unchanged | Nothing (accepted) |
| C4 | open | Not built: one dropped block's fees per recovery; a per-block credit journal in the recovery path is more risk than the residual | A journal of credit per block, undone by `recover_reorg` (Python, pins only) |
| C5 | partly closed | Blocks with forced records are order-checked since 59f4899, and a forced-only block was matched by the shadow on a real-proof net (agents 317/333, block 7). Credits and seed are still taken as the settler states them | The shadow keeping its own fee ledger |
| C6 | open (stated) | Unchanged | A measured block whose proof budget covered senders use up |
| C7 | open | Unchanged: mirroring the pools and waits needs the settled RPC changed (moves that binary) | One RPC change in the next identity batch |
| C8 | partly closed | The whole design ran on a settled stack with a real prover (agent 317 on e8f40c2 and, Part B, on the December build installed as documented; agent 333 continues). Not run: `rewind_check.sh` on blocks with user transactions | That one script on a database with user transactions |
| C9 | open | Unchanged | Not re-examined |
| C10 | **closed** | 91dbd30: five failed proofs of one block that cost proving time halt the worker (unit-tested; the separate bound on memory kills was seen with real kills by agent 317, Part B, block 4) | Done |
| C11 | **closed** | 91dbd30: the planner reads the declared gas limit | Done |
| D1 to D5 | launch line, unchanged | The kit does not move | The first kit revision after launch |
| D6 | **closed by measurement** | Agent 317, Part A: 64 deposits in one block on release 926d2cf with the installed settings: proved in 378.5 s, SP1 host peak 22.1 GiB, accepted. Memory on the kit follows the L2 height, not the deposits | Done; the height figure is the installer header's |

New in round 17:

| Item | Line | What | Closes it |
|---|---|---|---|
| N1 | fork, node | **The December native line is not on top of the released node.** `codex/l2-r15-recipients-20261116` (0861278c) branches from the release line at 4f34d87e; the released node 906336fd is 164 commits further (the security fixes of 2026-11-10 to 11-13, two consensus gates at epoch 8620, the L2 preflight of B1, changes in `l2_settlement.rs`, `transition/l2_*.rs`, `state_root.rs`). A trial merge (`git merge-tree`) conflicts in eight files: `hard_forks.rs`, `l2_settlement.rs`, `l2_settlement_tests.rs`, `wire_alloc.rs`, `engine.rs`, `engine/admission.rs`, `rpc/consensus_gates.rs`, `rpc/tests.rs`. The December node cannot be released from 0861278c as it is, and the three L2 binaries link the native transition, so the merge moves their identity | **Done in round 17** (agent 339): native `codex/native-l2-dec-merge-r17-20261117` `19aa156d` = `906336fd` merged with the December line, every L2 gate inert; this tree's `codex/l2-dec-merge-r17-20261117` builds against it (follower and producer moved, the settled RPC, the SP1 host and the guests did not; `docs/DECEMBER-BUILD-R15.md` section 11). Open: an independent review of the merge (it is new consensus-adjacent code in eight files), a second host for the two new binaries |
| N2 | launch and candidate | **Not verified: that an L2 follower built against an older native commit follows a chain run by release 906336fd past epoch 8620.** The follower verifies L1 blocks with the native code it links (78d4921c for release 926d2cf, 0861278c for the December build); neither has the two rules release 906336fd arms at 8620 | One follower run of each build against a private chain produced by 906336fd across 8620. For the December build the cause is removed by code (round 17: the follower links native `19aa156d`, which contains release 906336fd); the run itself is still not made |
| N3 | candidate | After a memory kill of the remote prover the local proof of the same pass still used the killed settings (seen by agent 317, Part B, block 6) | Fixed on `codex/l2-r17-pins-20261117` (settler, Python; its pin moves) |

From the round-17 review (agent 335, `R335-n`) and the real-proof run (agent 333, `F333-n`), on `codex/l2-r17-pins-20261117`:

| Finding | State | Closes it |
|---|---|---|
| R335-2 (Medium): a release build could reuse another tree's compiled crates in the fixed build directory | **fixed**: every build empties the directory, the lock lies beside it (`build-root.sh`, `test_build_root.py`) | Done |
| R335-4 (Medium): the pin lists' binary lines are not the December build's | **closed for the pin lists** on `codex/l2-dec-merge-r17-20261117` (binary lines regenerated from the build after the native merge, the two guests added, tests tie every installer pin to its line); open: the follower installer still names the signed launch release, and a December release folder, signing target and plan section do not exist | `docs/DECEMBER-BUILD-R15.md` section 3 |
| R335-3 (Low): planner and producer disagreed on "plain transfer" | **fixed** (planner reads the declared limit) | Done |
| R335-1 (Low): `audit` is green between `set` and `pins` | open | A pins-pending marker that `pins` removes and `audit`, `native-commit` and the build refuse |
| R335-5 (Low): release binaries accept `--rules mainnet-rehearsal` | text corrected; the flag itself is open (a compiled change: moves the producer and the settled RPC) | A cargo feature or a refusal of the mainnet domain, in the next rebuild of the binaries |
| R335-6 (Low), R335-9 (Info): texts | corrected on the L2 side; the two native comments (R335-9) wait for the next native change | The native comments |
| R335-7 (Low): 27 sweep-tool tests are skipped on a tree that carries the recipient | open | Fixtures independent of the committed constant |
| R335-8 (Info): the shadow omits three checks the settler makes on forced records | open | One shared function |
| R335-10 (Info): a negative test that the list did not decide | **fixed** | Done |
| F333-1 (Low): the build recipe did not say the reth snapshot must be prepared | **fixed** (document) | Done |

## B1, and what an operator of the released node can do today

**Superseded in part (round 17): this section describes release 78d4921c. Releases 7f1c116e and 906336fd already carry the checks; see B1 in the status table above.**

**The item.** In the released node line (78d4921c and later) an L2 deposit, DA batch or forced envelope is
admitted to the mempool on its signature, with any claimed tip, and eviction at capacity is by claimed tip. So
unfunded entries at the maximum tip can hold the 4,096 places of every node's pool against paying transfers. The
admission checks that close it (funding inputs present and owned, exact conservation, a tip ceiling, network and
chain, shape, the DA window, claims consensus would take) exist only in native a2fc3d0f. The reviewer read the
code and did not try it on a running node; neither did the developer.

**What it can and cannot do.** It delays other transactions' entry to the pool. It cannot spend anything, cannot
make an invalid block valid, and does not stop block production. Entries that spend outputs that do not exist
are swept after two epoch sweeps (about 16 to 32 minutes); entries that all spend one real output stay until the
100-slot age limit (about 50 minutes) or until a proposer selects and drops them. It has to be re-sent
continuously to last.

**Without a new release: nothing closes it.** The released node has no setting for the pool's capacity, for the
admission of these kinds or for a tip ceiling (its command line was searched at 78d4921c: none). What an operator
can do today is limited to:
1. Keep the node's RPC on loopback (`--rpc-bind`, the default is 127.0.0.1), so entries can reach the pool only
   through peers and not from any client of a public RPC.
2. Watch for it: a pool that stays full of L2 kinds while transfers are refused `AtCapacity` is this, and it
   clears by itself within the times above once the sender stops.
Neither was exercised for this note. A pool that is full is full on every node the entries reached, so there
is no node to hand a transaction to instead.

**With a release.** The fix is node policy only: no consensus rule, no state format and no fork height is
involved, so a node release that carries the admission checks of a2fc3d0f can be rolled out node by node, in any
order, and each upgraded node is protected from the moment it restarts. That is the recommendation: carry
`engine/admission.rs` of a2fc3d0f into the next node release, ahead of and independent of the December fork.
