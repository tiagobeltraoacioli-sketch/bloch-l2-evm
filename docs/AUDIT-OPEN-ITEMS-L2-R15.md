# L2 open items for the external audit (round 15)

One index of what the internal review of round 15 left open. The full text of every item (defect, scenario, how to
reproduce, direction) is the section "Open items for the external audit (final, self-contained)" of the reviewer's
report, `agents/308-l2-review-r15.md` (agent 308, sixth pass). This file does not restate it: it names each item,
says which line it belongs to, and where the developer's own record of it is. Nothing here is closed by this file.

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

## B1, and what an operator of the released node can do today

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
