# The rollback head reset: two options for the owner (one page)

Audit items A2 and A3 (review R308-2P-3, R308-4P-5). Nothing here is armed: `ROLLBACK_HEAD_RESET` is `None` and
every L2 gate is `u64::MAX` in both options. The question only matters on the day a December guest is found
faulty and the fallback program has to take over at the rollback gate R.

**What a reset is.** A rollback release names an L2 block N. At R the L1 moves the L2 head back to N so that the
bad blocks after N (the tail) are rebuilt. The release is public at least 72 hours before R. Until R the tail's
withdrawal roots pay claims like any others: small claims (under 100 BLCH) up to 10% of the escrow per day.

## Option A: keep both forms (the December line as it is, native 0861278c)

The release builder chooses per incident: **plain** (refuses itself if any claim was paid against the tail) or
**forfeit** (always applies; claims paid against the tail are forgotten and stay paid).

- For: when nothing was paid against the tail, the plain form costs the escrow nothing, and it is the only reset
  usable when the tail is honest (case G2b: an honest tail's paid withdrawals would otherwise be credited twice).
- Against: **one claim by anyone, for the price of one claim, vetoes a plain reset.** Wallets prove against the
  newest root, so an ordinary user does it by accident. At R the program still moves but the head stays on the
  bad block; the node reports it (`getl2settlement.head_resets`, a CRITICAL log line) and does not prevent it. A
  second release needs a build, a qualification and 72 hours again: three to four days in which the tail keeps
  paying, an upper bound of about 27 to 34% of the escrow on top of what left before R.
- Identity: nothing moves.

## Option B: forfeit is the only form at the rollback gate (branch `codex/l2-r15-forfeit-only-reset-20261110`, native 0238bce1, not merged)

A plain literal no longer compiles for the rollback; `arm.py` refuses a `reset.json` without `"forfeit": true`.

- For: **the head always moves at R**; the loss stops growing at R. No third party can keep the L2 on a bad block.
- Against, 1: **somebody must cover the shortfall**, the sum of the tail claims paid before R that the rebuilt
  chain does not contain (forged leaves, and honest tail withdrawals that come back as L2 balance). Bounded by
  the release window: at most about 10% of the escrow per day between the bad block and R. No tool sums it
  today (the record holds hashes; the amounts are in the claim transactions).
- Against, 2: **case G2b has no reset at all.** With an honest tail the only remedy left is to move the program
  at R and keep the head.
- Against, 3: large claims built against a tail root need a new attestation and wait 2,880 blocks again; forced
  records older than the 1,024-record log are not executed again (their senders pay again).
- Identity: one consensus rule changes, at the rollback gate only; state format unchanged. The three L2 binaries
  (follower, producer, settled RPC) link the native transition and move; guests, keys and configuration do not.

## Recommendation: Option B, with three things decided together

The plain form protects the escrow only while nobody claims against the tail, and anybody can end that for the
price of one claim during the 72 public hours. A safety mechanism a stranger can switch off is not one. Option B
turns an open-ended loss (27 to 34% and counting) into a bounded one that ends at R.

1. **Who covers the shortfall (owner input).** Proposed: the protocol treasury (`bloch1qe986…2073`, which
   receives the 5 bps crossing fee and the forced-inclusion surcharges), by an ordinary L2 deposit to an L2
   address nobody holds: the escrow rises by the amount and no L2 balance anyone can spend is created. No code
   is needed for that. The alternative is that depositors share the loss pro rata, which the L2 has no rule for.
2. **Keep the node-local brake in the December node release** (already built, inert without a key): it is what
   keeps the shortfall small between the bad block and R.
3. **Build the sum before arming** (item A3): the paid amount stored beside each paid-leaf entry and shown per
   root in `getl2settlement`, in the same native change, so the figure in point 1 is read, not estimated. Do this
   and the paid-leaf prune point (A5) in one native change with the merge onto the released node (item N1), so
   the three binaries and their pins move once.

If the owner prefers Option A: the runbook must say that a plain reset is chosen only when the brake has held
every claim since the bad block, and that a refused reset costs three to four more days.
