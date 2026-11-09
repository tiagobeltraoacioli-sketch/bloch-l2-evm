#!/usr/bin/env python3
"""Adversarial review r12 (agent 264) of sequencer policy v2 as amended by agent 243 (731b3da..33dad8e) on the
user-transaction candidate aa7f2e3.

Uses the fake producer and additive fake measurement of test_sequencer_policy_v2 (World) and agent 243's real-time model
(RealTime: a measured run inside the settler about 12 s, a cycle-limit verdict about 37 s; agents/224 measured 11-13 s
wall for the host alone on a 64-swap block, before the database copy, extend and export of the settler's run).

Every class names its finding (agents/264-policy-v2-review2.md). A test that fails here is the finding; it passes once
the finding is fixed. Run: python3 -B -m unittest -v test_review_r12_policy_v2
"""
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sequencer_policy_v2 as sp  # noqa: E402
from test_sequencer_policy_v2 import GWEI, OVER  # noqa: E402
from test_review_r11_policy_v2 import CAP, FLOOR, RealTime, SlotWorld  # noqa: E402
from test_settler_policy_v2 import Harness as SettlerHarness  # noqa: E402
import settler_v3 as settler  # noqa: E402


class F264_1OutOfWorkInsideTheSearchDropsTheFittingPrefix(RealTime):
    """F264-1 (High). `_first_misfit` returns None when the allowance (180 s / 24 runs) runs out inside the search, and
    `plan` then breaks with `best` unchanged: the prefix the search already measured as fitting is thrown away, and the
    offender is neither quarantined nor banned. Before any verdict every transaction is "small" (`large_gas` starts at
    `max_tx_gas`), so one unpaid offender at the lowest admissible tip is the last of 64 candidates. Its block then costs
    base + full verdict + 6 gallop + 5 bisection runs: 13 * 13 s + 37 s = 180 s at 13 s per measured run. The block
    takes no user transaction, and the same spool does the same in every block, for one funded key that never pays."""
    RUN_SECONDS = 13

    def scenario(self):
        for i in range(63):
            self.add(f'h{i}', f'user{i}', 0, 21_000, 1, tip=GWEI)
        self.add('evil', 'mallory', 0, 1_500_000, OVER, tip=FLOOR)

    def test_a_block_with_one_offender_at_the_back_still_serves_the_fitting_prefix(self):
        self.scenario()
        served = self.block()
        self.assertGreaterEqual(len(served), 32, f'exhausted={self.plans[-1].exhausted} runs={self.plans[-1].runs} '
                                                 f'seconds={self.plans[-1].seconds:.0f} held={len(self.plans[-1].held)}')

    def test_the_offender_does_not_starve_four_blocks_in_a_row(self):
        self.scenario()
        served = []
        for _ in range(4):
            served += self.block()
        self.assertTrue('evil' in self.quarantined or len(served) >= 63,
                        f'served {len(served)} honest in 4 blocks; evil quarantined: {"evil" in self.quarantined}')


class F264_1bDegradedSearchLosesItsPrefixToo(RealTime):
    """F264-1, degraded path. After one verdict the search starts from the front with `full_known=False`; running out of
    work there also returns None and drops what was measured as fitting. Two fresh offenders at the top tip then one at
    the back at 14 s per run: the block takes nothing."""
    RUN_SECONDS = 14

    def test_after_a_verdict_an_exhausted_search_keeps_what_fits(self):
        self.add('evil-a', 'mallory', 0, 1_500_000, OVER, tip=100 * GWEI)
        for i in range(62):
            self.add(f'h{i}', f'user{i}', 0, 21_000, 1, tip=GWEI)
        self.add('evil-b', 'trent', 0, 21_000, OVER, tip=FLOOR)  # small gas: stays in the first group
        served = self.block()
        self.assertGreaterEqual(len(served), 16, f'exhausted={self.plans[-1].exhausted} runs={self.plans[-1].runs} '
                                                 f'seconds={self.plans[-1].seconds:.0f}')


class F264_2GateFallbackCreatesUnpaidSlotsAboveTheBlockLimit(SlotWorld):
    """F264-2 (Medium). When the gate does not settle in `gate_passes` (6), `_gated` keeps the last pass's passing set
    (A243-12 fix, 2e3f2cf). A transaction behind the last refusal is counted with the new-slot counts of a selection
    that still held the refused writer, so it is counted 0 for slots it really creates. The bypass is not one slot: it is
    every slot the chain writes, and two chains bypass the 128-per-block write limit as well. Six senders that never pay
    (refused, never included) buy a seventh transaction any number of unpaid new slots at the floor tip."""

    def chain(self, tag, slots, top):
        for i in range(6):
            self.add_writer(f'chain{tag}{i}', f'c{tag}{i}', 0, 50_000, 1, slots, tip=(top - i) * GWEI // 10)
        self.add_writer(f'free{tag}', f'f{tag}', 0, 50_000, 1, slots, tip=FLOOR)

    def test_no_committed_transaction_creates_slots_it_did_not_pay_for(self):
        self.chain('a', [f'a{i}' for i in range(100)], top=39)
        self.chain('b', [f'b{i}' for i in range(100)], top=29)
        finals = []
        inner = self.policy.committed

        def committed(plan, final_report, now=None):
            finals.append(final_report)
            return inner(plan, final_report, now)
        self.policy.committed = committed
        self.block()
        price = sp.DEFAULTS['fresh_slot_price_wei']
        unpaid, in_block = [], 0
        for stat in finals[-1]['tx_stats']:
            fresh = sum(n for _, n in stat['fresh_slots'])
            in_block += fresh
            if fresh and int(stat['gas_used']) * int(stat['effective_tip']) < fresh * price:
                unpaid.append((stat['sender'], fresh))
        self.assertEqual(unpaid, [], f'unpaid new slots in the committed block; block total {in_block}')
        self.assertLessEqual(in_block, sp.DEFAULTS['fresh_slots_per_block'])


class F264_3DependentWaitSurvivesAPayingReplacement(SlotWorld):
    """F264-3 (Low). A refusal from the second gate pass on (below the write price or the sender write rate) waits
    `gate_dependent_wait_seconds` (1 h) keyed by sender and nonce (4d06e65). A user whose new slot was first hidden by an
    unpaid writer ahead (for example a 1-unit token transfer to them, at a higher tip) and who then replaces the
    transaction at a tip that pays is still refused for the hour. Agent 243's A243-11 shows that wallets at the suggested
    tip underpay their first new slot, so the first try of a new user is exactly this case. A second-pass refusal can
    also come without any dependency: a transaction outside the 15M-gas window of the first `select` enters the second
    one."""

    def test_a_replacement_that_pays_is_served_in_the_next_block(self):
        self.add_writer('nudge', 'mallory', 0, 15_000, 1, ['bal:nina'], tip=10 * GWEI)  # 150 uBLCH: unpaid, at a higher tip
        first = self.add_writer('swap', 'nina', 0, 50_000, 1, ['bal:nina'], tip=GWEI)  # underpays its one slot
        self.block()
        self.assertEqual(self.held().get('swap'), 'below-write-price')
        self.spool.remove(first)
        self.add_writer('swap-paid', 'nina', 0, 50_000, 1, ['bal:nina'], tip=8 * GWEI)  # 50k x 8 gwei = 400 uBLCH
        self.assertIn('swap-paid', self.block(), f'held: {self.held()}')


class F264_4ExemptOffenderIsMeasuredFirstEveryBlock(RealTime):
    """F264-4 (Low). An exempt sender is never banned (A243-5, fcc36d3) and is always in the first group by tip. If its
    key resends an over-budget transaction at the same nonce (a relayer bug, or a stolen hot signer key), every block
    spends two cycle-limit verdicts (~74 s of the 180 s allowance) on it before any other candidate, for ever. The
    pass criterion asks that a resend after a verdict within `sender_ban_seconds` is measured after the other candidates
    (or not at all), not that the sender is banned."""

    def config(self):
        return dict(super().config(), write_limit_exempt_senders=['relayer'])

    def test_a_resent_exempt_offender_is_not_measured_ahead_of_users(self):
        verdicts = []
        for number in range(4):
            name = f'mint-bad-{number}'
            self.add(name, 'relayer', 0, 1_500_000, OVER, tip=100 * GWEI)
            for i in range(8):
                self.add(f'u{number}-{i}', f'user{number}-{i}', 0, 21_000, 1, tip=GWEI)
            self.block()
            verdicts.append(self.runs_with.get(name, 0))
        self.assertLessEqual(sum(verdicts[1:]), 3, f'runs including the exempt offender per block: {verdicts}')


class F264_5LargeFreshTransactionBehindTheTransactionCap(RealTime):
    """F264-5 (Low). `max_block_txs` (64) is applied to the try order before any run, and every large transaction of a
    fresh sender comes after every small one whatever its tip (0ae2d71). Once a verdict has lowered `large_gas`
    (280k-gas offender: 140k), 64 small floor-tip transfers per block (about 0.13 mBLCH of tips) keep a fresh sender's
    150k-gas swap at 10x the cap out as `block-limits`, unmeasured, for as long as they are sent. The design text says
    such a sender is served "after the small ones"; under the cap it is not served at all. Mitigation exists (a small
    paid transaction first gives standing), so Low."""

    def test_a_fresh_large_swap_at_ten_times_the_cap_is_served_against_small_floor_transfers(self):
        self.add('kzg', 'mallory', 0, 280_000, OVER, tip=100 * GWEI)
        self.block(advance=0)
        self.assertEqual(self.policy.large_gas(), 140_000)
        self.add('swap', 'nina', 0, 150_000, 20, tip=10 * CAP)
        served = []
        for number in range(4):
            for i in range(64):
                self.add(f'x{number}-{i}', f'spam{number}-{i}', 0, 21_000, 0, tip=self.policy.required_tip(self.now))
            served += self.block()
        self.assertIn('swap', served, f'held: {self.held().get("swap")}')


class F264_6EveryRunCopiesTheWholeDatabase(SettlerHarness):
    """F264-6 (Medium, scaling). `measure_block` copies the whole L2 database for every run
    (`shutil.copytree(self.c['l2_db'], db)`), including the base, the control and every search step: up to 24 copies
    per block. The 11-13 s per run of agents/224 were measured on a small rehearsal database; the copy grows with the
    chain's state, and every second of it comes out of the 180 s allowance (F264-1). The pass criterion: at most one
    full copy per block plan."""

    def test_one_block_plan_copies_the_database_at_most_once(self):
        st = self.settler
        st.measure_block = settler.Settler.measure_block.__get__(st)
        copies = []
        real_copy = settler.shutil.copytree

        def copytree(src, dst, *args, **kwargs):
            copies.append(str(dst))
            return real_copy(src, dst, *args, **kwargs)

        costs = {}

        heads = {}  # database path: head number (the fake producer's chain: block 1 is the parent 'p')

        def produce(*args):
            target = args[args.index('--target') + 1] if '--target' in args else None
            if args[0] == 'export':
                Path(args[args.index('--out') + 1]).write_text('artifact')
                return {}
            if args[0] == 'head':
                return {'number': heads.get(target, 1), 'hash': 'p' if heads.get(target, 1) == 1 else 'x'}
            if args[0] == 'rewind':  # as the real producer: it removes the head block, named by number and hash
                named = int(args[args.index('--number') + 1]), args[args.index('--hash') + 1]
                if named != (heads.get(target, 1), 'x'):
                    raise settler.ProducerError(f'refused: the head is block {heads.get(target, 1)}, not {named[0]}')
                rewinds.append(target)
                heads[target] = named[0] - 1
                return {}
            if args[0] == 'extend':
                heads[target] = heads.get(target, 1) + 1
            return self.produce(*args)
        rewinds = []
        st.produce = produce
        st.preflight_request = 'request\n'

        def run_bounded(argv, env, stdout, stderr, timeout):
            artifact = Path(env['BLOCH_NATIVE_L2_ARTIFACT'])
            pool = artifact.parent / 'pool.json'
            raws = __import__('json').loads(pool.read_text()) if pool.exists() else []
            total = 2 + sum(costs.get(r, 1) for r in raws)
            limit = int(env['BLOCH_PREFLIGHT_CYCLE_LIMIT'])
            stdout.write(f'Settlement V3 preflight stage 1: instructions={min(total, limit)} elapsed_ms=1\n')
            if total >= limit:  # the two-stage host (agent 257): the gas-off count is the verdict
                stdout.write(f'Settlement V3 over cycle limit: limit={limit} instructions={limit} stage=1\n')
                return mock.Mock(returncode=3)
            stdout.write(f'Settlement V3 cost: gas={total} touched_memory=0 record_bytes=0 syscalls=0\n'
                         f'Settlement V3 guest matched the independent host statement: {total} instructions in 1 ms\n')
            return mock.Mock(returncode=0)
        st.run_bounded = run_bounded
        st.c['prover_path'] = '/usr/bin:/bin'
        self.spool(a=10, b=10_000, c=10, d=10)
        costs.update(self.cost)
        st.cost_line_checked, st.cost_line_program = True, (
            st.program['prover'], (), st.program['guest'], 'complete', st.policy().cycle_limit())
        with mock.patch.object(settler.shutil, 'copytree', side_effect=copytree):
            block = self.block()
        self.assertLessEqual(len(copies), 1, f'{len(copies)} full database copies for one block plan')
        self.assertGreaterEqual(len(rewinds), 3, 'every run takes its block off the copy again')
        self.assertNotIn('preflight-copy-discarded', [event for event, _ in self.logged])
        self.assertEqual(self.names(), [], 'the plan is the same as with a copy per run')
        self.assertEqual(self.quarantined(), ['b'])
        self.assertFalse((self.dir / 'preflight-db').exists(), 'the copy does not outlive the plan')
        self.assertEqual(block['transactions'], 3)

    def test_a_copy_that_does_not_rewind_is_thrown_away(self):
        st = self.settler
        st.preflight_shared = self.dir / 'preflight-db'
        scratch = self.dir / 'preflight-0'
        scratch.mkdir()
        db = st.preflight_database(self.dir, scratch)
        self.assertEqual(db, st.preflight_shared)
        st.produce = lambda *args: {'number': 2, 'hash': 'x'}  # the rewind leaves the measured block in place
        st.preflight_rewind(db, 'p', 2)
        self.assertFalse(db.exists())
        self.assertIn('preflight-copy-discarded', [event for event, _ in self.logged])


if __name__ == '__main__':
    unittest.main()
