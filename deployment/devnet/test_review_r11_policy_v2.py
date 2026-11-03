#!/usr/bin/env python3
"""Adversarial review r11 (agent 243) of sequencer policy v2 at 731b3da: the F223-4 reorder, the standing tier, the
congestion tip across restarts, the 24 h ban and exempt senders.

Uses the fake producer and additive fake measurement of test_sequencer_policy_v2 (World), with the real-time model of
agents/223 §6: a measured run inside the settler takes about 12 s (database copy, build, export, execute), a run that
ends at the cycle limit about 37 s (34.8-40.1 s measured), and the block allowance is 180 s / 24 runs.

Every class names its finding (agents/243-policy-v2-review.md). Run: python3 -B -m unittest -v test_review_r11_policy_v2
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sequencer_policy_v2 as sp  # noqa: E402
from test_sequencer_policy_v2 import GWEI, OVER, World  # noqa: E402
from test_settler_policy_v2 import Harness as SettlerHarness  # noqa: E402
import settler_v3 as settler  # noqa: E402

CAP = 3 * GWEI  # owner decision (OWNER-DECISIONS-R10, agent 166 item): congestion tip ceiling 3 gwei
FLOOR = GWEI // 10


class RealTime(World):
    """World with agent 223's measured run times and the installer's limits."""
    RUN_SECONDS = 12

    def config(self):
        return dict(super().config(), congestion_max_tip_wei=CAP)

    def setUp(self):
        super().setUp()
        self.verdict_seconds = 37

    def measure_with(self, base):
        inner = super().measure_with(base)

        def measure(raws):
            result, report = inner(raws)
            if isinstance(result, sp.Cost):
                self.now += self.RUN_SECONDS - 2
            return result, report
        return measure

    def pending(self, sender):
        return any(self.tx[r]['sender'] == sender for r in self.spool)

    def next_nonce(self, sender):
        used = [self.tx[r]['nonce'] for r in self.tx if self.tx[r]['sender'] == sender]
        return max([self.nonce.get(sender, 0) - 1] + used) + 1

    def refill(self, senders, gas, cost, tip, tag):
        """Each attacker sender keeps one transaction pending, at its next nonce."""
        for sender in senders:
            if not self.pending(sender):
                n = self.next_nonce(sender)
                self.add(f'{tag}-{sender}-{n}', sender, n, gas, cost, tip=tip)

    def give_standing(self, senders):
        for sender in senders:
            self.add(f'seed-{sender}', sender, self.next_nonce(sender), 21_000, 0, tip=CAP)
        self.block()
        for sender in senders:
            self.assertIn(sender, self.policy.state['standing'])


class A243_1StandingSquatsTheBudget(RealTime):
    """A243-1 (High). Senders with standing (one paid transaction in 7 days) are tried before every fresh sender,
    whatever the fresh sender's tip. Seven such senders, each keeping one SP1-heavy, low-gas call pending at the
    capped required tip, fill the SP1 budget of every block. A new user at 10x the cap is never served. On mainnet
    numbers that is about 450k gas of modexp per block (90M SP1 gas at ~200 SP1 gas per gas): about 1.4 mBLCH per
    block at 3 gwei, ~0.07 BLCH a day, and no ban, because nothing is ever over the budget."""

    def test_a_new_sender_at_ten_times_the_cap_is_served_against_standing_fillers(self):
        squatters = [f'sq{i}' for i in range(7)]
        self.give_standing(squatters)
        self.add('newcomer', 'nina', 0, 150_000, 20, tip=10 * CAP)
        served = []
        for _ in range(6):
            self.refill(squatters, 90_000, 15, CAP, 'fill')
            served += self.block()
        self.assertIn('newcomer', served, f'last plan held: {self.held()}')


class A243_2StandingSquatsTheTransactionCap(RealTime):
    """A243-2 (High). `max_block_txs` (64) is applied to the try order before any run, and the tier comes first in that
    order. 64 transfers from senders with standing, at the capped tip, keep every fresh sender past the cap: it is held
    as `block-limits` and never measured. About 64 x 21k gas x 3 gwei = 4 mBLCH per block."""

    def test_a_new_sender_at_ten_times_the_cap_is_not_cut_by_the_cap_behind_standing_transfers(self):
        squatters = [f'cq{i}' for i in range(64)]
        self.give_standing(squatters)
        self.add('newcomer', 'nina', 0, 21_000, 1, tip=10 * CAP)
        served = []
        for _ in range(4):
            self.refill(squatters, 21_000, 1, CAP, 'xfer')
            served += self.block()
        self.assertIn('newcomer', served, f'last plan held: {self.held().get("newcomer")}')


class A243_3DegradedOrderIgnoresTheTip(RealTime):
    """A243-3 (High, regression of 731b3da). After the first quarantine in a block, tier 1 is tried by ascending gas
    used and the tip only breaks ties (F223-4). One fresh offender at the top tip (never pays, banned 24 h) therefore
    switches room allocation from tip to size: floor-tip calls that are smaller than an honest swap fill the budget
    and the swap is held `block-full` at 500x their tip. Without 731b3da the swap is served (r8 N2)."""

    def scenario(self):
        self.add('evil', 'mallory', 0, 1_500_000, OVER, tip=100 * GWEI)
        for i in range(7):
            self.add(f'filler{i}', f'f{i}', 0, 90_000, 15, tip=FLOOR)
        self.add('swap', 'sam', 0, 150_000, 20, tip=50 * GWEI)

    def test_the_honest_swap_outbids_floor_tip_fillers_after_an_offender(self):
        self.scenario()
        self.policy.state['tip'] = FLOOR
        names = self.block()
        self.assertIn('evil', self.quarantined)
        self.assertIn('swap', names, f'held: {self.held()}')

    def test_sustained_one_offender_per_block_keeps_the_swap_out(self):
        self.scenario()
        served = []
        for number in range(6):
            served += self.block()
            self.add(f'evil{number}', f'mallory{number}', 0, 1_500_000, OVER, tip=100 * GWEI)
            self.refill([f'f{i}' for i in range(7)], 90_000, 15, CAP, f'fill{number}')
        self.assertIn('swap', served)


class A243_4F223_4StillHolds(RealTime):
    """What F223-4 is for, kept as a pass criterion for any fix: with real verdict times, fresh offenders at the top
    tip must not keep a small new sender out of the block (agents/223 F223-4)."""

    def test_six_fresh_offenders_leave_a_new_transfer_served_in_the_same_block(self):
        self.add('newcomer', 'nina', 0, 21_000, 1)
        for i in range(6):
            self.add(f'evil{i}', f'pool{i}', 0, 1_500_000, OVER, tip=100 * GWEI)
        self.assertIn('newcomer', self.block())

    def test_offenders_of_decreasing_size_still_leave_a_new_transfer_served(self):
        # sizes chosen so that each next offender is smaller than the last quarantined one, all above the transfer
        self.add('newcomer', 'nina', 0, 21_000, 1)
        for i in range(6):
            self.add(f'evil{i}', f'pool{i}', 0, 1_500_000 - i * 200_000, OVER, tip=(100 - i) * GWEI)
        self.assertIn('newcomer', self.block())

    def test_a_sender_with_standing_is_served_against_twelve_fresh_offenders(self):
        self.give_standing(['alice'])
        for number in range(3):
            for i in range(12):
                self.add(f'evil{number}-{i}', f'pool{number}-{i}', 0, 1_500_000, OVER, tip=100 * GWEI)
            n = self.next_nonce('alice')
            self.add(f'alice{number}', 'alice', n, 21_000, 1)
            self.assertIn(f'alice{number}', self.block(), f'block {number}: {self.held()}')


class A243_5ExemptSenderBannedForADay(RealTime):
    """A243-5 (Medium). A quarantine bans the sender for 24 h, exempt senders included. Exempt senders are the operator
    and the bridge signers/relayers (OWNER-DECISIONS-R10), with a 15M gas cap and a 60 s wall backstop that a 15M-gas
    run can exceed (agents/223 F223-3). One over-budget operator transaction (a deployment, or three runs without cost)
    then stops every later transaction of that address, bridge mints included, for a day."""

    def config(self):
        return dict(super().config(), write_limit_exempt_senders=['op'])

    def test_an_exempt_sender_is_not_banned_by_one_quarantined_transaction(self):
        self.add('deploy', 'op', 0, 12_000_000, OVER)
        self.block()
        self.assertIn('deploy', self.quarantined)
        self.add('mint', 'op', 0, 120_000, 5)
        self.assertIn('mint', self.block(), f'held: {self.held()}')


class A243_6RestartKeepsTheTipDecay(RealTime):
    """F223-1a, checked from the outside: the tip decays by wall time across any number of restarts and demand saves,
    and a restart never resets the stored tip or the last block time."""

    def test_decay_across_restarts_matches_an_unrestarted_policy(self):
        self.policy.state['tip'] = CAP
        self.policy.state['last_block_time'] = self.now
        self.policy.save(self.now)
        start = self.now
        reference = sp.Policy(self.config(), None, clock=lambda: self.now)
        reference.state = json.loads(json.dumps(self.policy.state))
        for step in range(1, 13):
            self.now = start + step * 900
            restarted = self.make_policy()  # a new settler process
            self.assertEqual(restarted.required_tip(), reference.required_tip(), f'after {step * 900} s')
            restarted.save()  # policy_demand saves on every idle cycle
            self.assertEqual(restarted.state['tip'], CAP)
            self.assertEqual(restarted.state['last_block_time'], start)
        self.assertLess(reference.required_tip(), CAP)

    def test_a_torn_state_file_after_a_restart_keeps_the_tip_at_the_floor_not_above(self):
        self.policy.state['tip'] = CAP
        self.policy.save(self.now)
        self.state_path.write_text(self.state_path.read_text()[:20])
        self.assertEqual(self.make_policy().required_tip(), FLOOR)

    def test_the_rpc_tip_in_the_state_file_follows_the_decay(self):
        self.policy.state['tip'] = CAP
        self.policy.state['last_block_time'] = self.now
        self.policy.save(self.now)
        self.now += 4500 + 1200
        policy = self.make_policy()
        policy.save()
        self.assertEqual(json.loads(self.state_path.read_text())['required_tip_wei'], CAP // 2)


class A243_7LargeGasThreshold(RealTime):
    """The fix for A243-1..3: small transactions by tip across tiers, large ones after them. Its threshold only moves on
    measured verdicts, is persisted, and halves at most once per offender."""

    def test_a_measured_verdict_halves_the_threshold_and_it_survives_a_restart(self):
        self.add('evil', 'mallory', 0, 1_500_000, OVER, tip=100 * GWEI)
        self.block()
        self.assertEqual(self.policy.large_gas(), 750_000)
        self.assertEqual(self.make_policy().large_gas(), 750_000)

    def test_a_run_without_cost_does_not_move_the_threshold_for_good(self):
        self.add('slow', 'sid', 0, 300_000, 1, fail_first=100)
        self.add('newcomer', 'nina', 0, 21_000, 1)
        self.block()
        self.assertEqual(self.held()['slow'], 'unmeasured')
        self.assertEqual(self.make_policy().large_gas(), sp.DEFAULTS['max_tx_gas'])

    def test_offenders_at_or_above_half_the_smallest_verdict_never_go_before_small_honest_transactions(self):
        self.add('evil-first', 'm-first', 0, 600_000, OVER, tip=100 * GWEI)
        self.block()
        for number in range(4):
            for i in range(6):
                self.add(f'evil{number}-{i}', f'pool{number}-{i}', 0, 300_000 + i * 1000, OVER, tip=100 * GWEI)
            self.add(f'new{number}', f'nina{number}', 0, 120_000, 1, tip=GWEI)
            self.assertIn(f'new{number}', self.block(), f'block {number}: {self.held()}')
        self.assertEqual(self.policy.large_gas(), 300_000)

    def test_an_exempt_large_transaction_keeps_its_place_by_tip(self):
        self.policy.c['write_limit_exempt_senders'] = ['op']
        self.policy.state['large_gas'] = 100_000
        stats = [{'hash': 'deploy', 'sender': 'op', 'nonce': 0, 'gas_used': 9_000_000, 'effective_tip': str(2 * GWEI)},
                 {'hash': 'x', 'sender': 'x', 'nonce': 0, 'gas_used': 21_000, 'effective_tip': str(GWEI)},
                 {'hash': 'big', 'sender': 'b', 'nonce': 0, 'gas_used': 400_000, 'effective_tip': str(9 * GWEI)}]
        self.assertEqual(self.policy.try_order(stats, self.now), ['deploy', 'x', 'big'])

    def test_nonce_order_holds_when_a_large_nonce_precedes_a_small_one(self):
        self.policy.state['large_gas'] = 100_000
        stats = [{'hash': 'a1', 'sender': 'a', 'nonce': 1, 'gas_used': 21_000, 'effective_tip': str(9 * GWEI)},
                 {'hash': 'a0', 'sender': 'a', 'nonce': 0, 'gas_used': 400_000, 'effective_tip': str(GWEI)},
                 {'hash': 'b', 'sender': 'b', 'nonce': 0, 'gas_used': 50_000, 'effective_tip': str(2 * GWEI)}]
        self.assertEqual(self.policy.try_order(stats, self.now), ['b', 'a0', 'a1'])

    def test_after_a_verdict_a_large_honest_transaction_goes_before_larger_offenders(self):
        self.policy.state['large_gas'] = 300_000
        self.add('evil-small', 'm0', 0, 250_000, OVER, tip=100 * GWEI)  # small enough to count as small: one verdict
        for i in range(4):
            self.add(f'evil{i}', f'pool{i}', 0, 1_500_000, OVER, tip=100 * GWEI)
        self.add('deploy', 'dana', 0, 400_000, 10, tip=GWEI)
        self.assertIn('deploy', self.block(), f'held: {self.held()}')

    def test_a_large_transaction_with_standing_outbids_small_standing_fillers(self):
        squatters = [f'sq{i}' for i in range(7)]
        self.give_standing(squatters + ['dana'])
        self.policy.state['large_gas'] = 200_000
        self.add('multi-hop', 'dana', self.next_nonce('dana'), 450_000, 20, tip=10 * CAP)
        served = []
        for _ in range(3):
            self.refill(squatters, 90_000, 15, CAP, 'fill')
            served += self.block()
        self.assertIn('multi-hop', served, f'held: {self.held()}')


class A243_8PlanStateSurvivesAFailedExtend(SettlerHarness):
    """A243-8 (Low). The plan's verdicts (quarantine ban, failure counts, waits) lived only in memory until
    `committed`. When the final `extend` is refused, the settler retries the block with deposits only and never calls
    `committed`: the quarantined file is already moved, but its sender is not banned, so it can send again and cost
    two cycle-limit verdicts in the next block. The same happens on a crash or a restart between plan and commit."""

    def test_the_ban_of_a_quarantined_sender_is_saved_before_the_final_extend(self):
        # the settler sets keccak256 as the policy's hash; World (same process) uses sha256
        self.addCleanup(sp.set_hash, lambda data: hashlib.sha256(data).digest())
        self.spool(a=10, b=10_000)
        inner = self.produce

        def produce(*args):
            if args[0] == 'extend' and '--txs' in args and args[args.index('--txs') + 1].endswith('selected.json'):
                raise settler.ProducerError('refused')
            if args[0] == 'head':
                return {'number': 1}
            return inner(*args)
        self.settler.produce = produce
        self.block()
        self.assertEqual(self.quarantined(), ['b'])
        state = json.loads((self.settler.work / 'sequencer-policy.json').read_text())
        self.assertIn('b'.encode().hex()[:4], state['bans'])


if __name__ == '__main__':
    unittest.main()
