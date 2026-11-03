#!/usr/bin/env python3
"""Unit tests for sequencer_policy_v2 (docs/SEQUENCER-POLICY-V2.md).

Each class names the review finding it closes (agents/121 F*, agents/135 N* and U*). The scenarios are agent 135's,
re-expressed against the v2 planning core, with a fake producer that follows `select.rs` (per-sender nonce order, best
tip across senders, a nonce gap deferred and never dropped, a used nonce dropped) and an additive fake measurement:

  cost int   the transaction's SP1 gas (and instructions) on top of the block's base
  OVER       the host's cycle limit ended the run (a measured fact)
  None       no cost (host failure, wall-clock timeout)

Run: python3 -B -m unittest -v test_sequencer_policy_v2
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sequencer_policy_v2 as sp  # noqa: E402

sp.set_hash(lambda data: hashlib.sha256(data).digest())
OVER = 'over'
GWEI = 10**9


def h(raw):
    return hashlib.sha256(bytes.fromhex(raw)).hexdigest()


class World(unittest.TestCase):
    BUDGET = 100
    EMPTY_BASE = 2
    DEPOSIT_BASE = 10
    PACE = 1800

    def config(self):
        return {'max_block_sp1_gas': self.BUDGET, 'max_block_instructions': self.BUDGET, 'fast_profile_max_sp1_gas': 20,
                'min_tip_wei': GWEI // 10}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_path = Path(self.tmp.name) / 'sequencer-policy.json'
        self.now = 1_000_000.0
        self.logged = []
        self.policy = self.make_policy()
        self.tx = {}  # raw: dict
        self.spool = []  # raws
        self.quarantined = []  # names
        self.nonce = {}  # sender: next nonce
        self.blocks = []  # names per block
        self.plans = []
        self.runs_with = {}  # name: measurements that included it
        self.timeouts = 0
        self.host_down = False
        self.mandatory_cost = None  # override of DEPOSIT_BASE
        self.verdict_seconds = 10  # wall time of a run that ends at the cycle limit

    def make_policy(self):
        return sp.Policy(self.config(), self.state_path, clock=lambda: self.now,
                         log=lambda event, **fields: self.logged.append((event, fields)))

    # Fake producer

    def select(self, raws, limit=10**6):
        queues, dropped = {}, []
        for raw in raws:
            queues.setdefault(self.tx[raw]['sender'], []).append(raw)
        for queue in queues.values():
            queue.sort(key=lambda r: (self.tx[r]['nonce'], -self.tx[r]['tip'], h(r)))
        expected, included = dict(self.nonce), []
        while True:
            heads = sorted(((self.tx[q[0]]['tip'], q[0]) for q in queues.values() if q), key=lambda x: (-x[0], h(x[1])))
            if not heads:
                break
            raw = heads[0][1]
            t = self.tx[raw]
            queue = queues[t['sender']]
            queue.pop(0)
            want = expected.get(t['sender'], 0)
            if t['nonce'] < want:
                dropped.append({'hash': h(raw), 'reason': 'nonce-too-low'})
                continue
            if t['nonce'] > want or len(included) >= limit:
                queue.clear()
                continue
            expected[t['sender']] = want + 1
            included.append(raw)
        return included, dropped, expected

    def report(self, raws):
        included, dropped, _ = self.select(raws)
        return {'included': [h(r) for r in included], 'dropped': dropped,
                'tx_stats': [{'hash': h(r), 'sender': self.tx[r]['sender'], 'nonce': self.tx[r]['nonce'],
                              'gas_used': self.tx[r]['gas'], 'effective_tip': str(self.tx[r]['tip']),
                              'fresh_slots': self.tx[r]['fresh']} for r in included]}

    def measure_with(self, base):
        def measure(raws):
            included, _, _ = self.select(raws, 64)
            for r in included:
                name = self.tx[r]['name']
                self.runs_with[name] = self.runs_with.get(name, 0) + 1
            if self.host_down:
                self.now += 60
                self.timeouts += 1
                return None, self.report(raws)
            failing = [r for r in included if self.tx[r]['fail_first'] > 0]
            for r in failing:
                self.tx[r]['fail_first'] -= 1
            costs = [self.tx[r]['cost'] for r in included]
            if failing or base == 'none' or any(c is None for c in costs):
                self.now += 60
                self.timeouts += 1
                return None, self.report(raws)
            if any(c == OVER for c in costs) or base == OVER:
                self.now += self.verdict_seconds
                return sp.OVER_LIMIT, self.report(raws)
            total = base + sum(costs)
            self.now += 2
            if total > 2 * self.BUDGET:
                return sp.OVER_LIMIT, self.report(raws)
            return sp.Cost(total, total), self.report(raws)
        return measure

    def measure_empty(self):
        if self.host_down:
            self.now += 60
            return None
        self.now += 2
        return sp.Cost(self.EMPTY_BASE, self.EMPTY_BASE)

    # Helpers

    def add(self, name, sender, nonce, gas, cost, tip=GWEI, fresh=(), fail_first=0):
        raw = name.encode().hex()
        self.tx[raw] = dict(name=name, sender=sender, nonce=nonce, gas=gas, cost=cost, tip=tip,
                            fresh=[list(f) for f in fresh], fail_first=fail_first)
        self.spool.append(raw)
        return raw

    def names(self, hashes):
        by = {h(r): self.tx[r]['name'] for r in self.tx}
        return [by[x] for x in hashes]

    def block(self, deposits=False, advance=None):
        base = self.mandatory_cost if self.mandatory_cost is not None else (self.DEPOSIT_BASE if deposits else self.EMPTY_BASE)
        plan = self.policy.plan(list(self.spool), self.report, self.measure_with(base), self.measure_empty, deposits)
        self.plans.append(plan)
        final = self.report(plan.raws)  # the committed block's own extend report
        included, dropped, expected = self.select(plan.raws)
        self.nonce = expected
        removed = set(self.policy.committed(plan, final))
        moved = {name for name, _ in plan.quarantine}
        self.quarantined += self.names(sorted(moved))
        self.spool = [r for r in self.spool if h(r) not in removed and h(r) not in moved]
        names = [self.tx[r]['name'] for r in included]
        self.blocks.append(names)
        self.now += self.PACE if advance is None else advance
        return names

    def spooled(self):
        return sorted(self.tx[r]['name'] for r in self.spool)

    def held(self, plan=None):
        plan = plan or self.plans[-1]
        return {name: reason for name, reason in zip(self.names([x for x, _ in plan.held]), [r for _, r in plan.held])}


# Review r8 (agent 135)

class N1NonceOrderAndSpoolRemoval(World):
    """A sender's later, cheaper nonce must never be chosen without its earlier one, and only what the committed block
    included or dropped leaves the spool."""

    def test_a_later_nonce_that_was_not_included_stays_in_the_spool(self):
        self.add('a0-call', 'alice', 0, 400_000, 50)
        self.add('a1-transfer', 'alice', 1, 21_000, 5)
        self.add('b0-call', 'bob', 0, 100_000, 45, tip=2 * GWEI)
        first = self.block(deposits=True)
        if 'a0-call' not in first:
            self.assertNotIn('a1-transfer', first)
        for name in ('a0-call', 'a1-transfer', 'b0-call'):
            if name not in first:
                self.assertIn(name, self.spooled())

    def test_both_nonces_of_a_sender_are_eventually_included(self):
        self.add('a0-call', 'alice', 0, 400_000, 50)
        self.add('a1-transfer', 'alice', 1, 21_000, 5)
        self.add('b0-call', 'bob', 0, 100_000, 45)
        included = [n for _ in range(5) for n in self.block(deposits=True)]
        self.assertIn('a0-call', included)
        self.assertIn('a1-transfer', included)
        self.assertEqual(self.spooled(), [])

    def test_committed_removes_only_what_the_final_report_included(self):
        plan = sp.Plan()
        plan.chosen = ['x', 'y']
        removed = self.policy.committed(plan, {'included': ['x'], 'dropped': [], 'tx_stats': []})
        self.assertEqual(removed, ['x'])

    def test_try_order_keeps_nonce_order_against_gas_and_tip(self):
        stats = [{'hash': 'n1', 'sender': 'a', 'nonce': 1, 'gas_used': 21_000, 'effective_tip': str(9 * GWEI)},
                 {'hash': 'n0', 'sender': 'a', 'nonce': 0, 'gas_used': 900_000, 'effective_tip': str(GWEI)},
                 {'hash': 'b', 'sender': 'b', 'nonce': 0, 'gas_used': 50_000, 'effective_tip': str(2 * GWEI)}]
        order = self.policy.try_order(stats, self.now)
        self.assertLess(order.index('n0'), order.index('n1'))


class N2TipBuysRoomInAFullBlock(World):
    def test_a_higher_tip_is_served_while_floor_tip_calls_fill_the_block(self):
        floor = GWEI // 10
        self.add('honest-swap', 'honest', 0, 150_000, 20, tip=100 * floor)
        for i in range(7):
            self.add(f'm{i}', f'attacker{i}', 0, 100_000, 12, tip=floor)
        self.assertIn('honest-swap', self.block(deposits=True))


class N3ReplacementRestartsNothing(World):
    def test_a_replaced_heavy_transaction_costs_one_block_then_nothing(self):
        self.add('honest', 'alice', 0, 21_000, 1)
        self.add('evil-0', 'mallory', 0, 4_900_000, OVER, tip=GWEI)
        self.block()
        self.assertIn('evil-0', self.quarantined)
        runs = []
        for i in range(1, 6):
            self.add(f'evil-{i}', 'mallory', 0, 4_900_000, OVER, tip=int(GWEI * 1.1 ** i))
            before = sum(self.runs_with.get(f'evil-{j}', 0) for j in range(i + 1))
            self.block()
            runs.append(sum(self.runs_with.get(f'evil-{j}', 0) for j in range(i + 1)) - before)
        self.assertEqual(runs, [0] * 5, 'a banned sender\'s replacement must not be measured')
        self.assertEqual(self.held()[f'evil-5'], 'sender-banned')


class N3bReplacementKeepsTheUnmeasuredWait(World):
    """A transaction without cost on a healthy host (the control measures) waits by sender and nonce: replacing it
    with a 10% higher fee neither restarts the wait nor resets the count."""

    def test_replacement_during_the_wait_is_not_measured_and_counts_on(self):
        self.add('slow-0', 'mallory', 0, 50_000, 1, fail_first=100)
        self.block(advance=60)
        self.spool = [r for r in self.spool if self.tx[r]['name'] != 'slow-0']  # the RPC replaced it
        self.add('slow-1', 'mallory', 0, 50_000, 1, fail_first=100, tip=int(GWEI * 1.1))
        self.block(advance=0)
        self.assertEqual(self.held()['slow-1'], 'unmeasured-wait')
        self.assertNotIn('slow-1', self.runs_with)
        self.now += 600
        self.block(advance=1800)
        self.assertEqual(self.policy.state['failures']['mallory:0']['count'], 2)


class N4OneUnmeasurableTransactionIsCheap(World):
    def test_a_heavy_transaction_costs_at_most_two_runs_and_no_timeout(self):
        self.add('evil', 'mallory', 0, 4_900_000, OVER, tip=10 * GWEI)
        self.add('honest', 'alice', 0, 21_000, 1)
        names = self.block()
        self.assertIn('honest', names)
        self.assertEqual(self.quarantined, ['evil'])
        self.assertLessEqual(self.runs_with['evil'], 2)
        self.assertEqual(self.timeouts, 0)


class N5MandatoryBandWaits(World):
    """A transaction over the budget only because of this block's deposits waits for a block without them, and is not
    measured again in every block with a deposit."""

    def test_band_transaction_measured_once_in_ten_deposit_blocks_then_served_without_deposits(self):
        self.add('band', 'bob', 0, 2_000_000, 95)  # 10 + 95 > 100, 2 + 95 fits
        self.add('honest', 'alice', 0, 21_000, 1)
        for _ in range(10):
            self.block(deposits=True)
        # The full and alone runs of the first block, then one alone run each time the 2 h wait ends (blocks 5 and 9).
        self.assertEqual(self.runs_with['band'], 4)
        self.assertIn('honest', [n for b in self.blocks for n in b])
        self.assertIn('band', self.block(deposits=False))
        self.assertNotIn('band', self.quarantined)


class N6MandatoryBlockWithoutCost(World):
    def test_mandatory_block_over_the_cycle_limit_carries_no_user_transaction_and_is_recorded(self):
        self.add('honest', 'alice', 0, 21_000, 1)
        self.mandatory_cost = OVER
        self.assertEqual(self.block(deposits=True), [])
        plan = self.plans[-1]
        self.assertTrue(plan.mandatory_over_budget)
        self.assertEqual(plan.profile, 'mandatory-heavy')
        self.assertEqual(self.quarantined, [])
        self.assertEqual(self.spooled(), ['honest'])

    def test_mandatory_block_without_cost_on_a_healthy_host_is_recorded_and_takes_no_user_transaction(self):
        self.add('honest', 'alice', 0, 21_000, 1)
        self.mandatory_cost = 'none'  # the deposit block's run fails without the cycle-limit verdict; the control measures
        self.assertEqual(self.block(deposits=True), [])
        plan = self.plans[-1]
        self.assertTrue(plan.mandatory_over_budget)
        self.assertFalse(plan.host_unavailable)
        self.assertEqual(plan.profile, 'mandatory-heavy')
        self.assertEqual(self.quarantined, [])

    def test_failing_host_takes_no_unmeasured_user_transactions(self):
        self.add('honest', 'alice', 0, 21_000, 1)
        self.host_down = True
        self.assertEqual(self.block(deposits=True), [])
        self.assertTrue(self.plans[-1].host_unavailable)
        self.assertEqual(self.quarantined, [])

    def test_producer_without_selection_report_takes_nothing(self):
        self.add('honest', 'alice', 0, 21_000, 1)
        plan = self.policy.plan(list(self.spool), lambda raws: {'included': [h(r) for r in raws]},
                                self.measure_with(self.EMPTY_BASE), self.measure_empty, False)
        self.assertEqual(plan.chosen, [])


class N7CongestionTipAgainstPartialSaturation(World):
    def tip_after(self, pattern, cycles, seconds_per_block):
        self.policy.path = None
        for _ in range(cycles):
            for saturated in pattern:
                plan = sp.Plan()
                plan.base = sp.Cost(self.EMPTY_BASE, self.EMPTY_BASE)
                plan.cost = sp.Cost(self.BUDGET if saturated else self.EMPTY_BASE, 0)
                self.policy.committed(plan, {'included': []})
                self.now += seconds_per_block
        return self.policy.required_tip(self.now - seconds_per_block)

    def test_five_of_six_saturated_blocks_raise_the_tip(self):
        self.assertGreater(self.tip_after([1, 1, 1, 1, 1, 0], 100, 600), 10 * GWEI)

    def test_one_of_two_saturated_blocks_raise_the_tip(self):
        self.assertGreater(self.tip_after([1, 0], 300, 600), GWEI)


class N8WaitingEntryIsNoDemand(World):
    def test_an_unmeasured_wait_is_not_demand(self):
        self.add('slow', 'alice', 0, 21_000, 1, fail_first=10)
        self.block()  # no cost: waits 10 min
        stats = self.report(self.spool)['tx_stats']
        self.assertFalse(self.policy.demand(stats, self.now - self.PACE + 60, False))


class N9U2HonestTransactionWithoutCostGetsThreeTriesInsideTheTtl(World):
    def test_400k_gas_deployment_with_two_failed_runs_is_served_within_three_hours(self):
        self.add('deploy', 'alice', 0, 400_000, 30, fail_first=2)
        start = self.now
        served = None
        for _ in range(40):
            stats = self.report(self.spool)['tx_stats']
            if self.spool and self.policy.demand(stats, self.now, False):
                if 'deploy' in self.block(advance=0):
                    served = self.now
                    break
            self.now += 300  # the settler's hold cycle
        self.assertIsNotNone(served)
        self.assertLess(served - start, 3 * 3600)
        self.assertEqual(self.quarantined, [])

    def test_a_host_that_fails_after_the_base_run_quarantines_nothing(self):
        self.add('deploy', 'alice', 0, 400_000, 30, fail_first=100)
        self.measure_empty = lambda: None  # the control fails too: the host, not the transaction
        for _ in range(6):
            self.block()
        self.assertTrue(self.plans[-1].host_unavailable)
        self.assertEqual(self.quarantined, [])
        self.assertEqual(self.policy.state['failures'], {})

    def test_no_cost_on_a_failing_host_never_quarantines(self):
        self.add('deploy', 'alice', 0, 400_000, 30)
        self.host_down = True
        for _ in range(6):
            self.block()
        self.assertEqual(self.quarantined, [])
        self.assertEqual(self.policy.state['bans'], {})


# Review r9 (agent 135)

class U1UnpaidTipDoesNotBuyMeasuringTime(World):
    def test_three_resending_senders_per_block_do_not_keep_an_honest_transfer_out(self):
        self.add('honest', 'alice', 0, 21_000, 1, tip=GWEI)
        served = None
        for number in range(20):
            for i in range(3):
                self.add(f'evil{number}-{i}', f'mallory{number % 2}-{i}', 0, 4_900_000, OVER, tip=100 * GWEI)
            if 'honest' in self.block():
                served = number
                break
        self.assertEqual(served, 0)
        self.assertEqual(self.timeouts, 0)

    def test_a_reused_pool_does_not_starve_a_sender_with_standing(self):
        self.add('first', 'alice', 0, 21_000, 1)
        self.block()
        for number in range(10):
            for i in range(12):  # twelve fresh senders per block at the top tip, each over the cycle limit: more than
                # the 180 s allowance can measure, so only the tier puts alice first
                self.add(f'evil{number}-{i}', f'pool{number}-{i}', 0, 4_900_000, OVER, tip=100 * GWEI)
            self.add(f'alice{number}', 'alice', number + 1, 21_000, 1)
            self.assertIn(f'alice{number}', self.block(), f'block {number}: {self.held()}')
            self.assertLessEqual(self.plans[-1].runs, sp.DEFAULTS['preflight_max_runs'])

    def test_measuring_per_offender_at_the_front_is_one_full_run_and_one_alone_run(self):
        for i in range(3):
            self.add(f'evil{i}', f'm{i}', 0, 4_900_000, OVER, tip=100 * GWEI)
        self.add('honest', 'alice', 0, 21_000, 1)
        self.assertEqual(self.block(), ['honest'])
        # base + 3 x (full + alone) + the final full run; agent 223 (F223-4): after the first quarantine the newcomer is
        # tried first (gas order), which costs one probe more
        self.assertLessEqual(self.plans[-1].runs, 1 + 3 * 2 + 2)


class U1ResidualNewSenderBound(World):
    """The documented residual (design section 7, R1): fresh senders at the top tip, each over the cycle limit, cost two
    cycle-limited runs (10 s each here) and a 24 h ban. Eight per block leave room for a new honest sender; nine exhaust
    the 180 s allowance before it is reached, and it is served in the next block unless the attacker spends nine more
    fresh senders. Senders with standing are never behind them."""

    def attack(self, k, tag):
        for i in range(k):
            self.add(f'evil{tag}-{i}', f'pool{tag}-{i}', 0, 4_900_000, OVER, tip=100 * GWEI)

    # Agent 223 (F223-4): with real verdict times (35-40 s per run inside the settler) the old order let 3 fresh attackers
    # exhaust the allowance. After the first quarantine of a block, tier 1 is tried in ascending gas used.

    def test_eight_fresh_attackers_per_block_leave_a_new_sender_served(self):
        self.add('newcomer', 'nina', 0, 21_000, 1)
        self.attack(8, 'a')
        self.assertIn('newcomer', self.block())

    def test_nine_fresh_attackers_per_block_leave_a_new_sender_served(self):
        self.add('newcomer', 'nina', 0, 21_000, 1)
        self.attack(9, 'a')
        self.assertIn('newcomer', self.block())

    def test_twenty_fresh_attackers_at_real_verdict_times_leave_a_new_sender_served(self):
        self.policy.c['preflight_max_seconds'] = 180
        self.verdict_seconds = 37  # 223-evidence: 34.8-40.1 s per over-limit run inside the settler
        self.add('newcomer', 'nina', 0, 21_000, 1)
        self.attack(20, 'b')
        self.assertIn('newcomer', self.block())

    def test_the_tip_still_orders_tier_one_until_a_quarantine(self):
        self.add('low', 'lena', 0, 21_000, 1, tip=GWEI)
        self.add('high', 'hugo', 0, 400_000, 1, tip=50 * GWEI)
        self.policy.state['tip'] = 10**8
        order = self.policy.try_order(self.report(list(self.spool))['tx_stats'], self.now)
        self.assertEqual(self.names(order), ['high', 'low'])


class U3QuarantinedNonceSentAgain(World):
    def test_the_same_nonce_after_the_ban_is_quarantined_at_its_first_failure(self):
        self.add('slow-0', 'mallory', 0, 50_000, 1, fail_first=100)
        for _ in range(3):
            self.now += 1800
            self.block(advance=0)
        self.assertEqual(self.quarantined, ['slow-0'])
        self.now += 86400 + 1
        self.add('slow-1', 'mallory', 0, 50_000, 1, fail_first=100, tip=2 * GWEI)
        self.block()
        self.assertEqual(self.quarantined, ['slow-0', 'slow-1'])


class U4BandDemandFollowsTheNextBlock(World):
    def test_a_band_entry_is_demand_when_the_next_block_has_no_deposit(self):
        self.add('band', 'bob', 0, 2_000_000, 95)
        self.block(deposits=True)
        stats = self.report(self.spool)['tx_stats']
        self.assertFalse(self.policy.demand(stats, self.now, True))
        self.assertTrue(self.policy.demand(stats, self.now, False))


class U5U6F6CongestionTipByTime(World):
    def test_after_a_spike_an_idle_chain_admits_a_floor_tip_transaction_within_three_hours(self):
        self.policy.state['tip'] = GWEI
        self.policy.state['last_block_time'] = self.now
        self.add('floor', 'alice', 0, 21_000, 1, tip=GWEI // 10)
        start = self.now
        while not self.policy.demand(self.report(self.spool)['tx_stats'], self.now, False):
            self.now += 300
            self.assertLess(self.now - start, 3 * 3600, 'still below the required tip after 3 h')
        self.assertIn('floor', self.block())

    def test_slow_blocks_do_not_decay_the_tip_under_five_of_six_saturation(self):
        self.policy.path = None
        for _ in range(100):
            for saturated in (1, 1, 1, 1, 1, 0):
                plan = sp.Plan()
                plan.base = sp.Cost(self.EMPTY_BASE, 0)
                plan.cost = sp.Cost(self.BUDGET if saturated else self.EMPTY_BASE, 0)
                self.policy.committed(plan, {'included': []})
                self.now += 3474  # agent 93's slowest measured proof (2c at height 8191)
        self.assertGreater(self.policy.required_tip(self.now - 3474), 10 * GWEI)

    def test_the_rpc_reads_the_decayed_tip(self):
        self.policy.state['tip'] = 50 * GWEI
        self.policy.state['last_block_time'] = self.now
        self.policy.save(self.now + 4500 + 1200)
        self.assertEqual(json.loads(self.state_path.read_text())['required_tip_wei'], 25 * GWEI)


# Review r7 (agent 121)

class F1OverBudgetWithDepositsIsQuarantined(World):
    def test_measured_over_without_deposits_goes_to_quarantine_even_with_a_deposit(self):
        self.add('evil', 'mallory', 0, 4_000_000, 150, tip=10 * GWEI)  # over alone without any deposit
        self.add('honest', 'alice', 0, 21_000, 1)
        self.policy.state['empty_base'] = self.EMPTY_BASE
        self.assertIn('honest', self.block(deposits=True))
        self.assertEqual(self.quarantined, ['evil'])


class F2F7Robustness(World):
    def test_torn_state_file_costs_the_counts_not_a_block(self):
        self.state_path.write_text('{"tip": 12')
        policy = self.make_policy()
        self.assertEqual(policy.state['tip'], GWEI // 10)
        self.assertTrue(any(event == 'policy-state-unreadable' for event, _ in self.logged))

    def test_start_up_refuses_a_prover_without_cost(self):
        with self.assertRaises(RuntimeError):
            sp.check_cost_line(None)
        sp.check_cost_line(sp.Cost(1, 1))


# The limits themselves

class Limits(World):
    def test_per_transaction_gas_cap_quarantines_without_a_ban(self):
        self.add('huge', 'bob', 0, 6_000_000, 1)
        self.block()
        self.assertEqual(self.quarantined, ['huge'])
        self.assertNotIn('bob', self.policy.state['bans'])

    def test_write_price_and_rates(self):
        price = sp.DEFAULTS['fresh_slot_price_wei']
        self.add('cheap-writer', 'w1', 0, 50_000, 1, tip=GWEI, fresh=[('token', 10)])  # 50k x 1 gwei < 10 x 200 µBLCH
        self.add('paying-writer', 'w2', 0, 50_000, 1, tip=10 * price // 50_000 + 1, fresh=[('token', 10)])
        names = self.block()
        self.assertEqual(names, ['paying-writer'])
        self.assertEqual(self.held(self.plans[-1])['cheap-writer'], 'below-write-price')

    def test_sender_write_window_is_in_seconds(self):
        self.policy.c['fresh_slots_per_block'] = 512
        tip = 300 * sp.DEFAULTS['fresh_slot_price_wei'] // 50_000
        for i in range(3):
            self.add(f'w{i}', 'writer', i, 50_000, 1, tip=tip, fresh=[('token', 100)])
        self.assertEqual(self.block(advance=0), ['w0', 'w1'])
        self.now += 47 * 3600
        self.assertEqual(self.block(advance=0), [])
        self.now += 2 * 3600
        self.assertEqual(self.block(advance=0), ['w2'])

    def test_exempt_sender_is_outside_write_limits_but_inside_the_budget(self):
        self.policy.c['write_limit_exempt_senders'] = ['signer']
        self.add('mint', 'signer', 0, 50_000, 1, tip=GWEI, fresh=[('token', 500)])
        self.add('heavy', 'signer2', 0, 50_000, 1, tip=GWEI, fresh=[('token', 500)])
        self.assertEqual(self.block(), ['mint'])
        self.policy.c['write_limit_exempt_senders'] = ['signer', 'signer3']
        self.add('too-heavy', 'signer3', 0, 50_000, 150)
        self.block()
        self.assertIn('too-heavy', self.quarantined)

    def test_exempt_deployment_above_the_per_transaction_cap_is_measured_not_refused(self):
        self.policy.c['write_limit_exempt_senders'] = ['deployer']
        self.add('router', 'deployer', 0, 7_000_000, 40)
        self.add('other', 'bob', 0, 7_000_000, 40)
        self.assertEqual(self.block(), ['router'])
        self.assertEqual(self.quarantined, ['other'])

    def test_prover_profile_by_preflight_sp1_gas(self):
        policy = sp.Policy()
        self.assertEqual(policy.profile_for(10_150_000), 'fast')  # agent 113 block 10: proved fast at 39.5 GiB
        self.assertEqual(policy.profile_for(65_100_000), 'lowmem-2c')  # 64 swaps: OOM fast at 64 GiB, 2c at 47.2 GiB
        self.assertEqual(policy.profile_for(93_800_000), 'mandatory-heavy')  # above the 90M budget
        self.assertEqual(policy.cycle_limit(), 180_000_000)

    def test_full_block_fits_in_one_measurement(self):
        for i in range(20):
            self.add(f't{i}', f's{i}', 0, 21_000, 1)
        self.assertEqual(len(self.block()), 20)
        self.assertEqual(self.plans[-1].runs, 2)  # base + one full run


if __name__ == '__main__':
    unittest.main()
