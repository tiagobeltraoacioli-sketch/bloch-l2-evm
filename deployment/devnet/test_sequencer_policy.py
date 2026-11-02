#!/usr/bin/env python3
"""Tests of the write limits and the required tip in `sequencer_policy.py`."""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sequencer_policy as p  # noqa: E402


def tx(name, sender='s', gas=100_000, tip=1, fresh=None, cleared=None):
    return {'hash': name, 'sender': sender, 'gas_used': gas, 'effective_tip': str(tip),
            'fresh_slots': fresh or [], 'cleared_slots': cleared or []}


def planner(**config):
    return p.Planner({'max_block_sp1_gas': 100, **config})


class Gate(unittest.TestCase):
    def test_no_limits_pass_everything(self):
        passing, refused = planner().gate([tx('a', fresh=[['c', 900]])], 1)
        self.assertEqual((passing, refused), (['a'], {}))

    def test_write_price_is_against_the_tips_paid(self):
        stats = [tx('cheap', gas=23_000, tip=10, fresh=[['c', 1]]), tx('paid', gas=23_000, tip=100, fresh=[['c', 1]]), tx('none', gas=23_000, tip=0)]
        passing, refused = planner(fresh_slot_price_wei=2_000_000).gate(stats, 1)
        self.assertEqual(passing, ['paid', 'none'])
        self.assertEqual(refused['cheap'], ('below-write-price', False))

    def test_block_write_limit_holds_the_excess_and_quarantines_the_impossible(self):
        stats = [tx('a', 'x', fresh=[['c', 60]]), tx('b', 'y', fresh=[['c', 60]]), tx('c', 'z', fresh=[['c', 40]]), tx('d', 'w', fresh=[['c', 101]])]
        passing, refused = planner(fresh_slots_per_block=100).gate(stats, 1)
        self.assertEqual(passing, ['a', 'c'])
        self.assertEqual(refused['b'], ('block-write-limit', False))
        self.assertEqual(refused['d'], ('larger-than-block-write-limit', True))

    def test_sender_window_counts_earlier_blocks_and_expires(self):
        q = planner(fresh_slots_per_sender=10, fresh_sender_window_blocks=5)
        q.state['senders']['s'] = [[3, 8]]
        self.assertEqual(q.gate([tx('a', fresh=[['c', 5]])], 7)[1]['a'], ('sender-write-limit', False))
        self.assertEqual(q.gate([tx('a', fresh=[['c', 5]])], 8)[0], ['a'])

    def test_account_cap_lets_existing_slots_be_used(self):
        q = planner(max_account_slots=10)
        q.state['account_slots']['c'] = 10
        passing, refused = q.gate([tx('new', fresh=[['c', 1]]), tx('old', gas=50_000)], 1)
        self.assertEqual(passing, ['old'])
        self.assertEqual(refused['new'], ('account-slot-cap', False))

    def test_deposit_exposure_sums_the_64_largest(self):
        q = planner(max_deposit_exposure_slots=640)
        for i in range(64):
            q.state['account_slots'][f'c{i}'] = 10
        q.state['account_slots']['small'] = 1
        passing, refused = q.gate([tx('grow', fresh=[['c0', 1]])], 1)
        self.assertEqual(refused['grow'], ('deposit-exposure', False))
        self.assertEqual(passing, [])

    def test_cooldown(self):
        q = planner()
        q.state['strikes']['s'] = 9
        self.assertEqual(q.gate([tx('a')], 8)[1]['a'], ('sender-cooldown', False))
        self.assertEqual(q.gate([tx('a')], 9)[0], ['a'])

    def test_tx_gas_cap_is_permanent(self):
        self.assertEqual(planner(max_tx_gas=10).gate([tx('a', gas=11)], 1)[1]['a'], ('tx-gas-cap', True))


class Congestion(unittest.TestCase):
    def step(self, q, used, fresh=0, number=1):
        plan = p.Plan()
        plan.base, plan.cost = p.Cost(0), p.Cost(used)
        plan.chosen_stats = [tx('a', fresh=[['c', fresh]])] if fresh else []
        q.committed(plan, number)

    def test_full_blocks_raise_the_tip_and_idle_blocks_lower_it_to_the_floor(self):
        q = planner(min_tip_wei=1_000, congestion_denominator=8)
        self.step(q, 100)
        self.assertEqual(q.required_tip(), 1_125)
        for _ in range(39):
            self.step(q, 100)
        self.assertGreater(q.required_tip(), 100_000)
        for _ in range(100):
            self.step(q, 0)
        self.assertEqual(q.required_tip(), 1_000)

    def test_target_use_keeps_the_tip(self):
        q = planner(min_tip_wei=1_000, congestion_denominator=8)
        self.step(q, 50)
        self.assertEqual(q.required_tip(), 1_000)

    def test_writes_raise_the_tip_when_proving_cost_does_not(self):
        q = planner(min_tip_wei=1_000, congestion_denominator=8, fresh_slots_per_block=10)
        self.step(q, 1, fresh=10)
        self.assertEqual(q.required_tip(), 1_125)

    def test_cap(self):
        q = planner(min_tip_wei=1_000, congestion_denominator=1, congestion_max_tip_wei=1_500)
        self.step(q, 100)
        self.assertEqual(q.required_tip(), 1_500)

    def test_account_slots_follow_writes_and_clears(self):
        q = planner()
        plan = p.Plan()
        plan.chosen_stats = [tx('a', fresh=[['c', 5]]), tx('b', cleared=[['c', 2]])]
        q.committed(plan, 1)
        self.assertEqual(q.state['account_slots']['c'], 3)


class State(unittest.TestCase):
    def test_a_lost_state_file_is_only_a_lost_limit(self):
        q = planner()
        self.assertEqual(q.required_tip(), 0)
        q.save()  # no path: no file, no failure


if __name__ == '__main__':
    unittest.main()
