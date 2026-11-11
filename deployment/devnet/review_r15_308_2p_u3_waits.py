#!/usr/bin/env python3
"""Second-pass review, U3 (producer write price). Imports the worktree's policy and test worlds by path."""
import sys
import unittest

sys.dont_write_bytecode = True
WT = str(__import__('pathlib').Path(__file__).resolve().parent)
sys.path.insert(0, WT)
import sequencer_policy_v2 as sp  # noqa: E402
from test_sequencer_policy_v2 import GWEI  # noqa: E402
from test_review_r11_policy_v2 import SlotWorld, sp_hash  # noqa: E402
from test_round15_producer_write_price import PricedWorld, PRICE  # noqa: E402


class Counting(PricedWorld):
    """PricedWorld that records, per producer call, the candidates it was given and the inner selection passes."""
    def setUp(self):
        super().setUp()
        self.calls = []

    def report(self, raws):
        raws, unpaid, passes = list(raws), [], 0
        given = len(raws)
        while True:
            passes += 1
            report = SlotWorld.report(self, raws)
            first = next((t for t in report['tx_stats']
                          if (fresh := sum(n for _, n in t['fresh_slots'])) and int(t['gas_used']) * int(t['effective_tip']) < fresh * PRICE), None)
            if first is None:
                report['unpaid'] = unpaid
                self.calls.append((given, passes))
                return report
            unpaid.append({'hash': first['hash'], 'sender': first['sender'], 'nonce': first['nonce']})
            raws = [raw for raw in raws if sp_hash(raw) != first['hash']]


class WaitsDoNotShieldTheProducer(Counting):
    def test_waiting_non_payers_are_handed_to_the_producer_again_every_block(self):
        for i in range(30):  # each writes a slot of its own: unpaid whoever runs first
            self.add_writer(f'np{i}', f'c{i}', 0, 50_000, 1, [f'own{i}'], tip=(39 - i) * GWEI // 10)
        self.add('h0', 'user0', 0, 21_000, 1, tip=GWEI)
        self.block(advance=120)   # round-15 fix: the next block comes inside the first wait (300 s)
        self.assertEqual(sum(w['kind'] == 'gate-dependent' for w in self.policy.state['waits'].values()), 30)
        first_block = list(self.calls)
        self.calls.clear()
        self.add('h1', 'user1', 0, 21_000, 1, tip=GWEI)
        self.block()
        print('\nblock 1 producer calls (candidates, selection passes):', first_block)
        print('block 2 producer calls (candidates, selection passes):', self.calls)
        # The docstring of the round-15 test says "the next block gates them out before the selection".
        self.assertLessEqual(max(passes for _, passes in self.calls), 2,
                             'the 30 waiting non-payers were given to the producer again and cost one pass each')


class APayerWaitsAnHour(PricedWorld):
    PRODUCER = True

    def config(self):
        return {**super().config(), 'producer_write_price': self.PRODUCER}

    def report(self, raws):
        return super().report(raws) if self.PRODUCER else SlotWorld.report(self, raws)

    def test_a_transaction_unpaid_in_one_block_is_served_in_the_next_when_it_no_longer_adds_a_slot(self):
        # x writes slot s at 1 gwei x 50k gas = 5e13 < 2e14: unpaid while s is new.
        self.add_writer('x', 'xavier', 0, 50_000, 1, ['s'], tip=GWEI)
        self.assertNotIn('x', self.block(advance=600))
        # Ten minutes later someone else creates s in the same block, ahead of x, and pays for it (5 gwei x 50k = 2.5e14):
        # x then adds no slot and owes nothing.
        self.add_writer('y', 'yara', 0, 50_000, 1, ['s'], tip=5 * GWEI)
        served = self.block(advance=600)
        print('\nproducer_write_price', self.PRODUCER, 'block 2 served', served, 'held', self.held(),
              'x waits', {k: (w['kind'], w['until'] - self.now) for k, w in self.policy.state['waits'].items()})
        self.assertIn('y', served)
        self.assertIn('x', served, f'held: {self.held()}')
        blocks = 2
        while 'x' not in served and blocks < 12:
            served, blocks = self.block(advance=600), blocks + 1
        print('x served in block', blocks)


class APayerWaitsAnHourWithoutProducerPrice(APayerWaitsAnHour):
    PRODUCER = False


if __name__ == '__main__':
    unittest.main()
