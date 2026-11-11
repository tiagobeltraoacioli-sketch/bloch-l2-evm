#!/usr/bin/env python3
"""Round 15 (agents/304 U3, the F264-2 residual): the write price inside the producer's own selection.

The fake producer here does what `bloch-l2-produce-dev --fresh-slot-price-wei` does (integrations/settlement-recovery
tests/produce_txs.rs `write_price_leaves_a_whole_chain_of_non_payers_pending` tests the real one): the first unpaid
transaction in block order leaves, the selection runs again, and what left is reported under `unpaid`.
Run: python3 -B -m unittest -v test_round15_producer_write_price
"""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sequencer_policy_v2 as sp  # noqa: E402
from test_sequencer_policy_v2 import GWEI  # noqa: E402
from test_review_r11_policy_v2 import FLOOR, SlotWorld, sp_hash  # noqa: E402

PRICE = sp.DEFAULTS['fresh_slot_price_wei']


class PricedWorld(SlotWorld):
    def config(self):
        return {**super().config(), 'producer_write_price': True}

    def report(self, raws):
        raws, unpaid = list(raws), []
        while True:
            report = super().report(raws)
            first = next((t for t in report['tx_stats']
                          if (fresh := sum(n for _, n in t['fresh_slots'])) and int(t['gas_used']) * int(t['effective_tip']) < fresh * PRICE), None)
            if first is None:
                report['unpaid'] = unpaid
                return report
            unpaid.append({'hash': first['hash'], 'sender': first['sender'], 'nonce': first['nonce']})
            raws = [raw for raw in raws if sp_hash(raw) != first['hash']]

    def committed_reports(self):
        finals, inner = [], self.policy.committed

        def committed(plan, final_report, now=None):
            finals.append(final_report)
            return inner(plan, final_report, now)
        self.policy.committed = committed
        return finals

    def unpaid_slots(self, report):
        return [(t['sender'], fresh) for t in report['tx_stats']
                if (fresh := sum(n for _, n in t['fresh_slots'])) and int(t['gas_used']) * int(t['effective_tip']) < fresh * PRICE]


class ProducerWritePrice(PricedWorld):
    def test_a_chain_far_longer_than_the_gate_passes_leaves_in_one_selection_and_users_are_served(self):
        for i in range(30):   # thirty senders write one slot, each below the price of one new slot
            self.add_writer(f'chain{i}', f'c{i}', 0, 50_000, 1, ['s0'], tip=(39 - i) * GWEI // 10)
        for i in range(20):
            self.add(f'h{i}', f'user{i}', 0, 21_000, 1, tip=GWEI)
        finals = self.committed_reports()
        served = self.block()
        self.assertEqual(sorted(n for n in served if n.startswith('h')), sorted(f'h{i}' for i in range(20)))
        self.assertEqual([n for n in served if n.startswith('chain')], [])
        self.assertEqual(self.unpaid_slots(finals[-1]), [])
        held = dict(self.plans[-1].held)
        self.assertEqual(sum(reason == 'below-write-price' for reason in held.values()), 30)
        events = [event for event, _ in self.logged]
        self.assertNotIn('gate-did-not-settle', events)
        self.assertNotIn('final-gate-unsettled', events)
        # The non-payers wait by sender, nonce and hash: the next block gates them out before the selection.
        self.assertEqual(sum(w['kind'] == 'gate-dependent' for w in self.policy.state['waits'].values()), 30)

    def test_the_f264_2_chains_buy_no_unpaid_slot_and_stay_under_the_block_limit(self):
        for tag, top in (('a', 39), ('b', 29)):
            slots = [f'{tag}{i}' for i in range(100)]
            for i in range(6):
                self.add_writer(f'chain{tag}{i}', f'c{tag}{i}', 0, 50_000, 1, slots, tip=(top - i) * GWEI // 10)
            self.add_writer(f'free{tag}', f'f{tag}', 0, 50_000, 1, slots, tip=FLOOR)
        finals = self.committed_reports()
        self.block()
        self.assertEqual(self.unpaid_slots(finals[-1]), [])
        self.assertLessEqual(sum(n for t in finals[-1]['tx_stats'] for _, n in t['fresh_slots']), sp.DEFAULTS['fresh_slots_per_block'])

    def test_a_payer_behind_non_payers_is_served_in_the_same_block(self):
        self.add_writer('unpaid', 'trent', 0, 50_000, 1, ['t0', 't1', 't2'], tip=5 * GWEI)  # 2.5e14 for three slots: no
        self.add_writer('payer', 'alice', 0, 50_000, 1, ['t0'], tip=4 * GWEI + GWEI // 10)  # 2.05e14 for one slot: pays
        finals = self.committed_reports()
        served = self.block()
        self.assertIn('payer', served)
        self.assertNotIn('unpaid', served)
        self.assertEqual(self.unpaid_slots(finals[-1]), [])


class UnpaidWaitsEscalate(PricedWorld):
    """Review R308-2P-13 / R308-2P-14: a first unpaid report waits five minutes, each further report of the same
    bytes twice as long up to the hour; a waiting non-payer is not handed to the producer; a replacement starts again."""

    def given(self):
        seen = []
        inner = self.report

        def report(raws):
            seen.append({self.tx[r]['name'] for r in raws})
            return inner(raws)
        self.report = report
        return seen

    def test_waits_double_and_keep_the_non_payer_out_of_the_producer(self):
        self.add_writer('np', 'mallory', 0, 50_000, 1, ['own'], tip=GWEI)
        waits = []
        for _ in range(6):
            seen = self.given()
            self.block(advance=0)
            wait = self.policy.state['waits'].get('mallory:0')
            waits.append(round(wait['until'] - self.now))
            self.assertTrue(any('np' in names for names in seen), 'a non-payer whose wait ended is tried again')
            self.now += waits[-1] - 1          # one second before the wait ends: not handed over
            seen = self.given()
            self.block(advance=2)              # and then past it
            self.assertFalse(any('np' in names for names in seen), f'handed to the producer inside its wait {waits}')
            self.assertEqual(dict(self.plans[-1].held).get(next(iter(dict(self.plans[-1].held)))), 'gate-dependent-wait')
        # measured from the end of the plan, which takes a few seconds of the world's clock
        self.assertTrue(all(0 <= want - got <= 30 for want, got in zip([300, 600, 1200, 2400, 3600, 3600], waits)), waits)

    def test_the_producers_pass_cap_holds_the_rest_without_a_wait(self):
        self.add('behind', 'user', 0, 21_000, 1, tip=GWEI)
        inner = self.report

        def capped(raws):
            report = inner(raws)
            if any(self.tx[r]['name'] == 'behind' for r in raws):
                report['included'] = [n for n in report['included'] if self.tx_name(n) != 'behind']
                report['tx_stats'] = [t for t in report['tx_stats'] if self.tx_name(t['hash']) != 'behind']
                report['not_judged'] = [sp_hash(r) for r in raws if self.tx[r]['name'] == 'behind']
            return report
        self.report = capped
        self.block(advance=0)
        self.assertIn('behind-unpaid-pass-cap', dict(self.plans[-1].held).values())
        self.assertEqual(self.policy.state['waits'], {})

    def tx_name(self, name):
        return next(t['name'] for r, t in self.tx.items() if sp_hash(r) == name)


if __name__ == '__main__':
    unittest.main()
