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
        self.assertEqual(sum(w['kind'] == 'unpaid-sender' for w in self.policy.state['waits'].values()), 30)

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
    """Review R308-3P-2 (coordinator decision): the SENDER of an unpaid transaction waits 40 minutes, longer than a
    block interval, and twice as long after each further report, up to a day; while it waits its bytes are not
    handed to the producer. The wait follows the sender: a replacement or another nonce does not start again."""

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
            self.assertEqual(dict(self.plans[-1].held).get(next(iter(dict(self.plans[-1].held)))), 'unpaid-sender-wait')
        # measured from the end of the plan, which takes a few seconds of the world's clock
        self.assertTrue(all(0 <= want - got <= 30 for want, got in zip([2400, 4800, 9600, 19200, 38400, 76800], waits)), waits)

    def test_a_replacement_or_a_later_nonce_does_not_reset_the_senders_wait(self):
        self.add_writer('np', 'mallory', 0, 50_000, 1, ['own'], tip=GWEI)
        self.block(advance=0)
        first = self.policy.state['unpaid_senders']['mallory']
        self.assertEqual(first['count'], 1)
        self.assertEqual(self.policy.waiting_senders(self.now), {'mallory'})
        self.now += 2500   # past the first wait: the sender tries other bytes
        self.spool.clear()
        self.add_writer('np2', 'mallory', 0, 50_000, 1, ['own2'], tip=2 * GWEI)
        self.block(advance=0)
        second = self.policy.state['unpaid_senders']['mallory']
        self.assertEqual(second['count'], 2)
        self.assertGreaterEqual(second['until'] - second['at'], 4800)

    def test_the_producers_allowance_holds_the_rest_without_a_wait(self):
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
        self.assertIn('unpaid-allowance-exhausted', dict(self.plans[-1].held).values())
        self.assertEqual(self.policy.state['waits'], {})

    def tx_name(self, name):
        return next(t['name'] for r, t in self.tx.items() if sp_hash(r) == name)


class CreditAndOwnDoing(PricedWorld):
    """Review R308-4P-1 and R308-4P-2 (agents/311 section 14). Credit is what a sender really paid in priority fees
    less the fee value of its work the producer executed and left out. A transaction the producer reports as made
    unpaid by an earlier transaction of the block (`own_doing: false`) is held without any wait."""

    def reporting(self, **fields):
        inner = self.report

        def report(raws):
            answer = inner(raws)
            for tx in answer['unpaid']:
                tx.update(fields)
            return answer
        self.report = report

    def test_credit_is_the_fees_paid_and_is_spent_by_wasted_work(self):
        self.add('pay', 'alice', 0, 21_000, 1, tip=GWEI)
        self.block(advance=0)
        self.assertEqual(self.policy.credits(self.now), {'alice': 21_000 * GWEI})
        self.spool.clear()
        self.add_writer('np', 'alice', 1, 50_000, 1, ['own'], tip=GWEI)
        self.reporting(gas_used=15_000, effective_tip=GWEI, own_doing=True)
        self.block(advance=0)
        self.assertEqual(self.policy.credits(self.now), {'alice': 6_000 * GWEI}, 'one debit per plan, whatever the passes')
        self.assertEqual(self.policy.waiting_senders(self.now), {'alice'})
        self.now += sp.DEFAULTS['credit_memory_seconds'] + 1
        self.assertEqual(self.policy.credits(self.now), {})

    def test_a_transaction_made_unpaid_by_another_one_does_not_wait_until_the_third_time(self):
        self.reporting(gas_used=30_000, effective_tip=GWEI, own_doing=False)
        for round_number in (1, 2):
            self.spool.clear()
            self.add_writer(f'v{round_number}', 'victim', 0, 50_000, 1, ['shared'], tip=GWEI)
            self.block(advance=0)
            self.assertIn('unpaid-in-this-block', dict(self.plans[-1].held).values())
            self.assertEqual(self.policy.waiting_senders(self.now), set())
            self.assertEqual(self.policy.state['waits'], {})
            self.now += 60
        self.spool.clear()
        self.add_writer('v3', 'victim', 0, 50_000, 1, ['shared'], tip=GWEI)
        self.block(advance=0)
        self.assertEqual(self.policy.waiting_senders(self.now), {'victim'}, 'the third report in the window is its own doing')

    def test_the_ledgers_survive_a_restart(self):
        self.add('pay', 'alice', 0, 21_000, 1, tip=GWEI)
        self.add_writer('np', 'mallory', 0, 50_000, 1, ['own'], tip=GWEI)
        self.block(advance=0)
        again = sp.Policy(self.policy.c, self.policy.path, clock=lambda: self.now)
        self.assertEqual(again.credits(self.now), self.policy.credits(self.now))
        self.assertEqual(again.waiting_senders(self.now), {'mallory'})


class SettlerHandsTheLedgerToTheProducer(unittest.TestCase):
    """The settler passes the policy's credit ledger, its waiting senders and its gas cap to the producer."""

    def test_pool_arguments_carry_credits_waiting_and_the_gas_cap(self):
        import json
        import tempfile
        import settler_v3 as settler
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            worker = object.__new__(settler.Settler)
            worker.work, worker.policy_clock = work, lambda: 1_000_000
            worker.c = {'user_transactions': True, 'max_block_sp1_gas': 90_000_000, 'producer_write_price': True,
                        'max_block_gas': 15_000_000, 'max_block_bytes': 100_000, 'max_block_txs': 64, 'max_tx_gas': 5_000_000}
            policy = worker.policy()
            policy.state['credit'] = {'aa' * 20: {'wei': 42, 'at': 999_999}, 'bb' * 20: {'wei': 7, 'at': 1}}
            policy.state['unpaid_senders'] = {'cc' * 20: {'count': 1, 'at': 999_000, 'until': 1_001_000}}
            policy.save(1_000_000)
            pool = work / 'pool'
            pool.mkdir()
            args = worker.pool_arguments(pool)
            self.assertNotIn('--write-standing', args)
            self.assertEqual(args[args.index('--write-max-tx-gas') + 1], '5000000')
            self.assertEqual(json.loads(Path(args[args.index('--write-credits') + 1]).read_text()), {'aa' * 20: '42'},
                             'credit older than the memory window is not handed over')
            self.assertEqual(json.loads(Path(args[args.index('--write-waiting') + 1]).read_text()), ['cc' * 20])


class ProducerTimeoutIsARefusal(unittest.TestCase):
    """Review R308-2P-13: a producer that does not answer is a ProducerError, which `extend` answers with the
    deposits-only block; it stays distinguishable (ProducerTimeout) for the kept-database scan of R308-22."""

    def test_a_timeout_of_the_producer_raises_the_refusal_class(self):
        import subprocess
        import settler_v3 as settler

        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))
        worker = object.__new__(settler.Settler)
        worker.c, worker.run, worker.network_args = {'produce': '/nonexistent/produce'}, run, []
        with self.assertRaises(settler.ProducerError) as caught:
            worker.produce('select', '--target', 'x')
        self.assertIsInstance(caught.exception, settler.ProducerTimeout)
        self.assertIn('timed out after 300 s for select', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
