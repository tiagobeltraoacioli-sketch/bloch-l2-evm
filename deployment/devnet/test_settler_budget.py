#!/usr/bin/env python3
"""Tests of the block budget (`max_block_sp1_gas`) through the settler: the selection logic with a fake measurement."""
from pathlib import Path
import sys
import json
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402


class Budget(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.pool = root / 'txpool'
        self.pool.mkdir()
        self.dir = root / 'work'
        self.dir.mkdir()
        self.deposits = self.dir / 'deposits.json'
        self.deposits.write_text('[]')
        self.settler = s.Settler.__new__(s.Settler)
        self.settler.c = {'txpool_dir': str(self.pool), 'max_block_sp1_gas': 100, 'max_block_gas': 1, 'max_block_bytes': 1, 'max_block_txs': 9,
                          'l2_db': 'x', 'timestamp_rule': None, 'user_transactions': True}
        self.settler.work = root
        self.settler.clock = lambda: 0
        self.settler.preflight_source = 'request'
        self.cost = {}
        self.deposit_cost = 10
        self.committed = None
        self.measures = []

        def report(raws):
            return {'included': [s.keccak256(bytes.fromhex(r)).hex() for r in raws], 'transactions': len(raws), 'dropped': [],
                    'tx_stats': [{'hash': s.keccak256(bytes.fromhex(r)).hex(), 'sender': r, 'gas_used': 21000, 'effective_tip': '1'} for r in raws]}

        def produce(*args):
            pool = args[args.index('--txs') + 1] if '--txs' in args else None
            raws = json.loads(Path(pool).read_text()) if pool else []
            if args[0] == 'select':
                return report(raws)
            self.committed = raws
            return report(raws)
        self.settler.produce = produce

        def measure(parent, anchor, deposits, slot, number, raws, tag):
            self.measures.append(tag)
            total = self.deposit_cost + sum(self.cost[r] for r in raws)
            return (None if total > 10_000 else s.sequencer_policy.Cost(total, total)), report(raws)
        self.settler.measure_block = measure

    def spool(self, **costs):
        for name, cost in costs.items():
            raw = name.encode().hex()
            self.cost[raw] = cost
            (self.pool / f'{name}.tx').write_text(raw + '\n')

    def run_it(self):
        return self.settler.extend_within_budget('p', 'a', self.deposits, 1, 2)

    def names(self):
        return sorted(p.stem for p in self.pool.glob('*.tx'))

    def quarantine(self):
        q = self.pool.with_name('txpool-quarantine')
        return sorted(p.stem for p in q.glob('*.tx')) if q.exists() else []

    def test_block_within_budget_commits_everything(self):
        self.spool(a=10, b=10)
        self.run_it()
        self.assertEqual(len(self.committed), 2)
        self.assertEqual(self.names(), [])
        self.assertEqual(len(self.measures), 2)  # deposit-only, then the block

    def test_heavy_transaction_is_quarantined_and_the_rest_settles(self):
        self.spool(a=10, b=10_000_000, c=10)
        self.run_it()
        self.assertEqual(self.committed, ['a'.encode().hex(), 'c'.encode().hex()])  # the same block
        self.assertEqual(self.quarantine(), ['b'])
        self.assertEqual(self.names(), [])

    def test_second_block_clears_what_was_held_back(self):
        self.spool(a=45, b=45, c=45)
        self.run_it()
        self.run_it()
        self.assertEqual(self.committed, ['c'.encode().hex()])
        self.assertEqual(self.names(), [])

    def test_block_full_of_fitting_transactions_defers_without_quarantine(self):
        self.spool(a=40, b=40, c=40, d=40)
        self.run_it()
        self.assertEqual(len(self.committed), 2)
        self.assertEqual(self.quarantine(), [])
        self.assertEqual(self.names(), ['c', 'd'])

    def test_empty_spool_makes_a_block_without_measuring(self):
        self.run_it()
        self.assertEqual(self.committed, [])
        self.assertEqual(self.measures, [])

    def test_several_heavy_transactions_do_not_empty_several_blocks(self):
        self.spool(a=10_000_000, b=10_000_000, c=10, d=10_000_000, e=10)
        self.run_it()
        self.assertEqual(sorted(self.committed), sorted(['c'.encode().hex(), 'e'.encode().hex()]))
        self.assertEqual(self.quarantine(), ['a', 'b', 'd'])

    def test_measuring_is_bounded_and_the_rest_waits(self):
        self.settler.c['preflight_max_runs'] = 5
        self.spool(a=10_000_000, b=10_000_000, c=10_000_000, d=10_000_000, e=10_000_000, f=10)
        self.run_it()
        self.assertLessEqual(len(self.measures), 5)
        self.assertEqual(self.committed, [])
        self.assertIn('f', self.names())

    def test_deposits_over_budget_still_commit_alone_and_no_transaction_rides_along(self):
        self.deposit_cost = 500
        self.deposits.write_text('[{"sats": 1}]')
        self.spool(a=10)
        self.run_it()
        self.assertEqual(self.committed, [])
        self.assertEqual(self.names(), ['a'])
        self.assertEqual(self.quarantine(), [])
        written = json.loads((self.dir / 'deposits-over-budget.json').read_text())
        self.assertEqual(written['sp1_gas'], 500)

    def test_deposits_are_measured_with_an_empty_spool(self):
        self.deposits.write_text('[{"sats": 1}]')
        self.run_it()
        self.assertEqual(self.measures, [0])

    def test_deposits_count_against_the_budget_of_user_transactions(self):
        self.deposit_cost = 80
        self.deposits.write_text('[{"sats": 1}]')
        self.spool(a=10, b=30)
        self.run_it()
        self.assertEqual(self.committed, ['a'.encode().hex()])
        self.assertEqual(self.names(), ['b'])

    def test_deposits_cannot_get_a_transaction_quarantined(self):
        self.deposit_cost = 95
        self.deposits.write_text('[{"sats": 1}]')
        self.spool(a=10, b=1)
        self.run_it()
        self.assertEqual(self.committed, ['b'.encode().hex()])
        self.assertEqual(self.quarantine(), [])
        self.assertEqual(self.names(), ['a'])

    def test_only_a_heavy_transaction_leaves_a_deposit_only_block(self):
        self.spool(evil=10_000_000)
        self.run_it()
        self.assertEqual(self.committed, [])
        self.assertEqual(self.quarantine(), ['evil'])


if __name__ == '__main__':
    unittest.main()
