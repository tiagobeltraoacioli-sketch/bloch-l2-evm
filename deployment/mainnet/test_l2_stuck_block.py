#!/usr/bin/env python3
"""Tests of the refusals and file handling of the stuck-block tool. The whole path runs in heavy/stuck_drill.py."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import l2_stuck_block as t  # noqa: E402


def batch(*txs):
    return len(txs).to_bytes(4, 'big') + b''.join(len(x).to_bytes(4, 'big') + x for x in txs)


CLEAN = {'number': 5, 'da_recorded_on_l1': [], 'settlement_submitted': False, 'proved': False, 'da_prepared': []}


class Refusals(unittest.TestCase):
    def test_clean_block_may_be_replaced(self):
        t.check_replaceable(CLEAN)

    def test_a_block_l1_may_have_seen_is_never_replaced(self):
        for change in ({'da_recorded_on_l1': [{'l2_number': 5}]}, {'settlement_submitted': True}, {'proved': True},
                       {'da_prepared': ['da-unsigned-0.hex']}):
            with self.assertRaises(t.Refuse):
                t.check_replaceable({**CLEAN, **change})

    def test_malformed_batch_is_refused(self):
        for bad in (b'', batch(b'a') + b'x', (2).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + b'a'):
            with self.assertRaises(t.Refuse):
                t.batch_transactions(bad)

    def test_batch_transactions_returns_each_raw_transaction(self):
        self.assertEqual(t.batch_transactions(batch(b'\x02abc', b'\x02de')), [b'\x02abc', b'\x02de'])


class Discard(unittest.TestCase):
    """discard() against a fake block: the swap, the spool and the quarantine."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.pool, self.db, self.work = root / 'txpool', root / 'canonical', root / 'work'
        self.pool.mkdir()
        self.db.mkdir()
        (self.db / 'old').write_text('old')
        self.directory = self.work / '00000005-abcd'
        self.directory.mkdir(parents=True)
        self.raws = [b'\x02good', b'\x02evil']
        self.names = [t.S.keccak256(r).hex() for r in self.raws]
        self.rebuilt = root / 'canonical.rebuilt-1'
        test = self

        class Fake:
            config = {'txpool_dir': str(self.pool), 'workdir': str(self.work)}
            db = self.db
            directory = self.directory
            number, accepted_hash = 5, 'aa'
            head = {'hash': 'bb'}

            def facts(self):
                return CLEAN

            def raws(self):
                return test.raws

            def rebuild(self, state, status):
                test.rebuilt.mkdir()
                (test.rebuilt / 'new').write_text('new')
                return test.rebuilt
        self.stuck = Fake()

    def test_plan_changes_nothing(self):
        report = t.discard(self.stuck, [self.names[1]], False, 'f', 's', apply=False)
        self.assertEqual(report['quarantine'], [self.names[1]])
        self.assertTrue((self.db / 'old').exists())
        self.assertFalse(self.rebuilt.exists())
        self.assertEqual(list(self.pool.iterdir()), [])

    def test_apply_swaps_and_quarantines(self):
        report = t.discard(self.stuck, [self.names[1]], False, 'f', 's', apply=True)
        self.assertTrue((self.db / 'new').exists())
        self.assertTrue((Path(report['old_database']) / 'old').exists())
        self.assertEqual((self.pool / f'{self.names[0]}.tx').read_text().strip(), self.raws[0].hex())
        self.assertFalse((self.pool / f'{self.names[1]}.tx').exists())
        self.assertTrue((Path(report['quarantine_dir']) / f'{self.names[1]}.tx').exists())
        self.assertFalse(self.directory.exists())
        self.assertTrue((Path(report['old_work']) / self.directory.name).exists())

    def test_must_name_a_transaction_of_this_block(self):
        with self.assertRaises(t.Refuse):
            t.discard(self.stuck, [], False, 'f', 's', apply=True)
        with self.assertRaises(t.Refuse):
            t.discard(self.stuck, ['00' * 32], False, 'f', 's', apply=True)

    def test_deposit_only_block_cannot_be_replaced(self):
        self.raws = []
        with self.assertRaises(t.Refuse):
            t.discard(self.stuck, [], True, 'f', 's', apply=True)


class Files(unittest.TestCase):
    def test_import_refuses_a_second_proof(self):
        class Fake:
            directory = Path('/nonexistent')

            def facts(self):
                return {**CLEAN, 'proved': True}
        with self.assertRaises(t.Refuse):
            t.import_proof(Fake(), 'x')

    def test_import_keeps_nothing_of_a_bad_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'p').write_text('bad')

            class Fake:
                directory = d
                head = {'hash': 'bb'}
                number = 5
                settler = types.SimpleNamespace(c={'home': tmp, 'prover': 'x', 'guest': 'g'}, prover_args=[],
                                                run=lambda *a, **k: types.SimpleNamespace(returncode=1))

                def facts(self):
                    return CLEAN
            with self.assertRaises(t.Refuse):
                t.import_proof(Fake(), d / 'p')
            self.assertFalse((d / 'settlement.proof').exists())
            self.assertFalse((d / 'proved.json').exists())


if __name__ == '__main__':
    unittest.main()
