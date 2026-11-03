#!/usr/bin/env python3
"""Review r10 (agent 152) of l2_reorg_recover.py 2a0cfabd: tests for the findings in agents/152-settler-review.md.

Every test here FAILS on 4b7f4f7 and passes once its finding is fixed. No network, no producer, no prover.
Run: python3 -m unittest discover -s deployment/mainnet -p 'test_l2_reorg_recover_review_r10.py' -v
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import l2_reorg_recover as r  # noqa: E402
from test_l2_reorg_recover import FakeSettler, batch  # noqa: E402

ACCEPTED = '33' * 32


def accepted_view(number=3):
    statement = bytearray(r.S.VALUES_BYTES)
    statement[:r.S.T] = r.S.TAG
    statement[r.S.T + 264:r.S.T + 272] = number.to_bytes(8, 'big')
    statement[r.S.T + 336:r.S.T + 368] = bytes.fromhex(ACCEPTED)
    return {'accepted': {'statement': bytes(statement).hex(), 'commitment': '99' * 32}, 'data_availability': []}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('db', 'work', 'pool', 'follower'):
            (self.root / name).mkdir()
        self.config = {'l2_db': str(self.root / 'db'), 'workdir': str(self.root / 'work'),
                       'txpool_dir': str(self.root / 'pool'), 'user_transactions': True}
        self.status = {'finalized_settlements': [{'l2_number': 3, 'l2_hash': ACCEPTED}]}


class OrphansAtOrBelowTheAcceptedNumber(Base):
    """Finding L2: the tool re-spools only work directories ABOVE the accepted number. When L1 replaced the settlement
    at that number (database "forked"), or the local chain left the accepted one below its head ("ahead" after a
    deeper reorg), the local block at the accepted number is orphaned too, and its user transactions are dropped."""

    def plan(self, head, local_hashes):
        settler = FakeSettler(self.root, accepted_view(3), head, ACCEPTED)
        settler.local_hash = lambda number: local_hashes.get(number, 'aa' * 32)
        with mock.patch.object(r.S, 'Settler', lambda config: settler):
            return r.plan(self.config, self.root / 'follower', True, status=self.status)

    def test_finding_forked_database_respools_the_orphaned_block_at_the_accepted_number(self):
        old = self.root / 'work/00000003-0123456789abcdef'
        old.mkdir()
        (old / 'da-payload.hex').write_text(batch(b'\x02orphaned-at-3').hex() + '\n')
        report = self.plan(head=3, local_hashes={3: 'aa' * 32})
        self.assertEqual(report['database'], 'forked')
        self.assertEqual(report['respooled'], 1, 'the user transaction of the replaced local block 3 is dropped')

    def test_finding_ahead_database_respools_every_block_off_the_accepted_chain(self):
        for number, tx in ((3, b'\x02orphaned-at-3'), (4, b'\x02orphaned-at-4')):
            d = self.root / f'work/0000000{number}-0123456789abcdef'
            d.mkdir()
            (d / 'da-payload.hex').write_text(batch(tx).hex() + '\n')
        report = self.plan(head=4, local_hashes={3: 'aa' * 32})
        self.assertEqual(report['database'], 'ahead')
        self.assertEqual(report['respooled'], 2, 'local block 3 is not on the accepted chain, yet only block 4 is respooled')


class ReconstructTimeout(Base):
    """Finding L3: the tool runs `produce reconstruct` through Settler.produce, whose timeout is 300 s for every
    producer command. The worker's own rebuild (foreign_recovery) allows `rebuild_timeout_seconds`, default 3,600 s.
    A rebuild replays every L2 block, so once the chain is long enough the operator's repair tool always times out
    (and the TimeoutExpired escapes as a traceback, leaving the partial `.rebuilt-*` directory)."""

    def test_finding_reconstruct_gets_the_rebuild_timeout_not_the_300s_producer_timeout(self):
        timeouts = {}

        def run(argv, **kwargs):
            timeouts[argv[1]] = kwargs.get('timeout')
            if argv[1] == 'head':
                return subprocess.CompletedProcess(argv, 0, json.dumps({'number': 4, 'hash': 'aa' * 32}), '')
            if argv[1] == 'reconstruct':
                Path(argv[argv.index('--target') + 1]).mkdir()
                return subprocess.CompletedProcess(argv, 0, json.dumps({'head': ACCEPTED, 'settled': 3}), '')
            raise AssertionError(argv)
        settler = r.S.Settler.__new__(r.S.Settler)
        settler.c, settler.network_args, settler.run = {'produce': 'produce'}, [], run
        settler.check_identity = lambda: True
        settler.native_view = lambda: accepted_view(3)
        settler.local_hash = lambda number: 'aa' * 32
        r.plan(self.config, self.root / 'follower', False, status=self.status, settler=settler)
        self.assertGreaterEqual(timeouts['reconstruct'], 3600)


class SwapIsNotCrashSafe(Base):
    """Finding L4: `--apply` renames the live database aside and then the rebuilt one into place, with no journal.
    A failure between the two renames (disk, kill, power) leaves no database at `l2_db`; the settler's own
    foreign_recovery journals the same swap (finish_swap) and resumes it."""

    def test_finding_failure_between_the_renames_leaves_a_database_or_a_journal(self):
        settler = FakeSettler(self.root, accepted_view(3), 4, ACCEPTED)
        real_rename = Path.rename

        def rename(self_path, target):
            if self_path.name.startswith('db.rebuilt-'):
                raise OSError(5, 'Input/output error')
            return real_rename(self_path, target)
        with mock.patch.object(r.S, 'Settler', lambda config: settler), mock.patch.object(Path, 'rename', rename):
            with self.assertRaises(OSError):
                r.plan(self.config, self.root / 'follower', True, status=self.status)
        journals = [p.name for p in self.root.iterdir() if 'journal' in p.name or p.name.endswith('.recovery.json')]
        self.assertTrue((self.root / 'db').exists() or journals,
                        'no database at l2_db and nothing that records how to finish the swap')


if __name__ == '__main__':
    unittest.main()
