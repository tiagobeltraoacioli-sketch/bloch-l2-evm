#!/usr/bin/env python3
"""Agent 198 (round 10): behaviour around agent 152's L2-L4 fixes in l2_reorg_recover.py that 152's tests do not pin."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import l2_reorg_recover as r  # noqa: E402
from test_l2_reorg_recover import FakeSettler, batch  # noqa: E402
from test_l2_reorg_recover_review_r10 import ACCEPTED, Base, accepted_view  # noqa: E402


class Fixes(Base):
    def settler(self, head, local_hashes=None, document=None):
        settler = FakeSettler(self.root, accepted_view(3), head, ACCEPTED)
        hashes = local_hashes or {}
        settler.local_hash = lambda number: hashes.get(number, 'aa' * 32)
        if document is not None:
            inner = settler.produce

            def produce(*args, timeout=300):
                out = inner(*args, timeout=timeout)
                return dict(out, **document) if args[0] == 'reconstruct' else out
            settler.produce = produce
        return settler

    def run_plan(self, settler, apply=True, **kw):
        with mock.patch.object(r.S, 'Settler', lambda config: settler):
            return r.plan(self.config, self.root / 'follower', apply, status=self.status, **kw)

    def test_rebuilt_blocks_place_the_common_ancestor(self):
        for number in (1, 2, 3, 4):
            d = self.root / f'work/0000000{number}-0123456789abcdef'
            d.mkdir()
            (d / 'da-payload.hex').write_text(batch(bytes([2, number])).hex() + '\n')
        blocks = [{'number': 1, 'hash': 'aa' * 32}, {'number': 2, 'hash': 'bb' * 32}, {'number': 3, 'hash': ACCEPTED}]
        report = self.run_plan(self.settler(4, document={'blocks': blocks}), apply=False)
        self.assertEqual(report['common_ancestor'], 1)
        self.assertNotIn('common_ancestor_assumed', report)
        self.assertEqual(report['orphaned_blocks'], ['00000002-0123456789abcdef', '00000003-0123456789abcdef',
                                                     '00000004-0123456789abcdef'])

    def test_a_database_on_the_accepted_chain_orphans_only_blocks_above_it(self):
        for number in (3, 4):
            (self.root / f'work/0000000{number}-0123456789abcdef').mkdir()
        report = self.run_plan(self.settler(4, {3: ACCEPTED}), apply=False)
        self.assertEqual(report['common_ancestor'], 3)
        self.assertEqual(report['orphaned_blocks'], ['00000004-0123456789abcdef'])

    def test_rebuild_timeout_is_refused_and_cleaned_up(self):
        settler = self.settler(4)

        def produce(*args, timeout=300):
            if args[0] == 'reconstruct':
                Path(args[args.index('--target') + 1]).mkdir()
                raise subprocess.TimeoutExpired(args, timeout)
            return {'number': 4, 'hash': 'aa' * 32}
        settler.produce = produce
        with self.assertRaisesRegex(r.Refuse, 'did not finish in 7200 s'):
            self.run_plan(settler, timeout=7200)
        self.assertEqual([p.name for p in self.root.iterdir() if '.rebuilt-' in p.name], [])

    def test_rebuild_timeout_defaults_to_the_foreign_recovery_setting(self):
        self.assertEqual(r.rebuild_timeout({}), 3600)
        self.assertEqual(r.rebuild_timeout({'foreign_recovery': {'rebuild_timeout_seconds': 9000}}), 9000)

    def test_an_interrupted_swap_is_finished_by_the_next_apply_and_refused_by_a_dry_run(self):
        (self.root / 'work/00000004-0123456789abcdef').mkdir()
        real_rename = Path.rename

        def rename(self_path, target):
            if self_path.name.startswith('db.rebuilt-'):
                raise OSError(5, 'Input/output error')
            return real_rename(self_path, target)
        with mock.patch.object(Path, 'rename', rename), self.assertRaises(OSError):
            self.run_plan(self.settler(4))
        self.assertFalse((self.root / 'db').exists())
        with self.assertRaisesRegex(r.Refuse, 'unfinished database swap'):
            self.run_plan(self.settler(4), apply=False)
        report = self.run_plan(self.settler(4))
        self.assertTrue(report['finished_interrupted_swap'])
        self.assertTrue((self.root / 'db').is_dir())
        self.assertFalse((self.root / 'db.recovery.json').exists())
        self.assertTrue((Path(report['orphaned_work']) / '00000004-0123456789abcdef').is_dir())
        generation = json.loads((self.root / 'l2-db-generation.json').read_text())
        self.assertEqual((generation['number'], generation['l2_hash']), (3, ACCEPTED))

    def test_the_journal_has_the_worker_format(self):
        """settler_v3's finish_swap must be able to finish a swap this tool started (it runs at every cycle)."""
        with mock.patch.object(r, 'finish_swap', lambda *a: None):
            self.run_plan(self.settler(4))
        state = json.loads((self.root / 'db.recovery.json').read_text())
        self.assertEqual(set(state), {'rebuilt', 'kept', 'work_aside', 'stale', 'number', 'l2_hash'})
        worker = r.S.Settler.__new__(r.S.Settler)
        worker.c, worker.work = dict(self.config), Path(self.config['workdir'])
        worker.finish_swap()
        self.assertTrue((self.root / 'db').is_dir())
        self.assertFalse((self.root / 'db.recovery.json').exists())
        self.assertTrue(Path(state['kept']).is_dir())


if __name__ == '__main__':
    unittest.main()
