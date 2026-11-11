#!/usr/bin/env python3
"""Review a308: demonstrations that apply to BOTH lines (kit 6e12ab6 and candidate 6b75a4c).
Run (WT = the worktree to test; nothing is written into it):
  WT=/Users/tiagobulhoes/worktrees/l2-release-review-r15-20261110 PYTHONDONTWRITEBYTECODE=1 nice -n 10 \
    python3 -B -m unittest -v test_a308_both_lines.py
"""
import itertools
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

WT = Path(os.environ.get('WT', str(Path(__file__).resolve().parents[3])))
sys.path.insert(0, str(WT / 'deployment/devnet'))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as t  # noqa: E402

TERMINAL = f"sendrawtransaction: {{'code': {s.TX_REFUSED}, 'message': 'L2 settlement policy, source, successor or proof failed'}}"


class Both(t.SettlerV3Test):
    for _name in [n for n in dir(t.SettlerV3Test) if n.startswith('test_')]:
        locals()[_name] = None

    def make(self, fake, **extra):
        clock = itertools.count(0, 3)
        return s.Settler(self.config(**extra), rpc=fake.rpc, run=fake.run, sleep=lambda _: None,
                         clock=lambda: next(clock))

    def pending_world(self):
        """Settlements are held by the nodes but never accepted."""
        fake = t.Fake(self.root, t.statement())
        inner = fake.rpc

        def rpc(port, method, params=()):
            if method == 'sendrawtransaction' and not params[0].startswith('15'):
                return {'status': 'duplicate', 'tx_hash': '00' * 32}
            return inner(port, method, params)
        fake.rpc = rpc
        return fake

    def test_1_unreadable_submitted_json_is_a_halt_not_an_endless_retry(self):
        fake = self.pending_world()
        settler = self.make(fake)
        with mock.patch.object(s, 'log'):
            self.assertFalse(settler.cycle())  # proved, broadcast, acceptance window ended
            record = next(self.root.glob('work/*/submitted.json'))
            for bad in ('', '{"tx_sha256": "ab', '[]'):
                record.write_text(bad)
                with self.subTest(bad=bad):
                    try:
                        settler.cycle()
                    except s.Halt:
                        pass  # acceptable: a logged halt for the operator
                    # anything else (ValueError/AttributeError) is the generic retry: exit 1, restart, same error

    def test_2_a_stray_orphaned_name_must_not_wedge_a_journalled_swap(self):
        fake = t.Fake(self.root, t.statement())
        settler = self.make(fake)
        db, rebuilt = self.root / 'db', self.root / 'db.rebuilt-5'
        db.mkdir(), rebuilt.mkdir(), (self.root / 'work').mkdir(exist_ok=True)
        (self.root / 'db.orphaned-1700000000000000000.bak').mkdir()  # an operator's copy of a kept database
        journal = settler.recovery_journal()
        journal.write_text(json.dumps({'rebuilt': str(rebuilt), 'kept': str(self.root / 'db.orphaned-7'),
                                       'work_aside': str(self.root / 'work-orphaned-7'), 'stale': [], 'number': 1,
                                       'l2_hash': 'aa' * 32}))
        settler.finish_swap()
        self.assertFalse(journal.exists(), 'the journal is finished')

    def test_3_terminal_refusals_with_one_endpoint_down_end_in_a_halt(self):
        fake = t.Fake(self.root, t.statement())
        inner = fake.rpc

        def rpc(port, method, params=()):
            if port == 3:
                raise ConnectionRefusedError(111, 'Connection refused')  # one endpoint down: the tolerated fault
            if method == 'sendrawtransaction' and not params[0].startswith('15'):
                raise s.RpcError(TERMINAL)
            return inner(port, method, params)
        fake.rpc = rpc
        settler = self.make(fake)
        with mock.patch.object(s, 'log') as logged, self.assertRaises(s.Halt):
            for _ in range(12):  # 12 acceptance windows
                settler.cycle()
        self.fail_note = logged


if __name__ == '__main__':
    unittest.main()
