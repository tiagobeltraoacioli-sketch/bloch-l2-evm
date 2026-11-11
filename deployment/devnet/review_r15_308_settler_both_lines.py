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

WT = Path(os.environ.get('WT', str(Path(__file__).resolve().parents[2])))
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
                    # tightened after the fix: the named halt is the only outcome (the reviewer's test also let a
                    # clean cycle pass)
                    with self.assertRaisesRegex(s.Halt, 'submitted.json is unreadable'):
                        settler.cycle()
            # negative: a readable record of the same bytes, or none at all, goes on as before
            record.unlink()
            self.assertFalse(settler.cycle())
            self.assertIn('tx_sha256', json.loads(record.read_text()))
            self.assertFalse(settler.cycle())

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
        self.assertTrue((self.root / 'db.orphaned-1700000000000000000.bak').is_dir(), "the operator's copy is left alone")
        self.assertTrue((self.root / 'db.orphaned-7').is_dir())

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
        with mock.patch.object(s, 'log') as logged, self.assertRaisesRegex(s.Halt, 'a quorum of native endpoints refused'):
            for _ in range(12):  # 12 acceptance windows
                settler.cycle()
        self.fail_note = logged
        windows = [c.kwargs['windows'] for c in logged.call_args_list if c.args[0] == 'settlement-refused-by-quorum']
        self.assertEqual(windows, [1, 2, 3, 4], 'the default max_unincluded_windows')

    def test_3b_the_count_can_be_alert_only_and_needs_a_quorum(self):
        def world(down, refuse=TERMINAL):
            fake = t.Fake(self.root, t.statement())
            inner = fake.rpc

            def rpc(port, method, params=()):
                if method == 'sendrawtransaction' and port in down:
                    raise ConnectionRefusedError(111, 'Connection refused')
                if method == 'sendrawtransaction' and not params[0].startswith('15'):
                    raise s.RpcError(refuse)
                return inner(port, method, params)
            fake.rpc = rpc
            return fake
        retryable = TERMINAL.replace(str(s.TX_REFUSED), str(s.TX_REFUSED_RETRYABLE))
        for name, fake, extra in (('alert only', world({3}), {'max_unincluded_windows': 0}),
                                  ('one answer is no quorum', world({2, 3}), {}),
                                  ('retryable refusals', world({3}, retryable), {})):
            with self.subTest(name=name), mock.patch.object(s, 'log') as logged:
                settler = self.make(fake, **extra)
                for _ in range(8):
                    settler.cycle()
                counted = [c for c in logged.call_args_list if c.args[0] == 'settlement-refused-by-quorum']
                self.assertEqual(len(counted) > 0, name == 'alert only')
            self.tearDown(), self.setUp()

    def test_3c_classification(self):
        bad = f"RpcError: sendrawtransaction: {{'code': {s.TX_REFUSED}, 'message': 'policy'}}"
        pending = f"RpcError: sendrawtransaction: {{'code': {s.TX_REFUSED}, 'message': '{s.ONE_PROOF_PENDING}'}}"
        down = 'ConnectionRefusedError: [Errno 111] Connection refused'
        odd = 'UnexpectedAnswer: {}'
        cases = [([bad, bad, down], 2, 'retry', True), ([bad, bad, bad], 2, 'terminal', False),
                 ([bad, down, down], 2, 'retry', False), ([bad, bad, odd], 2, 'retry', False),
                 ([bad, pending, down], 2, 'retry', False), ([bad, bad, down], None, 'retry', False),
                 ([down, down, down], 2, 'retry', False)]
        for errors, quorum, kind, by_quorum in cases:
            refused = s.SubmitRefused(list(enumerate(errors)), quorum)
            self.assertEqual((refused.kind(), refused.refused_by_quorum()), (kind, by_quorum), (errors, quorum))


if __name__ == '__main__':
    unittest.main()
