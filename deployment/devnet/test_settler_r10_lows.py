#!/usr/bin/env python3
"""Agent 198 (round 10): details of the fixes for agent 152's L1 (quorum floor stall) and L6 (prover timeout fallback)
that 152's acceptance tests (test_settler_review_r10.py) do not pin."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as t  # noqa: E402


class Lows(unittest.TestCase):
    setUp = t.SettlerV3Test.setUp
    tearDown = t.SettlerV3Test.tearDown
    config = t.SettlerV3Test.config
    settler = t.SettlerV3Test.settler
    remote = t.SettlerV3Test.remote
    quorum_settler = t.SettlerV3Test.quorum_settler

    def behind_floor(self, settler, ports, fake, reads):
        self.assertIsNotNone(settler.native_view())
        ports.modes = {1: 'down'}
        fake.accepted = None
        events, outcomes = [], []
        with mock.patch.object(s, 'log', lambda event, **kw: events.append((event, kw))):
            for _ in range(reads):
                try:
                    outcomes.append(settler.native_view())
                except s.QuorumFloorStall as error:
                    outcomes.append(error)
                    break
        return events, outcomes

    def fixture(self, **extra):
        fake = t.Fake(self.root, t.statement())
        fake.accepted = {'statement': t.statement().hex(), 'commitment': '99' * 32}
        ports = t.Ports(fake)
        settler = self.quorum_settler(ports)
        settler.c.update(extra)
        return settler, ports, fake

    def test_floor_stall_raises_a_retryable_error_not_a_halt_and_names_the_floor(self):
        settler, ports, fake = self.fixture()
        events, outcomes = self.behind_floor(settler, ports, fake, 300)
        self.assertIsInstance(outcomes[-1], s.QuorumFloorStall)
        self.assertNotIsInstance(outcomes[-1], s.Halt)
        self.assertIsInstance(outcomes[-1], Exception, 'run_main counts it as a retry and exits 1 at the limit')
        stall = [kw for e, kw in events if e == 'rpc-quorum-behind-floor']
        self.assertEqual(len(stall), 1)
        self.assertEqual((stall[0]['accepted'], stall[0]['seen']), (0, 1))
        self.assertGreaterEqual(stall[0]['seconds'], 1200)

    def test_floor_stall_can_be_turned_off(self):
        settler, ports, fake = self.fixture(quorum_floor_stall_seconds=0)
        _, outcomes = self.behind_floor(settler, ports, fake, 300)
        self.assertTrue(all(o is None for o in outcomes))

    def test_a_view_at_or_above_the_floor_resets_the_stall_clock(self):
        settler, ports, fake = self.fixture()
        self.behind_floor(settler, ports, fake, 2)
        self.assertIsNotNone(settler.floor_stall)
        fake.accepted = {'statement': t.statement().hex(), 'commitment': '99' * 32}
        with mock.patch.object(s, 'log'):
            self.assertIsNotNone(settler.native_view())
        self.assertIsNone(settler.floor_stall)

    def test_bad_floor_stall_setting_halts_at_start(self):
        for bad in (-1, 1.5, True, '1200'):
            config = self.config()
            config['quorum_floor_stall_seconds'] = bad
            with self.assertRaisesRegex(s.Halt, 'quorum_floor_stall_seconds'):
                s.Settler(config, run=t.Fake(self.root, t.statement()).run)

    def test_a_prover_timeout_is_logged_as_a_failed_attempt_with_exit_124(self):
        fake = t.Fake(self.root, t.statement())
        inner = fake.run

        def run(argv, **kwargs):
            if Path(argv[0]).name == 'ssh':
                raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))
            return inner(argv, **kwargs)
        fake.run = run
        events = []
        with mock.patch.object(s, 'log', lambda event, **kw: events.append((event, kw))):
            self.assertTrue(self.settler(fake, remote_prover=self.remote(order=['remote', 'local'])).cycle())
        failed = [kw for e, kw in events if e == 'prover-failed']
        self.assertEqual([(f['where'], f['exit_code'], f.get('timeout')) for f in failed], [('remote', 124, True)])


if __name__ == '__main__':
    unittest.main()
