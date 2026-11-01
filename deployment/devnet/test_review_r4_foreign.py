#!/usr/bin/env python3
"""Independent review, round 4: foreign settlements that keep coming, and whether anyone is told.

Fake native RPC and producer from test_settler_foreign.py; settler_v3.py and l2_monitor.py are the real code.
A failure here is a finding, reported with its output.
Run: python3 -m unittest deployment/devnet/test_review_r4_foreign.py
"""
import sys
import time
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'mainnet'))
import l2_monitor as M  # noqa: E402
import test_settler_foreign as F  # noqa: E402


class Starvation(F.ForeignTest):
    def rolling_foreign(self, world, settler, cycles):
        """A third party settles one block per finality lag: the accepted tip is always one above the finalized prefix."""
        finalized = []
        for n in range(1, cycles + 1):
            entry = F.block(f'{(n % 9) + 1}{(n // 9) % 9 + 1}')
            world.l1.append(entry)
            world.foreign(n, entry)
            settler.cycle()
            finalized.append(entry)
            world.finalize(*finalized[:-1])
            world.finalized_only = len(finalized) - 1
            settler.cycle()
        return finalized

    def test_a_tip_that_keeps_moving_does_not_stop_recovery_of_the_finalized_prefix(self):
        world = F.World(self.root, b'')
        self.lost_race(world, F.block('b1'))
        settler = self.settler(world)
        self.assertFalse(settler.cycle())
        world.during_prove = None
        finalized = self.rolling_foreign(world, settler, 12)
        rebuilds = [c for c in world.calls if 'reconstruct' in c]
        self.assertTrue(rebuilds and self.events('foreign-settlement-recovered'),
                        f'after {len(finalized)} foreign settlements, {len(finalized) - 1} of them finalized, the worker never '
                        f'rebuilt: local chain {[h[:4] for h in self.local()]}, events '
                        f'{len(self.events("foreign-settlement-waiting-finality"))} waiting, 0 recovered')

    def test_the_monitor_sees_a_worker_that_only_waits(self):
        now = time.time()
        stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 600))
        events = [{'event': 'foreign-settlement-waiting-finality', 'number': n, 'time': stamp} for n in range(1, 13)]
        report = M.Report()
        M.grade_foreign('settler', events, M.PROFILES['mainnet'], report)
        levels = [c.level if hasattr(c, 'level') else c for c in getattr(report, 'checks', [])]
        self.assertTrue(levels, f'12 foreign settlements waited on in a day and no check was added: {levels}')


if __name__ == '__main__':
    unittest.main()
