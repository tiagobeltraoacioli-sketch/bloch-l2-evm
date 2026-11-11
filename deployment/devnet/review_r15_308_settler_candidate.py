#!/usr/bin/env python3
"""Review a308: demonstrations on the candidate line (6b75a4c, commit 9340293).
Run:
  PYTHONDONTWRITEBYTECODE=1 nice -n 10 python3 -B -m unittest -v test_a308_candidate.py
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

WT = Path(os.environ.get('WT', str(Path(__file__).resolve().parents[2])))
sys.path.insert(0, str(WT / 'deployment/devnet'))
import settler_v3 as s  # noqa: E402
import test_settler_reorg_final as final  # noqa: E402

G, A1, A2, A3 = final.G, final.A1, final.A2, final.A3


class Candidate(final.Restore):
    for _name in [n for n in dir(final.Restore) if n.startswith('test_')]:
        locals()[_name] = None

    def slow_once(self, world, times=1):
        """The producer times out once on `head` of a kept database (a loaded host), then answers."""
        run, state = world.run, {'left': times}

        def slow(argv, **kwargs):
            if state['left'] and len(argv) > 3 and argv[1] == 'head' and '.orphaned-' in str(argv[3]):
                state['left'] -= 1
                raise subprocess.TimeoutExpired(argv, kwargs.get('timeout', 300))
            return run(argv, **kwargs)
        return slow

    def test_1_one_producer_timeout_on_the_kept_database_does_not_rebuild(self):
        """9340293 turns the timeout into `continue`: the only kept database that holds the landed block is skipped
        and the same cycle goes on to the foreign path (a full reconstruct and a swap) instead of retrying."""
        world, settler = self.rebuilt_then_landed()
        before = len(self.rebuilt(world))
        settler.run = self.slow_once(world)
        try:
            settler.cycle()
        except subprocess.TimeoutExpired:
            pass  # the behaviour before 9340293: a transient failure, retried by the bounded retry
        self.assertEqual(len(self.rebuilt(world)), before, 'a transient timeout started a second reconstruct')
        # the fix: the cycle waited (a logged event), and the next one swaps the kept database back
        self.assertEqual(settler.kept_scan_timeouts, 1)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertEqual(len(self.rebuilt(world)), before)
        self.assertEqual(settler.kept_scan_timeouts, 0)

    def test_1b_a_kept_database_that_always_times_out_is_given_up_after_the_limit(self):
        """Negative of the new rule: the wait is bounded, so a database the producer can never read does not hold
        the foreign rebuild back for ever."""
        world, settler = self.rebuilt_then_landed()
        before = len(self.rebuilt(world))
        settler.run = self.slow_once(world, times=10 ** 6)
        for waited in range(1, s.KEPT_SCAN_TIMEOUTS + 1):
            self.assertFalse(settler.cycle())
            self.assertEqual((settler.kept_scan_timeouts, len(self.rebuilt(world))), (waited, before))
        settler.cycle()
        self.assertEqual(len(self.rebuilt(world)), before + 1, 'after the limit the foreign rebuild runs')
        self.assertEqual(settler.kept_scan_timeouts, 0)

    def test_2_one_producer_timeout_without_foreign_recovery_is_not_a_halt(self):
        world = self.reorged()
        self.store_proved_block_2(world)
        # Adapted to the fix: reorg_recovery alone (the reviewer's configuration) is now refused when the worker
        # starts, so the case "timeout, no foreign path, Halt" cannot be configured; with both set the timeout waits.
        with self.assertRaisesRegex(s.Halt, 'reorg_recovery needs foreign_recovery'):
            self.settler(world, recovery=False, reorg={'resubmit_window_seconds': 0})
        settler = self.settler(world, recovery=True, reorg={'resubmit_window_seconds': 0})
        self.assertTrue(settler.cycle())
        world.foreign(2, A2)
        world.l1 = [A1, A2]
        world.finalize(A1, A2)
        settler.run = self.slow_once(world)
        before = len(self.rebuilt(world))
        try:
            self.assertFalse(settler.cycle())
        except subprocess.TimeoutExpired:
            pass
        # s.Halt here = exit 3, RestartPreventExitStatus: an operator is needed for one slow producer call
        self.assertEqual(len(self.rebuilt(world)), before)

    def test_3_first_sight_height_is_not_lowered_by_one_endpoint_of_a_partial_view(self):
        """`reorg_l1_height` gates the rebuild (`l1_final < self.reorg_l1_height` waits). Taken as the minimum of
        the two ports of a partial view, one lying (or freshly restarted) endpoint sets it to anything lower."""
        world = self.per_port(self.reorged())
        world.port_chain[2] = {'height': 1}
        settler = self.settler(world)
        settler.view_support = [1, 2]  # the partial quorum of the 153 M1 case (port 3 on the losing fork)
        self.assertEqual(settler.first_sight_height(), 500, 'ports 1 and 3 report 500')

    def test_3b_first_sight_height_over_two_and_three_answers(self):
        world = self.per_port(self.reorged())
        settler = self.settler(world)
        settler.view_support = [1, 2]
        rpc = world.rpc

        def without_3(port, method, params=()):
            if port == 3:
                raise ConnectionRefusedError(111, 'refused')
            return rpc(port, method, params)
        with mock.patch.object(s, 'log'):
            world.port_chain[1] = {'height': 10 ** 12}  # one of three cannot push it out of reach (153 L2)
            self.assertEqual(settler.first_sight_height(), 500)
            world.port_chain[1] = {'height': 'x'}  # an answer without a usable height is no answer
            self.assertEqual(settler.first_sight_height(), 500)
            world.port_chain.clear()
            settler.native.rpc = without_3
            world.port_chain[2] = {'height': 1}  # two answers: the larger
            self.assertEqual(settler.first_sight_height(), 500)
            world.port_chain[2] = {'height': 700}
            self.assertEqual(settler.first_sight_height(), 700)
            settler.view_support = [3]  # no endpoint of the view answered
            self.assertIsNone(settler.first_sight_height())

    def test_4_a_clock_step_back_must_not_evict_the_database_just_kept(self):
        """finish_swap orders kept databases by the wall-clock stamp in their names and removes all but `keep`."""
        world, settler = self.rebuilt_then_landed()  # one kept database (stamp = now) holds blocks 2 and 3
        kept = next(self.root.glob('db.orphaned-*'))
        newer = [self.root / f'db.orphaned-{int(kept.name.split("-")[1]) + n}' for n in (1, 2)]
        for path in newer:  # two kept databases from before the clock was stepped back
            path.mkdir()
            (path / 'chain.json').write_text(json.dumps([G]))
        rebuilt = self.root / 'db.rebuilt-1'
        rebuilt.mkdir()
        (rebuilt / 'chain.json').write_text(json.dumps([G, A1[0]]))
        settler.recovery_journal().write_text(json.dumps(
            {'rebuilt': str(rebuilt), 'kept': str(self.root / 'db.orphaned-5'), 'work_aside': str(self.root / 'work-orphaned-5'),
             'stale': [], 'number': 1, 'l2_hash': A1[0]}))  # stamp 5: the clock went back
        settler.finish_swap()
        self.assertTrue((self.root / 'db.orphaned-5').exists(), 'the database swapped out a moment ago is gone')
        # keep = 2: the one just kept and the newest of the others; the journal is finished
        self.assertEqual(sorted(p.name for p in self.root.glob('db.orphaned-*')), sorted(['db.orphaned-5', newer[1].name]))
        self.assertFalse(settler.recovery_journal().exists())
        # the next swap is numbered above everything in use, whatever the clock says
        with mock.patch.object(s.time, 'time_ns', return_value=3):
            self.assertEqual(settler.swap_stamp(), int(newer[1].name.split('-')[1]) + 1)
        self.assertGreater(settler.swap_stamp(), int(newer[1].name.split('-')[1]) + 1)

    def test_4b_keep_one_leaves_only_what_the_swap_kept(self):
        world, settler = self.rebuilt_then_landed(keep=1)
        settler.c['foreign_recovery']['keep'] = 1
        first = next(self.root.glob('db.orphaned-*'))
        rebuilt = self.root / 'db.rebuilt-1'
        rebuilt.mkdir()
        (rebuilt / 'chain.json').write_text(json.dumps([G, A1[0]]))
        settler.recovery_journal().write_text(json.dumps(
            {'rebuilt': str(rebuilt), 'kept': str(self.root / 'db.orphaned-5'), 'work_aside': str(self.root / 'work-orphaned-5'),
             'stale': [], 'number': 1, 'l2_hash': A1[0]}))
        settler.finish_swap()
        self.assertEqual([p.name for p in self.root.glob('db.orphaned-*')], ['db.orphaned-5'], first.name)
        self.assertEqual([p.name for p in self.root.glob('work-orphaned-*')], ['work-orphaned-5'])


if __name__ == '__main__':
    unittest.main()
