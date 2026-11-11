#!/usr/bin/env python3
"""Automatic recovery from an L1 reorg of this worker's own accepted settlement (`reorg_recovery`, off by default).

Report 35 bug 1 and report 94: an L1 reorg removes an accepted settlement while the next block is already built, and
the worker halts with "L2 head N cannot extend accepted settlement M". Fake native RPC, producer and prover (the world
of test_settler_foreign); the database is a real directory, so swaps are real.
Run: python3 -m unittest deployment/devnet/test_settler_reorg.py
"""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_foreign as f  # noqa: E402
import test_settler_v3 as base  # noqa: E402

G = f.GENESIS_HASH
A1, A2, A3, B2 = f.block('a1'), f.block('a2'), f.block('a3'), f.block('b2')
OTHER = b'\x02other'


class Base(unittest.TestCase):
    """The helpers of test_settler_foreign.ForeignTest, without inheriting its tests."""
    setUp, config, events, local = f.ForeignTest.setUp, f.ForeignTest.config, f.ForeignTest.events, f.ForeignTest.local
    base_settler = f.ForeignTest.settler


class ReorgTest(Base):
    def reorg_config(self, **extra):
        return {'follower_state': str(self.root / 'follower'), 'follower_status': str(self.root / 'status.json'),
                'stable_seconds': 0, 'alert_file': str(self.root / 'alerts.jsonl'), **extra}

    def settler(self, world, reorg=None, **extra):
        if reorg is not False:
            extra['reorg_recovery'] = self.reorg_config(**(reorg or {}))
        return self.base_settler(world, recovery=extra.pop('recovery', True), **extra)

    def reorged(self, finalized=True):
        """Local 1 (accepted, kept by L1), 2 (accepted on the losing fork) and 3 (built); L1 now accepts 1."""
        world = f.World(self.root, b'')
        world.write(self.root / 'db', [G, A1[0], A2[0], A3[0]])
        world.l1 = [A1]
        world.foreign(1, A1)
        if finalized:
            world.finalize(A1)
        world.chain = {'height': 500, 'finalized_height': 500 if finalized else 400}
        rpc = world.rpc

        def chain_rpc(port, method, params=()):
            answer = rpc(port, method, params)
            return {**answer, **world.chain} if method == 'getchaininfo' else answer
        world.rpc = chain_rpc
        for number in (2, 3):
            directory = self.root / 'work' / f'{number:08d}-{base.BLOCK[:16]}'
            directory.mkdir()
            (directory / 'proved.json').write_text('{}')
        return world

    def alerts(self):
        path = self.root / 'alerts.jsonl'
        return [json.loads(x)['event'] for x in path.read_text().splitlines()] if path.exists() else []

    def rebuilt(self, world):
        return [c for c in world.calls if 'reconstruct' in c]

    def test_off_by_default_halts_with_the_reason_of_old(self):
        world = self.reorged()
        with self.assertRaisesRegex(s.Halt, '^L2 head 3 cannot extend accepted settlement 1$'):
            self.settler(world, reorg=False).cycle()
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertFalse(self.rebuilt(world))

    def test_rebuilds_to_the_accepted_settlement_and_continues(self):
        world = self.reorged()
        settler = self.settler(world)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0]])
        recovered = self.events('reorg-recovered')[0]
        self.assertEqual((recovered['accepted'], recovered['database_head'], recovered['common_ancestor'],
                          recovered['orphaned_blocks'], recovered['wasted_proofs'], recovered['shape']), (1, 3, 1, [2, 3], 2, 'ahead'))
        self.assertTrue(recovered['finalized'])
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-recovered'])
        generation = json.loads((self.root / 'l2-db-generation.json').read_text())
        self.assertEqual((generation['number'], generation['l2_hash']), (1, A1[0]))
        aside = sorted(p.name for p in next(self.root.glob('work-orphaned-*')).iterdir())
        self.assertEqual([n[:8] for n in aside], ['00000002', '00000003'])
        self.assertEqual(self.local(next(self.root.glob('db.orphaned-*')).name), [G, A1[0], A2[0], A3[0]])
        # No operator: the next block is built on the accepted settlement, proved and accepted.
        world.next_block, world.values = B2, f.values_for(2, B2)
        self.assertTrue(settler.cycle())
        self.assertEqual(s.statement_fields(world.accepted['statement'])['l2_number'], 2)
        self.assertEqual(self.local(), [G, A1[0], B2[0]])

    def test_waits_until_the_accepted_settlement_is_final(self):
        world = self.reorged(finalized=False)
        settler = self.settler(world)
        for _ in range(3):
            self.assertFalse(settler.cycle())
        self.assertFalse(self.rebuilt(world), 'no rebuild before finality')
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-waiting-finality'], 'each alert once')
        world.finalize(A1)
        self.assertFalse(settler.cycle(), 'M is final, but L1 finality has not passed the height the reorg was seen at')
        self.assertFalse(self.rebuilt(world))
        world.chain['height'], world.chain['finalized_height'] = 600, 499
        self.assertFalse(settler.cycle(), 'the height recorded at detection counts, not the current one')
        world.chain['finalized_height'] = 500
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0]])

    def test_a_follower_finalized_above_the_view_waits(self):
        world = self.reorged()
        world.finalize(A1, A2)
        settler = self.settler(world)
        self.assertFalse(settler.cycle())
        self.assertFalse(self.rebuilt(world))
        self.assertIn('reorg-waiting-follower', self.alerts())

    def test_without_finality_wait_it_rebuilds_to_the_accepted_head(self):
        world = self.reorged(finalized=False)
        settler = self.settler(world, reorg={'wait_for_finality': False})
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0]])
        self.assertFalse(self.events('reorg-recovered')[0]['finalized'])

    def test_a_flapping_view_never_rebuilds(self):
        world = self.reorged()
        settler = self.settler(world, reorg={'stable_seconds': 60})
        self.assertFalse(settler.cycle())
        self.assertFalse(settler.cycle())
        # L1 flips back: settlement 2 is accepted again, so the local block 3 extends it.
        world.foreign(2, A2)
        world.values = f.values_for(3, A3)
        with mock.patch.object(settler, 'prove', return_value=None):
            self.assertFalse(settler.cycle())
        self.assertTrue(self.events('l2-block-reused'))
        # And back again: a new case, whose clock starts over.
        world.foreign(1, A1)
        self.assertFalse(settler.cycle())
        self.assertFalse(self.rebuilt(world))
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-resolved', 'reorg-detected'])

    def test_a_stable_view_rebuilds_after_stable_seconds(self):
        world = self.reorged()
        settler = self.settler(world, reorg={'stable_seconds': 60})
        cycles = 0
        while not settler.cycle():
            cycles += 1
            self.assertLess(cycles, 200)
        self.assertGreater(cycles, 1)
        self.assertEqual(self.local(), [G, A1[0]])

    def test_the_limit_halts_and_survives_a_restart(self):
        world = self.reorged()
        self.assertTrue(self.settler(world, reorg={'max_recoveries': 1}).cycle())
        # A second reorg of the same kind within the window: a new process (a restart) still counts the first.
        world.write(self.root / 'db', [G, A1[0], A2[0], A3[0]])
        with self.assertRaisesRegex(s.Halt, '1 automatic reorg recoveries within 21600 s'):
            self.settler(world, reorg={'max_recoveries': 1}).cycle()
        self.assertEqual(self.alerts()[-1], 'reorg-limit')
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])

    def test_old_recoveries_leave_the_window(self):
        world = self.reorged()
        history = self.root / 'db.reorg-recoveries.json'
        history.write_text(json.dumps([{'unix': 1, 'accepted': 1}]))
        self.assertTrue(self.settler(world, reorg={'max_recoveries': 1}).cycle())
        self.assertEqual(len(json.loads(history.read_text())), 1)

    def test_a_foreign_block_at_the_accepted_number_is_not_this_case(self):
        world = self.reorged()
        world.l1 = [f.block('c1')]
        world.foreign(1, f.block('c1'))
        world.finalize(f.block('c1'))
        # reorg_recovery always comes with foreign_recovery (R308-22): the block goes to the foreign path, which
        # is none of this suite's business; the reorg path neither detects nor counts it.
        self.settler(world).cycle()
        self.assertFalse(self.events('reorg-detected'))
        self.assertFalse((self.root / 'db.reorg-recoveries.json').exists())

    def test_a_follower_finality_that_contradicts_the_quorum_halts(self):
        world = self.reorged(finalized=False)
        world.finalize(f.block('c1'))
        with self.assertRaisesRegex(s.Halt, 'the follower finalized L2 block 1'):
            self.settler(world).cycle()

    def test_a_rebuild_behind_the_view_waits_and_keeps_the_database(self):
        world = self.reorged()
        world.l1 = []
        (self.root / 'status.json').write_text(json.dumps({'finalized_settlements': [{'l2_number': 1, 'l2_hash': A1[0]}],
                                                           'verified_tip': 98}))
        settler = self.settler(world)
        self.assertFalse(settler.cycle())
        self.assertFalse(settler.cycle())
        self.assertEqual(len(self.rebuilt(world)), 1, 'not repeated until the follower has more')
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertIn('reorg-waiting-follower', self.alerts())
        world.l1 = [A1]
        (self.root / 'status.json').write_text(json.dumps({'finalized_settlements': [{'l2_number': 1, 'l2_hash': A1[0]}],
                                                           'verified_tip': 99}))
        self.assertTrue(settler.cycle())

    def test_a_follower_still_on_the_losing_fork_is_waited_for(self):
        world = self.reorged()
        world.l1 = [A1, A2]  # the follower has not reverted settlement 2 yet
        settler = self.settler(world)
        self.assertFalse(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertTrue(self.events('reorg-rebuild-behind-view'))
        world.l1 = [A1]
        (self.root / 'status.json').write_text(json.dumps({'finalized_settlements': [{'l2_number': 1, 'l2_hash': A1[0]}],
                                                           'verified_tip': 7}))
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0]])

    def test_an_off_rule_rebuild_halts(self):
        world = self.reorged()
        world.refuse_rebuild = True
        with self.assertRaisesRegex(s.Halt, 'reorg of the accepted settlement'):
            self.settler(world).cycle()
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])

    def test_a_block_with_another_anchor_is_the_same_case(self):
        world = self.reorged()
        world.write(self.root / 'db', [G, A1[0], A2[0]])
        view = world.view
        world.view = lambda: {**view(), 'source': {**view()['source'], 'block': 'ab' * 32}}
        with self.assertRaisesRegex(s.Halt, 'has anchor'):
            self.settler(world, reorg=False).cycle()
        self.assertTrue(self.settler(world).cycle())
        self.assertEqual(self.events('reorg-recovered')[0]['shape'], 'anchor')
        self.assertEqual(self.local(), [G, A1[0]])

    def test_orphaned_user_transactions_go_back_to_the_spool(self):
        world = self.reorged()
        world.block_txs = {2: base.batch(2), 3: base.batch(1)}
        self.assertTrue(self.settler(world, users=True).cycle())
        self.assertEqual(self.events('reorg-recovered')[0]['respooled'], len({*s.da_batch_transactions(base.batch(2)),
                                                                              *s.da_batch_transactions(base.batch(1))}))
        self.assertTrue(list((self.root / 'txpool').glob('*.tx')))

    def test_dry_run_reports_the_case_and_changes_nothing(self):
        world = self.reorged()
        config = self.config(recovery=True, reorg_recovery=self.reorg_config())
        (self.root / 'out').mkdir()
        code = s.dry_run(config, out=str(self.root / 'out' / 'run'), rpc=world.rpc, run=world.run, sleep=lambda _: None)
        self.assertEqual(code, 2)
        report = json.loads((self.root / 'out' / 'run' / 'dry-run-report.json').read_text())
        self.assertIn('cannot extend accepted settlement 1', report['reason'])
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])

    def test_no_settlement_left_halts(self):
        world = self.reorged()
        world.write(self.root / 'db', [G, A1[0], A2[0]])
        world.accepted, world.l1 = None, []
        with self.assertRaisesRegex(s.Halt, 'no accepted settlement any more'):
            self.settler(world).cycle()

    def test_alert_command_gets_each_alert_and_cannot_stop_the_worker(self):
        world = self.reorged()
        seen = []
        run = world.run

        def hooked(argv, **kwargs):
            if argv[0] == 'alert-hook':
                seen.append(json.loads(kwargs['input'])['event'])
                raise OSError('hook down')
            return run(argv, **kwargs)
        world.run = hooked
        self.assertTrue(self.settler(world, reorg={'alert_command': ['alert-hook']}).cycle())
        self.assertEqual(seen, ['reorg-detected', 'reorg-recovered'])
        self.assertEqual(len(self.events('reorg-alert-failed')), 2)

    def test_bad_configuration_is_refused(self):
        world = self.reorged()
        for bad in ({'stable_seconds': -1}, {'max_recoveries': 0}, {'wait_for_finality': 'yes'}, {'alert_command': 'x'},
                    {'window_seconds': True}):
            with self.assertRaises(s.Halt):
                self.settler(world, reorg=bad)
        # R308-22: reorg_recovery alone is refused, with or without its own follower paths.
        for alone in ({}, self.reorg_config()):
            with self.assertRaisesRegex(s.Halt, 'reorg_recovery needs foreign_recovery'):
                self.base_settler(world, recovery=False, reorg_recovery=alone)
        # The follower paths can come from foreign_recovery.
        settler = self.base_settler(world, recovery=True, reorg_recovery={})
        self.assertEqual(settler.c['reorg_recovery']['follower_state'], str(self.root / 'follower'))
        self.assertEqual(settler.c['reorg_recovery']['stable_seconds'], 120)


class NoL1BatchTest(ReorgTest):
    """Kit 4b7f4f7 removed every read of a paid DA batch from L1 (agent 145 F1-F3). Agent 134's reservation of higher
    paid batches (reserved_batch_spool) read the same unauthenticated frames, so it is not ported: a recovery builds
    the next block from the spool only, and the orphaned transactions come back from the old database."""

    def test_no_l1_batch_reader_exists(self):
        for name in ('reserved_batch_spool', 'paid_batch_spool', 'node_da_batches'):
            self.assertFalse(hasattr(s.Settler, name), name)
        for name in ('recorded_da_batches', 'scan_da_frames'):
            self.assertFalse(hasattr(s, name), name)

    def test_the_block_after_a_recovery_is_built_from_the_spool(self):
        world = self.reorged()
        world.block_txs = {2: base.batch(2), 3: base.batch(1)}
        settler = self.settler(world, users=True)
        self.assertTrue(settler.cycle())
        world.next_block = B2
        with mock.patch.object(settler, 'prove', return_value=None):
            settler.cycle()
        extend = [c for c in world.calls if 'extend' in c][-1]
        self.assertEqual(extend[extend.index('--txs') + 1], str(self.root / 'txpool'), 'the main spool, nothing else')


if __name__ == '__main__':
    unittest.main()
