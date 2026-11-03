#!/usr/bin/env python3
"""Independent review (agent 153, round 10) of `reorg_recovery` (codex/reorg-auto-r8-20261102 3401bef).

Each test states a property the automatic recovery should have. Tests marked FAILS-AT-3401bef fail against the
reviewed tip; the rest pass and pin behaviour the review relies on. Same fake world as test_settler_reorg
(fake native RPC, producer and prover; the database is a real directory).
Run: python3 -m unittest deployment/devnet/test_settler_reorg_review.py
"""
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_foreign as f  # noqa: E402
import test_settler_reorg as r  # noqa: E402
import test_settler_v3 as base  # noqa: E402

G, A1, A2, A3, B2 = r.G, r.A1, r.A2, r.A3, r.B2


class ReviewTest(r.ReorgTest):
    """Reuses ReorgTest's helpers; its own tests are not re-run here."""

    def per_port(self, world):
        """Lets a test override getl2settlement / getchaininfo answers of single ports."""
        world.port_view, world.port_chain = {}, {}
        rpc = world.rpc

        def split(port, method, params=()):
            if method == 'getl2settlement' and port in world.port_view:
                return world.port_view[port]()
            answer = rpc(port, method, params)
            if method == 'getchaininfo' and port in world.port_chain:
                return {**answer, **world.port_chain[port]}
            return answer
        world.rpc = split
        return world

    def store_proved_block_2(self, world):
        """The work directory of block 2 holds what the worker built, proved and got accepted before the reorg:
        its request (the view's request is unchanged by the reorg) and its settlement bytes."""
        directory = self.root / 'work' / f'{2:08d}-{base.BLOCK[:16]}'
        view = world.view()
        (directory / 'native-request.txt').write_text(view['source']['request'] + f.PARENT_COMMITMENT + '\n'
                                                      + '1\n0\n1\n')
        tx = bytes([s.ASYNC_SETTLEMENT_TAG]) + b'\x5a' * 32 + f.values_for(2, A2) + b'proof'
        (directory / 'transaction.bin').write_bytes(tx)
        return tx


# Run only this file's tests, not ReorgTest's again.
for _name in [n for n in dir(r.ReorgTest) if n.startswith('test_')]:
    setattr(ReviewTest, _name, None)


class FalseSignal(ReviewTest):
    def test_one_lagging_endpoint_cannot_start_a_case(self):
        """Q1, passes: a single endpoint on an old view never forms the 2-of-3 view, so nothing is detected."""
        world = self.per_port(self.reorged())
        world.foreign(2, A2)
        world.l1 = [A1, A2]
        old = f.values_for(1, A1).hex()
        world.port_view[3] = lambda: {**world.view(), 'accepted': {'statement': old, 'commitment': f.PARENT_COMMITMENT}}
        settler = self.settler(world)
        with mock.patch.object(settler, 'prove', return_value=None):
            for _ in range(3):
                settler.cycle()
        self.assertFalse(self.rebuilt(world))
        self.assertNotIn('reorg-detected', self.alerts())

    def test_two_stale_endpoints_after_a_restart_are_held_by_the_finality_gate(self):
        """Q1, passes: after a restart (accepted_floor is not persisted) two stale endpoints do form a view one
        settlement behind. The case is detected and alerted, but the median finalized height of the two stale
        endpoints never passes the height of first sight, so nothing is rebuilt."""
        world = self.per_port(self.reorged())
        world.chain = {'height': 400, 'finalized_height': 300}  # the two stale endpoints
        world.port_chain[3] = {'height': 500, 'finalized_height': 499}
        settler = self.settler(world)
        for _ in range(5):
            self.assertFalse(settler.cycle())
        self.assertFalse(self.rebuilt(world))
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-waiting-finality'])

    def test_a_view_read_before_the_finality_read_never_rebuilds(self):
        """FAILS-AT-3401bef (Low). recover_reorg reads the view, then the follower, then finalized_height in
        separate reads. If the nodes apply the acceptance of M+1 (and finalize past it) between the view read and
        the finality read, the gate passes on a view that no longer holds. A follower that has not verified the
        block with M+1 yet then rebuilds to M and orphans the block L1 accepted; foreign_recovery has to rebuild
        back. Fix: re-read the view after the finality gate and require the same case, or gate on the
        follower's own verified height reaching the height of first sight."""
        world = self.reorged(finalized=True)
        world.chain = {'height': 500, 'finalized_height': 400}
        settler = self.settler(world)
        self.assertFalse(settler.cycle())  # detected; L1 finality still below the height of first sight
        original = settler.native.bounded_value

        def raced(method, field):
            world.foreign(2, A2)  # the nodes now accept M+1 again and finalize past it
            world.chain.update(height=600, finalized_height=600)
            return original(method, field)
        with mock.patch.object(settler.native, 'bounded_value', side_effect=raced):
            settler.cycle()
        self.assertFalse(self.rebuilt(world), 'rebuilt to M while L1 had finalized M+1')
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])

    def test_one_endpoint_reporting_a_far_height_cannot_block_recovery(self):
        """FAILS-AT-3401bef (Low, liveness). The height of first sight is the max over every endpoint that
        answered, so one wrong endpoint (the quorum tolerates one) sets it out of reach and the worker waits
        forever. Use the endpoints that support the view (or a bounded value), as the rest of the worker does."""
        world = self.per_port(self.reorged())
        world.port_chain[3] = {'height': 10 ** 9}
        settler = self.settler(world)
        for _ in range(3):
            if settler.cycle():
                break
        self.assertEqual(self.local(), [G, A1[0]], 'one faulty endpoint stopped the recovery')


class DeadFork(ReviewTest):
    def test_doc_the_default_never_rebuilds_on_a_fork_whose_finality_is_stalled(self):
        """Passes (Q4, report 94): two endpoints on a dead fork that lacks settlement 2 and no longer finalizes
        (finalized height stuck far below the head) are a 2-of-3 view after a restart. The default gate waits."""
        world = self.reorged(finalized=True)
        world.chain = {'height': 9000, 'finalized_height': 2900}
        settler = self.settler(world)
        for _ in range(4):
            self.assertFalse(settler.cycle())
        self.assertFalse(self.rebuilt(world))

    def test_without_the_finality_wait_a_dead_fork_view_is_rebuilt_onto(self):
        """FAILS-AT-3401bef (Low, opt-in only). `wait_for_finality: false` (documented in SETTLER-RUNBOOK.md, accepted
        by the worker on every network kind) rebuilds after stable_seconds on any 2-of-3 view, including a dead
        fork whose finality is stalled; the worker then settles M+1 there (report 94's settler settled 6-8 on
        such a fork). The option should be refused on the mainnet path, or still require L1 finality to advance."""
        world = self.reorged(finalized=True)
        world.chain = {'height': 9000, 'finalized_height': 2900}
        settler = self.settler(world, reorg={'wait_for_finality': False})
        with mock.patch.object(settler, 'prove', return_value=None):
            for _ in range(4):
                settler.cycle()
        self.assertFalse(self.rebuilt(world), 'rebuilt onto a view whose L1 finality is stalled')


class Floor(ReviewTest):
    def test_a_real_reorg_with_one_endpoint_left_on_the_losing_fork_is_at_least_alerted(self):
        """FAILS-AT-3401bef (Medium). The worker that saw accepted 2 unanimously keeps accepted_floor = 2. A real
        L1 reorg back to 1, with one of the three endpoints stuck on the losing fork (report 94's nodes 0 and 1,
        the known sync defect), never forms a unanimous view: native_view returns None every cycle, so
        reorg_recovery never runs and never alerts (only rpc-quorum-view-behind). A restart (floor 0) would
        detect it at once, see test_doc_a_restart_detects_the_same_reorg."""
        world = self.per_port(self.reorged())
        world.foreign(2, A2)
        settler = self.settler(world)
        self.assertIsNotNone(settler.native_view())  # floor 2
        stuck = dict(world.accepted)
        world.foreign(1, A1)  # the reorg: ports 1 and 2 accept 1 again
        world.port_view[3] = lambda: {**world.view(), 'accepted': stuck}
        # Agent 206: with the fix the gates pass (M final, L1 final past first sight) and the worker rebuilds, then
        # builds the next block; the fake prover cannot prove it (world.values is empty), so proving is stubbed.
        with mock.patch.object(settler, 'prove', return_value=None):
            for _ in range(5):
                settler.cycle()
        self.assertIn('reorg-detected', self.alerts(), 'a real reorg went unnoticed by reorg_recovery')

    def test_doc_a_restart_detects_the_same_reorg(self):
        """Passes: the same world after a restart is detected and recovered (finality passed)."""
        world = self.per_port(self.reorged())
        stuck = {'statement': f.values_for(2, A2).hex(), 'commitment': f.PARENT_COMMITMENT}
        world.port_view[3] = lambda: {**world.view(), 'accepted': stuck}
        self.assertTrue(self.settler(world).cycle())
        self.assertEqual(self.local(), [G, A1[0]])


class StillValidSettlement(ReviewTest):
    def test_unchanged_request_resubmits_the_proved_next_block_instead_of_rebuilding(self):
        """FAILS-AT-3401bef (Medium). The native source anchor is set by the first block after M's acceptance
        (l2_settlement.rs prepare_source), so a reorg that removes the acceptance of M+1 but keeps M's leaves the
        request unchanged. The worker's own proved settlement of M+1 is then still valid on L1, and anyone holding
        its public bytes can land it. The recovery discards that proof (wasted_proofs) and re-proves a block
        instead; the stored bytes should be rebroadcast first."""
        world = self.reorged()
        tx = self.store_proved_block_2(world)
        world.next_block, world.values = B2, f.values_for(2, B2)
        # Agent 206, fixture: the base fake's sendrawtransaction accepts `world.values` whatever bytes were sent, here
        # a block 2 (B2) the worker never built, which the worker rightly treats as a foreign settlement (a halt
        # without foreign_recovery). L1 accepts the statement the bytes carry; model that.
        rpc = world.rpc

        def lands(port, method, params=()):
            answer = rpc(port, method, params)
            if method == 'sendrawtransaction' and not params[0].startswith('15'):
                sent = bytes.fromhex(params[0])
                world.accepted = {'statement': sent[33:33 + s.VALUES_BYTES].hex(), 'commitment': f.PARENT_COMMITMENT}
            return answer
        world.rpc = lands
        settler = self.settler(world)
        with mock.patch.object(settler, 'prove', return_value=None):
            for _ in range(3):
                settler.cycle()
        self.assertTrue(tx in world.sent, 'the still-valid settlement of block 2 was never rebroadcast')
        self.assertFalse(self.rebuilt(world))
        self.assertEqual(s.statement_fields(world.accepted['statement'])['l2_hash'], A2[0])
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-resubmitting', 'reorg-resolved'])

    def test_the_old_settlement_landing_after_a_rebuild_costs_a_second_rebuild(self):
        """FAILS-AT-3401bef (Medium, the loop question). After the automatic rebuild to M, the old settlement of
        M+1 (still valid, see above) lands. With foreign_recovery on (the installer sets it whenever the follower
        paths are given, which --reorg-recovery requires), the worker rebuilds a second time, after a second
        finality wait. Each such pair is one more reconstruct of the whole L2 and one more wasted proof."""
        world = self.reorged()
        self.store_proved_block_2(world)
        # Agent 206: since the M2 fix the worker first rebroadcasts these bytes instead of rebuilding. A rebuild
        # happens only when they have not landed within resubmit_window_seconds; 0 models that window having passed.
        settler = self.settler(world, recovery=True, reorg={'resubmit_window_seconds': 0})
        self.assertTrue(settler.cycle())  # rebuild 1 (3401bef)
        world.foreign(2, A2)  # someone rebroadcasts the old bytes
        world.l1 = [A1, A2]
        world.finalize(A1, A2)
        with mock.patch.object(settler, 'prove', return_value=None):
            for _ in range(3):
                settler.cycle()
        self.assertEqual(self.local()[:3], [G, A1[0], A2[0]])
        self.assertEqual(len(self.rebuilt(world)), 1, 'two full rebuilds for one reorg')


class History(ReviewTest):
    def test_an_unreadable_recovery_history_halts(self):
        """FAILS-AT-3401bef (Low). A damaged <l2_db>.reorg-recoveries.json raises JSONDecodeError: a retry, then
        exit 1 and a systemd restart, then the same again (each restart re-alerts reorg-detected). The limit file is
        the loop guard; when it cannot be read the worker should halt for the operator (exit 3)."""
        world = self.reorged()
        (self.root / 'db.reorg-recoveries.json').write_text('{not json')
        with self.assertRaises(s.Halt):
            self.settler(world).cycle()


class TransactionsKept(ReviewTest):
    def test_orphaned_paid_batch_transactions_are_back_in_the_main_spool(self):
        """Q3, passes: every transaction of every orphaned block (whose DA batch was paid) is in the main spool after
        the swap, with or without a higher paid batch being reserved."""
        world = self.reorged()
        world.block_txs = {2: base.batch(2), 3: base.batch(1)}
        self.assertTrue(self.settler(world, users=True).cycle())
        spool = {p.name for p in (self.root / 'txpool').glob('*.tx')}
        for payload in world.block_txs.values():
            for raw in s.da_batch_transactions(payload):
                self.assertIn(f'{s.keccak256(raw).hex()}.tx', spool)


del ReviewTest  # only the subclasses run

if __name__ == '__main__':
    unittest.main()
