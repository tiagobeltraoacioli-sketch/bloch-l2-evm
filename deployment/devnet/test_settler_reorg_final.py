#!/usr/bin/env python3
"""reorg_recovery after review 153 (agent 206, round 11): the fixed behaviour of M1, M2 and L1-L5, and the cases the
fixes must not open. Same fake world as test_settler_reorg (fake native RPC, producer and prover; real database
directories, so swaps are real).
Run: python3 -m unittest deployment/devnet/test_settler_reorg_final.py
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
TX_DIR = f'{2:08d}-{base.BLOCK[:16]}'


class FinalTest(r.ReorgTest):
    def per_port(self, world):
        world.port_view, world.port_chain, world.refuse = {}, {}, None
        rpc = world.rpc

        def split(port, method, params=()):
            if method == 'getl2settlement' and port in world.port_view:
                return world.port_view[port]()
            if method == 'sendrawtransaction' and world.refuse and not params[0].startswith('15'):
                world.sent.append(bytes.fromhex(params[0]))
                raise s.RpcError(world.refuse)
            answer = rpc(port, method, params)
            if method == 'getchaininfo' and port in world.port_chain:
                return {**answer, **world.port_chain[port]}
            return answer
        world.rpc = split
        return world

    def landing(self, world, lands=True):
        """sendrawtransaction of a settlement: L1 accepts the statement the bytes carry (or holds it pending)."""
        rpc = world.rpc

        def send(port, method, params=()):
            if method == 'sendrawtransaction' and not params[0].startswith('15'):
                tx = bytes.fromhex(params[0])
                world.sent.append(tx)
                if lands:
                    world.accepted = {'statement': tx[33:33 + s.VALUES_BYTES].hex(), 'commitment': f.PARENT_COMMITMENT}
                return {'status': 'accepted', 'tx_hash': '00' * 32}
            return rpc(port, method, params)
        world.rpc = send
        return world

    def store_proved_block_2(self, world, user_txs=0, payload=None):
        directory = self.root / 'work' / TX_DIR
        directory.mkdir(exist_ok=True)
        (directory / 'native-request.txt').write_text(s.Settler.request_text(world.view()))
        tx = bytes([s.ASYNC_SETTLEMENT_TAG]) + b'\x5a' * 32 + f.values_for(2, A2, user_txs, payload) + b'proof'
        (directory / 'transaction.bin').write_bytes(tx)
        return tx

    def settlements_sent(self, world):
        """Distinct settlement bytes sent (the kit broadcasts every transaction to every endpoint, 193 M2)."""
        return list(dict.fromkeys(t for t in world.sent if t[0] == s.ASYNC_SETTLEMENT_TAG))

    def broadcasts(self):
        found = [*self.root.glob(f'work/{TX_DIR}/submitted.json'), *self.root.glob(f'work-orphaned-*/{TX_DIR}/submitted.json')]
        return json.loads(found[0].read_text())['attempts']


# Do not re-run ReorgTest's own tests here.
for _name in [n for n in dir(r.ReorgTest) if n.startswith('test_')]:
    setattr(FinalTest, _name, None)


class Mainnet(FinalTest):
    def test_wait_for_finality_false_is_refused_on_the_mainnet_path(self):
        world = self.reorged()
        for kind in ('mainnet', 'mainnet-rehearsal'):
            with mock.patch.object(s, 'check_mainnet_config'), mock.patch.object(s, 'check_rehearsal_config'):
                with self.assertRaisesRegex(s.Halt, 'wait_for_finality false is refused on the mainnet path'):
                    self.settler(world, reorg={'wait_for_finality': False}, network_kind=kind)
                self.settler(world, network_kind=kind)  # the default (true) is accepted

    def test_new_keys_are_validated(self):
        world = self.reorged()
        for key, bad in (('resubmit_window_seconds', -1), ('max_finality_lag', 0), ('max_finality_lag', True)):
            with self.assertRaisesRegex(s.Halt, f'reorg_recovery.{key} must be'):
                self.settler(world, reorg={key: bad})


class BehindFloor(FinalTest):
    def floored(self):
        """Floor 2 seen unanimously; then ports 1 and 2 show accepted 1 (port 3 stays on accepted 2)."""
        world = self.per_port(self.reorged())
        world.foreign(2, A2)
        settler = self.settler(world, reorg={'stable_seconds': 60})
        self.assertIsNotNone(settler.native_view())
        stuck = dict(world.accepted)
        world.foreign(1, A1)
        world.port_view[3] = lambda: {**world.view(), 'accepted': stuck}
        return world, settler

    def test_a_behind_floor_view_never_builds_or_pays(self):
        world, settler = self.floored()
        with mock.patch.object(settler, 'prove', side_effect=AssertionError('proved on a behind-floor view')):
            for _ in range(5):
                self.assertFalse(settler.cycle())
        self.assertFalse([c for c in world.calls if 'extend' in c])
        self.assertFalse(world.sent)
        self.assertEqual(self.alerts(), ['reorg-detected'])
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])

    def test_two_stale_endpoints_below_the_floor_are_held_by_the_gates(self):
        """The floor's own case (two stale endpoints, not a restart): detected, never rebuilt, since their
        finalized height never passes the height at which the view was first seen."""
        world, settler = self.floored()
        settler.c['reorg_recovery']['stable_seconds'] = 0
        world.chain = {'height': 400, 'finalized_height': 300}
        world.port_chain[3] = {'height': 900, 'finalized_height': 899}
        for _ in range(5):
            self.assertFalse(settler.cycle())
        self.assertFalse(self.rebuilt(world))
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-waiting-finality'])

    def test_a_database_at_the_view_waits_as_before(self):
        world, settler = self.floored()
        world.write(self.root / 'db', [G, A1[0]])
        for _ in range(3):
            self.assertFalse(settler.cycle())
        self.assertFalse(self.alerts())
        self.assertTrue(self.events('reorg-behind-floor-waiting'))
        self.assertFalse([c for c in world.calls if 'extend' in c])

    def test_after_the_recovery_the_floor_follows_the_view(self):
        world, settler = self.floored()
        settler.c['reorg_recovery']['stable_seconds'] = 0
        with mock.patch.object(settler, 'prove', return_value=None):
            self.assertTrue(settler.cycle())
            self.assertEqual(self.local(), [G, A1[0]])
            world.next_block = B2
            settler.cycle()
        self.assertEqual(self.local(), [G, A1[0], B2[0]], 'the next block is built on the recovered view')
        self.assertEqual(settler.accepted_floor, 1)

    def test_off_the_option_a_behind_floor_view_is_still_ignored(self):
        world, settler = self.floored()
        settler.c.pop('reorg_recovery')
        for _ in range(3):
            self.assertFalse(settler.cycle())
        self.assertTrue(self.events('rpc-quorum-view-behind'))
        self.assertFalse([c for c in world.calls if c[1:2] in (['head'], ['extend'])])


class Resubmit(FinalTest):
    def test_landing_resolves_without_a_rebuild_or_a_proof(self):
        world = self.landing(self.reorged())
        tx = self.store_proved_block_2(world)
        settler = self.settler(world)
        with mock.patch.object(settler, 'prove', return_value=None) as prove:
            self.assertFalse(settler.cycle())
            self.assertEqual(self.settlements_sent(world), [tx])
            settler.cycle()
        self.assertFalse(self.rebuilt(world))
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertEqual(prove.call_args[0][0].name[:8], '00000003', 'block 3 is next, its old proof reused')
        self.assertEqual(self.alerts(), ['reorg-detected', 'reorg-resubmitting', 'reorg-resolved'])
        self.assertEqual(json.loads((self.root / 'work' / TX_DIR / 'submitted.json').read_text())['attempts'], 1)

    def test_pending_bytes_are_rebroadcast_at_the_resubmit_interval_then_the_window_ends(self):
        world = self.landing(self.reorged(), lands=False)
        tx = self.store_proved_block_2(world)
        settler = self.settler(world, reorg={'resubmit_window_seconds': 600}, resubmit_seconds=120)
        cycles = 0
        while not self.rebuilt(world):
            settler.cycle()
            cycles += 1
            self.assertLess(cycles, 400)
        sent = self.broadcasts()
        self.assertEqual(self.settlements_sent(world), [tx])
        self.assertGreater(sent, 1)
        self.assertLessEqual(sent, 600 // 120 + 1)
        self.assertTrue(all(t == tx for t in self.settlements_sent(world)))
        self.assertEqual(self.local(), [G, A1[0]])
        self.assertEqual(self.alerts()[:3], ['reorg-detected', 'reorg-resubmitting', 'reorg-resubmit-expired'])

    def test_a_terminal_refusal_ends_the_resubmission(self):
        world = self.per_port(self.reorged())
        world.refuse = {'code': s.TX_REFUSED, 'message': 'stale successor'}
        self.store_proved_block_2(world)
        settler = self.settler(world)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0]])
        self.assertIn('reorg-resubmit-refused', self.alerts())

    def test_a_changed_request_is_never_resubmitted(self):
        world = self.landing(self.reorged())
        self.store_proved_block_2(world)
        (self.root / 'work' / TX_DIR / 'native-request.txt').write_text('other request\n')
        self.assertTrue(self.settler(world).cycle())
        self.assertFalse(self.settlements_sent(world))
        self.assertEqual(self.local(), [G, A1[0]])

    def test_bytes_of_another_block_are_never_resubmitted(self):
        world = self.landing(self.reorged())
        self.store_proved_block_2(world)
        directory = self.root / 'work' / TX_DIR
        tx = bytes([s.ASYNC_SETTLEMENT_TAG]) + b'\x5a' * 32 + f.values_for(2, B2) + b'proof'
        (directory / 'transaction.bin').write_bytes(tx)
        self.assertTrue(self.settler(world).cycle())
        self.assertFalse(self.settlements_sent(world))

    def test_the_anchor_shape_is_never_resubmitted(self):
        world = self.landing(self.reorged())
        world.write(self.root / 'db', [G, A1[0], A2[0]])
        view = world.view
        world.view = lambda: {**view(), 'source': {**view()['source'], 'block': 'ab' * 32}}
        self.store_proved_block_2(world)
        self.assertTrue(self.settler(world).cycle())
        self.assertFalse(self.settlements_sent(world))

    def test_a_missing_da_record_is_published_before_the_bytes(self):
        payload = base.batch(2)
        world = self.landing(self.reorged())
        world.block_txs = {2: payload, 3: base.batch(1)}
        tx = self.store_proved_block_2(world, user_txs=2, payload=payload)
        settler = self.settler(world, users=True)
        settler.c['da']['attempt_window_seconds'] = 3000
        with mock.patch.object(settler, 'prove', return_value=None):
            settler.cycle()
        frames = list(dict.fromkeys(t for t in world.sent if t[0] == 0x15))
        self.assertEqual(len(frames), 1, 'the DA batch of block 2 published once')
        self.assertEqual(s.da_frame_fields(frames[0])[1:], (2, payload))
        self.assertEqual(self.settlements_sent(world), [tx])
        self.assertLess(world.sent.index(frames[0]), world.sent.index(tx))

    def test_a_partial_view_never_pays_da_for_a_resubmission(self):
        payload = base.batch(2)
        world = self.per_port(self.landing(self.reorged()))
        world.block_txs = {2: payload, 3: base.batch(1)}
        world.foreign(2, A2)
        settler = self.settler(world, users=True)
        self.assertIsNotNone(settler.native_view())
        stuck = dict(world.accepted)
        world.foreign(1, A1)
        world.port_view[3] = lambda: {**world.view(), 'accepted': stuck}
        self.store_proved_block_2(world, user_txs=2, payload=payload)
        settler.cycle()
        self.assertFalse([t for t in world.sent if t[0] == 0x15])
        self.assertFalse(self.settlements_sent(world))
        self.assertIn('reorg-resubmit-expired', self.alerts())


class Restore(FinalTest):
    def rebuilt_then_landed(self, **reorg):
        world = self.reorged()
        self.store_proved_block_2(world)
        settler = self.settler(world, recovery=True, reorg={'resubmit_window_seconds': 0, **reorg})
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0]])
        world.foreign(2, A2)
        world.l1 = [A1, A2]
        world.finalize(A1, A2)
        return world, settler

    def test_the_kept_database_and_its_work_come_back(self):
        world, settler = self.rebuilt_then_landed()
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertEqual(len(self.rebuilt(world)), 1)
        self.assertTrue((self.root / 'work' / f'{3:08d}-{base.BLOCK[:16]}' / 'proved.json').exists(), 'proof of 3 back')
        self.assertTrue((self.root / 'work' / TX_DIR / 'transaction.bin').exists())
        self.assertEqual(self.alerts()[-1], 'reorg-restored')
        generation = json.loads((self.root / 'l2-db-generation.json').read_text())
        self.assertEqual((generation['number'], generation['l2_hash']), (3, A3[0]))
        history = json.loads((self.root / 'db.reorg-recoveries.json').read_text())
        self.assertEqual([('restored' in h) for h in history], [False, True])

    def test_a_block_built_on_the_rebuild_is_respooled_and_moved_aside(self):
        world, settler = self.rebuilt_then_landed()
        world.write(self.root / 'db', [G, A1[0], B2[0]])
        directory = self.root / 'work' / TX_DIR
        directory.mkdir()
        (directory / 'proved.json').write_text('{"b2": true}')
        settler2 = self.settler(world, recovery=True, users=True, reorg={'resubmit_window_seconds': 0})
        world.block_txs = {2: base.batch(3)}
        self.assertTrue(settler2.cycle())
        self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])
        self.assertEqual(self.events('reorg-restored')[0]['orphaned_blocks'], [2])
        self.assertEqual(json.loads((directory / 'proved.json').read_text()), {}, 'A2 work restored, B2 work aside')
        aside = [p for p in self.root.glob('work-orphaned-*') if (p / TX_DIR / 'proved.json').exists()
                 and json.loads((p / TX_DIR / 'proved.json').read_text()) == {'b2': True}]
        self.assertEqual(len(aside), 1)
        spool = {p.name for p in (self.root / 'txpool').glob('*.tx')}
        for raw in s.da_batch_transactions(base.batch(3)):
            self.assertIn(f'{s.keccak256(raw).hex()}.tx', spool)

    def test_restores_count_against_the_limit(self):
        world, settler = self.rebuilt_then_landed(max_recoveries=1)
        with self.assertRaisesRegex(s.Halt, '1 automatic reorg recoveries'):
            settler.cycle()
        self.assertEqual(self.local(), [G, A1[0]])

    def test_without_a_kept_database_it_is_the_foreign_path_as_before(self):
        world, settler = self.rebuilt_then_landed()
        for kept in self.root.glob('db.orphaned-*'):
            import shutil
            shutil.rmtree(kept)
        with mock.patch.object(settler, 'prove', return_value=None):
            self.assertTrue(settler.cycle())
        self.assertEqual(len(self.rebuilt(world)), 2)
        self.assertTrue(self.events('foreign-settlement-recovered'))

    def test_off_the_option_a_kept_database_is_never_used(self):
        world, settler = self.rebuilt_then_landed()
        settler.c.pop('reorg_recovery')
        with mock.patch.object(settler, 'prove', return_value=None):
            settler.cycle()
        self.assertFalse(self.events('reorg-restored'))


class History(FinalTest):
    def test_a_history_of_the_wrong_shape_halts(self):
        world = self.reorged()
        for text in ('{"unix": 1}', '[1, 2]', '[{"accepted": 1}]'):
            (self.root / 'db.reorg-recoveries.json').write_text(text)
            with self.assertRaisesRegex(s.Halt, 'history .* is unreadable'):
                self.settler(world).cycle()
            self.assertEqual(self.local(), [G, A1[0], A2[0], A3[0]])

    def test_the_history_is_written_before_the_swap(self):
        world = self.reorged()
        settler = self.settler(world)
        with mock.patch.object(settler, 'finish_swap', side_effect=[None, KeyboardInterrupt('crash')]):
            with self.assertRaises(KeyboardInterrupt):
                settler.cycle()
        self.assertEqual(len(json.loads((self.root / 'db.reorg-recoveries.json').read_text())), 1)
        self.assertTrue(self.root.joinpath('db.recovery.json').exists(), 'the journal completes the swap on restart')
        self.settler(world).finish_swap()
        self.assertEqual(self.local(), [G, A1[0]])


class FinalityLag(FinalTest):
    def test_without_the_wait_a_live_fork_is_rebuilt_once_finality_catches_up(self):
        world = self.reorged(finalized=False)
        world.chain = {'height': 1000, 'finalized_height': 600}
        settler = self.settler(world, reorg={'wait_for_finality': False, 'max_finality_lag': 256})
        self.assertFalse(settler.cycle())
        self.assertIn('reorg-waiting-finality', self.alerts())
        world.chain['finalized_height'] = 800
        self.assertTrue(settler.cycle())


del FinalTest

if __name__ == '__main__':
    unittest.main()
