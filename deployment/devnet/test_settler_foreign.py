#!/usr/bin/env python3
"""Foreign settlements (security review 2026-10-30, F3): rebuild from L1 and continue, or halt when L1 cannot.

Fake native RPC, producer and prover; the database is a real directory, so swaps and crashes are real.
Run: python3 -m unittest deployment/devnet/test_settler_foreign.py
"""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as base  # noqa: E402

GENESIS_HASH = 'f0' * 32
PARENT_COMMITMENT = '99' * 32


def block(tag):
    return (tag * 32, (tag[0] + 'e') * 32)  # (hash, state root)


def values_for(number, entry, user_txs=0, payload=None):
    overrides = {'264': number.to_bytes(8, 'big'), '336': bytes.fromhex(entry[0]), '368': bytes.fromhex(entry[1])}
    if number > 1:
        overrides['224'] = bytes.fromhex(PARENT_COMMITMENT)
    if user_txs:
        overrides[str(s.DA_COMMITMENT)] = s.da_commitment(number, payload)
    return base.statement(user_txs=user_txs, **overrides)


class World(base.Fake):
    status_schema = 'v2'

    """The local database is `chain.json` in the real l2_db directory; `l1` is what a rebuild derives."""

    def __init__(self, root, values):
        super().__init__(root, values)
        self.db = root / 'db'
        self.db.mkdir()
        self.l1, self.status = [], root / 'status.json'
        self.finalize()
        self.write(self.db, [GENESIS_HASH])
        self.next_block, self.refuse_rebuild, self.block_txs = block('a1'), False, {}
        self.during_prove = None

    @staticmethod
    def write(path, chain):
        (path / 'chain.json').write_text(json.dumps(chain))

    def finalize(self, *entries):
        listed = [{'l2_number': i + 1, 'l2_hash': e[0]} for i, e in enumerate(entries)]
        if self.status_schema == 'v3':
            lines = [json.dumps(x).encode() + b'\n' for x in listed]
            self.status.with_name('status.settlements.jsonl').write_bytes(b''.join(lines))
            self.status.write_text(json.dumps({'finalized_settlements_recent': listed[-64:], 'settlement_log': {
                'file': 'status.settlements.jsonl', 'entries': len(lines), 'bytes': sum(map(len, lines)), 'digest': ''}}))
            return
        self.status.write_text(json.dumps({'finalized_settlements': listed}))

    def foreign(self, number, entry):
        self.accepted = {'statement': values_for(number, entry).hex(), 'commitment': PARENT_COMMITMENT}

    def run(self, argv, **kwargs):
        self.calls.append([str(a) for a in argv])
        if Path(argv[0]).name != 'produce':
            if 'prove-groth16' in argv and self.during_prove:
                self.during_prove()
            return super().run(argv, **kwargs)
        out, command = types.SimpleNamespace(returncode=0, stdout='', stderr=''), argv[1]
        target = Path(argv[argv.index('--target') + 1])
        chain = json.loads((target / 'chain.json').read_text()) if command != 'reconstruct' else None
        number = int(argv[argv.index('--number') + 1]) if '--number' in argv else None
        if command == 'head':
            out.stdout = json.dumps({'number': len(chain) - 1, 'hash': chain[-1]})
        elif command == 'extend':
            chain.append(self.next_block[0])
            self.write(target, chain)
            users = self.block_txs.get(len(chain) - 1)
            out.stdout = json.dumps({'number': len(chain) - 1, 'hash': chain[-1], 'deposits': 1,
                                     'transactions': s.da_batch_count(users) if users else 0, 'deferred': [], 'dropped': []})
        elif command == 'hash':
            out.stdout = json.dumps({'number': number, 'hash': chain[number]})
        elif command == 'export':
            Path(argv[argv.index('--out') + 1]).write_bytes(b'artifact')
            out.stdout = json.dumps({'number': number, 'hash': chain[number], 'anchor': base.BLOCK, 'bytes': 8})
        elif command == 'da':
            payload = self.block_txs.get(number)
            if not payload:
                out.returncode, out.stderr = 2, f'block {number} has no user transactions: nothing to publish'
            else:
                Path(argv[argv.index('--out') + 1]).write_text(payload.hex() + '\n')
                out.stdout = json.dumps({'number': number})
        elif command == 'reconstruct':
            if self.refuse_rebuild:
                target.mkdir()
                out.returncode, out.stderr = 2, 'L2 block 1: rebuilt hash x / state root y differ from settled'
                return out
            target.mkdir()
            self.write(target, [GENESIS_HASH, *[e[0] for e in self.l1]])
            blocks = [{'number': i + 1, 'hash': e[0], 'state_root': e[1]} for i, e in enumerate(self.l1)]
            out.stdout = json.dumps({'head': self.l1[-1][0] if self.l1 else None, 'blocks': blocks, 'native_blocks': 40})
        else:
            raise AssertionError(argv)
        return out


class ForeignTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name, data in (('bloch-evm-sp1-settlement-v3', b'prover'), ('settlement_v3', b'guest'),
                           ('l2-config.bin', base.CONFIG_BYTES), ('bloch-pos', b'signer'), ('da.pub', b'5a' * 3749)):
            (self.root / name).write_bytes(data)
        (self.root / 'txpool').mkdir()
        (self.root / 'home').mkdir()
        (self.root / 'work').mkdir()
        self.logged = mock.patch.object(s, 'log').start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.tmp.cleanup)

    def config(self, recovery=True, users=False, **extra):
        c = {'network': base.NETWORK, 'l2_genesis': GENESIS_HASH, 'rpc_ports': [1, 2, 3],
             'produce': str(self.root / 'produce'), 'l2_db': str(self.root / 'db'), 'workdir': str(self.root / 'work'),
             'home': str(self.root / 'home'), 'gnark_image': 'image', 'prover_threads': 8,
             'acceptance_timeout_seconds': 60, 'idle_seconds': 1, 'max_consecutive_failures': 3}
        for key, name in (('prover', 'bloch-evm-sp1-settlement-v3'), ('guest', 'settlement_v3'),
                          ('l2_config', 'l2-config.bin')):
            c[key] = str(self.root / name)
            c[key + '_sha256'] = s.digest(self.root / name)
        if recovery:
            c['foreign_recovery'] = {'follower_state': str(self.root / 'follower'),
                                     'follower_status': str(self.root / 'status.json')}
        if users:
            c.update(user_transactions=True, txpool_dir=str(self.root / 'txpool'), da={
                'signer': str(self.root / 'bloch-pos'), 'signer_sha256': s.digest(self.root / 'bloch-pos'),
                'genesis': 'g', 'funding_pubkey': str(self.root / 'da.pub'), 'keystore_dir': 'k', 'passphrase_file': 'p'})
        c.update(extra)
        return c

    def settler(self, world, **extra):
        clock = iter(range(0, 100_000, 3))
        return s.Settler(self.config(**extra), rpc=world.rpc, run=world.run, sleep=lambda _: None,
                         clock=lambda: next(clock))

    def events(self, name):
        return [c.kwargs for c in self.logged.call_args_list if c.args[0] == name]

    def local(self, name='db'):
        return json.loads((self.root / name / 'chain.json').read_text())

    def da_sent(self, world):
        return [t for t in world.sent if t[0] == s.DA_TAG]

    def lost_race(self, world, foreign=block('b1')):
        """The local block 1 was proved while a foreign block 1 was accepted."""
        def land():
            world.l1 = [foreign]
            world.foreign(1, foreign)
        world.during_prove = land
        world.values = values_for(1, world.next_block)

    def test_without_the_option_a_foreign_block_halts_and_changes_nothing(self):
        world = World(self.root, b'')
        self.lost_race(world)
        settler = self.settler(world, recovery=False)
        self.assertFalse(settler.cycle())  # the stale proof is not submitted
        with self.assertRaisesRegex(s.Halt, 'another settler'):
            settler.cycle()
        self.assertEqual(self.local(), [GENESIS_HASH, block('a1')[0]])
        self.assertEqual(world.sent, [])

    def test_waits_for_finality_then_rebuilds_and_continues(self):
        world = World(self.root, b'')
        self.lost_race(world)
        settler = self.settler(world)
        self.assertFalse(settler.cycle())
        self.assertEqual(world.sent, [], 'a stale proof is never submitted')
        self.assertFalse(settler.cycle())
        self.assertFalse(settler.cycle())
        self.assertEqual(len(self.events('foreign-settlement-waiting-finality')), 1, 'reported once')
        self.assertFalse([c for c in world.calls if 'reconstruct' in c], 'no rebuild before finality')
        world.finalize(block('b1'))
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [GENESIS_HASH, block('b1')[0]])
        recovered = self.events('foreign-settlement-recovered')[0]
        self.assertEqual((recovered['common_ancestor'], recovered['orphaned_blocks'], recovered['wasted_proofs']), (0, [1], 1))
        self.assertTrue((self.root / 'l2-db-generation.json').exists())
        aside = next(self.root.glob('work-orphaned-*'))
        self.assertTrue(next(aside.iterdir()).name.startswith('00000001-'))
        self.assertEqual(self.local(next(self.root.glob('db.orphaned-*')).name), [GENESIS_HASH, block('a1')[0]])
        # Continue: block 2 on top of the foreign block is proved and accepted with no operator.
        world.during_prove, world.next_block = None, block('a2')
        world.values = values_for(2, block('a2'))
        self.assertTrue(settler.cycle())
        self.assertEqual(s.statement_fields(world.accepted['statement'])['l2_number'], 2)
        self.assertEqual(self.local(), [GENESIS_HASH, block('b1')[0], block('a2')[0]])

    def test_status_schema_v3_waits_and_recovers_the_same_way(self):
        world = World(self.root, b'')
        world.status_schema = 'v3'
        world.finalize()
        self.lost_race(world)
        settler = self.settler(world)
        self.assertFalse(settler.cycle())
        self.assertFalse([c for c in world.calls if 'reconstruct' in c], 'no rebuild before finality')
        world.finalize(block('b1'))
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [GENESIS_HASH, block('b1')[0]])

    def test_follower_finals_reads_the_part_of_the_log_the_status_covers(self):
        world = World(self.root, b'')
        world.status_schema = 'v3'
        world.finalize(block('b1'), block('b2'))
        self.assertEqual(s.follower_finals(world.status), {1: block('b1')[0], 2: block('b2')[0]})
        log = world.status.with_name('status.settlements.jsonl')
        good = log.read_bytes()
        log.write_bytes(good + b'{"torn')
        self.assertEqual(len(s.follower_finals(world.status)), 2)
        log.write_bytes(good[:-4])
        with self.assertRaisesRegex(s.Halt, 'does not match'):
            s.follower_finals(world.status)

    def test_off_rule_block_halts_and_keeps_the_database(self):
        world = World(self.root, b'')
        self.lost_race(world)
        world.refuse_rebuild = True
        settler = self.settler(world)
        settler.cycle()
        world.finalize(block('b1'))
        with self.assertRaisesRegex(s.Halt, 'off-rule'):
            settler.cycle()
        self.assertEqual(self.local(), [GENESIS_HASH, block('a1')[0]])
        self.assertFalse((self.root / 'db.rebuilding').exists())

    def test_a_rebuild_behind_the_view_starts_over_and_keeps_the_database(self):
        world = World(self.root, b'')
        self.lost_race(world)
        settler = self.settler(world)
        settler.cycle()
        world.finalize(block('b1'))
        world.l1 = []
        self.assertFalse(settler.cycle())
        self.assertEqual(self.local(), [GENESIS_HASH, block('a1')[0]])
        self.assertFalse((self.root / 'db.rebuilding').exists())

    def test_a_finalized_settlement_that_differs_from_the_rebuild_halts(self):
        world = World(self.root, b'')
        world.l1 = [block('c1'), block('b2')]
        world.foreign(2, block('b2'))
        world.status.write_text(json.dumps({'finalized_settlements': [{'l2_number': 1, 'l2_hash': block('d1')[0]},
                                                                      {'l2_number': 2, 'l2_hash': block('b2')[0]}]}))
        with self.assertRaisesRegex(s.Halt, 'differ from the finalized'):
            self.settler(world).cycle()

    def test_two_foreign_blocks_past_a_local_head_rebuild_once(self):
        world = World(self.root, b'')
        world.l1 = [block('b1'), block('b2')]
        world.foreign(2, block('b2'))
        world.finalize(*world.l1)
        self.assertTrue(self.settler(world).cycle())
        self.assertEqual(self.local(), [GENESIS_HASH, block('b1')[0], block('b2')[0]])

    def test_foreign_block_equal_to_the_local_one_needs_no_rebuild(self):
        world = World(self.root, b'')
        same = block('a1')
        world.values = values_for(1, same)
        def land():
            world.l1 = [same]
            world.accepted = {'statement': world.values.hex(), 'commitment': PARENT_COMMITMENT}
        world.during_prove = land
        settler = self.settler(world)
        settler.cycle()
        world.during_prove, world.next_block = None, block('a2')
        world.values = values_for(2, block('a2'))
        self.assertTrue(settler.cycle())
        self.assertFalse([c for c in world.calls if 'reconstruct' in c])
        self.assertEqual(self.local(), [GENESIS_HASH, block('a1')[0], block('a2')[0]])

    def test_no_da_payment_for_a_block_that_went_stale_during_the_proof(self):
        payload = base.batch(2)
        world = World(self.root, b'')
        world.block_txs = {1: payload}
        self.lost_race(world)
        world.values = values_for(1, world.next_block, 2, payload)
        settler = self.settler(world, users=True)
        self.assertFalse(settler.cycle())
        self.assertEqual(self.da_sent(world), [], 'no DA for a stale block')
        world.finalize(block('b1'))
        self.assertTrue(settler.cycle())
        spool = sorted(p.read_text().strip() for p in (self.root / 'txpool').iterdir())
        self.assertEqual(spool, sorted(raw.hex() for raw in s.da_batch_transactions(payload)), 'orphaned transactions return')
        self.assertEqual(self.events('foreign-settlement-recovered')[0]['respooled'], 2)
        # The next block carries them and pays for one DA batch, once.
        world.during_prove, world.next_block = None, block('a2')
        world.block_txs = {2: payload}
        world.values = values_for(2, block('a2'), 2, payload)
        with mock.patch.object(s, 'da_commitment', lambda number, data, chain_id=s.CHAIN_ID:
                               s.keccak256(s.DA_DOMAIN + chain_id.to_bytes(8, 'big') + number.to_bytes(8, 'big') + data)):
            self.assertTrue(settler.cycle())
            self.assertEqual(len(self.da_sent(world)), 1)
            self.assertEqual(s.da_frame_fields(self.da_sent(world)[0])[1], 2)

    def test_foreign_block_after_the_da_payment_counts_it_and_never_repays_it(self):
        payload = base.batch(1)
        world = World(self.root, b'')
        world.block_txs = {1: payload}
        world.values = values_for(1, world.next_block, 1, payload)
        settler = self.settler(world, users=True)
        real = world.rpc
        foreign = block('b1')
        def rpc(port, method, params=()):
            answer = real(port, method, params)
            if method == 'sendrawtransaction' and params[0].startswith('15'):
                world.l1 = [foreign]
                world.foreign(1, foreign)
            return answer
        settler.native.rpc = rpc
        self.assertFalse(settler.cycle())
        self.assertEqual(len(self.da_sent(world)), 1)
        world.finalize(foreign)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.events('foreign-settlement-recovered')[0]['wasted_da_signed'], 1)
        self.assertEqual(len(self.da_sent(world)), 1, 'the orphaned batch is not paid again')
        self.assertEqual(len(list((self.root / 'txpool').iterdir())), 1)

    def test_da_wait_ends_when_a_foreign_block_settles_that_number(self):
        payload = base.batch(1)
        world = World(self.root, b'')
        world.block_txs = {1: payload}
        world.include_da = False
        world.values = values_for(1, world.next_block, 1, payload)
        settler = self.settler(world, users=True)
        real, foreign = world.rpc, block('b1')
        def rpc(port, method, params=()):
            answer = real(port, method, params)
            if method == 'sendrawtransaction' and params[0].startswith('15'):
                world.foreign(1, foreign)
            return answer
        settler.native.rpc = rpc
        self.assertFalse(settler.cycle())
        self.assertEqual(len(self.events('da-wait-ended-block-settled')), 1)
        self.assertEqual(self.events('da-inclusion-timeout'), [])

    def test_a_local_block_on_a_replaced_parent_is_not_reused(self):
        world = World(self.root, b'')
        world.write(world.db, [GENESIS_HASH, block('a1')[0], block('a2')[0]])
        world.l1 = [block('b1')]
        world.foreign(1, block('b1'))
        world.finalize(block('b1'))
        self.assertTrue(self.settler(world).cycle())
        self.assertEqual(self.local(), [GENESIS_HASH, block('b1')[0]])
        self.assertEqual(self.events('foreign-settlement-recovered')[0]['orphaned_blocks'], [1, 2])

    def test_a_crash_at_any_step_of_the_swap_resumes(self):
        for crash in ('after-journal', 'after-old-moved', 'after-swap'):
            with self.subTest(crash=crash), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp)
                for name, data in (('bloch-evm-sp1-settlement-v3', b'prover'), ('settlement_v3', b'guest'),
                                   ('l2-config.bin', base.CONFIG_BYTES)):
                    (self.root / name).write_bytes(data)
                (self.root / 'work').mkdir()
                (self.root / 'work/00000001-aa').mkdir()
                world = World(self.root, b'')
                world.foreign(1, block('b1'))
                rebuilt, kept = self.root / 'db.rebuilt-5', self.root / 'db.orphaned-5'
                rebuilt.mkdir()
                world.write(rebuilt, [GENESIS_HASH, block('b1')[0]])
                (self.root / 'db.recovery.json').write_text(json.dumps({
                    'rebuilt': str(rebuilt), 'kept': str(kept), 'work_aside': str(self.root / 'work-orphaned-5'),
                    'stale': ['00000001-aa'], 'number': 1, 'l2_hash': block('b1')[0]}))
                if crash != 'after-journal':
                    (self.root / 'db').rename(kept)
                if crash == 'after-swap':
                    rebuilt.rename(self.root / 'db')
                settler = self.settler(world)
                settler.finish_swap()
                self.assertEqual(self.local(), [GENESIS_HASH, block('b1')[0]])
                self.assertTrue(kept.exists())
                self.assertTrue((self.root / 'work-orphaned-5/00000001-aa').exists())
                self.assertFalse((self.root / 'db.recovery.json').exists())

    def test_old_databases_are_pruned_so_griefing_cannot_fill_the_disk(self):
        world = World(self.root, b'')
        for stamp in (1, 2, 3):
            (self.root / f'db.orphaned-{stamp}').mkdir()
            (self.root / f'work-orphaned-{stamp}').mkdir()
        world.foreign(1, block('b1'))
        world.l1 = [block('b1')]
        world.finalize(block('b1'))
        world.write(world.db, [GENESIS_HASH])
        self.settler(world).cycle()
        self.assertEqual(len(list(self.root.glob('db.orphaned-*'))), 2)
        self.assertEqual(len(list(self.root.glob('work-orphaned-*'))), 2)

    def test_recovery_configuration_is_checked(self):
        world = World(self.root, b'')
        with self.assertRaisesRegex(s.Halt, 'foreign_recovery needs'):
            self.settler(world, foreign_recovery={'follower_state': 'x'})

    def test_dry_run_never_recovers(self):
        world = World(self.root, b'')
        settler = self.settler(world)
        settler.dry_run = True
        with self.assertRaisesRegex(s.Halt, 'another'):
            settler.recover_foreign('another settler')


if __name__ == '__main__':
    unittest.main()
