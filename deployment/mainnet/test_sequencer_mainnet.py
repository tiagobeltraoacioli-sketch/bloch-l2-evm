#!/usr/bin/env python3
"""Unit tests for sequencer_mainnet.py with a fake native RPC and producer.

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_*.py' -v
No network and no binary: every external call is a stub.
"""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sequencer_mainnet as q  # noqa: E402

SOURCE_BLOCK = '618c9b80cebda5b5bda0b0c7d79e19dae8dc24e773aa94a2c135eb805ff0dc9f'
SLOT = 187200
PENDING = [{'height': 3, 'tx_index': 0, 'txid': '11' * 32, 'vout': 1, 'sats': 5000, 'recipient': '42' * 20}]


def request(block=SOURCE_BLOCK, slot=SLOT, height=1):
    return f'{q.NATIVE_NETWORK}\n{q.NATIVE_GENESIS}\n{block}\n{slot}\n{height}\n{"ce" * 32}\n{"ae" * 32}\n'


def view(accepted=None, pending=(), **over):
    v = {'network': q.NATIVE_NETWORK, 'genesis': q.NATIVE_GENESIS, 'chain_id': q.CHAIN_ID, 'asynchronous': True,
         'profile': {'activated': True, 'deposits': True, 'user_transactions': True}, 'accepted': accepted,
         'native_height': 2797,
         'source': {'block': SOURCE_BLOCK, 'slot': SLOT, 'height': 1, 'commitment': 'ce' * 32, 'inbox_root': 'ae' * 32,
                    'inbox_count': len(pending), 'consumed_start': 0, 'consumed_end': len(pending),
                    'pending': list(pending), 'request': request()}}
    v.update(over)
    return v


def statement(number, l2_hash, chain_id=q.CHAIN_ID):
    s = bytearray(766)
    s[:q.T] = q.TAG
    s[q.T + 256:q.T + 264] = chain_id.to_bytes(8, 'big')
    s[q.T + 264:q.T + 272] = number.to_bytes(8, 'big')
    s[q.T + 336:q.T + 368] = bytes.fromhex(l2_hash)
    return s.hex()


def batch(n):
    return n.to_bytes(4, 'big') + b''.join((2).to_bytes(4, 'big') + bytes([2, i]) for i in range(n))


class FakeProducer:
    """Models the canonical database: a list of (hash, anchor, timestamp)."""

    def __init__(self, txs=0):
        self.chain = [{'hash': q.L2_GENESIS_HASH, 'state_root': q.L2_GENESIS_STATE, 'anchor': None, 'timestamp': q.L2_GENESIS_TIME}]
        self.calls, self.txs = [], txs

    def __call__(self, argv, **_):
        args = argv[1:]
        assert args[-6:] == q.NETWORK_ARGS, args
        cmd, opts = args[0], dict(zip(args[1:-6:2], args[2:-6:2]))
        self.calls.append(cmd)
        out = getattr(self, cmd)(opts)
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr='')

    def head(self, _):
        tip = self.chain[-1]
        return {'number': len(self.chain) - 1, 'hash': tip['hash'], 'state_root': tip['state_root'],
                'withdrawal_root': '00' * 32, 'withdrawal_count': 0}

    def extend(self, o):
        assert o['--timestamp-rule'] == q.TIMESTAMP_RULE
        parent = self.chain[-1]
        assert o['--parent'] == parent['hash']
        number = len(self.chain)
        ts = max(parent['timestamp'] + 1, q.l1_slot_time(int(o['--anchor-slot'])))
        deposits = json.loads(Path(o['--deposits']).read_text())
        txs = self.txs if '--txs' in o else 0
        self.chain.append({'hash': f'{number:02x}' * 32, 'state_root': f'{number + 0x80:02x}' * 32,
                           'anchor': o['--anchor'], 'timestamp': ts})
        return {'number': number, 'hash': self.chain[-1]['hash'], 'state_root': self.chain[-1]['state_root'],
                'parent': parent['hash'], 'anchor': o['--anchor'], 'timestamp': ts, 'deposits': len(deposits),
                'transactions': txs, 'withdrawal_root': '00' * 32, 'withdrawal_count': 0}

    def export(self, o):
        n = int(o['--number'])
        Path(o['--out']).write_bytes(b'artifact-%d' % n)
        return {'number': n, 'hash': self.chain[n]['hash'], 'anchor': self.chain[n]['anchor'], 'bytes': 10}

    def da(self, o):
        n = int(o['--number'])
        Path(o['--out']).write_text(batch(self.txs).hex() + '\n')
        return {'number': n, 'chain_id': q.CHAIN_ID, 'transactions': self.txs}

    def init(self, o):
        Path(o['--target']).mkdir()
        return {'number': 0, 'hash': q.L2_GENESIS_HASH}


class Rpc:
    def __init__(self, *views):
        self.views = list(views)

    def __call__(self, url, method, params, timeout):
        assert method == 'getl2settlement'
        v = self.views[self.urls.index(url)]
        if isinstance(v, Exception):
            raise v
        return v


class SequencerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        binary = root / 'produce'
        binary.write_bytes(b'pinned')
        self.config = {'produce': str(binary), 'produce_sha256': q.digest(binary), 'l2_db': str(root / 'db'),
                       'workdir': str(root / 'work'), 'rpc_urls': ['http://a', 'http://b', 'http://c']}
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, views, producer=None, clock=lambda: q.l1_slot_time(SLOT) + 3600, **config):
        rpc = Rpc(*views)
        rpc.urls = self.config['rpc_urls']
        producer = producer or FakeProducer()
        seq = q.Sequencer({**self.config, **config}, rpc=rpc, run=producer, clock=clock)
        return seq, producer, rpc

    def test_block_one_on_the_frozen_activation_source(self):
        seq, producer, _ = self.make([view()] * 3)
        job = seq.step()
        self.assertEqual((job['number'], job['parent'], job['anchor'], job['anchor_slot']),
                         (1, q.L2_GENESIS_HASH, SOURCE_BLOCK, SLOT))
        self.assertEqual(job['timestamp'], 1792272679)  # 2026-10-17 21:31:19 UTC, slot 187200
        d = Path(job['directory'])
        self.assertEqual(d.name, f'00000001-{SOURCE_BLOCK[:16]}')
        self.assertEqual((d / 'native-request.txt').read_text(), request() + '0' * 64 + '\n0\n0\n0\n')
        self.assertEqual((d / 'deposits.json').read_text(), '[]')
        self.assertIsNone(job['da'])
        # Idempotent: a second step only re-reads the head.
        producer.calls.clear()
        self.assertEqual(seq.step(), job)
        self.assertEqual(producer.calls, ['head'])

    def test_deposits_are_minted_and_follow_the_accepted_head(self):
        producer = FakeProducer()
        seq, _, rpc = self.make([view()] * 3, producer)
        first = seq.step()
        accepted = {'statement': statement(1, first['hash']), 'commitment': '77' * 32}
        nxt = view(accepted, PENDING)
        nxt['source'].update(block='dd' * 32, slot=SLOT + 40, height=41, request=request('dd' * 32, SLOT + 40, 41))
        rpc.views = [nxt] * 3
        job = seq.step()
        self.assertEqual((job['number'], job['parent'], job['deposits']), (2, first['hash'], 1))
        self.assertEqual(job['timestamp'], q.l1_slot_time(SLOT + 40))
        d = Path(job['directory'])
        self.assertEqual(json.loads((d / 'deposits.json').read_text()), PENDING)
        self.assertTrue((d / 'native-request.txt').read_text().endswith('77' * 32 + '\n1\n0\n1\n'))

    def test_an_unsettled_block_is_rewound_when_l1_moves_the_program(self):
        class Swap(FakeProducer):
            rules = {}

            def head(self, o):
                return {**super().head(o), 'rules': self.rules.get(len(self.chain) - 1, 'base')}

            def extend(self, o):
                out = super().extend(o)
                self.rules[out['number']] = o['--rule-set']
                return {**out, 'rules': o['--rule-set']}

            def rewind(self, o):
                assert int(o['--number']) == len(self.chain) - 1 and o['--hash'] == self.chain[-1]['hash']
                self.chain.pop()
                return {'number': len(self.chain) - 1}

        producer = Swap()
        seq, _, rpc = self.make([view()] * 3, producer, next_elf_keccak='ab' * 32)
        old = seq.step()
        self.assertEqual(producer.rules[1], 'base')
        moved = {**view(), 'program': {'elf_keccak': 'ab' * 32}}
        rpc.views = [moved] * 3
        producer.calls.clear()
        job = seq.step()
        self.assertIn('rewind', producer.calls)
        self.assertEqual(producer.rules[1], 'next')
        self.assertEqual(job['number'], 1)
        kept = [p for p in Path(old['directory']).parent.iterdir() if '.superseded-' in p.name]
        self.assertEqual(len(kept), 1)
        # The next step reuses the block under the next rules.
        producer.calls.clear()
        self.assertEqual(seq.step()['hash'], job['hash'])
        self.assertNotIn('rewind', producer.calls)

    def test_minority_views_are_never_used(self):
        bad = view(network='00' * 32)
        seq, producer, _ = self.make([view(), bad, RuntimeError('down')])
        self.assertIsNone(seq.step())
        self.assertEqual(producer.calls, [])
        seq, _, _ = self.make([view(), view(), bad])
        self.assertEqual(seq.step()['number'], 1)
        seq, _, _ = self.make([bad, bad, view()])
        with self.assertRaisesRegex(q.Halt, 'Genesis-4'):
            seq.step()

    def test_identity_and_profile_are_checked(self):
        for over, msg in (({'chain_id': 700771}, 'chain 700770'), ({'asynchronous': False}, 'chain 700770'),
                          ({'profile': {'activated': False, 'deposits': True}}, 'activated')):
            seq, _, _ = self.make([view(**over)] * 3)
            with self.assertRaisesRegex(q.Halt, msg):
                seq.step()

    def test_head_ahead_or_off_parent_halts(self):
        producer = FakeProducer()
        seq, _, rpc = self.make([view()] * 3, producer)
        seq.step()
        # The native chain now names a different source for block 1 (L1 reorg): never overwrite.
        moved = view()
        moved['source'].update(block='dd' * 32, request=request('dd' * 32))
        rpc.views = [moved] * 3
        with self.assertRaisesRegex(q.Halt, 'differs from what the native chain now requests|missing'):
            seq.step()
        # Accepted head that is not our block 1.
        rpc.views = [view({'statement': statement(1, 'ab' * 32), 'commitment': '77' * 32})] * 3
        with self.assertRaisesRegex(q.Halt, 'not the accepted parent'):
            seq.step()

    def test_pending_must_match_the_consumed_range(self):
        v = view(pending=PENDING)
        v['source']['consumed_end'] = 2
        seq, _, _ = self.make([v] * 3)
        with self.assertRaisesRegex(q.Halt, 'consumed range'):
            seq.step()

    def test_request_must_match_the_source(self):
        v = view()
        v['source']['request'] = request(slot=SLOT + 1)
        seq, _, _ = self.make([v] * 3)
        with self.assertRaisesRegex(q.Halt, 'does not match its source'):
            seq.step()

    def test_future_source_slot_means_a_bad_clock(self):
        seq, _, _ = self.make([view()] * 3, clock=lambda: q.l1_slot_time(SLOT) - 600)
        with self.assertRaisesRegex(q.Halt, 'future'):
            seq.step()

    def test_user_transactions_export_the_da_batch(self):
        pool = self.root / 'pool'
        pool.mkdir()
        producer = FakeProducer(txs=3)
        seq, _, _ = self.make([view()] * 3, producer, user_transactions=True, txpool_dir=str(pool))
        job = seq.step()
        payload = batch(3)
        self.assertEqual(job['transactions'], 3)
        self.assertEqual(job['da']['commitment'], q.da_commitment(1, payload).hex())
        self.assertEqual(job['da']['payload_bytes'], len(payload))

    def test_user_transactions_off_refuses_a_block_with_transactions(self):
        producer = FakeProducer(txs=2)
        producer.extend_orig = producer.extend
        producer.extend = lambda o: {**producer.extend_orig(o), 'transactions': 2}
        seq, _, _ = self.make([view()] * 3, producer)
        with self.assertRaisesRegex(q.Halt, 'user_transactions is false'):
            seq.step()

    def test_configuration_guards(self):
        with self.assertRaisesRegex(q.Halt, 'pin'):
            q.Sequencer({**self.config, 'produce_sha256': '00' * 32})
        with self.assertRaisesRegex(q.Halt, 'strict majority'):
            q.Sequencer({**self.config, 'rpc_quorum': 1})
        with self.assertRaisesRegex(q.Halt, 'txpool_dir'):
            q.Sequencer({**self.config, 'user_transactions': True})
        pool = self.root / 'pool'
        pool.mkdir()
        with self.assertRaisesRegex(q.Halt, 'max_block_bytes'):
            q.Sequencer({**self.config, 'user_transactions': True, 'txpool_dir': str(pool), 'max_block_bytes': 200_000})

    def test_init_checks_the_pinned_genesis(self):
        seq, producer, _ = self.make([view()] * 3)
        self.assertEqual(seq.init()['hash'], q.L2_GENESIS_HASH)
        with self.assertRaisesRegex(q.Halt, 'already exists'):
            seq.init()
        producer.chain[0]['state_root'] = '00' * 32
        Path(self.config['l2_db']).rmdir()
        with self.assertRaisesRegex(q.Halt, 'pinned mainnet genesis'):
            seq.init()

    def test_single_writer_lock(self):
        import fcntl
        seq, _, _ = self.make([view()] * 3)
        Path(self.config['workdir']).mkdir()
        with open(Path(self.config['workdir']) / '.sequencer.lock', 'w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with self.assertRaisesRegex(q.Halt, 'lock'):
                seq.step()

    def test_keccak_and_timestamp_constants(self):
        self.assertEqual(q.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(q.TIMESTAMP_RULE, '1:1786656679:30000')
        self.assertEqual(q.l1_slot_time(187200), 1792272679)

    # ---- shadow mode: the settler produces, the shadow rebuilds and compares ----
    def settler_dir(self, number=1, block=SOURCE_BLOCK):
        d = self.root / 'settler-work' / f'{number:08d}-{block[:16]}'
        d.mkdir(parents=True, exist_ok=True)
        return d

    def reference(self, txs=0):
        """What an honest settler (same deterministic producer) writes for block 1."""
        ref = FakeProducer(txs=txs)
        deposits = self.root / 'ref-deposits.json'
        deposits.write_text('[]')
        opts = {'--parent': q.L2_GENESIS_HASH, '--anchor': SOURCE_BLOCK, '--anchor-slot': str(SLOT),
                '--deposits': str(deposits), '--timestamp-rule': q.TIMESTAMP_RULE}
        if txs:
            opts['--txs'] = 'x'
        return ref.extend(opts)

    def test_shadow_waits_for_the_settler_then_matches(self):
        seq, producer, _ = self.make([view()] * 3, settler_workdir=str(self.root / 'settler-work'))
        self.assertIsNone(seq.step())
        self.assertNotIn('extend', producer.calls)
        (self.settler_dir() / 'block.json').write_text(json.dumps(self.reference()))
        job = seq.step()
        self.assertEqual((job['status'], job['number']), ('shadow-matched', 1))

    def test_shadow_halts_on_a_divergent_settler_block(self):
        seq, _, _ = self.make([view()] * 3, settler_workdir=str(self.root / 'settler-work'))
        bad = {**self.reference(), 'state_root': '99' * 32}
        (self.settler_dir() / 'block.json').write_text(json.dumps(bad))
        with self.assertRaisesRegex(q.Halt, r"differs from the independent rebuild in \['state_root'\]"):
            seq.step()

    def test_shadow_replays_the_settler_da_transactions(self):
        producer = FakeProducer(txs=2)
        seen = {}
        orig = producer.extend
        def extend(o):
            seen['txs'] = json.loads(Path(o['--txs']).read_text())
            self.assertNotIn('--max-gas', o)
            return orig(o)
        producer.extend = extend
        seq, _, _ = self.make([view()] * 3, producer, settler_workdir=str(self.root / 'settler-work'))
        d = self.settler_dir()
        (d / 'block.json').write_text(json.dumps(self.reference(txs=2)))
        self.assertIsNone(seq.step())  # DA batch not written yet: wait, do not halt
        (d / 'da-payload.hex').write_text(batch(2).hex() + '\n')
        job = seq.step()
        self.assertEqual(seen['txs'], ['0200', '0201'])
        self.assertEqual(job['da']['commitment'], q.da_commitment(1, batch(2)).hex())

    def test_shadow_configuration_guards(self):
        with self.assertRaisesRegex(q.Halt, 'leave user_transactions false'):
            q.Sequencer({**self.config, 'settler_workdir': '/x', 'user_transactions': True,
                         'txpool_dir': str(self.root)})
        with self.assertRaisesRegex(q.Halt, 'must not be the shadow workdir'):
            q.Sequencer({**self.config, 'settler_workdir': self.config['workdir']})



# ---- program schedule: the shadow across the swap and the rollback (agent 218) ----
NEXT_ELF = '1f744da8d3e0302cd39152e24e91071d7f0cfec7639245566a471cd6083a6b18'      # sparse PROGRAM_NEXT (forced, bc35e838)
FALLBACK_ELF = 'd95185a60668b0d4e1da49be00d85b9c550b412f13c5155be454e72889f90bf1'  # complete PROGRAM_FALLBACK (forced, 7fd7f3c0)
ACTIVATED_ELF = '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073'
GATE = 6000                      # swap epoch; gate slot 192000
ROLLBACK = 6100
LEAD_SLOTS = 60                  # 1800 s at 30 s slots
INSIDE = GATE * 32 - LEAD_SLOTS  # first L1 slot whose landing epoch is the gate
OUTSIDE = INSIDE - 1


class RuleProducer(FakeProducer):
    """FakeProducer with rule sets: a next-rules block has another hash, the switch is kept by the database, and
    rewind drops the head. A producer that ignores --rule-set (ignore=True) models a mis-pinned binary."""

    def __init__(self, ignore=False):
        super().__init__()
        self.rules, self.switched, self.ignore, self.rewound = {}, None, ignore, []

    def head(self, o):
        n = len(self.chain) - 1
        return {**super().head(o), 'rules': self.rules.get(n, 'base')}

    def extend(self, o):
        number = len(self.chain)
        wanted = 'base' if self.ignore else o.get('--rule-set', 'next' if self.switched and number >= self.switched else 'base')
        if wanted == 'base' and self.switched is not None and number >= self.switched:
            raise AssertionError('--rule-set base after the switch')
        if wanted == 'next' and self.switched is None:
            self.switched = number
        out = super().extend(o)
        if wanted == 'next':
            tip = self.chain[-1]
            tip['hash'], tip['state_root'] = f'{number + 0x40:02x}' * 32, f'{number + 0xc0:02x}' * 32
            out.update(hash=tip['hash'], state_root=tip['state_root'])
        self.rules[number] = wanted
        return {**out, 'rules': wanted}

    def rewind(self, o):
        assert int(o['--number']) == len(self.chain) - 1 and o['--hash'] == self.chain[-1]['hash']
        self.rewound.append(self.chain.pop()['hash'])
        self.rules.pop(len(self.chain), None)
        return {'number': len(self.chain) - 1}


class ScheduleRpc(Rpc):
    def __init__(self, *views, slots=None):
        super().__init__(*views)
        self.slots = slots

    def __call__(self, url, method, params, timeout):
        if method == 'getchaininfo':
            slot = self.slots[self.urls.index(url)]
            if isinstance(slot, Exception):
                raise slot
            return {'slot': slot}
        return super().__call__(url, method, params, timeout)


def program(elf):
    return {'configuration': '97' * 32, 'elf_keccak': elf, 'vkey_koalabear': '79' * 32, 'vkey_bn254': '00' * 32,
            'proof_policy': '15' * 32}


def schedule_view(held=ACTIVATED_ELF, schedule=((GATE, NEXT_ELF),), **over):
    v = view(program=program(held), program_schedule=[{'epoch': e, **program(elf)} for e, elf in schedule])
    v.update(over)
    return v


class ShadowScheduleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        binary = self.root / 'produce'
        binary.write_bytes(b'pinned')
        self.config = {'produce': str(binary), 'produce_sha256': q.digest(binary), 'l2_db': str(self.root / 'db'),
                       'workdir': str(self.root / 'work'), 'rpc_urls': ['http://a', 'http://b', 'http://c'],
                       'settler_workdir': str(self.root / 'settler-work'), 'next_elf_keccak': NEXT_ELF,
                       'fallback_elf_keccak': FALLBACK_ELF}
        self.settler = RuleProducer()  # the settler's own database (an honest, deterministic producer)
        self.settler_deposits = self.root / 'settler-deposits.json'
        self.settler_deposits.write_text('[]')

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, v, slot, producer=None, **config):
        rpc = ScheduleRpc(*([v] * 3), slots=slot if isinstance(slot, list) else [slot] * 3)
        rpc.urls = self.config['rpc_urls']
        producer = producer or RuleProducer()
        seq = q.Sequencer({**self.config, **config}, rpc=rpc, run=producer, clock=lambda: q.l1_slot_time(SLOT) + 3600)
        return seq, producer, rpc

    def settler_dir(self):
        return self.root / 'settler-work' / f'00000001-{SOURCE_BLOCK[:16]}'

    def settler_builds(self, rules):
        """The settler extends its database by block 1 under `rules` (rewinding a base head first, as at the swap)
        and writes block.json in a fresh work directory, superseding the old one."""
        if len(self.settler.chain) == 2:
            self.settler.rewind({'--number': '1', '--hash': self.settler.chain[1]['hash']})
        block = self.settler.extend({'--parent': q.L2_GENESIS_HASH, '--anchor': SOURCE_BLOCK, '--anchor-slot': str(SLOT),
                                     '--deposits': str(self.settler_deposits), '--timestamp-rule': q.TIMESTAMP_RULE,
                                     '--rule-set': rules})
        d = self.settler_dir()
        if d.exists():
            d.rename(d.with_name(f'{d.name}.superseded-{len(list(d.parent.iterdir()))}'))
        d.mkdir(parents=True)
        (d / 'block.json').write_text(json.dumps(block))
        (d / 'program.json').write_text(json.dumps({'name': 'next' if rules == 'next' else 'base'}))
        return block

    # -- the fix: a block built for the next program just before the gate is rebuilt under the next rules
    def test_a_next_rules_block_built_inside_the_window_is_matched_not_halted(self):
        built = self.settler_builds('next')
        seq, producer, _ = self.make(schedule_view(), INSIDE)
        job = seq.step()
        self.assertEqual((job['status'], job['hash'], job['rules']), ('shadow-matched', built['hash'], 'next'))
        self.assertEqual(producer.rules[1], 'next')

    def test_the_old_shadow_halted_on_the_same_block(self):
        """Regression evidence: the d462647 rule (L1's current program only) rebuilds it under the base rules."""
        self.settler_builds('next')
        seq, _, _ = self.make(schedule_view(), INSIDE)
        seq.shadow_rules = lambda view, number, block: seq.rules_held(view)  # the d462647 selection
        with self.assertRaisesRegex(q.Halt, r"differs from the independent rebuild in \['hash', 'state_root', 'rules'\]"):
            seq.step()

    def test_one_slot_before_the_window_the_shadow_waits_and_then_matches(self):
        built = self.settler_builds('next')
        seq, producer, rpc = self.make(schedule_view(), OUTSIDE)
        self.assertIsNone(seq.step())
        self.assertNotIn('extend', producer.calls)
        rpc.slots = [INSIDE] * 3
        self.assertEqual(seq.step()['hash'], built['hash'])

    def test_a_next_rules_block_with_no_gate_scheduled_halts(self):
        self.settler_builds('next')
        seq, _, _ = self.make(schedule_view(schedule=()), INSIDE)
        with self.assertRaisesRegex(q.Halt, 'which L1 does not justify'):
            seq.step()

    def test_before_the_window_a_base_block_matches_as_before(self):
        built = self.settler_builds('base')
        seq, producer, _ = self.make(schedule_view(), OUTSIDE)
        job = seq.step()
        self.assertEqual((job['hash'], job['rules']), (built['hash'], 'base'))
        self.assertEqual(producer.rules[1], 'base')

    def test_the_swap_rebuild_is_followed_rewound_and_matched_again(self):
        old = self.settler_builds('base')
        seq, producer, rpc = self.make(schedule_view(), OUTSIDE)
        self.assertEqual(seq.step()['hash'], old['hash'])
        rpc.slots = [INSIDE] * 3          # the window opens: the settler rewinds and rebuilds under the next rules
        new = self.settler_builds('next')
        job = seq.step()
        self.assertEqual((job['hash'], job['rules']), (new['hash'], 'next'))
        self.assertEqual(producer.rewound, [old['hash']])
        self.assertEqual(len([p for p in Path(self.config['workdir']).iterdir() if '.superseded-' in p.name]), 1)
        producer.calls.clear()
        self.assertEqual(seq.step()['hash'], new['hash'])  # idempotent
        self.assertEqual(producer.calls, ['head'])

    def test_a_stale_base_block_after_the_gate_is_waited_for_not_halted(self):
        self.settler_builds('base')
        after = schedule_view(held=NEXT_ELF, schedule=())
        seq, producer, _ = self.make(after, GATE * 32 + 5)
        self.assertIsNone(seq.step())
        self.assertNotIn('extend', producer.calls)
        new = self.settler_builds('next')
        self.assertEqual(seq.step()['hash'], new['hash'])

    def test_the_rollback_keeps_the_block_and_its_rules(self):
        built = self.settler_builds('next')
        seq, producer, rpc = self.make(schedule_view(held=NEXT_ELF, schedule=((ROLLBACK, FALLBACK_ELF),)), GATE * 32 + 5)
        self.assertEqual(seq.step()['hash'], built['hash'])
        # Inside the rollback window, then after the rollback: the settler re-proves the same block in a new work
        # directory without block.json (its database already holds it). The shadow neither rewinds nor halts.
        d = self.settler_dir()
        d.rename(d.with_name(d.name + '.superseded-99'))
        d.mkdir()
        (d / 'program.json').write_text(json.dumps({'name': 'fallback'}))
        for v, slot in ((schedule_view(held=NEXT_ELF, schedule=((ROLLBACK, FALLBACK_ELF),)), ROLLBACK * 32 - 10),
                        (schedule_view(held=FALLBACK_ELF, schedule=()), ROLLBACK * 32 + 5)):
            rpc.views, rpc.slots = [v] * 3, [slot] * 3
            producer.calls.clear()
            self.assertEqual(seq.step()['hash'], built['hash'])
            self.assertNotIn('rewind', producer.calls)

    def test_a_block_reused_at_the_rollback_is_verified_from_its_superseded_work(self):
        built = self.settler_builds('next')
        d = self.settler_dir()
        d.rename(d.with_name(d.name + '.superseded-99'))
        d.mkdir()
        seq, producer, _ = self.make(schedule_view(held=FALLBACK_ELF, schedule=()), ROLLBACK * 32 + 5)
        job = seq.step()
        self.assertEqual((job['hash'], job['rules']), (built['hash'], 'next'))
        self.assertEqual(producer.rules[1], 'next')

    def test_a_producer_that_ignores_the_rule_set_halts_on_the_rules(self):
        self.settler_builds('next')
        seq, _, _ = self.make(schedule_view(), INSIDE, producer=RuleProducer(ignore=True))
        with self.assertRaisesRegex(q.Halt, "'rules'"):
            seq.step()

    def test_a_settler_block_that_changes_without_a_rule_change_is_reverified_and_halts(self):
        self.settler_builds('base')
        seq, _, _ = self.make(schedule_view(), OUTSIDE)
        seq.step()
        d = self.settler_dir()
        forged = {**json.loads((d / 'block.json').read_text()), 'hash': 'ee' * 32}
        (d / 'block.json').write_text(json.dumps(forged))
        with self.assertRaisesRegex(q.Halt, r"differs from the independent rebuild in \['hash'\]"):
            seq.step()

    def test_the_slot_is_bounded_by_an_honest_node(self):
        built = self.settler_builds('next')
        seq, _, _ = self.make(schedule_view(), [OUTSIDE, OUTSIDE, 10 ** 9])  # one node lies high
        self.assertIsNone(seq.step())
        seq, _, _ = self.make(schedule_view(), [INSIDE, INSIDE, RuntimeError('down')])
        self.assertEqual(seq.step()['hash'], built['hash'])

    def test_an_unusable_schedule_fails_safe(self):
        self.settler_builds('next')
        cases = (('not a list', schedule_view(program_schedule={'epoch': GATE}), INSIDE, q.Halt),
                 ('unknown program', schedule_view(schedule=((GATE, 'ab' * 32),)), INSIDE, q.Halt),
                 ('decreasing', schedule_view(schedule=((GATE, NEXT_ELF), (GATE, FALLBACK_ELF))), INSIDE, q.Halt),
                 ('no slot', schedule_view(), [RuntimeError('x')] * 3, None))
        for name, v, slot, outcome in cases:
            with self.subTest(name):
                shutil.rmtree(self.config['workdir'], ignore_errors=True)
                shutil.rmtree(self.config['l2_db'], ignore_errors=True)
                seq, _, _ = self.make(v, slot)
                if outcome is q.Halt:  # the schedule is ignored: L1 holds the activated program, next is unjustified
                    with self.assertRaisesRegex(q.Halt, 'which L1 does not justify'):
                        seq.step()
                else:                  # the gate is named but the window cannot be measured: wait, never halt
                    self.assertIsNone(seq.step())
                self.assertIsNotNone(seq.schedule_problem)

    def test_the_base_block_before_the_window_also_matches_with_an_unusable_schedule(self):
        built = self.settler_builds('base')
        seq, _, _ = self.make(schedule_view(program_schedule=None), INSIDE)
        self.assertEqual(seq.step()['hash'], built['hash'])

    def test_producer_mode_builds_under_the_scheduled_rules(self):
        config = {k: v for k, v in self.config.items() if k != 'settler_workdir'}
        rpc = ScheduleRpc(*([schedule_view()] * 3), slots=[OUTSIDE] * 3)
        rpc.urls = config['rpc_urls']
        producer = RuleProducer()
        seq = q.Sequencer(config, rpc=rpc, run=producer, clock=lambda: q.l1_slot_time(SLOT) + 3600)
        self.assertEqual(seq.step()['rules'], 'base')
        rpc.slots = [INSIDE] * 3
        job = seq.step()
        self.assertEqual((job['rules'], producer.rewound[0][:2]), ('next', '01'))

    def test_configuration_guards(self):
        base = {k: v for k, v in self.config.items() if k not in ('next_elf_keccak', 'fallback_elf_keccak')}
        for over, msg in (({'next_elf_keccak': 'AB' * 32}, 'lowercase hex'), ({'next_elf_keccak': 'ab'}, 'lowercase hex'),
                          ({'fallback_elf_keccak': FALLBACK_ELF}, 'needs a different next_elf_keccak'),
                          ({'next_elf_keccak': NEXT_ELF, 'fallback_elf_keccak': NEXT_ELF}, 'different'),
                          ({'program_switch_lead_seconds': 0}, 'positive integer'),
                          ({'slots_per_epoch': True}, 'positive integer')):
            with self.subTest(over=over), self.assertRaisesRegex(q.Halt, msg):
                q.Sequencer({**base, **over})

    def test_without_next_elf_keccak_the_schedule_is_ignored(self):
        config = {k: v for k, v in self.config.items() if k not in ('next_elf_keccak', 'fallback_elf_keccak')}
        (self.settler_dir()).mkdir(parents=True)
        ref = FakeProducer().extend({'--parent': q.L2_GENESIS_HASH, '--anchor': SOURCE_BLOCK, '--anchor-slot': str(SLOT),
                                     '--deposits': str(self.settler_deposits), '--timestamp-rule': q.TIMESTAMP_RULE})
        (self.settler_dir() / 'block.json').write_text(json.dumps(ref))
        rpc = Rpc(*([schedule_view()] * 3))  # no getchaininfo: it must not be called
        rpc.urls = config['rpc_urls']
        producer = FakeProducer()
        seq = q.Sequencer(config, rpc=rpc, run=producer, clock=lambda: q.l1_slot_time(SLOT) + 3600)
        self.assertEqual(seq.step()['hash'], ref['hash'])



class InstallShadowTest(unittest.TestCase):
    """install-shadow.sh writes the program pins and the settler's window into the shadow config (agent 218)."""
    SCRIPT = HERE / 'install-shadow.sh'

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location('settler_v3_for_shadow', HERE.parent / 'devnet' / 'settler_v3.py')
        cls.settler = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(HERE.parent / 'devnet'))
        spec.loader.exec_module(cls.settler)
        cls.constants = dict(line.split('=', 1) for line in cls.SCRIPT.read_text().splitlines()
                             if line and line[0].isupper() and '=' in line and ' ' not in line.split('=', 1)[0])

    def print_config(self, settler_config='/nonexistent/config.json'):
        import os
        import re
        import subprocess
        env = dict(os.environ, L1_RPC_URLS='http://192.0.2.1:8080,http://192.0.2.2:8080,http://192.0.2.3:8080')
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / self.SCRIPT.name
            script.write_text(self.SCRIPT.read_text())
            unit = HERE / 'bloch-l2-mainnet-shadow.service'
            (Path(tmp) / unit.name).write_text(re.sub(r'(?m)^IPAddressAllow=.*$',
                'IPAddressAllow=192.0.2.1 192.0.2.2 192.0.2.3', unit.read_text()))
            return subprocess.run(['bash', str(script), '--print-config', str(settler_config)],
                                  capture_output=True, text=True, env=env)

    def test_the_pins_are_the_settlers_programs_and_this_tree(self):
        c = self.constants
        self.assertEqual(c['NEXT_ELF_KECCAK'], self.settler.MAINNET_NEXT_SPARSE['elf_keccak'])
        self.assertEqual(c['FALLBACK_ELF_KECCAK'], self.settler.MAINNET_FALLBACK['elf_keccak'])
        self.assertEqual(c['SEQUENCER_SHA256'], q.digest(HERE / 'sequencer_mainnet.py'))
        import importlib.util
        spec = importlib.util.spec_from_file_location('install_settler_for_shadow', HERE / 'install-settler-mainnet.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        self.assertEqual(c['PRODUCE_SHA256'], installer.PINS['bloch-l2-produce-dev'])

    def test_the_config_follows_the_swap_and_the_rollback_and_is_accepted(self):
        done = self.print_config()
        self.assertEqual(done.returncode, 0, done.stderr)
        config = json.loads(done.stdout)
        self.assertEqual((config['next_elf_keccak'], config['fallback_elf_keccak']),
                         (self.constants['NEXT_ELF_KECCAK'], self.constants['FALLBACK_ELF_KECCAK']))
        self.assertEqual((config['program_switch_lead_seconds'], config['slots_per_epoch']), (1800, 32))
        self.assertEqual(config['settler_workdir'], '/var/lib/bloch-l2-mainnet-settler/work')
        with mock.patch.object(q, 'digest', return_value=config['produce_sha256']):
            seq = q.Sequencer(config)
        self.assertEqual(seq.next_elves, {config['next_elf_keccak'], config['fallback_elf_keccak']})

    def test_the_settlers_window_and_programs_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'next.bin').write_bytes(self.settler.mainnet_l2_config(self.settler.MAINNET_NEXT_SPARSE))
            (root / 'fallback.bin').write_bytes(self.settler.mainnet_l2_config(self.settler.MAINNET_FALLBACK))
            settler = {'program_switch_lead_seconds': 2400, 'next_program': {'l2_config': str(root / 'next.bin')},
                       'fallback_program': {'l2_config': str(root / 'fallback.bin')}}
            (root / 'config.json').write_text(json.dumps(settler))
            done = self.print_config(root / 'config.json')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)['program_switch_lead_seconds'], 2400)
            # A settler whose next program is the complete guest: another ELF than the shadow's pin.
            (root / 'next.bin').write_bytes(self.settler.mainnet_l2_config(self.settler.MAINNET_NEXT))
            done = self.print_config(root / 'config.json')
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("the settler's next_program proves ELF", done.stderr)


if __name__ == '__main__':
    unittest.main()
