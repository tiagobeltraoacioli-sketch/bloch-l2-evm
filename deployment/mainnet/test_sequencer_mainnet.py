#!/usr/bin/env python3
"""Unit tests for sequencer_mainnet.py with a fake native RPC and producer.

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_*.py' -v
No network and no binary: every external call is a stub.
"""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

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


if __name__ == '__main__':
    unittest.main()
