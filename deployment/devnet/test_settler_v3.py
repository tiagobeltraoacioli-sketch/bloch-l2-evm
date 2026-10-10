#!/usr/bin/env python3
"""Unit tests for settler_v3.py with fake native RPC, producer and prover.

Run: python3 -m unittest discover -s deployment/devnet -p 'test_*.py' -v
No network, no prover, no Docker: every external call is a stub.
"""
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402

FRAME = HERE.parent.parent / 'tests/fixtures/native-settlement-v3/frame-async.hex'
NETWORK, GENESIS, BLOCK, SOURCE, INBOX = 'aa' * 32, 'bb' * 32, 'cc' * 32, 'dd' * 32, 'ee' * 32
CONFIG_BYTES = bytes(range(160)) + b'\x77' * 32  # identities[2..7] || proof policy
PENDING = [{'height': 3, 'tx_index': 0, 'txid': '11' * 32, 'vout': 1, 'sats': 5000, 'recipient': '42' * 20}]


def statement(user_txs=0, deposits=None, **overrides):
    """A 766-byte V3 statement consistent with the fake native request."""
    v = bytearray(s.VALUES_BYTES)
    v[:s.T] = s.TAG
    put = lambda offset, data: v.__setitem__(slice(s.T + offset, s.T + offset + len(data)), data)  # noqa: E731
    put(0, bytes.fromhex(NETWORK))
    put(32, bytes.fromhex(GENESIS))
    put(64, CONFIG_BYTES[:160])
    put(256, s.CHAIN_ID.to_bytes(8, 'big'))
    put(264, (1).to_bytes(8, 'big'))
    put(336, b'\x51' * 32)  # l2 header hash
    put(400, bytes.fromhex(BLOCK))
    put(432, (5).to_bytes(8, 'big'))
    put(440, (4).to_bytes(8, 'big'))
    put(448, bytes.fromhex(SOURCE))
    put(480, bytes.fromhex(INBOX))
    put(512, (1).to_bytes(8, 'big') + (0).to_bytes(8, 'big') + (1).to_bytes(8, 'big'))
    put(536, b'\x5b' * 32)
    put(s.DEPOSITS_HASH, s.deposits_hash(PENDING if deposits is None else deposits))
    put(s.TRANSACTIONS_ROOT, b'\x61' * 32)
    put(s.RECEIPTS_ROOT, b'\x62' * 32)
    put(s.USER_TX_COUNT, user_txs.to_bytes(8, 'big'))
    for offset, data in overrides.items():
        put(int(offset), data)
    return bytes(v)


def artifact(values, version=s.SP1_CIRCUIT_VERSION, trailing=b''):
    vec = lambda b: struct.pack('<Q', len(b)) + b  # noqa: E731
    proof = bytes((i * 3) % 256 for i in range(352))
    return (struct.pack('<I', 3) + vec(b'') * 5 + vec(proof.hex().encode()) + vec(b'') + b'\xab' * 32
            + vec(values) + vec(version) + b'\0' + trailing)


class Fake:
    """Native RPC + producer + prover stubs sharing one scripted world."""

    def __init__(self, root, values, produced_txs=0):
        self.root, self.values, self.produced_txs = root, values, produced_txs
        self.calls, self.sent, self.accepted, self.head = [], [], None, 0

    def view(self):
        request = ''.join(x + '\n' for x in (NETWORK, GENESIS, BLOCK, '5', '4', SOURCE, INBOX))
        return {'network': NETWORK, 'chain_id': s.CHAIN_ID, 'accepted': self.accepted,
                'source': {'block': BLOCK, 'request': request, 'pending': PENDING, 'inbox_count': 1,
                           'consumed_start': 0, 'consumed_end': 1}}

    def rpc(self, port, method, params=()):
        if method == 'getl2settlement':
            return self.view()
        if method == 'sendrawtransaction':
            self.sent.append(bytes.fromhex(params[0]))
            self.accepted = {'statement': self.values.hex(), 'commitment': '99' * 32}
            return {'status': 'accepted', 'tx_hash': '00' * 32}
        raise AssertionError(method)

    def run(self, argv, **kwargs):
        self.calls.append([str(a) for a in argv])
        name = Path(argv[0]).name
        out = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        if name == 'produce':
            command = argv[1]
            if command == 'head':
                out.stdout = json.dumps({'number': self.head, 'hash': 'f0' * 32})
            elif command == 'extend':
                self.head += 1
                out.stdout = json.dumps({'number': self.head, 'hash': '51' * 32, 'deposits': 1,
                                         'transactions': self.produced_txs, 'deferred': [], 'dropped': []})
            elif command == 'export':
                Path(argv[argv.index('--out') + 1]).write_bytes(b'artifact')
                out.stdout = json.dumps({'number': self.head, 'hash': '51' * 32, 'anchor': BLOCK, 'bytes': 8})
            return out
        if 'settlement-v3' in name:
            if argv[1] == 'prove-groth16':
                Path(argv[-1]).write_bytes(artifact(self.values))
            return out
        raise AssertionError(argv)


class SettlerV3Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name, data in (('bloch-evm-sp1-settlement-v3', b'prover'), ('settlement_v3', b'guest'),
                           ('l2-config.bin', CONFIG_BYTES)):
            (self.root / name).write_bytes(data)
        (self.root / 'txpool').mkdir()
        (self.root / 'home').mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def config(self, **extra):
        c = {'network': NETWORK, 'l2_genesis': 'f0' * 32, 'rpc_ports': [1, 2, 3], 'produce': str(self.root / 'produce'),
             'l2_db': str(self.root / 'db'), 'workdir': str(self.root / 'work'), 'home': str(self.root / 'home'),
             'gnark_image': 'image', 'prover_threads': 8, 'acceptance_timeout_seconds': 60, 'idle_seconds': 1,
             'max_consecutive_failures': 3}
        for key, name in (('prover', 'bloch-evm-sp1-settlement-v3'), ('guest', 'settlement_v3'),
                          ('l2_config', 'l2-config.bin')):
            c[key] = str(self.root / name)
            c[key + '_sha256'] = s.digest(self.root / name)
        c.update(extra)
        return c

    def settler(self, fake, **extra):
        clock = iter(range(0, 10_000, 3))
        return s.Settler(self.config(**extra), rpc=fake.rpc, run=fake.run, sleep=lambda _: None,
                         clock=lambda: next(clock))

    def extend_call(self, fake):
        return next(c for c in fake.calls if Path(c[0]).name == 'produce' and c[1] == 'extend')

    # ---- primitives ----
    def test_keccak_and_deposits_hash_match_the_rust_vectors(self):
        self.assertEqual(s.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(s.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        frame = bytes.fromhex(FRAME.read_text().strip())
        self.assertEqual(s.keccak256(frame).hex(), 'b4a32832b08b2297693a9f6f1468d59301f13bdedd0af059d6054200147117d4')
        record = {'height': 7, 'tx_index': 3, 'txid': '11' * 32, 'vout': 1, 'sats': 5000, 'recipient': '42' * 20}
        self.assertEqual(s.deposits_hash([record]).hex(),
                         '0cbc6acc037c5bd96bf847b916a584239e9fa7c22afbf1a37703f4b13afbcfd3')
        self.assertEqual(s.deposits_hash([]), s.keccak256(b''))

    def test_constants_follow_the_v3_layout_and_renumbered_tag(self):
        self.assertEqual((s.VALUES_BYTES, s.TRANSACTION_BYTES, s.ASYNC_SETTLEMENT_TAG), (766, 1155, 0x13))
        frame = bytes.fromhex(FRAME.read_text().strip())
        self.assertEqual(frame[0], s.ASYNC_SETTLEMENT_TAG)
        self.assertEqual(len(frame), s.TRANSACTION_BYTES)
        self.assertEqual(frame[33:33 + s.T], s.TAG)

    # ---- deposit-only (default) ----
    def test_deposit_only_cycle_builds_the_1155_byte_0x13_transaction(self):
        fake = Fake(self.root, statement())
        settler = self.settler(fake)
        self.assertFalse(settler.c['user_transactions'])
        self.assertTrue(settler.cycle())
        self.assertNotIn('--txs', self.extend_call(fake))
        self.assertIn('--deposits', self.extend_call(fake))
        [tx] = fake.sent
        self.assertEqual((len(tx), tx[0]), (1155, 0x13))
        self.assertEqual(tx[1:33], CONFIG_BYTES[160:192])
        self.assertEqual(tx[33:33 + 766], fake.values)
        self.assertEqual(tx[33 + 766:33 + 770], b'\xab' * 4)
        provers = [c for c in fake.calls if 'settlement-v3' in Path(c[0]).name]
        self.assertEqual([c[1] for c in provers], ['execute', 'prove-groth16', 'verify-groth16'])
        self.assertTrue(all(c[2] == 'native-artifact' and c[3].endswith('settlement_v3') for c in provers))

    def test_deposit_only_refuses_a_statement_or_block_with_user_transactions(self):
        with self.assertRaisesRegex(s.Halt, 'user_transactions is false'):
            self.settler(Fake(self.root, statement(user_txs=1))).cycle()
        with self.assertRaisesRegex(s.Halt, 'producer included user transactions'):
            self.settler(Fake(self.root, statement(), produced_txs=2)).cycle()

    # ---- user transactions ----
    def test_user_transactions_pass_the_pool_and_limits_and_must_match_the_block(self):
        pool = str(self.root / 'txpool')
        fake = Fake(self.root, statement(user_txs=3), produced_txs=3)
        settler = self.settler(fake, user_transactions=True, txpool_dir=pool, max_block_gas=1_000_000,
                               max_block_bytes=65536, max_block_txs=50)
        self.assertTrue(settler.cycle())
        call = self.extend_call(fake)
        for flag, value in (('--txs', pool), ('--max-gas', '1000000'), ('--max-bytes', '65536'), ('--max-txs', '50')):
            self.assertEqual(call[call.index(flag) + 1], value)
        self.assertEqual(int.from_bytes(fake.sent[0][33 + s.T + s.USER_TX_COUNT:33 + s.T + s.USER_TX_COUNT + 8], 'big'), 3)
        mismatch = Fake(self.root, statement(user_txs=2), produced_txs=3)
        self.tearDown(), self.setUp()
        with self.assertRaisesRegex(s.Halt, 'producer included 3'):
            self.settler(mismatch, user_transactions=True, txpool_dir=str(self.root / 'txpool')).cycle()

    def test_user_transactions_are_refused_outside_devnet_and_need_a_pool(self):
        fake = Fake(self.root, statement())
        with self.assertRaisesRegex(s.Halt, 'outside development networks'):
            self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'txpool'), network_kind='mainnet')
        with self.assertRaisesRegex(s.Halt, 'txpool_dir'):
            self.settler(fake, user_transactions=True)
        with self.assertRaisesRegex(s.Halt, 'txpool_dir'):
            self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'absent'))
        with self.assertRaisesRegex(s.Halt, 'true or false'):
            self.settler(fake, user_transactions='yes')
        with self.assertRaisesRegex(s.Halt, 'max_block_gas'):
            self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'txpool'), max_block_gas=0)
        # Deposit-only stays allowed on any network kind.
        self.settler(fake, network_kind='mainnet')

    # ---- V3 pre-submit checks ----
    def test_v3_fields_are_checked_before_submission(self):
        cases = {
            'deposits_hash': statement(deposits=[]),
            'zero transactions': statement(**{str(s.TRANSACTIONS_ROOT): bytes(32)}),
            'zero transactions or receipts': statement(**{str(s.RECEIPTS_ROOT): bytes(32)}),
            'reserved': statement(**{str(s.WITHDRAWAL_ROOT): b'\x01' + bytes(31)}),
            'reserved V3': statement(**{str(s.WITHDRAWAL_COUNT): (1).to_bytes(8, 'big')}),
            'reserved V3 fields': statement(**{str(s.DA_COMMITMENT): b'\x01' * 32}),
            'native request': statement(**{'432': (6).to_bytes(8, 'big')}),
            'native request ': statement(**{'64': b'\x00' * 32}),
        }
        for name, values in cases.items():
            with self.subTest(name):
                self.tearDown(), self.setUp()
                fake = Fake(self.root, values)
                with self.assertRaisesRegex(s.Halt, name.strip()):
                    self.settler(fake).cycle()
                self.assertEqual(fake.sent, [], name)

    def test_only_the_v3_prover_and_guest_are_accepted(self):
        (self.root / 'bloch-evm-sp1-settlement-v2').write_bytes(b'prover')
        bad = self.config(prover=str(self.root / 'bloch-evm-sp1-settlement-v2'))
        with self.assertRaisesRegex(s.Halt, 'V3 prover'):
            s.Settler(bad, rpc=None, run=None)
        with self.assertRaisesRegex(s.Halt, 'differs from its pin'):
            s.Settler(self.config(prover_sha256='00' * 32), rpc=None, run=None)

    def test_proof_artifact_framing_is_exact(self):
        good = statement()
        self.assertEqual(s.parse_proof_artifact(artifact(good))[0], good)
        self.assertEqual(len(s.parse_proof_artifact(artifact(good))[1]), 356)
        v2_length = b'BLOCH:EVM:SETTLEMENT:2' + good[s.T:590]
        for name, data in (('trailing', artifact(good, trailing=b'\0')), ('version', artifact(good, version=b'v5.0.0')),
                           ('v2 values', artifact(v2_length)), ('v2 tag', artifact(b'BLOCH:EVM:SETTLEMENT:2' + good[s.T:])),
                           ('truncated', artifact(good)[:-2]), ('empty', b'')):
            with self.subTest(name), self.assertRaises(s.Halt):
                s.parse_proof_artifact(data)


if __name__ == '__main__':
    unittest.main()
