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
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import remote_prover as rp  # noqa: E402

FRAME = HERE.parent.parent / 'tests/fixtures/native-settlement-v3/frame-async.hex'
NETWORK, GENESIS, BLOCK, SOURCE, INBOX = 'aa' * 32, 'bb' * 32, 'cc' * 32, 'dd' * 32, 'ee' * 32
CONFIG_BYTES = bytes(range(160)) + b'\x77' * 32  # identities[2..7] || proof policy
PENDING = [{'height': 3, 'tx_index': 0, 'txid': '11' * 32, 'vout': 1, 'sats': 5000, 'recipient': '42' * 20}]


def batch(user_txs):
    """A canonical DA batch of `user_txs` opaque envelopes."""
    return user_txs.to_bytes(4, 'big') + b''.join((2).to_bytes(4, 'big') + bytes([2, i]) for i in range(user_txs))


def da_frame(number, payload):
    """A 0x15 frame with the native layout (placeholder key and signature)."""
    return (bytes([s.DA_TAG]) + b'\x91' * 32 + (4).to_bytes(4, 'little') + b'kkkk' + (1).to_bytes(4, 'little')
            + b'\x33' * 36 + s.CHAIN_ID.to_bytes(8, 'little') + number.to_bytes(8, 'little')
            + len(payload).to_bytes(4, 'little') + payload + b'\0' * 60)


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
    put(s.WITHDRAWAL_ROOT, s.EMPTY_WITHDRAWAL_ROOT)
    if user_txs:
        put(s.DA_COMMITMENT, s.da_commitment(1, batch(user_txs)))
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

    def __init__(self, root, values, produced_txs=0, da_payload=None):
        self.root, self.values, self.produced_txs = root, values, produced_txs
        self.calls, self.sent, self.accepted, self.head = [], [], None, 0
        self.da_payload = batch(produced_txs) if da_payload is None else da_payload
        self.da_records, self.include_da = [], True
        self.extend_extra = {}
        self.remote_jobs, self.remote_fail = [], False

    def view(self):
        request = ''.join(x + '\n' for x in (NETWORK, GENESIS, BLOCK, '5', '4', SOURCE, INBOX))
        return {'network': NETWORK, 'chain_id': s.CHAIN_ID, 'accepted': self.accepted,
                'data_availability': list(self.da_records),
                'source': {'block': BLOCK, 'request': request, 'pending': PENDING, 'inbox_count': 1,
                           'consumed_start': 0, 'consumed_end': 1}}

    def rpc(self, port, method, params=()):
        if method == 'getl2settlement':
            return self.view()
        if method == 'getchaininfo':
            return {'next_base_fee_millisat_per_gas': '10'}
        if method == 'getutxos':
            return {'utxos': [{'txid': '33' * 32, 'vout': 0, 'value_sat': '9000000', 'script_hash': params[0]},
                              {'txid': '34' * 32, 'vout': 1, 'value_sat': '1000', 'script_hash': params[0]}]}
        if method == 'sendrawtransaction' and params[0].startswith('15'):
            tx = bytes.fromhex(params[0])
            self.sent.append(tx)
            if self.include_da:
                _, number, payload = s.da_frame_fields(tx)
                self.da_records.append({'l2_number': number, 'commitment': s.da_commitment(number, payload).hex(),
                                        'height': 9})
            return {'status': 'accepted', 'tx_hash': '01' * 32}
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
                                         'transactions': self.produced_txs, 'deferred': [], 'dropped': [],
                                         **self.extend_extra})
            elif command == 'da':
                Path(argv[argv.index('--out') + 1]).write_text(self.da_payload.hex() + '\n')
                out.stdout = json.dumps({'number': self.head, 'transactions': self.produced_txs,
                                         'da_commitment': s.da_commitment(self.head, self.da_payload).hex()})
            elif command == 'export':
                Path(argv[argv.index('--out') + 1]).write_bytes(b'artifact')
                out.stdout = json.dumps({'number': self.head, 'hash': '51' * 32, 'anchor': BLOCK, 'bytes': 8})
            return out
        if name == 'bloch-pos':
            assert argv[1] == 'l2-da' and kwargs['env']['BLOCH_KEYSTORE_PASSPHRASE_FILE']
            out_path = Path(argv[argv.index('--out') + 1])
            if argv[2] == 'prepare':
                inputs = [argv[i + 1] for i, a in enumerate(argv) if a == '--input']
                if sum(int(i.split(':')[2]) for i in inputs) < 5000000:
                    out.returncode, out.stderr = 2, 'inputs do not cover the fee'
                    return out
                payload = bytes.fromhex(Path(argv[argv.index('--payload') + 1]).read_text().strip())
                number = int(argv[argv.index('--number') + 1])
                out_path.write_text(da_frame(number, payload).hex() + '\n')
            else:
                out_path.write_text(Path(argv[argv.index('--tx') + 1]).read_text())
            return out
        if name == 'ssh':
            self.remote_jobs.append(rp.parse_job(__import__('io').BytesIO(kwargs['input'])))
            if self.remote_fail:
                out.returncode = 255
            else:
                kwargs['stdout'].write(artifact(self.values))
            return out
        if 'settlement-v3' in name:
            if argv[1] == 'prove-groth16':
                Path(argv[-1]).write_bytes(artifact(self.values))
            return out
        raise AssertionError(argv)


EVIL = [{'height': 3, 'tx_index': 0, 'txid': '66' * 32, 'vout': 0, 'sats': 10 ** 12, 'recipient': '66' * 20}]


class Ports:
    """Three native RPC endpoints over one Fake world, each 'ok', 'down',
    'erroring', 'lagging' (an older native view) or 'conflicting' (a different
    view at the same height). `chaininfo` and `utxos` override per port."""

    def __init__(self, fake, **modes):
        self.fake, self.modes, self.calls = fake, {int(k[1:]): v for k, v in modes.items()}, []
        self.chaininfo, self.utxos, self.reject = {}, {}, set()
        self.moving, self.script, self.reads = False, {}, 0  # head motion between reads

    def rpc(self, port, method, params=()):
        self.calls.append((port, method))
        mode = self.modes.get(port, 'ok')
        if mode == 'down':
            raise ConnectionRefusedError(111, 'Connection refused')
        if mode == 'erroring':
            raise s.RpcError(f"{method}: {{'code': -32004, 'message': 'consensus thread did not answer within 10s'}}")
        if method == 'getl2settlement':
            self.reads += 1
            view = {**self.fake.view(), 'native_height': 200 + (self.reads if self.moving else 0)}
            if self.moving:  # per-head bookkeeping the worker does not read
                view['withdrawals'] = {'count': 0, 'roots': [{'finalized': self.reads % 2 == 0}]}
                view['inbox'] = {'count': 1, 'consumed': 0, 'escrow_sat': str(5000 + self.reads)}
            if self.script.get(port):
                view.update(self.script[port].pop(0))
            if mode == 'lagging':
                view.update(native_height=150, accepted=None, data_availability=[],
                            source={**view['source'], 'block': '0c' * 32})
            if mode == 'conflicting':
                view['source'] = {**view['source'], 'pending': EVIL}
            if mode == 'wrong-network':
                view['network'] = '00' * 32
            return view
        if method == 'getchaininfo' and port in self.chaininfo:
            return {'next_base_fee_millisat_per_gas': str(self.chaininfo[port])}
        if method == 'getutxos' and port in self.utxos:
            return {'utxos': self.utxos[port]}
        if method == 'sendrawtransaction' and (mode != 'ok' or port in self.reject):
            raise s.RpcError('sendrawtransaction: settlement does not match the native request')
        return self.fake.rpc(port, method, params)

    def count(self, port, method='getl2settlement'):
        return self.calls.count((port, method))


class SettlerV3Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name, data in (('bloch-evm-sp1-settlement-v3', b'prover'), ('settlement_v3', b'guest'),
                           ('l2-config.bin', CONFIG_BYTES), ('bloch-pos', b'signer'), ('da.pub', b'5a' * 3749)):
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

    def da_config(self):
        return {'signer': str(self.root / 'bloch-pos'), 'signer_sha256': s.digest(self.root / 'bloch-pos'),
                'genesis': str(self.root / 'genesis'), 'funding_pubkey': str(self.root / 'da.pub'),
                'keystore_dir': str(self.root / 'keys'), 'passphrase_file': str(self.root / 'pass')}

    def user_settler(self, fake, **extra):
        extra.setdefault('da', self.da_config())
        return self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'txpool'), **extra)

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
        settler = self.user_settler(fake, max_block_gas=1_000_000, max_block_bytes=65536, max_block_txs=50)
        self.assertTrue(settler.cycle())
        call = self.extend_call(fake)
        for flag, value in (('--txs', pool), ('--max-gas', '1000000'), ('--max-bytes', '65536'), ('--max-txs', '50')):
            self.assertEqual(call[call.index(flag) + 1], value)
        # DA first (0x15, carrying the batch), then the settlement (0x13).
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])
        self.assertEqual(s.da_frame_fields(fake.sent[0]), (s.CHAIN_ID, 1, batch(3)))
        self.assertEqual(int.from_bytes(fake.sent[1][33 + s.T + s.USER_TX_COUNT:33 + s.T + s.USER_TX_COUNT + 8], 'big'), 3)
        mismatch = Fake(self.root, statement(user_txs=2), produced_txs=3)
        self.tearDown(), self.setUp()
        with self.assertRaisesRegex(s.Halt, 'producer included 3'):
            self.user_settler(mismatch).cycle()

    def test_user_transactions_are_refused_outside_devnet_and_need_a_pool(self):
        fake = Fake(self.root, statement())
        with self.assertRaisesRegex(s.Halt, 'outside development networks'):
            self.user_settler(fake, network_kind='mainnet')
        with self.assertRaisesRegex(s.Halt, 'da signer configuration'):
            self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'txpool'))
        with self.assertRaisesRegex(s.Halt, 'signer differs from its pin'):
            self.user_settler(fake, da={**self.da_config(), 'signer_sha256': '00' * 32})
        with self.assertRaisesRegex(s.Halt, 'txpool_dir'):
            self.settler(fake, user_transactions=True)
        with self.assertRaisesRegex(s.Halt, 'txpool_dir'):
            self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'absent'))
        with self.assertRaisesRegex(s.Halt, 'true or false'):
            self.settler(fake, user_transactions='yes')
        with self.assertRaisesRegex(s.Halt, 'max_block_gas'):
            self.user_settler(fake, max_block_gas=0)
        # Deposit-only stays allowed on any network kind.
        self.settler(fake, network_kind='mainnet')

    # ---- V3 pre-submit checks ----
    def test_v3_fields_are_checked_before_submission(self):
        cases = {
            'deposits_hash': statement(deposits=[]),
            'zero transactions': statement(**{str(s.TRANSACTIONS_ROOT): bytes(32)}),
            'zero transactions or receipts': statement(**{str(s.RECEIPTS_ROOT): bytes(32)}),
            'withdrawal root must change': statement(**{str(s.WITHDRAWAL_ROOT): b'\x01' + bytes(31)}),
            'withdrawal root must change ': statement(**{str(s.WITHDRAWAL_COUNT): (1).to_bytes(8, 'big')}),
            'da_commitment is not zero': statement(**{str(s.DA_COMMITMENT): b'\x01' * 32}),
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

    # ---- M4 withdrawals ----
    def test_withdrawal_vectors_match_the_shared_fixture(self):
        fixture = json.loads((HERE.parent.parent / 'tests/fixtures/l2-withdrawal-v1/vectors.json').read_text())
        unhex = lambda v: bytes.fromhex(v.removeprefix('0x'))  # noqa: E731
        self.assertEqual(s.EMPTY_WITHDRAWAL_ROOT, unhex(fixture['empty_root']))
        for leaf in fixture['leaves']:
            self.assertEqual(s.withdrawal_leaf(leaf['chain_id'], leaf['nonce'], unhex(leaf['l1_recipient']),
                                               leaf['sats']), unhex(leaf['leaf']))
        chain = fixture['chain_id']
        vector_leaf = lambda i: s.withdrawal_leaf(chain, i, bytes([i % 255 + 1]) * 32, 1_000_000 + i)  # noqa: E731
        for tree in fixture['trees']:
            leaves = [vector_leaf(i) for i in range(tree['count'])]
            root = s.withdrawal_tree_root(leaves)
            self.assertEqual(root, unhex(tree['root']), tree['count'])
            for proof in tree['proofs']:
                siblings = [unhex(x) for x in proof['siblings']]
                self.assertEqual(s.withdrawal_root_from_proof(leaves[proof['index']], proof['index'], siblings), root)
                self.assertNotEqual(s.withdrawal_root_from_proof(leaves[proof['index']], proof['index'] ^ 1,
                                                                 siblings), root)

    def test_withdrawal_root_and_count_follow_the_accepted_head(self):
        def with_withdrawals(root, count):
            return statement(**{str(s.WITHDRAWAL_ROOT): root, str(s.WITHDRAWAL_COUNT): count.to_bytes(8, 'big')})
        empty, first, second = with_withdrawals(s.EMPTY_WITHDRAWAL_ROOT, 0), with_withdrawals(b'\x01' * 32, 1), \
            with_withdrawals(b'\x02' * 32, 3)
        self.assertEqual(s.check_withdrawals(empty, None), (s.EMPTY_WITHDRAWAL_ROOT, 0))
        self.assertEqual(s.check_withdrawals(first, empty), (b'\x01' * 32, 1))
        self.assertEqual(s.check_withdrawals(second, first), (b'\x02' * 32, 3))
        self.assertEqual(s.check_withdrawals(first, first), (b'\x01' * 32, 1))
        # A V2 head has no withdrawals: the empty tree.
        self.assertEqual(s.check_withdrawals(first, b'\x00' * 590), (b'\x01' * 32, 1))
        with self.assertRaisesRegex(s.Halt, 'below the accepted'):
            s.check_withdrawals(first, second)
        with self.assertRaisesRegex(s.Halt, 'exactly when'):
            s.check_withdrawals(with_withdrawals(b'\x03' * 32, 1), first)
        with self.assertRaisesRegex(s.Halt, 'exactly when'):
            s.check_withdrawals(with_withdrawals(b'\x01' * 32, 2), first)

    def test_statement_withdrawals_must_match_the_producer_block(self):
        fake = Fake(self.root, statement())
        fake.extend_extra = {'withdrawal_root': (b'\x01' * 32).hex(), 'withdrawal_count': 1}
        with self.assertRaisesRegex(s.Halt, 'differ from the producer'):
            self.settler(fake).cycle()
        self.assertEqual(fake.sent, [])
        self.tearDown(), self.setUp()
        fake = Fake(self.root, statement())
        fake.extend_extra = {'withdrawal_root': s.EMPTY_WITHDRAWAL_ROOT.hex(), 'withdrawal_count': 0}
        self.assertTrue(self.settler(fake).cycle())

    # ---- M3 data availability ----
    def test_da_matches_the_shared_vector_and_batch_codec(self):
        payload = bytes.fromhex((HERE.parent.parent / 'tests/fixtures/l2-da-v1/batch.hex').read_text().strip())
        expected = (HERE.parent.parent / 'tests/fixtures/l2-da-v1/commitment-700771-7.hex').read_text().strip()
        self.assertEqual(s.da_commitment(7, payload).hex(), expected)
        self.assertEqual(s.da_batch_count(payload), 2)
        for bad in (b'', batch(0), batch(1) + b'\0', batch(2)[:-1], b'\0\0\0\1\0\0\0\0'):
            self.assertIsNone(s.da_batch_count(bad), bad)
        # The native 0x15 frame of the shared vector, parsed independently.
        frame = bytes.fromhex((HERE.parent.parent / 'tests/fixtures/l2-da-v1/tx-0x15.hex').read_text().strip())
        self.assertEqual(s.da_frame_fields(frame), (s.CHAIN_ID, 7, payload))
        with self.assertRaises(s.Halt):
            s.da_frame_fields(frame[:3800])

    def test_da_already_recorded_is_not_published_again(self):
        fake = Fake(self.root, statement(user_txs=2), produced_txs=2)
        fake.da_records.append({'l2_number': 1, 'commitment': s.da_commitment(1, batch(2)).hex(), 'height': 3})
        self.assertTrue(self.user_settler(fake).cycle())
        self.assertEqual([tx[0] for tx in fake.sent], [s.ASYNC_SETTLEMENT_TAG])
        self.assertFalse(any(Path(c[0]).name == 'bloch-pos' for c in fake.calls))

    def test_settlement_waits_for_da_inclusion(self):
        fake = Fake(self.root, statement(user_txs=2), produced_txs=2)
        fake.include_da = False
        self.assertFalse(self.user_settler(fake).cycle())
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG], 'no settlement before the DA record')
        # Next cycle: a new DA attempt (fresh files); once included, it settles.
        fake.include_da = True
        self.assertTrue(self.user_settler(fake).cycle())
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG, s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])
        prepares = [c for c in fake.calls if Path(c[0]).name == 'bloch-pos' and c[2] == 'prepare']
        self.assertTrue(prepares[0][-1].endswith('da-unsigned-0.hex') and prepares[1][-1].endswith('da-unsigned-1.hex'))

    def test_da_commitment_must_match_the_block_batch(self):
        wrong = Fake(self.root, statement(user_txs=2), produced_txs=2, da_payload=batch(2)[:-1] + b'\x09')
        with self.assertRaisesRegex(s.Halt, 'da_commitment does not match'):
            self.user_settler(wrong).cycle()
        self.assertEqual(wrong.sent, [])
        self.tearDown(), self.setUp()
        short = Fake(self.root, statement(user_txs=2), produced_txs=2, da_payload=batch(1))
        with self.assertRaisesRegex(s.Halt, 'exactly the statement user transactions'):
            self.user_settler(short).cycle()

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

    # ---- remote prover (second CPU host) ----
    def remote(self, **extra):
        (self.root / 'known_hosts').write_text('prover ssh-ed25519 AAAA\n')
        return {'target': 'prover@10.0.0.2', 'key': str(self.root / 'id'), 'known_hosts': str(self.root / 'known_hosts'),
                'ssh': str(self.root / 'ssh'), **extra}

    def test_remote_prover_proves_while_execute_and_verify_stay_local(self):
        fake = Fake(self.root, statement())
        self.assertTrue(self.settler(fake, remote_prover=self.remote(order=['remote'])).cycle())
        names = [(Path(c[0]).name, c[1]) for c in fake.calls if Path(c[0]).name != 'produce']
        self.assertEqual(names, [('bloch-evm-sp1-settlement-v3', 'execute'), ('ssh', '-i'),
                                 ('bloch-evm-sp1-settlement-v3', 'verify-groth16')])
        ssh = next(c for c in fake.calls if Path(c[0]).name == 'ssh')
        self.assertIn('StrictHostKeyChecking=yes', ssh)
        self.assertEqual(ssh[-2:], ['prover@10.0.0.2', 'prove'])
        [(request, data)] = fake.remote_jobs
        work = next((self.root / 'work').iterdir())
        self.assertEqual((request, data), ((work / 'native-request.txt').read_bytes(), b'artifact'))
        proved = json.loads((work / 'proved.json').read_text())
        self.assertEqual([x['where'] for x in proved['steps']], ['local', 'remote', 'local'])
        self.assertEqual(len(fake.sent), 1)

    def test_remote_failure_retries_or_falls_back_to_a_local_proof(self):
        fake = Fake(self.root, statement())
        fake.remote_fail = True
        with self.assertRaisesRegex(RuntimeError, 'prover prove failed'):
            self.settler(fake, remote_prover=self.remote(order=['remote'])).cycle()
        self.assertEqual(fake.sent, [])
        self.assertFalse(any((self.root / 'work').glob('*/settlement.proof*')))
        fake = Fake(self.root, statement())
        fake.remote_fail = True
        self.assertTrue(self.settler(fake, remote_prover=self.remote(order=['remote', 'local'])).cycle())
        provers = [c[1] for c in fake.calls if 'settlement-v3' in Path(c[0]).name]
        self.assertEqual(provers, ['execute', 'prove-groth16', 'verify-groth16'])

    def test_local_first_uses_the_remote_host_only_when_the_local_proof_fails(self):
        fake = Fake(self.root, statement())
        self.assertTrue(self.settler(fake, remote_prover=self.remote()).cycle())
        self.assertEqual(fake.remote_jobs, [])
        fake = Fake(self.root, statement())
        run = fake.run

        def local_fails(argv, **kwargs):
            if 'settlement-v3' in Path(argv[0]).name and argv[1] == 'prove-groth16':
                fake.calls.append([str(a) for a in argv])
                return types.SimpleNamespace(returncode=137, stdout='', stderr='')
            return run(argv, **kwargs)
        fake.run = local_fails
        self.assertTrue(self.settler(fake, remote_prover=self.remote(), workdir=str(self.root / 'work2')).cycle())
        self.assertEqual(len(fake.remote_jobs), 1)
        work = next((self.root / 'work2').iterdir())
        self.assertEqual([x['where'] for x in json.loads((work / 'proved.json').read_text())['steps']],
                         ['local', 'remote', 'local'])
        for order in ([], ['remote', 'remote'], ['gpu']):
            with self.subTest(order), self.assertRaisesRegex(s.Halt, 'order'):
                self.settler(Fake(self.root, statement()), remote_prover=self.remote(order=order))

    def test_remote_prover_needs_a_pinned_host_key(self):
        with self.assertRaisesRegex(s.Halt, 'remote_prover.key'):
            self.settler(Fake(self.root, statement()), remote_prover={'target': 'p@h', 'known_hosts': 'x'})
        with self.assertRaisesRegex(s.Halt, 'pin the prover host key'):
            self.settler(Fake(self.root, statement()), remote_prover={**self.remote(), 'known_hosts': '/nonexistent'})

    def test_remote_job_framing_is_exact(self):
        import io
        good = rp.MAGIC + struct.pack('>I', 3) + b'abc' + struct.pack('>Q', 2) + b'xy'
        self.assertEqual(rp.parse_job(io.BytesIO(good)), (b'abc', b'xy'))
        for name, data in (('magic', b'X' + good[1:]), ('trailing', good + b'\0'), ('truncated', good[:-1]),
                           ('empty request', rp.MAGIC + struct.pack('>I', 0) + struct.pack('>Q', 2) + b'xy'),
                           ('long request', rp.MAGIC + struct.pack('>I', 701) + b'a' * 701 + struct.pack('>Q', 1) + b'x'),
                           ('huge artifact', rp.MAGIC + struct.pack('>I', 1) + b'a' + struct.pack('>Q', 1 << 40))):
            with self.subTest(name), self.assertRaises(ValueError):
                rp.parse_job(io.BytesIO(data))
        self.assertEqual(s.REMOTE_MAGIC, rp.MAGIC)

    def test_remote_prover_runs_the_pinned_prover_and_returns_only_the_proof(self):
        import subprocess
        prover = self.root / 'fake-settlement-v3'
        prover.write_text('#!/bin/sh\n[ "$1 $2" = "prove-groth16 native-artifact" ] || exit 9\n'
                          'cat "$BLOCH_NATIVE_L2_REQUEST" "$BLOCH_NATIVE_L2_ARTIFACT" > "$4"\n')
        prover.chmod(0o755)
        (self.root / 'pwork').mkdir()
        config = {'prover': str(prover), 'prover_sha256': s.digest(prover), 'guest': str(self.root / 'settlement_v3'),
                  'guest_sha256': s.digest(self.root / 'settlement_v3'), 'workdir': str(self.root / 'pwork'),
                  'home': str(self.root / 'home'), 'prover_threads': 4, 'gnark_image': 'image'}
        (self.root / 'prover.json').write_text(json.dumps(config))
        job = rp.MAGIC + struct.pack('>I', 4) + b'req\n' + struct.pack('>Q', 3) + b'art'
        env = {'PATH': '/usr/bin:/bin', 'BLOCH_REMOTE_PROVER_CONFIG': str(self.root / 'prover.json')}
        run = lambda data, **e: subprocess.run([sys.executable, str(HERE / 'remote_prover.py')], input=data,  # noqa: E731
                                               capture_output=True, env={**env, **e})
        done = run(job, SSH_ORIGINAL_COMMAND='prove')
        self.assertEqual((done.returncode, done.stdout), (0, b'req\nart'))
        self.assertEqual([p.name for p in (self.root / 'pwork').iterdir() if p.name.startswith('job-')], [])
        self.assertEqual(run(job, SSH_ORIGINAL_COMMAND='sh -c id').returncode, 64)
        self.assertEqual(run(job[:-1]).returncode, 64)
        config['max_memory_bytes'] = 1  # no test runner sits under a 1-byte cgroup cap
        (self.root / 'prover.json').write_text(json.dumps(config))
        refused = run(job)
        self.assertEqual(refused.returncode, 70)
        self.assertIn(b'memory cap', refused.stderr)
        del config['max_memory_bytes']
        config['prover_sha256'] = '00' * 32
        (self.root / 'prover.json').write_text(json.dumps(config))
        self.assertEqual(run(job).returncode, 70)

    def test_remote_prover_reads_the_tightest_cgroup_memory_cap(self):
        cg = self.root / 'cg'
        (cg / 'user.slice/user-9.slice/session-1.scope').mkdir(parents=True)
        (cg / 'memory.max').write_text('max\n')
        (cg / 'user.slice/memory.max').write_text('max\n')
        (cg / 'user.slice/user-9.slice/memory.max').write_text(str(60 << 30) + '\n')
        (cg / 'user.slice/user-9.slice/session-1.scope/memory.max').write_text('max\n')
        proc = self.root / 'cgroup'
        proc.write_text('0::/user.slice/user-9.slice/session-1.scope\n')
        self.assertEqual(rp.cgroup_memory_cap(str(proc), str(cg)), 60 << 30)
        (cg / 'user.slice/user-9.slice/memory.max').write_text('max\n')
        self.assertIsNone(rp.cgroup_memory_cap(str(proc), str(cg)))


    # ---- native RPC quorum (2 of 3) ----
    def quorum_settler(self, ports, user=False, **extra):
        clock = iter(range(0, 100_000, 3))
        config = self.config(**extra)
        if user:
            config.update(user_transactions=True, txpool_dir=str(self.root / 'txpool'), da=self.da_config())
        return s.Settler(config, rpc=ports.rpc, run=ports.fake.run, sleep=lambda _: None, clock=lambda: next(clock))

    def events(self, recorder):
        return [c.args[0] for c in recorder.call_args_list]

    def test_quorum_all_healthy_behaves_as_before(self):
        fake = Fake(self.root, statement())
        ports = Ports(fake)
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.quorum_settler(ports).cycle())
        self.assertFalse([e for e in self.events(logged) if e.startswith('rpc-')])
        self.assertEqual(ports.count(1), ports.count(2))
        self.assertEqual(ports.count(1), ports.count(3))
        self.assertEqual([p for p, m in ports.calls if m == 'sendrawtransaction'], [1])
        self.assertEqual(len(fake.sent), 1)

    def test_quorum_one_endpoint_down_settles_through_the_others(self):
        for mode in ('down', 'erroring'):
            with self.subTest(mode=mode):
                self.tearDown(), self.setUp()
                fake = Fake(self.root, statement())
                ports = Ports(fake, p1=mode)
                with mock.patch.object(s, 'log') as logged:
                    self.assertTrue(self.quorum_settler(ports).cycle())
                self.assertEqual(len(fake.sent), 1)
                self.assertEqual([p for p, m in ports.calls if m == 'sendrawtransaction'], [2])
                self.assertIn('rpc-endpoint-failed', self.events(logged))
                self.assertLess(ports.count(1), ports.count(2), 'the failed endpoint is backed off')

    def test_quorum_one_endpoint_lagging_is_outvoted_and_reported(self):
        fake = Fake(self.root, statement())
        ports = Ports(fake, p3='lagging')
        settler = self.quorum_settler(ports)
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(settler.cycle())
            for _ in range(3):
                settler.native_view()
        self.assertEqual(len(fake.sent), 1)
        self.assertIn('rpc-endpoint-diverged', self.events(logged))
        self.assertEqual(ports.count(3), ports.count(1), 'a lagging endpoint is still queried')
        request = next((self.root / 'work').glob('*/native-request.txt')).read_text()
        self.assertNotIn('0c' * 32, request)

    def test_quorum_minority_conflicting_data_is_never_used(self):
        fake = Fake(self.root, statement())
        ports = Ports(fake, p2='conflicting')
        self.assertTrue(self.quorum_settler(ports).cycle())
        deposits = json.loads(next((self.root / 'work').glob('*/deposits.json')).read_text())
        self.assertEqual(deposits, PENDING)
        # A minority reporting another network does not halt the worker either.
        self.tearDown(), self.setUp()
        fake = Fake(self.root, statement())
        self.assertTrue(self.quorum_settler(Ports(fake, p3='wrong-network')).cycle())

    def test_quorum_single_endpoint_data_is_refused(self):
        # One down and one conflicting: the remaining honest view has no quorum.
        fake = Fake(self.root, statement())
        settler = self.quorum_settler(Ports(fake, p1='down', p2='conflicting'))
        with mock.patch.object(s, 'log') as logged:
            self.assertFalse(settler.cycle())
        self.assertIn('rpc-no-quorum', self.events(logged))
        self.assertEqual((fake.sent, fake.calls), ([], []))
        # Two down: fewer than a quorum answered, which is a retryable failure.
        fake = Fake(self.root, statement())
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(RuntimeError, '1 of 3 RPC endpoints answered'):
            self.quorum_settler(Ports(fake, p1='down', p3='erroring')).cycle()
        self.assertEqual((fake.sent, fake.calls), ([], []))
        # Three different views: no quorum, nothing produced.
        fake = Fake(self.root, statement())
        with mock.patch.object(s, 'log'):
            self.assertFalse(self.quorum_settler(Ports(fake, p2='conflicting', p3='lagging')).cycle())
        self.assertEqual((fake.sent, fake.calls), ([], []))

    def test_quorum_partial_view_never_moves_the_accepted_head_back(self):
        fake = Fake(self.root, statement())
        fake.accepted = {'statement': statement().hex(), 'commitment': '99' * 32}
        ports = Ports(fake)
        settler = self.quorum_settler(ports)
        self.assertIsNotNone(settler.native_view())
        self.assertEqual(settler.accepted_floor, 1)
        ports.modes = {2: 'lagging', 3: 'lagging'}  # two stale endpoints agree on an older head
        with mock.patch.object(s, 'log') as logged:
            self.assertIsNone(settler.native_view())
        self.assertIn('rpc-quorum-view-behind', self.events(logged))

    def test_quorum_da_fee_and_outputs_need_a_quorum(self):
        fake = Fake(self.root, statement(user_txs=2), produced_txs=2)
        ports = Ports(fake, p1='down')
        honest = [{'txid': '33' * 32, 'vout': 0, 'value_sat': '9000000'}]
        ports.utxos = {2: honest, 3: honest + [{'txid': '77' * 32, 'vout': 0, 'value_sat': '99000000'}]}
        ports.chaininfo = {2: 10, 3: 10 ** 9}
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.quorum_settler(ports, user=True).cycle())
        [prepare] = [c for c in fake.calls if Path(c[0]).name == 'bloch-pos' and c[2] == 'prepare']
        self.assertEqual(prepare[prepare.index('--input') + 1], '33' * 32 + ':0:9000000')
        self.assertNotIn('77' * 32 + ':0:99000000', prepare, 'an output only one endpoint reports is not spent')
        self.assertEqual(prepare[prepare.index('--base-fee') + 1], '10', 'an inflated fee from one endpoint is ignored')
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])
        # With three answers the base fee is the median.
        endpoints = s.Endpoints([1, 2, 3], 2, Ports(fake).rpc, lambda: 0)
        endpoints.rpc.__self__.chaininfo = {1: 7, 2: 12, 3: 10 ** 9}
        self.assertEqual(endpoints.bounded_value('getchaininfo', 'next_base_fee_millisat_per_gas'), 12)

    def test_quorum_submission_falls_through_to_the_next_endpoint(self):
        fake = Fake(self.root, statement())
        ports = Ports(fake)
        ports.reject = {1}
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.quorum_settler(ports).cycle())
        self.assertEqual([p for p, m in ports.calls if m == 'sendrawtransaction'], [1, 2])

    def test_quorum_endpoint_backoff_and_recovery(self):
        now = [0]
        ports = Ports(Fake(self.root, statement()), p1='down')
        endpoints = s.Endpoints([1, 2, 3], 2, ports.rpc, lambda: now[0])
        with mock.patch.object(s, 'log') as logged:
            endpoints.agreed('getl2settlement')
            endpoints.agreed('getl2settlement')
            self.assertEqual(ports.count(1), 1, 'skipped during its 10 s backoff')
            now[0] = 11
            endpoints.agreed('getl2settlement')
            self.assertEqual((ports.count(1), endpoints.state[1]['failures']), (2, 2))
            ports.modes = {}
            now[0] = 40
            view, support = endpoints.agreed('getl2settlement')
        self.assertEqual(support, [1, 2, 3])
        self.assertEqual(endpoints.state[1]['failures'], 0)
        self.assertEqual([c.kwargs.get('backoff_seconds') for c in logged.call_args_list
                          if c.args[0] == 'rpc-endpoint-failed'], [10, 20])
        self.assertIn('rpc-endpoint-recovered', self.events(logged))

    def test_quorum_configuration(self):
        self.assertEqual(s.rpc_quorum({'rpc_ports': [1, 2, 3]}), 2)
        self.assertEqual(s.rpc_quorum({'rpc_ports': [1, 2, 3], 'rpc_quorum': 3}), 3)
        self.assertEqual(s.rpc_quorum({'rpc_ports': [1]}), 1)
        for bad in ({'rpc_ports': [1, 2, 3], 'rpc_quorum': 1}, {'rpc_ports': [1, 2], 'rpc_quorum': 1},
                    {'rpc_ports': [1, 2, 3], 'rpc_quorum': 4}, {'rpc_ports': [1, 1, 2]}, {'rpc_ports': []}):
            with self.assertRaises(s.Halt):
                s.rpc_quorum(bad)
        with self.assertRaisesRegex(s.Halt, 'strict majority'):
            self.settler(Fake(self.root, statement()), rpc_quorum=1)

    def test_check_rpc_is_read_only(self):
        fake = Fake(self.root, statement())
        config = self.config()
        for modes, code in (({}, 0), ({'p3': 'down'}, 0), ({'p2': 'conflicting', 'p3': 'lagging'}, 2),
                            ({'p1': 'down', 'p2': 'down'}, 2)):
            ports = Ports(fake, **modes)
            ports.moving = True
            with mock.patch.object(s, 'log'):
                self.assertEqual(s.check_rpc(config, rpc=ports.rpc, sleep=lambda _: None), code, modes)
            self.assertEqual({m for _, m in ports.calls}, {'getl2settlement'})
        self.assertEqual((fake.sent, fake.calls), ([], []))

    # ---- head moves between reads ----
    def test_quorum_head_moving_between_reads_still_agrees(self):
        # native_height, inbox totals and withdrawal flags change on every read:
        # the worker does not use them, so they do not split the quorum.
        for modes in ({}, {'p1': 'down'}):
            with self.subTest(modes=modes):
                self.tearDown(), self.setUp()
                fake = Fake(self.root, statement())
                ports = Ports(fake, **modes)
                ports.moving = True
                with mock.patch.object(s, 'log') as logged:
                    self.assertTrue(self.quorum_settler(ports).cycle())
                self.assertNotIn('rpc-no-quorum', self.events(logged))
                self.assertEqual(len(fake.sent), 1)

    def test_quorum_split_by_a_new_source_is_reread_before_no_quorum(self):
        # 18940 down; 18942 already saw the next source, 18941 catches up one read later.
        fake = Fake(self.root, statement())
        ports = Ports(fake, p1='down')
        ports.moving = True
        moved = {**fake.view()['source'], 'block': '0d' * 32}
        ports.script = {2: [{}, {'source': moved}], 3: [{'source': moved}, {'source': moved}]}
        sleeps = []
        endpoints = s.Endpoints([1, 2, 3], 2, ports.rpc, lambda: 0, sleeps.append)
        with mock.patch.object(s, 'log') as logged:
            view, support = endpoints.agreed('getl2settlement', project=s.settlement_view)
        self.assertEqual((view['source']['block'], support), ('0d' * 32, [2, 3]))
        self.assertEqual(sleeps, [s.QUORUM_RETRY_SECONDS])
        self.assertNotIn('rpc-no-quorum', self.events(logged))
        self.assertNotIn('native_height', view, 'only the safety-relevant projection is returned')

    def test_quorum_persistent_split_is_logged_once_after_the_retries(self):
        fake = Fake(self.root, statement())
        ports = Ports(fake, p1='down', p2='conflicting')
        ports.moving = True
        sleeps = []
        endpoints = s.Endpoints([1, 2, 3], 2, ports.rpc, lambda: 0, sleeps.append)
        with mock.patch.object(s, 'log') as logged:
            for _ in range(2):
                self.assertEqual(endpoints.agreed('getl2settlement', project=s.settlement_view), (None, []))
        self.assertEqual(self.events(logged).count('rpc-no-quorum'), 1)
        self.assertEqual(ports.count(2), 2 * s.QUORUM_READ_ATTEMPTS, 'every attempt is a fresh read')
        self.assertEqual(len(sleeps), 2 * (s.QUORUM_READ_ATTEMPTS - 1))

    def test_quorum_projection_keeps_every_field_the_worker_reads(self):
        view = {**Fake(self.root, statement()).view(), 'native_height': 7, 'genesis': GENESIS, 'asynchronous': True,
                'inbox': {}, 'withdrawals': {}}
        self.assertEqual(set(s.settlement_view(view)),
                         {'network', 'genesis', 'chain_id', 'asynchronous', 'accepted', 'source', 'data_availability'})
        # A difference in any used field (here the DA records) still splits the quorum.
        fake = Fake(self.root, statement())
        ports = Ports(fake, p1='down')
        ports.script = {3: [{'data_availability': [{'l2_number': 1, 'commitment': '55' * 32, 'height': 9}]}] * 3}
        endpoints = s.Endpoints([1, 2, 3], 2, ports.rpc, lambda: 0, lambda _: None)
        with mock.patch.object(s, 'log'):
            self.assertEqual(endpoints.agreed('getl2settlement', project=s.settlement_view), (None, []))

if __name__ == '__main__':
    unittest.main()
