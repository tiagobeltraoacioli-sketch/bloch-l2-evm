#!/usr/bin/env python3
"""L1 forced inclusion (candidate) in settler_v3.py: the due records, the statement slot, the producer report,
forced-only blocks, crash reuse, idle blocks and the rehearsal-only censor knob.

Run: python3 -m unittest discover -s deployment/devnet -p 'test_*.py' -v
No network, no prover, no Docker.
"""
import json
from pathlib import Path
import random
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as base  # noqa: E402
import test_settler_foreign as foreign  # noqa: E402

ENVELOPE = bytes.fromhex('02f86b82ab3e80843b9aca0084773594008252089400000000000000000000000000000000000000558080c0')
SKIPPED = bytes.fromhex('02f86b82ab3e05843b9aca0084773594008252089400000000000000000000000000000000000000558080c0')


def record(envelope, height=12, txid='a1', gas=21_000, prefix=''):
    return {'height': height, 'l1_txid': prefix + txid * 32, 'envelope_hash': prefix + s.keccak256(envelope).hex(),
            'gas_limit': gas, 'envelope': prefix + envelope.hex()}


DUE = [record(ENVELOPE), record(SKIPPED, txid='a2')]


def forced_view(due, **extra):
    return {'queued': len(due), 'consumed': 0, 'pending': len(due), 'pending_weight': len(due), 'max_pending_weight': 256,
            'root': '77' * 32, 'due': due, 'due_hash': s.forced_hash(due).hex(), 'next_surcharge_sat': '1000', **extra}


def inbox_slot(due):
    return s.inbox_hash(s.deposits_hash(base.PENDING), due)


class ForcedFake(base.Fake):
    """The base world with an enabled forced queue and a producer that reports the forced prefix."""

    def __init__(self, root, values, due, included=1, produced_txs=0, report=True, **kwargs):
        super().__init__(root, values, produced_txs=produced_txs, **kwargs)
        self.due, self.included, self.report = due, included, report

    def view(self):
        view = super().view()
        view['forced'] = forced_view(self.due)
        return view

    def run(self, argv, **kwargs):
        out = super().run(argv, **kwargs)
        if Path(argv[0]).name == 'produce' and argv[1] == 'extend':
            block = json.loads(out.stdout)
            if self.report and '--forced' in argv:
                due = json.loads(Path(argv[argv.index('--forced') + 1]).read_text())
                skipped = [[i, 'nonce'] for i in range(self.included, len(due))]
                block['forced'] = {'due': len(due), 'included': self.included, 'skipped': skipped,
                                   'hashes': [r['envelope_hash'] for r in due[:self.included]]}
                block['user_transactions'] = self.produced_txs
                block['transactions'] = self.produced_txs + self.included
            out.stdout = json.dumps(block)
        return out


class ForcedPrimitivesTest(unittest.TestCase):
    def test_golden_vectors_are_the_native_and_l2_ones(self):
        one = [{'height': 7, 'l1_txid': '11' * 32, 'envelope_hash': '22' * 32, 'gas_limit': 21_000}]
        self.assertEqual(s.forced_record(one[0]).hex(), (7).to_bytes(8, 'big').hex() + '11' * 32 + '22' * 32
                         + (21_000).to_bytes(8, 'big').hex())
        self.assertEqual(s.forced_hash(one).hex(), '3209df24b99a7f67b3f05d26d89b51fc199a2c2cb2ed89b9677fba958f52e099')
        self.assertEqual(s.inbox_hash(s.keccak256(b''), one).hex(),
                         '364cbe02ac69f9eb79d5b5e2dd5dd0fde2f3d80b7ed81ae0e587cef4d785fea3')
        self.assertEqual(s.forced_hash([]), s.keccak256(b''))
        # Nothing consumed: the slot is the deposits hash itself, so such blocks keep their statement bytes.
        self.assertEqual(s.inbox_hash(b'\x33' * 32, []), b'\x33' * 32)

    def test_due_records_are_normalised_and_checked(self):
        due = s.forced_due({'forced': forced_view([record(ENVELOPE, prefix='0x')])})
        self.assertEqual(due, [record(ENVELOPE)])
        self.assertIsNone(s.forced_due({'source': {}}))
        self.assertEqual(s.forced_due({'forced': forced_view([])}), [])
        bad = record(ENVELOPE)
        bad['envelope'] = SKIPPED.hex()
        cases = {
            'does not hash': forced_view([bad], due_hash=s.forced_hash([bad]).hex()),
            'due_hash': forced_view([record(ENVELOPE)], due_hash='00' * 32),
            'malformed': {'due': [{k: v for k, v in record(ENVELOPE).items() if k != 'l1_txid'}]},
            'per-settlement cap': forced_view([record(ENVELOPE, txid=f'{i:02x}') for i in range(17)]),
            'more gas': forced_view([record(ENVELOPE, gas=200_000), record(SKIPPED, txid='a2', gas=200_000)]),
        }
        for name, view in cases.items():
            with self.subTest(name), self.assertRaisesRegex(s.Halt, name):
                s.forced_due({'forced': view})
        unreadable = forced_view([{**record(ENVELOPE), 'envelope': None}])
        with self.assertRaisesRegex(s.WaitForProgram, 'no envelope'):
            s.forced_due({'forced': unreadable})

    def test_the_quorum_compares_only_the_due_records(self):
        view = {'network': 'n', 'forced': forced_view(DUE), 'native_height': 9}
        projected = s.settlement_view(view)
        self.assertEqual(projected['forced'], {'due': DUE, 'due_hash': s.forced_hash(DUE).hex()})
        moved = s.settlement_view({**view, 'forced': forced_view(DUE, queued=9, pending=7, pending_weight=7,
                                                                 next_surcharge_sat='2000')})
        self.assertEqual(moved, projected)

    def test_envelope_sender_recovers_the_eip155_vector_and_a_typed_transaction(self):
        eip155 = bytes.fromhex('f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000'
                               '8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f'
                               '761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83')
        self.assertEqual(s.envelope_sender(eip155).hex(), '9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f')
        rng = random.Random(137)
        key = rng.randrange(1, s.SECP_N)
        public = s._ec_mul(key, s.SECP_G)
        address = s.keccak256(public[0].to_bytes(32, 'big') + public[1].to_bytes(32, 'big'))[12:]
        unsigned = [(700770).to_bytes(3, 'big'), b'', (10 ** 8).to_bytes(4, 'big'), (2 * 10 ** 9).to_bytes(4, 'big'),
                    (21_000).to_bytes(3, 'big'), b'\x00' * 19 + b'\x55', (10 ** 12).to_bytes(5, 'big'), b'', []]
        digest = s.keccak256(b'\x02' + s.rlp_encode(unsigned))
        while True:
            k = rng.randrange(1, s.SECP_N)
            point = s._ec_mul(k, s.SECP_G)
            r = point[0] % s.SECP_N
            sig = pow(k, -1, s.SECP_N) * (int.from_bytes(digest, 'big') + r * key) % s.SECP_N
            if r and sig:
                break
        parity = point[1] & 1
        if sig > s.SECP_N // 2:
            sig, parity = s.SECP_N - sig, parity ^ 1
        raw = b'\x02' + s.rlp_encode(unsigned + [bytes([parity]) if parity else b'', r.to_bytes(32, 'big'),
                                                  sig.to_bytes(32, 'big')])
        self.assertEqual(s.envelope_sender(raw), address)
        self.assertIsNone(s.envelope_sender(b'\x02\xc0'))
        self.assertIsNone(s.envelope_sender(b'not rlp'))


class ForcedSettlerTest(unittest.TestCase):
    T = base.SettlerV3Test
    setUp, tearDown, config, settler, da_config = T.setUp, T.tearDown, T.config, T.settler, T.da_config
    user_settler, extend_call = T.user_settler, T.extend_call

    def cycle(self, fake, user=True, **extra):
        settler = self.user_settler(fake, **extra) if user else self.settler(fake, **extra)
        with mock.patch.object(s, 'log'):
            return settler.cycle()

    def directory(self):
        [directory] = [p for p in (self.root / 'work').iterdir() if p.is_dir()]
        return directory

    def test_a_block_with_due_records_runs_them_and_binds_them_in_the_statement(self):
        fake = ForcedFake(self.root, base.statement(**{str(s.DEPOSITS_HASH): inbox_slot(DUE)}), DUE)
        self.assertTrue(self.cycle(fake, user=False))
        extend = self.extend_call(fake)
        self.assertEqual(json.loads(Path(extend[extend.index('--forced') + 1]).read_text()), DUE)
        self.assertEqual((self.directory() / 'forced.json').read_text(), json.dumps(DUE, sort_keys=True))
        # A forced-only block: no user transaction, no DA batch, only the 0x13 settlement.
        self.assertEqual([tx[0] for tx in fake.sent], [s.ASYNC_SETTLEMENT_TAG])
        self.assertFalse([c for c in fake.calls if c[1:2] == ['da']])

    def test_the_plain_deposits_hash_is_refused_while_records_are_due(self):
        fake = ForcedFake(self.root, base.statement(), DUE)
        with self.assertRaisesRegex(s.Halt, 'deposits_hash does not match the native pending deposits and forced'):
            self.cycle(fake)
        self.assertEqual(fake.sent, [])

    def test_with_nothing_due_nothing_changes(self):
        fake = ForcedFake(self.root, base.statement(), [])
        self.assertTrue(self.cycle(fake, user=False))
        self.assertNotIn('--forced', self.extend_call(fake))
        self.assertEqual((self.directory() / 'forced.json').read_text(), '[]')

    def test_without_the_queue_no_forced_file_is_written(self):
        fake = base.Fake(self.root, base.statement())
        self.assertTrue(self.cycle(fake, user=False))
        self.assertFalse((self.directory() / 'forced.json').exists())

    def test_user_count_is_the_sequencer_part_and_da_covers_only_it(self):
        values = base.statement(user_txs=2, **{str(s.DEPOSITS_HASH): inbox_slot(DUE)})
        fake = ForcedFake(self.root, values, DUE, produced_txs=2)
        self.assertTrue(self.cycle(fake))
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])
        self.assertEqual(s.da_frame_fields(fake.sent[0]), (s.CHAIN_ID, 1, base.batch(2)))
        block = json.loads((self.directory() / 'block.json').read_text())
        self.assertEqual((block['transactions'], block['user_transactions']), (3, 2))

    def test_a_statement_counting_forced_envelopes_as_user_transactions_is_refused(self):
        values = base.statement(user_txs=3, **{str(s.DEPOSITS_HASH): inbox_slot(DUE)})
        fake = ForcedFake(self.root, values, DUE, produced_txs=2, da_payload=base.batch(3))
        with self.assertRaisesRegex(s.Halt, 'reports 3 user transactions, the producer included 2'):
            self.cycle(fake)

    def test_a_producer_that_ignores_the_due_records_is_refused(self):
        fake = ForcedFake(self.root, base.statement(**{str(s.DEPOSITS_HASH): inbox_slot(DUE)}), DUE, report=False)
        with self.assertRaisesRegex(s.Halt, 'did not consume the 2 due forced records'):
            self.cycle(fake)
        fake = ForcedFake(self.root, base.statement(), [])
        fake.extend_extra = {'forced': {'due': 1, 'included': 1, 'skipped': []}}
        self.tearDown(), self.setUp()
        with self.assertRaisesRegex(s.Halt, 'does not name'):
            self.cycle(fake)

    def test_a_crash_left_forced_file_must_match(self):
        fake = ForcedFake(self.root, base.statement(**{str(s.DEPOSITS_HASH): inbox_slot(DUE)}), DUE)
        anchor = (self.root / 'work' / f'{1:08d}-{base.BLOCK[:16]}')
        anchor.mkdir(parents=True)
        (anchor / 'forced.json').write_text(json.dumps(DUE[:1], sort_keys=True))
        with self.assertRaisesRegex(s.Halt, 'already holds different forced records'):
            self.cycle(fake)
        (anchor / 'forced.json').write_text(json.dumps(DUE, sort_keys=True))
        self.assertTrue(self.cycle(fake))

    def test_censored_senders_stay_out_of_every_block_and_only_in_rehearsals(self):
        eip155 = bytes.fromhex('f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000'
                               '8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f'
                               '761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83')
        pool = self.root / 'txpool'
        (pool / 'censored.tx').write_text(eip155.hex() + '\n')
        (pool / 'other.tx').write_text(ENVELOPE.hex() + '\n')
        fake = base.Fake(self.root, base.statement())
        self.assertTrue(self.cycle(fake, censor_senders=['0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f']))
        self.assertFalse((pool / 'censored.tx').exists())
        self.assertTrue((self.root / 'txpool-censored' / 'censored.tx').exists())
        self.assertTrue((pool / 'other.tx').exists())
        for bad, reason in ((['zz'], '20-byte hex'), ('9d8a', '20-byte hex')):
            with self.assertRaisesRegex(s.Halt, reason):
                self.user_settler(fake, censor_senders=bad)
        with self.assertRaisesRegex(s.Halt, 'needs user_transactions'):
            self.settler(fake, censor_senders=[])
        with self.assertRaisesRegex(s.Halt, 'never runs on mainnet'):
            s.check_mainnet_config({'censor_senders': []})


class ForcedIdleWorld(foreign.IdleWorld):
    def __init__(self, root, values):
        super().__init__(root, values)
        self.forced = None

    def view(self):
        view = super().view()
        if self.forced is not None:
            view['forced'] = self.forced
        return view


class ForcedIdleTest(unittest.TestCase):
    settler, held = foreign.IdleTest.settler, foreign.IdleTest.held

    def setUp(self):
        self.base = foreign.ForeignTest('config')
        self.base.setUp()
        self.addCleanup(self.base.tmp.cleanup)
        self.addCleanup(mock.patch.stopall)
        self.root, self.world = self.base.root, ForcedIdleWorld(self.base.root, b'')
        self.options = dict(skip_idle_blocks=True, max_idle_seconds=3000, timestamp_rule='1:1000:30000')

    def test_a_due_forced_record_is_never_held(self):
        self.world.forced = forced_view([])
        self.assertTrue(self.held())
        self.world.forced = forced_view(DUE)
        self.assertFalse(self.held())

    def test_a_record_queued_after_the_freeze_makes_a_block_due(self):
        # The queue froze with the source: `due` is empty, but `pending` shows the new record.
        self.world.forced = forced_view([], pending=1, pending_weight=1)
        self.assertFalse(self.held())


if __name__ == '__main__':
    unittest.main()
