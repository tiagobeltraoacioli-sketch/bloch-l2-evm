#!/usr/bin/env python3
"""settler_v3: re-signing a DA batch when the fee moves, and never paying a second DA fee for an L2 number whose batch
this worker's DA key already paid (a database restored to the accepted head).

Run: python3 deployment/devnet/test_settler_r7.py
Same fakes as test_settler_v3.py: no network, no prover, no Docker.
"""
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as t  # noqa: E402


def prepares(fake):
    return [c for c in fake.calls if Path(c[0]).name == 'bloch-pos' and c[2] == 'prepare']


def inputs_of(call):
    return [call[i + 1] for i, a in enumerate(call) if a == '--input']


class Base(unittest.TestCase):
    """The fixture helpers of test_settler_v3.SettlerV3Test, without its tests."""
    setUp, tearDown, config, settler = (t.SettlerV3Test.setUp, t.SettlerV3Test.tearDown, t.SettlerV3Test.config,
                                        t.SettlerV3Test.settler)
    da_config, user_settler = t.SettlerV3Test.da_config, t.SettlerV3Test.user_settler


class FeeMarket(t.Fake):
    """A DA transaction is included only while the next base fee is the one it was signed for."""

    def __init__(self, root, values, produced_txs=0, fees=('10',), by='sends', **kw):
        super().__init__(root, values, produced_txs, **kw)
        self.fees, self.by, self.reads, self.da_sends, self.signed_fee = list(fees), by, 0, 0, {}
        self.extra_utxos = []

    def fee(self):
        """fees[k]: k = DA transactions sent so far (by='sends'), or getchaininfo reads (by='reads')."""
        k = self.da_sends if self.by == 'sends' else self.reads
        return self.fees[min(k, len(self.fees) - 1)]

    def rpc(self, port, method, params=()):
        if method == 'getchaininfo':
            self.reads += 1
            return {'next_base_fee_millisat_per_gas': self.fee(), 'epoch': self.epoch}
        if method == 'getutxos':
            answer = super().rpc(port, method, params)
            answer['utxos'] = self.extra_utxos + answer['utxos']
            return answer
        if method == 'sendrawtransaction' and params[0].startswith('15'):
            tx = bytes.fromhex(params[0])
            self.sent.append(tx)
            self.da_sends += 1
            if self.include_da and self.signed_fee.get(tx) == self.fee():
                _, number, payload = s.da_frame_fields(tx)
                self.da_records.append({'l2_number': number, 'commitment': s.da_commitment(number, payload).hex(),
                                        'height': 9})
            return {'status': 'accepted', 'tx_hash': '01' * 32}
        return super().rpc(port, method, params)

    def run(self, argv, **kwargs):
        out = super().run(argv, **kwargs)
        if Path(argv[0]).name == 'bloch-pos' and argv[2] == 'prepare' and not out.returncode:
            # Make the frames of different attempts distinct and remember the fee each was signed for.
            path = Path(argv[argv.index('--out') + 1])
            fee = argv[argv.index('--base-fee') + 1]
            frame = bytes.fromhex(path.read_text().strip()) + fee.encode()
            path.write_text(frame.hex() + '\n')
            self.signed_fee[frame] = fee
        return out


class FeeMoves(Base):
    def test_da_is_resigned_as_soon_as_the_fee_moves(self):
        # Signed at 10; the next base fee is 11 from the second read on and stays there. The old worker waited
        # inclusion_timeout_seconds (1800 on mainnet) on bytes that could never be included.
        fake = FeeMarket(self.root, t.statement(user_txs=2), produced_txs=2, fees=('10', '11'))
        da = {**self.da_config(), 'inclusion_timeout_seconds': 1800}
        clock = iter(range(0, 100_000, 3))
        settler = s.Settler(self.config(user_transactions=True, txpool_dir=str(self.root / 'txpool'), da=da),
                            rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
        self.assertTrue(settler.cycle(), 'settled in the same cycle, no inclusion timeout')
        calls = prepares(fake)
        self.assertEqual([c[c.index('--base-fee') + 1] for c in calls], ['10', '11'])
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG, s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])
        self.assertEqual(len(fake.da_records), 1, 'one record: one fee')
        self.assertLess(next(clock), 200, 'well inside one inclusion timeout')

    def test_a_new_attempt_spends_the_previous_inputs_first(self):
        # A larger output appears after the first attempt (a funding transfer). Sorting by value alone would sign the
        # second attempt from it, and both attempts could then be included: two fees for one batch.
        fake = FeeMarket(self.root, t.statement(user_txs=2), produced_txs=2, fees=('10', '11'))
        settler = self.user_settler(fake, da={**self.da_config(), 'inclusion_timeout_seconds': 1800})
        original = fake.run

        def run(argv, **kwargs):
            out = original(argv, **kwargs)
            if Path(argv[0]).name == 'bloch-pos' and argv[2] == 'sign' and not fake.extra_utxos:
                fake.extra_utxos.append({'txid': '35' * 32, 'vout': 0, 'value_sat': '90000000', 'script_hash': 'x'})
            return out
        fake.run = settler.run = run
        self.assertTrue(settler.cycle())
        first, second = prepares(fake)
        self.assertEqual(inputs_of(first)[-1], f"{'33' * 32}:0:9000000")
        self.assertIn(f"{'33' * 32}:0:9000000", inputs_of(second), 'the attempts conflict on the same input')

    def test_resigning_is_capped_by_the_mempool_retention_window(self):
        # The fee moves on every read and the DA is never included: at most max_attempts_per_window signatures,
        # then the worker waits on the last attempt (stale attempts fill the per-source mempool cap of 64).
        fake = FeeMarket(self.root, t.statement(user_txs=2), produced_txs=2, fees=[str(10 + i) for i in range(400)], by='reads')
        fake.include_da = False
        settler = self.user_settler(fake, da={**self.da_config(), 'inclusion_timeout_seconds': 60,
                                              'max_attempts_per_window': 3})
        self.assertFalse(settler.cycle())
        self.assertEqual(len(prepares(fake)), 3)
        meta = [json.loads(p.read_text()) for p in sorted((self.root / 'work').glob('*/da-meta-*.json'))]
        self.assertEqual(len(meta), 3)
        self.assertTrue(all(isinstance(m['signed_unix'], int) for m in meta))
        # Outside the window the cap is free again.
        settler.wall = lambda: meta[-1]['signed_unix'] + 4000
        before = len(prepares(fake))
        self.assertFalse(settler.cycle())
        self.assertGreater(len(prepares(fake)), before)

    def test_a_steady_fee_keeps_waiting_on_the_same_bytes(self):
        fake = FeeMarket(self.root, t.statement(user_txs=2), produced_txs=2, fees=('10',))
        fake.include_da = False
        settler = self.user_settler(fake, da={**self.da_config(), 'inclusion_timeout_seconds': 60})
        self.assertFalse(settler.cycle())
        self.assertEqual(len(prepares(fake)), 1)
        self.assertEqual(len(fake.sent), 1)


class Restored(t.Fake):
    """The producer reproduces the paid batch when given exactly its transactions; the main spool now holds
    something else (the restore lost the paid transactions, newer ones arrived)."""

    def __init__(self, root, values, paid, other):
        super().__init__(root, values, produced_txs=s.da_batch_count(paid))
        self.paid, self.other, self.pools = paid, other, []

    def run(self, argv, **kwargs):
        if Path(argv[0]).name == 'produce' and argv[1] == 'extend':
            pool = argv[argv.index('--txs') + 1] if '--txs' in argv else None
            self.pools.append(pool)
            self.da_payload = self.paid if pool and pool.endswith('da-reuse-spool') else self.other
            self.produced_txs = s.da_batch_count(self.da_payload) if pool else 0
            self.values = t.statement(user_txs=self.produced_txs)  # the proof follows the block actually built
        return super().run(argv, **kwargs)


class PaidBatch(Base):
    def follower_store(self, frames, junk=b'\x15\x00\x15' * 50):
        state = self.root / 'follower'
        (state / 'blocks').mkdir(parents=True)
        ids = []
        for i, frame in enumerate(frames):
            block_id = f'{i + 1:064x}'
            (state / 'blocks' / f'{block_id}.bin').write_bytes(junk + frame + junk)
            ids.append(block_id)
        (state / 'index').write_text(''.join(i + '\n' for i in ids))
        return state

    def own_frame(self, number, payload, key=None):
        key = key if key is not None else bytes.fromhex((self.root / 'da.pub').read_text().strip())
        return (bytes([s.DA_TAG]) + b'\x91' * 32 + len(key).to_bytes(4, 'little') + key + (1).to_bytes(4, 'little')
                + b'\x33' * 36 + s.CHAIN_ID.to_bytes(8, 'little') + number.to_bytes(8, 'little')
                + len(payload).to_bytes(4, 'little') + payload + b'\0' * 60)

    def setUp(self):
        super().setUp()
        (self.root / 'da.pub').write_text('5a' * 3749)
        self.paid, self.other = t.batch(2), t.batch(3)

    def test_restored_head_rebuilds_the_paid_batch_and_pays_no_second_fee(self):
        fake = Restored(self.root, t.statement(user_txs=2), self.paid, self.other)
        fake.da_records.append({'l2_number': 1, 'commitment': s.da_commitment(1, self.paid).hex(), 'height': 2})
        state = self.follower_store([b'\x01' * 40, self.own_frame(1, self.paid)])
        settler = self.user_settler(fake, follower_state=str(state))
        self.assertTrue(settler.cycle())
        self.assertEqual([tx[0] for tx in fake.sent], [s.ASYNC_SETTLEMENT_TAG], 'no DA transaction: no second fee')
        self.assertTrue(fake.pools[0].endswith('da-reuse-spool'))
        spool = sorted(p.name for p in (self.root / 'txpool').iterdir())
        self.assertEqual(spool, sorted(f'{s.keccak256(raw).hex()}.tx' for raw in s.da_batch_transactions(self.paid)),
                         'the paid transactions are back in the main spool too')

    def test_foreign_recovery_follower_state_is_used(self):
        fake = Restored(self.root, t.statement(user_txs=2), self.paid, self.other)
        fake.da_records.append({'l2_number': 1, 'commitment': s.da_commitment(1, self.paid).hex(), 'height': 1})
        state = self.follower_store([self.own_frame(1, self.paid)])
        settler = self.user_settler(fake, foreign_recovery={'follower_state': str(state),
                                                            'follower_status': str(self.root / 'status.json')})
        self.assertTrue(settler.cycle())
        self.assertEqual([tx[0] for tx in fake.sent], [s.ASYNC_SETTLEMENT_TAG])

    def test_a_batch_paid_by_another_key_is_never_reused(self):
        # Anyone can publish a DA record for any number: reusing it would let a third party fill the block.
        fake = Restored(self.root, t.statement(user_txs=3),
                        self.paid, self.other)
        fake.da_records.append({'l2_number': 1, 'commitment': s.da_commitment(1, self.paid).hex(), 'height': 1})
        state = self.follower_store([self.own_frame(1, self.paid, key=b'\x77' * 3749)])
        settler = self.user_settler(fake, follower_state=str(state))
        self.assertTrue(settler.cycle())
        self.assertEqual(fake.pools, [str(self.root / 'txpool')])
        self.assertEqual([tx[0] for tx in fake.sent], [s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])

    def test_scan_matches_only_the_recorded_commitment(self):
        payload = t.batch(2)
        frame = self.own_frame(4, payload)
        wanted = {(4, s.da_commitment(4, payload).hex())}
        data = b'\x15' * 7 + self.own_frame(4, t.batch(1)) + frame + b'\x15\x01'
        found = s.scan_da_frames(data, s.CHAIN_ID, wanted)
        self.assertEqual(list(found), list(wanted))
        self.assertEqual(found[next(iter(wanted))][1], payload)
        self.assertEqual(s.scan_da_frames(data, s.CHAIN_ID + 1, wanted), {})
        self.assertEqual(s.scan_da_frames(data, s.CHAIN_ID, {(4, '00' * 32)}), {})


if __name__ == '__main__':
    unittest.main()
