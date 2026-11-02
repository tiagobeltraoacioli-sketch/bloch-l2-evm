#!/usr/bin/env python3
"""Tests of the reorg recovery tool's file handling; the whole path runs in the l1-reorg recovery drill."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import l2_reorg_recover as r  # noqa: E402


def batch(*txs):
    return len(txs).to_bytes(4, 'big') + b''.join(len(t).to_bytes(4, 'big') + t for t in txs)


class RecoverFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_finalized_hash_reads_either_status_schema(self):
        v2 = {'finalized_settlements': [{'l2_number': 1, 'l2_hash': 'a'}]}
        self.assertEqual(r.finalized_hash(v2, None, 1), 'a')
        self.assertIsNone(r.finalized_hash(v2, None, 2))
        lines = ''.join(json.dumps({'l2_number': n, 'l2_hash': f'h{n}'}) + '\n' for n in range(1, 101))
        (self.root / 's.settlements.jsonl').write_text(lines)
        v3 = {'finalized_settlements_recent': [{'l2_number': 100, 'l2_hash': 'h100'}],
              'settlement_log': {'file': 's.settlements.jsonl', 'entries': 100, 'bytes': len(lines), 'digest': ''}}
        status = self.root / 's.json'
        self.assertEqual(r.finalized_hash(v3, status, 100), 'h100')
        self.assertEqual(r.finalized_hash(v3, status, 7), 'h7')
        self.assertIsNone(r.finalized_hash(v3, status, 101))
        self.assertIsNone(r.finalized_hash(v3, status, 0))

    def test_batch_transactions_returns_each_raw_transaction(self):
        self.assertEqual(r.batch_transactions(batch(b'\x02abc', b'\x02de')), [b'\x02abc', b'\x02de'])

    def test_malformed_batch_is_refused(self):
        for bad in (b'', batch(b'a') + b'x', (2).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + b'a'):
            with self.assertRaises(r.Refuse):
                r.batch_transactions(bad)

    def test_only_blocks_above_the_accepted_number_are_orphaned(self):
        for name in ('00000051-aa', '00000052-bb', '00000053-cc', 'notes', '.probe'):
            (self.root / name).mkdir()
        self.assertEqual([p.name for p in r.orphaned_dirs(self.root, 51)], ['00000052-bb', '00000053-cc'])

    def test_respool_names_entries_by_hash_and_keeps_existing_ones(self):
        pool = self.root / 'pool'
        pool.mkdir()
        block = self.root / '00000052-bb'
        block.mkdir()
        (block / 'da-payload.hex').write_text(batch(b'one', b'two').hex() + '\n')
        empty = self.root / '00000053-cc'
        empty.mkdir()
        written = r.respool([block, empty], pool)
        self.assertEqual(sorted(written), sorted(r.S.keccak256(t).hex() + '.tx' for t in (b'one', b'two')))
        self.assertEqual((pool / (r.S.keccak256(b'one').hex() + '.tx')).read_text(), b'one'.hex() + '\n')
        self.assertEqual(r.respool([block], pool), [])
        self.assertEqual([p.name for p in pool.iterdir() if p.name.endswith('.tmp')], [])

    def test_stdout_is_one_json_document_even_when_the_worker_logs(self):
        config = self.root / 'settler.json'
        config.write_text(json.dumps({'follower_status': 'x'}))
        def noisy(*_args, **_kw):
            r.S.log('identity-checked', network='n')
            return {'accepted_number': 5}
        out = io.StringIO()
        with mock.patch.object(r, 'plan', noisy), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(sys, 'argv', ['tool', '--config', str(config), '--follower-state', 'y']):
            r.main()
        self.assertEqual(json.loads(out.getvalue()), {'accepted_number': 5})


class FakeSettler:
    """What plan() reads from settler_v3.Settler: identity, the quorum view, the producer."""

    def __init__(self, root, view, head, rebuilt_head):
        self.root, self.view, self.head, self.rebuilt_head, self.chain_id = root, view, head, rebuilt_head, r.S.CHAIN_ID
        self.calls = []

    def check_identity(self):
        return True

    def native_view(self):
        return self.view

    def local_hash(self, number):
        return 'aa' * 32

    def produce(self, *args):
        self.calls.append(args)
        if args[0] == 'head':
            return {'number': self.head, 'hash': 'aa' * 32}
        if args[0] == 'reconstruct':
            Path(args[args.index('--target') + 1]).mkdir()
            return {'head': self.rebuilt_head, 'settled': 3}
        raise AssertionError(args)


class BehindAccepted(unittest.TestCase):
    """A restored backup behind the accepted head (agents/106): rebuild from L1, and return the user transactions of
    the unsettled block whose batch this DA key already paid, from L1 and from the pre-restore work directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('db', 'work', 'pool', 'follower/blocks', 'live-work/00000004-aa'):
            (self.root / name).mkdir(parents=True)
        self.key = b'\x5a' * 3749
        (self.root / 'da.pub').write_text(self.key.hex() + '\n')
        self.paid = batch(b'\x02paid-one', b'\x02paid-two')
        (self.root / 'live-work/00000004-aa/da-payload.hex').write_text(batch(b'\x02paid-one', b'\x02live').hex())
        frame = (bytes([r.S.DA_TAG]) + b'\x91' * 32 + len(self.key).to_bytes(4, 'little') + self.key
                 + (1).to_bytes(4, 'little') + b'\x33' * 36 + r.S.CHAIN_ID.to_bytes(8, 'little')
                 + (4).to_bytes(8, 'little') + len(self.paid).to_bytes(4, 'little') + self.paid + b'\0' * 60)
        (self.root / 'follower/blocks' / ('01' * 32 + '.bin')).write_bytes(b'\x15junk' + frame)
        (self.root / 'follower/index').write_text('01' * 32 + '\n')
        statement = bytearray(r.S.VALUES_BYTES)
        statement[:r.S.T] = r.S.TAG
        statement[r.S.T + 264:r.S.T + 272] = (3).to_bytes(8, 'big')
        statement[r.S.T + 336:r.S.T + 368] = b'\x33' * 32
        self.view = {'accepted': {'statement': bytes(statement).hex(), 'commitment': '99' * 32},
                     'data_availability': [{'l2_number': 4, 'commitment': r.S.da_commitment(4, self.paid).hex(),
                                            'height': 1}]}
        self.config = {'l2_db': str(self.root / 'db'), 'workdir': str(self.root / 'work'),
                       'txpool_dir': str(self.root / 'pool'), 'user_transactions': True,
                       'da': {'funding_pubkey': str(self.root / 'da.pub')}}
        self.status = {'finalized_settlements': [{'l2_number': 3, 'l2_hash': '33' * 32}]}

    def plan(self, head, apply=True, **kw):
        settler = FakeSettler(self.root, self.view, head, '33' * 32)
        with mock.patch.object(r.S, 'Settler', lambda config: settler):
            return r.plan(self.config, self.root / 'follower', apply, status=self.status, **kw), settler

    def test_database_behind_the_accepted_head_is_rebuilt_and_respooled(self):
        report, settler = self.plan(2, respool_from=[self.root / 'live-work'])
        self.assertEqual(report['database'], 'behind')
        pool = sorted(p.name for p in (self.root / 'pool').iterdir())
        expected = {r.S.keccak256(t).hex() + '.tx' for t in (b'\x02paid-one', b'\x02live')}
        self.assertEqual(set(pool), expected, 'only the pre-restore work directory is re-spooled')
        self.assertEqual(report['respooled'], 2)
        self.assertTrue(Path(report['old_database']).is_dir())
        self.assertEqual([c[0] for c in settler.calls], ['head', 'reconstruct'])

    def test_a_batch_on_l1_is_never_respooled(self):
        # The follower store holds a frame naming this settler's DA key for block 4 (setUp). L1 does not prove who
        # paid for a batch (agents/145 F1), so nothing is taken from L1, whichever key the frame names.
        report, _ = self.plan(2)
        self.assertEqual(report['respooled'], 0)
        self.assertNotIn('l1_batches', report)
        self.assertEqual(list((self.root / 'pool').iterdir()), [])
        self.assertFalse(hasattr(r, 'own_l1_batches'))

    def test_dry_run_reports_and_changes_nothing(self):
        report, _ = self.plan(2, apply=False)
        self.assertEqual(report['database'], 'behind')
        self.assertEqual(list((self.root / 'pool').iterdir()), [])
        self.assertEqual(sorted(p.name for p in self.root.iterdir() if p.name.startswith('db')), ['db'])

    def test_the_accepted_head_itself_is_still_refused(self):
        settler = FakeSettler(self.root, self.view, 3, '33' * 32)
        settler.local_hash = lambda number: '33' * 32
        with self.assertRaisesRegex(r.Refuse, 'nothing to recover'), mock.patch.object(r.S, 'Settler', lambda c: settler):
            r.plan(self.config, self.root / 'follower', True, status=self.status)


if __name__ == '__main__':
    unittest.main()
