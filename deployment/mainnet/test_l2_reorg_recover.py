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
        def noisy(*_args):
            r.S.log('identity-checked', network='n')
            return {'accepted_number': 5}
        out = io.StringIO()
        with mock.patch.object(r, 'plan', noisy), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(sys, 'argv', ['tool', '--config', str(config), '--follower-state', 'y']):
            r.main()
        self.assertEqual(json.loads(out.getvalue()), {'accepted_number': 5})


if __name__ == '__main__':
    unittest.main()
