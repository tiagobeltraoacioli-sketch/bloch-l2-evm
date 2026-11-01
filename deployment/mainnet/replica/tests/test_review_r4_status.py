#!/usr/bin/env python3
"""Independent review, round 4: the replica package against the next follower's status schema v3.
The refresh code is real. A failure here is a finding. Run: python3 test_review_r4_status.py"""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import replica_refresh as R  # noqa: E402


class SchemaV3(unittest.TestCase):
    def status(self):
        lines = [json.dumps({'l2_number': 1, 'l2_hash': 'aa' * 32, 'l2_state_root': 'bb' * 32}, separators=(',', ':')) + '\n']
        return {'schema': 'bloch.l2.native-follower-status.v3', 'network': R.NETWORK, 'chain_id': R.CHAIN_ID, 'production_finality': False,
                'l2_genesis': {'hash': R.L2_GENESIS, 'finalized': True}, 'written_at_unix': int(time.time()), 'verified_tip': 'cc' * 32,
                'finalized_settlements_count': 1, 'finalized_settlements_recent': [json.loads(lines[0])],
                'settlement_log': {'file': 'status.settlements.jsonl', 'entries': 1, 'bytes': len(lines[0]), 'digest': 'dd' * 32}}, lines

    def test_the_refresh_reads_a_v3_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'status.json'
            status, lines = self.status()
            path.write_text(json.dumps(status))
            path.with_name('status.settlements.jsonl').write_text(''.join(lines))
            self.assertIsNotNone(R.read_status(path, 3600, time.time()))

    def test_the_rebuild_check_covers_settlements_of_a_v3_status(self):
        status, _ = self.status()
        report = {'genesis': R.L2_GENESIS, 'blocks': [{'number': 1, 'hash': 'ff' * 32, 'state_root': 'bb' * 32}]}
        with self.assertRaises(R.Halt, msg='a rebuilt block that contradicts the finalized settlement must halt'):
            R.check_report(report, status, None)


if __name__ == '__main__':
    unittest.main()
