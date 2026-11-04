"""Source payloads in the launch manifest must match the checked-out kit.

Binary pins remain independently built release evidence. This check does not
recompute or approve them and does not turn a source checkout into a release.
"""
import hashlib
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SOURCES = {
    'artifacts/sequencer_mainnet.py': HERE / 'sequencer_mainnet.py',
    'release-settler-v2/settler_v3.py': HERE.parent / 'devnet' / 'settler_v3.py',
    'release-settler-v2/l2_reorg_recover.py': HERE / 'l2_reorg_recover.py',
    'release-settler-v2/install-settler-mainnet.py': HERE / 'install-settler-mainnet.py',
    'kit/l2_monitor.py': HERE / 'l2_monitor.py',
    'kit/l1_monitor.py': HERE / 'l1_monitor.py',
    'kit/attestor/sigfeed.py': HERE / 'attestor' / 'sigfeed.py',
    'kit/prover/install-prover-mainnet.py': HERE / 'prover' / 'install-prover-mainnet.py',
    'kit/verify_release_signature.py': HERE / 'verify_release_signature.py',
    'kit/follower-rpc/install.sh': HERE / 'follower-rpc' / 'install.sh',
    'kit/follower-rpc/l2_read_access.py': HERE / 'follower-rpc' / 'l2_read_access.py',
}


class KitSourcePins(unittest.TestCase):
    def test_each_source_payload_matches_its_release_manifest_entry(self):
        entries = {}
        for line in (HERE / 'GO-LIVE-PINS.sha256').read_text().splitlines():
            digest, name = line.split()
            self.assertNotIn(name, entries, f'duplicate manifest path: {name}')
            entries[name] = digest
        for name, source in SOURCES.items():
            with self.subTest(payload=name):
                self.assertIn(name, entries)
                self.assertEqual(entries[name], hashlib.sha256(source.read_bytes()).hexdigest(),
                                 f'{name} was changed without refreshing its source pin')


if __name__ == '__main__':
    unittest.main()
