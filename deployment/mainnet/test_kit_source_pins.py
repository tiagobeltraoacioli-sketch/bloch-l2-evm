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


class KitPinsCoverTheKitAndThePlan(unittest.TestCase):
    """Review R308-14 / R308-17, agent 312 F312-1: every kit file a host may run or install has a pin line,
    and the go-live plan's hash table and P2 GO line equal the tree. Refresh: refresh_kit_pins.py --write."""

    def test_pin_lists_and_plan_table_equal_the_tree(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('refresh_kit_pins', HERE / 'refresh_kit_pins.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.differences(), [])
        pinned = {name for name, _ in tool.read_pins(HERE / 'GO-LIVE-PINS.sha256')}
        for must in ('kit/install-shadow.sh', 'kit/bloch-l2-mainnet-shadow.service', 'kit/attestor/install-attestor.sh',
                     'kit/attestor/attestor_agent.py', 'kit/follower-rpc/bloch-l2-mainnet-rpc.service',
                     'kit/public-rpc/setup-gateway.sh', 'kit/replica/install-replica.sh', 'kit/monitor/bloch-l2-mainnet-monitor.service'):
            self.assertIn(must, pinned)

if __name__ == '__main__':
    unittest.main()
