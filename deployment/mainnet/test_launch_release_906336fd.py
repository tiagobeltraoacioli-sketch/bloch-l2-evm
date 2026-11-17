"""The launch release is the rebuild against node release 906336fd, and every kit pin names it.

Release `bloch-l2-2026-11-17-launch-native-906336fd` (build commit 3d35a0f, native 906336fd, lock ab7b3a09...) was
built from fresh clones at the reference WORK path on the two build hosts and assembled on each host
independently; both folders are byte-identical. Its metadata files (BUILD-INFO, build.json, release.json, SHA256SUMS:
the signing target) are kept in testdata/release-906336fd/. The binaries are not in the repository; their hashes are
in SHA256SUMS and build.json, which these tests tie to every place of the kit that pins a binary of the release.

The earlier build 926d2cf / native 78d4921c (signing target 6d3bd628...) halts on the fleet's chain after the KES
bind (docs/L2-FOLLOWER-NODE-906336FD.md): no installer, monitor or pin list may still accept it.
"""
import hashlib
import importlib.util
import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REL = HERE / 'testdata' / 'release-906336fd'
L2_COMMIT = '3d35a0f42f9b5f1a8657ee892dc3239a789a50ae'
NATIVE = '906336fd35f157dac380523b59dee8a5a325175a'
FLEET = '0067547f1cd8f740fa1b814361526a80be178885'
LOCK = 'ab7b3a0901f142d5e2a3905c68cf97eb69eb5cc968407621e55f21f14668cafa'
GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
OLD = {
    'follower': 'cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2',
    'produce': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
    'sums': '6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19',
    'build_json': '6ec47c0c35a9a6051028947c33c235d8364e518c904c7924bf441019303827c6',
    'lock': 'a3c38a462a273fc07b618ebb2a6dda51377ea7d2deb8530c44a17bc4bf3908a9',
    'l2_commit': '926d2cf50af11f389ad1ffa91c0b7720178b3472',
}
# Files a host runs or reads that pin a binary of the launch release.
PINNING = ['GO-LIVE-PINS.sha256', 'install-settler-mainnet.py', 'install-shadow.sh', 'l2_monitor.py',
           'follower-rpc/install.sh', 'attestor/install-attestor.sh', 'attestor/keykit/operator-pins-v2.sha256',
           'replica/PINS.sha256']


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def text(rel):
    return (HERE / rel).read_text()


def load_monitor():
    spec = importlib.util.spec_from_file_location('l2_monitor_launch_test', HERE / 'l2_monitor.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TheRelease(unittest.TestCase):
    def setUp(self):
        self.build = json.loads((REL / 'build.json').read_text())
        self.release = json.loads((REL / 'release.json').read_text())
        self.sums = dict(reversed(line.split('  ', 1)) for line in (REL / 'SHA256SUMS').read_text().splitlines())

    def test_metadata_files_are_the_ones_the_signing_target_covers(self):
        for name in ('BUILD-INFO', 'build.json', 'release.json'):
            self.assertEqual(self.sums[name], sha(REL / name), name)
        self.assertEqual(set(self.sums), {'BUILD-INFO', 'bloch-l2-native-follower', 'bloch-l2-produce-dev',
                                          'bloch-l2-settled-rpc', 'build.json', 'release.json', 'sequencer_mainnet.py',
                                          'settlement-recovery.native-906336fd.Cargo.lock'})
        self.assertEqual(self.sums['settlement-recovery.native-906336fd.Cargo.lock'],
                         sha(HERE / 'follower-rpc' / 'settlement-recovery.native-906336fd.Cargo.lock'))

    def test_build_json_is_the_rebuild_against_906336fd(self):
        b = self.build
        self.assertEqual(b['l2_commit'], L2_COMMIT)
        self.assertEqual(b['l2_tracked_changes'], 0)
        self.assertTrue(b['native'].startswith(NATIVE + ' '))
        self.assertEqual(b['settlement_recovery_lock_sha256'], LOCK)
        self.assertEqual(b['l2_genesis']['hash'], GENESIS)
        g = b['l1_activation_epochs']
        for k in ('HF3_KES_ENFORCE_EPOCH', 'ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH',
                  'KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH'):
            self.assertEqual(g[k], 8620, k)
        for name, digest in b['sha256'].items():
            self.assertEqual(self.sums[name], digest, name)

    def test_release_json_names_the_release_and_the_fleet(self):
        r = self.release
        self.assertEqual(r['release'], 'bloch-l2-2026-11-17-launch-native-906336fd')
        self.assertEqual((r['l2_commit'], r['native_commit'], r['chain_id']), (L2_COMMIT, NATIVE, 700770))
        self.assertEqual(r['compatible_l1_fleet'], [NATIVE, FLEET])
        self.assertEqual(r['binaries'], self.build['sha256'])
        self.assertFalse(r['signed'])

    def test_unchanged_files_keep_their_launch_pins(self):
        # Only the follower and the producer link the native transition; the settled RPC and the sequencer did not move.
        self.assertEqual(self.sums['bloch-l2-settled-rpc'], '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d')
        self.assertEqual(self.sums['sequencer_mainnet.py'], '15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2')


class EveryPinNamesTheRelease(unittest.TestCase):
    def setUp(self):
        b = json.loads((REL / 'build.json').read_text())
        self.follower = b['sha256']['bloch-l2-native-follower']
        self.produce = b['sha256']['bloch-l2-produce-dev']
        self.target = sha(REL / 'SHA256SUMS')

    def test_no_kit_file_pins_the_earlier_build(self):
        for rel in PINNING:
            t = text(rel)
            for what in ('follower', 'produce', 'sums', 'build_json'):
                self.assertNotIn(OLD[what], t, f'{rel} still pins the earlier build ({what})')

    def test_go_live_pins_name_the_release(self):
        pins = {}
        for line in text('GO-LIVE-PINS.sha256').splitlines():
            digest, path = line.split('  ', 1)
            pins.setdefault(path, digest)
        self.assertEqual(pins['artifacts/bloch-l2-native-follower'], self.follower)
        self.assertEqual(pins['artifacts/bloch-l2-produce-dev'], self.produce)
        self.assertEqual(pins['release-settler-v2/bloch-l2-produce-dev'], self.produce)
        self.assertEqual(pins['artifacts/build.json'], sha(REL / 'build.json'))
        self.assertEqual(pins['artifacts/SHA256SUMS'], self.target)

    def test_installers_name_the_release(self):
        self.assertRegex(text('follower-rpc/install.sh'), rf'(?m)^RELEASE_SHA256SUMS_SHA256={self.target}$')
        self.assertIn(f"'bloch-l2-produce-dev': '{self.produce}'", text('install-settler-mainnet.py'))
        shadow = text('install-shadow.sh')
        for line in (f'PRODUCE_SHA256={self.produce}', f'L2_COMMIT={L2_COMMIT}', f'NATIVE_COMMIT={NATIVE}',
                     f'NATIVE_LOCK_SHA256={LOCK}'):
            self.assertRegex(shadow, rf'(?m)^{re.escape(line)}$')
        att = text('attestor/install-attestor.sh')
        self.assertRegex(att, rf'(?m)^V2_FOLLOWER_SHA256={self.follower}$')
        self.assertRegex(att, rf'(?m)^V2_PRODUCE_SHA256={self.produce}$')
        for rel in ('attestor/keykit/operator-pins-v2.sha256', 'replica/PINS.sha256'):
            t = text(rel)
            self.assertIn(f'{self.follower}  bloch-l2-native-follower', t, rel)
            self.assertIn(f'{self.produce}  bloch-l2-produce-dev', t, rel)

    def test_the_shadow_requires_the_two_8620_gates(self):
        shadow = text('install-shadow.sh')
        for k in ('ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH', 'KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH'):
            self.assertRegex(shadow, rf"'{k}': 8620")

    def test_the_monitor_knows_the_release(self):
        m = load_monitor()
        self.assertEqual(m.V2_BUILD['l2_commit'], L2_COMMIT)
        self.assertEqual(m.V2_BUILD['native'], NATIVE)
        self.assertEqual(m.V2_BUILD['native_lock_sha256'], LOCK)
        self.assertEqual(m.V2_SHA256['bloch-l2-native-follower'], self.follower)
        self.assertEqual(m.V2_SHA256['bloch-l2-produce-dev'], self.produce)
        built = json.loads((REL / 'build.json').read_text())['l1_activation_epochs']
        for k in ('ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH', 'KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH'):
            self.assertEqual(m.V2_COMPILED_GATES.get(k), 8620, k)
        for k, v in m.V2_COMPILED_GATES.items():
            self.assertEqual(built[k], v, k)


if __name__ == '__main__':
    unittest.main()
