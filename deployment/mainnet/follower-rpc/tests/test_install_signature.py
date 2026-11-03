#!/usr/bin/env python3
"""install.sh refuses a release directory without a valid owner signature (dry run, no root)."""
import getpass
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
INSTALL = HERE.parent / 'install.sh'
MAINNET = HERE.parent.parent
sys.path.insert(0, str(MAINNET))
from test_verify_release_signature import Key  # noqa: E402
import verify_release_signature as v  # noqa: E402


@unittest.skipUnless(shutil.which('sha256sum'), 'sha256sum not installed')
class InstallSignature(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.art = t / 'artifacts'
        self.art.mkdir()
        for n in ('bloch-l2-native-follower', 'bloch-l2-settled-rpc'):
            (self.art / n).write_bytes(n.encode())
        release = {'release': 'bloch-l2-test', 'chain_id': 700770, 'l2_commit': 'c' * 40,
                   'native_commit': 'd' * 40, 'platform': 'linux-x86_64'}
        (self.art / 'release.json').write_text(json.dumps(release))
        sums = ''.join(f'{hashlib.sha256((self.art / n).read_bytes()).hexdigest()}  {n}\n'
                       for n in ('bloch-l2-native-follower', 'bloch-l2-settled-rpc', 'release.json'))
        (self.art / 'SHA256SUMS').write_text(sums)
        (self.art / 'mainnet.manifest').write_text('not the manifest')
        self.canonical = t / 'canonical'
        for d in ('db', 'static', 'rocks'):
            (self.canonical / d).mkdir(parents=True)
        self.txpool = t / 'txpool'
        self.txpool.mkdir()
        self.release, self.sums = release, sums.encode()

    def tearDown(self):
        self.tmp.cleanup()

    def run_install(self, *extra):
        return subprocess.run(['bash', str(INSTALL), '--artifacts', str(self.art), '--l1-rpc-url', 'http://127.0.0.1:1',
                               '--canonical', str(self.canonical), '--canonical-user', getpass.getuser(),
                               '--txpool', str(self.txpool), '--dry-run', *extra], capture_output=True, text=True)

    def test_unsigned_release_refused(self):
        done = self.run_install()
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('release signature check failed', done.stderr)
        self.assertIn('SHA256SUMS.minisig', done.stderr)

    def test_signature_by_other_key_refused(self):
        key = Key(b'not the release key')
        trusted = v.canonical_trusted_comment(self.release, hashlib.sha256(self.sums).hexdigest())
        (self.art / 'SHA256SUMS.minisig').write_bytes(key.minisig(self.sums, trusted))
        done = self.run_install()
        self.assertEqual(done.returncode, 1)
        self.assertIn('is not the pinned key 1A5D96A5C4955EF7', done.stderr)
        self.assertIn('release signature check failed', done.stderr)

    def test_allow_unsigned_skips_check_loudly(self):
        done = self.run_install('--allow-unsigned')
        self.assertIn('WARNING: --allow-unsigned', done.stderr)
        self.assertNotIn('release signature check failed', done.stderr)
        # It then reaches the hash checks; the fake manifest stops it there.
        self.assertIn('mainnet.manifest is not Genesis-4', done.stderr)


if __name__ == '__main__':
    unittest.main()
