#!/usr/bin/env python3
"""install.sh accepts a loopback --l1-rpc-url and refuses any other host unless the operator states that the node and
the path are trusted (review L2-05: the follower reads `safe` from that node without a proof). Dry run, no root."""
import getpass
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

INSTALL = Path(__file__).resolve().parent.parent / 'install.sh'
REFUSED = 'is not loopback'


@unittest.skipUnless(shutil.which('sha256sum'), 'sha256sum not installed')
class L1Source(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.art = t / 'artifacts'
        self.art.mkdir()
        self.canonical = t / 'canonical'
        for d in ('db', 'static', 'rocks'):
            (self.canonical / d).mkdir(parents=True)
        self.txpool = t / 'txpool'
        self.txpool.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_install(self, url, *extra):
        return subprocess.run(['bash', str(INSTALL), '--artifacts', str(self.art), '--l1-rpc-url', url,
                               '--canonical', str(self.canonical), '--canonical-user', getpass.getuser(),
                               '--txpool', str(self.txpool), '--dry-run', *extra], capture_output=True, text=True)

    def test_a_remote_l1_rpc_is_refused_without_the_statement(self):
        for url in ('http://10.0.0.5:8545', 'http://node.example.org:8545', 'http://128.0.0.1:1'):
            done = self.run_install(url)
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            self.assertIn(REFUSED, done.stderr)
            self.assertIn('L2-05', done.stderr)

    def test_loopback_passes_the_check(self):
        for url in ('http://127.0.0.1:8545', 'http://localhost:8545/', 'http://127.1.2.3:1'):
            done = self.run_install(url)
            self.assertNotIn(REFUSED, done.stderr, url)

    def test_the_statement_admits_a_remote_node_with_a_warning(self):
        done = self.run_install('http://10.0.0.5:8545', '--l1-rpc-remote-trusted')
        self.assertNotIn(REFUSED, done.stderr)
        self.assertIn('--l1-rpc-remote-trusted: safe trusts the native node at 10.0.0.5', done.stderr)
        self.assertIn('a follower with the loopback rule reads no safe from a remote node', done.stderr)


if __name__ == '__main__':
    unittest.main()
