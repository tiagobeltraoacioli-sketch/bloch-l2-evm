#!/usr/bin/env python3
"""The go-live plan's commands, as run word for word in the round-11 rehearsal (agent 202), and the hints the
installers print:

- P2 stages A and B from the owner's signed copy on the Mac, never host to host with `scp -3` (it dropped twice);
- the first call to the settled RPC after `systemctl enable --now`/`start` retries a refused connection (exit 7
  right after the start);
- the L1 RPCs are the owner's configuration (L1-8): the plan's settler `configure` passes `--rpc-urls`, names no
  validator host, and the installer refuses the plan's placeholder until the owner fills it in.
No host, no network."""
import importlib.util
import os
from pathlib import Path
import re
import shlex
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PLAN = ROOT / 'docs' / 'L2-MAINNET-GO-LIVE.md'
INSTALL_SH = HERE / 'follower-rpc' / 'install.sh'
spec = importlib.util.spec_from_file_location('install_settler_plan', HERE / 'install-settler-mainnet.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def blocks(text):
    """The plan's command blocks (```-fenced, no language tag), in order."""
    return [b.strip() for b in re.findall(r'^```\n(.*?)^```', text, re.S | re.M)]


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PLAN.read_text()
        cls.blocks = blocks(cls.text)

    def commands(self, prefix):
        return [b for b in self.blocks if b.startswith(prefix)]

    def test_no_third_party_scp(self):
        for block in self.blocks:
            for line in block.splitlines():
                self.assertNotRegex(line, r'^\s*scp\b.*\s-3\b', f'host-to-host scp in the plan: {line[:120]}')

    def test_p2_stages_a_and_b_from_the_mac_copy(self):
        stage = [b for b in self.commands('scp ') if ':l2-golive-next/artifacts/' in b]
        targets = {b.split()[-1].split(':')[0] for b in stage}
        self.assertEqual(targets, {'ubuntu@136.244.93.186', 'ubuntu@IP_OF_B'})
        for block in stage:
            sources = shlex.split(block)[3:-1]
            self.assertTrue(sources and all(s.startswith('~/bloch-l2-signing/') or s.startswith(os.path.expanduser('~'))
                                            for s in sources), f'P2 copies from the Mac copy only: {block[:160]}')
        release = [b for b in stage if 'from-4577/*' in b]
        self.assertEqual(len(release), 2, 'the signed release (with SHA256SUMS.minisig) goes to A and to B')
        fetch = [b for b in self.commands('scp ') if b.split()[-1] == '~/bloch-l2-signing/staging/']
        self.assertEqual(len(fetch), 1, 'manifest and carryover are fetched to the Mac once')
        self.assertIn('mainnet.manifest', fetch[0])

    def test_first_rpc_call_after_a_start_retries_a_refused_connection(self):
        checked = 0
        for i, block in enumerate(self.blocks[:-1]):
            if re.search(r'systemctl (enable --now|start|restart) bloch-l2-mainnet-rpc$', block, re.M):
                following = self.blocks[i + 1]
                if following.startswith('curl') and ':18955' in following:
                    checked += 1
                    self.assertIn('--retry-connrefused', following, f'after `{block}`: {following[:100]}')
        self.assertGreaterEqual(checked, 1)

    def test_no_validator_host_and_configure_takes_the_rpc_urls(self):
        for block in self.blocks:
            self.assertNotIn('45.77.67.251', block, 'L1-8: the third L1 RPC is the owner\'s THIRD_L1_RPC_URL')
        configure = [b for b in self.blocks if 'install-settler-mainnet.py configure' in b]
        self.assertEqual(len(configure), 1)
        argv = shlex.split(configure[0])
        urls = argv[argv.index('--rpc-urls') + 1]
        self.assertEqual(urls, 'http://80.240.16.185:8080,http://199.247.22.8:8080,THIRD_L1_RPC_URL')
        self.assertIn('THIRD_L1_RPC_URL', self.text.split('## 4. G0')[1].split('```')[0], 'G0 defines the placeholder')
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(AssertionError, 'placeholder'):
                m.l1_rpc_urls(['--rpc-urls', urls])
            filled = urls.replace('THIRD_L1_RPC_URL', 'http://192.0.2.33:8080')
            self.assertEqual(m.l1_rpc_urls(['--rpc-urls', filled])[2], 'http://192.0.2.33:8080')


class InstallerHints(unittest.TestCase):
    def test_follower_rpc_install_hint_retries_the_first_call(self):
        lines = INSTALL_SH.read_text().splitlines()
        start = [i for i, line in enumerate(lines) if line.strip() == 'sudo systemctl enable --now bloch-l2-mainnet-rpc']
        self.assertEqual(len(start), 1)
        following = lines[start[0] + 1].strip()
        self.assertTrue(following.startswith('curl '))
        self.assertIn('--retry-connrefused', following)


if __name__ == '__main__':
    unittest.main()
