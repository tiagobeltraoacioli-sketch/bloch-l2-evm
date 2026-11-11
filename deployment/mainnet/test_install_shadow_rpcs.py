#!/usr/bin/env python3
"""install-shadow.sh takes its L1 RPCs from configuration (L1_RPC_URLS or the settler config), never from code."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'install-shadow.sh')
UNIT = os.path.join(HERE, 'bloch-l2-mainnet-shadow.service')
# RFC 5737 documentation addresses only.
A, B, C, D = '192.0.2.10', '198.51.100.20', '203.0.113.30', '203.0.113.40'


class InstallShadowRpcs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        shutil.copy(SCRIPT, self.dir)
        shutil.copy(UNIT, self.dir)   # the unit as shipped (review R308-13: no rewritten allow-list)
        self.settler = os.path.join(self.dir, 'settler.json')

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_print(self, env_urls=None, settler=None):
        script = os.path.join(self.dir, 'install-shadow.sh')
        with open(script) as fh:
            text = fh.read()
        if settler is not None:
            text = text.replace('SETTLER_CONFIG=/etc/bloch-l2-mainnet-settler/config.json', 'SETTLER_CONFIG=' + settler)
            with open(script, 'w') as fh:
                fh.write(text)
        env = {k: v for k, v in os.environ.items() if k != 'L1_RPC_URLS'}
        if env_urls is not None:
            env['L1_RPC_URLS'] = env_urls
        return subprocess.run(['bash', script, '--print-l1-rpcs'], env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True)

    def test_no_hard_coded_l1_host(self):
        with open(SCRIPT) as fh:
            text = fh.read()
        hosts = set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text))
        self.assertEqual(hosts, set(), 'install-shadow.sh must not name any L1 host')

    def test_env_urls(self):
        p = self.run_print(env_urls=f'http://{A}:8080, http://{B}:8080 http://{C}:8080')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split(), [f'http://{A}:8080', f'http://{B}:8080', f'http://{C}:8080'])

    def test_settler_config_urls(self):
        with open(self.settler, 'w') as fh:
            json.dump({'rpc_urls': [f'http://{A}:8080', f'http://{B}:8080', f'http://{C}:8080'], 'rpc_quorum': 2}, fh)
        p = self.run_print(settler=self.settler)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(p.stdout.split()), 3)

    def test_env_overrides_settler(self):
        with open(self.settler, 'w') as fh:
            json.dump({'rpc_urls': [f'http://{A}:8080'] * 3}, fh)
        p = self.run_print(env_urls=f'http://{A}:8080 http://{B}:8080 http://{C}:8080', settler=self.settler)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_refuses_fewer_than_three(self):
        p = self.run_print(env_urls=f'http://{A}:8080 http://{B}:8080 http://{A}:8080')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('need at least 3', p.stderr)

    def test_shipped_unit_names_no_l1_host(self):
        """Review R308-13: the unit ships with localhost only; the installer writes the drop-in."""
        with open(UNIT) as fh:
            allow = [line.strip() for line in fh if line.startswith('IPAddressAllow=')]
        self.assertEqual(allow, ['IPAddressAllow=localhost'])
        with open(SCRIPT) as fh:
            text = fh.read()
        self.assertIn('l1-rpc.conf', text)
        self.assertNotIn('"rpc_quorum": 2', text)

    def test_any_third_host_and_names_as_the_settler_accepts(self):
        for urls in (f'http://{A}:8080 http://{B}:8080 http://{D}:8080',
                     'https://rpc-a.example:443 https://rpc-b.example:443 https://rpc-c.example:443'):
            p = self.run_print(env_urls=urls)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.split(), urls.split())

    def test_one_host_spelled_three_ways_is_one_host(self):
        """Review R308-20: a quorum must not come from one node."""
        p = self.run_print(env_urls=f'http://{A}:8080 http://{A}:8080/ http://{A}:8081')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('distinct hosts', p.stderr)

    def test_refuses_garbage(self):
        for bad in (f'ftp://{A}:8080', f'http://{A}', f'http://user@{A}:8080', f'http://{A}:8080/path', 'http://bad_host!:8080'):
            p = self.run_print(env_urls=f'{bad} http://{B}:8080 http://{C}:8080')
            self.assertNotEqual(p.returncode, 0, bad)
            self.assertIn('not an http(s)://HOST:PORT URL', p.stderr)

    def test_refuses_missing_config(self):
        p = self.run_print(settler=os.path.join(self.dir, 'absent.json'))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('no L1 RPCs', p.stderr)

    def test_monitor_example_has_no_validator_host(self):
        with open(os.path.join(HERE, 'monitor', 'monitor.env.example')) as fh:
            text = fh.read()
        rpcs = re.findall(r'--l1-rpc (\S+)', text)
        self.assertEqual(len(rpcs), 3)
        self.assertIn('http://TBD-owner:8080', rpcs)


if __name__ == '__main__':
    unittest.main()
