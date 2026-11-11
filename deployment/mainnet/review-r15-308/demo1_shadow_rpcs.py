#!/usr/bin/env python3
"""D1: the SHIPPED install-shadow.sh + SHIPPED bloch-l2-mainnet-shadow.service refuse every L1 RPC set the settler
installer accepts, except the three IPs hard-coded in the unit. Runs the real script by path (--print-l1-rpcs: no root,
changes nothing). The kit's own test passes only because it rewrites the unit's IPAddressAllow line first."""
import importlib.util, os, subprocess, sys, unittest
W = str(__import__('pathlib').Path(__file__).resolve().parents[1])
spec = importlib.util.spec_from_file_location('settler_installer', W + '/install-settler-mainnet.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def shadow(urls):
    env = {k: v for k, v in os.environ.items() if k != 'L1_RPC_URLS'}
    env['L1_RPC_URLS'] = ' '.join(urls)
    return subprocess.run(['bash', W + '/install-shadow.sh', '--print-l1-rpcs'], env=env, capture_output=True, text=True)

class D1(unittest.TestCase):
    def both(self, urls):
        accepted = m.l1_rpc_urls(['--rpc-urls', ','.join(urls)], environ={})   # settler configure accepts
        p = shadow(accepted)
        print('\nsettler accepts', accepted, '\nshadow rc', p.returncode, p.stdout.strip(), p.stderr.strip())
        self.assertEqual(p.returncode, 0, 'shadow refuses what the settler configure accepted')

    def test_plan_example_third_rpc(self):   # the value test_golive_plan_commands.py fills in for THIRD_L1_RPC_URL
        self.both(['http://80.240.16.185:8080', 'http://199.247.22.8:8080', 'http://192.0.2.33:8080'])
    def test_hostnames_https(self):
        self.both(['https://rpc-a.example:443', 'https://rpc-b.example:443', 'https://rpc-c.example:443'])
    def test_only_hard_coded_set_passes(self):   # control: passes, showing the three IPs are compiled in
        self.both(['http://80.240.16.185:8080', 'http://199.247.22.8:8080', 'http://45.77.67.251:8080'])
    def test_same_host_three_times_counts_as_three(self):
        p = shadow(['http://80.240.16.185:8080', 'http://80.240.16.185:8080/', 'http://80.240.16.185:8081'])
        print('\none host, three spellings: rc', p.returncode, p.stdout.strip(), p.stderr.strip())
        self.assertNotEqual(p.returncode, 0, 'one L1 host passes as "3 distinct L1 RPCs" (quorum 2 from one node)')
if __name__ == '__main__':
    unittest.main(verbosity=2)
