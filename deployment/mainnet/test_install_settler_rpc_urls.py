#!/usr/bin/env python3
"""The settler installer takes its L1 RPCs from configuration (configure --rpc-urls or L1_RPC_URLS), never from code,
and refuses a placeholder (TBD-owner). Reviews r11 235 and 240: install-settler-mainnet.py hard-coded a validator
host in RPC_URLS. No root, no RPC: every system call is faked."""
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'install-settler-mainnet.py'
spec = importlib.util.spec_from_file_location('install_settler_rpc_urls', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

URLS = ['http://198.51.100.1:8080', 'http://198.51.100.2:8080', 'https://rpc3.example.net:8443']


class Done:
    def __init__(self, code=0):
        self.returncode, self.stdout, self.stderr = code, '', ''


class RpcUrls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.etc = root / 'etc'
        self.etc.mkdir()
        (root / 'public').mkdir()
        for name in ('l2-config.bin', 'da.pubkey.hex'):
            (root / 'public' / name).write_text('x')
        rel = root / 'rel'
        rel.mkdir()
        for name in m.FILES:
            (rel / name).write_text('x')
        patches = dict(STATE=root, ETC=self.etc, PUBLIC=root / 'public', CONFIG=self.etc / 'config.json',
                       PENDING=self.etc / 'config.json.pending', release=lambda *_a: rel,
                       settler_module=lambda _d: types.SimpleNamespace(
                           MAINNET={'network': 'n', 'l2_genesis': 'g'}, MAINNET_TIMESTAMP_RULE='r',
                           Settler=lambda _c: None))
        for name, value in patches.items():
            patcher = mock.patch.object(m, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('L1_RPC_URLS', None)

    def configure(self, args):
        with mock.patch.object(m.subprocess, 'run', return_value=Done()) as run:
            m.configure(['--no-foreign-recovery', *args])
        return json.loads((self.etc / 'config.json').read_text()), run

    def refused(self, args, pattern):
        with mock.patch.object(m.subprocess, 'run', return_value=Done()) as run:
            with self.assertRaisesRegex(AssertionError, pattern):
                m.configure(['--no-foreign-recovery', *args])
        self.assertEqual(run.call_count, 0, 'refused before any check runs')
        self.assertFalse((self.etc / 'config.json').exists())
        self.assertFalse((self.etc / 'config.json.pending').exists())

    def test_no_l1_host_is_compiled_into_the_installer(self):
        code = SOURCE.read_text()
        for host in ('45.77.67.251', '80.240.16.185', '199.247.22.8', '139.180.173.231'):
            self.assertNotIn(host, code, f'{host} is hard-coded in install-settler-mainnet.py')
        self.assertFalse(hasattr(m, 'RPC_URLS'), 'no built-in RPC_URLS list')
        self.assertFalse(re.search(r"https?://\d+\.\d+\.\d+\.\d+", code), 'no literal L1 URL in the installer')

    def test_configure_writes_the_urls_given_with_a_majority_quorum(self):
        config, _ = self.configure(['--rpc-urls', ','.join(URLS)])
        self.assertEqual(config['rpc_urls'], URLS)
        self.assertEqual(config['rpc_quorum'], 2)

    def test_environment_is_the_fallback_and_the_flag_wins(self):
        os.environ['L1_RPC_URLS'] = ' '.join(URLS)
        config, _ = self.configure([])
        self.assertEqual(config['rpc_urls'], URLS)
        (self.etc / 'config.json').unlink()
        flag = ['http://192.0.2.7:8080', 'http://192.0.2.8:8080', 'http://192.0.2.9:8080', 'http://192.0.2.10:8080']
        config, _ = self.configure(['--rpc-urls', ' , '.join(flag)])
        self.assertEqual(config['rpc_urls'], flag)
        self.assertEqual(config['rpc_quorum'], 3, 'strict majority of four')

    def test_no_urls_is_refused(self):
        self.refused([], 'needs the L1 RPCs')
        self.refused(['--rpc-urls', ' , '], 'needs the L1 RPCs')

    def test_placeholders_are_refused(self):
        for third in ('http://TBD-owner:8080', 'TBD-owner', 'http://<L1_RPC_3>:8080', 'http://THIRD_L1_RPC_URL:8080',
                      'http://tbd-owner.invalid:8080'):
            self.refused(['--rpc-urls', ','.join(URLS[:2] + [third])], 'placeholder')
        os.environ['L1_RPC_URLS'] = ','.join(URLS[:2] + ['http://TBD-owner:8080'])
        self.refused([], 'L1_RPC_URLS.*placeholder')

    def test_malformed_urls_are_refused(self):
        for bad in ('198.51.100.3:8080', 'ftp://198.51.100.3:8080', 'http://198.51.100.3', 'http://198.51.100.3:x',
                    'http://u:p@198.51.100.3:8080', 'http://198.51.100.3:8080/rpc', 'http://198.51.100.3:8080/?a=1'):
            self.refused(['--rpc-urls', ','.join(URLS[:2] + [bad])], 'not an http')

    def test_fewer_than_three_or_repeated_hosts_are_refused(self):
        self.refused(['--rpc-urls', ','.join(URLS[:2])], 'at least 3')
        self.refused(['--rpc-urls', ','.join(URLS[:2] + ['http://198.51.100.1:9090'])], 'distinct hosts')


if __name__ == '__main__':
    unittest.main()
