#!/usr/bin/env python3
"""The settler installer's runuser path, its configure retry and its reorg tool pin. No root, no RPC."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('install_settler', HERE / 'install-settler-mainnet.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Done:
    def __init__(self, code=0):
        self.returncode, self.stdout, self.stderr = code, '', ''


class Installer(unittest.TestCase):
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
                       PENDING=self.etc / 'config.json.pending', release=lambda: rel,
                       settler_module=lambda _d: types.SimpleNamespace(
                           MAINNET={'network': 'n', 'l2_genesis': 'g'}, MAINNET_TIMESTAMP_RULE='r',
                           Settler=lambda _c: None))
        for name, value in patches.items():
            patcher = mock.patch.object(m, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_runuser_is_absolute_under_the_clean_path(self):
        with mock.patch.object(m.subprocess, 'run', return_value=Done()) as run:
            m.as_settler(['/bin/true'])
        self.assertEqual(run.call_args.args[0][0], '/usr/sbin/runuser')
        self.assertEqual(run.call_args.kwargs['env']['PATH'], '/usr/bin:/bin')

    def test_failed_check_leaves_no_config_and_a_retry_works(self):
        with mock.patch.object(m.subprocess, 'run', return_value=Done(1)):
            with self.assertRaises(AssertionError):
                m.configure([])
        self.assertFalse((self.etc / 'config.json').exists())
        with mock.patch.object(m.subprocess, 'run', return_value=Done()) as run:
            m.configure([])
        self.assertTrue((self.etc / 'config.json').exists())
        self.assertFalse((self.etc / 'config.json.pending').exists())
        self.assertTrue(run.call_args.kwargs['env']['BLOCH_SETTLER_CONFIG'].endswith('config.json.pending'))
        with self.assertRaisesRegex(AssertionError, 'configure once'):
            m.configure([])

    def test_failed_dry_run_also_leaves_no_config(self):
        with mock.patch.object(m.subprocess, 'run', side_effect=[Done(), Done(1)]):
            with self.assertRaisesRegex(AssertionError, 'dry run failed'):
                m.configure([])
        self.assertFalse((self.etc / 'config.json').exists())

    def test_reorg_tool_pin_is_the_file_in_this_tree(self):
        self.assertIn('l2_reorg_recover.py', m.FILES)
        self.assertEqual(hashlib.sha256((HERE / 'l2_reorg_recover.py').read_bytes()).hexdigest(),
                         m.PINS['l2_reorg_recover.py'])


if __name__ == '__main__':
    unittest.main()
