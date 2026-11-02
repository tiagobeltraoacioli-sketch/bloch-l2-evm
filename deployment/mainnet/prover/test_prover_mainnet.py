#!/usr/bin/env python3
"""Tests of the mainnet prover packaging: remote_prover.py in mainnet mode and
the install/rollback plan of install-prover-mainnet.py (no root, no Docker).

    python3 -m unittest deployment/mainnet/prover/test_prover_mainnet.py
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
DEVNET = HERE.parent.parent / 'devnet'
sys.path.insert(0, str(DEVNET))
import remote_prover as rp  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


install = load('install_prover_mainnet', HERE / 'install-prover-mainnet.py')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RemoteProverMainnet(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # The fake host records its argv and writes request+artifact as the "proof".
        self.prover = self.root / 'bloch-evm-sp1-settlement-v3'
        self.prover.write_text('#!/bin/sh\necho "$@" > "$(dirname "$0")/argv"\n'
                               'for last; do :; done\n'
                               'cat "$BLOCH_NATIVE_L2_REQUEST" "$BLOCH_NATIVE_L2_ARTIFACT" > "$last"\n')
        self.prover.chmod(0o755)
        self.guest = self.root / 'settlement_v3_mainnet'
        self.guest.write_bytes(b'elf')
        (self.root / 'work').mkdir()
        self.config = {'prover': str(self.prover), 'prover_sha256': sha256(self.prover),
                       'guest': str(self.guest), 'guest_sha256': sha256(self.guest),
                       'workdir': str(self.root / 'work'), 'home': str(self.root / 'work'),
                       'prover_threads': 2, 'gnark_image': 'image', 'mainnet': True}
        self.write()
        self.job = rp.MAGIC + struct.pack('>I', 4) + b'req\n' + struct.pack('>Q', 3) + b'art'

    def tearDown(self):
        self.tmp.cleanup()

    def write(self):
        (self.root / 'config.json').write_text(json.dumps(self.config))

    def run_prover(self, *args, env=None):
        return subprocess.run([sys.executable, str(DEVNET / 'remote_prover.py'), *args], input=self.job,
                              capture_output=True, env={'PATH': '/usr/bin:/bin', **(env or {})})

    def test_mainnet_config_runs_the_host_with_mainnet_before_the_mode(self):
        done = self.run_prover('--config', str(self.root / 'config.json'))
        self.assertEqual((done.returncode, done.stdout), (0, b'req\nart'), done.stderr)
        argv = (self.root / 'argv').read_text().split()
        self.assertEqual(argv[:4], ['--mainnet', 'prove-groth16', 'native-artifact', str(self.guest)])

    def test_a_sparse_config_adds_the_sparse_flag_and_only_on_the_next_rules(self):
        self.config['witness'] = 'sparse'
        self.write()
        done = self.run_prover('--config', str(self.root / 'config.json'))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.root / 'argv').read_text().split()[:3], ['--mainnet', '--sparse', 'prove-groth16'])
        for bad in ({'mainnet_flag': '--mainnet-v1'}, {'mainnet': False}, {'witness': 'other'}):
            with self.subTest(bad=bad):
                self.config.update({'mainnet': True, 'mainnet_flag': '--mainnet', 'witness': 'sparse', **bad})
                self.write()
                self.assertEqual(self.run_prover('--config', str(self.root / 'config.json')).returncode, 70)

    def test_prover_env_reaches_the_host_and_the_list_is_closed(self):
        self.prover.write_text(self.prover.read_text() + 'echo "$SP1_WORKER_NUM_CORE_WORKERS" > "$HOME/seen"\n')
        self.config['prover_sha256'] = sha256(self.prover)
        self.config['prover_env'] = {'SP1_WORKER_NUM_CORE_WORKERS': '1'}
        self.write()
        done = self.run_prover('--config', str(self.root / 'config.json'))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.root / 'work' / 'seen').read_text().strip(), '1')
        for bad in ({'WITHOUT_VK_VERIFICATION': '1'}, {'SP1_WORKER_MAX_COMPOSE_ARITY': '2'}, {'LD_PRELOAD': '1'},
                    {'SP1_WORKER_NUM_CORE_WORKERS': '0'}, {'SP1_WORKER_NUM_CORE_WORKERS': 1}, ['x']):
            self.config['prover_env'] = bad
            self.write()
            done = self.run_prover('--config', str(self.root / 'config.json'))
            self.assertEqual(done.returncode, 70, bad)

    def test_devnet_config_keeps_the_devnet_command(self):
        del self.config['mainnet']
        self.write()
        done = self.run_prover(env={'BLOCH_REMOTE_PROVER_CONFIG': str(self.root / 'config.json')})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.root / 'argv').read_text().split()[0], 'prove-groth16')

    def test_config_argument_is_strict(self):
        for args in (['--config'], ['--config', 'relative.json'], ['--other', '/x'], ['--config', '/a', '/b']):
            with self.subTest(args=args):
                self.assertEqual(self.run_prover(*args).returncode, 64)
        self.assertEqual(self.run_prover('--config', str(self.root / 'missing.json')).returncode, 70)

    def test_non_boolean_mainnet_is_refused(self):
        self.config['mainnet'] = 'yes'
        self.write()
        done = self.run_prover('--config', str(self.root / 'config.json'))
        self.assertEqual(done.returncode, 70)
        self.assertIn(b'mainnet must be a boolean', done.stderr)

    def test_pins_still_apply_in_mainnet_mode(self):
        self.config['guest_sha256'] = '00' * 32
        self.write()
        self.assertEqual(self.run_prover('--config', str(self.root / 'config.json')).returncode, 70)

    def test_config_path(self):
        self.assertEqual(rp.config_path([], {}), rp.CONFIG)
        self.assertEqual(rp.config_path([], {'BLOCH_REMOTE_PROVER_CONFIG': '/e.json'}), Path('/e.json'))
        self.assertEqual(rp.config_path(['--config', '/etc/x.json'], {}), Path('/etc/x.json'))


class InstallPlan(unittest.TestCase):
    def test_pins_match_the_native_program(self):
        self.assertEqual(install.PINNED['elf_keccak'],
                         '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073')
        self.assertEqual(install.PINNED['vkey_koalabear'],
                         '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e')
        self.assertEqual(install.PINNED['vkey_bn254'],
                         '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e')
        self.assertEqual(install.PINNED['proof_policy_v3'],
                         '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d')
        self.assertEqual(install.GUEST_SHA256, '203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473')

    def test_identity_check_refuses_any_difference(self):
        good = dict(install.PINNED, program='settlement_v3_mainnet')
        install.check_identity(json.dumps(good))
        for key in install.PINNED:
            with self.subTest(key=key), self.assertRaises(SystemExit):
                install.check_identity(json.dumps(dict(good, **{key: 'ff' * 32})))
        with self.assertRaises(SystemExit):
            install.check_identity('not json')

    def test_slice_and_authorized_keys(self):
        text = install.slice_dropin(memory_gib=48, threads=12)
        self.assertIn('MemoryMax=48G', text)
        self.assertIn('MemoryHigh=44G', text)
        self.assertIn('MemorySwapMax=0', text)
        self.assertIn('CPUQuota=1200%', text)
        key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample settler'
        line = install.authorized_line(key, '203.0.113.7', Path('/opt/x'), Path('/etc/y/config.json'))
        self.assertTrue(line.startswith('restrict,from="203.0.113.7",command="/usr/bin/python3 /opt/x/remote_prover.py'
                                        ' --config /etc/y/config.json" ssh-ed25519 '))
        for bad in ('ssh-rsa AAAA', 'ssh-ed25519 A"B', 'ssh-ed25519 A\nB'):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                install.authorized_line(bad, '203.0.113.7', Path('/opt/x'), Path('/etc/y/config.json'))

    def test_config_is_mainnet_and_capped(self):
        config = install.prover_config(Path('/opt/r'), Path('/var/lib/s'), 'aa' * 32, threads=12, memory_gib=48)
        self.assertIs(config['mainnet'], True)
        self.assertEqual(config['guest_sha256'], install.GUEST_SHA256)
        self.assertEqual(config['max_memory_bytes'], 48 << 30)
        self.assertEqual(config['prover_threads'], 12)
        self.assertEqual(config['gnark_image'], install.GNARK_IMAGE)
        self.assertTrue(config['guest'].endswith('/settlement_v3_mainnet'))

    def test_install_refuses_another_remote_prover_even_with_a_matching_sums_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            here = Path(tmp)
            for name in install.FILES:
                (here / name).write_bytes(b'an older file: ' + name.encode())
            sums = {name: sha256(here / name) for name in install.FILES}
            sums[install.FILES[1]] = install.GUEST_SHA256
            (here / 'SHA256SUMS').write_text(''.join(f'{v}  {n}\n' for n, v in sums.items()))
            real = install.digest
            pretend = lambda path: sums[Path(path).name] if Path(path).name == install.FILES[1] else real(path)
            with mock.patch.object(install, 'digest', pretend):
                with self.assertRaisesRegex(SystemExit, 'remote_prover.py is'):
                    install.install(argparse.Namespace(memory_gib=100, threads=24), here)

    def test_the_next_program_is_identified_and_configured_as_the_sparse_guest(self):
        good = dict(install.PINNED_NEXT, program='settlement_v3_mainnet_sparse')
        install.check_identity(json.dumps(good), 'next')
        with self.assertRaises(SystemExit):
            install.check_identity(json.dumps(good))  # the activated pins refuse it
        with self.assertRaises(SystemExit):
            install.check_identity(json.dumps(dict(install.PINNED, program='settlement_v3_mainnet')), 'next')
        config = install.prover_config(Path('/opt/r-next'), Path('/var/lib/s'), 'aa' * 32, 12, 48, program='next')
        self.assertEqual((config['mainnet_flag'], config['witness']), ('--mainnet', 'sparse'))
        self.assertEqual(config['guest_sha256'], install.NEXT_GUEST_SHA256)
        self.assertTrue(config['guest'].endswith('/settlement_v3_mainnet_sparse'))
        self.assertEqual(config['workdir'], '/var/lib/s/work', 'one work directory, so one proof at a time across both')
        activated = install.prover_config(Path('/opt/r'), Path('/var/lib/s'), 'aa' * 32, 12, 48)
        self.assertEqual(activated['mainnet_flag'], '--mainnet-v1', "this kit's host takes --mainnet for the next rules")
        self.assertEqual(install.PROGRAMS['activated']['host_args'], ['--mainnet-v1'])
        self.assertEqual(install.PROGRAMS['next']['host_args'], ['--mainnet', '--sparse'])

    def test_the_fallback_program_is_the_settlers_complete_next_guest(self):
        good = dict(install.PINNED_FALLBACK, program='settlement_v3_mainnet')
        install.check_identity(json.dumps(good), 'fallback')
        for other in ('activated', 'next'):
            with self.assertRaises(SystemExit):
                install.check_identity(json.dumps(good), other)
        with self.assertRaises(SystemExit):  # the old macOS build 44d4c9d7 of 776c6cb
            install.check_identity(json.dumps(dict(good, elf_keccak='f3c20f71b84bb09cbab76a75c83a62c507fbefff4b347f787ef2d89aceb6f2b8')),
                                   'fallback')
        config = install.prover_config(Path('/opt/r-fallback'), Path('/var/lib/s'), 'aa' * 32, 12, 48, program='fallback')
        self.assertEqual((config['mainnet_flag'], config['witness']), ('--mainnet', 'complete'))
        self.assertTrue(config['guest'].endswith('/settlement_v3_mainnet_fallback'))
        self.assertEqual(config['workdir'], '/var/lib/s/work')
        spec = importlib.util.spec_from_file_location('settler_v3_pins', DEVNET / 'settler_v3.py')
        settler = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(DEVNET))
        spec.loader.exec_module(settler)
        fallback = settler.MAINNET_FALLBACK
        self.assertEqual(fallback['guest_sha256'], install.FALLBACK_GUEST_SHA256)
        for key in ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'):
            self.assertEqual(fallback[key], install.PINNED_FALLBACK[key])
        self.assertEqual(install.PINNED_FALLBACK['configuration'], install.PINNED_NEXT['configuration'])

    def test_remote_prover_pin_is_the_file_in_this_tree(self):
        self.assertEqual(sha256(DEVNET / 'remote_prover.py'), install.REMOTE_PROVER_SHA256)
    def test_prover_env_option(self):
        self.assertEqual(install.parse_prover_env(['SP1_WORKER_NUM_CORE_WORKERS=1']),
                         {'SP1_WORKER_NUM_CORE_WORKERS': '1'})
        self.assertEqual(install.allowed_prover_env(), rp.PROVER_ENV_ALLOWED)
        for bad in ('WITHOUT_VK_VERIFICATION=1', 'SP1_WORKER_MAX_COMPOSE_ARITY=2', 'ELEMENT_THRESHOLD', 'ELEMENT_THRESHOLD=0'):
            with self.assertRaises(SystemExit):
                install.parse_prover_env([bad])
        config = install.prover_config(Path('/opt/r'), Path('/var/lib/s'), 'aa' * 32, 12, 48, {'ELEMENT_THRESHOLD': '1'}, 7000)
        self.assertEqual((config['prover_env'], config['timeout_seconds']), ({'ELEMENT_THRESHOLD': '1'}, 7000))
        self.assertNotIn('prover_env', install.prover_config(Path('/opt/r'), Path('/var/lib/s'), 'aa' * 32, 12, 48))

    def test_defaults_are_the_measured_settings(self):
        source = (HERE / 'install-prover-mainnet.py').read_text()
        self.assertIn("'--threads', type=int, default=32", source)
        self.assertIn("'--timeout-seconds', type=int, default=5400", source)
        self.assertEqual(install.parse_prover_env(install.DEFAULT_PROVER_ENV), {'ELEMENT_THRESHOLD': '268435456'})

    def test_memory_floor(self):
        for memory, threads in ((24, 8), (48, 0), (48, 64)):
            with self.subTest(memory=memory, threads=threads), self.assertRaises(SystemExit):
                install.check_sizes(memory, threads)
        install.check_sizes(32, 8)


if __name__ == '__main__':
    unittest.main()
