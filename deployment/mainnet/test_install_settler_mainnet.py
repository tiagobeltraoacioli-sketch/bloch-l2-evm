#!/usr/bin/env python3
"""The settler installer's runuser path, its configure retry, its pins and its prepare step. No root, no RPC."""
import hashlib
import json
import importlib.util
import json
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
STATE, DA_DIR, DA_PASSPHRASE = m.STATE, m.DA_DIR, m.DA_PASSPHRASE  # before any test patches them


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
        for name in ('l2-config.bin', 'l2-config.next.bin', 'l2-config.fallback.bin', 'da.pubkey.hex'):
            (root / 'public' / name).write_text('x')
        rel = root / 'rel'
        rel.mkdir()
        for name in m.FILES:
            (rel / name).write_text('x')
        (self.etc / 'da.passphrase').write_text('p\n')
        patches = dict(STATE=root, ETC=self.etc, PUBLIC=root / 'public', CONFIG=self.etc / 'config.json',
                       DA_PASSPHRASE=self.etc / 'da.passphrase',
                       PENDING=self.etc / 'config.json.pending', release=lambda *_a: rel,
                       settler_module=lambda _d: types.SimpleNamespace(
                           MAINNET={'network': 'n', 'l2_genesis': 'g'}, MAINNET_TIMESTAMP_RULE='r',
                           Settler=lambda _c: None))
        for name, value in patches.items():
            patcher = mock.patch.object(m, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The L1 RPCs are configuration (test_install_settler_rpc_urls.py); documentation addresses here.
        env = mock.patch.dict(m.os.environ, {'L1_RPC_URLS': 'http://192.0.2.1:8080,http://192.0.2.2:8080,http://192.0.2.3:8080'})
        env.start()
        self.addCleanup(env.stop)

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
        # follower readability (D17), --check-rpc, then the dry run fails
        with mock.patch.object(m.subprocess, 'run', side_effect=[Done(), Done(), Done(1)]):
            with self.assertRaisesRegex(AssertionError, 'dry run failed'):
                m.configure([])
        self.assertFalse((self.etc / 'config.json').exists())

    def test_configure_names_both_programs_with_this_kits_host_flags(self):
        import json
        with mock.patch.object(m.subprocess, 'run', return_value=Done()):
            m.configure([])
        config = json.loads((self.etc / 'config.json').read_text())
        self.assertEqual(config['prover_args'], ['--mainnet-v1'])
        self.assertEqual(config['next_program']['witness'], 'sparse')
        self.assertEqual(config['next_program']['prover_args'], ['--mainnet', '--sparse'])
        self.assertTrue(config['next_program']['guest'].endswith('/settlement_v3_mainnet_sparse'))
        self.assertTrue(config['next_program']['l2_config'].endswith('/l2-config.next.bin'))
        self.assertEqual(config['fallback_program']['witness'], 'complete')
        self.assertEqual(config['fallback_program']['prover_args'], ['--mainnet'])
        self.assertTrue(config['fallback_program']['guest'].endswith('/settlement_v3_mainnet_fallback'))
        self.assertTrue(config['fallback_program']['l2_config'].endswith('/l2-config.fallback.bin'))

    def test_the_proving_budget_is_set_only_when_given(self):
        import json
        with mock.patch.object(m.subprocess, 'run', return_value=Done()):
            m.configure(['--max-block-sp1-gas', '150000000', '--max-block-instructions', '90000000'])
        self.assertEqual(json.loads((self.etc / 'config.json').read_text())['max_block_sp1_gas'], 150_000_000)
        self.assertEqual(json.loads((self.etc / 'config.json').read_text())['max_block_instructions'], 90_000_000)

    def test_incomplete_custom_budget_never_writes_configuration(self):
        for args in (['--max-block-sp1-gas', '150000000'], ['--max-block-instructions', '90000000']):
            with self.subTest(args=args), self.assertRaisesRegex(AssertionError, 'supplied together'):
                m.configure(args)
            self.assertFalse((self.etc / 'config.json').exists())
            self.assertFalse((self.etc / 'config.json.pending').exists())

    def test_the_sparse_guest_pin_is_the_settlers(self):
        spec = importlib.util.spec_from_file_location('settler_v3', HERE.parent / 'devnet' / 'settler_v3.py')
        settler = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(HERE.parent / 'devnet'))
        spec.loader.exec_module(settler)
        self.assertEqual(settler.MAINNET_NEXT_SPARSE['guest_sha256'], m.PINS['settlement_v3_mainnet_sparse'])
        self.assertEqual(settler.MAINNET['guest_sha256'], m.PINS['settlement_v3_mainnet'])
        self.assertEqual(settler.MAINNET_FALLBACK['guest_sha256'], m.PINS['settlement_v3_mainnet_fallback'])
        self.assertIn('settlement_v3_mainnet_fallback', m.FILES)

    # ---- D17 (owner, 2026-11-02): foreign settlement recovery on at the deposit-only launch ----
    def configured(self, args):
        with mock.patch.object(m.subprocess, 'run', return_value=Done()) as run:
            m.configure(args)
        return json.loads((self.etc / 'config.json').read_text()), run

    def test_d17_foreign_recovery_is_on_by_default_with_follower_a(self):
        config, run = self.configured([])
        self.assertEqual(config['foreign_recovery'], {'follower_state': '/var/lib/bloch-l2-mainnet-follower/native',
                                                      'follower_status': '/var/lib/bloch-l2-mainnet-follower/status.json'})
        check = run.call_args_list[0].args[0]
        self.assertEqual(check[:4], ['/usr/sbin/runuser', '-u', m.USER, '--'])
        self.assertEqual(check[4], '/usr/bin/test')
        self.assertIn('/var/lib/bloch-l2-mainnet-follower/status.json', check, 'checked as the settler user')

    def test_d17_explicit_follower_paths_and_opt_out(self):
        config, _ = self.configured(['--follower-state', '/srv/f/native', '--follower-status', '/srv/f/status.json'])
        self.assertEqual(config['foreign_recovery']['follower_state'], '/srv/f/native')
        (self.etc / 'config.json').unlink()
        config, run = self.configured(['--no-foreign-recovery'])
        self.assertNotIn('foreign_recovery', config)
        self.assertNotIn('/usr/bin/test', [a for c in run.call_args_list for a in c.args[0]])
        (self.etc / 'config.json').unlink()
        with self.assertRaisesRegex(AssertionError, 'both'):
            self.configured(['--follower-state', '/srv/f/native'])
        with self.assertRaisesRegex(AssertionError, 'outside /home'):
            self.configured(['--follower-state', '/home/x/native', '--follower-status', '/home/x/status.json'])

    def test_d17_unreadable_follower_refuses_before_any_config(self):
        with mock.patch.object(m.subprocess, 'run', side_effect=[Done(1)]) as run:
            with self.assertRaisesRegex(AssertionError, 'cannot read the follower'):
                m.configure([])
        self.assertEqual(run.call_count, 1, 'no RPC check or dry run before the follower check passed')
        self.assertFalse((self.etc / 'config.json').exists())
        self.assertFalse((self.etc / 'config.json.pending').exists())

    # ---- review r10 M1: the unit lets the worker clean up its prover on stop ----
    def test_m1_unit_stops_the_worker_first_and_removes_its_ipc(self):
        (self.etc / 'config.json').write_text('{}')
        unit = self.etc / 'unit.service'
        with mock.patch.object(m, 'UNIT', unit), mock.patch.object(m, 'run', return_value=''):
            m.start(['--confirm-mainnet'])
        text = unit.read_text()
        for line in ('KillMode=mixed', 'TimeoutStopSec=120', 'RemoveIPC=yes', 'RestartPreventExitStatus=3'):
            self.assertIn(f'\n{line}\n', text)

    def test_every_installed_file_is_pinned(self):
        # Fork candidate: the kit files are pinned to this tree; the launch kit's GO-LIVE-PINS.sha256 still names
        # the activated guest, bloch-pos and the manifest; the December SP1 host is not pinned yet (refused).
        self.assertEqual(set(m.PINS), set(m.FILES))
        for name, path in (('settler_v3.py', HERE.parent / 'devnet' / 'settler_v3.py'),
                           ('sequencer_policy_v2.py', HERE.parent / 'devnet' / 'sequencer_policy_v2.py'),
                           ('l2_reorg_recover.py', HERE / 'l2_reorg_recover.py')):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), m.PINS[name], name)
        golive = {}
        for line in (HERE / 'GO-LIVE-PINS.sha256').read_text().splitlines():
            value, name = line.split()
            if name.startswith('release-settler-v2/'):
                golive[name.split('/', 1)[1]] = value
        for name in ('settlement_v3_mainnet', 'bloch-pos', 'mainnet.manifest'):
            self.assertEqual(golive[name], m.PINS[name], name)
        # The December build pinned the SP1 host (docs/DECEMBER-BUILD-R15.md); the prover installer pins the same one.
        self.assertEqual(m.PINS['bloch-evm-sp1-settlement-v3'], m.CANDIDATE_HOST_PIN)
        self.assertRegex(m.CANDIDATE_HOST_PIN, '^[0-9a-f]{64}$')

    def test_units_running_as_the_settler_user_hide_its_secrets(self):
        hidden = {'/run/docker.sock', str(DA_DIR), str(STATE / 'da.passphrase'), str(STATE / 'ssh'), str(DA_PASSPHRASE),
                  str(m.RUNTIME)}
        for unit in (HERE / 'bloch-l2-mainnet-shadow.service', HERE / 'follower-rpc' / 'bloch-l2-mainnet-rpc.service'):
            paths = set()
            for line in unit.read_text().splitlines():
                if line.startswith('InaccessiblePaths='):
                    paths |= {p.lstrip('-') for p in line.split('=', 1)[1].split()}
            self.assertLessEqual(hidden, paths, unit.name)

    def test_start_writes_a_hardened_unit_once(self):
        unit = self.etc / 'x.service'
        (self.etc / 'config.json').write_text('{}')
        with mock.patch.object(m, 'UNIT', unit), mock.patch.object(m, 'run') as run:
            m.start(['--confirm-mainnet'])
            text = unit.read_text()
            for line in ('NoNewPrivileges=true', 'ProtectSystem=strict', 'ProtectHome=true', 'UMask=0027',
                         'MemoryMax=32G', 'MemorySwapMax=0', 'Restart=on-failure', 'RestartPreventExitStatus=3',
                         'CapabilityBoundingSet=', 'ProtectKernelTunables=true', 'RestrictSUIDSGID=true'):
                self.assertIn(line + '\n', text)
            with self.assertRaisesRegex(AssertionError, 'start once'):
                m.start(['--confirm-mainnet'])
            self.assertEqual(unit.read_text(), text)
        self.assertEqual([c.args[0][:2] for c in run.call_args_list][-2:], [['systemctl', 'daemon-reload'],
                                                                            ['systemctl', 'enable']])

    def test_reorg_recovery_is_off_unless_asked_for(self):
        config, _ = self.configured([])
        self.assertIn('foreign_recovery', config)
        self.assertNotIn('reorg_recovery', config)

    def test_reorg_recovery_flag(self):
        with self.assertRaisesRegex(AssertionError, 'needs foreign recovery'):
            self.configured(['--reorg-recovery', '--no-foreign-recovery'])
        config, _ = self.configured(['--reorg-recovery'])
        self.assertEqual(config['reorg_recovery'], config['foreign_recovery'])
        (self.etc / 'config.json').unlink()
        config, _ = self.configured(['--reorg-recovery', '--follower-state', '/var/lib/f/native',
                                     '--follower-status', '/var/lib/f/status.json'])
        self.assertEqual(config['reorg_recovery'], {'follower_state': '/var/lib/f/native',
                                                    'follower_status': '/var/lib/f/status.json'})

    def test_sequencer_policy_v2_is_shipped_and_configured_only_with_user_transactions(self):
        self.assertIn('sequencer_policy_v2.py', m.FILES)
        with self.assertRaisesRegex(AssertionError, 'needs --user-transactions'):
            m.configure(['--sequencer-policy-v2'])
        with mock.patch.object(m.subprocess, 'run', return_value=Done()):
            m.configure(['--user-transactions', '--sequencer-policy-v2', '--no-foreign-recovery'])
        config = json.loads((self.etc / 'config.json').read_text())
        self.assertEqual((config['max_block_sp1_gas'], config['max_block_txs'], config['congestion_max_tip_wei']),
                         (90_000_000, 64, 3 * 10**9))
        sys.path.insert(0, str(HERE.parent / 'devnet'))
        import settler_v3
        settler_v3.check_policy_config(config)

    def test_reorg_tool_pin_is_the_file_in_this_tree(self):
        self.assertIn('l2_reorg_recover.py', m.FILES)
        self.assertEqual(hashlib.sha256((HERE / 'l2_reorg_recover.py').read_bytes()).hexdigest(),
                         m.PINS['l2_reorg_recover.py'])


class Prepare(unittest.TestCase):
    """prepare against a temporary root: pins on the copies, file modes, and a refused second run."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.source = root / 'release'
        self.source.mkdir()
        pins = {}
        for name in m.FILES:
            (self.source / name).write_bytes(f'fake {name}\n'.encode())
            pins[name] = hashlib.sha256((self.source / name).read_bytes()).hexdigest()
        self.root, self.calls = root, []
        for parent in ('etc/systemd/system', 'var/lib', 'opt'):
            (root / parent).mkdir(parents=True)
        etc = root / 'etc/bloch-l2-mainnet-settler'
        fake = types.SimpleNamespace(MAINNET={'guest_sha256': pins['settlement_v3_mainnet']},
                                     MAINNET_NEXT_SPARSE={'guest_sha256': pins['settlement_v3_mainnet_sparse']},
                                     MAINNET_FALLBACK={'guest_sha256': pins['settlement_v3_mainnet_fallback']},
                                     mainnet_l2_config=lambda program=None: b'cfg',
                                     MAINNET_L2_CONFIG_SHA256=hashlib.sha256(b'cfg').hexdigest())
        me = m.pwd.getpwuid(m.os.getuid())
        patches = dict(PINS=pins, STATE=root / 'var/lib/bloch-l2-mainnet-settler', DA_DIR=root / 'var/lib/da',
                       ETC=etc, PUBLIC=etc / 'public', OPT=root / 'opt/bloch/l2-mainnet-settler',
                       DA_PASSPHRASE=etc / 'da.passphrase',
                       UNIT=root / 'etc/systemd/system/x.service', settler_module=self.module(fake), run=self.fake_run)
        for name, value in patches.items():
            patcher = mock.patch.object(m, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        group = m.grp.getgrgid(m.os.getgid())
        for target, value, fake in ((m.pwd, 'getpwnam', lambda _n: me), (m.grp, 'getgrnam', lambda _n: group),
                                    (m.os, 'chown', lambda *_a: None)):
            patcher = mock.patch.object(target, value, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def module(self, fake):
        def load(directory):
            self.loaded_from = Path(directory)
            return fake
        return load

    def fake_run(self, argv, **_kw):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        if argv[1:] == ['--version'] or argv[1:] == ['buildinfo']:
            return 'bloch-pos 78d4921c\n'
        if argv[1] == 'keygen-public':
            return 'pub\t' + '00' * 3749 + '\n'
        if argv[1:3] == ['keys', 'inspect']:
            return 'sealed\n'
        if argv[1] == 'keygen':
            Path(argv[3], 'keystore.json').write_text('{}')
        return ''

    def test_prepare_installs_hashed_copies_with_private_key_material(self):
        m.prepare(['--release', str(self.source)])
        release = m.OPT / m.PINS['settler_v3.py'][:16]
        self.assertEqual(self.loaded_from, release)
        for argv in self.calls:
            self.assertFalse(argv[0].startswith(str(self.source)), argv)
        passphrase = m.DA_PASSPHRASE  # review r10 M-4: root-only in /etc, never in the worker's state directory
        self.assertEqual(passphrase.parent, m.ETC)
        self.assertEqual(passphrase.stat().st_mode & 0o7777, 0o400)
        self.assertEqual(len(passphrase.read_text().strip()), 96)
        self.assertFalse((m.STATE / 'da.passphrase').exists())
        keygen = [argv for argv in self.calls if argv[1] == 'keygen']
        self.assertEqual(len(keygen), 1)
        # decision 4: setgid read-group state, private ssh/ and DA keystore
        modes = {m.STATE: 0o2710, m.STATE / 'work': 0o2750, m.STATE / 'txpool': 0o2770, m.STATE / 'tmp': 0o2700,
                 m.STATE / 'ssh': 0o700, m.DA_DIR: 0o700}
        for directory, mode in modes.items():
            self.assertEqual(directory.stat().st_mode & 0o7777, mode, directory)
        self.assertIn(['groupadd', '--system', '-f', m.READ_GROUP], self.calls)
        useradd = next(argv for argv in self.calls if argv[0] == 'useradd')
        self.assertEqual(useradd[useradd.index('--groups') + 1], f'docker,{m.READ_GROUP}')
        self.assertFalse(list(release.glob('__pycache__')))
        before = passphrase.read_bytes()
        with self.assertRaisesRegex(AssertionError, 'already prepared'):
            m.prepare(['--release', str(self.source)])
        self.assertEqual(passphrase.read_bytes(), before)

    def test_a_file_changed_after_its_check_is_never_installed(self):
        real_copy = m.shutil.copyfile

        def swapped(src, dst):
            real_copy(src, dst)
            if Path(src).name == 'bloch-pos':
                Path(dst).write_bytes(b'swapped after the check\n')

        with mock.patch.object(m.shutil, 'copyfile', swapped):
            with self.assertRaisesRegex(AssertionError, 'bloch-pos differs from its pin'):
                m.prepare(['--release', str(self.source)])
        self.assertEqual(self.calls, [])
        self.assertFalse(m.OPT.exists())
        self.assertFalse(m.STATE.exists())
        m.prepare(['--release', str(self.source)])
        self.assertTrue(m.DA_PASSPHRASE.exists())


if __name__ == '__main__':
    unittest.main()
