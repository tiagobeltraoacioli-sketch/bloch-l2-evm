#!/usr/bin/env python3
"""Review r10 M-4 (DA passphrase as a unit credential), M-3 (pinned worker upgrade and its rollback) and decision 4
(read group for the RPC and shadow users) in the settler installer. No root, no RPC, no systemd: every system call
is recorded by a fake. The same paths ran under a real systemd 255 in agents/204-installers-systemd.md."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('install_settler_r11', HERE / 'install-settler-mainnet.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Done:
    def __init__(self, code=0):
        self.returncode, self.stdout, self.stderr = code, '', ''


def sha(data):
    return hashlib.sha256(data).hexdigest()


class World(unittest.TestCase):
    """An installed, configured and started settler (release OLD) and a staged newer release (NEW)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.root = root
        self.etc, self.opt = root / 'etc/bloch-l2-mainnet-settler', root / 'opt/bloch/l2-mainnet-settler'
        (self.etc / 'public').mkdir(parents=True)
        (self.etc / 'da.passphrase').write_text('p\n')
        self.unit = root / 'etc/systemd/system/bloch-l2-mainnet-settler.service'
        self.unit.parent.mkdir(parents=True)
        self.old_pins = self.release('old', self.opt)
        self.old = self.opt / self.old_pins['settler_v3.py'][:16]
        self.source = root / 'staging'
        self.new_pins = self.release('new', self.source, install=False)
        self.new = self.opt / self.new_pins['settler_v3.py'][:16]
        self.calls, self.active, self.checks = [], True, []
        self.fail_dry_run = False
        patches = dict(ETC=self.etc, PUBLIC=self.etc / 'public', CONFIG=self.etc / 'config.json',
                       PENDING=self.etc / 'config.json.pending', UPGRADE=self.etc / 'upgrade.json',
                       DA_PASSPHRASE=self.etc / 'da.passphrase', OPT=self.opt, UNIT=self.unit,
                       PINS=self.new_pins, run=self.fake_run, as_settler=self.fake_as_settler,
                       unit_active=lambda: self.active, settler_module=self.fake_module)
        for name, value in patches.items():
            patcher = mock.patch.object(m, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        config = {'network': 'n', 'produce': str(self.old / 'bloch-l2-produce-dev'),
                  'prover': str(self.old / 'bloch-evm-sp1-settlement-v3'),
                  'prover_sha256': self.old_pins['bloch-evm-sp1-settlement-v3'],
                  'guest': str(self.old / 'settlement_v3_mainnet'), 'guest_sha256': self.old_pins['settlement_v3_mainnet'],
                  'foreign_recovery': {'follower_state': '/f/native', 'follower_status': '/f/status.json'},
                  'user_transactions': False,
                  'da': {'signer': str(self.old / 'bloch-pos'), 'signer_sha256': self.old_pins['bloch-pos'],
                         'genesis': str(self.old / 'mainnet.manifest'), 'keystore_dir': '/var/lib/bloch-l2-mainnet-da',
                         'passphrase_file': str(m.DA_RUNTIME_PASSPHRASE)}}
        (self.etc / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
        self.unit.write_text(m.unit_text(self.old))
        self.old_config = (self.etc / 'config.json').read_text()

    def release(self, tag, directory, install=True):
        pins, files = {}, {}
        for name in m.FILES:
            files[name] = f'{tag} {name}\n'.encode()
            pins[name] = sha(files[name])
        target = directory / pins['settler_v3.py'][:16] if install else directory
        target.mkdir(parents=True)
        for name, data in files.items():
            (target / name).write_bytes(data)
        return pins

    def fake_module(self, directory):
        guest = sha((Path(directory) / 'settlement_v3_mainnet').read_bytes())
        return types.SimpleNamespace(
            MAINNET={'guest_sha256': guest},
            MAINNET_NEXT_SPARSE={'guest_sha256': sha((Path(directory) / 'settlement_v3_mainnet_sparse').read_bytes())},
            MAINNET_FALLBACK={'guest_sha256': sha((Path(directory) / 'settlement_v3_mainnet_fallback').read_bytes())},
            Settler=lambda config: self.checks.append(config))

    def fake_run(self, argv, **_kw):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        if argv[1:] in (['--version'], ['buildinfo']):
            return 'bloch-pos 78d4921c\n'
        if argv[:2] == ['systemctl', 'stop']:
            self.active = False
        if argv[:2] == ['systemctl', 'start']:
            self.active = True
        return ''

    def fake_as_settler(self, argv, env=None, config=None):
        argv = [str(a) for a in argv]
        self.calls.append(['as-settler', *argv, f'config={config}'])
        if '--dry-run' in argv and self.fail_dry_run:
            return Done(2)
        return Done()

    def config(self):
        return json.loads((self.etc / 'config.json').read_text())


class M4Passphrase(World):
    def test_the_unit_copies_the_root_only_passphrase_into_its_private_runtime_directory(self):
        text = m.unit_text(self.old)
        self.assertIn('\nRuntimeDirectory=bloch-l2-mainnet-settler\nRuntimeDirectoryMode=0700\n', text)
        self.assertIn(f'\nExecStartPre=+/usr/bin/install -m 0400 -o {m.USER} -g {m.USER} {self.etc / "da.passphrase"} '
                      '/run/bloch-l2-mainnet-settler/da.passphrase\n', text)
        self.assertEqual(self.config()['da']['passphrase_file'], '/run/bloch-l2-mainnet-settler/da.passphrase')

    def test_not_load_credential_whose_0440_copy_bloch_pos_refuses(self):
        # Measured under systemd 255: LoadCredential gives a User= service a 0440 file; bloch-pos refuses mode & 077.
        self.assertNotIn('LoadCredential', m.unit_text(self.old))

    def test_configure_points_the_worker_at_the_runtime_copy(self):
        source = (HERE / 'install-settler-mainnet.py').read_text()
        self.assertIn("'passphrase_file': str(DA_RUNTIME_PASSPHRASE)", source)
        self.assertNotIn("STATE / 'da.passphrase'", source)

    def test_no_unit_is_written_without_the_passphrase_file(self):
        (self.etc / 'da.passphrase').unlink()
        self.unit.unlink()
        with self.assertRaisesRegex(AssertionError, 'da.passphrase is missing'):
            m.start(['--confirm-mainnet'])
        self.assertFalse(self.unit.exists())

    def test_decision_4_the_worker_writes_group_readable_files_for_the_read_group(self):
        text = m.unit_text(self.old)
        self.assertIn('\nUMask=0027\n', text)
        self.assertIn(f'\nSupplementaryGroups=docker {m.READ_GROUP}\n', text)


class M3Upgrade(World):
    def test_upgrade_installs_checks_then_switches_release_config_and_unit(self):
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.assertTrue((self.new / 'settler_v3.py').is_file())
        for name, pin in self.new_pins.items():
            self.assertEqual(sha((self.new / name).read_bytes()), pin)
        config = self.config()
        self.assertEqual(Path(config['prover']).parent, self.new)
        self.assertEqual(config['prover_sha256'], self.new_pins['bloch-evm-sp1-settlement-v3'])
        self.assertEqual(config['guest_sha256'], self.new_pins['settlement_v3_mainnet'])
        self.assertEqual(config['da']['signer_sha256'], self.new_pins['bloch-pos'])
        self.assertEqual(config['da']['genesis'], str(self.new / 'mainnet.manifest'))
        self.assertEqual(config['da']['passphrase_file'], str(m.DA_RUNTIME_PASSPHRASE))
        self.assertEqual(config['foreign_recovery'], {'follower_state': '/f/native', 'follower_status': '/f/status.json'})
        self.assertEqual((self.etc / f'config.json.{self.old.name}').read_text(), self.old_config)
        self.assertIn(f'ExecStart=/usr/bin/python3 -u {self.new}/settler_v3.py\n', self.unit.read_text())
        self.assertFalse((self.etc / 'config.json.pending').exists())
        self.assertTrue(self.active)
        # order: stop, the checks of the NEW release on the PENDING config, then start
        order = [c for c in self.calls if c[0] in ('systemctl', 'as-settler')]
        stop = order.index(['systemctl', 'stop', m.UNIT_NAME])
        check = next(i for i, c in enumerate(order) if c[0] == 'as-settler' and '--check-rpc' in c)
        dry = next(i for i, c in enumerate(order) if c[0] == 'as-settler' and '--dry-run' in c)
        start = order.index(['systemctl', 'start', m.UNIT_NAME])
        self.assertLess(stop, check)
        self.assertLess(check, dry)
        self.assertLess(dry, start)
        self.assertIn(str(self.new / 'settler_v3.py'), order[check])
        self.assertTrue(order[dry][-1].endswith('config.json.pending'))
        record = json.loads((self.etc / 'upgrade.json').read_text())
        self.assertEqual((record['previous'], record['current']), (self.old.name, self.new.name))

    def test_upgrade_moves_both_scheduled_programs_and_rollback_restores_them(self):
        config = self.config()
        for key, witness, guest in (('next_program', 'sparse', 'settlement_v3_mainnet_sparse'),
                                    ('fallback_program', 'complete', 'settlement_v3_mainnet_fallback')):
            config[key] = {'witness': witness, 'prover': config['prover'],
                           'prover_sha256': config['prover_sha256'],
                           'guest': str(self.old / guest), 'guest_sha256': self.old_pins[guest],
                           'l2_config': f'/public/{key}.bin', 'l2_config_sha256': 'immutable-rules'}
        m.CONFIG.write_text(json.dumps(config))
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        changed = self.config()
        for key, guest in (('next_program', 'settlement_v3_mainnet_sparse'),
                          ('fallback_program', 'settlement_v3_mainnet_fallback')):
            with self.subTest(program=key):
                self.assertEqual(changed[key]['prover'], str(self.new / 'bloch-evm-sp1-settlement-v3'))
                self.assertEqual(changed[key]['prover_sha256'], self.new_pins['bloch-evm-sp1-settlement-v3'])
                self.assertEqual(changed[key]['guest'], str(self.new / guest))
                self.assertEqual(changed[key]['guest_sha256'], self.new_pins[guest])
                self.assertEqual(changed[key]['l2_config'], config[key]['l2_config'])
                self.assertEqual(changed[key]['witness'], config[key]['witness'])
        m.upgrade(['--rollback', '--confirm-mainnet'])
        self.assertEqual(self.config(), config)

    def test_rollback_refuses_a_changed_scheduled_guest_before_stopping(self):
        config = self.config()
        guest = 'settlement_v3_mainnet_fallback'
        config['fallback_program'] = {'prover': config['prover'], 'prover_sha256': config['prover_sha256'],
                                      'guest': str(self.old / guest), 'guest_sha256': self.old_pins[guest]}
        m.CONFIG.write_text(json.dumps(config))
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        (self.old / guest).write_text('tampered')
        self.calls.clear()
        with self.assertRaisesRegex(AssertionError, 'kept fallback_program .* changed'):
            m.upgrade(['--rollback', '--confirm-mainnet'])
        self.assertNotIn(['systemctl', 'stop', m.UNIT_NAME], self.calls)
        self.assertTrue(self.active)

    def test_a_failed_dry_run_leaves_the_old_release_running_and_a_retry_works(self):
        self.fail_dry_run = True
        old_unit = self.unit.read_text()
        with self.assertRaisesRegex(AssertionError, 'dry run failed'):
            m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.assertEqual((self.etc / 'config.json').read_text(), self.old_config)
        self.assertEqual(self.unit.read_text(), old_unit)
        self.assertFalse(self.new.exists())
        self.assertFalse((self.etc / 'config.json.pending').exists())
        self.assertFalse((self.etc / 'upgrade.json').exists())
        self.assertTrue(self.active, 'the old worker is started again')
        self.fail_dry_run = False
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.assertEqual(Path(self.config()['prover']).parent, self.new)

    def test_a_stopped_unit_stays_stopped(self):
        self.active = False
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.assertFalse(self.active)
        self.assertNotIn(['systemctl', 'start', m.UNIT_NAME], self.calls)

    def test_a_file_that_differs_from_its_pin_is_refused_before_any_stop(self):
        (self.source / 'bloch-pos').write_bytes(b'changed after review\n')
        with self.assertRaisesRegex(AssertionError, 'bloch-pos differs from its pin'):
            m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.assertFalse(self.new.exists())
        self.assertNotIn(['systemctl', 'stop', m.UNIT_NAME], self.calls)
        self.assertEqual((self.etc / 'config.json').read_text(), self.old_config)

    def test_refusals(self):
        with self.assertRaisesRegex(AssertionError, '--confirm-mainnet'):
            m.upgrade(['--release', str(self.source)])
        with mock.patch.object(m, 'PINS', self.old_pins):
            with self.assertRaisesRegex(AssertionError, 'already the running release'):
                m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.unit.unlink()
        with self.assertRaisesRegex(AssertionError, 'started settler'):
            m.upgrade(['--release', str(self.source), '--confirm-mainnet'])

    def test_rollback_returns_to_the_kept_release_and_upgrade_again_reuses_the_checked_copy(self):
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        upgraded = self.config()
        m.upgrade(['--rollback', '--confirm-mainnet'])
        self.assertEqual((self.etc / 'config.json').read_text(), self.old_config)
        self.assertIn(f'ExecStart=/usr/bin/python3 -u {self.old}/settler_v3.py\n', self.unit.read_text())
        self.assertEqual(json.loads((self.etc / f'config.json.{self.new.name}').read_text()), upgraded)
        record = json.loads((self.etc / 'upgrade.json').read_text())
        self.assertEqual((record['previous'], record['current']), (self.new.name, self.old.name))
        (self.etc / 'upgrade.json').write_text(json.dumps({**record, 'current': 'other'}))
        with self.assertRaisesRegex(AssertionError, 'last upgrade installed'):
            m.upgrade(['--rollback', '--confirm-mainnet'])
        (self.etc / 'upgrade.json').write_text(json.dumps(record))
        m.upgrade(['--release', str(self.root / 'gone'), '--confirm-mainnet'])  # the kept, re-hashed copy
        self.assertEqual(Path(self.config()['prover']).parent, self.new)

    def test_rollback_refuses_a_kept_release_that_changed(self):
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        (self.old / 'bloch-pos').write_bytes(b'tampered\n')
        with self.assertRaisesRegex(AssertionError, 'kept bloch-pos changed'):
            m.upgrade(['--rollback', '--confirm-mainnet'])
        self.assertEqual(Path(self.config()['prover']).parent, self.new)

    def test_release_follows_the_config_once_configured(self):
        self.assertEqual(m.release(), self.old)
        m.upgrade(['--release', str(self.source), '--confirm-mainnet'])
        self.assertEqual(m.release(), self.new)
        self.assertEqual(len(list(self.opt.glob('*/settler_v3.py'))), 2)


if __name__ == '__main__':
    unittest.main()
