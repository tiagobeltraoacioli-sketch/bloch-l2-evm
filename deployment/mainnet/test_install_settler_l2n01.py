#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit AUDIT-L1L2-20261123, L2N-01: the settler key in the settler installer (`settler-key prepare | enable`).
No root, no systemd, no key: every system call is recorded by the fakes of test_install_settler_r11."""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'devnet'))
import settler_v3 as s  # noqa: E402
import test_install_settler_r11 as r11  # noqa: E402

m = r11.m
KEY = lambda tag: bytes([tag]) * s.PQ_KEY_BYTES  # noqa: E731


class SettlerKey(r11.World):
    def setUp(self):
        super().setUp()
        self.state = self.root / 'var/lib/bloch-l2-mainnet-settler'
        self.state.mkdir(parents=True)
        self.keydir = self.root / 'var/lib/bloch-l2-mainnet-settler-key'
        self.active = False
        me = types.SimpleNamespace(pw_uid=__import__('os').getuid(), pw_gid=__import__('os').getgid())
        patches = dict(STATE=self.state, SETTLER_DIR=self.keydir, SETTLER_PASSPHRASE=self.etc / 'settler.passphrase',
                       SETTLER_PUBKEY=self.etc / 'public/settler.pubkey.hex', SETTLER_SET=self.state / 'settler.set')
        for name, value in patches.items():
            patcher = mock.patch.object(m, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target, value in ((m.pwd, 'getpwnam'),):
            patcher = mock.patch.object(target, value, lambda _name: me)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.has_tool, self.key_in_keystore = True, KEY(1)
        self.set_file = self.root / 'owner.set'
        self.set_file.write_text(KEY(1).hex() + '\n' + KEY(2).hex() + '\n')

    def fake_run(self, argv, **kw):
        argv = [str(a) for a in argv]
        if argv[1:3] == ['l2-settler', '--help'] and not self.has_tool:
            raise m.subprocess.CalledProcessError(2, argv)
        if argv[1:2] in (['keygen'], ['l2-settler']) and argv[2:3] != ['--help']:
            assert kw['env']['BLOCH_KEYSTORE_PASSPHRASE_FILE'] == str(self.etc / 'settler.passphrase')
        if argv[1:2] == ['keygen']:
            (Path(argv[argv.index('--dir') + 1]) / 'validator.key').write_bytes(b'BPOSKEY2 sealed bytes')
        if argv[1:3] == ['keys', 'inspect']:
            self.calls.append(argv)
            return 'format    : sealed (BPOSKEY2, Argon2id + XChaCha20-Poly1305)\n'
        if argv[1:3] == ['l2-settler', 'pubkey']:
            Path(argv[argv.index('--out') + 1]).write_text(self.key_in_keystore.hex() + '\n')
        if argv[1:3] == ['l2-settler', 'check']:
            keys = s.parse_settler_set(Path(argv[argv.index('--set') + 1]).read_text())
            if self.key_in_keystore not in keys:
                raise m.subprocess.CalledProcessError(2, argv)
        return super().fake_run(argv, **kw)

    def fake_module(self, directory):
        module = super().fake_module(directory)
        module.parse_settler_set, module.settler_set_hash = s.parse_settler_set, s.settler_set_hash
        return module

    def prepared(self):
        m.settler_key(['prepare'])

    def test_prepare_makes_a_sealed_keystore_and_publishes_only_the_public_key(self):
        before = m.unit_text(self.old)
        self.prepared()
        self.assertEqual(self.keydir.stat().st_mode & 0o777, 0o700)
        passphrase = self.etc / 'settler.passphrase'
        self.assertEqual(passphrase.stat().st_mode & 0o777, 0o400)
        self.assertEqual(len(passphrase.read_text().strip()), 96, '48 random bytes, never printed')
        self.assertEqual(bytes.fromhex((self.etc / 'public/settler.pubkey.hex').read_text().strip()), KEY(1))
        commands = [c[1:3] for c in self.calls if c[0].endswith('bloch-pos')]
        self.assertEqual(commands, [['l2-settler', '--help'], ['keygen', '--dir'], ['keys', 'inspect'],
                                    ['l2-settler', 'pubkey']])
        self.assertFalse(any('--allow-plaintext-keystore' in c for c in self.calls))
        # A second prepare never overwrites a key.
        with self.assertRaisesRegex(AssertionError, 'never overwritten'):
            self.prepared()
        # The unit gains the passphrase copy and the key directory only now.
        after = m.unit_text(self.old)
        self.assertNotIn('settler.passphrase', before)
        self.assertIn(f'ExecStartPre=+/usr/bin/install -m 0400 -o {m.USER} -g {m.USER} {passphrase} '
                      '/run/bloch-l2-mainnet-settler/settler.passphrase\n', after)
        self.assertIn(f'ReadWritePaths={self.state} {m.DA_DIR} {self.keydir}\n', after)

    def test_without_a_settler_key_the_unit_is_what_it_was(self):
        text = m.unit_text(self.old)
        self.assertEqual((text.count('ExecStartPre='), 'settler.passphrase' in text, 'L2N-01' in text), (1, False, False))
        self.assertIn(f'ReadWritePaths={self.state} {m.DA_DIR}\n', text)

    def test_a_release_without_the_tool_is_refused_before_anything_is_created(self):
        self.has_tool = False
        with self.assertRaises(m.subprocess.CalledProcessError):
            self.prepared()
        self.assertFalse(self.keydir.exists() or (self.etc / 'settler.passphrase').exists())

    def test_enable_adds_the_block_and_keeps_the_old_configuration(self):
        self.prepared()
        m.settler_key(['enable', '--set', str(self.set_file), '--confirm-mainnet'])
        config = self.config()
        block = config['settler_authorization']
        self.assertEqual(block, {'signer': str(self.old / 'bloch-pos'), 'signer_sha256': self.old_pins['bloch-pos'],
                                 'genesis': str(self.old / 'mainnet.manifest'), 'keystore_dir': str(self.keydir),
                                 'passphrase_file': '/run/bloch-l2-mainnet-settler/settler.passphrase',
                                 'pubkey': str(self.etc / 'public/settler.pubkey.hex'),
                                 'set': str(self.state / 'settler.set'), 'activation_epoch': 'l1'})
        self.assertEqual(s.parse_settler_set((self.state / 'settler.set').read_text()), [KEY(1), KEY(2)])
        self.assertEqual((self.etc / 'config.json.pre-settler-key').read_text(), self.old_config)
        self.assertEqual({k: v for k, v in config.items() if k != 'settler_authorization'}, json.loads(self.old_config))
        self.assertEqual(self.checks[-1], config, 'the worker validated the new configuration offline')
        self.assertIn('settler.passphrase', self.unit.read_text())
        self.assertIn(['l2-settler', 'check'], [c[1:3] for c in self.calls])
        with self.assertRaisesRegex(AssertionError, 'already enabled'):
            m.settler_key(['enable', '--set', str(self.set_file), '--confirm-mainnet'])

    def test_enable_refuses_a_set_without_this_key_a_running_unit_and_a_missing_confirmation(self):
        self.prepared()
        with self.assertRaisesRegex(AssertionError, 'confirm-mainnet'):
            m.settler_key(['enable', '--set', str(self.set_file)])
        self.set_file.write_text(KEY(2).hex() + '\n' + KEY(3).hex() + '\n')
        with self.assertRaisesRegex(AssertionError, "this host's settler key is not in --set"):
            m.settler_key(['enable', '--set', str(self.set_file), '--confirm-mainnet'])
        self.set_file.write_text('not a set\n')
        with self.assertRaisesRegex(AssertionError, 'not a settler set'):
            m.settler_key(['enable', '--set', str(self.set_file), '--confirm-mainnet'])
        self.set_file.write_text(KEY(1).hex() + '\n')
        self.active = True
        with self.assertRaisesRegex(AssertionError, 'stop'):
            m.settler_key(['enable', '--set', str(self.set_file), '--confirm-mainnet'])
        self.assertEqual((self.etc / 'config.json').read_text(), self.old_config)
        self.assertFalse((self.state / 'settler.set').exists())

    def test_a_failed_key_check_leaves_no_set_and_no_configuration_change(self):
        self.prepared()
        self.key_in_keystore = KEY(9)  # the keystore does not hold the published key
        with self.assertRaises(m.subprocess.CalledProcessError):
            m.settler_key(['enable', '--set', str(self.set_file), '--confirm-mainnet'])
        self.assertEqual((self.etc / 'config.json').read_text(), self.old_config)
        self.assertFalse((self.state / 'settler.set').exists())

    def test_da_with_the_settler_key_and_a_configured_epoch(self):
        self.prepared()
        m.settler_key(['enable', '--set', str(self.set_file), '--activation-epoch', '9000', '--da-settler-key',
                       '--confirm-mainnet'])
        config = self.config()
        self.assertEqual(config['settler_authorization']['activation_epoch'], 9000)
        self.assertEqual(config['da'], {'settler_key': True, 'settler_slot_activation_epoch': 'l1'})

    def test_an_upgrade_repoints_the_settler_signer_with_the_da_signer(self):
        config = {**json.loads(self.old_config),
                  'settler_authorization': {'signer': 'old', 'signer_sha256': 'old', 'genesis': 'old', 'set': 'kept'}}
        new = m.release_config(config, self.old)
        self.assertEqual(new['settler_authorization'], {'signer': str(self.old / 'bloch-pos'),
                                                        'signer_sha256': self.old_pins['bloch-pos'],
                                                        'genesis': str(self.old / 'mainnet.manifest'), 'set': 'kept'})
        config['da'] = {'settler_key': True}
        self.assertEqual(m.release_config(config, self.old)['da'], {'settler_key': True})


if __name__ == '__main__':
    unittest.main()
