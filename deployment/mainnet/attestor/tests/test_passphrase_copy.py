"""F204-4: systemd 255 hands LoadCredential files to a User= service at mode 0440, which the attestor
bloch-pos refuses. The agent must copy such a credential at 0400 into its RuntimeDirectory, and only there.

    python3 -m unittest tests.test_passphrase_copy   (from deployment/mainnet/attestor)
"""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import attestor_agent  # noqa: E402


def agent(config):
    a = attestor_agent.Agent.__new__(attestor_agent.Agent)
    a.c = config
    return a


class PassphraseCopy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.creds = self.root / 'credentials'
        self.creds.mkdir()
        self.cred = self.creds / 'passphrase'
        self.cred.write_bytes(b'host passphrase words\n')
        self.runtime = self.root / 'run-bloch-l2-attestor'
        self.runtime.mkdir(mode=0o700)
        os.chmod(self.runtime, 0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, runtime=True):
        e = {'CREDENTIALS_DIRECTORY': str(self.creds)}
        if runtime:
            e['RUNTIME_DIRECTORY'] = str(self.runtime)
        return mock.patch.dict(os.environ, e, clear=False)

    def test_owner_only_credential_is_used_in_place(self):
        os.chmod(self.cred, 0o400)
        with self.env():
            self.assertEqual(agent({'passphrase_credential': 'passphrase'}).passphrase_file(), str(self.cred))
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_0440_credential_is_copied_0400_into_the_runtime_directory(self):
        os.chmod(self.cred, 0o440)
        with self.env():
            a = agent({'passphrase_credential': 'passphrase'})
            path = Path(a.passphrase_file())
            self.assertEqual(path.parent, self.runtime)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(path.read_bytes(), self.cred.read_bytes())
            self.assertEqual(a.passphrase_file(), str(path))   # once per process
        self.assertEqual(sorted(p.name for p in self.runtime.iterdir()), ['passphrase'])

    def test_0440_credential_without_runtime_directory_halts(self):
        os.chmod(self.cred, 0o440)
        with self.env(runtime=False), mock.patch.dict(os.environ, {'RUNTIME_DIRECTORY': ''}):
            with self.assertRaisesRegex(attestor_agent.Halt, 'RuntimeDirectory'):
                agent({}).passphrase_file()

    def test_open_runtime_directory_halts(self):
        os.chmod(self.cred, 0o440)
        os.chmod(self.runtime, 0o755)
        with self.env():
            with self.assertRaisesRegex(attestor_agent.Halt, '0700'):
                agent({}).passphrase_file()
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_explicit_passphrase_file_wins(self):
        with self.env():
            self.assertEqual(agent({'passphrase_file': '/x/p'}).passphrase_file(), '/x/p')

    def test_units_and_printed_checks_give_a_private_runtime_directory(self):
        here = Path(__file__).resolve().parents[1]
        unit = (here / 'systemd/bloch-l2-attestor.service').read_text()
        self.assertIn('RuntimeDirectory=bloch-l2-attestor\n', unit)
        self.assertIn('RuntimeDirectoryMode=0700\n', unit)
        for f in ('install-attestor.sh', 'README.md', 'keykit/OPERATOR-INSTALL.template.md'):
            text = (here / f).read_text()
            n_cred = text.count('-p LoadCredential=passphrase:')
            self.assertEqual(text.count('-p RuntimeDirectory=bloch-l2-attestor-check -p RuntimeDirectoryMode=0700'), n_cred, f)


if __name__ == '__main__':
    unittest.main()
