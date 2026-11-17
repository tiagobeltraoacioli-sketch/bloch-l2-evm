#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The custody tool names no key folder of its own (publication review H398-4).

The attestor key folder is the owner's private location; the public kit must not name it, and the tool must not fall
back to a guessed folder: every mode needs --keys-dir DIR or BLOCH_ATTESTOR_KEYS_DIR, and refuses without either,
before it reads or writes anything.

  python3 -m unittest -v test_keys_dir_required
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

KIT = Path(__file__).resolve().parent.parent
TOOL = KIT / 'keykit' / 'make-operator-bundles.sh'
MODES = ('preflight', 'seal', 'verify', 'package', 'status', 'post-shred-check')


def run(*args, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != 'BLOCH_ATTESTOR_KEYS_DIR'}
    env.update(env_extra or {})
    with tempfile.TemporaryDirectory() as home:
        env['HOME'] = home
        return subprocess.run(['bash', str(TOOL), *args], capture_output=True, text=True, env=env, cwd=home)


class KeysDirRequired(unittest.TestCase):
    def test_every_mode_refuses_without_a_keys_dir(self):
        for mode in MODES:
            d = run(mode)
            self.assertNotEqual(d.returncode, 0, mode)
            self.assertIn('--keys-dir', d.stderr, mode)
            self.assertIn('BLOCH_ATTESTOR_KEYS_DIR', d.stderr, mode)

    def test_the_environment_variable_names_the_folder(self):
        with tempfile.TemporaryDirectory() as keys:
            d = run('status', env_extra={'BLOCH_ATTESTOR_KEYS_DIR': keys})
            self.assertNotIn('BLOCH_ATTESTOR_KEYS_DIR', d.stderr)

    def test_no_kit_file_names_the_owner_key_folder(self):
        hits = []
        for p in (KIT.parent).rglob('*'):
            if p.is_file() and p.suffix in ('.sh', '.md', '.py') and p.name != Path(__file__).name:
                if 'ATESTADORES' in p.read_text(errors='replace'):
                    hits.append(str(p.relative_to(KIT.parent)))
        self.assertEqual(hits, [])


if __name__ == '__main__':
    unittest.main()
