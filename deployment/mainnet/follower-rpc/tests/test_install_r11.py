#!/usr/bin/env python3
"""Round 11 (agent 204): the RPC unit's own-user template (install.sh --rpc-user/--read-group), and
l2_read_access.py (the MDBX lock file of the canonical database made writable for the RPC's read group).
The same paths ran as root under a real systemd 255 in agents/204-installers-systemd.md."""
import grp
import importlib.util
import os
from pathlib import Path
import pwd
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('l2_read_access', HERE / 'l2_read_access.py')
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
ME = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name


class RpcUnitTemplate(unittest.TestCase):
    """Decision 4: the RPC runs as --rpc-user in --read-group; without them, as --canonical-user (old behaviour)."""

    def render(self, rpc_user=None, group=None):
        text = (HERE / 'bloch-l2-mainnet-rpc.service').read_text()
        lines = []
        for line in text.splitlines():
            if '@READ_GROUP@' in line:
                if not rpc_user:
                    continue
                line = line.replace('@READ_GROUP@', group)
            lines.append(line.replace('@RPC_USER@', rpc_user or 'canon').replace('@CANONICAL_USER@', 'canon')
                         .replace('@CANONICAL@', '/c').replace('@STATE@', '/s').replace('@TXPOOL@', '/t')
                         .replace('@REQUIRED_TIP@', ''))
        return '\n'.join(lines) + '\n'

    def test_install_sh_substitutes_every_placeholder(self):
        script = (HERE / 'install.sh').read_text()
        placeholders = {p for p in ('@RPC_USER@', '@READ_GROUP@', '@CANONICAL_USER@', '@CANONICAL@', '@STATE@',
                                    '@TXPOOL@', '@REQUIRED_TIP@') if p in (HERE / 'bloch-l2-mainnet-rpc.service').read_text()}
        for placeholder in placeholders:
            self.assertIn(f's#{placeholder}#', script.replace("'/@READ_GROUP@/d'", 's#@READ_GROUP@#'), placeholder)
        self.assertIn('run install -m 0755 "$HERE/l2_read_access.py" $OPT/', script)

    def test_own_user(self):
        unit = self.render('bloch-l2-mainnet-rpc', 'bloch-l2-mainnet-l2read')
        self.assertIn('\nUser=bloch-l2-mainnet-rpc\nGroup=bloch-l2-mainnet-rpc\n', unit)
        self.assertIn('\nSupplementaryGroups=bloch-l2-mainnet-l2read\n', unit)
        pre = [line for line in unit.splitlines() if line.startswith('ExecStartPre=')]
        self.assertEqual(pre[0], 'ExecStartPre=+/usr/bin/python3 -I /opt/bloch/l2-mainnet/l2_read_access.py /c canon '
                                 'bloch-l2-mainnet-l2read')
        self.assertEqual(pre[1], 'ExecStartPre=/bin/rm -rf /s/rpc-view')
        self.assertIn('\nReadWritePaths=/s /t /c\n', unit, 'the lock file needs a writable mount')
        self.assertNotIn('@', unit)

    def test_without_rpc_user_it_is_the_canonical_user_and_no_root_step(self):
        unit = self.render()
        self.assertIn('\nUser=canon\nGroup=canon\n', unit)
        self.assertNotIn('SupplementaryGroups', unit)
        self.assertNotIn('ExecStartPre=+', unit)
        self.assertNotIn('@', unit)

    def test_secrets_stay_hidden_from_either_user(self):
        unit = self.render('bloch-l2-mainnet-rpc', 'g')
        hidden = next(line for line in unit.splitlines() if line.startswith('InaccessiblePaths='))
        for path in ('/run/docker.sock', '/var/lib/bloch-l2-mainnet-da', '/var/lib/bloch-l2-mainnet-settler/ssh',
                     '/var/lib/bloch-l2-mainnet-settler/da.passphrase', '/etc/bloch-l2-mainnet-settler/da.passphrase',
                     '/run/bloch-l2-mainnet-settler'):
            self.assertIn('-' + path, hidden.split('=', 1)[1].split())


class ReadAccess(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.canonical = Path(os.path.realpath(tmp.name)) / 'canonical'
        (self.canonical / 'db').mkdir(parents=True)
        self.lock = self.canonical / 'db' / 'mdbx.lck'
        self.lock.write_bytes(b'\0' * 16)
        self.lock.chmod(0o644)

    def test_the_lock_file_becomes_group_read_write_and_nothing_else_changes(self):
        (self.canonical / 'db' / 'mdbx.dat').write_bytes(b'd')
        (self.canonical / 'db' / 'mdbx.dat').chmod(0o640)
        access.grant(str(self.canonical), ME, GROUP)
        self.assertEqual(self.lock.stat().st_mode & 0o7777, 0o664)
        self.assertEqual(self.lock.stat().st_gid, grp.getgrnam(GROUP).gr_gid)
        self.assertEqual((self.canonical / 'db' / 'mdbx.dat').stat().st_mode & 0o7777, 0o640)

    def test_a_symlinked_lock_file_or_directory_is_refused(self):
        target = self.canonical.parent / 'elsewhere'
        target.write_bytes(b'x')
        target.chmod(0o600)
        self.lock.unlink()
        self.lock.symlink_to(target)
        with self.assertRaises(SystemExit):
            access.grant(str(self.canonical), ME, GROUP)
        self.assertEqual(target.stat().st_mode & 0o7777, 0o600)
        linked = self.canonical.parent / 'linked'
        linked.symlink_to(self.canonical)
        with self.assertRaises(SystemExit):
            access.grant(str(linked), ME, GROUP)

    def test_missing_lock_wrong_owner_and_relative_path_are_refused(self):
        with self.assertRaisesRegex(SystemExit, 'not a regular file of'):
            access.grant(str(self.canonical), 'root' if ME != 'root' else 'nobody', GROUP)
        self.lock.unlink()
        with self.assertRaisesRegex(SystemExit, 'not an initialized database'):
            access.grant(str(self.canonical), ME, GROUP)
        with self.assertRaisesRegex(SystemExit, 'not an absolute path'):
            access.grant('relative/canonical', ME, GROUP)


if __name__ == '__main__':
    unittest.main()
