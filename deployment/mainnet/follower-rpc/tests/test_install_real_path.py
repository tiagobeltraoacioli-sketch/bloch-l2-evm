#!/usr/bin/env python3
"""install.sh's real (non-dry-run) path on a fresh fake root (agent 202 F-1).

The script runs as written except for MANIFEST_SHA256, set to the test manifest's hash in a copy.
System commands that need root (useradd, install -o/-g, getent, systemctl) come from shims on PATH,
and BLOCH_L2_INSTALL_ROOT prefixes every system path. Needs GNU coreutils (sha256sum --strict).
"""
import getpass
import gzip
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent


def gnu_sha256sum():
    try:
        return 'GNU' in subprocess.run(['sha256sum', '--version'], capture_output=True, text=True).stdout
    except OSError:
        return False


SHIMS = {
    'useradd': '#!/bin/sh\necho "useradd $*" >> "$SHIM_LOG"\n',
    'getent': '#!/bin/sh\necho "127.0.0.1       STREAM $3"\n',
    'systemctl': '#!/bin/sh\necho "systemctl $*" >> "$SHIM_LOG"\n',
    # Drop -o/-g OWNER (needs root); everything else goes to the real install.
    'install': '#!/bin/bash\nargs=()\nwhile [ $# -gt 0 ]; do case $1 in -o|-g) shift 2;; *) args+=("$1"); shift;; esac; done\n'
               'exec /usr/bin/install "${args[@]}"\n',
}


@unittest.skipUnless(gnu_sha256sum() and Path('/usr/bin/install').exists(), 'needs GNU coreutils (Linux)')
class InstallRealPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.root = t / 'root'
        (self.root / 'etc/systemd/system').mkdir(parents=True)  # as on any systemd host
        self.kit = t / 'kit'
        shutil.copytree(KIT, self.kit / 'follower-rpc', ignore=shutil.ignore_patterns('tests', '__pycache__'))
        shutil.copy(KIT.parent / 'verify_release_signature.py', self.kit)
        self.art = t / 'artifacts'
        self.art.mkdir()
        for n in ('bloch-l2-native-follower', 'bloch-l2-settled-rpc'):
            (self.art / n).write_bytes(b'#!/bin/sh\necho ' + n.encode() + b'\n')
        (self.art / 'mainnet.manifest').write_bytes(b'test manifest\n')
        (self.art / 'carryover.tsv.gz').write_bytes(gzip.compress(b'a\t1\n'))
        gz = hashlib.sha256((self.art / 'carryover.tsv.gz').read_bytes()).hexdigest()
        (self.art / 'carryover.tsv.gz.sha256').write_text(f'{gz}  carryover.tsv.gz\n')
        self.write_sums()
        script = self.kit / 'follower-rpc/install.sh'
        s = script.read_text()
        old = 'MANIFEST_SHA256=7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd\n'
        self.assertEqual(s.count(old), 1)
        man = hashlib.sha256((self.art / 'mainnet.manifest').read_bytes()).hexdigest()
        script.write_text(s.replace(old, f'MANIFEST_SHA256={man}\n'))
        shims = t / 'shims'
        shims.mkdir()
        for name, body in SHIMS.items():
            (shims / name).write_text(body)
            (shims / name).chmod(0o755)
        self.env = dict(os.environ, PATH=f'{shims}:{os.environ["PATH"]}', BLOCH_L2_INSTALL_ROOT=str(self.root),
                        SHIM_LOG=str(t / 'shim.log'))
        self.canonical = t / 'canonical'
        for d in ('db', 'static', 'rocks'):
            (self.canonical / d).mkdir(parents=True)
        self.txpool = t / 'txpool'
        self.txpool.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write_sums(self):
        names = ('bloch-l2-native-follower', 'bloch-l2-settled-rpc')
        (self.art / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256((self.art / n).read_bytes()).hexdigest()}  {n}\n' for n in names))

    def run_install(self):
        return subprocess.run(['bash', str(self.kit / 'follower-rpc/install.sh'), '--artifacts', str(self.art),
                               '--l1-rpc-url', 'http://127.0.0.1:8080', '--canonical', str(self.canonical),
                               '--canonical-user', getpass.getuser(), '--txpool', str(self.txpool), '--allow-unsigned'],
                              capture_output=True, text=True, env=self.env)

    def test_fresh_root_installs_units_without_follower_env(self):
        self.assertFalse((self.root / 'etc/bloch-l2-mainnet/follower.env').exists())
        done = self.run_install()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        units = self.root / 'etc/systemd/system'
        for f in ('bloch-l2-mainnet-follower.service', 'bloch-l2-mainnet-rpc.service',
                  'bloch-l2-mainnet-follower.service.d/l1-rpc.conf'):
            self.assertTrue((units / f).is_file(), f)
        self.assertEqual((self.root / 'etc/bloch-l2-mainnet/follower.env').read_text(),
                         'BLOCH_L1_RPC_URL=http://127.0.0.1:8080\n')
        self.assertIn('IPAddressAllow=localhost 127.0.0.1', (units / 'bloch-l2-mainnet-follower.service.d/l1-rpc.conf').read_text())
        rpc = (units / 'bloch-l2-mainnet-rpc.service').read_text()
        self.assertNotIn('@CANONICAL', rpc)
        self.assertIn(str(self.canonical), rpc)
        self.assertIn('Installed, NOT started', done.stdout)

    def test_reinstall_keeps_the_status_schema(self):
        self.assertEqual(self.run_install().returncode, 0)
        env = self.root / 'etc/bloch-l2-mainnet/follower.env'
        env.write_text(env.read_text() + 'BLOCH_L2_STATUS_SCHEMA=v3\n')
        for f in ('bloch-l2-mainnet-follower.service', 'bloch-l2-mainnet-rpc.service'):
            (self.root / 'etc/systemd/system' / f).unlink()
        done = self.run_install()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('BLOCH_L2_STATUS_SCHEMA=v3', env.read_text())

    def test_failed_run_resumes_over_the_same_release(self):
        # Simulate a run that died after the copy: binaries in /opt, no unit files.
        opt = self.root / 'opt/bloch/l2-mainnet'
        opt.mkdir(parents=True)
        for n in ('bloch-l2-native-follower', 'bloch-l2-settled-rpc', 'SHA256SUMS'):
            shutil.copy(self.art / n, opt)
        done = self.run_install()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('resuming an incomplete installation', done.stdout)
        self.assertTrue((self.root / 'etc/systemd/system/bloch-l2-mainnet-follower.service').is_file())

    def test_resume_refuses_another_release_in_opt(self):
        opt = self.root / 'opt/bloch/l2-mainnet'
        opt.mkdir(parents=True)
        (opt / 'bloch-l2-settled-rpc').write_bytes(b'another build\n')
        done = self.run_install()
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("is not this release's bloch-l2-settled-rpc", done.stderr)

    def test_installed_units_still_refused(self):
        self.assertEqual(self.run_install().returncode, 0)
        done = self.run_install()
        self.assertEqual(done.returncode, 1)
        self.assertIn('exists; refusing to overwrite', done.stderr)

    def test_a_failing_step_is_reported_loudly(self):
        (self.root / 'etc/bloch-l2-mainnet').write_text('a file where a directory must be\n')
        done = self.run_install()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('install.sh: FAILED at line', done.stderr)
        self.assertIn('it resumes', done.stderr)


if __name__ == '__main__':
    unittest.main()
