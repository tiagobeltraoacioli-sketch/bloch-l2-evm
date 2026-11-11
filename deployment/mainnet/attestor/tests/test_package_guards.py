#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What an operator or the key holder can get wrong with a package. No native binary, root or systemd needed.

  python3 -m unittest -v test_package_guards
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

KIT = Path(__file__).resolve().parent.parent
OLD_PRODUCE = '7c1cc62b'
FAKE_POS = '#!/bin/sh\necho "l2-claim seal-key key-check"\necho "signer_index 0"\necho "set_hash x"\n'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Guards(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def artifacts(self):
        art = self.tmp / 'art'
        art.mkdir()
        for name in ('bloch-pos', 'bloch-l2-native-follower', 'bloch-l2-produce-dev'):
            (art / name).write_text(FAKE_POS)
        (art / 'mainnet.manifest').write_text('m')
        (art / 'carryover.tsv.gz').write_text('c')
        (art / 'carryover.tsv.gz.sha256').write_text(sha(art / 'carryover.tsv.gz') + '  carryover.tsv.gz\n')
        (art / 'SHA256SUMS').write_text(''.join(f'{sha(art / n)}  {n}\n' for n in ('bloch-pos', 'bloch-l2-native-follower', 'bloch-l2-produce-dev')))
        return art

    def install(self, art, *extra):
        (self.tmp / 'a.sealed').write_text('x')
        return subprocess.run(['bash', str(KIT / 'install-attestor.sh'), 'install', '--artifacts', str(art), '--index', '0', '--bundle', str(self.tmp / 'a.sealed'),
                               '--l1-rpc-url', 'http://127.0.0.1:1', *extra], capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def test_install_refuses_a_build_its_own_sha256sums_vouches_for(self):
        done = self.install(self.artifacts(), '--dry-run')
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('not the published', done.stderr)

    def test_install_refuses_one_rpc_host_written_three_ways(self):
        """Review R308-2P-12: the distinct-host rule compared names only, so a trailing dot, another case or the IP
        literal of the same node counted as another host and one node could be the 2-of-3 quorum."""
        cases = [['http://rpc-a.invalid:1', 'http://RPC-A.invalid.:2', 'http://198.51.100.3:3']]
        if shutil.which('getent'):   # the IP literal and a name of the same node (needs the resolver)
            cases.append(['http://127.0.0.1:1', 'http://localhost:2', 'http://198.51.100.3:3'])
        for rpcs in cases:
            done = self.install(self.artifacts(), '--dry-run', *sum((['--rpc', u] for u in rpcs), []))
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            self.assertIn('three distinct hosts', done.stderr, rpcs)

    def test_install_makes_a_copied_binary_executable(self):
        art = self.artifacts()
        for f in ('bloch-pos', 'bloch-l2-native-follower', 'bloch-l2-produce-dev'):
            (art / f).chmod(0o644)
        self.install(art, '--prefix', str(self.tmp / 'h'), '--rehearsal-set', str(KIT / 'public/attestors.set'), '--rehearsal-any-manifest')
        self.assertTrue((art / 'bloch-pos').stat().st_mode & stat.S_IXUSR)

    def test_rehearsal_flags_stay_rehearsal(self):
        art = self.artifacts()
        self.assertIn('needs --prefix', self.install(art, '--rehearsal-set', str(KIT / 'public/attestors.set'), '--dry-run').stderr)
        self.assertIn('needs --rehearsal-set', self.install(art, '--rehearsal-any-manifest', '--dry-run').stderr)

    def test_failed_key_step_leaves_nothing_and_a_retry_works(self):
        art = self.artifacts()
        failing = '#!/bin/sh\ncase "$*" in *seal-key\\ --sealed*) exit 1;; esac\necho "l2-claim seal-key"\necho "signer_index 0"\n'
        (art / 'bloch-pos').write_text(failing)
        (art / 'SHA256SUMS').write_text(''.join(f'{sha(art / n)}  {n}\n' for n in ('bloch-pos', 'bloch-l2-native-follower', 'bloch-l2-produce-dev')))
        set_file = KIT / 'public/attestors.set'
        set_hash = subprocess.run(['python3', '-I', '-c', 'import hashlib,sys\nl=[x.strip() for x in open(sys.argv[1]) if x.strip()]; k=[bytes.fromhex(x) for x in l[1:]]\n'
                                   'print(hashlib.sha3_256(b"BLOCH:L2:ATTESTOR-SET:1"+bytes([int(l[0]),len(k)])+b"".join(k)).hexdigest())', str(set_file)],
                                  capture_output=True, text=True).stdout.strip()
        (art / 'bloch-pos').write_text(failing + f'echo "set_hash {set_hash}"\n')
        (art / 'SHA256SUMS').write_text(''.join(f'{sha(art / n)}  {n}\n' for n in ('bloch-pos', 'bloch-l2-native-follower', 'bloch-l2-produce-dev')))
        host = self.tmp / 'h'
        for _ in range(2):
            done = self.install(art, '--prefix', str(host), '--rehearsal-set', str(set_file), '--rehearsal-any-manifest')
            self.assertIn('Nothing was installed', done.stderr, done.stdout + done.stderr)
            self.assertNotIn('refusing to overwrite', done.stderr)
        self.assertFalse(list(host.rglob('bloch-pos')))
        self.assertFalse(list(host.rglob('keystore.passphrase')))
        self.assertFalse(list(host.rglob('attestor.sealed*')))

    def package(self, pins, repo_copy):
        pos = self.tmp / 'pos'
        pos.write_text(FAKE_POS)
        pos.chmod(0o755)
        out = self.tmp / 'out'
        out.mkdir(exist_ok=True)
        return subprocess.run(['bash', str(repo_copy / 'keykit/make-operator-bundles.sh'), 'package', '--keys-dir', str(repo_copy / 'public'), '--out', str(out),
                               '--bloch-pos', str(pos), '--pins', str(pins)], capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def test_package_refuses_stale_or_disagreeing_pins(self):
        pins = (KIT / 'keykit/operator-pins-v2.sha256').read_text()
        produce = re.search(r'^(\w+)  bloch-l2-produce-dev$', pins, re.M).group(1)
        old = self.tmp / 'old.pins'
        old.write_text(pins.replace(produce, OLD_PRODUCE + produce[8:]))
        self.assertIn('old producer', self.package(old, KIT).stderr)
        for v21 in ('fb0d5313', 'c18752fd'):
            stale = self.tmp / f'{v21}.pins'
            stale.write_text(pins.replace(produce, v21 + produce[8:]))
            self.assertIn("v2.1's", self.package(stale, KIT).stderr)
        other = self.tmp / 'other.pins'
        other.write_text(pins.replace(produce, 'ab' * 32))
        self.assertIn('disagree', self.package(other, KIT).stderr)

    def test_check_refuses_a_bundle_with_old_or_disagreeing_pins(self):
        bundle = self.tmp / 'operator-0'
        (bundle / 'kit').mkdir(parents=True)
        for name in ('sigfeed.py', 'sigfeed.sha256', 'install-attestor.sh'):
            shutil.copy(KIT / name, bundle / 'kit')
        shutil.copy(KIT / 'keykit/check-operator-bundle.sh', bundle)
        shutil.copy(KIT / 'public/attestors.set', bundle)
        shutil.copy(KIT / 'public/attestors.set', bundle / 'kit/attestors.set')
        (bundle / 'kit/public').mkdir()
        shutil.copy(KIT / 'public/attestors.set', bundle / 'kit/public')
        shutil.copy(KIT / 'public/attestor-0.pk', bundle)
        (bundle / 'attestor-0.sealed').write_text('x')
        (bundle / 'IDENTITY.txt').write_text('attestor_index 0\nset_hash 1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b\n')
        pins = (KIT / 'keykit/operator-pins-v2.sha256').read_text()
        produce = re.search(r'^(\w+)  bloch-l2-produce-dev$', pins, re.M).group(1)
        for text, expect in ((pins.replace(produce, OLD_PRODUCE + produce[8:]), 'old producer'), (pins.replace(produce, 'fb0d5313' + produce[8:]), "v2.1's"),
                             (pins.replace(produce, 'ab' * 32), 'disagree')):
            (bundle / 'ARTIFACTS.sha256').write_text(text)
            (bundle / 'CONTENTS.sha256').write_text('')
            done = subprocess.run(['bash', str(bundle / 'check-operator-bundle.sh')], capture_output=True, text=True, env={**os.environ})
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            self.assertIn(expect, done.stderr)

    def test_install_text_starts_the_feed_and_opens_the_port(self):
        install = (KIT / 'keykit/OPERATOR-INSTALL.template.md').read_text()
        onboarding = (KIT / 'keykit/OPERATOR-ONBOARDING.md').read_text()
        self.assertIn('enable --now bloch-l2-attestor-feed', install)
        self.assertIn('/healthz', install)
        self.assertIn('ufw allow 8787/tcp', onboarding)
        self.assertLess(onboarding.index('port 22 proto tcp'), onboarding.index('sudo ufw enable'))
        self.assertNotIn('but not the follower', install)


if __name__ == '__main__':
    unittest.main()
