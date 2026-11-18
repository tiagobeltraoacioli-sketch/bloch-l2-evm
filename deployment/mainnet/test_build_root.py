"""build-root.sh: every release build starts from nothing, under a lock that removing the directory cannot lose.

Review R335-2 (agent 335): the fixed build directory kept its cargo target directories between builds, and `cp -a`
keeps the sources' modification times, so a build of tree B after a build of tree A reused A's compiled crates
under a `build.json` naming B; and the lock file lay inside the directory an operator was told to remove.

Needs bash and flock (Linux). No cargo: the staging function is run on toy trees with the root pointed at a
temporary directory (the variable is read at call time; the build scripts never override it)."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPOS = ('bloch-l2-evm', 'bloch-validator-payout', 'reth-bloch-rpc-snapshot')


@unittest.skipUnless(shutil.which('flock') and shutil.which('bash'), 'needs bash and flock')
class StageBuildRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='build-root-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root, self.lock = self.tmp / 'root', self.tmp / 'root.lock'

    def tree(self, name):
        work = self.tmp / name
        for repo in REPOS:
            (work / 'src' / repo).mkdir(parents=True)
            (work / 'src' / repo / 'marker').write_text(name)
        return work

    def stage(self, work, then='true'):
        script = (f'. "{HERE}/build-root.sh"; BLOCH_BUILD_ROOT="{self.root}"; BLOCH_BUILD_LOCK="{self.lock}"; '
                  f'stage_build_root "{work}" && {then}')
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True)

    def test_a_second_build_keeps_nothing_of_the_first(self):
        self.assertEqual(self.stage(self.tree('a')).returncode, 0)
        # What a build of tree A leaves behind.
        for target in ('l2-target', 'sp1-target'):
            (self.root / target / 'release').mkdir(parents=True)
            (self.root / target / 'release' / 'compiled-from-a').write_text('a')
        (self.root / 'settlement-recovery.tree.Cargo.lock').write_text('a')
        result = self.stage(self.tree('b'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['src'])
        for repo in REPOS:
            self.assertEqual((self.root / 'src' / repo / 'marker').read_text(), 'b')

    def test_the_lock_is_beside_the_directory_and_survives_its_removal(self):
        self.assertFalse(str(self.lock).startswith(str(self.root) + os.sep))
        holder = subprocess.Popen(['bash', '-c', f'. "{HERE}/build-root.sh"; BLOCH_BUILD_ROOT="{self.root}"; '
                                   f'BLOCH_BUILD_LOCK="{self.lock}"; stage_build_root "{self.tree("a")}" && '
                                   'echo staged && exec sleep 30'], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), 'staged')
            shutil.rmtree(self.root)   # the operator's "remove it first", while a build runs
            second = self.stage(self.tree('b'))
            self.assertEqual(second.returncode, 2)
            self.assertIn('another build holds', second.stderr)
            self.assertFalse(self.root.exists(), 'the refused build must not have staged anything')
        finally:
            holder.kill()
            holder.wait()
        self.assertEqual(self.stage(self.tree('c')).returncode, 0)

    def test_a_link_at_the_lock_name_is_refused_and_not_written_through(self):
        victim = self.tmp / 'victim'
        victim.write_text('keep')
        self.lock.symlink_to(victim)
        result = self.stage(self.tree('a'))
        self.assertEqual(result.returncode, 2)
        self.assertIn('must be a regular file', result.stderr)
        self.assertEqual(victim.read_text(), 'keep')

    def test_a_lock_file_of_another_user_is_refused_by_name(self):
        """Review R384-3: the lock's name is in a world-writable directory. Another user's file there is not a
        running build of the builder: it is refused as such, before it is opened, and nothing is staged."""
        text = (HERE / 'build-root.sh').read_text()
        self.assertIn('\nbuild_root_owned() { [ -O "$1" ]; }\n', text)   # the real check is ownership
        work = self.tree('a')
        self.lock.write_text('')
        foreign = (f'. "{HERE}/build-root.sh"; BLOCH_BUILD_ROOT="{self.root}"; BLOCH_BUILD_LOCK="{self.lock}"; '
                   'build_root_owned() { [ "$1" != "$BLOCH_BUILD_LOCK" ]; }; ' f'stage_build_root "{work}"')
        result = subprocess.run(['bash', '-c', foreign], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('belongs to another user', result.stderr)
        self.assertNotIn('another build holds', result.stderr)
        self.assertFalse(self.root.exists(), 'the refused build must not have staged anything')
        # The same for the directory (it already was refused; now through the same check).
        self.root.mkdir()
        (self.root / 'theirs').write_text('keep')
        foreign = foreign.replace('[ "$1" != "$BLOCH_BUILD_LOCK" ]', '[ "$1" != "$BLOCH_BUILD_ROOT" ]')
        result = subprocess.run(['bash', '-c', foreign], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('must be a directory owned by the user who builds', result.stderr)
        self.assertEqual((self.root / 'theirs').read_text(), 'keep')
        # The builder's own files pass.
        self.assertEqual(self.stage(work).returncode, 0)

    def test_the_fixed_names(self):
        text = (HERE / 'build-root.sh').read_text()
        self.assertIn('\nBLOCH_BUILD_ROOT=/var/tmp/bloch-l2-build\n', text)
        self.assertIn('\nBLOCH_BUILD_LOCK=/var/tmp/bloch-l2-build.lock\n', text)


if __name__ == '__main__':
    unittest.main()
