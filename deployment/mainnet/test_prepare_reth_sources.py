"""Prepared Reth must contain exactly the recorded patch, even with local ignores."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_reth_sources',
                                             HERE / 'integrations/reth-execution/prepare-reth.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparedSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / 'reth'
        self.target.mkdir()
        self.git('init', '-q')
        (self.target / 'lib.rs').write_text('// base\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'base')
        revision = self.git('rev-parse', 'HEAD').strip().decode()
        (self.target / 'lib.rs').write_text('// recorded patch\n')
        patch = Path(self.tmp.name) / 'recorded.patch'
        patch.write_bytes(self.git('diff', *prepare.DIFF))
        for name, value in (('BASE', revision), ('TARGET', self.target), ('PATCH', patch),
                            ('SOURCE', Path(self.tmp.name) / 'original')):
            patcher = mock.patch.object(prepare, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.target), *args], stderr=subprocess.STDOUT)

    def check(self):
        with mock.patch('sys.argv', ['prepare-reth.py', '--check']):
            prepare.main()

    def test_exact_patch_and_generated_target_are_accepted(self):
        self.check()
        output = self.target / 'crates/example/target/debug/generated.rs'
        output.parent.mkdir(parents=True)
        output.write_text('// output, not source\n')
        self.check()

    def test_local_ignore_cannot_hide_cargo_configuration(self):
        (self.target / '.git/info/exclude').write_text('/.cargo/\n')
        config = self.target / '.cargo/config.toml'
        config.parent.mkdir()
        config.write_text('[build]\nrustflags = ["--cfg", "unrecorded"]\n')
        with self.assertRaisesRegex(SystemExit, 'untracked files'):
            self.check()

    def test_global_ignore_cannot_hide_a_rust_input(self):
        ignore = Path(self.tmp.name) / 'global-ignore'
        ignore.write_text('*.rs\n')
        self.git('config', 'core.excludesFile', str(ignore))
        (self.target / 'injected.rs').write_text('// unrecorded source\n')
        with self.assertRaisesRegex(SystemExit, 'untracked files'):
            self.check()

    def test_an_extra_edit_does_not_match_the_recorded_patch(self):
        (self.target / 'lib.rs').write_text('// recorded patch plus unrecorded edit\n')
        with self.assertRaisesRegex(SystemExit, 'differs from the recorded patch'):
            self.check()


if __name__ == '__main__':
    unittest.main()
