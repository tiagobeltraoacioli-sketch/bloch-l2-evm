"""A release names exact source bytes, including the allowed native shim."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verify_build_sources', HERE / 'verify-build-sources.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class BuildSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'source'
        self.root.mkdir()
        self.git('init', '-q')
        for name in verify.MANIFESTS:
            path = self.root / name
            path.parent.mkdir(parents=True)
            path.write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n\n[features]\ndefault = []\n')
        (self.root / 'lib.rs').write_text('// pinned source\n')
        self.commit()
        self.revision = self.git('rev-parse', 'HEAD').strip().decode()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.STDOUT)

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')

    def native(self, applied=False):
        verify.verify_native(self.root, self.revision, applied)

    def apply(self):
        for name in verify.MANIFESTS:
            path = self.root / name
            path.write_text(verify.shim.shimmed_text(path.read_text(), name))

    def test_clean_source_then_exact_inert_shim(self):
        verify.verify_l2(self.root)
        self.native()
        with self.assertRaisesRegex(ValueError, 'exact inert feature shim'):
            self.native(applied=True)
        self.apply()
        self.native(applied=True)
        with self.assertRaisesRegex(ValueError, 'committed and clean'):
            verify.verify_l2(self.root)

    def test_extra_dependency_change_in_an_allowed_manifest_is_refused(self):
        self.apply()
        path = self.root / verify.MANIFESTS[0]
        path.write_text(path.read_text() + '\n[dependencies]\ninjected = "1"\n')
        with self.assertRaisesRegex(ValueError, 'exact inert feature shim'):
            self.native(applied=True)

    def test_edits_outside_the_shim_are_refused(self):
        (self.root / 'lib.rs').write_text('// altered consensus\n')
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.native()

    def test_untracked_source_is_not_clean_release_evidence(self):
        (self.root / 'new_module.rs').write_text('// new source\n')
        for check in (lambda: verify.verify_l2(self.root), self.native):
            with self.assertRaisesRegex(ValueError, 'untracked'):
                check()

    def test_staged_shim_cannot_hide_the_release_diff(self):
        self.apply()
        self.git('add', '.')
        with self.assertRaisesRegex(ValueError, 'staged'):
            self.native()

    def test_index_flags_cannot_hide_source_edits(self):
        self.git('update-index', '--assume-unchanged', 'lib.rs')
        (self.root / 'lib.rs').write_text('// hidden\n')
        for check in (lambda: verify.verify_l2(self.root), self.native):
            with self.assertRaisesRegex(ValueError, 'index flags'):
                check()

    def test_manifest_mode_changes_are_refused(self):
        self.apply()
        (self.root / verify.MANIFESTS[0]).chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'mode or identity'):
            self.native(applied=True)

    def test_manifest_symlink_is_refused(self):
        path = self.root / verify.MANIFESTS[0]
        copy = Path(self.tmp.name) / 'outside.toml'
        copy.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(copy)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.native()

    def test_selected_revision_must_match(self):
        with self.assertRaisesRegex(ValueError, 'revision'):
            verify.verify_native(self.root, '0' * 40)

    def test_native_release_with_real_features_is_unchanged(self):
        for name in verify.MANIFESTS:
            path = self.root / name
            path.write_text(path.read_text() + 'devnet-kes = ["real-kes"]\ndevnet-lc-roster = ["real-roster"]\n')
        self.commit()
        self.revision = self.git('rev-parse', 'HEAD').strip().decode()
        self.native(applied=True)


if __name__ == '__main__':
    unittest.main()
