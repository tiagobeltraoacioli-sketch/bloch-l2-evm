#!/usr/bin/env python3
"""D5: verify-build-sources.py answers "Verified clean ... source" while the bytes cargo would compile are not the
pinned commit's. Each test builds a throwaway repo (same fixture as the kit's test_verify_build_sources.py), changes
the working tree's lib.rs, and expects the verifier to refuse. Git only; no cargo."""
import importlib.util, os, subprocess, sys, tempfile, unittest
from pathlib import Path
sys.dont_write_bytecode = True
W = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_build_sources', W / 'verify-build-sources.py')
verify = importlib.util.module_from_spec(spec); spec.loader.exec_module(verify)
ID = ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false')

class D5(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')); self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name) / 'src'; self.root = self.work / 'source'; self.root.mkdir(parents=True)
        self.git('init', '-q')
        for name in verify.MANIFESTS:
            p = self.root / name; p.parent.mkdir(parents=True)
            p.write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n\n[features]\ndefault = []\n')
        (self.root / 'lib.rs').write_text('// pinned source\n')
        self.git('add', '.'); self.git(*ID, 'commit', '-qm', 'pinned')
        self.revision = self.git('rev-parse', 'HEAD').strip().decode()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.STDOUT)

    def refused(self, what):
        print(f'\n{what}: lib.rs on disk = {(self.root / "lib.rs").read_text().strip()!r}; '
              f'HEAD = {self.git("rev-parse", "HEAD").decode().strip()[:12]} (pinned {self.revision[:12]})')
        for name, check in (('verify_l2', lambda: verify.verify_l2(self.root)),
                            ('verify_native', lambda: verify.verify_native(self.root, self.revision))):
            with self.subTest(check=name):
                with self.assertRaises(ValueError, msg=f'{what}: {name} accepted an altered working tree'):
                    check()

    def test_replace_ref_keeps_the_pinned_head_id_over_other_sources(self):
        (self.root / 'lib.rs').write_text('// altered consensus\n')
        self.git('add', '.')
        tree = self.git('write-tree').strip().decode()
        other = self.git(*ID, 'commit-tree', tree, '-m', 'other').strip().decode()
        self.git('replace', self.revision, other)        # refs/replace: HEAD keeps its name, its tree is the other one
        self.refused('git replace')

    def test_clean_filter_in_info_attributes_hides_an_edit(self):
        (self.root / '.git/info').mkdir(exist_ok=True)
        (self.root / '.git/info/attributes').write_text('*.rs filter=pin\n')      # untracked, local
        self.git('config', 'filter.pin.clean', 'git show HEAD:%f')
        (self.root / 'lib.rs').write_text('// altered consensus\n')
        self.refused('clean filter')

    def test_cargo_config_beside_the_checkouts_is_never_looked_at(self):
        # cargo reads .cargo/config.toml from the working directory and every parent ([patch], [source], rustflags,
        # rustc-wrapper). WORK/src/.cargo is outside all three repositories.
        (self.work / '.cargo').mkdir(); (self.work / '.cargo/config.toml').write_text('[build]\nrustc-wrapper = "/tmp/evil"\n')
        with self.assertRaises(ValueError, msg='a Cargo configuration above the checkout is not part of the check'):
            verify.verify_l2(self.root)

    def test_untracked_rust_file_in_any_directory_named_target(self):
        d = self.root / 'crates/bloch-pos-committee/src/target'; d.mkdir(parents=True)
        (d / 'mod.rs').write_text('// untracked source\n')                    # --exclude=target/ matches at any depth
        with self.assertRaises(ValueError, msg='untracked .rs under src/target/ accepted'):
            verify.verify_l2(self.root)

if __name__ == '__main__':
    unittest.main(verbosity=2)
