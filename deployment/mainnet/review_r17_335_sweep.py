#!/usr/bin/env python3
"""Review r17 (agent 335): the five sweep-tool review tests that test_review_r15_sweep.py skips on a tree that
carries the recipient, re-expressed so that they RUN on such a tree (agents/335-l2-review-r17.md).

The skipped tests start from `MAINNET_FEE_SWEEP_RECIPIENT = None`. Here the committed tree is the start: the gate
tests put the constant back to `None` in a copy of the text; the full-tree tests move the committed recipient to
another one, which is the documented procedure of docs/DECEMBER-BUILD-R15.md section 5.
Named review_r17_* so that suite discovery does not pick it up.
Run: python3 -B -m unittest -v review_r17_335_sweep   (from deployment/mainnet, in a git checkout)
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_review_r15_sweep as r15  # noqa: E402

base, m, call = r15.base, r15.m, r15.call
A, B = r15.A, r15.B
OWNER = m.current_recipient(base.L2)


@unittest.skipIf(OWNER is None, 'the tree carries no recipient: test_review_r15_sweep.py runs instead')
class GateOnTheSetTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='r335-gate-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.set_text = (base.L2 / m.CHAINSPEC).read_text()
        self.unset = 'pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> = None;'
        self.unset_text = self.set_text.replace(m.recipient_constant(OWNER), self.unset)
        self.assertNotEqual(self.unset_text, self.set_text, 'the committed constant is not in the form apply writes')
        self.line = f'pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> = Some(Address::new(hex!("{A}")));'

    def gate(self, text):
        path = self.tmp / 'chainspec.rs'
        path.write_text(text)
        return call('gate', '--chainspec', path)[0]

    def test_the_committed_tree_passes_and_the_unset_one_does_not(self):
        self.assertEqual(self.gate(self.set_text), 0)
        self.assertNotEqual(self.gate(self.unset_text), 0)

    def test_the_line_apply_writes_survives_rustfmt(self):
        written = m.recipient_constant(A).split('\n')
        self.assertLessEqual(max(map(len, written)), 120)
        self.assertEqual(' '.join(part.strip() for part in written), self.line)

    def test_the_gate_reads_both_spellings(self):
        one_line = self.set_text.replace(m.recipient_constant(OWNER), self.line.replace(A, OWNER))
        self.assertEqual(self.gate(one_line), 0)

    def test_a_comment_cannot_stand_in_for_the_constant(self):
        self.assertNotEqual(self.gate(self.unset_text.replace(self.unset, f'// was: {self.line}\n{self.unset}')), 0)

    def test_the_rehearsal_recipient_is_refused_in_either_spelling(self):
        rehearsal = '00000000000000000000000000000000000fee01'
        for text in (self.set_text.replace(OWNER, rehearsal),
                     self.set_text.replace(m.recipient_constant(OWNER), self.line.replace(A, rehearsal))):
            self.assertNotEqual(self.gate(text), 0)


@unittest.skipIf(OWNER is None, 'the tree carries no recipient')
class AnotherRecipientFromTheSetTree(unittest.TestCase):
    """docs/DECEMBER-BUILD-R15.md section 5, step 1: `set NEW --confirm NEW` "rewrites every text naming the old
    recipient". Both trees are throwaway `git archive HEAD` copies: this L2 checkout and the December native tree
    (NATIVE_TREE, default the reviewer's native worktree at 0861278c)."""

    def setUp(self):
        import os
        native_src = Path(os.environ.get('NATIVE_TREE', Path.home() / 'worktrees/native-l2-review-r17-20261117'))
        if not (native_src / m.NATIVE_PINS).is_file():
            self.skipTest(f'needs the December native tree ({native_src})')
        self.tmp = Path(tempfile.mkdtemp(prefix='r335-sweep-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.l2, self.native = self.tmp / 'l2', self.tmp / 'native'
        for tree, src, paths in ((self.l2, base.L2, []),
                                 (self.native, native_src, [str(m.NATIVE_PINS), 'Cargo.lock', 'scripts/hf-release'])):
            tree.mkdir()
            done = subprocess.run(['git', '-C', str(src), 'archive', 'HEAD', *paths], capture_output=True)
            if done.returncode:
                self.skipTest('needs git checkouts (git archive HEAD)')
            subprocess.run(['tar', '-x', '-C', str(tree)], input=done.stdout, check=True)
            for args in (('init', '-q'), ('config', 'user.name', 't'), ('config', 'user.email', 't@t'),
                         ('config', 'commit.gpgsign', 'false'), ('add', '-A'), ('commit', '-qm', 'base')):
                base.git(tree, *args)

    def test_a_second_set_leaves_no_text_naming_the_owner_recipient(self):
        code, out = call('set', m.eip55(B), '--l2', self.l2, '--native', self.native, '--confirm', m.eip55(B))
        self.assertEqual(code, 0, out)
        left = []
        for tree in (self.l2, self.native):
            found = subprocess.run(['grep', '-rIil', '--exclude-dir=.git', OWNER, str(tree)], capture_output=True, text=True)
            left += [str(Path(p).relative_to(tree)) for p in found.stdout.split()]
        self.assertEqual(left, [], 'files still name the first recipient after the documented `set`')

    def test_audit_reports_the_old_identities_after_a_second_set(self):
        """After `set NEW` and before `pins`, the old configuration and guest identities are stale: audit must say so."""
        old_cfg = m.tree_configuration(self.l2, OWNER)
        self.assertEqual(call('set', m.eip55(B), '--l2', self.l2, '--native', self.native, '--confirm', m.eip55(B))[0], 0)
        code, out = call('audit', '--l2', self.l2, '--native', self.native, '--old', old_cfg)
        report = json.loads(out)
        self.assertNotEqual(code, 0, 'audit passes although the guests were not rebuilt')
        self.assertTrue(report['stale_values'] or not report['native_PROGRAM_NEXT_configuration_matches'])


if __name__ == '__main__':
    unittest.main()
