#!/usr/bin/env python3
"""Review r17 (agent 335): the five sweep-tool review tests that test_review_r15_sweep.py skips on a tree that
carries the recipient, re-expressed so that they RUN on such a tree (agents/335-l2-review-r17.md).

The skipped tests start from `MAINNET_FEE_SWEEP_RECIPIENT = None`. Here the committed tree is the start: the gate
tests put the constant back to `None` in a copy of the text; the full-tree tests move the committed recipient to
another one, which is the documented procedure of docs/DECEMBER-BUILD-R15.md section 5.
Round 19 (agent 404): in the suite now (it was named review_r17_* so that discovery did not pick it up, because
one test failed by design: R335-1). The finding is fixed (the pending record, `PINS_PENDING`), that test passes
with its assertion restated on the record, and the class PinsPending below tests the record itself. With the
skipped classes of test_set_sweep_recipient.py these are the tool's end-to-end tests on a tree that carries the
recipient (review R335-7). The native tree: $NATIVE_TREE, else the sibling `bloch-validator-payout` of the build
layout, else the developer's native worktree; without one the full-tree tests skip.
Run: python3 -B -m unittest -v test_review_r17_335_sweep   (from deployment/mainnet, in a git checkout)
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


def native_tree():
    """A December native checkout whose PROGRAM_NEXT pins this tree's configuration, or None."""
    import os
    candidates = [os.environ.get('NATIVE_TREE'), base.L2.parent / 'bloch-validator-payout',
                  Path.home() / 'worktrees/native-l2-dec-merge-r17-20261117']
    for candidate in candidates:
        if candidate and (Path(candidate) / m.NATIVE_PINS).is_file() and (Path(candidate) / '.git').exists():
            try:
                if m.native_program(Path(candidate), 'PROGRAM_NEXT')[0] == m.tree_configuration(base.L2, OWNER):
                    return Path(candidate)
            except SystemExit:
                continue
    return None


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


class SetTreeCopies(unittest.TestCase):
    """Both trees as throwaway `git archive HEAD` copies: this L2 checkout and the December native tree."""

    def setUp(self):
        native_src = native_tree()
        if native_src is None:
            self.skipTest('needs the December native tree (NATIVE_TREE)')
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

@unittest.skipIf(OWNER is None, 'the tree carries no recipient')
class AnotherRecipientFromTheSetTree(SetTreeCopies):
    """docs/DECEMBER-BUILD-R15.md section 5, step 1: `set NEW --confirm NEW` "rewrites every text naming the old
    recipient"."""

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
        # Restated in round 19: the reviewer's test accepted either of two signs the tool does not give (the
        # configuration IS rewritten everywhere); the tool now says it with the pending record, which names the
        # configuration the pinned guests were built for.
        self.assertEqual(report['pins_pending']['guests_built_for'], old_cfg)
        self.assertEqual(report['pins_pending']['configuration'], m.tree_configuration(self.l2, B))


@unittest.skipIf(OWNER is None, 'the tree carries no recipient')
class PinsPending(SetTreeCopies):
    """Review R335-1: between `set NEW` and `pins` the trees pin the new configuration beside the old guests."""

    def set(self, address):
        return call('set', m.eip55(address), '--l2', self.l2, '--native', self.native, '--confirm', m.eip55(address))

    def git_out(self, *args):
        return subprocess.run(['git', '-C', str(self.l2), *args], check=True, capture_output=True, text=True).stdout.strip()

    def record(self):
        path = self.l2 / m.PINS_PENDING
        return json.loads(path.read_text()) if path.exists() else None

    def test_the_committed_tree_has_no_pending_record(self):
        self.assertFalse((base.L2 / m.PINS_PENDING).exists(), 'this tree was set and never pinned: run `pins`')
        self.assertIsNone(self.record())
        self.assertEqual(call('gate', '--l2', self.l2)[0], 0)

    def test_set_writes_and_commits_the_record_and_everything_but_the_guest_build_refuses(self):
        old_cfg = m.tree_configuration(self.l2, OWNER)
        old_keccak = m.settler_pin(self.l2, 'MAINNET_NEXT_SPARSE')['elf_keccak']
        self.assertEqual(self.set(B)[0], 0)
        record = self.record()
        self.assertEqual((record['guests_built_for'], record['configuration']), (old_cfg, m.tree_configuration(self.l2, B)))
        self.assertEqual(record['pinned_guest_elf_keccak']['MAINNET_NEXT_SPARSE'], old_keccak)
        self.assertEqual(record['recipient'], m.eip55(B))
        self.assertNotIn(OWNER, json.dumps(record).lower(), 'the record names the old configuration, never the old address')
        # Committed with the edits: a clone of the set tree carries it.
        self.assertEqual(self.git_out('status', '--porcelain'), '')
        self.assertIn(m.PINS_PENDING, self.git_out('ls-files'))
        # The kit build's gate, native-commit and audit refuse; the guest build's gate does not.
        self.assertEqual(call('gate', '--l2', self.l2)[0], 3)
        self.assertEqual(call('gate', '--chainspec', self.l2 / m.CHAINSPEC)[0], 0)
        refused = call('native-commit', '--l2', self.l2, '--native', self.native)[0]
        self.assertIn('SWEEP-PINS-PENDING.json is present', str(refused))
        code, out = call('audit', '--l2', self.l2, '--native', self.native)
        self.assertEqual((code, json.loads(out)['native_PROGRAM_NEXT_configuration_matches']), (1, True))

    def test_a_third_recipient_keeps_what_the_guests_were_built_for_and_the_first_one_clears_it(self):
        old_cfg = m.tree_configuration(self.l2, OWNER)
        self.assertEqual(self.set(B)[0], 0)
        self.assertEqual(self.set(A)[0], 0)
        record = self.record()
        self.assertEqual((record['guests_built_for'], record['configuration']), (old_cfg, m.tree_configuration(self.l2, A)))
        self.assertEqual(self.set(OWNER)[0], 0)
        self.assertIsNone(self.record(), 'back on the recipient the pinned guests were built for')
        self.assertNotIn(m.PINS_PENDING, self.git_out('ls-files'))
        self.assertEqual(call('gate', '--l2', self.l2)[0], 0)
        self.assertEqual(call('audit', '--l2', self.l2, '--native', self.native)[0], 0)

    def test_pins_with_the_new_guests_identities_removes_the_record(self):
        self.assertEqual(self.set(B)[0], 0)
        cfg = m.tree_configuration(self.l2, B)
        arguments = ['pins', '--l2', self.l2, '--native', self.native]
        for kind, program, byte in (('sparse', 'settlement_v3_mainnet_sparse', 'a'), ('complete', 'settlement_v3_mainnet', 'c')):
            identity = self.tmp / f'{kind}.json'
            identity.write_text(json.dumps({
                'program': program, 'chain_id': m.CHAIN_ID, 'domain': m.L2_DOMAIN, 'configuration': cfg,
                'proof_policy_v3': m.PROOF_POLICY, 'elf_keccak': byte * 64, 'vkey_koalabear': byte * 63 + '1',
                'vkey_bn254': byte * 63 + '2'}))
            arguments += [f'--{kind}-identity', identity, f'--{kind}-elf', byte * 63 + '3']
        # Identities made for another configuration (the old guests') do not clear it.
        stale = json.loads((self.tmp / 'sparse.json').read_text())
        stale['configuration'] = m.tree_configuration(self.l2, OWNER)
        (self.tmp / 'stale.json').write_text(json.dumps(stale))
        wrong = [str(a) for a in arguments]
        wrong[wrong.index('--sparse-identity') + 1] = str(self.tmp / 'stale.json')
        self.assertNotEqual(call(*wrong)[0], 0)
        self.assertIsNotNone(self.record())
        code, out = call(*arguments)
        self.assertEqual(code, 0, out)
        self.assertIsNone(self.record())
        self.assertEqual(m.settler_pin(self.l2, 'MAINNET_NEXT_SPARSE')['elf_keccak'], 'a' * 64)
        self.assertEqual(call('gate', '--l2', self.l2)[0], 0)

    def test_a_record_that_does_not_parse_still_refuses(self):
        (self.l2 / m.PINS_PENDING).write_text('not json')
        self.assertEqual(call('gate', '--l2', self.l2)[0], 3)
        self.assertEqual(call('audit', '--l2', self.l2, '--native', self.native)[0], 1)


if __name__ == '__main__':
    unittest.main()
