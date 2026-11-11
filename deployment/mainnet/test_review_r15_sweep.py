#!/usr/bin/env python3
"""Review r15 (agent 308) of set-sweep-recipient.py on the candidate 6b75a4c (agents/308-l2-review-r15.md).

Every test names its finding and fails on 6b75a4c; it passes once the finding is fixed. The tool only ever runs on
throwaway copies of this tree (`git archive HEAD`) in a temporary directory.
Run: python3 -B -m unittest -v test_review_r15_sweep   (from deployment/mainnet)
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
import test_set_sweep_recipient as base  # noqa: E402

m = base.m
A = 'd8da6bf26964af9d7eed9e03e53415d37aa96045'
B = '5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'


def call(*argv):
    """(exit, stdout). exit 0 on success, else the SystemExit payload."""
    import contextlib
    import io
    buf = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        try:
            m.main([str(a) for a in argv])
        except SystemExit as stop:
            code = stop.code if stop.code is not None else 0
    return code, buf.getvalue()


class FullTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='r308-sweep-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.l2, self.native = self.tmp / 'l2', self.tmp / 'native'
        self.l2.mkdir()
        done = subprocess.run(['git', '-C', str(base.L2), 'archive', 'HEAD'], capture_output=True)
        if done.returncode:
            self.skipTest('needs a git checkout (git archive HEAD): not available in a plain export')
        archive = done.stdout
        subprocess.run(['tar', '-x', '-C', str(self.l2)], input=archive, check=True)
        (self.native / m.NATIVE_PINS).parent.mkdir(parents=True)
        (self.native / m.NATIVE_PINS).write_text(base.NATIVE)
        (self.native / 'Cargo.lock').write_text('lock\n')
        for tree in (self.l2, self.native):
            for args in (('init', '-q'), ('config', 'user.name', 't'), ('config', 'user.email', 't@t'),
                         ('config', 'commit.gpgsign', 'false'), ('add', '-A'), ('commit', '-qm', 'base')):
                base.git(tree, *args)


class R308_4UncheckedRecipient(unittest.TestCase):
    """R308-4 (Medium). The recipient is compiled into the guests and receives every L2 fee from the gate on; moving it
    is a new program. `parse_address` checks EIP-55 only for a mixed-case value, so an all-lowercase or all-uppercase
    address with one wrong nibble is accepted and committed by `set`."""

    def test_a_lowercase_address_with_one_wrong_nibble_is_refused(self):
        typo = '0x' + A[:-1] + '6'
        with self.assertRaises(SystemExit, msg=f'{typo} accepted: nothing in it can show the typo'):
            m.parse_address(typo)

    def test_an_address_without_a_checksum_is_refused_whatever_its_case(self):
        for text in ('0x' + A, '0x' + A.upper(), A):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                m.parse_address(text)


class R308_5AuditNeverPasses(FullTree):
    """R308-5 (Low). SWEEP-RECIPIENT-PROCEDURE.md step 8: `audit` "exits non-zero while the placeholder, the old
    configuration or any --old value is still present". On this tree it exits non-zero after a correct run of every
    step: it reports the constant `PLACEHOLDER_SWEEP_RECIPIENT` of revenue_monitor.py (merged in round 13, a constant
    the monitor needs) and three short-hash comments `pins` does not move."""

    def test_audit_exits_zero_after_the_whole_procedure(self):
        old = [v for pin in ('MAINNET_NEXT_SPARSE', 'MAINNET_NEXT') for v in m.settler_pin(self.l2, pin).values()]
        self.assertEqual(call('set', m.eip55(A), '--l2', self.l2, '--native', self.native, '--confirm', m.eip55(A))[0], 0)
        cfg = m.tree_configuration(self.l2, A)
        args = []
        for kind, program in (('sparse', 'settlement_v3_mainnet_sparse'), ('complete', 'settlement_v3_mainnet')):
            (self.tmp / f'{kind}.elf').write_bytes(kind.encode() * 1000)
            identity = {'program': program, 'chain_id': 700770, 'domain': m.L2_DOMAIN, 'configuration': cfg,
                        'proof_policy_v3': m.PROOF_POLICY, 'elf_keccak': m.keccak256(kind.encode()).hex(),
                        'vkey_koalabear': m.keccak256(b'kb' + kind.encode()).hex(),
                        'vkey_bn254': '00' + m.keccak256(b'bn' + kind.encode()).hex()[2:]}
            (self.tmp / f'{kind}.json').write_text(json.dumps(identity))
            args += [f'--{kind}-identity', self.tmp / f'{kind}.json', f'--{kind}-elf', self.tmp / f'{kind}.elf']
        self.assertEqual(call('pins', '--l2', self.l2, '--native', self.native, *args)[0], 0)
        base.git(self.l2, 'commit', '-qam', 'pins')
        base.git(self.native, 'commit', '-qam', 'pins')
        release = self.l2 / m.BUILD_RELEASE
        first = subprocess.run(['git', '-C', str(self.native), 'rev-list', '--max-parents=0', 'HEAD'], check=True,
                               capture_output=True, text=True).stdout.strip()
        release.write_text(re.sub(r'(?m)^CANDIDATE_NATIVE_COMMIT=[0-9a-f]{40}$', f'CANDIDATE_NATIVE_COMMIT={first}',
                                  release.read_text()))
        self.assertEqual(call('native-commit', '--l2', self.l2, '--native', self.native)[0], 0)
        code, out = call('audit', '--l2', self.l2, '--native', self.native, *sum((['--old', v] for v in old), []))
        stale = [h.replace(str(self.l2) + '/', '') for h in json.loads(out)['stale_values']]
        self.assertEqual((code, stale), (0, []))

    def test_a_second_set_leaves_no_text_naming_the_first_recipient(self):
        self.assertEqual(call('set', m.eip55(A), '--l2', self.l2, '--native', self.native, '--confirm', m.eip55(A))[0], 0)
        self.assertEqual(call('set', m.eip55(B), '--l2', self.l2, '--native', self.native, '--confirm', m.eip55(B))[0], 0)
        left = []
        for tree in (self.l2, self.native):
            found = subprocess.run(['grep', '-rIil', '--exclude-dir=.git', A, str(tree)], capture_output=True, text=True)
            left += [str(Path(p).relative_to(tree)) for p in found.stdout.split()]
        self.assertEqual(left, [], 'comments still say the first recipient is "fixed by the owner"')


class R308_6GateReadsOneSpelling(unittest.TestCase):
    """R308-6 (Low). The gate reads `MAINNET_FEE_SWEEP_RECIPIENT` with a one-line regular expression over the file."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='r308-gate-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.text = (base.L2 / m.CHAINSPEC).read_text()
        self.unset = 'pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> = None;'
        self.assertIn(self.unset, self.text)
        self.line = f'pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> = Some(Address::new(hex!("{A}")));'

    def gate(self, text):
        path = self.tmp / 'chainspec.rs'
        path.write_text(text)
        return call('gate', '--chainspec', path)[0]

    def test_the_line_apply_writes_survives_rustfmt(self):
        """`apply` writes a 126-column line; rustfmt.toml has max_width = 120, so `cargo fmt` (planned once at the audit
        freeze, together with the recipient rebuild: agents/304 U5) breaks it after the `=`. The gate, and with it
        build-release.sh, then refuses a correctly set tree."""
        written = m.recipient_constant(A).split('\n')
        self.assertLessEqual(max(map(len, written)), 120, 'the line apply writes is over rustfmt max_width')
        self.assertEqual(' '.join(part.strip() for part in written), self.line)

    def test_the_gate_reads_the_constant_as_rustfmt_formats_it(self):
        broken = self.line.replace(' = Some', ' =\n    Some')
        self.assertEqual(self.gate(m.set_constant(self.text, A)), 0)
        self.assertEqual(self.gate(m.set_constant(self.text, A).replace(m.recipient_constant(A), broken)), 0)

    def test_a_comment_cannot_stand_in_for_the_constant(self):
        """The constant is `None` (no recipient), a comment above it carries the set form: the gate passes."""
        self.assertNotEqual(self.gate(self.text.replace(self.unset, f'// was: {self.line}\n{self.unset}')), 0)


if __name__ == '__main__':
    unittest.main()
