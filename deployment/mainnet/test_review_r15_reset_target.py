#!/usr/bin/env python3
"""Review r15 (agent 308) of make_reset_target.py on the candidate 6b75a4c (agents/308-l2-review-r15.md, R308-9).

The tool's docstring: a wrong reset.json "silently freezes the L2", so the tool "is deliberately strict": two
independent followers, and the statement "carries the pinned network identities". Each test fails on 6b75a4c.
Run: python3 -B -m unittest -v test_review_r15_reset_target   (from deployment/mainnet)
"""
import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mrt', HERE / 'make_reset_target.py')
mrt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mrt)

POLICY, PROOF = b'\x33' * 32, b'\x44' * 356


def statement(number, identities=(b'\xa0' * 32, b'\xa1' * 32, b'\xa2' * 32), marker=0):
    s = bytearray(mrt.STATEMENT_V3_BYTES)
    s[:22] = mrt.STATEMENT_V3_TAG
    for i, value in enumerate(identities):
        s[22 + i * 32:22 + i * 32 + 32] = value
    s[22 + 264:22 + 272] = number.to_bytes(8, 'big')
    s[-1] = marker
    return bytes(s)


def settlement(text):
    return (bytes([0x13]) + POLICY + text + PROOF).hex()


def entry(number, text, **over):
    out = {'l2_number': number, 'l2_hash': 'aa' * 32, 'l2_state_root': 'bb' * 32, 'configuration': '11' * 32,
           'commitment': mrt.settlement_commitment(POLICY, text, PROOF).hex(), 'native_block': 'cc' * 32,
           'native_slot': 4096}
    out.update(over)
    return out


class R308_9ResetTargetIsNotStrict(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='r308-reset-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_statement_of_another_network_is_refused(self):
        """No code compares identities 0..2 with anything: a rehearsal or devnet statement is written out. On mainnet
        `reset_head` then refuses it at the gate without a word, and the program still moves."""
        foreign = statement(42, identities=(b'\xde' * 32, b'\xad' * 32, b'\xbe' * 32))
        with self.assertRaises((SystemExit, ValueError), msg='written without the pinned identities being checked'):
            mrt.build(42, [entry(42, foreign), entry(42, foreign)], [settlement(foreign)])

    def test_the_same_follower_file_twice_is_not_two_followers(self):
        text = statement(42)
        (self.tmp / 'f.json').write_text(json.dumps({'finalized_settlements': [entry(42, text)]}))
        (self.tmp / 'block.hex').write_text(settlement(text) + '\n')
        argv = ['make_reset_target.py', '--number', '42', '--follower-status', str(self.tmp / 'f.json'),
                '--follower-status', str(self.tmp / 'f.json'), '--l1-block-hex', str(self.tmp / 'block.hex'),
                '--out', str(self.tmp / 'reset.json')]
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stop:
                    mrt.main()
        except AssertionError:
            self.fail('one status file given twice was accepted as two independent followers')
        finally:
            sys.argv = old
        self.assertNotIn(stop.exception.code, (0, None))

    def test_the_output_states_the_reset_form(self):
        """G2a needs `forfeit: true`. The tool never writes the key and arm.py reads a missing key as false, so the
        forfeit form exists only as a hand edit of the file this tool is meant to make safe."""
        text = statement(42)
        out = mrt.build(42, [entry(42, text), entry(42, text)], [settlement(text)])
        self.assertIn('forfeit', out)

    def test_two_log_entries_for_one_block_are_refused_or_the_newest_wins(self):
        """After a first reset the same L2 number is settled again; the log is append-only and the first match wins,
        which is the settlement the reset dropped. (Whether the follower keeps the dropped line was not checked.)"""
        old, new = statement(50, marker=1), statement(50, marker=2)
        (self.tmp / 's.settlements.jsonl').write_text(json.dumps(entry(50, old, l2_hash='01' * 32)) + '\n'
                                                      + json.dumps(entry(50, new, l2_hash='02' * 32)) + '\n')
        (self.tmp / 's.json').write_text(json.dumps({'settlement_log': {'file': 's.settlements.jsonl'}}))
        try:
            got = mrt.load_follower(str(self.tmp / 's.json'), 50)
        except SystemExit:
            return
        self.assertEqual(got['l2_hash'], '02' * 32)


if __name__ == '__main__':
    unittest.main()
