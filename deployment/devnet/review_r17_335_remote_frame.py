#!/usr/bin/env python3
"""Review r17 (agent 335): the remote prover's job frame version 2 against hostile settings.

The tree's own test (test_settler_policy_v2 `test_the_remote_prover_gets_the_blocks_profile`) sends
`{"LD_PRELOAD":"1"}` cut to 16 of its 18 bytes, so it is refused as malformed JSON, not by the list of allowed
names (R335-10). These cases reach the list. All pass on f73131f: the list holds.
Run: python3 -B -m unittest -v review_r17_335_remote_frame   (from deployment/devnet)
"""
import io
import json
import struct
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import remote_prover as rp  # noqa: E402


def frame(obj=None, raw=None):
    body = raw if raw is not None else json.dumps(obj).encode()
    return (rp.MAGIC_PROFILE + struct.pack('>H', len(body)) + body + struct.pack('>I', 3) + b'a\nb'
            + struct.pack('>Q', 1) + b'x')


class FrameVersion2(unittest.TestCase):
    def refused(self, data, text):
        with self.assertRaisesRegex(ValueError, text):
            rp.parse_job(io.BytesIO(data))

    def test_the_trees_own_case_is_refused_as_malformed_json_not_by_the_list(self):
        self.refused(rp.MAGIC_PROFILE + b'\x00\x10' + b'{"LD_PRELOAD":"1"}'[:16] + b'\x00' * 32, 'not an ASCII JSON object')

    def test_names_outside_the_list_are_refused(self):
        for name in ('LD_PRELOAD', 'PATH', 'HOME', 'SP1_GNARK_IMAGE', 'SP1_CIRCUIT_MODE', 'RAYON_NUM_THREADS',
                     'BLOCH_NATIVE_L2_ARTIFACT', 'WITHOUT_VK_VERIFICATION', 'element_threshold'):
            self.refused(frame({name: '1'}), f'prover_env {name} is not allowed')

    def test_values_must_be_positive_ascii_decimals(self):
        for value in ('1; rm', '-1', '0', '', ' 1', '1\n', '0x10', 5, None, ['1'], {'a': '1'}):
            self.refused(frame({'ELEMENT_THRESHOLD': value}), 'must be a positive decimal string')
        self.refused(frame(raw='{"ELEMENT_THRESHOLD":"٣"}'.encode()), 'not an ASCII JSON object')

    def test_shape_and_size(self):
        self.refused(frame([1]), 'must be an object')
        self.refused(frame(raw=b'{' + b' ' * 1100 + b'}'), 'out of bounds')
        self.refused(frame(raw=b'[' * 400 + b']' * 400), 'must be an object')
        self.assertEqual(rp.parse_job(io.BytesIO(frame({})))[2], {})

    def test_what_the_settler_can_still_choose(self):
        """Any positive integer for a listed name, and the last of two equal keys: the settler's key only."""
        self.assertEqual(rp.parse_job(io.BytesIO(frame({'ELEMENT_THRESHOLD': '9' * 900})))[2]['ELEMENT_THRESHOLD'], '9' * 900)
        twice = b'{"ELEMENT_THRESHOLD":"1","ELEMENT_THRESHOLD":"268435456"}'
        self.assertEqual(rp.parse_job(io.BytesIO(frame(raw=twice)))[2], {'ELEMENT_THRESHOLD': '268435456'})


if __name__ == '__main__':
    unittest.main()
