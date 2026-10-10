#!/usr/bin/env python3
"""Unit tests for make_l2_config.py (run with python3 -m unittest)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_l2_config as m  # noqa: E402

IDENTITY = {'program': 'settlement_v3', 'chain_id': 700771, 'domain': 'd3' * 32, 'configuration': '01' * 32,
            'elf_keccak': '02' * 32, 'vkey_koalabear': '03' * 32, 'vkey_bn254': '04' * 32,
            'sp1_circuit_version': 'v6.1.0', 'proof_policy_v3': '05' * 32}
GENESIS = {'number': 0, 'hash': '06' * 32, 'state_root': '07' * 32}


class MakeL2ConfigTest(unittest.TestCase):
    def test_layout_matches_the_native_l2_config(self):
        config = m.build(IDENTITY, GENESIS, '05' * 32)
        self.assertEqual(len(config), 264)
        self.assertEqual(config[:32], bytes.fromhex('d3' * 32))
        for i, byte in enumerate((1, 2, 3, 4)):
            self.assertEqual(config[32 * (i + 1):32 * (i + 2)], bytes([byte]) * 32)
        self.assertEqual(config[160:192], b'\x05' * 32)
        self.assertEqual(config[192:200], (700771).to_bytes(8, 'little'))
        self.assertEqual(config[200:232], b'\x06' * 32)
        self.assertEqual(config[232:264], b'\x07' * 32)

    def test_refusals(self):
        cases = [
            ({**IDENTITY, 'program': 'settlement_v2'}, GENESIS, '05' * 32),
            ({**IDENTITY, 'chain_id': 1}, GENESIS, '05' * 32),
            ({**IDENTITY, 'proof_policy_v3': None}, GENESIS, '05' * 32),
            (IDENTITY, GENESIS, '06' * 32),  # native and L2 disagree on the policy
            (IDENTITY, {**GENESIS, 'number': 1}, '05' * 32),
            ({**IDENTITY, 'vkey_bn254': '00' * 32}, GENESIS, '05' * 32),
            ({**IDENTITY, 'configuration': 'zz' * 32}, GENESIS, '05' * 32),
        ]
        for identity, genesis, policy in cases:
            with self.assertRaises(SystemExit):
                m.build(identity, genesis, policy)

    def test_cli_writes_once(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 'id.json').write_text(json.dumps(IDENTITY))
            (d / 'g.json').write_text(json.dumps(GENESIS))
            args = ['--identity', str(d / 'id.json'), '--genesis', str(d / 'g.json'), '--native-policy', '05' * 32,
                    '--out', str(d / 'l2-config.bin')]
            m.main(args)
            self.assertEqual(len((d / 'l2-config.bin').read_bytes()), 264)
            with self.assertRaises(FileExistsError):
                m.main(args)


if __name__ == '__main__':
    unittest.main()
