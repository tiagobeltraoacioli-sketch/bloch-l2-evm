#!/usr/bin/env python3
"""Tests for make_l2_config_mainnet.py. Run: python3 -m unittest discover -s deployment/mainnet -p 'test_*.py'"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'devnet'))
import make_l2_config_mainnet as m  # noqa: E402

# The l2-config.bin the private mainnet-path rehearsal ran with on 2026-10-18
# (45.77 ~/l2-mainnet-rehearsal-20261018/run/l2-config.bin, 264 bytes).
REHEARSAL_CONFIG = bytes.fromhex(
    '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
    '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b'
    '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073'
    '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e'
    '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e'
    '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d'
    '62b10a0000000000'
    '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
    '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d')
# Its inputs: out/identity.json (`bloch-evm-sp1-settlement-v3 --mainnet identity`) and the
# producer's genesis head (run/state.json l2_genesis).
IDENTITY = {"program": "settlement_v3_mainnet", "chain_id": 700770,
            "domain": "1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733",
            "configuration": "8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b",
            "elf_keccak": "6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073",
            "vkey_koalabear": "389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e",
            "vkey_bn254": "007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e",
            "sp1_circuit_version": "v6.1.0",
            "proof_policy_v3": "154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"}
GENESIS = {'hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468', 'number': 0,
           'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d', 'withdrawal_count': 0,
           'withdrawal_root': '27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757'}


class MakeMainnetConfigTest(unittest.TestCase):
    def test_reproduces_the_rehearsal_config_byte_for_byte(self):
        self.assertEqual(len(REHEARSAL_CONFIG), 264)
        self.assertEqual(hashlib.sha256(REHEARSAL_CONFIG).hexdigest(), m.CONFIG_SHA256)
        self.assertEqual(m.build(IDENTITY, GENESIS, IDENTITY['proof_policy_v3']), REHEARSAL_CONFIG)
        self.assertEqual(m.from_pins(), REHEARSAL_CONFIG)

    def test_agrees_with_the_settler_pins(self):
        import settler_v3
        self.assertEqual(settler_v3.mainnet_l2_config(), REHEARSAL_CONFIG)
        self.assertEqual(settler_v3.MAINNET_L2_CONFIG_SHA256, m.CONFIG_SHA256)

    def test_refuses_anything_off_the_pins(self):
        cases = [
            ({**IDENTITY, 'program': 'settlement_v3'}, GENESIS, None, 'settlement_v3_mainnet'),
            ({**IDENTITY, 'chain_id': 700771}, GENESIS, None, '700770'),
            ({k: v for k, v in IDENTITY.items() if k != 'proof_policy_v3'}, GENESIS, None, 'source-settlement'),
            ({**IDENTITY, 'elf_keccak': 'ab' * 32}, GENESIS, None, 'elf_keccak differs'),
            ({**IDENTITY, 'domain': 'zz'}, GENESIS, None, 'domain must be 32 bytes'),
            (IDENTITY, GENESIS, '00' * 32, 'native build disagrees'),
            (IDENTITY, {**GENESIS, 'number': 1}, None, 'number 0'),
            (IDENTITY, {**GENESIS, 'hash': 'cd' * 32}, None, 'genesis hash differs'),
            (IDENTITY, {**GENESIS, 'state_root': 'cd' * 32}, None, 'state root differs'),
        ]
        for identity, genesis, policy, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(SystemExit, reason):
                m.build(identity, genesis, policy)

    def test_cli_writes_once_and_reports_the_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'identity.json').write_text(json.dumps(IDENTITY))
            (root / 'genesis.json').write_text(json.dumps(GENESIS))
            args = ['--identity', str(root / 'identity.json'), '--genesis', str(root / 'genesis.json'),
                    '--out', str(root / 'l2-config.bin')]
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                self.assertEqual(m.main(args), 0)
            self.assertEqual((root / 'l2-config.bin').read_bytes(), REHEARSAL_CONFIG)
            self.assertEqual(json.loads(printed.getvalue())['sha256'], m.CONFIG_SHA256)
            with self.assertRaises(FileExistsError):
                m.main(args)
            with contextlib.redirect_stdout(io.StringIO()):
                m.main(['--pins-only', '--out', str(root / 'pins.bin')])
            self.assertEqual((root / 'pins.bin').read_bytes(), REHEARSAL_CONFIG)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.main(['--pins-only', '--identity', 'x', '--out', str(root / 'other.bin')])


if __name__ == '__main__':
    unittest.main()
