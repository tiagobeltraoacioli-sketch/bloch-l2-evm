#!/usr/bin/env python3
"""make_native_program.py for the activated program and the candidate next program. No network."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('make_native_program', HERE / 'make_native_program.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

GENESIS = {'number': 0, 'hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
           'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'}
POLICY = '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d'
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
# `bloch-evm-sp1-settlement-v3 --mainnet --sparse identity` of the candidate host on 75b9c635 (2026-11-02, 45.77).
SPARSE = {'program': 'settlement_v3_mainnet_sparse', 'chain_id': 700770, 'domain': DOMAIN,
          'configuration': '975ec2585246abeaea86421dd5726918b632dd91a246f635fe74990b68bcd878',
          'elf_keccak': '54d264b8969845b82b3c8d0cec54562567ab7ee6f59dae7e2678c7d9e848c011',
          'vkey_koalabear': '5f802b085c7520f54383ee604e867d4d327a0d554388ca79254748973cf6c126',
          'vkey_bn254': '00bf00561171d483d61c1f7304e867d4d64f41aab0e2329e52a3a44bbcf6c126',
          'sp1_circuit_version': 'v6.1.0', 'proof_policy_v3': POLICY}
NETWORK, NATIVE_GENESIS = 'aa' * 32, 'bb' * 32


class NextProgram(unittest.TestCase):
    def test_the_sparse_identity_gives_the_native_program_next_literal(self):
        out = m.build(SPARSE, GENESIS, POLICY, NETWORK, NATIVE_GENESIS)
        self.assertEqual(out['const'], 'PROGRAM_NEXT')
        self.assertTrue(out['rust'].startswith('pub const PROGRAM_NEXT: NextProgram = NextProgram {'))
        for key in ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'):
            self.assertIn(f'h32("{SPARSE[key]}")', out['rust'])
        self.assertIn(f'proof_policy: h32("{POLICY}")', out['rust'])
        self.assertNotIn(DOMAIN, out['rust'], 'identities 0 to 2 stay as activated')

    def test_the_sparse_guest_is_never_the_activated_program_and_names_are_closed(self):
        with self.assertRaises(SystemExit):
            m.build(SPARSE, GENESIS, POLICY, NETWORK, NATIVE_GENESIS, 'PROGRAM')
        with self.assertRaises(SystemExit):
            m.build(SPARSE, GENESIS, POLICY, NETWORK, NATIVE_GENESIS, 'PROGRAM_FALLBACK')
        with self.assertRaises(SystemExit):
            m.build({**SPARSE, 'program': 'other'}, GENESIS, POLICY, NETWORK, NATIVE_GENESIS)

    def test_the_activated_program_keeps_its_literal(self):
        activated = {**SPARSE, 'program': 'settlement_v3_mainnet',
                     'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b'}
        out = m.build(activated, GENESIS, POLICY, NETWORK, NATIVE_GENESIS)
        self.assertTrue(out['rust'].startswith('pub const PROGRAM: Option<Program> = Some(Program {'))
        self.assertIn('initial_l2_parent', out['rust'])


if __name__ == '__main__':
    unittest.main()
