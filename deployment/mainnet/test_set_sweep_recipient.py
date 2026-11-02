#!/usr/bin/env python3
"""set-sweep-recipient.py: Keccak, the configuration commitment, address checks and the three edit steps
on throwaway git trees (no build, no network)."""
import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
L2 = HERE.parent.parent
spec = importlib.util.spec_from_file_location('ssr', HERE / 'set-sweep-recipient.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

PLACEHOLDER = '00000000000000000000000000000000000fee01'
PLACEHOLDER_CFG = '975ec2585246abeaea86421dd5726918b632dd91a246f635fe74990b68bcd878'
THROWAWAY = '14c0aeb5497a4e506b6c12556718be957302d96d'
OLD = {  # the candidate pins of d462647 / f12b4113
    'sparse': ('78c533fab3669e491d409f1c0d92e736ee0389e8e6fd7b64da3a7e3f69d37bea',
               '1f755262230baf9f1fded98a698cd3e31aa7f23a146116d4bd7e21e2bee2a5e0',
               '7e5b3c3345608ab36aced4db40f7692147a3fca80ace7a285bc335f342ee5910',
               '00fcb6786715822acf5676a6dc0f769218f47f9502b39e8a2de19af9c2ee5910'),
    'complete': ('3ad3a4f02b6f03768674de8804934064cc9f8f0b47fedbe0456dce79ddaa53b3',
                 'c9f8cd40b703b47c1fdfb183c223da9977ac9839e3d1c436c28c9b7f331aacf8',
                 '792452aa47ddaef1523907c03c39d3917df21180585eec804b27841626027d60',
                 '00f248a5551f76bbc691c83e03c39d391fbe42301617bb202593c20b26027d60'),
}
NATIVE = f'''pub mod mainnet {{
    /// guest ELF SHA-256 `78c533fa…7bea` (3 218 240 bytes). The state
    /// The configuration carries a PLACEHOLDER fee-sweep recipient, `TBD-owner`,
    /// and the guest is a candidate, so these values are examples until
    pub const PROGRAM_NEXT: NextProgram = NextProgram {{
        identities: [
            h32("{PLACEHOLDER_CFG}"),
            h32("{OLD['sparse'][1]}"),
            h32("{OLD['sparse'][2]}"),
            h32("{OLD['sparse'][3]}"),
        ],
        proof_policy: h32("{m.PROOF_POLICY}"),
    }};
    /// witness under the same rules, guest ELF SHA-256 `3ad3a4f0…53b3`
    /// (3 073 328 bytes). It replaces `44d4c9d7…ce47`.
    pub const PROGRAM_FALLBACK: NextProgram = NextProgram {{
        identities: [
            h32("{PLACEHOLDER_CFG}"),
            h32("{OLD['complete'][1]}"),
            h32("{OLD['complete'][2]}"),
            h32("{OLD['complete'][3]}"),
        ],
        proof_policy: h32("{m.PROOF_POLICY}"),
    }};
    pub const PROGRAM_NEXT_FINAL: bool = false;
}}
'''


def git(tree, *args):
    subprocess.run(['git', '-C', str(tree), *args], check=True, capture_output=True)


def run(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.main([str(a) for a in argv])
    return buf.getvalue()


class Commitment(unittest.TestCase):
    def test_keccak_and_both_known_commitments(self):
        self.assertEqual(m.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(m.configuration_commitment(), m.ACTIVATED_CONFIGURATION)
        self.assertEqual(m.configuration_commitment(PLACEHOLDER), PLACEHOLDER_CFG)
        self.assertNotEqual(m.configuration_commitment(THROWAWAY), PLACEHOLDER_CFG)

    def test_eip55_vector(self):
        self.assertEqual(m.eip55('5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'), '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')

    def test_addresses(self):
        self.assertEqual(m.parse_address('0x' + THROWAWAY.upper()), THROWAWAY)
        for bad in ('0x' + PLACEHOLDER, '0x4200000000000000000000000000000000000011', '0x' + '00' * 19 + '09',
                    '0x4200000000000000000000000000000000000abc', '0x1234', '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD',
                    '0x000000000000000000000000000000000000dEaD'):
            with self.assertRaises(SystemExit, msg=bad):
                m.parse_address(bad)
        self.assertEqual(m.parse_address('0x000000000000000000000000000000000000dEaD', allow_burn=True), '000000000000000000000000000000000000dead')


class Steps(unittest.TestCase):
    """apply, pins, native-commit and audit on copies of this tree's real files and a native fixture."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.l2, self.native = self.tmp / 'l2', self.tmp / 'native'
        for rel in (m.CHAINSPEC, m.SETTLER, m.BUILD_RELEASE, *m.CROSSINGS, 'docs/AUDIT-SCOPE-SPARSE.md',
                    'deployment/mainnet/SETTLER-RUNBOOK.md', 'deployment/mainnet/prover/install-prover-mainnet.py',
                    'deployment/mainnet/install-settler-mainnet.py', 'deployment/mainnet/test_make_native_program.py'):
            (self.l2 / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(L2 / rel, self.l2 / rel)
        (self.native / m.NATIVE_PINS).parent.mkdir(parents=True)
        (self.native / m.NATIVE_PINS).write_text(NATIVE)
        (self.native / 'Cargo.lock').write_text('lock\n')
        for tree in (self.l2, self.native):
            git(tree, 'init', '-q')
            git(tree, 'add', '-A')
            git(tree, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base')
        head = subprocess.run(['git', '-C', str(self.native), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        br = self.l2 / m.BUILD_RELEASE
        br.write_text(br.read_text().replace('CANDIDATE_NATIVE_COMMIT=f12b4113bfcba79ab21181cf5128602fc9550bb4',
                                             f'CANDIDATE_NATIVE_COMMIT={head}'))
        git(self.l2, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'native fixture')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def grep(self, value):
        out = subprocess.run(['grep', '-rl', '--exclude-dir=.git', value, str(self.l2), str(self.native)],
                             capture_output=True, text=True).stdout.split()
        return out

    def test_one_pass(self):
        new_cfg = m.configuration_commitment(THROWAWAY)
        run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native, '--dry-run')
        self.assertTrue(self.grep(PLACEHOLDER_CFG), 'dry run changes nothing')
        run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native)
        self.assertEqual(self.grep(PLACEHOLDER_CFG), [])
        self.assertEqual(self.grep(PLACEHOLDER), [])
        self.assertEqual(len(self.grep(new_cfg)), 7)  # settler, prover, 2 crossings, make_native test, audit scope, native
        self.assertIn(m.eip55(THROWAWAY), (self.native / m.NATIVE_PINS).read_text())
        self.assertNotIn('PLACEHOLDER', (self.l2 / m.CHAINSPEC).read_text().split('MAINNET_FEE_SWEEP_RECIPIENT: Address')[0][-600:])
        self.assertIn('nothing to change', run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native))
        with self.assertRaises(SystemExit):  # audit fails until the pins move
            run('audit', '--l2', self.l2, '--native', self.native, *sum((['--old', v] for v in OLD['sparse']), []))

        # phase 2 with fake ELFs and identities (stand-ins for the container builds and the host's identity)
        ids = {}
        for kind, program in (('sparse', 'settlement_v3_mainnet_sparse'), ('complete', 'settlement_v3_mainnet')):
            elf = self.tmp / f'{kind}.elf'
            elf.write_bytes(kind.encode() * 1000)
            ident = {'program': program, 'chain_id': 700770, 'domain': m.L2_DOMAIN, 'configuration': new_cfg,
                     'proof_policy_v3': m.PROOF_POLICY, 'elf_keccak': m.keccak256(kind.encode()).hex(),
                     'vkey_koalabear': m.keccak256(b'kb' + kind.encode()).hex(), 'vkey_bn254': '00' + m.keccak256(b'bn' + kind.encode()).hex()[2:]}
            (self.tmp / f'{kind}.json').write_text(json.dumps(ident))
            ids[kind] = ident
        bad = dict(ids['sparse'], configuration=PLACEHOLDER_CFG)
        (self.tmp / 'bad.json').write_text(json.dumps(bad))
        with self.assertRaises(SystemExit):
            run('pins', '--l2', self.l2, '--native', self.native, '--sparse-identity', self.tmp / 'bad.json',
                '--sparse-elf', self.tmp / 'sparse.elf', '--complete-identity', self.tmp / 'complete.json', '--complete-elf', self.tmp / 'complete.elf')
        run('pins', '--l2', self.l2, '--native', self.native, '--sparse-identity', self.tmp / 'sparse.json',
            '--sparse-elf', self.tmp / 'sparse.elf', '--complete-identity', self.tmp / 'complete.json', '--complete-elf', self.tmp / 'complete.elf')
        for old in OLD['sparse'] + OLD['complete']:
            self.assertEqual(self.grep(old), [], old)
            self.assertEqual(self.grep(old[:8]), [], old[:8])
        native = (self.native / m.NATIVE_PINS).read_text()
        self.assertIn('(6 000 bytes)', native)
        self.assertIn('(8 000 bytes)', native)
        self.assertEqual(m.native_program(self.native, 'PROGRAM_NEXT')[1], ids['sparse']['elf_keccak'])
        self.assertEqual(m.native_program(self.native, 'PROGRAM_FALLBACK')[3], ids['complete']['vkey_bn254'])

        # phase 3: commit native, move build-release.sh
        git(self.native, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'recipient')
        run('native-commit', '--l2', self.l2, '--native', self.native)
        head = subprocess.run(['git', '-C', str(self.native), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        self.assertIn(f'CANDIDATE_NATIVE_COMMIT={head}', (self.l2 / m.BUILD_RELEASE).read_text())
        out = json.loads(run('audit', '--l2', self.l2, '--native', self.native,
                             *sum((['--old', v] for v in OLD['sparse'] + OLD['complete']), [])))
        self.assertEqual(out['stale_values'], [])
        self.assertFalse(out['placeholder'])

    def test_native_commit_refuses_a_lock_change(self):
        (self.native / 'Cargo.lock').write_text('other\n')
        git(self.native, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'lock')
        with self.assertRaises(SystemExit):
            run('native-commit', '--l2', self.l2, '--native', self.native)

    def test_apply_refuses_a_tree_that_does_not_pin_its_own_recipient(self):
        p = self.l2 / m.CHAINSPEC
        p.write_text(p.read_text().replace(PLACEHOLDER, '00000000000000000000000000000000000fee02'))
        with self.assertRaises(SystemExit):
            run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native)


if __name__ == '__main__':
    unittest.main()
