#!/usr/bin/env python3
"""set-sweep-recipient.py: Keccak, the configuration commitment, address checks and the three edit steps
on throwaway git trees (no build, no network)."""
import contextlib
import importlib.util
import io
import json
import re
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
PLACEHOLDER_CFG = '975ec2585246abeaea86421dd5726918b632dd91a246f635fe74990b68bcd878'  # legacy: placeholder, no floor
REHEARSAL_CFG = '9d06fe0c95e743c08d482e6460831071f7be6288ce0fd8c05a769a0fa8518764'  # placeholder + 0.1 gwei floor
FLOOR = 100_000_000
THROWAWAY_FORCED_CFG = 'aa153f4ba3a4d1a60809b9701bf3e0ebec0046cbfd6882397442426d2227ae2e'  # throwaway + floor + forced bounds
THROWAWAY = '14c0aeb5497a4e506b6c12556718be957302d96d'
# Forced inclusion in the next rules (agents 137/215/216): the tree's next configuration is the version 4 value.
TREE_FORCED = m.current_forced(L2)
PLACEHOLDER_CFG_V3 = PLACEHOLDER_CFG
FORCED_PLACEHOLDER_CFG = 'b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d'  # agent 137's pins
if TREE_FORCED:
    PLACEHOLDER_CFG = FORCED_PLACEHOLDER_CFG
# The tree's own candidate pins (sparse = native PROGRAM_NEXT, complete = PROGRAM_FALLBACK), read from the settler.
OLD = {kind: tuple(m.settler_pin(L2, pin)[k] for k in ('guest_sha256', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'))
       for kind, pin in (('sparse', 'MAINNET_NEXT_SPARSE'), ('complete', 'MAINNET_NEXT'))}
NATIVE = f'''pub mod mainnet {{
    /// guest ELF SHA-256 `{OLD['sparse'][0][:8]}…{OLD['sparse'][0][-4:]}` (3 218 240 bytes). The state
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
    /// witness under the same rules, guest ELF SHA-256 `{OLD['complete'][0][:8]}…{OLD['complete'][0][-4:]}`
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
        self.assertEqual(m.configuration_commitment(PLACEHOLDER), PLACEHOLDER_CFG_V3)
        self.assertEqual(m.configuration_commitment(PLACEHOLDER, 0, True), FORCED_PLACEHOLDER_CFG)
        self.assertEqual(m.configuration_commitment(PLACEHOLDER, FLOOR, True), m.REHEARSAL_CONFIGURATION_FORCED)
        # Rust: chainspec::tests::rehearsal_configuration_matches_the_sweep_script, forced-inclusion feature.
        self.assertEqual(m.configuration_commitment(THROWAWAY, FLOOR, True), THROWAWAY_FORCED_CFG)
        self.assertEqual(m.configuration_commitment(PLACEHOLDER, FLOOR), REHEARSAL_CFG)
        self.assertEqual(m.REHEARSAL_CONFIGURATION, REHEARSAL_CFG)
        # Rust: chainspec::tests::rehearsal_configuration_matches_the_sweep_script pins the same value.
        self.assertEqual(m.configuration_commitment(THROWAWAY, FLOOR),
                         '7df770a35ce805982f12f552490337a77e842788ed3ab444fe42e35e6b3c1618')
        self.assertNotEqual(m.configuration_commitment(THROWAWAY), PLACEHOLDER_CFG_V3)

    def test_this_tree_is_gated(self):
        self.assertEqual(m.current_floor(L2), FLOOR)
        r = m.current_recipient(L2)
        self.assertEqual(m.gate_refusal(r) is None, r is not None)
        for guest in m.GUESTS:
            self.assertIn(m.GUEST_GATE, (L2 / guest).read_text(), guest)
        for script in ('integrations/sp1-execution/guest/build-container.sh',
                       'integrations/sp1-execution/guest-sparse/build-container.sh'):
            self.assertIn('set-sweep-recipient.py" > "$gate_script"', (L2 / script).read_text(), script)
        self.assertIn('set-sweep-recipient.py" gate --l2', (L2 / m.BUILD_RELEASE).read_text())

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


@unittest.skipUnless(m.current_recipient(L2) is None, 'this tree already carries a chosen recipient')
class Steps(unittest.TestCase):
    """apply, pins, native-commit and audit on copies of this tree's real files and a native fixture."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.l2, self.native = self.tmp / 'l2', self.tmp / 'native'
        for rel in (m.CHAINSPEC, m.FORCED_FILE, m.SETTLER, m.BUILD_RELEASE, *m.CROSSINGS, *m.GUESTS, 'docs/AUDIT-SCOPE-SPARSE.md',
                    'deployment/mainnet/SETTLER-RUNBOOK.md', 'deployment/mainnet/prover/install-prover-mainnet.py',
                    'deployment/mainnet/install-settler-mainnet.py', 'deployment/mainnet/test_make_native_program.py'):
            (self.l2 / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(L2 / rel, self.l2 / rel)
        (self.native / m.NATIVE_PINS).parent.mkdir(parents=True)
        (self.native / m.NATIVE_PINS).write_text(NATIVE)
        (self.native / 'Cargo.lock').write_text('lock\n')
        for tree in (self.l2, self.native):
            git(tree, 'init', '-q')
            git(tree, 'config', 'user.name', 't')  # `set` commits; hosts may have no global identity
            git(tree, 'config', 'user.email', 't@t')
            git(tree, 'add', '-A')
            git(tree, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base')
        head = subprocess.run(['git', '-C', str(self.native), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        br = self.l2 / m.BUILD_RELEASE
        br.write_text(re.sub(r'(?m)^CANDIDATE_NATIVE_COMMIT=[0-9a-f]{40}$', f'CANDIDATE_NATIVE_COMMIT={head}', br.read_text()))
        git(self.l2, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'native fixture')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def grep(self, value):
        out = subprocess.run(['grep', '-rl', '--exclude-dir=.git', value, str(self.l2), str(self.native)],
                             capture_output=True, text=True).stdout.split()
        return out

    def gate(self):
        try:
            run('gate', '--l2', self.l2)
        except SystemExit as stop:
            return stop.code
        return 0

    def test_one_pass(self):
        new_cfg = m.configuration_commitment(THROWAWAY, FLOOR, TREE_FORCED)
        self.assertEqual(self.gate(), 3, 'an unset tree is refused')
        before = sorted(self.grep(PLACEHOLDER_CFG))
        run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native, '--dry-run')
        self.assertTrue(self.grep(PLACEHOLDER_CFG), 'dry run changes nothing')
        self.assertEqual(self.gate(), 3)
        run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native)
        self.assertEqual(self.gate(), 0)
        self.assertEqual(self.grep(PLACEHOLDER_CFG), [])
        self.assertEqual([p for p in self.grep(PLACEHOLDER) if not p.endswith('chainspec.rs')], [])
        self.assertIn(f'Option<Address> = Some(Address::new(hex!("{THROWAWAY}")));', (self.l2 / m.CHAINSPEC).read_text())
        # settler, prover, 2 crossings, make_native test, audit scope, native, and chainspec.rs (its Rust test pins
        # the throwaway configuration as the cross-check of this script)
        if TREE_FORCED:
            # Forced next rules: every file that pinned agent 137's forced placeholder configuration now pins the
            # throwaway's (the Rust tests pin the rehearsal values, never the placeholder candidate pins).
            self.assertEqual(sorted(self.grep(new_cfg)), before)
        else:
            self.assertEqual(len(self.grep(new_cfg)), 8)
        self.assertIn(m.eip55(THROWAWAY), (self.native / m.NATIVE_PINS).read_text())
        self.assertNotIn('UNSET', (self.l2 / m.CHAINSPEC).read_text().split('MAINNET_FEE_SWEEP_RECIPIENT: Option')[0][-1400:])
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
        self.assertEqual(out['tbd_owner_sweep_mentions'], [])
        self.assertFalse(out['placeholder'])

    def test_native_commit_refuses_a_lock_change(self):
        (self.native / 'Cargo.lock').write_text('other\n')
        git(self.native, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'lock')
        with self.assertRaises(SystemExit):
            run('native-commit', '--l2', self.l2, '--native', self.native)

    def test_apply_refuses_a_tree_that_does_not_pin_its_own_recipient(self):
        p = self.l2 / m.SETTLER
        p.write_text(p.read_text().replace(PLACEHOLDER_CFG, '11' * 32, 1))
        with self.assertRaises(SystemExit):
            run('apply', THROWAWAY, '--l2', self.l2, '--native', self.native)

    def test_gate_refuses_placeholder_and_burn_from_a_chainspec_file(self):
        text = (self.l2 / m.CHAINSPEC).read_text()
        for value, code in ((PLACEHOLDER, 3), ('000000000000000000000000000000000000dead', 3), ('00' * 19 + '05', 3),
                            (THROWAWAY, 0)):
            f = self.tmp / f'{value}.rs'
            f.write_text(m.RECIPIENT_RE.sub(
                f'pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> = Some(Address::new(hex!("{value}")));', text))
            try:
                run('gate', '--chainspec', f)
                got = 0
            except SystemExit as stop:
                got = stop.code
            self.assertEqual(got, code, value)

    def test_set_is_one_command(self):
        run('set', '0x' + THROWAWAY, '--l2', self.l2, '--native', self.native)
        self.assertEqual(self.gate(), 0)
        for tree in (self.l2, self.native):
            status = subprocess.run(['git', '-C', str(tree), 'status', '--porcelain', '--untracked-files=no'],
                                    capture_output=True, text=True).stdout
            self.assertEqual(status, '', f'{tree} left uncommitted')
            log = subprocess.run(['git', '-C', str(tree), 'log', '-1', '--format=%s'], capture_output=True, text=True).stdout
            self.assertIn(m.eip55(THROWAWAY), log)
        self.assertEqual(m.settler_pin(self.l2, 'MAINNET_NEXT_SPARSE')['configuration'],
                         m.configuration_commitment(THROWAWAY, FLOOR, TREE_FORCED))
        self.assertIn('nothing to change', run('set', '0x' + THROWAWAY, '--l2', self.l2, '--native', self.native))
        with self.assertRaises(SystemExit):
            run('set', '0x' + PLACEHOLDER, '--l2', self.l2, '--native', self.native)


class OnChain(unittest.TestCase):
    """`onchain` against a loopback fake RPC: a 2-of-3 Safe v1.4.1, then a codeless address."""

    def serve(self, code):
        import http.server
        import threading
        owners = ['11' * 20, '22' * 20, '33' * 20]

        def word(v):
            return format(v, '064x')

        answers = {
            'eth_chainId': hex(700770), 'eth_getCode': code, 'eth_getBalance': hex(5 * 10**18),
            '0xe75235b8': '0x' + word(2),
            '0xa0e67e2b': '0x' + word(32) + word(3) + ''.join('0' * 24 + o for o in owners),
            '0xffa1ad74': '0x' + word(32) + word(5) + b'1.4.1'.hex().ljust(64, '0'),
        }

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['content-length'])))
                key = req['params'][0]['data'] if req['method'] == 'eth_call' else req['method']
                body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': answers[key]}).encode()
                self.send_response(200)
                self.send_header('content-type', 'application/json')
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_port}'

    def test_a_deployed_safe(self):
        out = json.loads(run('onchain', '0x' + THROWAWAY, '--rpc', self.serve('0x6080')))
        self.assertEqual((out['threshold'], len(out['owners']), out['safe_version']), (2, 3, '1.4.1'))
        self.assertEqual(out['balance_wei'], 5 * 10**18)

    def test_a_codeless_address_needs_the_flag(self):
        url = self.serve('0x')
        with self.assertRaises(SystemExit):
            run('onchain', '0x' + THROWAWAY, '--rpc', url)
        self.assertEqual(json.loads(run('onchain', '0x' + THROWAWAY, '--rpc', url, '--allow-codeless'))['code_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
