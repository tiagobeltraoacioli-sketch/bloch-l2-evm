#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests of the mainnet attestor agent and the claim aggregator.

The round trip is real: FRESH throwaway hybrid keys (bloch-pos ws-keygen), a throwaway 3-of-5 set,
keys sealed with `l2-claim seal-key`, three agents signing with `l2-claim attest --sealed`, the
aggregator, then the native `l2-claim verify-attestation` and `l2-claim prepare`/`inspect` (the
claim transaction's attestation, verified by `Attestation::verify`). Only the L2 rebuild
(produce-dev) is a test double. The real Genesis-4 mainnet.manifest gives the network domain.

  BLOCH_POS=/path/to/bloch-pos MAINNET_MANIFEST=/path/to/mainnet.manifest python3 -m unittest -v test_attestor
"""
import contextlib
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import aggregate_attestation  # noqa: E402
import attestor_agent  # noqa: E402
import attestor_lib as lib  # noqa: E402

BLOCH_POS = os.environ.get('BLOCH_POS', str(Path.home() / 'worktrees/l2-attestor-keystore-20261019/target/release/bloch-pos'))
MANIFEST = os.environ.get('MAINNET_MANIFEST', str(Path.home() / 'worktrees/l2-attestor-keystore-20261019/genesis/mainnet.manifest'))
NATIVE = Path(BLOCH_POS).is_file() and Path(MANIFEST).is_file()
BLCH = 100_000_000
L2_GENESIS = 'ab' * 32


def h(tag):
    return hashlib.sha256(tag.encode()).hexdigest()


class FakeRpc:
    """Three getl2settlement endpoints whose answers each test sets."""

    def __init__(self, n=3):
        self.views = [None] * n
        self.servers = []
        for i in range(n):
            owner = self

            class Handler(http.server.BaseHTTPRequestHandler):
                slot = i

                def do_POST(self):  # noqa: N802
                    self.rfile.read(int(self.headers['content-length']))
                    view = owner.views[self.slot]
                    if view is None:
                        self.send_response(500)
                        self.end_headers()
                        return
                    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': view}).encode()
                    self.send_response(200)
                    self.send_header('content-length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *a):
                    pass

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers.append(server)
        self.urls = [f'http://127.0.0.1:{s.server_address[1]}' for s in self.servers]

    def set_all(self, view):
        self.views = [json.loads(json.dumps(view)) for _ in self.views]

    def close(self):
        for s in self.servers:
            s.shutdown()


class PutSink:
    """An HTTP drop that accepts PUT and serves GET (the shared attestation drop)."""

    def __init__(self, root):
        self.root = Path(root)
        sink = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):  # noqa: N802
                if self.headers.get('authorization') != 'Bearer drop-token':
                    self.send_response(403)
                    self.end_headers()
                    return
                path = sink.root / self.path.lstrip('/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(self.rfile.read(int(self.headers['content-length'])))
                self.send_response(201)
                self.end_headers()

            def do_GET(self):  # noqa: N802
                path = sink.root / self.path.lstrip('/')
                if not path.is_file():
                    self.send_response(404)
                    self.end_headers()
                    return
                body = path.read_bytes()
                self.send_response(200)
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'


def run(*args, ok=True):
    done = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if ok and done.returncode:
        raise AssertionError(f'{args[:3]} failed: {done.stderr}')
    return done


class LibTest(unittest.TestCase):
    def test_empty_root_is_the_live_mainnet_empty_root(self):
        # getl2settlement withdrawals.root on mainnet with count 0 (2026-10-19).
        self.assertEqual(lib.EMPTY_ROOT.hex(), '27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757')

    def test_vendored_set_is_the_consensus_pin(self):
        path = HERE.parent / 'public' / 'attestors.set'
        self.assertEqual(lib.sha256_file(path), lib.SET_FILE_SHA256)
        threshold, keys = lib.read_set(path)
        self.assertEqual((threshold, len(keys), lib.set_hash(threshold, keys)), (3, 5, lib.SET_HASH))
        for i, key in enumerate(keys):
            self.assertEqual(bytes.fromhex((HERE.parent / 'public' / f'attestor-{i}.pk').read_text().strip()), key)

    def test_tree_proofs_and_claimed_bitmap(self):
        leaves = [lib.leaf(7, i, bytes([i]) * 32, BLCH + i) for i in range(5)]
        root = lib.tree_root(leaves)
        for i in range(5):
            self.assertEqual(lib.root_from_proof(leaves[i], i, lib.tree_proof(leaves, i)), root)
        self.assertNotEqual(lib.root_from_proof(leaves[0], 1, lib.tree_proof(leaves, 0)), root)
        view = {'floor': 1, 'words': [{'word': 2, 'bits': '0200'}]}
        self.assertTrue(lib.claimed(view, 255))
        self.assertTrue(lib.claimed(view, 513))
        self.assertFalse(lib.claimed(view, 512))
        self.assertFalse(lib.claimed(view, 300))


@unittest.skipUnless(NATIVE, f'needs BLOCH_POS ({BLOCH_POS}) with seal-key and MAINNET_MANIFEST')
class AgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='attestor-test-'))
        old = os.umask(0o077)
        keys = cls.tmp / 'keys'
        keys.mkdir()
        for i in range(5):
            run(BLOCH_POS, 'ws-keygen', '--out', keys / f't{i}')
        cls.set_file = cls.tmp / 'attestors.set'
        run(BLOCH_POS, 'l2-claim', 'attestor-set', '--threshold', '3',
            *[x for i in range(5) for x in ('--pubkey', keys / f't{i}.pk')], '--out', cls.set_file)
        threshold, pubkeys = lib.read_set(cls.set_file)
        cls.set_hash = lib.set_hash(threshold, pubkeys)
        cls.passes, cls.sealed = {}, {}
        for i in range(5):
            cls.passes[i] = cls.tmp / f'pass{i}'
            cls.passes[i].write_text(f'throwaway-test-passphrase-{i}-{os.urandom(8).hex()}\n')
            cls.sealed[i] = cls.tmp / f't{i}.sealed'
            run(BLOCH_POS, 'l2-claim', 'seal-key', '--key', keys / f't{i}.sk', '--attestors', cls.set_file,
                '--signer-index', i, '--passphrase-file', cls.passes[i], '--out', cls.sealed[i])
        # The plaintext throwaway secrets are no longer needed.
        shutil.rmtree(keys)
        os.umask(old)
        # A throwaway funding keystore (sealed) for the claim's fee inputs.
        cls.funding_dir = cls.tmp / 'funding'
        cls.funding_env = {**os.environ, 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(cls.passes[0])}
        subprocess.run([BLOCH_POS, 'keygen', '--dir', str(cls.funding_dir), '--index', '0'], env=cls.funding_env,
                       check=True, capture_output=True)
        public = subprocess.run([BLOCH_POS, 'keygen-public', '--dir', str(cls.funding_dir)], env=cls.funding_env,
                                check=True, capture_output=True, text=True).stdout.split('\t')[1]
        cls.funding_pk = cls.tmp / 'funding.pk'
        cls.funding_pk.write_text(public + '\n')
        cls.pins = lib.Pins(lib.CHAIN_ID, lib.NATIVE_NETWORK, lib.NATIVE_GENESIS, cls.set_hash,
                            lib.sha256_file(MANIFEST), L2_GENESIS, [], '1:0:30000', lib.LARGE_CLAIM_SAT)
        cls.produce = HERE / 'fake_produce.py'
        cls.rpc = FakeRpc()

    @classmethod
    def tearDownClass(cls):
        cls.rpc.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix='case-', dir=self.tmp))
        self.fixture = self.case / 'fixture.json'
        self.status = self.case / 'status.json'
        os.environ['FAKE_L2_FIXTURE'] = str(self.fixture)
        self.recipient = h('recipient')
        self.blocks = [
            {'number': 1, 'hash': h('b1'), 'state_root': h('s1'), 'withdrawals': []},
            {'number': 2, 'hash': h('b2'), 'state_root': h('s2'),
             'withdrawals': [{'l1_recipient': h('small'), 'sats': 5 * BLCH},
                             {'l1_recipient': self.recipient, 'sats': 150 * BLCH}]},
            {'number': 3, 'hash': h('b3'), 'state_root': h('s3'),
             'withdrawals': [{'l1_recipient': h('third'), 'sats': 2 * BLCH}]},
        ]
        self.write_fixture()
        self.write_status(finalized=[2, 3])
        self.rpc.set_all(self.view())

    def write_fixture(self, **extra):
        self.fixture.write_text(json.dumps({'genesis': L2_GENESIS, 'chain_id': lib.CHAIN_ID, 'native_blocks': 40,
                                            'blocks': self.blocks, **extra}))

    def commitments(self):
        out, leaves = {}, []
        for b in self.blocks:
            for w in b['withdrawals']:
                leaves.append(lib.leaf(lib.CHAIN_ID, len(leaves), bytes.fromhex(w['l1_recipient']), w['sats']))
            out[b['number']] = {'root': lib.tree_root(leaves).hex(), 'count': len(leaves)}
        return out

    def write_status(self, finalized, age=0, tamper=None):
        c = self.commitments()
        settlements = []
        for b in self.blocks:
            if b['number'] in finalized:
                entry = {'l2_number': b['number'], 'l2_hash': b['hash'], 'l2_state_root': b['state_root'],
                         'withdrawals': c[b['number']], 'native_slot': 100 + b['number'],
                         'native_block': h(f'n{b["number"]}')}
                if tamper and tamper[0] == b['number']:
                    entry.update(tamper[1])
                settlements.append(entry)
        self.status.write_text(json.dumps({
            'schema': 'bloch.l2.native-follower-status.v2', 'written_at_unix': time.time() - age,
            'network': lib.NATIVE_NETWORK, 'chain_id': lib.CHAIN_ID, 'verified_slot': 500,
            'l2_genesis': {'hash': L2_GENESIS, 'finalized': True}, 'finalized_settlements': settlements}))

    def view(self, claimed=None, attestor_set=None):
        c = self.commitments()
        roots, previous = [], 0
        for b in self.blocks:
            if c[b['number']]['count'] > previous:
                roots.append({'l2_number': b['number'], 'root': c[b['number']]['root'], 'count': c[b['number']]['count'],
                              'height': 10 + b['number'], 'finalized': True})
                previous = c[b['number']]['count']
        return {'network': lib.NATIVE_NETWORK, 'genesis': lib.NATIVE_GENESIS, 'chain_id': lib.CHAIN_ID,
                'native_height': 99,
                'withdrawals': {'roots': roots, 'claimed': claimed or {'count': 0, 'floor': 0, 'words': []},
                                'attestor_set': attestor_set or self.set_hash,
                                'large_claim_sat': str(lib.LARGE_CLAIM_SAT)}}

    def agent(self, index, dry_run=False, **extra):
        config = {
            'signer_index': index, 'bloch_pos': BLOCH_POS, 'bloch_pos_sha256': lib.sha256_file(BLOCH_POS),
            'produce': str(self.produce), 'produce_sha256': lib.sha256_file(self.produce), 'manifest': MANIFEST,
            'attestors': str(self.set_file), 'sealed_key': str(self.sealed[index]),
            'passphrase_file': str(self.passes[index]), 'follower_status': str(self.status),
            'follower_native': str(self.case / 'native'), 'state_dir': str(self.case / f'agent{index}'),
            'rpc_urls': self.rpc.urls, 'pause_file': str(self.case / 'PAUSE'),
            'approvals_file': str(self.case / f'approvals{index}.txt'), **extra}
        return attestor_agent.Agent(config, pins=self.pins, dry_run=dry_run)

    def once(self, agent):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                result = agent.cycle()
            except attestor_agent.Skip as e:
                result = f'skip: {e}'
        return result, [json.loads(line) for line in out.getvalue().splitlines() if line.startswith('{')]

    def root(self, number):
        return self.commitments()[number]['root']

    def partial(self, index, number):
        return self.case / f'agent{index}' / 'outbox' / lib.partial_relpath(lib.CHAIN_ID, self.root(number), index)

    def claim_proof(self, number, index=1):
        """The claimant's own proof (any party can produce it)."""
        done = run(sys.executable, self.produce, 'withdrawal-proof', '--target', 'x', '--index', index,
                   '--number', number, '--root', self.root(number), '--count', self.commitments()[number]['count'])
        path = self.case / f'proof-{number}-{index}.json'
        path.write_text(done.stdout)
        return path

    # ------------------------------------------------------------------ round trip
    def test_round_trip_three_agents_aggregate_and_native_verify(self):
        for i in (0, 2, 4):
            agent = self.agent(i)
            with contextlib.redirect_stdout(io.StringIO()):
                agent.check_identity(key='open')
            result, events = self.once(agent)
            self.assertEqual(result, 'ok')
            signed = [e for e in events if e['event'] == 'signed']
            # Roots of blocks 2 and 3 both cover the unclaimed 150 BLCH withdrawal (index 1).
            self.assertEqual(sorted(e['l2_number'] for e in signed), [2, 3], events)
            self.assertTrue(all(e['covers_large'] == [1] and e['alert'] for e in signed))
            index, digest, _ = lib.parse_partial(self.partial(i, 3).read_text())
            self.assertEqual((index, digest), (i, lib.attestation_digest(lib.NATIVE_NETWORK, lib.CHAIN_ID, self.root(3))))
        proof = self.claim_proof(3)
        out = self.case / 'agg'
        sources = [str(self.case / f'agent{i}' / 'outbox') for i in (0, 2, 4)]
        summary = aggregate_attestation.aggregate(proof, sources, out, BLOCH_POS, MANIFEST, str(self.set_file),
                                                  pins=self.pins)
        self.assertEqual(summary['signers'], [0, 2, 4])
        self.assertIn('attestation ok: 3-of-5', summary['native_verify'])
        self.assertIn(self.set_hash, summary['native_verify'])
        # The claim transaction the native code builds carries it (offline; nothing is broadcast).
        unsigned = self.case / 'claim.unsigned'
        done = run(BLOCH_POS, 'l2-claim', 'prepare', '--genesis', MANIFEST, '--funding-pubkey', self.funding_pk,
                   '--input', f'{"11" * 32}:0:1000000000', '--proof', proof, '--base-fee', '10', '--tip', '0',
                   *summary['prepare_args'], '--out', unsigned)
        self.assertIn(f'attestation    : 3-of-5 set {self.set_hash}, signers [0, 2, 4]', done.stdout)
        signed = self.case / 'claim.signed'
        done = subprocess.run([BLOCH_POS, 'l2-claim', 'sign', '--genesis', MANIFEST, '--tx', str(unsigned),
                               '--dir', str(self.funding_dir), '--out', str(signed)], env=self.funding_env,
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        inspect = run(BLOCH_POS, 'l2-claim', 'inspect', '--tx', signed).stdout
        self.assertIn('shape          : ok', inspect)
        self.assertIn('signed         : true', inspect)
        self.assertIn('signers [0, 2, 4]', inspect)
        self.assertIn(f'proves root    : {self.root(3)}', inspect)
        # Two partials are not enough; a tampered signature is refused by the native verifier.
        with self.assertRaises(SystemExit):
            aggregate_attestation.aggregate(proof, sources[:2], self.case / 'agg2', BLOCH_POS, MANIFEST,
                                            str(self.set_file), pins=self.pins)
        bad = self.case / 'bad'
        shutil.copytree(sources[0], bad)
        part = bad / lib.partial_relpath(lib.CHAIN_ID, self.root(3), 0)
        lines = part.read_text().split('\n')
        lines[2] = ('0' if lines[2][100] != '0' else '1').join([lines[2][:100], lines[2][101:]])
        part.write_text('\n'.join(lines))
        with self.assertRaises(SystemExit) as refused:
            aggregate_attestation.aggregate(proof, [str(bad)] + sources[1:], self.case / 'agg3', BLOCH_POS, MANIFEST,
                                            str(self.set_file), pins=self.pins)
        self.assertIn('native verification refused', str(refused.exception))
        # A claim proof against another root finds no partials for its root.
        with self.assertRaises(SystemExit):
            aggregate_attestation.aggregate(self.claim_proof(2, 0), [str(self.case / 'none')], self.case / 'agg4',
                                            BLOCH_POS, MANIFEST, str(self.set_file), pins=self.pins)

    def test_second_cycle_signs_nothing_new(self):
        agent = self.agent(1)
        self.once(agent)
        result, events = self.once(agent)
        self.assertEqual([e['event'] for e in events if e['event'] == 'signed'], [])

    # ------------------------------------------------------------------ refusals
    def test_not_finalized_on_own_replay_is_not_signed(self):
        self.write_status(finalized=[])
        _, events = self.once(self.agent(0))
        self.assertEqual({e['event'] for e in events}, {'awaiting-own-finality'})
        self.assertFalse(self.partial(0, 2).exists())

    def test_rpc_root_not_on_own_chain_is_refused(self):
        self.write_status(finalized=[2, 3], tamper=(2, {'withdrawals': {'root': h('other'), 'count': 2}}))
        _, events = self.once(self.agent(0))
        refused = [e for e in events if e['event'] == 'refused-root-not-on-own-chain']
        self.assertEqual(len(refused), 1)
        self.assertFalse(self.partial(0, 2).exists())
        # Block 3 is consistent and still signed.
        self.assertTrue(self.partial(0, 3).exists())

    def test_rebuild_that_differs_from_the_finalized_settlement_is_refused(self):
        self.write_status(finalized=[2, 3], tamper=(3, {'l2_state_root': h('forged')}))
        agent = self.agent(0)
        _, events = self.once(agent)
        self.assertIn('refused-rebuild-differs', [e['event'] for e in events])
        self.assertFalse(self.partial(0, 3).exists())
        _, again = self.once(agent)
        self.assertEqual([e.get('repeated') for e in again if e['event'] == 'refused-rebuild-differs'], [True])

    def test_failed_reconstruct_halts(self):
        self.write_fixture(reconstruct_fails=True)
        with self.assertRaises(attestor_agent.Halt):
            self.once(self.agent(0))

    def test_root_without_large_withdrawal_is_skipped(self):
        self.blocks[1]['withdrawals'][1]['sats'] = 99 * BLCH
        self.write_fixture()
        self.write_status(finalized=[2, 3])
        self.rpc.set_all(self.view())
        _, events = self.once(self.agent(0))
        self.assertEqual(sorted(e['l2_number'] for e in events if e['event'] == 'root-skipped'), [2, 3])

    def test_claimed_withdrawal_is_not_signed_again(self):
        self.rpc.set_all(self.view(claimed={'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '02'}]}))
        _, events = self.once(self.agent(0))
        self.assertEqual([e['event'] for e in events if e['event'] == 'signed'], [])

    def test_daily_cap_holds_until_the_operator_approves(self):
        agent = self.agent(0, daily_cap_sat=100 * BLCH)
        _, events = self.once(agent)
        held = [e for e in events if e['event'] == 'held']
        self.assertEqual(len(held), 2)
        self.assertFalse(self.partial(0, 2).exists())
        Path(agent.c['approvals_file']).write_text(held[0]['approve_with'][0] + '  # ticket 42\n')
        _, events = self.once(agent)
        self.assertEqual(len([e for e in events if e['event'] == 'signed']), 2)

    def test_single_withdrawal_above_maximum_is_held(self):
        _, events = self.once(self.agent(0, max_single_sat=120 * BLCH))
        self.assertEqual(len([e for e in events if e['event'] == 'held']), 2)

    def test_pause_file_stops_everything(self):
        (self.case / 'PAUSE').write_text('incident\n')
        self.assertEqual(self.once(self.agent(0))[0], 'paused')

    def test_stale_follower_waits(self):
        self.write_status(finalized=[2, 3], age=3600)
        self.assertIn('stalled follower', self.once(self.agent(0))[0])

    def test_no_rpc_quorum_waits_and_minority_is_ignored(self):
        views = [self.view(), self.view(claimed={'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '02'}]}), None]
        self.rpc.views = views
        self.assertIn('no RPC quorum', self.once(self.agent(0))[0])
        self.rpc.views = [self.view(), views[1], self.view()]
        _, events = self.once(self.agent(0))
        self.assertIn('rpc-endpoint-diverged', [e['event'] for e in events])
        self.assertEqual(len([e for e in events if e['event'] == 'signed']), 2)

    def test_live_policy_with_another_set_halts(self):
        self.rpc.set_all(self.view(attestor_set=lib.SET_HASH))
        with self.assertRaises(attestor_agent.Halt):
            self.once(self.agent(0))

    def test_wrong_passphrase_and_wrong_index_halt(self):
        wrong = self.case / 'wrong'
        wrong.write_text('not-the-right-passphrase\n')
        os.chmod(wrong, 0o600)
        with self.assertRaises(attestor_agent.Halt):
            with contextlib.redirect_stdout(io.StringIO()):
                self.agent(0, passphrase_file=str(wrong)).check_identity(key='open')
        with self.assertRaises(attestor_agent.Halt):
            with contextlib.redirect_stdout(io.StringIO()):
                self.agent(0, sealed_key=str(self.sealed[1])).check_identity(key='header')

    def test_binary_pin_mismatch_halts(self):
        with self.assertRaises(attestor_agent.Halt):
            self.agent(0, produce_sha256='00' * 32).check_identity(key='none')

    def test_dry_run_signs_nothing(self):
        _, events = self.once(self.agent(0, dry_run=True))
        self.assertEqual(len([e for e in events if e['event'] == 'would-sign']), 2)
        self.assertFalse(self.partial(0, 2).exists())

    def test_rebuild_check_passes_and_catches_a_divergent_rebuild(self):
        with contextlib.redirect_stdout(io.StringIO()):
            report = self.agent(0).rebuild_check()
        self.assertEqual(report['settled'], 3)
        self.write_status(finalized=[2, 3], tamper=(2, {'l2_hash': h('forged')}))
        with self.assertRaises(attestor_agent.Halt):
            with contextlib.redirect_stdout(io.StringIO()):
                self.agent(0).rebuild_check()

    def test_check_command_end_to_end(self):
        config = self.case / 'config.json'
        agent = self.agent(3)
        config.write_text(json.dumps(agent.c))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), unittest.mock.patch.object(attestor_agent, 'PINS', self.pins):
            code = attestor_agent.main(['check', '--config', str(config)])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn('"check-ok"', out.getvalue())

    # ------------------------------------------------------------------ publishing
    def test_publish_to_http_drop_and_command_drop_then_aggregate_from_them(self):
        drop = PutSink(self.case / 'http-drop')
        shared = self.case / 'shared-drop'
        creds = self.case / 'creds'
        creds.mkdir()
        (creds / 'publish-token').write_text('drop-token\n')
        os.environ['CREDENTIALS_DIRECTORY'] = str(creds)
        try:
            publish = [{'kind': 'http_put', 'url': drop.url, 'token_credential': 'publish-token'},
                       {'kind': 'command', 'argv': [sys.executable, '-c',
                                                    'import shutil,sys,os;os.makedirs(os.path.dirname(sys.argv[2]),exist_ok=True);'
                                                    'shutil.copy(sys.argv[1],sys.argv[2])',
                                                    '{file}', str(shared) + '/{relpath}']}]
            for i in (1, 3, 4):
                _, events = self.once(self.agent(i, publish=publish))
                self.assertEqual(len([e for e in events if e['event'] == 'published']), 4, events)
        finally:
            os.environ.pop('CREDENTIALS_DIRECTORY')
        proof = self.claim_proof(3)
        a = aggregate_attestation.aggregate(proof, [drop.url], self.case / 'from-http', BLOCH_POS, MANIFEST,
                                            str(self.set_file), pins=self.pins)
        b = aggregate_attestation.aggregate(proof, [str(shared)], self.case / 'from-dir', BLOCH_POS, MANIFEST,
                                            str(self.set_file), pins=self.pins)
        self.assertEqual(a['signers'], [1, 3, 4])
        self.assertEqual(b['signers'], [1, 3, 4])
        drop.server.shutdown()

    def test_publish_failure_is_retried(self):
        publish = [{'kind': 'command', 'argv': ['false']}]
        agent = self.agent(2, publish=publish)
        _, events = self.once(agent)
        self.assertEqual(len([e for e in events if e['event'] == 'publish-failed']), 2)
        agent.c['publish'] = [{'kind': 'command', 'argv': ['true']}]
        _, events = self.once(agent)
        self.assertEqual(len([e for e in events if e['event'] == 'published']), 2)


@unittest.skipUnless(NATIVE, 'needs BLOCH_POS with seal-key')
class KeykitTest(unittest.TestCase):
    """make-operator-bundles.sh on FRESH throwaway keys (passphrase files via the test hook)."""

    def test_seal_verify_and_shred_with_throwaway_keys(self):
        tmp = Path(tempfile.mkdtemp(prefix='keykit-'))
        old = os.umask(0o077)
        try:
            keys, passes, out = tmp / 'keys', tmp / 'pass', tmp / 'out'
            keys.mkdir()
            passes.mkdir()
            for i in range(5):
                run(BLOCH_POS, 'ws-keygen', '--out', keys / f'attestor-{i}')
                (passes / f'pass-{i}').write_text(f'throwaway-keykit-{i}-{os.urandom(6).hex()}\n')
            run(BLOCH_POS, 'l2-claim', 'attestor-set', '--threshold', '3',
                *[x for i in range(5) for x in ('--pubkey', keys / f'attestor-{i}.pk')], '--out', keys / 'attestors.set')
            expect = lib.set_hash(*lib.read_set(keys / 'attestors.set'))
            kit = HERE.parent / 'keykit' / 'make-operator-bundles.sh'
            env = {**os.environ, 'KEYKIT_PASSFILE_DIR': str(passes)}
            common = ['--keys-dir', str(keys), '--out', str(out), '--bloch-pos', BLOCH_POS]

            def kit_run(*args, extra=('--expect-set-hash', expect)):
                return subprocess.run(['bash', str(kit), *args, *common, *extra], capture_output=True, text=True, env=env)

            self.assertIn('not the consensus-pinned', kit_run('seal', extra=()).stderr)
            done = kit_run('shred-originals')
            self.assertNotEqual(done.returncode, 0, 'no shredding before a verified bundle')
            self.assertTrue((keys / 'attestor-0.sk').exists())
            self.assertEqual(kit_run('seal').returncode, 0)
            self.assertNotEqual(kit_run('seal', '--index', '1').returncode, 0, 'no overwrite')
            done = kit_run('verify')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(len((out / 'BUNDLES.sha256').read_text().splitlines()), 5)
            (passes / 'pass-2').write_text('a-wrong-passphrase-here\n')
            self.assertIn('authentication failed', kit_run('verify', '--index', '2').stderr)
            done = kit_run('shred-originals')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(sorted(p.name for p in keys.glob('*.sk')), [])
            self.assertEqual(len(list(keys.glob('*.pk'))), 5)
            # The bundles alone still carry the keys: each opens and signs for its public key.
            for i in (0, 4):
                run(BLOCH_POS, 'l2-claim', 'key-check', '--sealed', out / f'attestor-{i}.sealed', '--attestors',
                    keys / 'attestors.set', '--signer-index', i, '--passphrase-file', passes / f'pass-{i}')
        finally:
            os.umask(old)
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
