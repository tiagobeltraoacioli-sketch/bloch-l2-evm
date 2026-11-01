#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests of the replica kit. No network beyond loopback, no systemd, no root, no real binary is run.

  REPLICA_ARTIFACTS=DIR python3 -I tests/test_replica.py

DIR holds the real mainnet.manifest and carryover.tsv.gz, whose pins cannot be replaced. Binaries are fakes
under --rehearsal-pins. Without REPLICA_ARTIFACTS the installer tests are skipped.
"""
import hashlib
import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
INSTALLER = KIT / 'install-replica.sh'
FAKE = HERE / 'fake_produce.py'
ART = os.environ.get('REPLICA_ARTIFACTS')


def load(name):
    spec = importlib.util.spec_from_file_location(name, KIT / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


refresh = load('replica_refresh')
check = load('replica_check')
GENESIS = refresh.L2_GENESIS


class L1Handler(http.server.BaseHTTPRequestHandler):
    answers = {}

    def do_POST(self):
        doc = json.loads(self.rfile.read(int(self.headers['content-length'])))
        answer = self.answers.get(doc['method'])
        if callable(answer):
            answer = answer(doc['params'])
        body = {'jsonrpc': '2.0', 'id': doc['id']}
        body.update({'error': {'code': -32601, 'message': 'no'}} if answer is None and doc['method'] not in self.answers else {'result': answer})
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def serve(answers, host='127.0.0.1'):
    handler = type('H', (L1Handler,), {'answers': answers})
    server = http.server.ThreadingHTTPServer((host, 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def l1_answers(network=check.NETWORK):
    return {'getl2settlement': {'network': network, 'genesis': check.L1_GENESIS, 'chain_id': check.CHAIN_ID,
                                'source': {'block': check.ACTIVATION_BLOCK}, 'accepted': None},
            'getchaininfo': {'finalized': {'epoch': 100, 'root': 'aa'}}}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(ART, 'REPLICA_ARTIFACTS is not set')
class Installer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.l1 = serve(l1_answers())
        cls.url = f'http://127.0.0.1:{cls.l1.server_port}'
        cls.settler = f'http://127.0.0.2:{cls.l1.server_port}'
        cls.wrong = serve(l1_answers('00' * 32))

    @classmethod
    def tearDownClass(cls):
        for server in (cls.l1, cls.wrong):
            server.shutdown()
            server.server_close()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='replica-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.prefix = self.tmp / 'prefix'
        self.art = self.make_artifacts('art', 'v1')
        self.pins = self.make_pins(self.art, 'pins1')
        self.opt = self.prefix / 'opt/bloch/l2-replica'

    def make_artifacts(self, name, rpc_tag, follower_tag='v1'):
        art = self.tmp / name
        art.mkdir()
        for f in ('mainnet.manifest', 'carryover.tsv.gz'):
            shutil.copy(Path(ART) / f, art / f)
        for f, tag in (('bloch-l2-native-follower', follower_tag), ('bloch-l2-produce-dev', 'v1'), ('bloch-l2-settled-rpc', rpc_tag)):
            (art / f).write_text(f'#!/bin/sh\n# fake {f} {tag}\n')
        return art

    def make_pins(self, art, name):
        path = self.tmp / name
        files = ('bloch-l2-native-follower', 'bloch-l2-produce-dev', 'bloch-l2-settled-rpc', 'mainnet.manifest', 'carryover.tsv.gz')
        path.write_text(''.join(f'{sha(art / f)}  {f}\n' for f in files))
        return path

    def run_kit(self, *args, ok=True, pins=None, prefix=True):
        argv = [str(INSTALLER), *args]
        if prefix:
            argv += ['--prefix', str(self.prefix)]
        if pins:
            argv += ['--rehearsal-pins', str(pins)]
        done = subprocess.run(argv, capture_output=True, text=True)
        if ok is not None:
            self.assertEqual(done.returncode == 0, ok, done.stdout + done.stderr)
        return done.stdout + done.stderr

    def install(self, **kw):
        return self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', self.url,
                            '--settler-l1-rpc-url', self.settler, pins=self.pins, **kw)

    def snapshot(self):
        return sorted(str(p) for p in self.tmp.rglob('*') if 'prefix' in str(p))

    def test_dry_run_changes_nothing(self):
        before = self.snapshot()
        out = self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', self.url,
                           '--settler-l1-rpc-url', self.settler, '--dry-run', pins=self.pins)
        self.assertIn('DRY RUN', out)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.prefix.exists())

    def test_dry_run_still_checks_pins(self):
        (self.art / 'bloch-l2-settled-rpc').write_text('tampered')
        self.assertIn('does not match its pin', self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', self.url,
                                                             '--settler-l1-rpc-url', self.settler, '--dry-run', ok=False, pins=self.pins))

    def test_release_pins_refuse_fake_binaries(self):
        self.assertIn('does not match its pin', self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', self.url,
                                                             '--settler-l1-rpc-url', self.settler, ok=False))

    def test_rehearsal_pins_need_prefix(self):
        out = self.run_kit('install', '--artifacts', str(self.art), '--rehearsal-pins', str(self.pins), ok=False, prefix=False)
        self.assertIn('needs --prefix', out)

    def test_rehearsal_pins_cannot_change_the_manifest(self):
        text = self.pins.read_text().replace(sha(self.art / 'mainnet.manifest'), '0' * 64)
        self.pins.write_text(text)
        self.assertIn('may not change mainnet.manifest', self.run_kit('install', '--artifacts', str(self.art), ok=False, pins=self.pins))

    def test_refuses_same_l1_host_as_settler(self):
        out = self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', self.url, '--settler-l1-rpc-url', self.url + '/',
                           ok=False, pins=self.pins)
        self.assertIn('must read another one', out)

    def test_needs_settler_l1(self):
        self.assertIn('both required', self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', self.url, ok=False, pins=self.pins))

    def test_refuses_credentials_in_url(self):
        out = self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', f'http://u:p@127.0.0.1:{self.l1.server_port}',
                           '--settler-l1-rpc-url', self.settler, ok=False, pins=self.pins)
        self.assertIn('without credentials', out)

    def test_refuses_wrong_l1_network(self):
        out = self.run_kit('install', '--artifacts', str(self.art), '--l1-rpc-url', f'http://127.0.0.1:{self.wrong.server_port}',
                           '--settler-l1-rpc-url', self.settler, ok=False, pins=self.pins)
        self.assertIn('identity preflight', out)

    def test_refuses_secret_files(self):
        for name in ('attestor.sk', 'keystore.json', 'host.passphrase', 'attestor-1.sealed'):
            with self.subTest(name):
                (self.art / name).write_text('x')
                self.assertIn('secret-looking', self.install(ok=False))
                (self.art / name).unlink()

    def test_install_layout_and_units(self):
        out = self.install()
        self.assertIn('NOT started', out)
        self.assertEqual(os.readlink(self.opt / 'current'), f'releases/{sha(self.pins)[:12]}')
        units = self.prefix / 'systemd'
        follower = (units / 'bloch-l2-replica-follower.service').read_text()
        rpc = (units / 'bloch-l2-replica-rpc.service').read_text()
        rendered = ''.join(p.read_text() for p in units.iterdir())
        self.assertNotRegex(rendered, r'@[A-Z0-9_]+@')
        self.assertIn('IPAddressAllow=localhost 127.0.0.1\n', follower)
        self.assertIn('MemoryMax=6G', follower)
        self.assertIn('MemoryMax=4G', rpc)
        self.assertIn('--port 18965', rpc)
        for text in (follower, rpc):
            self.assertIn('User=bloch-l2-replica\n', text)
            self.assertIn('ProtectSystem=strict', text)
            self.assertIn('IPAddressDeny=any', text)
            self.assertIn('sha256sum -c', text)
        exec_rpc = next(l for l in rpc.splitlines() if l.startswith('ExecStart='))
        self.assertNotIn('--txpool', exec_rpc)
        for word in ('LoadCredential', 'keystore', 'passphrase'):
            self.assertNotIn(word, rendered)
        self.assertIn(f'BLOCH_L1_RPC_URL={self.url}\n', (self.prefix / 'etc/bloch-l2-replica/replica.env').read_text())
        self.assertIn('already', self.install(ok=False).replace('exists', 'already'))

    def test_upgrade_rpc_only_then_rollback_and_back(self):
        self.install()
        v1 = os.readlink(self.opt / 'current')
        art2 = self.make_artifacts('art2', 'v2')
        pins2 = self.make_pins(art2, 'pins2')
        dry = self.run_kit('upgrade', '--artifacts', str(art2), '--dry-run', pins=pins2)
        self.assertIn('DRY RUN', dry)
        self.assertEqual(os.readlink(self.opt / 'current'), v1)
        out = self.run_kit('upgrade', '--artifacts', str(art2), pins=pins2)
        self.assertIn('systemctl restart bloch-l2-replica-rpc', out)
        self.assertNotIn('systemctl restart bloch-l2-replica-follower', out)
        v2 = os.readlink(self.opt / 'current')
        self.assertNotEqual(v1, v2)
        self.assertEqual(os.readlink(self.opt / 'previous'), v1)
        self.assertIn('fake bloch-l2-settled-rpc v2', (self.opt / 'current/bloch-l2-settled-rpc').read_text())
        self.assertIn('already current', self.run_kit('upgrade', '--artifacts', str(art2), ok=False, pins=pins2))
        dry = self.run_kit('rollback', '--dry-run')
        self.assertEqual(os.readlink(self.opt / 'current'), v2)
        out = self.run_kit('rollback')
        self.assertIn('rolled back', out)
        self.assertEqual(os.readlink(self.opt / 'current'), v1)
        self.assertEqual(os.readlink(self.opt / 'previous'), v2)
        self.assertIn('fake bloch-l2-settled-rpc v1', (self.opt / 'current/bloch-l2-settled-rpc').read_text())
        self.run_kit('upgrade', '--artifacts', str(art2), pins=pins2)
        self.assertEqual(os.readlink(self.opt / 'current'), v2)

    def test_follower_change_warns_of_replay(self):
        self.install()
        art2 = self.make_artifacts('art2', 'v1', follower_tag='v2')
        out = self.run_kit('upgrade', '--artifacts', str(art2), pins=self.make_pins(art2, 'pins2'))
        self.assertIn('systemctl restart bloch-l2-replica-follower', out)
        self.assertIn('about an hour', out)

    def test_rollback_needs_previous_and_intact_release(self):
        self.install()
        self.assertIn('no previous release', self.run_kit('rollback', ok=False))
        art2 = self.make_artifacts('art2', 'v2')
        self.run_kit('upgrade', '--artifacts', str(art2), pins=self.make_pins(art2, 'pins2'))
        previous = self.opt / 'previous' / 'bloch-l2-settled-rpc'
        previous.resolve().write_text('tampered')
        self.assertIn('does not match', self.run_kit('rollback', ok=False))

    def test_upgrade_needs_install(self):
        self.assertIn('nothing installed', self.run_kit('upgrade', '--artifacts', str(self.art), ok=False, pins=self.pins))

    def test_remove_keeps_data_unless_purged(self):
        self.install()
        state = self.prefix / 'var/lib/bloch-l2-replica/follower/native'
        state.mkdir()
        self.assertIn('kept', self.run_kit('remove'))
        self.assertTrue(state.exists())
        self.assertFalse(self.opt.exists())
        self.assertFalse((self.prefix / 'systemd/bloch-l2-replica-rpc.service').exists())
        self.install()
        self.run_kit('remove', '--purge-data')
        self.assertFalse(state.exists())


def status(tip='t1', settlements=(), **over):
    doc = {'schema': refresh.SCHEMA, 'network': refresh.NETWORK, 'chain_id': refresh.CHAIN_ID, 'production_finality': False,
           'l2_genesis': {'hash': GENESIS, 'finalized': True, 'state_root': check.L2_STATE_ROOT, 'activation_block': check.ACTIVATION_BLOCK},
           'verified_tip': tip, 'written_at_unix': int(time.time()), 'finalized_settlements': list(settlements),
           'native_finalized_epoch': 95, 'native_finalized_block': 'bb', 'verified_blocks': 10}
    doc.update(over)
    return doc


class FollowerStatusV3(unittest.TestCase):
    """Both replica tools read schema v3; a log that differs from its status stops them."""

    def write(self, d, count):
        entries = [{'l2_number': n, 'l2_hash': f'h{n}', 'l2_state_root': f's{n}'} for n in range(1, count + 1)]
        text = b''.join(json.dumps(e, sort_keys=True).encode() + b'\n' for e in entries)
        path = Path(d) / 'status.json'
        (Path(d) / 'status.settlements.jsonl').write_bytes(text)
        doc = status(schema=refresh.SCHEMA_V3, finalized_settlements_count=count, finalized_settlements_recent=entries[-64:],
                     settlement_log={'file': 'status.settlements.jsonl', 'entries': count, 'bytes': len(text), 'digest': ''})
        doc.pop('finalized_settlements')
        path.write_text(json.dumps(doc))
        return path, doc, entries

    def test_both_tools_read_the_log(self):
        with tempfile.TemporaryDirectory() as d:
            path, doc, entries = self.write(d, 100)
            self.assertEqual(refresh.read_status(path, 3600, time.time())['finalized_settlements'], entries)
            self.assertEqual(check.settlements_of(doc, path), entries)

    def test_a_torn_log_halts_the_refresh_and_fails_the_check(self):
        with tempfile.TemporaryDirectory() as d:
            path, doc, _ = self.write(d, 10)
            log = path.with_name('status.settlements.jsonl')
            log.write_bytes(log.read_bytes()[:-3])
            with self.assertRaises(refresh.Halt):
                refresh.read_status(path, 3600, time.time())
            with self.assertRaises(ValueError):
                check.settlements_of(doc, path)

    def test_a_log_with_another_tip_stops_both(self):
        with tempfile.TemporaryDirectory() as d:
            path, doc, _ = self.write(d, 10)
            doc['finalized_settlements_recent'][-1]['l2_hash'] = 'other'
            path.write_text(json.dumps(doc))
            with self.assertRaises(refresh.Halt):
                refresh.read_status(path, 3600, time.time())
            with self.assertRaises(ValueError):
                check.settlements_of(doc, path)


def block(n, h='h'):
    return {'number': n, 'hash': f'{h}{n}', 'state_root': f's{n}', 'withdrawal_root': 'w', 'withdrawal_count': 0}


def report(*blocks, genesis=GENESIS):
    return {'genesis': genesis, 'native_blocks': 10, 'settled': len(blocks), 'head': blocks[-1]['hash'] if blocks else None, 'blocks': list(blocks)}


class Refresh(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix='replica-refresh-'))
        self.addCleanup(shutil.rmtree, self.state, True)
        for d in ('follower/native', 'generations', 'refresh'):
            (self.state / d).mkdir(parents=True)
        self.fixture = self.state / 'fixture.json'
        os.environ['REPLICA_FAKE_PRODUCE'] = str(self.fixture)
        self.generations = self.state / 'generations'
        self.stamp = 0

    def run_once(self, st, rep=None, **fixture):
        self.fixture.write_text(json.dumps({'report': rep or report(), **fixture}))
        if st is not None:
            (self.state / 'follower/status.json').write_text(json.dumps(st))
        time.sleep(1.05)  # generation names have 1 s resolution
        args = ['--produce', str(FAKE), '--state', str(self.state)]
        real_sleep, refresh.time.sleep = refresh.time.sleep, lambda _: None
        try:
            return refresh.main(args)
        finally:
            refresh.time.sleep = real_sleep

    def current(self):
        return os.readlink(self.generations / 'current') if (self.generations / 'current').is_symlink() else None

    def test_waits_without_status(self):
        self.assertEqual(self.run_once(None), 0)
        self.assertIsNone(self.current())

    def test_waits_until_genesis_final(self):
        st = status()
        st['l2_genesis']['finalized'] = False
        self.assertEqual(self.run_once(st), 0)
        self.assertIsNone(self.current())

    def test_waits_on_stale_status(self):
        self.assertEqual(self.run_once(status(written_at_unix=int(time.time()) - 7200)), 0)
        self.assertIsNone(self.current())

    def test_wrong_network_halts(self):
        self.assertEqual(self.run_once(status(network='00' * 32)), 3)

    def test_wrong_status_genesis_halts(self):
        st = status()
        st['l2_genesis']['hash'] = 'ff' * 32
        self.assertEqual(self.run_once(st), 3)

    def test_claimed_production_finality_halts(self):
        self.assertEqual(self.run_once(status(production_finality=True)), 3)

    def test_publishes_first_generation(self):
        self.assertEqual(self.run_once(status()), 0)
        self.assertTrue((self.generations / 'current/db').is_dir())
        meta = json.loads((self.state / 'refresh/generation').read_text())
        self.assertEqual(meta['generation'], self.current())
        self.assertEqual(meta['genesis'], GENESIS)

    def test_same_tip_skips_rebuild(self):
        self.run_once(status())
        first = self.current()
        self.assertEqual(self.run_once(status(), fail=True), 0)  # a rebuild would fail
        self.assertEqual(self.current(), first)

    def test_new_tip_same_chain_keeps_generation(self):
        self.run_once(status())
        first = self.current()
        before = (self.state / 'refresh/generation').read_text()
        self.assertEqual(self.run_once(status('t2')), 0)
        self.assertEqual(self.current(), first)
        self.assertEqual((self.state / 'refresh/generation').read_text(), before)  # the RPC is not restarted
        self.assertEqual(sum(p.name.startswith('g-') for p in self.generations.iterdir()), 1)
        self.assertEqual((self.state / 'refresh/seen-tip').read_text(), 't2')

    def test_grown_chain_swaps_and_prunes(self):
        self.run_once(status())
        names = [self.current()]
        for i in range(1, 4):
            blocks = [block(n) for n in range(1, i + 1)]
            self.assertEqual(self.run_once(status(f't{i + 1}'), report(*blocks)), 0)
            self.assertNotIn(self.current(), names)
            names.append(self.current())
        kept = sorted(p.name for p in self.generations.iterdir() if p.name.startswith('g-'))
        self.assertEqual(kept, names[-2:])

    def test_finalized_settlement_mismatch_halts_and_keeps_current(self):
        self.run_once(status())
        first = self.current()
        settlement = {'l2_number': 1, 'l2_hash': 'other', 'l2_state_root': 's1'}
        self.assertEqual(self.run_once(status('t2', [settlement]), report(block(1))), 3)
        self.assertEqual(self.current(), first)
        self.assertEqual(sum(p.name.startswith('g-') for p in self.generations.iterdir()), 1)

    def test_missing_finalized_settlement_halts(self):
        self.assertEqual(self.run_once(status('t2', [{'l2_number': 1, 'l2_hash': 'h1', 'l2_state_root': 's1'}])), 3)

    def test_withdrawal_mismatch_halts(self):
        s = {'l2_number': 1, 'l2_hash': 'h1', 'l2_state_root': 's1', 'withdrawals': {'root': 'x', 'count': 1}}
        self.assertEqual(self.run_once(status('t2', [s]), report(block(1))), 3)

    def test_matching_settlement_publishes(self):
        s = {'l2_number': 1, 'l2_hash': 'h1', 'l2_state_root': 's1', 'withdrawals': {'root': 'w', 'count': 0}}
        self.assertEqual(self.run_once(status('t2', [s]), report(block(1))), 0)
        self.assertIsNotNone(self.current())

    def test_shrunk_chain_halts(self):
        self.run_once(status(), report(block(1), block(2)))
        first = self.current()
        self.assertEqual(self.run_once(status('t2'), report(block(1))), 3)
        self.assertEqual(self.current(), first)

    def test_rewritten_chain_halts(self):
        self.run_once(status(), report(block(1)))
        self.assertEqual(self.run_once(status('t2'), report(block(1, 'x'), block(2, 'x'))), 3)

    def test_wrong_rebuilt_genesis_halts(self):
        self.assertEqual(self.run_once(status(), report(genesis='ee' * 32)), 3)
        self.assertIsNone(self.current())

    def test_failed_rebuild_halts_without_partial_target(self):
        self.assertEqual(self.run_once(status(), fail=True), 3)
        self.assertEqual([p.name for p in self.generations.iterdir()], [])


class Check(unittest.TestCase):
    def serve_replica(self, **over):
        zero = {'hash': '0x' + GENESIS, 'stateRoot': '0x' + check.L2_STATE_ROOT, 'number': '0x0'}
        answers = {'eth_chainId': '0xab162', 'bloch_finality': {'l2_genesis': {'hash': GENESIS}, 'finalized_height': 0, 'l1': {}},
                   'eth_getBlockByNumber': lambda p: zero, 'eth_getLogs': []}
        answers.update(over)
        server = serve(answers)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def verify(self, rpc, st=None, l1=None):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / 's.json').write_text(json.dumps(st or status()))
        server = serve(l1 or l1_answers())
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        null = open(os.devnull, 'w')
        self.addCleanup(null.close)
        stdout, sys.stdout = sys.stdout, null
        try:
            return check.main(['verify', '--rpc', rpc, '--status', str(tmp / 's.json'), '--l1', f'http://127.0.0.1:{server.server_port}'])
        finally:
            sys.stdout = stdout

    def test_good_replica_passes(self):
        self.assertEqual(self.verify(self.serve_replica()), 0)

    def test_wrong_chain_fails(self):
        self.assertEqual(self.verify(self.serve_replica(eth_chainId='0x1')), 1)

    def test_wrong_genesis_fails(self):
        block = {'hash': '0x' + 'ee' * 32, 'stateRoot': '0x' + check.L2_STATE_ROOT, 'number': '0x0'}
        self.assertEqual(self.verify(self.serve_replica(eth_getBlockByNumber=lambda p: block)), 1)

    def test_lagging_follower_fails(self):
        self.assertEqual(self.verify(self.serve_replica(), status(native_finalized_epoch=50)), 1)

    def test_settlement_unknown_to_l1_fails(self):
        s = {'l2_number': 1, 'l2_hash': GENESIS, 'l2_state_root': 's1'}
        self.assertEqual(self.verify(self.serve_replica(), status(finalized_settlements=[s])), 1)

    def test_null_finalized_fails(self):
        zero = {'hash': '0x' + GENESIS, 'stateRoot': '0x' + check.L2_STATE_ROOT, 'number': '0x0'}
        self.assertEqual(self.verify(self.serve_replica(eth_getBlockByNumber=lambda p: None if p[0] == 'finalized' else zero)), 1)


if __name__ == '__main__':
    unittest.main(verbosity=1)
