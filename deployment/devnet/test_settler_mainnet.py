#!/usr/bin/env python3
"""Mainnet-profile tests for settler_v3.py (chain 700770) with fake native RPC, producer and prover.

Run: python3 -m unittest discover -s deployment/devnet -p 'test_*.py' -v
No network, no prover, no Docker. The native view below is the live answer of
the three mainnet RPCs on 2026-10-18 (L2 activated at epoch 5850, nothing settled).
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as base  # noqa: E402

M = s.MAINNET
URLS = ['http://80.240.16.185:8080', 'http://199.247.22.8:8080', 'http://45.77.67.251:8080']
SOURCE_BLOCK = '618c9b80cebda5b5bda0b0c7d79e19dae8dc24e773aa94a2c135eb805ff0dc9f'
SOURCE_COMMITMENT = 'ce03aaebb03896b231c4605ebfb8eaf7b8e76d0df15eae8e9553fee42e5f7668'
INBOX_ROOT = 'aeaaac645079e68181cbc33803e6bc21d565f016d3fecdb0845d0502e59b0ecd'
REQUEST = ''.join(x + '\n' for x in (M['network'], M['genesis'], SOURCE_BLOCK, '187200', '1', SOURCE_COMMITMENT,
                                     INBOX_ROOT))
LIVE_VIEW = {
    'asynchronous': True, 'native_height': 2796, 'network': M['network'], 'genesis': M['genesis'],
    'chain_id': 700770,
    'source': {'block': SOURCE_BLOCK, 'slot': 187200, 'height': 1, 'commitment': SOURCE_COMMITMENT,
               'inbox_root': INBOX_ROOT, 'inbox_count': 0, 'consumed_start': 0, 'consumed_end': 0, 'pending': [],
               'request': REQUEST},
    'profile': {'activated': True, 'deposits': True, 'user_transactions': True},
    'inbox': {'count': 0, 'consumed': 0, 'escrow_sat': '0'},
    'data_availability': [],
    'withdrawals': {'root': s.EMPTY_WITHDRAWAL_ROOT.hex(), 'count': 0, 'delay_blocks': 64,
                    'large_claim_sat': '10000000000', 'large_delay_blocks': 2880,
                    'attestor_set': M['attestor_set'], 'escrow_conserved': True},
    'accepted': None,
}


def mainnet_statement(**overrides):
    """A V3 statement for L2 block 1 of chain 700770 anchored to the live source."""
    v = bytearray(s.VALUES_BYTES)
    v[:s.T] = s.TAG
    put = lambda offset, data: v.__setitem__(slice(s.T + offset, s.T + offset + len(data)), data)  # noqa: E731
    put(0, bytes.fromhex(M['network']))
    put(32, bytes.fromhex(M['genesis']))
    put(64, s.mainnet_l2_config()[:160])
    put(256, M['chain_id'].to_bytes(8, 'big'))
    put(264, (1).to_bytes(8, 'big'))
    put(336, b'\x51' * 32)
    put(400, bytes.fromhex(SOURCE_BLOCK))
    put(432, (187200).to_bytes(8, 'big'))
    put(440, (1).to_bytes(8, 'big'))
    put(448, bytes.fromhex(SOURCE_COMMITMENT))
    put(480, bytes.fromhex(INBOX_ROOT))
    put(s.DEPOSITS_HASH, s.deposits_hash([]))
    put(s.TRANSACTIONS_ROOT, b'\x61' * 32)
    put(s.RECEIPTS_ROOT, b'\x62' * 32)
    put(s.WITHDRAWAL_ROOT, s.EMPTY_WITHDRAWAL_ROOT)
    for offset, data in overrides.items():
        put(int(offset), data)
    return bytes(v)


class MainnetFake(base.Fake):
    """The live mainnet view; sendrawtransaction is scripted per call."""

    def __init__(self, root, values):
        super().__init__(root, values)
        self.live = copy.deepcopy(LIVE_VIEW)
        self.answers = []  # per sendrawtransaction call: dict response, Exception, or None = accept
        self.height, self.advancing = 154_810, True
        self.include = True
        self.genesis_hash = M['l2_genesis']

    def run(self, argv, **kwargs):
        if Path(argv[0]).name == 'produce' and argv[1] in ('init', 'head', 'export'):
            self.calls.append([str(a) for a in argv])
            if argv[1] == 'export':
                Path(argv[argv.index('--out') + 1]).write_bytes(b'artifact')
                answer = {'number': self.head, 'hash': '51' * 32, 'anchor': SOURCE_BLOCK, 'bytes': 8}
            else:
                answer = {'number': self.head, 'hash': self.genesis_hash if self.head == 0 else '51' * 32}
            return types.SimpleNamespace(returncode=0, stderr='', stdout=json.dumps(answer))
        return super().run(argv, **kwargs)

    def view(self):
        return {**copy.deepcopy(self.live), 'accepted': self.accepted}

    def rpc(self, port, method, params=()):
        if method == 'getl2settlement':
            return self.view()
        if method == 'getchaininfo':
            if self.advancing:
                self.height += 1
            return {'height': self.height, 'next_base_fee_millisat_per_gas': '10'}
        if method == 'sendrawtransaction':
            tx = bytes.fromhex(params[0])
            self.sent.append(tx)
            answer = self.answers.pop(0) if self.answers else None
            if isinstance(answer, Exception):
                raise answer
            if self.include and answer is None:
                self.accepted = {'statement': self.values.hex(), 'commitment': '99' * 32}
            return answer or {'status': 'accepted', 'tx_hash': '00' * 32}
        raise AssertionError(method)


def refusal(code, message):
    return s.RpcError(f"sendrawtransaction: {{'code': {code}, 'message': '{message}'}}")


class MainnetSettlerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'bloch-evm-sp1-settlement-v3').write_bytes(b'prover')
        (self.root / 'settlement_v3_mainnet').write_bytes(b'guest')
        (self.root / 'l2-config.bin').write_bytes(s.mainnet_l2_config())
        (self.root / 'home').mkdir()
        self.guest_pin = mock.patch.dict(s.MAINNET, guest_sha256=s.digest(self.root / 'settlement_v3_mainnet'))
        self.guest_pin.start()

    def tearDown(self):
        self.guest_pin.stop()
        self.tmp.cleanup()

    def config(self, **extra):
        c = {'network_kind': 'mainnet', 'network': M['network'], 'l2_genesis': M['l2_genesis'], 'rpc_urls': URLS,
             'produce': str(self.root / 'produce'), 'l2_db': str(self.root / 'db'),
             'workdir': str(self.root / 'work'), 'home': str(self.root / 'home'), 'gnark_image': 'image',
             'prover_threads': 6, 'acceptance_timeout_seconds': 600, 'idle_seconds': 30,
             'max_consecutive_failures': 5, 'timestamp_rule': s.MAINNET_TIMESTAMP_RULE}
        for key, name in (('prover', 'bloch-evm-sp1-settlement-v3'), ('guest', 'settlement_v3_mainnet'),
                          ('l2_config', 'l2-config.bin')):
            c[key] = str(self.root / name)
            c[key + '_sha256'] = s.digest(self.root / name)
        c.update(extra)
        return c

    def settler(self, fake, **extra):
        clock = iter(range(0, 1_000_000, 5))
        return s.Settler(self.config(**extra), rpc=fake.rpc, run=fake.run, sleep=lambda _: None,
                         clock=lambda: next(clock))

    @staticmethod
    def events(recorder):
        return [c.args[0] for c in recorder.call_args_list]

    # ---- pins ----
    def test_l2_config_is_derived_from_the_pinned_program(self):
        config = s.mainnet_l2_config()
        self.assertEqual(len(config), 264)
        self.assertEqual(hashlib.sha256(config).hexdigest(), s.MAINNET_L2_CONFIG_SHA256)
        self.assertEqual(config[160:192].hex(), '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d')
        self.assertEqual(int.from_bytes(config[192:200], 'little'), 700770)
        self.assertEqual(config[:32].hex(), M['l2_domain'])
        self.assertEqual(s.MAINNET_TIMESTAMP_RULE, '1:1786656679:30000')
        self.assertEqual(s.MAINNET['guest_sha256'], s.digest(self.root / 'settlement_v3_mainnet'))  # patched here
        self.guest_pin.stop()
        self.assertEqual(s.MAINNET['guest_sha256'], '203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473')
        self.guest_pin.start()

    def test_every_mainnet_pin_is_enforced(self):
        fake = MainnetFake(self.root, mainnet_statement())
        self.settler(fake)  # the correct configuration loads
        (self.root / 'wrong.bin').write_bytes(base.CONFIG_BYTES + bytes(72))
        (self.root / 'settlement_v3').write_bytes(b'guest')
        cases = {
            'Genesis-4 admission domain': {'network': 'aa' * 32},
            'pinned L2 genesis': {'l2_genesis': 'f0' * 32},
            'proof policy V3': {'l2_config': str(self.root / 'wrong.bin'),
                                'l2_config_sha256': s.digest(self.root / 'wrong.bin')},
            'settlement_v3_mainnet': {'guest': str(self.root / 'settlement_v3'),
                                      'guest_sha256': s.digest(self.root / 'settlement_v3')},
            'timestamp_rule must be': {'timestamp_rule': '228:1791841117:2000'},
            'rpc_urls on independent hosts': {'rpc_urls': None},
            'at least three rpc_urls': {'rpc_urls': URLS[:2]},
            'distinct hosts': {'rpc_urls': URLS[:2] + ['http://80.240.16.185:9090']},
            'http\\(s\\) URLs': {'rpc_urls': URLS[:2] + ['ftp://10.0.0.1']},
            'network_kind must be': {'network_kind': 'production'},
        }
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                config = self.config(**change)
                if change.get('rpc_urls', 0) is None:
                    del config['rpc_urls']
                    config['rpc_ports'] = [1, 2, 3]
                with self.assertRaisesRegex(s.Halt, reason):
                    s.Settler(config, rpc=fake.rpc, run=fake.run)

    def test_live_identity_is_checked_by_quorum(self):
        fake = MainnetFake(self.root, mainnet_statement())
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.settler(fake).check_identity())
        for path, value, reason in ((('withdrawals', 'attestor_set'), '00' * 32, 'differs from the pins'),
                                    (('profile', 'activated'), False, 'differs from the pins'),
                                    (('asynchronous',), False, 'differs from the pins'),
                                    (('genesis',), '00' * 32, 'differs from the pins'),
                                    (('chain_id',), 700771, 'identity differs from the configuration')):
            with self.subTest(path=path):
                fake = MainnetFake(self.root, mainnet_statement())
                target = fake.live
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, reason):
                    self.settler(fake).cycle()
                self.assertEqual((fake.sent, fake.calls), ([], []))
        fake = MainnetFake(self.root, mainnet_statement())
        fake.live['profile']['user_transactions'] = False
        (self.root / 'txpool').mkdir()
        da = {'signer': str(self.root / 'prover'), 'genesis': 'g', 'funding_pubkey': str(self.root / 'pk'),
              'keystore_dir': 'k', 'passphrase_file': 'p'}
        (self.root / 'prover').write_bytes(b'signer')
        (self.root / 'pk').write_text('5a' * 3749)
        da['signer_sha256'] = s.digest(self.root / 'prover')
        settler = self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'txpool'), da=da)
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'does not admit user transactions'):
            settler.cycle()

    def test_rpc_urls_reach_the_endpoints_and_check_rpc_is_read_only(self):
        self.assertEqual(s.endpoint_url(URLS[0]), URLS[0])
        self.assertEqual(s.endpoint_url(18940), 'http://127.0.0.1:18940')
        self.assertEqual(s.rpc_endpoints({'rpc_urls': URLS}), URLS)
        with self.assertRaisesRegex(s.Halt, 'not both'):
            s.rpc_endpoints({'rpc_urls': URLS, 'rpc_ports': [1]})
        fake = MainnetFake(self.root, mainnet_statement())
        calls = []
        rpc = lambda url, method, params=(): calls.append((url, method)) or fake.rpc(url, method, params)  # noqa
        with mock.patch.object(s, 'log'):
            self.assertEqual(s.check_rpc(self.config(), rpc=rpc, sleep=lambda _: None), 0)
        self.assertEqual({m for _, m in calls}, {'getl2settlement'})
        self.assertEqual({u for u, _ in calls}, set(URLS))

    # ---- the settlement ----
    def test_mainnet_cycle_uses_the_mainnet_rules_program_and_policy(self):
        fake = MainnetFake(self.root, mainnet_statement())
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.settler(fake).cycle())
        produce = [c for c in fake.calls if Path(c[0]).name == 'produce']
        for call in produce:
            self.assertEqual(call[-6:], list(s.MAINNET_PRODUCE_ARGS), call)
        extend = next(c for c in produce if c[1] == 'extend')
        self.assertEqual(extend[extend.index('--timestamp-rule') + 1], '1:1786656679:30000')
        self.assertEqual(extend[extend.index('--anchor-slot') + 1], '187200')
        self.assertEqual(extend[extend.index('--parent') + 1], M['l2_genesis'])
        self.assertEqual(extend[extend.index('--anchor') + 1], SOURCE_BLOCK)
        provers = [c for c in fake.calls if 'settlement-v3' in Path(c[0]).name]
        self.assertEqual([c[1:3] for c in provers], [['--mainnet', 'execute'], ['--mainnet', 'prove-groth16'],
                                                     ['--mainnet', 'verify-groth16']])
        self.assertTrue(all(c[4].endswith('settlement_v3_mainnet') for c in provers))
        [tx] = base.broadcasts(fake.sent)
        self.assertEqual((len(tx), tx[0], tx[1:33].hex()), (1155, 0x13, M['proof_policy']))
        request = next((self.root / 'work').glob('*/native-request.txt')).read_text()
        self.assertEqual(request, REQUEST + '0' * 64 + '\n0\n0\n0\n')

    def test_duplicate_answer_waits_for_acceptance(self):
        # The node already holds these bytes (or included them recently): not an error.
        fake = MainnetFake(self.root, mainnet_statement())
        fake.answers = [{'accepted': True, 'status': 'duplicate', 'tx_hash': '00' * 32}]
        fake.include = False
        settler = self.settler(fake)
        original = fake.view

        def later():
            if fake.sent:
                fake.accepted = {'statement': fake.values.hex(), 'commitment': '99' * 32}
            return original()
        fake.view = later
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(settler.cycle())
        self.assertIn('submitted-duplicate', self.events(logged))
        self.assertIn('accepted', self.events(logged))

    def test_pending_proof_refusal_waits_and_rebroadcasts_the_same_bytes(self):
        fake = MainnetFake(self.root, mainnet_statement())
        pending = refusal(s.TX_REFUSED, 'one L2 proof is already pending — this transaction cannot be admitted')
        fake.answers = [pending] * 6 + [None]
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler(fake, resubmit_seconds=30).cycle())
        self.assertEqual(len(set(fake.sent)), 1, 'always the same signed bytes')
        self.assertEqual(len(fake.sent), 9, 'two refused rounds on all three endpoints, then all three take it (M2)')
        self.assertEqual(self.events(logged).count('submit-refused'), 2)
        self.assertNotIn('halt', self.events(logged))

    def test_terminal_refusal_halts_unless_the_view_explains_it(self):
        invalid = refusal(s.TX_REFUSED, 'L2 settlement policy, source, successor or proof failed')
        fake = MainnetFake(self.root, mainnet_statement())
        fake.answers = [invalid] * 3
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'refuse the settlement of L2 block 1'):
            self.settler(fake).cycle()
        # Refused because it was already included: the next view shows it accepted.
        self.tearDown(), self.setUp()
        fake = MainnetFake(self.root, mainnet_statement())
        fake.answers = [invalid] * 3
        reads = fake.view

        def included():
            if fake.sent:
                fake.accepted = {'statement': fake.values.hex(), 'commitment': '99' * 32}
            return reads()
        fake.view = included
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.settler(fake).cycle())

    def test_refusal_classification(self):
        cases = [([refusal(-32008, 'L2 settlement policy, source, successor or proof failed')] * 3, 'terminal'),
                 ([refusal(-32008, 'one L2 proof is already pending')] * 3, 'retry'),
                 ([refusal(-32009, 'barred until slot 9')] * 3, 'retry'),
                 ([refusal(-32003, 'mempool is at capacity')] * 3, 'retry'),
                 ([refusal(-32008, 'x'), refusal(-32008, 'x'), ConnectionRefusedError(111, 'refused')], 'retry')]
        for errors, kind in cases:
            refused = s.SubmitRefused([(i, f'{type(e).__name__}: {e}') for i, e in enumerate(errors)])
            self.assertEqual(refused.kind(), kind, errors)

    def test_stalled_l1_times_out_without_reproving_and_reuses_the_bytes(self):
        # devnet4 block 231: the L1 halted, the worker looped on acceptance-timeout/"duplicate".
        fake = MainnetFake(self.root, mainnet_statement())
        fake.include, fake.advancing = False, False
        fake.answers = [None] + [{'status': 'duplicate'}] * 50
        settler = self.settler(fake, acceptance_timeout_seconds=120, resubmit_seconds=60)
        with mock.patch.object(s, 'log') as logged:
            self.assertFalse(settler.cycle())
            self.assertFalse(settler.cycle())
        events = self.events(logged)
        self.assertEqual(events.count('acceptance-timeout'), 2)
        self.assertEqual(events.count('l1-not-advancing'), 2)
        self.assertEqual(len(set(fake.sent)), 1, 'the same bytes, never a second proof')
        proves = [c for c in fake.calls if 'settlement-v3' in Path(c[0]).name and 'prove-groth16' in c]
        self.assertEqual(len(proves), 1)
        record = json.loads(next((self.root / 'work').glob('*/submitted.json')).read_text())
        self.assertEqual(record['tx_sha256'], hashlib.sha256(fake.sent[0]).hexdigest())
        self.assertGreater(record['attempts'], 2)
        # The L1 resumes: the reused bytes are accepted.
        fake.include, fake.advancing, fake.answers = True, True, []
        with mock.patch.object(s, 'log'):
            self.assertTrue(settler.cycle())

    def test_a_foreign_statement_for_the_same_block_halts(self):
        fake = MainnetFake(self.root, mainnet_statement())
        fake.include = False
        other = mainnet_statement(**{'336': b'\x52' * 32})
        fake.answers = [{'status': 'accepted'}]
        reads = fake.view

        def foreign():
            if fake.sent:
                fake.accepted = {'statement': other.hex(), 'commitment': '98' * 32}
            return reads()
        fake.view = foreign
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'another settler'):
            self.settler(fake).cycle()

    # ---- dry run ----
    def test_dry_run_execute_only_never_broadcasts(self):
        fake = MainnetFake(self.root, mainnet_statement())
        calls = []
        rpc = lambda url, method, params=(): calls.append(method) or fake.rpc(url, method, params)  # noqa: E731
        out = self.root / 'dry'
        with mock.patch.object(s, 'log'):
            code = s.dry_run(self.config(), out=str(out), rpc=rpc, run=fake.run, sleep=lambda _: None)
        report = json.loads((out / 'dry-run-report.json').read_text())
        self.assertEqual(code, 0, report)
        self.assertEqual((report['ok'], report['broadcast'], report['chain_id']), (True, False, 700770))
        self.assertEqual(report['native']['source_height'], 1)
        self.assertEqual(report['l2_block']['number'], 1)
        self.assertNotIn('sendrawtransaction', calls)
        self.assertEqual(fake.sent, [])
        provers = [c[1:3] for c in fake.calls if 'settlement-v3' in Path(c[0]).name]
        self.assertEqual(provers, [['--mainnet', 'execute']])
        self.assertFalse((self.root / 'work').exists() or (self.root / 'db').exists(), 'live state untouched')

    def test_dry_run_with_proof_builds_the_transaction_file(self):
        fake = MainnetFake(self.root, mainnet_statement())
        out = self.root / 'dry'
        with mock.patch.object(s, 'log'):
            code = s.dry_run(self.config(), prove=True, out=str(out), rpc=fake.rpc, run=fake.run,
                             sleep=lambda _: None)
        report = json.loads((out / 'dry-run-report.json').read_text())
        self.assertEqual(code, 0, report)
        tx = bytes.fromhex((out / 'settlement-tx.hex').read_text().strip())
        self.assertEqual(report['transaction']['sha256'], hashlib.sha256(tx).hexdigest())
        self.assertEqual((len(tx), tx[0], report['transaction']['proof_policy']), (1155, 0x13, M['proof_policy']))
        self.assertEqual(report['settlement_fee_sat'], 0)
        self.assertEqual(fake.sent, [])

    def test_dry_run_refuses_a_wrong_genesis_and_a_settled_chain_without_its_database(self):
        fake = MainnetFake(self.root, mainnet_statement())
        fake.genesis_hash = 'f0' * 32
        with mock.patch.object(s, 'log'):
            code = s.dry_run(self.config(), out=str(self.root / 'd1'), rpc=fake.rpc, run=fake.run,
                             sleep=lambda _: None)
        self.assertEqual(code, 2)
        self.assertIn('L2 genesis', json.loads((self.root / 'd1/dry-run-report.json').read_text())['reason'])
        fake.accepted = {'statement': mainnet_statement().hex(), 'commitment': '99' * 32}
        with mock.patch.object(s, 'log'):
            code = s.dry_run(self.config(), out=str(self.root / 'd2'), rpc=fake.rpc, run=fake.run,
                             sleep=lambda _: None)
        self.assertEqual(code, 2)
        self.assertIn('copy of the settled L2 database',
                      json.loads((self.root / 'd2/dry-run-report.json').read_text())['reason'])

    def test_remote_prover_passes_the_mainnet_flag(self):
        import struct
        import subprocess
        import remote_prover as rp
        prover = self.root / 'fake-settlement-v3'
        prover.write_text('#!/bin/sh\n[ "$1 $2 $3" = "--mainnet prove-groth16 native-artifact" ] || exit 9\n'
                          'cat "$BLOCH_NATIVE_L2_REQUEST" "$BLOCH_NATIVE_L2_ARTIFACT" > "$5"\n')
        prover.chmod(0o755)
        (self.root / 'pwork').mkdir()
        guest = self.root / 'settlement_v3_mainnet'
        config = {'prover': str(prover), 'prover_sha256': s.digest(prover), 'guest': str(guest),
                  'guest_sha256': s.digest(guest), 'workdir': str(self.root / 'pwork'), 'mainnet': True,
                  'home': str(self.root / 'home'), 'prover_threads': 4, 'gnark_image': 'image'}
        (self.root / 'prover.json').write_text(json.dumps(config))
        job = rp.MAGIC + struct.pack('>I', 4) + b'req\n' + struct.pack('>Q', 3) + b'art'
        done = subprocess.run([sys.executable, str(HERE / 'remote_prover.py')], input=job, capture_output=True,
                              env={'PATH': '/usr/bin:/bin', 'BLOCH_REMOTE_PROVER_CONFIG': str(self.root / 'prover.json'),
                                   'SSH_ORIGINAL_COMMAND': 'prove'})
        self.assertEqual((done.returncode, done.stdout), (0, b'req\nart'), done.stderr)

    # ---- fees ----
    def test_da_fee_estimate_follows_the_native_fee_market(self):
        # tx_bytes = 8471 + 36 * inputs + payload; gas = 5000 + 16 * tx_bytes + 72748 * inputs; ceil(gas * fee / 1000).
        self.assertEqual(s.da_fee_sat(0), 2139)
        self.assertEqual(s.da_fee_sat(s.DA_MAX_PAYLOAD_BYTES), 20489)
        self.assertEqual(s.da_fee_sat(s.DA_MAX_PAYLOAD_BYTES, base_fee_millisat_per_gas=1000), 2_048_868)
        self.assertEqual(s.da_fee_sat(100, inputs=2), -(-(5000 + 16 * (8471 + 72 + 100) + 2 * 72748) * 10 // 1000))


if __name__ == '__main__':
    unittest.main()
