#!/usr/bin/env python3
"""Mainnet RC tests for settler_v3.py: the mainnet-rehearsal profile and producer-failure resilience.

Run: python3 -m unittest discover -s deployment/devnet -p 'test_*.py' -v
No network, no prover, no Docker.
"""
import copy
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_mainnet as mn  # noqa: E402
import test_settler_v3 as base  # noqa: E402

M = s.MAINNET
PRIVATE_NETWORK, PRIVATE_GENESIS = '7a' * 32, '7b' * 32
REHEARSAL_ARGS = ['--rules', 'mainnet', '--domain', M['l2_domain'], '--genesis-time', '1786656679']


class RehearsalFake(mn.MainnetFake):
    """The mainnet program path on a private network (identities 0..1 are the private network's)."""

    def __init__(self, root, values):
        super().__init__(root, values)
        self.live['network'], self.live['genesis'] = PRIVATE_NETWORK, PRIVATE_GENESIS
        request = self.live['source']['request'].splitlines()
        request[0], request[1] = PRIVATE_NETWORK, PRIVATE_GENESIS
        self.live['source']['request'] = ''.join(x + '\n' for x in request)
        self.live['withdrawals']['attestor_set'] = '00' * 32  # placeholder set of a qualification build


def rehearsal_statement():
    return mn.mainnet_statement(**{'0': bytes.fromhex(PRIVATE_NETWORK), '32': bytes.fromhex(PRIVATE_GENESIS)})


class RehearsalProfileTest(unittest.TestCase):
    setUp, tearDown, config = mn.MainnetSettlerTest.setUp, mn.MainnetSettlerTest.tearDown, mn.MainnetSettlerTest.config

    def rehearsal_config(self, **extra):
        c = self.config(network_kind='mainnet-rehearsal', network=PRIVATE_NETWORK, rpc_ports=[1, 2, 3],
                        timestamp_rule='1:1791841117:2000', prover_path='/opt/shim:/usr/bin:/bin')
        del c['rpc_urls']
        c.update(extra)
        return c

    def rehearsal(self, fake, **extra):
        clock = iter(range(0, 1_000_000, 5))
        return s.Settler(self.rehearsal_config(**extra), rpc=fake.rpc, run=fake.run, sleep=lambda _: None,
                         clock=lambda: next(clock))

    def test_rehearsal_runs_the_mainnet_program_path_on_the_private_network(self):
        fake = RehearsalFake(self.root, rehearsal_statement())
        # The 2026-10-18 driver also wrote chain_id and network_args: accepted when they match.
        settler = self.rehearsal(fake, chain_id=700770, network_args=REHEARSAL_ARGS)
        self.assertEqual((settler.chain_id, settler.mainnet, settler.rehearsal), (700770, False, True))
        with mock.patch.object(s, 'log'):
            self.assertTrue(settler.cycle())
        produce = [c for c in fake.calls if Path(c[0]).name == 'produce']
        self.assertTrue(all(c[-6:] == REHEARSAL_ARGS for c in produce))
        extend = next(c for c in produce if c[1] == 'extend')
        self.assertEqual(extend[extend.index('--timestamp-rule') + 1], '1:1791841117:2000')
        provers = [c for c in fake.calls if 'settlement-v3' in Path(c[0]).name]
        self.assertTrue(provers and all(c[1] == '--mainnet' for c in provers))
        [tx] = base.broadcasts(fake.sent)
        self.assertEqual((len(tx), tx[0], tx[1:33].hex()), (1155, 0x13, M['proof_policy']))

    def test_rehearsal_prover_path_reaches_the_prover_environment(self):
        fake = RehearsalFake(self.root, rehearsal_statement())
        seen = []
        inner = fake.run

        def run(argv, **kwargs):
            if 'settlement-v3' in Path(argv[0]).name:
                seen.append(kwargs['env']['PATH'])
            return inner(argv, **kwargs)
        fake.run = run
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.rehearsal(fake).cycle())
        self.assertEqual(set(seen), {'/opt/shim:/usr/bin:/bin'})

    def test_rehearsal_pins_and_overrides_are_enforced(self):
        fake = RehearsalFake(self.root, rehearsal_statement())
        (self.root / 'wrong.bin').write_bytes(base.CONFIG_BYTES + bytes(72))
        (self.root / 'settlement_v3_other').write_bytes(b'other guest')
        cases = {
            'never runs on the Genesis-4 network': {'network': M['network']},
            'pinned L2 genesis': {'l2_genesis': 'f0' * 32},
            'proof policy V3': {'l2_config': str(self.root / 'wrong.bin'),
                                'l2_config_sha256': s.digest(self.root / 'wrong.bin')},
            'settlement_v3_mainnet': {'guest': str(self.root / 'settlement_v3_other'),
                                      'guest_sha256': s.digest(self.root / 'settlement_v3_other')},
            'chain_id 700771 does not match': {'chain_id': 700771},
            'network_args do not match': {'network_args': ['--rules', 'v3']},
        }
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                config = self.rehearsal_config(**change)
                with self.assertRaisesRegex(s.Halt, reason):
                    s.Settler(config, rpc=fake.rpc, run=fake.run)
        # A devnet configuration may not borrow the mainnet producer arguments either.
        with self.assertRaisesRegex(s.Halt, 'network_args do not match'):
            s.Settler(self.config(network_kind='devnet', network_args=REHEARSAL_ARGS, rpc_urls=None,
                                  rpc_ports=[1, 2, 3]), rpc=fake.rpc, run=fake.run)

    def test_rehearsal_requires_the_asynchronous_profile(self):
        fake = RehearsalFake(self.root, rehearsal_statement())
        fake.live['asynchronous'] = False
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'asynchronous mainnet profile'):
            self.rehearsal(fake).cycle()


class ProducerFailureTest(unittest.TestCase):
    """Security review 2026-10-18 finding 2: the spool is untrusted; a producer refusal never halts."""
    T = base.SettlerV3Test
    setUp, tearDown, config, settler = T.setUp, T.tearDown, T.config, T.settler
    da_config, user_settler = T.da_config, T.user_settler

    def failing_extend(self, fake, fail_with_txs=True, fail_without=False):
        inner = fake.run

        def run(argv, **kwargs):
            if Path(argv[0]).name == 'produce' and argv[1] == 'extend':
                if ('--txs' in argv and fail_with_txs) or ('--txs' not in argv and fail_without):
                    fake.calls.append([str(a) for a in argv])
                    return types.SimpleNamespace(returncode=1, stdout='', stderr='--txs holds more than 16384 entries')
            return inner(argv, **kwargs)
        fake.run = run

    def test_producer_refusal_is_retryable_not_a_halt(self):
        fake = base.Fake(self.root, base.statement())
        self.failing_extend(fake, fail_with_txs=False, fail_without=True)
        settler = self.settler(fake)
        with self.assertRaises(s.ProducerError) as raised:
            settler.cycle()
        self.assertNotIsInstance(raised.exception, s.Halt)
        self.assertIn('16384', str(raised.exception))

    def test_a_poisoned_spool_falls_back_to_a_deposit_only_block(self):
        fake = base.Fake(self.root, base.statement())
        self.failing_extend(fake)
        settler = self.user_settler(fake)
        with mock.patch.object(s, 'log') as log:
            self.assertTrue(settler.cycle())
        extends = [c for c in fake.calls if Path(c[0]).name == 'produce' and c[1] == 'extend']
        self.assertEqual(['--txs' in c for c in extends], [True, False])
        self.assertIn('--deposits', extends[1])
        self.assertIn('producer-refused-spool', [c.args[0] for c in log.call_args_list])
        self.assertEqual([tx[0] for tx in base.broadcasts(fake.sent)], [s.ASYNC_SETTLEMENT_TAG])

    def test_no_fallback_when_the_block_was_committed_before_the_failure(self):
        fake = base.Fake(self.root, base.statement())
        inner = fake.run

        def run(argv, **kwargs):
            if Path(argv[0]).name == 'produce' and argv[1] == 'extend':
                inner(argv, **kwargs)  # committed, then failed (e.g. while pruning the spool)
                return types.SimpleNamespace(returncode=1, stdout='', stderr='prune: No such file')
            return inner(argv, **kwargs)
        fake.run = run
        settler = self.user_settler(fake)
        with mock.patch.object(s, 'log'), self.assertRaises(s.ProducerError):
            settler.cycle()
        self.assertEqual(sum(1 for c in fake.calls if Path(c[0]).name == 'produce' and c[1] == 'extend'), 1)
        # The next cycle reuses the committed block instead of extending again.
        with mock.patch.object(s, 'log') as log:
            self.assertTrue(settler.cycle())
        self.assertIn('l2-block-reused', [c.args[0] for c in log.call_args_list])

    def test_main_loop_retries_producer_failures_and_exits_1_not_3(self):
        fake = base.Fake(self.root, base.statement())
        self.failing_extend(fake, fail_with_txs=False, fail_without=True)
        config = self.config(max_consecutive_failures=3)
        settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None)
        sleeps = []
        with mock.patch.object(s, 'CONFIG', types.SimpleNamespace(read_text=lambda: s.json.dumps(config))), \
                mock.patch.object(s, 'Settler', lambda c: settler), mock.patch.object(s.sys, 'argv', ['settler']), \
                mock.patch.object(s.time, 'sleep', sleeps.append), mock.patch.object(s, 'log') as log, \
                self.assertRaises(SystemExit) as exited:
            s.main()
        self.assertEqual(exited.exception.code, 1)  # Restart=on-failure restarts it; 3 would wait for an operator
        retries = [c for c in log.call_args_list if c.args[0] == 'retry']
        self.assertEqual(len(retries), 3)
        self.assertTrue(all('producer refused extend' in c.kwargs['reason'] for c in retries))
        self.assertNotIn('halt', [c.args[0] for c in log.call_args_list])
        self.assertEqual(sleeps, [15, 30])

    def test_mainnet_unit_restarts_without_a_start_limit(self):
        text = (HERE.parent / 'mainnet/install-settler-mainnet.py').read_text()
        self.assertIn('Restart=on-failure', text)
        self.assertIn('StartLimitIntervalSec=0', text)
        self.assertIn('RestartPreventExitStatus=3', text)


if __name__ == '__main__':
    unittest.main()
