#!/usr/bin/env python3
"""Program swap tests for settler_v3.py: the settlement stream follows the program L1 reports.

Run: python3 -m unittest discover -s deployment/devnet -p 'test_*.py' -v
No network, no prover, no Docker.
"""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_mainnet as mn  # noqa: E402

M = s.MAINNET
N = s.MAINNET_NEXT
BASE_REPORT = {'configuration': M['configuration'], 'elf_keccak': M['elf_keccak'], 'vkey_koalabear': M['vkey_koalabear'],
               'vkey_bn254': M['vkey_bn254'], 'proof_policy': M['proof_policy']}
NEXT_REPORT = {'configuration': N['configuration'], 'elf_keccak': N['elf_keccak'], 'vkey_koalabear': N['vkey_koalabear'],
               'vkey_bn254': N['vkey_bn254'], 'proof_policy': M['proof_policy']}


def next_statement():
    return mn.mainnet_statement(**{'64': s.mainnet_l2_config(s.MAINNET_NEXT)[:160]})


class SwapFake(mn.MainnetFake):
    """A producer that tracks the rules of its head and a program that moves when told to."""

    def __init__(self, root, values):
        super().__init__(root, values)
        self.live['program'] = dict(BASE_REPORT)
        self.head_rules, self.head_hash = 'base', M['l2_genesis']
        self.base_values, self.next_values = values, next_statement()
        self.rewound, self.swap_during_prove = [], False

    def swap(self):
        self.live['program'] = dict(NEXT_REPORT)
        self.values = self.next_values

    def run(self, argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'produce' and argv[1] == 'head':
            self.calls.append([str(a) for a in argv])
            return types.SimpleNamespace(returncode=0, stderr='', stdout=json.dumps(
                {'number': self.head, 'hash': self.head_hash if self.head else M['l2_genesis'], 'rules': self.head_rules}))
        if name == 'produce' and argv[1] == 'rewind':
            self.calls.append([str(a) for a in argv])
            self.rewound.append(int(argv[argv.index('--number') + 1]))
            self.head -= 1
            self.head_rules = 'base'
            return types.SimpleNamespace(returncode=0, stderr='', stdout=json.dumps({'number': self.head, 'respooled': 2}))
        if name == 'produce' and argv[1] == 'extend':
            rules = argv[argv.index('--rule-set') + 1]
            result = super().run(argv, **kwargs)
            self.head_rules, self.head_hash = rules, '51' * 32
            document = json.loads(result.stdout)
            document['rules'] = rules
            result.stdout = json.dumps(document)
            return result
        result = super().run(argv, **kwargs)
        if self.swap_during_prove and 'prove-groth16' in [str(a) for a in argv]:
            self.swap_during_prove = False
            self.swap()
        return result


class ProgramSwapTest(unittest.TestCase):
    setUp, tearDown, base_config = mn.MainnetSettlerTest.setUp, mn.MainnetSettlerTest.tearDown, mn.MainnetSettlerTest.config

    def config(self, **extra):
        (self.root / 'next-settlement-v3').write_bytes(b'next prover')
        (self.root / 'settlement_v3_mainnet.next').write_bytes(b'next guest')
        (self.root / 'l2-config.next.bin').write_bytes(s.mainnet_l2_config(s.MAINNET_NEXT))
        next_program = {'prover': str(self.root / 'next-settlement-v3'), 'guest': str(self.root / 'settlement_v3_mainnet.next'),
                        'l2_config': str(self.root / 'l2-config.next.bin'), 'guest_sha256': s.digest(self.root / 'settlement_v3_mainnet.next')}
        for key in ('prover', 'l2_config'):
            next_program[key + '_sha256'] = s.digest(next_program[key])
        return self.base_config(next_program=next_program, **extra)

    def settler(self, fake, **extra):
        clock = iter(range(0, 1_000_000, 5))
        config = self.config(**extra)
        self.next_pin = mock.patch.dict(s.MAINNET_NEXT, guest_sha256=config['next_program']['guest_sha256'])
        self.next_pin.start()
        self.addCleanup(self.next_pin.stop)
        return s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))

    def prover_calls(self, fake):
        return [c for c in fake.calls if 'settlement-v3' in Path(c[0]).name]

    def test_before_the_swap_nothing_changes_but_the_rule_set_argument(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.settler(fake).cycle())
        extend = next(c for c in fake.calls if c[1] == 'extend')
        self.assertEqual(extend[extend.index('--rule-set') + 1], 'base')
        for call in self.prover_calls(fake):
            self.assertEqual(Path(call[0]).name, 'bloch-evm-sp1-settlement-v3')
            self.assertIn(str(self.root / 'settlement_v3_mainnet'), call)
        self.assertEqual(fake.rewound, [])

    def test_without_next_program_the_worker_passes_no_rule_set(self):
        fake = mn.MainnetFake(self.root, mn.mainnet_statement())
        clock = iter(range(0, 1_000_000, 5))
        settler = s.Settler(self.base_config(), rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
        with mock.patch.object(s, 'log'):
            self.assertTrue(settler.cycle())
        extend = next(c for c in fake.calls if c[1] == 'extend')
        self.assertNotIn('--rule-set', extend)

    def test_a_block_in_flight_at_the_swap_is_rewound_rebuilt_and_settled_under_the_next_program(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        fake.swap_during_prove = True
        events = []
        settler = self.settler(fake)
        with mock.patch.object(s, 'log', lambda event, **f: events.append((event, f))):
            # The proof of the old program finishes after L1 moved: nothing is sent.
            self.assertFalse(settler.cycle())
            self.assertEqual(fake.sent, [])
            self.assertIn('program-moved-before-submit', [e for e, _ in events])
            # The next cycle rewinds the block and settles the same number under the next rules.
            self.assertTrue(settler.cycle())
        self.assertEqual(fake.rewound, [1])
        self.assertEqual([e for e, _ in events].count('l2-block-rewound-at-swap'), 1)
        [tx] = fake.sent
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.next_values)
        extends = [c for c in fake.calls if c[1] == 'extend']
        self.assertEqual([c[c.index('--rule-set') + 1] for c in extends], ['base', 'next'])
        last = self.prover_calls(fake)[-1]
        self.assertEqual(Path(last[0]).name, 'next-settlement-v3')
        self.assertIn(str(self.root / 'settlement_v3_mainnet.next'), last)
        kept = [p.name for p in (self.root / 'work').iterdir() if '.superseded-' in p.name]
        self.assertEqual(len(kept), 1)
        self.assertTrue((self.root / 'work' / kept[0] / 'proved.json').exists())

    def test_a_terminal_refusal_after_the_swap_does_not_halt(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        fake.answers = [mn.refusal(s.TX_REFUSED, 'policy')] * 3
        settler = self.settler(fake)
        view = settler.native_view()
        number, directory = settler.prepare_block(view)
        proof = settler.prove(directory)
        tx = settler.transaction(directory, proof, None)

        inner = settler.native_view
        calls = []

        def moved():
            calls.append(1)
            if len(calls) == 2:
                fake.swap()
            return inner()
        settler.native_view = moved
        with mock.patch.object(s, 'log'):
            self.assertFalse(settler.submit_and_wait(number, directory, tx, view))

    def test_a_terminal_refusal_with_the_same_program_still_halts(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        fake.answers = [mn.refusal(s.TX_REFUSED, 'policy')] * 3
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'refuse the settlement'):
            self.settler(fake).cycle()

    def test_a_crash_between_rewind_and_rebuild_loses_nothing(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        settler = self.settler(fake)
        with mock.patch.object(s, 'log'):
            view = settler.native_view()
            settler.prepare_block(view)
            fake.swap()
            # The database was already rewound by the crashed run; the old directory is still there.
            fake.head, fake.head_rules = 0, 'base'
            self.assertTrue(settler.cycle())
        self.assertEqual(fake.rewound, [])
        self.assertEqual(fake.sent[0][33:33 + s.VALUES_BYTES], fake.next_values)

    def test_a_program_this_worker_does_not_know_halts(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        fake.live['program'] = {**BASE_REPORT, 'elf_keccak': 'ab' * 32}
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'not configured for'):
            self.settler(fake).cycle()

    def test_an_l1_reorganization_across_the_gate_waits(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        fake.head, fake.head_rules, fake.head_hash = 1, 'next', '51' * 32
        events = []
        with mock.patch.object(s, 'log', lambda event, **f: events.append(event)):
            self.assertFalse(self.settler(fake).cycle())
        self.assertIn('waiting-for-program', events)
        self.assertEqual(fake.sent, [])

    def test_a_node_without_the_report_is_on_the_activated_program(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        del fake.live['program']
        settler = self.settler(fake)
        with mock.patch.object(s, 'log'):
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'base')

    def test_the_next_program_is_pinned(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        config = self.config()
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'pinned next settlement_v3_mainnet'):
            s.Settler(config, rpc=fake.rpc, run=fake.run)
        self.next_pin = mock.patch.dict(s.MAINNET_NEXT, guest_sha256=config['next_program']['guest_sha256'])
        self.next_pin.start()
        self.addCleanup(self.next_pin.stop)
        (self.root / 'l2-config.next.bin').write_bytes(s.mainnet_l2_config())
        with self.assertRaisesRegex(s.Halt, 'pinned next program'):
            s.Settler(self.config_with_stale_config(config), rpc=fake.rpc, run=fake.run)

    def test_a_sparse_next_program_exports_the_sparse_witness_and_selects_its_guest(self):
        sparse = s.MAINNET_NEXT_SPARSE
        report = {k: sparse[k] for k in ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254')}
        report['proof_policy'] = M['proof_policy']
        (self.root / 'next-settlement-v3').write_bytes(b'next prover')
        (self.root / 'settlement_v3_mainnet_sparse').write_bytes(b'sparse guest')
        (self.root / 'l2-config.next.bin').write_bytes(s.mainnet_l2_config(sparse))
        next_program = {'prover': str(self.root / 'next-settlement-v3'), 'guest': str(self.root / 'settlement_v3_mainnet_sparse'),
                        'l2_config': str(self.root / 'l2-config.next.bin'), 'witness': 'sparse',
                        'guest_sha256': s.digest(self.root / 'settlement_v3_mainnet_sparse')}
        for key in ('prover', 'l2_config'):
            next_program[key + '_sha256'] = s.digest(next_program[key])
        config = self.base_config(next_program=next_program)
        fake = SwapFake(self.root, mn.mainnet_statement())
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'pinned next settlement_v3_mainnet'):
            s.Settler(config, rpc=fake.rpc, run=fake.run)
        pin = mock.patch.dict(s.MAINNET_NEXT_SPARSE, guest_sha256=next_program['guest_sha256'])
        pin.start()
        self.addCleanup(pin.stop)
        bad = json.loads(json.dumps(config))
        bad['next_program']['prover_args'] = ['--mainnet']
        with self.assertRaisesRegex(s.Halt, 'its witness'):
            s.Settler(bad, rpc=fake.rpc, run=fake.run)
        fake.next_values = mn.mainnet_statement(**{'64': s.mainnet_l2_config(sparse)[:160]})
        fake.live['program'] = dict(report)
        fake.values = fake.next_values
        clock = iter(range(0, 1_000_000, 5))
        settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
        with mock.patch.object(s, 'log'):
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'next')
        exports = [c for c in fake.calls if c[1] == 'export']
        self.assertTrue(exports)
        for call in exports:
            self.assertEqual(call[call.index('--witness') + 1], 'sparse')
        for call in self.prover_calls(fake):
            self.assertEqual(call[1:3], ['--mainnet', '--sparse'])
            self.assertIn(str(self.root / 'settlement_v3_mainnet_sparse'), call)

    def test_a_complete_program_exports_without_the_witness_option(self):
        fake = SwapFake(self.root, mn.mainnet_statement())
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.settler(fake).cycle())
        for call in (c for c in fake.calls if c[1] == 'export'):
            self.assertNotIn('--witness', call)

    def config_with_stale_config(self, config):
        config['next_program']['l2_config_sha256'] = s.digest(self.root / 'l2-config.next.bin')
        return config


if __name__ == '__main__':
    unittest.main()
