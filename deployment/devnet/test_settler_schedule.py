#!/usr/bin/env python3
"""Program schedule tests for settler_v3.py: the settler picks the program for the epoch its settlement lands in.

L1 (`getl2settlement.program_schedule`, `getchaininfo.slot`) is mocked. No network, no prover, no Docker.
Run: python3 -m unittest discover -s deployment/devnet -p 'test_settler_schedule.py' -v
"""
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
from test_settler_v3 import broadcasts  # noqa: E402  (review r10 M2: one entry per endpoint)
import test_settler_mainnet as mn  # noqa: E402
import test_settler_next as nx  # noqa: E402

M = s.MAINNET
SPE = 32  # slots per epoch: 960 s epochs of 30 s slots
SLOT_S = 30
LEAD = 1800  # default program_switch_lead_seconds: 60 slots
LEAD_SLOTS = LEAD // SLOT_S
GATE = 7400  # a scheduled gate epoch
GATE_SLOT = GATE * SPE
SPARSE = s.MAINNET_NEXT_SPARSE
SPARSE_REPORT = {**{k: SPARSE[k] for k in ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254')},
                 'proof_policy': M['proof_policy']}


def entry(epoch, report):
    return {'epoch': epoch, **report}


class ScheduleFake(nx.SwapFake):
    """SwapFake plus an L1 head slot and a program schedule; `swap()` moves L1 to NEXT_REPORT and drops the gate."""

    def __init__(self, root, values, slot, schedule):
        super().__init__(root, values)
        self.slot, self.chaininfo_error = slot, None
        self.live['program_schedule'] = schedule

    def swap(self):
        super().swap()
        self.live['program_schedule'] = self.live.get('program_schedule', [])[1:]

    def rpc(self, port, method, params=()):
        if method == 'getchaininfo':
            if self.chaininfo_error:
                raise self.chaininfo_error
            answer = super().rpc(port, method, params)
            return {**answer, 'slot': self.slot, 'epoch': self.slot // SPE}
        return super().rpc(port, method, params)


class ProgramScheduleTest(unittest.TestCase):
    """The swap test's mainnet configuration, pins and helpers; only schedule cases."""
    P = nx.ProgramSwapTest
    setUp, tearDown, base_config, config = P.setUp, P.tearDown, P.base_config, P.config
    settler, prover_calls, rollback_config = P.settler, P.prover_calls, P.rollback_config

    def recorded(self):
        events = []
        return events, mock.patch.object(s, 'log', lambda event, **f: events.append((event, f)))

    def proofs(self, fake):
        return [c for c in self.prover_calls(fake) if 'prove-groth16' in c]

    def swap_fake(self, slot, schedule=None):
        if schedule is None:
            schedule = [entry(GATE, nx.NEXT_REPORT)]
        return ScheduleFake(self.root, mn.mainnet_statement(), slot, schedule)

    # ---- before the gate ----
    def test_before_the_window_the_activated_program_settles_unchanged(self):
        fake = self.swap_fake(GATE_SLOT - LEAD_SLOTS - 1)  # lands in GATE - 1
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'base')
        extend = next(c for c in fake.calls if c[1] == 'extend')
        self.assertEqual(extend[extend.index('--rule-set') + 1], 'base')
        [proof] = self.proofs(fake)
        self.assertEqual(Path(proof[0]).name, 'bloch-evm-sp1-settlement-v3')
        [tx] = broadcasts(fake.sent)
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.base_values)
        names = [e for e, _ in events]
        self.assertNotIn('program-scheduled', names)
        self.assertNotIn('program-schedule-unusable', names)

    def test_inside_the_window_the_block_is_built_and_proved_for_the_next_program_and_held(self):
        fake = self.swap_fake(GATE_SLOT - LEAD_SLOTS)  # lands exactly in GATE
        fake.values = fake.next_values  # the fake prover writes the statement of the program being proved
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            self.assertFalse(settler.cycle())
            # Proved for the next program; no DA, no settlement before L1 holds it.
            self.assertEqual(fake.sent, [])
            self.assertEqual(settler.program['name'], 'next')
            self.assertIn('program-gate-pending', [e for e, _ in events])
            self.assertFalse(settler.cycle())  # still ahead of the gate: same proof, still held
            self.assertEqual(fake.sent, [])
            fake.slot = GATE_SLOT
            fake.swap()
            self.assertTrue(settler.cycle())
        [proof] = self.proofs(fake)  # one proof in all: nothing wasted on the activated program
        self.assertEqual(Path(proof[0]).name, 'next-settlement-v3')
        self.assertIn(str(self.root / 'settlement_v3_mainnet.next'), proof)
        extends = [c for c in fake.calls if c[1] == 'extend']
        self.assertEqual([c[c.index('--rule-set') + 1] for c in extends], ['next'])
        self.assertEqual(fake.rewound, [])
        [tx] = broadcasts(fake.sent)
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.next_values)
        names = [e for e, _ in events]
        self.assertNotIn('program-moved-before-submit', names)
        self.assertEqual(names.count('program-scheduled'), 1)

    def test_one_slot_short_of_the_window_keeps_the_activated_program(self):
        fake = self.swap_fake(GATE_SLOT - LEAD_SLOTS - 1)
        with mock.patch.object(s, 'log'):
            settler = self.settler(fake)
            settler.cycle()
        self.assertEqual(settler.program['name'], 'base')

    def test_an_unproved_activated_block_in_flight_is_rewound_when_the_gate_enters_the_window(self):
        fake = self.swap_fake(GATE_SLOT - LEAD_SLOTS - 10)
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            settler.prepare_block(settler.native_view())  # built under base, not proved (crash or slow queue)
            fake.slot = GATE_SLOT - LEAD_SLOTS + 1
            fake.values = fake.next_values
            self.assertFalse(settler.cycle())
            fake.swap()
            self.assertTrue(settler.cycle())
        self.assertEqual(fake.rewound, [1])
        self.assertIn('l2-block-rewound-at-swap', [e for e, _ in events])
        [proof] = self.proofs(fake)
        self.assertEqual(Path(proof[0]).name, 'next-settlement-v3')

    def test_a_finished_proof_of_the_activated_program_is_still_sent_before_the_gate(self):
        fake = self.swap_fake(GATE_SLOT - LEAD_SLOTS - 10)
        fake.include = False  # L1 has not accepted it yet when the window reaches the gate
        with mock.patch.object(s, 'log'):
            settler = self.settler(fake)
            self.assertFalse(settler.cycle())  # proved for base, sent, acceptance timed out
            fake.slot = GATE_SLOT - 5
            fake.include = True
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'base')
        [proof] = self.proofs(fake)
        self.assertEqual(Path(proof[0]).name, 'bloch-evm-sp1-settlement-v3')
        self.assertEqual(fake.rewound, [])

    # ---- exactly at the gate and after ----
    def test_exactly_at_the_gate_before_l1_moved_the_next_program_is_proved_and_waits(self):
        fake = self.swap_fake(GATE_SLOT)  # the gate slot, the block installing the program not yet seen
        fake.values = fake.next_values
        with mock.patch.object(s, 'log'):
            settler = self.settler(fake)
            self.assertFalse(settler.cycle())
            self.assertEqual(fake.sent, [])
            fake.swap()
            self.assertTrue(settler.cycle())
        [proof] = self.proofs(fake)
        self.assertEqual(Path(proof[0]).name, 'next-settlement-v3')

    def test_exactly_at_the_gate_after_l1_moved_the_next_program_settles(self):
        fake = self.swap_fake(GATE_SLOT)
        fake.swap()  # program NEXT, schedule now empty
        with mock.patch.object(s, 'log'):
            settler = self.settler(fake)
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'next')
        self.assertEqual(fake.rewound, [])
        [tx] = broadcasts(fake.sent)
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.next_values)

    def test_after_the_gate_the_next_program_settles_with_an_empty_schedule(self):
        fake = self.swap_fake(GATE_SLOT + 5 * SPE)
        fake.swap()
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'next')
        names = [e for e, _ in events]
        self.assertNotIn('program-schedule-unusable', names)
        self.assertNotIn('program-scheduled', names)

    # ---- rollback direction ----
    def rollback_fake(self, slot):
        fake = ScheduleFake(self.root, mn.mainnet_statement(**{'64': s.mainnet_l2_config(SPARSE)[:160]}), slot,
                            [entry(GATE, nx.NEXT_REPORT)])  # NEXT_REPORT is the fallback's identity
        fake.live['program'] = dict(SPARSE_REPORT)
        fake.head_rules = 'base'
        fake.next_values = nx.next_statement()
        return fake

    def test_rollback_inside_the_window_proves_the_same_block_with_the_fallback_guest_only(self):
        config = self.rollback_config()
        fake = self.rollback_fake(GATE_SLOT - 3)
        fake.values = fake.next_values
        clock = iter(range(0, 1_000_000, 5))
        events, patch = self.recorded()
        with patch:
            settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
            self.assertFalse(settler.cycle())
            self.assertEqual(settler.program['name'], 'fallback')
            self.assertEqual(fake.sent, [])
            fake.swap()
            self.assertTrue(settler.cycle())
        [proof] = self.proofs(fake)  # no sparse proof was started
        self.assertIn(str(self.root / 'settlement_v3_mainnet.fallback'), proof)
        self.assertNotIn('--sparse', proof)
        self.assertEqual(fake.rewound, [])
        exports = [c for c in fake.calls if c[1] == 'export']
        self.assertTrue(exports)
        for call in exports:
            self.assertNotIn('--witness', call)
        [tx] = broadcasts(fake.sent)
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.next_values)
        self.assertIn('program-gate-pending', [e for e, _ in events])

    def test_rollback_outside_the_window_keeps_the_sparse_guest(self):
        config = self.rollback_config()
        fake = self.rollback_fake(GATE_SLOT - LEAD_SLOTS - 1)
        clock = iter(range(0, 1_000_000, 5))
        with mock.patch.object(s, 'log'):
            settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'next')
        [proof] = self.proofs(fake)
        self.assertIn(str(self.root / 'settlement_v3_mainnet_sparse'), proof)
        self.assertEqual(proof[1:3], ['--mainnet', '--sparse'])

    def test_a_block_already_proved_by_the_sparse_guest_is_reproved_when_the_rollback_enters_the_window(self):
        config = self.rollback_config()
        fake = self.rollback_fake(GATE_SLOT - LEAD_SLOTS - 10)
        clock = iter(range(0, 1_000_000, 5))
        events, patch = self.recorded()
        with patch:
            settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
            number, directory = settler.prepare_block(settler.native_view())
            settler.prove(directory)  # sparse proof done, not sent; the gate is already past by L1 time below
            fake.slot = GATE_SLOT  # at the gate: a sparse proof can no longer be sent safely
            fake.values = fake.next_values
            self.assertFalse(settler.cycle())
            fake.swap()
            self.assertTrue(settler.cycle())
        self.assertEqual([e for e, _ in events].count('l2-block-reproved-for-program'), 1)
        self.assertEqual(fake.rewound, [])
        sparse, fallback = self.proofs(fake)  # the fallback proof made ahead of the gate is not made again after it
        self.assertIn(str(self.root / 'settlement_v3_mainnet_sparse'), sparse)
        self.assertIn(str(self.root / 'settlement_v3_mainnet.fallback'), fallback)
        self.assertEqual(len(broadcasts(fake.sent)), 1)

    def test_a_block_reproved_for_the_rollback_is_not_proved_again_by_a_later_cycle(self):
        # Without the schedule (old path): the rollback passes during the sparse proof, the block is re-proved by the
        # fallback guest, acceptance times out; the next cycle must send that proof again, not make a third one.
        config = self.rollback_config()
        fake = self.rollback_fake(GATE_SLOT - LEAD_SLOTS - 10)
        del fake.live['program_schedule']
        fake.swap_during_prove = True
        clock = iter(range(0, 1_000_000, 5))
        with mock.patch.object(s, 'log'):
            settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
            self.assertFalse(settler.cycle())  # sparse proof, program moved before submit
            fake.include = False
            self.assertFalse(settler.cycle())  # fallback proof, sent, not accepted in time
            fake.include = True
            self.assertTrue(settler.cycle())
        self.assertEqual(len(self.proofs(fake)), 2)
        self.assertGreaterEqual(len(broadcasts(fake.sent)), 2)
        self.assertEqual(len(set(fake.sent)), 1)  # only the one fallback settlement, sent again

    def test_swap_and_rollback_both_inside_the_window_target_the_fallback(self):
        config = self.rollback_config()
        fake = ScheduleFake(self.root, mn.mainnet_statement(), GATE_SLOT - 10,
                            [entry(GATE, SPARSE_REPORT), entry(GATE + 1, nx.NEXT_REPORT)])
        clock = iter(range(0, 1_000_000, 5))
        with mock.patch.object(s, 'log'):
            settler = s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
            self.assertFalse(settler.cycle())
        self.assertEqual(settler.program['name'], 'fallback')
        extend = next(c for c in fake.calls if c[1] == 'extend')
        self.assertEqual(extend[extend.index('--rule-set') + 1], 'next')
        self.assertEqual(fake.sent, [])

    # ---- schedule unreadable: fail safe ----
    def assert_fails_safe(self, fake, reason):
        """The program L1 holds now is used, the reason is logged once, and the settlement is of that program."""
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'base')
        [proof] = self.proofs(fake)
        self.assertEqual(Path(proof[0]).name, 'bloch-evm-sp1-settlement-v3')
        [tx] = broadcasts(fake.sent)
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.base_values)
        unusable = [f['reason'] for e, f in events if e == 'program-schedule-unusable']
        self.assertEqual(len(unusable), 1, unusable)
        self.assertRegex(unusable[0], reason)
        self.assertNotIn('program-scheduled', [e for e, _ in events])

    def test_a_missing_schedule_fails_safe(self):
        fake = self.swap_fake(GATE_SLOT - 1)
        del fake.live['program_schedule']
        self.assert_fails_safe(fake, 'no program_schedule')

    def test_a_schedule_that_is_not_a_list_fails_safe(self):
        fake = self.swap_fake(GATE_SLOT - 1, schedule={'epoch': GATE})
        self.assert_fails_safe(fake, 'no program_schedule')

    def test_a_malformed_entry_fails_safe(self):
        for schedule, reason in (([{'epoch': GATE}], 'configuration'),
                                 ([entry(str(GATE), nx.NEXT_REPORT)], 'increasing integers'),
                                 ([entry(True, nx.NEXT_REPORT)], 'increasing integers'),
                                 ([entry(GATE, {**nx.NEXT_REPORT, 'elf_keccak': 'zz'})], 'non-hexadecimal'),
                                 ([entry(GATE, {**nx.NEXT_REPORT, 'elf_keccak': 'ab'})], 'five 32-byte'),
                                 ([entry(GATE, nx.NEXT_REPORT), entry(GATE, nx.NEXT_REPORT)], 'increasing'),
                                 (['junk'], 'string indices|indices')):
            with self.subTest(reason=reason):
                self.tearDown()
                self.setUp()
                self.assert_fails_safe(self.swap_fake(GATE_SLOT - 1, schedule=schedule), reason)

    def test_an_unknown_scheduled_program_fails_safe_until_l1_reports_it(self):
        fake = self.swap_fake(GATE_SLOT - 1, schedule=[entry(GATE, {**nx.NEXT_REPORT, 'elf_keccak': 'ab' * 32})])
        self.assert_fails_safe(fake, 'not configured for')

    def test_an_unreadable_l1_slot_fails_safe(self):
        fake = self.swap_fake(GATE_SLOT - 1)
        fake.chaininfo_error = ConnectionRefusedError(111, 'Connection refused')
        self.assert_fails_safe(fake, 'slot unreadable')

    def test_a_missing_slot_field_fails_safe(self):
        fake = self.swap_fake(GATE_SLOT - 1)
        inner = fake.rpc
        fake.rpc = lambda port, method, params=(): ({'height': 1} if method == 'getchaininfo' else inner(port, method, params))
        self.assert_fails_safe(fake, 'slot unreadable')

    def test_fail_safe_never_sends_a_proof_of_a_program_l1_does_not_hold(self):
        # Schedule unreadable and the gate passes during the proof: the old path, one wasted proof, nothing wrong sent.
        fake = self.swap_fake(GATE_SLOT - 1)
        del fake.live['program_schedule']
        fake.swap_during_prove = True
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            self.assertFalse(settler.cycle())
            self.assertEqual(fake.sent, [])
            self.assertTrue(settler.cycle())
        names = [e for e, _ in events]
        self.assertIn('program-moved-before-submit', names)
        [tx] = broadcasts(fake.sent)
        self.assertEqual(tx[33:33 + s.VALUES_BYTES], fake.next_values)

    def test_a_schedule_that_recovers_is_used_again(self):
        fake = self.swap_fake(GATE_SLOT - LEAD_SLOTS)
        fake.chaininfo_error = ConnectionRefusedError(111, 'Connection refused')
        events, patch = self.recorded()
        with patch:
            settler = self.settler(fake)
            view = settler.native_view()
            self.assertIsNone(settler.scheduled_program(view, self.root / 'none'))
            self.assertIsNone(settler.scheduled_program(view, self.root / 'none'))
            fake.chaininfo_error = None
            self.assertEqual(settler.scheduled_program(view, self.root / 'none')['name'], 'next')
        self.assertEqual([e for e, _ in events].count('program-schedule-unusable'), 1)

    # ---- configuration ----
    def test_the_window_settings_are_positive_integers(self):
        fake = self.swap_fake(0)
        for key in ('program_switch_lead_seconds', 'slots_per_epoch'):
            for bad in (0, -1, True, 1.5, '30'):
                with self.subTest(key=key, bad=bad), self.assertRaisesRegex(s.Halt, key):
                    self.settler(fake, **{key: bad})

    def test_a_longer_lead_reaches_the_gate_earlier(self):
        fake = self.swap_fake(GATE_SLOT - 2 * SPE)
        with mock.patch.object(s, 'log'):
            self.assertIsNone(self.settler(fake).scheduled_program(fake.view(), self.root / 'none'))
            self.assertEqual(self.settler(fake, program_switch_lead_seconds=2 * SPE * SLOT_S)
                             .scheduled_program(fake.view(), self.root / 'none')['name'], 'next')

    def test_without_next_program_the_schedule_is_ignored(self):
        fake = mn.MainnetFake(self.root, mn.mainnet_statement())
        fake.live.update(program=dict(nx.BASE_REPORT), program_schedule=[entry(GATE, nx.NEXT_REPORT)])
        clock = iter(range(0, 1_000_000, 5))
        settler = s.Settler(self.base_config(), rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))
        events, patch = self.recorded()
        with patch:
            self.assertTrue(settler.cycle())
        self.assertEqual(settler.program['name'], 'base')
        self.assertFalse([e for e, _ in events if e.startswith('program-')])


if __name__ == '__main__':
    unittest.main()
