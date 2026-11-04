#!/usr/bin/env python3
"""Two-stage preflight (agent 257, on agent 224's recommendation 2): the settler side.

The SP1 settlement V3 host, with BLOCH_PREFLIGHT_CYCLE_LIMIT set, first counts the guest's instructions with SP1 gas off
(stage 1, the plain executor, about 1B instructions per second) and prints

    Settlement V3 preflight stage 1: instructions=<N> elapsed_ms=<t>

At or over the limit that count is the verdict: the host prints
`Settlement V3 over cycle limit: limit=<n> instructions=<N> stage=1` and exits 3 after its runtime has shut down, with no
gas run. Under the limit it runs the gas execute (stage 2, still under the cycle limit) and prints the cost line; stage 2
must count exactly the same instructions or the host fails.

The settler accepts a measurement only from such a host: every line must be there and agree. A single-stage host (no
stage-1 line) gives no cost, and the start-up probe names the reason, so a prover that would take 30-40 s per offender
(agent 224, H1) is never used silently. Fake prover runs; no process is started.

Run: python3 -B -m unittest -v test_preflight_two_stage
"""
import types
import unittest

import settler_v3 as s
import sequencer_policy_v2 as sp
from test_settler_policy_v2 import Harness

STAGE1 = 'Settlement V3 preflight stage 1: instructions={n} elapsed_ms=2400\n'
COST = ('Settlement V3 cost: gas={gas} touched_memory=1 record_bytes=2 syscalls=\n'
        'Settlement V3 guest matched the independent host statement: {n} instructions in 1s\n')
OVER = 'Settlement V3 over cycle limit: limit={limit} instructions={n} stage=1\n'


class TwoStageMeasurement(Harness):
    def setUp(self):
        super().setUp()
        del self.settler.measure_block
        self.settler.preflight_request = 'request\n'
        self.out, self.code, self.envs = '', 0, []

        def run(argv, timeout=None, **kwargs):
            self.envs.append(kwargs.get('env'))
            kwargs['stdout'].write(self.out)
            return types.SimpleNamespace(returncode=self.code)
        self.settler.run = run
        real = self.produce

        def produce(*args):
            if args[0] == 'export':
                from pathlib import Path
                Path(args[args.index('--out') + 1]).write_bytes(b'artifact')
                return {}
            return real(*args)
        self.settler.produce = produce

    def measure_once(self):
        return self.settler.measure_block('p', 'a', self.deposits, 1, 2, [], 't')[0]

    def test_stage_one_verdict_is_over_limit(self):
        self.out, self.code = STAGE1.format(n=2_279_398_170) + OVER.format(limit=200, n=2_279_398_170), 3
        self.assertEqual(self.measure_once(), sp.OVER_LIMIT)

    def test_cost_needs_the_stage_one_line(self):
        self.out = COST.format(gas=707213, n=522277)  # a single-stage host: cost line only
        self.assertIsNone(self.measure_once())
        self.assertTrue(self.settler.preflight_single_stage)

    def test_cost_with_matching_stage_one_count(self):
        self.settler.c['max_block_instructions'] = 1_000_000  # limit 2M, above the count
        self.out = STAGE1.format(n=522277) + COST.format(gas=707213, n=522277)
        result = self.measure_once()
        self.assertEqual((result.sp1_gas, result.instructions), (707213, 522277))
        self.assertFalse(self.settler.preflight_single_stage)

    def test_stage_counts_that_differ_are_no_cost(self):
        self.settler.c['max_block_instructions'] = 1_000_000
        self.out = STAGE1.format(n=522276) + COST.format(gas=707213, n=522277)
        self.assertIsNone(self.measure_once())

    def test_over_limit_line_of_a_single_stage_host_is_no_verdict(self):
        # The gas-path stop of agent 223's host: correct but late (31-38 s); it never quarantines through this settler.
        self.out, self.code = 'Settlement V3 over cycle limit: limit=200\n', 3
        self.assertIsNone(self.measure_once())

    def test_over_limit_with_a_count_under_the_limit_is_no_verdict(self):
        self.out, self.code = STAGE1.format(n=150) + OVER.format(limit=200, n=150), 3
        self.assertIsNone(self.measure_once())

    def test_over_limit_with_a_different_limit_is_no_verdict(self):
        self.out, self.code = STAGE1.format(n=900) + OVER.format(limit=800, n=900), 3
        self.assertIsNone(self.measure_once())

    def test_a_cost_at_or_over_the_limit_is_no_cost(self):
        # The host never prints a cost for a count at the limit (stage 1 stops it): such output is not trusted.
        self.out = STAGE1.format(n=200) + COST.format(gas=200, n=200)
        self.assertIsNone(self.measure_once())

    def test_stage_one_line_alone_is_no_cost(self):
        self.out, self.code = STAGE1.format(n=150), 1  # stage 2 failed
        self.assertIsNone(self.measure_once())

    def test_probe_refuses_a_single_stage_host_by_name(self):
        self.out = COST.format(gas=707213, n=522277)
        self.spool(a=10)
        with self.assertRaises(s.Halt) as raised:
            self.block()
        self.assertIn('two-stage preflight', str(raised.exception))
        self.assertEqual(self.names(), ['a'])

    def test_probe_accepts_a_two_stage_host(self):
        self.out = STAGE1.format(n=40) + COST.format(gas=40, n=40)
        self.block()
        self.assertTrue(self.settler.cost_line_checked)

    def test_switching_program_requires_a_new_successful_control_before_selection(self):
        self.out = STAGE1.format(n=40) + COST.format(gas=40, n=40)
        self.block()
        self.spool(a=10)
        self.settler.program = dict(self.settler.program, guest='settlement_v3_mainnet_sparse', witness='sparse',
                                    prover_args=['--mainnet', '--sparse'])
        self.out = COST.format(gas=40, n=40)
        with self.assertRaisesRegex(s.Halt, 'two-stage preflight'):
            self.block()
        self.assertEqual(self.names(), ['a'])
        self.assertEqual(self.quarantined(), [])

    def test_preflight_uses_the_scheduled_program_and_sparse_export(self):
        self.settler.program = {'prover': '/test/pinned-next-host', 'prover_args': ['--mainnet', '--sparse'],
                                'guest': '/test/pinned-sparse-guest', 'witness': 'sparse'}
        self.out = STAGE1.format(n=40) + COST.format(gas=40, n=40)
        with unittest.mock.patch.object(self.settler, 'run', wraps=self.settler.run) as run:
            with unittest.mock.patch.object(self.settler, 'produce', wraps=self.settler.produce) as produce:
                self.assertIsNotNone(self.measure_once())
        self.assertEqual(run.call_args.args[0], ['/test/pinned-next-host', '--mainnet', '--sparse',
                                                'execute', 'native-artifact', '/test/pinned-sparse-guest'])
        export = next(call.args for call in produce.call_args_list if call.args[0] == 'export')
        self.assertEqual(export[-2:], ('--witness', 'sparse'))

    def test_duplicate_conflicting_and_out_of_order_cost_lines_are_no_cost(self):
        first, cost = STAGE1.format(n=40), COST.format(gas=50, n=40)
        malformed = [first + cost + cost, first + first + cost, cost + first,
                     first + COST.format(gas=99, n=39) + cost,
                     first + OVER.format(limit=200, n=40) + cost,
                     first.replace('elapsed_ms=2400', 'unexpected=2400') + cost,
                     first.replace('instructions=40', 'instructions=040') + cost,
                     first.replace('instructions=40', 'instructions=' + '9' * 5000) + cost,
                     first + COST.format(gas=2**64, n=40)]
        for text in malformed:
            with self.subTest(text=text[:80]):
                self.assertIsNone(self.settler.preflight_result(0, text, 200))

    def test_over_limit_never_accepts_a_gas_run_or_an_ambiguous_verdict(self):
        first, over = STAGE1.format(n=300), OVER.format(limit=200, n=300)
        for text in (over + first, first + over + over, first + COST.format(gas=500, n=300) + over,
                     first + over + 'Settlement V3 cost: gas=none touched_memory=1 record_bytes=1 syscalls=\n'):
            with self.subTest(text=text[:80]):
                self.assertIsNone(self.settler.preflight_result(3, text, 200))

    def test_invalid_limit_and_boolean_exit_status_are_not_measurements(self):
        text = STAGE1.format(n=40) + COST.format(gas=50, n=40)
        for limit in (0, -1, 2**64, True, 200.0):
            with self.subTest(limit=limit):
                self.assertIsNone(self.settler.preflight_result(0, text, limit))
        self.assertIsNone(self.settler.preflight_result(False, text, 200))


if __name__ == '__main__':
    unittest.main()
