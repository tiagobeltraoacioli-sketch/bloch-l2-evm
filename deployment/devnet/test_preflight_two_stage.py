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
        self.out = STAGE1.format(n=522277) + COST.format(gas=707213, n=522277)
        result = self.measure_once()
        self.assertEqual((result.sp1_gas, result.instructions), (707213, 522277))
        self.assertFalse(self.settler.preflight_single_stage)

    def test_stage_counts_that_differ_are_no_cost(self):
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


if __name__ == '__main__':
    unittest.main()
