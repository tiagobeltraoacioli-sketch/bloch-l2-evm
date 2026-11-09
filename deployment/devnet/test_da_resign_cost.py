#!/usr/bin/env python3
"""Round 14 (agent 304; round-12 task 261): the user-transaction build does not take agent 118's signed-batch-log
DA reuse (b4e0887). The kit path publishes a block's DA batch again when the block is rebuilt and never reads a paid
batch from L1 (4b7f4f7), which is what closes agents/145 F1 (an outsider's batch must never choose the L2 block; its
regression is test_settler_r7 `test_a_recorded_batch_never_chooses_our_block`).

What reuse would save is one DA fee per rebuilt block. These tests pin that number, so the decision is re-opened if
the L1 fee constants ever make it large: a full block of user transactions (`max_block_bytes` 114,688) costs about
0.0002 BLCH at the minimum L1 base fee, and the re-sign count is capped by the mempool retention window.
"""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import settler_v3 as s  # noqa: E402

FULL_BLOCK_BYTES = 114_688  # install-settler-mainnet.py max_block_bytes
SAT = 10**8


class DaResignCost(unittest.TestCase):
    def test_a_full_batch_costs_about_two_ten_thousandths_of_a_blch_at_the_minimum_base_fee(self):
        fee = s.da_fee_sat(FULL_BLOCK_BYTES)
        self.assertEqual(fee, 20_489)
        self.assertLess(fee / SAT, 0.00025)

    def test_the_cost_is_linear_in_the_l1_base_fee(self):
        base = s.da_fee_sat(FULL_BLOCK_BYTES)
        for factor in (10, 100):
            fee = s.da_fee_sat(FULL_BLOCK_BYTES, base_fee_millisat_per_gas=factor * s.MIN_BASE_FEE_MILLISAT_PER_GAS)
            self.assertLessEqual(abs(fee - factor * base), factor)
        # Even at 100 times the minimum base fee one republished full batch is about 0.02 BLCH.
        self.assertLess(s.da_fee_sat(FULL_BLOCK_BYTES, base_fee_millisat_per_gas=1_000) / SAT, 0.021)

    def test_an_ordinary_block_of_a_few_swaps_costs_a_tenth_of_that(self):
        self.assertLess(s.da_fee_sat(2_000), 2_500)

    def test_the_settler_has_no_path_that_reads_a_paid_batch_from_l1(self):
        source = (Path(__file__).resolve().parent / 'settler_v3.py').read_text()
        for gone in ('da-batch-reused', 'da-reuse-waiting-follower', 'find_paid_da', 'paid_da_batch'):
            self.assertNotIn(f"log('{gone}'", source)
            self.assertNotIn(f'def {gone}', source)


if __name__ == '__main__':
    unittest.main()
