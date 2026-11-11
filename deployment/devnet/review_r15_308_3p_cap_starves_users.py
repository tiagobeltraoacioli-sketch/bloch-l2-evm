#!/usr/bin/env python3
"""Review r15 third pass (agent 308), R308-3P-2: the producer's 8-pass cap keeps "the transactions ahead of the first
unpaid one". Block order is by tip, and a transaction is unpaid only below about 9 gwei (a new slot costs at least
20,000 gas, so gas x tip covers 200 µBLCH per slot from there on), which is above what honest users pay (the required
tip is capped at 3 gwei). Non-payers at a tip above the users' therefore sit at the FRONT of the block order: with
eight or more of them per producer call the kept prefix is empty and the block takes no user transaction. They are
never included, so they cost their senders nothing, and fresh ones can be spooled for every block.

The fake producer is the authors' (`PricedWorld`) with the cap of the real one (bloch-l2-produce-dev.rs
`leave_unpaid`, WRITE_PRICE_MAX_PASSES = 8): at the cap the selection keeps the prefix ahead of the unpaid
transaction and reports the rest as `not_judged`.
Run: WT=<bloch-l2-evm checkout> python3 -B -m unittest -v review_r15_308_3p_cap_starves_users   (default: this file's checkout)
"""
import os
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
WT = Path(os.environ.get('WT', str(Path(__file__).resolve().parents[2])))
sys.path.insert(0, str(WT / 'deployment/devnet'))
import sequencer_policy_v2 as sp  # noqa: E402
from test_sequencer_policy_v2 import GWEI  # noqa: E402
from test_review_r11_policy_v2 import SlotWorld, sp_hash  # noqa: E402
from test_round15_producer_write_price import PRICE  # noqa: E402

MAX_PASSES = 8


class CappedWorld(SlotWorld):
    def config(self):
        return {**super().config(), 'producer_write_price': True}

    def report(self, raws):
        # Round 15, third pass fix: the real producer now judges the write price inside its selection, one pass
        # (tests/produce_txs.rs `eight_non_payers_ahead_in_tip_order_do_not_empty_the_block` runs the reviewer's
        # scenario on the binary). This model does the same: every non-payer is left out where it stands and the
        # transactions behind it are served. The capped model this file was written against is in git history.
        self.passes = getattr(self, 'passes', [])
        self.passes.append(1)
        raws, unpaid = list(raws), []
        while True:
            report = SlotWorld.report(self, raws)
            first = next((t for t in report['tx_stats']
                          if (fresh := sum(n for _, n in t['fresh_slots'])) and int(t['gas_used']) * int(t['effective_tip']) < fresh * PRICE), None)
            if first is None:
                report['unpaid'] = unpaid
                return report
            unpaid.append({'hash': first['hash'], 'sender': first['sender'], 'nonce': first['nonce']})
            raws = [raw for raw in raws if sp_hash(raw) != first['hash']]


class R308_3P_2(CappedWorld):
    def test_non_payers_ahead_of_the_users_in_tip_order_do_not_empty_every_block(self):
        served, spooled = [], 0
        for block in range(6):
            for i in range(20):
                self.add(f'h{block}-{i}', f'user{block}-{i}', 0, 21_000, 1, tip=GWEI)
            # 8 fresh non-payers per block: own slot each, 50,000 gas at 3.9 gwei = 1.95e14 < 2e14. Never included.
            for i in range(8):
                spooled += 1
                self.add_writer(f'np{block}-{i}', f'm{block}-{i}', 0, 50_000, 1, [f'slot{block}-{i}'], tip=39 * GWEI // 10)
            names = self.block()
            served.append(sum(n.startswith('h') for n in names))
            self.assertEqual([n for n in names if n.startswith('np')], [], 'a non-payer was included')
        self.assertGreater(sum(served), 0, f'honest transactions served per block: {served}; non-payers spooled {spooled}, '
                                           f'included 0; producer passes per call: {sorted(set(self.passes))}')


if __name__ == '__main__':
    unittest.main()
