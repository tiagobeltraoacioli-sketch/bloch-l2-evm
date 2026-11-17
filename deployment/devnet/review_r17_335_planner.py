#!/usr/bin/env python3
"""Review r17 (agent 335), R335-3: the planner's reserved places and the producer disagree on "plain transfer".

The producer (src/node_execution/select.rs:880 and :963) calls a transaction a plain transfer when it DECLARES
21,000 gas and carries no data. The planner's cut (`Policy._capped`, `group`) calls it one when it USED 21,000 gas.
A value transfer that declares a larger limit is therefore a plain transfer of a sender without credit for the
planner (first claim on the reserved places of a full block, by tip) and an uncovered CALL for the producer (after
every uncovered plain transfer). Declaring a large limit also keeps an established sender "without credit" for about seventy
transfers per key: covered needs credit >= gas LIMIT x tip, and each transfer earns credit for 21,000 gas only.

Named review_r17_* so that suite discovery does not pick it up. Fails on f73131f.
Run: python3 -B -m unittest -v review_r17_335_planner   (from deployment/devnet)
"""
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_round15_producer_write_price as t  # noqa: E402

GWEI = t.GWEI


class PlainTransferIsTheProducersRule(t.PricedWorld):
    def test_a_declared_limit_above_21000_is_not_a_plain_transfer_for_the_reserved_places(self):
        for sender in range(8):
            self.policy.state['credit'][f'rich{sender}'] = {'wei': 10**18, 'at': self.now}
            for nonce in range(16):
                self.add(f'r{sender}-{nonce}', f'rich{sender}', nonce, 21_000, 1, tip=12 * GWEI // 10)
        # Eight real newcomers: plain transfers (21,000 declared and used) at 0.5 gwei.
        for i in range(8):
            self.add(f'new{i}', f'fresh{i}', 0, 21_000, 1, tip=5 * GWEI // 10)
        # One established sender: eight value transfers that declare 1,500,000 gas (the uncovered limit) and use
        # 21,000, at 0.6 gwei. It has paid for forty transfers already (credit 40 x 21,000 x tip); covered needs 1,500,000 x tip.
        tip = 6 * GWEI // 10
        self.policy.state['credit']['poser'] = {'wei': 40 * 21_000 * tip, 'at': self.now}
        for nonce in range(8):
            raw = t.signed_bytes(2, 1_500_000, f'poser-{nonce}')
            self.tx[raw] = dict(name=f'p{nonce}', sender='poser', nonce=nonce, gas=21_000, cost=1, tip=tip, fresh=[],
                                fail_first=0)
            self.spool.append(raw)
        served = self.block(advance=0)
        self.assertEqual(len(served), 64)
        self.assertEqual(sum(n.startswith('r') for n in served), 56)
        newcomers = sorted(n for n in served if n.startswith('new'))
        self.assertEqual(newcomers, sorted(f'new{i}' for i in range(8)),
                         'the reserved places went to transactions the producer does not call plain transfers: '
                         + ', '.join(sorted(n for n in served if n.startswith('p'))))


if __name__ == '__main__':
    unittest.main()
