#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit AUDIT-L1L2-20261123, L1X-04 (the settler half): consensus admits four DA (0x15) transactions per native
block and the proposer gives the slots to the highest tip rates, so four junk batches per block at a tip above the
settler's keep its batch, and with it every block with user transactions, off L1. The settler now raises the tip
of a batch that is not recorded within `da.tip_escalation_blocks` native blocks, up to a cap, and logs
`da-not-included` while it waits."""
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as t  # noqa: E402


class Auction(t.Fake):
    """L1 whose height moves one block per `getchaininfo` read of endpoint 1, and whose proposers include a DA
    transaction only when its tip is at least `clearing_tip` (what four junk batches per block pay)."""

    def __init__(self, *args, clearing_tip=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.clearing_tip, self.height, self.tips = clearing_tip, 1000, {}

    def rpc(self, port, method, params=()):
        if method == 'getchaininfo':
            self.height += 1
            return {'next_base_fee_millisat_per_gas': '10', 'epoch': self.epoch, 'height': self.height}
        if method == 'sendrawtransaction' and params[0].startswith('15'):
            self.include_da = self.tips[bytes.fromhex(params[0])] >= self.clearing_tip
        return super().rpc(port, method, params)

    def run(self, argv, **kwargs):
        out = super().run(argv, **kwargs)
        if Path(argv[0]).name == 'bloch-pos' and len(argv) > 2 and argv[2] == 'prepare' and not out.returncode:
            # Make the frames of different attempts distinct and remember the tip each was signed with.
            path = Path(argv[argv.index('--out') + 1])
            tip = argv[argv.index('--tip') + 1]
            frame = bytes.fromhex(path.read_text().strip()) + tip.encode()
            path.write_text(frame.hex() + '\n')
            self.tips[frame] = int(tip)
        return out


def tips(fake):
    return [int(c[c.index('--tip') + 1]) for c in fake.calls if Path(c[0]).name == 'bloch-pos' and c[2] == 'prepare']


class DaTipPolicy(unittest.TestCase):
    setUp, tearDown = t.SettlerV3Test.setUp, t.SettlerV3Test.tearDown
    config, da_config = t.SettlerV3Test.config, t.SettlerV3Test.da_config

    def settler_for(self, fake, **da):
        clock = iter(range(0, 1_000_000, 3))
        config = self.config(user_transactions=True, txpool_dir=str(self.root / 'txpool'),
                             da={**self.da_config(), 'inclusion_timeout_seconds': 1800, **da})
        return s.Settler(config, rpc=fake.rpc, run=fake.run, sleep=lambda _: None, clock=lambda: next(clock))

    def events(self, logged, name):
        return [c.kwargs for c in logged.call_args_list if c.args[0] == name]

    def test_without_contention_the_batch_pays_the_configured_tip_and_nothing_is_raised(self):
        fake = Auction(self.root, t.statement(user_txs=2), produced_txs=2)
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler_for(fake).cycle())
        self.assertEqual(tips(fake), [0], 'the default start tip is zero, as before')
        self.assertEqual(self.events(logged, 'da-tip-raised') + self.events(logged, 'da-not-included'), [])
        [meta] = [json.loads(p.read_text()) for p in (self.root / 'work').glob('*/da-meta-*.json')]
        self.assertEqual(meta['tip'], 0)
        self.assertIsInstance(meta['height'], int)

    def test_a_batch_kept_out_by_higher_tips_is_resigned_at_twice_the_tip_until_it_is_included(self):
        # Four junk batches per block pay 100 millisat per gas: the pinned settler (tip 0, for ever) never gets a
        # slot and waits out inclusion_timeout_seconds every cycle.
        fake = Auction(self.root, t.statement(user_txs=2), produced_txs=2, clearing_tip=100)
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler_for(fake).cycle(), 'settled in one cycle, inside one inclusion timeout')
        self.assertEqual(tips(fake), [0, 10, 20, 40, 80, 160], 'from the step, doubling, until above the clearing tip')
        raised = self.events(logged, 'da-tip-raised')
        self.assertEqual([e['tip_millisat_per_gas'] for e in raised], [10, 20, 40, 80, 160])
        self.assertEqual([e['previous_tip_millisat_per_gas'] for e in raised], [0, 10, 20, 40, 80])
        self.assertEqual(len(fake.da_records), 1, 'one record: the fee is paid once')
        self.assertEqual([tx[0] for tx in t.broadcasts(fake.sent)][-1], s.ASYNC_SETTLEMENT_TAG)
        # Every attempt spends the previous one's inputs, so only one can ever be included.
        meta = [json.loads(p.read_text()) for p in sorted((self.root / 'work').glob('*/da-meta-*.json'))]
        self.assertEqual([m['tip'] for m in meta], [0, 10, 20, 40, 80, 160])
        self.assertTrue(all(set(meta[0]['inputs']) & set(m['inputs']) for m in meta[1:]))
        # Each raise waited the escalation blocks (4 by default).
        heights = [m['height'] for m in meta]
        self.assertTrue(all(b - a >= 4 for a, b in zip(heights, heights[1:])), heights)

    def test_the_tip_stops_at_the_cap_and_the_alert_names_it(self):
        fake = Auction(self.root, t.statement(user_txs=2), produced_txs=2, clearing_tip=10 ** 9)
        with mock.patch.object(s, 'log') as logged:
            self.assertFalse(self.settler_for(fake, max_tip_millisat_per_gas=50, inclusion_timeout_seconds=600).cycle())
        self.assertEqual(tips(fake), [0, 10, 20, 40, 50], 'never above da.max_tip_millisat_per_gas')
        alerts = self.events(logged, 'da-not-included')
        self.assertTrue(alerts, 'a batch not recorded within the alert blocks is reported')
        self.assertTrue(all(a['waited_blocks'] >= 8 and a['max_tip_millisat_per_gas'] == 50 for a in alerts))
        self.assertFalse(alerts[0]['at_max_tip'])
        self.assertTrue(alerts[-1]['at_max_tip'] and alerts[-1]['tip_millisat_per_gas'] == 50)
        waited = [a['waited_blocks'] for a in alerts]
        self.assertTrue(all(b - a >= 8 for a, b in zip(waited, waited[1:])), 'once per alert interval, not per poll')
        self.assertEqual(self.events(logged, 'da-inclusion-timeout'), [{'number': 1}])
        self.assertEqual(fake.da_records, [])

    def test_the_defaults_and_the_options(self):
        fake = Auction(self.root, t.statement(user_txs=2), produced_txs=2)
        self.assertEqual(self.settler_for(fake).da_tip_policy(), (0, 10, 1000, 4, 8))
        self.assertEqual((s.DA_DEFAULT_MAX_TIP_MILLISAT_PER_GAS, s.DA_TIP_ESCALATION_BLOCKS,
                          s.DA_NOT_INCLUDED_ALERT_BLOCKS), (1000, 4, 8))
        custom = self.settler_for(fake, tip_millisat_per_gas=30, tip_step_millisat_per_gas=7,
                                  max_tip_millisat_per_gas=20, tip_escalation_blocks=2, not_included_alert_blocks=5)
        self.assertEqual(custom.da_tip_policy(), (30, 7, 30, 2, 5), 'the cap is never below the start tip')
        # The next tip: unchanged before the escalation blocks, doubled after, from the step at zero, capped.
        policy = self.settler_for(fake, max_tip_millisat_per_gas=100)
        self.assertEqual(policy.da_next_tip(None, 1000), 0)
        self.assertEqual(policy.da_next_tip({'tip': 0, 'height': 1000}, 1003), 0)
        self.assertEqual(policy.da_next_tip({'tip': 0, 'height': 1000}, 1004), 10)
        self.assertEqual(policy.da_next_tip({'tip': 40, 'height': 1000}, 1004), 80)
        self.assertEqual(policy.da_next_tip({'tip': 80, 'height': 1000}, 1010), 100)
        self.assertEqual(policy.da_next_tip({'tip': 100, 'height': 1000}, 1010), 100)
        # An attempt signed by the earlier settler has no height or tip: it is never raised blindly.
        self.assertEqual(policy.da_next_tip({'base_fee': '10'}, 5000), 0)
        self.assertEqual(policy.da_next_tip({'tip': 40, 'height': 1000}, None), 40, 'no height read, no raise')
        off = self.settler_for(fake, tip_escalation_blocks=0)
        self.assertEqual(off.da_next_tip({'tip': 0, 'height': 1000}, 9000), 0, 'escalation can be switched off')

    def test_escalation_off_keeps_the_pinned_behaviour_but_still_alerts(self):
        fake = Auction(self.root, t.statement(user_txs=2), produced_txs=2, clearing_tip=100)
        with mock.patch.object(s, 'log') as logged:
            self.assertFalse(self.settler_for(fake, tip_escalation_blocks=0, inclusion_timeout_seconds=300).cycle())
        self.assertEqual(tips(fake), [0])
        self.assertEqual(self.events(logged, 'da-tip-raised'), [])
        self.assertTrue(self.events(logged, 'da-not-included'))

    def test_the_fee_estimate_counts_the_tip(self):
        self.assertEqual(s.da_fee_sat(1000, 1, 10, 0), 2299)
        self.assertEqual(s.da_fee_sat(1000, 1, 10, 1000) - s.da_fee_sat(1000, 1, 10, 0), 229860)
        # A full batch at the default cap: about 0.02 BLCH of tip.
        self.assertEqual(s.da_fee_sat(s.DA_MAX_PAYLOAD_BYTES, 1, 10, 1000) - s.da_fee_sat(s.DA_MAX_PAYLOAD_BYTES), 2048868)


if __name__ == '__main__':
    unittest.main()
