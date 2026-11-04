#!/usr/bin/env python3
"""Review r9 (agent 135), run against sequencer policy v2 integrated in settler_v3.py (agent 223, round 11).

Source: agent 135's test_review_r9_policy.py on codex/policy-rereview-r9-20261102 (7dd3d25). It builds on
test_review_r8_policy_v2 (see that file for the harness changes). Every change is marked "ADAPTED (a223)". The
installer defaults the original names (no strike, 120 s / 600 s) are replaced by v2's defaults (no strike exists; 24 h
ban; 60 s backstop; 180 s per block) where the original relied on them, as noted.

Original header follows.

Review r9 (agent 135): failing tests against the round-8 rules of codex/policy-fixes-r7-20261102 (042cad6, fixes f6ac754).

Targets: the n, n+1, n+3 retry and the 300,000-gas cutoff for a transaction with no cost, the unpaid high tip that buys
measuring time under tip order, the deposit-free wait of 16 blocks, and the time-decayed congestion tip. Defaults are the
mainnet installer's (`install-settler-mainnet.py configure`): no `strike_cooldown_blocks`, no congestion settings,
`preflight_execute_seconds` 120 and `preflight_max_seconds` 600, unless a test says otherwise. A failure is the finding.
Run: python3 -B -m unittest -v test_review_r9_policy
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import sequencer_policy_v2 as sp  # noqa: E402  ADAPTED (a223)
import test_review_r8_policy_v2 as r8  # noqa: E402  ADAPTED (a223)

TIMEOUT = None
HEAVY = r8.HEAVY  # ADAPTED (a223): over the host's cycle limit


class Chain(r8.Chain):
    """Agent 135's round-8 harness, with `nonce` in the per-transaction report as the round-8 producer gives it, and a
    per-transaction count of measurements that fail before it measures normally (a loaded host)."""

    def setUp(self):
        super().setUp()
        self.fail_first = {}  # name: measurements that include it and fail before it measures

    def report(self, raws):
        out = super().report(raws)
        for t in out['tx_stats']:
            raw = next(r for r in raws if r8.h(r) == t['hash'])
            t['nonce'] = self.tx[raw]['nonce']
        return out

    def measure(self, parent, anchor, deposits, slot, number, raws, tag):
        included, _, _ = self.select(raws)
        failing = [r for r in included if self.fail_first.get(self.tx[r]['name'], 0) > 0]
        if failing:
            for r in failing:
                self.fail_first[self.tx[r]['name']] -= 1
            self.now += self.settler.c.get('preflight_execute_seconds', 120)
            self.timeouts += 1
            return None, self.report(raws)
        return super().measure(parent, anchor, deposits, slot, number, raws, tag)

    def resend(self, name, sender, nonce, gas, cost, tip):
        """The attacker sends the same nonce again (new bytes) once its last one left the spool for quarantine."""
        return self.add(name, sender, nonce, gas, cost, tip=tip)


class U1UnpaidTipBuysMeasuringTime(Chain):
    """Tip order: an attacker's transaction at a high tip it never pays is tried first. With no cost and more than 300k gas
    it is quarantined at once, but only after a full-block timeout and a bisection timeout. The quarantined transaction
    was never executed, so its nonce is free: the same sender sends it again. Without `strike_cooldown_blocks` (the
    installer sets none) nothing stops that; with a strike, a pool of senders funded once and reused after the cooldown
    does the same. Three per block spend the whole measuring allowance, and the honest transaction is never measured.
    No fee is ever paid; the attackers' balances are only held."""

    def test_installer_defaults_three_resending_senders_do_not_keep_an_honest_transfer_out(self):
        self.add('honest', 'alice', 0, 21_000, 1, tip=10**9)
        sent = {}
        for number in range(2, 22):
            for i in range(3):
                name = f'evil{i}-{sent.get(i, 0)}'
                if not (self.pool / f'{name}.tx').exists():
                    sent[i] = sent.get(i, 0) + 1
                    self.resend(f'evil{i}-{sent[i]}', f'mallory{i}', 0, 4_900_000, TIMEOUT, tip=10**11)
            if 'honest' in self.block(number):
                break
        served = [n for n, b in enumerate(self.blocks, start=2) if 'honest' in b]
        self.assertTrue(served, f'20 blocks: honest never served; {self.timeouts} timeouts '
                                f'({self.timeouts * 120 / 3600:.1f} h of measuring), {len(self.quarantined())} quarantined, '
                                f'fee paid by the attackers: 0')

    def test_with_a_strike_a_reused_sender_pool_does_not_keep_an_honest_transfer_out(self):
        self.settler.c.update(strike_cooldown_blocks=32, preflight_execute_seconds=30, preflight_max_seconds=180)
        self.add('honest', 'alice', 0, 21_000, 1, tip=10**9)
        pool, at = [f'mallory{i}' for i in range(3 * 33)], 0
        for number in range(2, 42):
            for _ in range(3):  # three senders per block from a pool of 99 funded once; each is free again after 32 blocks
                sender = pool[at % len(pool)]
                at += 1
                self.resend(f'evil-{number}-{sender}', sender, 0, 4_900_000, TIMEOUT, tip=10**11)
            if 'honest' in self.block(number):
                break
        served = [n for n, b in enumerate(self.blocks, start=2) if 'honest' in b]
        self.assertTrue(served, f'40 blocks: honest never served; {self.timeouts} timeouts, '
                                f'{len(self.quarantined())} quarantined, 99 senders funded once, fee paid: 0')

    def test_control_one_attacker_per_block_does_not_keep_it_out(self):
        self.settler.c.update(preflight_execute_seconds=30, preflight_max_seconds=180)
        self.add('honest', 'alice', 0, 21_000, 1, tip=10**9)
        self.add('evil', 'mallory', 0, 4_900_000, TIMEOUT, tip=10**11)
        self.assertIn('honest', self.block(2))


class U2CutoffQuarantinesHonestHeavyTransactions(Chain):
    """Above `unmeasured_retry_max_gas` (300,000 gas) a transaction with no cost goes to quarantine at its first failed
    round, and its sender is struck. On a loaded host (report 90: about 34 s per run at load 60, against 30 s) an honest
    deployment or a large swap whose runs time out once is lost: this is review r7 F2 again, for every transaction above
    300k gas."""

    def test_an_honest_400k_gas_deployment_survives_one_slow_round(self):
        self.settler.c.update(preflight_execute_seconds=30, strike_cooldown_blocks=32)
        self.add('deploy', 'alice', 0, 400_000, 20)
        self.fail_first['deploy'] = 2  # the block run and the alone run hit the limit; the host recovers afterwards
        # ADAPTED (a223): v2 retries a run without cost after 10 and 40 minutes (spec 3.4), so the window is the RPC's
        # 3 h TTL at PACE (600 s) per block, not 4 blocks.
        included = [n for b in (self.block(n) for n in range(2, 2 + 3 * 3600 // r8.PACE)) for n in b]
        self.assertTrue('deploy' in included and not self.quarantined(),
                        f'quarantined: {self.quarantined()}, bans: {self.state()["bans"]}')  # ADAPTED (a223)


class U3RetryResetsAfterQuarantine(Chain):
    """The n, n+1, n+3 schedule ends in quarantine and pops the wait. Without a strike (installer default) the sender sends
    the same nonce again at once and gets three more tries: a cheap transaction that cannot be measured (complete guest,
    a read of an inflated account) times a measurement out in most blocks, for no fee."""

    def test_a_cheap_unmeasurable_transaction_resent_after_quarantine_is_not_measured_in_most_blocks(self):
        self.settler.c.update(preflight_execute_seconds=30)
        sent, measured = 0, 0
        for number in range(2, 22):
            if not (self.pool / f'cheap{sent}.tx').exists():
                sent += 1
                self.resend(f'cheap{sent}', 'mallory', 0, 30_000, TIMEOUT, tip=10**9)
            before = self.timeouts
            self.block(number)
            measured += self.timeouts > before
        self.assertLessEqual(measured, 6, f'timed out a measurement in {measured} of 20 blocks; {sent} sends, '
                                          f'{len(self.quarantined())} quarantined, fee 0')



class U1U3WithTheCycleLimit(Chain):
    """ADAPTED (a223): U1 and U3 with the attackers as the host with the cycle limit sees them (HEAVY: OVER_LIMIT). The
    loops and assertions are U1's and U3's."""

    def test_three_resending_heavy_senders_do_not_keep_an_honest_transfer_out(self):
        self.add('honest', 'alice', 0, 21_000, 1, tip=10**9)
        sent = {}
        for number in range(2, 22):
            for i in range(3):
                name = f'evil{i}-{sent.get(i, 0)}'
                if not (self.pool / f'{name}.tx').exists():
                    sent[i] = sent.get(i, 0) + 1
                    self.resend(f'evil{i}-{sent[i]}', f'mallory{i}', 0, 4_900_000, HEAVY, tip=10**11)
            if 'honest' in self.block(number):
                break
        self.assertTrue([n for n, b in enumerate(self.blocks, start=2) if 'honest' in b])

    def test_a_reused_pool_of_heavy_senders_does_not_keep_an_honest_transfer_out(self):
        self.settler.c.update(preflight_execute_seconds=30, preflight_max_seconds=180)
        self.add('honest', 'alice', 0, 21_000, 1, tip=10**9)
        pool, at = [f'mallory{i}' for i in range(3 * 33)], 0
        for number in range(2, 42):
            for _ in range(3):
                sender = pool[at % len(pool)]
                at += 1
                self.resend(f'evil-{number}-{sender}', sender, 0, 4_900_000, HEAVY, tip=10**11)
            if 'honest' in self.block(number):
                break
        self.assertTrue([n for n, b in enumerate(self.blocks, start=2) if 'honest' in b])

    def test_a_cheap_heavy_transaction_resent_after_quarantine_is_not_measured_in_most_blocks(self):
        sent, measured = 0, 0
        for number in range(2, 22):
            if not (self.pool / f'cheap{sent}.tx').exists():
                sent += 1
                self.resend(f'cheap{sent}', 'mallory', 0, 30_000, HEAVY, tip=10**9)
            before = sum(self.runs_with.values())
            self.block(number)
            measured += sum(self.runs_with.values()) > before
        self.assertLessEqual(measured, 6, f'measured in {measured} of 20 blocks; {sent} sends')


class U4BandWaitIsNotDemand(unittest.TestCase):
    """A transaction over the budget only with deposits waits for a block without deposits (`band_wait_blocks` 16 at
    most). Under skip_idle_blocks a block without deposits is built only on demand, but `spool_demand` calls the gate with
    its default `has_deposits=True`, so the waiting transaction is no demand when the next block would carry no deposit.
    It waits for 16 deposit blocks or `max_idle_seconds` (86,400 s by default), then is measured again with deposits."""

    def test_a_band_transaction_is_demand_when_the_next_block_has_no_deposit(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'txpool').mkdir()
        raw = 'bd' * 8
        (root / 'txpool' / 'band.tx').write_text(raw)
        settler = s.Settler.__new__(s.Settler)
        settler.c = {'txpool_dir': str(root / 'txpool'), 'max_block_sp1_gas': 100, 'max_block_gas': 15_000_000,
                     'max_block_bytes': 114_688, 'max_block_txs': 128, 'l2_db': str(root / 'db'), 'timestamp_rule': None,
                     'user_transactions': True, 'max_block_instructions': 100}  # ADAPTED (a223)
        settler.work, settler.clock, settler.spool_open = root, lambda: 0, True
        name = r8.h(raw)
        (root / 'sequencer-policy.json').write_text(json.dumps(  # ADAPTED (a223): v2 wait record (seconds)
            {'waits': {'alice:0': {'until': 7200, 'kind': 'band'}}}))
        settler.produce = lambda *a: {'included': [name], 'dropped': [], 'tx_stats': [
            {'hash': name, 'sender': 'alice', 'nonce': 0, 'gas_used': 600_000, 'effective_tip': str(10**9),
             'fresh_slots': []}]}
        view = {'source': {'block': 'aa' * 32, 'pending': [], 'request': 'a\nb\nc\n7\n'}, 'accepted': None}
        with mock.patch.object(s, 'log'):
            demand = settler.spool_demand('bb' * 32, view)  # ADAPTED (a223): 4b984af signature (head, view)
        passing, _ = settler.policy().gate(settler.produce()['tx_stats'], 0, False)  # ADAPTED (a223): v2 API
        self.assertEqual(passing, [name], 'control: the plan of a deposit-free block takes it')
        self.assertTrue(demand, 'the next block has no deposit and would take it, but it is no demand')


class U5TimeDecayOnlyWhenABlockIsBuilt(unittest.TestCase):
    """The tip decays in `committed`, by the time since the last block. `required_tip()` and so the gate in
    `spool_demand` read the stored tip without that decay. Under skip_idle_blocks, a floor-tip transaction is below the
    required tip, so it is no demand, so no block is built, so the tip never decays: after a spike it waits for a deposit
    or `max_idle_seconds`, and the RPC evicts it at 3 h. Agent 90's adapted R6 commits a block every pace, which an idle
    chain does not do."""

    def test_three_quiet_hours_after_a_spike_make_a_floor_tip_transfer_demand(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'txpool').mkdir()
        raw = 'f1' * 8
        (root / 'txpool' / 'floor.tx').write_text(raw)
        settler = s.Settler.__new__(s.Settler)
        settler.c = {'txpool_dir': str(root / 'txpool'), 'max_block_sp1_gas': 150_000_000, 'max_block_gas': 15_000_000,
                     'max_block_bytes': 114_688, 'max_block_txs': 128, 'l2_db': str(root / 'db'), 'timestamp_rule': None,
                     'user_transactions': True, 'min_tip_wei': 10**8, 'max_block_instructions': 150_000_000,
                     'congestion_max_tip_wei': 3 * 10**9}  # ADAPTED (a223): v2 keys, owner's 3 gwei cap
        settler.work, settler.spool_open = root, True
        settler.clock = lambda: 10_000.0 + 3 * 3600  # three hours after the last block
        (root / 'sequencer-policy.json').write_text(json.dumps({'tip': 10**9, 'last_block_time': 10_000.0}))  # ADAPTED (a223)
        name = r8.h(raw)
        settler.produce = lambda *a: {'included': [name], 'dropped': [], 'tx_stats': [
            {'hash': name, 'sender': 'alice', 'nonce': 0, 'gas_used': 21_000, 'effective_tip': str(10**8),
             'fresh_slots': []}]}
        view = {'source': {'block': 'aa' * 32, 'pending': [], 'request': 'a\nb\nc\n7\n'}, 'accepted': None}
        with mock.patch.object(s, 'log'):
            demand = settler.spool_demand('bb' * 32, view)  # ADAPTED (a223)
        self.assertTrue(demand, 'after 3 h (6 half-lives) the floor-tip transfer is still below the stored 1 gwei tip')


class U6TimeDecayAtProofCadence(unittest.TestCase):
    """Growth is per congested block (at most 12.5% with D6), decay is per second since the last block. A block at the
    150M budget takes about 1,772 s to prove (report 90, h4097), so the one uncongested block after it decays by about
    one half-life: the same halving as review r8 N7. A 5-of-6 saturating attacker stays at the floor."""

    CONFIG = dict(max_block_sp1_gas=150_000_000, max_block_instructions=150_000_000, min_tip_wei=10**8,
                  congestion_max_tip_wei=3 * 10**9)  # ADAPTED (a223): v2 keys, owner's 3 gwei cap

    def run_pattern(self, full, empty, blocks, interval):
        now = [0.0]
        planner = sp.Policy(self.CONFIG, clock=lambda: now[0])  # ADAPTED (a223)
        for number in range(blocks):
            plan = sp.Plan()
            plan.base = sp.Cost(2_000_000, 1)
            plan.cost = sp.Cost(150_000_000, 1) if number % (full + empty) < full else plan.base
            planner.committed(plan, {'included': []})  # ADAPTED (a223)
            now[0] += interval
        return planner.required_tip()

    def test_a_five_in_six_attacker_at_the_proof_cadence_faces_a_rising_tip(self):
        tip = self.run_pattern(5, 1, 600, 1800)
        self.assertGreater(tip, 10 * 10**8, f'600 blocks at 1,800 s, 500 saturated: tip {tip / 1e9:.3f} gwei')

    def test_a_two_in_three_attacker_at_ten_minutes_faces_a_rising_tip(self):
        tip = self.run_pattern(2, 1, 600, 600)
        self.assertGreater(tip, 10 * 10**8, f'600 blocks at 600 s, 400 saturated: tip {tip / 1e9:.3f} gwei')

    def test_control_sustained_saturation_still_raises_the_tip(self):
        self.assertGreater(self.run_pattern(1, 0, 60, 1800), 10 * 10**8)


if __name__ == '__main__':
    unittest.main()
