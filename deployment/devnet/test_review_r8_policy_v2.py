#!/usr/bin/env python3
"""Review r8 (agent 135), run against sequencer policy v2 integrated in settler_v3.py (agent 223, round 11).

Source: agent 135's test_review_r8_policy.py on codex/policy-rereview-r8-20261102 (5129b15), sha1 recorded in
agents/223-policy-v2-int.md. The scenarios and assertions are kept; every change is marked "ADAPTED (a223)" and listed
in that report. Harness changes, all needed because v2 measures differently:
  - the module is sequencer_policy_v2 (Cost, OVER_LIMIT, Policy); the settler config carries max_block_instructions;
  - the fake report carries `nonce`, as the re-landed producer does (`tx_stats`);
  - the fake measurement models the host cycle limit: a block over 2 x the instruction budget ends as OVER_LIMIT in
    10 s, as `BLOCH_PREFLIGHT_CYCLE_LIMIT` does; a cost of None stays a run without cost (host failure, wall backstop);
  - each block advances the wall clock by PACE (600 s): v2 windows are seconds, not blocks (review r7 F6, r8 N9);
  - attackers that the reviewer modelled as TIMEOUT (a 4.9M-gas modexp, 1.06G SP1 gas) are run twice: as modelled
    (no cost) and as the host with the cycle limit sees them (HEAVY, over the cycle limit).

Original header follows.

Review r8 (agent 135): failing tests against the sequencer policy fixes of codex/policy-fixes-r7-20261102 (f4a4bce).

Each test states a property an honest user or the operator needs, against the new logic: cheapest-first ordering, the
2/4/8-block wait of an unmeasurable transaction, the 300,000-gas path when no cost is known, halving the congestion tip
after a block with no user transaction, and block-counted windows under pacing. A failure is the finding; nothing here
fixes code. Run: python3 -B -m unittest -v test_review_r8_policy
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

TIMEOUT = None  # a measurement that hits preflight_execute_seconds
HEAVY = 10_000  # ADAPTED (a223): over the cycle limit (2 x the 100 budget) with any base: OVER_LIMIT
PACE = 600  # ADAPTED (a223): wall seconds between blocks


def h(raw):
    return s.keccak256(bytes.fromhex(raw)).hex()


class Chain(unittest.TestCase):
    """The settler's budget path (`extend_within_budget`) with a fake producer that follows `select.rs`: each sender's
    transactions in nonce order, the best next one by tip across senders, a nonce gap deferred (never dropped), a used
    nonce dropped. The fake measurement adds each included transaction's cost to the block's base; a cost of None is a
    preflight timeout and advances the clock by `preflight_execute_seconds`."""

    BUDGET = 100
    EMPTY_BASE = 2
    DEPOSIT_BASE = 10

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.pool = root / 'txpool'
        self.pool.mkdir()
        self.dir = root / 'work'
        self.dir.mkdir()
        self.deposits = self.dir / 'deposits.json'
        self.deposits.write_text('[]')
        st = self.settler = s.Settler.__new__(s.Settler)
        st.c = {'txpool_dir': str(self.pool), 'max_block_sp1_gas': self.BUDGET, 'max_block_gas': 15_000_000,
                'max_block_bytes': 114_688, 'max_block_txs': 128, 'l2_db': 'x', 'timestamp_rule': None,
                'user_transactions': True, 'max_block_instructions': self.BUDGET}  # ADAPTED (a223)
        st.work = root
        self.now = 0.0
        st.clock = lambda: self.now
        st.next_program = None
        st.program = {"prover": st.c.get("prover"), "prover_args": [], "guest": st.c.get("guest")}
        st.preflight_source = 'request'
        st.spool_open = True
        self.tx = {}  # raw: dict(name, sender, nonce, gas, tip, cost)
        self.nonce = {}  # sender: next nonce, committed
        self.blocks = []
        self.runs_with = {}  # name: measurements that included it
        self.timeouts = 0
        self.logged = []
        mock.patch.object(s, 'log', side_effect=lambda event, **f: self.logged.append((event, f))).start()
        self.addCleanup(mock.patch.stopall)
        st.produce = self.produce
        st.measure_block = self.measure

    # The fake producer

    def select(self, raws):
        queues, dropped = {}, []
        for raw in raws:
            t = self.tx[raw]
            queues.setdefault(t['sender'], []).append(raw)
        for q in queues.values():
            q.sort(key=lambda r: (self.tx[r]['nonce'], -self.tx[r]['tip'], h(r)))
        expected = dict(self.nonce)
        included = []
        while True:
            heads = [(self.tx[q[0]]['tip'], q[0]) for q in queues.values() if q]
            if not heads:
                break
            heads.sort(key=lambda x: (-x[0], h(x[1])))
            raw = heads[0][1]
            t = self.tx[raw]
            queue = queues[t['sender']]
            queue.pop(0)
            want = expected.get(t['sender'], 0)
            if t['nonce'] < want:
                dropped.append({'hash': h(raw), 'reason': 'nonce-too-low'})
                continue
            if t['nonce'] > want or len(included) >= self.settler.c['max_block_txs']:
                queue.clear()  # deferred, with the rest of this sender
                continue
            expected[t['sender']] = want + 1
            included.append(raw)
        return included, dropped, expected

    def report(self, raws):
        included, dropped, _ = self.select(raws)
        return {'included': [h(r) for r in included], 'dropped': dropped, 'transactions': len(included),
                'tx_stats': [{'hash': h(r), 'sender': self.tx[r]['sender'], 'nonce': self.tx[r]['nonce'],  # ADAPTED (a223)
                              'gas_used': self.tx[r]['gas'],
                              'effective_tip': str(self.tx[r]['tip']), 'fresh_slots': []} for r in included]}

    def produce(self, *args):
        pool = args[args.index('--txs') + 1] if '--txs' in args else None
        raws = json.loads(Path(pool).read_text()) if pool and pool.endswith('.json') else (
            [p.read_text().strip() for p in sorted(Path(pool).glob('*.tx'))] if pool else [])
        if args[0] == 'select':
            return self.report(raws)
        included, _, expected = self.select(raws)
        self.nonce = expected
        self.blocks.append([self.tx[r]['name'] for r in included])
        return self.report(raws)

    def measure(self, parent, anchor, deposits, slot, number, raws, tag):
        included, _, _ = self.select(raws)
        for r in included:
            self.runs_with[self.tx[r]['name']] = self.runs_with.get(self.tx[r]['name'], 0) + 1
        costs = [self.tx[r]['cost'] for r in included]
        base = self.DEPOSIT_BASE if json.loads(Path(deposits).read_text()) else self.EMPTY_BASE
        if any(c is None for c in costs):
            self.now += self.settler.c.get('preflight_execute_seconds', 120)
            self.timeouts += 1
            return None, self.report(raws)
        total = base + sum(costs)
        if total > 2 * self.BUDGET:  # ADAPTED (a223): the host's cycle limit ends the run early with its verdict
            self.now += 10
            return sp.OVER_LIMIT, self.report(raws)
        self.now += 2
        return sp.Cost(total, total), self.report(raws)

    # Helpers

    def add(self, name, sender, nonce, gas, cost, tip=10**9):
        raw = name.encode().hex()
        self.tx[raw] = dict(name=name, sender=sender, nonce=nonce, gas=gas, tip=tip, cost=cost)
        (self.pool / f'{name}.tx').write_text(raw + '\n')
        return raw

    def block(self, number, deposits=False):
        self.deposits.write_text('[{"sats": 1000000}]' if deposits else '[]')
        self.now += PACE  # ADAPTED (a223)
        self.settler.extend('p', 'a', self.deposits, 1, number)
        return self.blocks[-1]

    def spooled(self):
        return sorted(p.stem for p in self.pool.glob('*.tx'))

    def quarantined(self):
        q = self.pool.with_name('txpool-quarantine')
        return sorted(p.stem for p in q.glob('*.tx')) if q.exists() else []

    def state(self):
        return json.loads((self.settler.work / 'sequencer-policy.json').read_text())


class N1CheapestFirstSplitsASendersNonces(Chain):
    """Cheapest-first by gas used tries a sender's later, cheaper nonce before its earlier one. A bisection prefix can then
    hold nonce n+1 without nonce n. The producer defers n+1 (nonce gap), but the plan lists it as chosen, and the settler
    removes every chosen transaction's spool file once the block is committed: n+1 is deleted without being included."""

    def test_a_later_nonce_that_was_not_included_stays_in_the_spool(self):
        # alice: a 400k-gas call (nonce 0) then a 21k-gas transfer (nonce 1). bob: one 100k-gas call. All three exceed
        # the 100 budget together (10 + 50 + 5 + 45); alice's call fits alone and goes in the next block.
        self.add('a0-call', 'alice', 0, 400_000, 50)
        self.add('a1-transfer', 'alice', 1, 21_000, 5)
        self.add('b0-call', 'bob', 0, 100_000, 45)
        first = self.block(2, deposits=True)
        self.assertEqual(first, ['b0-call'])
        self.assertIn('a1-transfer', self.spooled(),
                      f'alice nonce 1 was not in block 2 ({first}) but its spool file is gone: {self.spooled()}')

    def test_both_nonces_of_a_sender_are_eventually_included(self):
        self.add('a0-call', 'alice', 0, 400_000, 50)
        self.add('a1-transfer', 'alice', 1, 21_000, 5)
        self.add('b0-call', 'bob', 0, 100_000, 45)
        included = [n for b in (self.block(n, deposits=True) for n in range(2, 7)) for n in b]
        self.assertIn('a0-call', included)
        self.assertIn('a1-transfer', included, f'alice nonce 1 lost; blocks {self.blocks}, spool {self.spooled()}')


class N2CheapestFirstIgnoresTheTip(Chain):
    """The bisection keeps the longest prefix, in gas-used order, that fits the budget: the tip never decides which
    transactions get the block's budget. An attacker paying the floor tip with low-gas, SP1-heavy transactions (small
    modexp calls) fills every block, and an honest transaction with more gas waits for ever, whatever tip it pays."""

    def test_a_higher_tip_buys_room_in_a_full_block(self):
        floor = 10**8
        self.settler.c['min_tip_wei'] = floor
        self.add('honest-swap', 'honest', 0, 150_000, 20, tip=100 * floor)  # 100x the attacker's tip
        served = None
        for number in range(2, 12):
            for i in range(7):  # 7 x 100k-gas modexp calls at the floor tip, 12 each: 10 + 84 fits, + 20 does not
                self.add(f'm{number:02d}{i}', f'attacker{i}', self.nonce.get(f'attacker{i}', 0), 100_000, 12, tip=floor)
            if 'honest-swap' in self.block(number, deposits=True):
                served = number
                break
        self.assertIsNotNone(served, f'the honest swap at 100x the tip was held in all 10 blocks; last block {self.blocks[-1]}')


class N3ReplacementResetsTheUnmeasuredCount(Chain):
    """The 2/4/8-block wait and the quarantine at the 4th failed run are keyed by transaction hash. The RPC admits a
    same-nonce replacement with a 10% higher fee, which has a new hash: the count starts again at zero and the wait is
    gone. A sender that replaces its unmeasurable transaction after each block is measured, with timeouts, in every
    block, is never quarantined, never struck, and pays nothing."""

    def setUp(self):
        super().setUp()
        self.settler.c.update(preflight_execute_seconds=30, preflight_max_seconds=180, strike_cooldown_blocks=32)

    def test_a_replaced_unmeasurable_transaction_is_quarantined_and_its_sender_struck(self):
        tip, current = 10**9, None
        for number in range(2, 22):
            if current:
                (self.pool / f'{current}.tx').unlink(missing_ok=True)  # the RPC's replacement removes the old entry
            tip = tip * 11 // 10
            current = f'evil{number:02d}'
            self.add(current, 'mallory', 0, 4_900_000, TIMEOUT, tip=tip)
            self.block(number)
            if self.quarantined():
                break
        self.assertTrue(self.quarantined() or 'mallory' in self.state()['bans'],  # ADAPTED (a223): v2 bans, no strikes
                        f'20 blocks, {self.timeouts} preflight timeouts ({self.timeouts * 30} s of measuring), '
                        f'nothing quarantined, no strike')

    def test_no_unmeasurable_transaction_costs_every_block_a_measurement(self):
        # Agent 90's F1 fix: "No over-budget transaction now costs every block a bisection."
        tip, current, measured_blocks = 10**9, None, 0
        for number in range(2, 22):
            if current:
                (self.pool / f'{current}.tx').unlink(missing_ok=True)
            tip = tip * 11 // 10
            current = f'evil{number:02d}'
            self.add(current, 'mallory', 0, 4_900_000, TIMEOUT, tip=tip)
            before = self.timeouts
            self.block(number)
            measured_blocks += self.timeouts > before
        self.assertLessEqual(measured_blocks, 4, f'the replaced transaction timed out a measurement in {measured_blocks} '
                                                 f'of 20 blocks')


class N4ZeroFeeSendersAtScale(Chain):
    """Without replacement: each unmeasurable transaction now gets four rounds (blocks n, n+2, n+6, n+14) before its
    quarantine, and its sender is struck only then. Every round costs the full-block run, the bisection runs that hold it
    and its alone run, each up to `preflight_execute_seconds`. Before the fix, the first round quarantined it and struck
    the sender. Each funded sender, paying nothing, now buys four times the measuring time it bought before."""

    def setUp(self):
        super().setUp()
        self.settler.c.update(preflight_execute_seconds=30, preflight_max_seconds=180, strike_cooldown_blocks=32)

    def test_timeouts_per_zero_fee_transaction_stay_at_the_pre_fix_bound(self):
        self.add('evil', 'mallory', 0, 4_900_000, TIMEOUT)
        for number in range(2, 20):
            self.block(number)
            if self.quarantined():
                break
        # Before the fix: the block run and the alone run, then quarantine (2 timeouts).
        self.assertLessEqual(self.timeouts, 2, f'{self.timeouts} timeouts ({self.timeouts * 30} s) before quarantine, '
                                               f'quarantined at block {number}')


class N5HeldInTheDepositBand(Chain):
    """A transaction over the budget only with this block's deposits waits as 'deposits-fill-the-block' with no wait and
    no count: it is measured again in every block that has a deposit. While no deposit-free block was measured,
    `empty_base` is 0, so the band is everything between the budget minus the deposit-only base and the budget. Six
    such transactions use the 16 runs of every block with a deposit; an honest transaction with more gas is never
    measured."""

    def test_deposit_band_transactions_do_not_cost_every_block_a_bisection(self):
        for i in range(6):  # share 95: 10 + 95 > 100 with a deposit, 2 + 95 <= 100 without
            self.add(f'band{i}', f'mallory{i}', 0, 600_000, 95)
        for number in range(2, 12):
            self.block(number, deposits=True)
        self.assertLessEqual(self.runs_with.get('band0', 0), 8,
                             f'band0 was measured {self.runs_with.get("band0")} times in 10 blocks, never quarantined '
                             f'({self.quarantined()})')

    def test_an_honest_transaction_with_more_gas_is_served(self):
        for i in range(6):
            self.add(f'band{i}', f'mallory{i}', 0, 600_000, 95)
        self.add('honest-deploy', 'honest', 0, 2_000_000, 40)
        included = [n for b in (self.block(n, deposits=True) for n in range(2, 12)) for n in b]
        self.assertIn('honest-deploy', included, f'10 blocks with a deposit, the honest deployment never measured')




class N3N4WithTheCycleLimit(Chain):
    """ADAPTED (a223): N3, N3b and N4 with the attacker as the host with the cycle limit sees a 4.9M-gas modexp (HEAVY:
    OVER_LIMIT). Same loops and the same assertions as above."""

    def setUp(self):
        super().setUp()
        self.settler.c.update(preflight_execute_seconds=30, preflight_max_seconds=180)

    def test_a_replaced_heavy_transaction_is_quarantined_and_its_sender_banned(self):
        tip, current = 10**9, None
        for number in range(2, 22):
            if current:
                (self.pool / f'{current}.tx').unlink(missing_ok=True)
            tip = tip * 11 // 10
            current = f'evil{number:02d}'
            self.add(current, 'mallory', 0, 4_900_000, HEAVY, tip=tip)
            self.block(number)
            if self.quarantined():
                break
        self.assertTrue(self.quarantined() and 'mallory' in self.state()['bans'])

    def test_a_replaced_heavy_transaction_does_not_cost_every_block_a_measurement(self):
        tip, current, measured_blocks = 10**9, None, 0
        for number in range(2, 22):
            if current:
                (self.pool / f'{current}.tx').unlink(missing_ok=True)
            tip = tip * 11 // 10
            current = f'evil{number:02d}'
            self.add(current, 'mallory', 0, 4_900_000, HEAVY, tip=tip)
            before = self.runs_with.get(current, 0)
            self.block(number)
            measured_blocks += self.runs_with.get(current, 0) > before
        self.assertLessEqual(measured_blocks, 4, f'measured in {measured_blocks} of 20 blocks')

    def test_a_heavy_transaction_costs_no_timeout(self):
        self.add('evil', 'mallory', 0, 4_900_000, HEAVY)
        for number in range(2, 20):
            self.block(number)
            if self.quarantined():
                break
        self.assertEqual((self.timeouts, self.quarantined(), self.runs_with.get('evil')), (0, ['evil'], 1))

class N6NoCostIsNotUnderBudget(Chain):
    """When the deposit-only block has no cost, it must stay deposit-only and write its record (r8 N6)."""

    def test_a_timed_out_deposit_only_block_is_recorded_and_carries_no_user_transaction(self):
        self.settler.c.update(preflight_execute_seconds=30)
        real = self.measure

        def measure(parent, anchor, deposits, slot, number, raws, tag):
            if json.loads(Path(deposits).read_text()):
                self.now += 30
                return None, self.report(raws)  # 64 deposits to code-heavy contracts: the execute hits its limit
            return real(parent, anchor, deposits, slot, number, raws, tag)
        self.settler.measure_block = measure
        self.add('swap', 'alice', 0, 250_000, 30)
        block = self.block(2, deposits=True)
        record = self.dir / 'deposits-over-budget.json'
        self.assertTrue(block == [] and record.exists(),
                        f'block with unmeasured deposits carries {block}; deposits-over-budget.json written: {record.exists()}')

    def test_one_large_transaction_does_not_keep_the_unmeasured_block_empty(self):
        # ADAPTED (a223): v2 has no unmeasured 300k path. A prover without the cost line is refused at the first block
        # (check_cost_line, spec 3.4), so no block is ever "unmeasured": the property becomes "the settler refuses".
        self.settler.measure_block = lambda *a: (None, self.report(a[5]))  # a prover without the cost line
        self.add('big', 'mallory', 0, 400_000, 10, tip=10**11)
        self.add('transfer', 'alice', 0, 21_000, 1, tip=10**9)
        with self.assertRaises(s.Halt):
            self.block(2, deposits=True)
        self.assertEqual(self.blocks, [])

    def test_without_the_per_transaction_report_the_gas_cap_still_holds(self):
        # ADAPTED (a223): v2 takes nothing without tx_stats (no-selection-report); the 300k path does not exist.
        for i in range(40):
            self.add(f'big{i}', f'u{i}', 0, 1_000_000, 10)
        report, produce = self.report, self.produce
        self.settler.produce = lambda *a: (lambda r: {k: v for k, v in r.items() if k != 'tx_stats'})(
            report(json.loads(Path(a[a.index('--txs') + 1]).read_text()))) if a[0] == 'select' else produce(*a)
        self.assertEqual(self.block(2, deposits=True), [])
        self.assertEqual(len(self.spooled()), 40)


class N7CongestionHalvingUnderAlternation(unittest.TestCase):
    """ADAPTED (a223): the same patterns against v2's congestion tip (per-block steps, up 1/8, down 1/16; time decay only
    after 4,500 s idle), with the owner's cap of 3 gwei (agents/OWNER-DECISIONS-R10.md). The attacker's blocks are
    PACE apart."""

    CONFIG = dict(max_block_sp1_gas=150_000_000, max_block_instructions=150_000_000, min_tip_wei=10**8,
                  congestion_max_tip_wei=3 * 10**9)

    def run_pattern(self, full, empty, blocks, interval=PACE):
        now = [0.0]
        planner = sp.Policy(self.CONFIG, clock=lambda: now[0])
        paid = 0
        for number in range(blocks):
            plan = sp.Plan()
            plan.base = sp.Cost(2_000_000, 1)
            if number % (full + empty) < full:
                paid += planner.required_tip()
                plan.cost = sp.Cost(150_000_000, 1)  # saturated: ratio 2
            else:
                plan.cost = plan.base  # no user transaction in this block
            planner.committed(plan, {'included': []})
            now[0] += interval
        return planner.required_tip(), paid

    def test_a_five_in_six_saturating_attacker_faces_a_rising_tip(self):
        tip, paid = self.run_pattern(5, 1, 600)
        self.assertGreater(tip, 10 * 10**8, f'after 600 blocks (500 saturated) the required tip is {tip / 1e9:.3f} gwei')

    def test_a_one_in_two_saturating_attacker_faces_a_rising_tip(self):
        tip, paid = self.run_pattern(1, 1, 600)
        self.assertGreater(tip, 10**8, f'after 600 blocks (300 saturated) the required tip is {tip / 1e9:.3f} gwei')


class N8BackoffIsDemand(unittest.TestCase):
    """ADAPTED (a223): v2's wait lives in `waits` (sender:nonce, until in seconds); demand is `policy_demand`."""

    def test_a_transaction_waiting_out_a_failed_measurement_is_not_demand(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'txpool').mkdir()
        raw = 'ee' * 8
        (root / 'txpool' / 'evil.tx').write_text(raw)
        settler = s.Settler.__new__(s.Settler)
        settler.c = {'txpool_dir': str(root / 'txpool'), 'max_block_sp1_gas': 100, 'max_block_instructions': 100,
                     'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 128,
                     'l2_db': str(root / 'db'), 'timestamp_rule': None, 'user_transactions': True}
        settler.work, settler.clock, settler.spool_open = root, lambda: 1000.0, True
        settler.next_program = None
        name = h(raw)
        (root / 'sequencer-policy.json').write_text(json.dumps(
            {'waits': {'mallory:0': {'until': 1600.0, 'kind': 'unmeasured'}}}))
        settler.produce = lambda *a: {'included': [name], 'dropped': [], 'tx_stats': [
            {'hash': name, 'sender': 'mallory', 'nonce': 0, 'gas_used': 4_900_000, 'effective_tip': str(10**9),
             'fresh_slots': []}]}
        view = {'source': {'block': 'aa' * 32, 'pending': [], 'request': 'a\nb\nc\n7\n'}, 'accepted': None}
        with mock.patch.object(s, 'log'):
            demand = settler.spool_demand('bb' * 32, view)
        passing, refused = settler.policy().gate(settler.produce()['tx_stats'], 1000.0, False)
        self.assertEqual(refused, {name: ('unmeasured-wait', False)})
        self.assertFalse(demand, 'the entry the plan holds for its wait makes the block due')


class N9BlockCountedWaitUnderPacing(Chain):
    """ADAPTED (a223): the same honest transaction (two failed runs per round on a loaded host) through the settler with
    blocks 1,800 s apart; the tries must fall inside the RPC's 3 h TTL."""

    def test_an_honest_transaction_gets_three_tries_before_the_rpc_evicts_it(self):
        self.settler.c.update(preflight_execute_seconds=30)
        self.add('honest', 'alice', 0, 21_000, 1)
        tries, first = [], None
        real = self.measure

        def measure(parent, anchor, deposits, slot, number, raws, tag):
            if raws and len(tries) < 3 * 2:  # the first three rounds fail (block run and alone run)
                tries.append(self.now)
                self.now += 30
                return None, self.report(raws)
            return real(parent, anchor, deposits, slot, number, raws, tag)
        self.settler.measure_block = measure
        for number in range(2, 30):
            self.now += 1800 - PACE
            if 'honest' in self.block(number) or self.quarantined():
                break
        rounds = sorted({round(t) // 60 for t in tries})
        first = tries[0]
        self.assertLess(max(tries) - first, 3 * 3600, f'tries at {[(t - first) / 3600 for t in tries]} h')


class Controls(Chain):
    """The harness is fair: without the attack each property holds."""

    def test_both_nonces_in_one_block_when_the_block_fits(self):
        self.add('a0-call', 'alice', 0, 400_000, 50)
        self.add('a1-transfer', 'alice', 1, 21_000, 5)
        self.assertEqual(sorted(self.block(2, deposits=True)), ['a0-call', 'a1-transfer'])
        self.assertEqual(self.spooled(), [])

    def test_the_honest_swap_is_served_without_the_flood(self):
        self.add('honest-swap', 'honest', 0, 150_000, 20)
        self.assertEqual(self.block(2, deposits=True), ['honest-swap'])

    def test_band_transactions_fit_a_block_without_deposits(self):
        self.add('band0', 'mallory0', 0, 600_000, 95)
        self.assertEqual(self.block(2), ['band0'])

    def test_an_unmeasurable_transaction_is_quarantined_at_its_fourth_round_without_replacement(self):
        self.add('evil', 'mallory', 0, 4_900_000, TIMEOUT)
        rounds = []
        for number in range(2, 20):
            before = self.timeouts
            self.block(number)
            if self.timeouts > before:
                rounds.append(number)
            if self.quarantined():
                break
        # ADAPTED (a223): v2's schedule for a run without cost is t, t+10 min, t+40 min, quarantine at the third failure
        # (spec 3.4); with PACE 600 s per block that is blocks 2, 3 and 6.
        self.assertEqual((rounds, self.quarantined()), ([2, 3, 6], ['evil']))

    def test_sustained_saturation_raises_the_tip(self):
        tip, _ = N7CongestionHalvingUnderAlternation.run_pattern(N7CongestionHalvingUnderAlternation(), 1, 0, 60)
        self.assertGreater(tip, 10 * 10**8)  # ADAPTED (a223): v2 API


if __name__ == '__main__':
    unittest.main()
