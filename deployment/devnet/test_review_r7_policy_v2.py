#!/usr/bin/env python3
"""Review r7 (agent 121), run against sequencer policy v2 integrated in settler_v3.py (agent 223, round 11).

Source: agent 121's test_review_r7_policy.py on codex/policy-review-r7-20261102 (d03326c). Every change is marked
"ADAPTED (a223)" and listed in agents/223-policy-v2-int.md. Harness: sequencer_policy_v2; both budget keys; a
transaction over any budget (HEAVY) ends at the host's cycle limit (OVER_LIMIT, 10 s) instead of a timeout, since that
is what BLOCH_PREFLIGHT_CYCLE_LIMIT makes of it; a failed run (fail_runs) is still a run without cost.

Original header follows.

Review r7 (agent 121): failing tests against the sequencer policy of griefing-limits-r5 merged with idle-blocks-r5.

Each test states the property an honest user or the operator needs. A failure is the finding; nothing here fixes code.
Run: python3 -m unittest -v deployment/devnet/test_review_r7_policy.py
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
import test_settler_foreign as foreign  # noqa: E402

HEAVY = 10_000_000  # over any budget alone: the fake measurement then reports no cost (timeout), as for a 1G-SP1 modexp


class Harness(unittest.TestCase):
    """The settler's budget path with a fake producer and a fake measurement (as in test_settler_budget.py), plus a clock
    that measurement advances, so that the per-block time bound of the recommended settings applies."""

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
        self.settler = s.Settler.__new__(s.Settler)
        self.settler.c = {'txpool_dir': str(self.pool), 'max_block_sp1_gas': 100, 'max_block_gas': 1, 'max_block_bytes': 1,
                          'max_block_txs': 128, 'l2_db': 'x', 'timestamp_rule': None, 'user_transactions': True,
                          'max_block_instructions': 100}  # ADAPTED (a223)
        self.settler.work = root
        self.now = 0.0
        self.settler.clock = lambda: self.now
        self.settler.preflight_source = 'request'
        self.settler.next_program = None
        self.settler.program = {'prover': None, 'prover_args': [], 'guest': None}
        self.settler.spool_open = True
        self.cost, self.sender = {}, {}
        self.deposit_cost = 10
        self.blocks = []
        self.measures = 0
        self.fail_runs = {}  # raw: how many of its next measurements fail (timeout, prover exit, OOM)
        mock.patch.object(s, 'log').start()
        self.addCleanup(mock.patch.stopall)

        def report(raws):
            return {'included': [s.keccak256(bytes.fromhex(r)).hex() for r in raws], 'transactions': len(raws), 'dropped': [],
                    'tx_stats': [{'hash': s.keccak256(bytes.fromhex(r)).hex(), 'sender': self.sender.get(r, r),
                                  'gas_used': 21000, 'effective_tip': str(10**9)} for r in raws]}
        self.report = report

        def produce(*args):
            pool = args[args.index('--txs') + 1] if '--txs' in args else None
            raws = json.loads(Path(pool).read_text()) if pool and pool.endswith('.json') else (
                [p.read_text().strip() for p in sorted(Path(pool).glob('*.tx'))] if pool else [])
            if args[0] == 'select':
                return report(raws)
            self.blocks.append(raws)
            return report(raws)
        self.settler.produce = produce

        def measure(parent, anchor, deposits, slot, number, raws, tag):
            self.measures += 1
            failing = [r for r in raws if self.fail_runs.get(r)]
            pending = json.loads(Path(deposits).read_text())
            total = (self.deposit_cost if pending else 2) + sum(self.cost[r] for r in raws)
            if failing:
                for r in failing:
                    self.fail_runs[r] -= 1
                self.now += 30
                return None, report(raws)
            if total > 200:  # ADAPTED (a223): over the cycle limit (2 x budget): the host's verdict, in about 10 s
                self.now += 10
                return sp.OVER_LIMIT, report(raws)
            self.now += 2
            return sp.Cost(total, total), report(raws)
        self.settler.measure_block = measure

    def spool(self, sender=None, **costs):
        for name, cost in costs.items():
            raw = name.encode().hex()
            self.cost[raw] = cost
            if sender:
                self.sender[raw] = sender
            (self.pool / f'{name}.tx').write_text(raw + '\n')

    def block(self, number=2):
        self.settler.extend('p', 'a', self.deposits, 1, number)
        return [bytes.fromhex(r).decode() for r in self.blocks[-1]]

    def names(self):
        return sorted(p.stem for p in self.pool.glob('*.tx'))

    def quarantine(self):
        q = self.pool.with_name('txpool-quarantine')
        return sorted(p.stem for p in q.glob('*.tx')) if q.exists() else []


class R1HeldForEverWithDeposits(Harness):
    """F1: over-budget transactions are never quarantined while the block has deposits, and each one costs a full
    bisection of measuring. A few of them, ordered first by their (never paid) tip, use the block's whole measuring
    allowance; the honest transaction behind them is never measured. They stay in the spool, so this repeats each block."""

    def test_default_limits_six_heavy_transactions_and_one_deposit_per_block(self):
        self.spool(a=HEAVY, b=HEAVY, c=HEAVY, d=HEAVY, e=HEAVY, f=HEAVY, z=10)  # z: honest transfer, last by tip
        self.deposits.write_text('[{"sats": 1000000}]')
        included = [self.block(n) for n in range(2, 12)]
        # ADAPTED (a223): as agent 90's and agent 135's (r9 R9.2) adaptation: the first two assertions described the
        # round-7 behaviour (nothing quarantined, z still spooled), which cannot hold together with the third. v2:
        # the attackers are quarantined on the cycle-limit verdict, z is served and not quarantined.
        self.assertEqual(self.quarantine(), ['a', 'b', 'c', 'd', 'e', 'f'])
        self.assertEqual(self.names(), [], 'z served, attackers quarantined')
        self.assertTrue(any('z' in b for b in included), f'honest z never included in 10 blocks: {included}')

    def test_recommended_time_bounds_two_heavy_transactions_suffice(self):
        self.settler.c.update(preflight_execute_seconds=30, preflight_max_seconds=180)
        self.spool(a=HEAVY, b=HEAVY, z=10)
        self.deposits.write_text('[{"sats": 1000000}]')
        included = [self.block(n) for n in range(2, 12)]
        self.assertEqual(self.quarantine(), ['a', 'b'])  # ADAPTED (a223): quarantined on the cycle-limit verdict
        self.assertTrue(any('z' in b for b in included), f'honest z never included in 10 blocks: {included}')


class Controls(Harness):
    """The harness is fair: without the attack, or with one heavy transaction, the honest transfer is included."""

    def test_honest_transfer_with_a_deposit_is_included(self):
        self.spool(z=10)
        self.deposits.write_text('[{"sats": 1000000}]')
        self.assertEqual(self.block(), ['z'])

    def test_one_heavy_transaction_with_a_deposit_does_not_keep_the_honest_one_out(self):
        self.spool(a=HEAVY, z=10)
        self.deposits.write_text('[{"sats": 1000000}]')
        self.assertEqual(self.block(), ['z'])
        self.assertEqual((self.names(), self.quarantine()), ([], ['a']))  # ADAPTED (a223): quarantined, not kept

    def test_without_deposits_the_heavy_transactions_are_quarantined_and_the_honest_one_gets_in(self):
        self.spool(a=HEAVY, b=HEAVY, c=HEAVY, d=HEAVY, e=HEAVY, f=HEAVY, z=10)
        included = [self.block(n) for n in range(2, 5)]
        self.assertTrue(any('z' in b for b in included))

    def test_a_single_measurement_failure_only_holds(self):
        self.spool(h=10)
        self.fail_runs['h'.encode().hex()] = 1
        self.block()
        self.assertEqual(self.quarantine(), [])


class R2HonestQuarantinedByAFailedMeasurement(Harness):
    """F2: a measurement with no cost (timeout, prover exit, missing cost line) counts as over budget, so one failed
    run of an honest transaction alone moves it to quarantine and strikes its sender. Nothing retries it."""

    def test_two_failed_measurements_quarantine_an_honest_transfer(self):
        # A loaded host: the block run and the run of h alone both hit preflight_execute_seconds (about 60 s in all).
        self.settler.c.update(strike_cooldown_blocks=32)
        self.spool(sender='alice', h=10)
        self.fail_runs['h'.encode().hex()] = 2
        self.block()
        state = json.loads((self.settler.work / 'sequencer-policy.json').read_text())
        self.assertEqual(self.quarantine(), [], f"honest h quarantined for good; bans {state['bans']}")  # ADAPTED (a223)

    def test_a_prover_without_the_cost_line_starves_every_block(self):
        # measure_block returns no cost when the prover prints no "Settlement V3 cost" line (any prover not built from
        # this branch). Every deposit-only base then counts as over budget: no user transaction is ever served.
        self.settler.measure_block = lambda *a: (None, self.report(a[5]))
        self.spool(h=10)
        self.deposits.write_text('[{"sats": 1000000}]')
        # ADAPTED (a223): v2 refuses to run a budget on a prover without the cost line (spec 3.4, check_cost_line): the
        # settler stops at the first block instead of starving users silently. h stays spooled.
        with self.assertRaises(s.Halt):
            self.block(2)
        self.assertEqual((self.blocks, self.names()), ([], ['h']))


class R3PlannerStateWedge(Harness):
    """F7: the planner's state file is written without fsync and read with json.loads on every block. A torn or empty
    file raises a non-producer error: the settler retries, exits after max_consecutive_failures, and builds no block,
    deposits included, until an operator deletes the file."""

    def test_an_empty_state_file_stops_block_building(self):
        (self.settler.work / 'sequencer-policy.json').write_text('')
        self.spool(h=10)
        self.deposits.write_text('[{"sats": 1000000}]')
        try:
            self.block()
        except s.ProducerError:
            self.fail('not expected')
        except Exception as error:  # noqa: BLE001
            self.fail(f'block building raised {type(error).__name__}: {error}; deposits wait for an operator')


class R4StaleSourceBypassedByTheBudgetPath(unittest.TestCase):
    """F4 (idle-blocks + griefing-limits): hold_block closes the spool for a block on a stale source, so that a
    transaction does not run at an L2 time that is hours old. With max_block_sp1_gas set, extend() takes
    extend_within_budget, which reads the spool itself and ignores spool_open."""

    def setUp(self):
        self.idle = foreign.IdleTest('setUp')
        self.idle.setUp()
        self.addCleanup(self.idle.base.tmp.cleanup)
        self.addCleanup(mock.patch.stopall)

    def test_a_transaction_on_an_old_source_waits_for_a_fresh_one_with_the_budget_on(self):
        settler = self.idle.settler(users=True, max_block_sp1_gas=100, max_block_instructions=100,
                                    max_block_txs=64)  # ADAPTED (a223): both budget keys, v2's cap
        raw = 'aa'
        (self.idle.root / 'txpool' / 'a.tx').write_text(raw)
        self.idle.world.head_slot = 1000 + 21  # source 630 s old: above pace 0 + 600 s
        self.assertFalse(self.idle.held(settler))
        self.assertFalse(settler.spool_open)
        self.assertNotIn('--txs', settler.extend_arguments('p', 'a', 'd', 5))  # the plain path is closed, as designed
        committed = []

        def report(raws):
            return {'included': [s.keccak256(bytes.fromhex(r)).hex() for r in raws], 'dropped': [],
                    'tx_stats': [{'hash': s.keccak256(bytes.fromhex(r)).hex(), 'sender': 's', 'gas_used': 21000,
                                  'effective_tip': '1'} for r in raws]}

        def produce(*args):
            if args[0] == 'extend':
                pool = args[args.index('--txs') + 1] if '--txs' in args else None
                committed.append(json.loads(Path(pool).read_text()) if pool else [])
            return report(json.loads(Path(args[args.index('--txs') + 1]).read_text()) if '--txs' in args else [])
        settler.produce = produce
        settler.select_block = lambda *a: report(a[4])
        settler.measure_block = lambda *a: (sp.Cost(10, 10), report(a[5]))
        settler.preflight_source = 'request'
        deposits = self.idle.root / 'work' / 'deposits.json'
        deposits.write_text('[]')
        settler.extend('p', 'a', deposits, 5, 1)
        self.assertEqual(committed[-1], [], 'the budget path put a user transaction in the block on the stale source')


class R5HeldEntriesAreDemand(unittest.TestCase):
    """F5 (idle-blocks + user transactions): any *.tx file is demand. An entry no block will include (a nonce gap the
    RPC admits up to 16 ahead and keeps 3 h; below the congestion tip; sender cooldown; pilot closed or past its stop
    height) makes every cycle due, so the chain builds a block every pacing interval for free."""

    def setUp(self):
        self.idle = foreign.IdleTest('setUp')
        self.idle.setUp()
        self.addCleanup(self.idle.base.tmp.cleanup)
        self.addCleanup(mock.patch.stopall)

    def test_a_nonce_gap_entry_does_not_make_blocks_due(self):
        # Unchanged: without the budget. Fails on the base candidate 4b984af too: an entry that does not decode counts as
        # demand there by design (spool_demand docstring); see the policy variant below.
        settler = self.idle.settler(users=True)
        (self.idle.root / 'txpool' / 'gap.tx').write_text('00')  # deferred by every selection (DeferReason::NonceGap)
        due = 0
        for age_slots in (1, 2, 3, 4, 5):  # five consecutive fresh sources, no deposit, far below max_idle (100 slots)
            self.idle.world.head_slot = 1000 + age_slots
            due += not self.idle.held(settler)
        self.assertEqual(due, 0, f'{due} of 5 cycles built a block for an entry no block includes')


class R5WithThePolicy(R5HeldEntriesAreDemand):
    """ADAPTED (a223): the same entry with the v2 budget on: demand is the producer's select report through the policy
    gate. The fake producer answers select as the real one does for bytes that do not decode (dropped, no tx_stats)."""

    def test_a_nonce_gap_entry_does_not_make_blocks_due(self):
        settler = self.idle.settler(users=True, max_block_sp1_gas=100, max_block_instructions=100, max_block_txs=64)
        run = self.idle.world.run

        def world_run(argv, **kwargs):
            if Path(argv[0]).name == 'produce' and argv[1] == 'select':
                import types
                return types.SimpleNamespace(returncode=0, stderr='', stdout=json.dumps(
                    {'included': [], 'deferred': [], 'dropped': [{'index': 0, 'hash': None, 'reason': 'undecodable'}],
                     'tx_stats': []}))
            return run(argv, **kwargs)
        settler.run = world_run
        (self.idle.root / 'txpool' / 'gap.tx').write_text('00')
        due = 0
        for age_slots in (1, 2, 3, 4, 5):
            self.idle.world.head_slot = 1000 + age_slots
            due += not self.idle.held(settler)
        self.assertEqual(due, 0, f'{due} of 5 cycles built a block for an entry no block includes')


class R6CongestionTipOutlivesTheSpoolUnderPacing(unittest.TestCase):
    """F6 (griefing-limits congestion tip + idle-blocks pacing): the required tip decays per committed block, not per
    second, and blocks are paced. The RPC admits at its static --min-tip-wei and evicts an entry after 3 h. After a
    modest spike to 1 gwei, a floor-tip (0.1 gwei) transaction is evicted before the tip is back at the floor."""

    def test_floor_tip_transaction_gets_in_before_the_rpc_evicts_it(self):
        # ADAPTED (a223): v2 API (Policy, committed(plan, report)), v2 keys and the owner's 3 gwei cap; the paced
        # deposit-only blocks are kept, as in the original.
        config = dict(max_block_sp1_gas=90_000_000, max_block_instructions=90_000_000, min_tip_wei=10**8,
                      congestion_max_tip_wei=3 * 10**9)
        now = [0.0]
        planner = sp.Policy(config, clock=lambda: now[0])
        planner.state['tip'], planner.state['last_block_time'] = 10**9, 0.0
        pace, ttl, waited, blocks = 1800, 3 * 3600, 0, 0
        while planner.required_tip() > 10**8 and blocks < 200:
            now[0] += pace
            plan = sp.Plan()
            plan.base = plan.cost = sp.Cost(20_000_000, 1)  # deposit-only block: the floor-tip tx is held
            planner.committed(plan, {'included': []})
            blocks += 1
            waited += pace
        self.assertLessEqual(waited, ttl, f'{blocks} paced blocks, {waited / 3600:.1f} h: evicted by the RPC at 3 h')


    def test_idle_chain_floor_tip_transaction_gets_in_before_the_rpc_evicts_it(self):
        # ADAPTED (a223): the idle case of the same property (no deposit-only blocks): v2's time decay after the grace.
        now = [0.0]
        planner = sp.Policy(dict(max_block_sp1_gas=90_000_000, max_block_instructions=90_000_000, min_tip_wei=10**8,
                                 congestion_max_tip_wei=3 * 10**9), clock=lambda: now[0])
        planner.state['tip'], planner.state['last_block_time'] = 10**9, 0.0
        while planner.required_tip() > 10**8:
            now[0] += 60
        self.assertLessEqual(now[0], 3 * 3600, f'{now[0] / 3600:.1f} h to the floor')


if __name__ == '__main__':
    unittest.main()
