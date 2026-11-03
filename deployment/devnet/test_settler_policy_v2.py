#!/usr/bin/env python3
"""Settler integration of sequencer policy v2 (agent 223): the seams between settler_v3.py, sequencer_policy_v2.py, the
producer (`select`, `extend`) and the SP1 host's cycle limit. Fake producer and fake prover; no process is started.

Replaces test_settler_budget.py, which tested the plain budget path (l2-heavy-r3) that v2 replaces.
Run: python3 -B -m unittest -v test_settler_policy_v2
"""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import sequencer_policy_v2 as sp  # noqa: E402


def h(raw):
    return s.keccak256(bytes.fromhex(raw)).hex()


class Harness(unittest.TestCase):
    BUDGET = 100

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.root = Path(self.tmp.name)
        self.pool = root / 'txpool'
        self.pool.mkdir()
        self.dir = root / 'work' / '00000002-aa'
        self.dir.mkdir(parents=True)
        (root / 'db').mkdir()
        self.deposits = self.dir / 'deposits.json'
        self.deposits.write_text('[]')
        st = self.settler = s.Settler.__new__(s.Settler)
        st.c = {'txpool_dir': str(self.pool), 'max_block_sp1_gas': self.BUDGET, 'max_block_instructions': self.BUDGET,
                'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 64, 'l2_db': str(root / 'db'),
                'timestamp_rule': None, 'user_transactions': True, 'prover': str(root / 'bloch-evm-sp1-settlement-v3'),
                'guest': 'settlement_v3_mainnet', 'home': str(root), 'min_tip_wei': 1}
        st.work, st.spool_open, st.prover_args = root / 'work', True, []
        self.now = 1000.0
        st.clock = lambda: self.now
        st.preflight_source = 'request\n'
        self.cost = {}
        self.calls = []
        self.logged = []
        mock.patch.object(s, 'log', side_effect=lambda event, **f: self.logged.append((event, f))).start()
        self.addCleanup(mock.patch.stopall)
        st.produce = self.produce
        st.measure_block = self.measure

    def report(self, raws):
        return {'included': [h(r) for r in raws], 'dropped': [], 'deferred': [], 'transactions': len(raws),
                'tx_stats': [{'hash': h(r), 'sender': r[:4], 'nonce': 0, 'gas_used': 21_000, 'effective_tip': '10',
                              'fresh_slots': []} for r in raws]}

    def produce(self, *args):
        self.calls.append(list(args))
        pool = args[args.index('--txs') + 1] if '--txs' in args else None
        raws = json.loads(Path(pool).read_text()) if pool and pool.endswith('.json') else (
            [p.read_text().strip() for p in sorted(Path(pool).glob('*.tx'))] if pool else [])
        return self.report(raws)

    def measure(self, parent, anchor, deposits, slot, number, raws, tag):
        base = 10 if json.loads(Path(deposits).read_text()) else 2
        total = base + sum(self.cost.get(r, 1) for r in raws)
        if total > 2 * self.BUDGET:
            return sp.OVER_LIMIT, self.report(raws)
        return sp.Cost(total, total), self.report(raws)

    def spool(self, **costs):
        for name, cost in costs.items():
            raw = name.encode().hex()
            self.cost[raw] = cost
            (self.pool / f'{name}.tx').write_text(raw + '\n')

    def block(self):
        return self.settler.extend('p', 'a', self.deposits, 1, 2)

    def names(self):
        return sorted(p.stem for p in self.pool.glob('*.tx'))

    def quarantined(self):
        q = self.pool.with_name('txpool-quarantine')
        return sorted(p.stem for p in q.glob('*.tx')) if q.exists() else []


class BudgetPath(Harness):
    def test_block_within_budget_commits_everything_and_empties_the_spool(self):
        self.spool(a=10, b=10)
        block = self.block()
        self.assertEqual(block['transactions'], 2)
        self.assertEqual(self.names(), [])
        profile = json.loads((self.dir / 'prover-profile.json').read_text())
        self.assertEqual((profile['profile'], profile['sp1_gas']), ('fast', 22))

    def test_select_runs_without_the_transaction_cap_and_extend_with_it(self):
        self.spool(a=10)
        self.block()
        select = [c for c in self.calls if c[0] == 'select']
        extend = [c for c in self.calls if c[0] == 'extend']
        self.assertTrue(select and all('--max-txs' not in c for c in select))
        self.assertTrue(extend and all('--max-txs' in c for c in extend))

    def test_heavy_transaction_over_the_cycle_limit_is_quarantined_and_its_sender_banned(self):
        self.spool(a=10, b=10_000, c=10)
        self.block()
        self.assertEqual((self.names(), self.quarantined()), ([], ['b']))
        state = json.loads((self.settler.work / 'sequencer-policy.json').read_text())
        self.assertIn('b'.encode().hex()[:4], state['bans'])
        self.assertIn('required_tip_wei', state)  # what the RPC's --required-tip-file reads

    def test_a_closed_spool_is_not_read_by_the_budget_path(self):
        self.settler.spool_open = False
        self.spool(a=10)
        block = self.block()
        self.assertEqual((block['transactions'], self.names()), (0, ['a']))

    def test_mandatory_items_over_the_budget_commit_alone_with_the_record(self):
        self.spool(a=10)
        self.deposits.write_text('[{"sats": 1}]')
        real = self.measure

        def measure(parent, anchor, deposits, slot, number, raws, tag):
            if json.loads(Path(deposits).read_text()):
                return sp.Cost(150, 150), self.report(raws)
            return real(parent, anchor, deposits, slot, number, raws, tag)
        self.settler.measure_block = measure
        block = self.block()
        record = json.loads((self.dir / 'deposits-over-budget.json').read_text())
        self.assertEqual((block['transactions'], self.names()), (0, ['a']))
        self.assertEqual((record['sp1_gas'], record['profile'], record['deposits']), (150, 'mandatory-heavy', 1))

    def test_a_prover_without_the_cost_line_stops_the_settler(self):
        self.settler.measure_block = lambda *a: (None, self.report(a[5]))
        self.spool(a=10)
        with self.assertRaises(s.Halt):
            self.block()
        self.assertEqual(self.names(), ['a'])

    def test_only_what_the_committed_block_included_leaves_the_spool(self):
        self.spool(a=10, b=10)
        real = self.produce

        def produce(*args):
            out = real(*args)
            if args[0] == 'extend':  # the final extend defers b (a nonce gap, say)
                out['included'] = out['included'][:1]
                out['tx_stats'] = out['tx_stats'][:1]
            return out
        self.settler.produce = produce
        self.block()
        self.assertEqual(len(self.names()), 1)


class Measurement(Harness):
    """measure_block against a fake prover run: the cycle-limit verdict, a cost, and no cost."""

    def setUp(self):
        super().setUp()
        del self.settler.measure_block
        self.settler.preflight_request = 'request\n'
        self.out = ''
        self.code = 0
        self.envs = []

        def run(argv, timeout=None, **kwargs):
            self.envs.append(kwargs.get('env'))
            kwargs['stdout'].write(self.out)
            return types.SimpleNamespace(returncode=self.code)
        self.settler.run = run
        real = self.produce

        def produce(*args):
            if args[0] == 'export':
                Path(args[args.index('--out') + 1]).write_bytes(b'artifact')
                return {}
            return real(*args)
        self.settler.produce = produce

    def measure_once(self):
        return self.settler.measure_block('p', 'a', self.deposits, 1, 2, [], 't')[0]

    def test_cycle_limit_verdict(self):
        self.out, self.code = 'Settlement V3 over cycle limit: limit=180000000\n', 3
        self.assertEqual(self.measure_once(), sp.OVER_LIMIT)
        self.assertEqual(self.envs[-1]['BLOCH_PREFLIGHT_CYCLE_LIMIT'], str(2 * self.BUDGET))

    def test_default_cycle_limit_is_twice_the_instruction_budget(self):
        del self.settler.c['max_block_instructions']
        self.out, self.code = 'Settlement V3 over cycle limit: limit=180000000\n', 3
        self.measure_once()
        self.assertEqual(self.envs[-1]['BLOCH_PREFLIGHT_CYCLE_LIMIT'], '180000000')

    def test_cost(self):
        self.out = ('Settlement V3 cost: gas=707213 touched_memory=1 record_bytes=2 syscalls=\n'
                    'Settlement V3 guest matched the independent host statement: 522277 instructions in 1s\n')
        result = self.measure_once()
        self.assertEqual((result.sp1_gas, result.instructions), (707213, 522277))

    def test_exit_three_without_the_verdict_line_is_no_cost(self):
        self.out, self.code = 'Error: something else\n', 3
        self.assertIsNone(self.measure_once())

    def test_missing_cost_line_is_no_cost(self):
        self.out = 'Settlement V3 guest matched the independent host statement: 522277 instructions in 1s\n'
        self.assertIsNone(self.measure_once())

    def test_control_run_consumes_no_deposit(self):
        self.settler.preflight_request = 'a\nb\nc\n7\nroot\n5\n4\n6\n'
        seen = []
        real = self.settler.measure_block

        def spy(parent, anchor, deposits, slot, number, raws, tag):
            seen.append((json.loads(Path(deposits).read_text()), self.settler.preflight_request))
            return real(parent, anchor, deposits, slot, number, raws, tag)
        self.settler.measure_block = spy
        self.deposits.write_text('[{"sats": 1}]')
        self.settler.measure_empty('p', 'a', self.deposits, 1, 2, 'x')
        self.assertEqual(seen, [([], 'a\nb\nc\n7\nroot\n5\n4\n4\n')])
        self.assertEqual(self.settler.preflight_request, 'a\nb\nc\n7\nroot\n5\n4\n6\n')


class Profiles(Harness):
    def test_prover_env_follows_the_profile(self):
        (self.dir / 'prover-profile.json').write_text(json.dumps({'profile': 'lowmem-2c'}))
        profile = self.settler.prover_profile(self.dir)
        self.assertEqual(profile['env']['SP1_WORKER_NUM_CORE_WORKERS'], '2')
        (self.dir / 'prover-profile.json').write_text(json.dumps({'profile': 'fast'}))
        self.assertEqual(self.settler.prover_profile(self.dir)['env'], {'ELEMENT_THRESHOLD': '268435456'})

    def test_no_profile_without_the_budget(self):
        (self.dir / 'prover-profile.json').write_text(json.dumps({'profile': 'fast'}))
        del self.settler.c['max_block_sp1_gas']
        self.assertIsNone(self.settler.prover_profile(self.dir))

    def test_local_prover_refuses_a_profile_larger_than_its_scope(self):
        self.settler.c['local_prove_max_memory_gib'] = 64
        heavy = dict(sp.PROFILES['mandatory-heavy'], name='mandatory-heavy')
        self.assertFalse(self.settler.local_profile_fits(self.dir, heavy))
        self.assertTrue(self.settler.local_profile_fits(self.dir, dict(sp.PROFILES['lowmem-2c'], name='lowmem-2c')))


class Config(unittest.TestCase):
    def test_policy_limits(self):
        good = {'user_transactions': True, 'max_block_txs': 64, 'congestion_max_tip_wei': 3 * 10**9,
                'min_tip_wei': 10**8, 'write_limit_exempt_senders': ['ab' * 20]}
        s.check_policy_config(good)
        for bad in ({'max_block_txs': 128}, {'congestion_max_tip_wei': 10**7}, {'preflight_cycle_limit_factor': 1},
                    {'write_limit_exempt_senders': ['0x' + 'ab' * 20]}, {'max_tx_gas': 0}):
            with self.assertRaises(s.Halt, msg=bad):
                s.check_policy_config({**good, **bad})

    def test_state_keeps_the_last_block_time_across_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sequencer-policy.json'
            now = [0.0]
            policy = sp.Policy({'congestion_max_tip_wei': 3 * 10**9}, path, clock=lambda: now[0])
            policy.state['tip'] = 10**9
            plan = sp.Plan()
            plan.base = plan.cost = sp.Cost(1, 1)
            policy.committed(plan, {'included': []})
            now[0] = 3 * 3600.0
            restarted = sp.Policy({'congestion_max_tip_wei': 3 * 10**9}, path, clock=lambda: now[0])
            self.assertEqual(restarted.state['last_block_time'], 0.0)
            self.assertEqual(restarted.required_tip(), 10**8)


if __name__ == '__main__':
    unittest.main()
