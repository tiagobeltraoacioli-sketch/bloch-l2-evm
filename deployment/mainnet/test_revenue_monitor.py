#!/usr/bin/env python3
"""Unit tests for revenue_monitor.py against fixture worlds (no network, no keys).

The fixtures in testdata/revenue_monitor/ describe the chains semantically (pair reserves, vault immutables,
balances, events); FakeWorld answers the monitor's JSON-RPC calls from them with real ABI encoding, event
topics and block-range filtering.

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_revenue_monitor.py' -v
"""
import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revenue_monitor as m  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / 'testdata' / 'revenue_monitor'
DAY = 86_400
SEL = {v: k for k, v in m.VIEW_SELECTORS.items()}


def load(name):
    return json.loads((FIXTURES / name).read_text())


def w(n):
    return format(int(n), '064x')


def wa(a):
    return '0x' + a[2:].lower().rjust(64, '0')


class FakeWorld:
    """Answers L2, Ethereum and L1 RPC from a fixture. Records every call."""

    def __init__(self, world):
        self.world = world
        self.log = []
        self.urls = {}
        for u in world['config'].get('l2', {}).get('rpc', []):
            self.urls[u] = 'l2'
        for u in (world['config'].get('bridge') or {}).get('rpc', []):
            self.urls[u] = 'eth'
        for u in (world['config'].get('forced') or {}).get('l1_rpc', []):
            self.urls[u] = 'l1'
        self.down = set()

    def __call__(self, url, method, params):
        self.log.append((url, method, params))
        if url in self.down:
            raise m.RpcError(f'{url} down')
        side = self.urls[url]
        if side == 'l1':
            return self.l1(method, params)
        return self.evm(self.world[side], method, params)

    # -- L1
    def l1(self, method, params):
        l1 = self.world['l1']
        if method == 'getl2settlement':
            out = {'accepted': None}
            if l1.get('forced') is not None:
                out['forced'] = l1['forced']
            return out
        if method == 'getbalance':
            return {'script_hash': params[0], 'balance_sat': str(l1['balances'].get(params[0], 0)), 'utxo_count': 1}
        raise AssertionError(method)

    # -- EVM
    @staticmethod
    def ts(chain, number):
        head = chain['head']
        return head['timestamp'] - (head['number'] - number) * chain['spacing']

    def block(self, chain, number):
        branch = 0 if number == 0 else chain.get('branch', 0)
        identity = (chain['chain_id'] << 128) | (branch << 64) | number
        b = {'number': hex(number), 'timestamp': hex(self.ts(chain, number)), 'hash': f'0x{identity:064x}'}
        if 'baseFeePerGas' in chain['head']:
            b['baseFeePerGas'] = hex(chain['head']['baseFeePerGas'])
        return b

    def evm(self, chain, method, params):
        if method == 'eth_chainId':
            return hex(chain['chain_id'])
        if method == 'eth_getBlockByNumber':
            tag = params[0]
            n = chain['head']['number'] if tag in ('finalized', 'latest', 'safe') else int(tag, 16)
            return self.block(chain, n)
        if method in ('eth_getBalance', 'eth_getCode', 'eth_call'):
            assert params[1] == hex(chain['head']['number']), f'{method} not pinned to the finalized block: {params[1]}'
        if method == 'eth_getBalance':
            return hex(int(chain.get('accounts', {}).get(params[0].lower(), {}).get('balance', 0)))
        if method == 'eth_getCode':
            return chain.get('accounts', {}).get(params[0].lower(), {}).get('code', '0x')
        if method == 'eth_call':
            return self.call(chain, params[0]['to'].lower(), params[0]['data'].lower())
        if method == 'eth_getLogs':
            return self.logs(chain, params[0])
        raise AssertionError(method)

    def call(self, chain, to, data):
        sig = SEL[data[2:10]]
        arg = '0x' + data[-40:] if len(data) > 10 else None
        if to in chain.get('pairs', {}):
            p = chain['pairs'][to]
            return '0x' + {
                'getReserves()': lambda: w(p['reserves'][0]) + w(p['reserves'][1]) + w(0),
                'totalSupply()': lambda: w(p['totalSupply']),
                'kLast()': lambda: w(p['kLast']),
                'reserveCaps()': lambda: w(p['caps'][0]) + w(p['caps'][1]),
                'balanceOf(address)': lambda: w(p['lp'].get(arg, 0)),
            }[sig]()
        if to in chain.get('factory', {}):
            assert sig == 'feeTo()'
            return wa(chain['factory'][to]['feeTo'])
        if to in chain.get('vaults', {}):
            v = chain['vaults'][to]
            if sig in ('token()', 'feeRecipient()'):
                return wa(v[{'token()': 'token', 'feeRecipient()': 'feeRecipient'}[sig]])
            return '0x' + w(v[{'depositFeeBps()': 'depositFeeBps', 'releaseFeeBps()': 'releaseFeeBps',
                               'feesAccrued()': 'feesAccrued', 'totalLocked()': 'totalLocked'}[sig]])
        if to in chain.get('erc20', {}):
            assert sig == 'balanceOf(address)'
            return '0x' + w(chain['erc20'][to].get(arg, 0))
        raise m.RpcError(f'execution reverted: no contract at {to}')

    @staticmethod
    def encode(e):
        ev = e['event']
        topics, data = [m.TOPIC[ev]], ''
        if ev == 'Transfer':
            topics += [wa(e['from']), wa(e['to'])]
            data = w(e['value'])
        elif ev == 'Burn':
            topics += [wa(e['sender']), wa(e['to'])]
            data = w(e['amounts'][0]) + w(e['amounts'][1])
        elif ev == 'Swap':
            topics += [wa(e['sender']), wa(e['to'])]
            data = ''.join(w(a) for a in e['amounts'])
        elif ev == 'FeeAccrued':
            topics += ['0x' + w(e.get('id', 1))]
            data = w(e['fee'])
        elif ev == 'FeesSwept':
            topics += [wa(e['recipient'])]
            data = w(e['amount'])
        elif ev in ('Deposited', 'Released'):
            topics += ['0x' + w(1), '0x' + w(2)]
            data = w(0) + w(0) + w(e.get('amount', 0)) + w(0)
        elif ev == 'ReleaseExecuted':
            topics += ['0x' + w(1)]
            data = w(0) + w(e.get('amount', 0))
        return topics, '0x' + data

    def logs(self, chain, flt):
        lo, hi = int(flt['fromBlock'], 16), int(flt['toBlock'], 16)
        assert hi <= chain['head']['number'], 'log scan beyond the finalized block'
        addresses = flt['address'] if isinstance(flt['address'], list) else [flt['address']]
        addresses = [a.lower() for a in addresses]
        out = []
        for i, e in enumerate(chain.get('logs', [])):
            if e['address'].lower() not in addresses or not lo <= e['block'] <= hi:
                continue
            topics, data = self.encode(e)
            ok = True
            for pos, want in enumerate(flt.get('topics', [])):
                if want is None:
                    continue
                options = want if isinstance(want, list) else [want]
                if pos >= len(topics) or topics[pos].lower() not in [o.lower() for o in options]:
                    ok = False
                    break
            if ok:
                out.append({'address': e['address'], 'topics': topics, 'data': data, 'blockNumber': hex(e['block']),
                            'transactionHash': e['tx'], 'logIndex': hex(i)})
        return out


def run_world(world, state=None, now=None):
    state = m.empty_state() if state is None else state
    fake = FakeWorld(world)
    report = m.run(world['config'], state, m.Client(fake), now if now is not None else world['now'])
    return report, state, fake


def checks(report, level=None):
    return {c['name']: c for c in report['checks'] if level is None or c['level'] == level}


class LiveWorld(unittest.TestCase):
    def setUp(self):
        self.world = load('world_live.json')

    def test_healthy_world_is_ok_and_reports_every_product(self):
        report, state, _ = run_world(self.world)
        self.assertEqual(report['level'], 'OK', [c for c in report['checks'] if c['level'] != 'OK'])
        self.assertEqual(report['schema'], m.SCHEMA)
        self.assertEqual(set(report['products']), {'dex', 'bridge', 'l2_fees', 'forced'})
        json.dumps(report)  # serialisable

    def test_dex_safe_lp_underlying_and_pending_fee(self):
        report, _, _ = run_world(self.world)
        p = report['products']['dex']['pairs'][0]
        supply, safe_lp = 50_000_000_000_000, 100_000_000_000
        self.assertEqual(p['safe_underlying'], [str(500 * 10 ** 6 * safe_lp // supply), str(5 * 10 ** 18 * safe_lp // supply)])
        # Canonical v2 _mintFee closed form: totalSupply * (rootK - rootKLast) / (5 rootK + rootKLast).
        rk, rkl = m.isqrt(500 * 10 ** 6 * 5 * 10 ** 18), m.isqrt(2_400_000_000_000_000_000_000_000_000)
        self.assertEqual(int(p['pending_fee_lp']), supply * (rk - rkl) // (5 * rk + rkl))
        self.assertGreater(int(p['pending_fee_wblch_wei']), 0)
        self.assertFalse(p['at_k_ceiling'])
        # Value in WBLCH: the bUSDC side priced at the pool (r1 / r0).
        under = [int(x) for x in p['safe_underlying']]
        self.assertEqual(int(p['safe_value_wblch_wei']), under[1] + under[0] * 5 * 10 ** 18 // (500 * 10 ** 6))

    def test_keeper_skim_is_counted_and_a_safe_redemption_is_not_a_skim(self):
        report, state, _ = run_world(self.world)
        totals = report['totals']
        pair = self.world['config']['dex']['pairs'][0]['address']
        self.assertEqual(totals[f'dex_skim1:{pair}'], str(2 * 10 ** 15))
        self.assertEqual(totals[f'dex_skim0:{pair}'], '0')
        self.assertEqual(totals[f'dex_redeem0:{pair}'], '1000000')
        self.assertEqual(totals[f'dex_redeem1:{pair}'], str(10 ** 16))
        self.assertEqual(totals['dex_swaps'], '2')
        self.assertEqual(totals['dex_skim_wei'], str(2 * 10 ** 15))

    def test_bridge_accrued_swept_and_unswept(self):
        report, state, _ = run_world(self.world)
        b = report['products']['bridge']
        self.assertEqual(b['fees_accrued_unswept'], '1000000')
        self.assertEqual(b['recipient_balance'], '5000000')
        self.assertEqual(report['totals']['bridge_fee_accrued'], '6000000')
        self.assertEqual(report['totals']['bridge_fee_swept'], '5000000')
        self.assertEqual(report['totals']['bridge_deposits'], '2')
        # The unswept window starts at the FeeAccrued after the last sweep, from the log's block time.
        eth = self.world['eth']
        self.assertEqual(state['marks']['bridge_unswept_since'], FakeWorld.ts(eth, 20006000))

    def test_events_land_on_their_block_day(self):
        world = self.world
        world['eth']['spacing'] = 12 * 30  # spread the bridge logs over several days
        report, state, _ = run_world(world)
        days_with_fees = [d for d, row in state['days'].items() if 'bridge_fee_accrued' in row]
        self.assertEqual(len(days_with_fees), 2, state['days'].keys())

    def test_l2_vaults_sweep_to_the_safe_and_sweeps_are_measured(self):
        report, state, _ = run_world(self.world)
        l2 = report['products']['l2_fees']
        self.assertTrue(l2['fork_active'])
        self.assertEqual(l2['vaults']['base_fee']['sweep_recipient'], self.world['config']['l2_fees']['recipient'])
        # Next day: base vault swept to 0, sequencer vault grew.
        world2 = copy.deepcopy(self.world)
        acc = world2['l2']['accounts']
        acc[m.BASE_FEE_VAULT]['balance'] = 0
        acc[m.SEQUENCER_FEE_VAULT]['balance'] = 5 * 10 ** 16
        world2['l2']['head']['number'] += 180
        report2, state, _ = run_world(world2, state, world2['now'] + DAY)
        row = report2['days'][-1]
        self.assertEqual(row['l2_swept'], str(10 ** 16))
        self.assertEqual(row['l2_accrued'], str(3 * 10 ** 16))
        self.assertEqual(report2['level'], 'OK')

    def test_forced_inclusion_paying_the_treasury(self):
        report, state, _ = run_world(self.world)
        world2 = copy.deepcopy(self.world)
        world2['l1']['forced']['queued'] = 8
        world2['l1']['balances']['11' * 32] = 403_000
        report2, state, _ = run_world(world2, state, world2['now'] + 3600)
        self.assertEqual(checks(report2)['forced_route']['level'], 'OK')
        self.assertEqual(report2['totals']['forced_records'], '3')
        self.assertEqual(report2['totals']['forced_treasury_in_sat'], '3000')

    # -- alerts: a revenue path that should accrue does not

    def test_bridge_fees_never_swept_warns(self):
        world = self.world
        world['eth']['logs'] = [g for g in world['eth']['logs'] if g['event'] != 'FeesSwept']
        world['eth']['vaults'][world['config']['bridge']['vault']]['feesAccrued'] = 60 * 10 ** 6
        world['eth']['erc20']['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'][world['config']['bridge']['vault']] = 50_060 * 10 ** 6
        world['eth']['spacing'] = 120  # the first fee is ~8 days old
        report, _, _ = run_world(world)
        c = checks(report)['bridge_sweep']
        self.assertEqual(c['level'], 'WARN')
        self.assertIn('sweepFees() was never called', c['message'])

    def test_bridge_small_fees_below_the_sweep_minimum_do_not_warn(self):
        world = self.world
        world['eth']['spacing'] = 120
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['bridge_sweep']['level'], 'OK')

    def test_bridge_crossings_without_fee_are_crit(self):
        world = self.world
        world['eth']['logs'] = [g for g in world['eth']['logs'] if g['event'] == 'Deposited']
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['bridge_fee_accrual']['level'], 'CRIT')
        self.assertEqual(report['exit_code'], m.CRIT)

    def test_bridge_zero_or_wrong_rates_and_wrong_recipient_are_crit(self):
        vault = self.world['config']['bridge']['vault']
        for field, value, check in (('depositFeeBps', 0, 'bridge_fee_rates'), ('releaseFeeBps', 30, 'bridge_fee_rates'),
                                    ('feeRecipient', '0x000000000000000000000000000000000000dead', 'bridge_fee_recipient')):
            world = load('world_live.json')
            world['eth']['vaults'][vault][field] = value
            report, _, _ = run_world(world)
            self.assertEqual(checks(report)[check]['level'], 'CRIT', field)

    def test_bridge_backing_shortfall_is_crit(self):
        world = self.world
        world['eth']['erc20']['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'][world['config']['bridge']['vault']] = 50_000 * 10 ** 6
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['bridge_backing']['level'], 'CRIT')

    def test_bridge_reconciliation_catches_missing_logs(self):
        report, state, _ = run_world(self.world)
        world2 = copy.deepcopy(self.world)
        vault = world2['config']['bridge']['vault']
        world2['eth']['vaults'][vault]['feesAccrued'] = 3_000_000  # +2 USDC with no FeeAccrued log
        world2['eth']['erc20']['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'][vault] += 2_000_000
        world2['eth']['head']['number'] += 10
        report2, _, _ = run_world(world2, state, world2['now'] + 120)
        self.assertEqual(checks(report2)['bridge_reconcile']['level'], 'WARN')

    def test_l2_placeholder_recipient_is_crit(self):
        world = self.world
        code = m.sweep_code(m.PLACEHOLDER_SWEEP_RECIPIENT)
        for v in (m.BASE_FEE_VAULT, m.SEQUENCER_FEE_VAULT):
            world['l2']['accounts'][v]['code'] = code
        report, _, _ = run_world(world)
        c = checks(report)['l2_vault_code[base_fee]']
        self.assertEqual(c['level'], 'CRIT')
        self.assertIn('placeholder', c['message'])

    def test_l2_unknown_code_and_one_sided_fork_are_crit(self):
        world = self.world
        world['l2']['accounts'][m.BASE_FEE_VAULT]['code'] = '0x6080'
        world['l2']['accounts'][m.SEQUENCER_FEE_VAULT]['code'] = '0x'
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['l2_vault_code[base_fee]']['level'], 'CRIT')
        self.assertEqual(checks(report)['l2_vault_code']['level'], 'CRIT')

    def test_l2_fork_time_passed_without_sweep_code_is_crit(self):
        world = self.world
        for v in (m.BASE_FEE_VAULT, m.SEQUENCER_FEE_VAULT):
            world['l2']['accounts'][v]['code'] = '0x'
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['l2_fork']['level'], 'CRIT')
        world['config']['l2_fees']['fork_time'] = world['now'] - 3600  # within the 6 h grace
        report, _, _ = run_world(world)
        self.assertNotIn('l2_fork', checks(report))

    def test_l2_vault_not_swept_for_a_week_warns(self):
        world = self.world
        world['l2']['accounts'][m.SEQUENCER_FEE_VAULT]['balance'] = 10 ** 17
        report, state, _ = run_world(world)
        self.assertNotIn('l2_sweep[sequencer_fee]', checks(report))
        world['l2']['accounts'][m.SEQUENCER_FEE_VAULT]['balance'] = 2 * 10 ** 17
        report, state, _ = run_world(world, state, world['now'] + 8 * DAY)
        c = checks(report)['l2_sweep[sequencer_fee]']
        self.assertEqual(c['level'], 'WARN')
        self.assertIn('never swept', c['message'])
        # A sweep resets the window.
        world['l2']['accounts'][m.SEQUENCER_FEE_VAULT]['balance'] = 10 ** 15
        report, state, _ = run_world(world, state, world['now'] + 9 * DAY)
        self.assertNotIn('l2_sweep[sequencer_fee]', checks(report))

    def test_l2_base_fee_below_the_floor_after_the_fork_warns(self):
        world = self.world
        world['l2']['head']['baseFeePerGas'] = 249
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['l2_base_fee_floor']['level'], 'WARN')

    def test_l2_no_accrual_with_user_txs_open_warns(self):
        report, state, _ = run_world(self.world)
        report, state, _ = run_world(self.world, state, self.world['now'] + 25 * 3600)
        self.assertEqual(checks(report)['l2_accrual']['level'], 'WARN')

    def test_dex_fee_to_not_the_safe_is_crit(self):
        world = self.world
        world['l2']['factory'][world['config']['dex']['factory']]['feeTo'] = '0x000000000000000000000000000000000000beef'
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['dex_fee_to']['level'], 'CRIT')

    def test_dex_protocol_fee_off_is_crit(self):
        world = self.world
        world['l2']['pairs'][world['config']['dex']['pairs'][0]['address']]['kLast'] = 0
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['dex_fee_off[0xd1e00000]']['level'], 'CRIT')

    def test_dex_ceiling_excess_left_unskimmed_warns(self):
        world = self.world
        pair = world['config']['dex']['pairs'][0]['address']
        u, wb = world['config']['dex']['pairs'][0]['token0'], world['config']['dex']['wrapped']
        # k at the 64% ceiling of caps 1000 bUSDC x 10 WBLCH: 800 x 8.
        world['l2']['pairs'][pair]['reserves'] = [800 * 10 ** 6, 8 * 10 ** 18]
        world['l2']['pairs'][pair]['kLast'] = 6_000_000_000_000_000_000_000_000_000
        world['l2']['erc20'][u][pair] = 800 * 10 ** 6 + 600_000  # 0.6 bUSDC fee outside the reserves
        world['l2']['erc20'][wb][pair] = 8 * 10 ** 18
        world['l2']['logs'] = [g for g in world['l2']['logs'] if g['event'] != 'Transfer' or g['tx'] == '0x04']
        report, state, _ = run_world(world)
        p = report['products']['dex']['pairs'][0]
        self.assertTrue(p['at_k_ceiling'])
        self.assertEqual(int(p['skimmable_wblch_wei']), 600_000 * 8 * 10 ** 18 // (800 * 10 ** 6))
        self.assertEqual(checks(report)['dex_keeper[0xd1e00000]']['level'], 'OK')
        report, state, _ = run_world(world, state, world['now'] + 7 * 3600)
        self.assertEqual(checks(report)['dex_keeper[0xd1e00000]']['level'], 'WARN')

    def test_dex_safe_lp_leaving_without_a_burn_warns(self):
        report, state, _ = run_world(self.world)
        world = copy.deepcopy(self.world)
        pair = world['config']['dex']['pairs'][0]['address']
        world['l2']['pairs'][pair]['lp'][world['config']['dex']['safe']] = 1
        world['l2']['head']['number'] += 10
        report, state, _ = run_world(world, state, world['now'] + 600)
        self.assertEqual(checks(report)['dex_safe_lp[0xd1e00000]']['level'], 'WARN')

    def test_dex_from_the_deploy_gate_file(self):
        gate = {'schemaVersion': 2, 'chain': {'id': 700770, 'genesisHash': '0x' + '00' * 32}, 'deployment': {
            'contracts': {'factory': self.world['config']['dex']['factory'], 'wrappedNative': self.world['config']['dex']['wrapped']},
            'feeTo': self.world['config']['dex']['safe'], 'roles': {'blochInc': {'address': self.world['config']['dex']['safe']}},
            'pairs': self.world['config']['dex']['pairs']}}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'finality-gate.json'
            path.write_text(json.dumps(gate))
            self.world['config']['dex'] = {'gate': str(path), 'start_block': 100}
            report, _, _ = run_world(self.world)
        self.assertEqual(report['level'], 'OK')
        self.assertEqual(report['totals']['dex_swaps'], '2')

    def test_forced_treasury_not_growing_warns(self):
        report, state, _ = run_world(self.world)
        world2 = copy.deepcopy(self.world)
        world2['l1']['forced']['queued'] = 7
        report2, _, _ = run_world(world2, state, world2['now'] + 3600)
        self.assertEqual(checks(report2)['forced_route']['level'], 'WARN')

    # -- read-only and robustness

    def test_never_calls_a_write_method_or_a_non_view_selector(self):
        report, state, fake = run_world(self.world)
        methods = {c[1] for c in fake.log}
        self.assertTrue(methods <= m.READ_ONLY_METHODS, methods)
        for _, method, params in fake.log:
            if method == 'eth_call':
                self.assertIn(params[0]['data'][2:10], m.ALLOWED_SELECTORS)
                self.assertNotIn('from', params[0])
        client = m.Client(FakeWorld(self.world))
        for method in ('eth_sendRawTransaction', 'eth_sendTransaction', 'personal_sign', 'eth_sign'):
            with self.assertRaises(PermissionError):
                client.call(['http://l2a'], method, [])
        with self.assertRaises(PermissionError):  # sweepFees() is a write, even through eth_call
            client.call(['http://eth'], 'eth_call', [{'to': self.world['config']['bridge']['vault'], 'data': '0xd113b95c'}, 'latest'])

    def test_second_run_scans_only_new_blocks(self):
        report, state, fake = run_world(self.world)
        self.assertEqual(state['cursors']['bridge'], self.world['eth']['head']['number'])
        report2, state, fake2 = run_world(self.world, state, self.world['now'] + 60)
        self.assertFalse([c for c in fake2.log if c[1] == 'eth_getLogs'], 'no new blocks, no log scan')
        self.assertEqual(report2['totals']['bridge_fee_accrued'], '6000000', 'no double counting')

    def test_bounded_scan_continues_next_run(self):
        self.world['config']['thresholds'] = {'max_scan_blocks': 4000}
        report, state, _ = run_world(self.world)
        self.assertEqual(checks(report)['bridge_scan']['level'], 'WARN')
        self.assertEqual(report['totals'].get('bridge_fee_accrued'), '5000000')
        for _ in range(2):
            report, state, _ = run_world(self.world, state, self.world['now'] + 60)
        self.assertEqual(report['totals']['bridge_fee_accrued'], '6000000')
        self.assertNotIn('bridge_scan', checks(report))

    def test_endpoint_failover_and_unknown_when_all_down(self):
        world = self.world
        fake = FakeWorld(world)
        fake.down.add('http://l2a')
        report = m.run(world['config'], m.empty_state(), m.Client(fake), world['now'])
        self.assertEqual(report['level'], 'OK')
        fake.down.add('http://l2b')
        report = m.run(world['config'], m.empty_state(), m.Client(fake), world['now'])
        self.assertEqual(checks(report)['l2_rpc']['level'], 'UNKNOWN')
        self.assertEqual(report['exit_code'], m.UNKNOWN)

    def test_wrong_l2_chain_is_crit(self):
        self.world['l2']['chain_id'] = 700771
        report, _, _ = run_world(self.world)
        self.assertEqual(checks(report)['l2_chain']['level'], 'CRIT')


class PartialFailures(unittest.TestCase):
    def setUp(self):
        self.world = load('world_live.json')

    def test_bridge_failure_after_first_event_does_not_count_it_twice(self):
        bad = copy.deepcopy(self.world)
        fees = [e for e in bad['eth']['logs'] if e['event'] == 'FeeAccrued']
        self.assertGreaterEqual(len(fees), 2)
        fake = FakeWorld(bad)
        original = fake.encode

        def malformed_later_event(event):
            topics, data = original(event)
            return (topics, '0x') if event is fees[-1] else (topics, data)

        fake.encode = malformed_later_event
        state = m.empty_state()
        failed = m.run(bad['config'], state, m.Client(fake), bad['now'])
        self.assertIn('bridge_error', checks(failed))
        self.assertFalse(any(k.startswith('bridge_') for k in state['totals']))
        self.assertNotIn('bridge', state['cursors'])
        self.assertIn('dex', state['cursors'], 'successful independent sections must be retained')
        retried, state, _ = run_world(self.world, state)
        expected, _, _ = run_world(self.world)
        self.assertEqual(retried['totals']['bridge_fee_accrued'], expected['totals']['bridge_fee_accrued'])

    def test_l2_failure_after_one_vault_preserves_both_baselines(self):
        _, state, _ = run_world(self.world)
        before = copy.deepcopy(state)
        self.world['l2']['accounts'][m.BASE_FEE_VAULT]['balance'] = 0
        fake = FakeWorld(self.world)

        def fail_second_vault(url, method, params):
            if method == 'eth_getBalance' and params[0] == m.SEQUENCER_FEE_VAULT:
                raise m.RpcError('second vault unavailable')
            return fake(url, method, params)

        failed = m.run(self.world['config'], state, m.Client(fail_second_vault), self.world['now'])
        self.assertIn('l2_fees_error', checks(failed))
        self.assertEqual(state['last']['l2_vault:base_fee'], before['last']['l2_vault:base_fee'])
        self.assertNotIn('l2_swept_base_fee', state['totals'])
        report, state, _ = run_world(self.world, state)
        self.assertEqual(report['totals']['l2_swept_base_fee'], before['last']['l2_vault:base_fee'])

    def test_forced_failure_keeps_queue_counter_for_retry(self):
        _, state, _ = run_world(self.world)
        self.world['l1']['forced']['queued'] += 2
        fake = FakeWorld(self.world)

        def fail_balance(url, method, params):
            if method == 'getbalance':
                raise m.RpcError('treasury unavailable')
            return fake(url, method, params)

        before = copy.deepcopy(state)
        failed = m.run(self.world['config'], state, m.Client(fail_balance), self.world['now'])
        self.assertIn('forced_error', checks(failed))
        self.assertEqual(state['last']['forced_queued'], before['last']['forced_queued'])
        self.assertNotIn('forced_records', state['totals'])
        report, state, _ = run_world(self.world, state)
        self.assertEqual(report['totals']['forced_records'], '2')


class SnapshotConsistency(unittest.TestCase):
    def world_for(self, product):
        world = load('world_live.json')
        for name in ('dex', 'bridge', 'l2_fees', 'forced'):
            if name != product:
                world['config'][name] = {'enabled': False}
        return world

    def test_each_evm_product_discards_a_sample_that_changes_branch(self):
        for product in ('dex', 'bridge', 'l2_fees'):
            with self.subTest(product=product):
                world = self.world_for(product)
                fake = FakeWorld(world)
                side = 'eth' if product == 'bridge' else 'l2'
                mutated = False

                def change_branch(url, method, params):
                    nonlocal mutated
                    result = fake(url, method, params)
                    if not mutated and method in ('eth_call', 'eth_getBalance'):
                        world[side]['branch'] = 1
                        mutated = True
                    return result

                state = m.empty_state()
                report = m.run(world['config'], state, m.Client(change_branch), world['now'])
                self.assertTrue(mutated)
                self.assertIn(product + '_error', checks(report))
                for key in ('totals', 'cursors', 'last', 'marks', 'days'):
                    self.assertEqual(state[key], {}, key)

    def test_no_endpoint_failover_after_the_sample_has_started(self):
        world = self.world_for('dex')
        fake = FakeWorld(world)

        def first_endpoint_loses_state(url, method, params):
            if url == 'http://l2a' and method == 'eth_call':
                raise m.RpcError('state unavailable on pinned endpoint')
            return fake(url, method, params)

        report = m.run(world['config'], m.empty_state(), m.Client(first_endpoint_loses_state), world['now'])
        self.assertIn('dex_error', checks(report))
        self.assertFalse(any(url == 'http://l2b' for url, _, _ in fake.log))

    def test_recheck_rejects_wrong_number_even_with_the_same_hash(self):
        world = self.world_for('dex')
        fake = FakeWorld(world)
        head = hex(world['l2']['head']['number'])

        def wrong_height(url, method, params):
            result = fake(url, method, params)
            if method == 'eth_getBlockByNumber' and params[0] == head:
                result['number'] = hex(world['l2']['head']['number'] + 1)
            return result

        report = m.run(world['config'], m.empty_state(), m.Client(wrong_height), world['now'])
        self.assertIn('dex_error', checks(report))

    def test_missing_block_hash_refuses_before_observations(self):
        world = self.world_for('dex')
        fake = FakeWorld(world)

        def no_hash(url, method, params):
            result = fake(url, method, params)
            if method == 'eth_getBlockByNumber':
                result.pop('hash')
            return result

        report = m.run(world['config'], m.empty_state(), m.Client(no_hash), world['now'])
        self.assertEqual(checks(report)['l2_rpc']['level'], 'UNKNOWN')
        self.assertFalse(any(method == 'eth_call' for _, method, _ in fake.log))

    def test_reorg_between_runs_preserves_the_last_valid_history(self):
        for product in ('dex', 'bridge', 'l2_fees'):
            with self.subTest(product=product):
                world = self.world_for(product)
                _, state, _ = run_world(world)
                before = copy.deepcopy(state)
                world['eth' if product == 'bridge' else 'l2']['branch'] = 1
                report, state, _ = run_world(world, state)
                self.assertIn(product + '_error', checks(report))
                self.assertEqual(state, before)

    def test_rollback_does_not_record_a_false_fee_sweep(self):
        world = self.world_for('l2_fees')
        _, state, _ = run_world(world)
        before = copy.deepcopy(state)
        world['l2']['head']['number'] -= 1
        world['l2']['accounts'][m.BASE_FEE_VAULT]['balance'] = 0
        report, state, _ = run_world(world, state)
        self.assertIn('l2_fees_error', checks(report))
        self.assertEqual(state, before)

    def test_deployment_change_requires_separate_history(self):
        for product in ('dex', 'bridge', 'l2_fees'):
            with self.subTest(product=product):
                world = self.world_for(product)
                _, state, _ = run_world(world)
                before = copy.deepcopy(state)
                if product == 'l2_fees':
                    world['config'][product]['recipient'] = '0x' + '12' * 20
                else:
                    world['config'][product]['start_block'] += 1
                report, state, _ = run_world(world, state)
                self.assertIn(product + '_error', checks(report))
                self.assertEqual(state, before)

    def test_unanchored_legacy_history_is_preserved_for_review(self):
        world = self.world_for('bridge')
        _, state, _ = run_world(world)
        state['anchors'].clear()
        before = copy.deepcopy(state)
        report, state, _ = run_world(world, state)
        self.assertIn('bridge_error', checks(report))
        self.assertEqual(state, before)

    def test_canonical_advancement_keeps_the_existing_totals(self):
        for product in ('dex', 'bridge', 'l2_fees'):
            with self.subTest(product=product):
                world = self.world_for(product)
                _, state, _ = run_world(world)
                totals = dict(state['totals'])
                side = 'eth' if product == 'bridge' else 'l2'
                world[side]['head']['number'] += 1
                report, state, _ = run_world(world, state)
                self.assertNotIn(product + '_error', checks(report))
                self.assertEqual(state['totals'], totals)
                self.assertEqual(state['anchors'][product]['checkpoint']['number'], world[side]['head']['number'])


class LaunchWorld(unittest.TestCase):
    def setUp(self):
        self.world = load('world_launch.json')

    def test_deposit_only_launch(self):
        report, state, _ = run_world(self.world)
        c = checks(report)
        self.assertEqual(c['dex']['level'], 'OK')
        self.assertIn('not deployed', c['dex']['message'])
        self.assertEqual(c['l2_fees_locked']['level'], 'OK')
        self.assertIn('deposit-only', c['l2_fees_locked']['message'])
        self.assertEqual(c['forced']['level'], 'OK')
        self.assertEqual(c['bridge_sweep']['level'], 'OK')
        self.assertEqual(report['totals']['bridge_fee_accrued'], '5500')
        self.assertEqual(report['level'], 'OK')

    def test_forced_burned_route_warns_once_traffic_starts(self):
        world = self.world
        world['l1']['forced'] = {'queued': 0, 'consumed': 0, 'pending': 0, 'pending_weight': 0,
                                 'max_pending_weight': 256, 'next_surcharge_sat': '1000'}
        report, state, _ = run_world(world)
        self.assertEqual(checks(report)['forced_route']['level'], 'OK')
        world['l1']['forced']['queued'] = 2
        report, state, _ = run_world(world, state, world['now'] + 60)
        c = checks(report)['forced_route']
        self.assertEqual(c['level'], 'WARN')
        self.assertIn('burned', c['message'])
        self.assertEqual(report['totals']['forced_min_surcharge_sat'], '2000')

    def test_vault_balance_before_the_fork_counts_as_accrued_and_locked(self):
        report, state, _ = run_world(self.world)
        self.world['l2']['accounts'] = {m.SEQUENCER_FEE_VAULT: {'balance': 7, 'code': '0x'}}
        report, state, _ = run_world(self.world, state, self.world['now'] + 60)
        self.assertEqual(report['days'][-1]['l2_accrued'], '7')
        self.assertIn('locked', checks(report)['l2_fees_locked']['message'])

    def test_tbd_recipients_warn(self):
        world = self.world
        world['config']['bridge']['fee_recipient'] = 'TBD-owner'
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['bridge_fee_recipient']['level'], 'WARN')
        world['config']['forced']['route'] = 'treasury'
        world['config']['forced']['treasury_script_hash'] = 'TBD-owner'
        world['l1']['forced'] = {'queued': 0, 'consumed': 0, 'pending': 0, 'pending_weight': 0}
        report, _, _ = run_world(world)
        self.assertEqual(checks(report)['forced_route']['level'], 'WARN')


class Cli(unittest.TestCase):
    def test_table_json_out_state_and_exit_code(self):
        world = load('world_live.json')
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / 'revenue.json'
            cfg.write_text(json.dumps(world['config']))
            st, js = Path(d) / 'state' / 'state.json', Path(d) / 'out' / 'report.json'
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = m.main(['--config', str(cfg), '--state', str(st), '--json-out', str(js)],
                              transport=FakeWorld(world), now=world['now'])
            self.assertEqual(code, m.OK)
            text = buf.getvalue()
            self.assertIn('DEX Safe LP (WBLCH)', text)
            self.assertIn('Bridge fees (USDC)', text)
            self.assertIn(m.day_of(world['now']), text)
            saved = json.loads(st.read_text())
            self.assertEqual(saved['schema'], m.STATE_SCHEMA)
            report = json.loads(js.read_text())
            self.assertEqual(report['schema'], m.SCHEMA)
            self.assertEqual(report['level'], 'OK')
            # Second run with --json reuses the state.
            buf = io.StringIO()
            with redirect_stdout(buf):
                m.main(['--config', str(cfg), '--state', str(st), '--json'], transport=FakeWorld(world), now=world['now'] + 60)
            self.assertEqual(json.loads(buf.getvalue())['totals']['bridge_fee_accrued'], '6000000')

    def test_example_config_parses_and_has_every_section(self):
        example = Path(__file__).resolve().parent / 'monitor' / 'revenue.json.example'
        cfg = json.loads(example.read_text())
        self.assertEqual(set(cfg) - {'_comment'}, {'l2', 'dex', 'bridge', 'l2_fees', 'forced', 'thresholds'})
        self.assertEqual(set(cfg['thresholds']) - set(m.DEFAULT_THRESHOLDS), set())

    def test_sweep_code_matches_the_fork_candidate_bytes(self):
        # bloch-l2-evm src/chainspec.rs fee_vault_sweep_code (fork candidate d462647, lines 156-161):
        # [0x5f,0x5f,0x5f,0x5f,0x47,0x73] ++ recipient ++ [0x5a,0xf1,0x15,0x60,0x21,0x57,0x00,0x5b,0x5f,0x5f,0xfd]
        head = bytes([0x5f, 0x5f, 0x5f, 0x5f, 0x47, 0x73])
        tail = bytes([0x5a, 0xf1, 0x15, 0x60, 0x21, 0x57, 0x00, 0x5b, 0x5f, 0x5f, 0xfd])
        recipient = '0x14c0aeb5497a4e506b6c12556718be957302d96d'
        code = m.sweep_code(recipient)
        self.assertEqual(code, '0x' + (head + bytes.fromhex(recipient[2:]) + tail).hex())
        self.assertEqual(len(code), 2 + 2 * 37)

    def test_render_table_handles_missing_values(self):
        state = m.empty_state()
        m.put(state, '2026-11-03', 'bridge_unswept', 5_500)
        text = m.render_table(m.day_rows(state, 14))
        self.assertIn('0.005500', text)
        self.assertIn('-', text)


if __name__ == '__main__':
    unittest.main()
