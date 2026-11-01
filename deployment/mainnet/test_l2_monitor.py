#!/usr/bin/env python3
"""Unit tests for l2_monitor.py with fake RPC, command and HTTP transports (no network, no systemd).

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_l2_monitor.py' -v
"""
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import l2_monitor as m  # noqa: E402

EPOCH = 7000
NOW = m.epoch_start(EPOCH) + 100
L2A, L2B = 'http://l2a', 'http://l2b'
L1 = ['http://l1a', 'http://l1b', 'http://l1c']
BLCH_WEI = 10 ** 18
GENESIS = m.MAINNET_PINS['l2_genesis_hash']


def block(number, age, h=None):
    return {'number': hex(number), 'timestamp': hex(NOW - age), 'hash': '0x' + (h or f'{number:064x}'),
            'baseFeePerGas': hex(10 ** 9)}


def hard_forks():
    return {name: {'activation_epoch': (m.V2_COMPILED_GATES[c] if not isinstance(m.V2_COMPILED_GATES[c], list)
                                        else 7270), 'active': False}
            for name, c in m.GATE_CONSTANTS.items()} | {'hf3_lattice_emergency': {'activation_epoch': None,
                                                                                   'active': False}}


def healthy():
    """A live mainnet snapshot: settlement 5 min old, L1 finality 2 epochs, follower 3 epochs (structural)."""
    l1 = {
        'height': 186000, 'epoch': EPOCH, 'slot': EPOCH * 32 + 3, 'finalized_height': 185930,
        'finalized': {'epoch': EPOCH - 2, 'root': 'aa' * 32}, 'hard_forks': hard_forks(),
    }
    settlement = {
        'chain_id': 700770, 'network': m.MAINNET_PINS['network'], 'genesis': m.MAINNET_PINS['genesis'],
        'native_height': 34000, 'profile': {'activated': True},
        'source': {'slot': (NOW - 300 - m.L1_GENESIS_TIME) // 30, 'height': 101},
        'inbox': {'count': 3, 'consumed': 3, 'escrow_sat': str(124 * 10 ** 8)},
        'data_availability': [],
        'withdrawals': {'escrow_conserved': True, 'released_sat': str(176 * 10 ** 8),
                        'attestor_set': m.MAINNET_PINS['attestor_set'], 'roots': [],
                        'release_window': {'window': 7, 'cap_sat': str(10 ** 9), 'remaining_sat': str(10 ** 9)}},
        'accepted': {'commitment': 'cc' * 32, 'statement': '00' * 286 + (100).to_bytes(8, 'big').hex()},
    }
    backend = {
        'eth_chainId': '0xab162',
        'latest': block(101, 5 * 60), 'safe': block(100, 17 * 60), 'finalized': block(95, 100 * 60),
        'bloch_finality': {'finalized_height': 95,
                           'l1': {'verified_blocks': 185930, 'finalized': {'epoch': EPOCH - 5}}},
        'ledger': {'0x0': 300 * BLCH_WEI, '0x2': 0, '0x3': 176 * BLCH_WEI},
    }
    return {
        'l2': {L2A: backend, L2B: copy.deepcopy(backend)},
        'l1': {url: {'info': copy.deepcopy(l1), 'l2': copy.deepcopy(settlement)} for url in L1},
    }


def prelaunch():
    """The live mainnet today: L2 at genesis, nothing ever settled (accepted null)."""
    w = healthy()
    for node in w['l1'].values():
        node['l2']['accepted'] = None
        node['l2']['source'] = {'slot': 187200, 'height': 1}
        node['l2']['inbox'] = {'count': 0, 'consumed': 0, 'escrow_sat': '0'}
        node['l2']['withdrawals']['released_sat'] = '0'
    for b in w['l2'].values():
        g = block(0, NOW - 1786656679, GENESIS)
        b.update({'latest': g, 'safe': g, 'finalized': g, 'ledger': {'0x0': 0, '0x2': 0, '0x3': 0}})
        b['bloch_finality']['finalized_height'] = 0
    return w


class Fake:
    def __init__(self, world):
        self.world = world
        self.calls = []

    def __call__(self, url, method, params):
        self.calls.append((url, method))
        if url in (L2A, L2B):
            w = self.world['l2'].get(url)
            if w is None:
                raise m.RpcError('connection refused')
            if method == 'eth_chainId':
                return w['eth_chainId']
            if method == 'eth_getBlockByNumber':
                if w.get('closed') and params[0] in ('safe', 'finalized'):
                    raise m.RpcError('finality unavailable', m.FINALITY_CLOSED_CODE)
                return w[params[0]]
            if method == 'bloch_finality':
                return w['bloch_finality']
            if method == 'eth_getStorageAt':
                return hex(w['ledger'][params[1]])
        node = self.world['l1'].get(url)
        if node is None:
            raise m.RpcError('connection refused')
        if method == 'getchaininfo':
            return node['info']
        if method == 'getl2settlement':
            return node['l2']
        if method == 'getutxos':
            if 'utxos' not in node:
                raise m.RpcError('no such method')
            return {'utxos': [{'value_sat': str(v)} for v in node['utxos']]}
        raise AssertionError(f'unexpected {method}')


def run(world, *extra, phase='live', runner=None, fetch=None):
    argv = ['--profile', 'mainnet', '--phase', phase, '--l2-rpc', f'A={L2A}', '--l2-rpc', f'B={L2B}']
    argv += sum((['--l1-rpc', u] for u in L1), []) + list(extra)
    args = m.parse(argv)
    fake = Fake(world)
    return m.run(args, fake, now=NOW, run_cmd=runner or (lambda a: (1, '')), fetch=fetch or (lambda u: None)), fake


def level(report, name):
    found = [c['level'] for c in report.checks if c['check'] == name]
    if not found:
        raise AssertionError(f'no check {name}: {[c["check"] for c in report.checks]}')
    return found[0]


def partial(index, root, chain=700770):
    digest = hashlib.sha3_256(m.ATTESTATION_DOMAIN + bytes.fromhex(m.MAINNET_PINS['network'])
                              + chain.to_bytes(8, 'big') + bytes.fromhex(root)).hexdigest()
    return f'{index}\n{digest}\n{"ab" * 3000}\n'.encode()


class MonitorTests(unittest.TestCase):
    def test_healthy_snapshot_is_ok(self):
        r, _ = run(healthy())
        self.assertEqual(m.LEVEL_NAMES[r.status], 'OK', json.dumps(r.checks, indent=1))
        self.assertEqual(r.facts['l2_latest'], 101)
        self.assertEqual(r.facts['l1_finalized_epoch'], EPOCH - 2)
        self.assertEqual(r.facts['l2_settled_number'], 100)

    def test_prelaunch_mainnet_today_is_ok_and_live_phase_alerts(self):
        r, _ = run(prelaunch(), phase='prelaunch')
        self.assertEqual(m.LEVEL_NAMES[r.status], 'OK', json.dumps(r.checks, indent=1))
        r, _ = run(prelaunch(), phase='live')
        self.assertEqual(level(r, 'settlement_age'), 'CRIT')
        self.assertEqual(level(r, 'l2_head_age'), 'CRIT')

    def test_prelaunch_with_a_settlement_asks_for_live_phase(self):
        r, _ = run(healthy(), phase='prelaunch')
        self.assertEqual(level(r, 'phase'), 'WARN')

    def test_only_read_only_methods_are_called(self):
        _, fake = run(healthy())
        self.assertTrue({method for _, method in fake.calls} <= m.READ_ONLY_METHODS)

    def test_client_refuses_write_methods_without_io(self):
        transport = mock.Mock()
        client = m.Client(transport)
        for method in ('eth_sendRawTransaction', 'sendrawtransaction', 'personal_sign', 'eth_sign', 'submitl2'):
            with self.assertRaises(PermissionError):
                client.call(L2A, method, [])
        transport.assert_not_called()

    def test_runner_refuses_anything_but_systemctl_show_and_journalctl(self):
        for argv in (['systemctl', 'restart', 'x'], ['systemctl', 'stop', 'x'], ['rm', '-rf', '/']):
            with self.assertRaises(PermissionError):
                m.subprocess_runner(argv)

    # ---- L1
    def test_l1_finality_lag(self):
        w = healthy()
        for node in w['l1'].values():
            node['info']['finalized']['epoch'] = EPOCH - 5
        self.assertEqual(level(run(w)[0], 'l1_finality_lag'), 'WARN')
        for node in w['l1'].values():
            node['info']['finalized']['epoch'] = EPOCH - 9
        self.assertEqual(level(run(w)[0], 'l1_finality_lag'), 'CRIT')

    def test_one_l1_node_down_warns_majority_down_crits(self):
        w = healthy()
        del w['l1'][L1[0]]
        self.assertEqual(level(run(w)[0], 'l1_nodes'), 'WARN')
        del w['l1'][L1[1]]
        self.assertEqual(level(run(w)[0], 'l1_nodes'), 'CRIT')

    def test_l1_identity_pins(self):
        w = healthy()
        w['l1'][L1[2]]['l2']['withdrawals']['attestor_set'] = '00' * 32
        self.assertEqual(level(run(w)[0], 'l1_l2_identity'), 'CRIT')
        w = healthy()
        w['l1'][L1[0]]['l2']['network'] = '11' * 32
        self.assertEqual(level(run(w)[0], 'l1_l2_identity'), 'CRIT')

    def test_l1_accepted_split_warns(self):
        w = healthy()
        w['l1'][L1[2]]['l2']['accepted']['commitment'] = 'dd' * 32
        self.assertEqual(level(run(w)[0], 'l1_accepted_agreement'), 'WARN')

    # ---- settlement age
    def test_settlement_age(self):
        w = healthy()
        for node in w['l1'].values():
            node['l2']['source']['slot'] = (NOW - 30 * 60 - m.L1_GENESIS_TIME) // 30
        self.assertEqual(level(run(w)[0], 'settlement_age'), 'WARN')
        for node in w['l1'].values():
            node['l2']['source']['slot'] = (NOW - 50 * 60 - m.L1_GENESIS_TIME) // 30
        self.assertEqual(level(run(w)[0], 'settlement_age'), 'CRIT')

    # ---- L2 backends
    def test_stale_head_is_critical(self):
        w = healthy()
        for b in w['l2'].values():
            b['latest'] = block(101, 50 * 60)
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_head_age'), 'CRIT')
        self.assertEqual(r.status, m.CRIT)

    def test_unsafe_depth(self):
        w = healthy()
        for b in w['l2'].values():
            b['safe'] = block(99, 30 * 60)
        self.assertEqual(level(run(w)[0], 'l2_unsafe_depth'), 'WARN')
        for b in w['l2'].values():
            b['safe'] = block(96, 60 * 60)
        self.assertEqual(level(run(w)[0], 'l2_unsafe_depth'), 'CRIT')

    def test_tag_inversion_is_critical(self):
        w = healthy()
        w['l2'][L2B]['finalized'] = block(101, 5 * 60)
        w['l2'][L2B]['bloch_finality']['finalized_height'] = 101
        self.assertEqual(level(run(w)[0], 'l2_tag_order[B]'), 'CRIT')

    def test_one_backend_down_warns_both_down_crits(self):
        w = healthy()
        del w['l2'][L2B]
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_rpc[B]'), 'CRIT')
        self.assertEqual(level(r, 'l2_backends'), 'WARN')
        del w['l2'][L2A]
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_backends'), 'CRIT')

    def test_wrong_chain_id_on_one_backend(self):
        w = healthy()
        w['l2'][L2A]['eth_chainId'] = '0xab163'
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_rpc[A]'), 'CRIT')
        self.assertEqual(r.facts['l2_primary_backend'], 'B')

    def test_backends_disagree_on_a_block_is_critical(self):
        w = healthy()
        w['l2'][L2B]['finalized'] = block(95, 100 * 60, 'ee' * 32)
        self.assertEqual(level(run(w)[0], 'l2_backends_agree'), 'CRIT')

    def test_backend_finalized_spread(self):
        w = healthy()
        w['l2'][L2B]['finalized'] = block(90, 150 * 60)
        w['l2'][L2B]['bloch_finality']['finalized_height'] = 90
        self.assertEqual(level(run(w)[0], 'l2_backends_agree'), 'WARN')

    def test_wrong_l2_genesis_is_critical(self):
        w = prelaunch()
        w['l2'][L2B]['finalized'] = block(0, 10, 'ab' * 32)
        self.assertEqual(level(run(w, phase='prelaunch')[0], 'l2_genesis[B]'), 'CRIT')

    def test_rpc_without_follower_status_warns(self):
        w = healthy()
        for b in w['l2'].values():
            b['safe'] = None
            b['finalized'] = None
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_safe'), 'WARN')
        self.assertEqual(level(r, 'l2_finalized'), 'WARN')

    def test_finalized_age(self):
        w = healthy()
        for b in w['l2'].values():
            b['finalized'] = block(80, 5 * 3600)
            b['bloch_finality']['finalized_height'] = 80
        self.assertEqual(level(run(w)[0], 'l2_finalized_age'), 'CRIT')

    # ---- follower
    def test_follower_epoch_lag_three_is_structural(self):
        r, _ = run(healthy())
        self.assertEqual(level(r, 'follower_epoch_lag[A]'), 'OK')
        w = healthy()
        w['l2'][L2A]['bloch_finality']['l1']['finalized']['epoch'] = EPOCH - 2 - 5
        self.assertEqual(level(run(w)[0], 'follower_epoch_lag[A]'), 'WARN')
        w['l2'][L2A]['bloch_finality']['l1']['finalized']['epoch'] = EPOCH - 2 - 9
        self.assertEqual(level(run(w)[0], 'follower_epoch_lag[A]'), 'CRIT')

    def test_follower_verified_lag(self):
        w = healthy()
        w['l2'][L2B]['bloch_finality']['l1']['verified_blocks'] = 185930 - 400
        self.assertEqual(level(run(w)[0], 'follower_verified_lag[B]'), 'CRIT')

    def test_follower_status_size_alerts_before_the_rpc_limit(self):
        with tempfile.TemporaryDirectory() as d:
            def run(document, pad=0, log_text=None):
                path = Path(d) / 'status.json'
                document = {'written_at_unix': NOW, 'chain_id': 700770, 'network': m.MAINNET_PINS['network'],
                            'verified_blocks': 1, 'native_finalized_epoch': EPOCH, **document}
                path.write_text(json.dumps(document) + ' ' * pad)
                if log_text is not None:
                    (Path(d) / 'status.settlements.jsonl').write_text(log_text)
                r = m.Report()
                m.status_size('f', str(path), document, m.PROFILES['mainnet'], NOW, r)
                return r
            v2 = {'schema': 'v2', 'finalized_settlements': [{'l2_number': 1}]}
            self.assertEqual(level(run(v2), 'follower_status_size[f]'), 'OK')
            self.assertEqual(level(run(v2, pad=8 * 1_048_576), 'follower_status_size[f]'), 'WARN')
            self.assertEqual(level(run(v2, pad=12 * 1_048_576), 'follower_status_size[f]'), 'CRIT')
            self.assertIn('settlements before', [c for c in run(v2).checks if c['check'].startswith('follower_status_size')][0]['message'])
            v3 = {'schema': 'v3', 'finalized_settlements_count': 1,
                  'settlement_log': {'file': 'status.settlements.jsonl', 'entries': 1, 'bytes': 10}}
            r = run(v3, log_text='x' * 10)
            self.assertEqual(level(r, 'follower_status_size[f]'), 'OK')
            self.assertEqual(level(r, 'follower_settlement_log[f]'), 'OK')
            self.assertEqual(level(run(v3, log_text='x' * 9), 'follower_settlement_log[f]'), 'CRIT')
            (Path(d) / 'status.settlements.jsonl').unlink()
            self.assertEqual(level(run(v3), 'follower_settlement_log[f]'), 'CRIT')

    def test_status_runway_warns_months_ahead_at_the_observed_cadence(self):
        def runway(count, minutes):
            slots = int(minutes * 2)
            entries = [{'l2_number': n, 'native_slot': 100000 + n * slots} for n in range(max(1, count - 63), count + 1)]
            r = m.Report()
            m.settlement_runway('c', count, m.STATUS_V2_LIMIT_V21, m.settlement_rate(entries), m.PROFILES['mainnet'], NOW, r)
            return r
        limit = m.STATUS_V2_LIMIT_V21 // m.STATUS_BYTES_PER_SETTLEMENT
        # One settlement every 15 minutes: 251 days from zero.
        self.assertEqual(level(runway(100, 15), 'c'), 'OK')
        self.assertEqual(level(runway(limit - 11000, 15), 'c'), 'WARN')  # 114 days left
        self.assertEqual(level(runway(limit - 4000, 15), 'c'), 'CRIT')  # 41 days left
        # One a minute: 21 days from zero, so CRIT from the first window.
        self.assertEqual(level(runway(100, 1), 'c'), 'CRIT')
        self.assertIn('days left', runway(100, 15).checks[0]['message'])
        self.assertIn('--status-schema v3', runway(100, 1).checks[0]['message'])
        # The count alone grades when no rate is known.
        r = m.Report()
        m.settlement_runway('c', 15_000, m.STATUS_V2_LIMIT_V21, None, m.PROFILES['mainnet'], NOW, r)
        self.assertEqual(level(r, 'c'), 'WARN')
        r = m.Report()
        m.settlement_runway('c', 22_500, m.STATUS_V2_LIMIT_V21, None, m.PROFILES['mainnet'], NOW, r)
        self.assertEqual(level(r, 'c'), 'CRIT')
        r = m.Report()
        m.settlement_runway('c', 22_500, m.STATUS_V2_LIMIT_NEXT, None, m.PROFILES['mainnet'], NOW, r)
        self.assertEqual(level(r, 'c'), 'OK')

    def test_status_runway_from_the_rpc_alone(self):
        class Client:
            def __init__(self, table, fail=False): self.table, self.fail = table, fail
            def call(self, url, method, params):
                if self.fail: raise m.RpcError('down')
                return self.table.get(params[0])
        table = {n: {'l2_number': n, 'native_slot': 100000 + n * 24} for n in range(1, 30001)}  # one per 12 minutes
        def check(status, height=23000, fail=False):
            r = m.Report()
            view = {'name': 'A', 'url': 'u', 'finality': {'finalized_height': height, 'status': status}}
            m.rpc_status_runway(Client(table, fail), view, m.PROFILES['mainnet'], NOW, r)
            return r
        v21 = {'state': 'ok', 'age_s': 3}
        self.assertEqual(level(check(v21), 'l2_status_runway[A]'), 'CRIT')
        self.assertEqual(level(check(v21, height=100), 'l2_status_runway[A]'), 'OK')
        # Without bloch_settlement the count still grades, and a v2.1 RPC is not given the next build's limit.
        self.assertEqual(level(check(v21, fail=True), 'l2_status_runway[A]'), 'CRIT')
        self.assertEqual(level(check({**v21, 'schema': 'bloch.l2.native-follower-status.v2'}), 'l2_status_runway[A]'), 'OK')
        r = check({**v21, 'schema': 'bloch.l2.native-follower-status.v3'})
        self.assertEqual(level(r, 'l2_status_runway[A]'), 'OK')
        self.assertIn('no size limit', r.checks[0]['message'])
        self.assertEqual(check(v21, height=0).checks, [])
    def test_follower_file_against_the_rpc_finalized_height(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, 'f.json')
            base = {'chain_id': 700770, 'network': m.MAINNET_PINS['network'], 'verified_blocks': 185930,
                    'native_finalized_epoch': EPOCH - 5, 'l2_genesis': {'hash': GENESIS}, 'written_at_unix': NOW - 20}

            def lag_levels(newest, key='finalized_settlements'):
                path.write_text(json.dumps({**base, key: [{'l2_number': newest}]}))
                r, _ = run(healthy(), '--follower-status', f'f={path}')
                return level(r, 'finality_file_lag[f:A]')
            self.assertEqual(lag_levels(95), 'OK')
            self.assertEqual(lag_levels(90), 'OK', 'an RPC ahead of this file is not lagging')
            self.assertEqual(lag_levels(96), 'WARN')
            self.assertEqual(lag_levels(98), 'CRIT')
            self.assertEqual(lag_levels(98, 'finalized_settlements_recent'), 'CRIT', 'schema v3 lists its newest')
            world = healthy()
            world['l2'][L2A]['bloch_finality'] = {'finalized_height': 95, 'status': {'state': 'ok', 'age_s': 1, 'written_at_unix': NOW - 1}}
            path.write_text(json.dumps({**base, 'finalized_settlements': [{'l2_number': 200}]}))
            r, _ = run(world, '--follower-status', f'f={path}')
            self.assertEqual(level(r, 'finality_file_lag[f:A]'), 'CRIT', 'the case where age_s reads young')

    def test_follower_status_file(self):
        with tempfile.TemporaryDirectory() as d:
            good, stale, wrong = Path(d, 'a.json'), Path(d, 'b.json'), Path(d, 'c.json')
            base = {'chain_id': 700770, 'network': m.MAINNET_PINS['network'], 'verified_blocks': 185930,
                    'native_finalized_epoch': EPOCH - 5, 'l2_genesis': {'hash': GENESIS}, 'written_at_unix': NOW - 20}
            good.write_text(json.dumps(base))
            stale.write_text(json.dumps({**base, 'written_at_unix': NOW - 2000}))
            wrong.write_text(json.dumps({**base, 'network': '00' * 32}))
            r, _ = run(healthy(), '--follower-status', f'fa={good}', '--follower-status', f'fb={stale}',
                       '--follower-status', f'fc={wrong}', '--follower-status', f'fd={d}/missing.json')
        self.assertEqual(level(r, 'follower_status[fa]'), 'OK')
        self.assertEqual(level(r, 'follower_epoch_lag[fa:status]'), 'OK')
        self.assertEqual(level(r, 'follower_status[fb]'), 'CRIT')
        self.assertEqual(level(r, 'follower_status[fc]'), 'CRIT')
        self.assertEqual(level(r, 'follower_status[fd]'), 'CRIT')

    # ---- escrow / reserves
    def test_escrow_not_conserved_on_one_node(self):
        w = healthy()
        w['l1'][L1[1]]['l2']['withdrawals']['escrow_conserved'] = False
        self.assertEqual(level(run(w)[0], 'escrow_conserved'), 'CRIT')

    def test_escrow_backing_shortfall(self):
        w = healthy()
        for b in w['l2'].values():
            b['ledger']['0x0'] = 301 * BLCH_WEI
        r, _ = run(w)
        self.assertEqual(level(r, 'escrow_backing'), 'CRIT')
        w = healthy()
        for b in w['l2'].values():
            b['ledger']['0x3'] = 100 * BLCH_WEI
        self.assertEqual(level(run(w)[0], 'claims_vs_withdrawn'), 'CRIT')

    def test_reserve_ratio_fact(self):
        r, _ = run(healthy())
        self.assertEqual(r.facts['l2_outstanding_wei'], 124 * BLCH_WEI)
        self.assertEqual(r.facts['reserve_ratio'], 1.0)

    def test_backlogs_and_release_window(self):
        w = healthy()
        for node in w['l1'].values():
            node['l2']['inbox']['count'] = 60
            node['l2']['data_availability'] = [{}] * 12
            node['l2']['withdrawals']['release_window']['remaining_sat'] = '0'
        r, _ = run(w)
        self.assertEqual(level(r, 'inbox_backlog'), 'WARN')
        self.assertEqual(level(r, 'da_backlog'), 'CRIT')
        self.assertEqual(level(r, 'release_window'), 'WARN')

    # ---- gates
    def test_gate_approaching(self):
        r, _ = run(healthy())
        self.assertEqual(level(r, 'l1_gates'), 'OK')  # 180 epochs ahead
        w = healthy()
        for node in w['l1'].values():
            node['info']['epoch'] = 7100
        r, _ = run(w, '--set', 'l1_finality_epochs_warn=200', '--set', 'l1_finality_epochs_crit=300',
                   '--set', 'follower_epoch_lag_warn=200', '--set', 'follower_epoch_lag_crit=300')
        self.assertEqual(level(r, 'l1_gates'), 'WARN')
        for node in w['l1'].values():
            node['info']['epoch'] = 7176
        r, _ = run(w, '--set', 'l1_finality_epochs_warn=200', '--set', 'l1_finality_epochs_crit=300',
                   '--set', 'follower_epoch_lag_warn=200', '--set', 'follower_epoch_lag_crit=300')
        self.assertEqual(level(r, 'l1_gates'), 'CRIT')
        self.assertIn('e7180', next(c['message'] for c in r.checks if c['check'] == 'l1_gates'))

    def test_gate_mismatch_with_the_l2_build_is_critical(self):
        w = healthy()
        for node in w['l1'].values():
            node['info']['hard_forks']['hf2_growth_cap']['activation_epoch'] = 7300
        self.assertEqual(level(run(w)[0], 'l1_gates_vs_l2_build'), 'CRIT')

    def test_gate_check_reads_build_json(self):
        with tempfile.TemporaryDirectory() as d:
            bj = Path(d, 'build.json')
            bj.write_text(json.dumps({'l1_activation_epochs': {'HF1_CLAIM_FINALITY_EPOCH': 7181}}))
            r, _ = run(healthy(), '--build-json', str(bj))
        self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'CRIT')

    def test_l1_without_hard_forks_warns(self):
        w = healthy()
        for node in w['l1'].values():
            del node['info']['hard_forks']
        self.assertEqual(level(run(w)[0], 'l1_gates'), 'WARN')

    # ---- attestors
    def attest_world(self, ages):
        w = healthy()
        roots = [{'l2_number': 50 + i, 'root': f'{i + 1:064x}', 'count': i + 1, 'height': 34000 - age,
                  'finalized': True} for i, age in enumerate(ages)]
        for node in w['l1'].values():
            node['l2']['withdrawals']['roots'] = roots
        return w, roots

    def test_attestor_signatures_per_round(self):
        w, roots = self.attest_world([500, 400, 10])
        with tempfile.TemporaryDirectory() as d:
            def put(root, signers):
                for i in signers:
                    q = Path(d, '700770', root['root'], f'attestor-{i}.partial')
                    q.parent.mkdir(parents=True, exist_ok=True)
                    q.write_bytes(partial(i, root['root']))
            put(roots[0], [0, 1, 2, 3, 4])
            put(roots[1], [0, 1, 2, 4])
            put(roots[2], [0])  # within the grace period: not judged yet
            r, _ = run(w, '--attest-drop', d)
            self.assertEqual(level(r, 'attestors'), 'WARN')
            self.assertIn('#3 (1)', next(c['message'] for c in r.checks if c['check'] == 'attestors'))
            for i in (1, 2, 4):
                os.remove(Path(d, '700770', roots[1]['root'], f'attestor-{i}.partial'))
            r, _ = run(w, '--attest-drop', d)
            self.assertEqual(level(r, 'attestors'), 'CRIT')
            self.assertEqual([x['signatures'] for x in r.facts['attestation_rounds']], [5, 1, 1])

    def test_attestor_partial_must_match_index_and_digest(self):
        w, roots = self.attest_world([500])
        root = roots[0]['root']
        good = {f'https://drop/700770/{root}/attestor-{i}.partial': partial(i, root) for i in range(3)}
        good[f'https://drop/700770/{root}/attestor-3.partial'] = partial(4, root)       # wrong index
        good[f'https://drop/700770/{root}/attestor-4.partial'] = partial(4, 'ff' * 32)  # wrong root
        r, _ = run(w, '--attest-drop', 'https://drop', fetch=good.get)
        self.assertEqual(r.facts['attestation_rounds'][0]['signers'], [0, 1, 2])
        self.assertEqual(level(r, 'attestors'), 'WARN')

    def test_an_oversized_partial_is_not_a_vote(self):
        root = 'ab' * 32
        def sized(n):
            good = partial(1, root).decode().splitlines()
            return '\n'.join([good[0], good[1], 'ab' * n]).encode() + b'\n'
        self.assertTrue(m.partial_ok(sized(4593), 1, 700770, root))
        self.assertFalse(m.partial_ok(sized(4594), 1, 700770, root))

    def test_rounds_without_partials_are_not_faults(self):
        w, _ = self.attest_world([500, 400])
        with tempfile.TemporaryDirectory() as d:
            r, _ = run(w, '--attest-drop', d)
        self.assertEqual(level(r, 'attestors'), 'OK')

    # ---- units and logs
    def test_units_and_journal_events(self):
        def runner(argv):
            unit = argv[2]
            if argv[0] == 'systemctl':
                if unit == 'shadow.service':
                    return 0, 'LoadState=loaded\nActiveState=failed\nSubState=failed\nNRestarts=0\nExecMainStatus=3\nResult=exit-code\n'
                if unit == 'missing.service':
                    return 0, 'LoadState=not-found\n'
                return 0, 'LoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=1\nExecMainStatus=0\nResult=success\n'
            t = m.datetime.datetime.fromtimestamp(NOW - 60, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            old = m.datetime.datetime.fromtimestamp(NOW - 7200, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            if unit == 'settler.service':
                lines = [{'time': old, 'event': 'halt', 'reason': 'old'},
                         {'time': t, 'event': 'prover-failed', 'exit_code': 1},
                         {'time': t, 'event': 'remote-proof', 'exit_code': 137},
                         {'time': t, 'event': 'accepted', 'number': 7}]
            elif unit == 'shadow.service':
                lines = [{'time': t, 'event': 'halt', 'reason': 'block 7 differs from the settler'}]
            else:
                lines = [{'time': t, 'event': 'shadow-match'}]
            return 0, '\n'.join('Oct 30 host python3[1]: ' + json.dumps(x) for x in lines)
        r, _ = run(healthy(), '--unit', 'settler=settler.service', '--unit', 'shadow=shadow.service',
                   '--unit', 'missing.service', '--unit', 'ok=ok.service', runner=runner)
        self.assertEqual(level(r, 'unit[settler]'), 'OK')
        self.assertEqual(level(r, 'events[settler]'), 'WARN')
        self.assertIn('prover-failed x2', next(c['message'] for c in r.checks if c['check'] == 'events[settler]'))
        self.assertEqual(level(r, 'unit[shadow]'), 'CRIT')
        self.assertEqual(level(r, 'events[shadow]'), 'CRIT')
        self.assertEqual(level(r, 'unit[missing.service]'), 'CRIT')
        self.assertEqual(level(r, 'events[ok]'), 'OK')

    def test_foreign_settlements_alert_over_a_day(self):
        stamp = lambda age: m.datetime.datetime.fromtimestamp(NOW - age, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        ev = lambda age: json.dumps({'time': stamp(age), 'event': 'foreign-settlement-recovered', 'number': 7})
        with tempfile.TemporaryDirectory() as d:
            log = Path(d, 'settler.log')
            log.write_text(ev(90000) + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertNotIn('foreign_settlements[settler]', [c['check'] for c in r.checks])
            log.write_text(ev(90000) + '\n' + ev(7200) + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'foreign_settlements[settler]'), 'WARN')
            self.assertEqual(level(r, 'events[settler]'), 'OK')
            log.write_text(ev(7200) + '\n' + ev(60) + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'foreign_settlements[settler]'), 'CRIT')
            self.assertIn('L2 block 7', next(c['message'] for c in r.checks if c['check'] == 'foreign_settlements[settler]'))

        def runner(argv):
            if argv[0] == 'systemctl':
                return 0, 'LoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=0\nExecMainStatus=0\nResult=success\n'
            return 0, ev(7200) + '\n'
        r = m.Report()
        m.check_units(['settler=settler.service'], m.PROFILES['mainnet'], NOW, runner, r)
        self.assertEqual(level(r, 'foreign_settlements[settler]'), 'WARN')

    def test_repeated_warn_events_escalate(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d, 'settler.log')
            t = m.datetime.datetime.fromtimestamp(NOW - 30, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            log.write_text('\n'.join(json.dumps({'time': t, 'event': 'rpc-no-quorum'}) for _ in range(5)) + '\nnot json\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
        self.assertEqual(level(r, 'events[settler]'), 'CRIT')

    def test_finality_states_of_the_next_build(self):
        world = healthy()
        world['l2'][L2A]['bloch_finality']['status'] = {'state': 'lagging', 'age_s': 60, 'missing_settlement': 96}
        world['l2'][L2B]['bloch_finality']['status'] = {'state': 'lagging', 'age_s': 7200, 'missing_settlement': 96}
        r, _ = run(world)
        self.assertEqual(level(r, 'l2_finality_status[A]'), 'WARN')
        self.assertEqual(level(r, 'l2_finality_status[B]'), 'CRIT')
        self.assertIn('settlement 96', next(c['message'] for c in r.checks if c['check'] == 'l2_finality_status[A]'))
        world = healthy()
        world['l2'][L2A]['bloch_finality']['status'] = {'state': 'starting', 'age_s': None}
        r, _ = run(world)
        self.assertEqual(level(r, 'l2_finality_status[A]'), 'WARN')

    def test_finality_closed_and_status_age(self):
        world = healthy()
        world['l2'][L2A]['safe'] = world['l2'][L2A]['finalized'] = None
        world['l2'][L2A]['closed'] = True
        world['l2'][L2A]['bloch_finality'] = {'status': {'state': 'missing', 'age_s': None}}
        world['l2'][L2B]['bloch_finality']['status'] = {'state': 'ok', 'age_s': 5000}
        r, _ = run(world)
        self.assertEqual(level(r, 'l2_rpc[A]'), 'OK')
        self.assertEqual(level(r, 'l2_finality_closed[A]'), 'CRIT')
        self.assertEqual(level(r, 'l2_finality_status[B]'), 'CRIT')
        world = healthy()
        world['l2'][L2A]['bloch_finality']['status'] = {'state': 'ok', 'age_s': 30}
        world['l2'][L2B]['bloch_finality']['status'] = {'state': 'ok', 'age_s': 400}
        r, _ = run(world)
        self.assertEqual(level(r, 'l2_finality_status[A]'), 'OK')
        self.assertEqual(level(r, 'l2_finality_status[B]'), 'WARN')

    def test_guardian_health(self):
        good = {'t': NOW - 30, 'bridge': 'busdc', 'healthy': True, 'verified_t': NOW - 30, 'problems': {}}
        cases = [
            ('ok', good, 'OK', 'OK', 'OK'),
            ('failed-pause', {**good, 'healthy': False, 'problems': {'pause-failed': {'t': NOW, 'detail': 'x'}}}, 'CRIT', 'OK', 'OK'),
            ('dead', {**good, 't': NOW - 5000, 'verified_t': NOW - 5000}, 'OK', 'CRIT', 'CRIT'),
            ('late', {**good, 't': NOW - 400, 'verified_t': NOW - 400}, 'OK', 'WARN', 'WARN'),
            ('blind', {**good, 'verified_t': NOW - 5000}, 'OK', 'OK', 'CRIT'),
            ('never', {**good, 'verified_t': None}, 'OK', 'OK', 'CRIT'),
            ('old-format', {'t': NOW - 30, 'healthy': True, 'problems': {}}, 'OK', 'OK', 'CRIT'),
            ('truthy', {**good, 'healthy': 'yes'}, 'CRIT', 'OK', 'OK'),
        ]
        with tempfile.TemporaryDirectory() as d:
            args = []
            for name, doc, *_ in cases:
                Path(d, name).write_text(json.dumps(doc))
                args += ['--guardian-health', f'{name}={d}/{name}']
            Path(d, 'garbage').write_text('{half')
            Path(d, 'list').write_text('[]')
            Path(d, 'custom').write_text(json.dumps({**good, 't': NOW - 100, 'verified_t': NOW - 100}))
            args += ['--guardian-health', f'garbage={d}/garbage', '--guardian-health', f'list={d}/list',
                     '--guardian-health', f'missing={d}/none', '--guardian-health', f'custom={d}/custom:60']
            r, _ = run(healthy(), *args)
        for name, _, state, age, verified in cases:
            self.assertEqual(level(r, f'guardian[{name}]'), state, name)
            self.assertEqual(level(r, f'guardian_age[{name}]'), age, name)
            self.assertEqual(level(r, f'guardian_verified[{name}]'), verified, name)
        for name in ('garbage', 'list', 'missing'):
            self.assertEqual(level(r, f'guardian[{name}]'), 'CRIT', name)
        self.assertEqual(level(r, 'guardian_age[custom]'), 'WARN')
        self.assertEqual(level(r, 'guardian_verified[custom]'), 'WARN')

    def test_heartbeat_files(self):
        with tempfile.TemporaryDirectory() as d:
            fresh, stale = Path(d, 'fresh'), Path(d, 'stale')
            fresh.write_text('x')
            stale.write_text('x')
            os.utime(fresh, (NOW - 10, NOW - 10))
            os.utime(stale, (NOW - 1000, NOW - 1000))
            r, _ = run(healthy(), '--file', f'prover={fresh}', '--file', f'follower={stale}',
                       '--file', f'missing={d}/none:60')
        self.assertEqual(level(r, 'file:prover'), 'OK')
        self.assertEqual(level(r, 'file:follower'), 'CRIT')
        self.assertEqual(level(r, 'file:missing'), 'CRIT')

    def test_binary_pins(self):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d, 'bloch-l2-produce-dev')
            b.write_bytes(b'not the v2 build')
            r, _ = run(healthy(), '--binary', str(b))
            self.assertEqual(level(r, 'binary[bloch-l2-produce-dev]'), 'CRIT')
            with mock.patch.dict(m.V2_SHA256, {'bloch-l2-produce-dev': hashlib.sha256(b.read_bytes()).hexdigest()}):
                r, _ = run(healthy(), '--binary', str(b))
            self.assertEqual(level(r, 'binary[bloch-l2-produce-dev]'), 'OK')

    def test_threshold_override(self):
        r, _ = run(healthy(), '--set', 'head_age_warn=60')
        self.assertEqual(level(r, 'l2_head_age'), 'WARN')
        with self.assertRaises(SystemExit):
            run(healthy(), '--set', 'nonsense=1')

    # ---- alerts
    def alert_args(self, d, cfg, dry=False):
        path = Path(d, 'alert.json')
        path.write_text(json.dumps({'state_file': str(Path(d, 'state.json')), **cfg}))
        argv = ['--alert-config', str(path)] + (['--alert-dry-run'] if dry else [])
        return m.parse(argv)

    def test_alert_on_change_realert_and_recovery(self):
        sent = []

        def sender(cfg, text, payload, timeout, dry):
            sent.append((payload['event'], text))
            return ['webhook']
        w = healthy()
        for b in w['l2'].values():
            b['latest'] = block(101, 50 * 60)
        with tempfile.TemporaryDirectory() as d:
            args = self.alert_args(d, {'webhook_url': 'https://hook', 'realert_seconds': 600})
            bad, _ = run(w)
            self.assertEqual(m.handle_alerts(args, bad, NOW, sender), 'raise')
            self.assertIn('CRIT l2_head_age', sent[-1][1])
            self.assertIsNone(m.handle_alerts(args, bad, NOW + 60, sender))   # unchanged: quiet
            self.assertEqual(m.handle_alerts(args, bad, NOW + 700, sender), 'raise')  # reminder
            good, _ = run(healthy())
            self.assertEqual(m.handle_alerts(args, good, NOW + 800, sender), 'recover')
            self.assertIsNone(m.handle_alerts(args, good, NOW + 900, sender))
        self.assertEqual([e for e, _ in sent], ['raise', 'raise', 'recover'])

    def test_placeholder_targets_send_nothing_and_say_so(self):
        w = healthy()
        for b in w['l2'].values():
            b['latest'] = block(101, 50 * 60)
        with tempfile.TemporaryDirectory() as d:
            args = self.alert_args(d, {'webhook_url': 'TBD-owner',
                                       'telegram': {'bot_token_file': 'TBD-owner', 'chat_id': 'TBD-owner'}})
            r, _ = run(w)
            with mock.patch.object(m.urllib.request, 'urlopen') as urlopen:
                m.handle_alerts(args, r, NOW)
            urlopen.assert_not_called()
        self.assertEqual(level(r, 'alert_delivery'), 'WARN')

    def test_dry_run_alert_does_not_send_or_persist(self):
        w = healthy()
        for b in w['l2'].values():
            b['latest'] = block(101, 50 * 60)
        with tempfile.TemporaryDirectory() as d:
            tok = Path(d, 'tok')
            tok.write_text('123:abc')
            args = self.alert_args(d, {'webhook_url': 'https://hook',
                                       'telegram': {'bot_token_file': str(tok), 'chat_id': '-100'}}, dry=True)
            r, _ = run(w)
            with mock.patch.object(m.urllib.request, 'urlopen') as urlopen:
                m.handle_alerts(args, r, NOW)
            urlopen.assert_not_called()
            self.assertFalse(Path(d, 'state.json').exists())
        self.assertEqual(len(r.facts['alert']['sent']), 2)

    def test_main_prints_json_and_returns_status(self):
        fake = Fake(healthy())
        with mock.patch.object(m, 'http_transport', return_value=fake), mock.patch.object(m.time, 'time', return_value=NOW):
            out = io.StringIO()
            with redirect_stdout(out):
                code = m.main(['--l2-rpc', L2A, '--l1-rpc', L1[0], '--json'])
        doc = json.loads(out.getvalue())
        self.assertEqual(code, m.OK, json.dumps(doc['checks'], indent=1))
        self.assertEqual(doc['status'], 'OK')

    def test_da_balance_levels_and_no_answer(self):
        for sats, want in (([150_000_000], 'OK'), ([60_000_000, 1], 'WARN'), ([9_999_999], 'CRIT'), ([], 'CRIT')):
            w = healthy()
            for node in w['l1'].values():
                node['utxos'] = sats
            report, _ = run(w, '--da-script', 'da=' + 'ab' * 32)
            self.assertEqual(level(report, 'da_balance[da]'), want, sats)
        report, _ = run(healthy(), '--da-script', 'ab' * 32)
        self.assertEqual(level(report, 'da_balance[da]'), 'UNKNOWN')

    def test_disk_levels(self):
        gib = 2 ** 30
        cases = ((1000, 500, 'OK'), (1000, 100, 'WARN'), (1000, 40, 'CRIT'), (100, 18, 'WARN'), (40, 4, 'CRIT'))
        for total, free, want in cases:
            st = mock.Mock(f_bavail=free, f_blocks=total, f_frsize=gib)
            with mock.patch.object(m.os, 'statvfs', return_value=st):
                report, _ = run(healthy(), '--disk', 'state=/x')
            self.assertEqual(level(report, 'disk[state]'), want, (total, free))
        report, _ = run(healthy(), '--disk', 'state=/does/not/exist')
        self.assertEqual(level(report, 'disk[state]'), 'CRIT')

    def test_closed_finality_is_named_and_the_backend_stays_up(self):
        w = healthy()
        w['l2'][L2A]['closed'] = True
        w['l2'][L2A]['bloch_finality']['status'] = {'state': 'missing', 'written_at_unix': None, 'age_s': None}
        report, _ = run(w)
        self.assertEqual(level(report, 'l2_rpc[A]'), 'OK')
        self.assertEqual(level(report, 'l2_finality_closed[A]'), 'CRIT')
        self.assertEqual(level(report, 'l2_finality_status[A]'), 'CRIT')

    def test_a_down_backend_is_still_unreachable(self):
        w = healthy()
        w['l2'][L2A] = None
        report, _ = run(w)
        self.assertEqual(level(report, 'l2_rpc[A]'), 'CRIT')
        self.assertFalse([c for c in report.checks if c['check'] == 'l2_finality_closed[A]'])

    def test_finality_status_age(self):
        for age, want in ((20, 'OK'), (400, 'WARN'), (1000, 'CRIT')):
            w = healthy()
            w['l2'][L2A]['bloch_finality']['status'] = {'state': 'ok', 'written_at_unix': NOW - age, 'age_s': age}
            self.assertEqual(level(run(w)[0], 'l2_finality_status[A]'), want, age)


if __name__ == '__main__':
    unittest.main()
