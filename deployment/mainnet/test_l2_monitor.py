#!/usr/bin/env python3
"""Unit tests for l2_monitor.py with fake RPC, command and HTTP transports (no network, no systemd).

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_l2_monitor.py' -v
"""
import atexit
import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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
    return {name: {'activation_epoch': (None if m.V2_COMPILED_GATES[c] == 'inert'
                                        else m.V2_COMPILED_GATES[c] if not isinstance(m.V2_COMPILED_GATES[c], list)
                                        else 7270), 'active': False}
            for name, c in m.GATE_CONSTANTS.items() if c in m.V2_COMPILED_GATES} | {'hf3_lattice_emergency': {'activation_epoch': None,
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


# An attestation drop that exists and is empty: a live mainnet run without --attest-drop is WARN (review R308-30).
EMPTY_DROP = tempfile.mkdtemp(prefix='l2mon-drop-')
atexit.register(shutil.rmtree, EMPTY_DROP, True)


def run(world, *extra, phase='live', runner=None, fetch=None):
    argv = ['--profile', 'mainnet', '--phase', phase, '--l2-rpc', f'A={L2A}', '--l2-rpc', f'B={L2B}']
    argv += sum((['--l1-rpc', u] for u in L1), []) + list(extra)
    if '--attest-drop' not in extra and '--no-default-drop' not in extra:
        argv += ['--attest-drop', EMPTY_DROP]
    argv = [a for a in argv if a != '--no-default-drop']
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

    def idle_world(self, minutes_idle):
        w = healthy()
        slot = (NOW - minutes_idle * 60 - m.L1_GENESIS_TIME) // 30
        for node in w['l1'].values():
            node['l2']['source']['slot'] = slot
        old = NOW - minutes_idle * 60
        for backend in w['l2'].values():
            for tag in ('latest', 'safe', 'finalized'):
                backend[tag] = {**backend[tag], 'timestamp': hex(old)}
        return w

    def test_idle_settler_moves_the_age_checks_by_the_interval(self):
        w = self.idle_world(10 * 60)
        for name in ('settlement_age', 'l2_head_age', 'l2_finalized_age'):
            self.assertEqual(level(run(w)[0], name), 'CRIT', 'without the flag a quiet chain alarms')
        with tempfile.TemporaryDirectory() as d:
            idle = ('--max-idle-seconds', '86400', '--backlog-state', f'{d}/backlog')
            for name in ('settlement_age', 'l2_head_age', 'l2_finalized_age'):
                self.assertEqual(level(run(w, *idle)[0], name), 'OK')
            w = self.idle_world(24 * 60 + 50)
            self.assertEqual(level(run(w, *idle)[0], 'settlement_age'), 'CRIT', 'a missed heartbeat still alarms')

    def test_idle_flag_needs_the_state_file(self):
        with self.assertRaisesRegex(SystemExit, 'backlog-state'):
            run(healthy(), '--max-idle-seconds', '60')

    def test_deposit_wait_counts_from_first_seen_and_resets_on_consumption(self):
        with tempfile.TemporaryDirectory() as d:
            idle = ('--max-idle-seconds', '86400', '--backlog-state', f'{d}/backlog')
            def at(now, count, consumed):
                w = healthy()
                for node in w['l1'].values():
                    node['l2']['inbox'].update(count=count, consumed=consumed)
                return level(m.run(m.parse(['--profile', 'mainnet', '--phase', 'live', '--l2-rpc', f'A={L2A}',
                                            *sum((['--l1-rpc', u] for u in L1), []), *idle]),
                                   Fake(w), now=now, run_cmd=lambda a: (1, ''), fetch=lambda u: None), 'deposit_wait')
            self.assertEqual(at(NOW, 3, 3), 'OK')
            self.assertEqual(at(NOW + 60, 4, 3), 'OK', 'first seen now')
            self.assertEqual(at(NOW + 60 + 46 * 60, 4, 3), 'WARN')
            self.assertEqual(at(NOW + 60 + 91 * 60, 5, 3), 'CRIT', 'new deposits do not restart a stuck wait')
            self.assertEqual(at(NOW + 60 + 92 * 60, 5, 4), 'OK', 'a consumption restarts it')
            self.assertEqual(at(NOW + 60 + 93 * 60, 4, 5), 'OK')

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

    def test_height_runways(self):
        p = m.PROFILES['mainnet']
        def checks(settled, height=186000):
            r = m.Report()
            m.check_height_runway(settled, [{'height': height}], p, r)
            return {c['check']: c['level'] for c in r.checks}, r
        self.assertNotIn('l2_proof_cost', checks(4000)[0], 'height alone no longer grades the proof cost')
        self.assertEqual(m.empty_block_instructions(9000), m.empty_block_instructions(8191), 'flat once the ring wraps')
        for height, expected in ((256, 11.2e6), (4096, 116.2e6), (8191, 227.7e6)):
            self.assertLess(abs(m.empty_block_instructions(height) - expected) / expected, 0.25, height)
        r = checks(200)[1]
        m.check_proof_time(p, r)
        self.assertEqual(level(r, 'l2_proof_cost'), 'OK')
        self.assertIn('local fallback', next(c['message'] for c in r.checks if c['check'] == 'l2_proof_cost'))
        limit = p['l1_reconstruct_limit']
        self.assertEqual(checks(40, limit * 4 // 5 - 1)[0]['l1_reconstruct_runway'], 'OK')
        self.assertEqual(checks(40, limit * 4 // 5)[0]['l1_reconstruct_runway'], 'WARN')
        self.assertEqual(checks(40, limit * 19 // 20)[0]['l1_reconstruct_runway'], 'CRIT')
        if p['l2_export_limit'] is not None:
            self.assertEqual(checks(1023)[0]['l2_export_runway'], 'OK')
            self.assertEqual(checks(1024)[0]['l2_export_runway'], 'WARN')
            self.assertEqual(checks(3000)[0]['l2_export_runway'], 'CRIT')
        else:
            self.assertNotIn('l2_export_runway', checks(3000)[0])

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

    def test_forfeit_reset_is_subtracted_once_recorded(self):
        # After a forfeit reset, L1 released includes what forged claims took: CRIT until the owner records it.
        w = healthy()
        for b in w['l2'].values():
            b['ledger']['0x3'] = 100 * BLCH_WEI
        released = int(w['l1'][L1[0]]['l2']['withdrawals']['released_sat'])
        forfeit = released - 100 * 10 ** 8
        self.assertGreater(forfeit, 0)
        self.assertEqual(level(run(w)[0], 'claims_vs_withdrawn'), 'CRIT')
        r, _ = run(w, '--set', f'forfeit_sat={forfeit}')
        self.assertEqual(level(r, 'claims_vs_withdrawn'), 'OK')
        self.assertEqual(level(r, 'forfeit'), 'WARN')
        self.assertEqual(r.facts['forfeit_sat'], forfeit)
        # Recording more than was released is itself wrong.
        r, _ = run(healthy(), '--set', f'forfeit_sat={released + 1}')
        self.assertEqual(level(r, 'claims_vs_withdrawn'), 'CRIT')
        # No forfeit: no line.
        r, _ = run(healthy())
        self.assertNotIn('forfeit', [c['check'] for c in r.checks])

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

    def test_an_armed_l1_gate_the_l2_build_was_not_built_with_is_critical(self):
        """Node release 906336fd arms two consensus rules at epoch 8620 (the vote slot-epoch binding and the KES
        first-key floor) and reports them in getchaininfo. Release 926d2cf was built against native 78d4921c, which
        has neither: its follower and producer replay other rules from that epoch on. An inert gate is nothing a
        build needs to know. Round 18 (agent 382, review R384-6): the December build links the merged line on node
        release 0067547f, so the monitor's compiled list has both gates; the earlier build is given as its own
        build.json (its gate list without the two) and must still be CRIT."""
        w = healthy()
        for node in w['l1'].values():
            forks = node['info']['hard_forks']
            forks['hf3_kes_vote_slot_epoch_binding'] = {'activation_epoch': 8620, 'active': False}
            forks['hf3_kes_first_key_floor'] = {'activation_epoch': 8620, 'active': False}
            forks['hf3_kes_register_epoch_binding'] = {'activation_epoch': None, 'active': False}
        earlier = {k: v for k, v in m.V2_COMPILED_GATES.items()
                   if k not in ('ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH', 'KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH')}
        self.assertEqual(len(earlier), len(m.V2_COMPILED_GATES) - 2)
        with tempfile.TemporaryDirectory() as d:
            bj = Path(d, 'build.json')
            bj.write_text(json.dumps({'l1_activation_epochs': earlier}))
            r, _ = run(w, '--build-json', str(bj))
        self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'CRIT')
        message = next(c['message'] for c in r.checks if c['check'] == 'l1_gates_vs_l2_build')
        self.assertIn('hf3_kes_first_key_floor', message)
        self.assertIn('hf3_kes_vote_slot_epoch_binding', message)
        self.assertNotIn('hf3_kes_register_epoch_binding', message)
        # A build that names the two gates at the L1's epochs is in agreement again.
        with tempfile.TemporaryDirectory() as d:
            bj = Path(d, 'build.json')
            bj.write_text(json.dumps({'l1_activation_epochs': dict(
                m.V2_COMPILED_GATES, ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH=8620,
                KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH=8620, KES_REGISTER_EPOCH_BINDING_EPOCH='inert')}))
            r, _ = run(w, '--build-json', str(bj))
        self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'OK')
        # The December build's own compiled list (no --build-json) agrees with the fleet's gates.
        r, _ = run(w)
        self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'OK')

    def test_gate_check_reads_build_json(self):
        with tempfile.TemporaryDirectory() as d:
            bj = Path(d, 'build.json')
            bj.write_text(json.dumps({'l1_activation_epochs': {'HF1_CLAIM_FINALITY_EPOCH': 7181}}))
            r, _ = run(healthy(), '--build-json', str(bj))
        self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'CRIT')

    def test_an_armed_program_swap_the_l2_build_holds_inert_is_critical(self):
        # Round 18 (agent 382): the build.json carries the compiled list too; the December build has the two
        # 8620 gates the fleet arms, and a build.json without them is CRIT for them (340's check), not for this gate.
        w = healthy()
        for node in w['l1'].values():
            node['info']['hard_forks']['l2_next_program'] = {'activation_epoch': 10060, 'active': False}
        with tempfile.TemporaryDirectory() as d:
            bj = Path(d, 'build.json')
            bj.write_text(json.dumps({'l1_activation_epochs': {**m.V2_COMPILED_GATES, 'L2_NEXT_PROGRAM_EPOCH': 'inert'}}))
            r, _ = run(w, '--build-json', str(bj))
            self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'CRIT')
            self.assertIn('l2_next_program', next(c['message'] for c in r.checks if c['check'] == 'l1_gates_vs_l2_build'))
            bj.write_text(json.dumps({'l1_activation_epochs': {**m.V2_COMPILED_GATES, 'L2_NEXT_PROGRAM_EPOCH': 10060}}))
            self.assertEqual(level(run(w, '--build-json', str(bj))[0], 'l1_gates_vs_l2_build'), 'OK')

    def test_an_armed_da_slot_or_forced_inclusion_the_l2_build_holds_inert_is_critical(self):
        # Round 18 (agent 382): the build.json carries the compiled list too; the December build has the two
        # 8620 gates the fleet arms, and a build.json without them is CRIT for them (340's check), not for this gate.
        for gate, const in (('l2_da_reserved_slot', 'L2_DA_RESERVED_SLOT_EPOCH'),
                            ('l2_forced_inclusion', 'L2_FORCED_INCLUSION_EPOCH')):
            w = healthy()
            for node in w['l1'].values():
                node['info']['hard_forks'][gate] = {'activation_epoch': 10060, 'active': False}
            with tempfile.TemporaryDirectory() as d:
                bj = Path(d, 'build.json')
                bj.write_text(json.dumps({'l1_activation_epochs': {**m.V2_COMPILED_GATES, const: 'inert'}}))
                r, _ = run(w, '--build-json', str(bj))
                self.assertEqual(level(r, 'l1_gates_vs_l2_build'), 'CRIT')
                self.assertIn(gate, next(c['message'] for c in r.checks if c['check'] == 'l1_gates_vs_l2_build'))
                bj.write_text(json.dumps({'l1_activation_epochs': {**m.V2_COMPILED_GATES, const: 10060}}))
                self.assertEqual(level(run(w, '--build-json', str(bj))[0], 'l1_gates_vs_l2_build'), 'OK')

    def test_forced_queue_is_reported_once_enabled_and_warns_above_the_doubling(self):
        w = healthy()
        self.assertNotIn('forced_queue', {c['check'] for c in run(w)[0].checks})
        for weight, expected in ((0, 'OK'), (23, 'OK'), (24, 'WARN'), (256, 'CRIT')):
            for node in w['l1'].values():
                node['l2']['forced'] = {'queued': 5, 'consumed': 4, 'pending': 1, 'pending_weight': weight,
                                        'max_pending_weight': 256, 'due': [], 'next_surcharge_sat': '1000'}
            r, _ = run(w)
            self.assertEqual(level(r, 'forced_queue'), expected, weight)
        self.assertEqual(r.facts['forced_queue']['pending_weight'], 256)
        self.assertEqual(r.facts['forced_queue']['drain_settlements'], 19)

    # Native bloch-pos-committee `forced_pricing_matches_the_golden_vector` (agent 215): the same rows, byte for byte.
    FORCED_PRICING_VECTOR = [
        (0, 1, 1_000), (0, 14, 14_000), (23, 14, 27_000), (100, 3, 48_000), (232, 14, 10_240_000),
        (242, 14, 14_336_000), (229, 27, 22_016_000), (255, 1, 1_024_000),
    ]

    def test_forced_pricing_matches_the_native_golden_vector(self):
        self.assertEqual([(p, u, m.forced_surcharge_sat(p, u)) for p, u, _ in self.FORCED_PRICING_VECTOR],
                         self.FORCED_PRICING_VECTOR)
        self.assertIsNone(m.forced_surcharge_sat(256, 1))
        self.assertIsNone(m.forced_surcharge_sat(0, 0))
        self.assertEqual((m.FORCED_UNITS_PER_SETTLEMENT, m.FORCED_MAX_PENDING_WEIGHT, m.FORCED_SURCHARGE_DOUBLING), (14, 256, 24))

    def test_the_forced_inclusion_gate_is_compared_with_the_l2_build(self):
        # Round 18 (agent 382): the build.json carries the compiled list too; the December build has the two
        # 8620 gates the fleet arms, and a build.json without them is CRIT for them (340's check), not for this gate.
        self.assertEqual(m.GATE_CONSTANTS['l2_forced_inclusion'], 'L2_FORCED_INCLUSION_EPOCH')
        w = healthy()
        for node in w['l1'].values():
            node['info']['hard_forks']['l2_forced_inclusion'] = {'activation_epoch': 10060, 'active': False}
        with tempfile.TemporaryDirectory() as d:
            bj = Path(d, 'build.json')
            bj.write_text(json.dumps({'l1_activation_epochs': {**m.V2_COMPILED_GATES, 'L2_FORCED_INCLUSION_EPOCH': 'inert'}}))
            self.assertEqual(level(run(w, '--build-json', str(bj))[0], 'l1_gates_vs_l2_build'), 'CRIT')
            bj.write_text(json.dumps({'l1_activation_epochs': {**m.V2_COMPILED_GATES, 'L2_FORCED_INCLUSION_EPOCH': 10060}}))
            self.assertEqual(level(run(w, '--build-json', str(bj))[0], 'l1_gates_vs_l2_build'), 'OK')

    def test_l1_gates_resolves_a_gate_defined_as_another_gate(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import l1_gates
        source = ('pub const L2_NEXT_PROGRAM_EPOCH: u64 = 10060;\n'
                  'pub const L2_FORCED_INCLUSION_EPOCH: u64 = L2_NEXT_PROGRAM_EPOCH;\n'
                  'pub const L2_PROGRAM_ROLLBACK_EPOCH: u64 = u64::MAX;\n'
                  'pub const HF9_ODD_EPOCH: u64 = SOMETHING_ELSE + 1;\n')
        self.assertEqual(l1_gates.gates(source), {'L2_NEXT_PROGRAM_EPOCH': 10060, 'L2_FORCED_INCLUSION_EPOCH': 10060,
                                                  'L2_PROGRAM_ROLLBACK_EPOCH': 'inert', 'HF9_ODD_EPOCH': '?SOMETHING_ELSE + 1'})
        inert = source.replace('10060', 'u64::MAX')
        self.assertEqual(l1_gates.gates(inert)['L2_FORCED_INCLUSION_EPOCH'], 'inert')

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
        good['https://drop/healthz'] = b'ok\n'
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
    def test_proof_time_against_the_block_interval(self):
        def proof_level(seconds, *extra):
            def runner(argv):
                if argv[0] == 'systemctl':
                    return 0, 'LoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=0\nExecMainStatus=0\nResult=success\n'
                t = m.datetime.datetime.fromtimestamp(NOW - 60, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                return 0, '\n'.join('x: ' + json.dumps({'time': t, 'event': 'proof-generated', 'seconds': s}) for s in seconds)
            r, _ = run(healthy(), '--unit', 'settler=settler.service', *extra, runner=runner)
            return level(r, 'l2_proof_cost')
        interval = ('--set', 'block_interval_seconds=600')
        self.assertEqual(proof_level([300, 410], *interval), 'OK')
        self.assertEqual(proof_level([300, 420], *interval), 'WARN')
        self.assertEqual(proof_level([610], *interval), 'CRIT')
        self.assertEqual(proof_level([5000]), 'OK', 'without a configured interval it only reports')
        self.assertEqual(proof_level([], *interval), 'OK', 'no proof in the window')

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

    def test_reorg_recoveries_alert_each_time(self):
        stamp = lambda age: m.datetime.datetime.fromtimestamp(NOW - age, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        ev = lambda age, kind='reorg-recovered': json.dumps({'time': stamp(age), 'event': kind, 'accepted': 5,
                                                             'database_head': 9})
        with tempfile.TemporaryDirectory() as d:
            log = Path(d, 'settler.log')
            log.write_text(ev(90000) + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertNotIn('reorg_recoveries[settler]', [c['check'] for c in r.checks])
            log.write_text(ev(7200, 'reorg-detected') + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'reorg_recoveries[settler]'), 'WARN')
            log.write_text(ev(7200, 'reorg-detected') + '\n' + ev(7100) + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'reorg_recoveries[settler]'), 'WARN')
            self.assertIn('accepted L2 block 5, database head 9', next(c['message'] for c in r.checks
                                                                       if c['check'] == 'reorg_recoveries[settler]'))
            self.assertEqual(level(r, 'events[settler]'), 'OK')
            log.write_text(ev(7100) + '\n' + ev(60) + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'reorg_recoveries[settler]'), 'CRIT')
            log.write_text(ev(60, 'reorg-limit') + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'reorg_recoveries[settler]'), 'CRIT')
            self.assertIn('limit reached', next(c['message'] for c in r.checks if c['check'] == 'reorg_recoveries[settler]'))
            # Agent 206: a resubmission alert waits (WARN); a restore of the kept database counts as a recovery.
            log.write_text(ev(7200, 'reorg-resubmitting') + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'reorg_recoveries[settler]'), 'WARN')
            log.write_text(ev(7100) + '\n' + ev(60, 'reorg-restored') + '\n')
            r, _ = run(healthy(), '--event-log', f'settler={log}')
            self.assertEqual(level(r, 'reorg_recoveries[settler]'), 'CRIT')

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
        # prelaunch: a live run without heartbeat_url is WARN (review R308-31); the tests of that are below.
        argv = ['--phase', 'prelaunch', '--alert-config', str(path)] + (['--alert-dry-run'] if dry else [])
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
            args = self.alert_args(d, {'webhook_url': 'https://hook', 'realert_seconds': 600, 'recover_runs': 1})
            bad, _ = run(w)
            self.assertEqual(m.handle_alerts(args, bad, NOW, sender), 'raise')
            self.assertIn('CRIT l2_head_age', sent[-1][1])
            self.assertIsNone(m.handle_alerts(args, bad, NOW + 60, sender))   # unchanged: quiet
            self.assertEqual(m.handle_alerts(args, bad, NOW + 700, sender), 'raise')  # reminder
            good, _ = run(healthy())
            self.assertEqual(m.handle_alerts(args, good, NOW + 800, sender), 'recover')
            self.assertIsNone(m.handle_alerts(args, good, NOW + 900, sender))
        self.assertEqual([e for e, _ in sent], ['raise', 'raise', 'recover'])

    def test_flapping_check_is_one_alert_and_recovery_waits(self):
        sent = []

        def sender(cfg, text, payload, timeout, dry):
            sent.append(payload['event'])
            return ['command']
        w = healthy()
        for b in w['l2'].values():
            b['latest'] = block(101, 50 * 60)
        with tempfile.TemporaryDirectory() as d:
            args = self.alert_args(d, {'alert_command': ['/bin/true'], 'realert_seconds': 3600})
            bad, _ = run(w)
            for i in range(10):  # bad, good, bad, good ... once a minute
                r = bad if i % 2 == 0 else run(healthy())[0]
                m.handle_alerts(args, r, NOW + 60 * i, sender)
            self.assertEqual(sent, ['raise'])
            for i in range(10, 13):  # three clean runs in a row: one recovery
                m.handle_alerts(args, run(healthy())[0], NOW + 60 * i, sender)
        self.assertEqual(sent, ['raise', 'recover'])

    def test_alert_command_gets_text_and_payload(self):
        w = healthy()
        for b in w['l2'].values():
            b['latest'] = block(101, 50 * 60)
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, 'sink')
            args = self.alert_args(d, {'alert_command': ['/bin/sh', '-c', f'cat > {out}; echo "$0" >> {out}', '{event}:{status}']})
            r, _ = run(w)
            self.assertEqual(m.handle_alerts(args, r, NOW), 'raise')
            body = out.read_text()
            self.assertIn('CRIT l2_head_age', body)
            self.assertIn('raise:CRIT', body)
            failing = self.alert_args(d, {'alert_command': ['/bin/false'], 'state_file': str(Path(d, 's2'))})
            r2, _ = run(w)
            m.handle_alerts(failing, r2, NOW)
        self.assertEqual(level(r2, 'alert_delivery'), 'WARN')

    def test_report_of_another_monitor_and_its_age(self):
        with tempfile.TemporaryDirectory() as d:
            rep = Path(d, 'dex.json')
            rep.write_text(json.dumps({'level': 'CRIT', 'checks': [
                {'name': 'keeper_budget', 'level': 2, 'status': 'CRIT', 'detail': 'count used up'},
                {'name': 'closed_by_excess[WBLCH/bUSDC]', 'level': 1, 'status': 'WARN', 'detail': 'soft'},
                {'name': 'rpc_identity', 'level': 0, 'status': 'OK', 'detail': ''}]}))
            os.utime(rep, (NOW - 60, NOW - 60))
            r = m.Report()
            m.check_reports([f'dex={rep}:900'], dict(m.PROFILES['mainnet']), NOW, r)
            self.assertEqual(level(r, 'dex/keeper_budget'), 'CRIT')
            self.assertEqual(level(r, 'dex/closed_by_excess[WBLCH/bUSDC]'), 'WARN')
            self.assertEqual(level(r, 'report_age[dex]'), 'OK')
            os.utime(rep, (NOW - 3000, NOW - 3000))  # the DEX monitor died: its last report goes stale
            r = m.Report()
            m.check_reports([f'dex={rep}:900'], dict(m.PROFILES['mainnet']), NOW, r)
            self.assertEqual(level(r, 'report_age[dex]'), 'CRIT')
            r = m.Report()
            m.check_reports([f'dex={Path(d, "missing.json")}'], dict(m.PROFILES['mainnet']), NOW, r)
            self.assertEqual(level(r, 'report[dex]'), 'CRIT')

    def test_l1_stall_is_seen_although_the_lag_is_constant(self):
        with tempfile.TemporaryDirectory() as d:
            st = str(Path(d, 'l1.json'))
            p = dict(m.PROFILES['mainnet'])
            for dt, want in ((0, 'OK'), (700, 'WARN'), (2000, 'CRIT')):
                r = m.Report()
                r.facts['l1_height'] = 5000
                m.check_l1_progress(st, p, NOW + dt, r)
                self.assertEqual(level(r, 'l1_progress'), want, dt)
            r = m.Report()
            r.facts['l1_height'] = 5001
            m.check_l1_progress(st, p, NOW + 2100, r)
            self.assertEqual(level(r, 'l1_progress'), 'OK')

    def test_memory_levels(self):
        with tempfile.TemporaryDirectory() as d:
            mi = Path(d, 'meminfo')
            for avail, want in ((60, 'OK'), (12, 'WARN'), (5, 'CRIT')):
                mi.write_text(f'MemTotal: {100 * 2**20} kB\nMemAvailable: {avail * 2**20} kB\nSwapTotal: 0 kB\n')
                r = m.Report()
                m.check_memory(True, dict(m.PROFILES['mainnet']), r, str(mi))
                self.assertEqual(level(r, 'memory'), want, avail)

    def test_guardian_open_finding_is_named(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d, 'h.json')
            h.write_text(json.dumps({'t': NOW, 'healthy': False, 'verified_t': NOW, 'problems': {},
                                     'findings': {'mint:0xfe': {'severity': 'hard'}}}))
            r = m.Report()
            m.check_guardian_health([f'busdc={h}'], dict(m.PROFILES['mainnet']), NOW, r)
            c = next(c for c in r.checks if c['check'] == 'guardian[busdc]')
        self.assertEqual(c['level'], 'CRIT')
        self.assertIn('mint:0xfe', c['message'])

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
                code = m.main(['--l2-rpc', L2A, '--l1-rpc', L1[0], '--attest-drop', EMPTY_DROP, '--json'])
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


class StuckNode(unittest.TestCase):
    """The decision code shared with l1_stuck_check.py, and the monitor check that wraps it."""
    P = dict(m.PROFILES['mainnet'])

    def seq(self, *rows):
        st, out = None, []
        for s in rows:
            st, level, msg = m.stuck_step(st, s, self.P)
            out.append(level)
        self.msg = msg
        return out

    @staticmethod
    def s(rf, fin, parked=32, head=False, **kw):
        return {'ref_finalized': rf, 'finalized': fin, 'parked': parked, 'has_ref_head': head, **kw}

    def test_shared_code_is_identical(self):
        import ast
        import l1_stuck_check as c
        def body(path):
            tree = ast.parse(Path(path).read_text())
            return {n.name: ast.dump(n) for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name in ('stuck_step', 'stuck_metric')}
        self.assertEqual(len(body(m.__file__)), 2)
        self.assertEqual(body(m.__file__), body(c.__file__))
        for k in ('stuck_sustain_epochs', 'stuck_parked_min', 'stuck_min_samples', 'stuck_max_gap_epochs'):
            self.assertEqual(c.DEFAULTS[k], self.P[k])

    def test_all_three_sustained_is_crit(self):
        self.assertEqual(self.seq(*[self.s(20 + i, 14) for i in range(4)]), [m.OK, m.OK, m.OK, m.CRIT])
        self.assertIn('STUCK', self.msg)

    def test_parked_alone_never_alarms(self):
        self.assertEqual(set(self.seq(*[self.s(20 + i, 18 + i, 32, True) for i in range(12)])), {m.OK})

    def test_lagging_with_parked_and_head_known_never_alarms(self):
        self.assertEqual(set(self.seq(*[self.s(20 + i, 14, 40, True) for i in range(12)])), {m.OK})

    def test_finality_moving_resets(self):
        rows = [self.s(20, 10), self.s(21, 11), self.s(22, 12), self.s(23, 13), self.s(24, 14), self.s(25, 15)]
        self.assertEqual(set(self.seq(*rows)), {m.OK})

    def test_reference_not_advancing_never_alarms(self):
        self.assertEqual(set(self.seq(*[self.s(20, 14) for _ in range(30)])), {m.OK})

    def test_parked_dip_resets_only_parked(self):
        rows = [self.s(20, 14), self.s(21, 14), self.s(22, 14, 20), self.s(23, 14), self.s(24, 14), self.s(25, 14),
                self.s(26, 14)]
        out = self.seq(*rows)
        self.assertEqual(out[3:6], [m.WARN, m.WARN, m.WARN])
        self.assertEqual(out[6], m.CRIT)

    def test_restart_keeps_frozen_clock_and_rearms_parked(self):
        rows = [self.s(20 + i, 14) for i in range(4)]
        rows += [{'ref_finalized': 24, 'down': True}, self.s(25, 14, 3), self.s(26, 14), self.s(27, 14), self.s(28, 14),
                 self.s(29, 14), self.s(30, 14)]
        out = self.seq(*rows)
        self.assertEqual(out[3], m.CRIT)
        self.assertEqual(out[4], m.OK)
        self.assertNotEqual(out[6], m.CRIT)
        self.assertEqual(out[-1], m.CRIT)

    def test_normal_restart_is_quiet(self):
        rows = [{'ref_finalized': 20 + i, 'down': True} for i in range(2)]
        rows += [self.s(22, 14, 25), self.s(22, 14), self.s(23, 19), self.s(23, 21, 0, True), self.s(24, 22, 0, True)]
        self.assertEqual(set(self.seq(*rows)), {m.OK})

    def test_long_outage_is_unknown(self):
        out = self.seq(*[{'ref_finalized': 20 + i, 'down': True} for i in range(5)])
        self.assertEqual(out, [m.OK, m.OK, m.OK, m.UNKNOWN, m.UNKNOWN])

    def test_no_metrics_tops_out_at_warn(self):
        out = self.seq(*[self.s(20 + i, 14, None) for i in range(8)])
        self.assertEqual(max(out), m.WARN)
        self.assertIn('parked unknown', self.msg)

    def test_finalizing_with_unknown_head_warns(self):
        out = self.seq(*[self.s(20 + i, 20 + i - 2, 0, False) for i in range(5)])
        self.assertEqual(out[-1], m.WARN)

    def test_monitor_gap_clears_steady_evidence(self):
        out = self.seq(self.s(20, 14), self.s(21, 14), self.s(22, 14), self.s(40, 14))
        self.assertNotEqual(out[-1], m.CRIT)

    def test_no_reference(self):
        self.assertEqual(self.seq({'ref_finalized': None}), [m.UNKNOWN])

    def test_failed_head_lookup_neither_starts_nor_clears(self):
        out = self.seq(self.s(20, 14), self.s(21, 14), self.s(22, 14), self.s(23, 14, head=None), self.s(24, 14))
        self.assertEqual(out[-1], m.CRIT)

    def test_metric_parser(self):
        text = '# HELP bloch_pos_blocks_parked x\nbloch_pos_blocks_parked 32\nbloch_pos_blocks_parked_other 1\n'
        self.assertEqual(m.stuck_metric(text, 'bloch_pos_blocks_parked'), 32)
        self.assertIsNone(m.stuck_metric(text, 'absent'))
        self.assertIsNone(m.stuck_metric(None, 'absent'))

    def monitor(self, tmp, epochs, stuck=True, side_block=False):
        args = m.parse(['--phase', 'prelaunch', '--l1-rpc', 'http://ref', '--l1-stuck-node', 'n9=http://n9,http://n9/metrics',
                        '--l1-stuck-state', os.path.join(tmp, 's.json')])
        calls, levels = [], []
        for e in range(epochs):
            def transport(url, method, params, e=e):
                calls.append((url, method))
                if method == 'getchaininfo':
                    fin = 20 + e if url == 'http://ref' or not stuck else 14
                    return {'height': 1000, 'epoch': 22 + e, 'slot': 1, 'finalized_height': 900,
                            'finalized': {'epoch': fin, 'root': 'aa'}, 'block_id': 'bb'}
                if method == 'getblockbyid':
                    if stuck and side_block:
                        return {'id': 'bb', 'finality': 'not_canonical'}
                    if stuck:
                        raise m.RpcError("{'code': -32000, 'message': 'no block bb is known to this node'}")
                    return {'id': 'bb'}
                raise m.RpcError('unavailable')
            r = m.run(args, transport, now=NOW, fetch=lambda u: b'bloch_pos_blocks_parked 32\nbloch_pos_peer_count 28\n')
            levels.append(next(c['code'] for c in r.checks if c['check'] == 'l1_stuck[n9]'))
        return calls, levels

    def test_monitor_check_alarms_and_reads_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls, levels = self.monitor(tmp, 4)
        self.assertEqual(levels, [m.OK, m.OK, m.OK, m.CRIT])
        self.assertTrue({c for _, c in calls} <= m.READ_ONLY_METHODS)

    def test_monitor_stored_side_block_is_not_the_reference_head(self):
        """Agent 187 F1: a stuck node that stored the reference head on a branch it does not follow answers it with
        `finality: not_canonical`; that must not stop the missing clock."""
        with tempfile.TemporaryDirectory() as tmp:
            _, levels = self.monitor(tmp, 4, side_block=True)
        self.assertEqual(levels, [m.OK, m.OK, m.OK, m.CRIT])

    def test_monitor_healthy_node_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, levels = self.monitor(tmp, 6, stuck=False)
        self.assertEqual(set(levels), {m.OK})

    def test_without_the_option_nothing_changes(self):
        args = m.parse(['--phase', 'prelaunch', '--l1-rpc', 'http://ref'])
        calls = []
        def transport(url, method, params):
            calls.append(method)
            raise m.RpcError('down')
        r = m.run(args, transport, now=NOW, fetch=lambda u: None)
        self.assertNotIn('getblockbyid', calls)
        self.assertFalse([c for c in r.checks if c['check'].startswith('l1_stuck')])

    def test_option_without_state_is_unknown(self):
        args = m.parse(['--phase', 'prelaunch', '--l1-stuck-node', 'n=http://n'])
        r = m.run(args, lambda *a: (_ for _ in ()).throw(m.RpcError('x')), now=NOW, fetch=lambda u: None)
        self.assertTrue([c for c in r.checks if c['check'] == 'l1_stuck' and c['code'] == m.UNKNOWN])

    def test_identity_pins_untouched(self):
        self.assertEqual(m.V2_BUILD['l2_commit'], 'f349f65cb0125d1cac62dfc66c37a271b05d3a7a')  # round 19: the December build commit (review R384-6)
        self.assertEqual(m.MAINNET_PINS['attestor_set'], '1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b')


def stamp(age):
    return m.datetime.datetime.fromtimestamp(NOW - age, m.datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


ACTIVE = 'LoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=0\nExecMainStatus=0\nResult=success\n'
REPO = Path(__file__).resolve().parents[2]


def journal(lines_by_unit):
    """A runner whose journal for each unit is the given lines (dicts become settler JSON events, strings stay text)."""
    def runner(argv):
        if argv[0] == 'systemctl':
            return 0, ACTIVE
        lines = lines_by_unit.get(argv[2], [])
        return 0, '\n'.join(json.dumps(x) if isinstance(x, dict) else x for x in lines)
    return runner


def with_accepted(world, number, l2_hash):
    """Every L1 node accepted L2 block `number` with hash `l2_hash` (a full-length statement)."""
    raw = bytearray(22 + 432)
    raw[22 + 264:22 + 272] = number.to_bytes(8, 'big')
    raw[22 + 336:22 + 368] = bytes.fromhex(l2_hash)
    for node in world['l1'].values():
        node['l2']['accepted']['statement'] = raw.hex()
    return world


class ByNumber(Fake):
    """Fake that also answers eth_getBlockByNumber for a hex number, from world['l2'][url]['by_number']."""

    def __call__(self, url, method, params):
        if method == 'eth_getBlockByNumber' and str(params[0]).startswith('0x') and url in self.world['l2']:
            self.calls.append((url, method))
            return self.world['l2'][url].get('by_number', {}).get(int(params[0], 16))
        return super().__call__(url, method, params)


def run_by_number(world, *extra):
    argv = ['--profile', 'mainnet', '--phase', 'live', '--l2-rpc', f'A={L2A}', '--l2-rpc', f'B={L2B}']
    argv += sum((['--l1-rpc', u] for u in L1), []) + list(extra) + ['--attest-drop', EMPTY_DROP]
    fake = ByNumber(world)
    return m.run(m.parse(argv), fake, now=NOW, run_cmd=lambda a: (1, ''), fetch=lambda u: None), fake


class MonitorGapTests(unittest.TestCase):
    """Agent 157, round 10: failure modes of rounds 1-8 that reached no check. One test per gap."""

    # ---- 94 / L1-6b: part of the L1 finalizes, part is frozen on a branch of its own
    def test_l1_finality_spread_names_the_node_on_a_dead_branch(self):
        w = healthy()
        self.assertEqual(level(run(w)[0], 'l1_finality_spread'), 'OK')
        w['l1'][L1[0]]['info']['finalized']['epoch'] = EPOCH - 4  # 2 behind the others
        self.assertEqual(level(run(w)[0], 'l1_finality_spread'), 'WARN')
        w['l1'][L1[0]]['info']['finalized']['epoch'] = EPOCH - 580  # report 94: frozen at e290 while the rest went on
        w['l1'][L1[0]]['info']['height'] -= 5  # a minority branch has fewer proposers: its head trails a little
        r, _ = run(w)
        c = next(c for c in r.checks if c['check'] == 'l1_finality_spread')
        self.assertEqual(c['level'], 'CRIT')
        self.assertEqual(c['behind'], [L1[0]])
        self.assertIn('branch of its own', c['message'])
        self.assertEqual(level(r, 'l1_finality_lag'), 'OK', 'the best node still finalizes: the old check stays quiet')

    def test_l1_finality_spread_tells_a_syncing_node_apart(self):
        w = healthy()
        w['l1'][L1[1]]['info']['finalized']['epoch'] = EPOCH - 40
        w['l1'][L1[1]]['info']['height'] = 150000
        w['l1'][L1[1]]['info']['slot'] -= 36000 * 2  # a syncing node's head is an old block
        c = next(c for c in run(w)[0].checks if c['check'] == 'l1_finality_spread')
        self.assertEqual(c['level'], 'CRIT')
        self.assertIn('syncing or stuck', c['message'])

    def test_one_epoch_boundary_difference_is_normal(self):
        w = healthy()
        w['l1'][L1[2]]['info']['finalized']['epoch'] = EPOCH - 3
        self.assertEqual(level(run(w)[0], 'l1_finality_spread'), 'OK')

    # ---- L2-12 / 94: the RPC serves a block that L1 did not accept
    def test_rpc_block_at_the_accepted_number_must_be_the_accepted_block(self):
        good = 'ab' * 32
        w = with_accepted(healthy(), 100, good)
        for b in w['l2'].values():
            b['by_number'] = {100: {'hash': '0x' + good}}
        r, _ = run_by_number(w)
        self.assertEqual(level(r, 'l2_rpc_vs_l1[A]'), 'OK')
        self.assertEqual(m.LEVEL_NAMES[r.status], 'OK', json.dumps(r.checks, indent=1))
        w['l2'][L2B]['by_number'] = {100: {'hash': '0x' + 'cd' * 32}}  # B kept the reorged-out settlement
        r, _ = run_by_number(w)
        self.assertEqual(level(r, 'l2_rpc_vs_l1[A]'), 'OK')
        self.assertEqual(level(r, 'l2_rpc_vs_l1[B]'), 'CRIT')
        self.assertIn('l2_reorg_recover', next(c['message'] for c in r.checks if c['check'] == 'l2_rpc_vs_l1[B]'))

    def test_rpc_safe_above_the_accepted_number_warns(self):
        good = 'ab' * 32
        w = with_accepted(healthy(), 99, good)
        for b in w['l2'].values():
            b['by_number'] = {99: {'hash': '0x' + good}}
        self.assertEqual(level(run_by_number(w)[0], 'l2_rpc_vs_l1[A]'), 'WARN')  # safe 100 > accepted 99

    def test_short_statement_or_prelaunch_makes_no_extra_call(self):
        self.assertNotIn('l2_rpc_vs_l1[A]', [c['check'] for c in run(healthy())[0].checks])
        r, _ = run(prelaunch(), phase='prelaunch')
        self.assertEqual(m.LEVEL_NAMES[r.status], 'OK')

    # ---- 141 R-1: remote prover busy, local fallback; no prover at all
    def test_remote_busy_then_local_proof_is_a_fallback_warning(self):
        d = '/var/lib/settler/work/00000001-x'
        lines = [{'time': stamp(900), 'event': 'remote-proof', 'target': 'p', 'exit_code': 75, 'bytes': 0},
                 {'time': stamp(900), 'event': 'prover-failed', 'directory': d, 'where': 'remote', 'exit_code': 75},
                 {'time': stamp(60), 'event': 'proof-generated', 'directory': d, 'seconds': 1639.2}]
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': lines}))
        c = next(c for c in r.checks if c['check'] == 'prover_path[settler]')
        self.assertEqual(c['level'], 'WARN')
        self.assertIn('local fallback', c['message'])
        self.assertIn('75', c['message'])
        self.assertEqual(c['blocks'], ['00000001-x'])

    def test_remote_failed_and_local_refused_twice_is_crit(self):
        d = '/w/00000040-y'
        cycle = [{'time': stamp(600), 'event': 'prover-failed', 'directory': d, 'where': 'remote', 'exit_code': 75},
                 {'time': stamp(600), 'event': 'local-proof-refused', 'directory': d, 'instructions': 3_100_000,
                  'limit': 3_000_000},
                 {'time': stamp(600), 'event': 'prover-failed', 'directory': d, 'where': 'local', 'exit_code': 75}]
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': cycle}))
        self.assertEqual(level(r, 'prover_path[settler]'), 'WARN', 'one failed cycle: the settler retries')
        self.assertEqual(level(r, 'events[settler]'), 'WARN')
        self.assertIn('local-proof-refused', next(c['message'] for c in r.checks if c['check'] == 'events[settler]'))
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': cycle * 2}))
        self.assertEqual(level(r, 'prover_path[settler]'), 'CRIT')

    def test_a_later_proof_clears_the_block(self):
        d = '/w/00000002-z'
        lines = [{'time': stamp(600), 'event': 'prover-failed', 'directory': d, 'where': 'local', 'exit_code': 137}] * 3 + \
                [{'time': stamp(60), 'event': 'proof-generated', 'directory': d, 'seconds': 300}]
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': lines}))
        self.assertEqual(level(r, 'prover_path[settler]'), 'WARN')

    def test_no_prover_failure_no_prover_path_check(self):
        lines = [{'time': stamp(60), 'event': 'proof-generated', 'directory': '/w/1', 'seconds': 300}]
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': lines}))
        self.assertNotIn('prover_path[settler]', [c['check'] for c in r.checks])

    # ---- L2-18 and the rest of the settler's silent events
    def test_settler_events_that_were_graded_by_nobody(self):
        for event in ('da-resign-limited', 'da-batch-unrecoverable', 'foreign-rebuild-behind-view', 'idle-check-failed',
                      'spool-demand-unknown', 'local-proof-refused', 'block-over-budget', 'tx-quarantined'):
            r, _ = run(healthy(), '--unit', 'settler=s.service',
                       runner=journal({'s.service': [{'time': stamp(60), 'event': event}]}))
            self.assertEqual(level(r, 'events[settler]'), 'WARN', event)

    def test_every_settler_event_is_classified(self):
        """settler_v3.py's log() names: each is graded, progress, or listed here as informational. A new event name fails
        this test until someone decides whether it alerts."""
        import re
        source = (REPO / 'deployment' / 'devnet' / 'settler_v3.py').read_text()
        names = set(re.findall(r"\blog\('([a-z0-9-]+)'", source))
        info = {'started', 'identity-checked', 'dry-run', 'rpc-check', 'rpc-endpoint-view', 'rpc-endpoint-agrees',
                'rpc-endpoint-recovered', 'rpc-quorum-restored', 'transaction-built', 'submitted', 'remote-proof',
                'prover-stages-done', 'prover-shm-removed', 'l2-block-produced', 'l2-block-reused', 'idle-hold', 'idle-end',
                'da-submitted', 'da-included', 'da-wait-ended-block-settled', 'da-batch-reused', 'da-reuse-waiting-follower',
                'da-fee-moved', 'request-moved-before-proof', 'request-moved-after-proof', 'request-moved-before-submit',
                'foreign-settlement-recovered', 'foreign-settlement-waiting-finality',
                'stopped',
                # Fork candidate: expected steps of a program swap or rollback, and of the sequencer policy.
                'program-scheduled', 'program-gate-pending', 'l2-block-rewound-at-swap', 'l2-block-reproved-for-program',
                'block-plan', 'txs-held', 'tx-quarantined'}
        graded = m.CRIT_EVENTS | m.WARN_EVENTS | m.PROGRESS_EVENTS | info
        self.assertGreater(len(names), 40)
        self.assertEqual(sorted(names - graded), [])

    # ---- L2-20: acknowledged transactions evicted as expired
    def test_spool_expired_evictions_in_the_rpc_journal(self):
        lines = ['spooled tx=0xaa from=0x01 nonce=3', 'evicted tx file=0001-aa.tx (expired)',
                 'evicted tx file=0002-bb.tx (nonce used)', 'spool sweep evicted 1 stale entries']
        r, _ = run(healthy(), '--unit', 'rpc=r.service', runner=journal({'r.service': lines}))
        c = next(c for c in r.checks if c['check'] == 'spool_expired[rpc]')
        self.assertEqual(c['level'], 'WARN')
        self.assertEqual(c['value'], 1)
        r, _ = run(healthy(), '--unit', 'rpc=r.service',
                   runner=journal({'r.service': [f'evicted tx file=000{i}-cc.tx (expired)' for i in range(5)]}))
        self.assertEqual(level(r, 'spool_expired[rpc]'), 'CRIT')
        r, _ = run(healthy(), '--unit', 'rpc=r.service', runner=journal({'r.service': lines[2:]}))
        self.assertNotIn('spool_expired[rpc]', [c['check'] for c in r.checks])

    def test_the_rpc_still_prints_the_eviction_line_the_check_reads(self):
        rs = (REPO / 'integrations' / 'reth-execution' / 'src' / 'bin' / 'bloch-l2-settled-rpc.rs').read_text()
        self.assertIn('println!("evicted tx file={} ({reason})"', rs)
        self.assertIn('Some("expired")', rs)

    # ---- F8 of report 121 / report 94: /dev/shm full of leaked SP1 segments
    def test_shm_free_space_and_leaked_segments(self):
        gib = 2 ** 30

        def shm_level(free_gib, segments):
            with tempfile.TemporaryDirectory() as d:
                for name, age in segments:
                    f = Path(d, name)
                    f.write_bytes(b'x' * 1024)
                    os.utime(f, (NOW - age, NOW - age))
                fake = os.statvfs_result((4096, 4096, 63 * gib // 4096, 0, int(free_gib * gib) // 4096, 0, 0, 0, 0, 255))
                with mock.patch.object(m.os, 'statvfs', return_value=fake):
                    r, _ = run(healthy(), '--shm', f'sp1={d}')
            return next(c for c in r.checks if c['check'] == 'shm[sp1]')
        self.assertEqual(shm_level(60, [('sp1_live_t', 600)])['level'], 'OK')
        self.assertEqual(shm_level(60, [('sem.other', 99999)])['level'], 'OK', 'only sp1_ segments count')
        c = shm_level(40, [('sp1_old_t', 4 * 3600), ('sp1_live_t', 60)])
        self.assertEqual(c['level'], 'WARN')
        self.assertEqual(c['stale'], 1)
        self.assertEqual(shm_level(10, [])['level'], 'WARN')
        self.assertEqual(shm_level(4, [])['level'], 'CRIT')
        self.assertEqual(shm_level(0, [('sp1_a_t', 9 * 3600)] * 1)['level'], 'CRIT')

    def test_shm_unreadable_is_unknown(self):
        r, _ = run(healthy(), '--shm', '/nonexistent/shm')
        self.assertEqual(level(r, 'shm[shm]'), 'UNKNOWN')

    # ---- 105's gap (signer /healthz) and L1-2 (indexer /health)
    def test_http_health_routes(self):
        answers = {'http://s1/healthz': (200, b'{"ok":true}'), 'http://idx/health': (503, b''),
                   'http://s2/healthz': (200, b'{"ok":false}')}

        def probe(url):
            if url not in answers:
                raise OSError('connection refused')
            return answers[url]
        argv = ['--profile', 'mainnet', '--l2-rpc', f'A={L2A}', '--l2-rpc', f'B={L2B}'] + \
            sum((['--l1-rpc', u] for u in L1), []) + \
            ['--http', 'signer1=http://s1/healthz|"ok":true', '--http', 'signer2=http://s2/healthz|"ok":true',
             '--http', 'indexer=http://idx/health', '--http', 'gone=http://gone/health']
        r = m.run(m.parse(argv), Fake(healthy()), now=NOW, run_cmd=lambda a: (1, ''), fetch=lambda u: None, probe=probe)
        self.assertEqual(level(r, 'http[signer1]'), 'OK')
        self.assertEqual(level(r, 'http[signer2]'), 'CRIT')
        self.assertEqual(level(r, 'http[indexer]'), 'CRIT')
        self.assertEqual(level(r, 'http[gone]'), 'CRIT')

    def test_http_probe_refuses_other_schemes(self):
        with self.assertRaises(ValueError):
            m.http_probe(1.0)('file:///etc/passwd')

    def test_new_checks_stay_quiet_on_the_healthy_snapshot_and_alert_once(self):
        """The new checks reach the same alert path: one raise for a new CRIT, nothing on the repeat."""
        w = healthy()
        w['l1'][L1[0]]['info']['finalized']['epoch'] = EPOCH - 580
        r, _ = run(w)
        state = {}
        self.assertEqual(m.decide_alert(r, state, NOW, 3600, m.WARN), 'raise')
        state.update({'bad': {c['check']: c['level'] for c in r.checks if c['code'] != m.OK}, 'sent_at': NOW})
        self.assertIsNone(m.decide_alert(r, state, NOW + 60, 3600, m.WARN))



class DrillFindings(unittest.TestCase):
    """Agent 205, round 11: monitor defects found by the drills on real binaries (agents/205-monitor-drills.md)."""

    def test_one_busy_remote_prover_counts_once(self):
        """Drill d: the settler logs `remote-proof` exit 75 and then `prover-failed` where=remote for the same attempt."""
        d = '/w/00000004-8da1e0a826a9200b'
        attempt = [{'time': stamp(300), 'event': 'remote-proof', 'target': 'p', 'exit_code': 75, 'bytes': 0},
                   {'time': stamp(300), 'event': 'prover-failed', 'directory': d, 'where': 'remote', 'exit_code': 75}]
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': attempt}))
        msg = next(c['message'] for c in r.checks if c['check'] == 'events[settler]')
        self.assertIn('prover-failed x1', msg)
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': attempt * 3}))
        self.assertEqual(level(r, 'events[settler]'), 'WARN', 'three busy answers are three failures, not six')
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': attempt * 5}))
        self.assertEqual(level(r, 'events[settler]'), 'CRIT')

    def test_remote_proof_alone_still_counts_for_older_settlers(self):
        lines = [{'time': stamp(300), 'event': 'remote-proof', 'target': 'p', 'exit_code': 137, 'bytes': 0}]
        r, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': lines}))
        self.assertIn('prover-failed x1', next(c['message'] for c in r.checks if c['check'] == 'events[settler]'))

    def test_shm_leak_size_is_the_memory_in_use_not_the_sparse_size(self):
        """Drill e: a killed execute left `sp1_*_m` (2 TiB sparse, 0 bytes in use) and `sp1_*_t` (4.5 GiB, 4 KiB in
        use). The WARN said "2052.4 GiB" leaked."""
        gib = 2 ** 30
        with tempfile.TemporaryDirectory() as d:
            for name, size in (('sp1_x_m', 2 * 1024 * gib), ('sp1_x_t', 4775215104)):
                with open(Path(d, name), 'wb') as f:
                    f.truncate(size)  # sparse, like the SP1 segments
                    f.write(b'x' * 4096)
                os.utime(Path(d, name), (NOW - 4 * 3600, NOW - 4 * 3600))
            fake = os.statvfs_result((4096, 4096, 63 * gib // 4096, 0, 60 * gib // 4096, 0, 0, 0, 0, 255))
            with mock.patch.object(m.os, 'statvfs', return_value=fake):
                r, _ = run(healthy(), '--shm', f'sp1={d}')
        c = next(c for c in r.checks if c['check'] == 'shm[sp1]')
        self.assertEqual(c['level'], 'WARN')
        self.assertEqual(c['stale'], 2)
        self.assertIn('older than 3 h (0.0 GiB in use', c['message'])

    def test_shm_short_stale_threshold_reads_in_minutes(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'sp1_y_t').write_bytes(b'x' * 4096)
            os.utime(Path(d, 'sp1_y_t'), (NOW - 900, NOW - 900))
            r, _ = run(healthy(), '--shm', f'sp1={d}', '--set', 'shm_stale_seconds=600')
        self.assertIn('older than 10 min', next(c['message'] for c in r.checks if c['check'] == 'shm[sp1]'))

    def test_split_minority_far_behind_in_height_is_still_a_branch_of_its_own(self):
        """Drill a: after 15 min of a 2|3 split the minority was 70 blocks behind (fewer proposers) with a current head
        slot. Height alone classed it as syncing."""
        w = healthy()
        for u in L1[:2]:
            w['l1'][u]['info']['finalized']['epoch'] = EPOCH - 15
            w['l1'][u]['info']['height'] -= 70
        c = next(c for c in run(w)[0].checks if c['check'] == 'l1_finality_spread')
        self.assertEqual(c['level'], 'CRIT')
        self.assertIn('branch of its own', c['message'])

    def test_conflicting_finalized_roots_at_one_epoch_are_crit(self):
        """Drill a: both sides of a 2|3 split finalized e68 with different roots once the leak had run; no other check
        named it."""
        w = healthy()
        self.assertEqual(level(run(w)[0], 'l1_finalized_agreement'), 'OK')
        for u in L1[:1]:
            w['l1'][u]['info']['finalized']['root'] = 'bb' * 32
        r, _ = run(w)
        c = next(c for c in r.checks if c['check'] == 'l1_finalized_agreement')
        self.assertEqual(c['level'], 'CRIT')
        self.assertIn('CONFLICTING FINALITY', c['message'])
        self.assertIn(L1[0], c['message'])
        self.assertEqual(level(r, 'l1_finality_spread'), 'OK', 'the case the spread check cannot see')

    def test_a_held_settlement_raises_its_own_alert_while_events_is_already_warn(self):
        """Drill f: `settlement-not-included` arrived while events[settler] was WARN for a busy prover, so no alert left
        until realert_seconds."""
        d = '/w/00000004-8da1e0a826a9200b'
        busy = [{'time': stamp(1800), 'event': 'remote-proof', 'target': 'p', 'exit_code': 75, 'bytes': 0},
                {'time': stamp(1800), 'event': 'prover-failed', 'directory': d, 'where': 'remote', 'exit_code': 75}]
        held = [{'time': stamp(120), 'event': 'settlement-not-included', 'number': 4, 'held_by': [1, 2, 3], 'windows': 1,
                 'halt_after': 4}]
        r1, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': busy}))
        self.assertNotIn('settlement_inclusion[settler]', [c['check'] for c in r1.checks])
        state = {'bad': {c['check']: c['level'] for c in r1.checks if c['code'] != m.OK}, 'sent_at': NOW}
        r2, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': busy + held}))
        self.assertEqual(level(r2, 'events[settler]'), 'WARN')
        self.assertEqual(level(r2, 'settlement_inclusion[settler]'), 'WARN')
        self.assertEqual(m.decide_alert(r2, state, NOW + 60, 3600, m.WARN), 'raise')
        near = [dict(held[0], windows=3)]
        r3, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': near}))
        self.assertEqual(level(r3, 'settlement_inclusion[settler]'), 'CRIT', 'one window before the halt')
        done = held + [{'time': stamp(30), 'event': 'accepted', 'number': 4, 'commitment': 'cc' * 32}]
        r4, _ = run(healthy(), '--unit', 'settler=s.service', runner=journal({'s.service': done}))
        self.assertEqual(level(r4, 'settlement_inclusion[settler]'), 'OK')


class ReviewR15Tests(unittest.TestCase):
    """Review r15 (agent 308), R308-29 to R308-31 and R308-33a: the demonstrations of
    review-r15-308/monitors.py as regression tests."""
    UNIT = 'bloch-l2-mainnet-settler.service'

    # ---- R308-29: a journal that cannot be read is never silence
    def test_r308_29_unreadable_journal_is_an_unknown_events_check(self):
        for code, out in ((1, ''), (127, 'Command timed out after 30 seconds')):
            def runner(argv, code=code, out=out):
                return (0, ACTIVE) if argv[0] == 'systemctl' else (code, out)
            report, _ = run(healthy(), '--unit', f'settler={self.UNIT}', runner=runner)
            self.assertEqual(level(report, 'unit[settler]'), 'OK')
            self.assertEqual(level(report, 'events[settler]'), 'UNKNOWN')
            self.assertEqual(level(report, 'foreign_settlements[settler]'), 'UNKNOWN')
            self.assertIn('journalctl exit %d' % code, next(c['message'] for c in report.checks if c['check'] == 'events[settler]'))
            self.assertEqual(report.status, m.UNKNOWN)

    def test_r308_29_a_readable_journal_keeps_its_grades(self):
        report, _ = run(healthy(), '--unit', f'settler={self.UNIT}', runner=journal({self.UNIT: []}))
        self.assertEqual(level(report, 'events[settler]'), 'OK')
        self.assertNotIn('foreign_settlements[settler]', [c['check'] for c in report.checks])
        self.assertEqual(report.status, m.OK)

    def test_r308_29_subprocess_runner_reports_a_timeout_as_a_failure(self):
        with mock.patch.object(m.subprocess, 'run', side_effect=m.subprocess.TimeoutExpired('journalctl', 30)):
            code, out = m.subprocess_runner(['journalctl', '-u', self.UNIT])
        self.assertEqual(code, 127)
        self.assertIn('timed out', out)

    # ---- R308-30: attestors
    def roots_world(self, age=500, withdrawn_blch=176):
        world = healthy()
        for node in world['l1'].values():
            node['l2']['withdrawals']['roots'] = [{'root': 'ab' * 32, 'finalized': True, 'height': 34000 - age, 'l2_number': 90}]
        for b in world['l2'].values():
            b['ledger']['0x3'] = withdrawn_blch * BLCH_WEI
        return world

    def attest_message(self, report):
        return next(c['message'] for c in report.checks if c['check'] == 'attestors')

    def test_r308_30_live_mainnet_without_a_drop_is_warn(self):
        report, _ = run(healthy(), '--no-default-drop')
        self.assertEqual(level(report, 'attestors'), 'WARN')
        self.assertIn('not watched', self.attest_message(report))
        report, _ = run(prelaunch(), '--no-default-drop', phase='prelaunch')
        self.assertNotIn('attestors', [c['check'] for c in report.checks])

    def test_r308_30_a_fetcher_that_cannot_tell_absent_from_unreachable_counts_as_unreachable(self):
        report, _ = run(self.roots_world(), '--attest-drop', 'https://drop.example/attest', fetch=lambda url: None)
        self.assertEqual(level(report, 'attestors'), 'CRIT')
        self.assertIn('drop https://drop.example/attest unreachable (no answer)', self.attest_message(report))

    def test_r308_30_unreachable_drops_are_told_apart_from_nothing_to_sign(self):
        feeds = [f'http://att{i}.example:8600' for i in range(5)]
        args = sum((['--attest-drop', f] for f in feeds), [])

        def fetcher(down, no_health=()):
            def fetch(url):
                base = url.split('/', 3)[:3]
                base = '/'.join(base)
                if base in down:
                    fetch.errors[url] = 'URLError: connection refused'
                    return None
                if url.endswith('/healthz') and base not in no_health:
                    return b'ok\n'
                return None  # 404: a missing partial, or a static host with no health route
            fetch.errors = {}
            return fetch
        # No finalized root at all: all feeds up is OK, "nothing to sign"; any feed down is told.
        report, _ = run(healthy(), *args, fetch=fetcher(set()))
        self.assertEqual(level(report, 'attestors'), 'OK')
        report, _ = run(healthy(), *args, fetch=fetcher(set(), no_health=set(feeds)))
        self.assertEqual(level(report, 'attestors'), 'OK', 'a 404 on /healthz is an answer')
        report, _ = run(healthy(), *args, fetch=fetcher({feeds[4]}))
        self.assertEqual(level(report, 'attestors'), 'WARN')
        self.assertIn('nothing to sign; drop http://att4.example:8600 unreachable (URLError: connection refused)',
                      self.attest_message(report))
        report, _ = run(healthy(), *args, fetch=fetcher(set(feeds[:3])))
        self.assertEqual(level(report, 'attestors'), 'CRIT', 'fewer feeds reachable than the threshold of 3')
        report, _ = run(healthy(), *args, fetch=fetcher(set(feeds)))
        self.assertEqual(level(report, 'attestors'), 'CRIT')
        self.assertEqual(report.facts['attestation_drops'], {'configured': 5, 'unreachable': sorted(feeds)})
        # A missing directory drop is unreachable too.
        report, _ = run(healthy(), '--attest-drop', os.path.join(EMPTY_DROP, 'missing'))
        self.assertEqual(level(report, 'attestors'), 'CRIT')
        self.assertIn('not a directory', self.attest_message(report))

    def test_r308_30_old_unsigned_root_with_a_large_unclaimed_sum_is_warn(self):
        # 176 BLCH released on L1. Withdrawn on L2: 176 (all claimed), 275.99 (below 100 unclaimed), 276 (100 unclaimed).
        for withdrawn, age, want in ((176, 500, 'OK'), (275, 500, 'OK'), (276, 500, 'WARN'), (400, 500, 'WARN'),
                                     (400, 100, 'OK')):  # within the grace of 120 blocks: not judged yet
            report, _ = run(self.roots_world(age, withdrawn))
            self.assertEqual(level(report, 'attestors'), want, (withdrawn, age))
        self.assertIn('carry no partial while', self.attest_message(run(self.roots_world(500, 400))[0]))
        report, _ = run(self.roots_world(500, 400), '--set', 'attest_unclaimed_warn_sat=30000000000')
        self.assertEqual(level(report, 'attestors'), 'OK', 'the operator can move the threshold')

    def test_r308_30_http_fetcher_records_transport_errors_and_not_404(self):
        fetch = m.http_fetcher(1.0)

        def urlopen(url, timeout=None):
            if url.endswith('/gone'):
                raise m.urllib.error.HTTPError(url, 404, 'Not Found', {}, None)
            if url.endswith('/broken'):
                raise m.urllib.error.HTTPError(url, 502, 'Bad Gateway', {}, None)
            raise m.urllib.error.URLError('connection refused')
        with mock.patch.object(m.urllib.request, 'urlopen', urlopen):
            self.assertIsNone(fetch('http://x/gone'))
            self.assertIsNone(fetch('http://x/broken'))
            self.assertIsNone(fetch('http://x/down'))
        self.assertEqual(sorted(fetch.errors), ['http://x/broken', 'http://x/down'])

    # ---- R308-31: the monitor's own failures
    def alert_setup(self, d, phase='live', **cfg):
        path = Path(d, 'alert.json')
        path.write_text(json.dumps({'state_file': str(Path(d, 'alert.state')), **cfg}))
        return m.parse(['--phase', phase, '--alert-config', str(path)])

    def crit_report(self):
        r = m.Report()
        r.add('settlement_age', m.CRIT, 'last settlement accepted 180 min ago')
        return r

    def pings(self):
        seen = []

        def urlopen(req, timeout=None):
            seen.append(req.full_url)
            return io.BytesIO(b'OK')
        return seen, mock.patch.object(m.urllib.request, 'urlopen', urlopen)

    def test_r308_31_no_plain_ping_when_a_due_alert_was_not_delivered(self):
        def failing(cfg, text, payload, timeout, dry_run):
            raise OSError('HTTP Error 401: Unauthorized')
        for sender, why in ((failing, 'delivery raised'), (lambda *a: [], 'no target configured')):
            with tempfile.TemporaryDirectory() as d:
                args = self.alert_setup(d, webhook_url='https://hooks.example/x', heartbeat_url='https://hc.example/ping/uuid')
                seen, patch = self.pings()
                r = self.crit_report()
                with patch:
                    self.assertEqual(m.handle_alerts(args, r, 1_800_000_000.0, sender=sender), 'raise')
                self.assertEqual(seen, [], why)
                self.assertEqual(level(r, 'alert_delivery'), 'WARN')
                # With a failure URL the dead-man service is told at once.
                args = self.alert_setup(d, webhook_url='https://hooks.example/x', heartbeat_url='https://hc.example/ping/uuid',
                                        heartbeat_fail_url='https://hc.example/ping/uuid/fail')
                seen, patch = self.pings()
                with patch:
                    m.handle_alerts(args, self.crit_report(), 1_800_000_000.0, sender=sender)
                self.assertEqual(seen, ['https://hc.example/ping/uuid/fail'], why)

    def test_r308_31_the_ping_follows_a_delivered_alert_and_a_quiet_run(self):
        order = []

        def sender(cfg, text, payload, timeout, dry_run):
            order.append('alert')
            return ['webhook']
        with tempfile.TemporaryDirectory() as d:
            args = self.alert_setup(d, webhook_url='https://hooks.example/x', heartbeat_url='https://hc.example/ping/uuid')

            def urlopen(req, timeout=None):
                order.append('ping')
                return io.BytesIO(b'OK')
            with mock.patch.object(m.urllib.request, 'urlopen', urlopen):
                self.assertEqual(m.handle_alerts(args, self.crit_report(), 1_800_000_000.0, sender=sender), 'raise')
                self.assertIsNone(m.handle_alerts(args, self.crit_report(), 1_800_000_060.0, sender=sender))  # unchanged
                ok = m.Report()
                ok.add('l2_head_age', m.OK, 'fine')
                with tempfile.TemporaryDirectory() as d2:
                    quiet = self.alert_setup(d2, webhook_url='https://hooks.example/x', heartbeat_url='https://hc.example/ping/uuid')
                    self.assertIsNone(m.handle_alerts(quiet, ok, 1_800_000_000.0, sender=sender))
        self.assertEqual(order, ['alert', 'ping', 'ping', 'ping'])

    def test_r308_31_live_phase_without_heartbeat_is_warn_and_alerted(self):
        texts = []

        def sender(cfg, text, payload, timeout, dry_run):
            texts.append(text)
            return ['webhook']
        for url in ('TBD-owner', '', None):
            with tempfile.TemporaryDirectory() as d:
                args = self.alert_setup(d, webhook_url='https://hooks.example/x', heartbeat_url=url)
                r = m.Report()
                r.add('l2_head_age', m.OK, 'fine')
                self.assertEqual(m.handle_alerts(args, r, 1_800_000_000.0, sender=sender), 'raise')
                self.assertEqual(level(r, 'heartbeat'), 'WARN')
                self.assertIn('WARN heartbeat: no heartbeat_url configured', texts[-1])
                pre = self.alert_setup(d, phase='prelaunch', webhook_url='https://hooks.example/x', heartbeat_url=url,
                                       state_file=str(Path(d, 'pre.state')))
                r = m.Report()
                r.add('l2_head_age', m.OK, 'fine')
                self.assertIsNone(m.handle_alerts(pre, r, 1_800_000_000.0, sender=sender))
                self.assertNotIn('heartbeat', [c['check'] for c in r.checks])

    def test_r308_31_a_check_that_raises_is_a_crit_and_the_others_still_run(self):
        world = healthy()
        world['l1'][L1[0]]['info']['height'] += 1
        world['l1'][L1[0]]['l2']['inbox']['escrow_sat'] = None
        err = io.StringIO()
        with redirect_stderr(err):
            report, _ = run(world, '--unit', f'settler={self.UNIT}', runner=journal({self.UNIT: []}))
        self.assertEqual(level(report, 'monitor[escrow_and_backlog]'), 'CRIT')
        self.assertIn('TypeError', next(c['message'] for c in report.checks if c['check'] == 'monitor[escrow_and_backlog]'))
        self.assertIn('Traceback', err.getvalue())
        self.assertEqual(level(report, 'settlement_age'), 'OK')
        self.assertEqual(level(report, 'unit[settler]'), 'OK', 'checks after the failing one still ran')
        self.assertEqual(report.status, m.CRIT)

    def test_r308_31_main_turns_an_exception_into_a_crit_that_is_alerted(self):
        sent = []

        def sender(cfg, text, payload, timeout, dry_run):
            sent.append(text)
            return ['webhook']
        real_handle = m.handle_alerts
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d, 'alert.json')
            cfg.write_text(json.dumps({'state_file': str(Path(d, 'alert.state')), 'webhook_url': 'https://hooks.example/x',
                                       'heartbeat_url': 'https://hc.example/ping/uuid'}))
            seen, patch = self.pings()
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(m, 'run', side_effect=KeyError('height')), patch, \
                    mock.patch.object(m, 'handle_alerts', lambda a, r, now: real_handle(a, r, now, sender=sender)), \
                    redirect_stdout(out), redirect_stderr(err):
                code = m.main(['--l2-rpc', L2A, '--l1-rpc', L1[0], '--alert-config', str(cfg), '--json'])
            self.assertEqual(code, m.CRIT)
            doc = json.loads(out.getvalue())
            self.assertEqual([(c['check'], c['level']) for c in doc['checks']], [('monitor', 'CRIT')])
            self.assertIn('CRIT monitor: the monitor run failed with KeyError', sent[0])
            self.assertEqual(seen, ['https://hc.example/ping/uuid'], 'the alert was delivered, so the ping follows')
            self.assertIn('Traceback', err.getvalue())
            # An alert path that fails itself (config cut short) is CRIT too, exit 2, never a traceback with exit 1.
            cfg.write_text('{')
            fake = Fake(healthy())
            out = io.StringIO()
            with mock.patch.object(m, 'http_transport', return_value=fake), mock.patch.object(m.time, 'time', return_value=NOW), \
                    redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = m.main(['--l2-rpc', L2A, '--l1-rpc', L1[0], '--attest-drop', EMPTY_DROP, '--alert-config', str(cfg), '--json'])
            self.assertEqual(code, m.CRIT)
            self.assertIn(('alert_delivery', 'CRIT'), [(c['check'], c['level']) for c in json.loads(out.getvalue())['checks']])

    def test_r308_31_shipped_unit_and_alert_example(self):
        mon = Path(__file__).resolve().parent / 'monitor'
        example = json.loads((mon / 'alert.json.example').read_text())
        self.assertIn('heartbeat_url', example)
        self.assertIn('heartbeat_fail_url', example)
        # The feeds exist only after P10 of the go-live plan, so the example carries no --attest-drop; the live
        # monitor says so (WARN attestors) until the five feeds are added, and the plan tells the operator to.
        self.assertNotIn('--attest-drop', (mon / 'monitor.env.example').read_text())
        plan = (Path(__file__).resolve().parents[2] / 'docs' / 'L2-MAINNET-GO-LIVE.md').read_text()
        self.assertIn('--attest-drop http://FEED_HOST:8787', plan)
        self.assertIn('heartbeat_fail_url', plan)
        unit = (mon / 'bloch-l2-mainnet-monitor.service').read_text()
        self.assertIn('SupplementaryGroups=systemd-journal', unit)

    # ---- R308-33a: one L1 endpoint does not decide the settlement age
    def test_r308_33a_settlement_age_is_the_worst_among_nodes_within_the_height_spread(self):
        old = (NOW - 3 * 3600 - m.L1_GENESIS_TIME) // 30
        world = healthy()
        for url in L1[:2]:
            world['l1'][url]['l2']['source']['slot'] = old
        world['l1'][L1[2]]['info']['height'] += 1
        report, _ = run(world)
        self.assertEqual(level(report, 'settlement_age'), 'CRIT')
        self.assertIn('still reports this older settlement', next(c['message'] for c in report.checks if c['check'] == 'settlement_age'))
        # A node outside the tolerated spread (3 blocks on mainnet) is l1_height_spread's to report, not a witness.
        world = healthy()
        world['l1'][L1[0]]['l2']['source']['slot'] = old
        for url in L1[1:]:
            world['l1'][url]['info']['height'] += 3
        report, _ = run(world)
        self.assertEqual(level(report, 'settlement_age'), 'OK')
        self.assertEqual(level(report, 'l1_height_spread'), 'WARN')
        # All nodes agree: the message is the plain one.
        report, _ = run(healthy())
        self.assertNotIn('still reports', next(c['message'] for c in report.checks if c['check'] == 'settlement_age'))



class ReviewR15SecondPass(unittest.TestCase):
    """Review r15 second pass (agent 308), R308-2P-10 and R308-2P-11: the demonstrations of
    review-r15-308-2p/monitors2.py as regression tests. Real functions; only urlopen is replaced."""
    FEEDS = [f'https://att{i}.example/attest' for i in range(5)]

    def world(self, roots=1, age_blocks=500):
        return [{'height': 10, 'url': 'l1', 'l2': {'native_height': 1000, 'withdrawals': {'released_sat': 0, 'roots': [
            {'root': '0x' + f'{n + 0xa0:02x}' * 32, 'finalized': True, 'l2_number': 5 + n, 'height': 1000 - age_blocks}
            for n in range(roots)]}}}]

    def attestors(self, urlopen, world=None, **thresholds):
        report = m.Report()
        with mock.patch.object(m.urllib.request, 'urlopen', urlopen):
            m.check_attestors(self.FEEDS, world or self.world(), {**m.PROFILES['mainnet'], **thresholds},
                              m.http_fetcher(1.0), report, 'live')
        return next(c for c in report.checks if c['check'] == 'attestors'), report

    def test_r308_2p_10_feeds_that_refuse_the_monitor_are_unreachable(self):
        for code in (401, 403, 429, 502):
            def urlopen(url, timeout=None, code=code):
                raise m.urllib.error.HTTPError(url, code, 'refused', {}, io.BytesIO(b''))
            check, report = self.attestors(urlopen)
            self.assertEqual(check['level'], 'CRIT', code)
            self.assertIn(f'drop https://att0.example/attest unreachable (HTTP {code})', check['message'])
            self.assertEqual(len(report.facts['attestation_drops']['unreachable']), 5)

    def test_r308_2p_10_only_404_means_no_partial(self):
        def urlopen(url, timeout=None):
            raise m.urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO(b''))
        check, report = self.attestors(urlopen)   # static hosts without a health route and without partials
        self.assertEqual(check['level'], 'OK')
        self.assertEqual(report.facts['attestation_drops']['unreachable'], [])

    def test_r308_2p_10_partials_that_fail_behind_a_healthy_healthz_are_unreachable(self):
        asked = []

        def urlopen(url, timeout=None):
            asked.append(url)
            if url.endswith('/healthz'):
                return io.BytesIO(b'ok\n')
            raise m.urllib.error.URLError('timed out')
        check, report = self.attestors(urlopen, self.world(roots=3))
        self.assertEqual(check['level'], 'CRIT')
        self.assertIn('unreachable (partial request failed: URLError', check['message'])
        self.assertEqual(len(report.facts['attestation_drops']['unreachable']), 5)
        # a feed that failed one partial request is not asked again in this run: 5 health probes + 5 partials
        self.assertEqual(len(asked), 10)

    def test_r308_2p_10_one_feed_failing_its_partials_is_a_warn_and_the_others_still_count(self):
        def urlopen(url, timeout=None):
            if url.endswith('/healthz'):
                return io.BytesIO(b'ok\n')
            if 'att3.example' in url:
                raise m.urllib.error.HTTPError(url, 503, 'Unavailable', {}, io.BytesIO(b''))
            raise m.urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO(b''))
        check, report = self.attestors(urlopen)
        self.assertEqual(check['level'], 'WARN')
        self.assertEqual(report.facts['attestation_drops']['unreachable'], ['https://att3.example/attest'])

    def test_r308_2p_10_the_probing_stops_at_its_time_budget(self):
        clock = [0.0]

        def urlopen(url, timeout=None):
            clock[0] += 7.0   # every feed answers, slowly
            if url.endswith('/healthz'):
                return io.BytesIO(b'ok\n')
            raise m.urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO(b''))
        with mock.patch.object(m.time, 'monotonic', lambda: clock[0]):
            check, report = self.attestors(urlopen, self.world(roots=4))
        self.assertLessEqual(clock[0], 60 + 7, 'one run asked the feeds for longer than the budget plus one request')
        self.assertEqual(check['level'], 'WARN')
        self.assertIn('probing stopped at the time budget of 60 s: 4 root(s) not looked at in full', check['message'])
        with mock.patch.object(m.time, 'monotonic', lambda: clock[0]):
            check, _ = self.attestors(urlopen, self.world(roots=4), attest_probe_budget_s=0)
        self.assertEqual(check['level'], 'CRIT')
        self.assertIn('not probed: the probing time budget was used up', check['message'])

    def alerts(self, d, down=('telegram',)):
        token = Path(d, 'token')
        token.write_text('123:abc\n')
        cfg = Path(d, 'alert.json')
        cfg.write_text(json.dumps({'webhook_url': 'https://hooks.example/x', 'heartbeat_url': 'https://hc.example/ping',
                                   'heartbeat_fail_url': 'https://hc.example/ping/fail',
                                   'telegram': {'bot_token_file': str(token), 'chat_id': '1'},
                                   'state_file': str(Path(d, 'alert.state'))}))
        seen = []

        def urlopen(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            name = 'telegram' if 'telegram' in url else 'webhook' if 'hooks.example' in url else url
            seen.append(name)
            if name in down:
                raise m.urllib.error.URLError(f'{url} unreachable')
            return io.BytesIO(b'ok')
        args = m.parse(['--alert-config', str(cfg), '--timeout', '1'])
        return args, seen, urlopen

    def crit(self):
        report = m.Report()
        report.facts['checked_at'] = 1_800_000_000
        report.add('settlement_age', m.CRIT, 'no settlement for 3 h')
        return report

    def test_r308_2p_11_one_dead_target_does_not_undo_a_delivery(self):
        with tempfile.TemporaryDirectory() as d:
            args, seen, urlopen = self.alerts(d)
            with mock.patch.object(m.urllib.request, 'urlopen', urlopen):
                reports = [self.crit() for _ in range(3)]
                for n, report in enumerate(reports):
                    m.handle_alerts(args, report, 1_800_000_000 + 300 * n)
        self.assertEqual(seen, ['webhook', 'telegram', 'https://hc.example/ping', 'https://hc.example/ping',
                                'https://hc.example/ping'])
        delivery = next(c for c in reports[0].checks if c['check'] == 'alert_delivery')
        self.assertEqual(delivery['level'], 'WARN')
        self.assertIn('alert delivered by webhook; failed: telegram', delivery['message'])
        self.assertNotIn('123:abc', delivery['message'], 'the bot token (part of the URL) reached the report')
        self.assertEqual(reports[0].facts['alert'], {'decision': 'raise', 'sent': ['webhook']})

    def test_r308_2p_11_every_target_dead_is_still_not_delivered(self):
        with tempfile.TemporaryDirectory() as d:
            args, seen, urlopen = self.alerts(d, down=('telegram', 'webhook'))
            report = self.crit()
            with mock.patch.object(m.urllib.request, 'urlopen', urlopen):
                m.handle_alerts(args, report, 1_800_000_000)
                m.handle_alerts(args, self.crit(), 1_800_000_300)
        self.assertEqual(seen, ['webhook', 'telegram', 'https://hc.example/ping/fail'] * 2)
        self.assertIn('alert not delivered: webhook:', next(c['message'] for c in report.checks if c['check'] == 'alert_delivery'))


class ShadowOrderEvents(unittest.TestCase):
    """Review R308-6P-2: the shadow's `shadow-order-unchecked` (no selection.json from the settler, or forced
    records) is graded: a warning, critical when it repeats inside the window, like `shadow-policy-mismatch`."""

    def grade(self, event, count):
        report = m.Report()
        events = [{'event': event, 'time': f'2026-11-12T00:00:{i:02d}Z', 'number': i} for i in range(count)]
        m.grade_events('bloch-l2-mainnet-shadow', events, dict(m._COMMON), 3600, report)
        return report.facts['events[bloch-l2-mainnet-shadow]']['failures'], max(c['code'] for c in report.checks)

    def test_unchecked_order_warns_and_is_critical_when_it_persists(self):
        for event in ('shadow-order-unchecked', 'shadow-policy-mismatch'):
            counts, level = self.grade(event, 1)
            self.assertEqual((counts, level), ({event: 1}, m.WARN))
            repeat = m._COMMON['event_repeat_crit']
            self.assertEqual(self.grade(event, repeat), ({event: repeat}, m.CRIT))
        self.assertEqual(self.grade('shadow-order-ok', 9)[0], {})

if __name__ == '__main__':
    unittest.main()
