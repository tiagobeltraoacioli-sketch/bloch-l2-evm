#!/usr/bin/env python3
"""Unit tests for l2_monitor.py with a fake RPC transport (no network).

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_l2_monitor.py' -v
"""
import copy
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

NOW = 1_800_000_000
L2 = 'http://l2'
L1 = ['http://l1a', 'http://l1b', 'http://l1c']
BLCH_WEI = 10 ** 18


def block(number, age):
    return {'number': hex(number), 'timestamp': hex(NOW - age), 'hash': '0x' + f'{number:064x}',
            'baseFeePerGas': hex(10 ** 9)}


def healthy():
    """A mainnet snapshot shaped like the devnet4 replies of 2026-10-18."""
    l1 = {
        'height': 154813, 'epoch': 5944, 'finalized_height': 154736,
        'finalized': {'epoch': 5942, 'root': 'aa' * 32},
    }
    settlement = {
        'chain_id': 700770,
        'inbox': {'count': 3, 'consumed': 3, 'escrow_sat': str(124 * 10 ** 8)},
        'data_availability': [],
        'withdrawals': {'escrow_conserved': True, 'released_sat': str(176 * 10 ** 8),
                        'release_window': {'window': 7, 'cap_sat': str(10 ** 9), 'remaining_sat': str(10 ** 9)}},
        'accepted': {'commitment': 'cc' * 32},
    }
    return {
        'l2': {
            'eth_chainId': '0xab162',
            'latest': block(100, 5 * 60), 'safe': block(99, 17 * 60), 'finalized': block(95, 100 * 60),
            'bloch_finality': {'finalized_height': 95, 'l1': {'verified_blocks': 154700}},
            'ledger': {'0x0': 300 * BLCH_WEI, '0x2': 0, '0x3': 176 * BLCH_WEI},
        },
        'l1': {url: {'info': copy.deepcopy(l1), 'l2': copy.deepcopy(settlement)} for url in L1},
    }


class Fake:
    def __init__(self, world):
        self.world = world
        self.calls = []

    def __call__(self, url, method, params):
        self.calls.append((url, method))
        if url == L2:
            w = self.world['l2']
            if w is None:
                raise m.RpcError('connection refused')
            if method == 'eth_chainId':
                return w['eth_chainId']
            if method == 'eth_getBlockByNumber':
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
        raise AssertionError(f'unexpected {method}')


def run(world, *extra):
    args = m.parse(['--profile', 'mainnet', '--l2-rpc', L2] + sum((['--l1-rpc', u] for u in L1), []) + list(extra))
    fake = Fake(world)
    return m.run(args, fake, now=NOW), fake


def level(report, name):
    return next(c['level'] for c in report.checks if c['check'] == name)


class MonitorTests(unittest.TestCase):
    def test_healthy_snapshot_is_ok(self):
        r, fake = run(healthy())
        self.assertEqual(m.LEVEL_NAMES[r.status], 'OK', json.dumps(r.checks, indent=1))
        self.assertEqual(r.facts['l2_latest'], 100)
        self.assertEqual(r.facts['l1_finalized_epoch'], 5942)

    def test_only_read_only_methods_are_called(self):
        _, fake = run(healthy())
        self.assertTrue({method for _, method in fake.calls} <= m.READ_ONLY_METHODS)

    def test_client_refuses_write_methods_without_io(self):
        transport = mock.Mock()
        client = m.Client(transport)
        for method in ('eth_sendRawTransaction', 'sendrawtransaction', 'personal_sign', 'eth_sign'):
            with self.assertRaises(PermissionError):
                client.call(L2, method, [])
        transport.assert_not_called()

    def test_stale_head_is_critical(self):
        w = healthy()
        w['l2']['latest'] = block(100, 50 * 60)
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_head_age'), 'CRIT')
        self.assertEqual(r.status, m.CRIT)

    def test_settlement_backlog_warns_then_crits(self):
        w = healthy()
        w['l2']['safe'] = block(98, 30 * 60)
        self.assertEqual(level(run(w)[0], 'l2_unsafe_depth'), 'WARN')
        w['l2']['safe'] = block(96, 60 * 60)
        self.assertEqual(level(run(w)[0], 'l2_unsafe_depth'), 'CRIT')

    def test_finality_stall(self):
        w = healthy()
        w['l2']['finalized'] = block(80, 5 * 3600)
        w['l2']['bloch_finality']['finalized_height'] = 80
        for node in w['l1'].values():
            node['info']['finalized']['epoch'] = 5934
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_finalized_age'), 'CRIT')
        self.assertEqual(level(r, 'l1_finality_lag'), 'CRIT')

    def test_tag_inversion_is_critical(self):
        w = healthy()
        w['l2']['finalized'] = block(100, 5 * 60)
        w['l2']['safe'] = block(99, 17 * 60)
        w['l2']['bloch_finality']['finalized_height'] = 100
        self.assertEqual(level(run(w)[0], 'l2_tag_order'), 'CRIT')

    def test_nothing_settled_yet_is_a_warning(self):
        w = healthy()
        w['l2']['safe'] = None
        w['l2']['finalized'] = None
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_safe'), 'WARN')
        self.assertEqual(level(r, 'l2_finalized'), 'WARN')
        self.assertEqual(r.status, m.WARN)

    def test_wrong_chain_id(self):
        w = healthy()
        w['l2']['eth_chainId'] = '0xab163'
        self.assertEqual(level(run(w)[0], 'l2_chain_id'), 'CRIT')

    def test_escrow_not_conserved_on_one_node(self):
        w = healthy()
        w['l1'][L1[1]]['l2']['withdrawals']['escrow_conserved'] = False
        self.assertEqual(level(run(w)[0], 'escrow_conserved'), 'CRIT')

    def test_escrow_backing_shortfall(self):
        w = healthy()
        w['l2']['ledger']['0x0'] = 301 * BLCH_WEI
        r, _ = run(w)
        self.assertEqual(level(r, 'escrow_backing'), 'CRIT')
        w = healthy()
        w['l2']['ledger']['0x3'] = 100 * BLCH_WEI
        self.assertEqual(level(run(w)[0], 'claims_vs_withdrawn'), 'CRIT')

    def test_one_l1_node_down_warns_majority_down_crits(self):
        w = healthy()
        del w['l1'][L1[0]]
        self.assertEqual(level(run(w)[0], 'l1_nodes'), 'WARN')
        del w['l1'][L1[1]]
        self.assertEqual(level(run(w)[0], 'l1_nodes'), 'CRIT')

    def test_l2_rpc_down(self):
        w = healthy()
        w['l2'] = None
        r, _ = run(w)
        self.assertEqual(level(r, 'l2_rpc'), 'CRIT')
        self.assertEqual(r.status, m.CRIT)

    def test_follower_lag(self):
        w = healthy()
        w['l2']['bloch_finality']['l1']['verified_blocks'] = 154736 - 400
        self.assertEqual(level(run(w)[0], 'follower_lag'), 'CRIT')

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

    def test_l1_accepted_split_warns(self):
        w = healthy()
        w['l1'][L1[2]]['l2']['accepted']['commitment'] = 'dd' * 32
        self.assertEqual(level(run(w)[0], 'l1_accepted_agreement'), 'WARN')

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

    def test_threshold_override(self):
        w = healthy()
        r, _ = run(w, '--set', 'head_age_warn=60')
        self.assertEqual(level(r, 'l2_head_age'), 'WARN')
        with self.assertRaises(SystemExit):
            run(w, '--set', 'nonsense=1')

    def test_main_prints_json_and_returns_status(self):
        fake = Fake(healthy())
        with mock.patch.object(m, 'http_transport', return_value=fake), mock.patch.object(m.time, 'time', return_value=NOW):
            out = io.StringIO()
            with redirect_stdout(out):
                code = m.main(['--l2-rpc', L2, '--l1-rpc', L1[0], '--json'])
        doc = json.loads(out.getvalue())
        self.assertEqual(code, m.OK)
        self.assertEqual(doc['status'], 'OK')


if __name__ == '__main__':
    unittest.main()
