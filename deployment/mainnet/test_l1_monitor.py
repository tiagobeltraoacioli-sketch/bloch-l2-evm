#!/usr/bin/env python3
"""Unit tests for l1_monitor.py: replays of recorded private-net RPC answers, plus synthetic cases where no recording
exists (each says so). No network, no node, no systemd.

Fixtures: testdata/l1_monitor/*.json, made by testdata/l1_monitor/make_fixtures.py from the probes and verdicts that
agents 69 and 79 recorded on 1 s-slot private nets (getchaininfo fields, getblockbyid answers including the node's own
"no block ... is known to this node" error text, and /metrics lines). Their snapshots are about 3 epochs apart, so
the replays use agent 70's replay settings for stuck detection (min samples 2, no gap reset).

Run: python3 -m unittest discover -s deployment/mainnet -p 'test_l1_monitor.py' -v
"""
import inspect
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import l1_monitor as m  # noqa: E402
import l1_stuck_check  # noqa: E402
import l2_monitor  # noqa: E402

FIXTURES = HERE / 'testdata' / 'l1_monitor'
REPLAY = {'stuck_min_samples': 2, 'stuck_max_gap_epochs': 1000}
PRIVATE_NET = {'genesis_time': 0, 'slot_seconds': 1, 'slots_per_epoch': 32}


def fixture(case):
    return json.loads((FIXTURES / f'{case}.json').read_text())


def url(name):
    return f'http://{name}:8080'


def name_of(u):
    return u.split('//')[1].split(':')[0]


def transport_for(rd, calls=None):
    """Answers as the recorded nodes did: getchaininfo from the probe, getblockbyid true or the recorded error."""
    def call(u, method, params):
        if calls is not None:
            calls.append((name_of(u), method, tuple(params)))
        n = name_of(u)
        if method == 'getchaininfo':
            view = rd['getchaininfo'].get(n)
            if view is None:
                raise m.RpcError(f'getchaininfo at {u}: connection refused')
            return view
        if method == 'getblockbyid':
            ans = rd['getblockbyid'][n].get(params[0], f'getblockbyid: rpc error -32000: no block {params[0]} is known')
            if ans is True:
                return {'block_id': params[0]}
            raise m.RpcError(ans)
        raise AssertionError(f'unexpected method {method}')
    return call


def fetch_for(rd):
    def fetch(u):
        text = rd['metrics'].get(name_of(u))
        return text.encode() if text else None
    return fetch


def config(nodes, sources=None, quorum=None, thresholds=None, metrics=True, refs=None, **extra):
    cfg = {'network': PRIVATE_NET, 'thresholds': {**REPLAY, **(thresholds or {})},
           'nodes': [{'name': n, 'rpc': url(n), 'metrics': f'{url(n)}/metrics' if metrics else ''} for n in nodes],
           **extra}
    if refs:
        cfg['references'] = refs
    if sources:
        cfg['settler'] = {'rpc_urls': [url(n) for n in sources]}
        if quorum:
            cfg['settler']['rpc_quorum'] = quorum
    return cfg


def replay(case, cfg):
    """Returns [(tag, {check: (level, message)})] for every recorded round."""
    fx, prepared, state, out = fixture(case), m.prepare(cfg), {}, []
    for rd in fx['rounds']:
        r = m.run_once(prepared, transport_for(rd), fetch_for(rd), state, now=rd['now'])
        out.append((rd['tag'], {c['check']: (c['level'], c['message']) for c in r.checks}))
    return out


def levels(rounds, check):
    return [checks.get(check, ('-', ''))[0] for _, checks in rounds]


class RecordedStuckNodes(unittest.TestCase):
    """Nodes 9-13 stuck on their own branch (verdict SPLIT), nodes 0-8 following."""

    def test_p1noq_stuck_node_goes_crit_and_followers_stay_ok(self):
        rounds = replay('p1noq', config(['n0', 'n2', 'n9', 'n10']))
        self.assertEqual(levels(rounds, 'l1_stuck[n9]'), ['OK', 'OK', 'CRIT', 'CRIT'])
        self.assertEqual(levels(rounds, 'l1_stuck[n10]'), ['OK', 'OK', 'CRIT', 'CRIT'])
        self.assertIn('STUCK on its own branch', rounds[-1][1]['l1_stuck[n9]'][1])
        for n in ('n0', 'n2'):
            self.assertEqual(set(levels(rounds, f'l1_stuck[{n}]')), {'OK'}, n)
        self.assertEqual(levels(rounds, 'l1_split'), ['OK', 'WARN', 'WARN', 'WARN'])
        self.assertIn('n10', rounds[1][1]['l1_split'][1])

    def test_th2_stuck_after_restart_under_a_cut(self):
        rounds = replay('th2', config(['n0', 'n2', 'n9']))
        self.assertEqual(levels(rounds, 'l1_stuck[n9]')[-1], 'CRIT')
        self.assertNotIn('CRIT', levels(rounds, 'l1_stuck[n0]') + levels(rounds, 'l1_stuck[n2]'))
        # back and e24: n9 is behind on the same branch (recorded: online has its head), so no split yet
        self.assertEqual(levels(rounds, 'l1_split'), ['OK', 'OK', 'OK', 'WARN'])

    def test_parked_is_read_from_the_recorded_metrics(self):
        rounds = replay('p1noq', config(['n0', 'n9']))
        self.assertIn('parked 32', rounds[-1][1]['l1_stuck[n9]'][1])
        self.assertIn('peers 28', rounds[-1][1]['l1_stuck[n9]'][1])


class RecordedSettlerSources(unittest.TestCase):
    """Report 94: the settler settled L2 blocks on a dead fork because its quorum of L1 sources was there."""

    def test_quorum_on_the_stuck_side_is_crit_from_the_second_run(self):
        rounds = replay('p1noq', config(['n0', 'n2'], sources=['n0', 'n9', 'n10']))
        self.assertEqual(levels(rounds, 'l1_settler_sources'), ['WARN', 'CRIT', 'CRIT', 'CRIT'])
        msg = rounds[1][1]['l1_settler_sources'][1]
        self.assertIn('dead fork', msg)
        self.assertIn("apart ['n9:8080', 'n10:8080']", msg)  # sources not among `nodes` are added, named host:port

    def test_three_way_split_with_two_sources_left_behind(self):
        # k2: groups isolated e14-e40; afterwards 2-4 finalize, 0 stays at e12 and 1 at e13. n1 is a derived view
        # (only its finalized epoch and head prefix were recorded; see make_fixtures.py).
        rounds = replay('k2', config(['n2', 'n3'], sources=['n0', 'n1', 'n2']))
        # back: n0 and n1 apart (first run: WARN). e43: n2 still answers n0's head (recorded; the probe kept no
        # `finality` field), so only n1 is apart: a warning. e46: both apart again, first run. e69: CRIT.
        self.assertEqual(levels(rounds, 'l1_settler_sources'), ['WARN', 'WARN', 'WARN', 'CRIT'])
        self.assertIn("apart ['n1:8080']", rounds[1][1]['l1_settler_sources'][1])
        self.assertIn("apart ['n0:8080', 'n1:8080']", rounds[3][1]['l1_settler_sources'][1])
        self.assertEqual(levels(rounds, 'l1_finality'), ['CRIT', 'CRIT', 'OK', 'OK'])

    def test_one_source_apart_is_a_warning_not_a_page(self):
        rounds = replay('k2', config(['n3'], sources=['n0', 'n2', 'n4']))
        self.assertEqual(levels(rounds, 'l1_settler_sources'), ['OK', 'OK', 'OK', 'WARN'])
        self.assertIn('1 more apart', rounds[3][1]['l1_settler_sources'][1])

    def test_sources_on_the_finalizing_side_are_ok(self):
        rounds = replay('p1noq', config(['n9', 'n10'], sources=['n0', 'n1', 'n2']))
        self.assertEqual(set(levels(rounds, 'l1_settler_sources')), {'OK'})


class RecordedFinalityStall(unittest.TestCase):
    """ju: five nodes each on its own head after a long isolation, finality stalled at e12 everywhere."""

    def test_finality_stall_is_crit_and_no_node_is_called_stuck(self):
        rounds = replay('ju', config(['n0', 'n1', 'n2', 'n3', 'n4'], sources=['n0', 'n2', 'n4']))
        self.assertEqual(set(levels(rounds, 'l1_finality')), {'CRIT'})
        self.assertIn('FINALITY STALLED', rounds[0][1]['l1_finality'][1])
        for n in ('n0', 'n1', 'n2', 'n3', 'n4'):
            self.assertNotIn('CRIT', levels(rounds, f'l1_stuck[{n}]'), n)  # the reference never gains an epoch

    def test_a_tie_in_finality_is_reported_undecided_not_guessed(self):
        rounds = replay('ju', config(['n0', 'n2'], sources=['n0', 'n2', 'n4']))
        self.assertEqual(levels(rounds, 'l1_split'), ['OK', 'WARN', 'WARN', 'WARN'])
        self.assertIn('no side ahead in finality', rounds[1][1]['l1_split'][1])
        self.assertEqual(levels(rounds, 'l1_settler_sources'), ['OK', 'WARN', 'WARN', 'WARN'])
        self.assertIn('not yet decided', rounds[1][1]['l1_settler_sources'][1])


class RecordedRecoveries(unittest.TestCase):
    """w1fix (wipe and resync) and h2fix (restart and catch up), both REJOINED: nothing pages."""

    def test_rejoin_raises_nothing(self):
        for case in ('w1fix', 'h2fix'):
            rounds = replay(case, config(['n0', 'n2', 'n9', 'n10'], sources=['n0', 'n9', 'n10']))
            for tag, checks in rounds:
                for check, (level, message) in checks.items():
                    if check.startswith('l1_metrics'):
                        continue  # the first probe of each run has no metrics recorded
                    self.assertEqual(level, 'OK', f'{case} {tag} {check}: {message}')

    def test_zero_peers_right_after_a_wipe_is_not_graded(self):
        rounds = replay('w1fix', config(['n0', 'n9']))
        tags = [t for t, _ in rounds]
        e26 = rounds[tags.index('e26')][1]['l1_peers[n9]']
        self.assertEqual(e26[0], 'OK')
        self.assertIn('bloch_pos_peer_count 0: the node is isolated (seen 1 run(s)', e26[1])


class Synthetic(unittest.TestCase):
    """Cases with no recording. The views are recorded ones with one field changed, as each test says."""

    def rd(self, case='p1noq', tag='e37'):
        return json.loads(json.dumps(next(r for r in fixture(case)['rounds'] if r['tag'] == tag)))

    def test_stored_but_not_canonical_head_counts_as_apart(self):
        # Synthetic: the node has stored the other branch's head but does not follow it (finality: not_canonical).
        rd = self.rd()
        on, off = rd['getchaininfo']['n0']['block_id'], rd['getchaininfo']['n9']['block_id']
        cfg = m.prepare(config(['n0', 'n9']))

        def call(u, method, params):
            if method == 'getchaininfo':
                return rd['getchaininfo'][name_of(u)]
            return {'block_id': params[0], 'finality': 'not_canonical'} if params[0] in (on, off) else None
        state = {}
        for _ in range(2):
            r = m.run_once(cfg, call, fetch_for(rd), state, now=rd['now'])
        self.assertEqual(r.facts['l1_branch']['side'], {'n0': 'with', 'n9': 'apart'})

    def test_canonical_answer_counts_as_on_the_branch(self):
        rd = self.rd()
        cfg = m.prepare(config(['n0', 'n9']))

        def call(u, method, params):
            if method == 'getchaininfo':
                return rd['getchaininfo'][name_of(u)]
            return {'block_id': params[0], 'finality': 'canonical'}
        r = m.run_once(cfg, call, fetch_for(rd), {}, now=rd['now'])
        self.assertEqual(r.facts['l1_branch']['side'], {'n0': 'with', 'n9': 'with'})

    def peers_run(self, counts, thresholds=None):
        # Synthetic: the recorded metrics of n0 with bloch_pos_peer_count replaced.
        rd = self.rd('w1fix', 'e29')
        cfg = m.prepare(config(['n0', 'n2'], thresholds=thresholds))
        state, out = {}, []
        for count in counts:
            text = rd['metrics']['n0'].replace('bloch_pos_peer_count 28', f'bloch_pos_peer_count {count}')
            r = m.run_once(cfg, transport_for(rd), lambda u, t=text: t.encode() if 'n0' in u else None, state,
                           now=rd['now'])
            out.append(next((c['level'], c['message']) for c in r.checks if c['check'] == 'l1_peers[n0]'))
        return out

    def test_peer_collapse_against_the_recent_maximum(self):
        out = self.peers_run([28, 28, 10, 10, 10])
        self.assertEqual([lv for lv, _ in out], ['OK', 'OK', 'OK', 'WARN', 'WARN'])
        self.assertIn('fell to 10 from 28', out[3][1])

    def test_isolated_node_is_crit_once_held(self):
        out = self.peers_run([28, 0, 0, 2, 2, 5])
        self.assertEqual([lv for lv, _ in out], ['OK', 'OK', 'CRIT', 'WARN', 'WARN', 'WARN'])

    def test_small_baselines_do_not_count_as_collapse(self):
        out = self.peers_run([3, 3, 3], thresholds={'peers_warn': 0, 'peers_crit': -1})
        self.assertEqual([lv for lv, _ in out], ['OK', 'OK', 'OK'])

    def test_parked_held_on_a_node_that_follows(self):
        # Synthetic: the healthy n0 of p1noq with parked 32 in every round (recorded: 2, 30, 32).
        fx = fixture('p1noq')
        cfg, state, seen = m.prepare(config(['n0', 'n2', 'n9'], refs=['n2'])), {}, []
        for rd in fx['rounds']:
            text = 'bloch_pos_peer_count 28\nbloch_pos_blocks_parked 32'
            r = m.run_once(cfg, transport_for(rd), lambda u, t=text: t.encode(), state, now=rd['now'])
            checks = {c['check']: c['level'] for c in r.checks}
            seen.append((checks.get('l1_parked[n0]'), checks['l1_stuck[n0]'], checks.get('l1_parked[n9]')))
        self.assertEqual([s[0] for s in seen], ['OK', 'OK', 'WARN', 'WARN'])
        self.assertEqual({s[1] for s in seen}, {'OK'})
        self.assertEqual(seen[-1][2], 'OK')  # n9 is CRIT in l1_stuck; l1_parked does not repeat it

    def test_peers_from_getchaininfo_without_metrics(self):
        # Synthetic: the release's getchaininfo carries transport.peers (rpc.rs chain_info_json); the recorded
        # probes kept no such field. No metrics URL is configured here.
        rd = self.rd('w1fix', 'e29')
        cfg = m.prepare(config(['n0', 'n2'], metrics=False))
        state, out = {}, []
        for devnet in (28, 0, 0):
            view = dict(rd['getchaininfo']['n0'], transport={'name': 'devnet', 'peers': {'devnet': devnet, 'libp2p': None}},
                        wall_slot=rd['getchaininfo']['n0']['slot'])
            r = m.run_once(cfg, lambda u, meth, prm, v=view: v if meth == 'getchaininfo' and 'n0' in u else
                           transport_for(rd)(u, meth, prm), lambda u: None, state, now=rd['now'])
            out.append(next((c['level'], c['message']) for c in r.checks if c['check'] == 'l1_peers[n0]'))
        self.assertEqual([lv for lv, _ in out], ['OK', 'OK', 'CRIT'])
        self.assertIn('getchaininfo transport.peers 0', out[2][1])
        self.assertFalse(any(c['check'].startswith('l1_metrics') for c in r.checks))

    def test_wall_slot_counts_for_the_current_epoch(self):
        # Synthetic: a node whose state slot stopped but whose wall_slot moved on 10 epochs.
        rd = self.rd()
        cfg = m.prepare(config(['n0']))
        view = dict(rd['getchaininfo']['n0'], wall_slot=rd['getchaininfo']['n0']['slot'] + 10 * 32)
        r = m.run_once(cfg, lambda u, meth, prm: view, lambda u: None, {}, now=0)
        self.assertEqual(next(c['level'] for c in r.checks if c['check'] == 'l1_finality'), 'CRIT')

    def test_down_node_and_unreadable_metrics(self):
        rd = self.rd()
        del rd['getchaininfo']['n9']
        cfg = m.prepare(config(['n0', 'n9']))
        r = m.run_once(cfg, transport_for(rd), lambda u: None, {}, now=rd['now'])
        checks = {c['check']: (c['level'], c['message']) for c in r.checks}
        self.assertEqual(checks['l1_nodes'][0], 'WARN')
        self.assertEqual(checks['l1_metrics[n0]'][0], 'WARN')
        self.assertIn('does not answer', checks['l1_stuck[n9]'][1])

    def test_no_node_answers(self):
        cfg = m.prepare(config(['n0', 'n9']))

        def call(u, method, params):
            raise m.RpcError('connection refused')
        r = m.run_once(cfg, call, lambda u: None, {}, now=100)
        self.assertEqual(r.status, m.CRIT)
        self.assertEqual(r.checks[0]['check'], 'l1_nodes')

    def test_wall_clock_finality_when_every_node_freezes(self):
        # Synthetic: the last p1noq round read 20 epochs later with nothing changed (a whole-chain halt).
        rd = self.rd()
        cfg = m.prepare(config(['n0', 'n2']))
        r = m.run_once(cfg, transport_for(rd), fetch_for(rd), {}, now=rd['now'] + 20 * 32)
        self.assertEqual(next(c['level'] for c in r.checks if c['check'] == 'l1_finality'), 'CRIT')


class StoredSideBlocks(unittest.TestCase):
    """Finding for l1_stuck_check.py and l2_monitor --l1-stuck-node (agent 70): `has_ref_head` is bool(getblockbyid),
    so a stuck node that has stored the reference head as a block it does not follow (`finality: not_canonical`,
    engine.rs block_reply) counts as having it, the `missing` clock stops, and the node never reaches CRIT.
    Synthetic: no recording kept the `finality` field."""

    def test_l1_stuck_check_counts_a_stored_side_block_as_known(self):
        rd = next(r for r in fixture('p1noq')['rounds'] if r['tag'] == 'e37')

        def rpc(u, method, params, timeout):
            if method == 'getchaininfo':
                return rd['getchaininfo'][name_of(u)]
            return {'block_id': params[0], 'finality': 'not_canonical'}
        original = l1_stuck_check.rpc
        l1_stuck_check.rpc = rpc
        try:
            s = l1_stuck_check.sample({'name': 'n9', 'rpc': url('n9'), 'metrics': None}, [url('n0')], 1.0)
        finally:
            l1_stuck_check.rpc = original
        self.assertIs(s['has_ref_head'], True)  # agent 70's script: "reference head known"

    def test_l1_monitor_does_not(self):
        rd = next(r for r in fixture('p1noq')['rounds'] if r['tag'] == 'e37')
        cfg, state = m.prepare(config(['n0', 'n9'])), {}

        def call(u, method, params):
            if method == 'getchaininfo':
                return rd['getchaininfo'][name_of(u)]
            return {'block_id': params[0], 'finality': 'not_canonical'}
        r = m.run_once(cfg, call, fetch_for(rd), state, now=rd['now'])
        self.assertIn('reference head NOT known', next(c['message'] for c in r.checks if c['check'] == 'l1_stuck[n9]'))


class Config(unittest.TestCase):
    def test_settler_config_file_is_read_for_rpc_urls_and_quorum(self):
        with tempfile.TemporaryDirectory() as d:
            settler = Path(d) / 'config.json'
            settler.write_text(json.dumps({'rpc_urls': [url('n0'), url('n9') + '/', 'http://other:8080'],
                                           'rpc_quorum': 2, 'da': {'keystore_dir': '/never/read'}}))
            cfg = m.prepare({'nodes': [{'name': 'a', 'rpc': url('n0')}, {'name': 'b', 'rpc': url('n9')}],
                             'settler': {'config_file': str(settler)}})
        self.assertEqual(cfg['settler_names'], ['a', 'b', 'other:8080'])
        self.assertEqual(cfg['settler_quorum'], 2)
        self.assertEqual([n['rpc'] for n in cfg['nodes']][-1], 'http://other:8080')
        self.assertEqual(cfg['net'], m.MAINNET_NETWORK)

    def test_default_quorum_is_a_strict_majority(self):
        cfg = m.prepare({'settler': {'rpc_urls': [url('a'), url('b'), url('c')]}})
        self.assertEqual(cfg['settler_quorum'], 2)

    def test_bad_configs_are_refused(self):
        for bad in ({}, {'nodes': [{'rpc': 'n0'}]}, {'nodes': [{'name': 'a', 'rpc': url('a')}] * 2},
                    {'nodes': [{'name': 'a', 'rpc': url('a')}], 'thresholds': {'nope': 1}},
                    {'nodes': [{'name': 'a', 'rpc': url('a')}], 'references': ['b']},
                    {'settler': {'rpc_urls': [url('a')], 'rpc_quorum': 2}}):
            with self.assertRaises(SystemExit, msg=json.dumps(bad)):
                m.prepare(bad)

    def test_tbd_metrics_count_as_not_configured(self):
        cfg = m.prepare({'nodes': [{'name': 'a', 'rpc': url('a'), 'metrics': 'TBD-owner'}]})
        self.assertIsNone(cfg['nodes'][0]['metrics'])

    def test_example_config_parses(self):
        doc = json.loads((HERE / 'monitor' / 'l1-monitor.json.example').read_text())
        doc.pop('settler')  # it names the settler's config.json, which exists only on the settler host
        cfg = m.prepare(doc)
        self.assertEqual(cfg['net'], m.MAINNET_NETWORK)
        self.assertGreaterEqual(len(cfg['nodes']), 3)


class ReadOnly(unittest.TestCase):
    def test_only_read_methods_are_sent(self):
        call = m.http_transport(1.0)
        for method in ('sendrawtransaction', 'submitblock', 'getl2settlement'):
            with self.assertRaises(PermissionError):
                call('http://127.0.0.1:9', method, [])

    def test_a_round_calls_only_getchaininfo_and_getblockbyid(self):
        rd = next(r for r in fixture('k2')['rounds'] if r['tag'] == 'e69')
        calls = []
        cfg = m.prepare(config(['n0', 'n1', 'n2', 'n3'], sources=['n0', 'n1', 'n2']))
        m.run_once(cfg, transport_for(rd, calls), fetch_for(rd), {}, now=rd['now'])
        self.assertEqual({c[1] for c in calls}, {'getchaininfo', 'getblockbyid'})
        self.assertLessEqual(len(calls), 4 + 2 * 4 * 3)


class SharedCode(unittest.TestCase):
    def same(self, name, other):
        self.assertEqual(inspect.getsource(getattr(m, name)), inspect.getsource(getattr(other, name)), name)

    def test_stuck_decision_is_agent_70s(self):
        for name in ('stuck_metric', 'stuck_step'):
            self.same(name, l1_stuck_check)
            self.same(name, l2_monitor)
        self.assertEqual({k: m.DEFAULTS[k] for k in l1_stuck_check.DEFAULTS}, l1_stuck_check.DEFAULTS)

    def test_alert_delivery_is_l2_monitors(self):
        for name in ('configured', 'decide_alert', 'send_alert', 'write_alert_state', 'heartbeat'):
            self.same(name, l2_monitor)


class Alerts(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def report(self, level=m.CRIT, check='l1_settler_sources'):
        r = m.Report()
        r.facts['checked_at'] = 1000
        r.add('l1_nodes', m.OK, '3/3 L1 nodes answer')
        r.add(check, level, 'a quorum of the settler\'s L1 sources is on a branch apart')
        return r

    def alert_config(self, **extra):
        path = self.root / 'alert.json'
        path.write_text(json.dumps({'webhook_url': 'TBD-owner', 'telegram': {'bot_token_file': 'TBD-owner'},
                                    'min_level': 'WARN', 'realert_seconds': 3600, 'recover_runs': 2,
                                    'state_file': str(self.root / 'alert.state'), **extra}))
        return str(path)

    def test_alert_command_gets_event_status_and_the_json_on_stdin(self):
        out = self.root / 'called.jsonl'
        script = ('import json,sys; doc=json.load(sys.stdin); '
                  f'open({str(out)!r},"a").write(json.dumps({{"argv":sys.argv[1:],"doc":doc}})+"\\n")')
        cfg = self.alert_config(alert_command=[sys.executable, '-c', script, '{event}', '{status}'])
        self.assertEqual(m.handle_alerts(cfg, self.report(), 1000, False, 5.0), 'raise')
        self.assertIsNone(m.handle_alerts(cfg, self.report(), 1060, False, 5.0))  # deduplicated
        calls = [json.loads(line) for line in out.read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['argv'], ['raise', 'CRIT'])
        self.assertEqual(calls[0]['doc']['source'], 'l1_monitor')
        self.assertTrue(calls[0]['doc']['text'].startswith('BLOCH L1: CRIT'))
        self.assertEqual([c['check'] for c in calls[0]['doc']['checks']], ['l1_settler_sources'])
        ok = m.Report()
        ok.facts['checked_at'] = 1120
        ok.add('l1_nodes', m.OK, 'fine')
        self.assertIsNone(m.handle_alerts(cfg, ok, 1120, False, 5.0))  # held for recover_runs
        self.assertEqual(m.handle_alerts(cfg, ok, 1180, False, 5.0), 'recover')
        self.assertEqual([json.loads(x)['argv'][0] for x in out.read_text().splitlines()], ['raise', 'recover'])

    def test_worse_level_raises_again(self):
        cfg = self.alert_config()
        sent = []

        def sender(c, text, payload, timeout, dry):
            sent.append(payload['status'])
            return ['stub']
        m.handle_alerts(cfg, self.report(m.WARN), 1000, False, 5.0, sender=sender)
        m.handle_alerts(cfg, self.report(m.WARN), 1060, False, 5.0, sender=sender)
        m.handle_alerts(cfg, self.report(m.CRIT), 1120, False, 5.0, sender=sender)
        self.assertEqual(sent, ['WARN', 'CRIT'])

    def test_no_target_configured_is_reported(self):
        r = self.report()
        m.handle_alerts(self.alert_config(), r, 1000, False, 5.0)
        self.assertEqual(r.checks[-1]['check'], 'alert_delivery')
        self.assertIn('TBD-owner', r.checks[-1]['message'])

    def test_dry_run_sends_nothing_and_keeps_no_state(self):
        cfg = self.alert_config(alert_command=['/bin/false', '{event}'])
        r = self.report()
        self.assertEqual(m.handle_alerts(cfg, r, 1000, True, 5.0), 'raise')
        self.assertEqual(r.facts['alert']['sent'], ['command (dry run) /bin/false'])
        self.assertFalse((self.root / 'alert.state').exists())

    def test_failing_alert_command_is_reported_not_raised(self):
        r = self.report()
        m.handle_alerts(self.alert_config(alert_command=['/bin/false']), r, 1000, False, 5.0)
        self.assertEqual(r.checks[-1]['check'], 'alert_delivery')


class EndToEnd(unittest.TestCase):
    """main() with a config file, a state file kept between runs, and the report fed to l2_monitor --report."""

    def test_runs_keep_state_and_l2_monitor_reads_the_report(self):
        fx = fixture('p1noq')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = config(['n0', 'n2'], sources=['n0', 'n9', 'n10'], state_file=str(root / 'state.json'),
                         report_file=str(root / 'report.json'))
            (root / 'l1.json').write_text(json.dumps(cfg))
            codes = []
            for rd in fx['rounds'][:2]:
                with redirect_stdout(io.StringIO()) as out:
                    codes.append(m.main(['--config', str(root / 'l1.json'), '--json'], transport_for(rd),
                                        fetch_for(rd), clock=lambda rd=rd: rd['now']))
            self.assertEqual(codes, [m.WARN, m.CRIT])
            doc = json.loads(out.getvalue())
            self.assertEqual(doc['status'], 'CRIT')
            self.assertTrue((root / 'state.json').exists())
            r = l2_monitor.Report()
            l2_monitor.check_reports([f'l1={root / "report.json"}:180'], l2_monitor.PROFILES['mainnet'],
                                     os.stat(root / 'report.json').st_mtime + 5, r)
            got = {c['check']: c['level'] for c in r.checks}
            self.assertEqual(got['l1/l1_settler_sources'], 'CRIT')
            self.assertEqual(got['report_age[l1]'], 'OK')

    def test_an_overlapping_run_does_not_touch_the_state(self):
        import fcntl
        rd = fixture('p1noq')['rounds'][-1]
        with tempfile.TemporaryDirectory() as d:
            path, state = Path(d) / 'l1.json', Path(d) / 'state.json'
            path.write_text(json.dumps(config(['n0'], state_file=str(state))))
            with open(f'{state}.lock', 'a') as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                    code = m.main(['--config', str(path)], transport_for(rd), fetch_for(rd), clock=lambda: rd['now'])
            self.assertEqual(code, m.UNKNOWN)
            self.assertIn('not run', err.getvalue())
            self.assertFalse(state.exists())

    def test_one_shot_without_state_says_so(self):
        rd = fixture('p1noq')['rounds'][-1]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'l1.json'
            path.write_text(json.dumps(config(['n0', 'n9'])))
            err = io.StringIO()
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(err):
                code = m.main(['--config', str(path)], transport_for(rd), fetch_for(rd), clock=lambda: rd['now'])
        self.assertIn('no state_file', err.getvalue())
        self.assertIn('l1_stuck[n9]', out.getvalue())
        self.assertNotEqual(code, m.CRIT)

    def test_watch_with_duration_returns_the_worst(self):
        rd = fixture('p1noq')['rounds'][-1]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'l1.json'
            path.write_text(json.dumps(config(['n0', 'n2'], sources=['n0', 'n9', 'n10'])))
            with redirect_stdout(io.StringIO()) as out:
                code = m.main(['--config', str(path), '--watch', '0.01', '--duration', '0.03'], transport_for(rd),
                              fetch_for(rd), clock=lambda: rd['now'])
        self.assertEqual(code, m.CRIT)
        self.assertGreaterEqual(out.getvalue().count('BLOCH L1:'), 2)


if __name__ == '__main__':
    unittest.main()
