#!/usr/bin/env python3
"""Read-only L1 (bloch-pos) monitor for operators: nodes stuck on their own branch, finality stalled, parked blocks,
peer-count collapse, and the L2 settler's L1 sources all on one side of a split.

Runbooks: docs/L1-MONITOR.md (this script), docs/L1-STUCK-NODE-RUNBOOK.md (what to do about a stuck node).

It runs without a systemd unit: once per call (cron, a timer, or by hand) with a state file, or in a loop with
--watch. It reads one JSON config (see monitor/l1-monitor.json.example), calls only `getchaininfo` and
`getblockbyid` on the configured nodes and a GET of their metrics URL, holds no key and opens no node file. It may
read the settler's config.json, only for `rpc_urls` and `rpc_quorum`. It writes its state file, an optional report
file and the alert state; alerts use the same alert.json (webhook_url, alert_command, telegram, heartbeat_url,
min_level, realert_seconds, recover_runs, state_file) and the same delivery code as l2_monitor.py.

Checks:
  l1_nodes                 how many configured nodes answer
  l1_finality              epochs between now (wall clock and the nodes' slots) and the best finalized epoch
  l1_stuck[NAME]           agent 70's rule (l1_stuck_check.py): parked >= 32, finalized frozen below the reference
                           and the reference head unknown, held while the reference gains 3 finalized epochs
  l1_parked[NAME]          bloch_pos_blocks_parked held at >= 32 over the same window, on a node not already CRIT
  l1_peers[NAME]           bloch_pos_peer_count at or below a floor, or collapsed against its recent maximum
  l1_metrics[NAME]         a configured metrics URL that does not answer (stuck detection then stops at WARN)
  l1_split                 nodes on a branch apart from the one finalizing furthest
  l1_settler_sources       the settler's rpc_urls against that branch: a quorum of them apart is CRIT (report 94:
                           the settler settled L2 blocks on a dead fork because its quorum was on it)

Branches are compared with `getblockbyid`: two nodes are on one branch when either knows the other's head. The
branch that counts is the one with the highest (finalized, justified) epoch; a split whose sides tie on both is
reported as undecided, never guessed by counting nodes.

  l1_monitor.py --config /etc/bloch-l1-monitor/l1-monitor.json [--watch 60] [--json] [--alert-dry-run]

Exit status (Nagios): 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN. Dependency-free Python 3.9+. Run with `python3 -I`.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
import types
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3
LEVEL_NAMES = {OK: 'OK', WARN: 'WARN', CRIT: 'CRIT', UNKNOWN: 'UNKNOWN'}
LEVEL_CODES = {v: k for k, v in LEVEL_NAMES.items()}
SEVERITY = {OK: 0, WARN: 1, UNKNOWN: 2, CRIT: 3}
READ_ONLY_METHODS = frozenset({'getchaininfo', 'getblockbyid'})

# Genesis-4 mainnet (l2_monitor.py, sequencer_mainnet.py). A private net overrides these in the config's `network`.
MAINNET_NETWORK = {'genesis_time': 1786656679, 'slot_seconds': 30, 'slots_per_epoch': 32}
DEFAULTS: Dict[str, Any] = {
    # agent 70 (l1_stuck_check.py / l2_monitor.py): epochs are finalized epochs gained by the reference.
    'stuck_sustain_epochs': 3, 'stuck_parked_min': 32, 'stuck_min_samples': 3, 'stuck_max_gap_epochs': 2,
    # 2 epochs is normal; l2_monitor's l1_finality_lag uses the same figures.
    'finality_lag_warn': 4, 'finality_lag_crit': 8,
    # Production peer counts are not known to the author (TBD-owner): these floors only catch an isolated node.
    'peers_warn': 2, 'peers_crit': 0,
    'peer_collapse_ratio': 0.5, 'peer_collapse_min_baseline': 4, 'peer_window_runs': 30, 'peers_min_runs': 2,
    # Consecutive runs a split must be seen before it is graded (a head read mid-propagation is not a split).
    'split_min_runs': 2,
}
SETTLER_CONFIG = '/etc/bloch-l2-mainnet-settler/config.json'
Transport = Callable[[str, str, list], Any]
Fetcher = Callable[[str], Optional[bytes]]


class RpcError(Exception):
    pass


def http_transport(timeout: float) -> Transport:
    def call(url: str, method: str, params: list) -> Any:
        if method not in READ_ONLY_METHODS:
            raise PermissionError(f'{method} is not a read-only method')
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                reply = json.loads(resp.read(4 * 1024 * 1024))
        except Exception as e:  # noqa: BLE001 - network, HTTP or JSON error
            raise RpcError(f'{method} at {url}: {e}') from None
        if not isinstance(reply, dict):
            raise RpcError(f'{method} at {url}: malformed reply')
        if reply.get('error') is not None:
            raise RpcError(str(reply['error']))
        return reply.get('result')
    return call


def http_fetcher(timeout: float) -> Fetcher:
    def fetch(url: str) -> Optional[bytes]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return resp.read(1024 * 1024)
        except Exception:  # noqa: BLE001 - metrics are optional evidence
            return None
    return fetch


class Report:
    def __init__(self):
        self.checks: List[Dict[str, Any]] = []
        self.facts: Dict[str, Any] = {}

    def add(self, name: str, level: int, message: str, **values: Any) -> None:
        self.checks.append({'check': name, 'level': LEVEL_NAMES[level], 'code': level, 'message': message, **values})

    @property
    def status(self) -> int:
        codes = [c['code'] for c in self.checks]
        return max(codes, key=lambda c: SEVERITY[c]) if codes else UNKNOWN

    def doc(self) -> Dict[str, Any]:
        return {'status': LEVEL_NAMES[self.status], 'level': LEVEL_NAMES[self.status], 'facts': self.facts,
                'checks': self.checks}


# ---- Decision code. Identical to l1_stuck_check.py and l2_monitor.py; test_l1_monitor.py fails if they differ. ----
def stuck_metric(text: Optional[str], name: str) -> Optional[int]:
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == name:
            try:
                return int(float(parts[1]))
            except ValueError:
                return None
    return None


def stuck_step(st: Optional[Dict[str, Any]], s: Dict[str, Any], p: Dict[str, Any]) -> Tuple[Dict[str, Any], int, str]:
    """One sample of one node. Returns (new state, level, message). Pure: no I/O and no clock.

    s: ref_finalized (None: no reference answered), down, finalized, parked (None: unknown),
    has_ref_head (True, False, None: lookup failed), peers.
    """
    st = dict(st or {})
    rf = s.get('ref_finalized')
    if rf is None:
        return st, UNKNOWN, 'no reference answers: not evaluated'
    need, samples = p['stuck_sustain_epochs'], p['stuck_min_samples']
    last = st.get('last_ref')
    if last is not None and rf < last:
        rf = last  # another reference answered, and it is behind the best one seen
    st['last_ref'] = rf

    def stop(name: str) -> None:
        st.pop(name, None)

    def tick(name: str) -> None:
        clock = st.get(name) or {'base': rf, 'n': 0}
        st[name] = {'base': clock['base'], 'n': clock['n'] + 1}

    def held(name: str) -> bool:
        clock = st.get(name)
        return bool(clock) and clock['n'] >= samples and rf - clock['base'] >= need

    if last is not None and rf - last > p['stuck_max_gap_epochs']:  # the monitor was away: nothing steady was seen
        stop('parked')
        stop('missing')
    if s.get('down'):
        stop('parked')  # a restart empties the parked set
        stop('missing')
        tick('down')
        if held('down'):
            return st, UNKNOWN, f'node has not answered while the reference finalized {need}+ epochs'
        return st, OK, 'node does not answer (a restart?): not evaluated yet'
    stop('down')

    fin, parked, has_head = s['finalized'], s.get('parked'), s.get('has_ref_head')
    if st.get('frozen_at') != fin or fin >= rf:
        st['frozen_at'] = fin
        stop('frozen')
    tick('frozen')
    if parked is not None and parked >= p['stuck_parked_min']:
        tick('parked')
    else:
        stop('parked')
    if has_head is False:
        tick('missing')
    elif has_head is True:
        stop('missing')

    view = f'finalized e{fin}, reference e{rf}, parked {"unknown" if parked is None else parked}, ' \
           f'reference head {dict([(True, "known"), (False, "NOT known"), (None, "lookup failed")])[has_head]}, ' \
           f'peers {"unknown" if s.get("peers") is None else s["peers"]}'
    frozen, missing, steady = fin < rf and held('frozen'), held('missing'), held('parked')
    if frozen and missing and steady:
        return st, CRIT, f'STUCK on its own branch: {view}. A restart is not a reliable cure; see the runbook'
    if frozen and missing:
        why = 'parked unknown: read the metrics to confirm' if parked is None else \
            'parked below the stuck level: cut off from the reference, or not yet stuck'
        return st, WARN, f'not following the reference ({why}): {view}'
    if missing and rf - fin < need:  # further behind is an ordinary long sync
        return st, WARN, f'finalizing, but the reference head stays unknown (a branch of its own?): {view}'
    return st, OK, view



# ------------------------------------------------------------------------------------------------- config
def norm_url(url: str) -> str:
    return url.strip().rstrip('/')


def settler_sources(spec: Any) -> Tuple[List[str], int, str]:
    """The settler's L1 sources and quorum: from its config.json (`config_file`), or listed here. Same default quorum
    as settler_v3.py: a strict majority."""
    if not spec:
        return [], 0, ''
    if not isinstance(spec, dict):
        raise SystemExit('settler: an object with config_file, or rpc_urls and rpc_quorum')
    where = 'config'
    doc = spec
    if spec.get('config_file'):
        where = spec['config_file']
        try:
            doc = json.loads(Path(where).read_text())
        except (OSError, ValueError) as e:
            raise SystemExit(f'settler config_file {where}: {e}') from None
    urls = doc.get('rpc_urls')
    if not isinstance(urls, list) or not urls or not all(isinstance(u, str) and '://' in u for u in urls):
        raise SystemExit(f'settler rpc_urls missing or not URLs ({where})')
    quorum = doc.get('rpc_quorum', len(urls) // 2 + 1)
    if not isinstance(quorum, int) or quorum < 1 or quorum > len(urls):
        raise SystemExit(f'settler rpc_quorum must be 1..{len(urls)} ({where})')
    return [norm_url(u) for u in urls], quorum, where


def load_config(path: str) -> Dict[str, Any]:
    try:
        cfg = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise SystemExit(f'config {path}: {e}') from None
    return prepare(cfg)


def prepare(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Validates the config and returns it with `nodes` complete (settler sources added) and `p` (thresholds)."""
    if not isinstance(cfg, dict):
        raise SystemExit('config: a JSON object')
    nodes = []
    for i, n in enumerate(cfg.get('nodes') or []):
        if not isinstance(n, dict) or not isinstance(n.get('rpc'), str) or '://' not in n['rpc']:
            raise SystemExit(f'nodes[{i}]: needs rpc (an http(s) URL)')
        nodes.append({'name': str(n.get('name') or f'node{i}'), 'rpc': norm_url(n['rpc']),
                      'metrics': n['metrics'] if configured(n.get('metrics')) else None})
    urls, quorum, where = settler_sources(cfg.get('settler'))
    sources = []
    for i, url in enumerate(urls):
        known = [n for n in nodes if n['rpc'] == url]
        if not known:
            nodes.append({'name': urllib.parse.urlparse(url).netloc or f'settler{i}', 'rpc': url, 'metrics': None})
            known = nodes[-1:]
        sources.append(known[0]['name'])
    names = [n['name'] for n in nodes]
    if len(set(names)) != len(names):
        raise SystemExit('node names must be unique')
    if not nodes:
        raise SystemExit('config: no nodes and no settler sources')
    refs = cfg.get('references')
    if refs is not None and (not isinstance(refs, list) or any(r not in names for r in refs)):
        raise SystemExit('references: a list of node names')
    p = dict(DEFAULTS)
    for key, value in (cfg.get('thresholds') or {}).items():
        if key not in p:
            raise SystemExit(f'unknown threshold {key}')
        p[key] = type(p[key])(value)
    net = {**MAINNET_NETWORK, **(cfg.get('network') or {})}
    return {**cfg, 'nodes': nodes, 'references': refs, 'settler_names': sources, 'settler_quorum': quorum,
            'settler_where': where, 'p': p, 'net': net}


# -------------------------------------------------------------------------------------------------- probe
def rpc_peers(info: Dict[str, Any]) -> Optional[int]:
    """`getchaininfo.transport.peers` (78d4921c and later): peers per stack, null for a stack the node does not run.
    Lets the peer check work on a node without --metrics-port."""
    peers = (info.get('transport') or {}).get('peers') if isinstance(info.get('transport'), dict) else None
    if not isinstance(peers, dict):
        return None
    counts = [int(v) for v in peers.values() if isinstance(v, int) and not isinstance(v, bool)]
    return sum(counts) if counts else None


class Probe:
    """One round of reads. `knows(a, b)`: does node a have node b's head? Cached for the round."""

    def __init__(self, cfg: Dict[str, Any], transport: Transport, fetch: Fetcher):
        self.cfg, self.call, self.fetch = cfg, transport, fetch
        self.views: Dict[str, Dict[str, Any]] = {}
        self.errors: Dict[str, str] = {}
        self.text: Dict[str, Optional[str]] = {}
        self._knows: Dict[Tuple[str, str], Optional[bool]] = {}
        for n in cfg['nodes']:
            try:
                info = self.call(n['rpc'], 'getchaininfo', [])
                fin = info['finalized']
                just = info.get('justified')
                self.views[n['name']] = {
                    'finalized': int(fin['epoch'] if isinstance(fin, dict) else info['finalized_epoch']),
                    'justified': int(just['epoch']) if isinstance(just, dict) and just.get('epoch') is not None else -1,
                    'head': str(info['block_id']), 'height': info.get('height'),
                    'slot': int(info['slot']) if info.get('slot') is not None else None,
                    'wall_slot': int(info['wall_slot']) if info.get('wall_slot') is not None else None,
                    'epoch': int(info['epoch']) if info.get('epoch') is not None else None,
                    'peers': rpc_peers(info)}
            except (RpcError, KeyError, TypeError, ValueError) as e:
                self.errors[n['name']] = str(e)[:200]
                continue
            if n['metrics']:
                raw = self.fetch(n['metrics'])
                self.text[n['name']] = raw.decode(errors='replace') if raw else None

    def rpc_of(self, name: str) -> str:
        return next(n['rpc'] for n in self.cfg['nodes'] if n['name'] == name)

    def knows(self, a: str, b: str) -> Optional[bool]:
        """True when b's head is on a's canonical chain (a is at or ahead of b on one branch)."""
        va, vb = self.views.get(a), self.views.get(b)
        if not va or not vb:
            return None
        if va['head'] == vb['head']:
            return True
        key = (a, b)
        if key not in self._knows:
            try:
                block = self.call(self.rpc_of(a), 'getblockbyid', [vb['head']])
                # A node also stores blocks of a branch it does not follow; those answer `finality: not_canonical`.
                self._knows[key] = bool(block) and not (isinstance(block, dict) and block.get('finality') == 'not_canonical')
            except RpcError as e:
                self._knows[key] = False if 'no block' in str(e) else None
        return self._knows[key]

    def same_branch(self, a: str, b: str) -> Optional[bool]:
        ab = self.knows(a, b)
        if ab:
            return True
        ba = self.knows(b, a)
        if ba:
            return True
        return False if ab is False and ba is False else None


def branches(probe: Probe) -> Dict[str, Any]:
    """The branch finalizing furthest, by (finalized, justified) epoch, and where every answering node stands."""
    up = list(probe.views)
    if not up:
        return {'anchor': None, 'undecided': False, 'side': {}, 'rivals': []}
    key = {n: (probe.views[n]['finalized'], probe.views[n]['justified']) for n in up}
    top = max(key.values())
    cands, heads = [], set()
    for n in up:
        if key[n] == top and probe.views[n]['head'] not in heads:
            heads.add(probe.views[n]['head'])
            cands.append(n)
    members = {c: [x for x in up if probe.same_branch(x, c)] for c in cands}
    anchor = max(cands, key=lambda c: (len(members[c]), probe.views[c]['height'] or 0, c))
    rivals = [c for c in cands if c != anchor and probe.same_branch(c, anchor) is False]
    side = {}
    for x in up:
        same = probe.same_branch(x, anchor)
        side[x] = 'with' if same else ('apart' if same is False else 'unknown')
    return {'anchor': anchor, 'undecided': bool(rivals), 'side': side, 'rivals': rivals, 'members': members}


# ------------------------------------------------------------------------------------------------- checks
def current_epoch(views: Dict[str, Dict[str, Any]], net: Dict[str, Any], now: float) -> int:
    per_epoch = int(net['slot_seconds']) * int(net['slots_per_epoch'])
    best = int((now - float(net['genesis_time'])) // per_epoch) if now >= float(net['genesis_time']) else 0
    for v in views.values():
        if v.get('epoch') is not None:
            best = max(best, v['epoch'])
        for key in ('slot', 'wall_slot'):
            if v.get(key) is not None:
                best = max(best, v[key] // int(net['slots_per_epoch']))
    return best


def check_nodes(cfg: Dict[str, Any], probe: Probe, r: Report) -> None:
    n, up = len(cfg['nodes']), len(probe.views)
    if not up:
        r.add('l1_nodes', CRIT, f'none of {n} L1 nodes answers: ' + '; '.join(f'{k}: {v}' for k, v in probe.errors.items()))
    else:
        r.add('l1_nodes', OK if up == n else WARN, f'{up}/{n} L1 nodes answer', down=sorted(probe.errors))


def check_finality(cfg: Dict[str, Any], probe: Probe, now: float, r: Report) -> None:
    if not probe.views:
        return
    p = cfg['p']
    epoch = current_epoch(probe.views, cfg['net'], now)
    best = max(probe.views.values(), key=lambda v: (v['finalized'], v['justified']))
    lag = epoch - best['finalized']
    level = CRIT if lag >= p['finality_lag_crit'] else WARN if lag >= p['finality_lag_warn'] else OK
    r.facts.update({'l1_epoch': epoch, 'l1_finalized_epoch': best['finalized'], 'l1_justified_epoch': best['justified']})
    r.add('l1_finality', level, f'epoch {epoch}, best finalized e{best["finalized"]} (justified e{best["justified"]}): '
          f'{lag} epochs behind; 2 is normal' + ('. FINALITY STALLED on every node read' if level == CRIT else ''),
          value=lag, warn=p['finality_lag_warn'], crit=p['finality_lag_crit'])


def check_node(cfg: Dict[str, Any], probe: Probe, n: Dict[str, Any], st: Dict[str, Any], r: Report) -> None:
    """l1_stuck, l1_parked, l1_peers and l1_metrics of one node. `st` is this node's state, changed in place."""
    p, name = cfg['p'], n['name']
    refs = [x for x in (cfg['references'] or [m['name'] for m in cfg['nodes']]) if x != name and x in probe.views]
    ref = max(refs, key=lambda x: (probe.views[x]['finalized'], probe.views[x]['justified'])) if refs else None
    s: Dict[str, Any] = {'ref_finalized': probe.views[ref]['finalized'] if ref else None}
    if name not in probe.views:
        s['down'] = True
    else:
        text = probe.text.get(name)
        metric_peers = stuck_metric(text, 'bloch_pos_peer_count')
        s.update(finalized=probe.views[name]['finalized'], parked=stuck_metric(text, 'bloch_pos_blocks_parked'),
                 peers=metric_peers if metric_peers is not None else probe.views[name]['peers'],
                 has_ref_head=probe.knows(name, ref) if ref else None)
        if n['metrics'] and text is None:
            r.add(f'l1_metrics[{name}]', WARN, f'metrics URL does not answer: l1_stuck[{name}] can reach WARN at most')
    st['stuck'], level, message = stuck_step(st.get('stuck'), s, p)
    r.add(f'l1_stuck[{name}]', level, message + (f' (reference {ref})' if ref else ''))
    if s.get('down'):
        return
    clock = st['stuck'].get('parked')
    if (s.get('parked') is not None and level != CRIT and clock and clock['n'] >= p['stuck_min_samples']
            and st['stuck'].get('last_ref', 0) - clock['base'] >= p['stuck_sustain_epochs']):
        r.add(f'l1_parked[{name}]', WARN, f'bloch_pos_blocks_parked {s["parked"]} held for {clock["n"]} samples while '
              f'the reference finalized e{clock["base"]}..e{st["stuck"]["last_ref"]}')
    elif s.get('parked') is not None:
        r.add(f'l1_parked[{name}]', OK, f'bloch_pos_blocks_parked {s["parked"]}')
    peers = s.get('peers')
    if peers is None:
        return
    label = 'bloch_pos_peer_count' if metric_peers is not None else 'getchaininfo transport.peers'
    seen = [int(x) for x in st.get('peers') or []]
    base = max(seen) if seen else None
    st['peers'] = (seen + [peers])[-int(p['peer_window_runs']):]
    level, msg = OK, f'{label} {peers}'
    if peers <= p['peers_crit']:
        level, msg = CRIT, f'{label} {peers}: the node is isolated'
    elif peers <= p['peers_warn']:
        level, msg = WARN, f'{label} {peers} (floor {p["peers_warn"]})'
    elif base is not None and base >= p['peer_collapse_min_baseline'] and peers <= base * p['peer_collapse_ratio']:
        level, msg = WARN, f'{label} fell to {peers} from {base} in the last {len(seen)} runs'
    # A restarted node has no peers for a moment (recorded: 0 right after a wipe, 28 one sample later).
    runs = held_runs(st, 'peers_bad_runs', level != OK)
    if level != OK and runs < p['peers_min_runs']:
        level, msg = OK, msg + f' (seen {runs} run(s); graded from {p["peers_min_runs"]})'
    r.add(f'l1_peers[{name}]', level, msg)


def held_runs(state: Dict[str, Any], key: str, now_bad: bool) -> int:
    state[key] = int(state.get(key, 0)) + 1 if now_bad else 0
    return state[key]


def describe(probe: Probe, names: List[str]) -> str:
    out = []
    for x in names:
        v = probe.views.get(x)
        just = f'e{v["justified"]}' if v and v['justified'] >= 0 else '?'
        out.append(f'{x} (down)' if not v else f'{x} (fin e{v["finalized"]}, just {just}, head {v["head"][:10]})')
    return ', '.join(out) or 'none'


def check_split(cfg: Dict[str, Any], probe: Probe, b: Dict[str, Any], state: Dict[str, Any], r: Report) -> None:
    if not b['anchor']:
        return
    p = cfg['p']
    apart = sorted(x for x, s in b['side'].items() if s == 'apart')
    runs = held_runs(state, 'split_runs', bool(apart) or b['undecided'])
    r.facts['l1_branch'] = {'anchor': b['anchor'], 'head': probe.views[b['anchor']]['head'], 'side': b['side'],
                            'undecided': b['undecided']}
    if b['undecided']:
        msg = (f'split with no side ahead in finality: {describe(probe, [b["anchor"]] + b["rivals"])} tie on '
               f'(finalized, justified) on different branches')
    elif apart:
        msg = f'on a branch apart from the one finalizing furthest ({describe(probe, [b["anchor"]])}): {describe(probe, apart)}'
    else:
        unknown = sorted(x for x, s in b['side'].items() if s == 'unknown')
        r.add('l1_split', OK, f'{len(b["side"]) - len(unknown)} answering nodes on one branch'
              + (f'; branch unknown for {", ".join(unknown)}' if unknown else ''))
        return
    r.add('l1_split', WARN if runs >= p['split_min_runs'] else OK,
          msg + ('' if runs >= p['split_min_runs'] else f' (seen {runs} run(s); graded from {p["split_min_runs"]})'),
          apart=apart, runs=runs)


def check_settler(cfg: Dict[str, Any], probe: Probe, b: Dict[str, Any], state: Dict[str, Any], r: Report) -> None:
    names, q = cfg['settler_names'], cfg['settler_quorum']
    if not names:
        return
    p = cfg['p']
    side = {x: (b['side'].get(x) if x in probe.views else 'down') for x in names}
    on = [x for x in names if side[x] == 'with']
    apart = [x for x in names if side[x] == 'apart']
    other = [x for x in names if side[x] not in ('with', 'apart')]
    head = f'settler sources {len(names)}, quorum {q}: with the finalizing branch {on or "none"}, apart {apart or "none"}' \
           + (f', down or unknown {other}' if other else '')
    if b['undecided']:
        groups = {c: [x for x in names if x in b['members'].get(c, [])] for c in [b['anchor']] + b['rivals']}
        full = [c for c, g in groups.items() if len(g) >= q]
        held_runs(state, 'settler_apart_runs', False)
        held_runs(state, 'settler_some_apart_runs', False)
        level = WARN if held_runs(state, 'settler_undecided_runs', True) >= p['split_min_runs'] else OK
        if full:
            r.add('l1_settler_sources', level, f'L1 split not yet decided by finality, and the settler\'s quorum '
                  f'{groups[full[0]]} is on one side ({describe(probe, [full[0]])}); it settles there if that side loses. '
                  + head, sides=groups)
        else:
            r.add('l1_settler_sources', level, f'L1 split not yet decided by finality, settler sources spread: {groups}. '
                  + head, sides=groups)
        return
    held_runs(state, 'settler_undecided_runs', False)
    runs = held_runs(state, 'settler_apart_runs', len(apart) >= q)
    some = held_runs(state, 'settler_some_apart_runs', bool(apart))
    if len(apart) >= q:
        level = CRIT if runs >= p['split_min_runs'] else WARN
        r.add('l1_settler_sources', level, f'a quorum of the settler\'s L1 sources is on a branch apart from the one '
              f'finalizing furthest ({describe(probe, [b["anchor"]])}): {describe(probe, apart)}. The settler can accept '
              f'settlements on a dead fork (report 94); point rpc_urls at nodes on the finalizing branch. ' + head,
              apart=apart, runs=runs)
    elif len(on) < q:
        r.add('l1_settler_sources', WARN, f'the settler cannot reach its quorum on the finalizing branch '
              f'(it stalls with rpc-no-quorum). ' + head, apart=apart)
    elif apart:
        r.add('l1_settler_sources', WARN if some >= p['split_min_runs'] else OK,
              f'{describe(probe, apart)} apart from the finalizing branch; {q - len(apart)} more apart and the '
              f'settler follows the wrong branch (seen {some} run(s)). ' + head, apart=apart, runs=some)
    else:
        r.add('l1_settler_sources', OK, head + f' ({cfg["settler_where"]})')


def run_once(cfg: Dict[str, Any], transport: Transport, fetch: Fetcher, state: Dict[str, Any],
             now: Optional[float] = None) -> Report:
    """One round. `state` is changed in place; the caller keeps it."""
    now = time.time() if now is None else now
    r = Report()
    r.facts['checked_at'] = int(now)
    probe = Probe(cfg, transport, fetch)
    check_nodes(cfg, probe, r)
    check_finality(cfg, probe, now, r)
    nodes_state = state.setdefault('nodes', {})
    for n in cfg['nodes']:
        check_node(cfg, probe, n, nodes_state.setdefault(n['name'], {}), r)
    for gone in [k for k in nodes_state if k not in {n['name'] for n in cfg['nodes']}]:
        del nodes_state[gone]
    b = branches(probe)
    check_split(cfg, probe, b, state, r)
    check_settler(cfg, probe, b, state, r)
    return r


def load_state(path: Optional[str]) -> Dict[str, Any]:
    try:
        state = json.loads(Path(path).read_text()) if path else {}
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_json(path: Optional[str], doc: Dict[str, Any]) -> None:
    if path:
        tmp = f'{path}.tmp'
        Path(tmp).write_text(json.dumps(doc, default=str))
        os.replace(tmp, path)


# ---- Alert delivery. Identical to l2_monitor.py (agent 105); test_l1_monitor.py fails if they differ. ----
def configured(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and 'TBD' not in value


def decide_alert(r: Report, state: Dict[str, Any], now: float, realert: float, min_level: int,
                 recover_runs: int = 1) -> Optional[str]:
    """Returns 'raise', 'recover' or None. Alerts on a new or worse check, a recovery, or every `realert`
    seconds while something is still at or above min_level. A check that cleared stays in `bad` until it has been clean
    for `recover_runs` runs, so a flapping check is one alert, not one per run."""
    current = {c['check']: c['code'] for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]}
    previous = {k: LEVEL_CODES[v] for k, v in (state.get('bad') or {}).items()}
    clean = state.setdefault('clean', {})
    for k in list(previous):
        if k in current:
            clean.pop(k, None)
        else:
            clean[k] = int(clean.get(k, 0)) + 1
    for k in [k for k in clean if k not in previous]:
        del clean[k]
    held = {k: previous[k] for k in previous if k not in current and clean.get(k, 0) < recover_runs}
    state['held'] = held
    if current:
        worse = any(SEVERITY[c] > SEVERITY[previous.get(k, OK)] for k, c in current.items())
        if worse or now - float(state.get('sent_at', 0)) >= realert:
            return 'raise'
        return None
    if held:
        return None
    return 'recover' if previous else None


def send_alert(cfg: Dict[str, Any], text: str, payload: Dict[str, Any], timeout: float, dry_run: bool) -> List[str]:
    sent = []
    hook = cfg.get('webhook_url')
    if configured(hook):
        headers = {'content-type': 'application/json'}
        if configured(cfg.get('webhook_bearer_file')):
            headers['authorization'] = 'Bearer ' + Path(cfg['webhook_bearer_file']).read_text().strip()
        body = json.dumps({'text': text, **payload}, default=str).encode()
        if dry_run:
            sent.append(f'webhook (dry run) {hook}')
        else:
            urllib.request.urlopen(urllib.request.Request(hook, data=body, headers=headers), timeout=timeout).read()
            sent.append('webhook')
    command = cfg.get('alert_command')
    if isinstance(command, list) and command and all(configured(str(a)) for a in command):
        argv = [str(a).replace('{event}', str(payload.get('event'))).replace('{status}', str(payload.get('status')))
                .replace('{text}', text) for a in command]
        if dry_run:
            sent.append(f'command (dry run) {argv[0]}')
        else:
            done = subprocess.run(argv, input=json.dumps({'text': text, **payload}, default=str), capture_output=True,
                                  text=True, timeout=timeout)
            if done.returncode:
                raise RuntimeError(f'alert_command exit {done.returncode}: {done.stderr.strip()[-200:]}')
            sent.append('command')
    tg = cfg.get('telegram') or {}
    if configured(tg.get('bot_token_file')) and configured(str(tg.get('chat_id', ''))):
        if dry_run:
            sent.append(f'telegram (dry run) chat {tg["chat_id"]}')
        else:
            token = Path(tg['bot_token_file']).read_text().strip()
            body = json.dumps({'chat_id': tg['chat_id'], 'text': text, 'disable_web_page_preview': True}).encode()
            url = f'https://api.telegram.org/bot{token}/sendMessage'
            urllib.request.urlopen(urllib.request.Request(url, data=body, headers={'content-type': 'application/json'}),
                                   timeout=timeout).read()
            sent.append('telegram')
    return sent


def write_alert_state(path: Path, doc: Dict[str, Any]) -> None:
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, path)


def heartbeat(cfg: Dict[str, Any], args: argparse.Namespace, r: Report) -> None:
    """`heartbeat_url`: fetched every run, whatever the status. A dead-man service (healthchecks.io style, or the
    operator's own) alerts when the pings stop: a dead or hung monitor, a stopped timer or a host down. Nothing here
    can report its own death."""
    url = cfg.get('heartbeat_url')
    if not configured(url) or args.alert_dry_run:
        return
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers={'user-agent': 'bloch-l2-monitor'}),
                               timeout=args.timeout).read()
    except Exception as e:  # noqa: BLE001 - a missed ping is the dead-man's to alert on
        r.add('heartbeat', WARN, f'heartbeat_url not reached: {e}')


def alert_text(r: Report, min_level: int, now: float) -> str:
    lines = [f'BLOCH L1: {LEVEL_NAMES[r.status]} ({utc(now)})']
    for c in r.checks:
        if SEVERITY[c['code']] >= SEVERITY[min_level]:
            lines.append(f'{c["level"]} {c["check"]}: {c["message"]}')
    return '\n'.join(lines)[:3800]


def utc(ts: float) -> str:
    return time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(ts))


def handle_alerts(alert_config: Optional[str], r: Report, now: float, dry_run: bool, timeout: float,
                  sender=None) -> Optional[str]:
    """The same decision and delivery as l2_monitor.py's handle_alerts, with this script's text. Use a separate
    state_file from l2_monitor's, or leave alert_config out and feed report_file to `l2_monitor --report`."""
    if not alert_config:
        return None
    sender = sender or send_alert
    cfg = json.loads(Path(alert_config).read_text())
    min_level = LEVEL_CODES[cfg.get('min_level', 'WARN')]
    state_path = Path(cfg.get('state_file') or alert_config + '.state')
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    heartbeat(cfg, types.SimpleNamespace(alert_dry_run=dry_run, timeout=timeout), r)
    decision = decide_alert(r, state, now, float(cfg.get('realert_seconds', 3600)), min_level,
                            int(cfg.get('recover_runs', 3)))

    def bad_now() -> Dict[str, str]:
        bad = {c['check']: c['level'] for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]}
        bad.update({k: LEVEL_NAMES[v] for k, v in state.get('held', {}).items()})
        return bad

    if decision is None:
        if not dry_run:
            write_alert_state(state_path, {'bad': bad_now(), 'sent_at': state.get('sent_at', 0),
                                           'clean': state.get('clean', {})})
        return None
    text = alert_text(r, min_level, now) if decision == 'raise' else \
        f'BLOCH L1: RECOVERED, status {LEVEL_NAMES[r.status]} ({utc(now)})'
    payload = {'status': LEVEL_NAMES[r.status], 'event': decision, 'source': 'l1_monitor',
               'checks': [c for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]]}
    try:
        sent = sender(cfg, text, payload, timeout, dry_run)
    except Exception as e:  # noqa: BLE001 - an alert failure never hides the report
        r.add('alert_delivery', WARN, f'alert not delivered: {e}')
        return decision
    if not sent:
        r.add('alert_delivery', WARN, 'alert due but no target configured (webhook_url / alert_command / telegram are TBD-owner)')
    if not dry_run:
        write_alert_state(state_path, {'bad': bad_now(), 'sent_at': now if sent else state.get('sent_at', 0),
                                       'clean': state.get('clean', {}) if decision != 'recover' else {}})
    r.facts['alert'] = {'decision': decision, 'sent': sent}
    return decision


def print_report(r: Report, as_json: bool) -> None:
    if as_json:
        print(json.dumps(r.doc(), default=str), flush=True)
        return
    print(f'BLOCH L1: {LEVEL_NAMES[r.status]}  {utc(r.facts["checked_at"])}')
    for c in r.checks:
        print(f'  {c["level"]:<7} {c["check"]:<26} {c["message"]}')
    if r.facts.get('alert'):
        print(f'  alert: {r.facts["alert"]}')
    sys.stdout.flush()


def main(argv: Optional[List[str]] = None, transport: Optional[Transport] = None,
         fetch: Optional[Fetcher] = None, clock: Callable[[], float] = time.time) -> int:
    a = argparse.ArgumentParser(description='Read-only L1 monitor: stuck nodes, finality, parked blocks, peers, '
                                            'settler L1 sources across a split.')
    a.add_argument('--config', required=True, help='JSON config (monitor/l1-monitor.json.example)')
    a.add_argument('--watch', type=float, help='run every SECONDS until interrupted (no timer or cron needed)')
    a.add_argument('--duration', type=float, help='with --watch: stop after SECONDS; exit with the worst status seen')
    a.add_argument('--json', action='store_true', help='print the report as one JSON line per run')
    a.add_argument('--alert-dry-run', action='store_true', help='decide and print alerts, send nothing')
    a.add_argument('--no-alerts', action='store_true', help='ignore alert_config (for a manual run next to a timer)')
    args = a.parse_args(sys.argv[1:] if argv is None else argv)
    cfg = load_config(args.config)
    timeout = float(cfg.get('timeout', 8.0))
    transport = transport or http_transport(timeout)
    fetch = fetch or http_fetcher(timeout)
    state_path = cfg.get('state_file')
    if not state_path and not args.watch:
        print('note: no state_file and no --watch: one sample cannot show anything held, so l1_stuck stays below CRIT',
              file=sys.stderr)
    lock = None
    if state_path:  # a cron run that overlaps a slow one must not interleave their state writes
        lock = open(f'{state_path}.lock', 'a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f'another l1_monitor holds {state_path}.lock: not run', file=sys.stderr)
            return UNKNOWN
    state = load_state(state_path)
    worst, started = OK, time.time()
    try:
        while True:
            now = clock()
            r = run_once(cfg, transport, fetch, state, now)
            save_json(state_path, state)
            handle_alerts(None if args.no_alerts else cfg.get('alert_config'), r, now, args.alert_dry_run, timeout)
            save_json(cfg.get('report_file'), r.doc())
            print_report(r, args.json)
            worst = max(worst, r.status, key=lambda c: SEVERITY[c])
            if not args.watch:
                return r.status
            if args.duration and time.time() - started >= args.duration:
                return worst
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return worst


if __name__ == '__main__':
    sys.exit(main())
