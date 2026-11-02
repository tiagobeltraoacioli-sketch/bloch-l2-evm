#!/usr/bin/env python3
"""Read-only detection of an L1 bloch-pos node stuck on its own branch. Runbook: docs/L1-STUCK-NODE-RUNBOOK.md.

A stuck node shows, together and for a sustained time:
  * `bloch_pos_blocks_parked` steady at 32 or more;
  * its finalized epoch not moving while the reference's finalized epoch advances;
  * `getblockbyid` on the reference head answering "no block".
No single sign is enough: a healthy node has been seen at 27 and at 32 parked, and a restarting node lacks the
reference head for a while.

Time is counted in finalized epochs gained by the reference, so it needs no slot clock, and a chain whose
finality has stalled everywhere never alarms here. Calls only getchaininfo and getblockbyid, plus a GET of the
metrics URL. Holds no key and reads no node file. The only file it writes is the optional --state file.

  l1_stuck_check.py --node NAME=RPC_URL[,METRICS_URL] [--node ...] --reference RPC_URL [--reference ...]
                    (--state PATH | --watch SECONDS) [--json]

Without --state or --watch one sample is taken and at most WARN is reported, since nothing steady can be seen.
Exit status: 0 OK, 1 WARN, 2 CRIT (stuck), 3 UNKNOWN. Dependency-free Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3
LEVEL_NAMES = {OK: 'OK', WARN: 'WARN', CRIT: 'CRIT', UNKNOWN: 'UNKNOWN'}
SEVERITY = {OK: 0, WARN: 1, UNKNOWN: 2, CRIT: 3}
DEFAULTS = {'stuck_sustain_epochs': 3, 'stuck_parked_min': 32, 'stuck_min_samples': 3, 'stuck_max_gap_epochs': 2}
READ_ONLY_METHODS = frozenset({'getchaininfo', 'getblockbyid'})


# ---- Decision code. l2_monitor.py holds an identical copy; test_l2_monitor.py fails if the two differ. ----
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


# ---- I/O ----
class RpcError(Exception):
    pass


def rpc(url: str, method: str, params: list, timeout: float) -> Any:
    if method not in READ_ONLY_METHODS:
        raise PermissionError(f'{method} is not a read-only method')
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    req = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            reply = json.loads(resp.read(4 * 1024 * 1024))
    except Exception as e:  # network, HTTP or JSON error
        raise RpcError(f'{method} at {url}: {e}') from None
    if not isinstance(reply, dict):
        raise RpcError(f'{method} at {url}: malformed reply')
    if reply.get('error') is not None:
        raise RpcError(str(reply['error']))
    return reply.get('result')


def chain_view(url: str, timeout: float) -> Optional[Dict[str, Any]]:
    try:
        info = rpc(url, 'getchaininfo', [], timeout)
        return {'finalized': int(info['finalized']['epoch']), 'head': info['block_id'], 'url': url}
    except (RpcError, KeyError, TypeError, ValueError):
        return None


def sample(node: Dict[str, Optional[str]], refs: List[str], timeout: float) -> Dict[str, Any]:
    views = [v for v in (chain_view(u, timeout) for u in refs if u != node['rpc']) if v]
    ref = max(views, key=lambda v: v['finalized']) if views else None
    out: Dict[str, Any] = {'ref_finalized': ref['finalized'] if ref else None, 'ref_url': ref['url'] if ref else None}
    own = chain_view(node['rpc'], timeout)
    if own is None:
        out['down'] = True
        return out
    text = None
    if node.get('metrics'):
        try:
            with urllib.request.urlopen(node['metrics'], timeout=timeout) as resp:
                text = resp.read(1024 * 1024).decode()
        except Exception:  # metrics are optional evidence
            text = None
    out.update(finalized=own['finalized'], parked=stuck_metric(text, 'bloch_pos_blocks_parked'),
               peers=stuck_metric(text, 'bloch_pos_peer_count'), has_ref_head=None)
    if ref:
        try:
            out['has_ref_head'] = bool(rpc(node['rpc'], 'getblockbyid', [ref['head']], timeout))
        except RpcError as e:
            out['has_ref_head'] = False if re.search(r'no block', str(e)) else None
    return out


def one_shot(s: Dict[str, Any], p: Dict[str, Any]) -> Tuple[int, str]:
    if s.get('ref_finalized') is None:
        return UNKNOWN, 'no reference answers: not evaluated'
    if s.get('down'):
        return UNKNOWN, 'node does not answer'
    view = f'finalized e{s["finalized"]}, reference e{s["ref_finalized"]}, parked {s.get("parked")}, ' \
           f'has reference head {s.get("has_ref_head")}, peers {s.get("peers")}'
    behind = s['ref_finalized'] - s['finalized'] >= p['stuck_sustain_epochs']
    if behind and s.get('has_ref_head') is False and (s.get('parked') or 0) >= p['stuck_parked_min']:
        return WARN, f'matches the stuck pattern in one sample; use --watch to see whether it holds: {view}'
    return OK, view


def parse_node(spec: str) -> Dict[str, Optional[str]]:
    name, sep, rest = spec.partition('=')
    if not sep or '://' in name:
        raise SystemExit(f'--node needs NAME=RPC_URL[,METRICS_URL]: {spec}')
    url, _, metrics = rest.partition(',')
    return {'name': name, 'rpc': url, 'metrics': metrics or None}


def load_state(path: Optional[str]) -> Dict[str, Any]:
    try:
        state = json.loads(Path(path).read_text()) if path else {}
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Optional[str], state: Dict[str, Any]) -> None:
    if path:
        tmp = f'{path}.tmp'
        Path(tmp).write_text(json.dumps(state))
        os.replace(tmp, path)


def round_once(nodes, refs, p, state, stateful, timeout, emit) -> int:
    results = []
    for node in nodes:
        s = sample(node, refs, timeout)
        if stateful:
            state[node['name']], level, message = stuck_step(state.get(node['name']), s, p)
        else:
            level, message = one_shot(s, p)
        results.append({'node': node['name'], 'level': LEVEL_NAMES[level], 'code': level, 'message': message,
                        'sample': s, 'at': round(time.time(), 1)})
    emit(results)
    return max((c['code'] for c in results), key=lambda c: SEVERITY[c], default=UNKNOWN)


def main(argv: Optional[List[str]] = None) -> int:
    a = argparse.ArgumentParser(description='Read-only detection of an L1 node stuck on its own branch.')
    a.add_argument('--node', action='append', required=True, help='NAME=RPC_URL[,METRICS_URL]; repeat')
    a.add_argument('--reference', action='append', required=True, help='RPC URL of a node believed healthy; repeat')
    a.add_argument('--state', help='JSON state file kept between runs (for cron or a timer)')
    a.add_argument('--watch', type=float, help='sample every SECONDS until interrupted')
    a.add_argument('--duration', type=float, help='with --watch: stop after SECONDS; exit with the worst status seen')
    a.add_argument('--sustain-epochs', type=int, default=DEFAULTS['stuck_sustain_epochs'],
                   help='finalized epochs the reference must gain while the signs hold')
    a.add_argument('--parked-min', type=int, default=DEFAULTS['stuck_parked_min'])
    a.add_argument('--timeout', type=float, default=8.0)
    a.add_argument('--json', action='store_true', help='one JSON line per node and sample')
    args = a.parse_args(sys.argv[1:] if argv is None else argv)
    p = {**DEFAULTS, 'stuck_sustain_epochs': args.sustain_epochs, 'stuck_parked_min': args.parked_min}
    nodes = [parse_node(n) for n in args.node]
    stateful = bool(args.state or args.watch)
    state = load_state(args.state)

    def emit(results: List[Dict[str, Any]]) -> None:
        for c in results:
            print(json.dumps(c) if args.json else f'{c["level"]:<7} {c["node"]:<14} {c["message"]}', flush=True)

    if len({n['name'] for n in nodes}) != len(nodes):
        raise SystemExit('--node names must be unique')
    if len(args.reference) < 2:
        print('note: with one reference, a reference that is itself stuck cannot be noticed', file=sys.stderr)
    worst, started = OK, time.time()
    try:
        while True:
            status = round_once(nodes, args.reference, p, state, stateful, args.timeout, emit)
            worst = max(worst, status, key=lambda c: SEVERITY[c])
            save_state(args.state, state)
            if not args.watch:
                return status
            if args.duration and time.time() - started >= args.duration:
                return worst
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return worst


if __name__ == '__main__':
    sys.exit(main())
