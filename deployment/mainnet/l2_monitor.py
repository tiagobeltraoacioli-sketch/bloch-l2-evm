#!/usr/bin/env python3
"""Read-only health monitor for the Bloch L2 (mainnet chain id 700770, devnet4 700771).

Runbook: docs/MAINNET-OPS-RUNBOOK.md.

It reads, and never writes:
  * the L2 settled RPC (`bloch-l2-settled-rpc`): eth_chainId, the `latest`,
    `safe` and `finalized` blocks, `bloch_finality` and the supply ledger
    storage of 0x4200...0100;
  * one or more L1 node RPCs (`bloch-pos`): getchaininfo (or getblockcount)
    and getl2settlement;
  * optionally, local files (follower status, prover/settler heartbeats) for
    their age.

It holds no key, opens no keystore and can only call the read-only methods in
READ_ONLY_METHODS; any other method is refused before a request is made.
Dependency-free Python 3.9+.

Exit status (Nagios convention): 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN.

  l2_monitor.py --profile mainnet --l2-rpc http://127.0.0.1:18945 \\
      --l1-rpc http://127.0.0.1:8545 --l1-rpc http://127.0.0.1:8546 [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3
LEVEL_NAMES = {OK: 'OK', WARN: 'WARN', CRIT: 'CRIT', UNKNOWN: 'UNKNOWN'}

READ_ONLY_METHODS = frozenset({
    # L2 (Ethereum JSON-RPC subset + Bloch extensions)
    'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getStorageAt', 'bloch_finality',
    # L1 (bloch-pos)
    'getchaininfo', 'getblockcount', 'getl2settlement',
})

SUPPLY_LEDGER = '0x4200000000000000000000000000000000000100'
SLOT_MINTED, SLOT_BURNED, SLOT_WITHDRAWN = '0x0', '0x2', '0x3'
ATOM_SCALE = 10 ** 10  # wei per L1 sat (8 -> 18 decimals)

# Thresholds. Times in seconds. Rationale in docs/MAINNET-OPS-RUNBOOK.md.
PROFILES: Dict[str, Dict[str, Any]] = {
    'mainnet': {
        'chain_id': 700770,
        'head_age_warn': 25 * 60, 'head_age_crit': 45 * 60,
        'unsafe_depth_warn': 2, 'unsafe_depth_crit': 4,
        'finalized_age_warn': 150 * 60, 'finalized_age_crit': 240 * 60,
        'l1_finality_epochs_warn': 4, 'l1_finality_epochs_crit': 8,
        'l1_height_spread_warn': 3, 'l1_height_spread_crit': 32,
        'follower_lag_blocks_warn': 64, 'follower_lag_blocks_crit': 320,
        'inbox_backlog_warn': 50, 'inbox_backlog_crit': 500,
        'da_backlog_warn': 3, 'da_backlog_crit': 10,
        'file_age_warn': 120, 'file_age_crit': 600,
    },
    'devnet4': {
        'chain_id': 700771,
        'head_age_warn': 25 * 60, 'head_age_crit': 45 * 60,
        'unsafe_depth_warn': 2, 'unsafe_depth_crit': 4,
        'finalized_age_warn': 40 * 60, 'finalized_age_crit': 90 * 60,
        'l1_finality_epochs_warn': 4, 'l1_finality_epochs_crit': 8,
        'l1_height_spread_warn': 15, 'l1_height_spread_crit': 160,
        'follower_lag_blocks_warn': 160, 'follower_lag_blocks_crit': 960,
        'inbox_backlog_warn': 50, 'inbox_backlog_crit': 500,
        'da_backlog_warn': 3, 'da_backlog_crit': 10,
        'file_age_warn': 120, 'file_age_crit': 600,
    },
}


class RpcError(Exception):
    pass


Transport = Callable[[str, str, list], Any]


def http_transport(timeout: float) -> Transport:
    def call(url: str, method: str, params: list) -> Any:
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
            raise RpcError(f'{method} at {url}: {reply["error"]}')
        return reply.get('result')
    return call


class Client:
    """Refuses every method outside READ_ONLY_METHODS before any I/O."""

    def __init__(self, transport: Transport):
        self.transport = transport

    def call(self, url: str, method: str, params: Optional[list] = None) -> Any:
        if method not in READ_ONLY_METHODS:
            raise PermissionError(f'{method} is not a read-only monitor method')
        return self.transport(url, method, params or [])


def qty(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith('0x'):
        raise ValueError(f'not a quantity: {value!r}')
    return int(value, 16)


class Report:
    def __init__(self):
        self.checks: List[Dict[str, Any]] = []
        self.facts: Dict[str, Any] = {}

    def add(self, name: str, level: int, message: str, **values: Any) -> None:
        self.checks.append({'check': name, 'level': LEVEL_NAMES[level], 'code': level, 'message': message, **values})

    def graded(self, name: str, value: float, warn: float, crit: float, message: str, **values: Any) -> None:
        level = CRIT if value >= crit else WARN if value >= warn else OK
        self.add(name, level, message, value=value, warn=warn, crit=crit, **values)

    @property
    def status(self) -> int:
        codes = [c['code'] for c in self.checks]
        if not codes:
            return UNKNOWN
        if CRIT in codes:
            return CRIT
        if UNKNOWN in codes:
            return UNKNOWN
        return WARN if WARN in codes else OK


def minutes(seconds: float) -> str:
    return f'{seconds / 60:.1f} min'


def check_l2(client: Client, url: str, p: Dict[str, Any], now: float, r: Report) -> Optional[Dict[str, Any]]:
    try:
        chain_id = qty(client.call(url, 'eth_chainId'))
        blocks = {tag: client.call(url, 'eth_getBlockByNumber', [tag, False]) for tag in ('latest', 'safe', 'finalized')}
    except (RpcError, ValueError) as e:
        r.add('l2_rpc', CRIT, f'L2 RPC unreachable or malformed: {e}')
        return None
    r.add('l2_rpc', OK, f'L2 RPC answers at {url}')
    if chain_id != p['chain_id']:
        r.add('l2_chain_id', CRIT, f'chain id {chain_id} != expected {p["chain_id"]}', value=chain_id)
    else:
        r.add('l2_chain_id', OK, f'chain id {chain_id} ({hex(chain_id)})', value=chain_id)
    latest = blocks['latest']
    if not isinstance(latest, dict):
        r.add('l2_head', CRIT, 'no latest block')
        return None
    num = {t: (qty(b['number']) if isinstance(b, dict) else None) for t, b in blocks.items()}
    ts = {t: (qty(b['timestamp']) if isinstance(b, dict) else None) for t, b in blocks.items()}
    r.facts.update({'l2_latest': num['latest'], 'l2_safe': num['safe'], 'l2_finalized': num['finalized'],
                    'l2_latest_timestamp': ts['latest'], 'l2_base_fee_wei': qty(latest.get('baseFeePerGas', '0x0'))})
    r.graded('l2_head_age', max(0.0, now - ts['latest']), p['head_age_warn'], p['head_age_crit'],
             f'latest L2 block {num["latest"]} is {minutes(max(0.0, now - ts["latest"]))} old')
    if num['safe'] is None:
        r.add('l2_safe', WARN, 'no safe L2 block yet (nothing settled on L1)')
    else:
        r.graded('l2_unsafe_depth', num['latest'] - num['safe'], p['unsafe_depth_warn'], p['unsafe_depth_crit'],
                 f'latest - safe = {num["latest"] - num["safe"]} blocks (1 is normal: the block being proved)')
    if num['finalized'] is None:
        r.add('l2_finalized', WARN, 'no finalized L2 block yet')
    else:
        age = max(0.0, now - ts['finalized'])
        r.graded('l2_finalized_age', age, p['finalized_age_warn'], p['finalized_age_crit'],
                 f'finalized L2 block {num["finalized"]} is {minutes(age)} old, '
                 f'{num["latest"] - num["finalized"]} behind latest')
    ordered = [n for n in (num['finalized'], num['safe'], num['latest']) if n is not None]
    if ordered != sorted(ordered):
        r.add('l2_tag_order', CRIT, f'tags out of order: finalized {num["finalized"]} safe {num["safe"]} '
                                    f'latest {num["latest"]}')
    else:
        r.add('l2_tag_order', OK, 'finalized <= safe <= latest')
    try:
        finality = client.call(url, 'bloch_finality')
    except RpcError as e:
        r.add('l2_finality_view', WARN, f'bloch_finality unavailable: {e}')
        finality = None
    try:
        r.facts['l2_ledger'] = {name: qty(client.call(url, 'eth_getStorageAt', [SUPPLY_LEDGER, slot, 'latest']))
                                for name, slot in (('minted_wei', SLOT_MINTED), ('burned_wei', SLOT_BURNED),
                                                   ('withdrawn_wei', SLOT_WITHDRAWN))}
    except (RpcError, ValueError) as e:
        r.add('l2_ledger', WARN, f'supply ledger unreadable: {e}')
    return {'num': num, 'finality': finality}


def check_l1(client: Client, urls: List[str], p: Dict[str, Any], r: Report) -> List[Dict[str, Any]]:
    nodes = []
    for url in urls:
        node: Dict[str, Any] = {'url': url}
        try:
            try:
                info = client.call(url, 'getchaininfo')
            except RpcError:
                info = client.call(url, 'getblockcount')
            node['height'] = int(info['height'])
            node['epoch'] = int(info['epoch'])
            node['finalized_height'] = int(info['finalized_height'])
            fin = info.get('finalized')
            node['finalized_epoch'] = int(fin['epoch'] if isinstance(fin, dict) else info['finalized_epoch'])
        except (RpcError, KeyError, TypeError, ValueError) as e:
            node['error'] = str(e)
            nodes.append(node)
            continue
        try:
            node['l2'] = client.call(url, 'getl2settlement')
        except RpcError as e:
            node['l2_error'] = str(e)
        nodes.append(node)
    up = [n for n in nodes if 'error' not in n]
    down = len(nodes) - len(up)
    if not nodes:
        r.add('l1_nodes', UNKNOWN, 'no L1 RPC configured')
        return up
    if not up:
        r.add('l1_nodes', CRIT, f'all {len(nodes)} L1 RPCs down: ' + '; '.join(n['error'] for n in nodes))
        return up
    level = OK if down == 0 else (CRIT if 2 * len(up) <= len(nodes) else WARN)
    r.add('l1_nodes', level, f'{len(up)}/{len(nodes)} L1 RPCs answer',
          down=[n['url'] for n in nodes if 'error' in n])
    heights = [n['height'] for n in up]
    r.graded('l1_height_spread', max(heights) - min(heights), p['l1_height_spread_warn'], p['l1_height_spread_crit'],
             f'L1 heights {min(heights)}..{max(heights)}')
    best = max(up, key=lambda n: n['height'])
    r.facts.update({'l1_height': best['height'], 'l1_epoch': best['epoch'],
                    'l1_finalized_epoch': best['finalized_epoch'], 'l1_finalized_height': best['finalized_height']})
    lag = best['epoch'] - best['finalized_epoch']
    r.graded('l1_finality_lag', lag, p['l1_finality_epochs_warn'], p['l1_finality_epochs_crit'],
             f'L1 epoch {best["epoch"]}, finalized epoch {best["finalized_epoch"]} ({lag} epochs; 2 is normal)')
    with_l2 = [n for n in up if isinstance(n.get('l2'), dict)]
    if not with_l2:
        r.add('l1_l2_view', CRIT, 'no L1 node reports getl2settlement (L2 not installed on these nodes?)')
        return up
    chain_ids = {n['l2'].get('chain_id') for n in with_l2}
    if chain_ids != {p['chain_id']}:
        r.add('l1_l2_chain_id', CRIT, f'getl2settlement chain ids {sorted(map(str, chain_ids))} != {p["chain_id"]}')
    commits = [((n['l2'].get('accepted') or {}).get('commitment')) for n in with_l2]
    distinct = {c for c in commits if c}
    if len(distinct) > 1:
        # Nodes a block apart can legitimately differ for a moment; persistent splits matter.
        r.add('l1_accepted_agreement', WARN, f'L1 nodes report {len(distinct)} different accepted settlements')
    else:
        r.add('l1_accepted_agreement', OK, 'L1 nodes agree on the accepted settlement')
    check_escrow_and_backlog(with_l2, p, r)
    return up


def check_escrow_and_backlog(nodes: List[Dict[str, Any]], p: Dict[str, Any], r: Report) -> None:
    head = max(nodes, key=lambda n: n['height'])['l2']
    w = head.get('withdrawals') or {}
    inbox = head.get('inbox') or {}
    not_conserved = [n['url'] for n in nodes if (n['l2'].get('withdrawals') or {}).get('escrow_conserved') is False]
    if not_conserved:
        r.add('escrow_conserved', CRIT, f'escrow_conserved=false on {not_conserved}')
    elif all((n['l2'].get('withdrawals') or {}).get('escrow_conserved') is True for n in nodes):
        r.add('escrow_conserved', OK, 'every L1 node reports escrow_conserved=true')
    else:
        r.add('escrow_conserved', WARN, 'escrow_conserved missing on some L1 node')
    escrow = int(inbox.get('escrow_sat', 0))
    released = int(w.get('released_sat', 0))
    r.facts.update({'escrow_sat': escrow, 'released_sat': released})
    ledger = r.facts.get('l2_ledger')
    if ledger is not None:
        # Every minted wei came from an escrowed deposit; claims only return withdrawn
        # (burned out of L2 supply) value. So deposits = escrow + released >= minted - burned.
        backing = (escrow + released) * ATOM_SCALE
        need = ledger['minted_wei'] - ledger['burned_wei']
        if backing < need:
            r.add('escrow_backing', CRIT, f'(escrow + released) {backing} wei < L2 minted - burned {need} wei',
                  backing_wei=backing, minted_minus_burned_wei=need)
        else:
            r.add('escrow_backing', OK, f'(escrow + released) covers L2 minted - burned '
                                        f'({backing / 1e18:.8f} >= {need / 1e18:.8f} BLCH)')
        if released * ATOM_SCALE > ledger['withdrawn_wei']:
            r.add('claims_vs_withdrawn', CRIT, f'L1 released {released} sat > L2 withdrawn {ledger["withdrawn_wei"]} wei')
        else:
            r.add('claims_vs_withdrawn', OK, 'L1 released <= L2 withdrawn')
    backlog = int(inbox.get('count', 0)) - int(inbox.get('consumed', 0))
    r.graded('inbox_backlog', backlog, p['inbox_backlog_warn'], p['inbox_backlog_crit'],
             f'{backlog} L1 deposits not yet consumed by the L2')
    da = head.get('data_availability') or []
    r.graded('da_backlog', len(da), p['da_backlog_warn'], p['da_backlog_crit'],
             f'{len(da)} DA records awaiting their settlement')
    window = w.get('release_window') or {}
    if window:
        remaining = int(window.get('remaining_sat', 0))
        r.facts['release_window'] = window
        level = WARN if remaining == 0 else OK
        r.add('release_window', level, f'release window {window.get("window")}: {remaining / 1e8:.8f} BLCH '
                                       f'of {int(window.get("cap_sat", 0)) / 1e8:.8f} remaining')


def check_follower(l2: Optional[Dict[str, Any]], l1_up: List[Dict[str, Any]], p: Dict[str, Any], r: Report) -> None:
    finality = (l2 or {}).get('finality')
    if not isinstance(finality, dict) or not l1_up:
        return
    l1 = finality.get('l1') or {}
    verified = l1.get('verified_blocks')
    if verified is None:
        r.add('follower', WARN, 'bloch_finality reports no verified_blocks')
        return
    l1_fin = max(n['finalized_height'] for n in l1_up)
    lag = max(0, l1_fin - int(verified))
    r.graded('follower_lag', lag, p['follower_lag_blocks_warn'], p['follower_lag_blocks_crit'],
             f'follower verified {verified} L1 blocks, L1 finalized height {l1_fin} ({lag} behind)')
    num = l2['num']
    if finality.get('finalized_height') is not None and num['finalized'] is not None \
            and int(finality['finalized_height']) != num['finalized']:
        r.add('finality_view_consistency', WARN,
              f'bloch_finality finalized_height {finality["finalized_height"]} != tag {num["finalized"]}')


def check_files(specs: List[str], p: Dict[str, Any], now: float, r: Report) -> None:
    for spec in specs:
        name, _, rest = spec.partition('=')
        path, _, limit = rest.partition(':')
        warn = float(limit) if limit else p['file_age_warn']
        crit = warn * 5 if limit else p['file_age_crit']
        try:
            mtime = os.stat(path).st_mtime
        except OSError as e:
            r.add(f'file:{name}', CRIT, f'{path}: {e}')
            continue
        r.graded(f'file:{name}', max(0.0, now - mtime), warn, crit, f'{path} written {now - mtime:.0f} s ago')


def run(args: argparse.Namespace, transport: Transport, now: Optional[float] = None) -> Report:
    now = time.time() if now is None else now
    p = dict(PROFILES[args.profile])
    for item in args.set or []:
        key, _, value = item.partition('=')
        if key not in p:
            raise SystemExit(f'unknown threshold {key}')
        p[key] = type(p[key])(float(value)) if isinstance(p[key], int) else float(value)
    client = Client(transport)
    r = Report()
    r.facts.update({'profile': args.profile, 'checked_at': int(now)})
    l2 = check_l2(client, args.l2_rpc, p, now, r)
    l1_up = check_l1(client, args.l1_rpc or [], p, r)
    check_follower(l2, l1_up, p, r)
    check_files(args.file or [], p, now, r)
    return r


def parse(argv: List[str]) -> argparse.Namespace:
    a = argparse.ArgumentParser(description='Read-only Bloch L2 health monitor (no keys, no writes).')
    a.add_argument('--profile', choices=sorted(PROFILES), default='mainnet')
    a.add_argument('--l2-rpc', default='http://127.0.0.1:18945')
    a.add_argument('--l1-rpc', action='append', help='L1 bloch-pos RPC URL; repeat for each node')
    a.add_argument('--file', action='append', help='NAME=PATH[:MAX_AGE_S] heartbeat file to age-check')
    a.add_argument('--set', action='append', help='override a threshold, KEY=VALUE')
    a.add_argument('--timeout', type=float, default=8.0)
    a.add_argument('--json', action='store_true')
    return a.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse(sys.argv[1:] if argv is None else argv)
    r = run(args, http_transport(args.timeout))
    if args.json:
        print(json.dumps({'status': LEVEL_NAMES[r.status], 'facts': r.facts, 'checks': r.checks}, indent=2))
    else:
        print(f'BLOCH L2 {args.profile}: {LEVEL_NAMES[r.status]}')
        for c in r.checks:
            print(f'  {c["level"]:<7} {c["check"]:<26} {c["message"]}')
    return r.status


if __name__ == '__main__':
    sys.exit(main())
