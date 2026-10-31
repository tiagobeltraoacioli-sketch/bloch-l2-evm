#!/usr/bin/env python3
"""Read-only health monitor for the Bloch L2 mainnet (chain id 700770; devnet4 700771).

Runbook: docs/MAINNET-OPS-RUNBOOK.md. Release: the v2.1 L2 build `bloch-l2-2026-10-30-v21-native-78d4921c` (L2 a39b04e4, native
78d4921c, follower c18752fd, produce-dev fb0d5313, settled-rpc 18be911a).

What it reads (it never writes to a chain, holds no key and opens no keystore):
  * every L2 settled-RPC backend (`--l2-rpc NAME=URL`, repeat): eth_chainId, the `latest`, `safe` and
    `finalized` blocks, `bloch_finality` (the follower view it serves) and the supply-ledger storage of
    0x4200...0100;
  * one or more L1 node RPCs (`--l1-rpc`, repeat): getchaininfo (incl. `hard_forks`) and getl2settlement;
  * optionally: follower `status.json` files, the attestation drop (directory or HTTP GET base), the
    state and journal of systemd units (`systemctl show`, `journalctl`, read-only), JSON-lines log files,
    heartbeat-file ages, bridge guardian health files and installed binaries' SHA-256.

JSON-RPC calls are limited to READ_ONLY_METHODS; any other method is refused before a request is made.
The only outbound writes are the alert notifications the owner configures (`--alert-config`).

Checks: L1 RPC health and finality lag, L2 backend health and agreement, L2 head/finalized age, follower
verified lag and FFG epoch lag (structurally 3 epochs), settlement age, escrow vs L2 supply reserves,
inbox/DA backlog, attestor signatures per round, settler/prover/shadow/attestor failure events, unit
state, L1 gate epochs approaching (and agreement with the gates compiled into the v2 build).

Exit status (Nagios convention): 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN. Dependency-free Python 3.9+.

  l2_monitor.py --profile mainnet --phase live \\
      --l2-rpc A=http://127.0.0.1:18955 --l2-rpc B=http://10.0.0.2:18955 \\
      --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://45.77.67.251:8080 \\
      [--follower-status A=/var/lib/bloch-l2-mainnet-follower/status.json] \\
      [--attest-drop https://drop.example/attest] [--unit settler=bloch-l2-mainnet-settler.service] \\
      [--alert-config /etc/bloch-l2-monitor/alert.json] [--json]
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3
LEVEL_NAMES = {OK: 'OK', WARN: 'WARN', CRIT: 'CRIT', UNKNOWN: 'UNKNOWN'}
LEVEL_CODES = {v: k for k, v in LEVEL_NAMES.items()}
SEVERITY = {OK: 0, WARN: 1, UNKNOWN: 2, CRIT: 3}

READ_ONLY_METHODS = frozenset({
    # L2 (Ethereum JSON-RPC subset + Bloch extensions)
    'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getStorageAt', 'bloch_finality',
    # L1 (bloch-pos)
    'getchaininfo', 'getblockcount', 'getl2settlement',
})

# ---- Pinned mainnet identity (Genesis-4; deployment/mainnet/sequencer_mainnet.py) ----
L1_GENESIS_TIME = 1786656679
SLOT_SECONDS = 30
SLOTS_PER_EPOCH = 32
EPOCH_SECONDS = SLOT_SECONDS * SLOTS_PER_EPOCH
MAINNET_PINS = {
    'network': 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',
    'genesis': '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415',
    'l2_genesis_hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
    'attestor_set': '1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b',
}

# ---- The v2.1 L2 build (bloch-l2-2026-10-30-v21-native-78d4921c: SHA256SUMS and build.json) ----
V2_BUILD = {
    'l2_commit': 'a39b04e435b11bd2316dffe94d78df0163153c56',
    'native': '78d4921c3ec6ba41829f3878eed47f8d3bb96230',
    'native_lock_sha256': '26bf44539b996809bd75164a488d8a30137507716d06990721056a213364aef8',
}
V2_SHA256 = {
    'bloch-l2-native-follower': 'c18752fd4c6942678bcb45d8d36436bcd644b1ee6e48416d67e4999e7c7cf29a',
    'bloch-l2-produce-dev': 'fb0d531311d4f19a97f0839968146f5737acf57eb313fc93972ec215de950be9',
    'bloch-l2-settled-rpc': '18be911a47f0ab8975e1f079c860adef08dfc43c4b5062eca7b040e2e6eee83f',
    'sequencer_mainnet.py': '15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2',
}
# getchaininfo.hard_forks name -> the params.rs constant the v2 follower/producer were compiled with,
# and its value in the v2 build.json (`l1_activation_epochs`). A list means "any of" (cfg variants).
GATE_CONSTANTS = {
    'hf1_claim_finality': 'HF1_CLAIM_FINALITY_EPOCH',
    'hf1_frozen_set': 'HF1_FROZEN_FINALITY_SET_EPOCH',
    'hf1_own_target': 'HF1_OWN_TARGET_VOTES_EPOCH',
    'hf2_slashing_v2': 'HF2_SLASHING_V2_EPOCH',
    'hf2_growth_cap': 'HF2_GROWTH_CAP_EPOCH',
    'hf2_sig_canonical': 'SIG_CANONICAL_ACTIVATION_EPOCH',
    'hf2_mldsa_pin': 'MLDSA_PIN_ACTIVATION_EPOCH',
    'hf3_kes_registration': 'HF3_KES_EPOCH',
    'hf3_kes_enforce': 'HF3_KES_ENFORCE_EPOCH',
    'hf3_slh': 'HF3_SLH_SUITE_EPOCH',
    'hf3_pq_migration': 'HF3_PQ_MIGRATION_EPOCH',
}
V2_COMPILED_GATES: Dict[str, Any] = {
    'HF1_CLAIM_FINALITY_EPOCH': 7180, 'HF1_FROZEN_FINALITY_SET_EPOCH': 7180, 'HF1_OWN_TARGET_VOTES_EPOCH': 7186,
    'HF2_SLASHING_V2_EPOCH': 7270, 'HF2_GROWTH_CAP_EPOCH': 7270, 'SIG_CANONICAL_ACTIVATION_EPOCH': 7270,
    'MLDSA_PIN_ACTIVATION_EPOCH': ['0', '7270'], 'HF3_KES_EPOCH': 7360, 'HF3_KES_ENFORCE_EPOCH': 8620,
    'HF3_SLH_SUITE_EPOCH': 7360, 'HF3_PQ_MIGRATION_EPOCH': 7360,
}

SUPPLY_LEDGER = '0x4200000000000000000000000000000000000100'
SLOT_MINTED, SLOT_BURNED, SLOT_WITHDRAWN = '0x0', '0x2', '0x3'  # src/state.rs SUPPLY_LEDGER_*_SLOT
ATOM_SCALE = 10 ** 10  # wei per L1 sat (8 -> 18 decimals)

# Log events (settler_v3.py, sequencer_mainnet.py, attestor_agent.py). Unlisted events are ignored.
CRIT_EVENTS = frozenset({'halt', 'refused-rebuild-differs', 'refused-root-not-on-own-chain',
                         'request-moved-after-submit'})
WARN_EVENTS = frozenset({'prover-failed', 'retry', 'acceptance-timeout', 'l1-not-advancing', 'submit-refused',
                         'rpc-no-quorum', 'rpc-endpoint-diverged', 'rpc-endpoint-failed', 'da-funding-low',
                         'da-inclusion-timeout', 'da-paused-signature-fork', 'producer-refused-spool',
                         'native-no-quorum', 'publish-failed', 'alert-failed', 'held', 'check-not-ready',
                         'rpc-quorum-view-behind'})
PROGRESS_EVENTS = frozenset({'accepted', 'proof-generated', 'shadow-match', 'signed', 'rebuild-check-ok',
                             'job-ready', 'root-skipped'})

# Thresholds. Times in seconds. Rationale in docs/MAINNET-OPS-RUNBOOK.md.
_COMMON: Dict[str, Any] = {
    'unsafe_depth_warn': 2, 'unsafe_depth_crit': 4,
    'l1_finality_epochs_warn': 4, 'l1_finality_epochs_crit': 8,
    'follower_epoch_lag_expected': 3, 'follower_epoch_lag_warn': 5, 'follower_epoch_lag_crit': 8,
    'inbox_backlog_warn': 50, 'inbox_backlog_crit': 500,
    'da_backlog_warn': 3, 'da_backlog_crit': 10,
    'file_age_warn': 120, 'file_age_crit': 600,
    'guardian_age_warn': 300,
    'status_age_warn': 300, 'status_age_crit': 900,
    # A settled RPC before the next build stops advancing finality above 16 MiB of status file.
    'status_bytes_warn': 8 * 1_048_576, 'status_bytes_crit': 12 * 1_048_576,
    'gate_warn_epochs': 96, 'gate_crit_epochs': 6,
    'attestors_n': 5, 'attestors_k': 3, 'attest_grace_blocks': 120,
    'event_window_seconds': 3600, 'event_repeat_crit': 5,
    'l2_backend_spread_warn': 2, 'l2_backend_spread_crit': 8,
}
PROFILES: Dict[str, Dict[str, Any]] = {
    'mainnet': {**_COMMON,
                'chain_id': 700770,
                'head_age_warn': 25 * 60, 'head_age_crit': 45 * 60,
                'settlement_age_warn': 25 * 60, 'settlement_age_crit': 45 * 60,
                'finalized_age_warn': 150 * 60, 'finalized_age_crit': 240 * 60,
                'l1_height_spread_warn': 3, 'l1_height_spread_crit': 32,
                'follower_lag_blocks_warn': 64, 'follower_lag_blocks_crit': 320},
    'devnet4': {**_COMMON,
                'chain_id': 700771,
                'head_age_warn': 25 * 60, 'head_age_crit': 45 * 60,
                'settlement_age_warn': 25 * 60, 'settlement_age_crit': 45 * 60,
                'finalized_age_warn': 40 * 60, 'finalized_age_crit': 90 * 60,
                'l1_height_spread_warn': 15, 'l1_height_spread_crit': 160,
                'follower_lag_blocks_warn': 160, 'follower_lag_blocks_crit': 960},
}


class RpcError(Exception):
    pass


Transport = Callable[[str, str, list], Any]
Runner = Callable[[List[str]], Tuple[int, str]]
Fetcher = Callable[[str], Optional[bytes]]


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


def subprocess_runner(argv: List[str]) -> Tuple[int, str]:
    """Only `systemctl show` and `journalctl` (both read-only) are ever run."""
    if argv[:2] != ['systemctl', 'show'] and argv[:1] != ['journalctl']:
        raise PermissionError(f'{argv[:2]} is not a read-only monitor command')
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)
    return done.returncode, done.stdout


def http_fetcher(timeout: float) -> Fetcher:
    def fetch(url: str) -> Optional[bytes]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return resp.read(200_000)
        except Exception:  # a missing partial is normal
            return None
    return fetch


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


def strip0x(h: Any) -> str:
    return h[2:] if isinstance(h, str) and h.startswith('0x') else (h or '')


def utc(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def epoch_start(epoch: int) -> int:
    return L1_GENESIS_TIME + epoch * EPOCH_SECONDS


def slot_time(slot: int) -> int:
    return L1_GENESIS_TIME + slot * SLOT_SECONDS


def minutes(seconds: float) -> str:
    return f'{seconds / 60:.1f} min'


def named(spec: str, default: str) -> Tuple[str, str]:
    name, sep, rest = spec.partition('=')
    if sep and '://' not in name and '/' not in name:
        return name, rest
    return default, spec


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
        return max(codes, key=lambda c: SEVERITY[c])


# --------------------------------------------------------------------------------------------- L1
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
            node['finalized_root'] = fin.get('root') if isinstance(fin, dict) else None
            node['slot'] = int(info['slot']) if 'slot' in info else None
            node['hard_forks'] = info.get('hard_forks')
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
    if not nodes:
        r.add('l1_nodes', UNKNOWN, 'no L1 RPC configured')
        return up
    if not up:
        r.add('l1_nodes', CRIT, f'all {len(nodes)} L1 RPCs down: ' + '; '.join(n['error'] for n in nodes))
        return up
    down = len(nodes) - len(up)
    level = OK if down == 0 else (CRIT if 2 * len(up) <= len(nodes) else WARN)
    r.add('l1_nodes', level, f'{len(up)}/{len(nodes)} L1 RPCs answer',
          down=[n['url'] for n in nodes if 'error' in n])
    heights = [n['height'] for n in up]
    r.graded('l1_height_spread', max(heights) - min(heights), p['l1_height_spread_warn'], p['l1_height_spread_crit'],
             f'L1 heights {min(heights)}..{max(heights)}')
    best = max(up, key=lambda n: n['height'])
    r.facts.update({'l1_height': best['height'], 'l1_epoch': best['epoch'], 'l1_slot': best['slot'],
                    'l1_finalized_epoch': best['finalized_epoch'], 'l1_finalized_height': best['finalized_height']})
    lag = best['epoch'] - best['finalized_epoch']
    r.graded('l1_finality_lag', lag, p['l1_finality_epochs_warn'], p['l1_finality_epochs_crit'],
             f'L1 epoch {best["epoch"]}, finalized epoch {best["finalized_epoch"]} ({lag} epochs; 2 is normal)')
    return up


def check_gates(l1_up: List[Dict[str, Any]], p: Dict[str, Any], compiled: Dict[str, Any], now: float,
                r: Report) -> None:
    """L1 activation epochs ahead, and agreement with the epochs compiled into the L2 build."""
    if not l1_up:
        return
    best = max(l1_up, key=lambda n: n['height'])
    forks = best.get('hard_forks')
    if not isinstance(forks, dict):
        r.add('l1_gates', WARN, 'L1 node reports no hard_forks (not the armed release?)')
        return
    epoch = best['epoch']
    upcoming, mismatched = [], []
    for name, gate in sorted(forks.items(), key=lambda kv: ((kv[1] or {}).get('activation_epoch') or 1 << 62)):
        act = (gate or {}).get('activation_epoch')
        if act is None:
            continue
        const = GATE_CONSTANTS.get(name)
        if const and const in compiled:
            want = compiled[const]
            allowed = {str(x) for x in want} if isinstance(want, list) else {str(want)}
            if str(act) not in allowed:
                mismatched.append(f'{name}: L1 e{act}, L2 build {want}')
        if not gate.get('active') and act >= epoch:
            upcoming.append((act - epoch, name, act))
    r.facts['l1_gates_upcoming'] = [{'gate': n, 'epoch': a, 'in_epochs': d, 'at': utc(epoch_start(a))}
                                    for d, n, a in upcoming]
    if mismatched:
        r.add('l1_gates_vs_l2_build', CRIT, 'L1 gate epochs differ from the L2 build (the follower/producer would '
                                            'halt there): ' + '; '.join(mismatched))
    else:
        r.add('l1_gates_vs_l2_build', OK, 'every L1 gate epoch matches the L2 build')
    if not upcoming:
        r.add('l1_gates', OK, 'no L1 gate pending')
        return
    d, name, act = upcoming[0]
    same = [n for dd, n, a in upcoming if a == act]
    level = CRIT if d <= p['gate_crit_epochs'] else WARN if d <= p['gate_warn_epochs'] else OK
    r.add('l1_gates', level, f'next L1 gate e{act} ({", ".join(same)}) in {d} epochs, {utc(epoch_start(act))}',
          value=d, warn=p['gate_warn_epochs'], crit=p['gate_crit_epochs'])


def check_settlement(l1_up: List[Dict[str, Any]], p: Dict[str, Any], phase: str, now: float, r: Report) -> List[dict]:
    with_l2 = [n for n in l1_up if isinstance(n.get('l2'), dict)]
    if not l1_up:
        return with_l2
    if not with_l2:
        r.add('l1_l2_view', CRIT, 'no L1 node reports getl2settlement')
        return with_l2
    pin_errors = []
    for n in with_l2:
        v = n['l2']
        if v.get('chain_id') != p['chain_id']:
            pin_errors.append(f'{n["url"]}: chain_id {v.get("chain_id")}')
        if p['chain_id'] == 700770:
            for key in ('network', 'genesis'):
                if strip0x(v.get(key)) != MAINNET_PINS[key]:
                    pin_errors.append(f'{n["url"]}: {key} {v.get(key)}')
            aset = strip0x((v.get('withdrawals') or {}).get('attestor_set'))
            if aset != MAINNET_PINS['attestor_set']:
                pin_errors.append(f'{n["url"]}: attestor_set {aset}')
        if (v.get('profile') or {}).get('activated') is False:
            pin_errors.append(f'{n["url"]}: profile not activated')
    r.add('l1_l2_identity', CRIT if pin_errors else OK,
          '; '.join(pin_errors) if pin_errors else 'getl2settlement network, genesis, chain and attestor set pinned')
    commits = {(n['l2'].get('accepted') or {}).get('commitment') for n in with_l2}
    distinct = {c for c in commits if c}
    if len(distinct) > 1 or (distinct and None in commits):
        # Nodes a block apart can legitimately differ for a moment; persistent splits matter.
        r.add('l1_accepted_agreement', WARN, f'L1 nodes report {len(commits)} different accepted settlements')
    else:
        r.add('l1_accepted_agreement', OK, 'L1 nodes agree on the accepted settlement')
    head_node = max(with_l2, key=lambda n: n['height'])
    head = head_node['l2']
    source = head.get('source') or {}
    accepted = head.get('accepted')
    r.facts['l2_next_number'] = source.get('height')
    r.facts['l2_settled_number'] = (int(source['height']) - 1) if accepted and source.get('height') else None
    r.facts['l2_settlement_source_slot'] = source.get('slot')
    if accepted is None:
        if phase == 'prelaunch':
            r.add('settlement_age', OK, f'pre-launch: no settlement accepted yet (next L2 block '
                                        f'{source.get("height")}, source slot {source.get("slot")})')
        else:
            r.add('settlement_age', CRIT, 'no L2 settlement ever accepted on L1 (use --phase prelaunch before go-live)')
    else:
        if phase == 'prelaunch':
            r.add('phase', WARN, 'settlements exist: run with --phase live')
        try:
            age = max(0.0, now - slot_time(int(source['slot'])))
            r.graded('settlement_age', age, p['settlement_age_warn'], p['settlement_age_crit'],
                     f'last settlement (L2 block {int(source["height"]) - 1}) accepted about {minutes(age)} ago '
                     f'(source slot {source["slot"]})')
        except (KeyError, TypeError, ValueError):
            r.add('settlement_age', WARN, 'getl2settlement.source has no slot')
    return with_l2


def check_escrow_and_backlog(nodes: List[Dict[str, Any]], p: Dict[str, Any], r: Report) -> None:
    if not nodes:
        return
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
        # Every minted wei came from an escrowed deposit; claims only return withdrawn (burned out of L2
        # supply) value. So deposits = escrow + released >= minted - burned, and the escrow alone must
        # cover what is still on L2 plus what was withdrawn but not yet claimed.
        backing = (escrow + released) * ATOM_SCALE
        need = ledger['minted_wei'] - ledger['burned_wei']
        outstanding = ledger['minted_wei'] - ledger['burned_wei'] - ledger['withdrawn_wei']
        r.facts['l2_outstanding_wei'] = outstanding
        r.facts['reserve_ratio'] = round(escrow * ATOM_SCALE / outstanding, 6) if outstanding > 0 else None
        if backing < need:
            r.add('escrow_backing', CRIT, f'(escrow + released) {backing} wei < L2 minted - burned {need} wei',
                  backing_wei=backing, minted_minus_burned_wei=need)
        else:
            r.add('escrow_backing', OK, f'escrow {escrow / 1e8:.8f} + released {released / 1e8:.8f} BLCH covers L2 '
                                        f'minted - burned {need / 1e18:.8f} BLCH (L2 outstanding '
                                        f'{outstanding / 1e18:.8f})')
        if released * ATOM_SCALE > ledger['withdrawn_wei']:
            r.add('claims_vs_withdrawn', CRIT, f'L1 released {released} sat > L2 withdrawn {ledger["withdrawn_wei"]} wei')
        else:
            r.add('claims_vs_withdrawn', OK, 'L1 released <= L2 withdrawn')
    escrows = {str((n['l2'].get('inbox') or {}).get('escrow_sat')) for n in nodes}
    if len(escrows) > 1:
        r.add('escrow_agreement', WARN, f'L1 nodes report different escrow: {sorted(escrows)}')
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
        r.add('release_window', WARN if remaining == 0 else OK,
              f'release window {window.get("window")}: {remaining / 1e8:.8f} BLCH '
              f'of {int(window.get("cap_sat", 0)) / 1e8:.8f} remaining')


# --------------------------------------------------------------------------------------------- L2
def read_backend(client: Client, name: str, url: str, p: Dict[str, Any], r: Report) -> Optional[Dict[str, Any]]:
    tag = f'[{name}]'
    try:
        chain_id = qty(client.call(url, 'eth_chainId'))
        blocks = {t: client.call(url, 'eth_getBlockByNumber', [t, False]) for t in ('latest', 'safe', 'finalized')}
    except (RpcError, ValueError) as e:
        r.add(f'l2_rpc{tag}', CRIT, f'L2 RPC unreachable or malformed: {e}')
        return None
    if chain_id != p['chain_id']:
        r.add(f'l2_rpc{tag}', CRIT, f'{url}: chain id {chain_id} != expected {p["chain_id"]}', value=chain_id)
        return None
    latest = blocks['latest']
    if not isinstance(latest, dict):
        r.add(f'l2_rpc{tag}', CRIT, f'{url}: no latest block')
        return None
    try:
        num = {t: (qty(b['number']) if isinstance(b, dict) else None) for t, b in blocks.items()}
        ts = {t: (qty(b['timestamp']) if isinstance(b, dict) else None) for t, b in blocks.items()}
    except (KeyError, ValueError) as e:
        r.add(f'l2_rpc{tag}', CRIT, f'{url}: malformed block: {e}')
        return None
    hashes = {t: (strip0x(b.get('hash')) if isinstance(b, dict) else None) for t, b in blocks.items()}
    r.add(f'l2_rpc{tag}', OK, f'{url} answers: chain {chain_id}, latest {num["latest"]}, safe {num["safe"]}, '
                              f'finalized {num["finalized"]}')
    ordered = [n for n in (num['finalized'], num['safe'], num['latest']) if n is not None]
    if ordered != sorted(ordered):
        r.add(f'l2_tag_order{tag}', CRIT, f'tags out of order: finalized {num["finalized"]} safe {num["safe"]} '
                                          f'latest {num["latest"]}')
    if p['chain_id'] == 700770:
        bad = [t for t in blocks if num[t] == 0 and hashes[t] != MAINNET_PINS['l2_genesis_hash']]
        if bad:
            r.add(f'l2_genesis{tag}', CRIT, f'block 0 hash {hashes[bad[0]]} is not the pinned L2 genesis')
    try:
        finality = client.call(url, 'bloch_finality')
    except RpcError as e:
        r.add(f'l2_finality_view{tag}', WARN, f'bloch_finality unavailable: {e}')
        finality = None
    return {'name': name, 'url': url, 'num': num, 'ts': ts, 'hash': hashes, 'finality': finality,
            'base_fee': qty(latest.get('baseFeePerGas', '0x0'))}


def check_l2(client: Client, backends: List[Tuple[str, str]], p: Dict[str, Any], phase: str, now: float,
             r: Report) -> List[Dict[str, Any]]:
    views = [v for v in (read_backend(client, n, u, p, r) for n, u in backends) if v]
    if not backends:
        r.add('l2_backends', UNKNOWN, 'no L2 RPC configured')
        return views
    level = OK if len(views) == len(backends) else (CRIT if not views else WARN)
    r.add('l2_backends', level, f'{len(views)}/{len(backends)} L2 RPC backends healthy')
    if not views:
        return views
    if len(views) > 1:
        check_backend_agreement(views, p, r)
    best = max(views, key=lambda v: (v['num']['finalized'] or -1, v['num']['latest']))
    num, ts = best['num'], best['ts']
    r.facts.update({'l2_latest': num['latest'], 'l2_safe': num['safe'], 'l2_finalized': num['finalized'],
                    'l2_latest_timestamp': ts['latest'], 'l2_base_fee_wei': best['base_fee'],
                    'l2_primary_backend': best['name']})
    at_genesis = num['latest'] == 0
    if at_genesis and phase == 'prelaunch':
        r.add('l2_head_age', OK, 'pre-launch: the L2 head is the pinned genesis')
    else:
        age = max(0.0, now - ts['latest'])
        r.graded('l2_head_age', age, p['head_age_warn'], p['head_age_crit'],
                 f'latest L2 block {num["latest"]} is {minutes(age)} old')
    if num['safe'] is None:
        r.add('l2_safe', WARN, 'no safe L2 block (RPC without a follower status, or nothing settled)')
    else:
        r.graded('l2_unsafe_depth', num['latest'] - num['safe'], p['unsafe_depth_warn'], p['unsafe_depth_crit'],
                 f'latest - safe = {num["latest"] - num["safe"]} blocks (0-1 is normal: the block being proved)')
    if num['finalized'] is None:
        r.add('l2_finalized', WARN, 'no finalized L2 block (follower status missing or stale)')
    elif num['finalized'] == 0 and phase == 'prelaunch':
        r.add('l2_finalized_age', OK, 'pre-launch: finalized = the pinned L2 genesis')
    else:
        age = max(0.0, now - ts['finalized'])
        r.graded('l2_finalized_age', age, p['finalized_age_warn'], p['finalized_age_crit'],
                 f'finalized L2 block {num["finalized"]} is {minutes(age)} old, '
                 f'{num["latest"] - num["finalized"]} behind latest')
    try:
        r.facts['l2_ledger'] = {name: qty(client.call(best['url'], 'eth_getStorageAt', [SUPPLY_LEDGER, slot, 'latest']))
                                for name, slot in (('minted_wei', SLOT_MINTED), ('burned_wei', SLOT_BURNED),
                                                   ('withdrawn_wei', SLOT_WITHDRAWN))}
    except (RpcError, ValueError) as e:
        r.add('l2_ledger', WARN, f'supply ledger unreadable: {e}')
    return views


def check_backend_agreement(views: List[Dict[str, Any]], p: Dict[str, Any], r: Report) -> None:
    problems = []
    for t in ('latest', 'safe', 'finalized'):
        by_num: Dict[int, set] = {}
        for v in views:
            if v['num'][t] is not None:
                by_num.setdefault(v['num'][t], set()).add(v['hash'][t])
        for n, hs in by_num.items():
            if len(hs) > 1:
                problems.append(f'{t} block {n} differs between backends')
    if problems:
        r.add('l2_backends_agree', CRIT, '; '.join(problems))
        return
    fins = [v['num']['finalized'] for v in views if v['num']['finalized'] is not None]
    spread = (max(fins) - min(fins)) if fins else 0
    r.graded('l2_backends_agree', spread, p['l2_backend_spread_warn'], p['l2_backend_spread_crit'],
             f'backends agree on every common block; finalized spread {spread}')


def follower_lag(name: str, verified_blocks: Any, own_epoch: Any, l1_up: List[Dict[str, Any]], p: Dict[str, Any],
                 r: Report, source: str) -> None:
    if not l1_up:
        return
    l1_fin_h = max(n['finalized_height'] for n in l1_up)
    l1_fin_e = max(n['finalized_epoch'] for n in l1_up)
    if verified_blocks is None:
        r.add(f'follower_verified_lag[{name}]', WARN, f'{source} reports no verified_blocks')
    else:
        lag = max(0, l1_fin_h - int(verified_blocks))
        r.graded(f'follower_verified_lag[{name}]', lag, p['follower_lag_blocks_warn'], p['follower_lag_blocks_crit'],
                 f'{source}: verified {verified_blocks} L1 blocks, L1 finalized height {l1_fin_h} ({lag} behind)')
    if own_epoch is None:
        r.add(f'follower_epoch_lag[{name}]', WARN, f'{source} reports no FFG-finalized epoch')
    else:
        lag = l1_fin_e - int(own_epoch)
        r.graded(f'follower_epoch_lag[{name}]', lag, p['follower_epoch_lag_warn'], p['follower_epoch_lag_crit'],
                 f'{source}: own FFG-finalized epoch {own_epoch}, L1 finalized {l1_fin_e} ({lag} behind; '
                 f'{p["follower_epoch_lag_expected"]} is structural)', expected=p['follower_epoch_lag_expected'])


STATUS_BYTES_PER_SETTLEMENT = 555  # measured on a real follower status, schema v2


def status_size(name: str, path: str, s: Dict[str, Any], p: Dict[str, Any], r: 'Report') -> None:
    """Schema v2 repeats every settlement in the status file, and a settled RPC before the next build stops
    advancing finality above 16 MiB of it. Schema v3 stays small; its log must hold what the status names."""
    size = Path(path).stat().st_size
    log = s.get('settlement_log')
    if isinstance(log, dict):
        count, detail = s.get('finalized_settlements_count'), 'schema v3'
        try:
            on_disk = Path(path).with_name(str(log.get('file'))).stat().st_size
        except OSError as e:
            r.add(f'follower_settlement_log[{name}]', CRIT, f'{e}')
        else:
            if on_disk < int(log.get('bytes', 0)):
                r.add(f'follower_settlement_log[{name}]', CRIT,
                      f'{on_disk} bytes on disk, the status names {log.get("bytes")}')
            else:
                r.add(f'follower_settlement_log[{name}]', OK, f'{log.get("entries")} settlements, {on_disk} bytes')
    else:
        count = len(s.get('finalized_settlements') or [])
        left = max(0, 16 * 1_048_576 - size) // STATUS_BYTES_PER_SETTLEMENT
        detail = f'schema v2, about {left} settlements before a settled RPC older than the next build stops finality'
    r.graded(f'follower_status_size[{name}]', size, p['status_bytes_warn'], p['status_bytes_crit'],
             f'{path} is {size} bytes with {count} settlements ({detail})')


def check_followers(views: List[Dict[str, Any]], statuses: List[str], l1_up: List[Dict[str, Any]],
                    p: Dict[str, Any], now: float, r: Report) -> None:
    for v in views:
        f = v.get('finality')
        if not isinstance(f, dict):
            continue
        l1 = f.get('l1') or {}
        follower_lag(v['name'], l1.get('verified_blocks'), (l1.get('finalized') or {}).get('epoch'), l1_up, p, r,
                     'bloch_finality')
        if f.get('finalized_height') is not None and v['num']['finalized'] is not None \
                and int(f['finalized_height']) != v['num']['finalized']:
            r.add(f'finality_view_consistency[{v["name"]}]', WARN,
                  f'bloch_finality finalized_height {f["finalized_height"]} != tag {v["num"]["finalized"]}')
    for spec in statuses:
        name, path = named(spec, 'follower')
        try:
            s = json.loads(Path(path).read_text())
        except (OSError, ValueError) as e:
            r.add(f'follower_status[{name}]', CRIT, f'{path}: {e}')
            continue
        age = max(0.0, now - float(s.get('written_at_unix', 0)))
        problems = []
        if s.get('chain_id') != p['chain_id']:
            problems.append(f'chain_id {s.get("chain_id")}')
        if p['chain_id'] == 700770 and s.get('network') != MAINNET_PINS['network']:
            problems.append(f'network {s.get("network")}')
        if (s.get('l2_genesis') or {}).get('hash') not in (None, MAINNET_PINS['l2_genesis_hash']) \
                and p['chain_id'] == 700770:
            problems.append('L2 genesis is not the pin')
        if problems:
            r.add(f'follower_status[{name}]', CRIT, f'{path}: ' + ', '.join(problems))
            continue
        r.graded(f'follower_status[{name}]', age, p['status_age_warn'], p['status_age_crit'],
                 f'{path} written {age:.0f} s ago')
        status_size(name, path, s, p, r)
        follower_lag(f'{name}:status', s.get('verified_blocks'), s.get('native_finalized_epoch'), l1_up, p, r,
                     'status.json')


# ------------------------------------------------------------------------------------- attestors
ATTESTATION_DOMAIN = b'BLOCH:L2:WITHDRAW-ATTEST:1'  # attestor/attestor_lib.py


# funded::ADMISSION_PQ_SIGNATURE_MAX, the consensus bound on each attestor signature inside a claim.
ATTESTOR_SIGNATURE_MAX = 4593


def partial_ok(data: bytes, index: int, chain_id: int, root: str) -> bool:
    """Shape and digest of an `l2-claim attest` partial (index, digest, signature lines). The signature
    itself is verified natively by aggregate_attestation.py; here a partial only counts as a vote. A
    signature above the claim's bound can never be used in a claim, so it is not a vote."""
    try:
        lines = [x.strip() for x in data.decode().splitlines() if x.strip()]
        if len(lines) != 3 or int(lines[0]) != index or not 2000 <= len(bytes.fromhex(lines[2])) <= ATTESTOR_SIGNATURE_MAX:
            return False
        digest = hashlib.sha3_256(ATTESTATION_DOMAIN + bytes.fromhex(MAINNET_PINS['network'])
                                  + chain_id.to_bytes(8, 'big') + bytes.fromhex(root)).hexdigest()
        return lines[1].lower() == digest
    except (ValueError, UnicodeDecodeError):
        return False


def check_attestors(drops: List[str], with_l2: List[Dict[str, Any]], p: Dict[str, Any], fetch: Fetcher,
                    r: Report) -> None:
    """Signatures per round. A round is a retained, FFG-finalized withdrawal root. An agent signs only roots
    covering an unclaimed >= 100 BLCH withdrawal, so a round with no partial at all is not a fault; once
    one attestor signed, every live attestor signs the same root within a cycle or two."""
    if not drops or not with_l2:
        return
    head = max(with_l2, key=lambda n: n['height'])['l2']
    native_height = int(head.get('native_height', 0))
    roots = [x for x in (head.get('withdrawals') or {}).get('roots') or [] if x.get('finalized')]
    n_att, k = p['attestors_n'], p['attestors_k']
    rounds, worst = [], OK
    missing_count: Dict[int, int] = {}
    for rec in roots:
        root = strip0x(rec.get('root'))
        signers = []
        for i in range(n_att):
            rel = f'{p["chain_id"]}/{root}/attestor-{i}.partial'
            for d in drops:
                if d.startswith(('http://', 'https://')):
                    data = fetch(d.rstrip('/') + '/' + rel)
                else:
                    q = Path(d) / rel
                    data = q.read_bytes() if q.is_file() else None
                if data and partial_ok(data, i, p['chain_id'], root):
                    signers.append(i)
                    break
        age_blocks = max(0, native_height - int(rec.get('height', native_height)))
        entry = {'l2_number': rec.get('l2_number'), 'root': root[:16], 'signatures': len(signers),
                 'signers': signers, 'age_blocks': age_blocks}
        rounds.append(entry)
        if signers and age_blocks >= p['attest_grace_blocks']:
            for i in range(n_att):
                if i not in signers:
                    missing_count[i] = missing_count.get(i, 0) + 1
            lvl = CRIT if len(signers) < k else WARN if len(signers) < n_att else OK
            worst = max(worst, lvl, key=lambda c: SEVERITY[c])
    r.facts['attestation_rounds'] = rounds[-10:]
    signed = [x for x in rounds if x['signatures']]
    if not roots:
        r.add('attestors', OK, 'no finalized withdrawal root yet: nothing to sign')
        return
    msg = (f'{len(signed)}/{len(roots)} finalized withdrawal roots signed; last signed round: '
           f'{signed[-1]["signatures"]}/{n_att} signatures' if signed else
           f'none of {len(roots)} finalized withdrawal roots carries a partial (normal unless a >= 100 BLCH '
           f'withdrawal exists)')
    if missing_count:
        msg += '; silent attestors (rounds missed): ' + ', '.join(f'#{i} ({c})' for i, c in sorted(missing_count.items()))
    r.add('attestors', worst, msg, threshold=k, n=n_att)


# ---------------------------------------------------------------------------- units, logs, files
def parse_events(text: str, since: float) -> List[Dict[str, Any]]:
    events = []
    for line in text.splitlines():
        line = line.strip()
        start = line.find('{')
        if start < 0:
            continue
        try:
            ev = json.loads(line[start:])
        except ValueError:
            continue
        if not isinstance(ev, dict) or 'event' not in ev:
            continue
        t = ev.get('time')
        if isinstance(t, str):
            try:
                ts = datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
                if ts < since:
                    continue
                ev['_ts'] = ts
            except ValueError:
                pass
        events.append(ev)
    return events


def grade_events(name: str, events: List[Dict[str, Any]], p: Dict[str, Any], window: float, r: Report) -> None:
    counts: Dict[str, int] = {}
    level = OK
    last_bad = None
    for ev in events:
        e = ev['event']
        if e == 'remote-proof' and ev.get('exit_code') not in (0, None):
            e = 'prover-failed'
        if e in CRIT_EVENTS or e in WARN_EVENTS:
            counts[e] = counts.get(e, 0) + 1
            last_bad = ev
            lvl = CRIT if e in CRIT_EVENTS or counts[e] >= p['event_repeat_crit'] else WARN
            level = max(level, lvl, key=lambda c: SEVERITY[c])
    progress = [ev for ev in events if ev['event'] in PROGRESS_EVENTS]
    r.facts[f'events[{name}]'] = {'failures': counts, 'last_progress': progress[-1]['event'] + ' ' +
                                  str(progress[-1].get('time')) if progress else None}
    if counts:
        detail = ', '.join(f'{e} x{c}' for e, c in sorted(counts.items()))
        reason = (last_bad or {}).get('reason') or (last_bad or {}).get('error') or ''
        r.add(f'events[{name}]', level, f'last {window / 60:.0f} min: {detail}' + (f'; last: {str(reason)[:200]}' if reason else ''))
    else:
        r.add(f'events[{name}]', OK, f'no failure event in the last {window / 60:.0f} min '
                                     f'({len(events)} events, {len(progress)} progress)')


def check_units(specs: List[str], p: Dict[str, Any], now: float, run_cmd: Runner, r: Report) -> None:
    window = p['event_window_seconds']
    for spec in specs:
        name, unit = named(spec, '')
        name = name or unit
        code, out = run_cmd(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState',
                             '-p', 'NRestarts', '-p', 'ExecMainStatus', '-p', 'Result'])
        props = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
        if code != 0 or props.get('LoadState') in (None, 'not-found'):
            r.add(f'unit[{name}]', CRIT, f'{unit}: not installed or unreadable')
            continue
        state = f'{props.get("ActiveState")}/{props.get("SubState")}'
        restarts = int(props.get('NRestarts') or 0)
        if props.get('ActiveState') == 'active':
            lvl = WARN if restarts >= p['event_repeat_crit'] else OK
            r.add(f'unit[{name}]', lvl, f'{unit} {state}, {restarts} restarts')
        else:
            status = props.get('ExecMainStatus')
            why = ' (exit 3 = halt: operator review, no auto-restart)' if status == '3' else ''
            r.add(f'unit[{name}]', CRIT, f'{unit} {state}, result {props.get("Result")}, exit {status}{why}')
        code, out = run_cmd(['journalctl', '-u', unit, '-o', 'cat', '--no-pager', '-q',
                             '--since', f'@{int(now - window)}'])
        if code == 0:
            grade_events(name, parse_events(out, now - window), p, window, r)


def check_event_logs(specs: List[str], p: Dict[str, Any], now: float, r: Report) -> None:
    window = p['event_window_seconds']
    for spec in specs:
        name, path = named(spec, 'log')
        try:
            with open(path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 2 * 1024 * 1024))
                text = f.read().decode(errors='replace')
        except OSError as e:
            r.add(f'events[{name}]', CRIT, f'{path}: {e}')
            continue
        grade_events(name, parse_events(text, now - window), p, window, r)


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


def check_guardian_health(specs: List[str], p: Dict[str, Any], now: float, r: Report) -> None:
    """The bridge guardian's `health_file` (guardiao.py): alive, not reporting a problem, and still able to verify."""
    for spec in specs:
        name, _, rest = spec.partition('=')
        path, _, limit = rest.partition(':')
        warn = float(limit) if limit else p['guardian_age_warn']
        crit = warn * 3
        try:
            doc = json.loads(Path(path).read_text())
            if not isinstance(doc, dict):
                raise ValueError('not an object')
            written = float(doc['t'])
        except (OSError, ValueError, KeyError, TypeError) as e:
            r.add(f'guardian[{name}]', CRIT, f'{path}: {type(e).__name__}: {e}')
            continue
        r.graded(f'guardian_age[{name}]', max(0.0, now - written), warn, crit, f'{path} written {now - written:.0f} s ago')
        problems = doc.get('problems')
        ids = ', '.join(sorted(str(k) for k in problems)) if isinstance(problems, dict) else ''
        if doc.get('healthy') is True:
            r.add(f'guardian[{name}]', OK, 'healthy')
        else:
            r.add(f'guardian[{name}]', CRIT, f'unhealthy: {ids or "no problem listed"}')
        verified = doc.get('verified_t')
        if not isinstance(verified, (int, float)) or isinstance(verified, bool):
            r.add(f'guardian_verified[{name}]', CRIT, 'no round has verified the bridge yet')
        else:
            r.graded(f'guardian_verified[{name}]', max(0.0, now - verified), warn, crit,
                     f'last verified round {now - verified:.0f} s ago')


def check_binaries(paths: List[str], r: Report) -> None:
    for path in paths:
        name = Path(path).name
        want = V2_SHA256.get(name)
        try:
            got = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError as e:
            r.add(f'binary[{name}]', CRIT, f'{path}: {e}')
            continue
        if want is None:
            r.add(f'binary[{name}]', WARN, f'{path}: no v2 pin for this name (sha256 {got[:16]})')
        elif got != want:
            r.add(f'binary[{name}]', CRIT, f'{path}: sha256 {got[:16]}... is not the v2 pin {want[:16]}...')
        else:
            r.add(f'binary[{name}]', OK, f'{path} = v2 pin {want[:8]}')


# ----------------------------------------------------------------------------------------- alerts
def configured(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and 'TBD' not in value


def alert_text(profile: str, r: Report, min_level: int) -> str:
    lines = [f'BLOCH L2 {profile}: {LEVEL_NAMES[r.status]} ({utc(r.facts.get("checked_at", time.time()))})']
    for c in r.checks:
        if SEVERITY[c['code']] >= SEVERITY[min_level]:
            lines.append(f'{c["level"]} {c["check"]}: {c["message"]}')
    return '\n'.join(lines)[:3800]


def decide_alert(r: Report, state: Dict[str, Any], now: float, realert: float, min_level: int) -> Optional[str]:
    """Returns 'raise', 'recover' or None. Alerts on a new or worse check, a recovery, or every `realert`
    seconds while something is still at or above min_level."""
    current = {c['check']: c['code'] for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]}
    previous = {k: LEVEL_CODES[v] for k, v in (state.get('bad') or {}).items()}
    if current:
        worse = any(SEVERITY[c] > SEVERITY[previous.get(k, OK)] for k, c in current.items())
        if worse or now - float(state.get('sent_at', 0)) >= realert:
            return 'raise'
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


def handle_alerts(args: argparse.Namespace, r: Report, now: float, sender=send_alert) -> Optional[str]:
    if not args.alert_config:
        return None
    cfg = json.loads(Path(args.alert_config).read_text())
    min_level = LEVEL_CODES[cfg.get('min_level', 'WARN')]
    state_path = Path(cfg.get('state_file') or args.alert_config + '.state')
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    decision = decide_alert(r, state, now, float(cfg.get('realert_seconds', 3600)), min_level)
    if decision is None:
        return None
    text = alert_text(args.profile, r, min_level) if decision == 'raise' else \
        f'BLOCH L2 {args.profile}: RECOVERED, status {LEVEL_NAMES[r.status]} ({utc(now)})'
    payload = {'status': LEVEL_NAMES[r.status], 'event': decision,
               'checks': [c for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]]}
    try:
        sent = sender(cfg, text, payload, args.timeout, args.alert_dry_run)
    except Exception as e:  # noqa: BLE001 - an alert failure never hides the report
        r.add('alert_delivery', WARN, f'alert not delivered: {e}')
        return decision
    if not sent:
        r.add('alert_delivery', WARN, 'alert due but no target configured (webhook_url / telegram are TBD-owner)')
    if not args.alert_dry_run:
        bad = {c['check']: c['level'] for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]}
        tmp = state_path.with_suffix('.tmp')
        tmp.write_text(json.dumps({'bad': bad, 'sent_at': now if sent else state.get('sent_at', 0)}))
        os.replace(tmp, state_path)
    r.facts['alert'] = {'decision': decision, 'sent': sent}
    return decision


# -------------------------------------------------------------------------------------------- run
def thresholds(args: argparse.Namespace) -> Dict[str, Any]:
    p = dict(PROFILES[args.profile])
    for item in args.set or []:
        key, _, value = item.partition('=')
        if key not in p:
            raise SystemExit(f'unknown threshold {key}')
        p[key] = type(p[key])(float(value)) if isinstance(p[key], int) else float(value)
    return p


def compiled_gates(args: argparse.Namespace) -> Dict[str, Any]:
    if args.build_json:
        return json.loads(Path(args.build_json).read_text()).get('l1_activation_epochs') or {}
    return V2_COMPILED_GATES if args.profile == 'mainnet' else {}


def run(args: argparse.Namespace, transport: Transport, now: Optional[float] = None,
        run_cmd: Runner = subprocess_runner, fetch: Optional[Fetcher] = None) -> Report:
    now = time.time() if now is None else now
    p = thresholds(args)
    client = Client(transport)
    r = Report()
    r.facts.update({'profile': args.profile, 'phase': args.phase, 'checked_at': int(now)})
    backends = [named(s, f'rpc{i}') for i, s in enumerate(args.l2_rpc or [])]
    views = check_l2(client, backends, p, args.phase, now, r)
    l1_up = check_l1(client, args.l1_rpc or [], p, r)
    with_l2 = check_settlement(l1_up, p, args.phase, now, r)
    check_escrow_and_backlog(with_l2, p, r)
    check_followers(views, args.follower_status or [], l1_up, p, now, r)
    check_gates(l1_up, p, compiled_gates(args), now, r)
    check_attestors(args.attest_drop or [], with_l2, p, fetch or http_fetcher(args.timeout), r)
    check_units(args.unit or [], p, now, run_cmd, r)
    check_event_logs(args.event_log or [], p, now, r)
    check_files(args.file or [], p, now, r)
    check_guardian_health(args.guardian_health or [], p, now, r)
    check_binaries(args.binary or [], r)
    return r


def parse(argv: List[str]) -> argparse.Namespace:
    a = argparse.ArgumentParser(description='Read-only Bloch L2 health monitor (no keys, no chain writes).')
    a.add_argument('--profile', choices=sorted(PROFILES), default='mainnet')
    a.add_argument('--phase', choices=('prelaunch', 'live'), default='live',
                   help='prelaunch: an L2 at its pinned genesis with no settlement is expected, not an alert')
    a.add_argument('--l2-rpc', action='append', help='[NAME=]URL of a settled-RPC backend; repeat for each')
    a.add_argument('--l1-rpc', action='append', help='L1 bloch-pos RPC URL; repeat for each node')
    a.add_argument('--follower-status', action='append', help='[NAME=]PATH of a native follower status.json')
    a.add_argument('--attest-drop', action='append', help='attestation drop: directory or http(s) base URL')
    a.add_argument('--unit', action='append', help='[NAME=]UNIT: systemd state + journal failure events')
    a.add_argument('--event-log', action='append', help='[NAME=]PATH of a JSON-lines log (settler, shadow, ...)')
    a.add_argument('--file', action='append', help='NAME=PATH[:MAX_AGE_S] heartbeat file to age-check')
    a.add_argument('--guardian-health', action='append',
                   help='NAME=PATH[:MAX_AGE_S] health_file of a bridge guardian (WARN above MAX_AGE_S, CRIT above 3x)')
    a.add_argument('--binary', action='append', help='PATH of an installed binary to compare with the v2 pins')
    a.add_argument('--build-json', help='build.json of the L2 build (default: the v2 pins compiled in)')
    a.add_argument('--set', action='append', help='override a threshold, KEY=VALUE')
    a.add_argument('--alert-config', help='JSON: webhook_url, telegram{bot_token_file,chat_id}, min_level, ...')
    a.add_argument('--alert-dry-run', action='store_true', help='decide and print alerts, send nothing')
    a.add_argument('--timeout', type=float, default=8.0)
    a.add_argument('--json', action='store_true')
    return a.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse(sys.argv[1:] if argv is None else argv)
    now = time.time()
    r = run(args, http_transport(args.timeout), now=now)
    handle_alerts(args, r, now)
    if args.json:
        print(json.dumps({'status': LEVEL_NAMES[r.status], 'facts': r.facts, 'checks': r.checks}, indent=2,
                         default=str))
    else:
        print(f'BLOCH L2 {args.profile} ({args.phase}): {LEVEL_NAMES[r.status]}  {utc(now)}')
        for c in r.checks:
            print(f'  {c["level"]:<7} {c["check"]:<34} {c["message"]}')
        if r.facts.get('l1_gates_upcoming'):
            print('  gates: ' + ', '.join(f'{g["gate"]}@e{g["epoch"]} ({g["at"]})' for g in r.facts['l1_gates_upcoming']))
        if r.facts.get('alert'):
            print(f'  alert: {r.facts["alert"]}')
    return r.status


if __name__ == '__main__':
    sys.exit(main())
