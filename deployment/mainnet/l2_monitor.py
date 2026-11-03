#!/usr/bin/env python3
"""Read-only health monitor for the Bloch L2 mainnet (chain id 700770; devnet4 700771).

Runbook: docs/MAINNET-OPS-RUNBOOK.md. Build: the next L2 build, provisional and unsigned (L2 926d2cf5, native
78d4921c, follower cdf5da5c, produce-dev e3f1a290, settled-rpc 53e88565).

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
    'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getStorageAt', 'bloch_finality', 'bloch_settlement',
    # L1 (bloch-pos)
    'getchaininfo', 'getblockcount', 'getl2settlement', 'getutxos',
    # Only with --l1-stuck-node.
    'getblockbyid',
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
    'l2_commit': '926d2cf50af11f389ad1ffa91c0b7720178b3472',
    'native': '78d4921c3ec6ba41829f3878eed47f8d3bb96230',
    'native_lock_sha256': 'a3c38a462a273fc07b618ebb2a6dda51377ea7d2deb8530c44a17bc4bf3908a9',
}
V2_SHA256 = {
    'bloch-l2-native-follower': 'cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2',
    'bloch-l2-produce-dev': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
    'bloch-l2-settled-rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d',
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

FINALITY_CLOSED_CODE = -32001  # bloch-l2-settled-rpc: safe and finalized refused without a valid follower status
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
    # --max-idle-seconds: how long deposits may wait with no consumption. Two proofs after an idle stretch.
    'deposit_wait_warn': 45 * 60, 'deposit_wait_crit': 90 * 60,
    'da_backlog_warn': 3, 'da_backlog_crit': 10,
    'file_age_warn': 120, 'file_age_crit': 600,
    'guardian_age_warn': 300,
    'status_age_warn': 300, 'status_age_crit': 900,
    # Height runways. Export: the producer refuses to export a block above this (None: no such limit in this build).
    'l2_export_limit': None, 'l2_export_warn': 1024, 'l2_export_crit': 3000,
    # Native blocks one `reconstruct` reads: attestor rebuilds, replica refresh and foreign recovery stop above it.
    'l1_reconstruct_limit': 5000000,
    # Cost of an empty block by height, measured on guest 203114bf. Above the first figure the local fallback is gone;
    # the others are what has been proved at the planned limits.
    'proof_instructions_local': 3_000_000,
    # l2_proof_cost grades the measured proof time (settler `proof-generated` seconds) against the block interval the
    # operator configures (--set block_interval_seconds=N; 0: not set, the check then only reports). The empty-block
    # instruction model is shown in the message as context, not graded.
    'block_interval_seconds': 0, 'proof_time_warn_ratio': 0.7, 'proof_time_crit_ratio': 1.0,
    # Settlements the follower file has and an RPC's finalized_height has not. One can be a poll in flight.
    'finality_file_lag_warn': 1, 'finality_file_lag_crit': 3,
    # A settled RPC before the next build closes safe and finalized above 16 MiB of status file.
    'status_bytes_warn': 8 * 1_048_576, 'status_bytes_crit': 12 * 1_048_576,
    # Runway to that limit: replacing the RPC needs a signed build and a rollout, so the warning comes months ahead.
    'status_runway_days_warn': 120, 'status_runway_days_crit': 45,
    'status_settlements_warn': 15_000, 'status_settlements_crit': 22_500,
    'gate_warn_epochs': 96, 'gate_crit_epochs': 6,
    'attestors_n': 5, 'attestors_k': 3, 'attest_grace_blocks': 120,
    'event_window_seconds': 3600, 'event_repeat_crit': 5,
    'foreign_window_seconds': 86400, 'foreign_recovered_crit': 2,
    'l2_backend_spread_warn': 2, 'l2_backend_spread_crit': 8,
    # SETTLER-RUNBOOK: the worker logs da-funding-low below 1 BLCH; 0.1 BLCH is about 5 full batches at 100x the floor.
    'da_balance_warn_sat': 100_000_000, 'da_balance_crit_sat': 10_000_000,
    'mem_avail_pct_warn': 15.0, 'mem_avail_pct_crit': 7.0, 'swap_used_pct_warn': 50.0,
    'report_age_warn': 900.0, 'l1_stall_warn_s': 600.0, 'l1_stall_crit_s': 1800.0,
    'disk_free_pct_warn': 15.0, 'disk_free_pct_crit': 5.0, 'disk_free_gib_warn': 20.0, 'disk_free_gib_crit': 5.0,
    # --l1-stuck-node: docs/L1-STUCK-NODE-RUNBOOK.md. Epochs are finalized epochs gained by the reference.
    'stuck_sustain_epochs': 3, 'stuck_parked_min': 32, 'stuck_min_samples': 3, 'stuck_max_gap_epochs': 2,
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
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code


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
            error = reply['error']
            raise RpcError(f'{method} at {url}: {error}', error.get('code') if isinstance(error, dict) else None)
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
            node['block_id'] = info.get('block_id')
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


# ------------------------------------------------------------------------------- L1 node on its own branch
# The next two functions are identical to those in l1_stuck_check.py; test_l2_monitor.py fails if they differ.
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


def check_l1_stuck(client: Client, specs: List[str], state_path: Optional[str], l1_up: List[Dict[str, Any]],
                   p: Dict[str, Any], fetch: Fetcher, r: Report) -> None:
    """--l1-stuck-node NAME=RPC_URL[,METRICS_URL]: nothing is called without this option."""
    if not specs:
        return
    if not state_path:
        r.add('l1_stuck', UNKNOWN, '--l1-stuck-node needs --l1-stuck-state: nothing steady can be seen without it')
        return
    try:
        state = json.loads(Path(state_path).read_text())
        state = state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        state = {}
    for i, spec in enumerate(specs):
        name, rest = named(spec, f'node{i}')
        url, _, metrics = rest.partition(',')
        refs = [n for n in l1_up if n['url'] != url and n.get('block_id')]
        ref = max(refs, key=lambda n: n['finalized_epoch']) if refs else None
        s: Dict[str, Any] = {'ref_finalized': ref['finalized_epoch'] if ref else None}
        try:
            own = client.call(url, 'getchaininfo')
            s['finalized'] = int(own['finalized']['epoch'])
        except (RpcError, KeyError, TypeError, ValueError):
            s['down'] = True
        if not s.get('down'):
            raw = fetch(metrics) if metrics else None
            text = raw.decode(errors='replace') if raw else None
            s.update(parked=stuck_metric(text, 'bloch_pos_blocks_parked'),
                     peers=stuck_metric(text, 'bloch_pos_peer_count'), has_ref_head=None)
            if ref:
                try:
                    s['has_ref_head'] = bool(client.call(url, 'getblockbyid', [ref['block_id']]))
                except RpcError as e:
                    s['has_ref_head'] = False if 'no block' in str(e) else None
        state[name], level, message = stuck_step(state.get(name), s, p)
        r.add(f'l1_stuck[{name}]', level, message)
    try:
        tmp = f'{state_path}.tmp'
        Path(tmp).write_text(json.dumps(state))
        os.replace(tmp, state_path)
    except OSError as e:
        r.add('l1_stuck_state', WARN, f'cannot keep the state file, so nothing steady can be seen: {e}')


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


def statement_l2_number(accepted: Any) -> Optional[int]:
    """The L2 number of an accepted statement. source.height is an L1 count and differs from it once L1 moves on."""
    try:
        raw = bytes.fromhex(accepted['statement'])
        return int.from_bytes(raw[22 + 264:22 + 272], 'big') if len(raw) >= 22 + 272 else None
    except (KeyError, TypeError, ValueError):
        return None


PROOF_BASE_INSTRUCTIONS = 2_000_000
PROOF_INSTRUCTIONS_PER_BLOCK = 27_660
PROOF_RING_BLOCKS = 8_191  # the EIP-4788 ring: every block hydrates its whole storage, 2 slots per block until it wraps


def empty_block_instructions(height: int) -> int:
    """Guest instructions of an empty block at L2 height `height`, fitted to execute runs at 256 to 16,384."""
    return PROOF_BASE_INSTRUCTIONS + PROOF_INSTRUCTIONS_PER_BLOCK * min(height, PROOF_RING_BLOCKS)


def check_height_runway(settled: Optional[int], l1_up: List[Dict[str, Any]], p: Dict[str, Any], r: 'Report') -> None:
    """Limits that depend on height alone, well before they stop anything."""
    if isinstance(settled, int):
        limit = p['l2_export_limit']
        if limit is not None:
            r.graded('l2_export_runway', settled, p['l2_export_warn'], p['l2_export_crit'],
                     f'L2 block {settled}: this build refuses to export above {limit}, and settlement stops there. A fixed '
                     f'producer must be rolled out first ({limit - settled} blocks left)', limit=limit)
        r.facts['l2_proof_model_instructions'] = empty_block_instructions(settled)
    if l1_up:
        height = max(n['height'] for n in l1_up)
        limit = p['l1_reconstruct_limit']
        r.graded('l1_reconstruct_runway', height, limit * 4 // 5, limit * 19 // 20,
                 f'L1 height {height}: `reconstruct` refuses a follower store above {limit} blocks (attestor rebuild, replica '
                 'refresh, foreign recovery)', limit=limit)


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
    settled = statement_l2_number(accepted)
    r.facts['l2_settled_number'] = settled
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
                     f'last settlement (L2 block {settled}) accepted about {minutes(age)} ago '
                     f'(source slot {source["slot"]})')
        except (KeyError, TypeError, ValueError):
            r.add('settlement_age', WARN, 'getl2settlement.source has no slot')
    return with_l2


def check_escrow_and_backlog(nodes: List[Dict[str, Any]], p: Dict[str, Any], r: Report, now: float = 0.0,
                             idle_state: Optional[str] = None) -> None:
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
    if idle_state:
        check_deposit_wait(backlog, int(inbox.get('consumed', 0)), idle_state, p, now, r)
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
def check_finality_status(tag: str, finality: Any, p: Dict[str, Any], r: Report) -> None:
    """bloch_finality.status: the RPC's own view of the follower status. Absent before anything is finalized."""
    status = finality.get('status') if isinstance(finality, dict) else None
    if not isinstance(status, dict):
        return
    state, age = status.get('state'), status.get('age_s')
    if state == 'starting':
        r.add(f'l2_finality_status{tag}', WARN, 'the RPC has not finished its first read of the follower status: levels are closed')
    elif state == 'behind':
        r.add(f'l2_finality_status{tag}', CRIT, f'this database has not reached settlement {status.get("missing_settlement")}, and nothing '
              'was published since this RPC started: safe and finalized are closed. Check the producer or the replica refresh.')
    elif state == 'lagging':
        real = age if isinstance(age, (int, float)) else 0
        r.add(f'l2_finality_status{tag}', CRIT if real >= p['status_age_crit'] else WARN,
              f'this database has not reached settlement {status.get("missing_settlement")} of a status written {real} s ago: '
              'finalized stands at its old level. Check the producer or the replica refresh.')
    elif state != 'ok':
        r.add(f'l2_finality_status{tag}', CRIT, f'follower status is {state}: safe and finalized are closed')
    elif not isinstance(age, (int, float)):
        r.add(f'l2_finality_status{tag}', WARN, 'follower status state ok, no age reported')
    else:
        r.graded(f'l2_finality_status{tag}', age, p['status_age_warn'], p['status_age_crit'],
                 f'follower status written {age} s ago: a growing age means the follower stopped while the RPC '
                 'keeps serving its last finality')


def read_backend(client: Client, name: str, url: str, p: Dict[str, Any], r: Report) -> Optional[Dict[str, Any]]:
    tag = f'[{name}]'
    try:
        chain_id = qty(client.call(url, 'eth_chainId'))
        blocks = {'latest': client.call(url, 'eth_getBlockByNumber', ['latest', False])}
    except (RpcError, ValueError) as e:
        r.add(f'l2_rpc{tag}', CRIT, f'L2 RPC unreachable or malformed: {e}')
        return None
    closed = []
    for t in ('safe', 'finalized'):
        try:
            blocks[t] = client.call(url, 'eth_getBlockByNumber', [t, False])
        except RpcError as e:
            if e.code != FINALITY_CLOSED_CODE:
                r.add(f'l2_rpc{tag}', CRIT, f'L2 RPC unreachable or malformed: {e}')
                return None
            blocks[t] = None
            closed.append(t)
        except ValueError as e:
            r.add(f'l2_rpc{tag}', CRIT, f'L2 RPC unreachable or malformed: {e}')
            return None
    if closed == ['safe']:
        r.add(f'l2_finality_closed{tag}', WARN, f'{url}: safe is closed, finalized stands: the settlement at the L1 head is not '
                                                'in this database, usually a foreign settlement. See foreign_settlements.')
    elif closed:
        r.add(f'l2_finality_closed{tag}', CRIT, f'{url} answers, but {" and ".join(closed)} are closed: it lost a valid '
                                                'follower status. Check the follower and its status file.')
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
    check_finality_status(tag, finality, p, r)
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


# Schema v2 repeats every settlement in the status file. Measured on real binaries (agent 76): 556 bytes each, the
# settled RPC of v2.1 closes safe and finalized at 30,194 settlements, and the next RPC at about 483,000.
STATUS_BYTES_PER_SETTLEMENT = 556
STATUS_V2_LIMIT_V21 = 16 * 1_048_576
STATUS_V2_LIMIT_NEXT = 256 * 1_048_576
SLOT_SECONDS = 30
SETTLEMENT_RATE_WINDOW = 64


def settlement_rate(entries: List[Dict[str, Any]]) -> Optional[float]:
    """Settlements per day over the given entries (oldest first), from their L1 slots. None without two slots apart."""
    slots = [e.get('native_slot') for e in entries[-SETTLEMENT_RATE_WINDOW:] if isinstance(e, dict)]
    slots = [s for s in slots if isinstance(s, int)]
    if len(slots) < 2 or slots[-1] <= slots[0]:
        return None
    return (len(slots) - 1) * 86400 / ((slots[-1] - slots[0]) * SLOT_SECONDS)


def settlement_runway(check: str, count: int, limit_bytes: int, rate: Optional[float], p: Dict[str, Any], now: float,
                      r: 'Report') -> None:
    """How long a schema v2 status can grow before a settled RPC closes safe and finalized, and the date at this rate."""
    limit = limit_bytes // STATUS_BYTES_PER_SETTLEMENT
    left = max(0, limit - count)
    if rate:
        days = left / rate
        when = time.strftime('%Y-%m-%d', time.gmtime(now + days * 86400))
        detail = f'{rate:.1f} settlements a day, {days:.0f} days left, about {when}'
    else:
        days, detail = None, 'no settlement rate yet'
    level = OK
    if count >= p['status_settlements_warn'] * limit // (STATUS_V2_LIMIT_V21 // STATUS_BYTES_PER_SETTLEMENT) \
            or (days is not None and days < p['status_runway_days_warn']):
        level = WARN
    if count >= p['status_settlements_crit'] * limit // (STATUS_V2_LIMIT_V21 // STATUS_BYTES_PER_SETTLEMENT) \
            or (days is not None and days < p['status_runway_days_crit']):
        level = CRIT
    action = '' if level == OK else '; install the next settled RPC, then follower --status-schema v3'
    r.add(check, level, f'{count} of about {limit} settlements a schema v2 status can hold on this RPC ({detail}){action}')


def status_size(name: str, path: str, s: Dict[str, Any], p: Dict[str, Any], now: float, r: 'Report') -> None:
    """Schema v2 repeats every settlement in the status file, and a settled RPC before the next build closes safe and
    finalized above 16 MiB of it. Schema v3 stays small; its log must hold what the status names."""
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
        entries = s.get('finalized_settlements') or []
        count = len(entries)
        left = max(0, STATUS_V2_LIMIT_V21 - size) // STATUS_BYTES_PER_SETTLEMENT
        detail = f'schema v2, about {left} settlements before a settled RPC older than the next build closes finality'
        settlement_runway(f'follower_status_runway[{name}]', count, STATUS_V2_LIMIT_V21, settlement_rate(entries), p, now, r)
    r.graded(f'follower_status_size[{name}]', size, p['status_bytes_warn'], p['status_bytes_crit'],
             f'{path} is {size} bytes with {count} settlements ({detail})')


def rpc_status_runway(client: 'Client', v: Dict[str, Any], p: Dict[str, Any], now: float, r: 'Report') -> None:
    """The same runway from the RPC alone, for a monitor without the follower's file. The settled list is contiguous from
    block 1, so the finalized height is the count. A settled RPC that names the schema is at least the next build."""
    f = v.get('finality')
    height = f.get('finalized_height') if isinstance(f, dict) else None
    status = f.get('status') if isinstance(f, dict) else None
    if not isinstance(height, int) or height < 1 or not isinstance(status, dict):
        return
    schema = status.get('schema') or ''
    if schema.endswith('.v3'):
        r.add(f'l2_status_runway[{v["name"]}]', OK, f'{height} settlements, schema v3 has no size limit')
        return
    entries = []
    for number in (max(1, height - SETTLEMENT_RATE_WINDOW + 1), height):
        try:
            entries.append(client.call(v['url'], 'bloch_settlement', [number]))
        except RpcError:
            entries.append(None)
    rate = None
    if all(isinstance(e, dict) and isinstance(e.get('native_slot'), int) for e in entries) and height > entries[0]['l2_number']:
        elapsed = (entries[1]['native_slot'] - entries[0]['native_slot']) * SLOT_SECONDS
        rate = (height - entries[0]['l2_number']) * 86400 / elapsed if elapsed > 0 else None
    limit = STATUS_V2_LIMIT_NEXT if schema else STATUS_V2_LIMIT_V21
    settlement_runway(f'l2_status_runway[{v["name"]}]', height, limit, rate, p, now, r)


def finality_file_lag(name: str, s: Dict[str, Any], views: List[Dict[str, Any]], p: Dict[str, Any], r: Report) -> None:
    """The follower file's newest settlement against each RPC's finalized_height. `bloch_finality.status.age_s` of a
    settled RPC up to v2.1 stands still while its database lags the file, so that age cannot show this."""
    listed = s.get('finalized_settlements') or s.get('finalized_settlements_recent') or []
    newest = listed[-1].get('l2_number') if listed else 0
    if not isinstance(newest, int):
        r.add(f'finality_file_lag[{name}]', WARN, 'the follower file has no readable newest settlement')
        return
    for v in views:
        f = v.get('finality')
        height = f.get('finalized_height') if isinstance(f, dict) else None
        if height is not None:
            lag = max(0, newest - int(height))
            r.graded(f'finality_file_lag[{name}:{v["name"]}]', lag, p['finality_file_lag_warn'], p['finality_file_lag_crit'],
                     f'follower file settled through L2 block {newest}, {v["name"]} publishes finalized_height {height}',
                     newest=newest, finalized_height=height)


def check_followers(client: 'Client', views: List[Dict[str, Any]], statuses: List[str], l1_up: List[Dict[str, Any]],
                    p: Dict[str, Any], now: float, r: Report) -> None:
    for v in views:
        f = v.get('finality')
        if not isinstance(f, dict):
            continue
        rpc_status_runway(client, v, p, now, r)
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
        status_size(name, path, s, p, now, r)
        follower_lag(f'{name}:status', s.get('verified_blocks'), s.get('native_finalized_epoch'), l1_up, p, r,
                     'status.json')
        finality_file_lag(name, s, views, p, r)


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


# ---------------------------------------------------------------------------- DA funding, disk
def check_da_balance(client: Client, scripts: List[str], l1_up: List[Dict[str, Any]], p: Dict[str, Any],
                     r: Report) -> None:
    """Spendable balance of the DA fee key, read directly: the worker's da-funding-low only fires on a DA batch."""
    for spec in scripts:
        name, script = named(spec, 'da')
        balance = None
        for node in l1_up:
            try:
                answer = client.call(node['url'], 'getutxos', [strip0x(script), 64])
                balance = sum(int(u['value_sat']) for u in answer['utxos'])
                break
            except (RpcError, KeyError, TypeError, ValueError):
                continue
        if balance is None:
            r.add(f'da_balance[{name}]', UNKNOWN, 'no L1 node answered getutxos for the DA funding script')
            continue
        level = CRIT if balance < p['da_balance_crit_sat'] else WARN if balance < p['da_balance_warn_sat'] else OK
        r.add(f'da_balance[{name}]', level, f'DA fee key holds {balance / 1e8:.8f} BLCH (first 64 outputs); '
                                            f'warn below {p["da_balance_warn_sat"] / 1e8:.8f}, '
                                            f'crit below {p["da_balance_crit_sat"] / 1e8:.8f}', value=balance)


def check_disks(specs: List[str], p: Dict[str, Any], r: Report) -> None:
    for spec in specs:
        name, path = named(spec, 'disk')
        try:
            st = os.statvfs(path)
        except OSError as e:
            r.add(f'disk[{name}]', CRIT, f'{path}: {e}')
            continue
        free = st.f_bavail * st.f_frsize
        total = st.f_blocks * st.f_frsize or 1
        pct, gib = 100.0 * free / total, free / 2 ** 30
        level = CRIT if pct < p['disk_free_pct_crit'] or gib < p['disk_free_gib_crit'] else \
            WARN if pct < p['disk_free_pct_warn'] or gib < p['disk_free_gib_warn'] else OK
        r.add(f'disk[{name}]', level, f'{path}: {gib:.1f} GiB free, {pct:.1f}%', value=round(gib, 3))


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


def check_proof_time(p: Dict[str, Any], r: Report) -> None:
    """The slowest proof the settler logged in the event window, against the configured block interval. A proof slower
    than the interval means settlement falls behind block production."""
    cost = r.facts.get('l2_proof_model_instructions')
    model = '' if cost is None else (
        f'; model: an empty block at this height is about {cost / 1e6:.0f}M guest instructions'
        + (f', above {p["proof_instructions_local"] / 1e6:.0f}M the settler has no local fallback, only the remote prover'
           if cost > p['proof_instructions_local'] else ''))
    seconds = r.facts.get('proof_seconds') or []
    interval = p['block_interval_seconds']
    if not seconds:
        if cost is not None or interval:
            r.add('l2_proof_cost', OK, f'no proof-generated event in the window{model}')
        return
    worst = max(seconds)
    if not interval:
        r.add('l2_proof_cost', OK, f'slowest proof {worst:.0f} s; no block_interval_seconds set, not graded{model}',
              proof_seconds=worst)
        return
    r.graded('l2_proof_cost', worst / interval, p['proof_time_warn_ratio'], p['proof_time_crit_ratio'],
             f'slowest proof {worst:.0f} s against a block interval of {interval} s{model}',
             proof_seconds=worst, block_interval_seconds=interval)


def grade_events(name: str, events: List[Dict[str, Any]], p: Dict[str, Any], window: float, r: Report) -> None:
    for ev in events:
        if ev['event'] == 'proof-generated' and isinstance(ev.get('seconds'), (int, float)):
            r.facts.setdefault('proof_seconds', []).append(float(ev['seconds']))
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


def grade_foreign(name: str, events: List[Dict[str, Any]], p: Dict[str, Any], r: Report) -> None:
    """Foreign settlements recovered by the worker in the longer window. Funds are safe; more than one a day is
    an attack on liveness. Silent when there is none, since only a settler logs this event."""
    found = [ev for ev in events if ev['event'] == 'foreign-settlement-recovered']
    waiting = [ev for ev in events if ev['event'] == 'foreign-settlement-waiting-finality']
    if found or waiting:
        last = (found or waiting)[-1]
        r.graded(f'foreign_settlements[{name}]', max(len(found), len(waiting)), 1, p['foreign_recovered_crit'],
                 f'{len(found)} foreign settlement(s) recovered, {len(waiting)} waited on, in '
                 f'{p["foreign_window_seconds"] / 3600:.0f} h; last: L2 block {last.get("number")} at {last.get("time")}')


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
        day = p['foreign_window_seconds']
        code, out = run_cmd(['journalctl', '-u', unit, '-o', 'cat', '--no-pager', '-q', '--since', f'@{int(now - day)}'])
        if code == 0:
            grade_foreign(name, parse_events(out, now - day), p, r)


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
        grade_foreign(name, parse_events(text, now - p['foreign_window_seconds']), p, r)


def check_l1_progress(path: Optional[str], p: Dict[str, Any], now: float, r: Report) -> None:
    """--l1-progress-state: a stalled L1 keeps a constant finality lag, so `l1_finality_lag` stays quiet. This compares
    the best height with the previous run's and grades how long it has not moved."""
    if not path or 'l1_height' not in r.facts:
        return
    height = int(r.facts['l1_height'])
    try:
        st = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        st = {}
    if st.get('height') != height:
        st = {'height': height, 'since': now}
    try:
        tmp = Path(path).with_suffix('.tmp')
        tmp.write_text(json.dumps(st))
        os.replace(tmp, path)
    except OSError as e:
        r.add('l1_progress', WARN, f'cannot keep {path}: {e}')
        return
    still = now - float(st['since'])
    r.graded('l1_progress', still, p['l1_stall_warn_s'], p['l1_stall_crit_s'], f'L1 height {height} for {still:.0f} s')


def check_memory(enabled: bool, p: Dict[str, Any], r: Report, path: str = '/proc/meminfo') -> None:
    """Host memory: the OOMs of 2026-10-12 stalled finality before any chain check moved. MemAvailable, and swap in use."""
    if not enabled:
        return
    try:
        info = {}
        for line in Path(path).read_text().splitlines():
            k, _, v = line.partition(':')
            info[k.strip()] = int(v.split()[0])
        total, avail = info['MemTotal'], info['MemAvailable']
    except (OSError, ValueError, KeyError, IndexError) as e:
        r.add('memory', UNKNOWN, f'{path}: {type(e).__name__}: {e}')
        return
    pct = 100.0 * avail / total
    level = CRIT if pct < p['mem_avail_pct_crit'] else WARN if pct < p['mem_avail_pct_warn'] else OK
    r.add('memory', level, f'{avail / 2**20:.1f} GiB available of {total / 2**20:.1f} GiB ({pct:.1f}%)', value=round(pct, 2))
    swap_total = info.get('SwapTotal', 0)
    if swap_total:
        used = 100.0 * (swap_total - info.get('SwapFree', swap_total)) / swap_total
        r.add('swap', WARN if used >= p['swap_used_pct_warn'] else OK, f'{used:.0f}% of swap in use', value=round(used, 1))


def check_reports(specs: List[str], p: Dict[str, Any], now: float, r: Report) -> None:
    """NAME=PATH[:MAX_AGE_S]: the --json report of another monitor (dex-monitor.mjs, a second l2_monitor), written by its
    unit. Its WARN/CRIT checks go out through this monitor's alert path with one deduplication, and a report older than
    MAX_AGE_S (CRIT at 3x) means that monitor is dead or hung, which it cannot report itself."""
    for spec in specs:
        name, _, rest = spec.partition('=')
        path, _, limit = rest.partition(':')
        warn = float(limit) if limit else p['report_age_warn']
        try:
            mtime = os.stat(path).st_mtime
            doc = json.loads(Path(path).read_text())
            checks = doc['checks']
            if not isinstance(checks, list):
                raise ValueError('checks is not a list')
        except (OSError, ValueError, KeyError, TypeError) as e:
            r.add(f'report[{name}]', CRIT, f'{path}: {type(e).__name__}: {e}')
            continue
        r.graded(f'report_age[{name}]', max(0.0, now - mtime), warn, warn * 3, f'{path} written {now - mtime:.0f} s ago')
        bad = 0
        for c in checks:
            if not isinstance(c, dict):
                continue
            level = LEVEL_CODES.get(str(c.get('status') or c.get('level') or '').upper())
            if level is None:
                level = c.get('level') if c.get('level') in LEVEL_NAMES else UNKNOWN
            if level != OK:
                bad += 1
                r.add(f'{name}/{c.get("name") or c.get("check")}', level, str(c.get('detail') or c.get('message') or '')[:300])
        top = LEVEL_CODES.get(str(doc.get('level') or doc.get('status') or '').upper(), OK)
        if not bad:
            r.add(f'report[{name}]', top, f'{len(checks)} checks, none failing')


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
        findings = doc.get('findings')
        open_ = ', '.join(sorted(str(k) for k in findings)) if isinstance(findings, dict) else ''
        if doc.get('healthy') is True:
            r.add(f'guardian[{name}]', OK, 'healthy')
        else:
            r.add(f'guardian[{name}]', CRIT, 'unhealthy: ' + '; '.join(x for x in (ids, open_ and f'open hard findings: {open_}')
                                                                          if x) or 'unhealthy: no problem listed')
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
    heartbeat(cfg, args, r)
    decision = decide_alert(r, state, now, float(cfg.get('realert_seconds', 3600)), min_level,
                            int(cfg.get('recover_runs', 3)))
    if decision is None:
        if not args.alert_dry_run:  # the clean-run counters must survive, or a flapping check never settles
            bad = {c['check']: c['level'] for c in r.checks if SEVERITY[c['code']] >= SEVERITY[min_level]}
            bad.update({k: LEVEL_NAMES[v] for k, v in state.get('held', {}).items()})
            write_alert_state(state_path, {'bad': bad, 'sent_at': state.get('sent_at', 0), 'clean': state.get('clean', {})})
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
        bad.update({k: LEVEL_NAMES[v] for k, v in state.get('held', {}).items()})
        write_alert_state(state_path, {'bad': bad, 'sent_at': now if sent else state.get('sent_at', 0),
                                       'clean': state.get('clean', {}) if decision != 'recover' else {}})
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


def idle_thresholds(p: Dict[str, Any], max_idle: int) -> Dict[str, Any]:
    """A settler with skip_idle_blocks may rightly settle nothing for max_idle seconds. Stopped work is then found by
    unit[*], events[*] and deposit_wait, and by these checks only after the interval."""
    moved = {f'{name}_age_{level}': p[f'{name}_age_{level}'] + max_idle
             for name in ('head', 'settlement', 'finalized') for level in ('warn', 'crit')}
    return {**p, **moved}


def check_deposit_wait(backlog: int, consumed: int, path: str, p: Dict[str, Any], now: float, r: 'Report') -> None:
    """Time since deposits began to wait with no consumption, kept in a state file: L1 reports only counts. A deposit that
    arrives while idle is the one case settlement_age no longer covers, and a stopped settler is otherwise silent."""
    state_path = Path(path)
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    since = state.get('since') if backlog and state.get('consumed') == consumed else None
    since = now if backlog and since is None else since
    tmp = state_path.with_suffix('.tmp')
    tmp.write_text(json.dumps({'consumed': consumed, 'since': since}))
    os.replace(tmp, state_path)
    age = now - since if since is not None else 0.0
    r.graded('deposit_wait', age, p['deposit_wait_warn'], p['deposit_wait_crit'],
             f'{backlog} L1 deposits waiting, none consumed for {minutes(age)}' if backlog else 'no L1 deposit waiting')


def run(args: argparse.Namespace, transport: Transport, now: Optional[float] = None,
        run_cmd: Runner = subprocess_runner, fetch: Optional[Fetcher] = None) -> Report:
    now = time.time() if now is None else now
    p = thresholds(args)
    if args.max_idle_seconds:
        if not args.backlog_state:
            raise SystemExit('--max-idle-seconds needs --backlog-state: without it a waiting deposit raises no alert')
        p = idle_thresholds(p, args.max_idle_seconds)
    client = Client(transport)
    r = Report()
    r.facts.update({'profile': args.profile, 'phase': args.phase, 'checked_at': int(now)})
    backends = [named(s, f'rpc{i}') for i, s in enumerate(args.l2_rpc or [])]
    views = check_l2(client, backends, p, args.phase, now, r)
    l1_up = check_l1(client, args.l1_rpc or [], p, r)
    check_l1_stuck(client, args.l1_stuck_node or [], args.l1_stuck_state, l1_up, p, fetch or http_fetcher(args.timeout), r)
    with_l2 = check_settlement(l1_up, p, args.phase, now, r)
    check_height_runway(r.facts.get('l2_settled_number'), l1_up, p, r)
    check_escrow_and_backlog(with_l2, p, r, now, args.backlog_state if args.max_idle_seconds else None)
    check_followers(client, views, args.follower_status or [], l1_up, p, now, r)
    check_da_balance(client, args.da_script or [], l1_up, p, r)
    check_disks(args.disk or [], p, r)
    check_gates(l1_up, p, compiled_gates(args), now, r)
    check_attestors(args.attest_drop or [], with_l2, p, fetch or http_fetcher(args.timeout), r)
    check_units(args.unit or [], p, now, run_cmd, r)
    check_event_logs(args.event_log or [], p, now, r)
    check_proof_time(p, r)
    check_files(args.file or [], p, now, r)
    check_reports(args.report or [], p, now, r)
    check_memory(args.memory, p, r)
    check_l1_progress(args.l1_progress_state, p, now, r)
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
    a.add_argument('--l1-stuck-node', action='append',
                   help='NAME=RPC_URL[,METRICS_URL] of an L1 node to check for being stuck on its own branch, against --l1-rpc')
    a.add_argument('--l1-stuck-state', help='state file for --l1-stuck-node, kept between runs')
    a.add_argument('--follower-status', action='append', help='[NAME=]PATH of a native follower status.json')
    a.add_argument('--attest-drop', action='append', help='attestation drop: directory or http(s) base URL')
    a.add_argument('--unit', action='append', help='[NAME=]UNIT: systemd state + journal failure events')
    a.add_argument('--event-log', action='append', help='[NAME=]PATH of a JSON-lines log (settler, shadow, ...)')
    a.add_argument('--file', action='append', help='NAME=PATH[:MAX_AGE_S] heartbeat file to age-check')
    a.add_argument('--da-script', action='append', help='[NAME=]HEX funding script hash of the DA fee key (getutxos)')
    a.add_argument('--disk', action='append', help='[NAME=]PATH of a filesystem to check for free space')
    a.add_argument('--report', action='append',
                   help='NAME=PATH[:MAX_AGE_S] --json report of another monitor (dex-monitor.mjs) to alert on and age-check')
    a.add_argument('--l1-progress-state', help='state file: alert when the best L1 height stops moving')
    a.add_argument('--memory', action='store_true', help='check MemAvailable and swap of this host (/proc/meminfo)')
    a.add_argument('--guardian-health', action='append',
                   help='NAME=PATH[:MAX_AGE_S] health_file of a bridge guardian (WARN above MAX_AGE_S, CRIT above 3x)')
    a.add_argument('--binary', action='append', help='PATH of an installed binary to compare with the v2 pins')
    a.add_argument('--build-json', help='build.json of the L2 build (default: the v2 pins compiled in)')
    a.add_argument('--set', action='append', help='override a threshold, KEY=VALUE')
    a.add_argument('--max-idle-seconds', type=int, default=0,
                   help="the settler's max_idle_seconds when skip_idle_blocks is on; moves the age checks by that much")
    a.add_argument('--backlog-state', help='state file of deposit_wait; required with --max-idle-seconds')
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
