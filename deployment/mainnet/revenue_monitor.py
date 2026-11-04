#!/usr/bin/env python3
"""Read-only protocol revenue tracker for the Bloch DEX, the bUSDC bridge and the L2 (chain 700770).

It holds no key, opens no keystore and sends no transaction. JSON-RPC methods are limited to
READ_ONLY_METHODS; any other method is refused before a request is made. The only file it writes is its
own state file (`--state`), plus the optional `--json-out` report.

What it tracks, per product (owner rule, round 10: the DEX, the bridge and the L2 must all earn revenue):

  DEX (postern-dex, L2)  protocol LP shares held by the Bloch Inc Safe (`feeTo`, immutable) and their
                         underlying reserves; the protocol fee accrued but not yet minted (1/6 of the sqrt(k)
                         growth since `kLast`); keeper skims to the Safe (token Transfer pair -> Safe outside a
                         Burn); Safe redemptions (Burn to the Safe); the skimmable excess at the k ceiling.
  Bridge (Ethereum)      the vault's `feesAccrued`, `FeeAccrued` and `FeesSwept` logs, the immutable
                         `feeRecipient` and fee rates, the recipient's balance and the 1:1 backing
                         (vault balance >= totalLocked + feesAccrued).
  L2 fee vaults          balances of BASE_FEE_VAULT 0x4200..0019 and SEQUENCER_FEE_VAULT 0x4200..0011. Before
                         the December fork they have no code (locked); after it they carry the 37-byte sweep
                         program and every decrease is a sweep to the compiled recipient (the Bloch Inc L2
                         Safe, TBD-owner). The base-fee floor is checked once the fork is active.
  Forced inclusion (L1)  `getl2settlement.forced` counters and, once the surcharge goes to a treasury, that
                         treasury's L1 balance (`getbalance`).

Alerts (a revenue path that should accrue but does not): wrong or zero fee settings, fees accruing without
a sweep for too long, deposits or releases without a fee, vault balances not swept after the fork, the fork
time passed without sweep code, the placeholder sweep recipient, the keeper not capturing ceiling fees, the
DEX protocol fee switched off, forced-inclusion surcharges burned instead of paid to the treasury.

Amounts in WBLCH are valued at the pool price of the run. The first run records the L2 vault balances as
the baseline; accrued and swept L2 amounts are the balance changes between runs (a sweep and new fees between
two runs are netted, so run it at least hourly after the fork, e.g. from a systemd timer).

Output: a daily table on stdout (`--days N`) and a JSON report for the monitor (`--json`, `--json-out`).
Exit status (Nagios convention): 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN. Dependency-free Python 3.9+.

  revenue_monitor.py --config /etc/bloch-revenue/revenue.json --state /var/lib/bloch-revenue/state.json
  revenue_monitor.py --config revenue.json --state state.json --json-out /var/lib/bloch-revenue/report.json
"""
from __future__ import annotations

import argparse
import copy
import datetime
import fcntl
import json
import os
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SCHEMA = 'bloch-revenue-monitor/1'
STATE_SCHEMA = 'bloch-revenue-monitor-state/1'

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3
LEVEL_NAMES = {OK: 'OK', WARN: 'WARN', CRIT: 'CRIT', UNKNOWN: 'UNKNOWN'}
SEVERITY = {OK: 0, WARN: 1, UNKNOWN: 2, CRIT: 3}

READ_ONLY_METHODS = frozenset({
    # L2 settled RPC and Ethereum
    'eth_chainId', 'eth_getBlockByNumber', 'eth_call', 'eth_getBalance', 'eth_getCode', 'eth_getLogs',
    # L1 (bloch-pos)
    'getchaininfo', 'getl2settlement', 'getbalance',
})
# eth_call is read-only, but only these view functions are ever encoded (sweepFees, skim, sync, burn... never).
VIEW_SELECTORS = {
    'balanceOf(address)': '70a08231', 'totalSupply()': '18160ddd', 'getReserves()': '0902f1ac',
    'kLast()': '7464fc3d', 'reserveCaps()': 'd3dc9b31', 'feeTo()': '017e7e58', 'feesAccrued()': '94db0595',
    'feeRecipient()': '46904840', 'depositFeeBps()': 'ab879827', 'releaseFeeBps()': '9bb08a4a',
    'totalLocked()': '56891412', 'token()': 'fc0c546a',
}
ALLOWED_SELECTORS = frozenset(VIEW_SELECTORS.values())

TOPIC = {
    'Transfer': '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
    'Burn': '0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496',
    'Swap': '0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822',
    'Deposited': '0x86f22d28da637559602e716d294d9c661cb8177451cfdf19c194c0c79503c174',
    'Released': '0xefc74236f44fee676210517e8c459916af27488f41cc5bcb7973c09a425a4e1a',
    'ReleaseExecuted': '0x4e8874f9d0ed220298eea83a6688509ae5430437d1f937661fb4ca458d08395f',
    'FeeAccrued': '0x9d9812dea8de04c5c8cebc360d0887fe6c275594de9fc831f2b07767929596d0',
    'FeesSwept': '0x92b50d047432eb7fd2c813417cd6a222dd0be62d82cd2915e1358690ff4e3734',
}

BASE_FEE_VAULT = '0x4200000000000000000000000000000000000019'
SEQUENCER_FEE_VAULT = '0x4200000000000000000000000000000000000011'
PLACEHOLDER_SWEEP_RECIPIENT = '0x00000000000000000000000000000000000fee01'
SWEEP_CODE_HEAD = '5f5f5f5f4773'
SWEEP_CODE_TAIL = '5af115602157005b5f5ffd'
L2_CHAIN_ID = 700770
TBD = 'TBD-owner'

WEI_PER_BLCH = 10 ** 18
SAT_PER_BLCH = 10 ** 8
USDC_UNIT = 10 ** 6
BASE_SURCHARGE_SAT = 1_000  # forced::BASE_SURCHARGE_SAT, the price of one weight unit at an empty queue
DAY = 86_400

DEFAULT_THRESHOLDS = {
    # Bridge: sweepFees is permissionless; alert when this much waits longer than this.
    'bridge_sweep_min_units': 50 * USDC_UNIT,
    'bridge_sweep_max_age_days': 7,
    # L2 vaults after the fork: same rule.
    'l2_sweep_min_wei': WEI_PER_BLCH // 20,
    'l2_sweep_max_age_days': 7,
    # Hours after `l2_fees.fork_time` before a missing sweep program is CRIT.
    'l2_fork_grace_hours': 6,
    # With user transactions open, no increase of either vault for this long is a WARN.
    'l2_no_accrual_hours': 24,
    'l2_min_base_fee_wei': 100_000_000,
    # DEX keeper: ceiling floor of agent 196 (0.05 BLCH / 48), and how long excess may wait.
    'dex_keeper_floor_wei': 1_040_000_000_000_000,
    'dex_ceiling_unskimmed_hours': 6,
    # Log scans: blocks per eth_getLogs call and per run.
    'log_chunk_blocks': 2_000,
    'max_scan_blocks': 200_000,
    # Rows kept in the state file.
    'keep_days': 400,
}


class RpcError(Exception):
    pass


class FeeAccountingError(RpcError):
    """Crossing events and fee events contradict the immutable fee rule."""


Transport = Callable[[str, str, list], Any]


def http_transport(timeout: float) -> Transport:
    def call(url: str, method: str, params: list) -> Any:
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(url, data=body, headers={'content-type': 'application/json',
                                                              'user-agent': 'bloch-revenue-monitor'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                reply = json.loads(resp.read(16 * 1024 * 1024))
        except Exception as e:  # network, HTTP or JSON error
            raise RpcError(f'{method} at {url}: {e}') from None
        if not isinstance(reply, dict):
            raise RpcError(f'{method} at {url}: malformed reply')
        if reply.get('error') is not None:
            raise RpcError(f'{method} at {url}: {reply["error"]}')
        return reply.get('result')
    return call


class Client:
    """Refuses every method outside READ_ONLY_METHODS, and every eth_call outside the view selectors,
    before any I/O. Tries each URL of an endpoint list in order."""

    def __init__(self, transport: Transport):
        self.transport = transport
        self.calls = 0

    def call(self, urls: List[str], method: str, params: Optional[list] = None) -> Any:
        params = params or []
        if method not in READ_ONLY_METHODS:
            raise PermissionError(f'{method} is not a read-only revenue-monitor method')
        if method == 'eth_call':
            data = str(params[0].get('data', '')).lower()
            if data[2:10] not in ALLOWED_SELECTORS:
                raise PermissionError(f'eth_call selector {data[:10]} is not a view function of this monitor')
        last: Optional[Exception] = None
        for url in urls:
            try:
                self.calls += 1
                return self.transport(url, method, params)
            except RpcError as e:
                last = e
        raise RpcError(str(last) if last else f'{method}: no endpoint configured')


# ---------------------------------------------------------------- ABI helpers

def addr(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = str(value).strip().lower()
    if v == TBD.lower() or v in ('', 'null', 'none'):
        return None
    if not v.startswith('0x') or len(v) != 42 or any(c not in '0123456789abcdef' for c in v[2:]):
        raise ValueError(f'not an address: {value}')
    return v


def word_addr(a: str) -> str:
    return '0x' + a[2:].rjust(64, '0')


def calldata(signature: str, *args: str) -> str:
    return '0x' + VIEW_SELECTORS[signature] + ''.join(word_addr(a)[2:] for a in args)


def words(hexdata: Any) -> List[int]:
    if not isinstance(hexdata, str) or not hexdata.startswith('0x'):
        raise RpcError(f'malformed eth_call result {hexdata!r}')
    body = hexdata[2:]
    if len(body) == 0 or len(body) % 64:
        raise RpcError(f'eth_call result is not whole words ({len(body)} hex digits)')
    return [int(body[i:i + 64], 16) for i in range(0, len(body), 64)]


def word_to_addr(w: int) -> str:
    return '0x' + format(w, '064x')[-40:]


def hexint(v: Any) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.startswith('0x'):
        return int(v, 16)
    raise RpcError(f'not a hex quantity: {v!r}')


def isqrt(n: int) -> int:
    import math
    return math.isqrt(n)


def fmt_units(value: Optional[int], decimals: int, places: int = 6) -> str:
    if value is None:
        return '-'
    sign = '-' if value < 0 else ''
    value = abs(value)
    whole, frac = divmod(value, 10 ** decimals)
    if places == 0:
        return f'{sign}{whole}'
    frac_s = str(frac).rjust(decimals, '0')[:places]
    return f'{sign}{whole}.{frac_s}'


def day_of(ts: float) -> str:
    return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).strftime('%Y-%m-%d')


# ---------------------------------------------------------------- report

class Report:
    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []

    def add(self, name: str, level: int, message: str) -> None:
        self.checks.append({'name': name, 'level': LEVEL_NAMES[level], 'message': message})

    def level(self) -> int:
        worst = OK
        for c in self.checks:
            lv = {v: k for k, v in LEVEL_NAMES.items()}[c['level']]
            if SEVERITY[lv] > SEVERITY[worst]:
                worst = lv
        return worst


# ---------------------------------------------------------------- chain access

class Chain:
    """One EVM chain, read from one endpoint at one checked block identity."""

    def __init__(self, client: Client, urls: List[str], name: str):
        self.client, self.urls, self.name = client, urls, name
        self.block_ts_cache: Dict[int, int] = {}
        self.block_hash_cache: Dict[int, str] = {}
        self.number = 0
        self.timestamp = 0
        self.base_fee: Optional[int] = None
        self.hash: Optional[str] = None
        self.network: Optional[int] = None
        self.genesis_hash: Optional[str] = None

    def rpc(self, method: str, params: list) -> Any:
        return self.client.call(self.urls, method, params)

    def pin(self, tag: str = 'finalized') -> None:
        head = self.rpc('eth_getBlockByNumber', [tag, False])
        if not isinstance(head, dict):
            raise RpcError(f'{self.name}: no {tag} block')
        self.number = hexint(head['number'])
        self.hash = self.block_hash(head, self.number)
        self.timestamp = hexint(head['timestamp'])
        self.base_fee = hexint(head['baseFeePerGas']) if head.get('baseFeePerGas') is not None else None
        self.block_ts_cache[self.number] = self.timestamp
        self.block_hash_cache[self.number] = self.hash
        self.genesis_hash = self.block_hash(self.rpc('eth_getBlockByNumber', ['0x0', False]), 0)

    def chain_id(self) -> int:
        # Fail over only before selecting a chain. Mixing endpoints during a
        # sample can combine valid answers from different canonical branches.
        last: Optional[Exception] = None
        for url in self.urls:
            try:
                network = hexint(self.client.call([url], 'eth_chainId', []))
            except RpcError as error:
                last = error
                continue
            self.urls = [url]
            self.network = network
            return network
        raise RpcError(str(last) if last else f'{self.name}: no endpoint configured')

    def block_hash(self, block: Any, number: int) -> str:
        if not isinstance(block, dict) or hexint(block.get('number')) != number or number < 0:
            raise RpcError(f'{self.name}: missing or inconsistent block {number}')
        value = block.get('hash')
        if (not isinstance(value, str) or len(value) != 66 or not value.startswith('0x')
                or any(c not in '0123456789abcdefABCDEF' for c in value[2:])):
            raise RpcError(f'{self.name}: invalid hash for block {number}')
        return value.lower()

    def verify(self) -> None:
        if hexint(self.rpc('eth_chainId', [])) != self.network:
            raise RpcError(f'{self.name}: chain identity changed during observation')
        if self.block_hash(self.rpc('eth_getBlockByNumber', ['0x0', False]), 0) != self.genesis_hash:
            raise RpcError(f'{self.name}: genesis changed during observation')
        block = self.rpc('eth_getBlockByNumber', [self.at(), False])
        if self.block_hash(block, self.number) != self.hash:
            raise RpcError(f'{self.name}: pinned block changed during observation')

    def checkpoint(self) -> Dict[str, Any]:
        return {'chain_id': self.network, 'genesis_hash': self.genesis_hash,
                'number': self.number, 'hash': self.hash}

    def verify_previous(self, checkpoint: Dict[str, Any]) -> None:
        number = checkpoint['number']
        if type(number) is not int or number < 0 or number > self.number:
            raise RpcError(f'{self.name}: observation height regressed or prior checkpoint is invalid')
        if checkpoint['chain_id'] != self.network or checkpoint['genesis_hash'] != self.genesis_hash:
            raise RpcError(f'{self.name}: chain differs from the retained revenue history')
        block = self.rpc('eth_getBlockByNumber', [hex(number), False])
        if self.block_hash(block, number) != checkpoint['hash']:
            raise RpcError(f'{self.name}: retained revenue checkpoint is no longer canonical; '
                           'review the history and start a separate state file')

    def at(self) -> str:
        return hex(self.number)

    def view(self, to: str, signature: str, *args: str) -> List[int]:
        return words(self.rpc('eth_call', [{'to': to, 'data': calldata(signature, *args)}, self.at()]))

    def balance(self, a: str) -> int:
        return hexint(self.rpc('eth_getBalance', [a, self.at()]))

    def code(self, a: str) -> str:
        c = self.rpc('eth_getCode', [a, self.at()])
        return (c or '0x').lower()

    def block_time(self, number: int) -> int:
        if number not in self.block_ts_cache:
            b = self.rpc('eth_getBlockByNumber', [hex(number), False])
            if not isinstance(b, dict):
                raise RpcError(f'{self.name}: block {number} missing')
            self.block_hash_cache[number] = self.block_hash(b, number)
            self.block_ts_cache[number] = hexint(b['timestamp'])
        return self.block_ts_cache[number]

    def logs(self, address: Any, topics: list, start: int, end: int, chunk: int) -> List[Dict[str, Any]]:
        if type(chunk) is not int or chunk <= 0:
            raise RpcError('log_chunk_blocks must be a positive integer')
        out: List[Dict[str, Any]] = []
        addresses = {a.lower() for a in (address if isinstance(address, list) else [address])}
        seen = set()
        lo = start
        while lo <= end:
            hi = min(end, lo + chunk - 1)
            got = self.rpc('eth_getLogs', [{'address': address, 'topics': topics,
                                            'fromBlock': hex(lo), 'toBlock': hex(hi)}])
            if not isinstance(got, list):
                raise RpcError(f'{self.name}: eth_getLogs returned {type(got).__name__}')
            for raw in got:
                if not isinstance(raw, dict):
                    raise RpcError(f'{self.name}: malformed event')
                log = dict(raw)
                number, index = hexint(log['blockNumber']), hexint(log['logIndex'])
                if (type(number) is not int or type(index) is not int or not lo <= number <= hi or index < 0
                        or (log.get('removed') is not None and log.get('removed') is not False)):
                    raise RpcError(f'{self.name}: removed or out-of-range event')
                if not isinstance(log.get('address'), str) or log['address'].lower() not in addresses:
                    raise RpcError(f'{self.name}: event address does not match the filter')
                actual_topics = log.get('topics')
                if not isinstance(actual_topics, list) or any(not isinstance(t, str) for t in actual_topics):
                    raise RpcError(f'{self.name}: malformed event topics')
                for position, wanted in enumerate(topics):
                    if wanted is None:
                        continue
                    options = wanted if isinstance(wanted, list) else [wanted]
                    if position >= len(actual_topics) or actual_topics[position].lower() not in {t.lower() for t in options}:
                        raise RpcError(f'{self.name}: event topics do not match the filter')
                tx_hash = log.get('transactionHash')
                if (not isinstance(tx_hash, str) or len(tx_hash) != 66 or not tx_hash.startswith('0x')
                        or any(c not in '0123456789abcdefABCDEF' for c in tx_hash[2:])):
                    raise RpcError(f'{self.name}: malformed event transaction hash')
                log['_block'] = number
                log['_ts'] = self.block_time(number)
                block_hash = log.get('blockHash')
                if not isinstance(block_hash, str) or block_hash.lower() != self.block_hash_cache[number]:
                    raise RpcError(f'{self.name}: event block hash is not canonical')
                identity = (number, index)
                if identity in seen:
                    raise RpcError(f'{self.name}: duplicate event position')
                seen.add(identity)
                log['_day'] = day_of(log['_ts'])
                out.append(log)
            lo = hi + 1
        out.sort(key=lambda g: (g['_block'], hexint(g.get('logIndex', '0x0'))))
        return out


def scan_range(state_cursor: Optional[int], start_block: int, head: int, max_blocks: int) -> Tuple[int, int, bool]:
    """Blocks [lo, hi] to scan this run, and whether the scan reached the head."""
    if type(max_blocks) is not int or max_blocks <= 0:
        raise RpcError('max_scan_blocks must be a positive integer')
    lo = start_block if state_cursor is None else state_cursor + 1
    hi = min(head, lo + max_blocks - 1)
    return lo, hi, hi >= head


def log_data_words(log: Dict[str, Any]) -> List[int]:
    data = log.get('data') or '0x'
    return words(data) if data not in ('0x', '') else []


# ---------------------------------------------------------------- state

def empty_state() -> Dict[str, Any]:
    return {'schema': STATE_SCHEMA, 'cursors': {}, 'last': {}, 'marks': {}, 'days': {}, 'totals': {}, 'anchors': {}}


def load_state(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return empty_state()
    state = json.loads(path.read_text())
    if state.get('schema') != STATE_SCHEMA:
        raise SystemExit(f'{path}: state schema {state.get("schema")!r} is not {STATE_SCHEMA}')
    for key, value in empty_state().items():
        state.setdefault(key, value)
    return state


def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.revenue-state-', dir=str(path.parent))
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f, indent=1, sort_keys=True)
        f.write('\n')
    os.replace(tmp, path)


def bump(state: Dict[str, Any], day: str, key: str, amount: int) -> None:
    """Adds a flow (accrued, swept, skimmed) to a day's row and to the running totals. Amounts are strings in
    the state file so that wei values survive any JSON reader."""
    row = state['days'].setdefault(day, {})
    row[key] = str(int(row.get(key, '0')) + int(amount))
    state['totals'][key] = str(int(state['totals'].get(key, '0')) + int(amount))


def put(state: Dict[str, Any], day: str, key: str, value: Optional[int]) -> None:
    """Sets an end-of-day balance."""
    row = state['days'].setdefault(day, {})
    row[key] = None if value is None else str(int(value))


# ---------------------------------------------------------------- DEX

def dex_deployment(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """The DEX addresses: from the schema-2 gate file of deploy-dex.mjs, or listed in the config."""
    if cfg.get('gate'):
        gate = json.loads(Path(cfg['gate']).read_text())
        if gate.get('schemaVersion') != 2:
            raise ValueError('the DEX gate file must be schema 2 (deploy-dex.mjs record)')
        d = gate['deployment']
        safe = d['roles']['blochInc']['address'] if isinstance(d['roles']['blochInc'], dict) else d['roles']['blochInc']
        return {'factory': addr(d['contracts']['factory']), 'wrapped': addr(d['contracts'].get('wrappedNative')),
                'safe': addr(safe), 'fee_to': addr(d['feeTo']),
                'pairs': [{'address': addr(p['address']), 'token0': addr(p['token0']), 'token1': addr(p['token1'])}
                          for p in d['pairs']],
                'start_block': int(cfg.get('start_block', 0))}
    return {'factory': addr(cfg.get('factory')), 'wrapped': addr(cfg.get('wrapped')), 'safe': addr(cfg.get('safe')),
            'fee_to': addr(cfg.get('safe')),
            'pairs': [{'address': addr(p['address']), 'token0': addr(p['token0']), 'token1': addr(p['token1'])}
                      for p in cfg.get('pairs', [])],
            'start_block': int(cfg.get('start_block', 0))}


def wrapped_value(amount0: int, amount1: int, pair: Dict[str, Any], r0: int, r1: int, wrapped: Optional[str]) -> Optional[int]:
    """Value of (amount0, amount1) in wrapped-BLCH wei at the pool price; None for a pair without WBLCH."""
    if wrapped == pair['token0']:
        return amount0 + (amount1 * r0 // r1 if r1 else 0)
    if wrapped == pair['token1']:
        return amount1 + (amount0 * r1 // r0 if r0 else 0)
    return None


def check_dex(chain: Chain, cfg: Dict[str, Any], th: Dict[str, Any], state: Dict[str, Any], r: Report,
              today: str, now: float) -> Dict[str, Any]:
    dep = dex_deployment(cfg)
    out: Dict[str, Any] = {'enabled': True, 'safe': dep['safe'], 'pairs': []}
    if dep['safe'] is None:
        r.add('dex_safe', WARN, f'DEX: Bloch Inc Safe address is {TBD}; protocol LP shares cannot be tracked')
        return out
    if dep['factory']:
        fee_to = word_to_addr(chain.view(dep['factory'], 'feeTo()')[0])
        out['fee_to'] = fee_to
        if fee_to != dep['safe']:
            r.add('dex_fee_to', CRIT, f'DEX factory feeTo() is {fee_to}, not the Bloch Inc Safe {dep["safe"]}: '
                  'the 0.05% protocol fee goes elsewhere (feeTo is immutable; a new factory is needed)')
        else:
            r.add('dex_fee_to', OK, f'DEX factory feeTo() is the Bloch Inc Safe {fee_to}')

    cursor = state['cursors'].get('dex')
    lo, hi, complete = scan_range(cursor, dep['start_block'], chain.number, th['max_scan_blocks'])
    chunk = th['log_chunk_blocks']
    safe_topic = word_addr(dep['safe'])
    total_value = 0
    total_skim_value_run = 0
    pending_total = 0
    value_known = True
    for p in dep['pairs']:
        pa = p['address']
        r0, r1, _ = chain.view(pa, 'getReserves()')[:3]
        supply = chain.view(pa, 'totalSupply()')[0]
        k_last = chain.view(pa, 'kLast()')[0]
        safe_lp = chain.view(pa, 'balanceOf(address)', dep['safe'])[0]
        caps = chain.view(pa, 'reserveCaps()')[:2]
        bal0 = chain.view(p['token0'], 'balanceOf(address)', pa)[0]
        bal1 = chain.view(p['token1'], 'balanceOf(address)', pa)[0]
        under0 = r0 * safe_lp // supply if supply else 0
        under1 = r1 * safe_lp // supply if supply else 0
        # The protocol fee accrued since the last liquidity event, minted to feeTo on the next mint/burn.
        pending_lp = 0
        if k_last and supply:
            root_k, root_k_last = isqrt(r0 * r1), isqrt(k_last)
            if root_k > root_k_last:
                pending_lp = supply * (root_k - root_k_last) // (root_k * 5 + root_k_last)
        pend0 = r0 * pending_lp // (supply + pending_lp) if supply else 0
        pend1 = r1 * pending_lp // (supply + pending_lp) if supply else 0
        excess0, excess1 = max(0, bal0 - r0), max(0, bal1 - r1)
        at_ceiling = bool(caps[0] and caps[1] and r0 * r1 + max(r0, r1) > caps[0] * caps[1] * 6400 // 10_000)
        v_safe = wrapped_value(under0, under1, p, r0, r1, dep['wrapped'])
        v_pend = wrapped_value(pend0, pend1, p, r0, r1, dep['wrapped'])
        v_excess = wrapped_value(excess0, excess1, p, r0, r1, dep['wrapped'])

        # Logs: token transfers pair -> Safe are skims unless the same transaction burned LP to the Safe.
        skims: Dict[str, List[int]] = {}
        redeemed: Dict[str, List[int]] = {}
        swaps: Dict[str, int] = {}
        if lo <= hi:
            burns = chain.logs(pa, [TOPIC['Burn'], None, safe_topic], lo, hi, chunk)
            burn_txs = {b.get('transactionHash') for b in burns}
            for b in burns:
                w = log_data_words(b)
                acc = redeemed.setdefault(b['_day'], [0, 0])
                acc[0] += w[0]
                acc[1] += w[1]
            for idx, token in enumerate((p['token0'], p['token1'])):
                for t in chain.logs(token, [TOPIC['Transfer'], word_addr(pa), safe_topic], lo, hi, chunk):
                    if t.get('transactionHash') in burn_txs:
                        continue
                    skims.setdefault(t['_day'], [0, 0])[idx] += log_data_words(t)[0]
            for s in chain.logs(pa, [TOPIC['Swap']], lo, hi, chunk):
                swaps[s['_day']] = swaps.get(s['_day'], 0) + 1
        tag = pa[:10]
        for day, (a0, a1) in sorted(skims.items()):
            bump(state, day, f'dex_skim0:{pa}', a0)
            bump(state, day, f'dex_skim1:{pa}', a1)
            v = wrapped_value(a0, a1, p, r0, r1, dep['wrapped'])
            if v is not None:
                bump(state, day, 'dex_skim_wei', v)
                total_skim_value_run += v
            state['marks'][f'dex_last_skim:{pa}'] = now
        for day, (a0, a1) in sorted(redeemed.items()):
            bump(state, day, f'dex_redeem0:{pa}', a0)
            bump(state, day, f'dex_redeem1:{pa}', a1)
            v = wrapped_value(a0, a1, p, r0, r1, dep['wrapped'])
            if v is not None:
                bump(state, day, 'dex_redeem_wei', v)
        for day, n in swaps.items():
            bump(state, day, 'dex_swaps', n)

        prev_lp = state['last'].get(f'dex_safe_lp:{pa}')
        if prev_lp is not None and safe_lp < int(prev_lp) and not redeemed:
            r.add(f'dex_safe_lp[{tag}]', WARN, f'Safe LP shares of {pa} fell from {prev_lp} to {safe_lp} without a '
                  'Burn to the Safe in the scanned range: protocol shares left the Safe')
        state['last'][f'dex_safe_lp:{pa}'] = str(safe_lp)

        if supply and k_last == 0:
            r.add(f'dex_fee_off[{tag}]', CRIT, f'pair {pa} has LP supply but kLast = 0: the protocol fee is not '
                  'accruing (feeTo off at the last liquidity event)')
        # The keeper captures ceiling fees for the Safe; excess above its floor that waits too long is lost to bots.
        mark = f'dex_excess_since:{pa}'
        if at_ceiling and v_excess is not None and v_excess >= th['dex_keeper_floor_wei']:
            since = state['marks'].setdefault(mark, now)
            hours = (now - since) / 3600
            if hours >= th['dex_ceiling_unskimmed_hours']:
                r.add(f'dex_keeper[{tag}]', WARN, f'pair {pa} is at the k ceiling with {fmt_units(v_excess, 18)} '
                      f'WBLCH of skimmable fees for {hours:.1f} h and no keeper skim to the Safe: check '
                      'dex-skim-keeper (budget, cooldown, tip) - bots take what the keeper leaves')
            else:
                r.add(f'dex_keeper[{tag}]', OK, f'pair {pa} at the k ceiling, {fmt_units(v_excess, 18)} WBLCH '
                      f'skimmable for {hours:.1f} h (keeper floor {fmt_units(th["dex_keeper_floor_wei"], 18)})')
        else:
            state['marks'].pop(mark, None)
        if v_safe is None or v_pend is None:
            value_known = False
        else:
            total_value += v_safe
            pending_total += v_pend
        out['pairs'].append({
            'pair': pa, 'token0': p['token0'], 'token1': p['token1'], 'reserves': [str(r0), str(r1)],
            'lp_supply': str(supply), 'safe_lp': str(safe_lp), 'safe_share_ppm': (safe_lp * 10 ** 6 // supply) if supply else 0,
            'safe_underlying': [str(under0), str(under1)], 'safe_value_wblch_wei': None if v_safe is None else str(v_safe),
            'pending_fee_lp': str(pending_lp), 'pending_fee_underlying': [str(pend0), str(pend1)],
            'pending_fee_wblch_wei': None if v_pend is None else str(v_pend),
            'at_k_ceiling': at_ceiling, 'skimmable_excess': [str(excess0), str(excess1)],
            'skimmable_wblch_wei': None if v_excess is None else str(v_excess),
        })
        put(state, today, f'dex_safe_lp:{pa}', safe_lp)
    if hi >= lo:
        state['cursors']['dex'] = hi
    if not complete:
        r.add('dex_scan', WARN, f'DEX log scan reached block {hi} of {chain.number}; the next run continues')
    if value_known:
        put(state, today, 'dex_safe_value_wei', total_value)
        put(state, today, 'dex_pending_wei', pending_total)
        out['safe_value_wblch_wei'] = str(total_value)
        out['pending_fee_wblch_wei'] = str(pending_total)
    out['totals'] = {k: v for k, v in state['totals'].items() if k.startswith('dex_')}
    if not any(c['name'].startswith(('dex_fee_off', 'dex_fee_to')) and c['level'] == 'CRIT' for c in r.checks):
        r.add('dex_revenue', OK, f'DEX: Safe holds protocol LP worth {fmt_units(total_value, 18)} WBLCH, '
              f'{fmt_units(pending_total, 18)} WBLCH accrued but not yet minted'
              + ('' if value_known else ' (pairs without WBLCH are reported in raw units)'))
    return out


# ---------------------------------------------------------------- bridge

def check_crossing_fees(logs: List[Dict[str, Any]], deposit_bps: int, release_bps: int) -> None:
    """Bind each fee to its transaction and crossing ID; deposits report net amounts."""
    fees, crossings = {}, {}
    kinds = {TOPIC[name]: name for name in ('Deposited', 'Released', 'ReleaseExecuted', 'FeeAccrued')}
    for log in logs:
        kind = kinds.get(log['topics'][0].lower())
        if kind is None:
            continue
        topics = log['topics']
        expected_topics = 3 if kind in ('Deposited', 'Released') else 2
        data = log_data_words(log)
        expected_words = {'Deposited': 4, 'Released': 4, 'ReleaseExecuted': 2, 'FeeAccrued': 1}[kind]
        if len(topics) != expected_topics or len(data) != expected_words:
            raise RpcError(f'malformed {kind} event layout')
        event_id = topics[1]
        if (len(event_id) != 66 or not event_id.startswith('0x')
                or any(c not in '0123456789abcdefABCDEF' for c in event_id[2:])):
            raise RpcError(f'malformed {kind} event ID')
        key = (log['transactionHash'].lower(), event_id.lower())
        value = data[{'Deposited': 2, 'Released': 2, 'ReleaseExecuted': 1, 'FeeAccrued': 0}[kind]]
        if not 0 < value < 2 ** 64:
            raise RpcError(f'{kind} amount is not a positive uint64')
        target = fees if kind == 'FeeAccrued' else crossings
        if key in target:
            raise FeeAccountingError(f'duplicate {kind} for crossing {key[1]}')
        target[key] = value if kind == 'FeeAccrued' else (kind, value)
    for key, (kind, amount) in crossings.items():
        fee = fees.pop(key, 0)
        # A small crossing may legitimately pay zero after floor rounding. For
        # deposits the event's amount is net, so reconstruct gross with its fee.
        gross = amount + fee if kind == 'Deposited' else amount
        bps = deposit_bps if kind == 'Deposited' else release_bps
        expected = gross * bps // 10_000
        if gross >= 2 ** 64 or fee != expected:
            raise FeeAccountingError(f'{kind} {key[1]}: fee {fee} does not match {expected} '
                                     f'at {bps} bps (missing or mismatched FeeAccrued)')
    if fees:
        raise FeeAccountingError('FeeAccrued has no matching crossing in the same transaction')


def check_bridge(chain: Chain, cfg: Dict[str, Any], th: Dict[str, Any], state: Dict[str, Any], r: Report,
                 today: str, now: float) -> Dict[str, Any]:
    vault = addr(cfg.get('vault'))
    out: Dict[str, Any] = {'enabled': True, 'vault': vault}
    if vault is None:
        r.add('bridge_vault', WARN, f'bridge: vault address is {TBD}')
        return out
    token = addr(cfg.get('token')) or word_to_addr(chain.view(vault, 'token()')[0])
    want_recipient = addr(cfg.get('fee_recipient'))
    recipient = word_to_addr(chain.view(vault, 'feeRecipient()')[0])
    dep_bps = chain.view(vault, 'depositFeeBps()')[0]
    rel_bps = chain.view(vault, 'releaseFeeBps()')[0]
    accrued = chain.view(vault, 'feesAccrued()')[0]
    locked = chain.view(vault, 'totalLocked()')[0]
    held = chain.view(token, 'balanceOf(address)', vault)[0]
    recipient_balance = chain.view(token, 'balanceOf(address)', recipient)[0] if int(recipient, 16) else None
    out.update({'token': token, 'fee_recipient': recipient, 'deposit_fee_bps': dep_bps, 'release_fee_bps': rel_bps,
                'fees_accrued_unswept': str(accrued), 'total_locked': str(locked), 'vault_balance': str(held),
                'recipient_balance': None if recipient_balance is None else str(recipient_balance)})

    want_dep, want_rel = int(cfg.get('deposit_fee_bps', 5)), int(cfg.get('release_fee_bps', 5))
    if dep_bps == 0 or rel_bps == 0:
        r.add('bridge_fee_rates', CRIT, f'bridge vault fee rates are {dep_bps}/{rel_bps} bps: a crossing pays no fee '
              '(decided: 5 bps on deposit and 5 bps on release)')
    elif (dep_bps, rel_bps) != (want_dep, want_rel):
        r.add('bridge_fee_rates', CRIT, f'bridge vault fee rates are {dep_bps}/{rel_bps} bps, decided {want_dep}/{want_rel}')
    else:
        r.add('bridge_fee_rates', OK, f'bridge vault fee {dep_bps} bps on deposit, {rel_bps} bps on release')
    if not int(recipient, 16):
        r.add('bridge_fee_recipient', CRIT, 'bridge vault feeRecipient is the zero address')
    elif want_recipient is None:
        r.add('bridge_fee_recipient', WARN, f'bridge: the expected Ethereum treasury is {TBD} in the config; '
              f'the vault pays {recipient}')
    elif recipient != want_recipient:
        r.add('bridge_fee_recipient', CRIT, f'bridge vault feeRecipient is {recipient}, not the treasury {want_recipient}')
    else:
        r.add('bridge_fee_recipient', OK, f'bridge vault pays fees to the treasury {recipient}')
    if held < locked + accrued:
        r.add('bridge_backing', CRIT, f'bridge vault holds {fmt_units(held, 6)} USDC < totalLocked '
              f'{fmt_units(locked, 6)} + feesAccrued {fmt_units(accrued, 6)}: sweepFees and deposits revert')

    cursor = state['cursors'].get('bridge')
    lo, hi, complete = scan_range(cursor, int(cfg.get('start_block', 0)), chain.number, th['max_scan_blocks'])
    chunk = th['log_chunk_blocks']
    run_accrued = run_swept = 0
    if lo <= hi:
        logs = chain.logs(vault, [[TOPIC['FeeAccrued'], TOPIC['FeesSwept'], TOPIC['Deposited'], TOPIC['Released'],
                                   TOPIC['ReleaseExecuted']]], lo, hi, chunk)
        if (dep_bps, rel_bps) == (want_dep, want_rel) and 0 < dep_bps < 10_000 and 0 < rel_bps < 10_000:
            check_crossing_fees(logs, dep_bps, rel_bps)
        for g in logs:
            t0 = g['topics'][0].lower()
            if t0 == TOPIC['FeeAccrued']:
                fee = log_data_words(g)[0]
                bump(state, g['_day'], 'bridge_fee_accrued', fee)
                run_accrued += fee
                state['marks'].setdefault('bridge_unswept_since', g['_ts'])
                if state['marks']['bridge_unswept_since'] is None:
                    state['marks']['bridge_unswept_since'] = g['_ts']
            elif t0 == TOPIC['FeesSwept']:
                amount = log_data_words(g)[0]
                bump(state, g['_day'], 'bridge_fee_swept', amount)
                run_swept += amount
                state['marks']['bridge_last_sweep'] = g['_ts']
                state['marks']['bridge_unswept_since'] = None
            elif t0 == TOPIC['Deposited']:
                bump(state, g['_day'], 'bridge_deposits', 1)
            else:
                bump(state, g['_day'], 'bridge_releases', 1)
        state['cursors']['bridge'] = hi
    if not complete:
        r.add('bridge_scan', WARN, f'bridge log scan reached block {hi} of {chain.number}; the next run continues')

    # Reconciliation: the previous feesAccrued plus logged accruals minus logged sweeps is the current value.
    prev = state['last'].get('bridge_fees_accrued')
    if prev is not None and complete and lo <= hi and int(prev) + run_accrued - run_swept != accrued:
        r.add('bridge_reconcile', WARN, f'bridge feesAccrued {accrued} != previous {prev} + accrued {run_accrued} '
              f'- swept {run_swept} (missed logs or a reorg below the finalized block)')
    state['last']['bridge_fees_accrued'] = str(accrued)

    # sweepFees is permissionless and takes everything; fees that wait too long are a missed revenue transfer.
    marks = state['marks']
    if accrued == 0:
        marks.pop('bridge_unswept_since', None)
    else:
        if marks.get('bridge_unswept_since') is None:
            marks['bridge_unswept_since'] = now  # accrued before the scanned range
        age_days = (now - marks['bridge_unswept_since']) / DAY
        never = marks.get('bridge_last_sweep') is None
        if accrued >= th['bridge_sweep_min_units'] and age_days >= th['bridge_sweep_max_age_days']:
            r.add('bridge_sweep', WARN, f'bridge: {fmt_units(accrued, 6)} USDC of fees waiting {age_days:.1f} days; '
                  + ('sweepFees() was never called' if never else 'no sweepFees() since then')
                  + ' (permissionless: anyone may call it, the vault pays only the treasury)')
        else:
            r.add('bridge_sweep', OK, f'bridge: {fmt_units(accrued, 6)} USDC unswept for {age_days:.1f} days')
    put(state, today, 'bridge_unswept', accrued)
    put(state, today, 'bridge_recipient_balance', recipient_balance)
    out['totals'] = {k: v for k, v in state['totals'].items() if k.startswith('bridge_')}
    return out


# ---------------------------------------------------------------- L2 fee vaults

def sweep_code(recipient: str) -> str:
    return '0x' + SWEEP_CODE_HEAD + recipient[2:] + SWEEP_CODE_TAIL


def check_l2_fees(chain: Chain, cfg: Dict[str, Any], th: Dict[str, Any], state: Dict[str, Any], r: Report,
                  today: str, now: float) -> Dict[str, Any]:
    want_recipient = addr(cfg.get('recipient'))
    fork_time = cfg.get('fork_time')
    user_txs = bool(cfg.get('user_txs_open', False))
    out: Dict[str, Any] = {'enabled': True, 'vaults': {}, 'fork_active': False, 'user_txs_open': user_txs,
                           'finalized_block': chain.number}
    active = []
    total = 0
    for name, vault in (('base_fee', BASE_FEE_VAULT), ('sequencer_fee', SEQUENCER_FEE_VAULT)):
        bal = chain.balance(vault)
        code = chain.code(vault)
        total += bal
        info: Dict[str, Any] = {'address': vault, 'balance_wei': str(bal), 'code': 'none' if code in ('0x', '') else code}
        prev = state['last'].get(f'l2_vault:{name}')
        if prev is not None:
            delta = bal - int(prev)
            if delta > 0:
                bump(state, today, f'l2_accrued_{name}', delta)
                state['marks']['l2_last_increase'] = now
            elif delta < 0:
                # Only the sweep program moves value out of a vault: a decrease is a sweep (fees that arrived between
                # two runs are netted, so this is a lower bound of the swept amount).
                bump(state, today, f'l2_swept_{name}', -delta)
                state['marks'][f'l2_last_sweep:{name}'] = now
        else:
            state['marks'].setdefault('l2_last_increase', now)
        state['last'][f'l2_vault:{name}'] = str(bal)
        put(state, today, f'l2_vault_{name}', bal)
        if code not in ('0x', ''):
            active.append(name)
            compiled = '0x' + code[2 + len(SWEEP_CODE_HEAD):2 + len(SWEEP_CODE_HEAD) + 40] if len(code) == 2 + 74 else None
            info['sweep_recipient'] = compiled
            if compiled is None or code != sweep_code(compiled):
                r.add(f'l2_vault_code[{name}]', CRIT, f'{vault} has code that is not the 37-byte fee sweep: {code[:24]}...')
            elif compiled == PLACEHOLDER_SWEEP_RECIPIENT:
                r.add(f'l2_vault_code[{name}]', CRIT, f'{vault} sweeps to the placeholder {compiled}, an address with '
                      'no key: every L2 fee is lost (R197-1 / L1-9a)')
            elif want_recipient is None:
                r.add(f'l2_vault_code[{name}]', WARN, f'{vault} sweeps to {compiled}; expected recipient is {TBD} in the config')
            elif compiled != want_recipient:
                r.add(f'l2_vault_code[{name}]', CRIT, f'{vault} sweeps to {compiled}, not the Bloch Inc L2 Safe {want_recipient}')
            else:
                r.add(f'l2_vault_code[{name}]', OK, f'{vault} sweeps to the Bloch Inc L2 Safe {compiled}')
            # A vault that keeps a large balance for too long is a missed transfer. The window starts when the
            # vault first holds a balance after its last sweep.
            key = f'l2_sweepable_since:{name}'
            swept_now = prev is not None and bal < int(prev)
            if not bal:
                state['marks'].pop(key, None)
            elif swept_now or state['marks'].get(key) is None:
                state['marks'][key] = now
            since = state['marks'].get(key)
            if since is not None:
                age = (now - since) / DAY
                never = state['marks'].get(f'l2_last_sweep:{name}') is None
                if bal >= th['l2_sweep_min_wei'] and age >= th['l2_sweep_max_age_days']:
                    r.add(f'l2_sweep[{name}]', WARN, f'{vault} holds {fmt_units(bal, 18)} BLCH not swept for {age:.1f} days'
                          + (' (never swept)' if never else '') + ': any 0-value call to the vault sweeps it')
        out['vaults'][name] = info
    out['fork_active'] = len(active) == 2
    if len(active) == 1:
        r.add('l2_vault_code', CRIT, f'only {active[0]} has the sweep program; both vaults must get it at the fork')
    if not active:
        overdue = fork_time is not None and now > float(fork_time) + th['l2_fork_grace_hours'] * 3600
        if overdue:
            r.add('l2_fork', CRIT, f'the December fork time {int(float(fork_time))} has passed and the L2 fee vaults have no '
                  'sweep program: L2 fees stay locked')
        else:
            r.add('l2_fees_locked', OK, f'L2 fees are locked in keyless vaults until the December fork '
                  f'({fmt_units(total, 18)} BLCH accrued so far)'
                  + ('' if user_txs else '; deposit-only: no fee-paying transactions expected'))
    if out['fork_active'] and chain.base_fee is not None and chain.base_fee < th['l2_min_base_fee_wei']:
        r.add('l2_base_fee_floor', WARN, f'finalized L2 block base fee {chain.base_fee} wei is below the '
              f'{th["l2_min_base_fee_wei"]} wei floor decided for the December fork')
    if user_txs:
        last_inc = state['marks'].get('l2_last_increase', now)
        hours = (now - last_inc) / 3600
        if hours >= th['l2_no_accrual_hours']:
            r.add('l2_accrual', WARN, f'user transactions are open but no L2 fee vault grew for {hours:.0f} h')
    if want_recipient is not None:
        rb = chain.balance(want_recipient)
        out['recipient'] = want_recipient
        out['recipient_balance_wei'] = str(rb)
        put(state, today, 'l2_recipient_balance', rb)
    out['total_in_vaults_wei'] = str(total)
    out['base_fee_wei'] = chain.base_fee
    out['totals'] = {k: v for k, v in state['totals'].items() if k.startswith('l2_')}
    return out


# ---------------------------------------------------------------- forced inclusion (L1)

def check_forced(client: Client, cfg: Dict[str, Any], state: Dict[str, Any], r: Report, today: str,
                 now: float) -> Dict[str, Any]:
    urls = list(cfg.get('l1_rpc') or [])
    route = cfg.get('route', 'burned')
    settlement = client.call(urls, 'getl2settlement', [])
    forced = settlement.get('forced') if isinstance(settlement, dict) else None
    out: Dict[str, Any] = {'enabled': True, 'route': route, 'active': forced is not None}
    if forced is None:
        r.add('forced', OK, 'forced inclusion is not enabled on L1 (no `forced` in getl2settlement)')
        return out
    queued = int(forced['queued'])
    prev = state['last'].get('forced_queued')
    new = queued - int(prev) if prev is not None else 0
    state['last']['forced_queued'] = queued
    if new > 0:
        bump(state, today, 'forced_records', new)
        # Each record pays at least one weight unit at the base price; the exact surcharge depends on the depth.
        bump(state, today, 'forced_min_surcharge_sat', new * BASE_SURCHARGE_SAT)
    out.update({'queued': queued, 'consumed': int(forced['consumed']), 'pending_weight': int(forced['pending_weight']),
                'next_surcharge_sat': forced.get('next_surcharge_sat'), 'new_records': new})
    if route == 'burned':
        level = WARN if new > 0 else OK
        r.add('forced_route', level, f'{new} new forced records; their surcharge is burned by the node build. Decided '
              '(round 10, R4/R6): the fee and surcharge go to the protocol treasury - not in this build')
        return out
    script = cfg.get('treasury_script_hash')
    if not script or script == TBD:
        r.add('forced_route', WARN, f'forced-inclusion treasury script hash is {TBD}')
        return out
    bal = int(client.call(urls, 'getbalance', [script])['balance_sat'])
    prev_bal = state['last'].get('forced_treasury_sat')
    state['last']['forced_treasury_sat'] = str(bal)
    put(state, today, 'forced_treasury_sat', bal)
    out['treasury_balance_sat'] = str(bal)
    if prev_bal is not None:
        delta = bal - int(prev_bal)
        if delta > 0:
            bump(state, today, 'forced_treasury_in_sat', delta)
        if new > 0 and delta <= 0:
            r.add('forced_route', WARN, f'{new} new forced records but the treasury balance did not grow '
                  f'({prev_bal} -> {bal} sat): surcharges are not reaching the treasury')
            return out
    r.add('forced_route', OK, f'forced inclusion: {new} new records, treasury {fmt_units(bal, 8)} BLCH')
    return out


# ---------------------------------------------------------------- table

COLUMNS = [
    ('day', 'Day', None),
    ('dex_safe_value_wei', 'DEX Safe LP (WBLCH)', 18),
    ('dex_pending_wei', 'DEX unminted (WBLCH)', 18),
    ('dex_skim_wei', 'DEX skims (WBLCH)', 18),
    ('dex_redeem_wei', 'DEX redeemed (WBLCH)', 18),
    ('dex_swaps', 'Swaps', 0),
    ('bridge_fee_accrued', 'Bridge fees (USDC)', 6),
    ('bridge_fee_swept', 'Bridge swept (USDC)', 6),
    ('bridge_unswept', 'Bridge unswept (USDC)', 6),
    ('l2_vaults', 'L2 vaults (BLCH)', 18),
    ('l2_accrued', 'L2 accrued (BLCH)', 18),
    ('l2_swept', 'L2 swept (BLCH)', 18),
    ('forced_records', 'Forced recs', 0),
    ('forced_treasury_in_sat', 'Forced to treasury (BLCH)', 8),
]


def day_rows(state: Dict[str, Any], days: int) -> List[Dict[str, Any]]:
    rows = []
    for day in sorted(state['days'])[-days:]:
        raw = state['days'][day]

        def num(key: str) -> Optional[int]:
            v = raw.get(key)
            return None if v is None else int(v)

        def total(*keys: str) -> Optional[int]:
            vals = [num(k) for k in keys if raw.get(k) is not None]
            return sum(vals) if vals else None

        rows.append({
            'day': day,
            'dex_safe_value_wei': num('dex_safe_value_wei'), 'dex_pending_wei': num('dex_pending_wei'),
            'dex_skim_wei': num('dex_skim_wei'), 'dex_redeem_wei': num('dex_redeem_wei'), 'dex_swaps': num('dex_swaps'),
            'bridge_fee_accrued': num('bridge_fee_accrued'), 'bridge_fee_swept': num('bridge_fee_swept'),
            'bridge_unswept': num('bridge_unswept'), 'bridge_deposits': num('bridge_deposits'),
            'bridge_releases': num('bridge_releases'), 'bridge_recipient_balance': num('bridge_recipient_balance'),
            'l2_vaults': total('l2_vault_base_fee', 'l2_vault_sequencer_fee'),
            'l2_accrued': total('l2_accrued_base_fee', 'l2_accrued_sequencer_fee'),
            'l2_swept': total('l2_swept_base_fee', 'l2_swept_sequencer_fee'),
            'l2_recipient_balance': num('l2_recipient_balance'),
            'forced_records': num('forced_records'), 'forced_min_surcharge_sat': num('forced_min_surcharge_sat'),
            'forced_treasury_in_sat': num('forced_treasury_in_sat'),
        })
    return rows


def render_table(rows: List[Dict[str, Any]]) -> str:
    header = [c[1] for c in COLUMNS]
    body = []
    for row in rows:
        cells = []
        for key, _, dec in COLUMNS:
            v = row.get(key)
            if dec is None:
                cells.append(str(v))
            elif v is None:
                cells.append('-')
            else:
                cells.append(fmt_units(v, dec, 0 if dec == 0 else min(dec, 6)))
        body.append(cells)
    widths = [max(len(h), *(len(b[i]) for b in body)) if body else len(h) for i, h in enumerate(header)]
    line = lambda cells: ' | '.join(c.rjust(w) if i else c.ljust(w) for i, (c, w) in enumerate(zip(cells, widths)))
    out = [line(header), '-+-'.join('-' * w for w in widths)]
    out.extend(line(b) for b in body)
    return '\n'.join(out)


# ---------------------------------------------------------------- main

def run(config: Dict[str, Any], state: Dict[str, Any], client: Client, now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    today = day_of(now)
    th = dict(DEFAULT_THRESHOLDS)
    th.update(config.get('thresholds') or {})
    r = Report()
    products: Dict[str, Any] = {}

    l2_urls = list((config.get('l2') or {}).get('rpc') or [])
    l2: Optional[Chain] = None
    def enabled(name: str) -> bool:
        section_cfg = config.get(name)
        return bool(section_cfg) and section_cfg.get('enabled', True)

    needs_l2 = enabled('dex') or enabled('l2_fees')
    if needs_l2:
        try:
            l2 = Chain(client, l2_urls, 'L2')
            cid = l2.chain_id()
            want = int((config.get('l2') or {}).get('chain_id', L2_CHAIN_ID))
            if cid != want:
                r.add('l2_chain', CRIT, f'L2 RPC chain id {cid} is not {want}')
                l2 = None
            else:
                l2.pin((config.get('l2') or {}).get('block', 'finalized'))
        except (RpcError, KeyError, TypeError, ValueError) as e:
            r.add('l2_rpc', UNKNOWN, f'L2 RPC: {e}')
            l2 = None

    def has_history(name: str) -> bool:
        prefix = 'l2_' if name == 'l2_fees' else name + '_'
        return (name in state['cursors'] or any(key.startswith(prefix) for key in state['last'])
                or any(key.startswith(prefix) for key in state['totals']))

    def observe(name: str, chain: Chain, context: Dict[str, Any], fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        anchors = state.setdefault('anchors', {})
        previous = anchors.get(name)
        if has_history(name):
            if not isinstance(previous, dict):
                raise RpcError(f'{name}: prior revenue history has no chain checkpoint; '
                               'retain it for review and start a separate state file')
            if previous['context'] != context:
                raise RpcError(f'{name}: deployment configuration differs from retained revenue history; '
                               'start a separate state file')
            chain.verify_previous(previous['checkpoint'])
        result = fn()
        chain.verify()
        if has_history(name):
            anchors[name] = {'checkpoint': chain.checkpoint(), 'context': copy.deepcopy(context)}
        return result

    def section(name: str, fn: Callable[[], Dict[str, Any]]) -> None:
        # A later RPC or malformed event must not leave a partly advanced cursor,
        # balance baseline or daily total. Keep successful independent products.
        before = copy.deepcopy(state)
        first_check = len(r.checks)
        try:
            products[name] = fn()
        except (RpcError, KeyError, TypeError, IndexError, ValueError) as e:
            state.clear()
            state.update(before)
            del r.checks[first_check:]
            fee_error = isinstance(e, FeeAccountingError)
            r.add('bridge_fee_accrual' if fee_error else f'{name}_error', CRIT if fee_error else UNKNOWN,
                  f'{name}: {type(e).__name__}: {e}')
            products[name] = {'enabled': True, 'error': str(e)}

    dex_cfg = config.get('dex')
    if dex_cfg and dex_cfg.get('enabled', True):
        if l2 is not None:
            section('dex', lambda: observe('dex', l2, dex_deployment(dex_cfg),
                    lambda: check_dex(l2, dex_cfg, th, state, r, today, now)))
    else:
        products['dex'] = {'enabled': False}
        r.add('dex', OK, 'DEX not deployed (disabled in the config): no protocol fee yet')

    bridge_cfg = config.get('bridge')
    if bridge_cfg and bridge_cfg.get('enabled', True):
        def bridge() -> Dict[str, Any]:
            eth = Chain(client, list(bridge_cfg.get('rpc') or []), 'Ethereum')
            cid = eth.chain_id()
            if cid != int(bridge_cfg.get('chain_id', 1)):
                raise ValueError(f'Ethereum RPC chain id {cid} is not {bridge_cfg.get("chain_id", 1)}')
            eth.pin(bridge_cfg.get('block', 'finalized'))
            context = {key: value for key, value in bridge_cfg.items() if key not in ('rpc', 'enabled')}
            return observe('bridge', eth, context,
                           lambda: check_bridge(eth, bridge_cfg, th, state, r, today, now))
        section('bridge', bridge)
    else:
        products['bridge'] = {'enabled': False}
        r.add('bridge', OK, 'bridge vault not deployed (disabled in the config): no bridge fee yet')

    l2_cfg = config.get('l2_fees')
    if l2_cfg is not None and l2_cfg.get('enabled', True):
        if l2 is not None:
            section('l2_fees', lambda: observe('l2_fees', l2, {'recipient': addr(l2_cfg.get('recipient'))},
                    lambda: check_l2_fees(l2, l2_cfg, th, state, r, today, now)))
    else:
        products['l2_fees'] = {'enabled': False}

    forced_cfg = config.get('forced')
    if forced_cfg and forced_cfg.get('enabled', True):
        section('forced', lambda: check_forced(client, forced_cfg, state, r, today, now))
    else:
        products['forced'] = {'enabled': False}

    # Keep the day rows bounded.
    for day in sorted(state['days'])[:-th['keep_days']]:
        del state['days'][day]
    state['updated'] = now
    level = r.level()
    return {
        'schema': SCHEMA, 'generated_at': int(now), 'generated_at_utc': datetime.datetime.fromtimestamp(
            int(now), datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
        'level': LEVEL_NAMES[level], 'exit_code': level,
        'units': {'dex': 'WBLCH wei (1e18) or token base units', 'bridge': 'USDC base units (1e6)',
                  'l2_fees': 'BLCH wei (1e18)', 'forced': 'sat (1e8 per BLCH)'},
        'checks': r.checks, 'products': products, 'days': [{k: (None if v is None else (v if isinstance(v, str) else str(v)))
                                                              for k, v in row.items()} for row in day_rows(state, th['keep_days'])],
        'totals': dict(state['totals']), 'rpc_calls': client.calls,
    }


def main(argv: Optional[List[str]] = None, transport: Optional[Transport] = None, now: Optional[float] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', required=True, type=Path, help='JSON config (see monitor/revenue.json.example)')
    ap.add_argument('--state', type=Path, help='state file (cursors, daily rows); without it the run is stateless')
    ap.add_argument('--json', action='store_true', help='print the JSON report instead of the table')
    ap.add_argument('--json-out', type=Path, help='also write the JSON report to this file')
    ap.add_argument('--days', type=int, default=14, help='rows of the daily table (default 14)')
    ap.add_argument('--timeout', type=float, default=20.0)
    args = ap.parse_args(argv)
    lock = None
    try:
        if args.state is not None:
            args.state.parent.mkdir(parents=True, exist_ok=True)
            lock = os.open(str(args.state) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                print(f'another revenue monitor holds {args.state}.lock: not run', file=sys.stderr)
                return UNKNOWN
        return main_locked(args, transport, now)
    finally:
        if lock is not None:
            os.close(lock)


def main_locked(args: argparse.Namespace, transport: Optional[Transport], now: Optional[float]) -> int:
    # The state lock covers the read, every observation, and publication. Locking
    # only the atomic rename would still permit two runs to lose each other's data.
    config = json.loads(args.config.read_text())
    state = load_state(args.state)
    client = Client(transport or http_transport(args.timeout))
    report = run(config, state, client, now)
    if args.state:
        save_state(args.state, state)
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.json_out.with_name(args.json_out.name + '.tmp')
        tmp.write_text(text + '\n')
        os.replace(tmp, args.json_out)
    if args.json:
        print(text)
    else:
        print(f'Bloch protocol revenue - {report["generated_at_utc"]} - {report["level"]}')
        print(render_table(day_rows(state, args.days)))
        print()
        for c in report['checks']:
            print(f'{c["level"]:7} {c["name"]}: {c["message"]}')
    return report['exit_code']


if __name__ == '__main__':
    sys.exit(main())
