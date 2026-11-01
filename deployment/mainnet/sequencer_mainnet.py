#!/usr/bin/env python3
"""Bloch L2 MAINNET block producer (sequencer stage), chain id 700770.

The natively settled L2 has no free-running block clock: the native chain
freezes one *source* block (`getl2settlement.source`) and the next L2 block
must be anchored to exactly that block and mint exactly the inbox records
(0x14 deposits) it lists as pending. After the native chain accepts the
settlement (0x13) of that L2 block it freezes a new source at the next native
block. So the producer makes exactly one unsettled L2 block at a time:

    read the native settlement view (quorum of mainnet nodes, read-only)
      -> extend the canonical L2 database by one block anchored to the source
         (`bloch-l2-produce-dev extend --rules mainnet ...`, wall-clock
         timestamp = start of the anchored 30 s native slot, rule R5)
      -> export the prover input (`block.artifact`), the native request and,
         with user transactions, the canonical L1 DA batch (0x15 payload)
      -> write `job.json`: the handoff to the prover / settler.

It never proves, signs, submits or publishes anything, never reads a key and
only issues read-only `getl2settlement` calls.

ONE WRITER. On mainnet the producer is the settler (`settler_v3.py`,
`network_kind: "mainnet"`, branch codex/l2-mainnet-settler-20261018): it
extends its own canonical database inside its cycle, exactly as on devnet4.
This script therefore runs in one of two modes:

* shadow (the installed unit; `settler_workdir` set): an independent second
  producer on its OWN database. For every block the settler has produced
  (`<settler_workdir>/<number:08d>-<anchor[:16]>/block.json`) it rebuilds the
  same block from the native view alone (plus, with user transactions, the
  transactions of the settler's DA batch `da-payload.hex`, i.e. exactly what
  goes to L1) and halts (exit 3) unless hash, state root, timestamp, deposits,
  transactions and withdrawal root/count are identical. Its head must also be
  the parent of every statement the native chain accepts. It catches a
  non-deterministic, mis-pinned or mis-configured producer before the proof,
  and needs no access to the settler's database (read-only on its work dir).
* producer (`settler_workdir` absent): the stage on its own, for tests and
  rehearsals, writing the settler_v3 job layout (`deposits.json`,
  `block.json`, `block.artifact`, `native-request.txt`, `da-payload.hex`)
  plus `job.json`. Never point it at a database a settler also writes.

Commands (configuration: $BLOCH_SEQUENCER_CONFIG or --config FILE):
  init    create the canonical database at the pinned mainnet L2 genesis
  check   read-only: native view, local head, what `step` would do
  step    produce (or verify the already produced) next block, then exit
  run     `step` every `poll_seconds` (the systemd unit)

Exit status: 0 ok, 2 no native quorum (check), 3 halt (divergence; the unit
must not restart until an operator looked: RestartPreventExitStatus=3).
Dependency-free Python 3.9+.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

# ---- Pinned mainnet identity (docs/MAINNET-PROGRAM.md; native 78b7343a l2_settlement::mainnet) ----
CHAIN_ID = 700770
NATIVE_NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
NATIVE_GENESIS = '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415'
L2_DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L2_GENESIS_TIME = 1786656679          # Genesis-4 slot-0 time (MAINNET_GENESIS_TIMESTAMP)
L1_SLOT_MILLIS = 30_000                # Genesis-4 slot duration
L2_GENESIS_HASH = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
L2_GENESIS_STATE = '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'
TIMESTAMP_RULE = f'1:{L2_GENESIS_TIME}:{L1_SLOT_MILLIS}'
NETWORK_ARGS = ['--rules', 'mainnet', '--domain', L2_DOMAIN, '--genesis-time', str(L2_GENESIS_TIME)]

# ---- Native constants (bloch-pos-committee 78b7343a) ----
TAG = b'BLOCH:EVM:SETTLEMENT:3'
T = len(TAG)
MAX_INBOX_PER_SETTLEMENT = 64
DA_DOMAIN = b'BLOCH:L2:DA:1'
DA_MAX_PAYLOAD_BYTES = 114_688
# The getl2settlement fields that decide the next block (others move every native block).
VIEW_FIELDS = ('network', 'genesis', 'chain_id', 'asynchronous', 'profile', 'accepted', 'source', 'program')
DEFAULTS = {'poll_seconds': 15, 'user_transactions': False, 'max_block_gas': 15_000_000,
            'max_block_bytes': DA_MAX_PAYLOAD_BYTES, 'max_block_txs': 256, 'rpc_timeout_seconds': 15,
            'max_clock_skew_seconds': 120}


class Halt(Exception):
    """A divergence an operator must review; never auto-repaired."""


class RetryLater(Exception):
    """An input another process is still writing; the next step retries."""


def log(event, **fields):
    print(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event, **fields},
                     sort_keys=True), flush=True)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


# ---- Keccak-256 (Ethereum padding), dependency-free; same as settler_v3.py ----
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    padded = bytearray(data) + b'\x01'
    padded += b'\x00' * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], 'little')
        state = _keccak_f(state)
    return b''.join(state[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


def da_commitment(number, payload):
    """keccak256("BLOCH:L2:DA:1" || chain_id BE8 || l2_block_number BE8 || payload)."""
    return keccak256(DA_DOMAIN + CHAIN_ID.to_bytes(8, 'big') + int(number).to_bytes(8, 'big') + payload)


def da_batch_count(payload):
    """Number of transactions in a canonical DA batch, or None."""
    if not 4 <= len(payload) <= DA_MAX_PAYLOAD_BYTES:
        return None
    count, at = int.from_bytes(payload[:4], 'big'), 4
    for _ in range(count):
        if at + 4 > len(payload):
            return None
        size = int.from_bytes(payload[at:at + 4], 'big')
        at += 4 + size
        if size == 0 or at > len(payload):
            return None
    return count if count and at == len(payload) else None


def statement_fields(hex_statement):
    s = bytes.fromhex(hex_statement)
    if len(s) < T + 400 or s[:T] != TAG:
        raise Halt('accepted statement is not a settlement V3 statement')
    return {'chain_id': int.from_bytes(s[T + 256:T + 264], 'big'), 'l2_number': int.from_bytes(s[T + 264:T + 272], 'big'),
            'l2_hash': s[T + 336:T + 368].hex(), 'l2_state_root': s[T + 368:T + 400].hex()}


def l1_slot_time(slot):
    return L2_GENESIS_TIME + slot * L1_SLOT_MILLIS // 1000


def http_rpc(url, method, params=(), timeout=15):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        reply = json.loads(response.read())
    if 'error' in reply:
        raise RuntimeError(f'{method}: {reply["error"]}')
    return reply['result']


def view_projection(view):
    return {k: view[k] for k in VIEW_FIELDS if k in view} if isinstance(view, dict) else view


class Sequencer:
    def __init__(self, config, rpc=http_rpc, run=subprocess.run, clock=time.time):
        self.c = {**DEFAULTS, **config}
        self.rpc, self.run, self.clock = rpc, run, clock
        for key in ('produce', 'produce_sha256', 'l2_db', 'workdir', 'rpc_urls'):
            if not self.c.get(key):
                raise Halt(f'{key} is required')
        if digest(self.c['produce']) != self.c['produce_sha256']:
            raise Halt('producer binary differs from its pin')
        urls = self.c['rpc_urls']
        if not isinstance(urls, list) or len(set(urls)) != len(urls) or not all(isinstance(u, str) for u in urls):
            raise Halt('rpc_urls must list distinct URLs')
        self.quorum = self.c.get('rpc_quorum', len(urls) // 2 + 1)
        if not isinstance(self.quorum, int) or isinstance(self.quorum, bool) or not len(urls) < 2 * self.quorum <= 2 * len(urls):
            raise Halt('rpc_quorum must be a strict majority of rpc_urls')
        if not isinstance(self.c['user_transactions'], bool):
            raise Halt('user_transactions must be true or false')
        if self.c['user_transactions']:
            if not self.c.get('txpool_dir') or not Path(self.c['txpool_dir']).is_dir():
                raise Halt('user_transactions requires an existing txpool_dir')
            for key, cap in (('max_block_gas', 30_000_000), ('max_block_bytes', DA_MAX_PAYLOAD_BYTES),
                             ('max_block_txs', 4096)):
                value = self.c[key]
                if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= cap:
                    raise Halt(f'{key} must be a positive integer <= {cap}')
        self.shadow = bool(self.c.get('settler_workdir'))
        if self.shadow:
            if self.c['user_transactions']:
                raise Halt('shadow mode takes the transactions from the settler DA batch: leave user_transactions false')
            if Path(self.c['settler_workdir']).resolve() == Path(self.c['workdir']).resolve():
                raise Halt('settler_workdir must not be the shadow workdir')
        self.work = Path(self.c['workdir'])

    # ---- shadow mode: the settler (settler_v3.py) is the producer; this rebuilds and compares ----
    def settler_block(self, number, source):
        path = Path(self.c['settler_workdir']) / f'{number:08d}-{source["block"][:16]}' / 'block.json'
        if not path.is_file():
            return None
        return json.loads(path.read_text())

    def settler_transactions(self, number, source, settler_block):
        """The signed transactions of the settler's block, from its canonical DA batch."""
        path = Path(self.c['settler_workdir']) / f'{number:08d}-{source["block"][:16]}' / 'da-payload.hex'
        if not path.is_file():
            raise RetryLater(f'settler block {number} has transactions but no da-payload.hex yet')
        payload = bytes.fromhex(path.read_text().strip())
        count = da_batch_count(payload)
        if count != settler_block['transactions']:
            raise Halt(f'settler DA batch of block {number} does not hold its {settler_block["transactions"]} transactions')
        txs, at = [], 4
        for _ in range(count):
            size = int.from_bytes(payload[at:at + 4], 'big')
            txs.append(payload[at + 4:at + 4 + size].hex())
            at += 4 + size
        return txs

    # ---- external calls ----
    def produce(self, *args):
        result = self.run([self.c['produce'], *args, *NETWORK_ARGS], capture_output=True, text=True, timeout=600)
        if result.returncode:
            raise Halt(f'producer refused {args[0]}: {result.stderr.strip()[:400]}')
        return json.loads(result.stdout)

    def native_view(self):
        """The decision-relevant settlement view a strict majority of nodes return identically, or None."""
        groups, errors = {}, []
        for url in self.c['rpc_urls']:
            try:
                view = view_projection(self.rpc(url, 'getl2settlement', (), self.c['rpc_timeout_seconds']))
            except Exception as error:
                errors.append(f'{url}: {type(error).__name__}: {error}'[:200])
                continue
            groups.setdefault(canonical(view), (view, []))[1].append(url)
        best = max(groups.values(), key=lambda g: len(g[1]), default=(None, []))
        if len(best[1]) < self.quorum:
            log('native-no-quorum', quorum=self.quorum, groups=[sorted(g[1]) for g in groups.values()], errors=errors)
            return None
        view = best[0]
        if view.get('network') != NATIVE_NETWORK or view.get('genesis') != NATIVE_GENESIS:
            raise Halt('native network identity differs from Genesis-4 mainnet')
        if view.get('chain_id') != CHAIN_ID or view.get('asynchronous') is not True:
            raise Halt('native L2 is not the asynchronous chain 700770')
        profile = view.get('profile') or {}
        if not (profile.get('activated') and profile.get('deposits')):
            raise Halt('native L2 profile is not the activated mainnet profile')
        if self.c['user_transactions'] and not profile.get('user_transactions'):
            raise Halt('user_transactions configured but the native profile refuses them')
        return view

    # ---- the next block ----
    def plan(self, view):
        """(number, parent, source, pending, anchor_slot) the native view asks for."""
        accepted = view.get('accepted')
        if accepted:
            fields = statement_fields(accepted['statement'])
            if fields['chain_id'] != CHAIN_ID:
                raise Halt('accepted statement belongs to another chain id')
            number, parent = fields['l2_number'] + 1, fields['l2_hash']
        else:
            number, parent = 1, L2_GENESIS_HASH
        source = view.get('source')
        if not source:
            return None
        request = source['request'].splitlines()
        if len(request) < 7 or request[0] != NATIVE_NETWORK or request[1] != NATIVE_GENESIS \
                or request[2] != source['block'] or int(request[3]) != source['slot'] or int(request[4]) != source['height']:
            raise Halt('native request does not match its source')
        pending = source.get('pending', [])
        if len(pending) != source.get('consumed_end', 0) - source.get('consumed_start', 0) \
                or len(pending) > MAX_INBOX_PER_SETTLEMENT:
            raise Halt('native pending deposits do not match the consumed range')
        for record in pending:
            if set(record) < {'height', 'tx_index', 'txid', 'vout', 'sats', 'recipient'}:
                raise Halt('malformed native pending deposit')
        anchor_slot = source['slot']
        if l1_slot_time(anchor_slot) > self.clock() + self.c['max_clock_skew_seconds']:
            raise Halt(f'source slot {anchor_slot} starts in the future: check the host clock')
        return number, parent, source, pending, anchor_slot

    def job_dir(self, number, source):
        return self.work / f'{number:08d}-{source["block"][:16]}'

    @staticmethod
    def write_once(path, text):
        if path.exists():
            if path.read_text() != text:
                raise Halt(f'{path} already holds different content')
            return
        tmp = path.with_suffix(path.suffix + '.tmp')
        tmp.write_text(text)
        os.replace(tmp, path)

    def next_program_active(self, view):
        """Whether L1 holds the next program (`next_elf_keccak`, candidate; absent keeps one rule set)."""
        elf = self.c.get('next_elf_keccak')
        return bool(elf) and (view.get('program') or {}).get('elf_keccak') == elf

    def follow_program(self, number, source, active):
        """An unsettled head under the old rules cannot settle once L1 moved the program: same rule as the settler."""
        if not active:
            return
        head = self.produce('head', '--target', self.c['l2_db'])
        if head['number'] == number and head.get('rules') != 'next':
            self.produce('rewind', '--target', self.c['l2_db'], '--number', str(number), '--hash', head['hash'])
            log('l2-block-rewound-at-swap', number=number, hash=head['hash'])
        directory = self.job_dir(number, source)
        produced = directory / 'block.json'
        if produced.exists() and json.loads(produced.read_text()).get('rules') != 'next':
            directory.rename(directory.with_name(f'{directory.name}.superseded-{int(time.time())}'))

    def extend_args(self, parent, anchor, deposits, anchor_slot, shadow_txs=None):
        args = ['extend', '--target', self.c['l2_db'], '--parent', parent, '--anchor', anchor,
                '--deposits', str(deposits), '--timestamp-rule', TIMESTAMP_RULE, '--anchor-slot', str(anchor_slot)]
        if self.c.get('next_elf_keccak'):
            args += ['--rule-set', self.rule_set]
        if shadow_txs is not None:
            # Exactly the transactions the settler's DA batch carries; protocol limits.
            args += ['--txs', str(shadow_txs)]
        elif self.c['user_transactions']:
            args += ['--txs', self.c['txpool_dir'], '--max-gas', str(self.c['max_block_gas']),
                     '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs'])]
        return args

    def step(self):
        """Produce or verify the block the native chain waits for. Returns the job or None."""
        self.work.mkdir(parents=True, exist_ok=True)
        with open(self.work / '.sequencer.lock', 'w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Halt('another process holds the sequencer lock (one writer per canonical database)') from None
            view = self.native_view()
            if view is None:
                return None
            planned = self.plan(view)
            if planned is None:
                return None
            try:
                return self.produce_job(view, *planned)
            except RetryLater as wait:
                log('waiting', reason=str(wait))
                return None

    def produce_job(self, view, number, parent, source, pending, anchor_slot):
        anchor = source['block']
        active = self.next_program_active(view)
        self.rule_set = 'next' if active else 'base'
        self.follow_program(number, source, active)
        directory = self.job_dir(number, source)
        job_path = directory / 'job.json'
        if job_path.exists():
            job = json.loads(job_path.read_text())
            head = self.produce('head', '--target', self.c['l2_db'])
            if head['number'] != number or head['hash'] != job['hash']:
                raise Halt(f'job {number} exists but the L2 head is {head["number"]} {head["hash"]}')
            return job
        settler_block, shadow_txs = None, None
        if self.shadow:
            settler_block = self.settler_block(number, source)
            if settler_block is None:
                return None  # the settler has not produced this block yet
        directory.mkdir(parents=True, exist_ok=True)
        deposits = directory / 'deposits.json'
        self.write_once(deposits, json.dumps(pending, sort_keys=True))
        if settler_block is not None and settler_block.get('transactions', 0):
            shadow_txs = directory / 'settler-transactions.json'
            self.write_once(shadow_txs, json.dumps(self.settler_transactions(number, source, settler_block)))
        head = self.produce('head', '--target', self.c['l2_db'])
        produced = directory / 'block.json'
        if head['number'] == number - 1:
            if head['hash'] != parent:
                raise Halt(f'L2 head {head["hash"]} is not the accepted parent {parent}')
            block = self.produce(*self.extend_args(parent, anchor, deposits, anchor_slot, shadow_txs))
            if block['number'] != number or block['parent'] != parent or block['anchor'] != anchor:
                raise Halt('producer extended a different block than requested')
            if block.get('transactions', 0) and not self.c['user_transactions'] and not self.shadow:
                raise Halt('producer included user transactions while user_transactions is false')
            if block['deposits'] != len(pending):
                raise Halt('producer minted a different number of deposits than the native inbox lists')
            self.write_once(produced, json.dumps(block, sort_keys=True) + '\n')
            log('l2-block-produced', number=number, hash=block['hash'], anchor=anchor, timestamp=block['timestamp'],
                deposits=block['deposits'], transactions=block.get('transactions', 0),
                deferred=len(block.get('deferred', [])), dropped=len(block.get('dropped', [])))
        elif head['number'] == number:
            if not produced.exists():
                raise Halt(f'L2 head is already block {number} but {produced} is missing')
            block = json.loads(produced.read_text())
            if block['hash'] != head['hash'] or block['anchor'] != anchor or block['parent'] != parent:
                raise Halt(f'unsettled L2 block {number} differs from what the native chain now requests')
            log('l2-block-reused', number=number, hash=block['hash'])
        else:
            raise Halt(f'L2 head {head["number"]} cannot extend accepted settlement {number - 1}')
        # R5: wall-clock time of the anchored slot, strictly after the parent.
        expected_floor = l1_slot_time(anchor_slot)
        if block['timestamp'] < expected_floor:
            raise Halt('block timestamp is earlier than its anchored native slot')
        artifact = directory / 'block.artifact'
        if not artifact.exists():
            tmp = directory / 'block.artifact.partial'
            tmp.unlink(missing_ok=True)
            info = self.produce('export', '--target', self.c['l2_db'], '--number', str(number), '--out', str(tmp))
            if info['hash'] != block['hash'] or info['anchor'] != anchor:
                raise Halt('exported artifact is not the produced block')
            os.replace(tmp, artifact)
        request_text = source['request'] + (view['accepted']['commitment'] if view.get('accepted') else '0' * 64) + '\n'
        if 'inbox_count' in source:
            request_text += f"{source['inbox_count']}\n{source['consumed_start']}\n{source['consumed_end']}\n"
        self.write_once(directory / 'native-request.txt', request_text)
        da = None
        if block.get('transactions', 0):
            path = directory / 'da-payload.hex'
            if not path.exists():
                info = self.produce('da', '--target', self.c['l2_db'], '--number', str(number), '--out', str(path))
                if info.get('number') != number or info.get('chain_id') != CHAIN_ID:
                    raise Halt('producer exported the DA batch of another block or chain')
            payload = bytes.fromhex(path.read_text().strip())
            if da_batch_count(payload) != block['transactions']:
                raise Halt('DA batch does not hold exactly the block transactions')
            da = {'payload_bytes': len(payload), 'commitment': da_commitment(number, payload).hex(),
                  'payload_sha256': hashlib.sha256(payload).hexdigest()}
        if settler_block is not None:
            fields = ('number', 'hash', 'state_root', 'parent', 'anchor', 'timestamp', 'deposits', 'transactions',
                      'withdrawal_root', 'withdrawal_count')
            differ = [k for k in fields if block.get(k) != settler_block.get(k, 0 if k == 'transactions' else None)]
            if differ:
                raise Halt(f'settler block {number} differs from the independent rebuild in {differ}: '
                           f'settler {settler_block.get("hash")}, shadow {block["hash"]}')
            log('shadow-match', number=number, hash=block['hash'], state_root=block['state_root'],
                transactions=block.get('transactions', 0))
        job = {'status': 'shadow-matched' if self.shadow else 'ready-for-prover', 'chain_id': CHAIN_ID, 'number': number, 'hash': block['hash'],
               'parent': parent, 'state_root': block['state_root'], 'timestamp': block['timestamp'],
               'anchor': anchor, 'anchor_slot': anchor_slot, 'anchor_height': source['height'],
               'deposits': block['deposits'], 'transactions': block.get('transactions', 0),
               'withdrawal_root': block.get('withdrawal_root'), 'withdrawal_count': block.get('withdrawal_count'),
               'da': da, 'artifact_sha256': digest(artifact),
               'native_request_sha256': digest(directory / 'native-request.txt'),
               'produce_sha256': self.c['produce_sha256'], 'directory': str(directory)}
        self.write_once(job_path, json.dumps(job, indent=2, sort_keys=True) + '\n')
        log('job-ready', number=number, hash=block['hash'], directory=str(directory), da=bool(da))
        return job

    # ---- one-off commands ----
    def init(self):
        target = Path(self.c['l2_db'])
        if target.exists():
            raise Halt(f'{target} already exists')
        genesis = self.produce('init', '--target', str(target))
        head = self.produce('head', '--target', str(target))
        if genesis['hash'] != L2_GENESIS_HASH or head['hash'] != L2_GENESIS_HASH or head['state_root'] != L2_GENESIS_STATE:
            raise Halt(f'L2 genesis {head["hash"]} / {head["state_root"]} is not the pinned mainnet genesis')
        log('l2-genesis', hash=head['hash'], state_root=head['state_root'])
        return head

    def check(self):
        view = self.native_view()
        if view is None:
            return 2
        planned = self.plan(view)
        head = self.produce('head', '--target', self.c['l2_db'])
        if planned is None:
            log('check', head=head, next=None)
            return 0
        number, parent, source, pending, slot = planned
        action = ('extend' if head['number'] == number - 1 and head['hash'] == parent else
                  'verify-produced' if head['number'] == number else 'HALT')
        log('check', head_number=head['number'], head_hash=head['hash'], next_number=number, parent=parent,
            anchor=source['block'], anchor_slot=slot, anchor_time=l1_slot_time(slot), pending=len(pending),
            action=action)
        return 0 if action != 'HALT' else 3


def main(argv):
    path = os.environ.get('BLOCH_SEQUENCER_CONFIG', '/etc/bloch-l2-mainnet-sequencer/config.json')
    if len(argv) >= 2 and argv[0] == '--config':
        path, argv = argv[1], argv[2:]
    if len(argv) != 1 or argv[0] not in ('init', 'check', 'step', 'run'):
        print(__doc__, file=sys.stderr)
        return 64
    try:
        sequencer = Sequencer(json.loads(Path(path).read_text()))
        if argv[0] == 'init':
            sequencer.init()
            return 0
        if argv[0] == 'check':
            return sequencer.check()
        if argv[0] == 'step':
            job = sequencer.step()
            print(json.dumps(job, sort_keys=True))
            return 0
        log('started', chain_id=CHAIN_ID, user_transactions=sequencer.c['user_transactions'],
            produce_sha256=sequencer.c['produce_sha256'])
        failures = 0
        while True:
            try:
                sequencer.step()
                failures = 0
            except Halt:
                raise
            except Exception as error:  # transient RPC/IO failure: bounded retry
                failures += 1
                log('retry', reason=f'{type(error).__name__}: {error}'[:400], failures=failures)
                if failures >= 20:
                    return 1
            time.sleep(sequencer.c['poll_seconds'])
    except Halt as error:
        log('halt', reason=str(error))
        return 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
