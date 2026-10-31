#!/usr/bin/env python3
"""At-limit test of the settled RPC on a real private L2 database.
usage: limit.py WORK OLD_RPC NEW_RPC KIT WITHDRAWAL_ROOT
WORK holds chain/ (private DB) and blocks.jsonl (real number, hash, state root of every block).
Entries have the exact fields and sizes of a real follower status (native fields synthetic: no L1 here)."""
import json, os, subprocess, sys, time, urllib.request
from pathlib import Path
WORK, OLD, NEW, KIT, WROOT = Path(sys.argv[1]), sys.argv[2], sys.argv[3], Path(sys.argv[4]), sys.argv[5]
sys.path[:0] = [str(KIT), str(KIT / 'attestor')]
import l2_monitor as M
import attestor_lib as L
NET = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
DOM = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
RULES = ['--rules', 'mainnet', '--domain', DOM, '--genesis-time', '1786656679']
PORT = 24601
LIMIT = 16 * 1048576
results = []
def check(name, ok, detail=''):
    results.append(bool(ok)); print(('PASS ' if ok else 'FAIL ') + name + (f': {detail}' if detail != '' else ''), flush=True)
blocks = [json.loads(l) for l in open(WORK / 'blocks.jsonl')]
def entry(n):
    b = blocks[n - 1]; assert b['number'] == n
    seed = f'{n:064x}'
    return {'commitment': seed[::-1], 'l2_hash': b['hash'], 'l2_number': n, 'l2_state_root': b['state_root'],
            'native_block': seed, 'native_slot': 300000 + n, 'withdrawals': {'count': 0, 'root': WROOT}}
GEN = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
def base():
    return {'chain_id': 700770, 'l2_genesis': {'activation_block': 'ab' * 32, 'activation_slot': 187200, 'finalized': True,
            'hash': GEN, 'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'},
            'native_finalized_block': 'cd' * 32, 'native_finalized_epoch': 7000, 'native_finalized_slot': 224000, 'network': NET,
            'production_finality': False, 'safe_settlement': None, 'settlement_policy': 'ef' * 32, 'verified_blocks': 200000,
            'verified_slot': 224100, 'verified_tip': '12' * 32, 'written_at_unix': int(time.time())}
ST = WORK / 'run' / 'status.json'
LOG = WORK / 'run' / 'status.settlements.jsonl'
def replace(path, data):
    t = path.with_suffix('.tmp'); t.write_bytes(data); t.replace(path)
def write_v2(n):
    d = base(); d['schema'] = 'bloch.l2.native-follower-status.v2'; d['finalized_settlements'] = [entry(i) for i in range(1, n + 1)]
    replace(ST, json.dumps(d, indent=2, sort_keys=True).encode()); return ST.stat().st_size
class V3:
    def __init__(self): self.n = 0; self.bytes = 0; self.d = L.keccak256(L.SETTLEMENT_LOG_DOMAIN); LOG.write_bytes(b'')
    def grow(self, n):
        new = [json.dumps(entry(i), separators=(',', ':'), sort_keys=True).encode() + b'\n' for i in range(self.n + 1, n + 1)]
        with open(LOG, 'ab') as f: f.write(b''.join(new))
        for l in new: self.d = L.keccak256(self.d + l)
        self.bytes += sum(map(len, new)); self.n = n
        d = base(); d['schema'] = 'bloch.l2.native-follower-status.v3'; d['finalized_settlements_count'] = n
        d['finalized_settlements_recent'] = [entry(i) for i in range(max(1, n - 63), n + 1)]
        d['settlement_log'] = {'file': LOG.name, 'entries': n, 'bytes': self.bytes, 'digest': self.d.hex()}
        replace(ST, json.dumps(d, indent=2, sort_keys=True).encode()); return ST.stat().st_size
def call(method, params=()):
    r = urllib.request.Request(f'http://127.0.0.1:{PORT}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode(), {'content-type': 'application/json'})
    return json.loads(urllib.request.urlopen(r, timeout=30).read())
class Rpc:
    def __init__(self, binary, tag):
        self.log = WORK / 'run' / f'{tag}.log'
        self.view = WORK / 'run' / f'view-{tag}-{time.time_ns()}'
        self.p = subprocess.Popen([binary, '--data-dir', WORK / 'chain', '--view-dir', self.view, '--finality-status', ST, '--network', NET, '--port', str(PORT), '--poll-ms', '2000', *RULES], stdout=open(self.log, 'a'), stderr=subprocess.STDOUT)
        self.t0 = time.time()
        for _ in range(600):
            try:
                call('eth_chainId'); break
            except Exception: time.sleep(0.2)
    def stop(self):
        self.p.send_signal(2)
        try: self.p.wait(30)
        except subprocess.TimeoutExpired: self.p.kill(); self.p.wait()
    def hwm(self):
        return next(int(l.split()[1]) // 1024 for l in open(f'/proc/{self.p.pid}/status') if l.startswith('VmHWM'))
    def cpu(self):
        f = open(f'/proc/{self.p.pid}/stat').read().rsplit(')', 1)[1].split(); return (int(f[11]) + int(f[12])) / os.sysconf('SC_CLK_TCK')
    def text(self): return self.log.read_text()
def finalized():
    r = call('bloch_finality')['result']; return (r or {}).get('finalized_height')
def wait(n, seconds=240):
    t = time.time()
    while time.time() - t < seconds:
        if finalized() == n: return time.time() - t
        time.sleep(0.1)
    return None
def idle_cost(rpc, seconds=40):
    c = rpc.cpu(); time.sleep(seconds); return (rpc.cpu() - c) / seconds * 2  # CPU seconds per 2 s poll
def probe(n=200):
    ts = []
    for _ in range(n):
        t = time.time(); call('eth_blockNumber'); ts.append(time.time() - t); time.sleep(0.02)
    ts.sort(); return ts[len(ts) // 2] * 1000, ts[-1] * 1000
def monitor(status_path, doc):
    r = M.Report(); M.status_size('t', str(status_path), doc, M.PROFILES['mainnet'], r)
    return {c['check'].split('[')[0]: c['level'] for c in r.checks}, [c['message'] for c in r.checks if 'size' in c['check']][0]
(WORK / 'run').mkdir(exist_ok=True)
for f in (WORK / 'run').glob('*'):
    if f.is_file(): f.unlink()
TOP = len(blocks)
print(f'database: {TOP} real blocks')

# How many settlements fit, in the real pretty-printed shape
small = write_v2(1000); per = (write_v2(2000) - small) / 1000
FIT = int((LIMIT - small) / per) + 1000 - 50
print(f'INFO bytes per settlement in a v2 status: {per:.1f}; {FIT} settlements just below 16 MiB')
size = write_v2(FIT); check('fixture is just below the limit', size <= LIMIT, size)
over = FIT + 200; assert over < TOP
doc = json.loads(ST.read_text())
levels, msg = monitor(ST, doc); check('monitor at the limit: CRIT long before finality stops is already raised', levels['follower_status_size'] == 'CRIT', msg)
for n, want in ((14000, 'OK'), (16000, 'WARN'), (23000, 'CRIT')):
    size = write_v2(n); levels, msg = monitor(ST, json.loads(ST.read_text()))
    print(f'INFO monitor at {n} settlements, {size} bytes: {levels["follower_status_size"]}')
    check(f'monitor grade at {n} settlements', levels['follower_status_size'] == want, msg)

print('--- v2.1 binary, v2 status (reproduces the bug)')
write_v2(FIT); old = Rpc(OLD, 'old')
d = wait(FIT); check('v2.1: finalized reaches the last settlement below the limit', d is not None, d); print(f'INFO v2.1 first read of {FIT} settlements: {d}')
cost = idle_cost(old); ph = probe(); print(f'INFO v2.1 at {FIT}: {cost:.3f} CPU s per poll, RSS peak {old.hwm()} MiB, eth_blockNumber p50 {ph[0]:.1f} ms, max {ph[1]:.1f} ms')
size = write_v2(over); print(f'INFO status now {size} bytes, {over} settlements')
d = wait(over, 20); check('v2.1: above 16 MiB finality does NOT advance (the known bug)', d is None and finalized() == FIT, finalized())
check('v2.1: the log says so', 'finality status too large' in old.text())
old.stop()

print('--- next build, same v2 status above the limit (RPC-only recovery)')
new = Rpc(NEW, 'new-v2')
d = wait(over); check('next: finalized advances past the old limit on v2', d is not None, d); print(f'INFO next first read of {over} v2 settlements: {d}')
cost = idle_cost(new); ph = probe(); print(f'INFO next on v2 at {over}: {cost:.3f} CPU s per poll, RSS peak {new.hwm()} MiB, eth_blockNumber p50 {ph[0]:.1f} ms, max {ph[1]:.1f} ms')
r = call('bloch_settlement', [1])['result']; check('next v2: bloch_settlement oldest', r and r['l2_hash'] == blocks[0]['hash'] and r['finalized'] is True, r)
r = call('bloch_settlement', [over])['result']; check('next v2: bloch_settlement newest', r and r['l2_hash'] == blocks[over - 1]['hash'], r)
print('--- running RPC, the follower upgrades: v2 to v3 in place')
log = V3(); size = log.grow(over + 10)
d = wait(over + 10); check('next: v2 to v3 in place advances', d is not None, d)
check('v3 status is small', size < 200_000, size); print(f'INFO v3 status {size} bytes, log {LOG.stat().st_size} bytes at {over + 10}')
check('no error so far', 'finality not advanced' not in new.text(), new.text()[-300:])
new.stop()

print('--- next build, v3 from a cold start at the limit, then growth')
new = Rpc(NEW, 'new-v3')
d = wait(over + 10); check('next v3: cold start reaches the tip', d is not None, d); print(f'INFO cold read of {over + 10} v3 settlements: {d}')
measures = {}
for n in (over + 10, 60000, 120000):
    if n > TOP: continue
    if n != over + 10:
        t = time.time(); log.grow(n); g = time.time() - t; d = wait(n); check(f'next v3: grows to {n}', d is not None, d); print(f'INFO grow to {n}: fixture {g:.1f} s, finality after {d}')
    t = time.time(); log.grow(n + 1); d = wait(n + 1, 30); check(f'next v3: one more settlement at {n + 1} is final within a poll', d is not None and d < 5, d)
    cost = idle_cost(new); ph = probe(); measures[n] = cost
    print(f'INFO next v3 at {n + 1}: new-entry latency {d:.2f} s, {cost:.3f} CPU s per poll, RSS peak {new.hwm()} MiB, eth_blockNumber p50 {ph[0]:.1f} ms, max {ph[1]:.1f} ms')
    r = call('bloch_settlement', [n + 1])['result']; check(f'bloch_settlement newest at {n + 1}', r and r['l2_hash'] == blocks[n]['hash'], r)
    r = call('bloch_settlement', [17])['result']; check(f'bloch_settlement old at {n + 1}', r and r['l2_hash'] == blocks[16]['hash'], r)
top = log.n
r = call('bloch_settlement', [top + 1])['result']; check('bloch_settlement above the tip is null', r is None, r)
r = call('bloch_getWithdrawalProof', [0]); check('withdrawal method is not frozen', r.get('error', {}).get('code') == -32042, r)
levels, msg = monitor(ST, json.loads(ST.read_text())); check('monitor on v3: size and log OK', levels == {'follower_settlement_log': 'OK', 'follower_status_size': 'OK'}, levels); print('INFO', msg)
got = L.follower_settlements(json.loads(ST.read_text()), ST); check('attestor reader takes the log', len(got) == top and got[-1]['l2_hash'] == blocks[top - 1]['hash'], len(got))
t = time.time(); L.follower_settlements(json.loads(ST.read_text()), ST); print(f'INFO attestor reader cycle at {top}: {time.time() - t:.3f} s')

print('--- damage')
saved = LOG.read_bytes()
LOG.write_bytes(saved[:-10]); keep = (log.n, log.bytes, log.d)
new_n = log.n + 1; log = log  # the status names more than the torn file holds
d = base(); d['schema'] = 'bloch.l2.native-follower-status.v3'; line = json.dumps(entry(new_n), separators=(',', ':'), sort_keys=True).encode() + b'\n'
d['finalized_settlements_count'] = new_n; d['finalized_settlements_recent'] = [entry(i) for i in range(new_n - 63, new_n + 1)]
d['settlement_log'] = {'file': LOG.name, 'entries': new_n, 'bytes': log.bytes + len(line), 'digest': L.keccak256(log.d + line).hex()}
replace(ST, json.dumps(d, indent=2, sort_keys=True).encode())
time.sleep(6); check('truncated log: safe and finalized close', finalized() is None and call('bloch_finality')['result']['status']['state'] == 'invalid', call('bloch_finality')['result'])
check('truncated log: the tag answers an error', 'error' in call('eth_getBlockByNumber', ['finalized', False]))
check('truncated log: logged', 'settlement log' in new.text(), new.text()[-200:])
check('truncated log: reads keep serving', 'result' in call('eth_blockNumber'))
LOG.write_bytes(saved + line); time.sleep(0.1)
d2 = wait(new_n, 10); check('repaired log: finality reopens, rereading the log', d2 is not None, d2)
r = call('bloch_settlement', [17])['result']; check('repaired log: old settlement served again', r and r['l2_hash'] == blocks[16]['hash'], r)
log.bytes += len(line); log.d = L.keccak256(log.d + line); log.n = new_n
# forged line, right size, digest of the good file
bad = bytearray(LOG.read_bytes()); line2 = json.dumps(entry(new_n + 1), separators=(',', ':'), sort_keys=True).encode() + b'\n'
forged = line2.replace(blocks[new_n]['hash'].encode(), ('0' * 64).encode())
with open(LOG, 'ab') as f: f.write(forged)
d = base(); d['schema'] = 'bloch.l2.native-follower-status.v3'; d['finalized_settlements_count'] = new_n + 1
fe = json.loads(forged); d['finalized_settlements_recent'] = [entry(i) for i in range(new_n - 62, new_n + 1)] + [fe]
d['settlement_log'] = {'file': LOG.name, 'entries': new_n + 1, 'bytes': log.bytes + len(forged), 'digest': L.keccak256(log.d + forged).hex()}
replace(ST, json.dumps(d, indent=2, sort_keys=True).encode())
time.sleep(6); check('self-consistent log with a hash not on the local chain: levels close', finalized() is None, finalized())
check('it is logged as differing from the local header', 'differs from the local canonical header' in new.text())
new.stop()
print(f'{sum(results)}/{len(results)} passed')
(WORK / 'limit.verdict').write_text(f'{sum(results)}/{len(results)}\n')
sys.exit(0 if all(results) else 1)
