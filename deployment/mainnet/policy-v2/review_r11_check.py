#!/usr/bin/env python3
"""Agent 243 (review r11): S7 (A243-1) and S8 (A243-12) added to agent 223's driver; run with SCENARIOS=S7,S8.

Sequencer policy v2 with real binaries (agent 223, round 11; spec test H2, plus H1's run times). Agent 135's
review_r8_check.py (codex/policy-rereview-r8-20261102, 5129b15) and the S6 of review_r9_tip.py, run against the v2
settler, the producer with `select`, and the SP1 host with BLOCH_PREFLIGHT_CYCLE_LIMIT. Changes are marked
"ADAPTED (a223)": both budget keys (the instruction budget sets the cycle limit, 2x), bans instead of strikes, the
cycle-limit verdict counted next to timeouts, S5b (a run ended by the cycle limit leaves no segment), S6, and a
timing line per measurement (kind, seconds) for H1. Execute-only, private database, throwaway keys, no L1, no proof.

Original header follows.

Review r8 (agent 135): the settler's budget path at f4a4bce with real binaries, no proof and no L1. Modelled on
settler_check.py: real producer (`select`, `extend`, `export`), real guest in execute mode, a private database, throwaway
keys. Each scenario states the property; a failed check is the finding.

  S1  cheapest-first splits a sender's nonces: a later nonce the block did not include loses its spool file.
  S2  cheapest-first ignores the tip: floor-tip low-gas modexp calls keep a 100x-tip honest transaction out.
  S3  a same-nonce replacement resets the unmeasured count: a timing-out transaction is measured every block, never
      quarantined, its sender never struck.
  S5  two measurements at once, one killed on its timeout: the other one's segments survive and it returns a cost.

Environment as settler_check.py: SC_WORK, SC_PRODUCE, SC_HOST, SC_GUEST, SC_ANCHOR, SC_SOURCE, SC_LIB."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.environ['SC_LIB'])
import heavy_gen as g  # noqa: E402
import settler_v3 as S  # noqa: E402
import sequencer_policy_v2 as P  # noqa: E402  ADAPTED (a223)
S_OVER = P.OVER_LIMIT

W = Path(os.environ['SC_WORK'])
shutil.rmtree(W, ignore_errors=True)
(W / 'txpool').mkdir(parents=True)
(W / 'work').mkdir()
(W / 'home/tmp').mkdir(parents=True)
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
CHAIN = 700770
anchor, slot = Path(os.environ['SC_ANCHOR']).read_text().split()
source = Path(os.environ['SC_SOURCE']).read_text()
EVENTS = []
_log = S.log


def log(event, **fields):
    EVENTS.append((event, fields))
    _log(event, **fields)


S.log = log
s = S.Settler.__new__(S.Settler)
s.c = {'produce': os.environ['SC_PRODUCE'], 'l2_db': str(W / 'db'), 'txpool_dir': str(W / 'txpool'), 'workdir': str(W / 'work'),
       'home': str(W / 'home'), 'user_transactions': True, 'timestamp_rule': '1:1786656679:30000', 'max_block_gas': 15_000_000,
       'max_block_bytes': 114_688, 'max_block_txs': 128, 'prover': os.environ['SC_HOST'], 'guest': os.environ['SC_GUEST'],
       'max_block_sp1_gas': 30_000_000, 'max_block_instructions': 30_000_000,  # ADAPTED (a223)
       'preflight_execute_seconds': 120, 'min_tip_wei': 100_000_000, 'max_tx_gas': 5_000_000,
       'preflight_max_runs': 24, 'preflight_max_seconds': 600}  # ADAPTED (a223): v2 has no strike (24 h ban)
s.run = subprocess.run
s.work = W / 'work'
s.clock = time.monotonic
s.policy_clock = time.time  # ADAPTED (a223)
TIMES = []  # ADAPTED (a223): (kind, seconds, sp1_gas, instructions) of every measurement, for H1
_measure = S.Settler.measure_block


def timed(self, *args):
    started = time.monotonic()
    result, report = _measure(self, *args)
    kind = 'over-limit' if result == S_OVER else 'cost' if result is not None else 'no-cost'
    TIMES.append((kind, round(time.monotonic() - started, 1), getattr(result, 'sp1_gas', None),
                  getattr(result, 'instructions', None), self.c.get('max_block_instructions')))
    print(json.dumps({'measure': TIMES[-1]}), flush=True)
    return result, report


S.Settler.measure_block = timed
s.spool_open = True
s.network_args = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
s.prover_args = ['--mainnet']
s.c.setdefault('l2_genesis', '00' * 32)
s.produce('init', '--target', s.c['l2_db'])
head = s.produce('head', '--target', s.c['l2_db'])['hash']
number, consumed, dep_h = 0, 0, 1
checks = []


def check(name, ok, **fields):
    checks.append(bool(ok))
    print(json.dumps({'check': name, 'ok': bool(ok), **fields}), flush=True)


def note(**fields):
    print(json.dumps({'note': fields}), flush=True)


def dep(recipient, sats=1_000_000):
    global dep_h
    dep_h += 1
    return {'height': dep_h, 'tx_index': 1, 'txid': f'{dep_h:064x}', 'vout': 1, 'sats': sats, 'recipient': recipient.hex()}


def request(deposits, n=None):
    # ADAPTED (a223): the release host refuses a previous settlement for L2 block 1 (host-metrics did not check it).
    n = number if n is None else n
    previous = '00' * 32 if n == 1 else 'cd' * 32
    return source + previous + f'\n{consumed + len(deposits)}\n{consumed}\n{consumed + len(deposits)}\n'


def block(deposits=()):
    global number, head, consumed
    number += 1
    d = W / 'work' / f'{number:08d}'
    d.mkdir()
    (d / 'deposits.json').write_text(json.dumps(list(deposits)))
    s.preflight_source = request(deposits)
    consumed += len(deposits)
    b = s.extend_within_budget(head, anchor, d / 'deposits.json', slot, number)
    head = b['hash']
    return b, d


def measure(raws, deposits=(), settler=None, tag='cal'):
    """The cost of the next block built from exactly these raws (hex), as the planner would measure it."""
    settler = settler or s
    d = W / 'work' / f'measure-{tag}-{time.monotonic_ns()}'
    d.mkdir()
    (d / 'deposits.json').write_text(json.dumps(list(deposits)))
    settler.preflight_request = request(deposits, number + 1)
    started = time.monotonic()
    cost, report = settler.measure_block(head, anchor, d / 'deposits.json', slot, number + 1, raws, 0)
    return cost, report, time.monotonic() - started


def spool(name, raw):
    (W / 'txpool' / f'{name}.tx').write_text(raw.hex() + '\n')


def names():
    return sorted(p.stem for p in (W / 'txpool').glob('*.tx'))


def quarantined():
    q = W / 'txpool-quarantine'
    return sorted(p.stem for p in q.glob('*.tx')) if q.exists() else []


def clear():
    for p in (W / 'txpool').glob('*.tx'):
        p.unlink()


def account_nonce(key):
    return int(s.produce('account', '--target', s.c['l2_db'], '--address', g.address(key).hex())['nonce'])


nonce = {}


def tx(key, to, data, gas, value=0, tip=10**9, max_fee=4 * 10**9, at=None):
    n = nonce.setdefault(key, 0) if at is None else at
    raw = g.tx(key, CHAIN, n, gas, to, value, data, max_fee=max_fee, tip=tip)
    if at is None:
        nonce[key] += 1
    return raw


MODEXP = g.memory_blob_call(5, g.modexp_input(64, b'\xff' * 32, 64), 64)  # report 90's 'pc-modexp-512b' init code
honest, other, honest2 = (1 << 201) | 7, (1 << 203) | 9, (1 << 205) | 3
RUN = set(os.environ.get('SCENARIOS', 'S1,S2,S3,S5').split(','))
attackers = [(1 << 202) | (i + 11) for i in range(8)]
mallory = (1 << 204) | 5
everyone = [honest, other, honest2, mallory, *attackers]
b, _ = block([dep(g.address(k), 100_000_000_000) for k in everyone])
check('setup: deposits only', b['deposits'] == len(everyone) and b['transactions'] == 0)
A = g.address(other)

def s1():
    # S1. alice (honest): nonce 0 a 600k-gas call, nonce 1 a transfer. bob (other): a 300k-gas call. Budget calibrated so that
    # each call fits alone and all three do not.
    s.c['max_block_sp1_gas'] = s.c['max_block_instructions'] = 10**12  # ADAPTED (a223): calibrate without a cycle limit
    h0 = tx(honest, b'', MODEXP, 600_000)
    h1 = tx(honest, A, b'', 21_000, value=1)
    b0 = tx(other, b'', MODEXP, 300_000)
    c_h0, _, _ = measure([h0.hex()])
    c_b0, _, _ = measure([b0.hex()])
    c_all, r_all, _ = measure([h0.hex(), h1.hex(), b0.hex()])
    base1, _, _ = measure([])
    # Margin: a quarter of the smaller share, so that base growth over the next blocks cannot push alice's call over.
    s.c['max_block_sp1_gas'] = max(c_h0.sp1_gas, c_b0.sp1_gas) + (min(c_h0.sp1_gas, c_b0.sp1_gas) - base1.sp1_gas) // 4
    s.c['max_block_instructions'] = 10 * s.c['max_block_sp1_gas']  # ADAPTED (a223): SP1 gas binds, as in the original
    note(scenario='S1', h0=c_h0.sp1_gas, b0=c_b0.sp1_gas, all=c_all.sp1_gas, budget=s.c['max_block_sp1_gas'],
         gas={t['hash'][:8]: t['gas_used'] for t in r_all['tx_stats']})
    spool('s1-alice-n0-call', h0)
    spool('s1-alice-n1-transfer', h1)
    spool('s1-bob-n0-call', b0)
    b, _ = block()
    included = [t['hash'] for t in b.get('tx_stats', [])]
    h1_hash = S.keccak256(h1).hex()
    check('S1: alice nonce 1, not included in the block, keeps its spool file',
          h1_hash not in included and 's1-alice-n1-transfer' in names(), included=len(included), spool=names())
    for _ in range(3):
        block()
    check('S1: both of alice nonces are eventually included', account_nonce(honest) == 2,
          alice_nonce=account_nonce(honest), spool=names())
    clear()
    nonce[honest] = account_nonce(honest)
    nonce[other] = account_nonce(other)


def s2():
    # S2. seven attackers, each a 150k-gas modexp call at the floor tip, against an honest 10 KB-calldata transfer
    # (about 181k gas used, cheap to prove) at 100x the tip. Budget calibrated: the seven fit, the seven plus honest do not.
    floor = s.c['min_tip_wei']
    s.c['max_block_sp1_gas'] = s.c['max_block_instructions'] = 10**12  # ADAPTED (a223)
    honest_raw = tx(honest2, A, b'\x01' * 10_000, 200_000, value=1, tip=100 * floor, max_fee=40 * 10**9)
    c_base, _, _ = measure([])
    c_honest, _, _ = measure([honest_raw.hex()])
    probe = [tx(k, b'', MODEXP, 150_000, tip=floor, at=nonce.get(k, 0)) for k in attackers[:7]]
    c_seven, r_seven, _ = measure([p.hex() for p in probe])
    share = c_honest.sp1_gas - c_base.sp1_gas
    s.c['max_block_sp1_gas'] = c_seven.sp1_gas + share // 2
    s.c['max_block_instructions'] = 10 * s.c['max_block_sp1_gas']  # ADAPTED (a223)
    note(scenario='S2', base=c_base.sp1_gas, honest=c_honest.sp1_gas, seven=c_seven.sp1_gas, budget=s.c['max_block_sp1_gas'],
         attacker_gas=[t['gas_used'] for t in r_seven['tx_stats']][:2], scale_at_150M=round(150e6 / max(1, (c_seven.sp1_gas - c_base.sp1_gas) / 7)))
    spool('s2-honest', honest_raw)
    served = None
    for i in range(3):
        for j, k in enumerate(attackers[:7]):
            spool(f's2-attacker{j}-{i}', tx(k, b'', MODEXP, 150_000, tip=floor))
        b, _ = block()
        if 's2-honest' not in names():
            served = i + 1
            break
    check('S2: the honest transaction at 100x the tip is served while floor-tip low-gas calls fill the block',
          served is not None, blocks=3, held=[f['held'] for e, f in EVENTS if e == 'txs-held'][-1:], spool=names())
    b, _ = block()
    check('S2 control: without the attackers the honest transaction is served', 's2-honest' not in names(),
          transactions=b['transactions'])
    clear()
    for k in [honest2, *attackers]:
        nonce[k] = account_nonce(k)


def s3():
    # S3. mallory's 4.9M-gas modexp call times out (20 s, as settler_check's forced timeout). After every block she replaces
    # it with the same nonce and a 10% higher tip (what the RPC admits), so the 2/4/8 wait never applies.
    s.c.update(max_block_sp1_gas=30_000_000, max_block_instructions=30_000_000,
               preflight_execute_seconds=int(os.environ.get('S3_PREFLIGHT_SECONDS', 20)),  # ADAPTED (a223): 60 in v2
               preflight_max_seconds=180)  # ADAPTED (a223): cycle limit 60M instructions
    timeouts = []
    real_measure = s.measure_block


    def counting(*args):
        started = time.monotonic()
        cost, report = real_measure(*args)
        if cost is None:
            timeouts.append(round(time.monotonic() - started, 1))
        return cost, report


    s.measure_block = counting
    tip, current, per_block = 10**9, None, []
    n0 = account_nonce(mallory)
    for i in range(5):
        if current:
            (W / 'txpool' / f'{current}.tx').unlink(missing_ok=True)
        tip = tip * 11 // 10
        current = f's3-mallory-r{i}'
        spool(current, tx(mallory, b'', MODEXP, 4_900_000, tip=tip, max_fee=10 * 10**9, at=n0))
        before = len(timeouts)
        started = time.monotonic()
        block()
        per_block.append({'timeouts': len(timeouts) - before, 'seconds': round(time.monotonic() - started)})
    state = json.loads((s.work / 'sequencer-policy.json').read_text())
    check('S3: a replaced unmeasurable transaction is quarantined or its sender banned within 5 blocks',
          any(q.startswith('s3-') for q in quarantined()) or g.address(mallory).hex() in state.get('bans', {}),
          per_block=per_block, quarantine=quarantined(), bans=state.get('bans'))  # ADAPTED (a223)
    check('S3: no measurement timed out; the heavy call ended at the cycle limit', not timeouts and
          any(t[0] == 'over-limit' for t in TIMES), timeouts=timeouts)  # ADAPTED (a223), spec H2
    s.measure_block = real_measure
    clear()



def s5():
    # S5. Two measurements at once: one heavy and killed at its 10 s limit, one normal with 120 s. The kill and the segment
    # cleanup of the first must leave the second's segments alone.
    def segments():
        return {p.name for p in Path('/dev/shm').iterdir() if p.name.startswith(('sp1_', 'sem.sp1_'))}


    keep = ('measure-live', 'measure-killed', 'measure-alone')
    real_rmtree = S.shutil.rmtree
    S.shutil.rmtree = lambda path, *a, **k: None if any(x in str(path) for x in keep) else real_rmtree(path, *a, **k)

    def tail(cost_report_seconds, tag):
        logs = sorted((W / 'work').glob(f'measure-{tag}-*/preflight-0/execute.log'))
        return logs[-1].read_text(errors='replace')[-1500:] if logs else None

    def memory_events():
        try:
            cg = Path('/proc/self/cgroup').read_text().split('::')[-1].strip()
            return Path('/sys/fs/cgroup' + cg + '/memory.events').read_text().split()
        except OSError as error:
            return str(error)
    before = segments()
    s.c['max_block_sp1_gas'] = s.c['max_block_instructions'] = 10**12  # ADAPTED (a223): no cycle limit in reach
    quick = copy.copy(s)
    quick.c = dict(s.c, preflight_execute_seconds=10)
    slow = copy.copy(s)
    slow.c = dict(s.c, preflight_execute_seconds=120)
    for one in (quick, slow):  # s may carry an instance-bound measure_block (S3): bind each copy's own
        one.measure_block = S.Settler.measure_block.__get__(one)
    heavy_raw = tx(mallory, b'', MODEXP, 4_900_000, tip=10**9, max_fee=10 * 10**9, at=account_nonce(mallory)).hex()
    normal_raws = [tx(k, b'', MODEXP, 1_500_000, tip=10**9, at=account_nonce(k)).hex() for k in attackers[:3]]
    alone = measure(normal_raws, settler=slow, tag='alone')
    note(scenario='S5 control', alone_cost=repr(alone[0]), alone_seconds=round(alone[2], 1), memory_events=memory_events(),
         log=None if alone[0] else tail(alone, 'alone'))
    out = {}
    removed_before = sum(1 for e, _ in EVENTS if e == 'prover-shm-removed')
    t1 = threading.Thread(target=lambda: out.__setitem__('killed', measure([heavy_raw], settler=quick, tag='killed')))
    t2 = threading.Thread(target=lambda: out.__setitem__('live', measure(normal_raws, settler=slow, tag='live')))
    t2.start()
    time.sleep(1)
    t1.start()
    t1.join()
    t2.join()
    time.sleep(2)
    killed, live = out['killed'], out['live']
    note(scenario='S5 logs', memory_events=memory_events(), live_log=tail(live, 'live'), killed_log=tail(killed, 'killed'))
    removed = [f['segments'] for e, f in EVENTS if e == 'prover-shm-removed'][removed_before:]
    check('S5: the run killed at its limit has no cost; the concurrent run returns its cost',
          killed[0] is None and live[0] is not None and live[0].sp1_gas > 0,
          killed_seconds=round(killed[2], 1), live_seconds=round(live[2], 1), live_cost=repr(live[0]), removed=removed)
    check('S5: no new SP1 segment is left behind', not sorted(segments() - before), left=sorted(segments() - before))
    # S5b. ADAPTED (a223): the same heavy call ended by the cycle limit (exit 3), not by a kill: no segment left.
    limited = copy.copy(s)
    limited.c = dict(s.c, max_block_instructions=90_000_000, preflight_execute_seconds=120)
    limited.measure_block = S.Settler.measure_block.__get__(limited)
    before = segments()
    over = measure([heavy_raw], settler=limited, tag='limited')
    time.sleep(2)
    check('S5b: a run ended by the 180M cycle limit gives the verdict and leaves no segment',
          over[0] == S_OVER and not sorted(segments() - before), seconds=round(over[2], 1),
          left=sorted(segments() - before))




def s6():
    # S6 (agent 135, review_r9_tip.py). ADAPTED (a223): three senders resend a 4.9M-gas modexp at a 100 gwei tip they never
    # pay, against an honest 1 gwei transfer; v2 budget 30M with the cycle limit 60M.
    s.c.update(max_block_sp1_gas=30_000_000, max_block_instructions=30_000_000,
               preflight_execute_seconds=int(os.environ.get('S6_PREFLIGHT_SECONDS', 30)),
               preflight_max_seconds=180)
    alice = (1 << 206) | 1
    A6 = g.address(alice)
    m6 = [(1 << 207) | (i + 3) for i in range(int(os.environ.get('S6_ATTACKERS', 3)))]  # ADAPTED (a223)
    block([dep(A6, 100_000_000_000)] + [dep(g.address(k), 100_000_000_000) for k in m6])
    block()
    honest_raw = g.tx(alice, CHAIN, 0, 21_000, A6, 1, b'', max_fee=4 * 10**9, tip=10**9)
    (W / 'txpool' / 's6-honest.tx').write_text(honest_raw.hex() + '\n')
    sends, per_block = {i: 0 for i in range(len(m6))}, []
    for n in range(4):
        for i, k in enumerate(m6):
            name = W / 'txpool' / f's6-evil{i}-{sends[i]}.tx'
            if sends[i] == 0 or not name.exists():
                sends[i] += 1
                raw = g.tx(k, CHAIN, 0, 4_900_000, b'', 0, MODEXP, max_fee=110 * 10**9, tip=100 * 10**9 + sends[i])
                (W / 'txpool' / f's6-evil{i}-{sends[i]}.tx').write_text(raw.hex() + '\n')
        started = time.monotonic()
        b, _ = block()
        plan = [f for e, f in EVENTS if e == 'block-plan'][-1]
        per_block.append({'seconds': round(time.monotonic() - started), 'runs': plan['runs'],
                          'exhausted': plan['exhausted'], 'transactions': b['transactions']})
        print(json.dumps({'s6-block': number, **per_block[-1]}), flush=True)
        if not (W / 'txpool' / 's6-honest.tx').exists():
            break
    check('S6: the honest 1 gwei transfer is served while three senders resend 100 gwei calls they never pay',
          not (W / 'txpool' / 's6-honest.tx').exists() and len(per_block) == 1, per_block=per_block, sends=sends,
          quarantine=quarantined())
    held = [f for e, f in EVENTS if e == 'txs-held']
    check('S6: resent nonces of banned senders are refused by the gate without a run',
          sum(1 for t in TIMES[-12:] if t[0] == 'over-limit') <= 3, held=held[-1:] if held else None)
    clear()



def s7():
    # S7 (agent 243, A243-1): seven senders with standing keep one SP1-heavy, low-gas call pending in every block at a
    # low tip; a fresh sender's transfer at 10x their tip must be served. Budget calibrated as S2: the seven fit, the
    # seven plus the honest transfer do not.
    s.c['max_block_sp1_gas'] = s.c['max_block_instructions'] = 10**12
    squat = [(1 << 208) | (i + 1) for i in range(7)]
    fresh = (1 << 209) | 1
    block([dep(g.address(k), 100_000_000_000) for k in squat + [fresh]])
    for i, k in enumerate(squat):
        nonce[k] = account_nonce(k)
        spool(f's7-seed{i}', tx(k, A, b'', 21_000, value=1, tip=10**9))
    block()
    check('S7 setup: the seven squatters were included once (standing)', not [n for n in names() if n.startswith('s7-seed')])
    for k in squat + [fresh]:
        nonce[k] = account_nonce(k)
    honest_raw = tx(fresh, A, b'\x01' * 10_000, 200_000, value=1, tip=10 * 10**9, max_fee=40 * 10**9)
    c_base, _, _ = measure([])
    c_honest, _, _ = measure([honest_raw.hex()])
    probe = [tx(k, b'', MODEXP, 150_000, tip=10**9, at=nonce[k]) for k in squat]
    c_seven, _, _ = measure([p.hex() for p in probe])
    s.c['max_block_sp1_gas'] = c_seven.sp1_gas + (c_honest.sp1_gas - c_base.sp1_gas) // 2
    s.c['max_block_instructions'] = 10 * s.c['max_block_sp1_gas']
    note(scenario='S7', base=c_base.sp1_gas, honest=c_honest.sp1_gas, seven=c_seven.sp1_gas, budget=s.c['max_block_sp1_gas'])
    spool('s7-honest', honest_raw)
    per_block = []
    for i in range(3):
        for j, k in enumerate(squat):
            if not [n for n in names() if n.startswith(f's7-squat{j}-')]:
                spool(f's7-squat{j}-{i}', tx(k, b'', MODEXP, 150_000, tip=10**9))
        b, _ = block()
        per_block.append(b['transactions'])
        if 's7-honest' not in names():
            break
    check('S7: a fresh sender at 10x the tip is served in the first block against seven squatters with standing',
          's7-honest' not in names() and len(per_block) == 1, per_block=per_block,
          held=[f['held'] for e, f in EVENTS if e == 'txs-held'][-1:])
    clear()


RUNTIME_SSTORE_CALLER = bytes.fromhex('335f5500')  # CALLER PUSH0 SSTORE STOP: writes slot 0
INIT_SSTORE_CALLER = bytes.fromhex('63335f55005f526004601cf3')  # PUSH4 runtime, PUSH0 MSTORE, RETURN 4 bytes from 28


def s8():
    # S8 (agent 243, A243-12): seven senders call a contract that writes slot 0, at descending tips from 4.5 gwei, each
    # below the write price for one new slot (about 43k gas x tip < 200 uBLCH). The gate peels one per pass; an honest
    # transfer in the same block must still be served.
    s.c['max_block_sp1_gas'] = s.c['max_block_instructions'] = 1_000_000_000
    deployer = (1 << 210) | 9
    chain = [(1 << 211) | (i + 1) for i in range(7)]
    fresh = (1 << 212) | 1
    block([dep(g.address(k), 100_000_000_000) for k in [deployer, fresh] + chain])
    for k in [deployer, fresh] + chain:
        nonce[k] = account_nonce(k)
    at = nonce[deployer]
    spool('s8-deploy', tx(deployer, b'', INIT_SSTORE_CALLER, 200_000))
    block()
    contract = g.keccak(g.rlp([g.address(deployer), at]))[12:]
    check('S8 setup: the slot-0 contract is deployed', 's8-deploy' not in names(), contract=contract.hex())
    for i, k in enumerate(chain):
        spool(f's8-chain{i}', tx(k, contract, b'', 60_000, tip=(45 - i) * 10**8, max_fee=10 * 10**9))
    spool('s8-honest', tx(fresh, A, b'', 21_000, value=1, tip=10**9))
    before = len(EVENTS)
    b, _ = block()
    unsettled = [f for e, f in EVENTS[before:] if e == 'gate-did-not-settle']
    check('S8: an honest transfer is served in the block where a slot chain peels the gate', 's8-honest' not in names(),
          transactions=b['transactions'], gate_did_not_settle=bool(unsettled),
          stats=[(t['gas_used'], t['fresh_slots']) for t in b.get('tx_stats', [])],
          held=[f['held'] for e, f in EVENTS[before:] if e == 'txs-held'][-1:])
    clear()

for name, fn in (('S1', s1), ('S2', s2), ('S3', s3), ('S5', s5), ('S6', s6), ('S7', s7), ('S8', s8)):
    if name in RUN:
        fn()
print(json.dumps({'times': TIMES}), flush=True)
print(json.dumps({'passed': sum(checks), 'of': len(checks)}), flush=True)
sys.exit(0 if all(checks) else 1)
