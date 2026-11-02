#!/usr/bin/env python3
"""Rehearsal of skip_idle_blocks on one private net with real Groth16 proofs. Loopback only, throwaway keys.

  FS=... idle_run.py PHASE...     phases: setup quiet wedge flush idle burst heartbeat user claim pace, or all

Each phase appends to $FS/results/verdicts.jsonl. Needs the fullstack-r3 harness (stack.py, fullstack.py) beside it, with the ports moved.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stack as st  # noqa: E402
from stack import L2, OPS, R, RUN, fs, l1, l2  # noqa: E402

sys.path.insert(0, str(R / 'src/settler'))
import settler_v3 as s  # noqa: E402

RESULTS = R / 'results'
RESULTS.mkdir(exist_ok=True)
DEADLINE = float(os.environ.get('IDLE_DEADLINE', time.time() + 5 * 3600))
PROOFS = 3 * 3600
MAX_IDLE = 2400
SAT = 10**8
LEVELS = ('settlement_age', 'l2_head_age', 'l2_finalized_age', 'deposit_wait', 'inbox_backlog', 'follower_status',
          'l2_finality_status', 'l2_finality_closed', 'attestors')


class Fail(Exception):
    pass


def record(phase, name, ok, **detail):
    entry = {'t': int(time.time()), 'phase': phase, 'check': name, 'ok': bool(ok), **detail}
    with (RESULTS / 'verdicts.jsonl').open('a') as f:
        f.write(json.dumps(entry, default=str) + '\n')
    print(json.dumps(entry, default=str), flush=True)
    return ok


def until(what, fn, timeout, step=5):
    end = min(time.time() + timeout, DEADLINE)
    while time.time() < end:
        try:
            value = fn()
        except Exception:  # noqa: BLE001 - a net restarting
            value = None
        if value:
            return value
        time.sleep(step)
    raise Fail(f'timed out: {what}')


def view():
    return l1('getl2settlement')


def accepted(v=None):
    a = (v or view()).get('accepted')
    return s.statement_fields(a['statement'])['l2_number'] if a else 0


def inbox():
    i = view()['inbox']
    return int(i['count']), int(i['consumed'])


def events(kind):
    found, path = [], RUN / 'logs/settler.log'
    for line in path.read_text(errors='replace').splitlines() if path.exists() else []:
        if line.startswith('{'):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get('event') == kind or e.get('kind') == kind or kind in e.values():
                found.append(e)
    return found


def tag(name):
    return l2('eth_getBlockByNumber', name, False)


def number(name):
    b = tag(name)
    return int(b['number'], 16) if b else None


def settler(script='settler', **options):
    st.down('settler')
    path = RUN / 'settler.json'
    config = json.loads(path.read_text())
    for key in ('skip_idle_blocks', 'max_idle_seconds', 'min_block_interval_seconds'):
        config.pop(key, None)
    config.update(options)
    path.write_text(json.dumps(config, indent=2) + '\n')
    st.unit('settler', ['/usr/bin/python3', '-u', R / f'src/{script}/settler_v3.py'], {'BLOCH_SETTLER_CONFIG': str(path)})
    st.up('settler')


def on(script='settler', max_idle=MAX_IDLE, **more):
    settler(script, skip_idle_blocks=True, max_idle_seconds=max_idle, **more)


def monitor(*flags):
    argv = [sys.executable, str(R / 'src/mainnet/rehearsal/ops/monitor_private.py'), str(RUN / 'state.json'), str(st.RPC[0]),
            '--profile', 'mainnet', '--phase', 'live', '--l2-rpc', f'A={L2}', '--follower-status', f'A={RUN}/follower-main/status.json',
            '--event-log', f'settler={RUN}/logs/settler.log', '--attest-drop', f'{OPS}/a0/state/outbox',
            '--build-json', str(OPS / 'no-gates.json'), '--json', '--alert-dry-run', *flags]
    for port in st.RPC[:3]:
        argv += ['--l1-rpc', f'http://127.0.0.1:{port}']
    done = subprocess.run(argv, capture_output=True, text=True, timeout=240)
    report = json.loads(done.stdout)
    return {c['check']: c['level'] for c in report['checks'] if c['check'] in LEVELS}


IDLE_FLAGS = ('--max-idle-seconds', str(MAX_IDLE), '--backlog-state', str(OPS / 'backlog.json'))


def deposit(name, sats):
    before = fs.wallet_input()
    count = inbox()[0]
    fs.deposit(name, sats)
    until('L1 includes the deposit', lambda: inbox()[0] > count and fs.wallet_input() != before, 300, 2)
    return time.time()


def age_of_source():
    return (l1('getchaininfo')['slot'] - view()['source']['slot']) * fs.SLOT_MS / 1000


def produced():
    return {e['number']: e for e in events('l2-block-produced')}


def block_at(n):
    return l2('eth_getBlockByNumber', hex(n), False)


# ── phases ────────────────────────────────────────────────────────────────────
def p_setup():
    if not RUN.exists():
        st.net()
    until('L1 past the flag day and HF3', lambda: l1('getchaininfo')['slot'] >= 32 * 11, 3600)
    (OPS / 'no-gates.json').write_text('{"l1_activation_epochs": {}}\n')
    if 'l2_address_user' not in fs.state():
        fs.l2key('user')
    if not (RUN / 'canonical').exists():
        up, st.up = st.up, lambda *names: None  # l2init would start the settler with its default configuration
        st.l2init()
        st.up = up
    st.attestor_units()
    st.up('follower', 'rpc', *[f'{k}{i}' for k in ('afol', 'attestor', 'afeed') for i in range(5)])
    record('setup', 'binaries', True, **{Path(p).name: fs.sha(p) for p in (fs.BIN, fs.PRODUCE, st.OUT / 'bloch-l2-native-follower',
                                                                           st.OUT / 'bloch-l2-settled-rpc', fs.PROVER, fs.ELF)},
           settler=fs.sha(R / 'src/settler/settler_v3.py'), old_settler=fs.sha(R / 'src/settler-724bf4c/settler_v3.py'))
    until('RPC up', lambda: number('latest') == 0, 300)


def p_quiet():
    on()
    time.sleep(180)
    v = view()
    record('quiet', 'no block on a quiet chain', not produced() and accepted(v) == 0 and number('latest') == 0,
           source_slot=v['source']['slot'], source_age_s=age_of_source(), holds=len(events('idle-hold')))


def p_wedge():
    settler('settler-724bf4c', skip_idle_blocks=True)
    time.sleep(30)
    deposit('user', 500 * SAT)
    time.sleep(300)
    v = view()
    record('wedge', 'commit 724bf4c never sees a deposit made while idle',
           v['inbox']['count'] == 1 and v['inbox']['consumed'] == 0 and v['source']['pending'] == [] and not produced() and number('latest') == 0,
           inbox=v['inbox'], pending=v['source']['pending'], latest=number('latest'), produced=len(produced()))


def p_flush():
    t0 = time.time()
    on()
    until('block 2 accepted', lambda: accepted() >= 2, PROOFS)
    blocks, v = produced(), view()
    record('flush', 'a deposit made while idle takes two blocks: an empty one on the old source, then the mint',
           blocks[1]['deposits'] == 0 and blocks[2]['deposits'] == 1 and v['inbox']['consumed'] == 1 and accepted(v) == 2,
           seconds=int(time.time() - t0), blocks={n: {k: e.get(k) for k in ('deposits', 'transactions')} for n, e in blocks.items()},
           times={n: int(block_at(n)['timestamp'], 16) for n in (1, 2)}, inbox=v['inbox'])
    balance = int(l2('eth_getBalance', '0x' + fs.state()['l2_address_user'], 'latest'), 16)
    record('flush', 'the deposit is on L2', balance == 500 * SAT * 10**10, balance_wei=balance)


def p_idle():
    start, n = time.time(), accepted()
    first = monitor(*IDLE_FLAGS)
    while time.time() - start < 1800:
        time.sleep(60)
        if accepted() != n or number('latest') != n:
            record('idle', 'height stays while idle', False, seconds=int(time.time() - start), accepted=accepted(), latest=number('latest'))
            return
    until('finalized reaches the idle head', lambda: number('finalized') == n, 1800)
    finality = l2('bloch_finality')
    record('idle', 'height stays 30 min; latest, safe and finalized all at the head; levels open',
           (number('latest'), number('safe'), number('finalized')) == (n, n, n) and finality['status']['state'] == 'ok',
           latest=n, finality_state=finality['status'].get('state'), status_age=finality['status'].get('age_s'))
    control, flagged = monitor(), monitor(*IDLE_FLAGS)
    record('idle', 'monitor: alarms without the flag, quiet with it',
           control['settlement_age'] != 'OK' and control['l2_head_age'] != 'OK' and flagged['settlement_age'] == 'OK' and flagged['l2_head_age'] == 'OK',
           control=control, flagged=flagged, first=first)
    rebuilt = RUN / 'rebuild-idle'
    shutil.rmtree(rebuilt, ignore_errors=True)
    out = fs.produce('reconstruct', '--target', rebuilt, '--l1-follower', RUN / 'follower-main/native',
                     '--timestamp-rule', f"1:{fs.state()['genesis_secs_approx']}:{fs.SLOT_MS}")
    head, ours = fs.produce('head', '--target', rebuilt), fs.produce('head', '--target', RUN / 'canonical')
    record('idle', 'a rebuild from L1 alone gives the same head', head['hash'] == ours['hash'], rebuilt=head, canonical=ours, native_blocks=out.get('native_blocks'))
    shutil.rmtree(rebuilt, ignore_errors=True)


def p_burst():
    n = accepted()
    monitor(*IDLE_FLAGS)
    t0 = deposit('user', 2 * SAT)
    during = monitor(*IDLE_FLAGS)
    until('the empty block is built', lambda: n + 1 in produced(), 600)
    t1 = deposit('user', 3 * SAT)
    t2 = deposit('user', 4 * SAT)
    until('deposits consumed', lambda: inbox()[0] == inbox()[1], PROOFS)
    t3 = time.time()
    blocks = produced()
    new = {k: blocks[k]['deposits'] for k in sorted(blocks) if k > n}
    record('burst', 'a burst of 3 deposits while idle or proving took at most 2 blocks past the flush', new[n + 1] == 0 and sum(new.values()) == 3 and len(new) <= 3,
           blocks=new, first_deposit_to_consumed_s=int(t3 - t0), later_deposits_to_consumed_s=[int(t3 - t1), int(t3 - t2)], monitor_while_waiting=during)


def p_heartbeat():
    until('settled', lambda: accepted() == number('latest'), PROOFS)
    n, t0 = accepted(), time.time()
    start_age = age_of_source()
    until('heartbeat block', lambda: n + 1 in produced(), MAX_IDLE + 300, 10)
    built_after = time.time() - t0 + start_age
    until('heartbeat accepted', lambda: accepted() == n + 1, PROOFS)
    last = [e for e in events('idle-end')][-1]
    record('heartbeat', 'no demand: one block at max_idle_seconds, accepted', last.get('reason') == 'max-idle' and MAX_IDLE - 60 <= built_after <= MAX_IDLE + 120,
           built_after_s=int(built_after), max_idle=MAX_IDLE, end=last, gap_s=int(block_at(n + 1)['timestamp'], 16) - int(block_at(n)['timestamp'], 16))


def p_user():
    on(max_idle=8 * 3600)
    until('source older than the fresh limit', lambda: age_of_source() > 660, 900)
    n = accepted()
    fs.txs('user', 10**15, 5 * SAT, 100 * SAT)
    until('the transaction block is accepted', lambda: fs.produce('withdrawal-proof', '--target', RUN / 'canonical', '--index', 0, '--number', number('latest')) and view()['withdrawals']['count'] >= 1, 2 * PROOFS, 15)
    blocks = produced()
    new = {k: (blocks[k].get('deposits'), blocks[k].get('transactions')) for k in sorted(blocks) if k > n}
    tx_block = min(k for k, v in new.items() if v[1])
    stamps = {k: int(block_at(k)['timestamp'], 16) for k in new}
    build_time = max(e.get('t', 0) for e in events('l2-block-produced')) or None
    record('user', 'transactions on an old source wait for a fresh one', new[n + 1][1] == 0 and tx_block == n + 2, blocks=new, stamps=stamps,
           da=len(events('da-included')), spool_closed=[e for e in events('idle-end') if not e.get('spool_open')][-1:], build=build_time)
    previous = int(block_at(n)['timestamp'], 16)
    source_age_at_tx = stamps[tx_block] - stamps[n + 1]
    record('user', 'the transaction block runs at fresh L1 time', stamps[n + 1] >= previous and source_age_at_tx > 0, flush_to_tx_s=source_age_at_tx, parent=previous)


def p_claim():
    n = accepted()
    t0 = time.time()
    w = until('small claim available without another block', lambda: (lambda x: x if x.get('claimable') and x['claimable']['count'] >= 1 else None)(view()['withdrawals']), 1800, 10)
    fs.claim(0)
    claimed = view()['withdrawals'].get('claimed')
    record('claim', 'a small claim matures and is included with no L2 block after the withdrawal', accepted() == n and bool(claimed) and int(claimed.get('claims', 0)) >= 1,
           seconds=int(time.time() - t0), claimable=w['claimable'], claimed=claimed, accepted=accepted(), head=number('latest'))
    signed = until('3 attestors sign', lambda: (lambda c: c if len(c) >= 3 else None)([p for p in OPS.glob('a*/state/outbox/**/*') if p.is_file()]), 1800, 15)
    record('claim', 'attestors sign the finalized root with no later block', accepted() == n, files=[str(p.relative_to(OPS)) for p in signed][:10], accepted=accepted())


def p_pace():
    pace = 900
    on(max_idle=8 * 3600, min_block_interval_seconds=pace)
    until('settled', lambda: accepted() == number('latest'), PROOFS)
    n = accepted()
    t0 = deposit('user', 6 * SAT)
    until('mint accepted', lambda: inbox()[0] == inbox()[1], 2 * PROOFS, 15)
    gaps = []
    blocks = sorted(k for k in produced() if k > n)
    stamps = [int(block_at(k)['timestamp'], 16) for k in [n] + blocks]
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    record('pace', 'blocks wait for the pacing, measured from the last acceptance', len(blocks) == 2 and gaps[-1] >= pace,
           pace=pace, blocks=blocks, stamp_gaps_s=gaps, deposit_to_consumed_s=int(time.time() - t0))


PHASES = {k[2:]: v for k, v in list(globals().items()) if k.startswith('p_')}


def main():
    names = sys.argv[1:]
    names = list(PHASES) if names == ['all'] else names
    for name in names:
        try:
            PHASES[name]()
            record(name, 'phase-done', True)
        except Exception as error:  # noqa: BLE001
            record(name, 'phase-failed', False, error=f'{type(error).__name__}: {error}'[:600])
            if name in ('setup', 'flush'):
                break
    (RESULTS / 'RUN-DONE').write_text(time.strftime('%FT%TZ', time.gmtime()) + '\n')


if __name__ == '__main__':
    main()
