#!/usr/bin/env python3
"""Stuck-block rehearsal on a private loopback net: drives drillctl.py, the real settler_v3 and l2_stuck_block.py.

Phases (each records evidence under results/, resumable through results/phase-*.done):
  base     net up, L2 block 1 accepted, two funded L2 users (real L1 deposits, real proofs)
  discard  a real 15M-gas block that OOMs the prover, with honest transactions, a withdrawal and a deposit beside it;
           triage, discard, resume; the replacement settles, attacker quarantined, nothing lost
  elsewhere a block that OOMs under a low cap; export, prove outside the settler, refusal of discard, import; same hash
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

R = Path(os.environ['FS'])
RUN = R / 'run'
RES = R / 'results'
RES.mkdir(exist_ok=True)
D = ['python3', str(R / 'src/rehearsal/drills/drillctl.py')]
TOOL = ['python3', str(R / 'src/l2_stuck_block.py')]
GEN = ['python3', '-I', str(R.parent / 'tools/heavy_gen.py')]
ENV = {**os.environ, 'BLOCH_SETTLER_V3': str(R / 'src/settler/settler_v3.py'), 'DRILL_SETTLER_DIR': str(R / 'src/settler'),
       'DRILL_RPC_BIN': str(R / 'out/bloch-l2-settled-rpc-v21')}
sys.path.insert(0, str(R / 'src/rehearsal/drills'))
sys.path.insert(0, str(R / 'src/rehearsal'))
import drillctl as d  # noqa: E402
fs = d.fs


def note(event, **fields):
    line = json.dumps({'time': time.strftime('%FT%TZ', time.gmtime()), 'event': event, **fields})
    print(line, flush=True)
    with (RES / 'timeline.jsonl').open('a') as f:
        f.write(line + '\n')


def ctl(*args, check=True, timeout=None):
    r = subprocess.run([*D, *map(str, args)], env=ENV, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise SystemExit(f'drillctl {args}: {r.stdout[-500:]} {r.stderr[-500:]}')
    return r.stdout


def tool(*args, retry_75=False, deadline=3600):
    end = time.time() + deadline
    while True:
        r = subprocess.run([*TOOL, args[0], '--config', str(RUN / 'settler.json'), *map(str, args[1:])], env=ENV, capture_output=True, text=True)
        if r.returncode == 75 and retry_75 and time.time() < end:
            note('tool-not-yet', args=args[0], out=r.stdout[-200:])
            time.sleep(20)
            continue
        return r.returncode, json.loads(r.stdout) if r.stdout.strip().startswith('{') else {'raw': r.stdout, 'err': r.stderr[-800:]}


def events():
    return d.events()


def wait_event(pred, what, timeout):
    end = time.time() + timeout
    while time.time() < end:
        for e in events():
            if pred(e):
                return e
        if (RUN / 'settler.halted').exists():
            raise SystemExit(f'settler halted waiting for {what}')
        time.sleep(3)
    raise SystemExit(f'timeout waiting for {what}')


def accepted_number():
    v = d.safe_rpc('getl2settlement')
    return fs_statement(v)


def fs_statement(v):
    if not isinstance(v, dict) or not v.get('accepted'):
        return None
    return d.statement(v)


def head():
    return fs.produce('head', '--target', RUN / 'canonical')


def account(address):
    return fs.produce('account', '--target', RUN / 'canonical', '--address', address)


def snapshot(name):
    (RES / f'{name}.json').write_text(ctl('check', '--deep', check=False))
    for f in ('settler.log',):
        if (RUN / f).exists():
            shutil.copy2(RUN / f, RES / f'{name}.{f}')


def phase(name):
    return (RES / f'phase-{name}.done').exists()


def done(name, **f):
    (RES / f'phase-{name}.done').write_text(json.dumps(f) + '\n')
    note(f'phase-{name}-done', **f)


def rpc_send(raw):
    return d.rpc('eth_sendRawTransaction', ['0x' + raw.strip().removeprefix('0x')], port=d.L2_RPC)


def wait_accepted(number, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = d.safe_rpc('getl2settlement')
        if isinstance(v, dict) and v.get('accepted'):
            import settler_v3 as S
            f = S.statement_fields(v['accepted']['statement'])
            if f['l2_number'] >= number:
                return f
        time.sleep(5)
    raise SystemExit(f'timeout waiting for L2 {number} accepted')


def base():
    if not RUN.exists():
        ctl('net')
    deadline = time.time() + 400
    while time.time() < deadline:
        c = d.safe_rpc('getchaininfo')
        if isinstance(d.safe_rpc('getl2settlement'), dict) and (c.get('height') or 0) > 5:
            break
        time.sleep(5)
    if not (RUN / 'settler.json').exists():
        ctl('l2init')
        # This host has a Docker daemon: the pinned Gnark image, not the drill's rootfs shim.
        shim = R / 'bin/docker'
        shim.write_text('#!/bin/sh\nexec /usr/bin/docker "$@"\n')
        cfg = json.loads((RUN / 'settler.json').read_text())
        cfg['max_block_txs'] = 128
        cfg['max_consecutive_failures'] = 100
        (RUN / 'settler.json').write_text(json.dumps(cfg, indent=2) + '\n')
        (RUN / 'prover.cap').write_text('56G\n')
        for name in ('user', 'attacker'):
            ctl('l2key', name)
    ctl('up', 'follower', 'rpc', 'settler')
    for name in ('user', 'attacker'):
        ctl('deposit', name, 2_000_000_000)
        time.sleep(8)
    s = fs.state()
    wait_accepted(2, 5400)
    deadline = time.time() + 5400
    while time.time() < deadline:
        h = head()
        if all(int(account(s[f'l2_address_{n}'])['balance_wei']) > 0 for n in ('user', 'attacker')):
            break
        time.sleep(15)
    done('base', head=h['number'], user=account(s['l2_address_user']), attacker=account(s['l2_address_attacker']))


def raw_transfer(nonce, to_tail, wei=10**12):
    staged = RUN / 'signed' / f'hv-{time.time_ns()}.tx'
    staged.parent.mkdir(exist_ok=True)
    fs.produce('sign-tx', '--key', RUN / 'user.l2.key', '--nonce', nonce, '--to', '00' * 19 + to_tail, '--value-wei', wei, '--out', staged)
    return staged.read_text().strip()


def raw_withdraw(nonce, script, sats):
    staged = RUN / 'signed' / f'hv-{time.time_ns()}.tx'
    fs.produce('sign-tx', '--key', RUN / 'user.l2.key', '--nonce', nonce, '--withdraw-to', script, '--sats', sats, '--out', staged)
    return staged.read_text().strip()


def discard_phase():
    s = fs.state()
    user = s['l2_address_user']
    before = {'user': account(user), 'attacker': account(s['l2_address_attacker']), 'head': head()}
    start_line = len(events())
    nonce = int(d.rpc('eth_getTransactionCount', ['0x' + user, 'pending'], port=d.L2_RPC), 16)
    honest = [rpc_send(raw_transfer(nonce + i, f'{0x60 + i:02x}')) for i in range(3)]
    withdrawal = rpc_send(raw_withdraw(nonce + 3, s['wallet_script'], 100_000_000))
    gen = RUN / 'attacker-tx'
    shutil.rmtree(gen, ignore_errors=True)
    subprocess.run([*GEN, 'pc-modexp-512b', '--key', str(RUN / 'attacker.l2.key'), '--out', str(gen), '--block-gas', '15000000', '--txs', '1',
                    '--nonce', str(int(d.rpc('eth_getTransactionCount', ['0x' + s['l2_address_attacker'], 'pending'], port=d.L2_RPC), 16))], check=True)
    attacker = rpc_send(next(gen.iterdir()).read_text())
    ctl('deposit', 'user', 300_000_000)
    note('stuck-sent', honest=honest, withdrawal=withdrawal, attacker=attacker)
    a = attacker.removeprefix('0x')
    e = wait_event(lambda e: e.get('event') == 'l2-block-produced' and e.get('transactions', 0) > 0 and e.get('number', 0) > before['head']['number'] - 1
                   and (RUN / 'canonical').exists() and stuck_has(e, a), 'block with the attacker tx', 3600)
    number = e['number']
    note('stuck-block', **e)
    t0 = time.time()
    # The settler must fail at least twice on its own: real prover failures, no operator.
    while sum(1 for x in events()[start_line:] if x.get('event') == 'prover-failed') < 2:
        if time.time() - t0 > 7200:
            note('no-prover-failure-in-2h')
            break
        time.sleep(10)
    failed = [x for x in events()[start_line:] if x.get('event') in ('prover-failed', 'retry')]
    note('settler-stuck', failures=failed, seconds=round(time.time() - t0))
    snapshot('stuck-before')
    latest = d.safe_rpc('eth_getBlockByNumber', ['latest', False], port=d.L2_RPC)
    safe = d.safe_rpc('eth_getBlockByNumber', ['safe', False], port=d.L2_RPC)
    receipt = d.safe_rpc('eth_getTransactionReceipt', [attacker], port=d.L2_RPC)
    note('rpc-while-stuck', latest=(latest or {}).get('number'), safe=(safe or {}).get('number'), attacker_receipt_status=(receipt or {}).get('status') if isinstance(receipt, dict) else str(receipt)[:100],
         attacker_gas_used=(receipt or {}).get('gasUsed') if isinstance(receipt, dict) else None)
    # Operator from here on.
    ctl('down', 'settler')
    time.sleep(5)
    subprocess.run(['pkill', '-KILL', '-f', f'{R}/out/bloch-evm-sp1-settlement-v3 --mainnet prove-groth16'], check=False)
    ctl('down', 'rpc')
    rc, status = tool('status')
    note('tool-status', rc=rc, status=status)
    t1 = time.time()
    follow = ('--follower-state', RUN / 'follower', '--follower-status', RUN / 'follower-status.json')
    triage_file = RES / 'triage.json'
    rc, tri = tool('triage', '--budget', os.environ.get('DRILL_BUDGET', '30000000'), *follow, '--out', triage_file, retry_75=True)
    note('tool-triage', rc=rc, kept=tri.get('kept'), exclude=tri.get('exclude'), after=tri.get('instructions_after'), steps=tri.get('steps'), seconds=round(time.time() - t1), other=None if 'kept' in tri else tri)
    if rc:
        raise SystemExit('triage failed')
    rc, plan = tool('discard', *follow, '--exclude-file', triage_file)
    note('tool-discard-plan', rc=rc, plan=plan)
    rc, applied = tool('discard', *follow, '--exclude-file', triage_file, '--apply', retry_75=True)
    note('tool-discard-applied', rc=rc, result=applied, head_after=head())
    if rc:
        raise SystemExit('discard failed')
    ctl('up', 'rpc', 'settler')
    f = wait_accepted(number, 5400)
    t2 = time.time()
    note('replacement-accepted', statement=f, old_hash=applied.get('old_hash'), recovery_seconds=round(t2 - t1))
    deadline = time.time() + 3600
    while time.time() < deadline:
        # Settle a further block too: the chain really moves on.
        v = d.safe_rpc('getl2settlement')
        import settler_v3 as S
        if S.statement_fields(v['accepted']['statement'])['l2_number'] >= number + 1:
            break
        time.sleep(10)
    after = {'user': account(user), 'attacker': account(s['l2_address_attacker']), 'head': head()}
    rcp = {h: d.safe_rpc('eth_getTransactionReceipt', [h], port=d.L2_RPC) for h in honest + [withdrawal, attacker]}
    summary = {h: ({'status': r.get('status'), 'block': r.get('blockNumber'), 'hash': r.get('blockHash')} if isinstance(r, dict) else r) for h, r in rcp.items()}
    note('after-discard', before=before, after=after, receipts=summary, quarantine=sorted(p.name for p in (RUN / 'txpool-quarantine').iterdir()))
    snapshot('discard-after')
    done('discard', number=number, replacement=f['l2_hash'], old=applied.get('old_hash'))


def stuck_has(event, attacker):
    block = None
    for p in (RUN / 'work').glob(f'{event["number"]:08d}-*/block.json'):
        block = json.loads(p.read_text())
    return bool(block) and attacker in block.get('included', [])


def elsewhere_phase():
    s = fs.state()
    user = s['l2_address_user']
    cap = os.environ.get('DRILL_LOW_CAP', '12G')
    start_line = len(events())
    (RUN / 'prover.cap').write_text(cap + '\n')
    nonce = int(d.rpc('eth_getTransactionCount', ['0x' + user, 'pending'], port=d.L2_RPC), 16)
    sent = [rpc_send(raw_transfer(nonce + i, f'{0x70 + (i % 16):02x}')) for i in range(4)]
    e = wait_event(lambda e: e.get('event') == 'l2-block-produced' and e.get('transactions', 0) >= 1 and events().index(e) >= start_line, 'low-cap block', 3600)
    number = e['number']
    note('low-cap-block', **e)
    t0 = time.time()
    while True:
        evs = events()[start_line:]
        failures = [x for x in evs if x.get('event') == 'prover-failed' and f'{number:08d}-' in x.get('directory', '')]
        if len(failures) >= 2:
            break
        if any(x.get('event') == 'accepted' and x.get('number') == number for x in evs):
            raise SystemExit('the low-cap proof succeeded: lower the cap')
        if time.time() - t0 > 7200:
            raise SystemExit('no failures in 2 h')
        time.sleep(10)
    note('low-cap-stuck', failures=failures, seconds=round(time.time() - t0))
    ctl('down', 'settler')
    time.sleep(5)
    subprocess.run(['pkill', '-KILL', '-f', f'{R}/out/bloch-evm-sp1-settlement-v3 --mainnet prove-groth16'], check=False)
    t1 = time.time()
    job = R / f'job-{number}'
    rc, exported = tool('export-job', '--out', job)
    note('tool-export', rc=rc, result=exported)
    proof = job / 'external.proof'
    # "A bigger machine": a separate prover run with its own environment and a higher cap, under the host lock.
    env = {'PATH': f'{R}/bin:/usr/bin:/bin', 'HOME': str(R / 'home'), 'TMPDIR': str(R / 'home/tmp'), 'XDG_RUNTIME_DIR': f'/run/user/{os.getuid()}',
           'RAYON_NUM_THREADS': '24', 'SP1_CIRCUIT_MODE': 'release', 'SP1_GNARK_IMAGE': fs.GNARK,
           'BLOCH_NATIVE_L2_REQUEST': str(job / 'native-request.txt'), 'BLOCH_NATIVE_L2_ARTIFACT': str(job / 'block.artifact')}
    r = subprocess.run(['/usr/bin/flock', str(fs.LOCK), 'systemd-run', '--user', '--scope', '-q', '-p', 'MemoryMax=56G', '-p', 'MemorySwapMax=0',
                        str(fs.PROVER), '--mainnet', 'prove-groth16', 'native-artifact', str(fs.ELF), str(proof)], env=env, capture_output=True, text=True)
    note('external-proof', rc=r.returncode, seconds=round(time.time() - t1), tail=r.stdout[-300:])
    if r.returncode:
        raise SystemExit('external proof failed')
    rc, wrong = tool('import-proof', '--proof', job / 'block.artifact')
    note('tool-import-garbage', rc=rc, result=wrong)
    rc, imported = tool('import-proof', '--proof', proof)
    note('tool-import', rc=rc, result=imported)
    follow = ('--follower-state', RUN / 'follower', '--follower-status', RUN / 'follower-status.json')
    rc, refused = tool('discard', *follow, '--exclude-all')
    note('tool-discard-refused-after-proof', rc=rc, result=refused)
    (RUN / 'prover.cap').write_text('56G\n')
    h = head()
    ctl('up', 'settler')
    f = wait_accepted(number, 3600)
    note('same-block-accepted', statement=f, db_hash_before=h['hash'], same=f['l2_hash'] == h['hash'] or h['number'] != number, recovery_seconds=round(time.time() - t1))
    snapshot('elsewhere-after')
    done('elsewhere', number=number, hash=f['l2_hash'])


if __name__ == '__main__':
    what = sys.argv[1]
    if what == 'base' and not phase('base'):
        base()
    elif what == 'discard' and not phase('discard'):
        discard_phase()
    elif what == 'elsewhere' and not phase('elsewhere'):
        elsewhere_phase()
    elif what == 'stop':
        ctl('stop', check=False)
        subprocess.run(['pkill', '-KILL', '-f', f'{R}/out/bloch-evm-sp1-settlement-v3 --mainnet prove-groth16'], check=False)
    note(f'{what}-exit')
