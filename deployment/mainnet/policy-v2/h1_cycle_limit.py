#!/usr/bin/env python3
"""Spec test H1 (agent 223): the SP1 host's preflight cycle limit with real binaries, execute-only, private database.

Builds blocks on a throwaway database (the settler's own measure_block path is not used, so nothing is removed) and
runs `bloch-evm-sp1-settlement-v3 --mainnet execute native-artifact` on each with BLOCH_PREFLIGHT_CYCLE_LIMIT set and no
wall-clock limit, in its own process group. Records exit code, verdict line, wall time, and whether any process of the
group or any SP1 segment it mapped is left. Cases: an empty block, a 1.5M-gas and a 4.9M-gas modexp call, each at
limits 60M and 180M instructions, plus the 1.5M call without a limit (the reference cost).
Environment as policy_v2_check.py: SC_WORK, SC_PRODUCE, SC_HOST, SC_GUEST, SC_ANCHOR, SC_SOURCE, SC_LIB."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.environ['SC_LIB'])
import heavy_gen as g  # noqa: E402
import settler_v3 as S  # noqa: E402

W = Path(os.environ['SC_WORK'])
shutil.rmtree(W, ignore_errors=True)
(W / 'home/tmp').mkdir(parents=True)
NET = ['--rules', 'mainnet', '--domain', '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
       '--genesis-time', '1786656679']
PRODUCE, HOST, GUEST = os.environ['SC_PRODUCE'], os.environ['SC_HOST'], os.environ['SC_GUEST']
anchor, slot = Path(os.environ['SC_ANCHOR']).read_text().split()
source = Path(os.environ['SC_SOURCE']).read_text()
RULE = ['--timestamp-rule', '1:1786656679:30000', '--anchor-slot', slot]


def produce(*args):
    out = subprocess.run([PRODUCE, *args, *NET], capture_output=True, text=True, timeout=600)
    if out.returncode:
        raise RuntimeError(out.stderr[-400:])
    return json.loads(out.stdout)


def segments():
    return {p.name for p in Path('/dev/shm').iterdir() if p.name.startswith(('sp1_', 'sem.sp1_'))}


db = W / 'db'
produce('init', '--target', str(db))
head = produce('head', '--target', str(db))['hash']
key = (1 << 210) | 77
deposits = W / 'deposits.json'
deposits.write_text(json.dumps([{'height': 2, 'tx_index': 1, 'txid': f'{2:064x}', 'vout': 1, 'sats': 100_000_000_000,
                                  'recipient': g.address(key).hex()}]))
b1 = produce('extend', '--target', str(db), '--parent', head, '--anchor', anchor, '--deposits', str(deposits), *RULE)
head = b1['hash']
MODEXP = g.memory_blob_call(5, g.modexp_input(64, b'\xff' * 32, 64), 64)
cases = {'empty': [], 'modexp-1.5M': [g.tx(key, 700770, 0, 1_500_000, b'', 0, MODEXP, max_fee=4 * 10**9, tip=10**9).hex()],
         'modexp-4.9M': [g.tx(key, 700770, 0, 4_900_000, b'', 0, MODEXP, max_fee=10 * 10**9, tip=10**9).hex()]}
request = source + 'cd' * 32 + '\n1\n1\n1\n'
(W / 'empty.json').write_text('[]')
artifacts = {}
for name, raws in cases.items():
    copy = W / f'db-{name}'
    shutil.copytree(db, copy, symlinks=True)
    pool = W / f'{name}.json'
    pool.write_text(json.dumps(raws))
    block = produce('extend', '--target', str(copy), '--parent', head, '--anchor', anchor, '--deposits', str(W / 'empty.json'),
                    *RULE, '--txs', str(pool), '--max-gas', '15000000', '--max-bytes', '114688', '--max-txs', '64')
    art = W / f'{name}.artifact'
    produce('export', '--target', str(copy), '--number', '2', '--out', str(art))
    artifacts[name] = (art, block['transactions'])
(W / 'request.txt').write_text(request)
results = []
plan = [('modexp-1.5M', None), ('empty', 60_000_000), ('empty', 180_000_000), ('modexp-1.5M', 60_000_000),
        ('modexp-1.5M', 180_000_000), ('modexp-4.9M', 60_000_000), ('modexp-4.9M', 180_000_000)]
for name, limit in plan:
    art, txs = artifacts[name]
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(W / 'home'), 'TMPDIR': str(W / 'home/tmp'), 'SP1_CIRCUIT_MODE': 'release',
           'BLOCH_NATIVE_L2_REQUEST': str(W / 'request.txt'), 'BLOCH_NATIVE_L2_ARTIFACT': str(art)}
    if limit:
        env['BLOCH_PREFLIGHT_CYCLE_LIMIT'] = str(limit)
    before = segments()
    log = W / f'{name}-{limit}.log'
    started = time.monotonic()
    with log.open('w') as out:
        proc = subprocess.Popen([HOST, '--mainnet', 'execute', 'native-artifact', GUEST], env=env, stdout=out,
                                stderr=subprocess.STDOUT, start_new_session=True)
        seen = set()
        while proc.poll() is None:
            seen |= S.group_segments(proc.pid, '/dev/shm')
            time.sleep(0.5)
            if time.monotonic() - started > 900:
                os.killpg(proc.pid, signal.SIGKILL)
    seconds = round(time.monotonic() - started, 1)
    time.sleep(1)
    try:
        os.killpg(proc.pid, 0)
        left_group = True
    except ProcessLookupError:
        left_group = False
    text = log.read_text(errors='replace')
    verdict = [line for line in text.splitlines() if 'over cycle limit' in line or 'Settlement V3 cost' in line
               or 'instructions in' in line or 'exceeded' in line]
    result = {'case': name, 'transactions': txs, 'limit': limit, 'exit': proc.returncode, 'seconds': seconds,
              'verdict': verdict[-3:], 'group_left': left_group, 'segments_mapped': len(seen),
              'segments_left': sorted((segments() - before) & seen)}
    results.append(result)
    print(json.dumps(result), flush=True)
print(json.dumps({'h1': results}), flush=True)
