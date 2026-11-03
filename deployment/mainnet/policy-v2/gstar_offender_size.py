#!/usr/bin/env python3
"""Agent 243: smallest gas used of a transaction over the preflight cycle limit (G*), execute-only, private database.
Modelled on agents/223's h1_cycle_limit.py; reuses 223's binaries read-only (copied). One transaction per block, each a
contract creation looping one precompile until about 60k gas is left. No cycle limit: records instructions, SP1 gas."""
import json, os, shutil, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, os.environ['SC_LIB'])
import heavy_gen as g  # noqa: E402

W = Path(os.environ['SC_WORK']); shutil.rmtree(W, ignore_errors=True); (W / 'home/tmp').mkdir(parents=True)
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

db = W / 'db'; produce('init', '--target', str(db)); head = produce('head', '--target', str(db))['hash']
key = (1 << 210) | 243
deposits = W / 'deposits.json'
deposits.write_text(json.dumps([{'height': 2, 'tx_index': 1, 'txid': f'{2:064x}', 'vout': 1, 'sats': 100_000_000_000,
                                  'recipient': g.address(key).hex()}]))
head = produce('extend', '--target', str(db), '--parent', head, '--anchor', anchor, '--deposits', str(deposits), *RULE)['hash']
sc = g.scenarios()
cases = [('pc-kzg', 300_000), ('pc-kzg', 450_000), ('pc-blake2f-100k', 450_000), ('pc-modexp-512b', 450_000),
         ('pc-bnpair', 450_000), ('pc-kzg', 200_000)]
(W / 'empty.json').write_text('[]'); (W / 'request.txt').write_text(source + 'cd' * 32 + '\n1\n1\n1\n')
for name, gas in cases:
    tag = f'{name}-{gas}'
    copy = W / f'db-{tag}'; shutil.copytree(db, copy, symlinks=True)
    pool = W / f'{tag}.json'
    pool.write_text(json.dumps([g.tx(key, 700770, 0, gas, b'', 0, sc[name], max_fee=4 * 10**9, tip=10**9).hex()]))
    block = produce('extend', '--target', str(copy), '--parent', head, '--anchor', anchor, '--deposits', str(W / 'empty.json'),
                    *RULE, '--txs', str(pool), '--max-gas', '15000000', '--max-bytes', '114688', '--max-txs', '64')
    art = W / f'{tag}.artifact'; produce('export', '--target', str(copy), '--number', '2', '--out', str(art))
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(W / 'home'), 'TMPDIR': str(W / 'home/tmp'), 'SP1_CIRCUIT_MODE': 'release',
           'BLOCH_NATIVE_L2_REQUEST': str(W / 'request.txt'), 'BLOCH_NATIVE_L2_ARTIFACT': str(art)}
    log = W / f'{tag}.log'; started = time.monotonic()
    with log.open('w') as out:
        rc = subprocess.run([HOST, '--mainnet', 'execute', 'native-artifact', GUEST], env=env, stdout=out,
                            stderr=subprocess.STDOUT, start_new_session=True, timeout=900).returncode
    text = log.read_text(errors='replace')
    lines = [l for l in text.splitlines() if 'Settlement V3 cost' in l or 'instructions' in l]
    stats = (block.get('tx_stats') or [{}])[0]
    print(json.dumps({'case': name, 'gas_limit': gas, 'gas_used': stats.get('gas_used'), 'txs': block.get('transactions'),
                      'exit': rc, 'seconds': round(time.monotonic() - started, 1), 'lines': [l[:200] for l in lines[-3:]]}),
          flush=True)
    shutil.rmtree(copy, ignore_errors=True)
