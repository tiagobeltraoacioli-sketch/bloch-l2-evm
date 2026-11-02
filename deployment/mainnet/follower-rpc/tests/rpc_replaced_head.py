#!/usr/bin/env python3
"""A running settled RPC across a replaced head, with no L1. Real: settled RPC, producer, private L2 database. The head is removed
with examples/rewind_head, as a rewind or a recovery would replace it. Loopback only.
usage: rpc_replaced_head.py PRODUCE REWIND_HEAD SETTLED_RPC WORKDIR PORT"""
import json, shutil, subprocess, sys, time, urllib.request
from pathlib import Path
produce_bin, rewind_bin, rpc_bin, work, port = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]), sys.argv[5]
DOM, GT = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733', '1786656679'
NET = ['--rules', 'mainnet', '--domain', DOM, '--genesis-time', GT]
shutil.rmtree(work, ignore_errors=True); work.mkdir(parents=True); db = work / 'db'; fails = 0
def produce(*a):
    d = subprocess.run([produce_bin, *map(str, a), *NET], capture_output=True, text=True)
    if d.returncode: raise SystemExit(d.stderr[-600:])
    return json.loads(d.stdout)
def rewind(h):
    d = subprocess.run([rewind_bin, db, h, DOM, GT], capture_output=True, text=True)
    if d.returncode: raise SystemExit(d.stderr[-600:])
    return json.loads(d.stdout)
def call(m, *p):
    r = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': list(p)}).encode(), {'content-type': 'application/json'})
    return json.loads(urllib.request.urlopen(r, timeout=10).read())
def check(name, ok, detail=None):
    global fails; fails += 0 if ok else 1
    print(('PASS ' if ok else 'FAIL ') + name + ('' if ok else f': {detail}'), flush=True)
(work / 'dep.json').write_text('[]')
def extend(slot, anchor):
    h = produce('head', '--target', db)['hash']
    return produce('extend', '--target', db, '--parent', h, '--anchor', anchor * 32, '--deposits', work / 'dep.json', '--timestamp-rule', f'1:{GT}:30000', '--anchor-slot', slot)
def settled(b, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        latest = call('eth_getBlockByNumber', 'latest', False).get('result') or {}
        by_number = call('eth_getBlockByNumber', hex(b['number']), False).get('result') or {}
        if latest.get('hash') == by_number.get('hash') == '0x' + b['hash']:
            return True, round(seconds - (end - time.time()), 1)
        time.sleep(0.25)
    return False, {'latest': latest.get('hash'), 'by_number': by_number.get('hash')}
produce('init', '--target', db); extend(100, 'a1'); b2 = extend(200, 'a2')
rpc = subprocess.Popen([rpc_bin, '--data-dir', db, '--view-dir', work / 'view', '--finality-status', work / 'absent.json', '--network', 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',
                        '--port', port, '--poll-ms', '2000', *NET], stdout=(work / 'rpc.log').open('w'), stderr=subprocess.STDOUT)
try:
    ok, d = settled(b2, 60); check('the RPC serves block 2', ok, d)
    call('eth_getBlockByHash', '0x' + b2['hash'], False)  # into the API's cache
    rewind(b2['hash']); n2 = extend(201, 'b2')
    check('the replacement differs', n2['hash'] != b2['hash'])
    ok, d = settled(n2); check('a head replaced at the same number within one poll is served', ok, d)
    old = call('eth_getBlockByHash', '0x' + b2['hash'], False).get('result')
    check('the removed block is not served by hash', old is None, old and old.get('hash'))
    for m in ('eth_getBlockTransactionCountByHash', 'eth_getBlockReceipts'):
        check(f'{m} of the removed block is null', call(m, '0x' + b2['hash']).get('result') is None)
    check('the replacement is served by hash', (call('eth_getBlockByHash', '0x' + n2['hash'], False).get('result') or {}).get('hash') == '0x' + n2['hash'])
    b3 = extend(300, 'a3'); ok, d = settled(b3); check('the next block is served', ok, d)
    rewind(b3['hash']); ok, d = settled(n2); check('a rewind that stays lower: the head goes back', ok, d)
    check('the removed block 3 is not served by hash', call('eth_getBlockByHash', '0x' + b3['hash'], False).get('result') is None)
    n3 = extend(301, 'b3'); ok, d = settled(n3); check('and forward again', ok, d)
finally:
    rpc.terminate(); rpc.wait()
print(f'{fails} failed'); sys.exit(1 if fails else 0)
