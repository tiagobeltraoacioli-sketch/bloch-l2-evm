#!/usr/bin/env python3
"""A running settled RPC across a live rewind, with no L1: rewind and rebuild at the same number within one poll, then a rewind
that leaves the head lower. Rehearsal only, loopback. usage: rpc_rewind.py PRODUCE SETTLED_RPC WORKDIR PORT"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

produce_bin, rpc_bin, work, port = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4]
NET = ['--rules', 'mainnet', '--domain', '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733', '--genesis-time', '1786656679']
RULE = '1:1786656679:30000'
VAULT = '0x4200000000000000000000000000000000000019'
shutil.rmtree(work, ignore_errors=True)
work.mkdir(parents=True)
db = work / 'db'
fails = 0


def produce(*args):
    done = subprocess.run([produce_bin, *map(str, args), *NET], capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(done.stderr[-800:])
    return json.loads(done.stdout)


def call(method, *params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}', body, {'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def check(name, ok, detail=None):
    global fails
    fails += 0 if ok else 1
    print(json.dumps({'check': name, 'verdict': 'PASS' if ok else 'FAIL', 'detail': detail}), flush=True)


deposits = work / 'deposits.json'
deposits.write_text('[]')


def extend(number, rule_set):
    head = produce('head', '--target', db)
    return produce('extend', '--target', db, '--parent', head['hash'], '--anchor', f'{0xa0 + number:02x}' * 32, '--deposits', deposits,
                   '--timestamp-rule', RULE, '--anchor-slot', 100 * number, '--rule-set', rule_set)


def settled(expected, seconds=20):
    """Latest, the same block by number and a state read all agree on `expected` within `seconds`."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            latest = call('eth_getBlockByNumber', 'latest', False).get('result')
            by_number = call('eth_getBlockByNumber', hex(expected['number']), False).get('result')
            state = call('eth_call', {'to': VAULT, 'data': '0x'}, 'latest')
            if latest and by_number and 'error' not in state and latest['hash'] == by_number['hash'] == '0x' + expected['hash']:
                return True, round(seconds - (deadline - time.time()), 1)
        except OSError:
            pass
        time.sleep(0.25)
    return False, {'latest': latest and latest['hash'], 'by_number': by_number and by_number['hash'], 'state': state}


produce('init', '--target', db)
extend(1, 'base')
b2 = extend(2, 'base')
logf = (work / 'rpc.log').open('w')
rpc = subprocess.Popen([rpc_bin, '--data-dir', db, '--view-dir', work / 'view', '--finality-status', work / 'absent.json', '--network', 'aa' * 32, '--port', port,
                        '--poll-ms', '2000', *NET], stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
try:
    ok, detail = settled(b2, 60)
    check('the RPC serves the head before the rewind', ok, detail)
    # The same number, replaced within one poll.
    produce('rewind', '--target', db, '--number', 2, '--hash', b2['hash'])
    new2 = extend(2, 'next')
    check('the replacement block differs', new2['hash'] != b2['hash'])
    ok, detail = settled(new2)
    check('after a replacement at the same number: latest, by-number and state reads agree', ok, detail)
    code = call('eth_getCode', VAULT, 'latest').get('result', '')
    check('latest reads the next-rule state', len(code) > 2, code)
    old = call('eth_getBlockByHash', '0x' + b2['hash'], False).get('result')
    check('the removed block is no longer served by hash', old is None, old and old['hash'])
    b3 = extend(3, 'next')
    ok, detail = settled(b3)
    check('the next block is served', ok, detail)
    # A rewind that stays lower for a while.
    produce('rewind', '--target', db, '--number', 3, '--hash', b3['hash'])
    ok, detail = settled(new2)
    check('after a rewind the head goes back', ok, detail)
    new3 = extend(3, 'next')
    ok, detail = settled(new3)
    check('and comes forward again', ok, detail)
    log = (work / 'rpc.log').read_text(errors='replace')
    check('the RPC logged the switch', 'rules: next from block 2' in log)
finally:
    rpc.terminate()
    rpc.wait(20)
print(json.dumps({'verdict': 'PASS' if not fails else 'FAIL', 'fails': fails}))
sys.exit(1 if fails else 0)
