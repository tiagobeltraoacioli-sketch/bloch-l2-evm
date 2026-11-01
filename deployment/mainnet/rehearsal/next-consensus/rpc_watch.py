#!/usr/bin/env python3
"""Record what a running settled RPC serves across a live rewind: one line per change of its latest block, and each answer for
the block number it served before. Rehearsal only, loopback. usage: rpc_watch.py PORT OUT_JSONL DEADLINE_SECONDS"""
import json
import sys
import time
import urllib.request

port, out, deadline = int(sys.argv[1]), sys.argv[2], time.time() + int(sys.argv[3])
VAULT = '0x4200000000000000000000000000000000000019'


def call(method, *params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}', body, {'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        reply = json.loads(response.read())
    return reply.get('result'), reply.get('error')


seen, last = {}, None
with open(out, 'a') as log:
    while time.time() < deadline:
        record = {'at': time.strftime('%FT%TZ', time.gmtime())}
        try:
            latest, error = call('eth_getBlockByNumber', 'latest', False)
            if error or not latest:
                record.update(kind='latest-error', error=error)
            else:
                number = int(latest['number'], 16)
                code, code_error = call('eth_getCode', VAULT, 'latest')
                call_result, call_error = call('eth_call', {'to': VAULT, 'data': '0x'}, 'latest')
                by_number, by_error = call('eth_getBlockByNumber', hex(number), False)
                state = (number, latest['hash'], latest['stateRoot'], code)
                record.update(kind='latest', number=number, hash=latest['hash'], state_root=latest['stateRoot'], vault_code=len(code or '') // 2 - 1 if code else None,
                              code_error=code_error, eth_call=call_result if call_error is None else call_error,
                              by_number_agrees=bool(by_number) and by_number['hash'] == latest['hash'], by_error=by_error)
                changed = state != last
                last = state
                if number in seen and seen[number] != latest['hash']:
                    record['replaced'] = seen[number]
                seen[number] = latest['hash']
                if not changed and record['by_number_agrees'] and not code_error:
                    time.sleep(1)
                    continue
        except OSError as error:
            record.update(kind='transport-error', error=str(error)[:200])
        log.write(json.dumps(record) + '\n')
        log.flush()
        time.sleep(1)
