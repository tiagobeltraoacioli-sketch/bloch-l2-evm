#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Integration tests for the public RPC gateway pair started by tests/pair.sh.

  test_gateway.py [--a https://127.0.0.1:19671] [--b https://127.0.0.1:19672] [--raw-tx HEX --sender ADDR]
                  [--failover 'STOP_A' 'START_A' 'STOP_B' 'START_B']

Expects both settled RPCs to serve chain 700770 at the pinned genesis. The
edge (Cloudflare) is 127.0.0.1, so each test picks its client address with
CF-Connecting-IP. --raw-tx: a signed transaction from a throwaway key (the
spool's answer is checked to come from the sequencer, not from the gateway).
--failover: shell commands that stop/start the backends behind A and B.
"""
import argparse
import http.client
import json
import os
import random
import ssl
import subprocess
import sys
import time
import urllib.parse

GENESIS = '0x632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

results = []
SIM_PER_IP = int(os.environ.get('SIM_PER_IP', '2'))  # render.py --sim-per-ip default


def client_ip():
    return f'198.51.100.{random.randint(1, 254)}' if random.random() < 0.5 else f'203.0.113.{random.randint(1, 254)}'


def request(url, body=None, method='POST', headers=None, ip=None, source=None, raw=None):
    u = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30,
                                       source_address=(source, 0) if source else None)
    h = {'Content-Type': 'application/json', 'CF-Connecting-IP': ip or client_ip()}
    h.update(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    conn.request(method, u.path or '/', body=data, headers=h)
    resp = conn.getresponse()
    text = resp.read()
    conn.close()
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = text.decode(errors='replace')
    return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), parsed


def call(url, method, params=None, id=1, **kw):
    return request(url, {'jsonrpc': '2.0', 'id': id, 'method': method, 'params': params or []}, **kw)


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond else f'  {detail}'))


def basic(url, label):
    s, _, r = call(url, 'eth_chainId')
    check(f'{label} eth_chainId', s == 200 and r['result'] == '0xab162', r)
    s, _, r = call(url, 'net_version')
    check(f'{label} net_version', r['result'] == '700770', r)
    _, _, r = call(url, 'eth_blockNumber')
    head = r['result']
    for tag in ['latest', 'pending', 'safe', 'finalized', 'earliest', '0x0']:
        s, _, r = call(url, 'eth_getBlockByNumber', [tag, False])
        b = r.get('result') or {}
        # No L2 block is settled yet: safe/finalized are the genesis.
        want = (lambda b: b.get('number') == head) if tag in ('latest', 'pending') else (lambda b: b.get('hash') == GENESIS)
        check(f'{label} block {tag}', want(b) and 'sha3Uncles' in b and 'nonce' in b, r)
    s, _, r = call(url, 'eth_getBlockByHash', [GENESIS, True])
    check(f'{label} block by hash', (r.get('result') or {}).get('number') == '0x0', r)
    s, _, r = call(url, 'bloch_finality')
    check(f'{label} bloch_finality', (r.get('result') or {}).get('l2_genesis', {}).get('finalized') is True, r)
    s, _, r = call(url, 'bloch_getWithdrawalProof', [2 ** 40])
    check(f'{label} bloch_getWithdrawalProof reaches the backend', (r.get('error') or {}).get('code') == -32042, r)
    s, _, r = call(url, 'eth_call', [{'to': '0x4200000000000000000000000000000000000011', 'data': '0x'}, 'pending'])
    check(f'{label} eth_call pending', 'result' in r, r)
    s, _, r = call(url, 'eth_estimateGas', [{'from': '0x000000000000000000000000000000000000dEaD', 'to': '0x000000000000000000000000000000000000bEEF', 'value': '0x0'}])
    check(f'{label} eth_estimateGas', r.get('result') == '0x5208', r)
    s, _, r = call(url, 'eth_feeHistory', ['0x1', 'latest', [50]])
    check(f'{label} eth_feeHistory', 'baseFeePerGas' in (r.get('result') or {}), r)

    batch = [{'jsonrpc': '2.0', 'id': i, 'method': m, 'params': p} for i, (m, p) in enumerate([
        ('eth_blockNumber', []), ('eth_chainId', []), ('eth_gasPrice', []), ('debug_traceBlockByNumber', ['0x0']),
        ('eth_getBalance', ['0x000000000000000000000000000000000000dEaD', 'latest']), ('net_version', [])])]
    s, _, r = request(url, batch)
    ids = [x.get('id') for x in r] if isinstance(r, list) else None
    check(f'{label} batch order+ids', ids == list(range(6)), r)
    check(f'{label} batch local+forwarded+refused', isinstance(r, list) and r[1].get('result') == '0xab162'
          and r[3]['error']['code'] == -32601 and r[0].get('result', '').startswith('0x'), r)
    s, _, r = request(url, [{'jsonrpc': '2.0', 'id': i, 'method': 'eth_blockNumber', 'params': []} for i in range(100)])
    check(f'{label} batch of 100 forwarded', isinstance(r, list) and len(r) == 100, r)
    s, _, r = request(url, [{'jsonrpc': '2.0', 'id': i, 'method': 'eth_blockNumber', 'params': []} for i in range(101)])
    check(f'{label} batch of 101 refused', isinstance(r, dict) and r['error']['code'] == -32600, r)
    s, _, r = request(url, [])
    check(f'{label} empty batch', r['error']['code'] == -32600, r)
    s, _, r = request(url, raw=b'{not json')
    check(f'{label} parse error', r['error']['code'] == -32700, r)
    s, _, r = request(url, {'jsonrpc': '1.0', 'id': 1, 'method': 'eth_chainId'})
    check(f'{label} jsonrpc 1.0 refused', r['error']['code'] == -32600, r)
    for m in ['debug_traceTransaction', 'admin_peers', 'txpool_content', 'personal_listAccounts', 'engine_newPayloadV3', 'eth_newFilter', 'eth_sendTransaction', 'eth_subscribe']:
        s, _, r = call(url, m, [])
        check(f'{label} refuses {m}', r['error']['code'] == -32601, r)
    s, _, r = call(url, 'eth_getLogs', [{'fromBlock': '0x0', 'toBlock': '0x7d0'}])
    check(f'{label} getLogs 2001 blocks refused', r.get('error', {}).get('code') == -32602, r)
    s, _, r = call(url, 'eth_getLogs', [{'fromBlock': 'earliest', 'toBlock': 'latest'}])
    check(f'{label} getLogs tags ok', r.get('result') == [], r)
    s, _, r = call(url, 'eth_getLogs', [{'address': ['0x' + '11' * 20] * 257, 'fromBlock': '0x0', 'toBlock': '0x0'}])
    check(f'{label} getLogs 257 addresses refused', r.get('error', {}).get('code') == -32602, r)

    s, h, r = request(url, raw=b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["' + b'a' * (520 * 1024) + b'"]}')
    check(f'{label} body over 512k -> 413 JSON', s == 413 and r['error']['code'] == -32600, (s, r))
    s, h, r = request(url, None, method='GET')
    check(f'{label} GET / info', s == 200 and r['chainId'] == '0xab162', (s, r))
    s, h, r = request(url, None, method='PUT', raw=b'{}')
    check(f'{label} PUT -> 405', s == 405, (s, r))
    s, h, r = request(url + '/health', None, method='GET')
    check(f'{label} /health', s == 200 and r['ok'] is True and isinstance(r['local']['head'], int), (s, r))
    s, h, r = request(url + '/debug', None, method='GET')
    check(f'{label} unknown path 404', s == 404, s)

    for o, allowed in [('https://blochdex.com', True), ('https://www.blochl1.com', True), ('https://blochbridge.com', True),
                       ('https://evil.example', False), ('http://blochdex.com', False), ('null', False)]:
        s, h, _ = request(url, None, method='OPTIONS', headers={'Origin': o, 'Access-Control-Request-Method': 'POST',
                                                               'Access-Control-Request-Headers': 'content-type'})
        acao = h.get('access-control-allow-origin')
        check(f'{label} CORS preflight {o}', s == 204 and (acao == o if allowed else acao is None), (s, h))
    s, h, r = call(url, 'eth_blockNumber', headers={'Origin': 'https://blochdex.com'})
    check(f'{label} CORS on POST', h.get('access-control-allow-origin') == 'https://blochdex.com' and h.get('vary') == 'Origin', h)
    s, h, r = request(url, {'jsonrpc': '2.0', 'id': 7, 'method': 'eth_blockNumber', 'params': []}, headers={'Content-Type': 'text/plain'})
    check(f'{label} text/plain body accepted', r.get('result', '').startswith('0x'), r)

    s, h, r = call(url, 'eth_chainId', source='127.0.0.2')
    check(f'{label} non-edge source refused', s == 403, s)


def limits(url):
    base = random.randint(0, 200)
    ip = f'192.0.2.{base}'
    batch = [{'jsonrpc': '2.0', 'id': i, 'method': 'eth_blockNumber', 'params': []} for i in range(20)]
    statuses = [request(url, batch, ip=ip)[0] for _ in range(61)]
    check('calls/min budget: 60 batches of 20 pass, the 61st is 429', statuses[:60] == [200] * 60 and statuses[60] == 429, statuses[55:])
    s, h, r = request(url, batch, ip=ip)
    check('budget 429 is JSON-RPC -32005 per id with Retry-After', s == 429 and r[0]['error']['code'] == -32005 and h.get('retry-after') == '60', (s, h, r))
    s, _, _ = request(url, batch, ip=f'192.0.2.{base + 1}')
    check('other client unaffected', s == 200, s)
    ip = f'192.0.2.{base + 2}'
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(32) as ex:
        statuses = list(ex.map(lambda _: call(url, 'eth_chainId', ip=ip)[0], range(300)))
    n429 = statuses.count(429)
    check(f'limit_req per IP: burst of 300 parallel -> some 429 ({n429})', n429 > 0 and statuses.count(200) >= 100, statuses.count(200))


def simulations(url):
    ip = f'198.19.{random.randint(0, 255)}.{random.randint(1, 254)}'
    call_ = lambda i: {'jsonrpc': '2.0', 'id': i, 'method': 'eth_call', 'params': [{'to': '0x' + '00' * 19 + 'be', 'data': '0x'}, 'latest']}
    s, _, r = request(url, [call_(i) for i in range(SIM_PER_IP)], ip=ip)
    check(f'simulations: a batch of {SIM_PER_IP} eth_call is answered', s == 200 and len(r) == SIM_PER_IP and all('result' in x for x in r), r)
    s, h, r = request(url, [call_(i) for i in range(SIM_PER_IP + 1)], ip=ip)
    check(f'simulations: a batch of {SIM_PER_IP + 1} eth_call exceeds the per-client slots (429, -32005)', s == 429 and r[0]['error']['code'] == -32005, (s, r))
    statuses = [request(url, call_(i), ip=ip)[0] for i in range(60)]
    check('simulations: slots are released (60 sequential eth_call all 200)', statuses == [200] * 60, statuses)
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(48) as ex:
        st = list(ex.map(lambda i: request(url, call_(i), ip=ip)[0], range(400)))
    check(f'simulations: 400 parallel eth_call from one IP -> only 200/429 ({st.count(429)} x 429)', set(st) <= {200, 429}, set(st))
    time.sleep(6)  # let the per-IP request rate (limit_req) recover
    s, _, r = request(url, [call_(i) for i in range(SIM_PER_IP)], ip=ip)
    check(f'simulations: no slot leak after the parallel burst ({SIM_PER_IP} slots free again)', s == 200, (s, r))


def tx(a, b, raw, sender):
    s, _, r = call(a, 'eth_sendRawTransaction', [raw])
    check('tx via A reaches the sequencer spool (answer from the node)', s == 200 and ('result' in r or r['error']['code'] not in (-32601, -32052, -32053, -32005)), r)
    s, _, r2 = call(b, 'eth_sendRawTransaction', [raw])
    check('tx via B (replica) is routed to the sequencer', s == 200 and json.dumps(r2.get('error', {}).get('code')) == json.dumps(r.get('error', {}).get('code')), (r, r2))
    s, _, r = call(b, 'eth_getTransactionCount', [sender, 'pending'])
    check('pending nonce via B (sequencer first)', 'result' in r, r)
    mixed = [{'jsonrpc': '2.0', 'id': 'a', 'method': 'eth_chainId', 'params': []},
             {'jsonrpc': '2.0', 'id': 'b', 'method': 'eth_sendRawTransaction', 'params': [raw]},
             {'jsonrpc': '2.0', 'id': 'c', 'method': 'eth_blockNumber', 'params': []}]
    s, _, r = request(b, mixed)
    check('mixed batch (tx + reads) split and merged in order', [x['id'] for x in r] == ['a', 'b', 'c'] and r[2]['result'].startswith('0x'), r)
    ip = f'198.18.{random.randint(0, 255)}.{random.randint(1, 254)}'
    codes = [call(a, 'eth_sendRawTransaction', [raw], ip=ip)[0] for _ in range(31)]
    check('tx budget: 30/min pass, the 31st is 429', codes[:30] == [200] * 30 and codes[30] == 429, codes)


def sh(cmd):
    subprocess.run(cmd, shell=True, check=True)


def wait_health(url, pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        s, _, r = request(url + '/health', None, method='GET')
        if isinstance(r, dict) and pred(s, r):
            return True
        time.sleep(0.5)
    return False


def finality(a, b, status_a, status_b):
    """Follower status of the backends: act on age and closed levels. Restores both files."""
    saved_a, saved_b = open(status_a).read(), open(status_b).read()

    def stamp(path, text, age):
        document = json.loads(text)
        document['written_at_unix'] = int(time.time()) - age
        temporary = path + '.test'
        with open(temporary, 'w') as f:
            json.dump(document, f)
        os.replace(temporary, path)

    def age(url):
        return ((call(url, 'bloch_finality')[2].get('result') or {}).get('status') or {}).get('age_s')

    def seen(url, side, pred):
        return wait_health(url, lambda s, r: pred(r[side].get('followerStatus') or {}, r))

    try:
        stamp(status_a, saved_a, 0)
        stamp(status_b, saved_b, 0)
        check('finality: both fresh, /health current', seen(a, 'local', lambda f, r: f.get('state') == 'ok' and f.get('ageS', 9999) < 60) and seen(a, 'peer', lambda f, r: f.get('ageS', 9999) < 60))
        stamp(status_a, saved_a, 7200)
        check('finality: /health shows the old status of A', seen(a, 'local', lambda f, r: f.get('ageS', 0) >= 7200 and r['local']['finalityCurrent'] is False and r['finalityCurrent'] is True))
        ages = [age(a) for _ in range(5)]
        check('finality: old status on A, finality reads go to the peer', all(x is not None and x < 900 for x in ages), ages)
        s, _, r = call(a, 'eth_blockNumber')
        check('finality: old status does not touch other reads', r.get('result', '').startswith('0x'), r)
        stamp(status_b, saved_b, 7200)
        check('finality: both old, /health 200 and not current', wait_health(a, lambda s, r: s == 200 and r['finalityCurrent'] is False))
        s, _, r = call(a, 'eth_getBlockByNumber', ['finalized', False])
        check('finality: both old, finalized is still served', (r.get('result') or {}).get('hash') == GENESIS, r)
        stamp(status_b, saved_b, 0)
        stamp(status_a, saved_a, 0)
        check('finality: fresh again', seen(a, 'local', lambda f, r: f.get('ageS', 9999) < 60))

        # Closed on A: the first reads race the probe, so these exercise the retry as well as the routing.
        os.remove(status_a)
        codes, ends = [], time.time() + 8
        while time.time() < ends:
            _, _, r = call(a, 'eth_getBlockByNumber', ['finalized', False])
            codes.append((r.get('error') or {}).get('code') or ((r.get('result') or {}).get('hash') == GENESIS))
            time.sleep(0.05)
        check(f'finality: A closes, every finalized read of {len(codes)} is answered by a backend with open levels', all(c is True for c in codes), set(map(str, codes)))
        check('finality: /health shows A as not valid', seen(a, 'local', lambda f, r: f.get('state') == 'missing' and r['local']['ok'] is True))
        batch = [{'jsonrpc': '2.0', 'id': 1, 'method': 'eth_blockNumber', 'params': []},
                 {'jsonrpc': '2.0', 'id': 2, 'method': 'eth_getBlockByNumber', 'params': ['safe', False]},
                 {'jsonrpc': '2.0', 'id': 3, 'method': 'eth_getLogs', 'params': [{'fromBlock': 'finalized', 'toBlock': 'finalized'}]},
                 {'jsonrpc': '2.0', 'id': 4, 'method': 'bloch_settlement', 'params': ['0x1']},
                 {'jsonrpc': '2.0', 'id': 5, 'method': 'eth_getBalance', 'params': ['0x' + '00' * 20, {'blockNumber': 'finalized'}]}]
        s, _, r = request(a, batch)
        check('finality: a mixed batch stays in order, finalized parts answered', [x['id'] for x in r] == [1, 2, 3, 4, 5] and all('error' not in x for x in r), r)
        os.remove(status_b)
        check('finality: both closed, seen', wait_health(a, lambda s, r: (r['peer'].get('followerStatus') or {}).get('state') == 'missing'))
        s, _, r = call(a, 'eth_getBlockByNumber', ['finalized', False], id=9)
        check('finality: both closed, -32001 reaches the client with its id', r.get('id') == 9 and (r.get('error') or {}).get('code') == -32001, r)
        s, _, r = call(a, 'eth_blockNumber')
        check('finality: both closed, latest still answers', r.get('result', '').startswith('0x'), r)
        s, _, r = call(a, 'bloch_finality')
        check('finality: both closed, bloch_finality says so', (r.get('result') or {}).get('status', {}).get('state') == 'missing', r)
    finally:
        with open(status_a, 'w') as f:
            f.write(saved_a)
        with open(status_b, 'w') as f:
            f.write(saved_b)
    check('finality: reopened', wait_health(a, lambda s, r: (r['local'].get('followerStatus') or {}).get('state') == 'ok' and (r['peer'].get('followerStatus') or {}).get('state') == 'ok'))


def failover(a, b, raw, cmds):
    stop_a, start_a, stop_b, start_b = cmds
    sh(stop_a)
    time.sleep(1)
    s, _, r = call(a, 'eth_blockNumber')
    check('A backend down: immediate read through A fails over to the peer', r.get('result', '').startswith('0x'), r)
    check('A health sees the local backend down', wait_health(a, lambda s, r: not r['local']['ok'] and r['peer']['ok'] and s == 200))
    s, _, r = call(a, 'eth_getBlockByNumber', ['finalized', False])
    check('A backend down: finalized block served by the peer', (r.get('result') or {}).get('hash') == GENESIS, r)
    if raw:
        check('B health sees the sequencer down', wait_health(b, lambda s, r: not r['peer']['ok'] and not r['sequencer']))
        s, _, r = call(b, 'eth_sendRawTransaction', [raw])
        check('sequencer down: tx refused as not submitted (-32053)', r.get('error', {}).get('code') == -32053 and r['error'].get('data', {}).get('submitted') is False, r)
    sh(start_a)
    check('A recovers', wait_health(a, lambda s, r: r['local']['ok']))
    sh(stop_b)
    time.sleep(1)
    s, _, r = call(b, 'eth_blockNumber')
    check('B backend down: read through B served by A', r.get('result', '').startswith('0x'), r)
    sh(stop_a)
    check('both down: /health 503', wait_health(a, lambda s, r: s == 503 and not r['ok']))
    s, h, r = call(a, 'eth_blockNumber', id=42)
    check('both down: JSON-RPC -32053 with the caller id', s == 503 and r['id'] == 42 and r['error']['code'] == -32053, (s, r))
    s, h, r = request(a, [{'jsonrpc': '2.0', 'id': 1, 'method': 'eth_blockNumber', 'params': []}, {'jsonrpc': '2.0', 'id': 2, 'method': 'eth_gasPrice', 'params': []}])
    check('both down: batch gets one error per id', s == 503 and [x['id'] for x in r] == [1, 2], (s, r))
    sh(start_a)
    sh(start_b)
    check('both recover', wait_health(a, lambda s, r: r['local']['ok'] and r['peer']['ok']) and wait_health(b, lambda s, r: r['local']['ok']))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--a', default='https://127.0.0.1:19671')
    p.add_argument('--b', default='https://127.0.0.1:19672')
    p.add_argument('--raw-tx')
    p.add_argument('--sender')
    p.add_argument('--skip-limits', action='store_true')
    p.add_argument('--failover', nargs=4)
    p.add_argument('--status-files', nargs=2, metavar=('A', 'B'), help='follower status files of the backends behind A and B')
    o = p.parse_args()
    basic(o.a, 'A')
    basic(o.b, 'B')
    if o.raw_tx:
        tx(o.a, o.b, o.raw_tx, o.sender)
    if not o.skip_limits:
        limits(o.a)
        simulations(o.a)
    if o.status_files:
        finality(o.a, o.b, *o.status_files)
    if o.failover:
        failover(o.a, o.b, o.raw_tx, o.failover)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
