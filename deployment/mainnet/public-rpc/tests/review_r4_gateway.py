#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent review, round 4: which backend the gateway picks for finality reads and withdrawal proofs.

Real here: nginx, njs, l2rpc-gateway.js, the config render.py writes and the mTLS peer hop. Fake: the two
settled RPC backends, scripted so that each scenario holds still. Loopback ports only, throwaway certificates.

Each check states what a client needs. A FAIL is a finding, reported with its output.

  NJS_SO=/path/ngx_http_js_module.so review_r4_gateway.py --work NEW_DIR --port-base 27720
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
RENDER = HERE.parent / 'render.py'
CHAIN = '0xab162'
results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok)))
    print(f'{"PASS" if ok else "FAIL"} {name}: {json.dumps(detail)[:500]}', flush=True)


class Backend:
    """A settled RPC in a scripted state."""

    def __init__(self, port, name):
        self.name, self.head, self.finalized = name, 1000, 100
        self.state, self.age = 'ok', 5
        self.view_null = False
        self.proof = {'result': {'index': 0, 'finalized': True, 'from': name}}
        self.seen = []
        backend = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['content-length'])))
                out = json.dumps([backend.answer(c) for c in body] if isinstance(body, list) else backend.answer(body)).encode()
                self.send_response(200)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def closed(self):
        return self.state != 'ok' and not self.view_null

    def answer(self, call):
        method, params, reply = call['method'], call.get('params') or [], {'jsonrpc': '2.0', 'id': call.get('id')}
        if method != 'bloch_finality':
            self.seen.append(method)
        if method == 'eth_chainId':
            reply['result'] = CHAIN
        elif method == 'eth_blockNumber':
            reply['result'] = hex(self.head)
        elif method == 'eth_getBlockByNumber':
            if params[0] in ('safe', 'finalized') and self.closed():
                reply['error'] = {'code': -32001, 'message': 'closed'}
            elif params[0] in ('safe', 'finalized'):
                reply['result'] = None if self.view_null else {'number': hex(self.finalized), 'from': self.name}
            else:
                reply['result'] = {'number': hex(self.head), 'from': self.name}
        elif method == 'bloch_finality':
            reply['result'] = None if self.view_null else {'finalized_height': self.finalized,
                                                           'status': {'state': self.state, 'age_s': self.age if self.state == 'ok' else None}}
        elif method == 'bloch_settlement':
            reply['result'] = None if (self.closed() or self.view_null) else {'finalized': True, 'from': self.name}
        elif method == 'bloch_getWithdrawalProof':
            reply.update(self.proof)
        else:
            reply['error'] = {'code': -32601, 'message': method}
        return reply


def run(*argv, **kwargs):
    return subprocess.run([str(a) for a in argv], check=True, capture_output=True, text=True, **kwargs)


class Pair:
    def __init__(self, work, base, njs):
        self.work = work
        self.a_rpc, self.b_rpc = base, base + 1
        self.a, self.b = f'http://127.0.0.1:{base + 2}', f'http://127.0.0.1:{base + 3}'
        certs = work / 'certs'
        certs.mkdir(parents=True)
        common = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2']
        run('openssl', 'req', '-x509', *common, '-subj', '/CN=l2rpc.test', '-keyout', certs / 'origin.key', '-out', certs / 'origin.pem')
        (certs / 'edge.txt').write_text('127.0.0.1/32\n')
        for x in 'ab':
            (work / x / 'peer').mkdir(parents=True)
            run('openssl', 'req', '-x509', *common, '-subj', '/CN=l2rpc-peer', '-addext', 'subjectAltName=DNS:l2rpc-peer',
                '-keyout', work / x / 'peer/self.key', '-out', work / x / 'peer/self.crt')
        for me, other in (('a', 'b'), ('b', 'a')):
            (work / me / 'peer/peer.crt').write_bytes((work / other / 'peer/self.crt').read_bytes())
        plans = {'a': ('sequencer', self.a_rpc, base + 4, base + 6, base + 8, base + 10, base + 7, base + 2),
                 'b': ('replica', self.b_rpc, base + 5, base + 7, base + 9, base + 11, base + 6, base + 3)}
        self.confs = []
        for x, (role, rpc, public, listen, out, probe, peer, plain) in plans.items():
            conf = work / x / 'conf'
            run(sys.executable, RENDER, '--role', role, '--name', f'test-{x}', '--out', conf, '--standalone', '--njs-module', njs,
                '--local-rpc', f'127.0.0.1:{rpc}', '--peer', f'127.0.0.1:{peer}', '--peer-allow', '127.0.0.1',
                '--peer-listen', f'127.0.0.1:{listen}', '--peer-out-port', out, '--probe-port', probe, '--peer-dir', work / x / 'peer',
                '--server-name', 'l2rpc.test', '--public-listen', f'127.0.0.1:{public}', '--test-plain-listen', f'127.0.0.1:{plain}',
                '--tls-cert', certs / 'origin.pem', '--tls-key', certs / 'origin.key', '--client-ca', 'none',
                '--edge-ranges', certs / 'edge.txt', '--log-dir', conf / 'logs', '--probe-interval', '1s',
                '--req-rate', '1000', '--req-burst', '2000', '--calls-per-minute', '100000')
            run('nginx', '-q', '-p', conf, '-c', conf / 'nginx.conf')
            self.confs.append(conf)

    def stop(self):
        for conf in self.confs:
            subprocess.run(['nginx', '-q', '-p', str(conf), '-c', str(conf / 'nginx.conf'), '-s', 'quit'], capture_output=True)


def rpc(url, method, params=()):
    request = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 7, 'method': method, 'params': list(params)}).encode(),
                                     {'content-type': 'application/json', 'CF-Connecting-IP': '198.51.100.7'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return json.loads(error.read())


def health(url):
    with urllib.request.urlopen(url + '/health', timeout=10) as response:
        return json.loads(response.read())


def settle():
    """Long enough for both gateways to probe the new state of both backends."""
    time.sleep(4)


def finalized_number(answer):
    result = answer.get('result')
    return int(result['number'], 16) if isinstance(result, dict) else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--work', required=True)
    p.add_argument('--port-base', type=int, default=27720)
    a = p.parse_args()
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    A, B = Backend(a.port_base, 'A'), Backend(a.port_base + 1, 'B')
    pair = Pair(work, a.port_base, os.environ['NJS_SO'])
    try:
        settle()
        check('baseline: the rig answers', rpc(pair.a, 'eth_chainId').get('result') == CHAIN and health(pair.a)['ok'], health(pair.a))

        # 1. Both "current", the first one far behind in finalized.
        A.finalized, B.finalized = 100, 200
        settle()
        answer = rpc(pair.a, 'eth_getBlockByNumber', ['finalized', False])
        view = health(pair.a)
        check('two current backends: finalized comes from the one with the higher finalized level',
              finalized_number(answer) == 200, {'answer': finalized_number(answer), 'from': (answer.get('result') or {}).get('from'),
                                                'health_local': view['local'].get('finalized'), 'health_peer': view['peer'].get('finalized')})

        # 2. A read of finalized never moves backwards because routing moved.
        A.finalized, B.finalized, A.head, B.head = 200, 100, 1000, 1000
        settle()
        first = finalized_number(rpc(pair.a, 'eth_getBlockByNumber', ['finalized', False]))
        B.head = 1001
        settle()
        second = finalized_number(rpc(pair.a, 'eth_getBlockByNumber', ['finalized', False]))
        check('routing by head does not move a client backwards in finalized', second is not None and first is not None and second >= first,
              {'first_read': first, 'after_peer_head_moves_one_block': second})
        A.head, B.head, A.finalized, B.finalized = 1000, 1000, 100, 100

        # 3. A restarted backend, or one started without a status: bloch_finality is null, finalized is null.
        B.finalized = 150
        A.view_null = True
        settle()
        view = health(pair.a)
        answer = rpc(pair.a, 'eth_getBlockByNumber', ['finalized', False])
        check('a backend whose bloch_finality is null is not "finalityCurrent"', view['local'].get('finalityCurrent') is not True, view['local'])
        check('a backend with no status view does not answer finalized:null while the peer has a level',
              finalized_number(answer) == 150, {'answer': answer})
        settlement = rpc(pair.a, 'bloch_settlement', ['0x1'])
        check('bloch_settlement of a settled block: the peer answers while the first backend is starting',
              (settlement.get('result') or {}).get('from') == 'B', settlement)
        A.view_null, B.finalized = False, 100

        # 4. Both closed: is "no settlement" what the client reads?
        A.state, B.state = 'missing', 'missing'
        settle()
        answer = rpc(pair.a, 'eth_getBlockByNumber', ['finalized', False])
        check('baseline: both closed, finalized answers -32001', (answer.get('error') or {}).get('code') == -32001, answer)
        settlement = rpc(pair.a, 'bloch_settlement', ['0x1'])
        check('both closed: bloch_settlement answers -32001, not null ("not settled")', (settlement.get('error') or {}).get('code') == -32001, settlement)
        A.state, B.state = 'ok', 'ok'

        # 5. A closes between probes: bloch_settlement has no closed answer, so no retry.
        settle()
        A.state = 'invalid'
        nulls = total = 0
        ends = time.time() + 0.5
        while time.time() < ends:
            total += 1
            nulls += rpc(pair.a, 'bloch_settlement', ['0x1']).get('result') is None
        check('A closes between probes: bloch_settlement goes to the open peer', nulls == 0, {'null_answers': nulls, 'of': total})
        A.state = 'ok'

        # 6. Withdrawal proofs take the read route: no retry, no finality routing.
        settle()
        A.proof = {'error': {'code': -32046, 'message': 'withdrawal proofs are frozen'}}
        settle()
        answer = rpc(pair.a, 'bloch_getWithdrawalProof', [0])
        check('one backend frozen: the proof comes from the healthy peer (the tool treats -32046 as a final refusal)',
              (answer.get('result') or {}).get('from') == 'B', answer)
        A.proof = {'error': {'code': -32041, 'message': 'not covered by a finalized settlement yet', 'data': {'finalized_block': 3}}}
        answer = rpc(pair.a, 'bloch_getWithdrawalProof', [0])
        check('the first backend is behind: the proof comes from the peer that has it', (answer.get('result') or {}).get('from') == 'B', answer)
        A.proof = {'result': {'index': 0, 'finalized': True, 'from': 'A'}}
        A.state = 'missing'
        settle()
        answer = rpc(pair.a, 'bloch_getWithdrawalProof', [0])
        check('the first backend has closed levels: finalized:true is not read from it', (answer.get('result') or {}).get('from') == 'B', answer)
        A.state = 'ok'
    finally:
        pair.stop()
    failed = [n for n, ok in results if not ok]
    print(f'{len(results) - len(failed)} passed, {len(failed)} failed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
