#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent review, round 10: the gateway under real nginx + njs, production limits.

Real here: nginx, njs, l2rpc-gateway.js, the config render.py writes with the production limits (no rate
overrides), the mTLS peer hop. Fake: the two settled RPC backends, scripted (slow eth_call, large answers).
Loopback ports only, throwaway certificates, no chain.

Each check states what the public endpoint needs. A FAIL is a finding of report 154.

  NJS_SO=/path/ngx_http_js_module.so review_r10_rig.py --work NEW_DIR --port-base 35400 [--only R1,R2,...]
"""
import argparse
import concurrent.futures as cf
import http.server
import json
import os
from pathlib import Path
import socket
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
    print(f'{"PASS" if ok else "FAIL"} {name}: {json.dumps(detail)[:600]}', flush=True)


class Backend:
    """A settled RPC stand-in: eth_call sleeps `call_delay` s; eth_getCode answers `big` bytes of hex."""

    def __init__(self, port, name):
        self.name, self.call_delay, self.big = name, 0.0, 64
        self.calls = 0
        self.lock = threading.Lock()
        backend = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['content-length'])))
                items = body if isinstance(body, list) else [body]
                if any(c.get('method') == 'eth_call' for c in items):
                    with backend.lock:
                        backend.calls += sum(c.get('method') == 'eth_call' for c in items)
                    time.sleep(backend.call_delay)
                answers = [backend.answer(c) for c in items]
                out = json.dumps(answers if isinstance(body, list) else answers[0]).encode()
                try:
                    self.send_response(200)
                    self.send_header('content-type', 'application/json')
                    self.send_header('content-length', str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, call):
        method, params, reply = call.get('method'), call.get('params') or [], {'jsonrpc': '2.0', 'id': call.get('id')}
        if method == 'eth_chainId':
            reply['result'] = CHAIN
        elif method == 'eth_blockNumber':
            reply['result'] = hex(1000)
        elif method == 'eth_getBlockByNumber':
            reply['result'] = {'number': hex(100 if params and params[0] in ('safe', 'finalized') else 1000)}
        elif method == 'bloch_finality':
            reply['result'] = {'finalized_height': 100, 'status': {'state': 'ok', 'age_s': 5}}
        elif method == 'eth_call':
            reply['result'] = '0x' + '00' * 32
        elif method == 'eth_getCode':
            reply['result'] = '0x' + 'ab' * (self.big // 2)
        else:
            reply['result'] = '0x1'
        return reply


def run(*argv):
    return subprocess.run([str(a) for a in argv], check=True, capture_output=True, text=True)


class Pair:
    """Gateway A (sequencer) and B (replica), production limits, plain loopback listeners for the client."""

    def __init__(self, work, base, njs):
        self.a_rpc, self.b_rpc = base, base + 1
        self.a, self.b = f'http://127.0.0.1:{base + 2}', f'http://127.0.0.1:{base + 3}'
        certs = work / 'certs'
        certs.mkdir(parents=True)
        common = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2']
        run('openssl', 'req', '-x509', *common, '-subj', '/CN=l2rpc.test', '-keyout', certs / 'origin.key', '-out', certs / 'origin.pem')
        (certs / 'edge.txt').write_text('127.0.0.1/32\n')
        for x in 'ab':
            (work / x / 'peer').mkdir(parents=True)
            (work / x / 'hop').mkdir(mode=0o700)
            run('openssl', 'req', '-x509', *common, '-subj', '/CN=l2rpc-peer', '-addext', 'subjectAltName=DNS:l2rpc-peer',
                '-keyout', work / x / 'peer/self.key', '-out', work / x / 'peer/self.crt')
        for me, other in (('a', 'b'), ('b', 'a')):
            (work / me / 'peer/peer.crt').write_bytes((work / other / 'peer/self.crt').read_bytes())
        plans = {'a': ('sequencer', self.a_rpc, base + 4, base + 6, base + 8, base + 10, base + 7, base + 2),
                 'b': ('replica', self.b_rpc, base + 5, base + 7, base + 9, base + 11, base + 6, base + 3)}
        self.confs = []
        for x, (role, rpc, public, listen, out, probe, peer, plain) in plans.items():
            conf = work / x / 'conf'
            # setup-gateway.sh's production flags: --cors-any --backend-conns 400; every limit at its default.
            run(sys.executable, RENDER, '--role', role, '--name', f'test-{x}', '--out', conf, '--standalone', '--njs-module', njs,
                '--local-rpc', f'127.0.0.1:{rpc}', '--peer', f'127.0.0.1:{peer}', '--peer-allow', '127.0.0.1',
                '--peer-listen', f'127.0.0.1:{listen}', '--hop-dir', work / x / 'hop', '--probe-port', probe, '--peer-dir', work / x / 'peer',
                '--server-name', 'l2rpc.test', '--public-listen', f'127.0.0.1:{public}', '--test-plain-listen', f'127.0.0.1:{plain}',
                '--tls-cert', certs / 'origin.pem', '--tls-key', certs / 'origin.key', '--client-ca', 'none',
                '--edge-ranges', certs / 'edge.txt', '--log-dir', conf / 'logs', '--probe-interval', '1s',
                '--cors-any', '--backend-conns', '400')
            run('nginx', '-q', '-p', conf, '-c', conf / 'nginx.conf')
            self.confs.append(conf)

    def workers_rss_kib(self):
        total = 0
        for conf in self.confs:
            master = int((conf / 'nginx.pid').read_text())
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                try:
                    status = Path(f'/proc/{pid}/status').read_text()
                except OSError:
                    continue
                if f'PPid:\t{master}\n' in status:
                    total += int(status.split('VmRSS:')[1].split()[0])
        return total

    def stop(self):
        for conf in self.confs:
            subprocess.run(['nginx', '-q', '-p', str(conf), '-c', str(conf / 'nginx.conf'), '-s', 'quit'], capture_output=True)


def post(url, body, ip, timeout=90):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(url, data, {'content-type': 'application/json', 'CF-Connecting-IP': ip})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        text = error.read()
        try:
            return error.code, json.loads(text)
        except ValueError:
            return error.code, text[:200].decode(errors='replace')


def call(i, method='eth_call', params=None):
    if params is None:
        params = [{'to': '0x' + '00' * 19 + 'be', 'data': '0x'}, 'latest'] if method == 'eth_call' else []
    return {'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params}


def r1_abort(pair, A, B, sims):
    """G3: a client that closes its connection while its simulations run."""
    ip = '203.0.113.31'
    A.call_delay = B.call_delay = 3
    body = json.dumps([call(i) for i in range(sims)]).encode()
    port = int(pair.a.rsplit(':', 1)[1])
    s = socket.create_connection(('127.0.0.1', port))
    s.sendall(b'POST / HTTP/1.1\r\nHost: l2rpc.test\r\nContent-Type: application/json\r\nCF-Connecting-IP: ' + ip.encode()
              + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    time.sleep(0.5)
    s.close()
    time.sleep(5)
    A.call_delay = B.call_delay = 0
    status, answer = post(pair.a, [call(i) for i in range(sims)], ip)
    check(f'R1/G3: {sims} eth_call after an aborted batch of {sims} from the same client are served (slots released)', status == 200,
          {'status': status, 'answer': answer if status != 200 else 'ok'})
    status, answer = post(pair.a, call(1), ip)
    check('R1/G3: one eth_call after the aborted batch is served', status == 200, {'status': status, 'answer': answer if status != 200 else 'ok'})
    ip2 = '203.0.113.32'
    A.call_delay = B.call_delay = 3
    s = socket.create_connection(('127.0.0.1', port))
    s.sendall(b'POST / HTTP/1.1\r\nHost: l2rpc.test\r\nContent-Type: application/json\r\nCF-Connecting-IP: ' + ip2.encode()
              + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    s.shutdown(socket.SHUT_WR)
    time.sleep(0.5)
    s.close()
    time.sleep(5)
    A.call_delay = B.call_delay = 0
    status, answer = post(pair.a, call(1), ip2)
    check('R1/G3: half-close then close (a browser tab closed): one eth_call afterwards is served', status == 200,
          {'status': status, 'answer': answer if status != 200 else 'ok'})
    # A client that keeps calling (one eth_call every 30 s): is it served again within 330 s?
    statuses, ends = [], time.time() + 330
    while time.time() < ends:
        statuses.append(post(pair.a, call(1), ip)[0])
        if statuses[-1] == 200:
            break
        time.sleep(30)
    check('R1/G3: a client that keeps calling every 30 s is served again within 330 s of the abort', statuses[-1] == 200, statuses)


def r2_ipv6(pair):
    """G1 at the nginx layer: limit_req (20 r/s, burst 100) is keyed on the full address."""
    def one(i):
        return post(pair.a, call(i, 'eth_chainId'), f'2001:db8:77:1::{i + 1:x}')[0]
    with cf.ThreadPoolExecutor(32) as ex:
        statuses = list(ex.map(one, range(400)))
    check('R2/G1: 400 parallel requests from one IPv6 /64 meet limit_req (some 429)', statuses.count(429) > 0,
          {'200': statuses.count(200), '429': statuses.count(429)})

    def same(i):
        return post(pair.a, call(i, 'eth_chainId'), '2001:db8:77:2::1')[0]
    with cf.ThreadPoolExecutor(32) as ex:
        statuses = list(ex.map(same, range(400)))
    check('R2 control: 400 parallel requests from one IPv6 address meet limit_req', statuses.count(429) > 0,
          {'200': statuses.count(200), '429': statuses.count(429)})


def r3_timeout(pair, A, B):
    """G4: an eth_call that outlives proxy_read_timeout (30 s)."""
    A.calls = B.calls = 0
    A.call_delay = B.call_delay = 35
    ip = '198.51.100.41'
    started = time.time()
    status, answer = post(pair.a, [call(1), call(2, 'eth_blockNumber')], ip, timeout=120)
    took = time.time() - started
    arrivals = {'A': A.calls, 'B': B.calls}
    check('R3/G4: an eth_call is run by one backend, not replayed on the other after the gateway times out',
          A.calls + B.calls == 1, {'arrivals': arrivals, 'status': status, 'seconds': round(took, 1)})
    A.call_delay = B.call_delay = 0
    time.sleep(36)


def r4_memory(pair, A, B):
    """G5: answers of a split batch are held in njs memory (subrequest_output_buffer_size 16m)."""
    A.big = B.big = 15 * 1024 * 1024
    base = pair.workers_rss_kib()
    peak = [base]
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            peak[0] = max(peak[0], pair.workers_rss_kib())
            time.sleep(0.05)
    t = threading.Thread(target=sample)
    t.start()
    A.call_delay = B.call_delay = 0.5
    batch = [call(1), call(2, 'eth_getCode', ['0x' + '11' * 20, 'latest'])]
    with cf.ThreadPoolExecutor(32) as ex:
        statuses = list(ex.map(lambda i: post(pair.a, batch, f'198.51.100.{51 + i % 2}', timeout=120)[0], range(32)))
    A.call_delay = B.call_delay = 0
    stop.set()
    t.join()
    grew_mib = (peak[0] - base) / 1024
    check('R4/G5: 32 concurrent split batches with a 15 MB answer from two clients add under 512 MiB to the nginx workers',
          grew_mib < 512, {'workers_rss_base_mib': round(base / 1024), 'peak_growth_mib': round(grew_mib),
                           'statuses': {str(s): statuses.count(s) for s in set(statuses)}})
    A.big = B.big = 64


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--work', required=True)
    p.add_argument('--port-base', type=int, default=35400)
    p.add_argument('--only', default='R1,R2,R3,R4')
    p.add_argument('--sims', type=int, default=16, help="the rendered --sim-per-ip (16 at f1c8033, 2 at 8d1c873)")
    a = p.parse_args()
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    A, B = Backend(a.port_base, 'A'), Backend(a.port_base + 1, 'B')
    pair = Pair(work, a.port_base, os.environ['NJS_SO'])
    only = set(a.only.split(','))
    try:
        time.sleep(4)
        status, answer = post(pair.a, call(1, 'eth_blockNumber'), '192.0.2.1')
        check('baseline: the rig answers', status == 200 and answer.get('result') == '0x3e8', answer)
        if 'R1' in only:
            r1_abort(pair, A, B, a.sims)
        if 'R2' in only:
            time.sleep(2)
            r2_ipv6(pair)
        if 'R3' in only:
            r3_timeout(pair, A, B)
        if 'R4' in only:
            r4_memory(pair, A, B)
    finally:
        pair.stop()
    failed = [n for n, ok in results if not ok]
    print(f'{len(results) - len(failed)} passed, {len(failed)} failed', flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
