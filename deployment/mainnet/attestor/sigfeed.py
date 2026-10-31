#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""sigfeed: the untrusted transport for bridge partial signatures and L2 withdrawal attestations.

Every operator serves its own signatures as static files from a read-only endpoint. Everyone else
polls with plain GET, only for paths derived from its OWN view of the chain (a deposit, a burn, a
withdrawal root), and keeps only what its own verifier accepts. There is no shared store, no write
credential, no listing and no upload path.

  sigfeed.py serve --root DIR --port N [--bind ADDR] [--tls-cert F --tls-key F]
  sigfeed.py get URL [--max-bytes N] [--ca-file F]

What this file enforces (the verifiers live with the content they understand):
  server: GET/HEAD only; a path allow-list; regular files only (no symlinks); a size cap per file;
          wall-clock deadlines, shorter until the request has arrived; connection caps globally and per IP (per /64 on
          IPv6); a request budget per IP. When every slot is taken, the connection idle the longest makes room, so idle
          connections cannot lock out a reader that asks at once.
  client: http/https only; no redirects, no proxies; a byte cap and a wall-clock deadline per fetch; a bound on the paths
          asked per cycle, resumed on the next; a failing peer backs off and costs the others nothing. A peer that
          answers but is busy, or a cycle that runs out of time, is not a failure.

Python standard library only. This same file ships in the bridge signer and in the attestor kit.
"""
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse

MAX_FILE = 64 * 1024
MAX_PATHS_PER_CYCLE = 120  # one pull; two pulls a pass from a signer and a relayer on one host stay under 600 a minute
PATH_RE = re.compile(r'^(?:\d{1,12}/[0-9a-f]{64}/attestor-\d{1,3}\.partial'
                     r'|bridge/[0-9a-f]{40}/(?:mint|release)/[0-9a-f]{64}/[0-9a-f]{40}\.json)$')


def client_key(ip):
    """What the per-client limits count: the address, or its /64 on IPv6 (one host commonly owns a whole /64)."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f'{ip}/64', strict=False)) if parsed.version == 6 else ip


class FeedServer:
    """A read-only static file server small enough to read. One thread per connection, bounded."""

    def __init__(self, root, host='127.0.0.1', port=0, tls=None, max_file=MAX_FILE, max_conns=64, per_ip_conns=4,
                 per_ip_requests=600, window=60.0, deadline=10.0, idle_deadline=2.0):
        self.root = os.path.realpath(root)
        self.max_file, self.deadline, self.idle_deadline = max_file, deadline, min(idle_deadline, deadline)
        self.per_ip_conns, self.per_ip_requests, self.window = per_ip_conns, per_ip_requests, window
        self.slots = threading.BoundedSemaphore(max_conns)
        self.lock = threading.Lock()
        self.conns, self.budget = {}, {}
        self.live = {}  # connection key -> {'sock', 'since', 'idle'}
        self.tls = None
        if tls:
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls.load_cert_chain(*tls)
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.stopping = False
        self.watching = False

    def serve_forever(self):
        self.watch()
        while not self.stopping:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                return
            ip = client_key(addr[0])
            if not self.admit(ip):
                self.refuse(conn)
                continue
            try:
                threading.Thread(target=self.connection, args=(conn, ip), daemon=True).start()
            except RuntimeError:  # the thread limit: this connection loses, the server does not
                self.leave(ip)
                close_quietly(conn)

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.stopping = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def watch(self):
        """One thread enforces every deadline, so a connection costs one thread, not two."""
        if self.watching:
            return
        self.watching = True
        tick = min(0.1, self.idle_deadline / 4)

        def loop():
            while not self.stopping:
                time.sleep(tick)
                now = time.monotonic()
                with self.lock:
                    late = [c['sock'] for c in self.live.values()
                            if now - c['since'] > (self.idle_deadline if c['idle'] else self.deadline)]
                for sock in late:
                    close_quietly(sock)
        threading.Thread(target=loop, daemon=True).start()

    def admit(self, ip):
        with self.lock:
            now = time.monotonic()
            start, used = self.budget.get(ip, (now, 0))
            if now - start > self.window:
                start, used = now, 0
            if self.conns.get(ip, 0) >= self.per_ip_conns or used >= self.per_ip_requests:
                return False
            self.conns[ip] = self.conns.get(ip, 0) + 1
            self.budget[ip] = (start, used + 1)
            if len(self.budget) > 4096:  # the table itself stays bounded under address spray
                self.budget = {k: v for k, v in self.budget.items() if now - v[0] <= self.window}
        if self.slots.acquire(blocking=False) or (self.evict_idle() and self.slots.acquire(timeout=0.2)):
            return True
        self.forget(ip)
        return False

    def evict_idle(self):
        """Every slot is taken: the connection that has been idle the longest makes room."""
        with self.lock:
            idle = [c for c in self.live.values() if c['idle']]
            oldest = min(idle, key=lambda c: c['since'])['sock'] if idle else None
        if oldest is None:
            return False
        close_quietly(oldest)
        return True

    def forget(self, ip):
        with self.lock:
            left = self.conns.get(ip, 1) - 1
            if left:
                self.conns[ip] = left
            else:
                self.conns.pop(ip, None)

    def leave(self, ip):
        self.forget(ip)
        self.slots.release()

    def refuse(self, conn):
        """A busy answer, best effort: the reader must not mistake a full server for a dead one."""
        try:
            if not self.tls:
                conn.setblocking(False)
                conn.send(b'HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nRetry-After: 30\r\nConnection: close\r\n\r\n')
        except OSError:
            pass
        close_quietly(conn)

    def connection(self, conn, ip):
        # A wall-clock limit on the whole connection, so a slow client cannot hold a slot.
        entry = {'sock': conn, 'since': time.monotonic(), 'idle': True}
        key = object()
        try:
            with self.lock:
                self.live[key] = entry
            conn.settimeout(self.idle_deadline)
            sock = conn
            if self.tls:  # wrapping detaches `conn`: the deadline must follow the wrapped socket
                sock = entry['sock'] = self.tls.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
                sock.do_handshake()
            self.respond(sock, entry)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            with self.lock:
                self.live.pop(key, None)
            close_quietly(entry['sock'])
            self.leave(ip)

    def respond(self, sock, entry):
        head = b''
        while b'\r\n\r\n' not in head:
            part = sock.recv(1024)
            if not part:
                return
            head += part
            if len(head) > 4096:
                return send(sock, 431, b'')
        entry['idle'] = False
        sock.settimeout(self.deadline)
        request = head.split(b'\r\n', 1)[0].split(b' ')
        if len(request) != 3 or not request[2].startswith(b'HTTP/1.'):
            return send(sock, 400, b'')
        method, target = request[0], request[1].decode('ascii', 'replace')
        if method not in (b'GET', b'HEAD'):
            return send(sock, 405, b'', [('Allow', 'GET, HEAD')])
        if target == '/healthz':
            return send(sock, 200, b'ok\n', head_only=method == b'HEAD')
        body = self.read_file(target[1:]) if target.startswith('/') else None
        if body is None:
            return send(sock, 404, b'', head_only=method == b'HEAD')
        return send(sock, 200, body, head_only=method == b'HEAD')

    def read_file(self, rel):
        if not PATH_RE.match(rel):
            return None
        path = os.path.join(self.root, rel)
        if os.path.realpath(path) != path:  # a symlink anywhere on the way
            return None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        with os.fdopen(fd, 'rb') as f:
            info = os.fstat(f.fileno())
            if (info.st_mode & 0o170000) != 0o100000 or info.st_size > self.max_file:
                return None
            return f.read(self.max_file + 1)[:self.max_file]


def send(sock, status, body, extra=(), head_only=False):
    reason = {200: 'OK', 400: 'Bad Request', 404: 'Not Found', 405: 'Method Not Allowed',
              431: 'Headers Too Large'}.get(status, 'Error')
    lines = [f'HTTP/1.1 {status} {reason}', f'Content-Length: {len(body)}', 'Content-Type: application/octet-stream',
             'Cache-Control: no-store', 'X-Content-Type-Options: nosniff', 'Connection: close']
    lines += [f'{k}: {v}' for k, v in extra]
    sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode() + (b'' if head_only else body))


def close_quietly(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError):
        pass
    try:
        sock.close()
    except OSError:
        pass


class FetchError(Exception):
    def __init__(self, kind, detail=''):
        super().__init__(f'{kind} {detail}'.strip())
        self.kind = kind  # unreachable | bad-url | bad-status | oversized | deadline | busy


def fetch(url, max_bytes=MAX_FILE, deadline=5.0, ca_file=None):
    """GET with hard limits. Returns the body, None for a 404, or raises FetchError.
    `deadline` is wall-clock for everything but name resolution, so a server that drips bytes loses."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
        raise FetchError('bad-url', url)
    target = (u.path or '/') + (f'?{u.query}' if u.query else '')
    if u.scheme == 'https':
        context = ssl.create_default_context(cafile=ca_file)
        conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=deadline, context=context)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=deadline)
    fired = threading.Event()

    def expire():
        fired.set()
        if conn.sock is not None:
            close_quietly(conn.sock)

    killer = threading.Timer(deadline, expire)
    killer.daemon = True
    killer.start()
    try:
        conn.connect()  # a peer that takes no connection is down; one that drops an accepted connection is busy
    except OSError as e:
        killer.cancel()
        conn.close()
        raise FetchError('deadline' if fired.is_set() else 'unreachable', type(e).__name__) from e
    answered = False
    try:
        conn.request('GET', target, headers={'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = conn.getresponse()
        answered = True
        if response.status == 404:
            return None
        if response.status == 503:
            raise FetchError('busy', url)
        if response.status != 200:  # redirects included: a peer never sends us elsewhere
            raise FetchError('bad-status', str(response.status))
        if response.getheader('Content-Encoding', 'identity') != 'identity':
            raise FetchError('bad-status', 'encoded response')
        declared = response.getheader('Content-Length')
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise FetchError('oversized', declared)
        chunks, total = [], 0
        while True:
            chunk = response.read1(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise FetchError('oversized', f'>{max_bytes}')
            chunks.append(chunk)
        if fired.is_set():  # the deadline closed the socket, which reads as a clean end of stream
            raise FetchError('deadline', url)
        if response.length:  # the connection closed before the declared length
            raise FetchError('unreachable', 'truncated')
        return b''.join(chunks)
    except FetchError:
        raise
    except (OSError, http.client.HTTPException, ValueError) as e:
        if fired.is_set():
            raise FetchError('deadline', url) from e
        if not answered and isinstance(e, (ConnectionError, http.client.RemoteDisconnected)):
            raise FetchError('busy', type(e).__name__) from e
        raise FetchError('unreachable', f'{type(e).__name__}') from e
    finally:
        killer.cancel()
        conn.close()


class Peers:
    """The set-once list of feed URLs, with one backoff per peer and counters for the operator."""

    def __init__(self, urls, base_backoff=30.0, max_backoff=600.0, clock=time.monotonic):
        self.state = {u.rstrip('/'): {'failures': 0, 'retry_at': 0.0, 'last_ok': None, 'last_error': None,
                                      'rejected': 0, 'accepted': 0} for u in urls}
        self.base, self.max, self.clock = base_backoff, max_backoff, clock
        self.lock = threading.Lock()
        self.cursors = {}

    def available(self):
        now = self.clock()
        return [u for u, s in self.state.items() if s['retry_at'] <= now]

    def ok(self, url):
        with self.lock:
            s = self.state[url]
            s.update(failures=0, retry_at=0.0, last_ok=int(time.time()), last_error=None)

    def fail(self, url, reason):
        with self.lock:
            s = self.state[url]
            s['failures'] += 1
            s['last_error'] = reason
            s['retry_at'] = self.clock() + min(self.max, self.base * 2 ** (s['failures'] - 1))

    def note(self, url, reason):
        """Worth telling the operator, but the peer is healthy: no backoff."""
        with self.lock:
            self.state[url]['last_error'] = reason

    def cursor(self, url, total):
        """Where this peer's next cycle starts, so a long list is covered over several cycles."""
        with self.lock:
            return self.cursors.setdefault(url, random.randrange(total)) % total

    def advance(self, url, scanned):
        with self.lock:
            self.cursors[url] = self.cursors.get(url, 0) + scanned

    def count(self, url, what):
        with self.lock:
            self.state[url][what] += 1

    def status(self):
        with self.lock:
            return {u: {k: v for k, v in s.items() if k != 'retry_at'} for u, s in self.state.items()}


def pull(peers, paths, accept, max_bytes=MAX_FILE, fetch_deadline=5.0, peer_budget=20.0, ca_file=None, first_wins=True,
         fetcher=fetch, max_paths=MAX_PATHS_PER_CYCLE):
    """Ask every available peer for `paths`, one thread per peer, so a bad peer delays nobody else.

    `accept(path, body, url)` verifies and stores, returning True for content it took. It must be
    thread-safe. With `first_wins`, a path one peer satisfied is not asked of the others. A peer that
    fails to answer at all is dropped for this cycle and backs off; a 404 is healthy. A busy peer, or a peer not finished
    within `peer_budget` seconds or `max_paths` paths, is left for the next cycle with no backoff, and that cycle resumes
    where this one stopped. Returns when every peer finished or spent `peer_budget` seconds."""
    done, done_lock = set(), threading.Lock()

    def one_peer(url):
        stop = time.monotonic() + peer_budget
        order = list(paths)
        start = peers.cursor(url, len(order)) if order else 0
        order = order[start:] + order[:start]
        scanned = asked = 0
        try:
            for path in order:
                if time.monotonic() >= stop:
                    peers.note(url, 'budget')
                    return
                with done_lock:
                    if first_wins and path in done:
                        scanned += 1
                        continue
                if asked >= max_paths:
                    return
                asked += 1
                try:
                    body = fetcher(f'{url}/{path}', max_bytes=max_bytes,
                                   deadline=min(fetch_deadline, stop - time.monotonic()), ca_file=ca_file)
                except FetchError as e:
                    if e.kind in ('unreachable', 'deadline'):
                        peers.fail(url, e.kind)
                        return
                    if e.kind == 'busy':
                        peers.note(url, 'busy')
                        peers.count(url, 'rejected')
                        return
                    peers.count(url, 'rejected')  # oversized, bad status: a misbehaving reply, next path
                    scanned += 1
                    continue
                scanned += 1
                peers.ok(url)
                if body is None:
                    continue
                taken = accept(path, body, url)
                peers.count(url, 'accepted' if taken else 'rejected')
                if taken:
                    with done_lock:
                        done.add(path)
        finally:
            peers.advance(url, scanned)

    threads = [threading.Thread(target=one_peer, args=(u,), daemon=True) for u in peers.available()]
    for t in threads:
        t.start()
    limit = time.monotonic() + peer_budget + fetch_deadline + 1.0
    for t in threads:
        t.join(max(0.0, limit - time.monotonic()))
    return done


def atomic_write(path, data):
    """Readers (and the server) only ever see a complete file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def tree_bytes(*roots):
    total = 0
    for root in roots:
        for base, _, files in os.walk(root):
            for name in files:
                try:
                    total += os.lstat(os.path.join(base, name)).st_size
                except OSError:
                    pass
    return total


def disk_free(path):
    probe = Path(path)
    while not probe.exists():
        probe = probe.parent
    return shutil.disk_usage(probe).free


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('serve')
    s.add_argument('--root', required=True)
    s.add_argument('--bind', default='127.0.0.1')
    s.add_argument('--port', type=int, required=True)
    s.add_argument('--tls-cert')
    s.add_argument('--tls-key')
    g = sub.add_parser('get')
    g.add_argument('url')
    g.add_argument('--max-bytes', type=int, default=MAX_FILE)
    g.add_argument('--ca-file')
    a = p.parse_args(argv)
    if a.cmd == 'serve':
        tls = (a.tls_cert, a.tls_key) if a.tls_cert else None
        server = FeedServer(a.root, a.bind, a.port, tls=tls)
        print(json.dumps({'event': 'sigfeed-serving', 'root': server.root, 'bind': a.bind, 'port': server.port,
                          'tls': bool(tls)}), flush=True)
        server.serve_forever()
        return 0
    try:
        body = fetch(a.url, max_bytes=a.max_bytes, ca_file=a.ca_file)
    except FetchError as e:
        print(e, file=sys.stderr)
        return 1
    if body is None:
        print('404', file=sys.stderr)
        return 1
    sys.stdout.buffer.write(body)
    return 0


if __name__ == '__main__':
    sys.exit(main())
