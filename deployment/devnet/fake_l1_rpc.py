# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test support: local fake L1 JSON-RPC endpoints on 127.0.0.1 with a chosen fault (audit L2N-20, L2N-21).

    honest     answers `result(method)` at once
    drip       sends the headers and the start of a body, then one byte every `gap` seconds, for ever
    flood      sends an endless body as fast as the client reads
    silent     accepts the connection and never answers
    status     answers HTTP 500
    raw        answers the bytes `body` as they are
"""
import http.server
import json
import threading
import time


def serve(mode, result=lambda method: {}, gap=0.2, body=b''):
    """Start one endpoint; returns its URL. The thread and its sockets end with the process."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            method = json.loads(self.rfile.read(int(self.headers['content-length'])))['method']
            if mode == 'silent':
                time.sleep(3600)
                return
            if mode == 'status':
                self.send_response(500)
                self.send_header('content-length', '0')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            if mode in ('drip', 'flood'):
                self.end_headers()
                self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":"')
                self.wfile.flush()
                try:
                    while True:
                        if mode == 'drip':
                            time.sleep(gap)
                            self.wfile.write(b'a')
                        else:
                            self.wfile.write(b'a' * 65536)
                        self.wfile.flush()
                except OSError:
                    return
            answer = body if mode == 'raw' else json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': result(method)}).encode()
            self.send_header('content-length', str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f'http://127.0.0.1:{server.server_address[1]}'
