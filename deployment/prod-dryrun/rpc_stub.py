#!/usr/bin/env python3
"""DRY-RUN ONLY (agent 385): a loopback stand-in for the settled RPC, so that setup-gateway.sh's backend check
(eth_chainId == 0xab162 on 127.0.0.1:18955) and the gateway's /health can be exercised in a container where the
real RPC is never started. It answers eth_chainId and refuses every other method with -32601."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length') or 0) or 0)
        try:
            request = json.loads(body or b'{}')
        except ValueError:
            request = {}
        calls = request if isinstance(request, list) else [request]
        out = []
        for call in calls:
            ident = call.get('id', 1) if isinstance(call, dict) else 1
            method = call.get('method') if isinstance(call, dict) else None
            if method in ('eth_chainId', None):
                out.append({'jsonrpc': '2.0', 'id': ident, 'result': '0xab162'})
            else:
                out.append({'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32601, 'message': 'dry-run stub'}})
        data = json.dumps(out if isinstance(request, list) else out[0]).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
