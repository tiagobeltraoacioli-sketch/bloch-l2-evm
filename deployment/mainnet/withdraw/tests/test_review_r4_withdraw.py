#!/usr/bin/env python3
"""Independent review, round 4: what the withdraw tool does with the gateway's and the edge's failure answers.
The tool code is real; the RPC is a loopback stub. A failure here is a finding. Run: python3 test_review_r4_withdraw.py"""
import http.server
import importlib.util
from pathlib import Path
import threading
import unittest

spec = importlib.util.spec_from_file_location('withdraw', Path(__file__).resolve().parents[1] / 'bloch-l2-withdraw.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


def serve(status, body, truncate=False):
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['content-length']))
            self.send_response(status)
            self.send_header('content-length', str(len(body) + (10 if truncate else 0)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f'http://127.0.0.1:{server.server_port}'


class Failures(unittest.TestCase):
    def outcome(self, status, body, **kw):
        server, url = serve(status, body, **kw)
        try:
            W.ask_proof(url, 0)
        except Exception as error:  # noqa: BLE001
            return type(error).__name__, str(error)[:120]
        finally:
            server.shutdown()
        return 'answered', ''

    def test_an_edge_error_page_is_retryable_not_a_refusal(self):
        kind, text = self.outcome(502, b'<html><title>502 Bad Gateway</title></html>')
        self.assertEqual(kind, 'NotReady', text)

    def test_an_answer_cut_short_is_retryable_and_does_not_escape_main(self):
        kind, text = self.outcome(200, b'{"jsonrpc":"2.0"', truncate=True)
        self.assertEqual(kind, 'NotReady', text)

    def test_frozen_on_one_backend_is_not_final_behind_a_gateway(self):
        kind, text = self.outcome(200, b'{"jsonrpc":"2.0","id":1,"error":{"code":-32046,"message":"frozen"}}')
        self.assertEqual(kind, 'NotReady', text)


if __name__ == '__main__':
    unittest.main()
