#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit AUDIT-L1L2-20261123, L2N-21: `sigfeed.fetch` promises a wall-clock deadline per fetch. Once the headers
of a `Connection: close` answer were read, the deadline timer had no socket left to close, and a source that
dripped the body held the fetch for `max_bytes x deadline` (days). The deadline now covers the body."""
import http.server
from pathlib import Path
import sys
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'attestor'))
import sigfeed  # noqa: E402


def feed(mode, gap=0.2):
    """A feed source on 127.0.0.1: `whole` answers at once; `drip-body` sends the headers and then one byte
    every `gap` seconds for ever; `drip-headers` does the same with the header block."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if mode == 'whole':
                self.send_response(200)
                self.send_header('Content-Length', '5')
                self.end_headers()
                self.wfile.write(b'hello')
                return
            self.wfile.write(b'HTTP/1.0 200 OK\r\n')
            if mode == 'drip-body':
                self.wfile.write(b'\r\n')
            self.wfile.flush()
            try:
                while True:
                    time.sleep(gap)
                    self.wfile.write(b'a')
                    self.wfile.flush()
            except OSError:
                return

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f'http://127.0.0.1:{server.server_address[1]}/x'


class FetchDeadline(unittest.TestCase):
    def test_an_honest_source_is_read_as_before(self):
        self.assertEqual(sigfeed.fetch(feed('whole'), deadline=2.0), b'hello')

    def test_the_deadline_ends_a_dripped_body(self):
        # Every gap (0.2 s) is inside the socket timeout (1 s): only the wall-clock timer can end this.
        started = time.monotonic()
        with self.assertRaises(sigfeed.FetchError) as raised:
            sigfeed.fetch(feed('drip-body'), deadline=1.0)
        self.assertEqual(raised.exception.kind, 'deadline')
        self.assertLess(time.monotonic() - started, 3, 'the pinned fetch was still reading after 25 s')

    def test_the_deadline_ends_dripped_headers(self):
        started = time.monotonic()
        with self.assertRaises(sigfeed.FetchError) as raised:
            sigfeed.fetch(feed('drip-headers'), deadline=1.0)
        self.assertEqual(raised.exception.kind, 'deadline')
        self.assertLess(time.monotonic() - started, 3)

    def test_the_byte_cap_still_applies(self):
        with self.assertRaises(sigfeed.FetchError) as raised:
            sigfeed.fetch(feed('drip-body', gap=0.001), max_bytes=20, deadline=5.0)
        self.assertEqual(raised.exception.kind, 'oversized')


if __name__ == '__main__':
    unittest.main()
