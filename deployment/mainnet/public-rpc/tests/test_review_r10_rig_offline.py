#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The real-nginx rig's own plumbing, without nginx (review_r10_rig.py R4 gave no verdict in rounds 10 and 11: its
client timed out and the exception ended the run, and its RSS sampler thread could die on one bad sample and leave
a stale peak). Loopback only."""
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('review_r10_rig', HERE / 'review_r10_rig.py')
rig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rig)


class Client(unittest.TestCase):
    def test_a_client_timeout_is_a_result_not_an_exception(self):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(4)
        self.addCleanup(server.close)
        held = []
        threading.Thread(target=lambda: held.append(server.accept()), daemon=True).start()
        started = time.time()
        status, detail = rig.post(f'http://127.0.0.1:{server.getsockname()[1]}', rig.call(1), '192.0.2.1', timeout=1)
        self.assertEqual(status, 'timeout', detail)
        self.assertLess(time.time() - started, 10)

    def test_a_refused_or_dropped_connection_is_a_result(self):
        free = socket.socket()
        free.bind(('127.0.0.1', 0))
        port = free.getsockname()[1]
        free.close()
        status, detail = rig.post(f'http://127.0.0.1:{port}', rig.call(1), '192.0.2.1', timeout=2)
        self.assertEqual(status, 'error', detail)
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(4)
        self.addCleanup(server.close)

        def drop():
            conn, _ = server.accept()
            conn.recv(65536)
            conn.close()
        threading.Thread(target=drop, daemon=True).start()
        status, detail = rig.post(f'http://127.0.0.1:{server.getsockname()[1]}', rig.call(1), '192.0.2.1', timeout=5)
        self.assertEqual(status, 'error', detail)


class FakePair:
    def __init__(self, results):
        self.results, self.calls = list(results), 0

    def workers_rss(self):
        self.calls += 1
        item = self.results[min(self.calls - 1, len(self.results) - 1)]
        if isinstance(item, Exception):
            raise item
        return item


class Sampler(unittest.TestCase):
    def test_workers_rss_never_raises_on_a_reloading_master(self):
        with tempfile.TemporaryDirectory() as tmp:
            confs = []
            for content in (None, '', 'x\n', f'{os.getpid()}\n'):
                conf = Path(tmp) / str(len(confs))
                conf.mkdir()
                if content is not None:
                    (conf / 'nginx.pid').write_text(content)
                confs.append(conf)
            pair = rig.Pair.__new__(rig.Pair)
            pair.confs = confs
            total, workers = pair.workers_rss()  # /proc may not exist (macOS): then nothing is counted
            self.assertGreaterEqual(total, 0)
            self.assertGreaterEqual(workers, 0)

    def test_a_sample_error_does_not_stop_the_sampler_and_is_reported(self):
        pair = FakePair([(1000, 2), ValueError('no VmRSS'), (4000, 2)])
        with rig.RssSampler(pair) as rss:
            time.sleep(0.6)
        self.assertGreaterEqual(rss.samples, 5, 'kept sampling after the error')
        self.assertEqual(rss.peak, 4000)
        self.assertEqual(rss.errors, ['ValueError: no VmRSS'])
        self.assertFalse(rss.measured(), 'a sampler error makes the verdict a FAIL, not a silent PASS')

    def test_no_worker_found_is_not_a_measurement(self):
        with rig.RssSampler(FakePair([(0, 0)])) as rss:
            time.sleep(0.4)
        self.assertEqual(rss.samples, 0)
        self.assertFalse(rss.measured())

    def test_a_clean_run_is_measured(self):
        with rig.RssSampler(FakePair([(2048, 4)])) as rss:
            time.sleep(0.5)
        self.assertTrue(rss.measured())
        self.assertEqual(rss.detail()['workers'], 4)


if __name__ == '__main__':
    unittest.main()
