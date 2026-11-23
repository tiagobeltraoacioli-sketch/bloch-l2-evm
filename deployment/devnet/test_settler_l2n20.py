#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit AUDIT-L1L2-20261123, L2N-20: one faulty L1 RPC endpoint of three must not stop the settler.

(B) an endpoint that drips or floods its answer is a failed endpoint within the exchange deadline, and the
    quorum read returns from the two honest ones;
(A) an endpoint that answers the quorum-checked fields honestly and garbage in the fields `hold_block` reads
    outside the quorum is a missing vote, not a failed read: the block is still built.
"""
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fake_l1_rpc  # noqa: E402
import settler_v3 as s  # noqa: E402

GENESIS = 'aa' * 32
VIEW = {'network': 'net', 'genesis': 'gen', 'chain_id': 700770, 'asynchronous': True, 'accepted': None,
        'source': {'block': 'bb' * 32, 'slot': 100, 'pending': [], 'request': 'x'}, 'data_availability': [],
        'inbox': {'count': 1, 'consumed': 0}}  # one unconsumed deposit: a block is due
CHAIN = {'slot': 100 + 4000, 'height': 4000}


def honest(method):
    return dict(VIEW) if method == 'getl2settlement' else dict(CHAIN)


def malformed(method):
    """The same safety-relevant view; garbage in the two fields read outside the quorum projection."""
    answer = honest(method)
    if method == 'getl2settlement':
        answer['inbox'] = None
    else:
        answer['slot'] = 'not-a-number'
    return answer


def settler(urls, directory, deadline=1.0):
    """The real Settler methods and the real rpc(), without the binary pins of __init__."""
    it = s.Settler.__new__(s.Settler)
    it.c = {**s.DEFAULTS, 'l2_db': directory, 'l2_genesis': GENESIS, 'user_transactions': False,
            'skip_idle_blocks': True, 'max_idle_seconds': 86400, 'min_block_interval_seconds': 1800,
            'timestamp_rule': '1:1786656679:30000', 'network': 'net'}
    it.chain_id, it.clock, it.sleep = 700770, time.monotonic, time.sleep
    it.native = s.Endpoints(urls, 2, lambda port, method, params=(): s.rpc(port, method, params, deadline=deadline),
                            time.monotonic)
    it.accepted_floor, it.floor_stall, it.holding_since, it.hold_logged_at, it.spool_open = 0, None, None, None, True
    it.produce = lambda *a, **k: {'hash': GENESIS, 'number': 0}
    return it


class BoundedExchange(unittest.TestCase):
    def test_an_honest_answer_and_a_json_rpc_error_are_read_as_before(self):
        self.assertEqual(s.rpc(fake_l1_rpc.serve('honest', honest), 'getchaininfo'), CHAIN)
        self.assertIsNone(s.rpc(fake_l1_rpc.serve('honest', lambda method: None), 'getchaininfo'))
        refusing = fake_l1_rpc.serve('raw', body=b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"no"}}')
        with self.assertRaisesRegex(s.RpcError, 'getchaininfo: .*no'):
            s.rpc(refusing, 'getchaininfo')
        with self.assertRaisesRegex(s.RpcError, 'not a JSON-RPC object'):
            s.rpc(fake_l1_rpc.serve('raw', body=b'["not", "an", "object"]'), 'getchaininfo')
        with self.assertRaises(ValueError):
            s.rpc(fake_l1_rpc.serve('raw', body=b'<html>gateway error</html>'), 'getchaininfo')

    def test_the_deadline_covers_the_whole_exchange_not_each_socket_call(self):
        # One byte every 0.2 s never trips a per-operation timeout; the pinned rpc() read it for ever.
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, 'getl2settlement: no complete answer within 1.0 s'):
            s.rpc(fake_l1_rpc.serve('drip'), 'getl2settlement', deadline=1.0)
        self.assertLess(time.monotonic() - started, 5)
        # An endpoint that says nothing at all ends at the deadline or at the socket timeout, whichever is first.
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, 'getl2settlement: (no complete answer within|endpoint silent for) 1.0 s'):
            s.rpc(fake_l1_rpc.serve('silent'), 'getl2settlement', deadline=1.0)
        self.assertLess(time.monotonic() - started, 5)

    def test_an_answer_above_the_byte_cap_is_refused_while_it_is_read(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'answer larger than 100000 bytes'):
            s.rpc(fake_l1_rpc.serve('flood'), 'getl2settlement', deadline=20, max_bytes=100_000)
        self.assertLess(time.monotonic() - started, 10)

    def test_an_http_error_status_and_a_closed_port_are_failures(self):
        with self.assertRaisesRegex(ValueError, 'HTTP status 500'):
            s.rpc(fake_l1_rpc.serve('status'), 'getchaininfo')
        with self.assertRaises(OSError):
            s.rpc('http://127.0.0.1:1', 'getchaininfo', deadline=2)
        with self.assertRaisesRegex(ValueError, 'not an http'):
            s.rpc('file:///etc/hosts', 'getchaininfo')

    def test_the_defaults_are_thirty_seconds_and_sixteen_mebibytes(self):
        self.assertEqual((s.RPC_DEADLINE_SECONDS, s.RPC_MAX_RESPONSE_BYTES), (30, 16 << 20))


class OneFaultyEndpointOfThree(unittest.TestCase):
    def test_a_dripping_endpoint_fails_inside_the_deadline_and_the_quorum_read_returns(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(s, 'log') as logged:
            for position in (0, 2):  # first in the list (the worker never reached the others), and last
                urls = [fake_l1_rpc.serve('honest', honest) for _ in range(2)]
                urls.insert(position, fake_l1_rpc.serve('drip'))
                it = settler(urls, directory)
                started = time.monotonic()
                view = it.native_view()
                self.assertIsNotNone(view, 'two honest endpoints are a quorum')
                self.assertLess(time.monotonic() - started, 6)
                failed = [c for c in logged.call_args_list if c.args[0] == 'rpc-endpoint-failed']
                self.assertTrue(failed and all(c.kwargs['port'] == urls[position] for c in failed))
                self.assertIn('TimeoutError', failed[-1].kwargs['reason'])
                # In backoff: the next read does not wait for it again.
                started = time.monotonic()
                self.assertIsNotNone(it.native_view())
                self.assertLess(time.monotonic() - started, 0.9)
                logged.reset_mock()

    def test_garbage_outside_the_quorum_projection_is_a_missing_vote_and_the_block_is_built(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(s, 'log') as logged:
            urls = [fake_l1_rpc.serve('honest', honest), fake_l1_rpc.serve('honest', honest),
                    fake_l1_rpc.serve('honest', malformed)]
            it = settler(urls, directory)
            view = it.native_view()
            self.assertIsNotNone(view, 'the faulty endpoint agrees on every quorum-checked field')
            self.assertEqual([it.hold_block(view) for _ in range(3)], [False, False, False],
                             'the pinned settler held every cycle (idle-check-failed)')
            events = [c.args[0] for c in logged.call_args_list]
            self.assertNotIn('idle-check-failed', events)
            self.assertIn('idle-end', events)
            bad = [c.kwargs for c in logged.call_args_list if c.args[0] == 'rpc-endpoint-malformed']
            self.assertEqual({(k['port'], k['method']) for k in bad},
                             {(urls[2], 'getchaininfo'), (urls[2], 'getl2settlement')})
            self.assertEqual(it.inbox_backlog(), 1)

    def test_the_bound_is_still_no_larger_than_an_honest_answer(self):
        answers = {}
        endpoints = s.Endpoints([1, 2, 3], 2, lambda port, method, params=(): answers[port], lambda: 0)
        read = lambda: endpoints.bounded_value('getchaininfo', 'slot')  # noqa: E731
        with mock.patch.object(s, 'log') as logged:
            answers.update({1: {'slot': 7}, 2: {'slot': 12}, 3: {'slot': 10 ** 9}})
            self.assertEqual(read(), 12, 'the median of three: an inflated answer is ignored')
            # One unusable answer: the smaller of the two that are left.
            for garbage in ({'slot': 'x'}, {}, None, [], {'slot': None}, {'slot': [1]}, 'text'):
                answers.update({1: {'slot': 7}, 2: {'slot': 12}, 3: garbage})
                logged.reset_mock()
                self.assertEqual(read(), 7, garbage)
                self.assertEqual([c.args[0] for c in logged.call_args_list], ['rpc-endpoint-malformed'], garbage)
            # A numeric string is what the native RPC sends for large integers.
            answers.update({1: {'slot': '7'}, 2: {'slot': '12'}, 3: {'slot': '9'}})
            self.assertEqual(read(), 9)
            # Two unusable answers of three: no quorum, the read fails (and hold_block holds).
            answers.update({1: {'slot': 7}, 2: {}, 3: None})
            with self.assertRaisesRegex(RuntimeError, '1 of 3 RPC endpoints gave a usable answer, 2 needed'):
                read()


if __name__ == '__main__':
    unittest.main()
