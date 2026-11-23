#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit AUDIT-L1L2-20261123, L2N-20: the shadow producer and the attestor agent read L1 with the same
exchange as the settler. One endpoint of three that drips its answer is a missing vote within the exchange
deadline; the quorum view returns from the two honest endpoints."""
from pathlib import Path
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'attestor'))
sys.path.insert(0, str(HERE.parent / 'devnet'))
import attestor_agent as aa  # noqa: E402
import attestor_lib as lib  # noqa: E402
import fake_l1_rpc  # noqa: E402
import sequencer_mainnet as q  # noqa: E402
import test_sequencer_mainnet as shadow_fixtures  # noqa: E402

P = lib.MAINNET
ATTESTOR_VIEW = {'network': P.network, 'genesis': P.genesis, 'chain_id': P.chain_id,
                 'withdrawals': {'attestor_set': P.set_hash, 'large_claim_sat': P.large_claim_sat, 'roots': [],
                                 'claimed': {}}}


class ShadowProducer(unittest.TestCase):
    def test_the_exchange_has_one_deadline_of_twice_the_configured_timeout_and_a_byte_cap(self):
        honest = fake_l1_rpc.serve('honest', lambda method: {'ok': method})
        self.assertEqual(q.http_rpc(honest, 'getl2settlement'), {'ok': 'getl2settlement'})
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, 'no complete answer within 1.0 s'):
            q.http_rpc(fake_l1_rpc.serve('drip'), 'getl2settlement', (), 0.5)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(q.RPC_MAX_RESPONSE_BYTES, 16 << 20)
        with self.assertRaisesRegex(ValueError, 'answer larger than'):
            q.bounded_post(fake_l1_rpc.serve('flood'), b'{"method":"x"}', 20, 100_000, {})
        with self.assertRaisesRegex(RuntimeError, 'getl2settlement: .*no'):
            q.http_rpc(fake_l1_rpc.serve('raw', body=b'{"error":{"message":"no"}}'), 'getl2settlement')
        with self.assertRaisesRegex(RuntimeError, 'not a JSON-RPC object'):
            q.http_rpc(fake_l1_rpc.serve('raw', body=b'[1]'), 'getl2settlement')

    def test_native_view_returns_with_one_dripping_endpoint_of_three(self):
        view = shadow_fixtures.view()
        for position in (0, 2):
            urls = [fake_l1_rpc.serve('honest', lambda method: view) for _ in range(2)]
            urls.insert(position, fake_l1_rpc.serve('drip'))
            shadow = q.Sequencer.__new__(q.Sequencer)
            shadow.c = {**q.DEFAULTS, 'rpc_urls': urls, 'rpc_timeout_seconds': 0.5}
            shadow.rpc, shadow.quorum = q.http_rpc, 2
            started = time.monotonic()
            self.assertEqual(shadow.native_view(), q.view_projection(view))
            self.assertLess(time.monotonic() - started, 5, 'the pinned shadow never returned')


class AttestorAgent(unittest.TestCase):
    def agent(self, urls, timeout=0.5):
        agent = aa.Agent.__new__(aa.Agent)
        agent.pins = P
        agent.c = {**aa.DEFAULTS, 'rpc_urls': urls, 'rpc_timeout_seconds': timeout}
        return agent

    def test_the_exchange_has_one_deadline_of_twice_the_configured_timeout_and_a_byte_cap(self):
        agent = self.agent([])
        self.assertEqual(agent.rpc(fake_l1_rpc.serve('honest', lambda method: ATTESTOR_VIEW), 'getl2settlement'),
                         ATTESTOR_VIEW)
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, 'no complete answer within 1.0 s'):
            agent.rpc(fake_l1_rpc.serve('drip'), 'getl2settlement')
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(aa.RPC_MAX_RESPONSE_BYTES, 8_000_000)
        with self.assertRaisesRegex(ValueError, 'answer larger than'):
            aa.bounded_post(fake_l1_rpc.serve('flood'), b'{"method":"x"}', 20, 100_000, {})
        with self.assertRaisesRegex(ValueError, 'getl2settlement: .*no'):
            agent.rpc(fake_l1_rpc.serve('raw', body=b'{"error":{"message":"no"}}'), 'getl2settlement')
        with self.assertRaisesRegex(ValueError, 'not a JSON-RPC object'):
            agent.rpc(fake_l1_rpc.serve('raw', body=b'[1]'), 'getl2settlement')

    def test_view_returns_with_one_dripping_endpoint_of_three(self):
        for position in (0, 1, 2):
            urls = [fake_l1_rpc.serve('honest', lambda method: ATTESTOR_VIEW) for _ in range(2)]
            urls.insert(position, fake_l1_rpc.serve('drip'))
            started = time.monotonic()
            view = self.agent(urls).view()
            self.assertLess(time.monotonic() - started, 5, 'the pinned agent never returned')
            self.assertEqual(view['chain_id'], P.chain_id)

    def test_two_dripping_endpoints_of_three_are_no_quorum_and_still_return(self):
        urls = [fake_l1_rpc.serve('drip'), fake_l1_rpc.serve('honest', lambda method: ATTESTOR_VIEW),
                fake_l1_rpc.serve('drip')]
        started = time.monotonic()
        with self.assertRaises(aa.Skip):
            self.agent(urls).view()
        self.assertLess(time.monotonic() - started, 8)


if __name__ == '__main__':
    unittest.main()
