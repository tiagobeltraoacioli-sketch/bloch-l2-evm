#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""render.py checks for review 154's G6 and G8 (no nginx needed).

G6: the outbound peer hop is a unix socket in --hop-dir, never a TCP listener, and the peer
probe goes through a fixed-body loopback location. G8: the public server trusts the owner's
own Authenticated Origin Pulls CA (depth 1) and refuses Cloudflare's shared CA.

    python3 -m unittest tests/test_render_r10.py
"""
import base64
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RENDER = HERE / 'render.py'
GATEWAY_JS = HERE / 'l2rpc-gateway.js'


def pem(der):
    body = base64.encodebytes(der).decode()
    return f'-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n'


class RenderR10(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def render(self, *extra, role='replica', peer=True):
        out = self.dir / f'out-{len(list(self.dir.iterdir()))}'
        args = [sys.executable, RENDER, '--role', role, '--name', 't', '--out', out, '--tls-cert', 'c', '--tls-key', 'k']
        if peer:
            args += ['--peer', '203.0.113.7:18956', '--peer-allow', '203.0.113.7', '--peer-dir', self.dir / 'peer']
        result = subprocess.run([str(a) for a in args + list(extra)], capture_output=True, text=True)
        return result, out

    def test_the_peer_hop_is_a_unix_socket_in_the_hop_dir(self):
        result, out = self.render('--hop-dir', '/run/bloch-l2rpc', '--client-ca', 'none')
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (out / 'l2rpc-gateway.conf').read_text()
        self.assertIn('    listen unix:/run/bloch-l2rpc/peer-out.sock;', conf)
        listens = re.findall(r'^\s*listen\s+([^;]+);', conf, re.M)
        tcp = [x for x in listens if not x.startswith('unix:')]
        # Public TLS listeners, the probe server on loopback and the inbound mTLS peer listener only.
        self.assertEqual(sorted(tcp), sorted(['443 ssl http2', '[::]:443 ssl http2', '127.0.0.1:18958', '0.0.0.0:18956 ssl']))
        self.assertNotIn('18957', conf)
        # Every upstream that reaches the peer uses the socket.
        for line in re.findall(r'^\s*server\s+(\S+)', conf, re.M):
            self.assertFalse(line.startswith('127.0.0.1:1895') and line != '127.0.0.1:18955', line)
        self.assertGreaterEqual(conf.count('server unix:/run/bloch-l2rpc/peer-out.sock'), 3)

    def test_the_peer_probe_sends_only_its_fixed_batch(self):
        result, out = self.render('--client-ca', 'none')
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (out / 'l2rpc-gateway.conf').read_text()
        block = re.search(r'location = /_peer_probe \{(.*?)\n    \}', conf, re.S).group(1)
        self.assertIn('allow 127.0.0.1;', block)
        self.assertIn('deny all;', block)
        self.assertIn('proxy_pass http://unix:/run/bloch-l2rpc/peer-out.sock:/;', block)
        body = re.search(r"proxy_set_body '([^']*)';", block).group(1)
        # The same batch the njs probe sends and parses by id.
        js = GATEWAY_JS.read_text()
        js_body = re.search(r'const PROBE_BODY = JSON.stringify\((\[.*?\])\);', js, re.S).group(1)
        js_methods = re.findall(r"method: '([A-Za-z_]+)'", js_body)
        self.assertEqual([c['method'] for c in json.loads(body)], js_methods)
        self.assertEqual(json.loads(body)[2]['params'], ['finalized', False])
        self.assertEqual([c['id'] for c in json.loads(body)], [1, 2, 3, 4])
        config = (out / 'l2rpc-config.js').read_text()
        self.assertIn('"peerProbeUrl": "http://127.0.0.1:18958/_peer_probe"', config)

    def test_no_peer_no_hop(self):
        result, out = self.render('--client-ca', 'none', role='sequencer', peer=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (out / 'l2rpc-gateway.conf').read_text()
        # The only unix socket left is the subrequest size guard (no peer hop).
        self.assertNotIn('peer-out.sock', conf)
        self.assertEqual(set(re.findall(r'unix:[^ ;:]+', conf)), {'unix:/run/bloch-l2rpc/guard.sock'})
        self.assertNotIn('_peer_probe', conf)

    def test_subrequest_size_guard(self):
        result, out = self.render('--client-ca', 'none')
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (out / 'l2rpc-gateway.conf').read_text()
        self.assertIn('location ~ ^/_l2s/(local|peer|seqread|seq)$', conf)
        self.assertIn('subrequest_output_buffer_size 2162688;', conf)
        self.assertEqual(conf.count('js_body_filter l2rpc.guardBody buffer_type=buffer;'), 4)
        self.assertNotIn('16m;\n', (out / 'l2rpc-proxy.inc').read_text())
        self.assertIn('"subAnswerMaxBytes": 2097152', (out / 'l2rpc-config.js').read_text())
        bad, _ = self.render('--client-ca', 'none', '--sub-answer-max', '1000')
        self.assertNotEqual(bad.returncode, 0)

    def test_transaction_routes_allow_admission_time_but_never_retry(self):
        result, out = self.render('--client-ca', 'none')
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (out / 'l2rpc-gateway.conf').read_text()
        for route in ('/_l2/seq', '/seq'):
            block = re.search(r'location = ' + re.escape(route) + r' \{(.*?)\n    \}', conf, re.S).group(1)
            self.assertIn('proxy_read_timeout 30s;', block)
            self.assertIn('proxy_next_upstream off;', block)
            self.assertNotIn('proxy_next_upstream_tries', block)

    def test_the_old_tcp_hop_option_is_refused(self):
        result, _ = self.render('--peer-out-port', '18957', '--client-ca', 'none')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unix socket', result.stderr)

    def test_a_relative_hop_dir_is_refused(self):
        result, _ = self.render('--hop-dir', 'run/x', '--client-ca', 'none')
        self.assertNotEqual(result.returncode, 0)

    def test_the_owner_ca_is_trusted_at_depth_one(self):
        ca = self.dir / 'aop-client-ca.pem'
        ca.write_text(pem(b'0\x82 subject CN=Bloch L2 RPC AOP CA ...'))
        result, out = self.render('--client-ca', ca)
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (out / 'l2rpc-gateway.conf').read_text()
        public = conf.split('# ------------------------------------------------------------------ public')[1].split('location')[0]
        self.assertIn(f'ssl_client_certificate {ca};', public)
        self.assertIn('ssl_verify_client on;', public)
        self.assertIn('ssl_verify_depth 1;', public)

    def test_the_default_client_ca_is_the_owner_file(self):
        result, out = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ssl_client_certificate /etc/ssl/bloch-l2rpc/aop-client-ca.pem;', (out / 'l2rpc-gateway.conf').read_text())

    def test_cloudflare_shared_ca_is_refused(self):
        shared = self.dir / 'shared.pem'
        shared.write_text(pem(b'0\x82 ... CN=origin-pull.cloudflare.net ...'))
        result, _ = self.render('--client-ca', shared)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shared AOP CA", result.stderr)
        # A bundle that still carries it (switch-over) needs the explicit flag.
        bundle = self.dir / 'bundle.pem'
        bundle.write_text(pem(b'0\x82 own CA') + shared.read_text())
        result, _ = self.render('--client-ca', bundle)
        self.assertNotEqual(result.returncode, 0)
        result, _ = self.render('--client-ca', bundle, '--allow-shared-aop-ca')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_ca_file_without_certificates_is_refused(self):
        empty = self.dir / 'empty.pem'
        empty.write_text('not a certificate\n')
        result, _ = self.render('--client-ca', empty)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
