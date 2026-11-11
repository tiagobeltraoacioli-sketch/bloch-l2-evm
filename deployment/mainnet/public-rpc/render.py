#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the Bloch L2 public RPC gateway (nginx + njs) for one host.

Writes into OUT: l2rpc-gateway.conf (http{} context), l2rpc-proxy.inc,
l2rpc-gateway.js, l2rpc-config.js and, with --standalone, nginx.conf (a full
main config for a private test instance run as an unprivileged user).

Production (Cloudflare in front, two hosts; see README.md):
  render.py --role sequencer --name l2rpc-136 --peer 45.77.142.123:18956 --peer-allow 45.77.142.123 \
            --out /etc/nginx/bloch-l2rpc

The outbound hop to the peer's mTLS listener is a unix socket in --hop-dir, a
directory only root and the nginx workers' group can enter (setup-gateway.sh
creates it, mode 0750): no other local user can use this host's peer
certificate to reach the other host's settled RPC (review 154, G6).
Authenticated Origin Pulls trust the owner's own client CA for this hostname,
never Cloudflare's shared CA (review 154, G8; README.md).
"""
import argparse
import ipaddress
import json
import re
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
OFFICIAL_ORIGINS = [
    'https://blochl1.com',
    'https://www.blochl1.com',
    'https://blochdex.com',
    'https://www.blochdex.com',
    'https://blochbridge.com',
    'https://www.blochbridge.com',
]
CHAIN_ID = 700770
# The probe batch (the same calls as PROBE_BODY in l2rpc-gateway.js, which parses
# the answers by id). The peer is probed through a loopback location that always
# sends exactly this body, so the probe server opens no general path to the peer.
PEER_PROBE_BODY = json.dumps([
    {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []},
    {'jsonrpc': '2.0', 'id': 2, 'method': 'eth_blockNumber', 'params': []},
    {'jsonrpc': '2.0', 'id': 3, 'method': 'eth_getBlockByNumber', 'params': ['finalized', False]},
    {'jsonrpc': '2.0', 'id': 4, 'method': 'bloch_finality', 'params': []},
], separators=(',', ':'))
# Cloudflare's zone-level (shared) Authenticated Origin Pulls CA names this host in
# its subject; every Cloudflare customer's pulls present a certificate under it.
SHARED_AOP_MARKER = b'origin-pull.cloudflare.net'


def hostport(value):
    host, _, port = value.rpartition(':')
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f'expected HOST:PORT, got {value!r}')
    return value


def origin(value):
    if not (value.startswith('https://') or value.startswith('http://')) or value.count('/') != 2 or value.endswith('/'):
        raise argparse.ArgumentTypeError(f'expected a scheme://host[:port] origin, got {value!r}')
    return value


def pem_certificates(path):
    """DER bytes of every certificate in a PEM file."""
    import base64
    text = Path(path).read_text()
    out = []
    for block in re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', text, re.S):
        out.append(base64.b64decode(''.join(block.split())))
    return out


def ranges(paths):
    out = []
    for p in paths:
        for line in Path(p).read_text().split():
            out.append(str(ipaddress.ip_network(line.strip(), strict=True)))
    if not out:
        sys.exit('no edge ranges')
    return out


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument('--role', choices=['sequencer', 'replica'], required=True,
                   help='sequencer: this host runs the settled RPC with --txpool; replica: transactions go to the peer')
    a.add_argument('--name', required=True, help='gateway name shown by /health (no addresses)')
    a.add_argument('--out', required=True)
    a.add_argument('--local-rpc', type=hostport, default='127.0.0.1:18955')
    a.add_argument('--peer', type=hostport, help="the other host's mTLS peer listener HOST:PORT")
    a.add_argument('--peer-allow', help='source address allowed on this host\'s peer listener')
    a.add_argument('--peer-listen', default='0.0.0.0:18956')
    a.add_argument('--hop-dir', default='/run/bloch-l2rpc',
                   help='directory of the unix socket of the outbound peer hop; must be enterable only by root and the '
                        'nginx workers (setup-gateway.sh: 0750 root:www-data)')
    a.add_argument('--peer-out-port', help=argparse.SUPPRESS)
    a.add_argument('--probe-port', type=int, default=18958)
    a.add_argument('--peer-dir', default='/etc/nginx/bloch-l2rpc/peer',
                   help='self.crt, self.key and peer.crt (the other host\'s self.crt)')
    a.add_argument('--server-name', default='l2rpc.blochl1.com')
    a.add_argument('--public-listen', action='append', help='listen spec (default: 443 and [::]:443)')
    a.add_argument('--test-plain-listen', action='append', default=[],
                   help='TESTS ONLY: extra plaintext listen spec on loopback (clients that cannot trust a test certificate)')
    a.add_argument('--tls-cert', default='/etc/ssl/bloch-l2rpc/origin.pem', help='Cloudflare Origin CA certificate')
    a.add_argument('--tls-key', default='/etc/ssl/bloch-l2rpc/origin.key')
    a.add_argument('--client-ca', default='/etc/ssl/bloch-l2rpc/aop-client-ca.pem',
                   help="the owner's own Authenticated Origin Pulls CA (per-hostname AOP; README.md); "
                        "'none' disables client verification (tests only)")
    a.add_argument('--allow-shared-aop-ca', action='store_true',
                   help="accept Cloudflare's shared AOP CA in --client-ca (any Cloudflare zone could then reach the origin)")
    a.add_argument('--edge-ranges', action='append',
                   help='files with the edge (Cloudflare) source ranges (default: the bundled v4 and v6 lists)')
    a.add_argument('--cors-origin', action='append', type=origin, help='allowed browser origin (default: the official frontends)')
    a.add_argument('--cors-any', action='store_true', help='Access-Control-Allow-Origin: * (any website)')
    a.add_argument('--req-rate', type=int, default=20, help='HTTP requests per second per client IP (nginx limit_req)')
    a.add_argument('--req-burst', type=int, default=100)
    a.add_argument('--conn-per-ip', type=int, default=32)
    a.add_argument('--calls-per-minute', type=int, default=1200, help='JSON-RPC calls per minute per client IP (a batch counts each call)')
    a.add_argument('--tx-per-minute', type=int, default=30)
    a.add_argument('--sim-per-ip', type=int, default=2,
                   help='EVM simulations in flight per client (IPv4 address or IPv6 /56); a batch with more runs them this many at a time')
    a.add_argument('--tx-per-ip', type=int, default=1,
                   help='eth_sendRawTransaction admissions in flight per client, counted apart from its simulations; '
                        'above 1 it must be at most half of --tx-reserve (no client may hold the reserve)')
    a.add_argument('--sim-total', type=int, default=8,
                   help='EVM simulations and transaction admissions in flight through this gateway for all clients (each backend also enforces its shared permits)')
    a.add_argument('--tx-reserve', type=int, default=3,
                   help='slots of --sim-total kept for eth_sendRawTransaction: simulations use at most --sim-total minus this')
    a.add_argument('--sim-floor', type=int, default=2,
                   help='slots of --sim-total kept for simulations: transaction admissions use at most --sim-total minus this')
    a.add_argument('--slot-ttl', type=int, default=60,
                   help='seconds one wave of a request may keep its EVM slots at most (renewals stop there); '
                        'above the 40 s a subrequest can last')
    a.add_argument('--slot-grace', type=int, default=20,
                   help='seconds an EVM slot keeps counting after its request last renewed it (a request in flight renews every quarter of this; '
                        'a handler that never comes back, e.g. a killed worker, renews nothing): the time a backend may still work on the call '
                        '(10 s permit wait + 5 s execution)')
    a.add_argument('--backend-conns', type=int, default=48,
                   help='active connections from this gateway to the local settled RPC for reads (sequencer/peer paths get a quarter each)')
    a.add_argument('--max-batch', type=int, default=100, help='calls per batch (ethers v6 batches up to 100)')
    a.add_argument('--sub-answer-max', type=int, default=2 * 1024 * 1024,
                   help='largest backend answer of a split request (njs subrequest), bytes; larger ones get -32005')
    a.add_argument('--max-body', default='512k', help='request body cap (the settled RPC refuses more than 512 KiB)')
    a.add_argument('--max-log-range', type=int, default=2000)
    a.add_argument('--max-lag', type=int, default=0,
                   help='blocks the local backend may trail the peer and still take reads (0: reads go to the freshest backend, ties stay local)')
    a.add_argument('--probe-interval', default='3s')
    a.add_argument('--max-status-age', type=int, default=900,
                   help='seconds: older follower status sends finality reads to the other backend (matches the monitor CRIT)')
    a.add_argument('--log-dir', default='/var/log/nginx')
    a.add_argument('--standalone', action='store_true', help='also write nginx.conf for a private unprivileged test instance')
    a.add_argument('--njs-module', default='modules/ngx_http_js_module.so', help='load_module path for --standalone')
    o = a.parse_args()
    for x in o.test_plain_listen:
        if not x.startswith('127.'):
            a.error('--test-plain-listen is for loopback test instances only')

    if o.peer_out_port is not None:
        a.error('--peer-out-port is gone: the outbound peer hop is a unix socket in --hop-dir (review 154, G6)')
    if o.client_ca != 'none' and Path(o.client_ca).exists():
        certs = pem_certificates(o.client_ca)
        if not certs:
            a.error(f'--client-ca {o.client_ca} holds no PEM certificate')
        if any(SHARED_AOP_MARKER in der for der in certs) and not o.allow_shared_aop_ca:
            a.error(f"--client-ca {o.client_ca} contains Cloudflare's shared AOP CA: any Cloudflare zone could reach this "
                    'origin. Use your own per-hostname AOP CA (README.md), or --allow-shared-aop-ca during a switch-over')
    if o.peer and not o.peer_allow:
        a.error('--peer needs --peer-allow')
    if o.role == 'replica' and not o.peer:
        a.error('a replica needs --peer (transactions go to the sequencer host)')
    out = Path(o.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    hop = Path(o.hop_dir)
    if not hop.is_absolute():
        a.error('--hop-dir must be absolute')
    if o.sim_per_ip < 1 or o.tx_per_ip < 1:
        a.error('--sim-per-ip and --tx-per-ip must be at least 1')
    if not 0 <= o.tx_reserve < o.sim_total:
        a.error('--tx-reserve must be at least 0 and below --sim-total (simulations need a slot)')
    if not 0 <= o.sim_floor <= o.sim_total - o.tx_reserve:
        a.error('--sim-floor must be at least 0 and at most --sim-total minus --tx-reserve')
    if o.sim_floor == o.sim_total:
        a.error('--sim-floor must be below --sim-total (transactions need a slot)')
    if o.sim_per_ip > o.sim_total - o.tx_reserve:
        a.error(f'--sim-per-ip {o.sim_per_ip} is above the {o.sim_total - o.tx_reserve} slots simulations can use '
                '(--sim-total minus --tx-reserve): such a wave could never run')
    if o.tx_per_ip > o.sim_total - o.sim_floor:
        a.error('--tx-per-ip is above the slots transaction admissions can use (--sim-total minus --sim-floor)')
    if o.tx_per_ip > 1 and 2 * o.tx_per_ip > o.tx_reserve:
        a.error(f'--tx-per-ip {o.tx_per_ip} is more than half of --tx-reserve {o.tx_reserve}: one client could hold '
                'the slots kept for everyone\'s transactions. Raise --tx-reserve or lower --tx-per-ip')
    if not 5 <= o.slot_grace <= o.slot_ttl:
        a.error('--slot-grace must be between 5 seconds and --slot-ttl')
    if not 45 <= o.slot_ttl <= 600:
        a.error('--slot-ttl must be between 45 and 600 seconds (a subrequest can last 40 s)')
    if not 65536 <= o.sub_answer_max <= 16 * 1024 * 1024:
        a.error('--sub-answer-max must be between 64 KiB and 16 MiB')
    peer_out = f'unix:{hop}/peer-out.sock'
    local = o.local_rpc
    seq = local if o.role == 'sequencer' else peer_out
    other = (peer_out if o.role == 'sequencer' else local) if o.peer else None

    edge = ranges(o.edge_ranges or [HERE / 'cloudflare-ips-v4.txt', HERE / 'cloudflare-ips-v6.txt'])
    if o.cors_any:
        cors = '    "~." "*";'
    else:
        cors = '\n'.join(f'    "{x}" "{x}";' for x in (o.cors_origin or OFFICIAL_ORIGINS))
    listens = o.public_listen or ['443', '[::]:443']
    tls = [f'    ssl_certificate {o.tls_cert};', f'    ssl_certificate_key {o.tls_key};',
           '    ssl_protocols TLSv1.2 TLSv1.3;', '    ssl_session_cache shared:l2rpc_tls:10m;', '    ssl_session_timeout 1h;']
    if o.client_ca != 'none':
        # The owner's own AOP CA signs one client certificate, the one Cloudflare presents
        # for this hostname: a chain longer than CA -> leaf is not expected.
        tls += [f'    ssl_client_certificate {o.client_ca};', '    ssl_verify_client on;', '    ssl_verify_depth 1;']

    peer_servers = ''
    if o.peer:
        peer_servers = f'''
# ----------------------------------- peer listener (the other gateway, mTLS)
upstream l2_peer_in {{
    zone l2_peer_in 64k;
    server {local} max_conns={o.backend_conns // 4};
    keepalive 2;
    keepalive_timeout 20s;
}}
server {{
    listen {o.peer_listen} ssl;
    server_name l2rpc-peer;
    server_tokens off;
    ssl_certificate {o.peer_dir}/self.crt;
    ssl_certificate_key {o.peer_dir}/self.key;
    ssl_client_certificate {o.peer_dir}/peer.crt;
    ssl_verify_client on;
    ssl_verify_depth 1;
    ssl_protocols TLSv1.3;
    access_log {o.log_dir}/l2rpc-peer-access.log l2rpc buffer=64k flush=5s;
    allow {o.peer_allow};
    deny all;
    client_max_body_size 640k;
    client_body_buffer_size 640k;
    location = / {{
        limit_except POST {{ deny all; }}
        proxy_pass http://l2_peer_in/;
        include {out}/l2rpc-proxy.inc;
        proxy_read_timeout 30s;
    }}
    location / {{
        return 404;
    }}
}}

# ------------------------- outbound hop to the peer (unix socket -> mTLS)
# Only root and the nginx workers can enter {hop}, so no other local user can
# send requests to the other host with this host's peer certificate (G6).
upstream l2_peer_tls {{
    server {o.peer};
    keepalive 4;
    keepalive_timeout 20s;
}}
server {{
    listen {peer_out};
    access_log off;
    client_max_body_size 640k;
    client_body_buffer_size 640k;
    location = / {{
        proxy_pass https://l2_peer_tls/;
        include {out}/l2rpc-proxy.inc;
        proxy_read_timeout 30s;
        proxy_ssl_certificate {o.peer_dir}/self.crt;
        proxy_ssl_certificate_key {o.peer_dir}/self.key;
        proxy_ssl_trusted_certificate {o.peer_dir}/peer.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 1;
        proxy_ssl_name l2rpc-peer;
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.3;
        proxy_ssl_session_reuse on;
    }}
}}
'''

    values = {
        'NAME': o.name,
        'ROLE': o.role,
        'JS_DIR': str(out),
        'CONF_DIR': str(out),
        'LOG_DIR': o.log_dir,
        'REAL_IP_FROM': '\n'.join(f'    set_real_ip_from {r};' for r in edge),
        'EDGE_GEO': '\n'.join(f'    {r} 1;' for r in edge),
        'CORS_MAP': cors,
        'REQ_RATE': str(o.req_rate),
        'REQ_BURST': str(o.req_burst),
        'CONN_PER_IP': str(o.conn_per_ip),
        'MAX_BODY': o.max_body,
        'LOCAL_RPC': local,
        'PEER_BACKUP': f'    server {peer_out} max_conns={o.backend_conns} backup;' if o.peer else '',
        'PEER_PRIMARY': f'    server {peer_out} max_conns={o.backend_conns} max_fails=1 fail_timeout=5s;' if o.peer else '',
        'SEQ_ADDR': seq,
        'SEQREAD_BACKUP': f'    server {other} max_conns={o.backend_conns // 4} backup;' if other else '',
        'BC': str(o.backend_conns),
        'BCQ': str(o.backend_conns // 4),
        'SERVER_NAME': o.server_name,
        'PUBLIC_LISTEN': '\n'.join([f'    listen {x} ssl http2;' for x in listens] + [f'    listen {x};' for x in o.test_plain_listen]),
        'PUBLIC_TLS': '\n'.join(tls),
        'PROBE_PORT': str(o.probe_port),
        'HOP_DIR': str(hop),
        'SLOT_ZONE_TIMEOUT': str(2 * o.slot_ttl),
        'SUB_MAX': str(o.sub_answer_max),
        'SUB_BUF': str(o.sub_answer_max + 65536),
        'PROBE_INTERVAL': o.probe_interval,
        'PEER_SERVERS': peer_servers,
        'PEER_PROBE': f'''    # The peer probe: always this fixed read-only batch, whatever the local caller sends.
    location = /_peer_probe {{
        allow 127.0.0.1;
        deny all;
        proxy_pass http://{peer_out}:/;
        include {out}/l2rpc-proxy.inc;
        proxy_set_body '{PEER_PROBE_BODY}';
        proxy_read_timeout 5s;
    }}''' if o.peer else '',
    }
    conf = (HERE / 'l2rpc-gateway.conf.in').read_text()
    for k, v in values.items():
        conf = conf.replace(f'@{k}@', v)
    leftovers = sorted(set(re.findall(r'@[A-Z_]+@', conf)))
    if leftovers:
        sys.exit(f'unrendered placeholders: {leftovers}')
    (out / 'l2rpc-gateway.conf').write_text(conf)
    shutil.copyfile(HERE / 'l2rpc-proxy.inc', out / 'l2rpc-proxy.inc')
    shutil.copyfile(HERE / 'l2rpc-gateway.js', out / 'l2rpc-gateway.js')
    config = {
        'name': o.name,
        'role': o.role,
        'chainId': CHAIN_ID,
        'chainIdHex': hex(CHAIN_ID),
        'maxBatch': o.max_batch,
        'callsPerMinute': o.calls_per_minute,
        'txPerMinute': o.tx_per_minute,
        'simPerIp': o.sim_per_ip,
        'simTotal': o.sim_total,
        'txPerIp': o.tx_per_ip,
        'txReserve': o.tx_reserve,
        'simFloor': o.sim_floor,
        'slotTtlMs': o.slot_ttl * 1000,
        'slotGraceMs': o.slot_grace * 1000,
        'subAnswerMaxBytes': o.sub_answer_max,
        'maxLogBlockRange': o.max_log_range,
        'maxLogAddresses': 256,
        'maxLagBlocks': o.max_lag,
        'stateMaxAgeMs': 15000,
        'maxStatusAgeS': o.max_status_age,
        'localProbeUrl': f'http://{local}/',
        'peerProbeUrl': f'http://127.0.0.1:{o.probe_port}/_peer_probe' if o.peer else None,
    }
    (out / 'l2rpc-config.js').write_text('// Rendered by render.py.\nexport default ' + json.dumps(config, indent=2) + ';\n')
    if o.standalone:
        (out / 'logs').mkdir(exist_ok=True)
        (out / 'nginx.conf').write_text(f'''load_module {o.njs_module};
pid {out}/nginx.pid;
error_log {o.log_dir}/nginx-error.log warn;
worker_processes 4;
worker_rlimit_nofile 16384;
events {{ worker_connections 4096; }}
http {{
    client_body_temp_path {out}/tmp/body;
    proxy_temp_path {out}/tmp/proxy;
    fastcgi_temp_path {out}/tmp/fastcgi;
    uwsgi_temp_path {out}/tmp/uwsgi;
    scgi_temp_path {out}/tmp/scgi;
    access_log off;
    include {out}/l2rpc-gateway.conf;
}}
''')
        (out / 'tmp').mkdir(exist_ok=True)
    print(f'rendered {out}/l2rpc-gateway.conf ({o.role}, peer {o.peer or "none"}, '
          f'{"CORS any" if o.cors_any else "CORS " + str(len(o.cors_origin or OFFICIAL_ORIGINS)) + " origins"}, '
          f'{len(edge)} edge ranges)')


if __name__ == '__main__':
    main()
