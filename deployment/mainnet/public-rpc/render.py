#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the Bloch L2 public RPC gateway (nginx + njs) for one host.

Writes into OUT: l2rpc-gateway.conf (http{} context), l2rpc-proxy.inc,
l2rpc-gateway.js, l2rpc-config.js and, with --standalone, nginx.conf (a full
main config for a private test instance run as an unprivileged user).

Production (Cloudflare in front, two hosts; see README.md):
  render.py --role sequencer --name l2rpc-136 --peer 45.77.142.123:18956 --peer-allow 45.77.142.123 \
            --out /etc/nginx/bloch-l2rpc
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


def hostport(value):
    host, _, port = value.rpartition(':')
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f'expected HOST:PORT, got {value!r}')
    return value


def origin(value):
    if not (value.startswith('https://') or value.startswith('http://')) or value.count('/') != 2 or value.endswith('/'):
        raise argparse.ArgumentTypeError(f'expected a scheme://host[:port] origin, got {value!r}')
    return value


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
    a.add_argument('--peer-out-port', type=int, default=18957)
    a.add_argument('--probe-port', type=int, default=18958)
    a.add_argument('--peer-dir', default='/etc/nginx/bloch-l2rpc/peer',
                   help='self.crt, self.key and peer.crt (the other host\'s self.crt)')
    a.add_argument('--server-name', default='l2rpc.blochl1.com')
    a.add_argument('--public-listen', action='append', help='listen spec (default: 443 and [::]:443)')
    a.add_argument('--test-plain-listen', action='append', default=[],
                   help='TESTS ONLY: extra plaintext listen spec on loopback (clients that cannot trust a test certificate)')
    a.add_argument('--tls-cert', default='/etc/ssl/bloch-l2rpc/origin.pem', help='Cloudflare Origin CA certificate')
    a.add_argument('--tls-key', default='/etc/ssl/bloch-l2rpc/origin.key')
    a.add_argument('--client-ca', default='/etc/ssl/bloch-l2rpc/cloudflare-aop-ca.pem',
                   help="Cloudflare Authenticated Origin Pulls CA; 'none' disables client verification (tests only)")
    a.add_argument('--edge-ranges', action='append',
                   help='files with the edge (Cloudflare) source ranges (default: the bundled v4 and v6 lists)')
    a.add_argument('--cors-origin', action='append', type=origin, help='allowed browser origin (default: the official frontends)')
    a.add_argument('--cors-any', action='store_true', help='Access-Control-Allow-Origin: * (any website)')
    a.add_argument('--req-rate', type=int, default=20, help='HTTP requests per second per client IP (nginx limit_req)')
    a.add_argument('--req-burst', type=int, default=100)
    a.add_argument('--conn-per-ip', type=int, default=32)
    a.add_argument('--calls-per-minute', type=int, default=1200, help='JSON-RPC calls per minute per client IP (a batch counts each call)')
    a.add_argument('--tx-per-minute', type=int, default=30)
    a.add_argument('--sim-per-ip', type=int, default=16,
                   help='eth_call/eth_estimateGas/eth_createAccessList in flight per client IP (a batch counts each call)')
    a.add_argument('--backend-conns', type=int, default=48,
                   help='active connections from this gateway to the local settled RPC for reads (sequencer/peer paths get a quarter each)')
    a.add_argument('--max-batch', type=int, default=100, help='calls per batch (ethers v6 batches up to 100)')
    a.add_argument('--max-body', default='512k', help='request body cap (the settled RPC refuses more than 512 KiB)')
    a.add_argument('--max-log-range', type=int, default=2000)
    a.add_argument('--max-lag', type=int, default=0,
                   help='blocks the local backend may trail the peer and still take reads (0: reads go to the freshest backend, ties stay local)')
    a.add_argument('--probe-interval', default='3s')
    a.add_argument('--log-dir', default='/var/log/nginx')
    a.add_argument('--standalone', action='store_true', help='also write nginx.conf for a private unprivileged test instance')
    a.add_argument('--njs-module', default='modules/ngx_http_js_module.so', help='load_module path for --standalone')
    o = a.parse_args()
    for x in o.test_plain_listen:
        if not x.startswith('127.'):
            a.error('--test-plain-listen is for loopback test instances only')

    if o.peer and not o.peer_allow:
        a.error('--peer needs --peer-allow')
    if o.role == 'replica' and not o.peer:
        a.error('a replica needs --peer (transactions go to the sequencer host)')
    out = Path(o.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    peer_out = f'127.0.0.1:{o.peer_out_port}'
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
        tls += [f'    ssl_client_certificate {o.client_ca};', '    ssl_verify_client on;']

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

# ------------------------------- outbound hop to the peer (loopback -> mTLS)
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
        'REAL_IP_FROM': '\n'.join(f'set_real_ip_from {r};' for r in edge),
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
        'PROBE_INTERVAL': o.probe_interval,
        'PEER_SERVERS': peer_servers,
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
        'maxLogBlockRange': o.max_log_range,
        'maxLogAddresses': 256,
        'maxLagBlocks': o.max_lag,
        'stateMaxAgeMs': 15000,
        'localProbeUrl': f'http://{local}/',
        'peerProbeUrl': f'http://{peer_out}/' if o.peer else None,
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
