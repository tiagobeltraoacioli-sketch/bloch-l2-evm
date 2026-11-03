#!/bin/bash
# Private two-gateway test rig (unprivileged, loopback only).
#
#   pair.sh render|start|stop|reload
#
# Gateway A (role sequencer) fronts the settled RPC on $A_RPC, gateway B (role
# replica) the one on $B_RPC; each uses the other as peer over the same mTLS
# hop production uses. The "edge" is 127.0.0.1, so a test client picks its
# client address with the CF-Connecting-IP header. Public TLS uses a throwaway
# self-signed certificate; Cloudflare's Authenticated Origin Pulls CA is
# replaced by a throwaway test CA when CLIENT_CA=1. Plaintext loopback listeners
# (19673/19674) exist for clients that cannot trust a test certificate (forge).
#
# Env: WORK (state dir), NJS_SO (ngx_http_js_module.so matching /usr/sbin/nginx),
#      A_RPC / B_RPC (default 127.0.0.1:19661 / 127.0.0.1:19662), CLIENT_CA (0|1),
#      EXTRA (extra render.py flags, e.g. rate limits).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:?set WORK}
NJS_SO=${NJS_SO:?set NJS_SO}
A_RPC=${A_RPC:-127.0.0.1:19661}
B_RPC=${B_RPC:-127.0.0.1:19662}
CLIENT_CA=${CLIENT_CA:-0}
EXTRA=${EXTRA:-}

certs() {
  mkdir -p "$WORK/certs" "$WORK/a/peer" "$WORK/b/peer"
  [ -f "$WORK/certs/origin.pem" ] && return 0
  cd "$WORK/certs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=l2rpc.test \
    -addext subjectAltName=DNS:l2rpc.test -keyout origin.key -out origin.pem 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=test-edge-ca \
    -keyout edge-ca.key -out edge-ca.pem 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=test-edge \
    -keyout edge.key -out edge.csr 2>/dev/null
  openssl x509 -req -in edge.csr -CA edge-ca.pem -CAkey edge-ca.key -CAcreateserial -days 30 -out edge.pem 2>/dev/null
  for x in a b; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=l2rpc-peer \
      -addext subjectAltName=DNS:l2rpc-peer -keyout "$WORK/$x/peer/self.key" -out "$WORK/$x/peer/self.crt" 2>/dev/null
  done
  cp "$WORK/b/peer/self.crt" "$WORK/a/peer/peer.crt"
  cp "$WORK/a/peer/self.crt" "$WORK/b/peer/peer.crt"
  echo 127.0.0.1/32 > "$WORK/certs/edge-ranges.txt"
}

render_one() {
  local x=$1 role=$2 rpc=$3 pub=$4 plisten=$5 probe=$6 peer=$7 plain=$8
  local ca=none
  install -d -m 0700 "$WORK/$x/hop"
  [ "$CLIENT_CA" = 1 ] && ca="$WORK/certs/edge-ca.pem"
  # shellcheck disable=SC2086
  python3 "$HERE/render.py" --role "$role" --name "test-$x" --out "$WORK/$x/conf" --standalone --njs-module "$NJS_SO" \
    --local-rpc "$rpc" --peer "$peer" --peer-allow 127.0.0.1 --peer-listen "$plisten" --hop-dir "$WORK/$x/hop" \
    --probe-port "$probe" --peer-dir "$WORK/$x/peer" --server-name l2rpc.test --public-listen "$pub" --test-plain-listen "$plain" \
    --tls-cert "$WORK/certs/origin.pem" --tls-key "$WORK/certs/origin.key" --client-ca "$ca" \
    --edge-ranges "$WORK/certs/edge-ranges.txt" --log-dir "$WORK/$x/conf/logs" --probe-interval 2s $EXTRA
  nginx -t -q -p "$WORK/$x/conf" -c "$WORK/$x/conf/nginx.conf"
}

render() {
  certs
  render_one a sequencer "$A_RPC" 127.0.0.1:19671 127.0.0.1:19681 19601 127.0.0.1:19682 127.0.0.1:19673
  render_one b replica "$B_RPC" 127.0.0.1:19672 127.0.0.1:19682 19602 127.0.0.1:19681 127.0.0.1:19674
}

case "${1:-}" in
  render) render ;;
  start)
    render
    for x in a b; do nginx -p "$WORK/$x/conf" -c "$WORK/$x/conf/nginx.conf"; done
    echo "A https://127.0.0.1:19671 (plain 19673)  B https://127.0.0.1:19672 (plain 19674)" ;;
  reload)
    render
    for x in a b; do nginx -p "$WORK/$x/conf" -c "$WORK/$x/conf/nginx.conf" -s reload; done ;;
  stop)
    for x in a b; do
      [ -f "$WORK/$x/conf/nginx.pid" ] && nginx -p "$WORK/$x/conf" -c "$WORK/$x/conf/nginx.conf" -s quit || true
    done ;;
  *) echo "usage: pair.sh render|start|stop|reload" >&2; exit 2 ;;
esac
