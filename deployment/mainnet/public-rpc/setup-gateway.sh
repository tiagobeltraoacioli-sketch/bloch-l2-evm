#!/bin/bash
# Install / remove the Bloch L2 public RPC gateway on one host (run as root by
# the owner; nothing here is run by automation).
#
#   setup-gateway.sh peer-cert                 create this host's peer mTLS key pair, print its certificate
#   setup-gateway.sh plan                      check prerequisites and render into a staging dir
#   setup-gateway.sh apply                     install, nginx -t, reload nginx, open the firewall
#   setup-gateway.sh rollback                  remove the gateway and its firewall rules, reload nginx
#
# Env (plan/apply): ROLE (sequencer|replica), NAME (shown by /health),
#   PEER (the other host's IP:18956), PEER_ALLOW (the other host's IP),
#   EXTRA (more render.py flags, optional; a later --backend-conns overrides the default).
# Production defaults: CORS open to any origin; --backend-conns 400, which needs settled RPC v2.1
# (1,024 connections) and must be lowered to 48 for an older binary.
# Files the owner places first (see README.md):
#   /etc/ssl/bloch-l2rpc/origin.pem, origin.key   Cloudflare Origin CA certificate for l2rpc.blochl1.com
#   /etc/ssl/bloch-l2rpc/aop-client-ca.pem         the owner's OWN per-hostname Authenticated Origin Pulls CA
#                                                  (certificate only; README.md "Authenticated Origin Pulls").
#                                                  render.py refuses Cloudflare's shared AOP CA.
#   /etc/nginx/bloch-l2rpc/peer/peer.crt           the OTHER host's peer certificate (from its peer-cert)
# The outbound peer hop is a unix socket in /run/bloch-l2rpc (0750 root:$NGINX_GROUP, recreated at
# boot by /etc/tmpfiles.d/bloch-l2rpc.conf, written by apply): only root and the nginx workers can
# use this host's peer certificate. Run no untrusted local user on either host (README.md).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
DEST=/etc/nginx/bloch-l2rpc
PEERDIR=$DEST/peer
INCLUDE=/etc/nginx/conf.d/bloch-l2rpc.conf
SSL=/etc/ssl/bloch-l2rpc
PEER_PORT=18956
HOP=/run/bloch-l2rpc
TMPFILES=/etc/tmpfiles.d/bloch-l2rpc.conf
NGINX_GROUP=${NGINX_GROUP:-www-data}

need_root() { [ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }; }

render_to() {
  : "${ROLE:?set ROLE}" "${NAME:?set NAME}" "${PEER:?set PEER}" "${PEER_ALLOW:?set PEER_ALLOW}"
  # shellcheck disable=SC2086
  python3 "$HERE/render.py" --role "$ROLE" --name "$NAME" --out "$1" --peer "$PEER" --peer-allow "$PEER_ALLOW" \
    --peer-listen "0.0.0.0:$PEER_PORT" --peer-dir "$PEERDIR" --hop-dir "$HOP" --client-ca "$SSL/aop-client-ca.pem" \
    --cors-any --backend-conns 400 ${EXTRA:-}
}

check() {
  local ok=1
  dpkg -s libnginx-mod-http-js >/dev/null 2>&1 || { echo "MISSING: apt-get install libnginx-mod-http-js"; ok=0; }
  getent group "$NGINX_GROUP" >/dev/null || { echo "MISSING: group $NGINX_GROUP (the nginx workers' group; set NGINX_GROUP)"; ok=0; }
  grep -qE "^\s*user\s+[a-z_][a-z0-9_-]*(\s+$NGINX_GROUP)?;" /etc/nginx/nginx.conf \
    || echo "NOTE: check that the nginx workers run with group $NGINX_GROUP (user directive in /etc/nginx/nginx.conf)"
  [ -e "$SSL/aop-client-ca.pem" ] || [ ! -e "$SSL/cloudflare-aop-ca.pem" ] \
    || echo "NOTE: $SSL/cloudflare-aop-ca.pem is the shared CA and is no longer used; place your own CA as aop-client-ca.pem"
  for f in "$SSL/origin.pem" "$SSL/origin.key" "$SSL/aop-client-ca.pem" "$PEERDIR/self.crt" "$PEERDIR/self.key" "$PEERDIR/peer.crt"; do
    [ -s "$f" ] || { echo "MISSING: $f"; ok=0; }
  done
  if [ -s "$PEERDIR/self.crt" ] && [ -s "$PEERDIR/peer.crt" ] && cmp -s "$PEERDIR/self.crt" "$PEERDIR/peer.crt"; then
    echo "WRONG: peer.crt is this host's own certificate"; ok=0
  fi
  grep -qE '^\s*worker_processes\s+[0-9]+;' /etc/nginx/nginx.conf || echo "NOTE: worker_processes is not a number in /etc/nginx/nginx.conf (README: use 4)"
  curl -fsS -m 5 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:18955/ \
    | grep -q '"0xab162"' || { echo "MISSING: the settled RPC on 127.0.0.1:18955 does not answer chain 0xab162"; ok=0; }
  [ $ok = 1 ]
}

firewall() {
  local action=$1
  command -v ufw >/dev/null && ufw status | grep -q 'Status: active' || { echo "ufw inactive: restrict 443 to Cloudflare and $PEER_PORT to $PEER_ALLOW in the provider firewall"; return 0; }
  while read -r cidr; do
    [ -n "$cidr" ] || continue
    if [ "$action" = add ]; then ufw allow proto tcp from "$cidr" to any port 443 comment bloch-l2rpc; else ufw delete allow proto tcp from "$cidr" to any port 443 || true; fi
  done < <(cat "$HERE/cloudflare-ips-v4.txt" "$HERE/cloudflare-ips-v6.txt")
  if [ "$action" = add ]; then ufw allow proto tcp from "$PEER_ALLOW" to any port $PEER_PORT comment bloch-l2rpc-peer
  else ufw delete allow proto tcp from "$PEER_ALLOW" to any port $PEER_PORT || true; fi
}

case "${1:-}" in
  peer-cert)
    need_root
    install -d -m 0700 "$PEERDIR"
    if [ ! -s "$PEERDIR/self.key" ]; then
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj /CN=l2rpc-peer \
        -addext subjectAltName=DNS:l2rpc-peer -keyout "$PEERDIR/self.key" -out "$PEERDIR/self.crt" 2>/dev/null
      chmod 0600 "$PEERDIR/self.key"
    fi
    openssl x509 -in "$PEERDIR/self.crt" -noout -fingerprint -sha256
    cat "$PEERDIR/self.crt" ;;
  plan)
    need_root
    check || echo "plan: prerequisites missing (above)"
    T=$(mktemp -d)
    render_to "$T"
    echo "rendered into $T; would install into $DEST and $INCLUDE"
    diff -ru "$DEST" "$T" 2>/dev/null | head -50 || true ;;
  apply)
    need_root
    check
    TS=$(date -u +%Y%m%dT%H%M%SZ)
    [ -f "$DEST/l2rpc-gateway.conf" ] && cp -a "$DEST" "/root/bloch-l2rpc.bak-$TS"
    echo "d $HOP 0750 root $NGINX_GROUP -" > "$TMPFILES"
    systemd-tmpfiles --create "$TMPFILES"
    [ "$(stat -c '%a %U %G' "$HOP")" = "750 root $NGINX_GROUP" ] || { echo "$HOP is not 0750 root:$NGINX_GROUP" >&2; exit 1; }
    render_to "$DEST"
    echo "include $DEST/l2rpc-gateway.conf;" > "$INCLUDE"
    if ! nginx -t; then
      rm -f "$INCLUDE"
      echo "nginx -t failed; include removed, nginx not reloaded" >&2
      exit 1
    fi
    systemctl reload nginx
    firewall add
    sleep 4
    curl -fsS http://127.0.0.1:18958/health; echo ;;
  rollback)
    need_root
    rm -f "$INCLUDE"
    nginx -t && systemctl reload nginx
    rm -f "$TMPFILES"
    : "${PEER_ALLOW:?set PEER_ALLOW}"
    firewall delete
    echo "gateway removed; $DEST (and the peer key) kept" ;;
  *) sed -n 2,25p "$0"; exit 2 ;;
esac
