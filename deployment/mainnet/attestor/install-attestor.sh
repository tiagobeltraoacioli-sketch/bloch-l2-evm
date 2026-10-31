#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install (do NOT start), inspect or roll back the Bloch L2 MAINNET withdrawal attestor agent on ONE
# operator host. Run as root. Never prints a secret; the transport passphrase is typed at the tty.
#
#   sudo ./install-attestor.sh install --artifacts DIR --index I --bundle attestor-I.sealed \
#        --l1-rpc-url http://HOST:8080 [--rpc http://H:8080 --rpc ... (3; default: the 3 public RPCs)] \
#        [--publish-url https://drop.example/attest --publish-token-file FILE] \
#        [--publish-command '["rsync","-a","{file}","drop@host:/srv/attest/{relpath}"]'] \
#        [--feed-port N [--feed-bind ADDR]] \
#        [--alert-command '["/usr/local/bin/notify-attestor","{event}"]'] [--dry-run]
#        [--prefix DIR [--rehearsal-set attestors.set]]
#   sudo ./install-attestor.sh rollback [--purge-key]
#   sudo ./install-attestor.sh status
#
# DIR holds: bloch-pos (built from codex/l2-attestor-keystore-20261019: l2-claim seal-key/key-check/
# attest --sealed), bloch-l2-native-follower and bloch-l2-produce-dev (the RC pinned build,
# build-release.sh), mainnet.manifest, carryover.tsv.gz + carryover.tsv.gz.sha256 (bloch-sis-pow
# 78b7343a), and SHA256SUMS over the three binaries.
#
# The key: the operator's transport bundle (attestor-I.sealed from make-operator-bundles.sh) is
# opened ONCE with the transport passphrase (typed here) and re-sealed under a fresh random host
# passphrase in /etc/bloch-l2-attestor/keystore.passphrase (root, 0400), handed to the agent via
# systemd LoadCredential. The host never holds a plaintext key file. Keep the transport bundle
# offline as the backup; remove the copy you brought to this host after install.
#
# --feed-port N: the default way to publish. Prepares bloch-l2-attestor-feed.service (not enabled, not
# started), a read-only endpoint serving only the agent's outbox partials. It holds no credential, and
# the agent keeps its no-listener unit. The push options above stay for operators with no inbound port.
#
# --prefix DIR (rehearsal/staging): install every file under DIR instead of /opt, /etc and
# /var/lib, as the invoking user, without useradd, chown or systemctl (units are written to
# DIR/systemd and never loaded). --rehearsal-set FILE (only with --prefix) accepts a THROWAWAY
# attestor set instead of the pinned one, to rehearse the owner flow end to end without real keys.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OPT=/opt/bloch/l2-attestor ETC=/etc/bloch-l2-attestor STATE=/var/lib/bloch-l2-attestor
FSTATE=/var/lib/bloch-l2-attestor-follower UNITS=/etc/systemd/system
USER_AGENT=bloch-l2-attestor USER_FOLLOWER=bloch-l2-attestor-follower
MANIFEST_SHA256=7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
SET_FILE_SHA256=9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0
SET_HASH=1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b
DEFAULT_RPCS=(http://80.240.16.185:8080 http://199.247.22.8:8080 http://45.77.67.251:8080)

die() { echo "install-attestor: $*" >&2; exit 1; }
DRY=0
run() { echo "+ $*"; [ $DRY = 1 ] || "$@"; }
host_of() { [[ $1 =~ ^https?://([A-Za-z0-9.-]+)(:[0-9]+)?(/.*)?$ ]] || die "bad URL $1"; echo "${BASH_REMATCH[1]}"; }
ip_of() { getent ahostsv4 "$1" | awk 'NR==1{print $1}'; }

cmd_install() {
  local ART= INDEX= BUNDLE= L1= PUB_URL= PUB_TOKEN= PUB_CMD= ALERT= RPCS=() PREFIX= RSET= FEED_PORT= FEED_BIND=0.0.0.0
  while [ $# -gt 0 ]; do
    case $1 in
      --artifacts) ART=$2; shift 2;; --index) INDEX=$2; shift 2;; --bundle) BUNDLE=$2; shift 2;;
      --l1-rpc-url) L1=$2; shift 2;; --rpc) RPCS+=("$2"); shift 2;;
      --publish-url) PUB_URL=$2; shift 2;; --publish-token-file) PUB_TOKEN=$2; shift 2;;
      --publish-command) PUB_CMD=$2; shift 2;; --alert-command) ALERT=$2; shift 2;;
      --feed-port) FEED_PORT=$2; shift 2;; --feed-bind) FEED_BIND=$2; shift 2;;
      --dry-run) DRY=1; shift;; --prefix) PREFIX=$2; shift 2;; --rehearsal-set) RSET=$2; shift 2;;
      *) die "unknown option $1";;
    esac
  done
  [ -z "$FEED_PORT" ] || [[ $FEED_PORT =~ ^[0-9]{2,5}$ ]] || die "--feed-port must be a port number"
  [[ $FEED_BIND =~ ^[0-9A-Fa-f:.]+$ ]] || die "--feed-bind must be an IP address"
  [ -z "$RSET" ] || [ -n "$PREFIX" ] || die "--rehearsal-set needs --prefix (never on a real install)"
  local SETF="$HERE/public/attestors.set"
  if [ -n "$PREFIX" ]; then
    mkdir -p "$PREFIX"; PREFIX=$(cd "$PREFIX" && pwd)
    [ "$PREFIX" != / ] || die "--prefix / is a real install; drop --prefix"
    OPT=$PREFIX$OPT ETC=$PREFIX$ETC STATE=$PREFIX$STATE FSTATE=$PREFIX$FSTATE UNITS=$PREFIX/systemd
    echo "REHEARSAL: installing under $PREFIX as $(id -un); no users, no chown, no systemctl" >&2
  fi
  if [ -n "$RSET" ]; then
    SETF=$(cd "$(dirname "$RSET")" && pwd)/$(basename "$RSET")
    SET_FILE_SHA256=$(sha256sum "$SETF" | cut -d' ' -f1)
    SET_HASH=$(python3 -I -c 'import hashlib,sys
l=[x.strip() for x in open(sys.argv[1]) if x.strip()]; k=[bytes.fromhex(x) for x in l[1:]]
print(hashlib.sha3_256(b"BLOCH:L2:ATTESTOR-SET:1"+bytes([int(l[0]),len(k)])+b"".join(k)).hexdigest())' "$SETF")
    echo "REHEARSAL: THROWAWAY attestor set $SET_HASH (not the pinned 1c06adbb…)" >&2
  fi
  [ -n "$ART" ] && [ -n "$INDEX" ] && [ -n "$BUNDLE" ] && [ -n "$L1" ] || { sed -n 3,12p "$0"; exit 2; }
  [[ $INDEX =~ ^[0-4]$ ]] || die "--index must be 0..4"
  [ ${#RPCS[@]} -gt 0 ] || RPCS=("${DEFAULT_RPCS[@]}")
  [ ${#RPCS[@]} -eq 3 ] || die "give exactly three --rpc URLs (quorum 2-of-3)"
  [[ $L1 =~ ^http://[A-Za-z0-9.-]+:[0-9]+/?$ ]] || die "--l1-rpc-url must be http://HOST:PORT"
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$PREFIX" ] || die "run as root"
  [ -n "$PUB_URL$PUB_CMD$FEED_PORT" ] || echo "WARNING: no --feed-port/--publish-url/--publish-command: partials stay in $STATE/outbox only" >&2
  [ -z "$PUB_TOKEN" ] || [ -n "$PUB_URL" ] || die "--publish-token-file goes with --publish-url"
  for f in "$UNITS/bloch-l2-attestor.service" "$UNITS/bloch-l2-attestor-follower.service" "$OPT/bloch-pos" "$ETC/attestor.sealed"; do
    [ ! -e "$f" ] || die "$f exists; refusing to overwrite (rollback first)"
  done
  local py; py=$(command -v python3) || die "python3 is required"
  [ "$py" = /usr/bin/python3 ] || echo "note: the unit runs /usr/bin/python3" >&2

  # 1. Artifacts and public inputs, by hash.
  (cd "$ART" && sha256sum -c --strict SHA256SUMS) || die "binary hashes do not match SHA256SUMS"
  for b in bloch-pos bloch-l2-native-follower bloch-l2-produce-dev; do
    grep -q "  $b\$" "$ART/SHA256SUMS" || die "SHA256SUMS does not cover $b"
  done
  echo "$MANIFEST_SHA256  $ART/mainnet.manifest" | sha256sum -c --strict || die "mainnet.manifest is not Genesis-4"
  echo "$SET_FILE_SHA256  $SETF" | sha256sum -c --strict || die "attestors.set is not the pinned set"
  echo "$(cut -d' ' -f1 "$ART/carryover.tsv.gz.sha256")  $ART/carryover.tsv.gz" | sha256sum -c --strict \
    || die "carryover.tsv.gz does not match carryover.tsv.gz.sha256"
  "$ART/bloch-pos" l2-claim --help | grep -q 'seal-key' || die "$ART/bloch-pos has no l2-claim seal-key (build the attestor-keystore branch)"
  local info; info=$("$ART/bloch-pos" l2-claim key-info --sealed "$BUNDLE") || die "$BUNDLE is not a sealed attestor key"
  grep -qx "signer_index $INDEX" <<<"$info" || die "$BUNDLE is not attestor $INDEX"
  grep -qx "set_hash $SET_HASH" <<<"$info" || die "$BUNDLE belongs to another attestor set"

  # 2. Users and directories.
  local own_agent=(-o $USER_AGENT -g $USER_AGENT) own_follower=(-o $USER_FOLLOWER -g $USER_FOLLOWER)
  if [ -n "$PREFIX" ]; then own_agent=() own_follower=()
  else
    for u in $USER_AGENT $USER_FOLLOWER; do
      id "$u" >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
    done
  fi
  # $ETC stays traversable (the follower reads public/); the secrets are restricted per file.
  run install -d -m 0755 "$OPT" "$ETC" "$ETC/public"
  run install -d -m 0700 "${own_agent[@]}" "$STATE" "$STATE/outbox"
  run install -d -m 0755 "${own_follower[@]}" "$FSTATE"
  run install -m 0755 "$ART/bloch-pos" "$ART/bloch-l2-native-follower" "$ART/bloch-l2-produce-dev" "$OPT/"
  run install -m 0644 "$HERE/attestor_agent.py" "$HERE/attestor_lib.py" "$HERE/aggregate_attestation.py" "$HERE/sigfeed.py" "$OPT/"
  run install -m 0644 "$ART/mainnet.manifest" "$ETC/public/"
  run install -m 0644 "$SETF" "$ETC/public/attestors.set"
  if [ $DRY = 1 ]; then echo "+ gunzip carryover.tsv.gz > $ETC/public/carryover.tsv"
  else gunzip -c "$ART/carryover.tsv.gz" > "$ETC/public/carryover.tsv"; chmod 0644 "$ETC/public/carryover.tsv"; fi

  # 3. The key: re-seal the transport bundle under a fresh random host passphrase.
  if [ $DRY = 1 ]; then echo "+ re-seal $BUNDLE -> $ETC/attestor.sealed under a new random $ETC/keystore.passphrase (0400 root)"
  else
    (umask 077; head -c 48 /dev/urandom | base64 | tr -d '\n=+/' > "$ETC/keystore.passphrase")
    chmod 0400 "$ETC/keystore.passphrase"
    echo "Type the TRANSPORT passphrase of attestor $INDEX's bundle (the one you received out of band):"
    "$OPT/bloch-pos" l2-claim seal-key --sealed "$BUNDLE" --attestors "$ETC/public/attestors.set" --signer-index "$INDEX" \
      --passphrase-file "$ETC/keystore.passphrase" --out "$ETC/attestor.sealed" \
      || { shred -u "$ETC/keystore.passphrase"; die "re-seal failed (nothing installed for the key)"; }
    [ -n "$PREFIX" ] || chown root:$USER_AGENT "$ETC/attestor.sealed"; chmod 0440 "$ETC/attestor.sealed"
    "$OPT/bloch-pos" l2-claim key-check --sealed "$ETC/attestor.sealed" --attestors "$ETC/public/attestors.set" \
      --signer-index "$INDEX" --passphrase-file "$ETC/keystore.passphrase" || die "host key check failed"
  fi
  if [ -n "$PUB_TOKEN" ]; then run install -m 0400 -o root -g root "$PUB_TOKEN" "$ETC/publish-token"; fi
  [ -e "$ETC/approvals.txt" ] || run install -m 0644 /dev/null "$ETC/approvals.txt"

  # 4. Config (binary pins from SHA256SUMS).
  local sum_pos sum_produce publish='[]' alert=null
  sum_pos=$(awk '$2=="bloch-pos"{print $1}' "$ART/SHA256SUMS")
  sum_produce=$(awk '$2=="bloch-l2-produce-dev"{print $1}' "$ART/SHA256SUMS")
  [ -z "$PUB_URL" ] || publish=$(python3 -c 'import json,sys; t={"kind":"http_put","url":sys.argv[1]}
if sys.argv[2]: t["token_credential"]="publish-token"
print(json.dumps([t]))' "$PUB_URL" "$PUB_TOKEN")
  [ -z "$PUB_CMD" ] || publish=$(python3 -c 'import json,sys; p=json.loads(sys.argv[1]); c=json.loads(sys.argv[2])
assert isinstance(c,list) and all(isinstance(a,str) for a in c), "argv list"
print(json.dumps(p+[{"kind":"command","argv":c}]))' "$publish" "$PUB_CMD")
  [ -z "$ALERT" ] || alert=$ALERT
  local config
  config=$(python3 - "$INDEX" "$sum_pos" "$sum_produce" "$publish" "$alert" "$OPT" "$ETC" "$STATE" "$FSTATE" "${RPCS[@]}" <<'PY'
import json, sys
index, pos, produce, publish, alert, opt, etc, state, fstate, *rpcs = sys.argv[1:]
print(json.dumps({
    'signer_index': int(index), 'bloch_pos': f'{opt}/bloch-pos', 'bloch_pos_sha256': pos,
    'produce': f'{opt}/bloch-l2-produce-dev', 'produce_sha256': produce,
    'manifest': f'{etc}/public/mainnet.manifest', 'attestors': f'{etc}/public/attestors.set',
    'sealed_key': f'{etc}/attestor.sealed', 'passphrase_credential': 'passphrase',
    'follower_status': f'{fstate}/status.json',
    'follower_native': f'{fstate}/native', 'state_dir': state,
    'rpc_urls': rpcs, 'rpc_quorum': 2, 'poll_seconds': 60, 'daily_cap_sat': 1000 * 10**8, 'max_single_sat': 1000 * 10**8,
    'pause_file': f'{etc}/PAUSE', 'approvals_file': f'{etc}/approvals.txt',
    'publish': json.loads(publish), 'alert_command': json.loads(alert)}, indent=1))
PY
)
  if [ $DRY = 1 ]; then echo "+ write $ETC/config.json:"; echo "$config"
  else (umask 027; echo "$config" > "$ETC/config.json"); [ -n "$PREFIX" ] || chown root:$USER_AGENT "$ETC/config.json"; fi

  # 5. Units (not enabled, not started) and the network allow-list.
  local allow_agent="localhost" h ip
  for u in "${RPCS[@]}" ${PUB_URL:+"$PUB_URL"}; do
    h=$(host_of "$u"); ip=$(ip_of "$h"); [ -n "$ip" ] || die "cannot resolve $h"; allow_agent+=" $ip"
  done
  [ -z "$PUB_URL" ] || echo "note: the drop host is pinned by IP ($PUB_URL); re-run the drop-in if its address changes" >&2
  h=$(host_of "$L1"); ip=$(ip_of "$h"); [ -n "$ip" ] || die "cannot resolve $h"
  if [ $DRY = 1 ]; then echo "+ units, follower.env ($L1), drop-ins: agent IPAddressAllow=$allow_agent; follower IPAddressAllow=localhost $ip"
  else
    printf 'BLOCH_L1_RPC_URL=%s\n' "$L1" > "$ETC/follower.env"; chmod 0644 "$ETC/follower.env"
    [ -z "$PREFIX" ] || mkdir -p "$UNITS"
    install -m 0644 "$HERE/systemd/bloch-l2-attestor.service" "$HERE/systemd/bloch-l2-attestor-follower.service" "$UNITS/"
    install -d "$UNITS/bloch-l2-attestor.service.d" "$UNITS/bloch-l2-attestor-follower.service.d"
    printf '[Service]\nIPAddressAllow=%s\n' "$allow_agent" > "$UNITS/bloch-l2-attestor.service.d/network.conf"
    [ -z "$PUB_TOKEN" ] || printf 'LoadCredential=publish-token:%s/publish-token\n' "$ETC" >> "$UNITS/bloch-l2-attestor.service.d/network.conf"
    printf '[Service]\nIPAddressAllow=localhost %s\n' "$ip" > "$UNITS/bloch-l2-attestor-follower.service.d/l1-rpc.conf"
    if [ -n "$FEED_PORT" ]; then
      install -m 0644 "$HERE/systemd/bloch-l2-attestor-feed.service" "$UNITS/"
      printf 'SIGFEED_BIND=%s\nSIGFEED_PORT=%s\n' "$FEED_BIND" "$FEED_PORT" > "$ETC/feed.env"; chmod 0644 "$ETC/feed.env"
    fi
    [ -n "$PREFIX" ] || systemctl daemon-reload
  fi
  if [ -n "$PREFIX" ]; then
    cat <<MSG
REHEARSAL install of attestor $INDEX under $PREFIX (units in $UNITS, not loaded). Check the host key:
  $OPT/bloch-pos l2-claim key-check --sealed $ETC/attestor.sealed \\
       --attestors $ETC/public/attestors.set --signer-index $INDEX --passphrase-file $ETC/keystore.passphrase
MSG
    return 0
  fi
  cat <<MSG
Installed attestor $INDEX, NOT started. Next (each step is read-only until the last):
  sudo systemctl enable --now bloch-l2-attestor-follower      # first replay of ~155k L1 blocks: 30-60 min
  journalctl -fu bloch-l2-attestor-follower                    # wait for l2_genesis.finalized=true in $FSTATE/status.json
  sudo systemd-run --pipe --wait -p User=$USER_AGENT -p LoadCredential=passphrase:$ETC/keystore.passphrase \\
       /usr/bin/python3 -I $OPT/attestor_agent.py check --config $ETC/config.json
 ${FEED_PORT:+ sudo systemctl enable --now bloch-l2-attestor-feed                # read-only endpoint on TCP $FEED_PORT
} sudo systemctl enable --now bloch-l2-attestor
  journalctl -fu bloch-l2-attestor -o cat                      # 'started', then 'waiting'/'awaiting-own-finality'/'signed'
Then remove the transport bundle copy from this host ($BUNDLE); its offline backup stays with you.
MSG
}

cmd_rollback() {
  local PURGE=0
  while [ $# -gt 0 ]; do case $1 in --purge-key) PURGE=1; shift;; --dry-run) DRY=1; shift;; *) die "unknown option $1";; esac; done
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || die "run as root"
  for unit in bloch-l2-attestor-feed bloch-l2-attestor bloch-l2-attestor-follower; do
    run systemctl disable --now "$unit.service" || true
    run rm -rf "$UNITS/$unit.service" "$UNITS/$unit.service.d"
  done
  run systemctl daemon-reload
  if [ $PURGE = 1 ]; then
    for f in "$ETC/attestor.sealed" "$ETC/keystore.passphrase" "$ETC/publish-token"; do
      [ ! -e "$f" ] || run shred -u "$f"
    done
    echo "Host key removed. The offline transport bundle is now the only copy of attestor's key on your side."
  fi
  echo "Rolled back: units removed. Kept: $OPT, $ETC (config$( [ $PURGE = 1 ] || echo ', sealed key, passphrase')), $STATE (state, outbox), $FSTATE."
  echo "Signatures already published stay valid (they sign finalized, rebuilt roots only)."
}

cmd_status() {
  systemctl --no-pager status bloch-l2-attestor bloch-l2-attestor-follower bloch-l2-attestor-feed 2>/dev/null | sed -n '1,12p' || true
  [ -e "$ETC/PAUSE" ] && echo "PAUSED ($ETC/PAUSE exists)"
  [ -e "$STATE/state.json" ] && python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))
print(json.dumps({k: len(v) for k, v in s.items()}))' "$STATE/state.json"
  journalctl -u bloch-l2-attestor -o cat -n 5 --no-pager 2>/dev/null || true
}

case ${1:-} in
  install) shift; cmd_install "$@";;
  rollback) shift; cmd_rollback "$@";;
  status) cmd_status;;
  *) sed -n 3,12p "$0"; exit 2;;
esac
