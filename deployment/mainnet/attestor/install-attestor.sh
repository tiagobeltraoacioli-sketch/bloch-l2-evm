#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install (do NOT start), upgrade, inspect or uninstall the Bloch L2 MAINNET withdrawal attestor agent on
# ONE operator host. Run as root. Never prints a secret; the transport passphrase is typed at the tty.
#
#   sudo ./install-attestor.sh upgrade --artifacts DIR [--tag pre-hf123] [--resume] [--no-unpause]
#        [--wait-timeout SEC (7200)] [--advance-timeout SEC (2400)] [--poll SEC (30)]
#   sudo ./install-attestor.sh upgrade-rollback [--tag pre-hf123] [--follower-sha256 HEX] [--resume] [--no-unpause] [timeouts]
#   sudo ./install-attestor.sh install --artifacts DIR --index I --bundle attestor-I.sealed \
#        --l1-rpc-url http://HOST:8080 [--rpc http://H:8080 --rpc ... (3; default: the 3 public RPCs)] \
#        [--publish-url https://drop.example/attest --publish-token-file FILE] \
#        [--publish-command '["rsync","-a","{file}","drop@host:/srv/attest/{relpath}"]'] \
#        [--feed-port N [--feed-bind ADDR]] \
#        [--alert-command '["/usr/local/bin/notify-attestor","{event}"]'] [--dry-run]
#        [--prefix DIR [--rehearsal-set attestors.set [--rehearsal-any-manifest]]]
#   sudo ./install-attestor.sh rollback [--purge-key]      (UNINSTALL: removes the units)
#   sudo ./install-attestor.sh status
#
# upgrade: swap the follower and producer of an installed host for the HF1-3 build (v2 for L1 78d4921c,
# hashes below) and pin BOTH in config.json (`follower`, `follower_sha256`, `produce_sha256`). DIR holds
# bloch-l2-native-follower and bloch-l2-produce-dev (SHA256SUMS optional; if present it must agree).
# The steps: verify the files against the published hashes, PAUSE, stop agent + follower, back up
# /opt/bloch/l2-attestor and config.json (suffix .TAG), move status.json aside, install the two binaries
# and the kit's agent scripts, re-hash them on disk, update the pins, start the follower, wait for its
# re-verify (status.json rewritten: about 50-60 min), run `attestor_agent.py check` (must print
# check-ok), wait for native_finalized_epoch to advance, remove PAUSE, start the agent. Any failure
# stops with PAUSE in place and the follower running; `--resume` continues from the follower start.
# Run it inside tmux/screen: the wait is long.
# upgrade-rollback: restore the .TAG backup (binaries, agent scripts, config.json), move status.json
# aside, then the same wait/check/unpause tail. A backup that holds a PRE-fork follower is refused from
# 70 min before epoch 7180 (HF1, 2026-11-01 16:11 UTC) on: it cannot follow the chain past the fork; fix
# forward instead. A backup whose follower is the published post-fork build (the launch pin below, or
# --follower-sha256 of a later published build) can be restored at any time: this is the way back from
# a corrected build that does not come up.
#
# install refuses any bloch-pos, follower or producer whose SHA-256 is not the published one below, even when
# DIR/SHA256SUMS lists it: that file travels with the binaries and cannot vouch for them.
# A wrong transport passphrase, or a host that cannot be resolved, leaves nothing behind: just run install again.
#
# DIR holds: bloch-pos (built from codex/l2-attestor-keystore-20261019: l2-claim seal-key/key-check/
# attest --sealed), bloch-l2-native-follower and bloch-l2-produce-dev (the pinned L2 release build,
# build-release.sh), mainnet.manifest, carryover.tsv.gz + carryover.tsv.gz.sha256 (bloch-sis-pow
# 78b7343a), and SHA256SUMS over the three binaries.
#
# The key: the operator's transport bundle (attestor-I.sealed from make-operator-bundles.sh) is
# opened ONCE with the transport passphrase (typed here) and re-sealed under a fresh random host
# passphrase in /etc/bloch-l2-attestor/keystore.passphrase (root, 0400), handed to the agent via
# systemd LoadCredential. The host never holds a plaintext key file. After check-ok the operator
# re-seals an offline backup under their own passphrase (INSTALL.md step 9) and deletes every copy of
# the transport bundle (step 10): the key holder can open the transport bundle, so it is not a backup.
#
# upgrade also installs sigfeed.py and prepares the feed unit (not enabled; feed.env 0.0.0.0:8787 unless it
# exists or --feed-port/--feed-bind are given; --no-feed skips the unit), and it restarts a running feed.
# Open inbound TCP 8787, then enable the unit. upgrade-rollback removes a feed that the upgrade added.
#
# --feed-port N: the default way to publish. Prepares bloch-l2-attestor-feed.service (not enabled, not
# started), a read-only endpoint serving only the agent's outbox partials. It holds no credential, and
# the agent keeps its no-listener unit. The push options above stay for operators with no inbound port.
#
# --prefix DIR (rehearsal/staging): install every file under DIR instead of /opt, /etc and
# /var/lib, as the invoking user, without useradd, chown or systemctl (units are written to
# DIR/systemd and never loaded). --rehearsal-set FILE (only with --prefix) accepts a THROWAWAY
# attestor set instead of the pinned one, to rehearse the owner flow end to end without real keys, and
# lifts the published-binary check. --rehearsal-any-manifest (only with --rehearsal-set) also accepts a private
# net's genesis as mainnet.manifest.
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
usage() { sed -n '3,/^set -euo/p' "$0" | sed '$d'; }
DRY=0
run() { echo "+ $*"; [ $DRY = 1 ] || "$@"; }
host_of() { [[ $1 =~ ^https?://([A-Za-z0-9.-]+)(:[0-9]+)?(/.*)?$ ]] || die "bad URL $1"; echo "${BASH_REMATCH[1]}"; }
ip_of() { { getent ahostsv4 "$1" || true; } | awk 'NR==1{print $1}'; }

cmd_install() {
  local ART= INDEX= BUNDLE= L1= PUB_URL= PUB_TOKEN= PUB_CMD= ALERT= RPCS=() PREFIX= RSET= FEED_PORT= FEED_BIND=0.0.0.0 ANYMANIFEST=0
  while [ $# -gt 0 ]; do
    case $1 in
      --artifacts) ART=$2; shift 2;; --index) INDEX=$2; shift 2;; --bundle) BUNDLE=$2; shift 2;;
      --l1-rpc-url) L1=$2; shift 2;; --rpc) RPCS+=("$2"); shift 2;;
      --publish-url) PUB_URL=$2; shift 2;; --publish-token-file) PUB_TOKEN=$2; shift 2;;
      --publish-command) PUB_CMD=$2; shift 2;; --alert-command) ALERT=$2; shift 2;;
      --feed-port) FEED_PORT=$2; shift 2;; --feed-bind) FEED_BIND=$2; shift 2;;
      --dry-run) DRY=1; shift;; --prefix) PREFIX=$2; shift 2;; --rehearsal-set) RSET=$2; shift 2;;
      --rehearsal-any-manifest) ANYMANIFEST=1; shift;;
      *) die "unknown option $1";;
    esac
  done
  [ $ANYMANIFEST = 0 ] || [ -n "$RSET" ] || die "--rehearsal-any-manifest needs --rehearsal-set"
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
  [ -n "$ART" ] && [ -n "$INDEX" ] && [ -n "$BUNDLE" ] && [ -n "$L1" ] || { usage; exit 2; }
  [[ $INDEX =~ ^[0-4]$ ]] || die "--index must be 0..4"
  [ ${#RPCS[@]} -gt 0 ] || RPCS=("${DEFAULT_RPCS[@]}")
  [ ${#RPCS[@]} -eq 3 ] || die "give exactly three --rpc URLs (quorum 2-of-3)"
  [[ $L1 =~ ^http://[A-Za-z0-9.-]+:[0-9]+/?$ ]] || die "--l1-rpc-url must be http://HOST:PORT"
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$PREFIX" ] || die "run as root"
  [ -n "$PUB_URL$PUB_CMD$FEED_PORT" ] || echo "WARNING: no --feed-port/--publish-url/--publish-command: partials stay in $STATE/outbox only" >&2
  [ -z "$PUB_TOKEN" ] || [ -n "$PUB_URL" ] || die "--publish-token-file goes with --publish-url"
  for f in "$UNITS/bloch-l2-attestor.service" "$UNITS/bloch-l2-attestor-follower.service" "$ETC/attestor.sealed"; do
    [ ! -e "$f" ] || die "$f exists: this host already has an attestor. To replace it on purpose: install-attestor.sh rollback --purge-key, and have your offline backup first"
  done
  local py; py=$(command -v python3) || die "python3 is required"
  [ "$py" = /usr/bin/python3 ] || echo "note: the unit runs /usr/bin/python3" >&2

  # 1. Artifacts and public inputs, by hash.
  for b in bloch-pos bloch-l2-native-follower bloch-l2-produce-dev; do
    [ -f "$ART/$b" ] || die "$ART/$b is missing"
    [ -x "$ART/$b" ] || chmod +x "$ART/$b" 2>/dev/null || [ $DRY = 1 ] || die "$ART/$b is not executable and cannot be made so"
  done
  [ -f "$ART/SHA256SUMS" ] || die "$ART/SHA256SUMS is missing: run ./check-operator-bundle.sh first, it writes it"
  (cd "$ART" && sha256sum -c --strict SHA256SUMS) || die "binary hashes do not match SHA256SUMS"
  if [ -z "$RSET" ]; then
    local got want
    for b in "bloch-pos $V2_BLOCH_POS_SHA256" "bloch-l2-native-follower $V2_FOLLOWER_SHA256" "bloch-l2-produce-dev $V2_PRODUCE_SHA256"; do
      got=$(sha256sum "$ART/${b% *}" | cut -d' ' -f1); want=${b#* }
      [ "$got" = "$want" ] || die "$ART/${b% *} is $got, not the published $want: do not install it. Ask the coordinator for the published build"
    done
  fi
  for b in bloch-pos bloch-l2-native-follower bloch-l2-produce-dev; do
    grep -q "  $b\$" "$ART/SHA256SUMS" || die "SHA256SUMS does not cover $b"
  done
  [ $ANYMANIFEST = 1 ] || echo "$MANIFEST_SHA256  $ART/mainnet.manifest" | sha256sum -c --strict || die "mainnet.manifest is not Genesis-4"
  echo "$SET_FILE_SHA256  $SETF" | sha256sum -c --strict || die "attestors.set is not the pinned set"
  echo "$(cut -d' ' -f1 "$ART/carryover.tsv.gz.sha256")  $ART/carryover.tsv.gz" | sha256sum -c --strict \
    || die "carryover.tsv.gz does not match carryover.tsv.gz.sha256"
  "$ART/bloch-pos" l2-claim --help | grep 'seal-key' >/dev/null || die "$ART/bloch-pos has no l2-claim seal-key (build the attestor-keystore branch)"
  local info; info=$("$ART/bloch-pos" l2-claim key-info --sealed "$BUNDLE") || die "$BUNDLE is not a sealed attestor key"
  grep -qx "signer_index $INDEX" <<<"$info" || die "$BUNDLE is not attestor $INDEX"
  grep -qx "set_hash $SET_HASH" <<<"$info" || die "$BUNDLE belongs to another attestor set"
  local allow_agent="localhost" allow_follower h ip
  for u in "${RPCS[@]}" ${PUB_URL:+"$PUB_URL"}; do
    h=$(host_of "$u"); ip=$(ip_of "$h"); [ -n "$ip" ] || die "cannot resolve $h"; allow_agent+=" $ip"
  done
  h=$(host_of "$L1"); allow_follower=$(ip_of "$h"); [ -n "$allow_follower" ] || die "cannot resolve $h"

  # 2. The key comes first: a mistyped passphrase must leave nothing that blocks a second try.
  if [ $DRY = 1 ]; then echo "+ re-seal $BUNDLE -> $ETC/attestor.sealed under a new random $ETC/keystore.passphrase (0400 root)"
  else
    install -d -m 0755 "$ETC"
    (umask 077; head -c 48 /dev/urandom | base64 | tr -d '\n=+/' > "$ETC/keystore.passphrase")
    chmod 0400 "$ETC/keystore.passphrase"
    echo "Type the TRANSPORT passphrase of attestor $INDEX's bundle (the one you received out of band):"
    "$ART/bloch-pos" l2-claim seal-key --sealed "$BUNDLE" --attestors "$SETF" --signer-index "$INDEX" \
      --passphrase-file "$ETC/keystore.passphrase" --out "$ETC/attestor.sealed.new" \
      || { rm -f "$ETC/attestor.sealed.new"; shred -fu "$ETC/keystore.passphrase"; die "re-seal failed. Nothing was installed. Check the passphrase and run the same command again"; }
    "$ART/bloch-pos" l2-claim key-check --sealed "$ETC/attestor.sealed.new" --attestors "$SETF" \
      --signer-index "$INDEX" --passphrase-file "$ETC/keystore.passphrase" \
      || { rm -f "$ETC/attestor.sealed.new"; shred -fu "$ETC/keystore.passphrase"; die "host key check failed. Nothing was installed"; }
  fi

  # 3. Users and directories.
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

  # The re-sealed key takes its final name last among the key steps; its presence marks an installed host.
  if [ $DRY = 0 ]; then
    [ -n "$PREFIX" ] || chown root:$USER_AGENT "$ETC/attestor.sealed.new"
    chmod 0440 "$ETC/attestor.sealed.new"; mv "$ETC/attestor.sealed.new" "$ETC/attestor.sealed"
  fi
  if [ -n "$PUB_TOKEN" ]; then run install -m 0400 -o root -g root "$PUB_TOKEN" "$ETC/publish-token"; fi
  [ -e "$ETC/approvals.txt" ] || run install -m 0644 /dev/null "$ETC/approvals.txt"

  # 4. Config (binary pins from SHA256SUMS).
  local sum_pos sum_produce sum_follower publish='[]' alert=null
  sum_pos=$(awk '$2=="bloch-pos"{print $1}' "$ART/SHA256SUMS")
  sum_produce=$(awk '$2=="bloch-l2-produce-dev"{print $1}' "$ART/SHA256SUMS")
  sum_follower=$(awk '$2=="bloch-l2-native-follower"{print $1}' "$ART/SHA256SUMS")
  [ -z "$PUB_URL" ] || publish=$(python3 -c 'import json,sys; t={"kind":"http_put","url":sys.argv[1]}
if sys.argv[2]: t["token_credential"]="publish-token"
print(json.dumps([t]))' "$PUB_URL" "$PUB_TOKEN")
  [ -z "$PUB_CMD" ] || publish=$(python3 -c 'import json,sys; p=json.loads(sys.argv[1]); c=json.loads(sys.argv[2])
assert isinstance(c,list) and all(isinstance(a,str) for a in c), "argv list"
print(json.dumps(p+[{"kind":"command","argv":c}]))' "$publish" "$PUB_CMD")
  [ -z "$ALERT" ] || alert=$ALERT
  local config
  config=$(python3 - "$INDEX" "$sum_pos" "$sum_produce" "$sum_follower" "$publish" "$alert" "$OPT" "$ETC" "$STATE" "$FSTATE" "${RPCS[@]}" <<'PY'
import json, sys
index, pos, produce, follower, publish, alert, opt, etc, state, fstate, *rpcs = sys.argv[1:]
print(json.dumps({
    'signer_index': int(index), 'bloch_pos': f'{opt}/bloch-pos', 'bloch_pos_sha256': pos,
    'produce': f'{opt}/bloch-l2-produce-dev', 'produce_sha256': produce,
    'follower': f'{opt}/bloch-l2-native-follower', 'follower_sha256': follower,
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
  [ -z "$PUB_URL" ] || echo "note: the drop host is pinned by IP ($PUB_URL); re-run the drop-in if its address changes" >&2
  ip=$allow_follower
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
Installed attestor $INDEX, NOT started. Follow INSTALL.md from step 6. The commands, in order:
  sudo systemctl enable --now bloch-l2-attestor-follower
  sudo journalctl -fu bloch-l2-attestor-follower
  (the first replay takes 60-90 min or more; wait for l2_genesis.finalized=true in $FSTATE/status.json)
  sudo systemd-run --pipe --wait -p User=$USER_AGENT -p LoadCredential=passphrase:$ETC/keystore.passphrase \\
       -p RuntimeDirectory=bloch-l2-attestor-check -p RuntimeDirectoryMode=0700 /usr/bin/python3 -I $OPT/attestor_agent.py check --config $ETC/config.json
 ${FEED_PORT:+ sudo systemctl enable --now bloch-l2-attestor-feed
} sudo systemctl enable --now bloch-l2-attestor
  sudo journalctl -fu bloch-l2-attestor -o cat
Then re-seal your offline backup under your own passphrase (INSTALL.md step 9) and delete every copy
of the transport bundle, here ($BUNDLE) and elsewhere (INSTALL.md step 10).
MSG
}

cmd_rollback() {
  local PURGE=0
  while [ $# -gt 0 ]; do case $1 in --purge-key) PURGE=1; shift;; --dry-run) DRY=1; shift;; *) die "unknown option $1";; esac; done
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || die "run as root"
  if [ $PURGE = 1 ] && [ $DRY = 0 ]; then
    echo "--purge-key destroys this host's copy of the attestor key. Without your offline backup AND its passphrase the key is gone, and replacing it needs an L1 hard fork."
    local answer; read -r -p "Type PURGE to continue: " answer
    [ "$answer" = PURGE ] || die "not purged; nothing changed"
  fi
  for unit in bloch-l2-attestor-feed bloch-l2-attestor bloch-l2-attestor-follower; do
    run systemctl disable --now "$unit.service" || true
    run rm -rf "$UNITS/$unit.service" "$UNITS/$unit.service.d"
  done
  run systemctl daemon-reload
  if [ $PURGE = 1 ]; then
    for f in "$ETC/attestor.sealed" "$ETC/keystore.passphrase" "$ETC/publish-token"; do
      [ ! -e "$f" ] || run shred -fu "$f"
    done
    echo "Host key removed. Your re-sealed offline backup (INSTALL.md step 9, opened only by your own passphrase) is now the only copy of this attestor's key on your side."
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

# ------------------------------------------------------------------------------------------ upgrade
# The launch build (release bloch-l2-2026-11-03-next-native-78d4921c, L2 926d2cf5 against L1 78d4921c). Override only for a later
# corrected build whose hashes the coordinator published.
V2_FOLLOWER_SHA256=cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2
V2_PRODUCE_SHA256=e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69
V2_BLOCH_POS_SHA256=093909a2bda70381bb3f71535029ceeb0b8b21378c3419c4c1dd0783a1a3387e
L1_GENESIS_UNIX=1786656679 L1_EPOCH_SECONDS=960 HF1_EPOCH=7180
ROLLBACK_LEAD_SECONDS=4200   # re-verify (~50 min) + check must finish before HF1 starts
KIT_FILES=(attestor_agent.py attestor_lib.py aggregate_attestation.py sigfeed.py)
FEED_UNIT=bloch-l2-attestor-feed.service FEED_PORT= FEED_BIND= NO_FEED=0
SERVICE_CMD= CHECK_CMD= NOW_UNIX= TAG=pre-hf123 RESUME=0 UNPAUSE=1 WAIT_TIMEOUT=7200 ADVANCE_TIMEOUT=2400 POLL=30

now() { echo "${NOW_UNIX:-$(date +%s)}"; }
say() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
jget() {  # jget FILE KEY: a top-level JSON value ('' when absent)
  python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"
}
svc() {  # svc start|stop|is-active follower|agent
  local unit=bloch-l2-attestor; [ "$2" = agent ] || unit=bloch-l2-attestor-follower
  if [ -n "$SERVICE_CMD" ]; then bash -c "$SERVICE_CMD $1 $2"; return; fi
  case $1 in is-active) systemctl is-active --quiet "$unit";; *) systemctl "$1" "$unit";; esac
}
run_check() {
  if [ -n "$CHECK_CMD" ]; then bash -c "$CHECK_CMD"; return; fi
  systemd-run --pipe --wait --quiet -p User=$USER_AGENT -p LoadCredential=passphrase:$ETC/keystore.passphrase \
    -p RuntimeDirectory=bloch-l2-attestor-check -p RuntimeDirectoryMode=0700 /usr/bin/python3 -I "$OPT/attestor_agent.py" check --config "$ETC/config.json"
}
write_state() {  # the resumable record of an upgrade / upgrade-rollback in progress
  printf 'op=%s\ntag=%s\nphase=%s\nmoved_at=%s\n' "$OP" "$TAG" "$1" "$MOVED_AT" > "$ETC/upgrade.state.tmp"
  mv "$ETC/upgrade.state.tmp" "$ETC/upgrade.state"
}
status_newer_than() {  # the follower wrote status.json at or after unix time $1 (it writes only after re-verify)
  python3 -I -c 'import json,sys
try: s=json.load(open(sys.argv[1]))
except (OSError, ValueError): sys.exit(1)
sys.exit(0 if float(s.get("written_at_unix", 0)) >= float(sys.argv[2]) else 1)' "$FSTATE/status.json" "$1"
}
read_state() { [ ! -e "$ETC/upgrade.state" ] || sed -n "s/^$1=//p" "$ETC/upgrade.state"; }
set_pins() {  # config.json: produce_sha256, follower, follower_sha256 (atomic; keeps every other key, mode, owner)
  python3 -I - "$ETC/config.json" "$1" "$OPT/bloch-l2-native-follower" "$2" <<'PY'
import json, os, sys
path, produce, follower, follower_sha = sys.argv[1:]
c = json.load(open(path))
old = {k: c.get(k) for k in ('produce_sha256', 'follower', 'follower_sha256')}
c.update(produce_sha256=produce, follower=follower, follower_sha256=follower_sha)
st = os.stat(path)
tmp = path + '.tmp'
with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, st.st_mode & 0o777), 'w') as f:
    f.write(json.dumps(c, indent=1) + '\n')
os.chmod(tmp, st.st_mode & 0o777)
if os.geteuid() == 0:
    os.chown(tmp, st.st_uid, st.st_gid)
os.replace(tmp, path)
for k, v in old.items():
    print(f'  config.json {k}: {v} -> {c[k]}')
PY
}
verify_pins_on_disk() {  # every pinned binary on disk equals config.json (the agent's own check_identity rule)
  local name file pin
  for name in bloch_pos produce follower; do
    file=$(jget "$ETC/config.json" "$name") pin=$(jget "$ETC/config.json" "${name}_sha256")
    if [ -z "$pin" ] && [ "$name" = follower ]; then say "  follower: not pinned in this config.json (pre-2026-10-30 kit)"; continue; fi
    [ "$(sha "$file")" = "$pin" ] || die "$file does not match its pin ${name}_sha256 $pin"
    say "  $name $pin  $file"
  done
}
upgrade_opts() {  # shared options; sets ART, FOLLOWER_SHA256, PRODUCE_SHA256 and the prefix paths
  local PREFIX=
  ART= FOLLOWER_SHA256=$V2_FOLLOWER_SHA256 PRODUCE_SHA256=$V2_PRODUCE_SHA256
  while [ $# -gt 0 ]; do
    case $1 in
      --artifacts) ART=$2; shift 2;; --tag) TAG=$2; shift 2;; --resume) RESUME=1; shift;;
      --no-unpause) UNPAUSE=0; shift;; --wait-timeout) WAIT_TIMEOUT=$2; shift 2;;
      --advance-timeout) ADVANCE_TIMEOUT=$2; shift 2;; --poll) POLL=$2; shift 2;;
      --follower-sha256) FOLLOWER_SHA256=$2; shift 2;; --produce-sha256) PRODUCE_SHA256=$2; shift 2;;
      --prefix) PREFIX=$2; shift 2;; --service-cmd) SERVICE_CMD=$2; shift 2;; --check-cmd) CHECK_CMD=$2; shift 2;;
      --now-unix) NOW_UNIX=$2; shift 2;;
      --feed-port) FEED_PORT=$2; shift 2;; --feed-bind) FEED_BIND=$2; shift 2;; --no-feed) NO_FEED=1; shift;;
      *) die "unknown option $1";;
    esac
  done
  [ -z "$FEED_PORT" ] || [[ $FEED_PORT =~ ^[0-9]{2,5}$ ]] || die "--feed-port must be a port number"
  [ -z "$FEED_BIND" ] || [[ $FEED_BIND =~ ^[0-9A-Fa-f:.]+$ ]] || die "--feed-bind must be an IP address"
  [[ $TAG =~ ^[A-Za-z0-9._-]+$ ]] || die "--tag: letters, digits, . _ - only"
  [[ $FOLLOWER_SHA256$PRODUCE_SHA256 =~ ^[0-9a-f]{128}$ ]] || die "--follower-sha256/--produce-sha256: 64 hex digits each"
  [[ $WAIT_TIMEOUT$ADVANCE_TIMEOUT =~ ^[0-9]+$ ]] && [[ $POLL =~ ^[1-9][0-9]*$ ]] || die "timeouts are seconds"
  if [ -n "$PREFIX" ]; then
    [ -n "$SERVICE_CMD" ] && [ -n "$CHECK_CMD" ] || die "--prefix needs --service-cmd and --check-cmd (no systemd in a rehearsal)"
    PREFIX=$(cd "$PREFIX" && pwd); [ "$PREFIX" != / ] || die "--prefix / is a real host; drop --prefix"
    OPT=$PREFIX$OPT ETC=$PREFIX$ETC STATE=$PREFIX$STATE FSTATE=$PREFIX$FSTATE UNITS=$PREFIX/systemd
    echo "REHEARSAL: upgrading the --prefix install under $PREFIX" >&2
  else
    [ -z "$SERVICE_CMD$CHECK_CMD$NOW_UNIX" ] || die "--service-cmd/--check-cmd/--now-unix are rehearsal-only (need --prefix)"
    [ "$(id -u)" = 0 ] || die "run as root"
  fi
  [ -s "$ETC/config.json" ] && [ -e "$OPT/bloch-pos" ] || die "no attestor install under $OPT and $ETC"
}
check_artifact() {  # check_artifact NAME EXPECTED: DIR/NAME has the published hash (and SHA256SUMS agrees, if present)
  local f=$ART/$1 got listed
  [ -f "$f" ] || die "$f is missing"
  got=$(sha "$f")
  [ "$got" = "$2" ] || die "$f is $got, not the published $2: do not install it"
  if [ -e "$ART/SHA256SUMS" ]; then
    listed=$(awk -v n="$1" '$2==n || $2=="*"n {print $1}' "$ART/SHA256SUMS")
    [ "$listed" = "$2" ] || die "SHA256SUMS lists $1 as '${listed:-nothing}', not $2"
  fi
  say "  ok $2  $f"
}
upgrade_fail() {
  echo >&2
  echo "install-attestor: $OP STOPPED: $*" >&2
  echo "  PAUSE stays in $ETC/PAUSE; the agent is stopped; the follower keeps running." >&2
  echo "  Continue after fixing: $0 $OP --resume${TAG:+ --tag $TAG}" >&2
  [ "$OP" = upgrade-rollback ] || echo "  Or go back (only before HF1, epoch $HF1_EPOCH): $0 upgrade-rollback --tag $TAG" >&2
  exit 1
}
upgrade_tail() {  # follower start -> re-verify -> check -> finality advances -> unpause
  local t0 e0 e1 out code tries=0
  say "start the follower"; svc start follower || upgrade_fail "the follower did not start"
  write_state started
  say "wait for the follower to re-verify its retained L1 history and write a new status.json (about 50-60 min)"
  t0=$(date +%s)
  while :; do
    status_newer_than "$MOVED_AT" && break
    svc is-active follower || upgrade_fail "the follower exited during re-verify (journalctl -u bloch-l2-attestor-follower)"
    [ $(( $(date +%s) - t0 )) -lt "$WAIT_TIMEOUT" ] || upgrade_fail "no new status.json after ${WAIT_TIMEOUT}s"
    [ $(( ($(date +%s) - t0) % 300 )) -ge "$POLL" ] || say "  still re-verifying ($(( ($(date +%s) - t0) / 60 )) min)"
    sleep "$POLL"
  done
  say "  status.json written after $(( $(date +%s) - t0 )) s: epoch $(jget "$FSTATE/status.json" native_finalized_epoch)"
  say "self-check: attestor_agent.py check (pins incl. follower, key, follower, RPC quorum, rebuild)"
  while :; do
    code=0; out=$(run_check 2>&1) || code=$?
    printf '%s\n' "$out" | sed 's/^/  | /'
    if [ $code = 0 ] && grep -q '"event": "check-ok"' <<<"$out"; then break; fi
    [ $code = 1 ] && [ $tries -lt 10 ] || upgrade_fail "check did not print check-ok (exit $code)"
    tries=$((tries + 1)); say "  check-not-ready: retry $tries/10 in $((2 * POLL)) s"; sleep $((2 * POLL))
  done
  e0=$(jget "$FSTATE/status.json" native_finalized_epoch); t0=$(date +%s)
  [[ $e0 =~ ^[0-9]+$ ]] || upgrade_fail "status.json has no native_finalized_epoch"
  say "wait for native_finalized_epoch to advance past $e0 (one epoch is 16 min)"
  while :; do
    e1=$(jget "$FSTATE/status.json" native_finalized_epoch 2>/dev/null || true)
    if [[ $e1 =~ ^[0-9]+$ ]] && [ "$e1" -gt "$e0" ]; then break; fi
    [ $(( $(date +%s) - t0 )) -lt "$ADVANCE_TIMEOUT" ] || upgrade_fail "native_finalized_epoch stayed at $e0 for ${ADVANCE_TIMEOUT}s"
    sleep "$POLL"
  done
  say "  native_finalized_epoch $e0 -> $e1"
  if [ $UNPAUSE = 0 ]; then
    write_state verified
    say "--no-unpause: PAUSE kept, agent stopped. To resume signing: rm $ETC/PAUSE; systemctl start bloch-l2-attestor"
  else
    rm -f "$ETC/PAUSE"; svc start agent || upgrade_fail "the agent did not start"
    sleep 5; svc is-active agent || upgrade_fail "the agent exited right after start (journalctl -u bloch-l2-attestor)"
    write_state done
    say "PAUSE removed, agent started. Watch: journalctl -fu bloch-l2-attestor -o cat (started, rebuild-check-ok)"
  fi
  say "REPORT: attestor $(jget "$ETC/config.json" signer_index): $OP check-ok, epoch $e0->$e1, follower $(jget "$ETC/config.json" follower_sha256 | cut -c1-8), produce $(jget "$ETC/config.json" produce_sha256 | cut -c1-8)"
}
resume_or_fresh() {  # a recorded unfinished operation must be resumed (or rolled back), never restarted
  local op phase; op=$(read_state op) phase=$(read_state phase)
  if [ $RESUME = 1 ]; then
    [ "$op" = "$OP" ] && [ -n "$phase" ] && [ "$phase" != done ] || die "nothing to resume for $OP (state: ${op:-none} ${phase:-})"
    case $phase in installed|started|verified) ;; *) die "$OP stopped in phase '$phase' before the install finished: inspect, then run upgrade-rollback";; esac
    TAG=$(read_state tag) MOVED_AT=$(read_state moved_at)
    say "resume $OP (tag $TAG, phase $phase): pins on disk"
    verify_pins_on_disk
    upgrade_tail; [ "$OP" != upgrade ] || feed_note; exit 0
  fi
  if [ -n "$phase" ] && [ "$phase" != done ] && { [ "$OP" = upgrade ] || [ "$op" = upgrade-rollback ]; }; then
    die "an unfinished $op (phase $phase) is recorded in $ETC/upgrade.state: use --resume (or upgrade-rollback)"
  fi
  return 0
}

feed_current() {  # the feed unit is installed as this kit ships it (or the operator opted out)
  [ "$NO_FEED" = 1 ] || { cmp -s "$HERE/systemd/$FEED_UNIT" "$UNITS/$FEED_UNIT" && [ -s "$ETC/feed.env" ]; }
}
kit_current() {
  local f
  for f in "${KIT_FILES[@]}"; do cmp -s "$HERE/$f" "$OPT/$f" || return 1; done
}
install_feed() {  # prepare the read-only feed as `install --feed-port` does; never enables it
  if [ "$NO_FEED" = 1 ]; then say "   feed unit skipped (--no-feed)"; return 0; fi
  mkdir -p "$UNITS"
  [ -e "$UNITS/$FEED_UNIT" ] || touch "$ETC/feed-added.$TAG"
  install -m 0644 "$HERE/systemd/$FEED_UNIT" "$UNITS/"
  if [ -n "$FEED_PORT$FEED_BIND" ] || [ ! -s "$ETC/feed.env" ]; then
    printf 'SIGFEED_BIND=%s\nSIGFEED_PORT=%s\n' "${FEED_BIND:-0.0.0.0}" "${FEED_PORT:-8787}" > "$ETC/feed.env"; chmod 0644 "$ETC/feed.env"
  fi
  if [ -z "$SERVICE_CMD" ]; then systemctl daemon-reload; systemctl try-restart "$FEED_UNIT"; fi
}
feed_note() {
  [ "$NO_FEED" = 0 ] && [ -s "$ETC/feed.env" ] || return 0
  local port; port=$(sed -n 's/^SIGFEED_PORT=//p' "$ETC/feed.env")
  say "feed: open inbound TCP $port to everyone, then: sudo systemctl enable --now ${FEED_UNIT%.service}"
  say "feed: check from another host: curl -fsS http://<public IPv4>:$port/healthz"
}
cmd_upgrade() {
  OP=upgrade; upgrade_opts "$@"; resume_or_fresh
  [ -n "$ART" ] || { usage; exit 2; }
  for f in "${KIT_FILES[@]}" "systemd/$FEED_UNIT"; do [ -f "$HERE/$f" ] || die "kit file $HERE/$f missing"; done
  say "1. verify the new binaries against the published SHA-256"
  check_artifact bloch-l2-native-follower "$FOLLOWER_SHA256"
  check_artifact bloch-l2-produce-dev "$PRODUCE_SHA256"
  if [ "$(jget "$ETC/config.json" follower_sha256)" = "$FOLLOWER_SHA256" ] && \
     [ "$(jget "$ETC/config.json" produce_sha256)" = "$PRODUCE_SHA256" ] && \
     [ "$(sha "$OPT/bloch-l2-native-follower")" = "$FOLLOWER_SHA256" ] && [ "$(sha "$OPT/bloch-l2-produce-dev")" = "$PRODUCE_SHA256" ] && kit_current && feed_current; then
    say "already upgraded: installed binaries, config.json pins, agent scripts and feed unit are the requested ones; nothing changed"; return 0
  fi
  for f in "$OPT.$TAG" "$ETC/config.json.$TAG"; do [ ! -e "$f" ] || die "$f exists (an earlier backup): choose another --tag"; done
  say "   installed now: follower $(sha "$OPT/bloch-l2-native-follower"), produce $(sha "$OPT/bloch-l2-produce-dev"), config produce_sha256 $(jget "$ETC/config.json" produce_sha256)"
  say "2. pause and stop the agent and the follower"
  touch "$ETC/PAUSE"; svc stop agent || die "could not stop the agent"; svc stop follower || die "could not stop the follower"
  say "3. back up to $OPT.$TAG and config.json.$TAG; move status.json aside"
  cp -a "$OPT" "$OPT.$TAG"; cp -a "$ETC/config.json" "$ETC/config.json.$TAG"
  MOVED_AT=$(date +%s)
  [ ! -e "$FSTATE/status.json" ] || mv "$FSTATE/status.json" "$FSTATE/status.json.$TAG"
  write_state stopped
  say "4. install the two binaries, the agent scripts and the feed unit (not enabled)"
  install -m 0755 "$ART/bloch-l2-native-follower" "$ART/bloch-l2-produce-dev" "$OPT/"
  for f in "${KIT_FILES[@]}"; do install -m 0644 "$HERE/$f" "$OPT/"; done
  install_feed
  say "5. re-hash on disk"
  [ "$(sha "$OPT/bloch-l2-native-follower")" = "$FOLLOWER_SHA256" ] || upgrade_fail "installed follower hash differs"
  [ "$(sha "$OPT/bloch-l2-produce-dev")" = "$PRODUCE_SHA256" ] || upgrade_fail "installed produce hash differs"
  say "6. update the pins in config.json"
  set_pins "$PRODUCE_SHA256" "$FOLLOWER_SHA256"
  verify_pins_on_disk
  write_state installed
  upgrade_tail
  feed_note
}

cmd_upgrade_rollback() {
  OP=upgrade-rollback; upgrade_opts "$@"
  local fork=$((L1_GENESIS_UNIX + HF1_EPOCH * L1_EPOCH_SECONDS)) t epoch f
  t=$(now); epoch=$(( (t - L1_GENESIS_UNIX) / L1_EPOCH_SECONDS ))
  # A backup that holds the published post-fork follower (the launch pin, or --follower-sha256 of a later
  # published build) follows the chain at any epoch: going back to it from a corrected build is allowed.
  local backup_pin= backup_file=$OPT.$TAG/bloch-l2-native-follower
  [ ! -f "$ETC/config.json.$TAG" ] || backup_pin=$(jget "$ETC/config.json.$TAG" follower_sha256)
  if [ "$backup_pin" = "$FOLLOWER_SHA256" ] && [ -f "$backup_file" ] && [ "$(sha "$backup_file")" = "$FOLLOWER_SHA256" ]; then
    say "L1 epoch $epoch: the backup .$TAG holds the published post-fork follower ${FOLLOWER_SHA256:0:8}, rollback allowed"
  elif [ $((t + ROLLBACK_LEAD_SECONDS)) -ge $fork ]; then
    die "refused: L1 epoch $epoch; HF1 (epoch $HF1_EPOCH) starts at $(date -u -d @$fork +%FT%TZ 2>/dev/null || echo $fork). A pre-fork follower re-verifying now cannot follow past the fork. Keep PAUSE and fix forward with the published build."
  else
    say "L1 epoch $epoch: $(( (fork - t) / 60 )) min before HF1, rollback allowed"
  fi
  resume_or_fresh
  [ -d "$OPT.$TAG" ] && [ -f "$ETC/config.json.$TAG" ] || die "no backup $OPT.$TAG + $ETC/config.json.$TAG to roll back to"
  say "1. check the backup against its own config.json pins"
  [ "$(sha "$OPT.$TAG/bloch-l2-produce-dev")" = "$(jget "$ETC/config.json.$TAG" produce_sha256)" ] || die "backup produce does not match config.json.$TAG"
  f=$(jget "$ETC/config.json.$TAG" follower_sha256)
  [ -z "$f" ] || [ "$(sha "$OPT.$TAG/bloch-l2-native-follower")" = "$f" ] || die "backup follower does not match config.json.$TAG"
  say "   backup follower $(sha "$OPT.$TAG/bloch-l2-native-follower"), produce $(sha "$OPT.$TAG/bloch-l2-produce-dev")"
  say "2. pause and stop the agent and the follower"
  touch "$ETC/PAUSE"; svc stop agent || die "could not stop the agent"; svc stop follower || die "could not stop the follower"
  say "3. restore the binaries, agent scripts and config.json from .$TAG; move status.json aside"
  install -m 0755 "$OPT.$TAG/bloch-l2-native-follower" "$OPT.$TAG/bloch-l2-produce-dev" "$OPT/"
  for f in "${KIT_FILES[@]}"; do
    if [ -f "$OPT.$TAG/$f" ]; then install -m 0644 "$OPT.$TAG/$f" "$OPT/"; else rm -f "$OPT/$f"; fi
  done
  if [ -e "$ETC/feed-added.$TAG" ]; then  # this upgrade added the feed: the restored kit may not carry sigfeed.py
    [ -n "$SERVICE_CMD" ] || systemctl disable --now "$FEED_UNIT" 2>/dev/null || true
    rm -f "$UNITS/$FEED_UNIT" "$ETC/feed.env" "$ETC/feed-added.$TAG"
    [ -n "$SERVICE_CMD" ] || systemctl daemon-reload
  elif [ -z "$SERVICE_CMD" ]; then
    systemctl try-restart "$FEED_UNIT" 2>/dev/null || true
  fi
  cp -a "$ETC/config.json.$TAG" "$ETC/config.json"
  MOVED_AT=$(date +%s)
  [ ! -e "$FSTATE/status.json" ] || mv "$FSTATE/status.json" "$FSTATE/status.json.rolled-back-$MOVED_AT"
  verify_pins_on_disk
  write_state installed
  upgrade_tail
}

case ${1:-} in
  install) shift; cmd_install "$@";;
  rollback) shift; cmd_rollback "$@";;
  upgrade) shift; cmd_upgrade "$@";;
  upgrade-rollback) shift; cmd_upgrade_rollback "$@";;
  status) cmd_status;;
  *) usage; exit 2;;
esac
