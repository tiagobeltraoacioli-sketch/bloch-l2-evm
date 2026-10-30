#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install (do NOT start), upgrade, roll back, remove or inspect a standalone READ-ONLY replica of
# Bloch L2 mainnet (chain id 700770) on one host: native follower + settled RPC, rebuilt from L1.
# No txpool, no signing, no secret of any kind. See README.md.
#
#   sudo ./install-replica.sh install --artifacts DIR --l1-rpc-url http://HOST:PORT \
#        --settler-l1-rpc-url http://HOST:PORT [--port 18965] [--dry-run] [--prefix DIR [--rehearsal-pins FILE]]
#   sudo ./install-replica.sh upgrade --artifacts DIR [--l1-rpc-url URL --settler-l1-rpc-url URL] \
#        [--dry-run] [--prefix DIR [--rehearsal-pins FILE]]
#   sudo ./install-replica.sh rollback [--dry-run] [--prefix DIR]
#   sudo ./install-replica.sh remove [--purge-data] [--dry-run] [--prefix DIR]
#   ./install-replica.sh status [--prefix DIR]
#
# DIR holds bloch-l2-native-follower, bloch-l2-settled-rpc, bloch-l2-produce-dev, mainnet.manifest and
# carryover.tsv.gz, each pinned in PINS.sha256 next to this script. An upgrade to new binaries is a
# reviewed change of PINS.sha256.
#
# --settler-l1-rpc-url names the L1 RPC the settler uses. The replica refuses to read from the same host,
# so one L1 RPC cannot feed both. --dry-run verifies everything and changes nothing.
#
# --prefix DIR (rehearsal/staging): every file goes under DIR, as the invoking user, without useradd, chown
# or systemctl. Units are rendered to DIR/systemd and never loaded. --rehearsal-pins FILE (only with
# --prefix) replaces the binary pins; the manifest and carryover pins stay enforced.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OPT=/opt/bloch/l2-replica ETC=/etc/bloch-l2-replica STATE=/var/lib/bloch-l2-replica UNITS=/etc/systemd/system
USER_=bloch-l2-replica
DEFAULT_PORT=18965
UNIT_FILES=(bloch-l2-replica-follower.service bloch-l2-replica-rpc.service bloch-l2-replica-refresh.service
            bloch-l2-replica-refresh.timer bloch-l2-replica-rpc-reload.path bloch-l2-replica-rpc-reload.service)
BINARIES=(bloch-l2-native-follower bloch-l2-settled-rpc bloch-l2-produce-dev)
SCRIPTS=(replica_refresh.py replica_check.py)
CARRYOVER_TSV_SHA256=84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6
SETTLER_STATE=/var/lib/bloch-l2-mainnet-settler

die() { echo "install-replica: $*" >&2; exit 1; }
DRY=0 PREFIX= PINS=$HERE/PINS.sha256 ART= L1= SETTLER_L1= PORT= PURGE=0 RPINS=
run() { echo "+ $*"; [ $DRY = 1 ] || "$@"; }

parse() {
  while [ $# -gt 0 ]; do
    case $1 in
      --artifacts) ART=$2; shift 2;; --l1-rpc-url) L1=$2; shift 2;; --settler-l1-rpc-url) SETTLER_L1=$2; shift 2;;
      --port) PORT=$2; shift 2;; --dry-run) DRY=1; shift;; --prefix) PREFIX=$2; shift 2;;
      --rehearsal-pins) RPINS=$2; shift 2;; --purge-data) PURGE=1; shift;;
      *) die "unknown option $1";;
    esac
  done
  [ -z "$RPINS" ] || [ -n "$PREFIX" ] || die "--rehearsal-pins needs --prefix (never on a real install)"
  if [ -n "$PREFIX" ]; then
    [ $DRY = 1 ] || mkdir -p "$PREFIX"
    case $PREFIX in /*) ;; *) PREFIX=$PWD/$PREFIX;; esac
    [ "$PREFIX" != / ] || die "--prefix / is a real install; drop --prefix"
    OPT=$PREFIX$OPT ETC=$PREFIX$ETC STATE=$PREFIX$STATE UNITS=$PREFIX/systemd
    echo "REHEARSAL: under $PREFIX as $(id -un); no users, no chown, no systemctl" >&2
  fi
  if [ -n "$RPINS" ]; then
    for f in mainnet.manifest carryover.tsv.gz; do
      [ "$(pin_of "$f" "$RPINS")" = "$(pin_of "$f" "$HERE/PINS.sha256")" ] || die "--rehearsal-pins may not change $f"
    done
    PINS=$RPINS
    echo "REHEARSAL: binary pins from $RPINS, not the release pins" >&2
  fi
}

pin_of() { awk -v f="$1" '$2==f{print $1}' "$2"; }
host_of() { [[ $1 =~ ^http://([A-Za-z0-9.-]+):([0-9]+)/?$ ]] || die "L1 RPC URL must be http://HOST:PORT, without credentials: $1"; echo "${BASH_REMATCH[1]}"; }
ip_of() { local ip; ip=$(getent ahostsv4 "$1" | awk 'NR==1{print $1}'); [ -n "$ip" ] || die "cannot resolve $1"; echo "$ip"; }
env_get() { sed -n "s/^$1=//p" "$ETC/replica.env" 2>/dev/null || true; }

check_artifacts() {
  [ -d "$ART" ] || die "--artifacts is not a directory"
  local bad
  bad=$(find "$ART" -maxdepth 2 \( -name '*.sk' -o -name 'keystore*' -o -name '*passphrase*' -o -name '*.sealed' \) -print -quit)
  [ -z "$bad" ] || die "secret-looking file in the artifacts directory ($bad); a replica holds no secret"
  local f want
  for f in "${BINARIES[@]}" mainnet.manifest carryover.tsv.gz; do
    want=$(pin_of "$f" "$PINS"); [ -n "$want" ] || die "$f has no pin in $PINS"
    [ -f "$ART/$f" ] || die "$ART/$f is missing"
    echo "$want  $ART/$f" | sha256sum -c --strict --quiet || die "$f does not match its pin"
    echo "pin ok: $f ${want:0:16}…"
  done
  [ "$(gunzip -c "$ART/carryover.tsv.gz" | sha256sum | cut -d' ' -f1)" = "$CARRYOVER_TSV_SHA256" ] || die "carryover.tsv does not match its pin"
}

check_independent() {
  [ -n "$L1" ] && [ -n "$SETTLER_L1" ] || die "--l1-rpc-url and --settler-l1-rpc-url are both required"
  local a b; a=$(host_of "$L1"); b=$(host_of "$SETTLER_L1")
  [ "$(ip_of "$a")" != "$(ip_of "$b")" ] || die "$a is the settler's L1 source; the replica must read another one"
  /usr/bin/python3 -I "$HERE/replica_check.py" preflight --l1 "$L1" >/dev/null || die "L1 RPC $L1 failed the identity preflight (network, genesis, chain id, activation)"
  echo "L1 source ok: $L1 (settler reads $SETTLER_L1)"
}

release_id() { sha256sum "$PINS" | cut -c1-12; }

# Rendered units are stored per release, so a rollback also restores the units of that release.
render_units() { # DEST_DIR L1_IP PORT
  local out=$1 ip=$2 port=$3 u
  for u in "${UNIT_FILES[@]}"; do
    sed -e "s#@OPT@#$OPT#g" -e "s#@ETC@#$ETC#g" -e "s#@STATE@#$STATE#g" -e "s#@USER@#$USER_#g" \
        -e "s#@PORT@#$port#g" -e "s#@L1_IP@#$ip#g" "$HERE/systemd/$u" > "$out/$u"
    ! grep -nE -- '--txpool|LoadCredential|keystore|passphrase|@[A-Z0-9_]+@' "$out/$u" | grep -v '^[0-9]*:#' \
      || die "rendered unit $u is not read-only or has an unresolved placeholder"
  done
}

stage_release() { # ID L1_IP PORT
  local id=$1 rel=$OPT/releases/$1 f
  if [ -e "$rel" ]; then # upgrading back to a release kept on disk
    (cd "$rel" && sha256sum -c --strict --quiet SHA256SUMS) || die "$rel on disk does not match its SHA256SUMS"
    return 0
  fi
  run install -d -m 0755 "$OPT/releases" "$rel" "$rel/units"
  for f in "${BINARIES[@]}"; do run install -m 0755 "$ART/$f" "$rel/"; done
  for f in "${SCRIPTS[@]}"; do run install -m 0644 "$HERE/$f" "$rel/"; done
  run install -m 0644 "$PINS" "$rel/PINS.sha256"
  if [ $DRY = 1 ]; then echo "+ write $rel/SHA256SUMS and render units"; return 0; fi
  (cd "$rel" && sha256sum "${BINARIES[@]}" "${SCRIPTS[@]}" > SHA256SUMS)
  render_units "$rel/units" "$2" "$3"
}

install_units() { # ID
  local rel=$OPT/releases/$1 u
  run install -d -m 0755 "$UNITS"
  for u in "${UNIT_FILES[@]}"; do run install -m 0644 "$rel/units/$u" "$UNITS/$u"; done
  [ -n "$PREFIX" ] || run systemctl daemon-reload
}

flip() { # ID: previous <- current, current <- ID, both atomic
  local old=
  [ ! -L "$OPT/current" ] || old=$(readlink "$OPT/current")
  [ -z "$old" ] || run ln -sfn "$old" "$OPT/previous"
  run ln -s "releases/$1" "$OPT/current.new"
  run mv -T "$OPT/current.new" "$OPT/current"
}

changed_units() { # OLD_REL NEW_REL: which services must restart for this flip
  local old=$1 new=$2 list=()
  [ "$(pin_of bloch-l2-native-follower "$old/PINS.sha256")" = "$(pin_of bloch-l2-native-follower "$new/PINS.sha256")" ] || list+=(bloch-l2-replica-follower)
  [ "$(pin_of bloch-l2-settled-rpc "$old/PINS.sha256")" = "$(pin_of bloch-l2-settled-rpc "$new/PINS.sha256")" ] || list+=(bloch-l2-replica-rpc)
  echo "${list[*]:-}"
}

restart_hint() {
  [ -n "$1" ] || { echo "No follower or RPC binary changed; nothing needs a restart."; return 0; }
  echo "Restart to apply (a follower restart re-verifies the chain from Genesis-4, about an hour; finality stays frozen meanwhile):"
  local u; for u in $1; do echo "  sudo systemctl restart $u"; done
}

cmd_install() {
  parse "$@"
  [ -n "$ART" ] || { sed -n 3,13p "$0"; exit 2; }
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$PREFIX" ] || die "run as root"
  [ -n "$PREFIX" ] || [ ! -e "$SETTLER_STATE" ] || die "$SETTLER_STATE exists: this is the settler host, and a replica here is not independent"
  [ ! -e "$OPT/current" ] || die "$OPT/current exists; use upgrade, or remove first"
  for u in "${UNIT_FILES[@]}"; do [ ! -e "$UNITS/$u" ] || die "$UNITS/$u exists; refusing to overwrite"; done
  PORT=${PORT:-$DEFAULT_PORT}
  [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || die "bad --port"
  check_artifacts
  check_independent
  local id ip own=()
  id=$(release_id); ip=$(ip_of "$(host_of "$L1")")
  if [ -z "$PREFIX" ]; then
    id -u "$USER_" >/dev/null 2>&1 || run useradd --system --user-group --no-create-home --home-dir "$STATE" --shell /usr/sbin/nologin "$USER_"
    own=(-o "$USER_" -g "$USER_")
  fi
  run install -d -m 0755 "$OPT" "$ETC" "$ETC/public"
  run install -d -m 0750 "${own[@]}" "$STATE" "$STATE/follower" "$STATE/rpc" "$STATE/generations" "$STATE/refresh"
  run install -m 0644 "$ART/mainnet.manifest" "$ETC/public/mainnet.manifest"
  if [ $DRY = 1 ]; then echo "+ gunzip carryover.tsv.gz > $ETC/public/carryover.tsv; write $ETC/replica.env"
  else
    gunzip -c "$ART/carryover.tsv.gz" > "$ETC/public/carryover.tsv"; chmod 0644 "$ETC/public/carryover.tsv"
    printf 'BLOCH_L1_RPC_URL=%s\nBLOCH_SETTLER_L1_RPC_URL=%s\nBLOCH_REPLICA_PORT=%s\n' "$L1" "$SETTLER_L1" "$PORT" > "$ETC/replica.env"
    chmod 0644 "$ETC/replica.env"
  fi
  stage_release "$id" "$ip" "$PORT"
  flip "$id"
  install_units "$id"
  [ $DRY = 0 ] || { echo "DRY RUN: nothing was changed."; return 0; }
  echo "release $id installed, NOT started."
  [ -n "$PREFIX" ] || cat <<MSG
To start (the first replay of the whole L1 takes about an hour):
  sudo systemctl enable --now bloch-l2-replica-follower bloch-l2-replica-refresh.timer bloch-l2-replica-rpc-reload.path
  sudo systemctl enable bloch-l2-replica-rpc
The refresh builds the database once the follower reports the L2 genesis final, and the path unit then starts the RPC.
MSG
}

cmd_upgrade() {
  parse "$@"
  [ -n "$ART" ] || { sed -n 3,13p "$0"; exit 2; }
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$PREFIX" ] || die "run as root"
  [ -L "$OPT/current" ] || die "nothing installed at $OPT; use install"
  [ -n "$L1" ] || L1=$(env_get BLOCH_L1_RPC_URL)
  [ -n "$SETTLER_L1" ] || SETTLER_L1=$(env_get BLOCH_SETTLER_L1_RPC_URL)
  PORT=$(env_get BLOCH_REPLICA_PORT); PORT=${PORT:-$DEFAULT_PORT}
  check_artifacts
  check_independent
  local id old ip
  id=$(release_id); old=$(readlink "$OPT/current")
  [ "$old" != "releases/$id" ] || die "release $id is already current"
  ip=$(ip_of "$(host_of "$L1")")
  stage_release "$id" "$ip" "$PORT"
  flip "$id"
  if [ $DRY = 1 ]; then echo "+ write $ETC/replica.env"
  else printf 'BLOCH_L1_RPC_URL=%s\nBLOCH_SETTLER_L1_RPC_URL=%s\nBLOCH_REPLICA_PORT=%s\n' "$L1" "$SETTLER_L1" "$PORT" > "$ETC/replica.env"; fi
  [ $DRY = 1 ] && [ ! -d "$OPT/releases/$id/units" ] && { echo "+ install rendered units of $id"; echo "DRY RUN: nothing was changed."; return 0; }
  install_units "$id"
  [ $DRY = 0 ] || { echo "DRY RUN: nothing was changed."; return 0; }
  echo "upgraded ${old#releases/} -> $id"
  restart_hint "$(changed_units "$OPT/$old" "$OPT/releases/$id")"
}

cmd_rollback() {
  parse "$@"
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$PREFIX" ] || die "run as root"
  [ -L "$OPT/previous" ] || die "no previous release to roll back to"
  local old new id
  old=$(readlink "$OPT/current"); new=$(readlink "$OPT/previous"); id=${new#releases/}
  (cd "$OPT/$new" && sha256sum -c --strict --quiet SHA256SUMS) || die "release $id on disk does not match its SHA256SUMS"
  flip "$id"
  install_units "$id"
  [ $DRY = 0 ] || { echo "DRY RUN: nothing was changed."; return 0; }
  echo "rolled back ${old#releases/} -> $id (the release you left stays as previous)"
  restart_hint "$(changed_units "$OPT/$old" "$OPT/$new")"
}

cmd_remove() {
  parse "$@"
  [ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$PREFIX" ] || die "run as root"
  local u
  if [ -z "$PREFIX" ]; then
    for u in "${UNIT_FILES[@]}"; do run systemctl disable --now "$u" 2>/dev/null || true; done
  fi
  for u in "${UNIT_FILES[@]}"; do run rm -f "$UNITS/$u"; done
  [ -n "$PREFIX" ] || run systemctl daemon-reload
  run rm -rf "$OPT" "$ETC"
  if [ $PURGE = 1 ]; then run rm -rf "$STATE"; else echo "kept $STATE (the follower's verified blocks); --purge-data deletes it"; fi
}

cmd_status() {
  parse "$@"
  [ -L "$OPT/current" ] || die "nothing installed at $OPT"
  echo "current:  $(readlink "$OPT/current")"
  echo "previous: $(readlink "$OPT/previous" 2>/dev/null || echo none)"
  (cd "$OPT/current" && sha256sum -c --strict --quiet SHA256SUMS) && echo "binaries: match SHA256SUMS"
  cat "$ETC/replica.env"
  [ -n "$PREFIX" ] || systemctl --no-pager --no-legend list-units 'bloch-l2-replica-*' || true
  /usr/bin/python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1]))
print({k:d.get(k) for k in ("verified_blocks","verified_tip","native_finalized_epoch","native_finalized_block")}, "l2_genesis.finalized", d["l2_genesis"]["finalized"])' "$STATE/follower/status.json" 2>/dev/null || echo "follower: no status yet"
  cat "$STATE/refresh/generation" 2>/dev/null | cut -c1-300 || true; echo
}

cmd=${1:-}; [ $# -eq 0 ] || shift
case $cmd in
  install) cmd_install "$@";; upgrade) cmd_upgrade "$@";; rollback) cmd_rollback "$@";;
  remove) cmd_remove "$@";; status) cmd_status "$@";;
  *) sed -n 3,27p "$0"; exit 2;;
esac
