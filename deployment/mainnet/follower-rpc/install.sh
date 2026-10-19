#!/bin/bash
# Install (do NOT start) the Bloch L2 MAINNET follower and settled RPC units.
# Run as root on the L2 host, from a directory holding the built binaries
# (build.sh OUT), their SHA256SUMS, this directory's units, mainnet.manifest
# and carryover.tsv.gz (both from bloch-sis-pow 78b7343a).
#
#   sudo ./install.sh --artifacts DIR --l1-rpc-url http://HOST:PORT \
#        --canonical /var/lib/bloch-l2-mainnet/canonical --canonical-user bloch-l2-mainnet \
#        --txpool /var/lib/bloch-l2-mainnet/txpool [--dry-run]
#
# Refuses to overwrite an existing installation. Prints the start commands.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ART= L1= CANONICAL= CANON_USER= TXPOOL= DRY=0
while [ $# -gt 0 ]; do
  case $1 in
    --artifacts) ART=$2; shift 2;; --l1-rpc-url) L1=$2; shift 2;;
    --canonical) CANONICAL=$2; shift 2;; --canonical-user) CANON_USER=$2; shift 2;;
    --txpool) TXPOOL=$2; shift 2;; --dry-run) DRY=1; shift;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ -n "$ART" ] && [ -n "$L1" ] && [ -n "$CANONICAL" ] && [ -n "$CANON_USER" ] && [ -n "$TXPOOL" ] || { sed -n 2,12p "$0"; exit 2; }
run() { echo "+ $*"; [ $DRY = 1 ] || "$@"; }
die() { echo "install.sh: $*" >&2; exit 1; }

MANIFEST_SHA256=7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
CARRYOVER_GZ_SHA256=$(cut -d' ' -f1 "$ART/carryover.tsv.gz.sha256" 2>/dev/null || true)
[[ $L1 =~ ^http://([A-Za-z0-9.-]+):([0-9]+)/?$ ]] || die "--l1-rpc-url must be http://HOST:PORT"
L1_HOST=${BASH_REMATCH[1]}
[ "$(id -u)" = 0 ] || [ $DRY = 1 ] || die "run as root"
id "$CANON_USER" >/dev/null 2>&1 || die "canonical user $CANON_USER does not exist (sequencer installs it)"
[ -d "$CANONICAL/db" ] && [ -d "$CANONICAL/static" ] && [ -d "$CANONICAL/rocks" ] || die "$CANONICAL is not an initialized L2 database"
[ -d "$TXPOOL" ] || die "$TXPOOL missing (sequencer spool)"
for unit in bloch-l2-mainnet-follower bloch-l2-mainnet-rpc; do
  [ ! -e /etc/systemd/system/$unit.service ] || die "/etc/systemd/system/$unit.service exists; refusing to overwrite"
done
[ ! -e /opt/bloch/l2-mainnet/bloch-l2-native-follower ] || die "/opt/bloch/l2-mainnet already populated"

# 1. Artifacts and public inputs, by hash.
(cd "$ART" && sha256sum -c --strict SHA256SUMS) || die "binary hashes do not match SHA256SUMS"
echo "$MANIFEST_SHA256  $ART/mainnet.manifest" | sha256sum -c --strict || die "mainnet.manifest is not Genesis-4"
[ -n "$CARRYOVER_GZ_SHA256" ] && echo "$CARRYOVER_GZ_SHA256  $ART/carryover.tsv.gz" | sha256sum -c --strict \
  || die "carryover.tsv.gz does not match carryover.tsv.gz.sha256 (the manifest commitment is checked again at start)"

# 2. Users, directories, files.
id bloch-l2-follower-main >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin bloch-l2-follower-main
run install -d -m 0755 /opt/bloch/l2-mainnet /etc/bloch-l2-mainnet /etc/bloch-l2-mainnet/public
run install -m 0755 "$ART/bloch-l2-native-follower" "$ART/bloch-l2-settled-rpc" /opt/bloch/l2-mainnet/
run install -m 0644 "$ART/SHA256SUMS" /opt/bloch/l2-mainnet/
run install -m 0644 "$ART/mainnet.manifest" /etc/bloch-l2-mainnet/public/mainnet.manifest
if [ $DRY = 1 ]; then echo "+ gunzip -c carryover.tsv.gz > /etc/bloch-l2-mainnet/public/carryover.tsv"
else gunzip -c "$ART/carryover.tsv.gz" > /etc/bloch-l2-mainnet/public/carryover.tsv; chmod 0644 /etc/bloch-l2-mainnet/public/carryover.tsv; fi
run install -d -m 0755 -o bloch-l2-follower-main -g bloch-l2-follower-main /var/lib/bloch-l2-mainnet-follower
STATE=/var/lib/bloch-l2-mainnet-rpc
run install -d -m 0700 -o "$CANON_USER" -g "$CANON_USER" $STATE

# 3. Units (not enabled, not started).
if [ $DRY = 1 ]; then echo "+ write follower.env, units, drop-in"; else
  printf 'BLOCH_L1_RPC_URL=%s\n' "$L1" > /etc/bloch-l2-mainnet/follower.env
  install -m 0644 "$HERE/bloch-l2-mainnet-follower.service" /etc/systemd/system/
  install -d /etc/systemd/system/bloch-l2-mainnet-follower.service.d
  printf '[Service]\nIPAddressAllow=localhost %s\n' "$(getent ahostsv4 "$L1_HOST" | awk 'NR==1{print $1}')" \
    > /etc/systemd/system/bloch-l2-mainnet-follower.service.d/l1-rpc.conf
  sed -e "s#@CANONICAL_USER@#$CANON_USER#g" -e "s#@CANONICAL@#$CANONICAL#g" -e "s#@STATE@#$STATE#g" -e "s#@TXPOOL@#$TXPOOL#g" \
    "$HERE/bloch-l2-mainnet-rpc.service" > /etc/systemd/system/bloch-l2-mainnet-rpc.service
  systemctl daemon-reload
fi
cat <<MSG
Installed, NOT started. To start (the first replay of ~155k L1 blocks takes ~30-40 min):
  sudo systemctl enable --now bloch-l2-mainnet-follower
  journalctl -fu bloch-l2-mainnet-follower        # wait for status.json with l2_genesis.finalized=true
  sudo systemctl enable --now bloch-l2-mainnet-rpc
  curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_finality","params":[]}'
MSG
