#!/bin/bash
# Install (do NOT start) the Bloch L2 MAINNET follower and settled RPC units.
# Run as root on the L2 host, from a directory holding the built binaries
# (build.sh OUT), their SHA256SUMS, this directory's units, mainnet.manifest
# and carryover.tsv.gz (both from bloch-sis-pow 78b7343a).
#
#   sudo ./install.sh --artifacts DIR --l1-rpc-url http://HOST:PORT \
#        --canonical /var/lib/bloch-l2-mainnet/canonical --canonical-user bloch-l2-mainnet \
#        --txpool /var/lib/bloch-l2-mainnet/txpool [--dry-run] [--allow-unsigned]
#
# DIR must hold the owner's SHA256SUMS.minisig and release.json: the release signature is checked
# against the pinned release key (../verify_release_signature.py) before anything else.
# --allow-unsigned skips that check, for private rehearsals only.
#
# Refuses to overwrite an existing installation (installed unit files). A run that failed after
# copying the binaries is resumed: the files already in /opt/bloch/l2-mainnet must equal this
# release's SHA256SUMS, or it refuses. Every failure prints the line and command that failed.
# Prints the start commands.
#
# BLOCH_L2_INSTALL_ROOT (tests only): a fake root that prefixes every system path; useradd,
# install -o/-g, getent and systemctl then come from the test's PATH.
set -Eeuo pipefail
trap 'echo "install.sh: FAILED at line $LINENO: $BASH_COMMAND (nothing was started; fix the cause and run it again: it resumes)" >&2' ERR
HERE=$(cd "$(dirname "$0")" && pwd)
ART= L1= CANONICAL= CANON_USER= TXPOOL= DRY=0 UNSIGNED=0
while [ $# -gt 0 ]; do
  case $1 in
    --artifacts) ART=$2; shift 2;; --l1-rpc-url) L1=$2; shift 2;;
    --canonical) CANONICAL=$2; shift 2;; --canonical-user) CANON_USER=$2; shift 2;;
    --txpool) TXPOOL=$2; shift 2;; --dry-run) DRY=1; shift;; --allow-unsigned) UNSIGNED=1; shift;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ -n "$ART" ] && [ -n "$L1" ] && [ -n "$CANONICAL" ] && [ -n "$CANON_USER" ] && [ -n "$TXPOOL" ] || { sed -n 2,16p "$0"; exit 2; }
run() { echo "+ $*"; [ $DRY = 1 ] || "$@"; }
die() { trap - ERR; echo "install.sh: $*" >&2; exit 1; }
R=${BLOCH_L2_INSTALL_ROOT:-}
OPT=$R/opt/bloch/l2-mainnet ETC=$R/etc/bloch-l2-mainnet UNITS=$R/etc/systemd/system

MANIFEST_SHA256=7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
CARRYOVER_GZ_SHA256=$(cut -d' ' -f1 "$ART/carryover.tsv.gz.sha256" 2>/dev/null || true)
[[ $L1 =~ ^http://([A-Za-z0-9.-]+):([0-9]+)/?$ ]] || die "--l1-rpc-url must be http://HOST:PORT"
L1_HOST=${BASH_REMATCH[1]}
[ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$R" ] || die "run as root"
id "$CANON_USER" >/dev/null 2>&1 || die "canonical user $CANON_USER does not exist (sequencer installs it)"
[ -d "$CANONICAL/db" ] && [ -d "$CANONICAL/static" ] && [ -d "$CANONICAL/rocks" ] || die "$CANONICAL is not an initialized L2 database"
[ -d "$TXPOOL" ] || die "$TXPOOL missing (sequencer spool)"
for unit in bloch-l2-mainnet-follower bloch-l2-mainnet-rpc; do
  [ ! -e $UNITS/$unit.service ] || die "$UNITS/$unit.service exists; refusing to overwrite"
done
RESUME=0
if [ -e $OPT/bloch-l2-native-follower ] || [ -e $OPT/bloch-l2-settled-rpc ] || [ -e $OPT/SHA256SUMS ]; then
  # A previous run stopped before the units were written: resume only over this exact release.
  for f in bloch-l2-native-follower bloch-l2-settled-rpc; do
    want=$(awk -v f="$f" '$2 == f {print $1}' "$ART/SHA256SUMS")
    [ -n "$want" ] || die "$ART/SHA256SUMS has no line for $f"
    [ ! -e $OPT/$f ] || echo "$want  $OPT/$f" | sha256sum -c --strict --quiet \
      || die "$OPT/$f is not this release's $f; refusing to overwrite another installation"
  done
  [ ! -e $OPT/SHA256SUMS ] || cmp -s $OPT/SHA256SUMS "$ART/SHA256SUMS" \
    || die "$OPT/SHA256SUMS is another release's; refusing to overwrite another installation"
  RESUME=1
  echo "resuming an incomplete installation of this release in $OPT (no unit file was written)"
fi

# 0. Release signature (owner's key, pinned in verify_release_signature.py) and every SHA256SUMS line.
if [ $UNSIGNED = 1 ]; then
  echo "WARNING: --allow-unsigned: the release signature is NOT checked (private rehearsals only)" >&2
else
  python3 -I "$HERE/../verify_release_signature.py" --release-dir "$ART" \
    || die "release signature check failed: $ART needs the owner's SHA256SUMS.minisig (docs/RELEASE-SIGNING.md)"
fi

# 1. Artifacts and public inputs, by hash.
(cd "$ART" && sha256sum -c --strict SHA256SUMS) || die "binary hashes do not match SHA256SUMS"
echo "$MANIFEST_SHA256  $ART/mainnet.manifest" | sha256sum -c --strict || die "mainnet.manifest is not Genesis-4"
[ -n "$CARRYOVER_GZ_SHA256" ] && echo "$CARRYOVER_GZ_SHA256  $ART/carryover.tsv.gz" | sha256sum -c --strict \
  || die "carryover.tsv.gz does not match carryover.tsv.gz.sha256 (the manifest commitment is checked again at start)"

# 2. Users, directories, files.
id bloch-l2-follower-main >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin bloch-l2-follower-main
run install -d -m 0755 $OPT $ETC $ETC/public
run install -m 0755 "$ART/bloch-l2-native-follower" "$ART/bloch-l2-settled-rpc" $OPT/
run install -m 0644 "$ART/SHA256SUMS" $OPT/
run install -m 0644 "$ART/mainnet.manifest" $ETC/public/mainnet.manifest
if [ $DRY = 1 ]; then echo "+ gunzip -c carryover.tsv.gz > $ETC/public/carryover.tsv"
else gunzip -c "$ART/carryover.tsv.gz" > $ETC/public/carryover.tsv; chmod 0644 $ETC/public/carryover.tsv; fi
run install -d -m 0755 -o bloch-l2-follower-main -g bloch-l2-follower-main $R/var/lib/bloch-l2-mainnet-follower
STATE=/var/lib/bloch-l2-mainnet-rpc
run install -d -m 0700 -o "$CANON_USER" -g "$CANON_USER" $R$STATE

# 3. Units (not enabled, not started).
if [ $DRY = 1 ]; then echo "+ write follower.env, units, drop-in"; else
  # A reinstall keeps a host's chosen status schema; v2 is the unit's default.
  # (A fresh host has no follower.env: that is not an error.)
  SCHEMA=
  if [ -f $ETC/follower.env ]; then SCHEMA=$(sed -n 's/^BLOCH_L2_STATUS_SCHEMA=//p' $ETC/follower.env | tail -n 1); fi
  L1_IP=$(getent ahostsv4 "$L1_HOST" | awk 'NR==1{print $1}') || true
  [ -n "$L1_IP" ] || die "cannot resolve the L1 RPC host $L1_HOST to an IPv4 address (needed for IPAddressAllow)"
  printf 'BLOCH_L1_RPC_URL=%s\n' "$L1" > $ETC/follower.env
  if [ -n "$SCHEMA" ]; then printf 'BLOCH_L2_STATUS_SCHEMA=%s\n' "$SCHEMA" >> $ETC/follower.env; fi
  install -m 0644 "$HERE/bloch-l2-mainnet-follower.service" $UNITS/
  install -d $UNITS/bloch-l2-mainnet-follower.service.d
  printf '[Service]\nIPAddressAllow=localhost %s\n' "$L1_IP" > $UNITS/bloch-l2-mainnet-follower.service.d/l1-rpc.conf
  sed -e "s#@CANONICAL_USER@#$CANON_USER#g" -e "s#@CANONICAL@#$CANONICAL#g" -e "s#@STATE@#$STATE#g" -e "s#@TXPOOL@#$TXPOOL#g" \
    "$HERE/bloch-l2-mainnet-rpc.service" > $UNITS/bloch-l2-mainnet-rpc.service
  install -m 0644 "$HERE/bloch-l2-mainnet-rpc-restart.path" "$HERE/bloch-l2-mainnet-rpc-restart.service" $UNITS/
  systemctl daemon-reload
fi
cat <<MSG
Installed, NOT started. To start (the first replay of ~155k L1 blocks takes ~30-40 min):
  sudo systemctl enable --now bloch-l2-mainnet-follower
  journalctl -fu bloch-l2-mainnet-follower        # wait for status.json with l2_genesis.finalized=true
  sudo systemctl enable --now bloch-l2-mainnet-rpc
  curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_finality","params":[]}'
Only on the sequencer host with foreign_recovery on, so the RPC reopens the worker's swapped database:
  sudo systemctl enable --now bloch-l2-mainnet-rpc-restart.path
MSG
