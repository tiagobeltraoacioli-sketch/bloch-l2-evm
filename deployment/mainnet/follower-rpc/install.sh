#!/bin/bash
# Install (do NOT start) the Bloch L2 MAINNET follower and settled RPC units.
# Run as root on the L2 host, from a directory holding the built binaries
# (build.sh OUT), their SHA256SUMS, this directory's units, mainnet.manifest
# and carryover.tsv.gz (both from bloch-sis-pow 78b7343a).
#
#   sudo ./install.sh --artifacts DIR --l1-rpc-url http://HOST:PORT \
#        --canonical /var/lib/bloch-l2-mainnet/canonical --canonical-user bloch-l2-mainnet \
#        --txpool /var/lib/bloch-l2-mainnet/txpool [--rpc-user USER --read-group GROUP] [--dry-run] [--allow-unsigned]
#        [--required-tip-file /var/lib/bloch-l2-mainnet-settler/work/sequencer-policy.json]
#
# --rpc-user/--read-group (review r10 decision 4; the sequencer host uses bloch-l2-mainnet-rpc and
# bloch-l2-mainnet-l2read, created by install-settler-mainnet.py prepare): the RPC runs as its own system user
# in GROUP, the read group of the database writer, instead of as --canonical-user. Its unit makes the MDBX lock
# file group-writable before every start (l2_read_access.py). Without them it runs as --canonical-user.
#
# --required-tip-file (user transactions under sequencer policy v2 only; never at the deposit-only launch): the
# settler's policy state, which carries the required tip and the admission snapshot. The RPC then suggests that tip
# and refuses a transaction that underpays its new storage slots. The file is group-readable through the settler's
# read group, so this needs --rpc-user/--read-group. Without the option the unit's command line is unchanged.
# The RPC always gets --min-tip-wei MIN_TIP_WEI (below), with or without the option: the tip floor the settler's producer applies
# (install-settler-mainnet.py MIN_TIP_WEI, the same number). The RPC's compiled default is 0.1 gwei; without the
# flag it would spool transactions between the two floors that the producer never includes.
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
ART= L1= CANONICAL= CANON_USER= TXPOOL= DRY=0 UNSIGNED=0 RPC_USER= READ_GROUP= TIP_FILE=
while [ $# -gt 0 ]; do
  case $1 in
    --artifacts) ART=$2; shift 2;; --l1-rpc-url) L1=$2; shift 2;;
    --canonical) CANONICAL=$2; shift 2;; --canonical-user) CANON_USER=$2; shift 2;;
    --txpool) TXPOOL=$2; shift 2;; --dry-run) DRY=1; shift;; --allow-unsigned) UNSIGNED=1; shift;;
    --rpc-user) RPC_USER=$2; shift 2;; --read-group) READ_GROUP=$2; shift 2;;
    --required-tip-file) TIP_FILE=$2; shift 2;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ -n "$ART" ] && [ -n "$L1" ] && [ -n "$CANONICAL" ] && [ -n "$CANON_USER" ] && [ -n "$TXPOOL" ] || { sed -n 2,33p "$0"; exit 2; }
[ -n "$RPC_USER$READ_GROUP" ] && { [ -z "$RPC_USER" ] || [ -z "$READ_GROUP" ]; } && { echo "install.sh: --rpc-user and --read-group go together" >&2; exit 2; }
if [ -n "$TIP_FILE" ]; then
  # It goes into a unit's command line: an absolute path of plain characters, nothing systemd would expand or split.
  [[ $TIP_FILE =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ $TIP_FILE != *..* ]] || { echo "install.sh: --required-tip-file must be an absolute path of letters, digits, '.', '_', '-' and '/'" >&2; exit 2; }
  [ -n "$RPC_USER" ] || { echo "install.sh: --required-tip-file needs --rpc-user and --read-group (the file is read through the settler's read group)" >&2; exit 2; }
fi
run() { echo "+ $*"; [ $DRY = 1 ] || "$@"; }
die() { trap - ERR; echo "install.sh: $*" >&2; exit 1; }
R=${BLOCH_L2_INSTALL_ROOT:-}
OPT=$R/opt/bloch/l2-mainnet ETC=$R/etc/bloch-l2-mainnet UNITS=$R/etc/systemd/system

# The L2 tip floor, 1 gwei: equal to install-settler-mainnet.py MIN_TIP_WEI (a test compares them). Passed to the RPC on
# every install, with or without --required-tip-file (review R384-2: without it the RPC kept the compiled 0.1 gwei,
# suggested it to wallets and spooled transactions the producer never includes).
MIN_TIP_WEI=1000000000
MANIFEST_SHA256=7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
# The launch release this kit installs: SHA-256 of its signed SHA256SUMS (release bloch-l2-2026-11-03-next-native-78d4921c,
# build 926d2cf). A release the same key signed earlier or later is refused (review R308-16); a later release ships
# with a kit that names it here.
RELEASE_SHA256SUMS_SHA256=6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19
CARRYOVER_GZ_SHA256=$(cut -d' ' -f1 "$ART/carryover.tsv.gz.sha256" 2>/dev/null || true)
[[ $L1 =~ ^http://([A-Za-z0-9.-]+):([0-9]+)/?$ ]] || die "--l1-rpc-url must be http://HOST:PORT"
L1_HOST=${BASH_REMATCH[1]}
[ "$(id -u)" = 0 ] || [ $DRY = 1 ] || [ -n "$R" ] || die "run as root"
id "$CANON_USER" >/dev/null 2>&1 || die "canonical user $CANON_USER does not exist (sequencer installs it)"
[ -d "$CANONICAL/db" ] && [ -d "$CANONICAL/static" ] && [ -d "$CANONICAL/rocks" ] || die "$CANONICAL is not an initialized L2 database"
[ -d "$TXPOOL" ] || die "$TXPOOL missing (sequencer spool)"
if [ -n "$RPC_USER" ]; then
  [ "$RPC_USER" != "$CANON_USER" ] || die "--rpc-user must differ from --canonical-user"
  getent group "$READ_GROUP" >/dev/null || die "read group $READ_GROUP missing (install-settler-mainnet.py prepare creates it)"
  [ -f "$CANONICAL/db/mdbx.lck" ] || die "$CANONICAL/db/mdbx.lck missing (not an initialized L2 database)"
fi
if [ -n "$TIP_FILE" ]; then
  [ -d "$R$(dirname "$TIP_FILE")" ] || die "$(dirname "$TIP_FILE") missing (the settler's work directory; install-settler-mainnet.py prepare creates it)"
fi
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
  python3 -I "$HERE/../verify_release_signature.py" --release-dir "$ART" --expect-sha256 "$RELEASE_SHA256SUMS_SHA256" \
    || die "release signature check failed: $ART needs the owner's SHA256SUMS.minisig over the launch release ${RELEASE_SHA256SUMS_SHA256:0:8}… (docs/RELEASE-SIGNING.md)"
fi
# What gets installed is what was checked: the two lines are taken once, now, and the copies are hashed in place.
WANT_FOLLOWER=$(awk '$2 == "bloch-l2-native-follower" {print $1}' "$ART/SHA256SUMS")
WANT_RPC=$(awk '$2 == "bloch-l2-settled-rpc" {print $1}' "$ART/SHA256SUMS")
[[ $WANT_FOLLOWER$WANT_RPC =~ ^[0-9a-f]{128}$ ]] || die "$ART/SHA256SUMS has no line for the follower or the settled RPC"

# 1. Artifacts and public inputs, by hash.
(cd "$ART" && sha256sum -c --strict SHA256SUMS) || die "binary hashes do not match SHA256SUMS"
echo "$MANIFEST_SHA256  $ART/mainnet.manifest" | sha256sum -c --strict || die "mainnet.manifest is not Genesis-4"
[ -n "$CARRYOVER_GZ_SHA256" ] && echo "$CARRYOVER_GZ_SHA256  $ART/carryover.tsv.gz" | sha256sum -c --strict \
  || die "carryover.tsv.gz does not match carryover.tsv.gz.sha256 (the manifest commitment is checked again at start)"

# 2. Users, directories, files.
id bloch-l2-follower-main >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin bloch-l2-follower-main
if [ -n "$RPC_USER" ]; then
  id "$RPC_USER" >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin --groups "$READ_GROUP" "$RPC_USER"
  # The own user must reach the database through the writer's read group alone (and the spool, to write it).
  if [ $DRY = 0 ]; then
    runuser -u "$RPC_USER" -- test -r "$CANONICAL/db/mdbx.dat" -a -x "$CANONICAL/rocks" -a -r "$CANONICAL/static" \
      || die "$RPC_USER cannot read $CANONICAL through group $READ_GROUP (prepare by an older installer?)"
    runuser -u "$RPC_USER" -- test -w "$TXPOOL" -a -x "$TXPOOL" || die "$RPC_USER cannot write the spool $TXPOOL"
  fi
fi
UNIT_USER=${RPC_USER:-$CANON_USER}
run install -d -m 0755 $OPT $ETC $ETC/public
run install -m 0755 "$ART/bloch-l2-native-follower" "$ART/bloch-l2-settled-rpc" $OPT/
if [ $DRY = 0 ]; then
  printf '%s  %s\n%s  %s\n' "$WANT_FOLLOWER" "$OPT/bloch-l2-native-follower" "$WANT_RPC" "$OPT/bloch-l2-settled-rpc" | sha256sum -c --strict --quiet \
    || die "the installed copies in $OPT are not the files that were checked in $ART (changed during the install?)"
fi
run install -m 0755 "$HERE/l2_read_access.py" $OPT/
run install -m 0644 "$ART/SHA256SUMS" $OPT/
run install -m 0644 "$ART/mainnet.manifest" $ETC/public/mainnet.manifest
if [ $DRY = 1 ]; then echo "+ gunzip -c carryover.tsv.gz > $ETC/public/carryover.tsv"
else gunzip -c "$ART/carryover.tsv.gz" > $ETC/public/carryover.tsv; chmod 0644 $ETC/public/carryover.tsv; fi
run install -d -m 0755 -o bloch-l2-follower-main -g bloch-l2-follower-main $R/var/lib/bloch-l2-mainnet-follower
STATE=/var/lib/bloch-l2-mainnet-rpc
run install -d -m 0700 -o "$UNIT_USER" -g "$UNIT_USER" $R$STATE

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
  if [ -n "$RPC_USER" ]; then KEEP=(-e "s#@READ_GROUP@#$READ_GROUP#g"); else KEEP=(-e '/@READ_GROUP@/d'); fi
  sed "${KEEP[@]}" -e "s#@RPC_USER@#$UNIT_USER#g" -e "s#@CANONICAL_USER@#$CANON_USER#g" -e "s#@CANONICAL@#$CANONICAL#g" \
    -e "s#@STATE@#$STATE#g" -e "s#@TXPOOL@#$TXPOOL#g" -e "s#@REQUIRED_TIP@#${TIP_FILE:+ --required-tip-file $TIP_FILE} --min-tip-wei $MIN_TIP_WEI#g" "$HERE/bloch-l2-mainnet-rpc.service" > $UNITS/bloch-l2-mainnet-rpc.service
  install -m 0644 "$HERE/bloch-l2-mainnet-rpc-restart.path" "$HERE/bloch-l2-mainnet-rpc-restart.service" $UNITS/
  systemctl daemon-reload
fi
cat <<MSG
Installed, NOT started. To start (the first replay of ~155k L1 blocks takes ~30-40 min):
  sudo systemctl enable --now bloch-l2-mainnet-follower
  journalctl -fu bloch-l2-mainnet-follower        # wait for status.json with l2_genesis.finalized=true
  sudo systemctl enable --now bloch-l2-mainnet-rpc
  curl -s --retry 30 --retry-delay 1 --retry-connrefused -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_finality","params":[]}'
Only on the sequencer host with foreign_recovery on, so the RPC reopens the worker's swapped database:
  sudo systemctl enable --now bloch-l2-mainnet-rpc-restart.path
MSG
