#!/bin/bash
# Install the Bloch L2 mainnet SHADOW producer. REVIEWED BY THE OPERATOR, RUN AS ROOT.
# The producer of record is the settler (settler_v3.py mainnet mode, install-settler-mainnet.py,
# user bloch-l2-mainnet-settler): it writes the canonical L2 database. This unit rebuilds every
# block the settler produced on its OWN database from the native view (+ the settler's DA batch)
# and stops (exit 3) on any difference, before the proof reaches L1. Install after the settler's
# `prepare` (it needs the settler user and /var/lib/bloch-l2-mainnet-settler/work).
#
#   install-shadow.sh OUT_DIR [--start]
#   install-shadow.sh --rollback
#
# OUT_DIR is build-sequencer.sh's WORK/out (bloch-l2-produce-dev, sequencer_mainnet.py, SHA256SUMS).
# What it does: verifies both files against the pins below, creates
# /var/lib/bloch-l2-mainnet-shadow/{work,tmp} owned by the settler user, writes the config, creates
# the shadow L2 database at the pinned mainnet genesis (refuses any other hash), runs a read-only
# `check` against the three mainnet nodes and installs the unit. It starts the unit only with
# --start. The shadow never signs, proves or submits and never opens the settler's database:
# starting it sends nothing to Bloch L1. It reads getl2settlement only.
#
# Rollback: stops and disables the unit, removes the unit file, and MOVES (never deletes)
# /opt/bloch/l2-mainnet-shadow, its config and /var/lib/bloch-l2-mainnet-shadow aside with a
# timestamp. The settler is not touched; nothing on L1 depends on the shadow.
set -euo pipefail
PRODUCE_SHA256=aedd83af1939e9559c9461fb355705552e4c4bcab807af51b0c11e3431e004cf
SEQUENCER_SHA256=15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2
UNIT=bloch-l2-mainnet-shadow.service
OPT=/opt/bloch/l2-mainnet-shadow
ETC=/etc/bloch-l2-mainnet-shadow
VAR=/var/lib/bloch-l2-mainnet-shadow
USER_=bloch-l2-mainnet-settler
SETTLER_WORK=/var/lib/bloch-l2-mainnet-settler/work
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  systemctl disable --now "$UNIT" 2>/dev/null || true
  rm -f "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  [ -d "$OPT" ] && mv "$OPT" "$OPT.rollback-$TS"
  [ -d "$ETC" ] && mv "$ETC" "$ETC.rollback-$TS"
  [ -d "$VAR" ] && mv "$VAR" "$VAR.rollback-$TS"
  echo "rolled back at $TS (data kept as *.rollback-$TS; settler untouched)"
  exit 0
fi

OUT=$(cd "${1:?usage: install-shadow.sh OUT_DIR [--start] | --rollback}" && pwd)
START=${2:-}
[ -z "$START" ] || [ "$START" = "--start" ] || { echo "unknown option $START"; exit 1; }
echo "$PRODUCE_SHA256  $OUT/bloch-l2-produce-dev" | sha256sum -c -
echo "$SEQUENCER_SHA256  $OUT/sequencer_mainnet.py" | sha256sum -c -
[ -f "$HERE/$UNIT" ] || { echo "missing $HERE/$UNIT"; exit 1; }
if systemctl is-active --quiet "$UNIT"; then echo "$UNIT is running; roll back first"; exit 1; fi
[ ! -e "$VAR/canonical" ] || { echo "$VAR/canonical exists; roll back first (it is moved aside, not deleted)"; exit 1; }

id "$USER_" >/dev/null 2>&1 || { echo "user $USER_ missing: run install-settler-mainnet.py prepare first"; exit 1; }
[ -d "$SETTLER_WORK" ] || { echo "$SETTLER_WORK missing: run install-settler-mainnet.py prepare first"; exit 1; }
install -d -m 0755 "$OPT"
install -m 0755 "$OUT/bloch-l2-produce-dev" "$OPT/bloch-l2-produce-dev"
install -m 0644 "$OUT/sequencer_mainnet.py" "$OPT/sequencer_mainnet.py"
install -d -m 0700 -o "$USER_" -g "$USER_" "$VAR" "$VAR/work" "$VAR/tmp"
install -d -m 0755 "$ETC"
cat > "$ETC/config.json" <<JSON
{
  "produce": "$OPT/bloch-l2-produce-dev",
  "produce_sha256": "$PRODUCE_SHA256",
  "l2_db": "$VAR/canonical",
  "workdir": "$VAR/work",
  "rpc_urls": ["http://80.240.16.185:8080", "http://199.247.22.8:8080", "http://45.77.67.251:8080"],
  "rpc_quorum": 2,
  "poll_seconds": 15,
  "settler_workdir": "$SETTLER_WORK"
}
JSON
chmod 0644 "$ETC/config.json"

S="runuser -u $USER_ -- env BLOCH_SEQUENCER_CONFIG=$ETC/config.json TMPDIR=$VAR/tmp /usr/bin/python3 -u $OPT/sequencer_mainnet.py"
$S init        # shadow database; refuses unless the genesis is 632e45ae...f468 / 2ad7e807...c05d
$S check || { echo "read-only check failed (see above); unit NOT installed"; exit 1; }
install -m 0644 "$HERE/$UNIT" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
if [ "$START" = "--start" ]; then
  systemctl enable --now "$UNIT"
  sleep 20
  journalctl -u "$UNIT" -n 20 --no-pager
else
  echo "installed, not started: systemctl enable --now $UNIT"
fi
