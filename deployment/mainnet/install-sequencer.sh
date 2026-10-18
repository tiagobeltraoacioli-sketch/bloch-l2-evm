#!/bin/bash
# Install the Bloch L2 mainnet block producer (sequencer stage). REVIEWED BY THE OPERATOR, RUN AS ROOT.
#
#   install-sequencer.sh OUT_DIR [--start]
#   install-sequencer.sh --rollback
#
# OUT_DIR is build-sequencer.sh's WORK/out (bloch-l2-produce-dev, sequencer_mainnet.py, SHA256SUMS).
# What it does: verifies both files against the pins below, creates the system user bloch-l2-main
# and /var/lib/bloch-l2-mainnet/{canonical,work,txpool,tmp}, writes the config, creates the
# canonical L2 database at the pinned mainnet genesis (refuses any other hash), runs a read-only
# `check` against the three mainnet nodes and installs the unit. It starts the unit only with
# --start. The producer never signs, proves or submits: starting it sends nothing to Bloch L1.
# It reads getl2settlement only.
#
# Rollback: stops and disables the unit, removes the unit file and /opt/bloch/l2-mainnet-sequencer,
# and MOVES (never deletes) /var/lib/bloch-l2-mainnet and the config aside with a timestamp. No
# on-chain state depends on this host: an L2 block that was not settled simply does not exist, and
# a new install rebuilds the same deterministic block from the same native source.
set -euo pipefail
PRODUCE_SHA256=__PRODUCE_SHA256__
SEQUENCER_SHA256=__SEQUENCER_SHA256__
UNIT=bloch-l2-mainnet-sequencer.service
OPT=/opt/bloch/l2-mainnet-sequencer
ETC=/etc/bloch-l2-mainnet-sequencer
VAR=/var/lib/bloch-l2-mainnet
USER_=bloch-l2-main
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
  echo "rolled back at $TS (data kept as *.rollback-$TS; user $USER_ kept)"
  exit 0
fi

OUT=$(cd "${1:?usage: install-sequencer.sh OUT_DIR [--start] | --rollback}" && pwd)
START=${2:-}
[ -z "$START" ] || [ "$START" = "--start" ] || { echo "unknown option $START"; exit 1; }
echo "$PRODUCE_SHA256  $OUT/bloch-l2-produce-dev" | sha256sum -c -
echo "$SEQUENCER_SHA256  $OUT/sequencer_mainnet.py" | sha256sum -c -
[ -f "$HERE/$UNIT" ] || { echo "missing $HERE/$UNIT"; exit 1; }
if systemctl is-active --quiet "$UNIT"; then echo "$UNIT is running; roll back first"; exit 1; fi
[ ! -e "$VAR/canonical" ] || { echo "$VAR/canonical exists; roll back first (it is moved aside, not deleted)"; exit 1; }

id "$USER_" >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin "$USER_"
install -d -m 0755 "$OPT"
install -m 0755 "$OUT/bloch-l2-produce-dev" "$OPT/bloch-l2-produce-dev"
install -m 0644 "$OUT/sequencer_mainnet.py" "$OPT/sequencer_mainnet.py"
install -d -m 0750 -o "$USER_" -g "$USER_" "$VAR" "$VAR/work" "$VAR/txpool" "$VAR/tmp"
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
  "user_transactions": false,
  "txpool_dir": "$VAR/txpool",
  "max_block_gas": 15000000,
  "max_block_bytes": 114688,
  "max_block_txs": 256
}
JSON
chmod 0644 "$ETC/config.json"

S="runuser -u $USER_ -- env BLOCH_SEQUENCER_CONFIG=$ETC/config.json TMPDIR=$VAR/tmp /usr/bin/python3 -u $OPT/sequencer_mainnet.py"
$S init        # refuses unless the genesis is 632e45ae...f468 / 2ad7e807...c05d
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
