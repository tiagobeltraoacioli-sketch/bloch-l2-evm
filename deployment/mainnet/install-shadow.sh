#!/bin/bash
# Install the Bloch L2 mainnet SHADOW producer. REVIEWED BY THE OPERATOR, RUN AS ROOT.
# The producer of record is the settler (settler_v3.py mainnet mode, install-settler-mainnet.py,
# user bloch-l2-mainnet-settler): it writes the canonical L2 database. This unit rebuilds every
# block the settler produced on its OWN database from the native view (+ the settler's DA batch)
# and stops (exit 3) on any difference, before the proof reaches L1. Install after the settler's
# `prepare` (it needs the settler user and /var/lib/bloch-l2-mainnet-settler/work).
#
#   install-shadow.sh --verify OUT_DIR     (no root: pin + build.json checks only, changes nothing)
#   install-shadow.sh OUT_DIR [--start]
#   install-shadow.sh --rollback
#
# OUT_DIR is build-release.sh's OUT of the v2.1 L2 build `bloch-l2-2026-10-30-v21-native-78d4921c` (L2 18b9e1d1, native 78d4921c
# = the armed L1 release with HF1 e7180/7186, HF2 e7270, HF3 e7360, KES enforce e8620; settlement-
# recovery lock 26bf4453...): bloch-l2-produce-dev fb0d5313..., sequencer_mainnet.py 15daa26f...
# (unchanged since the RC), SHA256SUMS and build.json.
# The producer RUNS the native transition, so a shadow built against a pre-HF native (the RC pin
# 192eda33..., native 78b7343a) halts at HF1. Install the v2 build before epoch 7178.
# What it does: verifies both files against the pins below and build.json against the v2 build
# (commit, native, lock, compiled L1 gates), requires the settler's producer (if configured) to be
# the same v2 build, creates /var/lib/bloch-l2-mainnet-shadow/{work,tmp} owned by the settler user,
# writes the config, creates the shadow L2 database at the pinned mainnet genesis (refuses any other
# hash), runs a read-only `check` against the three mainnet nodes and installs the unit. It starts the
# unit only with --start. The shadow never signs, proves or submits and never opens the settler's
# database: starting it sends nothing to Bloch L1. It reads getl2settlement only.
#
# Rollback: stops and disables the unit, removes the unit file, and MOVES (never deletes)
# /opt/bloch/l2-mainnet-shadow, its config and /var/lib/bloch-l2-mainnet-shadow aside with a
# timestamp. The settler is not touched; nothing on L1 depends on the shadow.
set -euo pipefail
# v2.1 build bloch-l2-2026-10-30-v21-native-78d4921c (out/SHA256SUMS). v2 was 7c1cc62b... (no flag-day rebuild fix). The RC pin was 192eda33... (native 78b7343a, pre-HF).
PRODUCE_SHA256=fb0d531311d4f19a97f0839968146f5737acf57eb313fc93972ec215de950be9
SEQUENCER_SHA256=15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2
L2_COMMIT=18b9e1d1645782b8c3cb2c095161f7649dd32d72
NATIVE_COMMIT=78d4921c3ec6ba41829f3878eed47f8d3bb96230
NATIVE_LOCK_SHA256=26bf44539b996809bd75164a488d8a30137507716d06990721056a213364aef8
SETTLER_CONFIG=/etc/bloch-l2-mainnet-settler/config.json
UNIT=bloch-l2-mainnet-shadow.service
OPT=/opt/bloch/l2-mainnet-shadow
ETC=/etc/bloch-l2-mainnet-shadow
VAR=/var/lib/bloch-l2-mainnet-shadow
USER_=bloch-l2-mainnet-settler
SETTLER_WORK=/var/lib/bloch-l2-mainnet-settler/work
HERE=$(cd "$(dirname "$0")" && pwd)

verify_out() {
  local out=$1
  echo "$PRODUCE_SHA256  $out/bloch-l2-produce-dev" | sha256sum -c -
  echo "$SEQUENCER_SHA256  $out/sequencer_mainnet.py" | sha256sum -c -
  (cd "$out" && sha256sum -c --strict --ignore-missing SHA256SUMS)
  [ -f "$out/build.json" ] || { echo "missing $out/build.json (not a build-release.sh OUT)"; return 1; }
  python3 -I - "$out/build.json" "$L2_COMMIT" "$NATIVE_COMMIT" "$NATIVE_LOCK_SHA256" "$PRODUCE_SHA256" <<'PY'
import json, sys
path, l2, native, lock, produce = sys.argv[1:]
b = json.load(open(path))
gates = b.get('l1_activation_epochs') or {}
want = {'HF1_CLAIM_FINALITY_EPOCH': 7180, 'HF1_FROZEN_FINALITY_SET_EPOCH': 7180, 'HF1_OWN_TARGET_VOTES_EPOCH': 7186,
        'HF2_SLASHING_V2_EPOCH': 7270, 'HF2_GROWTH_CAP_EPOCH': 7270, 'SIG_CANONICAL_ACTIVATION_EPOCH': 7270,
        'HF3_KES_EPOCH': 7360, 'HF3_SLH_SUITE_EPOCH': 7360, 'HF3_PQ_MIGRATION_EPOCH': 7360,
        'HF3_KES_ENFORCE_EPOCH': 8620}
errors = []
if b.get('chain_id') != 700770: errors.append(f"chain_id {b.get('chain_id')}")
if b.get('l2_commit') != l2: errors.append(f"l2_commit {b.get('l2_commit')} != {l2}")
if not str(b.get('native', '')).startswith(native): errors.append(f"native {b.get('native')} != {native}")
if b.get('settlement_recovery_lock_sha256') != lock: errors.append('settlement-recovery lock is not the v2 lock')
if (b.get('sha256') or {}).get('bloch-l2-produce-dev') != produce: errors.append('build.json produce-dev sha differs')
if (b.get('l2_genesis') or {}).get('hash') != '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468':
    errors.append('L2 genesis is not the pin')
errors += [f'{k} compiled {gates.get(k)} != L1 release {v}' for k, v in want.items() if gates.get(k) != v]
if errors:
    sys.exit('build.json is not the v2 build: ' + '; '.join(errors))
print(f"build.json OK: L2 {l2[:8]}, native {native[:8]}, HF1 7180/7186, HF2 7270, HF3 7360, KES enforce 8620")
PY
}

if [ "${1:-}" = "--verify" ]; then
  verify_out "$(cd "${2:?usage: install-shadow.sh --verify OUT_DIR}" && pwd)"
  echo "verify OK (nothing installed)"
  exit 0
fi

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
verify_out "$OUT"
if [ -f "$SETTLER_CONFIG" ]; then
  SETTLER_PRODUCE=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("produce",""))' "$SETTLER_CONFIG")
  if [ -n "$SETTLER_PRODUCE" ]; then
    echo "$PRODUCE_SHA256  $SETTLER_PRODUCE" | sha256sum -c - || {
      echo "the settler's producer $SETTLER_PRODUCE is not the v2 build: upgrade the settler first"; exit 1; }
  fi
fi
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
