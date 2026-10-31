#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rehearsal of `install-attestor.sh upgrade` / `upgrade-rollback` with THROWAWAY keys on --prefix installs
# written by the OLD kit (no follower pin), against the live L1 mainnet through the public read-only RPCs.
# Linux host; no root, no systemd. Each subcommand is one stage (the follower re-verify takes ~50 min).
#
#   export OLD_KIT=.../attestor (kit before 2026-10-30)  OLD_BIN_DIR=DIR (RC follower+produce)
#          NEW_BIN_DIR=DIR (v2 follower+produce)  BLOCH_POS=... MAINNET_MANIFEST=... CARRYOVER_DIR=...
#          SEED_NATIVE=DIR (a follower's native/ state to copy)  WORK=/scratch/dir
#   rehearse_upgrade.sh setup               old-kit owner flow (hosts 0,2,4) + seed follower state + N1
#   rehearse_upgrade.sh upgrade I [opts]    new kit: install-attestor.sh upgrade on host I
#   rehearse_upgrade.sh negatives I         N2..N5 on an upgraded host I
#   rehearse_upgrade.sh rollback I [opts]   new kit: install-attestor.sh upgrade-rollback on host I
set -euo pipefail
K=$(cd "$(dirname "$0")/.." && pwd)
W=${WORK:?}
step() { printf '\n######## %s %s\n' "$(date -u +%FT%TZ)" "$*"; }
sethash() { cat "$W/owner/SETHASH"; }
host() { echo "$W/owner/host-$1"; }
upgrade_cmd() {  # upgrade_cmd I SUBCOMMAND [opts]
  local i=$1 sub=$2 H; H=$(host "$1"); shift 2
  CREDENTIALS_DIRECTORY=$H/cred bash "$K/install-attestor.sh" "$sub" --prefix "$H/root" \
    --service-cmd "bash $K/tests/rehearsal_services.sh $H/root $(sethash)" \
    --check-cmd "python3 -I $K/tests/rehearsal_check.py $H/root/opt/bloch/l2-attestor $H/root/etc/bloch-l2-attestor/config.json $(sethash) check" \
    "$@"
}
check_new_agent() {  # check_new_agent I: this kit's agent (not the installed one) on host I's config
  local H; H=$(host "$1")
  CREDENTIALS_DIRECTORY=$H/cred python3 -I "$K/tests/rehearsal_check.py" "$K" "$H/root/etc/bloch-l2-attestor/config.json" "$(sethash)" check
}

case ${1:-} in
setup)
  : "${OLD_KIT:?}" "${OLD_BIN_DIR:?}" "${SEED_NATIVE:?}"
  [ ! -e "$W/owner" ] || { echo "$W/owner exists; give a fresh WORK" >&2; exit 1; }
  mkdir -p "$W"
  step "S1. OLD kit owner flow (throwaway keys; hosts 0, 2, 4 installed with the RC binaries)"
  WORK=$W/owner PLACEHOLDER_BIN_DIR=$OLD_BIN_DIR bash "$OLD_KIT/tests/rehearse_owner_flow.sh" > "$W/S1-owner-flow.log" 2>&1
  tail -1 "$W/S1-owner-flow.log"
  sed -n 's/^throwaway set //p' "$W/S1-owner-flow.log" | head -1 > "$W/owner/SETHASH"; echo "throwaway set $(sethash)"
  for i in 0 2 4; do
    C=$(host $i)/root/etc/bloch-l2-attestor/config.json
    python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1])); print(sys.argv[1].split("/owner/")[1], "follower_sha256" in c, c["produce_sha256"][:16])' "$C"
  done
  step "S2. seed the follower state of hosts 0 and 2 from $SEED_NATIVE (status.json is NOT copied)"
  for i in 0 2; do cp -a "$SEED_NATIVE" "$(host $i)/root/var/lib/bloch-l2-attestor-follower/native"; done
  du -sh "$(host 0)/root/var/lib/bloch-l2-attestor-follower/native"
  step "N1. this kit's agent on an OLD-kit config.json: halt, exit 3, with the upgrade instructions"
  code=0; check_new_agent 4 || code=$?
  echo "exit=$code"; [ $code = 3 ] || { echo "UNEXPECTED"; exit 1; }
  step "S3. start the OLD follower on hosts 0 and 2 (it is running when the operator starts the upgrade)"
  for i in 0 2; do bash "$K/tests/rehearsal_services.sh" "$(host $i)/root" "$(sethash)" start follower; done
  step "SETUP OK";;
upgrade)
  i=$2; shift 2
  step "U$i. install-attestor.sh upgrade on host $i ($*)"
  upgrade_cmd "$i" upgrade --artifacts "${NEW_BIN_DIR:?}" "$@";;
rollback)
  i=$2; shift 2
  step "R$i. install-attestor.sh upgrade-rollback on host $i ($*)"
  upgrade_cmd "$i" upgrade-rollback "$@";;
negatives)
  i=$2; H=$(host "$i"); O=$H/root/opt/bloch/l2-attestor
  step "N2. upgraded host $i: the agent's check_identity passes; then the follower replaced by /bin/true halts it"
  cp -a "$O/bloch-l2-native-follower" "$W/follower.keep"
  install -m 0755 /bin/true "$O/bloch-l2-native-follower"
  code=0; CREDENTIALS_DIRECTORY=$H/cred python3 -I "$K/tests/rehearsal_check.py" "$O" "$H/root/etc/bloch-l2-attestor/config.json" "$(sethash)" check || code=$?
  install -m 0755 "$W/follower.keep" "$O/bloch-l2-native-follower"; rm -f "$W/follower.keep"
  echo "exit=$code"; [ $code = 3 ] || { echo "UNEXPECTED"; exit 1; }
  step "N3. a second upgrade changes nothing"
  upgrade_cmd "$i" upgrade --artifacts "${NEW_BIN_DIR:?}"
  step "N4. upgrade-rollback after HF1 (clock moved to epoch 7181) is refused"
  code=0; upgrade_cmd "$i" upgrade-rollback --now-unix $((1786656679 + 7181 * 960)) || code=$?
  echo "exit=$code"; [ $code = 1 ] || { echo "UNEXPECTED"; exit 1; }
  step "N5. upgrade with a non-published follower (the RC one) is refused before anything is touched"
  mkdir -p "$W/bad-art"; cp "${OLD_BIN_DIR:?}/bloch-l2-native-follower" "$NEW_BIN_DIR/bloch-l2-produce-dev" "$W/bad-art/"
  code=0; CREDENTIALS_DIRECTORY=$H/cred bash "$K/install-attestor.sh" upgrade --prefix "$H/root" --artifacts "$W/bad-art" \
    --service-cmd false --check-cmd false --tag never || code=$?
  echo "exit=$code"; [ $code = 1 ] && [ ! -e "$H/root/opt/bloch/l2-attestor.never" ] || { echo "UNEXPECTED"; exit 1; }
  step "NEGATIVES OK";;
*) sed -n 3,14p "$0"; exit 2;;
esac
