#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Dry rehearsal of the attestor OWNER flow with THROWAWAY keys (never the real ones), Linux host:
#   keys -> keykit seal (tty) -> verify (tty) -> offline copy read-back -> install-attestor.sh install
#   --prefix (no systemd, tty transport passphrase) for operators 0, 2, 4 -> host key check + agent
#   identity check on the installed config.json -> each signs a synthetic withdrawal root with its
#   host-sealed key -> aggregate 3-of-5 -> native verify-attestation -> keykit shred-originals (tty).
#
#   BLOCH_POS=.../bloch-pos MAINNET_MANIFEST=.../genesis/mainnet.manifest \
#   CARRYOVER_DIR=DIR_WITH_carryover.tsv.gz+.sha256 PLACEHOLDER_BIN_DIR=DIR_WITH_follower+produce \
#   WORK=/scratch/dir ./rehearse_owner_flow.sh
#
# The follower/produce binaries are only hashed and copied (no follower runs), so any build works.
# Passphrases are typed through a real pty by tty_driver.py. Measured 2026-10-19 on 209.250.236.240.
set -euo pipefail
umask 077
K=$(cd "$(dirname "$0")/.." && pwd)
POS=${BLOCH_POS:?} MAN=${MAINNET_MANIFEST:?} CARRY=${CARRYOVER_DIR:?} PLACEHOLDER_BIN_DIR=${PLACEHOLDER_BIN_DIR:?}
TTY="python3 -I $K/tests/tty_driver.py"
W=${WORK:?}; [ ! -e "$W" ] || { echo "$W exists; give a fresh WORK dir" >&2; exit 1; }; mkdir -p "$W"
KEYS=$W/THROWAWAY-KEYS PASS=$W/THROWAWAY-PASS OUT=$W/bundles
mkdir -p "$KEYS" "$PASS"
step() { printf '\n######## %s\n' "$*"; }

step "0. throwaway keys + set (stands in for ~/Desktop/L2-MAINNET-ATESTADORES)"
for i in 0 1 2 3 4; do
  "$POS" ws-keygen --out "$KEYS/attestor-$i" >/dev/null
  printf 'throwaway rehearsal words %s %s\n' "$i" "$(head -c 9 /dev/urandom | base64)" > "$PASS/pass-$i"
done
"$POS" l2-claim attestor-set --threshold 3 $(for i in 0 1 2 3 4; do echo --pubkey "$KEYS/attestor-$i.pk"; done) --out "$KEYS/attestors.set"
SETHASH=$(python3 -I -c 'import hashlib,sys
l=[x.strip() for x in open(sys.argv[1]) if x.strip()]; k=[bytes.fromhex(x) for x in l[1:]]
print(hashlib.sha3_256(b"BLOCH:L2:ATTESTOR-SET:1"+bytes([int(l[0]),len(k)])+b"".join(k)).hexdigest())' "$KEYS/attestors.set")
echo "throwaway set $SETHASH"; ls -l "$KEYS"

step "1a. kit seal WITHOUT --expect-set-hash must refuse (pinned set)"
if bash "$K/keykit/make-operator-bundles.sh" seal --keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS" 2>&1; then echo UNEXPECTED; exit 1; fi

step "1b. kit seal (tty: each passphrase typed twice)"
$TTY "$PASS" 0 -- bash "$K/keykit/make-operator-bundles.sh" seal --keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS" --expect-set-hash "$SETHASH"
ls -l "$OUT"

step "2. kit verify (tty: each passphrase once)"
$TTY "$PASS" 0 -- bash "$K/keykit/make-operator-bundles.sh" verify --keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS" --expect-set-hash "$SETHASH"
cat "$OUT/BUNDLES.sha256"

step "2b. wrong passphrase is refused"
cp "$PASS/pass-1" "$W/good-1"; echo 'definitely the wrong passphrase' > "$PASS/pass-1"
if $TTY "$PASS" 1 -- bash "$K/keykit/make-operator-bundles.sh" verify --index 1 --keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS" --expect-set-hash "$SETHASH"; then echo UNEXPECTED; exit 1; fi
cp "$W/good-1" "$PASS/pass-1"

step "3. offline backup read-back (sha256 vs BUNDLES.sha256)"
mkdir -p "$W/usb-A"; cp "$OUT"/attestor-*.sealed "$OUT/BUNDLES.sha256" "$W/usb-A/"
(cd "$W/usb-A" && sha256sum -c BUNDLES.sha256)

step "4. artifacts dir for the installer"
A=$W/artifacts; mkdir -p "$A"
cp "$POS" "$A/bloch-pos"
cp "$PLACEHOLDER_BIN_DIR/bloch-l2-native-follower" "$PLACEHOLDER_BIN_DIR/bloch-l2-produce-dev" "$A/"
cp "$MAN" "$A/mainnet.manifest"; cp "$CARRY/carryover.tsv.gz" "$CARRY/carryover.tsv.gz.sha256" "$A/"
(cd "$A" && sha256sum bloch-pos bloch-l2-native-follower bloch-l2-produce-dev > SHA256SUMS)

for i in 0 2 4; do
  step "4.$i operator $i: hash check, install into scratch prefix host-$i (tty: transport passphrase once)"
  H=$W/host-$i; mkdir -p "$H/inbox"; cp "$W/usb-A/attestor-$i.sealed" "$H/inbox/"
  (cd "$H/inbox" && grep " attestor-$i.sealed\$" "$W/usb-A/BUNDLES.sha256" | sha256sum -c)
  if bash "$K/install-attestor.sh" install --artifacts "$A" --index "$i" --bundle "$H/inbox/attestor-$i.sealed" \
       --l1-rpc-url http://80.240.16.185:8080 --prefix "$H/root" 2>&1; then echo "UNEXPECTED: throwaway set accepted without --rehearsal-set"; exit 1; fi
  rm -rf "$H/root"
  $TTY "$PASS" "$i" -- bash "$K/install-attestor.sh" install --artifacts "$A" --index "$i" --bundle "$H/inbox/attestor-$i.sealed" \
       --l1-rpc-url http://80.240.16.185:8080 --prefix "$H/root" --rehearsal-set "$KEYS/attestors.set"
  E=$H/root/etc/bloch-l2-attestor
  ls -l "$E"
  step "4.$i check: host key opens with the HOST passphrase, header names index $i / throwaway set"
  "$POS" l2-claim key-info --sealed "$E/attestor.sealed"
  "$POS" l2-claim key-check --sealed "$E/attestor.sealed" --attestors "$E/public/attestors.set" --signer-index "$i" --passphrase-file "$E/keystore.passphrase"
  step "4.$i check: agent identity check on the installed config.json (LoadCredential simulated)"
  mkdir -p "$H/cred"; ln -sf "$E/keystore.passphrase" "$H/cred/passphrase"
  CREDENTIALS_DIRECTORY=$H/cred python3 -I - "$K" "$E/config.json" "$SETHASH" <<'PY'
import sys; sys.path.insert(0, sys.argv[1])
import attestor_agent as a, attestor_lib as lib
m = lib.MAINNET
pins = lib.Pins(m.chain_id, m.network, m.genesis, sys.argv[3], m.manifest_sha256, m.l2_genesis_hash,
                m.network_args, m.timestamp_rule, m.large_claim_sat)
print('check_identity', a.Agent(a.load_config(sys.argv[2]), pins=pins).check_identity(key='open'))
PY
  step "4.$i operator deletes the transport bundle copy from the host"
  rm -f "$H/inbox/attestor-$i.sealed"
done

step "5. synthetic withdrawal root (150 BLCH at index 1) and its proof"
cat > "$W/fixture.json" <<JSON
{"genesis": "$(python3 -I -c "import sys; sys.path.insert(0,'$K'); import attestor_lib as l; print(l.L2_GENESIS_HASH)")",
 "chain_id": 700770, "native_blocks": 40,
 "blocks": [{"number": 2, "hash": "$(printf b2 | sha256sum | cut -c1-64)", "state_root": "$(printf s2 | sha256sum | cut -c1-64)",
   "withdrawals": [{"l1_recipient": "$(printf small | sha256sum | cut -c1-64)", "sats": 500000000},
                   {"l1_recipient": "$(printf recipient | sha256sum | cut -c1-64)", "sats": 15000000000}]}]}
JSON
FAKE_L2_FIXTURE=$W/fixture.json python3 -I "$K/tests/fake_produce.py" withdrawal-proof --target x --index 1 --number 2 > "$W/proof.json"
ROOT=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["withdrawal_root"])' "$W/proof.json"); echo "root $ROOT"

step "6. each installed operator signs it with its HOST-sealed key (attest --sealed, as the agent does)"
for i in 0 2 4; do
  E=$W/host-$i/root/etc/bloch-l2-attestor; D=$W/drop/700770/$ROOT; mkdir -p "$D"
  "$POS" l2-claim attest --genesis "$E/public/mainnet.manifest" --proof "$W/proof.json" --attestors "$E/public/attestors.set" \
    --signer-index "$i" --sealed "$E/attestor.sealed" --passphrase-file "$E/keystore.passphrase" --out "$D/attestor-$i.partial"
done
ls -l "$W/drop/700770/$ROOT"

step "7. aggregate 3-of-5 from the drop (aggregate_attestation.aggregate, throwaway pins) + native verify"
python3 -I - "$K" "$W" "$POS" "$MAN" "$KEYS/attestors.set" "$SETHASH" <<'PY'
import sys; sys.path.insert(0, sys.argv[1])
import aggregate_attestation as ag, attestor_lib as lib
k, w, pos, man, setf, sh = sys.argv[1:]
m = lib.MAINNET
pins = lib.Pins(m.chain_id, m.network, m.genesis, sh, m.manifest_sha256, m.l2_genesis_hash, m.network_args,
                m.timestamp_rule, m.large_claim_sat)
s = ag.aggregate(f'{w}/proof.json', [f'{w}/drop'], f'{w}/agg', pos, man, setf, pins=pins)
print('signers', s['signers']); print(s['native_verify'])
try:
    ag.aggregate(f'{w}/proof.json', [f'{w}/drop'], f'{w}/agg-mainnet', pos, man, setf)
    print('UNEXPECTED: mainnet pins accepted a throwaway set'); sys.exit(1)
except SystemExit as e:
    print('mainnet pins refuse the throwaway set:', e)
PY

step "8. native verify-attestation directly (what prepare and the claim transition run)"
P=$W/drop/700770/$ROOT
"$POS" l2-claim verify-attestation --genesis "$MAN" --proof "$W/proof.json" --attestors "$KEYS/attestors.set" \
  --attestation "$P/attestor-0.partial" --attestation "$P/attestor-2.partial" --attestation "$P/attestor-4.partial" --expect-set-hash "$SETHASH"
echo "-- 2 partials must fail:"
if "$POS" l2-claim verify-attestation --genesis "$MAN" --proof "$W/proof.json" --attestors "$KEYS/attestors.set" \
  --attestation "$P/attestor-0.partial" --attestation "$P/attestor-2.partial" --expect-set-hash "$SETHASH"; then echo UNEXPECTED; exit 1; fi
echo "-- the pinned set hash must refuse the throwaway set:"
if "$POS" l2-claim verify-attestation --genesis "$MAN" --proof "$W/proof.json" --attestors "$KEYS/attestors.set" \
  --attestation "$P/attestor-0.partial" --attestation "$P/attestor-2.partial" --attestation "$P/attestor-4.partial" \
  --expect-set-hash 1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b; then echo UNEXPECTED; exit 1; fi

step "9. kit shred-originals (tty: DESTROY I) on the throwaway originals"
$TTY "$PASS" 0 -- bash "$K/keykit/make-operator-bundles.sh" shred-originals --keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS" --expect-set-hash "$SETHASH"
ls -l "$KEYS"
step "REHEARSAL OK"
