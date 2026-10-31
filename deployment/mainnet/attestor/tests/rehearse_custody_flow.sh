#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rehearsal of the attestor CUSTODY flow (keykit/make-operator-bundles.sh and
# keykit/check-operator-bundle.sh) with THROWAWAY keys only. It never touches the real key folder:
# every path is under WORK, and the Spotlight search is switched off (KEYKIT_SKIP_SEARCH=1).
#
# Owner part (macOS or Linux), run where the owner's bloch-pos lives:
#   BLOCH_POS=.../bloch-pos WORK=/scratch/new-dir ./rehearse_custody_flow.sh owner
#     throwaway keys + set -> preflight -> seal (tty) -> verify (tty) -> wrong passphrase refused ->
#     package -> shred refused before backups -> backup-check on two media (+ a corrupt copy refused)
#     -> status (5 of 5 warning) -> shred-originals (tty DESTROY) -> post-shred-check -> release
#     refused without check-ok -> record + release-owner-copy 0, 2, 4 (tty RELEASE) -> status (2 of 5).
#
# Operator part (Linux x86_64), on a copy of WORK/media-A and WORK/THROWAWAY-PASS:
#   BLOCH_POS=.../linux/bloch-pos ARTIFACTS=DIR WORK=/scratch/dir ./rehearse_custody_flow.sh operator MEDIA_DIR PASS_DIR
#     ARTIFACTS holds the files named in keykit/operator-pins-v2.sha256 plus carryover.tsv.gz.sha256.
#     For operators 0, 2, 4: PACKAGES line check -> extract -> tamper refused -> check-operator-bundle.sh
#     --rehearsal --open (tty transport passphrase) -> install-attestor.sh --prefix --rehearsal-set (tty)
#     -> the host-sealed key opens with the host passphrase -> remove the bundle copy.
set -euo pipefail
umask 077
K=$(cd "$(dirname "$0")/.." && pwd)
TTY="python3 -I $K/tests/tty_driver.py"
KIT="bash $K/keykit/make-operator-bundles.sh"
POS=${BLOCH_POS:?} W=${WORK:?}
export KEYKIT_SKIP_SEARCH=1
step() { printf '\n######## %s\n' "$*"; }
expect_fail() { if "$@" > "$W/last-fail.log" 2>&1; then cat "$W/last-fail.log"; echo "UNEXPECTED SUCCESS: $*"; exit 1; fi
                echo "refused as expected: $(grep -iE 'error|fail|refus' "$W/last-fail.log" | tail -2 | tr '\n' ' ')"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
sethash() { python3 -I -c 'import hashlib,sys
l=[x.strip() for x in open(sys.argv[1]) if x.strip()]; k=[bytes.fromhex(x) for x in l[1:]]
print(hashlib.sha3_256(b"BLOCH:L2:ATTESTOR-SET:1"+bytes([int(l[0]),len(k)])+b"".join(k)).hexdigest())' "$1"; }

owner() {
  [ ! -e "$W" ] || { echo "$W exists; give a fresh WORK dir" >&2; exit 1; }; mkdir -p "$W"
  KEYS=$W/THROWAWAY-KEYS PASS=$W/THROWAWAY-PASS OUT=$W/bundles
  mkdir -p "$KEYS" "$PASS"
  C=(--keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS")

  step "0. throwaway keys + 3-of-5 set (stands in for the real key folder)"
  for i in 0 1 2 3 4; do
    "$POS" ws-keygen --out "$KEYS/attestor-$i" >/dev/null
    printf 'throwaway custody words %s %s\n' "$i" "$(head -c 9 /dev/urandom | base64)" > "$PASS/pass-$i"
  done
  # shellcheck disable=SC2046
  "$POS" l2-claim attestor-set --threshold 3 $(for i in 0 1 2 3 4; do echo --pubkey "$KEYS/attestor-$i.pk"; done) --out "$KEYS/attestors.set"
  SETHASH=$(sethash "$KEYS/attestors.set"); echo "throwaway set $SETHASH"
  C+=(--expect-set-hash "$SETHASH")

  step "1. preflight (informational here: the rehearsal machine is not the owner's air-gapped Mac)"
  $KIT preflight "${C[@]}" || echo "(preflight reported a FAIL on this machine; expected outside the owner's Mac)"

  step "2. seal refuses the throwaway set without --expect-set-hash (pinned set)"
  expect_fail $KIT seal --keys-dir "$KEYS" --out "$OUT" --bloch-pos "$POS"

  step "3. seal (tty: each passphrase typed twice)"
  $TTY "$PASS" 0 -- $KIT seal "${C[@]}"

  step "4. package refused before verify"
  expect_fail $KIT package "${C[@]}" --index 0

  step "5. verify = decrypt + sign test (tty: each passphrase once)"
  $TTY "$PASS" 0 -- $KIT verify "${C[@]}"
  cp "$PASS/pass-3" "$W/good-3"; echo 'definitely the wrong passphrase' > "$PASS/pass-3"
  expect_fail $TTY "$PASS" 3 -- $KIT verify "${C[@]}" --index 3
  cp "$W/good-3" "$PASS/pass-3"

  step "6. package all five (v2 pins, no embedded binaries)"
  $KIT package "${C[@]}"
  cat "$OUT/PACKAGES.sha256"
  tar -tf "$OUT/operator-0.tar" | LC_ALL=C sort
  cat "$OUT/operator-0/IDENTITY.txt"
  grep -c '@[A-Z_]*@' "$OUT/operator-2/INSTALL.md" && { echo "UNEXPECTED: unfilled placeholder"; exit 1; } || echo "INSTALL.md placeholders filled"
  expect_fail $KIT package "${C[@]}" --index 0

  step "7. shred refused before two confirmed backups"
  expect_fail $KIT shred-originals "${C[@]}"

  step "8. backups: two media, read back against PACKAGES.sha256; a corrupt copy is refused"
  for m in A B; do mkdir -p "$W/media-$m"; cp "$OUT"/operator-*.tar "$OUT/PACKAGES.sha256" "$W/media-$m/"; done
  mkdir -p "$W/media-bad"; cp "$OUT/operator-1.tar" "$W/media-bad/"; printf 'x' >> "$W/media-bad/operator-1.tar"
  expect_fail $KIT backup-check "${C[@]}" --media "$W/media-bad" --label usb-bad
  $KIT backup-check "${C[@]}" --media "$W/media-A" --label usb-A
  expect_fail $KIT shred-originals "${C[@]}"
  $KIT backup-check "${C[@]}" --media "$W/media-B" --label usb-B
  (cd "$W/media-B" && if command -v sha256sum >/dev/null; then sha256sum -c PACKAGES.sha256; else shasum -a 256 -c PACKAGES.sha256; fi)

  step "9. status before the shred: 5 plaintext, 5 of 5 controlled (warning expected)"
  $KIT status "${C[@]}" | tee "$W/status-1.txt"
  grep -q 'WARNING' "$W/status-1.txt"

  step "10. shred-originals (tty: DESTROY I) + post-shred-check"
  $TTY "$PASS" 0 -- $KIT shred-originals "${C[@]}"
  ls -l "$KEYS"
  if ls "$KEYS"/*.sk >/dev/null 2>&1; then echo "UNEXPECTED: .sk left"; exit 1; fi
  for i in 0 1 2 3 4; do [ -f "$KEYS/attestor-$i.pk" ]; done

  step "11. release refused without operator-check-ok; then record + release 0, 2, 4"
  expect_fail $KIT release-owner-copy "${C[@]}" --index 0
  expect_fail $KIT record "${C[@]}" --index 0 --event something-else
  for i in 0 2 4; do
    $KIT record "${C[@]}" --index "$i" --event bundle-delivered --note "rehearsal channel A"
    $KIT record "${C[@]}" --index "$i" --event operator-check-ok --note "rehearsal host-$i"
    $TTY "$PASS" "$i" -- $KIT release-owner-copy "${C[@]}" --index "$i"
    [ ! -e "$OUT/attestor-$i.sealed" ] && [ ! -e "$OUT/operator-$i.tar" ] && [ ! -e "$OUT/operator-$i" ]
  done
  $KIT status "${C[@]}" | tee "$W/status-2.txt"
  grep -q 'not released): 2 of 5' "$W/status-2.txt"
  if grep -q WARNING "$W/status-2.txt"; then echo "UNEXPECTED: warning after release"; exit 1; fi
  cat "$OUT/CUSTODY-LEDGER.tsv"
  step "OWNER REHEARSAL OK (set $SETHASH)"
}

operator() {
  MEDIA=${1:?media dir} PASS=${2:?throwaway passphrase dir} ART=${ARTIFACTS:?}
  [ "$(uname -s)" = Linux ] || { echo "operator part runs on Linux" >&2; exit 1; }
  [ ! -e "$W" ] || { echo "$W exists; give a fresh WORK dir" >&2; exit 1; }; mkdir -p "$W"
  for i in 0 2 4; do
    H=$W/host-$i; mkdir -p "$H/inbox"
    step "op $i.1 transfer: the tar over channel A, its PACKAGES line over channel C"
    cp "$MEDIA/operator-$i.tar" "$H/inbox/"
    grep " operator-$i.tar\$" "$MEDIA/PACKAGES.sha256" > "$H/inbox/PACKAGES.sha256"
    (cd "$H/inbox" && sha256sum -c PACKAGES.sha256 && tar -xf "operator-$i.tar")
    B=$H/inbox/operator-$i
    mkdir -p "$B/artifacts"
    cp "$ART"/bloch-pos "$ART"/bloch-l2-native-follower "$ART"/bloch-l2-produce-dev "$ART"/mainnet.manifest \
       "$ART"/carryover.tsv.gz "$ART"/carryover.tsv.gz.sha256 "$B/artifacts/"
    SETHASH=$(awk '$1=="set_hash"{print $2}' "$B/IDENTITY.txt")

    step "op $i.2 refusals: pinned mode refuses the throwaway set; a tampered file; a wrong artifact"
    expect_fail "$B/check-operator-bundle.sh"
    cp "$B/kit/attestor_agent.py" "$W/agent.bak"; echo '# tampered' >> "$B/kit/attestor_agent.py"
    expect_fail "$B/check-operator-bundle.sh" --rehearsal
    cp "$W/agent.bak" "$B/kit/attestor_agent.py"
    cp "$B/artifacts/bloch-l2-native-follower" "$W/follower.bak"; printf 'x' >> "$B/artifacts/bloch-l2-native-follower"
    expect_fail "$B/check-operator-bundle.sh" --rehearsal
    cp "$W/follower.bak" "$B/artifacts/bloch-l2-native-follower"

    step "op $i.3 check-operator-bundle.sh --rehearsal --open (tty: transport passphrase)"
    $TTY "$PASS" "$i" -- "$B/check-operator-bundle.sh" --rehearsal --open
    for f in bloch-pos bloch-l2-native-follower bloch-l2-produce-dev; do grep -q "  $f\$" "$B/artifacts/SHA256SUMS"; done

    step "op $i.4 install into a scratch prefix (tty: transport passphrase once)"
    $TTY "$PASS" "$i" -- bash "$B/kit/install-attestor.sh" install --artifacts "$B/artifacts" --index "$i" \
      --bundle "$B/attestor-$i.sealed" --l1-rpc-url http://80.240.16.185:8080 --prefix "$H/root" \
      --rehearsal-set "$B/attestors.set" --feed-port 8787 --feed-bind 127.0.0.1
    E=$H/root/etc/bloch-l2-attestor O=$H/root/opt/bloch/l2-attestor
    "$O/bloch-pos" l2-claim key-check --sealed "$E/attestor.sealed" --attestors "$E/public/attestors.set" \
      --signer-index "$i" --passphrase-file "$E/keystore.passphrase"
    (cd "$B" && for f in bloch-pos bloch-l2-native-follower bloch-l2-produce-dev; do
       [ "$(sha256sum "$O/$f" | cut -d' ' -f1)" = "$(awk -v n=$f '$2==n{print $1}' ARTIFACTS.sha256)" ] || { echo "installed $f differs"; exit 1; }
     done)
    python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1])); assert c["signer_index"]==int(sys.argv[2]); print("config.json signer_index", c["signer_index"], "produce_sha256", c["produce_sha256"][:16])' "$E/config.json" "$i"
    [ "$(awk '$1=="set_hash"{print $2}' "$B/IDENTITY.txt")" = "$SETHASH" ]
    grep -qx 'SIGFEED_BIND=127.0.0.1' "$E/feed.env"; grep -qx 'SIGFEED_PORT=8787' "$E/feed.env"
    [ -f "$H/root/systemd/bloch-l2-attestor-feed.service" ] || find "$H/root" -name bloch-l2-attestor-feed.service | grep -q .
    [ "$(sha256sum "$O/sigfeed.py" | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$B/kit/sigfeed.sha256")" ]

    step "op $i.5 remove the bundle copy from the host"
    shred -u "$B/attestor-$i.sealed" "$H/inbox/operator-$i.tar"
  done
  step "OPERATOR REHEARSAL OK (set $SETHASH)"
}

case ${1:-} in
  owner) owner;;
  operator) shift; operator "$@";;
  *) sed -n 3,20p "$0"; exit 2;;
esac
