#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Owner-side custody of the five mainnet attestor keys: seal each key for one operator, prove every
# bundle opens, package it with everything the operator needs, check the offline backups, destroy the
# plaintext originals, and finally release the owner's own copies once each operator runs. Run by the
# key holder on the Mac (or an air-gapped machine), at the terminal. No sudo.
#
#   make-operator-bundles.sh preflight        [common options]
#   make-operator-bundles.sh seal             [common options]
#   make-operator-bundles.sh verify           [common options]
#   make-operator-bundles.sh package          [common options] [--pins FILE] [--artifacts DIR]
#   make-operator-bundles.sh backup-check     [common options] --media DIR --label NAME
#   make-operator-bundles.sh shred-originals  [common options]
#   make-operator-bundles.sh post-shred-check [common options]
#   make-operator-bundles.sh record           [common options] --index I --event EVENT [--note TEXT]
#   make-operator-bundles.sh release-owner-copy [common options] --index I
#   make-operator-bundles.sh status           [common options]
#
# Common options: [--keys-dir DIR] [--out DIR] [--bloch-pos BIN] [--index I ...]
# Defaults: --keys-dir ~/Desktop/L2-MAINNET-ATESTADORES, --out ~/L2-ATTESTOR-BUNDLES,
# --bloch-pos ~/worktrees/l2-attestor-keystore-20261019/target/release/bloch-pos, all indices 0..4,
# --pins keykit/operator-pins-v2.sha256.
#
# preflight  Read-only. FileVault, iCloud Desktop/Documents sync, Time Machine, local snapshots,
#            network, bloch-pos hash, which .sk names exist. Exit 1 on a FAIL.
# seal       For each I: checks attestor-I.pk is key I of the pinned set 1c06adbb… (public parts
#            only), then `bloch-pos l2-claim seal-key` reads attestor-I.sk itself, proves it signs for
#            that public key, and seals it (Argon2id 256 MiB + XChaCha20-Poly1305, bound to index, set
#            and public key) under a passphrase YOU type twice (one distinct passphrase per operator;
#            at least 12 characters; use 6+ random words). Writes OUT/attestor-I.sealed (0600).
# verify     For each I: the bundle's public header names index I of the pinned set, and
#            `l2-claim key-check` opens it with the passphrase you type and proves the key inside signs
#            for the pinned public key I (the decrypt test). Records OUT/attestor-I.verified.
# package    For each verified I: OUT/operator-I/ and OUT/operator-I.tar holding the sealed key, the
#            public key, the set, IDENTITY.txt (set hash, hashes, public header), ARTIFACTS.sha256 (the
#            v2 binary/manifest/carryover pins), INSTALL.md, ONBOARDING.md, the attestor kit, the
#            operator-side check-operator-bundle.sh and CONTENTS.sha256. --artifacts DIR also embeds
#            the Linux binaries, after checking them against the pins. Writes OUT/PACKAGES.sha256.
# backup-check  For each OUT/operator-I.tar found on the medium DIR: its hash must equal
#            PACKAGES.sha256. Records "backup-ok LABEL" per index. Use one distinct LABEL per medium.
# shred-originals  For each I with a current verified record, a package and backups on two distinct
#            media: asks you to type `DESTROY I`, overwrites attestor-I.sk with random bytes and deletes
#            it. The .pk files stay. Then runs post-shred-check.
# post-shred-check  Read-only: what is left in the keys folder, the Trash, Spotlight and local
#            snapshots, by file name only.
# record     Appends an event to OUT/CUSTODY-LEDGER.tsv: bundle-delivered, passphrase-delivered,
#            hash-confirmed, operator-check-ok, endpoint-received, backup-to-operator, backup-to-escrow.
# release-owner-copy  After operator-check-ok for I and the shred: asks you to type `RELEASE I`, then
#            deletes the Mac copies of bundle I (sealed, package, tar). From then on you no longer hold I.
# status     Per index: plaintext present, sealed, verified, packaged, backups, delivered, check-ok,
#            released; and how many keys you still control alone (threshold 3).
#
# This script never reads, prints, copies or hashes a .sk file: only bloch-pos opens it, and only in
# seal. Test-only hooks (throwaway keys): KEYKIT_PASSFILE_DIR (pass-I files instead of the tty),
# KEYKIT_SKIP_SEARCH=1 (no Spotlight search) and --expect-set-hash HEX (another set).
set -euo pipefail
umask 077
PINNED_SET_HASH=1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b
PINNED_SET_SHA256=9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0
KIT=$(cd "$(dirname "$0")/.." && pwd)
KEYS="$HOME/Desktop/L2-MAINNET-ATESTADORES" OUT="$HOME/L2-ATTESTOR-BUNDLES"
BIN="$HOME/worktrees/l2-attestor-keystore-20261019/target/release/bloch-pos"
PINS="$KIT/keykit/operator-pins-v2.sha256" ARTIFACTS= MEDIA= LABEL= EVENT= NOTE=
EXPECT=$PINNED_SET_HASH INDICES=()
MIN_BACKUPS=2
die() { echo "error: $*" >&2; exit 1; }
sha256() { if command -v shasum >/dev/null; then shasum -a 256 "$1"; else sha256sum "$1"; fi | cut -d' ' -f1; }
now() { date -u +%FT%TZ; }

MODE=${1:-}; [ $# -gt 0 ] && shift
ARGS=("$@")
while [ $# -gt 0 ]; do
  case $1 in
    --keys-dir) KEYS=$2; shift 2;; --out) OUT=$2; shift 2;; --bloch-pos) BIN=$2; shift 2;;
    --index) INDICES+=("$2"); shift 2;; --expect-set-hash) EXPECT=$2; shift 2;;
    --pins) PINS=$2; shift 2;; --artifacts) ARTIFACTS=$2; shift 2;;
    --media) MEDIA=$2; shift 2;; --label) LABEL=$2; shift 2;;
    --event) EVENT=$2; shift 2;; --note) NOTE=$2; shift 2;;
    *) die "unknown option $1";;
  esac
done
[ ${#INDICES[@]} -gt 0 ] || INDICES=(0 1 2 3 4)
for i in "${INDICES[@]}"; do [[ $i =~ ^[0-4]$ ]] || die "--index must be 0..4"; done
case $MODE in
  preflight|seal|verify|package|backup-check|shred-originals|post-shred-check|record|release-owner-copy|status) ;;
  *) sed -n 3,51p "$0"; exit 2;;
esac
SET="$KEYS/attestors.set"
LEDGER="$OUT/CUSTODY-LEDGER.tsv"
[ -f "$SET" ] || die "$SET missing"

# ---- the ledger: public events only (no secret, no passphrase) ----
ledger() {  # index event note
  [ -d "$OUT" ] || die "$OUT missing (run seal first)"
  printf '%s\t%s\t%s\t%s\n' "$(now)" "$1" "$2" "$(printf '%s' "${3:-}" | tr '\t\n' '  ')" >> "$LEDGER"
}
has_event() {  # index event
  [ -f "$LEDGER" ] && awk -F'\t' -v i="$1" -v e="$2" '$2==i && $3==e {f=1} END {exit !f}' "$LEDGER"
}
backup_labels() {  # index -> number of distinct media labels
  [ -f "$LEDGER" ] || { echo 0; return; }
  awk -F'\t' -v i="$1" '$2==i && $3=="backup-ok" {l[$4]=1} END {n=0; for (k in l) n++; print n}' "$LEDGER"
}
verified_current() {  # index
  local B="$OUT/attestor-$1.sealed" V="$OUT/attestor-$1.verified"
  [ -f "$B" ] && [ -f "$V" ] && grep -q "bundle sha256 $(sha256 "$B") " "$V"
}

# ---- where the bundles go: never into a synced folder ----
check_not_synced() {
  local path; path=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
  case $path in *"/Library/Mobile Documents/"*|*"/Library/CloudStorage/"*) die "$1 is inside a cloud-synced folder";; esac
  if [ "$(uname)" = Darwin ]; then
    for f in Desktop Documents; do
      if [ "$(defaults read com.apple.finder FXICloudDriveDesktop 2>/dev/null || echo 0)" = 1 ] && [[ $path == "$HOME/$f"* ]]; then
        die "$1 is under ~/$f, which iCloud Drive syncs (System Settings > Apple ID > iCloud Drive > Desktop & Documents)"
      fi
    done
  fi
}
check_not_synced "$OUT"
check_not_synced "$KEYS"

# ---- the set: pinned, and each .pk is its key I (public parts only) ----
need_bin() {
  [ -x "$BIN" ] || die "$BIN is not executable (cargo build --release in the attestor-keystore worktree)"
  "$BIN" l2-claim --help | grep -q 'seal-key' || die "$BIN has no l2-claim seal-key"
}
check_set() {
  if [ "$EXPECT" = "$PINNED_SET_HASH" ]; then
    [ "$(sha256 "$SET")" = "$PINNED_SET_SHA256" ] || die "$SET is not the consensus-pinned attestor set file"
  fi
  python3 -I - "$SET" "$KEYS" "$EXPECT" "${INDICES[@]}" <<'PY' || die "public key check failed"
import hashlib, sys
from pathlib import Path
set_file, keys_dir, expect, *indices = sys.argv[1:]
lines = [l.strip() for l in Path(set_file).read_text().splitlines() if l.strip()]
k, keys = int(lines[0]), [bytes.fromhex(l) for l in lines[1:]]
h = hashlib.sha3_256(b'BLOCH:L2:ATTESTOR-SET:1' + bytes([k, len(keys)]) + b''.join(keys)).hexdigest()
if h != expect:
    sys.exit(f'set hash {h} is not {expect}')
for i in map(int, indices):
    pk = bytes.fromhex((Path(keys_dir) / f'attestor-{i}.pk').read_text().strip())
    if pk != keys[i]:
        sys.exit(f'attestor-{i}.pk is not key {i} of the set')
print(f'set {h[:16]}… {k}-of-{len(keys)}: public keys {indices} match')
PY
}
case $MODE in seal|verify|package|shred-originals|preflight) check_set;; esac
case $MODE in seal|verify|package) need_bin;; esac

pass_args() {  # test hook only
  if [ -n "${KEYKIT_PASSFILE_DIR:-}" ]; then echo "$1 $KEYKIT_PASSFILE_DIR/pass-$2"; fi
}
confirm() {  # prompt expected -> 0 if typed exactly (test hook: KEYKIT_PASSFILE_DIR answers yes)
  local answer
  [ -z "${KEYKIT_PASSFILE_DIR:-}" ] || return 0
  read -r -p "$1: " answer
  [ "$answer" = "$2" ]
}

post_shred_check() {
  echo "== what is left in $KEYS (names only):"
  ls -1 "$KEYS"
  local left; left=$(cd "$KEYS" && ls -1 2>/dev/null | grep -E '\.sk$' || true)
  if [ -n "$left" ]; then echo "STILL PRESENT: $(echo $left)"; else echo "ok: no .sk file in $KEYS"; fi
  if [ -d "$HOME/.Trash" ]; then
    if ls -1 "$HOME/.Trash" 2>/dev/null | grep -qE '(attestor-[0-9]\.sk|L2-MAINNET-ATESTADORES)'; then
      echo "FOUND in the Trash: a copy of a key or the keys folder. Empty the Trash (Finder > Empty Trash)."
    else echo "ok: nothing named attestor-I.sk in the Trash"; fi
  fi
  if [ "$(uname)" = Darwin ] && [ -z "${KEYKIT_SKIP_SEARCH:-}" ]; then
    local hits; hits=$(mdfind -name 'attestor-' 2>/dev/null | grep -E '/attestor-[0-9]\.sk$' || true)
    if [ -n "$hits" ]; then echo "Spotlight still finds key files by name (delete each, then empty the Trash):"; echo "$hits"
    else echo "ok: Spotlight finds no file named attestor-I.sk"; fi
    local snaps; snaps=$(tmutil listlocalsnapshots / 2>/dev/null | grep -c com.apple || true)
    if [ "${snaps:-0}" -gt 0 ]; then
      echo "WARNING: $snaps local APFS snapshot(s) exist and may still hold the deleted .sk files."
      echo "         macOS removes them within 24 h; with FileVault on they are encrypted at rest."
    else echo "ok: no local APFS snapshots"; fi
  fi
  echo "Also check by hand: Downloads, AirDrop received files, USB drives, mail drafts, chat apps,"
  echo "any earlier cp/zip of the folder, and other computers. Overwriting a file on an APFS SSD is best"
  echo "effort; FileVault keeps any leftover blocks encrypted at rest."
}

write_packages_sha() {
  (cd "$OUT" && for t in operator-[0-4].tar; do [ -f "$t" ] && printf '%s  %s\n' "$(sha256 "$t")" "$t"; done; true) > "$OUT/PACKAGES.sha256"
}

case $MODE in
preflight)
  fail=0
  ok() { echo "PASS  $*"; }; warn() { echo "WARN  $*"; }; bad() { echo "FAIL  $*"; fail=1; }
  if [ "$(uname)" = Darwin ]; then
    if fdesetup status 2>/dev/null | grep -q 'FileVault is On'; then ok "FileVault is on"; else bad "FileVault is not on (System Settings > Privacy & Security > FileVault)"; fi
    if [ "$(defaults read com.apple.finder FXICloudDriveDesktop 2>/dev/null || echo 0)" = 1 ]; then
      warn "iCloud syncs Desktop & Documents: the keys folder on the Desktop may already be in iCloud"
    else ok "iCloud Desktop & Documents sync is off"; fi
    if tmutil destinationinfo 2>/dev/null | grep -q 'No destinations configured'; then ok "Time Machine has no destination"
    else warn "Time Machine has a destination: exclude $KEYS and $OUT, or past backups may hold the .sk files"; fi
    snaps=$(tmutil listlocalsnapshots / 2>/dev/null | grep -c com.apple || true)
    if [ "${snaps:-0}" -gt 0 ]; then warn "$snaps local APFS snapshot(s) exist"; else ok "no local APFS snapshots"; fi
  else
    warn "not macOS: check full-disk encryption, sync clients and backups by hand"
  fi
  if route -n get default >/dev/null 2>&1 || ip route show default 2>/dev/null | grep -q default; then
    warn "this machine has a default route (online). Turn Wi-Fi off for seal, verify, package and shred if you can"
  else ok "offline (no default route)"; fi
  if [ -e "$OUT" ]; then warn "$OUT already exists (seal refuses to overwrite a bundle; status shows where you are)"
  else ok "$OUT does not exist yet"; fi
  if [ -x "$BIN" ]; then ok "bloch-pos $(sha256 "$BIN") $BIN"; else bad "$BIN is not executable"; fi
  [ -f "$PINS" ] && ok "operator pins $(sha256 "$PINS") $PINS" || bad "$PINS missing"
  for i in "${INDICES[@]}"; do
    if [ -f "$KEYS/attestor-$i.sk" ]; then echo "INFO  attestor-$i.sk present (plaintext)"; else echo "INFO  attestor-$i.sk absent"; fi
  done
  [ $fail = 0 ] || exit 1
  ;;
seal)
  mkdir -p "$OUT"; chmod 700 "$OUT"
  for i in "${INDICES[@]}"; do
    [ -f "$KEYS/attestor-$i.sk" ] || die "$KEYS/attestor-$i.sk missing"
    [ ! -e "$OUT/attestor-$i.sealed" ] || die "$OUT/attestor-$i.sealed exists; refusing to overwrite"
    echo "== attestor $i: choose the passphrase for operator $i (typed twice, not shown)"
    # shellcheck disable=SC2046
    "$BIN" l2-claim seal-key --key "$KEYS/attestor-$i.sk" --attestors "$SET" --signer-index "$i" \
      $(pass_args --passphrase-file "$i") --out "$OUT/attestor-$i.sealed"
    cp "$KEYS/attestor-$i.pk" "$OUT/attestor-$i.pk"
    chmod 600 "$OUT/attestor-$i.sealed"
    ledger "$i" sealed "bloch-pos $(sha256 "$BIN")"
  done
  cp "$SET" "$OUT/attestors.set"
  echo "Sealed ${INDICES[*]} into $OUT. Next: $0 verify ${ARGS[*]:-} (types each passphrase once more)."
  ;;
verify)
  for i in "${INDICES[@]}"; do
    B="$OUT/attestor-$i.sealed"
    [ -f "$B" ] || die "$B missing"
    info=$("$BIN" l2-claim key-info --sealed "$B")
    grep -qx "signer_index $i" <<<"$info" || die "$B is not attestor $i"
    grep -qx "set_hash $EXPECT" <<<"$info" || die "$B is not sealed for set $EXPECT"
    echo "== attestor $i: type operator $i's passphrase to prove the bundle opens"
    # shellcheck disable=SC2046
    "$BIN" l2-claim key-check --sealed "$B" --attestors "$SET" --signer-index "$i" $(pass_args --passphrase-file "$i")
    printf 'attestor %s bundle sha256 %s verified %s\n' "$i" "$(sha256 "$B")" "$(now)" > "$OUT/attestor-$i.verified"
    printf '%s\n' "$info" > "$OUT/attestor-$i.info"
    ledger "$i" verified "sealed sha256 $(sha256 "$B")"
  done
  (cd "$OUT" && for t in attestor-[0-4].sealed; do [ -f "$t" ] && printf '%s  %s\n' "$(sha256 "$t")" "$t"; done; true) > "$OUT/BUNDLES.sha256"
  echo "Verified ${INDICES[*]}. Bundle hashes: $OUT/BUNDLES.sha256 (public)."
  echo "Next: $0 package"
  ;;
package)
  [ -f "$PINS" ] || die "$PINS missing"
  python3 -I - "$PINS" <<'PY' || die "$PINS is malformed"
import re, sys
names = []
for line in open(sys.argv[1]):
    m = re.fullmatch(r'([0-9a-f]{64})  (\S+)\n?', line)
    if not m: sys.exit(f'bad line {line!r}')
    names.append(m.group(2))
want = ['bloch-pos', 'bloch-l2-native-follower', 'bloch-l2-produce-dev', 'mainnet.manifest', 'carryover.tsv.gz']
if sorted(names) != sorted(want): sys.exit(f'pins must name exactly {want}')
PY
  pin() { awk -v n="$1" '$2==n {print $1}' "$PINS"; }
  # A package fixes what the operator installs for good, so it must come from the tree it claims to be.
  grep -q '^7c1cc62b' "$PINS" && die "$PINS pins the old producer 7c1cc62b…: it halts on the first settled deposit. Package from the current kit"
  grep -qE '^(fb0d5313|c18752fd)' "$PINS" && die "$PINS pins v2.1's producer fb0d5313… or follower c18752fd…: superseded by the next build. Package from the current kit"
  [ "$(sha256 "$KIT/sigfeed.py")" = "$(cut -d' ' -f1 "$KIT/sigfeed.sha256")" ] || die "$KIT/sigfeed.py does not match sigfeed.sha256"
  if [ "$EXPECT" = "$PINNED_SET_HASH" ]; then
    for pair in bloch-pos:V2_BLOCH_POS_SHA256 bloch-l2-native-follower:V2_FOLLOWER_SHA256 bloch-l2-produce-dev:V2_PRODUCE_SHA256; do
      [ "$(sed -n "s/^${pair#*:}=//p" "$KIT/install-attestor.sh")" = "$(pin "${pair%:*}")" ] || die "$PINS and install-attestor.sh disagree on ${pair%:*}"
    done
    [ -z "$(git -C "$KIT" status --porcelain -- . 2>/dev/null | head -1)" ] || die "the kit has local changes: commit them or package from a clean checkout"
  fi
  [ -n "$ARTIFACTS" ] || echo "note: no --artifacts. Operators then need the five files from another source. Embedding them is simpler for a non-expert."
  if [ -n "$ARTIFACTS" ]; then
    for f in bloch-pos bloch-l2-native-follower bloch-l2-produce-dev mainnet.manifest carryover.tsv.gz; do
      [ -f "$ARTIFACTS/$f" ] || die "$ARTIFACTS/$f missing"
      [ "$(sha256 "$ARTIFACTS/$f")" = "$(pin "$f")" ] || die "$ARTIFACTS/$f does not match its pin in $PINS"
    done
    [ -f "$ARTIFACTS/carryover.tsv.gz.sha256" ] || die "$ARTIFACTS/carryover.tsv.gz.sha256 missing"
  fi
  commit=$(git -C "$KIT" rev-parse HEAD 2>/dev/null || echo unknown)
  dirty=$(git -C "$KIT" status --porcelain -- . 2>/dev/null | head -1 || true)
  [ -z "$dirty" ] || commit="$commit (with local changes)"
  for i in "${INDICES[@]}"; do
    B="$OUT/attestor-$i.sealed" P="$OUT/operator-$i"
    verified_current "$i" || die "attestor $i: no current verified bundle; run verify first"
    [ ! -e "$P" ] && [ ! -e "$P.tar" ] || die "$P exists; refusing to overwrite (delete $P and $P.tar to repackage)"
    mkdir -p "$P/kit/systemd" "$P/kit/public"
    cp "$B" "$OUT/attestor-$i.pk" "$OUT/attestors.set" "$P/"
    cp "$KIT/install-attestor.sh" "$KIT/attestor_agent.py" "$KIT/attestor_lib.py" "$KIT/aggregate_attestation.py" "$KIT/sigfeed.py" "$KIT/sigfeed.sha256" "$KIT/README.md" "$P/kit/"
    cp "$KIT"/systemd/*.service "$P/kit/systemd/"
    cp "$KIT"/public/* "$P/kit/public/"
    cp "$PINS" "$P/ARTIFACTS.sha256"
    cp "$KIT/keykit/check-operator-bundle.sh" "$P/"
    cp "$KIT/keykit/OPERATOR-ONBOARDING.md" "$P/ONBOARDING.md"
    chmod 755 "$P/check-operator-bundle.sh" "$P/kit/install-attestor.sh"
    if [ -n "$ARTIFACTS" ]; then
      mkdir -p "$P/artifacts"
      cp "$ARTIFACTS"/bloch-pos "$ARTIFACTS"/bloch-l2-native-follower "$ARTIFACTS"/bloch-l2-produce-dev \
         "$ARTIFACTS"/mainnet.manifest "$ARTIFACTS"/carryover.tsv.gz "$ARTIFACTS"/carryover.tsv.gz.sha256 "$P/artifacts/"
      chmod 755 "$P/artifacts/bloch-pos" "$P/artifacts/bloch-l2-native-follower" "$P/artifacts/bloch-l2-produce-dev"
      grep -E '  (bloch-pos|bloch-l2-native-follower|bloch-l2-produce-dev)$' "$PINS" > "$P/artifacts/SHA256SUMS"
    fi
    sealed_sha=$(sha256 "$B")
    {
      echo "attestor_index $i"
      echo "set_hash $EXPECT"
      echo "set_file_sha256 $(sha256 "$OUT/attestors.set")"
      echo "public_key_sha256 $(sha256 "$OUT/attestor-$i.pk")"
      echo "sealed_sha256 $sealed_sha"
      echo "pins_sha256 $(sha256 "$PINS")"
      echo "kit_commit $commit"
      echo "sealed_with_bloch_pos_sha256 $(sha256 "$BIN")"
      echo "packaged_utc $(now)"
      echo "# public header of attestor-$i.sealed (bloch-pos l2-claim key-info):"
      sed 's/^/header /' "$OUT/attestor-$i.info"
    } > "$P/IDENTITY.txt"
    sed -e "s|@INDEX@|$i|g" -e "s|@SET_HASH@|$EXPECT|g" -e "s|@SEALED_SHA256@|$sealed_sha|g" \
        -e "s|@KIT_COMMIT@|$commit|g" "$KIT/keykit/OPERATOR-INSTALL.template.md" > "$P/INSTALL.md"
    (cd "$P" && find . -type f ! -name CONTENTS.sha256 | LC_ALL=C sort | sed 's|^\./||' | while read -r f; do
       printf '%s  %s\n' "$(sha256 "$f")" "$f"; done) > "$P/CONTENTS.sha256"
    (cd "$OUT" && COPYFILE_DISABLE=1 tar --format ustar -cf "operator-$i.tar" "operator-$i")
    chmod 600 "$P.tar"
    # Re-check what the operator will receive: the sealed key inside the tar is byte-identical to the
    # verified one (so it opens with the same passphrase) and its header names index I and the set.
    T=$(mktemp -d "$OUT/.recheck-XXXXXX")
    (cd "$T" && tar -xf "$P.tar")
    [ "$(sha256 "$T/operator-$i/attestor-$i.sealed")" = "$sealed_sha" ] || die "operator-$i.tar: sealed key differs from the verified one"
    info=$("$BIN" l2-claim key-info --sealed "$T/operator-$i/attestor-$i.sealed")
    grep -qx "signer_index $i" <<<"$info" && grep -qx "set_hash $EXPECT" <<<"$info" || die "operator-$i.tar: wrong key header"
    rm -rf "$T"
    write_packages_sha
    ledger "$i" packaged "tar sha256 $(sha256 "$P.tar")"
    echo "packaged attestor $i: $P.tar ($(sha256 "$P.tar"))"
  done
  echo "Package hashes: $OUT/PACKAGES.sha256 (public; read each operator its line over a separate channel)."
  echo "Next: copy every operator-I.tar and PACKAGES.sha256 to TWO offline media, then for each medium:"
  echo "  $0 backup-check --media /Volumes/NAME --label NAME"
  ;;
backup-check)
  [ -n "$MEDIA" ] && [ -n "$LABEL" ] || die "backup-check needs --media DIR and --label NAME"
  [[ $LABEL =~ ^[A-Za-z0-9._-]+$ ]] || die "--label: letters, digits, . _ - only"
  [ -f "$OUT/PACKAGES.sha256" ] || die "$OUT/PACKAGES.sha256 missing (run package first)"
  [ "$(cd "$MEDIA" && pwd)" != "$(cd "$OUT" && pwd)" ] || die "--media is the bundle folder itself"
  found=0
  for i in "${INDICES[@]}"; do
    t="$MEDIA/operator-$i.tar"
    [ -f "$t" ] || continue
    want=$(awk -v n="operator-$i.tar" '$2==n {print $1}' "$OUT/PACKAGES.sha256")
    [ -n "$want" ] || die "operator-$i.tar is not in PACKAGES.sha256"
    [ "$(sha256 "$t")" = "$want" ] || die "$t does NOT match PACKAGES.sha256 (bad copy)"
    ledger "$i" backup-ok "$LABEL"
    echo "ok: $LABEL holds operator-$i.tar ($(backup_labels "$i") distinct medium/media for attestor $i)"
    found=$((found + 1))
  done
  [ $found -gt 0 ] || die "no operator-I.tar on $MEDIA"
  [ -f "$MEDIA/PACKAGES.sha256" ] || echo "note: also copy PACKAGES.sha256 to $MEDIA"
  ;;
shred-originals)
  for i in "${INDICES[@]}"; do
    SK="$KEYS/attestor-$i.sk"
    [ -f "$SK" ] || { echo "attestor-$i.sk already gone"; continue; }
    verified_current "$i" || die "attestor $i: no verified bundle, or it changed since verify; run seal and verify first"
    [ -f "$OUT/operator-$i.tar" ] || die "attestor $i: not packaged yet"
    n=$(backup_labels "$i")
    [ "$n" -ge $MIN_BACKUPS ] || die "attestor $i: backups confirmed on $n medium/media, need $MIN_BACKUPS (backup-check)"
    if ! confirm "Type DESTROY $i to overwrite and delete $SK" "DESTROY $i"; then echo "skipped attestor $i"; continue; fi
    size=$(wc -c < "$SK")
    dd if=/dev/urandom of="$SK" bs="$size" count=1 conv=notrunc 2>/dev/null
    sync
    rm -f "$SK"
    ledger "$i" shredded ""
    echo "attestor-$i.sk overwritten and deleted"
  done
  post_shred_check
  ;;
post-shred-check)
  post_shred_check
  ;;
record)
  [ ${#INDICES[@]} -eq 1 ] || die "record needs exactly one --index"
  case $EVENT in
    bundle-delivered|passphrase-delivered|hash-confirmed|operator-check-ok|endpoint-received|backup-to-operator|backup-to-escrow) ;;
    *) die "--event must be one of bundle-delivered passphrase-delivered hash-confirmed operator-check-ok endpoint-received backup-to-operator backup-to-escrow";;
  esac
  ledger "${INDICES[0]}" "$EVENT" "$NOTE"
  echo "recorded attestor ${INDICES[0]} $EVENT"
  ;;
release-owner-copy)
  [ ${#INDICES[@]} -eq 1 ] || die "release-owner-copy needs exactly one --index"
  i=${INDICES[0]}
  [ ! -f "$KEYS/attestor-$i.sk" ] || die "attestor $i: the plaintext original still exists (shred-originals first)"
  has_event "$i" operator-check-ok || die "attestor $i: no operator-check-ok recorded (record --index $i --event operator-check-ok)"
  if ! confirm "Type RELEASE $i once operator $i has check-ok, you hold no backup medium of index $i, and your note of its passphrase is destroyed" "RELEASE $i"; then
    echo "not released"; exit 1
  fi
  rm -rf "$OUT/operator-$i" "$OUT/operator-$i.tar" "$OUT/attestor-$i.sealed"
  ledger "$i" released ""
  echo "released attestor $i: the Mac no longer holds its bundle. PACKAGES.sha256 and the ledger stay (public)."
  ;;
status)
  ctl=0 plain=0
  printf '%-3s %-9s %-6s %-8s %-8s %-7s %-9s %-8s %-8s\n' idx plaintext sealed verified packaged backups delivered check-ok released
  for i in 0 1 2 3 4; do
    yn() { if "$@"; then echo yes; else echo no; fi; }
    p=$(yn test -f "$KEYS/attestor-$i.sk"); [ "$p" = no ] || plain=$((plain + 1))
    r=$(yn has_event "$i" released); [ "$r" = yes ] || ctl=$((ctl + 1))
    printf '%-3s %-9s %-6s %-8s %-8s %-7s %-9s %-8s %-8s\n' "$i" "$p" "$(yn test -f "$OUT/attestor-$i.sealed")" \
      "$(yn verified_current "$i")" "$(yn test -f "$OUT/operator-$i.tar")" "$(backup_labels "$i")" \
      "$(yn has_event "$i" bundle-delivered)" "$(yn has_event "$i" operator-check-ok)" "$r"
  done
  echo "plaintext keys on this machine: $plain of 5"
  echo "keys you still control alone (not released): $ctl of 5; threshold 3"
  if [ $ctl -ge 3 ]; then echo "WARNING: you alone can still produce a valid 3-of-5 attestation. Finish the handoff and release."; fi
  ;;
esac
