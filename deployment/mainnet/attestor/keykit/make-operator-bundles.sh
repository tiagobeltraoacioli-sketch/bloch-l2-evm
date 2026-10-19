#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Seal each mainnet attestor key into a per-operator bundle, verify every bundle, and (only after
# you confirm) destroy the plaintext originals. Run by the key holder on the Mac, at the terminal.
#
#   make-operator-bundles.sh seal   [--keys-dir DIR] [--out DIR] [--bloch-pos BIN] [--index I ...]
#   make-operator-bundles.sh verify [--keys-dir DIR] [--out DIR] [--bloch-pos BIN] [--index I ...]
#   make-operator-bundles.sh shred-originals [--keys-dir DIR] [--out DIR] [--index I ...]
#
# Defaults: --keys-dir ~/Desktop/L2-MAINNET-ATESTADORES, --out ~/L2-ATTESTOR-BUNDLES,
# --bloch-pos ~/worktrees/l2-attestor-keystore-20261019/target/release/bloch-pos, all indices 0..4.
#
# seal    For each I: checks attestor-I.pk is key I of the pinned set 1c06adbb… (public parts only),
#         then `bloch-pos l2-claim seal-key` reads attestor-I.sk itself, proves it signs for that
#         public key, and seals it (Argon2id 256 MiB + XChaCha20-Poly1305, bound to index, set and
#         public key) under a passphrase YOU type twice (one distinct passphrase per operator; at
#         least 12 characters; use 6+ random words). Writes OUT/attestor-I.sealed (0600).
# verify  For each I: the bundle's public header names index I of the pinned set, and
#         `l2-claim key-check` opens it with the passphrase you type and proves the key inside signs
#         for the pinned public key I. Records OUT/attestor-I.verified (bundle SHA-256, no secret).
# shred-originals  For each I with a current .verified record: asks you to type `DESTROY I`, then
#         overwrites attestor-I.sk with random bytes and deletes it. The .pk files stay.
#
# This script never reads, prints, copies or hashes a .sk file: only bloch-pos opens it.
# Test-only hooks (throwaway keys): KEYKIT_PASSFILE_DIR (pass-I files instead of the tty) and
# --expect-set-hash HEX (another set).
set -euo pipefail
umask 077
PINNED_SET_HASH=1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b
PINNED_SET_SHA256=9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0
KEYS="$HOME/Desktop/L2-MAINNET-ATESTADORES" OUT="$HOME/L2-ATTESTOR-BUNDLES"
BIN="$HOME/worktrees/l2-attestor-keystore-20261019/target/release/bloch-pos"
EXPECT=$PINNED_SET_HASH INDICES=()
die() { echo "error: $*" >&2; exit 1; }
sha256() { if command -v shasum >/dev/null; then shasum -a 256 "$1"; else sha256sum "$1"; fi | cut -d' ' -f1; }

MODE=${1:-}; [ $# -gt 0 ] && shift
ARGS=("$@")
while [ $# -gt 0 ]; do
  case $1 in
    --keys-dir) KEYS=$2; shift 2;; --out) OUT=$2; shift 2;; --bloch-pos) BIN=$2; shift 2;;
    --index) INDICES+=("$2"); shift 2;; --expect-set-hash) EXPECT=$2; shift 2;;
    *) die "unknown option $1";;
  esac
done
[ ${#INDICES[@]} -gt 0 ] || INDICES=(0 1 2 3 4)
case $MODE in seal|verify|shred-originals) ;; *) sed -n 3,29p "$0"; exit 2;; esac
SET="$KEYS/attestors.set"
[ -f "$SET" ] || die "$SET missing"

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
[ -x "$BIN" ] || die "$BIN is not executable (cargo build --release in the attestor-keystore worktree)"
"$BIN" l2-claim --help | grep -q 'seal-key' || die "$BIN has no l2-claim seal-key"
if [ "$EXPECT" = "$PINNED_SET_HASH" ]; then
  [ "$(sha256 "$SET")" = "$PINNED_SET_SHA256" ] || die "$SET is not the consensus-pinned attestor set file"
fi
python3 - "$SET" "$KEYS" "$EXPECT" "${INDICES[@]}" <<'PY' || die "public key check failed"
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

pass_args() {  # test hook only
  if [ -n "${KEYKIT_PASSFILE_DIR:-}" ]; then echo "$1 $KEYKIT_PASSFILE_DIR/pass-$2"; fi
}

case $MODE in
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
    printf 'attestor %s bundle sha256 %s verified %s\n' "$i" "$(sha256 "$B")" "$(date -u +%FT%TZ)" > "$OUT/attestor-$i.verified"
  done
  (cd "$OUT" && for i in "${INDICES[@]}"; do printf '%s  attestor-%s.sealed\n' "$(sha256 "attestor-$i.sealed")" "$i"; done) > "$OUT/BUNDLES.sha256"
  echo "Verified ${INDICES[*]}. Bundle hashes: $OUT/BUNDLES.sha256 (public; give each operator its line)."
  echo "Next: two offline backups per bundle and the handoff (KEY-HANDOFF-CHECKLIST.md steps 3-4); shred-originals only after that."
  ;;
shred-originals)
  for i in "${INDICES[@]}"; do
    SK="$KEYS/attestor-$i.sk" B="$OUT/attestor-$i.sealed" V="$OUT/attestor-$i.verified"
    [ -f "$SK" ] || { echo "attestor-$i.sk already gone"; continue; }
    [ -f "$V" ] && [ -f "$B" ] || die "attestor $i: no verified bundle; run seal and verify first"
    grep -q "bundle sha256 $(sha256 "$B") " "$V" || die "attestor $i: bundle changed since it was verified; verify again"
    if [ -z "${KEYKIT_PASSFILE_DIR:-}" ]; then
      read -r -p "Type DESTROY $i to overwrite and delete $SK: " answer
      [ "$answer" = "DESTROY $i" ] || { echo "skipped attestor $i"; continue; }
    fi
    size=$(wc -c < "$SK")
    dd if=/dev/urandom of="$SK" bs="$size" count=1 conv=notrunc 2>/dev/null
    sync
    rm -f "$SK"
    echo "attestor-$i.sk overwritten and deleted"
  done
  echo "Note: on an SSD with APFS an overwrite is not guaranteed to reach the old blocks; FileVault"
  echo "(on) keeps them encrypted at rest. Also empty any Trash/backup/snapshot that holds a copy."
  ;;
esac
