#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Operator side: check an attestor bundle (operator-I.tar from the key holder) and the Linux artifacts
# BEFORE installing. Run from inside the extracted operator-I/ directory, as any user. Read-only,
# except that it writes artifacts/SHA256SUMS when that file is missing and every pin matched.
#
#   ./check-operator-bundle.sh [--artifacts DIR] [--open] [--rehearsal]
#
# 1. Every file of the bundle matches CONTENTS.sha256.
# 2. attestors.set is the consensus-pinned set 1c06adbb… (its file hash and its set hash), the kit's
#    public/attestors.set is the same file, and attestor-I.pk is key I of it.
# 3. Every artifact in DIR (default ./artifacts) matches ARTIFACTS.sha256: bloch-pos, the v2
#    bloch-l2-native-follower and bloch-l2-produce-dev, mainnet.manifest and carryover.tsv.gz.
#    The installer itself does not pin the follower binary, so this is where it is checked.
# 4. bloch-pos (from DIR) reads the sealed key's public header: index I, set 1c06adbb….
# 5. --open: bloch-pos opens the sealed key with the transport passphrase you type and proves it signs
#    for public key I. Nothing is written. (install-attestor.sh does the same check again.)
# --rehearsal accepts a throwaway set (never use it with a real bundle).
set -euo pipefail
PINNED_SET_HASH=1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b
PINNED_SET_SHA256=9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0
cd "$(dirname "$0")"
ART=./artifacts OPEN=0 REHEARSAL=0
while [ $# -gt 0 ]; do
  case $1 in
    --artifacts) ART=$2; shift 2;; --open) OPEN=1; shift;; --rehearsal) REHEARSAL=1; shift;;
    *) sed -n 3,21p "$0"; exit 2;;
  esac
done
die() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# 1. bundle integrity
[ -f CONTENTS.sha256 ] && [ -f IDENTITY.txt ] || die "run this from inside the extracted operator-I directory"
while read -r h f; do
  [ -f "$f" ] || die "$f listed in CONTENTS.sha256 is missing"
  [ "$(sha256 "$f")" = "$h" ] || die "$f does not match CONTENTS.sha256"
done < CONTENTS.sha256
ok "all $(wc -l < CONTENTS.sha256 | tr -d ' ') bundle files match CONTENTS.sha256"
I=$(awk '$1=="attestor_index"{print $2}' IDENTITY.txt)
SETHASH=$(awk '$1=="set_hash"{print $2}' IDENTITY.txt)
[[ $I =~ ^[0-4]$ ]] || die "IDENTITY.txt has no attestor_index"
SEALED=attestor-$I.sealed
[ -f "$SEALED" ] || die "$SEALED missing"

# 2. the set and the public key
if [ $REHEARSAL = 1 ]; then
  echo "REHEARSAL: accepting the THROWAWAY set $SETHASH (not the pinned 1c06adbb…)"
else
  [ "$SETHASH" = "$PINNED_SET_HASH" ] || die "IDENTITY.txt names set $SETHASH, not the pinned $PINNED_SET_HASH"
  [ "$(sha256 attestors.set)" = "$PINNED_SET_SHA256" ] || die "attestors.set is not the pinned set file"
  [ "$(sha256 kit/public/attestors.set)" = "$PINNED_SET_SHA256" ] || die "kit/public/attestors.set is not the pinned set file"
fi
python3 -I - attestors.set "attestor-$I.pk" "$I" "$SETHASH" <<'PY' || die "set / public key check failed"
import hashlib, sys
setf, pkf, i, expect = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
lines = [l.strip() for l in open(setf) if l.strip()]
k, keys = int(lines[0]), [bytes.fromhex(l) for l in lines[1:]]
h = hashlib.sha3_256(b'BLOCH:L2:ATTESTOR-SET:1' + bytes([k, len(keys)]) + b''.join(keys)).hexdigest()
if h != expect: sys.exit(f'set hash {h} is not {expect}')
if bytes.fromhex(open(pkf).read().strip()) != keys[i]: sys.exit(f'{pkf} is not key {i} of the set')
print(f'ok: set {h[:16]}… {k}-of-{len(keys)}; attestor-{i}.pk is key {i}')
PY

# 3. artifacts against the pins
[ -d "$ART" ] || die "artifacts directory $ART not found (give --artifacts DIR)"
while read -r h f; do
  [ -f "$ART/$f" ] || die "$ART/$f missing"
  [ "$(sha256 "$ART/$f")" = "$h" ] || die "$ART/$f does not match its pin $h"
  ok "$f $h"
done < ARTIFACTS.sha256
[ -f "$ART/carryover.tsv.gz.sha256" ] || die "$ART/carryover.tsv.gz.sha256 missing (the installer needs it)"
if [ -f "$ART/SHA256SUMS" ]; then
  while read -r h f; do
    case $f in bloch-pos|bloch-l2-native-follower|bloch-l2-produce-dev)
      [ "$h" = "$(awk -v n="$f" '$2==n{print $1}' ARTIFACTS.sha256)" ] || die "$ART/SHA256SUMS disagrees with the pins on $f";;
    esac
  done < "$ART/SHA256SUMS"
  ok "$ART/SHA256SUMS agrees with the pins"
else
  grep -E '  (bloch-pos|bloch-l2-native-follower|bloch-l2-produce-dev)$' ARTIFACTS.sha256 > "$ART/SHA256SUMS"
  ok "wrote $ART/SHA256SUMS from the pins"
fi

# 4./5. the sealed key
[ "$(uname -s)" = Linux ] || die "the artifacts are Linux x86_64 binaries; run this on the attestor host"
info=$("$ART/bloch-pos" l2-claim key-info --sealed "$SEALED") || die "$SEALED is not a sealed attestor key"
grep -qx "signer_index $I" <<<"$info" || die "$SEALED is not attestor $I"
grep -qx "set_hash $SETHASH" <<<"$info" || die "$SEALED is sealed for another set"
ok "$SEALED header: attestor $I of set ${SETHASH:0:16}…"
if [ $OPEN = 1 ]; then
  echo "Type the TRANSPORT passphrase of attestor $I (received over the second channel):"
  "$ART/bloch-pos" l2-claim key-check --sealed "$SEALED" --attestors attestors.set --signer-index "$I"
fi
echo "BUNDLE OK for attestor $I. Next: INSTALL.md step 4 (install-attestor.sh install)."
