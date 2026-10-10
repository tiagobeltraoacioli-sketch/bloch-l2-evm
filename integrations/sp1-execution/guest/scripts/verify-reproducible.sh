#!/usr/bin/env bash
# Check that the guest ELFs of one commit are byte-identical when built from
# two different absolute paths. Exports the commit (default HEAD) twice with
# `git archive` into two differently named directories under a scratch root,
# builds both with build-reproducible.sh (fresh target directories), and
# compares the SHA-256 of every ELF. Exit 0 only if all match.
#
# Usage: verify-reproducible.sh [COMMIT] [SCRATCH_ROOT]
set -euo pipefail

repo="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
commit="$(git -C "$repo" rev-parse "${1:-HEAD}")"
scratch="${2:-$(mktemp -d)}"
a="$scratch/a/first-checkout"
b="$scratch/b/second/deeper-checkout"
for dir in "$a" "$b"; do
  mkdir -p "$dir"
  git -C "$repo" archive "$commit" | tar -x -C "$dir"
done
echo "commit $commit" >&2
"$a/integrations/sp1-execution/guest/scripts/build-reproducible.sh" > "$scratch/a.sha256"
"$b/integrations/sp1-execution/guest/scripts/build-reproducible.sh" > "$scratch/b.sha256"
echo "== $a"; cat "$scratch/a.sha256"
echo "== $b"; cat "$scratch/b.sha256"
if cmp -s "$scratch/a.sha256" "$scratch/b.sha256"; then
  echo "REPRODUCIBLE: identical ELFs from two paths"
else
  echo "NOT REPRODUCIBLE" >&2
  exit 1
fi
