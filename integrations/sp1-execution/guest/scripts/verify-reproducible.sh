#!/usr/bin/env bash
# Check that one commit's guest ELFs are byte-identical when built from two
# different checkouts. The commit (default HEAD) is exported with `git archive`
# into two differently named directories under a scratch root; each copy's own
# build-reproducible.sh then builds it from a clean target (--clean) in the
# fixed build root, and the SHA-256 of every ELF is compared. Exit 0 only if
# all match. Optionally compare with an expected list ("sha256  name" lines,
# for example a pinned recipe value).
#
# Usage: verify-reproducible.sh [COMMIT] [SCRATCH_ROOT] [EXPECTED_FILE]
set -euo pipefail

repo="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
commit="$(git -C "$repo" rev-parse --verify "${1:-HEAD}^{commit}")"
scratch="${2:-$(mktemp -d)}"
expected="${3:-}"
a="$scratch/a/first-checkout"
b="$scratch/b/second/deeper-checkout"
for dir in "$a" "$b"; do
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$repo" archive "$commit" | tar -x -C "$dir"
  # A repository is needed for `git archive` inside the copy.
  git -C "$dir" init -q
  git -C "$dir" -c user.name=verify -c user.email=verify@localhost add -A
  git -C "$dir" -c user.name=verify -c user.email=verify@localhost commit -q -m snapshot
done
echo "commit $commit" >&2
"$a/integrations/sp1-execution/guest/scripts/build-reproducible.sh" --clean > "$scratch/a.sha256"
"$b/integrations/sp1-execution/guest/scripts/build-reproducible.sh" --clean > "$scratch/b.sha256"
echo "== $a"; cat "$scratch/a.sha256"
echo "== $b"; cat "$scratch/b.sha256"
if ! cmp -s "$scratch/a.sha256" "$scratch/b.sha256"; then
  echo "NOT REPRODUCIBLE" >&2
  exit 1
fi
if [[ -n $expected ]] && ! cmp -s "$scratch/a.sha256" "$expected"; then
  echo "REPRODUCIBLE, but different from $expected" >&2
  exit 1
fi
echo "REPRODUCIBLE: identical ELFs from two checkouts"
