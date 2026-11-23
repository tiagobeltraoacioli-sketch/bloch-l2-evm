#!/usr/bin/env bash
# Build the SP1 guest programs (bloch-evm-synthetic-guest, settlement_v2,
# settlement_v3, settlement_v3_mainnet, settlement_v3_mainnet_bound) of one commit so that the ELF bytes do not depend on where the
# checkout or the Cargo home live.
#
# Two things made the ELF path-dependent (the same commit built at the M1 and
# M2 worktree paths gave 6dd5f5a3… and a80aa3a5…):
#
# 1. absolute source paths embedded in panic locations and tracing call sites;
# 2. Cargo's -C metadata of `bloch-l2-evm`, a path dependency outside the
#    guest's own workspace, which hashes its ABSOLUTE path into every symbol
#    name (and so into section layout). Path remapping cannot fix this one.
#
# So the commit is exported with `git archive` into a FIXED directory
# ($BLOCH_GUEST_BUILD_ROOT, default /tmp/bloch-guest-build, then
# bloch-l2-evm/) and built there, with the remaining absolute prefixes
# remapped: the build root -> /bloch-l2-evm and $CARGO_HOME -> /cargo
# (registry sources and the git patches). The script refuses an ELF that still
# contains either local prefix.
#
# Inputs that still change the ELF, pinned with it: the commit (sources and
# Cargo.lock, including patch commits), SP1 CLI 6.8.0, the `succinct`
# rustc (succinct-1.96.0-64bit-v2, docs/SP1-TOOLCHAIN.md) and the compiler's
# host platform (only macOS x86_64 measured so far).
#
# Usage: build-reproducible.sh [--commit REV] [--out DIR] [--clean]
#   default REV is HEAD (uncommitted changes are NOT built); --out copies the
#   ELFs to DIR; --clean discards the cached target of the fixed build root.
#   CARGO_PROVE: SP1 CLI command (default "cargo prove"); CARGO_BUILD_JOBS
#   defaults to 2. Prints "sha256  name" for each program on stdout.
set -euo pipefail

guest_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$(git -C "$guest_dir" rev-parse --show-toplevel)"
rev=HEAD out="" clean=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit) rev="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --clean) clean=1; shift ;;
    *) echo "usage: $0 [--commit REV] [--out DIR] [--clean]" >&2; exit 2 ;;
  esac
done
commit="$(git -C "$repo" rev-parse --verify "$rev^{commit}")"
if [[ $rev == HEAD && -n "$(git -C "$repo" status --porcelain)" ]]; then
  echo "note: building committed HEAD $commit; uncommitted changes are ignored" >&2
fi

root="${BLOCH_GUEST_BUILD_ROOT:-/tmp/bloch-guest-build}"
src="$root/bloch-l2-evm"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
mkdir -p "$root"
root="$(cd "$root" && pwd -P)"
src="$root/bloch-l2-evm"
case "$src$cargo_home" in
  *" "* | *","*) echo "paths with spaces or commas cannot be remapped" >&2; exit 2 ;;
esac
# Keep the previous target (same fixed path, so it stays valid) unless --clean.
cache="$root/guest-target.cache"
rm -rf "$cache"
if [[ $clean == 0 && -d $src/integrations/sp1-execution/guest/target ]]; then
  mv "$src/integrations/sp1-execution/guest/target" "$cache"
fi
rm -rf "$src"
mkdir -p "$src"
git -C "$repo" archive "$commit" | tar -x -C "$src"
if [[ -d $cache ]]; then
  mv "$cache" "$src/integrations/sp1-execution/guest/target"
fi

# Comma-separated: the SP1 CLI splits --rustflags on commas into rustc arguments.
remap="--remap-path-prefix=$src=/bloch-l2-evm,--remap-path-prefix=$cargo_home=/cargo"
echo "building $commit in $src" >&2
(cd "$src/integrations/sp1-execution/guest" &&
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" ${CARGO_PROVE:-cargo prove} build --locked "--rustflags=$remap" >&2)

elf_dir="$src/integrations/sp1-execution/guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"
for name in bloch-evm-synthetic-guest settlement_v2 settlement_v3 settlement_v3_mainnet settlement_v3_mainnet_bound; do
  # Count (not grep -q): an early grep exit would fail `strings` under pipefail.
  if [[ $(strings "$elf_dir/$name" | grep -cF -e "$root" -e "$cargo_home" -e "$repo") != 0 ]]; then
    echo "$name still embeds a local absolute path" >&2
    exit 1
  fi
  shasum -a 256 "$elf_dir/$name" | sed "s|  .*|  $name|"
  if [[ -n $out ]]; then
    mkdir -p "$out"
    cp "$elf_dir/$name" "$out/$name"
  fi
done
