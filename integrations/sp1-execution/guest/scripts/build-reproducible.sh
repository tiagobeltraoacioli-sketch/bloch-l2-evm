#!/usr/bin/env bash
# Build the SP1 guest programs (bloch-evm-synthetic-guest, settlement_v2,
# settlement_v3) so that their ELF bytes do not depend on where the sources or
# the Cargo home live.
#
# Without this, the ELF embeds absolute source paths (panic locations and
# tracing call sites): the same commit built at ~/worktrees/l2-v3-m1-20261010
# and ~/worktrees/l2-v3-m2-20261010 gave different ELFs, hence different SP1
# keys and a different genesis policy. Every absolute prefix that reaches the
# compiler is remapped to a fixed virtual path:
#
#   <repository root>  -> /bloch-l2-evm
#   $CARGO_HOME        -> /cargo          (registry sources, git patches)
#
# Remaining inputs that DO change the ELF, and are pinned elsewhere: the
# sources and Cargo.lock (commit), the SP1 CLI (v6.8.0) and the `succinct`
# rustc (succinct-1.96.0-64bit-v2, see docs/SP1-TOOLCHAIN.md), and the host
# platform of that compiler (only macOS x86_64 was measured).
#
# Usage: build-reproducible.sh [--out DIR]
#   CARGO_PROVE  command for the SP1 CLI (default: "cargo prove")
#   CARGO_BUILD_JOBS defaults to 2.
# Prints "sha256  name" for each ELF; with --out also copies them to DIR.
set -euo pipefail

guest_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo_root="$(cd "$guest_dir/../../.." && pwd -P)"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
out=""
if [[ $# -eq 2 && $1 == --out ]]; then
  out="$2"
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--out DIR]" >&2
  exit 2
fi
case "$repo_root$cargo_home" in
  *" "* | *","*) echo "paths with spaces or commas cannot be remapped" >&2; exit 2 ;;
esac

# Comma-separated: the SP1 CLI splits --rustflags on commas into rustc arguments.
remap="--remap-path-prefix=$repo_root=/bloch-l2-evm,--remap-path-prefix=$cargo_home=/cargo"
cd "$guest_dir"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" ${CARGO_PROVE:-cargo prove} build --locked "--rustflags=$remap" >&2

elf_dir="$guest_dir/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"
for name in bloch-evm-synthetic-guest settlement_v2 settlement_v3; do
  # Count (not grep -q): an early grep exit would fail `strings` under pipefail.
  if [[ $(strings "$elf_dir/$name" | grep -cF -e "$repo_root" -e "$cargo_home") != 0 ]]; then
    echo "$name still embeds a local absolute path" >&2
    exit 1
  fi
  shasum -a 256 "$elf_dir/$name" | sed "s|  .*|  $name|"
  if [[ -n $out ]]; then
    mkdir -p "$out"
    cp "$elf_dir/$name" "$out/$name"
  fi
done
