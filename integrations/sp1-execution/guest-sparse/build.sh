#!/usr/bin/env bash
# Build the candidate sparse guests of one commit, in the manner of
# ../guest/scripts/build-reproducible.sh: a `git archive` export into a fixed
# directory with local prefixes remapped. A separate crate, so that the feature
# this needs cannot reach the programs built by that script.
# Usage: build.sh OUT_DIR [REV]. CARGO_PROVE defaults to "cargo prove".
set -euo pipefail
out="$1"; rev="${2:-HEAD}"
repo="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
commit="$(git -C "$repo" rev-parse --verify "$rev^{commit}")"
root="${BLOCH_GUEST_BUILD_ROOT:-/tmp/bloch-guest-sparse-build}"
mkdir -p "$root"; root="$(cd "$root" && pwd -P)"; src="$root/bloch-l2-evm"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
cache="$root/guest-target.cache"; rm -rf "$cache"
crate=integrations/sp1-execution/guest-sparse
if [[ -d $src/$crate/target ]]; then mv "$src/$crate/target" "$cache"; fi
rm -rf "$src"; mkdir -p "$src"
git -C "$repo" archive "$commit" | tar -x -C "$src"
if [[ -d $cache ]]; then mv "$cache" "$src/$crate/target"; fi
remap="--remap-path-prefix=$src=/bloch-l2-evm,--remap-path-prefix=$cargo_home=/cargo"
(cd "$src/$crate" && CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" ${CARGO_PROVE:-cargo prove} build --locked "--rustflags=$remap" >&2)
mkdir -p "$out"
for name in settlement_v3_mainnet_sparse settlement_v3_mainnet_sparse_eager settlement_v3_mainnet_v1_sparse; do
  cp "$src/$crate/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/$name" "$out/$name"
  shasum -a 256 "$out/$name" | sed "s|  .*|  $name|"
done
