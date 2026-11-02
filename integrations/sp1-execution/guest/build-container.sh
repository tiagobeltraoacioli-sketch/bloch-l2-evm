#!/usr/bin/env bash
# Build the complete-witness guests of one commit (bloch-evm-synthetic-guest,
# settlement_v2, settlement_v3, settlement_v3_mainnet) inside the pinned
# container of the sparse guests (../guest-sparse/container/Dockerfile), so
# that the ELF does not depend on the build host. `settlement_v3_mainnet` of
# the fork tree is the next rules under the complete witness: the program that
# native `PROGRAM_FALLBACK` names.
#
# Same image, inputs and checks as ../guest-sparse/build-container.sh; only the
# crate (working directory) and the program list differ.
#
# Usage: build-container.sh OUT_DIR [REV]
#   DOCKER       docker command (default "docker"; for example a sudo wrapper)
#   WORK         host scratch directory (default /tmp/bloch-guest-complete-container);
#                its contents are replaced
#   DOWNLOADS    directory with the two release tarballs; fetched when missing
#   MEMORY       container memory cap (default 24g)
#   KEEP_CARGO=1 reuse WORK/cargo (the crate registry) from an earlier run
#
# Writes OUT_DIR/<program>, OUT_DIR/SHA256SUMS ("sha256  name" lines) and
# OUT_DIR/build-info.txt. Refuses an ELF that embeds a host path. Two hosts that
# print the same SHA256SUMS have built the same programs.
set -euo pipefail
out="$1"; rev="${2:-HEAD}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
commit="$(git -C "$repo" rev-parse --verify "$rev^{commit}")"
docker="${DOCKER:-docker}"
work="${WORK:-/tmp/bloch-guest-complete-container}"
downloads="${DOWNLOADS:-$work/downloads}"
crate=integrations/sp1-execution/guest
dockerfile=integrations/sp1-execution/guest-sparse/container/Dockerfile
programs=(bloch-evm-synthetic-guest settlement_v2 settlement_v3 settlement_v3_mainnet)

fetch() { # name url sha256
  if [[ ! -f $downloads/$1 ]]; then curl -fsSL -o "$downloads/$1.part" "$2" && mv "$downloads/$1.part" "$downloads/$1"; fi
  echo "$3  $downloads/$1" | sha256sum -c - >&2
}
mkdir -p "$work" "$downloads"
fetch cargo_prove_v6.8.0_linux_amd64.tar.gz \
  https://github.com/succinctlabs/sp1/releases/download/v6.8.0/cargo_prove_v6.8.0_linux_amd64.tar.gz \
  6b25f9fb1e04009d264b17b7d4bd770bffa900cc004cab7fd4d44a675cf70c42
fetch rust-toolchain-x86_64-unknown-linux-gnu.tar.gz \
  https://github.com/succinctlabs/rust/releases/download/succinct-1.96.0-64bit-v2/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz \
  ff3afc3a6f22af93d162652972f254fcecf443ca4b2de18897312f19997fb94b

# The image, from a context holding only the Dockerfile and the two checked tarballs.
ctx="$work/context"; rm -rf "$ctx"; mkdir -p "$ctx"
git -C "$repo" show "$commit:$dockerfile" > "$ctx/Dockerfile"
cp "$downloads"/cargo_prove_v6.8.0_linux_amd64.tar.gz "$downloads"/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz "$ctx/"
tag="bloch-sparse-guest-builder:$(sha256sum "$ctx/Dockerfile" | cut -c1-12)"
$docker build -q -t "$tag" "$ctx" >&2
image="$($docker image inspect --format '{{.Id}}' "$tag")"

# Sources of exactly one commit at a fixed path; the registry at a fixed path.
src="$work/bloch-l2-evm"; rm -rf "$src"; mkdir -p "$src"
git -C "$repo" archive "$commit" | tar -x -C "$src"
if [[ ${KEEP_CARGO:-0} != 1 ]]; then rm -rf "$work/cargo"; fi
mkdir -p "$work/cargo"
remap="--remap-path-prefix=/bloch-l2-evm=/bloch-l2-evm,--remap-path-prefix=/cargo=/cargo"
$docker run --rm --memory "${MEMORY:-24g}" --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$src:/bloch-l2-evm" -v "$work/cargo:/cargo" -w "/bloch-l2-evm/$crate" "$image" \
  cargo prove build --locked "--rustflags=$remap" >&2
versions="$($docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp "$image" sh -c 'cargo prove --version; rustc +succinct -vV | head -1; rustc -vV | head -1')"

mkdir -p "$out"
elf_dir="$src/$crate/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"
: > "$out/SHA256SUMS"
for name in "${programs[@]}"; do
  if [[ $(strings "$elf_dir/$name" | grep -cF -e "$work" -e "$repo" -e "$HOME") != 0 ]]; then
    echo "$name embeds a host path" >&2; exit 1
  fi
  cp "$elf_dir/$name" "$out/$name"
  (cd "$out" && sha256sum "$name") >> "$out/SHA256SUMS"
done
{ echo "commit $commit"; echo "image $image"; echo "$versions"; echo "host $(uname -srm)"; } > "$out/build-info.txt"
cat "$out/SHA256SUMS"
