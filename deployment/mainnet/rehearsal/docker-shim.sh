#!/bin/bash
# Rehearsal-only docker shim (no daemon, runs as ubuntu): executes /gnark-cli of the
# pinned sp1-gnark image (index sha256:e1a1cd62..., layers verified by digest and
# extracted to gnark/rootfs) with the bind mounts mapped back to host paths.
set -euo pipefail
ROOTFS=/home/ubuntu/l2-mainnet-rehearsal-20261018/gnark/rootfs
PIN=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d
case "${1:-}" in
  info) echo "docker shim: $PIN"; exit 0;;
  run) shift;;
  *) echo "docker shim: unsupported command ${1:-}" >&2; exit 64;;
esac
declare -A MOUNT
while [ $# -gt 0 ]; do
  case "$1" in
    --rm) shift;;
    -v) MOUNT[${2#*:}]=${2%%:*}; shift 2;;
    -u|-e|-w) shift 2;;
    -*) echo "docker shim: unsupported flag $1" >&2; exit 64;;
    *) break;;
  esac
done
image=$1; shift
[ "$image" = "$PIN" ] || { echo "docker shim: image $image is not the pinned $PIN" >&2; exit 65; }
args=()
for a in "$@"; do
  if [ -n "${MOUNT[$a]+x}" ]; then args+=("${MOUNT[$a]}"); else args+=("$a"); fi
done
echo "docker shim: gnark-cli ${args[*]}" >&2
exec "$ROOTFS/gnark-cli" "${args[@]}"
