#!/bin/bash
# Superseded by the single pinned mainnet build: deployment/mainnet/build-release.sh WORK [OUT]
# (follower, settled RPC and producer against native 78b7343a, shim + mainnet lock, SHA256SUMS).
# Kept as a wrapper: build.sh SRC OUT [TARGET_DIR] with SRC = WORK/src.
set -euo pipefail
SRC=$(cd "${1:?usage: build.sh SRC OUT [TARGET_DIR]}" && pwd)
[ "$(basename "$SRC")" = src ] || { echo "SRC must be WORK/src (siblings bloch-l2-evm, bloch-validator-payout, reth-bloch-rpc-snapshot)" >&2; exit 2; }
[ -z "${3:-}" ] || export CARGO_TARGET_DIR=$3
exec "$SRC/bloch-l2-evm/deployment/mainnet/build-release.sh" "$(dirname "$SRC")" "${2:?usage: build.sh SRC OUT [TARGET_DIR]}"
