#!/bin/bash
# THE pinned build of the settlement V3 prover host, bloch-evm-sp1-settlement-v3 (the SP1 host). Builds only: no
# key, no service, no network transaction.
#
#   build-prover-host.sh WORK [OUT]      (OUT defaults to WORK/out-host)
#
# WORK/src holds bloch-l2-evm, bloch-validator-payout and reth-bloch-rpc-snapshot as siblings, as for
# build-release.sh. Writes OUT/bloch-evm-sp1-settlement-v3 and OUT/SHA256SUMS.
# Env: HOST_FEATURES (default source-settlement,node-artifact,sparse-witness: the host that serves --mainnet-v1,
# --mainnet and --mainnet --sparse), JOBS (default 8), PROTOC (default /usr/bin/protoc), PROTOC_INCLUDE.
#
# The binary does not depend on where or by whom it is built:
#   * the build runs in the fixed directory of build-root.sh (cargo hashes the absolute paths of the path
#     dependencies into every symbol name);
#   * the paths of the sources, the cargo registry and the target directory are remapped to fixed names. This is
#     set as CARGO_BUILD_RUSTFLAGS, not RUSTFLAGS: the host embeds a runner binary that the build script of
#     sp1-core-executor-runner builds with a nested cargo after REMOVING RUSTFLAGS, so with RUSTFLAGS the embedded
#     binary kept 152 build paths. The nested cargo inherits CARGO_BUILD_RUSTFLAGS and its target directory lies
#     under the mapped one. A caller's RUSTFLAGS would override it and change the binary, so it is refused.
set -euo pipefail
W=$(cd "${1:?usage: build-prover-host.sh WORK [OUT]}" && pwd)
OUT=${2:-$W/out-host}
case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
[ -z "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}${CARGO_BUILD_RUSTFLAGS:-}" ] \
  || { echo "build-prover-host: unset RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS and CARGO_BUILD_RUSTFLAGS (the build sets its own flags)" >&2; exit 2; }
. "$W/src/bloch-l2-evm/deployment/mainnet/build-root.sh"
if [ "${BLOCH_BUILD_STAGED:-}" != "$BLOCH_BUILD_ROOT" ]; then
  stage_build_root "$W"
  BLOCH_BUILD_STAGED=$BLOCH_BUILD_ROOT exec bash "$BLOCH_BUILD_ROOT/src/bloch-l2-evm/deployment/mainnet/build-prover-host.sh" "$BLOCH_BUILD_ROOT" "$OUT"
fi
L2=$W/src/bloch-l2-evm
FEATURES=${HOST_FEATURES:-source-settlement,node-artifact,sparse-witness}
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
export PROTOC=${PROTOC:-/usr/bin/protoc} CARGO_TARGET_DIR=$W/sp1-target CARGO_BUILD_JOBS=${JOBS:-8}
export CARGO_BUILD_RUSTFLAGS="--remap-path-prefix=$W/src=/bloch-build/src --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/bloch-build/cargo --remap-path-prefix=$CARGO_TARGET_DIR=/bloch-build/target"
echo "== settlement V3 prover host ($FEATURES) at $(git -C "$L2" rev-parse HEAD) ($(date -u +%FT%TZ))" >&2
nice cargo +1.98.1 build --release --locked --manifest-path "$L2/integrations/sp1-execution/host/Cargo.toml" \
  --features "$FEATURES" --bin bloch-evm-sp1-settlement-v3 >&2
mkdir -p "$OUT"
install -m 0755 "$CARGO_TARGET_DIR/release/bloch-evm-sp1-settlement-v3" "$OUT/bloch-evm-sp1-settlement-v3"
(cd "$OUT" && sha256sum bloch-evm-sp1-settlement-v3 > SHA256SUMS && cat SHA256SUMS)
echo "== BUILD OK: $OUT ($(date -u +%FT%TZ))" >&2
