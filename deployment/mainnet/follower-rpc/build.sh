#!/bin/bash
# Build the MAINNET native follower and settled RPC (chain id 700770).
# No devnet features. Builds only: no key, no service, no network transaction.
#
# Layout (siblings, as every L2 integration crate expects):
#   $SRC/bloch-l2-evm             this branch
#   $SRC/bloch-validator-payout   native mainnet release 78b7343a (bloch-sis-pow)
#   $SRC/reth-bloch-rpc-snapshot  8eb21017 + reth-snapshot.patch (as for devnet4)
# Usage: build.sh SRC OUT [TARGET_DIR]
set -euo pipefail
SRC=$(cd "$1" && pwd); OUT=$2; TARGET=${3:-$SRC/l2-target}
NATIVE_COMMIT=78b7343a347d2c53944a7058b7cb1c2ca4efe842
HERE=$SRC/bloch-l2-evm/deployment/mainnet/follower-rpc
test "$(git -C "$SRC/bloch-validator-payout" rev-parse HEAD)" = "$NATIVE_COMMIT" || { echo "native checkout is not $NATIVE_COMMIT" >&2; exit 2; }
# The release lacks the devnet-kes/devnet-lc-roster feature names that
# settlement-recovery forwards; add them empty (inert, never enabled).
python3 "$HERE/native-feature-shim.py" "$SRC/bloch-validator-payout"
test -z "$(git -C "$SRC/bloch-validator-payout" status --porcelain | grep -v -E '^ M crates/bloch-pos-(committee|node)/Cargo.toml$')" || { echo "native checkout has other changes" >&2; exit 2; }
# The native release resolves three extra lock entries (bincode/serde, cc).
cp "$HERE/settlement-recovery.mainnet.Cargo.lock" "$SRC/bloch-l2-evm/integrations/settlement-recovery/Cargo.lock"
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
export CARGO_TARGET_DIR=$TARGET
cargo +1.98.1 build --release --locked --manifest-path "$SRC/bloch-l2-evm/integrations/settlement-recovery/Cargo.toml" \
  --bin bloch-l2-native-follower --bin bloch-l2-produce-dev
cargo +1.98.1 build --release --locked --manifest-path "$SRC/bloch-l2-evm/integrations/reth-execution/Cargo.toml" \
  --bin bloch-l2-settled-rpc
git -C "$SRC/bloch-l2-evm" checkout -- integrations/settlement-recovery/Cargo.lock 2>/dev/null || true
mkdir -p "$OUT"
cp "$TARGET/release/bloch-l2-native-follower" "$TARGET/release/bloch-l2-settled-rpc" "$TARGET/release/bloch-l2-produce-dev" "$OUT/"
(cd "$OUT" && sha256sum bloch-l2-native-follower bloch-l2-settled-rpc bloch-l2-produce-dev | tee SHA256SUMS)
