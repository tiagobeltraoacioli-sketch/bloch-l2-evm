#!/bin/bash
# Private mainnet-path rehearsal build on 45.77 (ubuntu, no keys, no services).
# Native: dd287b6c (= release 78b7343a + docs) with l2-activation-rehearsal-mainnet-policy
# at epoch $E. L2: codex/l2-mainnet-rehearsal-20261018. Mainnet ELF: the pinned one.
set -euo pipefail
R=$HOME/l2-mainnet-rehearsal-20261018
P=$HOME/l2-program-mainnet-20261014
E=${E:-4}
JOBS=${JOBS:-16}
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
log() { echo "== $* ($(date -u +%FT%TZ))"; }
mkdir -p $R/out
for t in sp1-target l2-target; do
  [ -d $R/$t ] || { log "seed $t"; cp -a --reflink=auto $P/$t $R/$t; }
done
[ -d $R/native-target ] || { log "seed native-target"; cp -a --reflink=auto $HOME/bloch-l2-devnet4-20261012/build-finality/../build/native-target $R/native-target 2>/dev/null || mkdir -p $R/native-target; }

log "native bloch-pos rehearsal-mainnet-policy epoch $E"
(cd $R/src/bloch-validator-payout && BLOCH_BUILD_COMMIT=dd287b6c BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$E \
  CARGO_TARGET_DIR=$R/native-target CARGO_BUILD_JOBS=$JOBS \
  cargo +1.94.1 build --locked --release -p bloch-pos-node --bin bloch-pos --features l2-activation-rehearsal-mainnet-policy) > $R/build-native.log 2>&1
cp $R/native-target/release/bloch-pos $R/out/bloch-pos
$R/out/bloch-pos --version

# Native 78b7343a lacks the devnet-kes/devnet-lc-roster names settlement-recovery
# forwards: the same inert shim as the release build (deployment/mainnet/build-release.sh).
python3 $R/src/bloch-l2-evm/deployment/mainnet/follower-rpc/native-feature-shim.py $R/src/bloch-validator-payout
cp $R/src/bloch-l2-evm/deployment/mainnet/follower-rpc/settlement-recovery.mainnet.Cargo.lock \
  $R/src/bloch-l2-evm/integrations/settlement-recovery/Cargo.lock
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
log "produce-dev + follower (rehearsal-mainnet-policy epoch $E)"
BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$E CARGO_TARGET_DIR=$R/l2-target CARGO_BUILD_JOBS=$JOBS cargo +1.98.1 build --release --locked \
  --manifest-path $R/src/bloch-l2-evm/integrations/settlement-recovery/Cargo.toml \
  --features bloch-pos-committee/l2-activation-rehearsal-mainnet-policy,bloch-pos-node/l2-activation-rehearsal-mainnet-policy \
  --bin bloch-l2-produce-dev --bin bloch-l2-native-follower > $R/build-l2.log 2>&1
cp $R/l2-target/release/bloch-l2-produce-dev $R/l2-target/release/bloch-l2-native-follower $R/out/
log "settled rpc"
CARGO_TARGET_DIR=$R/l2-target CARGO_BUILD_JOBS=$JOBS cargo +1.98.1 build --release --locked \
  --manifest-path $R/src/bloch-l2-evm/integrations/reth-execution/Cargo.toml --bin bloch-l2-settled-rpc > $R/build-rpc.log 2>&1
cp $R/l2-target/release/bloch-l2-settled-rpc $R/out/
log "prover host"
PROTOC=/usr/bin/protoc CARGO_TARGET_DIR=$R/sp1-target CARGO_BUILD_JOBS=$JOBS cargo +1.98.1 build --release --locked \
  --manifest-path $R/src/bloch-l2-evm/integrations/sp1-execution/host/Cargo.toml \
  --features source-settlement,node-artifact --bin bloch-evm-sp1-settlement-v3 > $R/build-prover.log 2>&1
cp $R/sp1-target/release/bloch-evm-sp1-settlement-v3 $R/out/
cp $P/settlement_v3_mainnet $R/out/
log "identity"
$R/out/bloch-evm-sp1-settlement-v3 --mainnet identity $R/out/settlement_v3_mainnet > $R/out/identity.json
cat $R/out/identity.json
sha256sum $R/out/*
log "BUILD OK"
