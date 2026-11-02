#!/bin/bash
# a81 copy of agent 75 prep-build.sh: native = agent 89 0fbd07a6 (PROGRAM_NEXT = sparse guest), L2 = codex/sparse-export-r6-20261102.
# QUALIFICATION ONLY, never released: forced L1 and L2 builds for the program-swap rehearsal.
#   prep-build.sh A GATE   the swap at epoch GATE, no head reset
#   prep-build.sh B GATE   the swap at epoch GATE with a head reset to the L2 genesis
# Flag day e4, HF1 e5 (own target e7), HF2 e9, HF3 e10, as in the full-stack rehearsal r3. KES enforcement stays at 8620,
# so the compile-time order check of the next-program gate is removed in the forced copy only. Runs from a fresh copy of the
# native source every time. The throwaway attestor set is public data of an earlier rehearsal; this run makes no large claim.
set -euo pipefail
V=$1; G=$2
A=$HOME/l2dexbridge-20261030/sparse-crossing-r6
TOOLS=$A/tools
E=4; HF1=5; OWN=7; HF2=9; HF3=10
log() { echo "== $* ($(date -u +%FT%TZ))"; }
B=$A/build-$V; rm -rf "$B"; mkdir -p "$B" "$A/out-$V"
log "forced copy $V, gate e$G"
cp -a "$A/src/bloch-validator-payout" "$B/bloch-validator-payout"
N=$B/bloch-validator-payout
python3 -I "$TOOLS/arm.py" "$N" --no-hf --past-gate 1 --report "$B/arming.json" > "$B/arming.log"
for g in HF1_CLAIM_FINALITY_EPOCH=$HF1 HF1_FROZEN_FINALITY_SET_EPOCH=$HF1 HF1_OWN_TARGET_VOTES_EPOCH=$OWN \
         HF2_SLASHING_V2_EPOCH=$HF2 HF2_GROWTH_CAP_EPOCH=$HF2 SIG_CANONICAL_ACTIVATION_EPOCH=$HF2 MLDSA_PIN_ACTIVATION_EPOCH=$HF2 \
         HF3_KES_EPOCH=$HF3 HF3_SLH_SUITE_EPOCH=$HF3 HF3_PQ_MIGRATION_EPOCH=$HF3 HF2_MIN_EPOCHS_AFTER_HF1=4 \
         L2_NEXT_PROGRAM_EPOCH=$G; do
  python3 -I "$TOOLS/hf-gates.py" force --tree "$N" --gate "${g%%=*}" --epoch "${g#*=}" >> "$B/patch.txt"
done
sed -i '/gate_is_inert_or_not_before(L2_NEXT_PROGRAM_EPOCH/d' "$N/crates/bloch-pos-committee/src/params.rs"
cp "$TOOLS/attestors.set" "$N/crates/bloch-pos-committee/l2-mainnet/attestors.set"
if [ "$V" = B ]; then
  sed -i 's/pub const HEAD_RESET: Option<HeadReset> = None;/pub const HEAD_RESET: Option<HeadReset> = Some(HeadReset { number: 0, commitment: [0; 32], statement: None });/' \
    "$N/crates/bloch-pos-committee/src/l2_settlement.rs"
  grep -q 'HEAD_RESET: Option<HeadReset> = Some' "$N/crates/bloch-pos-committee/src/l2_settlement.rs"
fi
export PATH=$HOME/.cargo/bin:/usr/bin:/bin CARGO_BUILD_JOBS=6
log "bloch-pos, forced"
(cd "$N" && BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$E CARGO_TARGET_DIR=$A/native-target \
  nice -n 10 cargo +1.94.1 build -j 6 --locked --release -p bloch-pos-node --bin bloch-pos --features l2-activation-rehearsal-mainnet-policy) > "$B/build-native.log" 2>&1
cp "$A/native-target/release/bloch-pos" "$A/out-$V/bloch-pos"
"$A/out-$V/bloch-pos" --version | tee "$B/version.txt"
L=$B/l2; mkdir -p "$L"
cp -a "$A/src/bloch-l2-evm" "$L/bloch-l2-evm"
cp -a "$N" "$L/bloch-validator-payout"
ln -s "$A/src/reth-bloch-rpc-snapshot" "$L/reth-bloch-rpc-snapshot"
python3 "$L/bloch-l2-evm/deployment/mainnet/follower-rpc/native-feature-shim.py" "$L/bloch-validator-payout"
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
log "produce-dev and follower against the forced native (unlocked: the tree lock targets 78d4921c)"
BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$E CARGO_TARGET_DIR=$A/l2-target nice -n 10 cargo +1.98.1 build -j 6 --release \
  --manifest-path "$L/bloch-l2-evm/integrations/settlement-recovery/Cargo.toml" \
  --features bloch-pos-committee/l2-activation-rehearsal-mainnet-policy,bloch-pos-node/l2-activation-rehearsal-mainnet-policy \
  --bin bloch-l2-produce-dev --bin bloch-l2-native-follower > "$B/build-l2.log" 2>&1
cp "$A/l2-target/release/bloch-l2-produce-dev" "$A/l2-target/release/bloch-l2-native-follower" "$A/out-$V/"
log "settled RPC and prover host"
CARGO_TARGET_DIR=$A/l2-target nice -n 10 cargo +1.98.1 build -j 6 --release \
  --manifest-path "$L/bloch-l2-evm/integrations/reth-execution/Cargo.toml" --bin bloch-l2-settled-rpc > "$B/build-rpc.log" 2>&1
cp "$A/l2-target/release/bloch-l2-settled-rpc" "$A/out-$V/"
PROTOC=$HOME/tools/protoc/bin/protoc CARGO_TARGET_DIR=$A/sp1-target nice -n 10 cargo +1.98.1 build -j 6 --release --locked \
  --manifest-path "$L/bloch-l2-evm/integrations/sp1-execution/host/Cargo.toml" --features source-settlement,node-artifact,sparse-witness \
  --bin bloch-evm-sp1-settlement-v3 > "$B/build-host.log" 2>&1
cp "$A/sp1-target/release/bloch-evm-sp1-settlement-v3" "$A/out-$V/"
sha256sum "$A/out-$V"/* | tee "$B/out.sha256"
log "BUILD OK $V"
touch "$A/BUILD-DONE-$V"
