#!/bin/bash
# Agent 137 copy of agents 75/81/116's prep-build.sh for the forced-inclusion crossing.
# QUALIFICATION ONLY, never released: forced L1 and L2 builds for the program-swap rehearsal with L1 forced inclusion.
#   prep-build.sh A GATE   the swap at epoch GATE, forced inclusion enabled at the same boundary, no head reset
#   prep-build.sh B GATE   the same with a head reset to the L2 genesis
# Sources: $A/src/bloch-validator-payout (native, NATIVE_REV) and $A/src/bloch-l2-evm (L2, L2_REV), staged fresh by
# stage.sh. Flag day e4, HF1 e5 (own target e7), HF2 e9, HF3 e10, as in the full-stack rehearsal r3. KES enforcement stays
# at 8620, so the compile-time order check of the next-program gate is removed in the forced copy only. The arming and gate
# tools come from the native source itself (scripts/hf-rehearsal/arm.py, scripts/hf-release/hf-gates.py). The throwaway
# attestor set is public data of an earlier rehearsal (ATTESTORS_SET); this run makes no large claim.
# Builds need cargo, the 1.94.1 and 1.98.1 toolchains and protoc (PROTOC, default $HOME/tools/protoc/bin/protoc); no SP1
# execution or proof runs here, so a host whose /dev/shm is full can build.
set -euo pipefail
V=$1; G=$2
A=${NC:-$HOME/l2dexbridge-20261030/forced-guest-r8}
ATTESTORS_SET=${ATTESTORS_SET:-$HOME/l2dexbridge-20261030/fork-candidate-r7/tools/attestors.set}
PROTOC=${PROTOC:-$HOME/tools/protoc/bin/protoc}
E=4; HF1=5; OWN=7; HF2=9; HF3=10
log() { echo "== $* ($(date -u +%FT%TZ))"; }
B=$A/build-$V; rm -rf "$B"; mkdir -p "$B" "$A/out-$V"
log "forced copy $V, gate e$G (native $(cat "$A/src/NATIVE_REV" 2>/dev/null), L2 $(cat "$A/src/L2_REV" 2>/dev/null))"
cp -a "$A/src/bloch-validator-payout" "$B/bloch-validator-payout"
N=$B/bloch-validator-payout
TOOLS=$N/scripts
P=$N/crates/bloch-pos-committee/src/params.rs
python3 -I "$TOOLS/hf-rehearsal/arm.py" "$N" --no-hf --past-gate 1 --report "$B/arming.json" > "$B/arming.log"
for g in HF1_CLAIM_FINALITY_EPOCH=$HF1 HF1_FROZEN_FINALITY_SET_EPOCH=$HF1 HF1_OWN_TARGET_VOTES_EPOCH=$OWN \
         HF2_SLASHING_V2_EPOCH=$HF2 HF2_GROWTH_CAP_EPOCH=$HF2 SIG_CANONICAL_ACTIVATION_EPOCH=$HF2 MLDSA_PIN_ACTIVATION_EPOCH=$HF2 \
         HF3_KES_EPOCH=$HF3 HF3_SLH_SUITE_EPOCH=$HF3 HF3_PQ_MIGRATION_EPOCH=$HF3 HF2_MIN_EPOCHS_AFTER_HF1=4 \
         L2_NEXT_PROGRAM_EPOCH=$G; do
  python3 -I "$TOOLS/hf-release/hf-gates.py" force --tree "$N" --gate "${g%%=*}" --epoch "${g#*=}" >> "$B/patch.txt"
done
# Forced inclusion opens at the swap boundary. A literal gate is forced; one defined as L2_NEXT_PROGRAM_EPOCH follows it.
if grep -Eq '^pub const L2_FORCED_INCLUSION_EPOCH: u64 = (u64::MAX|[0-9_]+);' "$P"; then
  python3 -I "$TOOLS/hf-release/hf-gates.py" force --tree "$N" --gate L2_FORCED_INCLUSION_EPOCH --epoch "$G" >> "$B/patch.txt"
fi
sed -i '/gate_is_inert_or_not_before(L2_NEXT_PROGRAM_EPOCH/d' "$P"
python3 -I "$A/src/bloch-l2-evm/deployment/mainnet/l1_gates.py" "$P" > "$B/gates.json"
python3 - "$B/gates.json" "$G" <<'EOF'
import json, sys
gates, gate = json.load(open(sys.argv[1])), int(sys.argv[2])
for name in ('L2_NEXT_PROGRAM_EPOCH', 'L2_FORCED_INCLUSION_EPOCH'):
    if gates.get(name) != gate:
        sys.exit(f'forced copy: {name} is {gates.get(name)!r}, not e{gate}')
print('forced copy: L2_NEXT_PROGRAM_EPOCH and L2_FORCED_INCLUSION_EPOCH at e%d' % gate)
EOF
# The candidate must list the next program's configuration as implementing forced inclusion (it is not forced here).
S=$N/crates/bloch-pos-committee/src/l2_settlement.rs
if grep -Eq 'FORCED_INCLUSION_CONFIGURATIONS: &\[\[u8; 32\]\] = &\[\];' "$S"; then
  echo "native FORCED_INCLUSION_CONFIGURATIONS is empty: the queue would never be enabled" >&2; exit 2
fi
# The queue is never enabled without a treasury (TBD-owner on mainnet): a throwaway script hash for the rehearsal only.
if grep -q 'pub const FORCED_INCLUSION_TREASURY: Option<\[u8; 32\]> = None;' "$S"; then
  sed -i 's/pub const FORCED_INCLUSION_TREASURY: Option<\[u8; 32\]> = None;/pub const FORCED_INCLUSION_TREASURY: Option<[u8; 32]> = Some([0x7e; 32]);/' "$S"
  grep -q 'FORCED_INCLUSION_TREASURY: Option<\[u8; 32\]> = Some(\[0x7e; 32\]);' "$S"
fi
cp "$ATTESTORS_SET" "$N/crates/bloch-pos-committee/l2-mainnet/attestors.set"
if [ "$V" = B ]; then
  sed -i 's/pub const HEAD_RESET: Option<HeadReset> = None;/pub const HEAD_RESET: Option<HeadReset> = Some(HeadReset { number: 0, commitment: [0; 32], statement: None });/' "$S"
  grep -q 'HEAD_RESET: Option<HeadReset> = Some' "$S"
fi
export PATH=$HOME/.cargo/bin:/usr/bin:/bin CARGO_BUILD_JOBS=6
log "bloch-pos, forced"
(cd "$N" && BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$E CARGO_TARGET_DIR=$A/native-target \
  nice -n 10 cargo +1.94.1 build -j 6 --locked --release -p bloch-pos-node --bin bloch-pos --features l2-activation-rehearsal-mainnet-policy) > "$B/build-native.log" 2>&1
cp "$A/native-target/release/bloch-pos" "$A/out-$V/bloch-pos"
"$A/out-$V/bloch-pos" --version | tee "$B/version.txt"
if grep -q 'sha3-256:35c2b943' "$B/version.txt"; then echo "forced build reports the release source digest" >&2; exit 2; fi
"$A/out-$V/bloch-pos" l2-forced --help > "$B/l2-forced-help.txt" 2>&1 || "$A/out-$V/bloch-pos" help l2-forced > "$B/l2-forced-help.txt" 2>&1 || true
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
PROTOC=$PROTOC CARGO_TARGET_DIR=$A/sp1-target nice -n 10 cargo +1.98.1 build -j 6 --release --locked \
  --manifest-path "$L/bloch-l2-evm/integrations/sp1-execution/host/Cargo.toml" --features "${HOST_FEATURES:-source-settlement,node-artifact,sparse-witness}" \
  --bin bloch-evm-sp1-settlement-v3 > "$B/build-host.log" 2>&1
cp "$A/sp1-target/release/bloch-evm-sp1-settlement-v3" "$A/out-$V/"
sha256sum "$A/out-$V"/* | tee "$B/out.sha256"
log "BUILD OK $V"
touch "$A/BUILD-DONE-$V"
