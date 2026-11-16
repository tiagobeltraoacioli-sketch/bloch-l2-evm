#!/usr/bin/env bash
# Build the Bloch L2 mainnet (chain 700770) program pins on a Linux build box.
# No keys, no network services. Layout: WORK/src/{bloch-l2-evm,bloch-validator-payout,
# reth-bloch-rpc-snapshot} side by side (as for devnet4, docs/DEVNET4-RECIPE.md),
# and the guest ELF built with integrations/sp1-execution/guest/scripts/build-reproducible.sh
# (the ELF is pinned where it was built; see docs/MAINNET-PROGRAM.md).
#
# Usage: build-program.sh WORK ELF [NATIVE_TREE]
#   NATIVE_TREE (default WORK/src/bloch-validator-payout): the native tree whose
#   policy_commitment_v3() must equal the host's proof_policy_v3 (use the tree that
#   carries l2_settlement::mainnet).
# Writes WORK/out/{bloch-evm-sp1-settlement-v3,bloch-l2-produce-dev,identity.json,
# l2-genesis.json,program.json} and prints program.json (with the Rust PROGRAM literal).
set -euo pipefail
work=$(cd "$1" && pwd -P); elf=$(cd "$(dirname "$2")" && pwd -P)/$(basename "$2"); native=${3:-$work/src/bloch-validator-payout}
l2=$work/src/bloch-l2-evm
out=$work/out
mkdir -p "$out"
log() { echo "== $* ($(date -u +%FT%TZ))" >&2; }
# Pinned values (bloch-l2-evm src/chainspec.rs; verified by its tests).
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733   # MAINNET_DOMAIN
GENESIS_TIME=1786656679                                                    # MAINNET_GENESIS_TIMESTAMP
G4_NETWORK=f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966 # GENESIS4_NETWORK_DOMAIN
G4_GENESIS=9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415 # Genesis-4 genesis block id
NET=(--rules mainnet --domain "$DOMAIN" --genesis-time "$GENESIS_TIME")
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
jobs=${CARGO_BUILD_JOBS:-8}

log "settlement V3 prover host (source-settlement, node-artifact)"
# build-prover-host.sh builds it in the fixed directory of build-root.sh with the path prefixes remapped, so
# that the host is the same binary wherever WORK is (its header says why both are needed).
HOST_FEATURES=source-settlement,node-artifact JOBS=$jobs PROTOC=${PROTOC:-/usr/bin/protoc} \
  bash "$l2/deployment/mainnet/build-prover-host.sh" "$work" "$work/out-host" >&2
cp "$work/out-host/bloch-evm-sp1-settlement-v3" "$out/"

log "bloch-l2-produce-dev"
CARGO_TARGET_DIR=$work/l2-target CARGO_BUILD_JOBS=$jobs cargo +1.98.1 build --release --locked \
  --manifest-path "$l2/integrations/settlement-recovery/Cargo.toml" --bin bloch-l2-produce-dev >&2
cp "$work/l2-target/release/bloch-l2-produce-dev" "$out/"

log "native policy_commitment_v3 ($native)"
policy=$(cd "$native" && CARGO_TARGET_DIR=$work/native-target CARGO_BUILD_JOBS=$jobs \
  cargo +1.94.1 test --locked -p bloch-l2-proof print_policy_commitment_v3 -- --ignored --nocapture 2>/dev/null \
  | sed -n 's/^policy_commitment_v3 //p')
[[ ${#policy} == 64 ]] || { echo "no native policy" >&2; exit 1; }

log "program identity (SP1 setup, no proof) and sanity execution"
"$out/bloch-evm-sp1-settlement-v3" --mainnet identity "$elf" > "$out/identity.json"
"$out/bloch-evm-sp1-settlement-v3" --mainnet execute empty "$elf" >&2

log "L2 genesis (two independent inits must agree)"
rm -rf "$work/l2-genesis" "$work/l2-genesis-check"
"$out/bloch-l2-produce-dev" init --target "$work/l2-genesis" "${NET[@]}" >&2
"$out/bloch-l2-produce-dev" init --target "$work/l2-genesis-check" "${NET[@]}" >&2
"$out/bloch-l2-produce-dev" head --target "$work/l2-genesis" "${NET[@]}" > "$out/l2-genesis.json"
cmp <("$out/bloch-l2-produce-dev" head --target "$work/l2-genesis-check" "${NET[@]}") "$out/l2-genesis.json"

python3 "$l2/deployment/mainnet/make_native_program.py" --identity "$out/identity.json" \
  --genesis "$out/l2-genesis.json" --native-policy "$policy" --network "$G4_NETWORK" \
  --native-genesis "$G4_GENESIS" --elf "$elf" > "$out/program.json"
sha256sum "$out/bloch-evm-sp1-settlement-v3" "$out/bloch-l2-produce-dev" "$elf" >&2
cat "$out/program.json"
