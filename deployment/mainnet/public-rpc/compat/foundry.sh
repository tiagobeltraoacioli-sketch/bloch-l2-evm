#!/bin/bash
# Foundry (cast/forge) compatibility checks against the public gateway.
#
#   foundry.sh URL WORKDIR
#
# Needs cast and forge on PATH (and a cached or downloadable solc). Uses a
# throwaway key generated here and never written to disk; it holds no funds,
# so cast send must fail with "insufficient funds" from the sequencer.
set -uo pipefail
URL=${1:?usage: foundry.sh URL WORKDIR}
WORK=${2:?usage: foundry.sh URL WORKDIR}
GENESIS=0x632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
ko() { fail=$((fail + 1)); echo "FAIL $1: $2"; }
expect() {
  local name=$1 want=$2 out
  shift 2
  out=$("$@" 2>&1)
  if printf '%s' "$out" | grep -qiE -- "$want"; then ok "$name"; else ko "$name" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"; fi
}

expect 'cast chain-id' '^700770$' cast chain-id --rpc-url "$URL"
for tag in latest pending; do
  expect "cast block $tag" '"sha3Uncles"' cast block "$tag" --rpc-url "$URL" --json
done
# No L2 block is settled yet: safe/finalized are the genesis.
for tag in safe finalized earliest 0; do
  expect "cast block $tag" "$GENESIS" cast block "$tag" --rpc-url "$URL" --json
done
expect 'cast block-number' '^[0-9]+$' cast block-number --rpc-url "$URL"
expect 'cast gas-price' '^[0-9]+$' cast gas-price --rpc-url "$URL"
expect 'cast base-fee' '^[0-9]+$' cast base-fee --rpc-url "$URL"
expect 'cast balance' '^0$' cast balance 0x000000000000000000000000000000000000dEaD --rpc-url "$URL"
expect 'cast nonce pending' '^0$' cast nonce 0x000000000000000000000000000000000000dEaD --block pending --rpc-url "$URL"
expect 'cast code' '^0x$' cast code 0x000000000000000000000000000000000000bEEF --rpc-url "$URL"
expect 'cast estimate' '^21000$' cast estimate --from 0x000000000000000000000000000000000000dEaD 0x000000000000000000000000000000000000bEEF --rpc-url "$URL"
expect 'cast call' '^0x$' cast call 0x000000000000000000000000000000000000bEEF 0x --rpc-url "$URL"
expect 'cast logs' '^(\[\])?$' cast logs --from-block 0 --to-block latest --rpc-url "$URL" --json
expect 'cast rpc bloch_finality' '"finalized":true' cast rpc bloch_finality --rpc-url "$URL"
expect 'cast fee history' 'baseFeePerGas|base_fee' cast rpc eth_feeHistory 0x1 latest '[50]' --rpc-url "$URL"

KEY=$(cast wallet new --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["private_key"])')
expect 'cast send (unfunded) -> insufficient funds from the sequencer' 'insufficient funds' \
  cast send --private-key "$KEY" --rpc-url "$URL" 0x000000000000000000000000000000000000bEEF --value 1
expect 'cast send --legacy (unfunded) -> insufficient funds' 'insufficient funds' \
  cast send --legacy --private-key "$KEY" --rpc-url "$URL" 0x000000000000000000000000000000000000bEEF --value 1

mkdir -p "$WORK/src" "$WORK/script"
cat > "$WORK/foundry.toml" <<'EOF'
[profile.default]
src = "src"
out = "out"
libs = []
evm_version = "cancun"
solc_version = "0.8.28"
EOF
cat > "$WORK/src/Counter.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract Counter {
    uint256 public number;
    function increment() external { number += 1; }
}
EOF
cat > "$WORK/script/Deploy.s.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {Counter} from "../src/Counter.sol";
interface Vm { function startBroadcast(uint256) external; function stopBroadcast() external; }
contract Deploy {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function run() external {
        vm.startBroadcast(uint256(keccak256("bloch-l2-gateway-compat-throwaway")));
        Counter c = new Counter();
        c.increment();
        vm.stopBroadcast();
    }
}
EOF
# Simulation only (no --broadcast): forks the chain over the gateway, runs the
# script, then simulates every transaction on-chain-state and estimates gas.
expect 'forge script (fork + on-chain simulation, no broadcast)' 'SIMULATION COMPLETE|ONCHAIN EXECUTION COMPLETE|Simulated On-chain Traces|Estimated total gas' \
  bash -c "cd '$WORK' && forge script script/Deploy.s.sol:Deploy --rpc-url '$URL' -vv"
echo
echo "$pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
