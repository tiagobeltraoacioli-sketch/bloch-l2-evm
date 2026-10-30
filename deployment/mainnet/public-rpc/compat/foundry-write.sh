#!/bin/bash
# Foundry write-path checks (cast send, forge script --broadcast) against a
# gateway in front of a PRIVATE L2 copy whose blocks are produced from the
# sequencer spool. KEY: throwaway funded key; the forge script broadcasts from
# keccak256("bloch-l2-gateway-compat-throwaway"), which must be funded too.
#   KEY=... foundry-write.sh URL WORKDIR   (WORKDIR prepared by foundry.sh)
set -uo pipefail
URL=${1:?}
WORK=${2:?}
pass=0
fail=0
run() {
  local name=$1 want=$2 out
  shift 2
  out=$("$@" 2>&1)
  if printf '%s' "$out" | grep -qiE -- "$want"; then pass=$((pass + 1)); echo "PASS $name"; else fail=$((fail + 1)); echo "FAIL $name: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-400)"; fi
}
run 'cast send (1559) waits for a receipt' '^status +1 \(success\)' cast send --private-key "$KEY" --rpc-url "$URL" --timeout 60 0x000000000000000000000000000000000000bEEF --value 3
run 'cast send --legacy waits for a receipt' '^status +1 \(success\)' cast send --legacy --private-key "$KEY" --rpc-url "$URL" --timeout 60 0x000000000000000000000000000000000000bEEF --value 4
run 'forge script --broadcast deploys and calls' 'ONCHAIN EXECUTION COMPLETE & SUCCESSFUL' \
  bash -c "cd '$WORK' && forge script script/Deploy.s.sol:Deploy --rpc-url '$URL' --broadcast --slow --timeout 120 -vv"
ADDR=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print([t['contractAddress'] for t in d['transactions'] if t.get('contractAddress')][0])" "$WORK/broadcast/Deploy.s.sol/700770/run-latest.json" 2>/dev/null)
run 'cast call on the deployed contract' '^1$' cast call "$ADDR" 'number()(uint256)' --rpc-url "$URL"
run 'cast receipt of the deployment' 'status +1' bash -c "cast receipt \$(python3 -c \"import json; print(json.load(open('$WORK/broadcast/Deploy.s.sol/700770/run-latest.json'))['transactions'][0]['hash'])\") --rpc-url '$URL'"
echo
echo "$pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
