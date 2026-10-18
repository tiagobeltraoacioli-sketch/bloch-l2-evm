#!/usr/bin/env bash
# Real Groth16 proofs of settlement_v3_mainnet over three representative L2 blocks,
# with time and peak memory, inside a capped cgroup (systemd --user scope). Sends
# nothing anywhere: the only network access is ONE read-only `getl2settlement` call
# to a mainnet RPC (block A) and Docker's local pinned Gnark image.
#
#   A  mainnet L2 block 1 exactly as the live chain requests it today (empty,
#      anchored to the activation source block; a valid proof for mainnet)
#   B  block 1 with 1 deposit + 4 transfers + 1 withdrawal (synthetic inbox)
#   C  block 1 with 1 deposit + N transfers (default 200; synthetic inbox)
#
# B and C use a synthetic native request (inbox_count/consumed changed), so their
# proofs verify offline but would be refused natively (inbox root): benchmarks only.
# Their sender is a throwaway key generated here; it holds nothing on any network.
#
# Usage: bench-prove-blocks.sh WORK [A B C]
#   WORK/out/{bloch-evm-sp1-settlement-v3,bloch-l2-produce-dev}, WORK/elf/settlement_v3_mainnet,
#   WORK/home/.sp1/circuits/groth16/v6.1.0. Env: THREADS (8), MEMORY_MAX (40G), CPU_QUOTA (800%),
#   RPC (http://80.240.16.185:8080), C_TXS (200), DOCKER_SUDO=1 to run only the docker CLI via sudo -n.
set -euo pipefail
work=$(cd "$1" && pwd -P); shift
blocks=${*:-A B C}
THREADS=${THREADS:-8} MEMORY_MAX=${MEMORY_MAX:-40G} CPU_QUOTA=${CPU_QUOTA:-800%}
RPC=${RPC:-http://80.240.16.185:8080} C_TXS=${C_TXS:-200}
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
GENESIS_TIME=1786656679
NET=(--rules mainnet --domain "$DOMAIN" --genesis-time "$GENESIS_TIME")
L2_GENESIS=632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468
P=$work/out/bloch-l2-produce-dev H=$work/out/bloch-evm-sp1-settlement-v3 E=$work/elf/settlement_v3_mainnet
GNARK=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d
[[ $(sha256sum "$E" | cut -d' ' -f1) == 203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473 ]] || { echo "guest is not the pinned ELF" >&2; exit 1; }
path=/usr/bin:/bin
if [[ ${DOCKER_SUDO:-0} == 1 ]]; then
  mkdir -p "$work/dockerwrap"
  printf '#!/bin/sh\nexec sudo -n /usr/bin/docker "$@"\n' > "$work/dockerwrap/docker"
  chmod 755 "$work/dockerwrap/docker"
  path=$work/dockerwrap:$path
fi
run=$work/bench-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$run" "$work/home/tmp"
log() { echo "== $* ($(date -u +%FT%TZ))"; }

# Live source of the mainnet L2 (read-only).
curl -s -m 20 -X POST "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' > "$run/getl2settlement.json"
python3 -I - "$run" <<'PY'
import json, sys
run = sys.argv[1]
r = json.load(open(run + '/getl2settlement.json'))['result']
assert r['chain_id'] == 700770 and r['accepted'] is None, 'mainnet L2 already settled block 1: block A would be stale'
s = r['source']
open(run + '/source.txt', 'w').write(s['request'])
open(run + '/anchor', 'w').write(s['block'] + '\n' + str(s['slot']) + '\n')
# Block 1 request: source request + zero previous settlement + inbox fields (settler_v3.prepare_block).
open(run + '/A.request', 'w').write(s['request'] + '0' * 64 + f"\n{s['inbox_count']}\n{s['consumed_start']}\n{s['consumed_end']}\n")
for name in ('B', 'C'):
    open(run + f'/{name}.request', 'w').write(s['request'] + '0' * 64 + '\n1\n0\n1\n')
PY
anchor=$(sed -n 1p "$run/anchor") slot=$(sed -n 2p "$run/anchor")

key=$run/throwaway.key
( umask 077; python3 -I -c 'import secrets; print(secrets.token_hex(32))' > "$key" )
sender=$("$P" address --key "$key" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["address"])')
cat > "$run/deposit.json" <<EOF
[{"height":1,"tx_index":1,"txid":"$(printf 'ab%.0s' {1..32})","vout":0,"sats":1000000000,"recipient":"$sender"}]
EOF
pool() {  # pool DIR TRANSFERS WITHDRAWALS
  mkdir -p "$1"
  local n=0
  for ((i = 0; i < $2; i++)); do
    "$P" sign-tx --key "$key" --nonce $n --to "$(printf '%040x' $((0x1000 + i)))" --value-wei 1000000000000 \
      --max-fee-wei 2000000000 --out "$1/$(printf '%05d' $n).tx" "${NET[@]}" > /dev/null
    n=$((n + 1))
  done
  for ((i = 0; i < $3; i++)); do
    "$P" sign-tx --key "$key" --nonce $n --withdraw-to "$(printf '%064x' $((0x77 + i)))" --sats 1000000 \
      --max-fee-wei 2000000000 --out "$1/$(printf '%05d' $n).tx" "${NET[@]}" > /dev/null
    n=$((n + 1))
  done
}

for b in $blocks; do
  d=$run/$b
  mkdir -p "$d"
  "$P" init --target "$d/l2" "${NET[@]}" > /dev/null
  genesis=$("$P" head --target "$d/l2" "${NET[@]}" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["hash"])')
  [[ $genesis == "$L2_GENESIS" ]] || { echo "L2 genesis $genesis is not the pinned $L2_GENESIS" >&2; exit 1; }
  extra=()
  case $b in
    A) ;;
    B) pool "$d/txs" 4 1; extra=(--deposits "$run/deposit.json" --txs "$d/txs") ;;
    C) pool "$d/txs" "$C_TXS" 0; extra=(--deposits "$run/deposit.json" --txs "$d/txs") ;;
  esac
  "$P" extend --target "$d/l2" --parent "$genesis" --anchor "$anchor" --timestamp-rule "1:$GENESIS_TIME:30000" \
    --anchor-slot "$slot" "${extra[@]}" "${NET[@]}" > "$d/block.json"
  "$P" export --target "$d/l2" --number 1 --out "$d/block.artifact" "${NET[@]}" > "$d/export.json"
  cp "$run/$b.request" "$d/native-request.txt"
  log "$b block: $(cat "$d/block.json" | head -c 600)"
  env=(PATH=$path HOME=$work/home TMPDIR=$work/home/tmp RAYON_NUM_THREADS=$THREADS SP1_CIRCUIT_MODE=release
       SP1_GNARK_IMAGE=$GNARK BLOCH_NATIVE_L2_REQUEST=$d/native-request.txt BLOCH_NATIVE_L2_ARTIFACT=$d/block.artifact)
  log "$b execute"; env -i "${env[@]}" "$H" --mainnet execute native-artifact "$E" | tee "$d/execute.log"
  # Memory sampler: system MemAvailable floor and the Gnark container's usage.
  ( while sleep 5; do
      echo "$(date +%s) $(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo) $(env PATH=$path docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' 2>/dev/null | tr '\n' ' ')"
    done ) > "$d/memory.samples" &
  sampler=$!
  log "$b prove (threads $THREADS, MemoryMax $MEMORY_MAX)"
  start=$(date +%s)
  systemd-run --user --scope -q -p MemoryMax="$MEMORY_MAX" -p MemorySwapMax=0 -p CPUQuota="$CPU_QUOTA" \
    env -i "${env[@]}" /usr/bin/time -v "$H" --mainnet prove-groth16 native-artifact "$E" "$d/proof.sp1proof" \
    > "$d/prove.log" 2>&1 || { kill $sampler; tail -40 "$d/prove.log"; exit 1; }
  echo "prove_seconds $(( $(date +%s) - start ))" | tee "$d/prove.seconds"
  kill $sampler
  log "$b verify"; env -i "${env[@]}" "$H" --mainnet verify-groth16 native-artifact "$E" "$d/proof.sp1proof" | tee "$d/verify.log"
  grep -E 'Maximum resident|Elapsed|Percent of CPU' "$d/prove.log"
  awk 'NR==1||$2<m{m=$2} END{print "min_mem_available_mib", m}' "$d/memory.samples"
  sha256sum "$d/block.artifact" "$d/native-request.txt" "$d/proof.sp1proof"
done
log "BENCH OK $run"
