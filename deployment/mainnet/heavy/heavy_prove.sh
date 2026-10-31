#!/usr/bin/env bash
# Real Groth16 proof of a block built by heavy_exec.sh, under PROVING.lock, in a capped scope.
# Usage: heavy_prove.sh NAME [THREADS] [MEMORY_GIB] [TIME_LIMIT_SECONDS] [TAG]
# Writes runs/NAME/prove-TAG/{result.json,prove.log,memory.samples,proof.sp1proof}. result.json is the final marker.
set -uo pipefail
W=$HOME/l2dexbridge-20261030/l2-heavy-r3
name=$1 threads=${2:-24} mem=${3:-100} limit=${4:-10800} tag=${5:-t${2:-24}m${3:-100}}
d=$W/runs/$name o=$d/prove-$tag
mkdir -p "$o" "$W/home/tmp"
H=$W/out/bloch-evm-sp1-settlement-v3 E=$W/elf/settlement_v3_mainnet
GNARK=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d
exec 9>>"$HOME/l2dexbridge-20261030/PROVING.lock"
echo "waiting lock $(date -u +%FT%TZ)" > "$o/status"
# Wait until the lock is free AND nothing else proves AND the memory is there; release the lock between tries.
deadline=$(( $(date +%s) + ${HEAVY_WAIT_SECONDS:-21600} ))
need=$((mem + 8))
while :; do
  flock 9
  others=$(pgrep -fc 'bloch-evm-sp1-settlement-v3.*prove-groth16' || true)
  gnark=$(docker ps --format '{{.Image}}' 2>/dev/null | grep -c sp1-gnark || true)
  avail=$(awk '/MemAvailable/{print int($2/1048576)}' /proc/meminfo)
  [[ $others == 0 && $gnark == 0 && $avail -ge $need ]] && break
  flock -u 9
  echo "not ready others=$others gnark=$gnark avail=$avail need=$need $(date -u +%FT%TZ)" >> "$o/status"
  if (( $(date +%s) > deadline )); then
    echo "{\"name\":\"$name\",\"tag\":\"$tag\",\"verdict\":\"NOT-RUN\",\"others\":\"$others\",\"gnark\":\"$gnark\",\"mem_available_gib\":$avail}" | tee "$o/result.json"
    exit 4
  fi
  sleep 60
done
echo "l2-heavy-r3 $name pid $$ $(date -u +%FT%TZ)" >&9
echo "lock held avail=$avail $(date -u +%FT%TZ)" >> "$o/status"
env=(PATH=/usr/bin:/bin HOME=$W/home TMPDIR=$W/home/tmp RAYON_NUM_THREADS=$threads SP1_CIRCUIT_MODE=release
     SP1_GNARK_IMAGE=$GNARK BLOCH_NATIVE_L2_REQUEST=$d/native-request.txt BLOCH_NATIVE_L2_ARTIFACT=$d/block.artifact)
while IFS= read -r v; do env+=("$v"); done < <(env | grep '^SP1_WORKER_' || true)
( while sleep 5; do
    echo "$(date +%s) $(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo) $(cut -d' ' -f1 /proc/loadavg) $(docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' 2>/dev/null | tr '\n' ' ')"
  done ) > "$o/memory.samples" &
sampler=$!
trap 'kill $sampler 2>/dev/null' EXIT
start=$(date +%s)
scope=heavy-$$
timeout -s KILL "$limit" systemd-run --user --scope -q --unit="$scope" -p MemoryMax="${mem}G" -p MemorySwapMax=0 -p CPUQuota="$((threads * 100))%" \
  env -i "${env[@]}" /usr/bin/time -v "$H" --mainnet prove-groth16 native-artifact "$E" "$o/proof.sp1proof" > "$o/prove.log" 2>&1
rc=$?
secs=$(( $(date +%s) - start ))
kill $sampler 2>/dev/null
systemctl --user stop "$scope.scope" 2>/dev/null
pkill -KILL -f "$H --mainnet prove-groth16 native-artifact $E $o/" 2>/dev/null
verify=none
if [[ $rc == 0 ]]; then
  env -i "${env[@]}" "$H" --mainnet verify-groth16 native-artifact "$E" "$o/proof.sp1proof" > "$o/verify.log" 2>&1 && verify=ok || verify=failed
fi
python3 -I - "$d" "$o" "$name" "$tag" "$threads" "$mem" "$limit" "$rc" "$secs" "$verify" <<'PY'
import json, re, sys
d, o, name, tag, threads, mem, limit, rc, secs, verify = sys.argv[1:11]
log = open(o + '/prove.log', errors='replace').read()
rss = re.findall(r'Maximum resident set size \(kbytes\): (\d+)', log)
cpu = re.findall(r'Percent of CPU this job got: (\d+)', log)
ex = open(d + '/execute.log', errors='replace').read()
ins = re.findall(r'(\d+) instructions', ex)
samples = [l.split() for l in open(o + '/memory.samples')] or [[0, 0, 0]]
minav = min(int(s[1]) for s in samples if len(s) > 1)
load = max(float(s[2]) for s in samples if len(s) > 2)
rc = int(rc)
v = 'PROVED' if rc == 0 and verify == 'ok' else 'TIME-LIMIT' if rc == 137 and int(secs) >= int(limit) - 5 else 'OOM-OR-KILLED' if rc in (137, 1) and 'Killed' in log or rc == 137 else 'FAILED'
r = dict(name=name, tag=tag, verdict=v, exit=rc, seconds=int(secs), threads=int(threads), memory_max_gib=int(mem),
         rss_gib=round(int(rss[0]) / 2**20, 2) if rss else None, cpu_pct=int(cpu[0]) if cpu else None,
         instructions=int(ins[-1]) if ins else None, min_mem_available_mib=minav, max_load=load, verify=verify,
         tail='' if rc == 0 else log[-300:])
open(o + '/result.json', 'w').write(json.dumps(r) + '\n')
print(json.dumps(r))
PY
cat "$o/result.json" >> "$W/proofs.jsonl"
