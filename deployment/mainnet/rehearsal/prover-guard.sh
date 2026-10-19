#!/bin/bash
# Rehearsal memory guard around the pinned prover. 45.77 is shared with devnet4, whose
# Groth16 prover (measured 2026-10-18) runs ~12 min per proof, ramps to 60-83 GB RSS
# between +2 and +5 min, then stays ~15-20 GB. We start right after a devnet4 proof has
# peaked (seen >= 40 GB) and fallen below 25 GB (~9 min before its next ramp), only with
# >= FLOOR+NEED GB available, and kill our whole process group the moment the host
# drops below FLOOR GB available.
REAL=/home/ubuntu/l2-mainnet-rehearsal-20261018/out/bloch-evm-sp1-settlement-v3
FLOOR=32; NEED=30
case " $* " in *" prove-groth16 "*) ;; *) exec "$REAL" "$@";; esac
avail() { awk '/MemAvailable/ {print int($2/1048576)}' /proc/meminfo; }
d4() { ps -eo pid=,rss=,args= | grep "/opt/bloch/l2-devnet4-settler/bloch-evm-sp1-settlement-v3 prove-groth16" | grep -v grep | head -1 | awk '{print $1, int($2/1048576)}'; }
seen_pid=; seen_max=0
while true; do
  read -r pid gb <<< "$(d4)"
  if [ -n "$pid" ]; then
    [ "$pid" != "$seen_pid" ] && { seen_pid=$pid; seen_max=0; }
    [ "$gb" -gt "$seen_max" ] && seen_max=$gb
    if [ "$seen_max" -ge 40 ] && [ "$gb" -lt 25 ] && [ "$(avail)" -ge $((FLOOR + NEED)) ]; then break; fi
  fi
  sleep 3
done
echo "guard $(date -u +%T): start, available $(avail) GB (devnet4 pid $seen_pid peaked at ${seen_max} GB)" >&2
setsid "$REAL" "$@" & pid=$!
while kill -0 $pid 2>/dev/null; do
  if [ "$(avail)" -lt $FLOOR ]; then
    echo "guard $(date -u +%T): available $(avail) GB < $FLOOR GB, killing the proof" >&2
    kill -TERM -- -$pid 2>/dev/null; sleep 3; kill -KILL -- -$pid 2>/dev/null; wait $pid; exit 75
  fi
  sleep 1
done
wait $pid; rc=$?
echo "guard $(date -u +%T): prover exit $rc" >&2
exit $rc
