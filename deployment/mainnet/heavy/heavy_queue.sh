#!/usr/bin/env bash
# Prove blocks in order (each proof takes and releases the lock). Lines of FILE: NAME THREADS MEMORY_GIB LIMIT_SECONDS TAG
W=$HOME/l2dexbridge-20261030/l2-heavy-r3
while read -r n t m l g extra; do
  [[ -z $n ]] && continue
  [[ -f $W/runs/$n/prove-$g/result.json ]] && continue
  env $extra bash "$W/tools/heavy_prove.sh" "$n" "$t" "$m" "$l" "$g" || true
  sleep 30
done < "$1"
echo "QUEUE-DONE $(date -u +%FT%TZ)" >> "$W/proofs.jsonl.markers"
