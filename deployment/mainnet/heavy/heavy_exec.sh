#!/usr/bin/env bash
# Build one synthetic benchmark block with the release producer and run the guest in execute mode (no proof, no lock).
# Usage: heavy_exec.sh NAME SCENARIO GAS TXS [TIMEOUT_SECONDS]
# Writes runs/NAME/{block.json,execute.log,exec.json}. Nothing leaves this host.
set -uo pipefail
W=$HOME/l2dexbridge-20261030/l2-heavy-r3
name=$1 scen=$2 gas=$3 txs=$4 tmo=${5:-1800}
d=$W/runs/$name
rm -rf "$d"; mkdir -p "$d"
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
NET=(--rules mainnet --domain "$DOMAIN" --genesis-time 1786656679)
P=$W/out/bloch-l2-produce-dev H=$W/out/bloch-evm-sp1-settlement-v3 E=$W/elf/settlement_v3_mainnet
anchor=$(sed -n 1p "$W/anchor") slot=$(sed -n 2p "$W/anchor")
key=$W/throwaway.key
[[ -f $key ]] || ( umask 077; python3 -I -c 'import secrets; print(secrets.token_hex(32))' > "$key" )
sender=$(python3 -I "$W/tools/heavy_gen.py" address --key "$key")
cat > "$d/deposit.json" <<JSON
[{"height":1,"tx_index":1,"txid":"$(printf 'ab%.0s' {1..32})","vout":0,"sats":1000000000,"recipient":"$sender"}]
JSON
python3 -I "$W/tools/heavy_gen.py" "$scen" --key "$key" --out "$d/txs" --block-gas "$gas" --txs "$txs" > "$d/gen.txt" || exit 2
"$P" init --target "$d/l2" "${NET[@]}" > /dev/null
genesis=$("$P" head --target "$d/l2" "${NET[@]}" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["hash"])')
s=$(date +%s.%N)
"$P" extend --target "$d/l2" --parent "$genesis" --anchor "$anchor" --timestamp-rule "1:1786656679:30000" \
  --anchor-slot "$slot" --deposits "$d/deposit.json" --txs "$d/txs" --max-gas 15000000 --max-bytes 114688 --max-txs 128 \
  "${NET[@]}" > "$d/block.json" 2> "$d/extend.err" || { echo "EXTEND-REFUSED $(cat "$d/extend.err")" > "$d/exec.json"; cat "$d/exec.json"; exit 3; }
extend_s=$(echo "$(date +%s.%N) - $s" | bc)
"$P" export --target "$d/l2" --number 1 --out "$d/block.artifact" "${NET[@]}" > "$d/export.json"
{ cat "$W/source.txt"; printf '%064d\n1\n0\n1\n' 0; } > "$d/native-request.txt"
env=(PATH=/usr/bin:/bin HOME=$W/home TMPDIR=$W/home/tmp RAYON_NUM_THREADS=8 SP1_CIRCUIT_MODE=release
     BLOCH_NATIVE_L2_REQUEST=$d/native-request.txt BLOCH_NATIVE_L2_ARTIFACT=$d/block.artifact)
s=$(date +%s.%N)
timeout "$tmo" env -i "${env[@]}" /usr/bin/time -v "$H" --mainnet execute native-artifact "$E" > "$d/execute.log" 2>&1
rc=$?
exec_s=$(echo "$(date +%s.%N) - $s" | bc)
python3 -I - "$d" "$scen" "$gas" "$txs" "$rc" "$extend_s" "$exec_s" <<'PY'
import json, re, sys, os
d, scen, gas, txs, rc, ext, exe = sys.argv[1:8]
b = json.load(open(d + '/block.json'))
log = open(d + '/execute.log', errors='replace').read()
m = re.findall(r'(\d+) instructions', log)
rss = re.findall(r'Maximum resident set size \(kbytes\): (\d+)', log)
print(json.dumps({'name': os.path.basename(d), 'scenario': scen, 'declared_gas': int(gas), 'txs': int(txs), 'included': b.get('transactions'),
  'deferred': len(b.get('deferred', [])), 'dropped': b.get('dropped', [])[:2], 'bytes': b.get('bytes'),
  'artifact_bytes': os.path.getsize(d + '/block.artifact'), 'exit': int(rc), 'instructions': int(m[-1]) if m else None,
  'extend_s': round(float(ext), 1), 'execute_s': round(float(exe), 1), 'exec_rss_gib': round(int(rss[0]) / 2**20, 2) if rss else None,
  'tail': '' if m else log[-400:]}))
PY
