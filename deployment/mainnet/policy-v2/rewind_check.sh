#!/bin/bash
# Round 14 (agent 304): does `produce-dev rewind` leave a database on which the next block is the same as on a fresh copy?
# (the preflight's one-copy-per-plan mode, F264-6). usage: rewind-check.sh PRODUCE WORKDIR
set -euo pipefail
P=$1; W=$2
rm -rf "$W"; mkdir -p "$W"
j() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
"$P" init --target "$W/a" > "$W/init.json"
G=$("$P" head --target "$W/a" | j "['hash']")
A1=$(printf '11%.0s' $(seq 32)); A2=$(printf '22%.0s' $(seq 32)); A3=$(printf '33%.0s' $(seq 32))
dep() { printf '[{"height": %d, "tx_index": 0, "txid": "%s", "vout": 0, "sats": %d, "recipient": "%s"}]' "$1" "$2" "$3" "$4" > "$5"; }
R1=00000000000000000000000000000000000000a1; R2=00000000000000000000000000000000000000b2
dep 5 "$A1" 150000 "$R1" "$W/d1.json"; dep 6 "$A2" 250000 "$R2" "$W/d2.json"; dep 6 "$A2" 990000 "$R1" "$W/d2x.json"
"$P" extend --target "$W/a" --parent "$G" --anchor "$A1" --deposits "$W/d1.json" > "$W/b1.json"
H1=$("$P" head --target "$W/a" | j "['hash']")
cp -a "$W/a" "$W/fresh"; cp -a "$W/a" "$W/reused"
# Three measured blocks on the reused copy, each rewound, with different contents (as preflight runs do).
for i in 1 2 3; do
  "$P" extend --target "$W/reused" --parent "$H1" --anchor "$A3" --deposits "$W/d2x.json" > "$W/reused-x$i.json"
  "$P" export --target "$W/reused" --number 2 --out "$W/reused-x$i.artifact" > /dev/null
  HX=$("$P" head --target "$W/reused" | j "['hash']")
  "$P" rewind --target "$W/reused" --number 2 --hash "$HX" > "$W/rewind$i.json"
  [ "$("$P" head --target "$W/reused" | j "['hash']")" = "$H1" ] || { echo "FAIL: head after rewind $i"; exit 1; }
  [ "$("$P" head --target "$W/reused" | j "['number']")" = 1 ] || { echo "FAIL: number after rewind $i"; exit 1; }
done
"$P" extend --target "$W/reused" --parent "$H1" --anchor "$A2" --deposits "$W/d2.json" > "$W/reused-b2.json"
"$P" extend --target "$W/fresh" --parent "$H1" --anchor "$A2" --deposits "$W/d2.json" > "$W/fresh-b2.json"
"$P" export --target "$W/reused" --number 2 --out "$W/reused-b2.artifact" > /dev/null
"$P" export --target "$W/fresh" --number 2 --out "$W/fresh-b2.artifact" > /dev/null
HR=$("$P" head --target "$W/reused"); HF=$("$P" head --target "$W/fresh")
echo "reused head: $HR"; echo "fresh  head: $HF"
[ "$HR" = "$HF" ] || { echo "FAIL: heads differ"; exit 1; }
SR=$(sha256sum < "$W/reused-b2.artifact"); SF=$(sha256sum < "$W/fresh-b2.artifact")
echo "artifact reused $SR"; echo "artifact fresh  $SF"
[ "$SR" = "$SF" ] || { echo "FAIL: exported artifacts differ"; exit 1; }
for a in "$R1" "$R2"; do
  [ "$("$P" account --target "$W/reused" --address $a)" = "$("$P" account --target "$W/fresh" --address $a)" ] || { echo "FAIL: account $a differs"; exit 1; }
done
echo "accounts: $("$P" account --target "$W/reused" --address $R1) $("$P" account --target "$W/reused" --address $R2)"
echo "PASS: after 3 measured-and-rewound blocks the next block, its export and the accounts equal a fresh copy's"
