#!/usr/bin/env bash
# Real SP1 Groth16 proof of the mainnet program for the native fixture
# `mainnet-empty.{values,proof,request}` (bloch-sis-pow
# crates/bloch-l2-proof/tests/fixtures, test
# `mainnet_program_real_groth16_settles_on_the_activated_l2`).
#
# REQUEST: the 11-line native request printed by the native helper
#   cargo test -p bloch-pos-committee --lib print_mainnet_program_fixture_request -- --ignored --nocapture
# (lines between BEGIN-REQUEST/END-REQUEST). It depends on the native test chain
# AND on the pinned PROGRAM (the boundary block commits the whole policy), so
# print it from the tree that carries the final PROGRAM.
#
# Usage (as root or a docker-group user; RAM: ~20 GB peak at 6 threads):
#   prove-native-fixture.sh WORK ELF REQUEST OUT_DIR
# WORK holds out/{bloch-evm-sp1-settlement-v3,bloch-l2-produce-dev} from
# build-program.sh and HOME-style SP1 circuits in WORK/home/.sp1 (groth16 v6.1.0).
set -euo pipefail
work=$(cd "$1" && pwd -P); elf=$2; request=$3; dest=$4
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
GENESIS_TIME=1786656679
SLOT_MS=30000
NET=(--rules mainnet --domain "$DOMAIN" --genesis-time "$GENESIS_TIME")
P=$work/out/bloch-l2-produce-dev
H=$work/out/bloch-evm-sp1-settlement-v3
[[ $(wc -l < "$request") == 11 ]] || { echo "request must have 11 lines" >&2; exit 1; }
anchor=$(sed -n 3p "$request"); slot=$(sed -n 4p "$request")
run=$work/fixture-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$run" "$dest" "$work/home/tmp"
cp "$request" "$run/native-request.txt"
"$P" init --target "$run/l2" "${NET[@]}" > /dev/null
genesis=$("$P" head --target "$run/l2" "${NET[@]}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["hash"])')
"$P" extend --target "$run/l2" --parent "$genesis" --anchor "$anchor" \
  --timestamp-rule "1:$GENESIS_TIME:$SLOT_MS" --anchor-slot "$slot" "${NET[@]}" > "$run/l2-block1.json"
"$P" export --target "$run/l2" --number 1 --out "$run/block1.artifact" "${NET[@]}" > /dev/null
export HOME=$work/home TMPDIR=$work/home/tmp RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-6} SP1_CIRCUIT_MODE=release \
  SP1_GNARK_IMAGE=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d \
  BLOCH_NATIVE_L2_REQUEST=$run/native-request.txt BLOCH_NATIVE_L2_ARTIFACT=$run/block1.artifact
"$H" --mainnet execute native-artifact "$elf"
"$H" --mainnet prove-groth16 native-artifact "$elf" "$run/mainnet-empty.sp1proof"
"$H" --mainnet verify-groth16 native-artifact "$elf" "$run/mainnet-empty.sp1proof"
# Canonical 766-byte values and 356-byte proof (the settler's parser).
python3 -I - "$(dirname "$0")/../devnet" "$run/mainnet-empty.sp1proof" "$dest" "$request" <<'PY'
import hashlib, shutil, sys
sys.path.insert(0, sys.argv[1])
import settler_v3
data = open(sys.argv[2], 'rb').read()
values, proof = settler_v3.parse_proof_artifact(data)
assert len(values) == 766 and len(proof) == 356
open(sys.argv[3] + '/mainnet-empty.values', 'wb').write(values)
open(sys.argv[3] + '/mainnet-empty.proof', 'wb').write(proof)
shutil.copyfile(sys.argv[4], sys.argv[3] + '/mainnet-empty.request')
for name, blob in (('sp1_proof', data), ('public_values', values), ('canonical_proof', proof)):
    print(name, hashlib.sha256(blob).hexdigest())
PY
sha256sum "$run/block1.artifact" "$run/native-request.txt"
cat "$run/l2-block1.json"
