#!/usr/bin/env bash
# Prove one L2 block on the installed mainnet prover over its forced-command key and
# verify the proof HERE (on the settler host) with the settler's own pinned host and
# guest. Submits nothing. Use it once after install-prover-mainnet.py and after any
# prover host change.
#
# Usage: selfcheck-remote-prover.sh TARGET KEY KNOWN_HOSTS REQUEST ARTIFACT HOST ELF OUT_PROOF
#   TARGET       bloch-l2-prover-mainnet@PROVER_HOST
#   KEY          the settler's private key file for the prover (never leaves this host)
#   KNOWN_HOSTS  file pinning the prover host key (install prints it)
#   REQUEST      11-line native request (e.g. block A of bench-prove-blocks.sh)
#   ARTIFACT     the block's execution artifact (bloch-l2-produce-dev export)
#   HOST / ELF   the settler's pinned bloch-evm-sp1-settlement-v3 and settlement_v3_mainnet
set -euo pipefail
[[ $# == 8 ]] || { sed -n 2,15p "$0" >&2; exit 2; }
target=$1 key=$2 known=$3 request=$4 artifact=$5 host=$6 elf=$7 out=$8
[[ ! -e $out ]] || { echo "$out exists" >&2; exit 1; }
start=$(date +%s)
python3 -I - "$request" "$artifact" <<'PY' | ssh -i "$key" -o BatchMode=yes -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known" -o ConnectTimeout=20 \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=6 "$target" prove > "$out.partial"
import struct, sys
request = open(sys.argv[1], 'rb').read()
artifact = open(sys.argv[2], 'rb').read()
sys.stdout.buffer.write(b'BLOCH:L2:PROVE:1\n' + struct.pack('>I', len(request)) + request
                        + struct.pack('>Q', len(artifact)) + artifact)
PY
mv "$out.partial" "$out"
echo "remote proof: $(( $(date +%s) - start )) s, $(stat -c %s "$out") bytes, sha256 $(sha256sum "$out" | cut -d' ' -f1)"
BLOCH_NATIVE_L2_REQUEST=$request BLOCH_NATIVE_L2_ARTIFACT=$artifact "$host" --mainnet verify-groth16 native-artifact "$elf" "$out"
