#!/bin/bash
# Superseded by the single pinned mainnet build: deployment/mainnet/build-release.sh WORK [OUT].
# Its OUT holds bloch-l2-produce-dev and sequencer_mainnet.py (what install-shadow.sh takes) with
# SHA256SUMS and build.json. Kept as a wrapper: build-sequencer.sh WORK  (OUT = WORK/out).
set -euo pipefail
W=$(cd "${1:?usage: build-sequencer.sh WORK}" && pwd)
exec "$W/src/bloch-l2-evm/deployment/mainnet/build-release.sh" "$W" "$W/out"
