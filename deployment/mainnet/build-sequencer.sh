#!/bin/bash
# Build the mainnet L2 block producer (bloch-l2-produce-dev, no devnet features) against the
# native release that runs on Genesis-4 mainnet (bloch-sis-pow 78b7343a), then run its tests.
# Builds and tests only: no key, no service, no network write.
#
#   build-sequencer.sh WORK
#
# WORK/src must hold bloch-l2-evm (this branch), bloch-validator-payout (= bloch-sis-pow at
# 78b7343a, e.g. `git archive 78b7343a`) and reth-bloch-rpc-snapshot (the tree devnet4 builds
# with, 8eb2101 + its working-tree change). The native tree gets an inert feature shim:
# settlement-recovery forwards the devnet-only features devnet-kes / devnet-lc-roster, which the
# mainnet release does not define, so Cargo would refuse to resolve. The shim adds the two names
# as empty features (no code); they are never enabled here.
# Result: WORK/out/{bloch-l2-produce-dev,sequencer_mainnet.py,SHA256SUMS,build.json}
set -euo pipefail
W=$(cd "${1:?usage: build-sequencer.sh WORK}" && pwd)
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
L2=$W/src/bloch-l2-evm
N=$W/src/bloch-validator-payout
M=$L2/integrations/settlement-recovery/Cargo.toml
log() { echo "== $* ($(date -u +%FT%TZ))"; }
for d in "$L2" "$N" "$W/src/reth-bloch-rpc-snapshot"; do [ -d "$d" ] || { echo "missing $d"; exit 1; }; done
grep -q 'pub const L2_SETTLEMENT_ACTIVATION_EPOCH: u64 = 5_850;' "$N/crates/bloch-pos-committee/src/params.rs" \
  || { echo "native tree is not the epoch-5850 mainnet release"; exit 1; }

log "native feature shim"
for crate in bloch-pos-committee bloch-pos-node; do
  f=$N/crates/$crate/Cargo.toml
  if ! grep -q '^devnet-kes = \[\]' "$f"; then
    grep -q 'devnet-kes\|devnet-lc-roster' "$f" && { echo "$f already defines devnet-kes/devnet-lc-roster"; exit 1; }
    [ "$(grep -c '^\[features\]$' "$f")" = 1 ] || { echo "$f: expected one [features] table"; exit 1; }
    sed -i 's/^\[features\]$/[features]\n# Build shim (L2 mainnet producer): inert devnet names, never enabled.\ndevnet-kes = []\ndevnet-lc-roster = []/' "$f"
  fi
done

log "producer (no features)"
mkdir -p "$W/out"
CARGO_TARGET_DIR=$W/l2-target CARGO_BUILD_JOBS=${JOBS:-16} nice cargo +1.98.1 build --release \
  --manifest-path "$M" --bin bloch-l2-produce-dev > "$W/build.log" 2>&1
cp "$W/l2-target/release/bloch-l2-produce-dev" "$W/out/"
cp "$L2/deployment/mainnet/sequencer_mainnet.py" "$W/out/"
cp "$L2/integrations/settlement-recovery/Cargo.lock" "$W/out/settlement-recovery.Cargo.lock"

log "tests"
CARGO_TARGET_DIR=$W/l2-target CARGO_BUILD_JOBS=${JOBS:-16} nice cargo +1.98.1 test --release \
  --manifest-path "$M" --test produce_mainnet --test produce_txs --test withdrawal_settlement --lib > "$W/test.log" 2>&1
python3 -m unittest discover -s "$L2/deployment/mainnet" -p 'test_*.py' > "$W/test-py.log" 2>&1

log "pinned genesis"
G=$(mktemp -d)
P=$W/out/bloch-l2-produce-dev
NET=(--rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679)
"$P" init --target "$G/db" "${NET[@]}" > /dev/null
HEAD=$("$P" head --target "$G/db" "${NET[@]}")
rm -rf "$G"
python3 - "$HEAD" <<'PY'
import json, sys
h = json.loads(sys.argv[1])
assert h['hash'] == '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468', h
assert h['state_root'] == '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d', h
PY
(cd "$W/out" && sha256sum bloch-l2-produce-dev sequencer_mainnet.py settlement-recovery.Cargo.lock > SHA256SUMS)
python3 - "$W" "$HEAD" <<'PY'
import json, sys, re
from pathlib import Path
w = Path(sys.argv[1])
tests = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed', (w / 'test.log').read_text())
out = {'ok': True, 'native': '78b7343a (+ inert feature shim)', 'features': [], 'genesis': json.loads(sys.argv[2]),
       'cargo_tests_passed': sum(int(p) for p, _ in tests), 'cargo_tests_failed': sum(int(f) for _, f in tests),
       'python_tests': (w / 'test-py.log').read_text().strip().splitlines()[-3:],
       'sha256': dict(l.split()[::-1] for l in (w / 'out/SHA256SUMS').read_text().splitlines())}
(w / 'out/build.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out, indent=2))
PY
log "SEQUENCER BUILD OK"
