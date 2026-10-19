#!/bin/bash
# THE pinned build of the Bloch L2 MAINNET binaries (chain 700770) against the native release that
# runs Genesis-4 mainnet (bloch-sis-pow 78b7343a, L2 activation at epoch 5850). One recipe for:
#   bloch-l2-native-follower   (settlement-recovery, no features)
#   bloch-l2-produce-dev       (settlement-recovery, no features; settler producer + shadow)
#   bloch-l2-settled-rpc       (reth-execution)
# plus sequencer_mainnet.py, with SHA256SUMS and build.json. Builds only: no key, no service,
# no network transaction. Replaces follower-rpc/build.sh and build-sequencer.sh (now wrappers).
#
#   build-release.sh WORK [OUT]          (OUT defaults to WORK/out; must not exist yet)
#
# WORK/src must hold, as siblings (the layout every L2 integration crate expects):
#   bloch-l2-evm             this tree (a git checkout: its commit and cleanliness are recorded)
#   bloch-validator-payout   bloch-sis-pow at exactly 78b7343a, clean
#   reth-bloch-rpc-snapshot  8eb21017 + the devnet4 working-tree change (reth-snapshot.patch)
# Handled once, here:
#   * native feature shim: settlement-recovery forwards devnet-kes / devnet-lc-roster, which the
#     mainnet release does not define; follower-rpc/native-feature-shim.py adds them as EMPTY
#     features (no code) to the scratch native checkout. They are never enabled.
#   * Cargo lock: 78b7343a resolves three extra lock entries; the build uses
#     follower-rpc/settlement-recovery.mainnet.Cargo.lock (--locked) and restores the tree's lock.
# Env: JOBS (default 8), TOOLCHAIN (default 1.98.1), CARGO_TARGET_DIR (default WORK/l2-target).
set -euo pipefail
W=$(cd "${1:?usage: build-release.sh WORK [OUT]}" && pwd)
OUT=${2:-$W/out}
NATIVE_COMMIT=78b7343a347d2c53944a7058b7cb1c2ca4efe842
RETH_COMMIT=8eb210175687c9f0c889a3b6795c16781d830e3a
TOOLCHAIN=${TOOLCHAIN:-1.98.1}
JOBS=${JOBS:-8}
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
export VERGEN_GIT_SHA=$RETH_COMMIT VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$W/l2-target} CARGO_BUILD_JOBS=$JOBS
L2=$W/src/bloch-l2-evm
N=$W/src/bloch-validator-payout
RETH=$W/src/reth-bloch-rpc-snapshot
HERE=$L2/deployment/mainnet
SR=$L2/integrations/settlement-recovery
log() { echo "== $* ($(date -u +%FT%TZ))"; }
die() { echo "build-release: $*" >&2; exit 2; }

for d in "$L2" "$N" "$RETH"; do [ -d "$d" ] || die "missing $d"; done
[ ! -e "$OUT" ] || die "$OUT exists; choose a new OUT"
[ "$(git -C "$N" rev-parse HEAD)" = "$NATIVE_COMMIT" ] || die "native checkout is not $NATIVE_COMMIT"
[ "$(git -C "$RETH" rev-parse HEAD)" = "$RETH_COMMIT" ] || die "reth snapshot is not $RETH_COMMIT"
grep -q 'pub const L2_SETTLEMENT_ACTIVATION_EPOCH: u64 = 5_850;' "$N/crates/bloch-pos-committee/src/params.rs" \
  || die "native tree is not the epoch-5850 mainnet release"
L2_COMMIT=$(git -C "$L2" rev-parse HEAD 2>/dev/null || echo unknown)
L2_DIRTY=$(git -C "$L2" status --porcelain 2>/dev/null | grep -v '^??' | wc -l || true)

log "native feature shim (inert devnet-kes / devnet-lc-roster)"
python3 "$HERE/follower-rpc/native-feature-shim.py" "$N"
OTHER=$(git -C "$N" status --porcelain | grep -v -E '^ M crates/bloch-pos-(committee|node)/Cargo.toml$' || true)
[ -z "$OTHER" ] || die "native checkout has other changes: $OTHER"

log "mainnet Cargo lock for settlement-recovery"
cp "$SR/Cargo.lock" "$W/settlement-recovery.tree.Cargo.lock"
restore() { cp "$W/settlement-recovery.tree.Cargo.lock" "$SR/Cargo.lock"; }
trap restore EXIT
cp "$HERE/follower-rpc/settlement-recovery.mainnet.Cargo.lock" "$SR/Cargo.lock"

log "follower + producer (settlement-recovery, no features)"
nice cargo "+$TOOLCHAIN" build --release --locked --manifest-path "$SR/Cargo.toml" \
  --bin bloch-l2-native-follower --bin bloch-l2-produce-dev
log "settled RPC (reth-execution)"
nice cargo "+$TOOLCHAIN" build --release --locked --manifest-path "$L2/integrations/reth-execution/Cargo.toml" \
  --bin bloch-l2-settled-rpc
restore
trap - EXIT

mkdir -p "$OUT"
for b in bloch-l2-native-follower bloch-l2-produce-dev bloch-l2-settled-rpc; do
  install -m 0755 "$CARGO_TARGET_DIR/release/$b" "$OUT/$b"
done
install -m 0644 "$HERE/sequencer_mainnet.py" "$OUT/sequencer_mainnet.py"

log "pinned L2 genesis from the built producer"
G=$(mktemp -d)
NET=(--rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679)
"$OUT/bloch-l2-produce-dev" init --target "$G/db" "${NET[@]}" > /dev/null
HEAD=$("$OUT/bloch-l2-produce-dev" head --target "$G/db" "${NET[@]}")
rm -rf "$G"

(cd "$OUT" && sha256sum bloch-l2-native-follower bloch-l2-produce-dev bloch-l2-settled-rpc sequencer_mainnet.py > SHA256SUMS)
python3 - "$OUT" "$HEAD" "$L2_COMMIT" "$L2_DIRTY" "$NATIVE_COMMIT" "$RETH_COMMIT" "$TOOLCHAIN" \
  "$(sha256sum "$HERE/follower-rpc/settlement-recovery.mainnet.Cargo.lock" | cut -d' ' -f1)" <<'PY'
import json, subprocess, sys
from pathlib import Path
out, head, l2, dirty, native, reth, toolchain, lock = sys.argv[1:]
genesis = json.loads(head)
pins = {'hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
        'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'}
if any(genesis.get(k) != v for k, v in pins.items()) or genesis.get('number') != 0:
    sys.exit(f'built producer does not reproduce the pinned L2 genesis: {genesis}')
rustc = subprocess.run(['rustc', f'+{toolchain}', '--version'], capture_output=True, text=True).stdout.strip()
report = {'chain_id': 700770, 'l2_commit': l2, 'l2_tracked_changes': int(dirty),
          'native': f'{native} (+ inert devnet-kes/devnet-lc-roster shim)', 'reth_snapshot': reth,
          'rustc': rustc, 'features': [], 'settlement_recovery_lock_sha256': lock, 'l2_genesis': genesis,
          'sha256': dict(l.split()[::-1] for l in (Path(out) / 'SHA256SUMS').read_text().splitlines())}
(Path(out) / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
PY
log "BUILD OK: $OUT"
