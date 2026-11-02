#!/bin/bash
# THE pinned build of the Bloch L2 MAINNET binaries (chain 700770) against the native release that
# runs Genesis-4 mainnet (bloch-sis-pow 78d4921c armed release, L2 activation at epoch 5850). One recipe for:
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
#   bloch-validator-payout   bloch-sis-pow at exactly NATIVE_COMMIT, clean
#   reth-bloch-rpc-snapshot  8eb21017 + the devnet4 working-tree change (reth-snapshot.patch)
# Handled once, here:
#   * native feature shim: settlement-recovery forwards devnet-kes / devnet-lc-roster, which the
#     mainnet release does not define; follower-rpc/native-feature-shim.py adds them as EMPTY
#     features (no code) to the scratch native checkout. They are never enabled.
#   * Cargo lock: the release pins exactly one lock, follower-rpc/settlement-recovery.native-78d4921c.Cargo.lock
#     (sha256 a3c38a46...). It is the only committed lock that resolves native 78d4921c, and the build
#     refuses any other lock for that commit. integrations/settlement-recovery/Cargo.lock is a byte copy.
# Env: JOBS (default 8), TOOLCHAIN (default 1.98.1), CARGO_TARGET_DIR (default WORK/l2-target).
#
# L1 hard forks (docs/L2-HARD-FORK-OPERATOR-STEPS.md): the follower and the producer RUN the native
# transition, so they must be rebuilt against the native release that arms a fork BEFORE its epoch,
# or they halt at it (state-root mismatch). NATIVE_COMMIT selects that release (default: the running
# one); NATIVE_LOCK (default: the pinned lock above) must be the lock resolved against it. Only a
# different NATIVE_COMMIT may use a different lock. settlement-recovery.mainnet.Cargo.lock
# (43be49f5..., native 78b7343a) is kept for the historical rehearsal/build.sh only and cannot build
# this release.
#
# FORK CANDIDATE v2 (codex/fork-candidate-l2-r8-20261102): the default native is the candidate of the L2 program
# swap, bloch-sis-pow codex/fork-candidate-native-r8-20261102 f12b4113: v1 27f195d7 (guest activation 0fbd07a6 + node RC
# c6f20bd2 + hf-gates discover fix + PROGRAM_NEXT = sparse ELF 78c533fa) + the reserved DA slot 1ca3d382 + PROGRAM_FALLBACK =
# complete ELF 3ad3a4f0 (d6a704b8) + L1 forced inclusion 3533cd56. L2_NEXT_PROGRAM_EPOCH, L2_PROGRAM_ROLLBACK_EPOCH,
# L2_DA_RESERVED_SLOT_EPOCH and L2_FORCED_INCLUSION_EPOCH are all inert. Its one pinned lock is still
# follower-rpc/settlement-recovery.native-27f195d7.Cargo.lock (sha256 ab7b3a09...): the v2 merges change no native
# Cargo.toml or Cargo.lock, so the same lock resolves it. It is the 78d4921c lock plus
# pqcrypto-mlkem and the mesh transport's dependencies, nothing else moved. NATIVE_COMMIT=78d4921c... with
# the 78d4921c lock still builds the release this branch came from. A native commit that arms the gate is
# another commit, and needs its own lock line here. build.json records every L1 activation epoch the binaries were compiled with
# (l1_activation_epochs, read from the native params.rs; "inert" = u64::MAX) so the operator can
# compare them with the release notice.
set -euo pipefail
W=$(cd "${1:?usage: build-release.sh WORK [OUT]}" && pwd)
OUT=${2:-$W/out}
CANDIDATE_NATIVE_COMMIT=f12b4113bfcba79ab21181cf5128602fc9550bb4
CANDIDATE_LOCK_SHA256=ab7b3a0901f142d5e2a3905c68cf97eb69eb5cc968407621e55f21f14668cafa
NATIVE_COMMIT=${NATIVE_COMMIT:-$CANDIDATE_NATIVE_COMMIT}
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
if [ "$NATIVE_COMMIT" = "$CANDIDATE_NATIVE_COMMIT" ]; then
  NATIVE_LOCK=${NATIVE_LOCK:-$HERE/follower-rpc/settlement-recovery.native-27f195d7.Cargo.lock}
else
  NATIVE_LOCK=${NATIVE_LOCK:-$HERE/follower-rpc/settlement-recovery.native-78d4921c.Cargo.lock}
fi
RELEASE_NATIVE_COMMIT=78d4921c3ec6ba41829f3878eed47f8d3bb96230
RELEASE_LOCK_SHA256=a3c38a462a273fc07b618ebb2a6dda51377ea7d2deb8530c44a17bc4bf3908a9
log() { echo "== $* ($(date -u +%FT%TZ))"; }
die() { echo "build-release: $*" >&2; exit 2; }

for d in "$L2" "$N" "$RETH"; do [ -d "$d" ] || die "missing $d"; done
[ ! -e "$OUT" ] || die "$OUT exists; choose a new OUT"
if [ "$NATIVE_COMMIT" = "$RELEASE_NATIVE_COMMIT" ]; then
  [ "$(sha256sum "$NATIVE_LOCK" | cut -d' ' -f1)" = "$RELEASE_LOCK_SHA256" ] \
    || die "$NATIVE_LOCK is not the pinned lock $RELEASE_LOCK_SHA256 of native $RELEASE_NATIVE_COMMIT"
fi
if [ "$NATIVE_COMMIT" = "$CANDIDATE_NATIVE_COMMIT" ]; then
  [ "$(sha256sum "$NATIVE_LOCK" | cut -d' ' -f1)" = "$CANDIDATE_LOCK_SHA256" ] \
    || die "$NATIVE_LOCK is not the pinned lock $CANDIDATE_LOCK_SHA256 of native $CANDIDATE_NATIVE_COMMIT"
  grep -q 'pub const L2_NEXT_PROGRAM_EPOCH: u64 = u64::MAX;' "$N/crates/bloch-pos-committee/src/params.rs" \
    && grep -q 'pub const L2_PROGRAM_ROLLBACK_EPOCH: u64 = u64::MAX;' "$N/crates/bloch-pos-committee/src/params.rs" \
    && grep -q 'pub const L2_DA_RESERVED_SLOT_EPOCH: u64 = u64::MAX;' "$N/crates/bloch-pos-committee/src/params.rs" \
    && grep -q 'pub const L2_FORCED_INCLUSION_EPOCH: u64 = u64::MAX;' "$N/crates/bloch-pos-committee/src/params.rs" \
    || die "the candidate native tree must keep the program, DA-slot and forced-inclusion gates inert"
fi
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
cp "$NATIVE_LOCK" "$SR/Cargo.lock"

log "L1 activation epochs compiled in"
GATES=$(python3 "$HERE/l1_gates.py" "$N/crates/bloch-pos-committee/src/params.rs")
echo "$GATES"

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
  "$(sha256sum "$NATIVE_LOCK" | cut -d' ' -f1)" "$GATES" <<'PY'
import json, subprocess, sys
from pathlib import Path
out, head, l2, dirty, native, reth, toolchain, lock, gates = sys.argv[1:]
genesis = json.loads(head)
pins = {'hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
        'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'}
if any(genesis.get(k) != v for k, v in pins.items()) or genesis.get('number') != 0:
    sys.exit(f'built producer does not reproduce the pinned L2 genesis: {genesis}')
rustc = subprocess.run(['rustc', f'+{toolchain}', '--version'], capture_output=True, text=True).stdout.strip()
report = {'chain_id': 700770, 'l2_commit': l2, 'l2_tracked_changes': int(dirty),
          'native': f'{native} (+ inert devnet-kes/devnet-lc-roster shim)', 'reth_snapshot': reth,
          'rustc': rustc, 'features': [], 'settlement_recovery_lock_sha256': lock, 'l2_genesis': genesis,
          'l1_activation_epochs': json.loads(gates),
          'sha256': dict(l.split()[::-1] for l in (Path(out) / 'SHA256SUMS').read_text().splitlines())}
(Path(out) / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
PY
log "BUILD OK: $OUT"
