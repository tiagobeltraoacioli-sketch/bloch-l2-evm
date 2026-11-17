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
#   bloch-l2-evm             this tree (a committed, clean git checkout)
#   bloch-validator-payout   bloch-sis-pow at exactly NATIVE_COMMIT, clean
#   reth-bloch-rpc-snapshot  8eb21017 + integrations/reth-execution/reth-snapshot.patch (transaction snapshot
#                            boundary; RPC simulation gas cap and time budget, RETH-SNAPSHOT.md)
# Handled once, here:
#   * native feature shim: settlement-recovery forwards devnet-kes / devnet-lc-roster, which the
#     mainnet release does not define; follower-rpc/native-feature-shim.py adds them as EMPTY
#     features (no code) to the scratch native checkout. They are never enabled.
#   * Cargo lock: the release pins exactly one lock, follower-rpc/settlement-recovery.native-78d4921c.Cargo.lock
#     (sha256 a3c38a46...). It is the only committed lock that resolves native 78d4921c, and the build
#     refuses any other lock for that commit. integrations/settlement-recovery/Cargo.lock is a byte copy.
# Env: JOBS (default 8), TOOLCHAIN (default 1.98.1). The build itself runs in the fixed directory of build-root.sh
# (/var/tmp/bloch-l2-build), with its target directory there, so that the binaries are the same wherever WORK is.
#
# L1 hard forks (docs/L2-HARD-FORK-OPERATOR-STEPS.md): the follower and the producer RUN the native
# transition, so they must be rebuilt against the native release that arms a fork BEFORE its epoch,
# or they halt at it (state-root mismatch). NATIVE_COMMIT selects that release (default: the running
# one); NATIVE_LOCK (default: the pinned lock above) must be the lock resolved against it. Only a
# different NATIVE_COMMIT may use a different lock. settlement-recovery.mainnet.Cargo.lock
# (43be49f5..., native 78b7343a) is kept for the historical rehearsal/build.sh only and cannot build
# this release.
#
# FORK CANDIDATE v4.1 (round 18, agent 382): the default native is codex/native-l2-dec-merge-r17-20261117 711e60ba = the
# line below (19aa156d) with bloch-sis-pow main 857a10ac merged in (the DEPLOYED node release 0067547f = 906336fd + 49
# node commits), one restated test and notes. Between 19aa156d and 711e60ba no native Cargo.toml of a crate this tree
# builds changed; the native root Cargo.lock moved (gossipsub 0.49.5, tokio 1.53.3, rustix 1.1.6) and
# services/pq-shield-api's manifest and lock changed. This tree builds with its own settlement-recovery lock
# (ab7b3a09..., unchanged), so those bumps do NOT reach the L2 binaries; `cargo build --locked` below stops if the lock
# would have to change. `set-sweep-recipient.py native-commit` refuses any Cargo.toml/Cargo.lock difference by rule
# (kept as it is), so the two commit pins were moved by hand again, to what that command writes.
#
# FORK CANDIDATE v4 (round 17, agent 339): the default native is codex/native-l2-dec-merge-r17-20261117 19aa156d =
# the RELEASED node 906336fd (release/node-906336fd-20261113: HF1 to HF3, KES enforcement and its two follow-up rules at
# epoch 8620, the mempool state preflight of the L2 kinds) merged with the December native line 189f3178 (0861278c: the
# owner's recipients and the December program pins). Every L2 gate is inert. Between 0861278c and this commit three native
# Cargo.toml files differ (comments in bloch-crypto and fips205; two features without dependencies in bloch-pos-node:
# ws-release-anchor, ws-auto-checkpoint) and the native Cargo.lock does not, so the same settlement-recovery lock
# (ab7b3a09...) still resolves it: `cargo build --locked` below is the check, it stops if the lock would change.
# `set-sweep-recipient.py native-commit` refuses any native Cargo.toml difference by rule, so CANDIDATE_NATIVE_COMMIT
# here and NATIVE_COMMIT in install-shadow.sh were moved by hand for this step, to what that command writes.
#
# FORK CANDIDATE v3 (codex/fork-candidate-l2-r11-20261103, agent 219): the default native is
# codex/fork-candidate-native-r11-20261103 = node release A 4f34d87e + v2 f12b4113 + qualify kit + rollback kit and
# runbook v3 + agent 215 forced final + agent 216 forced fallback (PROGRAM_FALLBACK 7528e26d) + agent 221 + agent 222
# (G2 forfeit, brake off) + agent 233 L2 revenue fee + one protocol treasury. Every L2 gate is inert (forced inclusion and
# the L2 revenue fee are aliases of L2_NEXT_PROGRAM_EPOCH). No native Cargo.lock change since f12b4113 (one comment in
# tools/bloch-indexer/Cargo.toml), so the same settlement-recovery lock still resolves it. The next-rules release is
# refused while the fee-sweep recipient is unset (agent 217's gate below).
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
CANDIDATE_NATIVE_COMMIT=711e60baeb40419e045783b104661fec308e7654
CANDIDATE_LOCK_SHA256=ab7b3a0901f142d5e2a3905c68cf97eb69eb5cc968407621e55f21f14668cafa
NATIVE_COMMIT=${NATIVE_COMMIT:-$CANDIDATE_NATIVE_COMMIT}
RETH_COMMIT=8eb210175687c9f0c889a3b6795c16781d830e3a
TOOLCHAIN=${TOOLCHAIN:-1.98.1}
JOBS=${JOBS:-8}
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
# The binaries must not depend on WHERE they are built or by whom. Two things made them:
#   1. cargo hashes the absolute paths of the path dependencies into every symbol name, so the build runs in the
#      one fixed directory of build-root.sh: WORK/src is copied there (the caller's trees are not modified) and
#      this script runs again from the copy;
#   2. the binaries embedded the paths of the sources, the cargo registry and the target directory (panic
#      locations); each prefix is mapped to a fixed name below. A caller's own RUSTFLAGS would change the
#      binaries, so it is refused.
# The December build of round 15 gave other hashes in another directory for these two reasons alone
# (docs/DECEMBER-BUILD-R15.md section 3).
[ -z "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}" ] || { echo "build-release: unset RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS (the build sets its own)" >&2; exit 2; }
. "$W/src/bloch-l2-evm/deployment/mainnet/build-root.sh"
if [ "${BLOCH_BUILD_STAGED:-}" != "$BLOCH_BUILD_ROOT" ]; then
  case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac
  [ ! -e "$OUT" ] || { echo "build-release: $OUT exists; choose a new OUT" >&2; exit 2; }
  stage_build_root "$W"
  BLOCH_BUILD_STAGED=$BLOCH_BUILD_ROOT CARGO_TARGET_DIR=$BLOCH_BUILD_ROOT/l2-target exec bash "$BLOCH_BUILD_ROOT/src/bloch-l2-evm/deployment/mainnet/build-release.sh" "$BLOCH_BUILD_ROOT" "$OUT"
fi
export VERGEN_GIT_SHA=$RETH_COMMIT VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$W/l2-target} CARGO_BUILD_JOBS=$JOBS
export RUSTFLAGS="--remap-path-prefix=$W/src=/bloch-build/src --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/bloch-build/cargo --remap-path-prefix=$CARGO_TARGET_DIR=/bloch-build/target"
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
  # Every L2 gate of the candidate is inert: u64::MAX, or an alias of an inert gate (L2_FORCED_INCLUSION_EPOCH and
  # L2_REVENUE_EPOCH ride with L2_NEXT_PROGRAM_EPOCH; agents 215, 233, fork candidate v3). l1_gates.py resolves aliases.
  python3 "$HERE/l1_gates.py" "$N/crates/bloch-pos-committee/src/params.rs" | python3 -c '
import json, sys
g = json.load(sys.stdin)
names = ("L2_NEXT_PROGRAM_EPOCH", "L2_PROGRAM_ROLLBACK_EPOCH", "L2_DA_RESERVED_SLOT_EPOCH", "L2_FORCED_INCLUSION_EPOCH",
         "L2_REVENUE_EPOCH")
sys.exit(0 if all(g.get(n) == "inert" for n in names) else 1)' \
    || die "the candidate native tree must keep the program, rollback, DA-slot, forced-inclusion and L2-revenue gates inert"
  # Release gate (agents 163 B-1, 217): this native commit is the next-rules (program swap) release, and its
  # follower, producer and RPC compile ChainSpec::mainnet(). Refuse it until the owner's fee-sweep recipient is set.
  python3 "$HERE/set-sweep-recipient.py" gate --l2 "$L2" >/dev/null \
    || die "the next-rules release needs the owner's fee-sweep recipient: set-sweep-recipient.py set 0xADDRESS --l2 ... --native ... --rpc URL (or --confirm 0xADDRESS); the address in EIP-55 form"
fi
[ "$(git -C "$N" rev-parse HEAD)" = "$NATIVE_COMMIT" ] || die "native checkout is not $NATIVE_COMMIT"
[ "$(git -C "$RETH" rev-parse HEAD)" = "$RETH_COMMIT" ] || die "reth snapshot is not $RETH_COMMIT"
grep -q 'pub const L2_SETTLEMENT_ACTIVATION_EPOCH: u64 = 5_850;' "$N/crates/bloch-pos-committee/src/params.rs" \
  || die "native tree is not the epoch-5850 mainnet release"
log "verify release sources before any source mutation or build"
python3 "$HERE/verify-build-sources.py" --l2 "$L2" --native "$N" --native-revision "$NATIVE_COMMIT"
python3 "$L2/integrations/reth-execution/prepare-reth.py" --check
L2_COMMIT=$(git -C "$L2" rev-parse HEAD)
L2_DIRTY=0
RETH_PATCH_SHA256=$(sha256sum "$L2/integrations/reth-execution/reth-snapshot.patch" | cut -d' ' -f1)

log "native feature shim (inert devnet-kes / devnet-lc-roster)"
python3 "$HERE/follower-rpc/native-feature-shim.py" "$N"
python3 "$HERE/verify-build-sources.py" --l2 "$L2" --native "$N" --native-revision "$NATIVE_COMMIT" --shim-applied

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
python3 "$L2/integrations/reth-execution/prepare-reth.py" --check -- nice cargo "+$TOOLCHAIN" build --release --locked --manifest-path "$L2/integrations/reth-execution/Cargo.toml" \
  --bin bloch-l2-settled-rpc
restore
trap - EXIT
log "verify source identity after the build"
python3 "$HERE/verify-build-sources.py" --l2 "$L2" --native "$N" --native-revision "$NATIVE_COMMIT" --shim-applied
python3 "$L2/integrations/reth-execution/prepare-reth.py" --check
[ "$(git -C "$L2" rev-parse HEAD)" = "$L2_COMMIT" ] || die "L2 source revision changed during the build"

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
  "$(sha256sum "$NATIVE_LOCK" | cut -d' ' -f1)" "$GATES" "$RETH_PATCH_SHA256" <<'PY'
import json, subprocess, sys
from pathlib import Path
out, head, l2, dirty, native, reth, toolchain, lock, gates, reth_patch = sys.argv[1:]
genesis = json.loads(head)
pins = {'hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
        'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'}
if any(genesis.get(k) != v for k, v in pins.items()) or genesis.get('number') != 0:
    sys.exit(f'built producer does not reproduce the pinned L2 genesis: {genesis}')
rustc = subprocess.run(['rustc', f'+{toolchain}', '--version'], capture_output=True, text=True).stdout.strip()
report = {'chain_id': 700770, 'l2_commit': l2, 'l2_tracked_changes': int(dirty),
          'native': f'{native} (+ inert devnet-kes/devnet-lc-roster shim)', 'reth_snapshot': reth,
          'reth_patch_sha256': reth_patch,
          'rustc': rustc, 'features': [], 'settlement_recovery_lock_sha256': lock, 'l2_genesis': genesis,
          'l1_activation_epochs': json.loads(gates),
          'sha256': dict(l.split()[::-1] for l in (Path(out) / 'SHA256SUMS').read_text().splitlines())}
(Path(out) / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
PY
log "BUILD OK: $OUT"
