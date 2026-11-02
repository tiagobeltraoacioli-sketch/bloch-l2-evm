#!/bin/bash
# Stage fresh sources of the forced-inclusion crossing on a host (rehearsal only).
#   stage.sh HOST
# Exports exactly NATIVE_REV of the native repository and L2_REV of the L2 repository with `git archive` (no worktree
# state, no untracked files), unpacks them under $A/src on HOST, links the reth RPC snapshot (RETH_SNAPSHOT on the host),
# copies the rehearsal docker shim for gnark (SHIM_FROM on the host) to $A/tools/bin and the activated guest 203114bf
# (BASE_ELF_FROM, hash-checked) to $A/elf, and records both revisions. The next guest and elf/next-program.json are placed
# by whoever built them.
#   NATIVE_REPO / L2_REPO   local repositories (default: the agent 137 worktrees)
#   NATIVE_REV / L2_REV     revisions (default: codex/forced-guest-native-r8-20261102, codex/forced-guest-r8-20261102)
#   KEY                     SSH identity (default ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4; used as an identity only)
set -euo pipefail
HOST=$1
NATIVE_REPO=${NATIVE_REPO:-$HOME/worktrees/forced-guest-native-r8-20261102}
L2_REPO=${L2_REPO:-$HOME/worktrees/forced-guest-r8-20261102}
NATIVE_REV=${NATIVE_REV:-codex/forced-guest-native-r8-20261102}
L2_REV=${L2_REV:-codex/forced-guest-r8-20261102}
KEY=${KEY:-$HOME/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4}
REMOTE_A=${REMOTE_A:-l2dexbridge-20261030/forced-guest-r8}
RETH_SNAPSHOT=${RETH_SNAPSHOT:-/home/ubuntu/l2dexbridge-20261030/next-consensus-r4/src/reth-bloch-rpc-snapshot}
SHIM_FROM=${SHIM_FROM:-/home/ubuntu/l2dexbridge-20261030/fork-candidate-r7/tools/bin/docker}
# The activated program's guest (settlement_v3_mainnet 203114bf), used before the gate.
BASE_ELF_FROM=${BASE_ELF_FROM:-/home/ubuntu/l2dexbridge-20261030/fork-candidate-r7/elf/settlement_v3_mainnet.v1}
native=$(git -C "$NATIVE_REPO" rev-parse --verify "$NATIVE_REV^{commit}")
l2=$(git -C "$L2_REPO" rev-parse --verify "$L2_REV^{commit}")
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git -C "$NATIVE_REPO" archive --prefix=bloch-validator-payout/ "$native" > "$tmp/native.tar"
git -C "$L2_REPO" archive --prefix=bloch-l2-evm/ "$l2" > "$tmp/l2.tar"
ssh=(ssh -o ConnectTimeout=20 -i "$KEY" "ubuntu@$HOST")
"${ssh[@]}" "mkdir -p ~/$REMOTE_A/src.new"
scp -q -o ConnectTimeout=20 -i "$KEY" "$tmp/native.tar" "$tmp/l2.tar" "ubuntu@$HOST:$REMOTE_A/src.new/"
"${ssh[@]}" bash -s -- "$REMOTE_A" "$native" "$l2" "$RETH_SNAPSHOT" "$SHIM_FROM" "$BASE_ELF_FROM" <<'EOF'
set -euo pipefail
A=$HOME/$1; cd "$A/src.new"
tar -xf native.tar && tar -xf l2.tar && rm native.tar l2.tar
echo "$2" > NATIVE_REV; echo "$3" > L2_REV
ln -s "$4" reth-bloch-rpc-snapshot
if [ -d "$A/src" ]; then mv "$A/src" "$A/src.old-$(date +%s)"; fi
mv "$A/src.new" "$A/src"
mkdir -p "$A/tools/bin" "$A/elf"
if [ -f "$5" ]; then cp "$5" "$A/tools/bin/docker"; chmod 755 "$A/tools/bin/docker"; fi
if [ -f "$6" ] && echo "203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473  $6" | sha256sum -c --quiet -; then
  cp "$6" "$A/elf/settlement_v3_mainnet.v1"
fi
cp "$A/src/bloch-l2-evm/deployment/mainnet/rehearsal/forced-inclusion/"{crossing.py,prep-build.sh} "$A/"
echo "staged native $2 and L2 $3 in $A/src"
EOF
