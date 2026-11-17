# Sourced by build-release.sh and build-prover-host.sh: the ONE directory every release build runs in.
#
# Why a fixed directory and not only --remap-path-prefix. cargo names each crate by a hash that takes in the
# ABSOLUTE path of every path dependency outside the workspace of the crate being built (here the L2 root crate,
# the native crates and the reth snapshot, which are siblings of the integration crates), and rustc mangles every
# symbol of those crates with that hash. No rustc flag reaches it: with the path prefixes remapped the binaries
# no longer CONTAIN a build path, yet the December build of round 15 still gave four different SP1 hosts in four
# directories (docs/DECEMBER-BUILD-R15.md section 3). So the build scripts copy WORK/src to BLOCH_BUILD_ROOT and
# build there, whatever WORK is and whoever runs them; the caller's trees are not modified. /var/tmp is
# world-writable on Linux: no privilege, no mount namespace and no particular user name or home is needed. The
# cargo registry stays where it is (crates from a registry are named by the registry, not by its path); its
# path is remapped by the scripts.
#
# One build at a time per machine (a lock, held until the build script ends). EVERY build starts from nothing:
# staging removes whatever BLOCH_BUILD_ROOT holds, the cargo target directories included (review R335-2). They
# used to stay between builds; `cp -a` keeps the sources' modification times and cargo decides "fresh" by
# modification time, so a build of tree B after a build of tree A could reuse A's compiled crates under a
# build.json that names B. There is no incremental mode. The lock file lies BESIDE the directory, not in it, so
# removing the directory by hand cannot let a second build start next to a running one.
BLOCH_BUILD_ROOT=/var/tmp/bloch-l2-build
BLOCH_BUILD_LOCK=/var/tmp/bloch-l2-build.lock

# stage_build_root WORK: take the lock, empty BLOCH_BUILD_ROOT, copy
# WORK/src/{bloch-l2-evm,bloch-validator-payout,reth-bloch-rpc-snapshot} to BLOCH_BUILD_ROOT/src (git metadata
# included: the build verifies commits and clean trees) and keep the lock on file descriptor 9, which the build
# script that is exec'ed next inherits. That script is told by BLOCH_BUILD_STAGED that it runs from the copy.
stage_build_root() {
  local from=$1 repo
  for repo in bloch-l2-evm bloch-validator-payout reth-bloch-rpc-snapshot; do
    [ -d "$from/src/$repo" ] || { echo "build-root: missing $from/src/$repo" >&2; return 2; }
  done
  # The lock file is created without following a link (noclobber: O_EXCL) and only ever opened for reading, so a
  # link planted at its name in the world-writable parent cannot make this script write anywhere.
  ( set -C; : > "$BLOCH_BUILD_LOCK" ) 2>/dev/null || true
  [ -f "$BLOCH_BUILD_LOCK" ] && [ ! -L "$BLOCH_BUILD_LOCK" ] \
    || { echo "build-root: $BLOCH_BUILD_LOCK must be a regular file (a link or a directory is refused)" >&2; return 2; }
  exec 9< "$BLOCH_BUILD_LOCK"
  flock -n 9 || { echo "build-root: another build holds $BLOCH_BUILD_LOCK; one release build at a time per machine" >&2; return 2; }
  mkdir -p -m 0700 "$BLOCH_BUILD_ROOT"
  [ -d "$BLOCH_BUILD_ROOT" ] && [ ! -L "$BLOCH_BUILD_ROOT" ] && [ -O "$BLOCH_BUILD_ROOT" ] \
    || { echo "build-root: $BLOCH_BUILD_ROOT must be a directory owned by the user who builds (another user's build directory, or a link, is refused)" >&2; return 2; }
  # From nothing: the previous build's sources AND its target directories go (review R335-2).
  find "$BLOCH_BUILD_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  mkdir "$BLOCH_BUILD_ROOT/src"
  for repo in bloch-l2-evm bloch-validator-payout reth-bloch-rpc-snapshot; do
    cp -a "$from/src/$repo" "$BLOCH_BUILD_ROOT/src/$repo"
  done
}
