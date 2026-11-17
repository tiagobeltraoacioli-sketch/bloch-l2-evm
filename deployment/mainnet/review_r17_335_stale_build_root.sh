#!/bin/bash
# Agent 335, R335-2: the staging of deployment/mainnet/build-root.sh (cp -a of WORK/src into ONE fixed directory,
# target directories kept between builds) lets cargo reuse the artifacts of ANOTHER source tree. Toy crates, the
# same staging steps (rm -rf ROOT/src; cp -a WORK/src/<repo> ROOT/src/<repo>; build with the target under ROOT).
set -eu
. $HOME/.cargo/env
T=$(mktemp -d -p "$PWD" run.XXXXXX); ROOT=$T/fixed-build-root
mk() { mkdir -p $T/$1/src/dep/src $T/$1/src/app/src
  printf "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n" > $T/$1/src/dep/Cargo.toml
  printf "pub fn recipient() -> &\x27static str { \"%s\" }\n" "$2" > $T/$1/src/dep/src/lib.rs
  printf "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n[workspace]\n" > $T/$1/src/app/Cargo.toml
  printf "fn main() { println!(\"{}\", dep::recipient()); }\n" > $T/$1/src/app/src/main.rs; }
# Two checkouts prepared first (as two agents, or two candidate trees, on one build machine), built one after the other.
mk work-b "tree B: the release candidate"; sleep 2; mk work-a "tree A: somebody else, another branch"
stage_and_build() { mkdir -p $ROOT; rm -rf $ROOT/src; mkdir $ROOT/src; cp -a $T/$1/src/dep $ROOT/src/dep; cp -a $T/$1/src/app $ROOT/src/app
  CARGO_TARGET_DIR=$ROOT/target cargo build -q --release --manifest-path $ROOT/src/app/Cargo.toml; $ROOT/target/release/app; }
echo "build 1 (WORK = work-a):"; stage_and_build work-a
echo "build 2 (WORK = work-b, sources verified to be tree B):"; grep -o "tree B[^\"]*" $ROOT/src/dep/src/lib.rs >/dev/null 2>&1 || true; stage_and_build work-b
echo "source staged for build 2: $(grep -o "\"tree.*\"" $ROOT/src/dep/src/lib.rs)"
