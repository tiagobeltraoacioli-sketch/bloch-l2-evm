#!/usr/bin/env python3
"""Prepare or verify the isolated, pinned Reth source plus the recorded patch."""
import argparse
import os
from pathlib import Path
import subprocess

BASE = "8eb210175687c9f0c889a3b6795c16781d830e3a"
HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2] / "reth-bloch-integration"
TARGET = HERE.parents[2] / "reth-bloch-rpc-snapshot"
PATCH = HERE / "reth-snapshot.patch"
DIFF = ("--no-ext-diff", "--no-textconv", "--no-color", "--full-index", "--no-renames",
        "--unified=3", "--src-prefix=a/", "--dst-prefix=b/", "--binary")


def git(directory, *args):
    return subprocess.check_output(["git", "-C", str(directory), *args])


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify only; never create or patch")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="optional command after --, with verified Git build metadata")
    args = parser.parse_args()
    expected = PATCH.read_bytes()
    require(bool(expected), "Recorded Reth patch is empty")
    require(not TARGET.is_symlink(), "Prepared Reth target must not be a symlink")
    require(TARGET.resolve() != SOURCE.resolve(), "Prepared Reth target must differ from the original checkout")
    if not TARGET.exists():
        require(not args.check, f"Missing prepared Reth checkout: {TARGET}")
        require(git(SOURCE, "rev-parse", "HEAD").decode().strip() == BASE, "Reth source is not the pinned base")
        require(not git(SOURCE, "status", "--porcelain", "--untracked-files=all"), "Reth source must be clean")
        git(SOURCE, "worktree", "add", "--detach", str(TARGET), BASE)
    require(Path(git(TARGET, "rev-parse", "--show-toplevel").decode().strip()).resolve() == TARGET.resolve(),
            "Prepared Reth target must be its own worktree root")
    require(git(TARGET, "rev-parse", "HEAD").decode().strip() == BASE, "Prepared Reth HEAD differs from the pin")
    flags = git(TARGET, "ls-files", "-v", "-z").split(b"\0")
    require(all(not entry or (not entry[:1].islower() and entry[:1] != b"S") for entry in flags),
            "Prepared Reth has index flags that can hide working-tree edits")
    require(not git(TARGET, "diff", "--cached", *DIFF), "Prepared Reth has staged changes")
    # Local/global ignore rules cannot hide Rust sources or Cargo configuration.
    # Only reserved build output and platform metadata are exempt.
    require(not git(TARGET, "ls-files", "--others", "--exclude=target/", "--exclude=.DS_Store", "-z"),
            "Prepared Reth has untracked files outside reserved build outputs")
    actual = git(TARGET, "diff", *DIFF)
    if not actual and not args.check:
        git(TARGET, "apply", "--check", str(PATCH))
        git(TARGET, "apply", str(PATCH))
        actual = git(TARGET, "diff", *DIFF)
    require(actual == expected, "Prepared Reth differs from the recorded patch; existing edits were preserved")
    print(f"Verified Reth base {BASE} plus {PATCH.name}: {TARGET}", flush=True)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if command:
        # Native Git understands shallow worktrees where the build's libgit2
        # describe traversal can fail on an unavailable parent object. Report
        # the actual verified revision/description and the recorded local diff.
        env = os.environ.copy()
        env["VERGEN_GIT_SHA"] = git(TARGET, "rev-parse", "HEAD").decode().strip()
        env["VERGEN_GIT_DESCRIBE"] = git(TARGET, "describe", "--always", "--tags").decode().strip()
        env["VERGEN_GIT_DIRTY"] = "true"
        raise SystemExit(subprocess.call(command, env=env))


if __name__ == "__main__":
    main()
