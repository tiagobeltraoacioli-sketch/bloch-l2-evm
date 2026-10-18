#!/usr/bin/env python3
"""Build shim for the mainnet native release (bloch-sis-pow 78b7343a).

settlement-recovery forwards the devnet-only features `devnet-kes` and
`devnet-lc-roster` to bloch-pos-committee / bloch-pos-node. The mainnet
release does not define them, so Cargo refuses to resolve the workspace even
though the mainnet follower never enables them. This adds the two names as
empty features (no code, no dependency) right after `[features]` in both
crates of a scratch checkout. Idempotent; refuses any other layout.
"""
import pathlib
import sys

SHIM = (
    "# Build shim (bloch-l2-evm mainnet follower): inert devnet feature names,\n"
    "# never enabled on mainnet; no code depends on them in this release.\n"
    "devnet-kes = []\n"
    "devnet-lc-roster = []\n"
)


def main(root: str) -> int:
    for crate in ("bloch-pos-committee", "bloch-pos-node"):
        path = pathlib.Path(root, "crates", crate, "Cargo.toml")
        text = path.read_text()
        if "devnet-kes" in text or "devnet-lc-roster" in text:
            if SHIM in text:
                continue
            sys.exit(f"{path}: already defines a devnet-kes/devnet-lc-roster feature; not a mainnet release tree")
        if text.count("\n[features]\n") != 1:
            sys.exit(f"{path}: expected exactly one [features] table")
        path.write_text(text.replace("\n[features]\n", "\n[features]\n" + SHIM, 1))
        print(f"shimmed {path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: native-feature-shim.py NATIVE_CHECKOUT")
    raise SystemExit(main(sys.argv[1]))
