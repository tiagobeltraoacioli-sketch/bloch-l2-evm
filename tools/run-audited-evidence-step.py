#!/usr/bin/env python3
"""CI gate for the three evidence steps whose records pin inspected ("audited") source files.

  run-audited-evidence-step.py production-node-build-request
  run-audited-evidence-step.py partial-implementation-evidence
  run-audited-evidence-step.py node-qualification-package

The records `deployment/production-node-build-request.json` (baseline ccdcc20d) and
`deployment/partial-implementation-evidence.json` (baseline 68bbd9f8) state the SHA-256 of the source
files that were inspected for the testnet (chain 700771) production-node path. The mainnet work since
then changed some of those files, so `tools/test-<step>.py`, which asserts that the checked-in records
verify on the tree, fails on every later commit.

Decision (round 15, 2026-11-11, technical): the steps are GATED on the audited inputs. The hashes are
not refreshed (that would state an inspection nobody made) and the records are not deleted (they are
the evidence of the inspection that was made).

  * Tree equals the records: the step runs `tools/test-<step>.py` unchanged.
  * Tree has moved: the step lists the moved inputs and asserts the only thing that still must hold,
    that each checker REFUSES the record on this tree (fail closed: no build is permitted and no
    evidence is accepted for a tree nobody inspected). It then exits 0. It asserts no audit.

Whoever re-inspects the moved files updates the records in the same change; the full tests then run
again by themselves.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEPS = ("production-node-build-request", "partial-implementation-evidence", "node-qualification-package")
RECORDS = (
    ("deployment/production-node-build-request.json", "auditedInputs", "tools/check-production-node-build-request.py",
     "BuildRequestError", "hash mismatch"),
    ("deployment/partial-implementation-evidence.json", "artifacts", "tools/check-partial-implementation-evidence.py",
     "PartialEvidenceError", "sha256 mismatch"),
)


def load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def moved_inputs() -> dict[str, list[str]]:
    """Per record: the pinned files whose bytes differ from the record (or are gone)."""
    moved: dict[str, list[str]] = {}
    for record, key, _, _, _ in RECORDS:
        for item in json.loads((ROOT / record).read_text())[key]:
            path = ROOT / item["path"]
            actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
            if actual != item["sha256"]:
                moved.setdefault(record, []).append(item["path"])
    return moved


def assert_checkers_refuse(moved: dict[str, list[str]]) -> None:
    for record, _, checker, error, text in RECORDS:
        if record not in moved:
            continue
        module = load(ROOT / checker)
        try:
            module.validate(json.loads((ROOT / record).read_text()))
        except getattr(module, error) as why:
            if text not in str(why):
                raise SystemExit(f"{checker} refused {record} for another reason: {why}")
            print(f"  {checker}: refuses the record on this tree ({why})")
        else:
            raise SystemExit(f"{checker} ACCEPTED {record} although {len(moved[record])} pinned inputs moved")


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in STEPS:
        print(__doc__)
        return 2
    moved = moved_inputs()
    if not moved:
        return subprocess.run([sys.executable, str(ROOT / "tools" / f"test-{argv[0]}.py")], cwd=ROOT).returncode
    print(f"audited-evidence step {argv[0]}: GATED, the tree is not the inspected one. No audit is asserted.")
    for record, paths in moved.items():
        print(f"  {record}: {len(paths)} pinned input(s) moved: {', '.join(paths)}")
    assert_checkers_refuse(moved)
    print("  the checkers fail closed; tools/test-%s.py runs again when the records describe the tree" % argv[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
