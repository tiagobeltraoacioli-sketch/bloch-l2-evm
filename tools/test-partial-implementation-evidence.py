#!/usr/bin/env python3
"""Adversarial tests for partial implementation evidence."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "partial_implementation_evidence", ROOT / "tools/check-partial-implementation-evidence.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PartialImplementationEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(
            (ROOT / "deployment/partial-implementation-evidence.json").read_text(encoding="utf-8")
        )

    def test_checked_in_evidence_records_partial_work_without_authority(self) -> None:
        report = MODULE.validate(self.value, ROOT)
        self.assertEqual(report["artifactsVerified"], 11)
        self.assertEqual(report["capabilitiesWithPartialImplementation"], 4)
        self.assertTrue(report["frozenGenesisPending"])
        self.assertFalse(report["productionReady"])
        self.assertTrue(all(not item["productionQualified"] for item in self.value["artifacts"]))
        self.assertTrue(all(not item["productionQualified"] for item in self.value["capabilityAssessments"]))
        self.assertTrue(all(value is False for value in self.value["permissions"].values()))

    def test_artifact_tampering_and_inventory_changes_are_rejected(self) -> None:
        wrong_hash = deepcopy(self.value)
        wrong_hash["artifacts"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(MODULE.PartialEvidenceError, "sha256 mismatch"):
            MODULE.validate(wrong_hash, ROOT)
        missing = deepcopy(self.value)
        missing["artifacts"].pop()
        with self.assertRaisesRegex(MODULE.PartialEvidenceError, "wrong length"):
            MODULE.validate(missing, ROOT)

    def test_partial_evidence_cannot_self_qualify_or_open_permissions(self) -> None:
        variants = []
        ready = deepcopy(self.value)
        ready["productionReady"] = True
        variants.append(ready)
        qualified = deepcopy(self.value)
        qualified["capabilityAssessments"][0]["productionQualified"] = True
        variants.append(qualified)
        permission = deepcopy(self.value)
        permission["permissions"]["startNode"] = True
        variants.append(permission)
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(MODULE.PartialEvidenceError):
                    MODULE.validate(value, ROOT)

    def test_strict_gate_remains_closed(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/check-partial-implementation-evidence.py"),
             "--require-production-ready"],
            stdout=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
