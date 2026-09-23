#!/usr/bin/env python3
"""Adversarial tests for the workspace production-node gap report."""

from __future__ import annotations

import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "workspace_production_node_gap",
    ROOT / "tools" / "check-workspace-production-node-gap.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WorkspaceProductionNodeGapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads(
            (ROOT / "deployment/workspace-production-node-gap-report.json").read_text()
        )

    def test_checked_in_report_has_no_compatible_candidate(self) -> None:
        result = MODULE.validate(self.report)
        self.assertEqual(result["sourcesInspected"], 4)
        self.assertEqual(result["symbolsRecorded"], 44)
        self.assertEqual(result["capabilityGaps"], 9)
        self.assertEqual(result["compatibleCandidates"], 0)
        self.assertTrue(result["legacyDevnetRejected"])
        self.assertFalse(result["productionReady"])

    def test_legacy_chain_8400_cannot_be_promoted(self) -> None:
        for field, replacement in [
            ("reportedChainId", 700771),
            ("compatibility", "production"),
            ("effect", "qualification"),
        ]:
            with self.subTest(field=field):
                changed = deepcopy(self.report)
                changed["runtimeObservations"][0][field] = replacement
                with self.assertRaises(MODULE.GapReportError):
                    MODULE.validate(changed)

    def test_gap_cannot_be_omitted_reordered_or_self_qualified(self) -> None:
        variants = []
        missing = deepcopy(self.report)
        missing["gaps"].pop()
        variants.append(missing)
        reordered = deepcopy(self.report)
        reordered["gaps"].reverse()
        variants.append(reordered)
        qualified = deepcopy(self.report)
        qualified["gaps"][0]["status"] = "qualified"
        variants.append(qualified)
        for changed in variants:
            with self.assertRaises(MODULE.GapReportError):
                MODULE.validate(changed)

    def test_interface_or_l1_source_cannot_be_relabelled(self) -> None:
        changed = deepcopy(self.report)
        changed["interface"]["registeredCandidate"] = True
        with self.assertRaisesRegex(MODULE.GapReportError, "must not register"):
            MODULE.validate(changed)
        changed = deepcopy(self.report)
        changed["sources"][1]["sourceChainId"] = 700771
        with self.assertRaisesRegex(MODULE.GapReportError, "L1 source"):
            MODULE.validate(changed)

    def test_interface_hash_and_production_claim_are_rejected(self) -> None:
        changed = deepcopy(self.report)
        changed["interface"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(MODULE.GapReportError, "sha256 mismatch"):
            MODULE.validate(changed)
        changed = deepcopy(self.report)
        changed["productionReady"] = True
        with self.assertRaisesRegex(MODULE.GapReportError, "cannot nominate"):
            MODULE.validate(changed)


if __name__ == "__main__":
    unittest.main()
