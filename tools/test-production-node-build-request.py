#!/usr/bin/env python3
"""Adversarial tests for the blocked production-node build request."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "production_node_build_request",
    ROOT / "tools" / "check-production-node-build-request.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProductionNodeBuildRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = json.loads(
            (ROOT / "deployment/production-node-build-request.json").read_text()
        )

    def test_checked_in_request_verifies_inputs_but_refuses_build(self) -> None:
        report = MODULE.validate(self.request)
        self.assertEqual(report["chainId"], 700_771)
        self.assertEqual(report["auditedInputsVerified"], 8)
        self.assertEqual(report["requiredDecisionsMissing"], 9)
        self.assertFalse(report["candidateProductionEligible"])
        self.assertFalse(report["preparedRethTreeVerified"])
        self.assertFalse(report["buildPermitted"])
        self.assertFalse(report["sideEffects"])

    def test_chain_candidate_and_output_claims_are_rejected(self) -> None:
        variants = []
        chain = deepcopy(self.request)
        chain["chainId"] = 84001
        variants.append(chain)
        candidate = deepcopy(self.request)
        candidate["candidate"]["productionEligible"] = True
        variants.append(candidate)
        output = deepcopy(self.request)
        output["outputs"]["image"] = "invented@sha256:" + "a" * 64
        variants.append(output)
        permission = deepcopy(self.request)
        permission["buildPermitted"] = True
        variants.append(permission)
        for changed in variants:
            with self.assertRaises(MODULE.BuildRequestError):
                MODULE.validate(changed)

    def test_missing_decision_cannot_be_self_approved(self) -> None:
        changed = deepcopy(self.request)
        changed["requiredDecisions"][0].update(
            status="approved", artifact="decision.json", sha256="0" * 64
        )
        with self.assertRaisesRegex(MODULE.BuildRequestError, "remain missing"):
            MODULE.validate(changed)
        changed = deepcopy(self.request)
        changed["requiredDecisions"].reverse()
        with self.assertRaisesRegex(MODULE.BuildRequestError, "reordered"):
            MODULE.validate(changed)

    def test_input_tamper_and_path_escape_are_rejected(self) -> None:
        changed = deepcopy(self.request)
        changed["auditedInputs"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(MODULE.BuildRequestError, "hash mismatch"):
            MODULE.validate(changed)
        changed = deepcopy(self.request)
        changed["auditedInputs"][0]["path"] = "../Cargo.toml"
        with self.assertRaisesRegex(MODULE.BuildRequestError, "repository-relative"):
            MODULE.validate(changed)

    def test_symlink_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("source", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(MODULE.BuildRequestError, "symlink"):
                MODULE.repository_file(root, "link", "audited input")


if __name__ == "__main__":
    unittest.main()
