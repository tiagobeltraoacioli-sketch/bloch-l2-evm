#!/usr/bin/env python3
"""Adversarial tests for synthetic production-entrypoint conformance."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "production_entrypoint_conformance",
    ROOT / "tools" / "check-production-entrypoint-conformance.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProductionEntrypointConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(
            (ROOT / "deployment/production-entrypoint-conformance.json").read_text()
        )
        self.fixture = json.loads(
            (ROOT / "tests/fixtures/production-entrypoint-synthetic-observations.json").read_text()
        )

    def test_all_synthetic_checks_pass_without_qualifying_any_capability(self) -> None:
        report = MODULE.validate(self.plan)
        self.assertEqual(report["syntheticChecksPassed"], 9)
        self.assertEqual(report["syntheticChecksTotal"], 9)
        self.assertEqual(report["productionCapabilitiesQualified"], 0)
        self.assertFalse(report["productionQualified"])
        self.assertFalse(report["permissionsOpened"])
        self.assertFalse(report["sideEffects"])

    def fixture_plan(self, root: Path, fixture: dict) -> dict:
        contract_source = ROOT / "deployment/production-entrypoint-contract.json"
        contract = root / "contract.json"
        contract.write_bytes(contract_source.read_bytes())
        fixture_path = root / "fixture.json"
        fixture_path.write_text(json.dumps(fixture) + "\n", encoding="utf-8")
        plan = deepcopy(self.plan)
        plan["contract"] = {
            "artifact": "contract.json",
            "sha256": hashlib.sha256(contract.read_bytes()).hexdigest(),
        }
        plan["fixture"] = {
            "artifact": "fixture.json",
            "sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
        }
        return plan

    def test_fake_process_or_observation_cannot_claim_production_evidence(self) -> None:
        for field, replacement, message in [
            ("subjectKind", "production-process", "synthetic process double"),
            ("productionEvidence", True, "cannot be production evidence"),
            ("adapterId", "production-adapter", "unexpected adapter"),
        ]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = deepcopy(self.fixture)
                fixture["observations"][0][field] = replacement
                plan = self.fixture_plan(Path(directory), fixture)
                with self.assertRaisesRegex(MODULE.ConformanceError, message):
                    MODULE.validate(plan, Path(directory))

    def test_missing_reordered_or_weakened_coverage_is_rejected(self) -> None:
        fixtures = []
        missing = deepcopy(self.fixture)
        missing["observations"].pop()
        fixtures.append(missing)
        reordered = deepcopy(self.fixture)
        reordered["observations"].reverse()
        fixtures.append(reordered)
        weakened = deepcopy(self.fixture)
        weakened["observations"][3]["acceptanceExercised"].pop()
        fixtures.append(weakened)
        for fixture in fixtures:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises(MODULE.ConformanceError):
                    MODULE.validate(self.fixture_plan(root, fixture), root)

    def test_plan_cannot_open_permission_or_claim_qualification(self) -> None:
        variants = []
        qualification = deepcopy(self.plan)
        qualification["mayQualifyProduction"] = True
        variants.append(qualification)
        effect = deepcopy(self.plan)
        effect["effect"] = "qualification"
        variants.append(effect)
        permission = deepcopy(self.plan)
        permission["permissions"]["bindRpc"] = True
        variants.append(permission)
        for changed in variants:
            with self.assertRaises(MODULE.ConformanceError):
                MODULE.validate(changed)

    def test_hash_tamper_and_path_escape_are_rejected(self) -> None:
        changed = deepcopy(self.plan)
        changed["fixture"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(MODULE.ConformanceError, "does not match"):
            MODULE.validate(changed)
        changed = deepcopy(self.plan)
        changed["fixture"]["artifact"] = "../fixture.json"
        with self.assertRaisesRegex(MODULE.ConformanceError, "repository-relative"):
            MODULE.validate(changed)


if __name__ == "__main__":
    unittest.main()
