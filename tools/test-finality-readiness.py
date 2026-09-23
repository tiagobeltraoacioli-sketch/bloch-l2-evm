#!/usr/bin/env python3
"""Adversarial tests for the production finality permission gate."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "finality_readiness", ROOT / "tools" / "check-finality-readiness.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FinalityReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.finality = json.loads(
            (ROOT / "network" / "finality.json").read_text(encoding="utf-8")
        )
        self.identity = json.loads(
            (ROOT / "network" / "identity.json").read_text(encoding="utf-8")
        )

    def test_checked_in_gate_is_valid_and_closed(self) -> None:
        report = MODULE.validate(self.finality, self.identity)
        self.assertEqual(report["requirementsSatisfied"], 0)
        self.assertFalse(report["productionFinalityReady"])
        self.assertFalse(any(report["permissions"].values()))

    def test_permission_cannot_open_early(self) -> None:
        for permission in MODULE.PERMISSION_FIELDS:
            with self.subTest(permission=permission):
                changed = deepcopy(self.finality)
                changed["permissions"][permission] = True
                with self.assertRaisesRegex(MODULE.FinalityError, "permissions"):
                    MODULE.validate(changed, self.identity)

    def test_claim_without_evidence_and_evidence_without_claim_are_rejected(self) -> None:
        claimed = deepcopy(self.finality)
        claimed["requirements"][0]["satisfied"] = True
        with self.assertRaisesRegex(MODULE.FinalityError, "evidence exactly"):
            MODULE.validate(claimed, self.identity)
        unclaimed = deepcopy(self.finality)
        unclaimed["requirements"][0]["evidence"] = [{
            "artifact": "release/evidence.json",
            "sha256": "ab" * 32,
            "verifiedAt": "2026-09-20",
        }]
        with self.assertRaisesRegex(MODULE.FinalityError, "evidence exactly"):
            MODULE.validate(unclaimed, self.identity)

    def test_all_requirements_need_evidence_and_identity_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_root = Path(directory)
            ready = deepcopy(self.finality)
            for item in ready["requirements"]:
                support = Path("network/evidence/support") / f"{item['id']}.log"
                support_path = evidence_root / support
                support_path.parent.mkdir(parents=True, exist_ok=True)
                support_path.write_text(f"reviewed support for {item['id']}", encoding="utf-8")
                artifact = Path("network/evidence/requirements") / f"{item['id']}.json"
                artifact_path = evidence_root / artifact
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_path.write_text(json.dumps({
                    "schema": "bloch.l2.finality-requirement-evidence.v1",
                    "network": "bloch-l2-testnet",
                    "chainId": 700_771,
                    "requirementId": item["id"],
                    "classification": "production-operational-reviewed",
                    "conclusion": "satisfied",
                    "reviewedAt": "2026-09-20",
                    "support": [{
                        "artifact": support.as_posix(),
                        "sha256": hashlib.sha256(support_path.read_bytes()).hexdigest(),
                    }],
                    "limitations": [],
                }), encoding="utf-8")
                item["satisfied"] = True
                item["evidence"] = [{
                    "artifact": artifact.as_posix(),
                    "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                    "verifiedAt": "2026-09-20",
                }]
            ready["productionFinalityReady"] = True
            with self.assertRaisesRegex(MODULE.FinalityError, "finalizedRpcVerified"):
                MODULE.validate(ready, self.identity, evidence_root)
            identity = deepcopy(self.identity)
            identity["activation"]["finalizedRpcVerified"] = True
            report = MODULE.validate(ready, identity, evidence_root)
            self.assertTrue(report["productionFinalityReady"])

    def test_arbitrary_hash_bound_file_cannot_satisfy_a_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_root = Path(directory)
            artifact = evidence_root / "network/evidence/requirements/checkpoint.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("not a requirement evidence envelope", encoding="utf-8")
            changed = deepcopy(self.finality)
            item = changed["requirements"][0]
            item["satisfied"] = True
            item["evidence"] = [{
                "artifact": "network/evidence/requirements/checkpoint.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "verifiedAt": "2026-09-20",
            }]
            with self.assertRaises(MODULE.FinalityError):
                MODULE.validate(changed, self.identity, evidence_root)

    def test_missing_duplicate_reordered_and_foreign_requirements_are_rejected(self) -> None:
        cases = []
        missing = deepcopy(self.finality)
        missing["requirements"].pop()
        cases.append(missing)
        duplicate = deepcopy(self.finality)
        duplicate["requirements"][-1]["id"] = duplicate["requirements"][0]["id"]
        cases.append(duplicate)
        reordered = deepcopy(self.finality)
        reordered["requirements"].reverse()
        cases.append(reordered)
        foreign = deepcopy(self.finality)
        foreign["chainId"] = 84001
        cases.append(foreign)
        for changed in cases:
            with self.assertRaises(MODULE.FinalityError):
                MODULE.validate(changed, self.identity)

    def test_malformed_evidence_is_rejected(self) -> None:
        for field, value in [
            ("artifact", "x"),
            ("sha256", "zz" * 32),
            ("verifiedAt", "20-09-2026"),
        ]:
            changed = deepcopy(self.finality)
            item = changed["requirements"][0]
            item["satisfied"] = True
            item["evidence"] = [{
                "artifact": "evidence/checkpoint.json",
                "sha256": "ab" * 32,
                "verifiedAt": "2026-09-20",
            }]
            item["evidence"][0][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.FinalityError):
                MODULE.validate(changed, self.identity)

    def test_missing_traversing_and_hash_mismatched_artifacts_are_rejected(self) -> None:
        cases = [
            ("evidence/missing.json", "ab" * 32),
            ("../outside.json", "ab" * 32),
        ]
        with tempfile.TemporaryDirectory() as directory:
            evidence_root = Path(directory)
            artifact = evidence_root / "evidence" / "actual.json"
            artifact.parent.mkdir()
            artifact.write_text("real evidence", encoding="utf-8")
            cases.append(("evidence/actual.json", "ab" * 32))
            for artifact_name, digest in cases:
                changed = deepcopy(self.finality)
                item = changed["requirements"][0]
                item["satisfied"] = True
                item["evidence"] = [{
                    "artifact": artifact_name,
                    "sha256": digest,
                    "verifiedAt": "2026-09-20",
                }]
                with self.subTest(artifact=artifact_name), self.assertRaises(
                    MODULE.FinalityError
                ):
                    MODULE.validate(changed, self.identity, evidence_root)


if __name__ == "__main__":
    unittest.main()
