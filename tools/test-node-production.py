#!/usr/bin/env python3
"""Adversarial tests for the production-node bind gate."""

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
    "node_production", ROOT / "tools" / "check-node-production.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NodeProductionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "network" / "node-production.json").read_text(encoding="utf-8")
        )

    def test_checked_in_manifest_is_pending_and_cannot_bind(self) -> None:
        report = MODULE.validate(self.manifest)
        self.assertEqual(report["requirementsSatisfied"], 0)
        self.assertFalse(report["productionReady"])
        self.assertFalse(report["bindPermitted"])

    def test_chain_id_and_schema_substitution_are_rejected(self) -> None:
        for field, replacement in [("chainId", 84001), ("schema", "foreign.v1")]:
            with self.subTest(field=field):
                changed = deepcopy(self.manifest)
                changed[field] = replacement
                with self.assertRaises(MODULE.NodeProductionError):
                    MODULE.validate(changed)

    def test_missing_duplicate_and_reordered_requirements_are_rejected(self) -> None:
        variants = []
        missing = deepcopy(self.manifest)
        missing["requirements"].pop()
        variants.append(missing)
        duplicated = deepcopy(self.manifest)
        duplicated["requirements"][-1] = deepcopy(duplicated["requirements"][0])
        variants.append(duplicated)
        reordered = deepcopy(self.manifest)
        reordered["requirements"].reverse()
        variants.append(reordered)
        for changed in variants:
            with self.subTest(ids=[item["id"] for item in changed["requirements"]]):
                with self.assertRaises(MODULE.NodeProductionError):
                    MODULE.validate(changed)

    def test_pending_requirement_cannot_carry_placeholder_evidence(self) -> None:
        for field, replacement in [("artifact", "evidence.json"), ("sha256", "0" * 64)]:
            with self.subTest(field=field):
                changed = deepcopy(self.manifest)
                changed["requirements"][0][field] = replacement
                with self.assertRaisesRegex(MODULE.NodeProductionError, "must be null"):
                    MODULE.validate(changed)

    def test_open_bind_or_published_endpoint_before_readiness_is_rejected(self) -> None:
        mutations = [
            lambda value: value["bind"].update(enabled=True),
            lambda value: value["bind"].update(rpcListen="0.0.0.0:8545"),
            lambda value: value.update(productionReady=True),
        ]
        for mutate in mutations:
            changed = deepcopy(self.manifest)
            mutate(changed)
            with self.assertRaises(MODULE.NodeProductionError):
                MODULE.validate(changed)

    def test_satisfied_requirement_needs_existing_hash_bound_artifact(self) -> None:
        changed = deepcopy(self.manifest)
        requirement = changed["requirements"][0]
        requirement.update(satisfied=True, artifact="missing.json", sha256="0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODULE.NodeProductionError, "does not exist"):
                MODULE.validate(changed, Path(directory))

    def test_hash_mismatch_and_path_escape_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.json"
            artifact.write_text("reviewed", encoding="utf-8")
            for artifact_name, digest, message in [
                ("evidence.json", "0" * 64, "does not match"),
                ("../evidence.json", hashlib.sha256(b"reviewed").hexdigest(), "relative"),
            ]:
                with self.subTest(message=message):
                    changed = deepcopy(self.manifest)
                    changed["requirements"][0].update(
                        satisfied=True, artifact=artifact_name, sha256=digest
                    )
                    with self.assertRaisesRegex(MODULE.NodeProductionError, message):
                        MODULE.validate(changed, root)

    def test_bind_only_opens_after_every_hash_bound_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "qualification.json"
            artifact.write_text("reviewed qualification", encoding="utf-8")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            changed = deepcopy(self.manifest)
            for requirement in changed["requirements"]:
                requirement.update(
                    satisfied=True, artifact="qualification.json", sha256=digest
                )
            changed["productionReady"] = True
            changed["bind"] = {
                "enabled": True,
                "rpcListen": "0.0.0.0:8545",
                "p2pListen": "0.0.0.0:30303",
            }
            report = MODULE.validate(changed, root)
            self.assertTrue(report["bindPermitted"])

            changed["requirements"][-1].update(
                satisfied=False, artifact=None, sha256=None
            )
            with self.assertRaisesRegex(MODULE.NodeProductionError, "productionReady"):
                MODULE.validate(changed, root)


if __name__ == "__main__":
    unittest.main()
