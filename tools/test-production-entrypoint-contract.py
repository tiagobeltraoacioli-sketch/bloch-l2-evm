#!/usr/bin/env python3
"""Adversarial tests for the production entrypoint capability contract."""

from __future__ import annotations

import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "production_entrypoint_contract",
    ROOT / "tools" / "check-production-entrypoint-contract.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProductionEntrypointContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(
            (ROOT / "deployment/production-entrypoint-contract.json").read_text()
        )

    def test_checked_in_contract_is_complete_but_all_capabilities_missing(self) -> None:
        report = MODULE.validate(self.contract)
        self.assertEqual(report["chainId"], 700_771)
        self.assertEqual(report["capabilitiesRequired"], 9)
        self.assertEqual(report["capabilitiesSatisfied"], 0)
        self.assertFalse(report["entrypointDefined"])
        self.assertFalse(report["productionReady"])
        self.assertFalse(report["permissionsOpened"])

    def test_chain_and_classification_substitution_are_rejected(self) -> None:
        for field, replacement in [
            ("chainId", 84001),
            ("classification", "production"),
            ("schema", "foreign.v1"),
        ]:
            with self.subTest(field=field):
                changed = deepcopy(self.contract)
                changed[field] = replacement
                with self.assertRaises(MODULE.EntrypointContractError):
                    MODULE.validate(changed)

    def test_synthetic_or_invented_entrypoint_cannot_be_inserted(self) -> None:
        for field, replacement in [
            ("binary", "bloch-evm-dev"),
            ("image", "invented@sha256:" + "a" * 64),
            ("arguments", ["--synthetic-dev"]),
            ("genesisArtifact", "invented-genesis.json"),
        ]:
            with self.subTest(field=field):
                changed = deepcopy(self.contract)
                changed["entrypoint"][field] = replacement
                with self.assertRaises(MODULE.EntrypointContractError):
                    MODULE.validate(changed)

    def test_capability_cannot_be_omitted_reordered_or_self_approved(self) -> None:
        variants = []
        missing = deepcopy(self.contract)
        missing["capabilities"].pop()
        variants.append(missing)
        reordered = deepcopy(self.contract)
        reordered["capabilities"].reverse()
        variants.append(reordered)
        approved = deepcopy(self.contract)
        approved["capabilities"][0].update(
            status="qualified", evidence="claim.json", sha256="0" * 64
        )
        variants.append(approved)
        weakened = deepcopy(self.contract)
        weakened["capabilities"][0]["required"] = False
        variants.append(weakened)
        acceptance = deepcopy(self.contract)
        acceptance["capabilities"][3]["acceptance"].remove("settlement-bound-finality")
        variants.append(acceptance)
        for changed in variants:
            with self.assertRaises(MODULE.EntrypointContractError):
                MODULE.validate(changed)

    def test_no_permission_or_readiness_can_open_early(self) -> None:
        for field in MODULE.PERMISSION_FIELDS:
            with self.subTest(field=field):
                changed = deepcopy(self.contract)
                changed["permissions"][field] = True
                with self.assertRaisesRegex(MODULE.EntrypointContractError, "permission"):
                    MODULE.validate(changed)
        changed = deepcopy(self.contract)
        changed["productionReady"] = True
        with self.assertRaisesRegex(MODULE.EntrypointContractError, "not be production ready"):
            MODULE.validate(changed)


if __name__ == "__main__":
    unittest.main()
