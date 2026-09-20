#!/usr/bin/env python3
"""Adversarial tests for the Bloch L2 chain-ID decision gate."""

from __future__ import annotations

import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "network_identity", ROOT / "tools" / "check-network-identity.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NetworkIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = MODULE.validate_identity(
            json.loads((ROOT / "network" / "identity.json").read_text(encoding="utf-8"))
        )
        self.record = {
            **MODULE.expected_registry_record(self.identity),
            "rpc": [],
            "faucets": [],
            "infoURL": "https://posternlabs.com",
        }
        self.proposal = json.loads(
            (ROOT / "network" / "eip155-700771.json").read_text(encoding="utf-8")
        )

    def test_registration_proposal_matches_the_selected_identity(self) -> None:
        self.assertEqual(
            MODULE.validate_proposal(self.identity, self.proposal)["chainId"], 700_771
        )

    def test_proposal_cannot_publish_an_unqualified_rpc_or_foreign_domain(self) -> None:
        for mutate, message in [
            (lambda value: value.update(rpc=["http://127.0.0.1:8545"]), "RPC list"),
            (lambda value: value.update(networkId=84001), "networkId"),
            (lambda value: value["nativeCurrency"].update(symbol="ETH"), "nativeCurrency"),
        ]:
            with self.subTest(message=message):
                changed = deepcopy(self.proposal)
                mutate(changed)
                with self.assertRaisesRegex(MODULE.IdentityError, message):
                    MODULE.validate_proposal(self.identity, changed)

    def test_unregistered_candidate_is_available_but_not_ready(self) -> None:
        report = MODULE.check_registry(self.identity, [{"chainId": 1}])
        self.assertEqual(report["availability"], "available-unregistered")
        self.assertFalse(report["registered"])
        self.assertFalse(report["productionReady"])

    def test_exact_registration_is_recognized_but_activation_stays_closed(self) -> None:
        report = MODULE.check_registry(self.identity, [self.record])
        self.assertEqual(report["availability"], "registered-to-bloch")
        self.assertTrue(report["registered"])
        self.assertFalse(report["productionReady"])

    def test_collision_and_metadata_substitution_are_rejected(self) -> None:
        for field, replacement in [
            ("name", "Foreign Chain"),
            ("shortName", "foreign"),
            ("chain", "FOREIGN"),
            ("networkId", 7),
            ("status", "active"),
        ]:
            with self.subTest(field=field):
                record = deepcopy(self.record)
                record[field] = replacement
                with self.assertRaisesRegex(MODULE.IdentityError, field):
                    MODULE.check_registry(self.identity, [record])

    def test_duplicate_chain_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.IdentityError, "duplicate"):
            MODULE.check_registry(self.identity, [self.record, deepcopy(self.record)])

    def test_name_and_short_name_must_not_be_owned_by_another_chain(self) -> None:
        for field in ("name", "shortName"):
            with self.subTest(field=field):
                foreign = {"chainId": 99, field: self.record[field]}
                with self.assertRaisesRegex(MODULE.IdentityError, field):
                    MODULE.check_registry(self.identity, [foreign])

    def test_activation_cannot_claim_ready_with_an_open_gate(self) -> None:
        changed = deepcopy(self.identity)
        changed["activation"]["productionReady"] = True
        with self.assertRaisesRegex(MODULE.IdentityError, "conjunction"):
            MODULE.validate_identity(changed)

    def test_candidate_chain_and_caip_substitution_are_rejected(self) -> None:
        for mutate in [
            lambda value: value.update(chainId=84001),
            lambda value: value.update(caip2="eip155:84001"),
            lambda value: value["decision"].update(supersedes=[8400]),
        ]:
            changed = deepcopy(self.identity)
            mutate(changed)
            with self.assertRaises(MODULE.IdentityError):
                MODULE.validate_identity(changed)


if __name__ == "__main__":
    unittest.main()
