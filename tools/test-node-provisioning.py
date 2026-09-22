#!/usr/bin/env python3
"""Adversarial tests for the side-effect-free L2 provisioning preflight."""

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
    "node_provisioning", ROOT / "tools" / "check-node-provisioning.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IMAGE = "registry.example/bloch/reth@sha256:" + "a" * 64


class NodeProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "deployment/l2-node.json").read_text(encoding="utf-8")
        )

    def test_checked_in_plan_is_pending_and_side_effect_free(self) -> None:
        report = MODULE.validate(self.manifest)
        self.assertEqual(report["chainId"], 700_771)
        self.assertFalse(report["imagePinned"])
        self.assertFalse(report["genesisPinned"])
        self.assertFalse(report["nodeBindPermitted"])
        self.assertFalse(report["startPermitted"])
        self.assertFalse(report["sideEffects"])

    def test_chain_schema_and_unpinned_image_are_rejected(self) -> None:
        mutations = [
            ("chainId", 84001),
            ("schema", "foreign.v1"),
        ]
        for field, replacement in mutations:
            with self.subTest(field=field):
                changed = deepcopy(self.manifest)
                changed[field] = replacement
                with self.assertRaises(MODULE.ProvisioningError):
                    MODULE.validate(changed)
        for image in ["registry.example/bloch/reth:latest", "sha256:" + "a" * 64]:
            with self.subTest(image=image):
                changed = deepcopy(self.manifest)
                changed["runtime"]["image"] = image
                with self.assertRaisesRegex(MODULE.ProvisioningError, "pinned"):
                    MODULE.validate(changed)

    def test_partial_genesis_and_early_start_are_rejected(self) -> None:
        changed = deepcopy(self.manifest)
        changed["genesis"]["artifact"] = "genesis.json"
        with self.assertRaisesRegex(MODULE.ProvisioningError, "both be null"):
            MODULE.validate(changed)
        changed = deepcopy(self.manifest)
        changed["startPermitted"] = True
        with self.assertRaisesRegex(MODULE.ProvisioningError, "all provisioning"):
            MODULE.validate(changed)

    def reviewed_fixture(self, root: Path) -> tuple[dict, str]:
        genesis = root / "genesis.json"
        genesis.write_text('{"chainId":700771}\n', encoding="utf-8")
        genesis_digest = hashlib.sha256(genesis.read_bytes()).hexdigest()
        qualification = root / "qualification.json"
        qualification.write_text("reviewed\n", encoding="utf-8")
        qualification_digest = hashlib.sha256(qualification.read_bytes()).hexdigest()
        readiness = {
            "schema": "bloch.l2.node-production-readiness.v1",
            "network": "bloch-l2-testnet", "chainId": 700771,
            "requirements": [
                {"id": identifier, "satisfied": True,
                 "artifact": "qualification.json", "sha256": qualification_digest}
                for identifier in [
                    "chain-identity", "production-genesis", "execution-domain", "p2p-policy",
                    "checkpoint-policy", "source-derivation-policy", "settlement-policy",
                    "finality-policy",
                ]
            ],
            "productionReady": True,
            "bind": {"enabled": True, "rpcListen": "127.0.0.1:8545",
                     "p2pListen": "0.0.0.0:30303"},
        }
        readiness_path = root / "node-production.json"
        readiness_path.write_text(json.dumps(readiness) + "\n", encoding="utf-8")
        manifest = deepcopy(self.manifest)
        manifest.update(classification="reviewed-production", startPermitted=True)
        manifest["runtime"]["image"] = IMAGE
        manifest["genesis"] = {"artifact": "genesis.json", "sha256": genesis_digest}
        manifest["storage"]["dataDirectory"] = "/var/lib/bloch-l2"
        manifest["listeners"] = {"rpc": "127.0.0.1:8545", "p2p": "0.0.0.0:30303"}
        manifest["readiness"] = {
            "artifact": "node-production.json",
            "sha256": hashlib.sha256(readiness_path.read_bytes()).hexdigest(),
        }
        return manifest, genesis_digest

    def test_complete_plan_requires_external_image_and_genesis_pins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, genesis_digest = self.reviewed_fixture(root)
            with self.assertRaisesRegex(MODULE.ProvisioningError, "all provisioning"):
                MODULE.validate(manifest, root)
            report = MODULE.validate(manifest, root, IMAGE, genesis_digest)
            self.assertTrue(report["imageExternallyTrusted"])
            self.assertTrue(report["genesisExternallyTrusted"])
            self.assertTrue(report["startPermitted"])

    def test_hash_tamper_listener_drift_and_symlink_genesis_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, genesis_digest = self.reviewed_fixture(root)
            changed = deepcopy(manifest)
            changed["genesis"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(MODULE.ProvisioningError, "does not match"):
                MODULE.validate(changed, root, IMAGE, genesis_digest)
            changed = deepcopy(manifest)
            changed["listeners"]["rpc"] = "0.0.0.0:8545"
            with self.assertRaisesRegex(MODULE.ProvisioningError, "all provisioning"):
                MODULE.validate(changed, root, IMAGE, genesis_digest)
            link = root / "genesis-link.json"
            link.symlink_to(root / "genesis.json")
            changed = deepcopy(manifest)
            changed["genesis"]["artifact"] = "genesis-link.json"
            with self.assertRaisesRegex(MODULE.ProvisioningError, "non-symlink"):
                MODULE.validate(changed, root, IMAGE, genesis_digest)


if __name__ == "__main__":
    unittest.main()
