#!/usr/bin/env python3
"""Adversarial tests for authenticated operational observation intake."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "operational_evidence_intake", ROOT / "tools" / "intake-operational-evidence.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OperationalEvidenceIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "observer"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        public = self.key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(f"operator@example.test {public}\n", encoding="utf-8")
        self.details = self.root / "details.json"
        self.details.write_bytes(b'{"probe":"finalized","result":"unavailable"}\n')
        self.value = {
            "schema": "bloch.l2.operational-observation.v1", "network": "bloch-l2-testnet",
            "chainId": 700771, "requirementId": "reth-finalized-tag-verified",
            "observedAt": "2026-09-22T12:34:56Z", "observer": "operator@example.test",
            "source": "l2-node-a/offline-finality-probe", "result": "pass",
            "detailsSha256": hashlib.sha256(self.details.read_bytes()).hexdigest(),
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_observation(self, value=None, canonical=True) -> Path:
        path = self.root / "observation.json"
        value = self.value if value is None else value
        content = MODULE.canonical(value) if canonical else json.dumps(value, indent=2).encode()
        path.write_bytes(content)
        return path

    def sign(self, observation: Path, namespace=MODULE.NAMESPACE, key=None) -> Path:
        signature = Path(str(observation) + ".sig")
        signature.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-q", "-f", str(key or self.key),
             "-n", namespace, str(observation)], check=True,
        )
        return signature

    def authenticate(self, observation: Path, signature: Path, output=None, allowed=None):
        args = type("Args", (), {
            "observation": observation, "signature": signature,
            "details": self.details,
            "allowed_signers": allowed or self.allowed,
            "trusted_allowed_signers_sha256": hashlib.sha256(
                self.allowed.read_bytes()
            ).hexdigest(),
            "output": output or self.root / "authenticated.json",
        })
        return MODULE.authenticate(args)

    def test_valid_signature_creates_observation_only_artifact(self) -> None:
        observation = self.write_observation()
        report = self.authenticate(observation, self.sign(observation))
        artifact = json.loads((self.root / "authenticated.json").read_text())
        self.assertTrue(report["authenticated"])
        self.assertFalse(report["qualified"])
        self.assertEqual(artifact["effect"], "observation-only")
        self.assertFalse(artifact["qualified"])
        self.assertTrue(artifact["detailsBoundAtIntake"])
        self.assertEqual(artifact["detailsBytes"], len(self.details.read_bytes()))
        self.assertEqual(artifact["observation"], self.value)

    def test_authenticated_artifact_can_be_independently_reverified(self) -> None:
        observation = self.write_observation()
        signature = self.sign(observation)
        self.authenticate(observation, signature)
        args = type("Args", (), {
            "observation": observation, "details": self.details, "signature": signature,
            "allowed_signers": self.allowed,
            "trusted_allowed_signers_sha256": hashlib.sha256(
                self.allowed.read_bytes()
            ).hexdigest(),
            "artifact": self.root / "authenticated.json",
        })
        report = MODULE.verify(args)
        self.assertTrue(report["authenticated"])
        self.assertFalse(report["qualified"])

        artifact = json.loads(args.artifact.read_text())
        artifact["qualified"] = True
        args.artifact.write_bytes(MODULE.canonical(artifact))
        with self.assertRaisesRegex(MODULE.IntakeError, "does not match"):
            MODULE.verify(args)

    def test_changed_details_are_rejected(self) -> None:
        observation = self.write_observation()
        signature = self.sign(observation)
        self.details.write_bytes(b'{"probe":"finalized","result":"pass"}\n')
        with self.assertRaisesRegex(MODULE.IntakeError, "do not match"):
            self.authenticate(observation, signature)

    def test_tamper_wrong_namespace_and_wrong_principal_are_rejected(self) -> None:
        observation = self.write_observation()
        signature = self.sign(observation)
        observation.write_bytes(MODULE.canonical({**self.value, "result": "fail"}))
        with self.assertRaisesRegex(MODULE.IntakeError, "verification failed"):
            self.authenticate(observation, signature)
        observation.write_bytes(MODULE.canonical(self.value))
        wrong_signature = self.sign(observation, "wrong-namespace")
        with self.assertRaisesRegex(MODULE.IntakeError, "verification failed"):
            self.authenticate(observation, wrong_signature)
        changed = {**self.value, "observer": "intruder@example.test"}
        observation.write_bytes(MODULE.canonical(changed))
        changed_signature = self.sign(observation)
        with self.assertRaisesRegex(MODULE.IntakeError, "verification failed"):
            self.authenticate(observation, changed_signature)

    def test_noncanonical_signed_json_is_rejected(self) -> None:
        observation = self.write_observation(canonical=False)
        signature = self.sign(observation)
        with self.assertRaisesRegex(MODULE.IntakeError, "not canonical"):
            self.authenticate(observation, signature)

    def test_unknown_fields_requirement_and_bad_time_are_rejected(self) -> None:
        cases = [
            ({**self.value, "claim": "ready"}, "fields"),
            ({**self.value, "requirementId": "invented"}, "unknown requirementId"),
            ({**self.value, "observedAt": "2026-09-22"}, "RFC3339 UTC"),
        ]
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(MODULE.IntakeError, message):
                    MODULE.validate_observation(value)

    def test_repository_local_trust_root_is_rejected(self) -> None:
        observation = self.write_observation()
        signature = self.sign(observation)
        local = ROOT / ".test-allowed-signers"
        try:
            local.write_bytes(self.allowed.read_bytes())
            with self.assertRaisesRegex(MODULE.IntakeError, "outside the repository"):
                self.authenticate(observation, signature, allowed=local)
        finally:
            local.unlink(missing_ok=True)

    def test_self_created_policy_is_rejected_against_trusted_digest(self) -> None:
        observation = self.write_observation()
        attacker_key = self.root / "attacker"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(attacker_key)],
            check=True,
        )
        attacker_public = attacker_key.with_suffix(".pub").read_text().strip()
        attacker_policy = self.root / "attacker_allowed_signers"
        attacker_policy.write_text(
            f"operator@example.test {attacker_public}\n", encoding="utf-8"
        )
        signature = self.sign(observation, key=attacker_key)
        args = type("Args", (), {
            "observation": observation, "signature": signature,
            "details": self.details,
            "allowed_signers": attacker_policy,
            "trusted_allowed_signers_sha256": hashlib.sha256(
                self.allowed.read_bytes()
            ).hexdigest(),
            "output": self.root / "attacker-output.json",
        })
        with self.assertRaisesRegex(MODULE.IntakeError, "externally trusted SHA-256"):
            MODULE.authenticate(args)

    def test_symlink_inputs_and_existing_output_are_rejected(self) -> None:
        observation = self.write_observation()
        signature = self.sign(observation)
        link = self.root / "observation-link.json"
        link.symlink_to(observation)
        with self.assertRaisesRegex(MODULE.IntakeError, "symlink"):
            self.authenticate(link, signature)
        output = self.root / "exists.json"
        output.write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.IntakeError, "already exists"):
            self.authenticate(observation, signature, output=output)
        self.assertEqual(output.read_text(), "preserve")

    def test_normalization_is_deterministic_and_never_qualifies(self) -> None:
        source = self.write_observation(canonical=False)
        output = self.root / "normalized.json"
        args = type("Args", (), {"input": source, "output": output})
        report = MODULE.normalize(args)
        self.assertTrue(report["normalized"])
        self.assertEqual(output.read_bytes(), MODULE.canonical(self.value))
        self.assertNotIn(b"qualified", output.read_bytes())


if __name__ == "__main__":
    unittest.main()
