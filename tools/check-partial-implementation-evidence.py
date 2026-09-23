#!/usr/bin/env python3
"""Validate non-authorizing implementation evidence for L2 qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TOP_FIELDS = {
    "schema", "network", "chainId", "classification", "baselineRevision",
    "artifacts", "capabilityAssessments", "permissions", "productionReady",
}
ARTIFACT_FIELDS = {"id", "path", "sha256", "evidenceClass", "productionQualified"}
ASSESSMENT_FIELDS = {
    "capabilityId", "status", "artifactIds", "remainingBlockers", "productionQualified",
}
EXPECTED_ARTIFACTS = [
    ("frozen-genesis-admission-contract", "deployment/frozen-genesis-admission.json", "pending-contract"),
    ("frozen-genesis-admission-verifier", "tools/check-frozen-genesis-admission.mjs", "verifier-source"),
    ("frozen-genesis-admission-tests", "tools/test-frozen-genesis-admission.mjs", "test-source"),
    ("frozen-genesis-ceremony-tool", "tools/frozen-genesis-ceremony.mjs", "ceremony-tool-source"),
    ("frozen-genesis-ceremony-tests", "tools/test-frozen-genesis-ceremony.mjs", "test-source"),
    ("frozen-genesis-ceremony-procedure", "docs/FROZEN-GENESIS-ADMISSION.md", "procedure-source"),
    ("compiled-genesis-identity-source", "examples/bloch-genesis-identity.rs", "implementation-source"),
    ("runtime-lifecycle-source", "integrations/reth-execution/src/lifecycle.rs", "implementation-source"),
    ("runtime-lifecycle-tests", "integrations/reth-execution/tests/runtime_lifecycle.rs", "test-source"),
    ("durable-supervisor-source", "integrations/reth-execution/src/supervisor.rs", "implementation-source"),
    ("durable-supervisor-tests", "integrations/reth-execution/tests/durable_supervisor.rs", "test-source"),
]
EXPECTED_CAPABILITIES = ["frozen-genesis", "durable-persistence", "graceful-shutdown", "crash-recovery"]


class PartialEvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PartialEvidenceError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == fields,
            f"{label} fields must be exactly {sorted(fields)}")
    return value


def repository_file(root: Path, relative: Any, label: str) -> Path:
    require(type(relative) is str and relative.strip() == relative and relative,
            f"{label} path is invalid")
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts,
            f"{label} must be repository-relative")
    repository = root.resolve()
    candidate = repository / path
    require(not candidate.is_symlink(), f"{label} must not be a symlink")
    resolved = candidate.resolve()
    require(resolved.is_relative_to(repository), f"{label} escapes the repository")
    try:
        metadata = resolved.lstat()
    except OSError as error:
        raise PartialEvidenceError(f"cannot stat {label}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not resolved.is_symlink(),
            f"{label} must be a regular non-symlink file")
    require(metadata.st_size <= 16 * 1024 * 1024, f"{label} is too large")
    return resolved


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PartialEvidenceError(f"cannot read {label}: {error}") from error


def validate(value: Any, root: Path = ROOT) -> dict[str, Any]:
    evidence = exact_object(value, TOP_FIELDS, "partial implementation evidence")
    require(evidence["schema"] == "bloch.l2.partial-implementation-evidence.v1",
            "unsupported partial evidence schema")
    require(evidence["network"] == "bloch-l2-testnet" and evidence["chainId"] == 700_771,
            "partial evidence targets the wrong chain")
    require(evidence["classification"] == "implementation-audit-non-authorizing",
            "partial evidence classification changed")
    require(type(evidence["baselineRevision"]) is str
            and HEX40.fullmatch(evidence["baselineRevision"]) is not None,
            "partial evidence baseline revision is invalid")

    artifacts = evidence["artifacts"]
    require(type(artifacts) is list and len(artifacts) == len(EXPECTED_ARTIFACTS),
            "partial evidence artifact inventory has the wrong length")
    artifact_ids: list[str] = []
    for item, expected in zip(artifacts, EXPECTED_ARTIFACTS):
        artifact = exact_object(item, ARTIFACT_FIELDS, "partial evidence artifact")
        artifact_id, relative, evidence_class = expected
        require((artifact["id"], artifact["path"], artifact["evidenceClass"])
                == (artifact_id, relative, evidence_class),
                "partial evidence artifact inventory changed")
        require(artifact["productionQualified"] is False,
                f"partial artifact cannot qualify production: {artifact_id}")
        require(type(artifact["sha256"]) is str and HEX64.fullmatch(artifact["sha256"]) is not None,
                f"partial artifact sha256 is invalid: {artifact_id}")
        actual = hashlib.sha256(repository_file(root, relative, "partial artifact").read_bytes()).hexdigest()
        require(actual == artifact["sha256"], f"partial artifact sha256 mismatch: {artifact_id}")
        artifact_ids.append(artifact_id)

    contract = load_json(root / "deployment/production-entrypoint-contract.json", "capability contract")
    contract_ids = [item["id"] for item in contract.get("capabilities", [])]
    assessments = evidence["capabilityAssessments"]
    require(type(assessments) is list and len(assessments) == len(EXPECTED_CAPABILITIES),
            "partial capability assessment inventory has the wrong length")
    observed_capabilities: list[str] = []
    for item in assessments:
        assessment = exact_object(item, ASSESSMENT_FIELDS, "partial capability assessment")
        capability = assessment["capabilityId"]
        observed_capabilities.append(capability)
        require(capability in contract_ids, f"unknown partial capability: {capability}")
        require(type(assessment["status"]) is str and assessment["status"].startswith("partial-implementation-"),
                f"partial capability status is invalid: {capability}")
        require(assessment["productionQualified"] is False,
                f"partial capability cannot qualify production: {capability}")
        require(type(assessment["artifactIds"]) is list and assessment["artifactIds"]
                and all(item_id in artifact_ids for item_id in assessment["artifactIds"]),
                f"partial capability artifacts are invalid: {capability}")
        require(type(assessment["remainingBlockers"]) is list and len(assessment["remainingBlockers"]) >= 2
                and all(type(blocker) is str and len(blocker) >= 24 for blocker in assessment["remainingBlockers"]),
                f"partial capability blockers are incomplete: {capability}")
    require(observed_capabilities == EXPECTED_CAPABILITIES,
            "partial capabilities are missing, duplicated or reordered")

    frozen = load_json(root / "deployment/frozen-genesis-admission.json", "frozen genesis admission")
    require(frozen.get("status") == "pending" and frozen.get("genesisAdmitted") is False,
            "frozen genesis must remain pending and non-admitted")
    require(type(frozen.get("permissions")) is dict
            and all(value is False for value in frozen["permissions"].values()),
            "frozen genesis admission permissions must remain closed")
    permissions = exact_object(
        evidence["permissions"], {"admitGenesis", "startNode", "bindRpc", "publishFinalized"},
        "partial evidence permissions",
    )
    require(all(value is False for value in permissions.values()) and evidence["productionReady"] is False,
            "partial implementation evidence cannot authorize production")
    return {
        "artifactsVerified": len(artifacts),
        "capabilitiesWithPartialImplementation": len(assessments),
        "frozenGenesisPending": True,
        "productionReady": False,
        "sideEffects": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence", type=Path,
        default=ROOT / "deployment/partial-implementation-evidence.json",
    )
    parser.add_argument("--require-production-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(load_json(args.evidence, "partial implementation evidence"), ROOT)
        if args.require_production_ready:
            raise PartialEvidenceError("partial implementation evidence is not production-ready")
    except PartialEvidenceError as error:
        print(json.dumps({"ok": False, "error": str(error), "sideEffects": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
