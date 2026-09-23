#!/usr/bin/env python3
"""Validate the non-authorizing request for a reproducible production-node build."""

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
    "schema", "network", "chainId", "classification", "inspectionBaselineRevision",
    "candidate", "auditedInputs", "externalReth", "requiredDecisions", "outputs",
    "buildPermitted",
}
INPUT_FIELDS = {"path", "role", "sha256"}
DECISION_FIELDS = {"id", "status", "artifact", "sha256"}
ROLES = [
    "candidate-manifest", "candidate-lockfile", "candidate-toolchain",
    "synthetic-entrypoint", "external-source-verifier", "external-source-patch",
    "production-entrypoint-contract",
    "production-entrypoint-conformance-plan",
]
DECISIONS = [
    "production-node-entrypoint", "frozen-production-genesis",
    "authenticated-native-derivation", "production-consensus-finality",
    "builder-image-digest", "runtime-image-digest", "container-build-definition",
    "complete-source-sbom", "build-provenance-policy",
]


class BuildRequestError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildRequestError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildRequestError(f"cannot read build request: {error}") from error


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
        raise BuildRequestError(f"cannot stat {label}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not resolved.is_symlink(),
            f"{label} must be a regular non-symlink file")
    require(metadata.st_size <= 16 * 1024 * 1024, f"{label} is too large")
    return resolved


def validate(value: Any, root: Path = ROOT) -> dict[str, Any]:
    request = exact_object(value, TOP_FIELDS, "production node build request")
    require(request["schema"] == "bloch.l2.production-node-build-request.v1",
            "unsupported build request schema")
    require(request["network"] == "bloch-l2-testnet", "unexpected build request network")
    require(type(request["chainId"]) is int and request["chainId"] == 700_771,
            "build request chainId must be 700771")
    require(request["classification"] == "constraints-only-non-authorizing",
            "build request must remain non-authorizing")
    require(type(request["inspectionBaselineRevision"]) is str
            and HEX40.fullmatch(request["inspectionBaselineRevision"]) is not None,
            "inspection baseline revision is invalid")

    candidate = exact_object(
        request["candidate"],
        {"package", "binary", "classification", "productionEligible"},
        "candidate",
    )
    require(candidate == {
        "package": "bloch-reth-execution",
        "binary": "bloch-evm-dev",
        "classification": "synthetic-development-only",
        "productionEligible": False,
    }, "only the synthetic, production-ineligible candidate is currently documented")

    inputs = request["auditedInputs"]
    require(type(inputs) is list and len(inputs) == len(ROLES),
            "audited input inventory has the wrong length")
    roles: list[str] = []
    paths: set[str] = set()
    resolved_inputs: dict[str, bytes] = {}
    for item in inputs:
        record = exact_object(item, INPUT_FIELDS, "audited input")
        require(type(record["role"]) is str, "audited input role is invalid")
        roles.append(record["role"])
        require(type(record["path"]) is str and record["path"] not in paths,
                "audited input paths must be unique")
        paths.add(record["path"])
        require(type(record["sha256"]) is str
                and HEX64.fullmatch(record["sha256"]) is not None,
                "audited input sha256 is invalid")
        path = repository_file(root, record["path"], "audited input")
        content = path.read_bytes()
        require(hashlib.sha256(content).hexdigest() == record["sha256"],
                f"audited input hash mismatch: {record['path']}")
        resolved_inputs[record["role"]] = content
    require(roles == ROLES, "audited input roles are missing, duplicated or reordered")

    entrypoint = resolved_inputs["synthetic-entrypoint"]
    require(b"--synthetic-dev is mandatory" in entrypoint
            and b"no P2P/L1 derivation/finality" in entrypoint,
            "candidate entrypoint no longer proves its synthetic-only boundary")

    external = exact_object(
        request["externalReth"],
        {"repository", "baseRevision", "preparedTreeVerified", "preparedTreeDigest"},
        "external Reth source",
    )
    require(external["repository"] == "https://github.com/paradigmxyz/reth",
            "unexpected external Reth repository")
    require(external["baseRevision"] == "8eb210175687c9f0c889a3b6795c16781d830e3a",
            "unexpected external Reth base revision")
    require(external["preparedTreeVerified"] is False
            and external["preparedTreeDigest"] is None,
            "portable prepared Reth tree remains unverified and must not carry a digest claim")
    require(external["baseRevision"].encode() in resolved_inputs["external-source-verifier"],
            "external source verifier does not bind the declared Reth base")

    decisions = request["requiredDecisions"]
    require(type(decisions) is list and len(decisions) == len(DECISIONS),
            "required decision list has the wrong length")
    ids: list[str] = []
    for item in decisions:
        decision = exact_object(item, DECISION_FIELDS, "required decision")
        ids.append(decision["id"])
        require(decision["status"] == "missing"
                and decision["artifact"] is None and decision["sha256"] is None,
                f"unreviewed decision must remain missing: {decision['id']}")
    require(ids == DECISIONS, "required decisions are missing, duplicated or reordered")

    outputs = exact_object(request["outputs"], {"image", "sbom", "provenance"}, "outputs")
    require(all(value is None for value in outputs.values()),
            "blocked build must not claim image, SBOM or provenance outputs")
    require(request["buildPermitted"] is False,
            "constraints request can never authorize a production build")
    return {
        "chainId": 700_771,
        "candidateProductionEligible": False,
        "auditedInputsVerified": len(inputs),
        "requiredDecisionsMissing": len(decisions),
        "preparedRethTreeVerified": False,
        "imageProduced": False,
        "sbomProduced": False,
        "provenanceProduced": False,
        "buildPermitted": False,
        "sideEffects": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--request", type=Path,
        default=ROOT / "deployment/production-node-build-request.json",
    )
    parser.add_argument("--require-build-permitted", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(load(args.request))
        if args.require_build_permitted:
            raise BuildRequestError("production node build is not permitted")
    except BuildRequestError as error:
        print(json.dumps({"ok": False, "error": str(error), "sideEffects": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
