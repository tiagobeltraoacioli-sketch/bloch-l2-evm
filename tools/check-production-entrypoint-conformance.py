#!/usr/bin/env python3
"""Run the non-authorizing synthetic conformance harness for a future entrypoint."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"[0-9a-f]{64}")
PLAN_FIELDS = {
    "schema", "network", "chainId", "classification", "contract", "fixture",
    "effect", "mayQualifyProduction", "permissions",
}
REFERENCE_FIELDS = {"artifact", "sha256"}
FIXTURE_FIELDS = {"schema", "classification", "chainId", "observations"}
OBSERVATION_FIELDS = {
    "capabilityId", "adapterId", "subjectKind", "acceptanceExercised", "result",
    "productionEvidence",
}
PERMISSION_FIELDS = {"build", "start", "bindRpc", "bindP2p", "publishFinalized"}


class ConformanceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConformanceError(f"cannot read {label}: {error}") from error


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
        raise ConformanceError(f"cannot stat {label}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not resolved.is_symlink(),
            f"{label} must be a regular non-symlink file")
    require(metadata.st_size <= 1024 * 1024, f"{label} is too large")
    return resolved


def referenced_json(reference: Any, root: Path, label: str) -> Any:
    record = exact_object(reference, REFERENCE_FIELDS, label)
    require(type(record["sha256"]) is str and HEX64.fullmatch(record["sha256"]) is not None,
            f"{label} sha256 is invalid")
    path = repository_file(root, record["artifact"], label)
    require(hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"],
            f"{label} sha256 does not match its artifact")
    return load_json(path, label)


def contract_validator() -> Any:
    path = ROOT / "tools/check-production-entrypoint-contract.py"
    spec = importlib.util.spec_from_file_location("production_entrypoint_contract", path)
    require(spec is not None and spec.loader is not None, "cannot load contract validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate(plan: Any, root: Path = ROOT) -> dict[str, Any]:
    value = exact_object(plan, PLAN_FIELDS, "entrypoint conformance plan")
    require(value["schema"] == "bloch.l2.entrypoint-conformance-plan.v1",
            "unsupported conformance plan schema")
    require(value["network"] == "bloch-l2-testnet", "unexpected conformance network")
    require(type(value["chainId"]) is int and value["chainId"] == 700_771,
            "conformance chainId must be 700771")
    require(value["classification"] == "synthetic-adapter-plan-non-authorizing",
            "conformance plan must remain explicitly synthetic")
    require(value["effect"] == "rehearsal-only" and value["mayQualifyProduction"] is False,
            "synthetic conformance may not qualify production")
    permissions = exact_object(value["permissions"], PERMISSION_FIELDS, "permissions")
    require(all(permission is False for permission in permissions.values()),
            "synthetic conformance cannot open a permission")

    contract = referenced_json(value["contract"], root, "capability contract")
    validator = contract_validator()
    try:
        contract_report = validator.validate(contract)
    except validator.EntrypointContractError as error:
        raise ConformanceError(str(error)) from error
    fixture = exact_object(
        referenced_json(value["fixture"], root, "synthetic fixture"),
        FIXTURE_FIELDS,
        "synthetic fixture",
    )
    require(fixture["schema"] == "bloch.l2.entrypoint-conformance-fixture.v1",
            "unsupported synthetic fixture schema")
    require(fixture["classification"] == "synthetic-process-observations-non-authorizing",
            "fixture must remain explicitly synthetic")
    require(fixture["chainId"] == 700_771, "fixture chainId must be 700771")
    observations = fixture["observations"]
    capabilities = contract["capabilities"]
    require(type(observations) is list and len(observations) == len(capabilities),
            "fixture must cover every capability exactly once")
    passes = 0
    for observation, capability in zip(observations, capabilities):
        record = exact_object(observation, OBSERVATION_FIELDS, "synthetic observation")
        capability_id = capability["id"]
        require(record["capabilityId"] == capability_id,
                "synthetic observations are missing, duplicated or reordered")
        require(record["adapterId"] == f"{capability_id}-synthetic-adapter-v1",
                f"unexpected adapter for {capability_id}")
        require(record["subjectKind"] == "synthetic-process-double",
                f"{capability_id} subject must remain a synthetic process double")
        require(record["acceptanceExercised"] == capability["acceptance"],
                f"{capability_id} fixture does not cover the exact acceptance contract")
        require(record["result"] in {"pass", "fail", "inconclusive"},
                f"{capability_id} result is invalid")
        require(record["productionEvidence"] is False,
                f"synthetic observation cannot be production evidence: {capability_id}")
        passes += record["result"] == "pass"
    return {
        "chainId": 700_771,
        "syntheticChecksPassed": passes,
        "syntheticChecksTotal": len(observations),
        "contractCapabilitiesRequired": contract_report["capabilitiesRequired"],
        "productionCapabilitiesQualified": 0,
        "productionQualified": False,
        "permissionsOpened": False,
        "sideEffects": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--plan", type=Path,
        default=ROOT / "deployment/production-entrypoint-conformance.json",
    )
    parser.add_argument("--require-production-qualified", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(load_json(args.plan, "conformance plan"))
        if args.require_production_qualified:
            raise ConformanceError("synthetic conformance cannot qualify production")
    except ConformanceError as error:
        print(json.dumps({"ok": False, "error": str(error), "sideEffects": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
