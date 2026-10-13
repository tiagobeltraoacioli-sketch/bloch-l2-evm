#!/usr/bin/env python3
"""Validate the fail-closed Bloch L2 finality and product-permission gate."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = [
    "native-finality-replay-verified",
    "raw-header-ancestry-verified",
    "settlement-proof-transport-qualified",
    "native-settlement-consensus-active",
    "l2-settlement-inclusion-verified",
    "settlement-cursor-durable",
    "reth-finalized-tag-verified",
]
TOP_FIELDS = {
    "schema", "network", "chainId", "requirements",
    "productionFinalityReady", "permissions",
}
REQUIREMENT_FIELDS = {"id", "satisfied", "evidence"}
EVIDENCE_FIELDS = {"artifact", "sha256", "verifiedAt"}
PERMISSION_FIELDS = {"bridgeMintRelease", "dexLiquidity", "aggregatorExecution"}
ATTESTATION_FIELDS = {
    "schema", "network", "chainId", "requirementId", "classification",
    "conclusion", "reviewedAt", "support", "limitations",
}
SUPPORT_FIELDS = {"artifact", "sha256"}


class FinalityError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FinalityError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise FinalityError(f"cannot read {path}: {error}") from error


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def validate_evidence(
    value: Any, requirement_id: str, satisfied: bool, evidence_root: Path
) -> None:
    require(type(value) is list, f"{requirement_id} evidence must be an array")
    require(bool(value) == satisfied,
            f"{requirement_id} must have evidence exactly when satisfied")
    for index, item in enumerate(value):
        record = exact_object(item, EVIDENCE_FIELDS, f"{requirement_id} evidence {index}")
        require(type(record["artifact"]) is str and len(record["artifact"]) >= 8,
                f"{requirement_id} evidence artifact is invalid")
        artifact = Path(record["artifact"])
        require(not artifact.is_absolute() and ".." not in artifact.parts,
                f"{requirement_id} evidence artifact must be repository-relative")
        repository_root = evidence_root.resolve()
        artifact_path = (repository_root / artifact).resolve()
        require(artifact_path.is_relative_to(repository_root) and artifact_path.is_file(),
                f"{requirement_id} evidence artifact does not exist in the repository")
        digest = record["sha256"]
        require(type(digest) is str and len(digest) == 64
                and all(char in "0123456789abcdef" for char in digest),
                f"{requirement_id} evidence sha256 is invalid")
        actual_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        require(actual_digest == digest,
                f"{requirement_id} evidence sha256 does not match its artifact")
        verified_at = record["verifiedAt"]
        require(type(verified_at) is str, f"{requirement_id} evidence verifiedAt is invalid")
        try:
            parsed_date = datetime.date.fromisoformat(verified_at)
        except ValueError as error:
            raise FinalityError(
                f"{requirement_id} evidence verifiedAt is invalid"
            ) from error
        require(parsed_date.isoformat() == verified_at,
                f"{requirement_id} evidence verifiedAt is invalid")
        validate_attestation(
            artifact_path, artifact, requirement_id, verified_at, evidence_root
        )


def validate_attestation(
    artifact_path: Path,
    artifact: Path,
    requirement_id: str,
    verified_at: str,
    evidence_root: Path,
) -> None:
    require(
        artifact.parts[:3] == ("network", "evidence", "requirements")
        and artifact.suffix == ".json",
        f"{requirement_id} evidence must be a requirement envelope under network/evidence/requirements",
    )
    value = exact_object(load(artifact_path), ATTESTATION_FIELDS,
                         f"{requirement_id} evidence envelope")
    require(value["schema"] == "bloch.l2.finality-requirement-evidence.v1",
            f"{requirement_id} evidence schema is unsupported")
    require(value["network"] == "bloch-l2-testnet"
            and type(value["chainId"]) is int and value["chainId"] == 700_771,
            f"{requirement_id} evidence network identity is invalid")
    require(value["requirementId"] == requirement_id,
            f"{requirement_id} evidence audience is invalid")
    require(value["classification"] == "production-operational-reviewed"
            and value["conclusion"] == "satisfied",
            f"{requirement_id} evidence is not a reviewed production satisfaction")
    require(value["reviewedAt"] == verified_at,
            f"{requirement_id} evidence review date differs from the manifest")
    require(value["limitations"] == [],
            f"{requirement_id} evidence has unresolved limitations")
    support = value["support"]
    require(type(support) is list and 1 <= len(support) <= 32,
            f"{requirement_id} evidence support is invalid")
    previous: str | None = None
    repository_root = evidence_root.resolve()
    for index, item in enumerate(support):
        record = exact_object(item, SUPPORT_FIELDS,
                              f"{requirement_id} support {index}")
        support_name = record["artifact"]
        require(type(support_name) is str,
                f"{requirement_id} support path is invalid")
        support_artifact = Path(support_name)
        require(not support_artifact.is_absolute()
                and ".." not in support_artifact.parts
                and support_artifact.parts[:2] == ("network", "evidence")
                and support_artifact != artifact
                and (previous is None or previous < support_name),
                f"{requirement_id} support paths must be unique, ordered repository evidence")
        support_path = (repository_root / support_artifact).resolve()
        require(support_path.is_relative_to(repository_root) and support_path.is_file(),
                f"{requirement_id} support artifact does not exist")
        support_digest = record["sha256"]
        require(type(support_digest) is str and len(support_digest) == 64
                and all(char in "0123456789abcdef" for char in support_digest),
                f"{requirement_id} support sha256 is invalid")
        require(hashlib.sha256(support_path.read_bytes()).hexdigest() == support_digest,
                f"{requirement_id} support sha256 does not match its artifact")
        previous = support_name


def validate(finality: Any, identity: Any, evidence_root: Path = ROOT) -> dict[str, Any]:
    value = exact_object(finality, TOP_FIELDS, "finality readiness")
    require(value["schema"] == "bloch.l2.finality-readiness.v1", "unsupported finality schema")
    require(value["network"] == "bloch-l2-testnet", "unexpected finality network")
    require(type(value["chainId"]) is int and value["chainId"] == 700_771,
            "finality chainId must be 700771")

    identity = exact_object(
        identity,
        {"schema", "network", "chainId", "caip2", "decision", "registration", "activation"},
        "network identity",
    )
    require(identity["network"] == value["network"] and identity["chainId"] == value["chainId"],
            "finality and network identity differ")

    requirements = value["requirements"]
    require(type(requirements) is list and len(requirements) == len(REQUIREMENTS),
            "finality requirements have the wrong length")
    ids: list[str] = []
    satisfied: list[bool] = []
    for item in requirements:
        record = exact_object(item, REQUIREMENT_FIELDS, "finality requirement")
        require(type(record["id"]) is str, "finality requirement id is invalid")
        require(type(record["satisfied"]) is bool,
                f"{record['id']} satisfied must be boolean")
        ids.append(record["id"])
        satisfied.append(record["satisfied"])
        validate_evidence(
            record["evidence"], record["id"], record["satisfied"], evidence_root
        )
    require(ids == REQUIREMENTS, "finality requirements are missing, duplicated or reordered")

    ready = all(satisfied)
    require(type(value["productionFinalityReady"]) is bool
            and value["productionFinalityReady"] == ready,
            "productionFinalityReady must equal the conjunction of all requirements")
    activation = identity.get("activation")
    require(type(activation) is dict
            and activation.get("finalizedRpcVerified") == ready,
            "network identity finalizedRpcVerified differs from finality readiness")

    permissions = exact_object(value["permissions"], PERMISSION_FIELDS, "permissions")
    require(all(type(flag) is bool for flag in permissions.values()),
            "permissions must be booleans")
    require(ready or not any(permissions.values()),
            "product permissions cannot open before production finality")
    return {
        "chainId": value["chainId"],
        "requirementsSatisfied": sum(satisfied),
        "requirementsTotal": len(satisfied),
        "productionFinalityReady": ready,
        "permissions": permissions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--finality", type=Path, default=ROOT / "network" / "finality.json"
    )
    parser.add_argument(
        "--identity", type=Path, default=ROOT / "network" / "identity.json"
    )
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(load(args.finality), load(args.identity))
        if args.require_ready and not report["productionFinalityReady"]:
            raise FinalityError("production L2 finality is not ready")
    except FinalityError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
