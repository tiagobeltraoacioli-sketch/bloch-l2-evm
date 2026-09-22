#!/usr/bin/env python3
"""Validate the offline, fail-closed Bloch L2 production-node bind gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = [
    "chain-identity",
    "production-genesis",
    "execution-domain",
    "p2p-policy",
    "checkpoint-policy",
    "source-derivation-policy",
    "settlement-policy",
    "finality-policy",
]
TOP_FIELDS = {
    "schema", "network", "chainId", "requirements", "productionReady", "bind"
}
REQUIREMENT_FIELDS = {"id", "satisfied", "artifact", "sha256"}
BIND_FIELDS = {"enabled", "rpcListen", "p2pListen"}


class NodeProductionError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NodeProductionError(message)


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise NodeProductionError(f"cannot read {path}: {error}") from error


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def validate_artifact(record: dict[str, Any], evidence_root: Path) -> None:
    requirement_id = record["id"]
    satisfied = record["satisfied"]
    artifact = record["artifact"]
    digest = record["sha256"]
    require(type(satisfied) is bool, f"{requirement_id} satisfied must be boolean")
    if not satisfied:
        require(artifact is None and digest is None,
                f"{requirement_id} pending evidence must be null")
        return

    require(type(artifact) is str and len(artifact) >= 3,
            f"{requirement_id} artifact is invalid")
    relative_path = Path(artifact)
    require(not relative_path.is_absolute() and ".." not in relative_path.parts,
            f"{requirement_id} artifact must be repository-relative")
    repository_root = evidence_root.resolve()
    artifact_path = (repository_root / relative_path).resolve()
    require(artifact_path.is_relative_to(repository_root) and artifact_path.is_file(),
            f"{requirement_id} artifact does not exist in the repository")
    require(type(digest) is str and len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest),
            f"{requirement_id} sha256 is invalid")
    actual_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    require(actual_digest == digest,
            f"{requirement_id} sha256 does not match its artifact")


def validate(value: Any, evidence_root: Path = ROOT) -> dict[str, Any]:
    manifest = exact_object(value, TOP_FIELDS, "node production manifest")
    require(manifest["schema"] == "bloch.l2.node-production-readiness.v1",
            "unsupported node production schema")
    require(manifest["network"] == "bloch-l2-testnet", "unexpected network")
    require(type(manifest["chainId"]) is int and manifest["chainId"] == 700_771,
            "production node chainId must be 700771")

    requirements = manifest["requirements"]
    require(type(requirements) is list and len(requirements) == len(REQUIREMENTS),
            "node requirements have the wrong length")
    ids: list[str] = []
    satisfied: list[bool] = []
    for item in requirements:
        record = exact_object(item, REQUIREMENT_FIELDS, "node requirement")
        require(type(record["id"]) is str, "node requirement id is invalid")
        ids.append(record["id"])
        validate_artifact(record, evidence_root)
        satisfied.append(record["satisfied"])
    require(ids == REQUIREMENTS,
            "node requirements are missing, duplicated or reordered")

    ready = all(satisfied)
    require(type(manifest["productionReady"]) is bool
            and manifest["productionReady"] == ready,
            "productionReady must equal the conjunction of all node requirements")

    bind = exact_object(manifest["bind"], BIND_FIELDS, "bind policy")
    require(type(bind["enabled"]) is bool, "bind enabled must be boolean")
    require(bind["enabled"] == ready,
            "bind enabled must equal production readiness")
    if bind["enabled"]:
        for field in ("rpcListen", "p2pListen"):
            endpoint = bind[field]
            require(type(endpoint) is str and endpoint.strip() == endpoint
                    and len(endpoint) >= 3 and ":" in endpoint,
                    f"enabled bind {field} must be an explicit host:port")
    else:
        require(bind["rpcListen"] is None and bind["p2pListen"] is None,
                "disabled bind endpoints must be null")

    return {
        "chainId": manifest["chainId"],
        "requirementsSatisfied": sum(satisfied),
        "requirementsTotal": len(satisfied),
        "productionReady": ready,
        "bindPermitted": bind["enabled"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "network" / "node-production.json"
    )
    parser.add_argument("--require-bind-permitted", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(load(args.manifest))
        if args.require_bind_permitted and not report["bindPermitted"]:
            raise NodeProductionError("production node bind is not permitted")
    except NodeProductionError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
