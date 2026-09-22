#!/usr/bin/env python3
"""Validate the fail-closed production entrypoint capability contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOP_FIELDS = {
    "schema", "network", "chainId", "classification", "entrypoint",
    "capabilities", "permissions", "productionReady",
}
ENTRYPOINT_FIELDS = {
    "binary", "image", "arguments", "serviceUser", "dataDirectory", "genesisArtifact",
}
CAPABILITY_FIELDS = {"id", "required", "acceptance", "status", "evidence", "sha256"}
PERMISSION_FIELDS = {"build", "start", "bindRpc", "bindP2p", "publishFinalized"}
ACCEPTANCE = {
    "p2p-networking": [
        "authenticated-peer-identity", "chain-domain-separation",
        "fork-choice-input-validation",
    ],
    "authenticated-native-l1-derivation": [
        "authenticated-native-checkpoint", "raw-header-ancestry",
        "deposit-source-conservation",
    ],
    "production-consensus": [
        "deterministic-block-production", "fork-choice-policy", "reorganization-policy",
    ],
    "finalized-head": [
        "non-regressing-finalized-above-genesis", "canonical-finalized-reread",
        "settlement-bound-finality",
    ],
    "frozen-genesis": [
        "exact-genesis-bytes-sha256", "reviewed-genesis-state-root", "chain-id-700771",
    ],
    "gated-json-rpc": [
        "readiness-gated-bind", "chain-id-700771", "safe-finalized-tag-semantics",
        "bounded-method-policy",
    ],
    "durable-persistence": [
        "canonical-head-durability", "state-root-durability", "receipt-durability",
        "settlement-cursor-durability",
    ],
    "graceful-shutdown": [
        "stop-transaction-admission", "drain-pending-writes", "close-storage",
        "restart-integrity-check",
    ],
    "crash-recovery": [
        "interrupted-write-detection", "deterministic-replay-or-rollback",
        "no-unreviewed-auto-repair", "qualified-fault-matrix",
    ],
}


class EntrypointContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EntrypointContractError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EntrypointContractError(f"cannot read entrypoint contract: {error}") from error


def validate(value: Any) -> dict[str, Any]:
    contract = exact_object(value, TOP_FIELDS, "production entrypoint contract")
    require(contract["schema"] == "bloch.l2.production-entrypoint-contract.v1",
            "unsupported production entrypoint contract schema")
    require(contract["network"] == "bloch-l2-testnet", "unexpected entrypoint network")
    require(type(contract["chainId"]) is int and contract["chainId"] == 700_771,
            "entrypoint chainId must be 700771")
    require(contract["classification"] == "required-interface-non-authorizing",
            "entrypoint contract must remain non-authorizing")

    entrypoint = exact_object(contract["entrypoint"], ENTRYPOINT_FIELDS, "entrypoint")
    require(entrypoint["arguments"] == [], "missing entrypoint cannot declare arguments")
    for field in ENTRYPOINT_FIELDS - {"arguments"}:
        require(entrypoint[field] is None, f"missing entrypoint {field} must be null")

    capabilities = contract["capabilities"]
    require(type(capabilities) is list and len(capabilities) == len(ACCEPTANCE),
            "capability list has the wrong length")
    ids: list[str] = []
    for item in capabilities:
        capability = exact_object(item, CAPABILITY_FIELDS, "capability")
        capability_id = capability["id"]
        require(type(capability_id) is str and capability_id in ACCEPTANCE,
                "unknown production capability")
        ids.append(capability_id)
        require(capability["required"] is True, f"{capability_id} must remain required")
        require(capability["acceptance"] == ACCEPTANCE[capability_id],
                f"{capability_id} acceptance contract changed")
        require(capability["status"] == "missing"
                and capability["evidence"] is None and capability["sha256"] is None,
                f"unimplemented capability must remain missing: {capability_id}")
    require(ids == list(ACCEPTANCE), "capabilities are missing, duplicated or reordered")

    permissions = exact_object(contract["permissions"], PERMISSION_FIELDS, "permissions")
    require(all(permission is False for permission in permissions.values()),
            "incomplete entrypoint cannot hold a production permission")
    require(contract["productionReady"] is False,
            "constraints-only entrypoint cannot be production ready")
    return {
        "chainId": 700_771,
        "capabilitiesSatisfied": 0,
        "capabilitiesRequired": len(ACCEPTANCE),
        "entrypointDefined": False,
        "productionReady": False,
        "permissionsOpened": False,
        "sideEffects": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--contract", type=Path,
        default=ROOT / "deployment/production-entrypoint-contract.json",
    )
    parser.add_argument("--require-production-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(load(args.contract))
        if args.require_production_ready:
            raise EntrypointContractError("production entrypoint is not ready")
    except EntrypointContractError as error:
        print(json.dumps({"ok": False, "error": str(error), "sideEffects": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
