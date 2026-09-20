#!/usr/bin/env python3
"""Validate the selected Bloch L2 chain ID against an EVM chain registry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


IDENTITY_FIELDS = {
    "schema", "network", "chainId", "caip2", "decision", "registration", "activation"
}
DECISION_FIELDS = {"status", "selectedAt", "supersedes", "reason"}
REGISTRATION_FIELDS = {
    "registry", "path", "name", "shortName", "chain", "nativeCurrency", "status"
}
ACTIVATION_FIELDS = {
    "registered", "genesisFrozen", "finalizedRpcVerified", "clientMigrationVerified",
    "productionReady",
}
CURRENCY_FIELDS = {"name", "symbol", "decimals"}
PROPOSAL_FIELDS = {
    "name", "chain", "rpc", "faucets", "nativeCurrency", "infoURL", "shortName",
    "chainId", "networkId", "status",
}


class IdentityError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IdentityError(message)


def object_with_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IdentityError(f"cannot read {path}: {error}") from error


def validate_identity(value: Any) -> dict[str, Any]:
    identity = object_with_fields(value, IDENTITY_FIELDS, "identity")
    require(identity["schema"] == "bloch.l2.network-identity.v1", "unsupported identity schema")
    require(identity["network"] == "bloch-l2-testnet", "unexpected network name")
    require(type(identity["chainId"]) is int and identity["chainId"] == 700_771,
            "canonical candidate chainId must be 700771")
    require(identity["caip2"] == "eip155:700771", "CAIP-2 identity does not match chainId")

    decision = object_with_fields(identity["decision"], DECISION_FIELDS, "decision")
    require(decision["status"] == "selected-pending-registration",
            "decision must remain pending until public registration")
    require(decision["selectedAt"] == "2026-09-20", "unexpected decision date")
    require(decision["supersedes"] == [8400, 84001], "retired/client IDs are not explicit")
    require(type(decision["reason"]) is str and len(decision["reason"]) >= 80,
            "decision rationale is missing")

    registration = object_with_fields(
        identity["registration"], REGISTRATION_FIELDS, "registration"
    )
    require(registration["registry"] == "https://github.com/ethereum-lists/chains",
            "unexpected registry")
    require(registration["path"] == "_data/chains/eip155-700771.json",
            "registry path does not match chainId")
    require(registration["name"] == "Bloch L2 Testnet", "unexpected registered name")
    require(registration["shortName"] == "blochl2t", "unexpected short name")
    require(registration["chain"] == "BLOCH", "unexpected chain label")
    currency = object_with_fields(
        registration["nativeCurrency"], CURRENCY_FIELDS, "native currency"
    )
    require(currency == {"name": "Bridged BLCH", "symbol": "BLCH", "decimals": 18},
            "unexpected native currency")
    require(registration["status"] == "incubating", "testnet registration must be incubating")

    activation = object_with_fields(identity["activation"], ACTIVATION_FIELDS, "activation")
    require(all(type(flag) is bool for flag in activation.values()),
            "activation gates must be booleans")
    required = [
        activation["registered"], activation["genesisFrozen"],
        activation["finalizedRpcVerified"], activation["clientMigrationVerified"],
    ]
    require(activation["productionReady"] == all(required),
            "productionReady must equal the conjunction of every activation gate")
    return identity


def expected_registry_record(identity: dict[str, Any]) -> dict[str, Any]:
    registration = identity["registration"]
    return {
        "name": registration["name"],
        "shortName": registration["shortName"],
        "chain": registration["chain"],
        "chainId": identity["chainId"],
        "networkId": identity["chainId"],
        "nativeCurrency": registration["nativeCurrency"],
        "status": registration["status"],
    }


def validate_proposal(identity: dict[str, Any], value: Any) -> dict[str, Any]:
    proposal = object_with_fields(value, PROPOSAL_FIELDS, "registration proposal")
    expected = expected_registry_record(identity)
    for field, expected_value in expected.items():
        require(proposal[field] == expected_value, f"registration proposal mismatch: {field}")
    require(proposal["rpc"] == [], "RPC list must stay empty until an endpoint is qualified")
    require(proposal["faucets"] == [], "faucet list must stay empty until a faucet is qualified")
    require(proposal["infoURL"] == "https://posternlabs.com", "unexpected information URL")
    return proposal


def check_registry(identity: dict[str, Any], registry: Any) -> dict[str, Any]:
    require(type(registry) is list, "registry must be an array")
    expected = expected_registry_record(identity)
    for field in ("name", "shortName"):
        owners = [
            entry for entry in registry
            if type(entry) is dict
            and entry.get(field) == expected[field]
            and entry.get("chainId") != identity["chainId"]
        ]
        require(not owners, f"registry {field} is already owned by another chain")
    matches = [entry for entry in registry if type(entry) is dict and entry.get("chainId") == identity["chainId"]]
    require(len(matches) <= 1, "registry contains duplicate chain IDs")
    if not matches:
        return {
            "chainId": identity["chainId"],
            "availability": "available-unregistered",
            "registered": False,
            "productionReady": False,
        }

    record = matches[0]
    for field, value in expected.items():
        require(record.get(field) == value, f"chain ID collision or registration mismatch: {field}")
    return {
        "chainId": identity["chainId"],
        "availability": "registered-to-bloch",
        "registered": True,
        "productionReady": identity["activation"]["productionReady"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", type=Path, help="downloaded chainid.network chains JSON")
    parser.add_argument(
        "--identity", type=Path,
        default=Path(__file__).resolve().parents[1] / "network" / "identity.json",
    )
    parser.add_argument(
        "--proposal", type=Path,
        default=Path(__file__).resolve().parents[1] / "network" / "eip155-700771.json",
    )
    parser.add_argument("--require-registered", action="store_true")
    args = parser.parse_args(argv)
    try:
        identity = validate_identity(load_json(args.identity))
        validate_proposal(identity, load_json(args.proposal))
        report = check_registry(identity, load_json(args.registry))
        if args.require_registered and not report["registered"]:
            raise IdentityError("chain ID 700771 is not publicly registered")
    except IdentityError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
