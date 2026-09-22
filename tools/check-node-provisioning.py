#!/usr/bin/env python3
"""Validate a reproducible L2 node provision plan without starting anything."""

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
MAX_GENESIS_BYTES = 16 * 1024 * 1024
TOP_FIELDS = {
    "schema", "network", "chainId", "classification", "runtime", "genesis",
    "storage", "listeners", "readiness", "startPermitted",
}
HEX64 = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"[^\s@]+@sha256:([0-9a-f]{64})")


class ProvisioningError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProvisioningError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProvisioningError(f"cannot read {label}: {error}") from error


def repository_file(root: Path, relative: Any, label: str) -> Path:
    require(type(relative) is str and relative.strip() == relative and relative,
            f"{label} path is invalid")
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts,
            f"{label} must be repository-relative")
    repository = root.resolve()
    candidate = repository / path
    require(not candidate.is_symlink(), f"{label} must be a regular non-symlink file")
    resolved = candidate.resolve()
    require(resolved.is_relative_to(repository), f"{label} escapes the repository")
    try:
        metadata = resolved.lstat()
    except OSError as error:
        raise ProvisioningError(f"cannot stat {label}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not resolved.is_symlink(),
            f"{label} must be a regular non-symlink file")
    return resolved


def sha256_file(path: Path, limit: int | None = None) -> str:
    if limit is not None:
        require(path.stat().st_size <= limit, f"{path.name} exceeds {limit} bytes")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_node_validator() -> Any:
    path = ROOT / "tools" / "check-node-production.py"
    spec = importlib.util.spec_from_file_location("node_production", path)
    require(spec is not None and spec.loader is not None,
            "cannot load node production validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate(
    manifest: Any,
    root: Path = ROOT,
    trusted_image: str | None = None,
    trusted_genesis_sha256: str | None = None,
) -> dict[str, Any]:
    value = exact_object(manifest, TOP_FIELDS, "node provisioning manifest")
    require(value["schema"] == "bloch.l2.node-provisioning.v1",
            "unsupported node provisioning schema")
    require(value["network"] == "bloch-l2-testnet", "unexpected provisioning network")
    require(type(value["chainId"]) is int and value["chainId"] == 700_771,
            "provisioning chainId must be 700771")
    require(value["classification"] in {
        "pending-non-authorizing", "reviewed-production"
    }, "invalid provisioning classification")
    if trusted_image is not None:
        require(type(trusted_image) is str and IMAGE.fullmatch(trusted_image) is not None,
                "trusted image must be a digest-pinned reference")
    if trusted_genesis_sha256 is not None:
        require(type(trusted_genesis_sha256) is str
                and HEX64.fullmatch(trusted_genesis_sha256) is not None,
                "trusted genesis sha256 is invalid")

    runtime = exact_object(value["runtime"], {"engine", "image"}, "runtime")
    require(runtime["engine"] == "docker", "runtime engine must be docker")
    image = runtime["image"]
    image_pinned = False
    image_trusted = False
    if image is not None:
        require(type(image) is str and IMAGE.fullmatch(image) is not None,
                "runtime image must be pinned by sha256 digest")
        image_pinned = True
        image_trusted = trusted_image is not None and image == trusted_image

    genesis = exact_object(value["genesis"], {"artifact", "sha256"}, "genesis")
    genesis_pinned = False
    genesis_trusted = False
    if genesis["artifact"] is None or genesis["sha256"] is None:
        require(genesis["artifact"] is None and genesis["sha256"] is None,
                "pending genesis artifact and sha256 must both be null")
    else:
        require(type(genesis["sha256"]) is str
                and HEX64.fullmatch(genesis["sha256"]) is not None,
                "genesis sha256 is invalid")
        genesis_path = repository_file(root, genesis["artifact"], "genesis artifact")
        require(sha256_file(genesis_path, MAX_GENESIS_BYTES) == genesis["sha256"],
                "genesis sha256 does not match its artifact")
        genesis_pinned = True
        genesis_trusted = (
            trusted_genesis_sha256 is not None
            and genesis["sha256"] == trusted_genesis_sha256
        )

    readiness = exact_object(value["readiness"], {"artifact", "sha256"}, "readiness")
    require(type(readiness["sha256"]) is str
            and HEX64.fullmatch(readiness["sha256"]) is not None,
            "readiness sha256 is invalid")
    readiness_path = repository_file(root, readiness["artifact"], "readiness artifact")
    require(sha256_file(readiness_path) == readiness["sha256"],
            "readiness sha256 does not match its artifact")
    node_validator = load_node_validator()
    try:
        readiness_value = load_json(readiness_path, "readiness artifact")
        node_report = node_validator.validate(readiness_value, root)
    except node_validator.NodeProductionError as error:
        raise ProvisioningError(str(error)) from error

    storage = exact_object(value["storage"], {"dataDirectory"}, "storage")
    data_directory = storage["dataDirectory"]
    storage_explicit = False
    if data_directory is not None:
        require(type(data_directory) is str and Path(data_directory).is_absolute()
                and data_directory not in {"/", "/home", "/home/ubuntu"},
                "dataDirectory must be a narrow absolute path")
        storage_explicit = True

    listeners = exact_object(value["listeners"], {"rpc", "p2p"}, "listeners")
    listeners_bound = False
    if listeners["rpc"] is None or listeners["p2p"] is None:
        require(listeners["rpc"] is None and listeners["p2p"] is None,
                "pending listeners must both be null")
    else:
        listeners_bound = (
            listeners["rpc"] == readiness_value["bind"]["rpcListen"]
            and listeners["p2p"] == readiness_value["bind"]["p2pListen"]
        )

    computed = bool(
        value["classification"] == "reviewed-production"
        and image_pinned and image_trusted
        and genesis_pinned and genesis_trusted
        and storage_explicit and listeners_bound
        and node_report["bindPermitted"]
    )
    require(type(value["startPermitted"]) is bool
            and value["startPermitted"] == computed,
            "startPermitted must equal all provisioning and readiness gates")
    return {
        "chainId": 700_771,
        "classification": value["classification"],
        "imagePinned": image_pinned,
        "imageExternallyTrusted": image_trusted,
        "genesisPinned": genesis_pinned,
        "genesisExternallyTrusted": genesis_trusted,
        "storageExplicit": storage_explicit,
        "listenersBoundToReadiness": listeners_bound,
        "nodeBindPermitted": node_report["bindPermitted"],
        "startPermitted": computed,
        "sideEffects": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "deployment/l2-node.json")
    parser.add_argument("--trusted-image")
    parser.add_argument("--trusted-genesis-sha256")
    parser.add_argument("--require-start-permitted", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(
            load_json(args.manifest, "provisioning manifest"), ROOT,
            args.trusted_image, args.trusted_genesis_sha256,
        )
        if args.require_start_permitted and not report["startPermitted"]:
            raise ProvisioningError("L2 node start is not permitted")
    except ProvisioningError as error:
        print(json.dumps({"ok": False, "error": str(error), "sideEffects": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
