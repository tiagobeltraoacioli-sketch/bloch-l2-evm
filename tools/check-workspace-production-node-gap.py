#!/usr/bin/env python3
"""Validate the workspace-wide, fail-closed production-node gap report."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TOP_FIELDS = {
    "schema", "network", "chainId", "classification", "inspectionBaselineRevision",
    "interface", "runtimeObservations", "sources", "gaps",
    "productionEntrypointCandidate", "productionReady",
}
SOURCE_FIELDS = {
    "id", "repository", "origin", "revision", "protocol", "sourceChainId",
    "compatibility", "symbols",
}
SYMBOL_FIELDS = {"path", "sha256", "names"}
GAP_FIELDS = {
    "capabilityId", "status", "nearbySourceIds", "requiredProtocol", "incompatibility",
}
INTERFACE_FIELDS = {"crate", "registeredCandidate", "files"}
FILE_FIELDS = {"path", "sha256"}
RUNTIME_FIELDS = {
    "id", "provenance", "host", "service", "binary", "arguments", "reportedChainId",
    "reportedFinalizedBlock", "binarySha256", "buildId", "classification",
    "compatibility", "effect",
}
SOURCE_IDS = [
    "bloch-l2-execution", "bloch-genesis4-l1", "bloch-l2-bridge-observer", "upstream-reth",
]


class GapReportError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GapReportError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GapReportError(f"cannot read {label}: {error}") from error


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
        raise GapReportError(f"cannot stat {label}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and not resolved.is_symlink(),
            f"{label} must be a regular non-symlink file")
    require(metadata.st_size <= 16 * 1024 * 1024, f"{label} is too large")
    return resolved


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_bytes(repository: Path, revision: str, path: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repository), "show", f"{revision}:{path}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise GapReportError(f"cannot verify workspace source {repository.name}:{path}") from error
    return result.stdout


def validate(value: Any, root: Path = ROOT, workspace_root: Path | None = None) -> dict[str, Any]:
    report = exact_object(value, TOP_FIELDS, "workspace gap report")
    require(report["schema"] == "bloch.l2.workspace-production-node-gap-report.v1",
            "unsupported workspace gap report schema")
    require(report["network"] == "bloch-l2-testnet", "unexpected gap report network")
    require(type(report["chainId"]) is int and report["chainId"] == 700_771,
            "gap report chainId must be 700771")
    require(report["classification"] == "workspace-audit-non-authorizing",
            "workspace audit must remain non-authorizing")
    require(type(report["inspectionBaselineRevision"]) is str
            and HEX40.fullmatch(report["inspectionBaselineRevision"]) is not None,
            "inspection baseline revision is invalid")

    interface = exact_object(report["interface"], INTERFACE_FIELDS, "interface")
    require(interface["crate"] == "bloch-production-entrypoint-api"
            and interface["registeredCandidate"] is False,
            "interface must not register a production candidate")
    files = interface["files"]
    require(type(files) is list and len(files) == 3, "interface file inventory is incomplete")
    for item in files:
        record = exact_object(item, FILE_FIELDS, "interface file")
        require(type(record["sha256"]) is str and HEX64.fullmatch(record["sha256"]) is not None,
                "interface file sha256 is invalid")
        require(digest_file(repository_file(root, record["path"], "interface file"))
                == record["sha256"], "interface file sha256 mismatch")

    runtime = report["runtimeObservations"]
    require(type(runtime) is list and len(runtime) == 1,
            "legacy runtime observation must be preserved exactly once")
    observation = exact_object(runtime[0], RUNTIME_FIELDS, "runtime observation")
    require(observation["id"] == "legacy-bloch-l2-devnet-8400"
            and observation["provenance"] == "orchestrator-read-only-observation"
            and observation["reportedChainId"] == 8400
            and observation["reportedChainId"] != report["chainId"],
            "legacy runtime must remain classified under incompatible chain ID 8400")
    require(observation["classification"] == "legacy-single-rpc-devnet"
            and observation["compatibility"] == "incompatible-chain-id-and-unproven-finality"
            and observation["effect"] == "observation-only",
            "legacy devnet observation cannot become production evidence")
    require(HEX64.fullmatch(observation["binarySha256"]) is not None
            and HEX40.fullmatch(observation["buildId"]) is not None,
            "legacy runtime binary identity is invalid")

    sources = report["sources"]
    require(type(sources) is list and len(sources) == len(SOURCE_IDS),
            "workspace source inventory has the wrong length")
    ids: list[str] = []
    workspace_verified = workspace_root is not None
    symbol_count = 0
    for item in sources:
        source = exact_object(item, SOURCE_FIELDS, "workspace source")
        source_id = source["id"]
        ids.append(source_id)
        require(type(source["revision"]) is str and HEX40.fullmatch(source["revision"]) is not None,
                f"{source_id} revision is invalid")
        require(source["compatibility"] in {
            "partial-l2-non-entrypoint", "l1-only", "bridge-only", "generic-ethereum-only"
        }, f"{source_id} compatibility classification is invalid")
        require(not (source["compatibility"] == "l1-only" and source["sourceChainId"] == 700_771),
                "L1 source cannot be relabelled as chain-700771 L2")
        symbols = source["symbols"]
        require(type(symbols) is list and symbols, f"{source_id} symbols are empty")
        for item_symbol in symbols:
            symbol = exact_object(item_symbol, SYMBOL_FIELDS, "source symbol")
            require(type(symbol["sha256"]) is str and HEX64.fullmatch(symbol["sha256"]) is not None,
                    f"{source_id} symbol sha256 is invalid")
            require(type(symbol["names"]) is list and symbol["names"]
                    and all(type(name) is str and name for name in symbol["names"]),
                    f"{source_id} symbol names are invalid")
            symbol_count += len(symbol["names"])
            if workspace_root is not None:
                repository = workspace_root / source["repository"]
                require(repository.is_dir(), f"workspace repository is missing: {source['repository']}")
                require(hashlib.sha256(
                    git_bytes(repository, source["revision"], symbol["path"])
                ).hexdigest() == symbol["sha256"],
                        f"workspace source digest mismatch: {source_id}:{symbol['path']}")
    require(ids == SOURCE_IDS, "workspace sources are missing, duplicated or reordered")

    contract = load_json(root / "deployment/production-entrypoint-contract.json", "capability contract")
    capability_ids = [capability["id"] for capability in contract["capabilities"]]
    gaps = report["gaps"]
    require(type(gaps) is list and len(gaps) == len(capability_ids),
            "gap list must cover every contract capability")
    gap_ids: list[str] = []
    for item in gaps:
        gap = exact_object(item, GAP_FIELDS, "capability gap")
        gap_ids.append(gap["capabilityId"])
        require(gap["status"] == "missing-compatible-implementation",
                f"capability cannot be self-qualified: {gap['capabilityId']}")
        require(type(gap["nearbySourceIds"]) is list and gap["nearbySourceIds"]
                and all(source_id in SOURCE_IDS for source_id in gap["nearbySourceIds"]),
                f"nearby sources are invalid: {gap['capabilityId']}")
        for field in ("requiredProtocol", "incompatibility"):
            require(type(gap[field]) is str and gap[field].strip() == gap[field]
                    and len(gap[field]) >= 16,
                    f"{gap['capabilityId']} {field} is not exact enough")
    require(gap_ids == capability_ids, "gaps are missing, duplicated or reordered")
    require(report["productionEntrypointCandidate"] is None and report["productionReady"] is False,
            "workspace gap report cannot nominate or approve a production entrypoint")
    return {
        "chainId": 700_771,
        "sourcesInspected": len(sources),
        "symbolsRecorded": symbol_count,
        "capabilityGaps": len(gaps),
        "compatibleCandidates": 0,
        "workspaceProvenanceVerified": workspace_verified,
        "legacyDevnetRejected": True,
        "productionReady": False,
        "sideEffects": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report", type=Path,
        default=ROOT / "deployment/workspace-production-node-gap-report.json",
    )
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--require-workspace-provenance", action="store_true")
    parser.add_argument("--require-production-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.require_workspace_provenance and args.workspace_root is None:
            raise GapReportError("workspace root is required for provenance verification")
        result = validate(load_json(args.report, "gap report"), ROOT, args.workspace_root)
        if args.require_production_ready:
            raise GapReportError("no compatible production entrypoint exists in the workspace")
    except GapReportError as error:
        print(json.dumps({"ok": False, "error": str(error), "sideEffects": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
