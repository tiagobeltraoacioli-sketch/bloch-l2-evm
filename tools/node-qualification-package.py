#!/usr/bin/env python3
"""Build and verify portable, fail-closed L2 node qualification packages."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORE_FILES = (
    "network/identity.json",
    "network/eip155-700771.json",
    "network/finality.json",
    "network/node-production.json",
    "deployment/l2-node.json",
    "deployment/production-node-build-request.json",
    "deployment/production-entrypoint-contract.json",
    "deployment/production-entrypoint-conformance.json",
)
MANIFEST_NAME = "qualification-package.json"
SCHEMA = "bloch.l2.node-qualification-package.v6"
VERIFIER_SCHEMA = "bloch.l2.node-qualification-verifier.v1"
VERIFIER_FILES = (
    "tools/node-qualification-package.py",
    "tools/check-network-identity.py",
    "tools/check-finality-readiness.py",
    "tools/check-node-production.py",
    "tools/check-node-provisioning.py",
    "tools/check-production-node-build-request.py",
    "tools/check-production-entrypoint-contract.py",
    "tools/check-production-entrypoint-conformance.py",
)
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(
        rb"(?i)(?:private[_-]?key|ssh[_-]?password|mnemonic|seed[_-]?phrase|api[_-]?token)"
        rb"[\"']?\s*[:=]\s*[\"']?(?!null\b|false\b|redacted\b)[^\s,}\"']{8,}"
    ),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
)
FORBIDDEN_BASENAMES = {
    ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials",
}


class PackageError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validator_modules() -> tuple[Any, Any, Any, Any, Any, Any, Any]:
    """Load semantic validators only after verifier provenance is checked."""
    return (
        load_module("network_identity", ROOT / "tools/check-network-identity.py"),
        load_module("finality_readiness", ROOT / "tools/check-finality-readiness.py"),
        load_module("node_production", ROOT / "tools/check-node-production.py"),
        load_module("node_provisioning", ROOT / "tools/check-node-provisioning.py"),
        load_module(
            "production_node_build_request",
            ROOT / "tools/check-production-node-build-request.py",
        ),
        load_module(
            "production_entrypoint_contract",
            ROOT / "tools/check-production-entrypoint-contract.py",
        ),
        load_module(
            "production_entrypoint_conformance",
            ROOT / "tools/check-production-entrypoint-conformance.py",
        ),
    )


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verifier_identity(root: Path = ROOT) -> dict[str, Any]:
    records = []
    for relative in VERIFIER_FILES:
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                f"verifier source is missing or not a regular file: {relative}")
        data = path.read_bytes()
        records.append({"path": relative, "sha256": digest(data), "bytes": len(data)})
    identity = {"schema": VERIFIER_SCHEMA, "files": records}
    identity["sha256"] = digest(json_bytes(identity, "verifier identity"))
    return identity


def git_file(root: Path, revision: str, relative: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), "show", f"{revision}:{relative}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise PackageError(
            f"cannot read {relative} from expected source revision {revision}"
        ) from error
    return result.stdout


def assert_files_match_revision(
    root: Path, revision: str, expected_files: dict[str, bytes]
) -> None:
    require(REVISION_PATTERN.fullmatch(revision) is not None,
            "source revision must be a lowercase 40-character git SHA")
    try:
        result = subprocess.run(
            [
                "git", "--no-replace-objects", "-C", str(root),
                "rev-parse", "--verify", f"{revision}^{{commit}}",
            ],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise PackageError(f"source revision is not a commit in checkout: {revision}") from error
    require(result.stdout.strip() == revision,
            "source revision does not resolve to the exact expected commit")
    for relative, data in expected_files.items():
        require(data == git_file(root, revision, relative),
                f"package source differs from source revision: {relative}")


def assert_checkout_provenance(
    root: Path, revision: str, packaged_files: dict[str, bytes]
) -> None:
    assert_files_match_revision(root, revision, packaged_files)
    for relative in VERIFIER_FILES:
        require((root / relative).read_bytes() == git_file(root, revision, relative),
                f"verifier source differs from source revision: {relative}")


def safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    require(
        "\\" not in value and "\x00" not in value
        and value == path.as_posix() and not path.is_absolute() and ".." not in path.parts,
        f"unsafe package path: {value}",
    )
    require(value not in ("", ".") and not value.startswith("/"), f"unsafe package path: {value}")
    return path


def assert_secret_free(path: str, data: bytes) -> None:
    relative = safe_relative_path(path)
    require(relative.name.lower() not in FORBIDDEN_BASENAMES,
            f"secret-bearing filename is forbidden: {path}")
    for pattern in SECRET_PATTERNS:
        require(pattern.search(data) is None, f"possible secret material in {path}")


def json_bytes(value: Any, label: str) -> bytes:
    try:
        return canonical_json(value)
    except (TypeError, ValueError) as error:
        raise PackageError(f"cannot encode {label}: {error}") from error


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackageError(f"cannot read {path}: {error}") from error


def referenced_files(
    finality: dict[str, Any], node: dict[str, Any], build_request: dict[str, Any],
    conformance_plan: dict[str, Any],
) -> set[str]:
    paths: set[str] = set(CORE_FILES)
    for requirement in finality.get("requirements", []):
        for evidence in requirement.get("evidence", []):
            if isinstance(evidence, dict) and isinstance(evidence.get("artifact"), str):
                paths.add(evidence["artifact"])
    for requirement in node.get("requirements", []):
        if isinstance(requirement, dict) and isinstance(requirement.get("artifact"), str):
            paths.add(requirement["artifact"])
    for item in build_request.get("auditedInputs", []):
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            paths.add(item["path"])
    for field in ("contract", "fixture"):
        reference = conformance_plan.get(field)
        if isinstance(reference, dict) and isinstance(reference.get("artifact"), str):
            paths.add(reference["artifact"])
    for path in paths:
        safe_relative_path(path)
    return paths


def validate_sources(
    root: Path,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    (
        identity_validator, finality_validator, node_validator,
        provisioning_validator, build_request_validator, entrypoint_validator,
        conformance_validator,
    ) = validator_modules()
    identity = read_json(root / CORE_FILES[0])
    proposal = read_json(root / CORE_FILES[1])
    finality = read_json(root / CORE_FILES[2])
    node = read_json(root / CORE_FILES[3])
    provisioning = read_json(root / CORE_FILES[4])
    build_request = read_json(root / CORE_FILES[5])
    entrypoint_contract = read_json(root / CORE_FILES[6])
    conformance_plan = read_json(root / CORE_FILES[7])
    try:
        identity_validator.validate_identity(identity)
        identity_validator.validate_proposal(identity, proposal)
        finality_report = finality_validator.validate(finality, identity, root)
        node_report = node_validator.validate(node, root)
        provisioning_report = provisioning_validator.validate(provisioning, root)
        build_report = build_request_validator.validate(build_request, root)
        entrypoint_report = entrypoint_validator.validate(entrypoint_contract)
        conformance_report = conformance_validator.validate(conformance_plan, root)
    except (
        identity_validator.IdentityError,
        finality_validator.FinalityError,
        node_validator.NodeProductionError,
        provisioning_validator.ProvisioningError,
        build_request_validator.BuildRequestError,
        entrypoint_validator.EntrypointContractError,
        conformance_validator.ConformanceError,
    ) as error:
        raise PackageError(str(error)) from error
    identity_ready = identity["activation"]["productionReady"]
    report = {
        "identityProductionReady": identity_ready,
        "finality": finality_report,
        "node": node_report,
        "provisioning": provisioning_report,
        "productionBuild": build_report,
        "productionEntrypoint": entrypoint_report,
        "entrypointConformance": conformance_report,
        "activationPermitted": bool(
            identity_ready
            and finality_report["productionFinalityReady"]
            and node_report["bindPermitted"]
            and provisioning_report["startPermitted"]
            and build_report["buildPermitted"]
            and entrypoint_report["productionReady"]
            and conformance_report["productionQualified"]
        ),
    }
    return finality, node, build_request, conformance_plan, report


def package_contents(root: Path, revision: str) -> dict[str, bytes]:
    require(REVISION_PATTERN.fullmatch(revision) is not None,
            "source revision must be a lowercase 40-character git SHA")
    finality, node, build_request, conformance_plan, report = validate_sources(root)
    files: dict[str, bytes] = {}
    for relative in sorted(referenced_files(finality, node, build_request, conformance_plan)):
        path = (root / relative).resolve()
        require(path.is_relative_to(root.resolve()) and path.is_file(),
                f"package source is missing: {relative}")
        require(not path.is_symlink(), f"package source must not be a symlink: {relative}")
        data = path.read_bytes()
        assert_secret_free(relative, data)
        files[relative] = data
    manifest = {
        "schema": SCHEMA,
        "network": "bloch-l2-testnet",
        "chainId": 700_771,
        "sourceRevision": revision,
        "verifier": verifier_identity(root),
        "files": [
            {"path": path, "sha256": digest(data), "bytes": len(data)}
            for path, data in files.items()
        ],
        "report": report,
    }
    files[MANIFEST_NAME] = json_bytes(manifest, "package manifest")
    return files


def package_contents_from_checkout(root: Path, revision: str) -> dict[str, bytes]:
    files = package_contents(root, revision)
    assert_checkout_provenance(
        root, revision, {name: data for name, data in files.items() if name != MANIFEST_NAME}
    )
    return files


def write_package(output: Path, files: dict[str, bytes]) -> None:
    require(not output.exists(), f"refusing to overwrite existing package: {output}")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name in sorted(files):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, files[name])
    except (OSError, zipfile.BadZipFile) as error:
        raise PackageError(f"cannot write package {output}: {error}") from error


def read_package(package: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        with zipfile.ZipFile(package, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            require(len(infos) <= 256, "package contains too many members")
            require(sum(info.file_size for info in infos) <= 64 * 1024 * 1024,
                    "package uncompressed size exceeds the limit")
            require(len(names) == len(set(names)), "package contains duplicate members")
            for info in infos:
                safe_relative_path(info.filename)
                require(not info.is_dir(), f"package directories are forbidden: {info.filename}")
                mode = info.external_attr >> 16
                require(mode == 0 or stat.S_ISREG(mode),
                        f"package member must be a regular file: {info.filename}")
                require(info.file_size <= 16 * 1024 * 1024,
                        f"package member is too large: {info.filename}")
            require(MANIFEST_NAME in names, "package manifest is missing")
            files = {name: archive.read(name) for name in names}
    except (OSError, zipfile.BadZipFile) as error:
        raise PackageError(f"cannot read package {package}: {error}") from error
    try:
        manifest = json.loads(files.pop(MANIFEST_NAME).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PackageError(f"invalid package manifest: {error}") from error
    return manifest, files


def verify_package(
    package: Path, expected_source_revision: str, trusted_verifier_sha256: str
) -> dict[str, Any]:
    manifest, files = read_package(package)
    fields = {
        "schema", "network", "chainId", "sourceRevision", "verifier", "files", "report"
    }
    require(type(manifest) is dict and set(manifest) == fields,
            "package manifest fields are not exact")
    require(manifest["schema"] == SCHEMA, "unsupported package schema")
    require(manifest["network"] == "bloch-l2-testnet", "unexpected package network")
    require(manifest["chainId"] == 700_771, "unexpected package chainId")
    require(type(manifest["sourceRevision"]) is str
            and REVISION_PATTERN.fullmatch(manifest["sourceRevision"]) is not None,
            "invalid package source revision")
    require(REVISION_PATTERN.fullmatch(expected_source_revision) is not None,
            "expected source revision must be a lowercase 40-character git SHA")
    require(manifest["sourceRevision"] == expected_source_revision,
            "package source revision does not match the externally expected revision")
    require(re.fullmatch(r"[0-9a-f]{64}", trusted_verifier_sha256) is not None,
            "trusted verifier SHA-256 must be 64 lowercase hexadecimal characters")
    local_verifier = verifier_identity(ROOT)
    require(local_verifier["sha256"] == trusted_verifier_sha256,
            "local verifier suite does not match the externally trusted SHA-256")
    require(manifest["verifier"] == local_verifier,
            "package verifier identity does not match the trusted local verifier suite")
    records = manifest["files"]
    require(type(records) is list and records, "package file inventory is empty")
    expected_names: list[str] = []
    for record in records:
        require(type(record) is dict and set(record) == {"path", "sha256", "bytes"},
                "package file record fields are not exact")
        path = record["path"]
        require(type(path) is str, "package file path is invalid")
        safe_relative_path(path)
        expected_names.append(path)
        require(path in files, f"inventoried package file is missing: {path}")
        data = files[path]
        require(type(record["bytes"]) is int and record["bytes"] == len(data),
                f"package file size mismatch: {path}")
        require(type(record["sha256"]) is str and record["sha256"] == digest(data),
                f"package file digest mismatch: {path}")
        assert_secret_free(path, data)
    require(expected_names == sorted(expected_names) and len(expected_names) == len(set(expected_names)),
            "package inventory must be sorted and unique")
    require(set(files) == set(expected_names), "package contains unlisted files")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, data in files.items():
            target = root.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        finality, node, build_request, conformance_plan, report = validate_sources(root)
        require(
            set(expected_names)
            == referenced_files(finality, node, build_request, conformance_plan),
                "package does not contain the exact evidence closure")
    require(manifest["report"] == report, "package qualification report does not match its sources")
    return {
        "sourceRevision": manifest["sourceRevision"],
        "verifierSha256": local_verifier["sha256"],
        "filesVerified": len(files),
        **report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--revision", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("package", type=Path)
    verify.add_argument("--expected-source-revision", required=True)
    verify.add_argument("--trusted-verifier-sha256", required=True)
    verify.add_argument("--require-activation-permitted", action="store_true")
    subparsers.add_parser("verifier-id")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            files = package_contents_from_checkout(ROOT, args.revision)
            write_package(args.output, files)
            report = verify_package(
                args.output, args.revision, verifier_identity(ROOT)["sha256"]
            )
            report["packageSha256"] = digest(args.output.read_bytes())
        elif args.command == "verify":
            report = verify_package(
                args.package, args.expected_source_revision, args.trusted_verifier_sha256
            )
            if args.require_activation_permitted and not report["activationPermitted"]:
                raise PackageError("node activation is not permitted by this package")
        else:
            report = verifier_identity(ROOT)
    except PackageError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
