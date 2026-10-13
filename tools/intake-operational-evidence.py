#!/usr/bin/env python3
"""Normalize and authenticate observation-only Bloch L2 operational evidence."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "bloch-l2-operational-evidence-v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_DETAILS_BYTES = 1024 * 1024
REQUIREMENTS = {
    "native-finality-replay-verified", "raw-header-ancestry-verified",
    "settlement-proof-transport-qualified", "native-settlement-consensus-active",
    "l2-settlement-inclusion-verified", "settlement-cursor-durable",
    "reth-finalized-tag-verified", "chain-identity", "production-genesis",
    "execution-domain", "p2p-policy", "checkpoint-policy",
    "source-derivation-policy", "settlement-policy", "finality-policy",
}
OBSERVATION_FIELDS = {
    "schema", "network", "chainId", "requirementId", "observedAt", "observer",
    "source", "result", "detailsSha256",
}


class IntakeError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IntakeError(message)


def read_regular(path: Path, label: str, limit: int = MAX_INPUT_BYTES) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
            require(metadata.st_size <= limit, f"{label} exceeds {limit} bytes")
            content = source.read(limit + 1)
            require(len(content) <= limit, f"{label} exceeds {limit} bytes")
            return content
    except OSError as error:
        if path.is_symlink():
            raise IntakeError(f"{label} must not be a symlink") from error
        raise IntakeError(f"cannot read {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                       sort_keys=True) + "\n").encode("utf-8")


def validate_observation(value: Any) -> dict[str, Any]:
    require(type(value) is dict, "observation must be an object")
    require(set(value) == OBSERVATION_FIELDS,
            f"observation fields must be exactly {sorted(OBSERVATION_FIELDS)}")
    require(value["schema"] == "bloch.l2.operational-observation.v1",
            "unsupported observation schema")
    require(value["network"] == "bloch-l2-testnet", "unexpected observation network")
    require(type(value["chainId"]) is int and value["chainId"] == 700_771,
            "observation chainId must be 700771")
    require(value["requirementId"] in REQUIREMENTS, "unknown requirementId")
    for field in ("observer", "source"):
        text = value[field]
        require(type(text) is str and text.strip() == text and 1 <= len(text) <= 128,
                f"observation {field} is invalid")
        require(all(character.isprintable() for character in text),
                f"observation {field} is invalid")
    require(value["result"] in {"pass", "fail", "inconclusive"},
            "observation result is invalid")
    digest = value["detailsSha256"]
    require(type(digest) is str and len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest),
            "observation detailsSha256 is invalid")
    observed_at = value["observedAt"]
    require(type(observed_at) is str and observed_at.endswith("Z"),
            "observation observedAt must be RFC3339 UTC")
    try:
        parsed = datetime.datetime.fromisoformat(observed_at[:-1] + "+00:00")
    except ValueError as error:
        raise IntakeError("observation observedAt must be RFC3339 UTC") from error
    require(parsed.tzinfo == datetime.timezone.utc
            and parsed.isoformat(timespec="seconds").replace("+00:00", "Z") == observed_at,
            "observation observedAt must use second-precision canonical UTC")
    return value


def load_observation(path: Path, require_canonical: bool) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path, "observation")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntakeError(f"observation is not valid UTF-8 JSON: {error}") from error
    observation = validate_observation(value)
    normalized = canonical(observation)
    if require_canonical:
        require(raw == normalized,
                "signed observation is not canonical; run normalize before signing")
    return observation, normalized


def outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
        return False
    except ValueError:
        return True


def write_new(path: Path, content: bytes) -> None:
    require(not path.exists() and not path.is_symlink(), "output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
    except OSError as error:
        raise IntakeError(f"cannot create output: {error}") from error


def normalize(args: argparse.Namespace) -> dict[str, Any]:
    observation, normalized = load_observation(args.input, False)
    write_new(args.output, normalized)
    return {"normalized": True, "requirementId": observation["requirementId"],
            "output": str(args.output)}


def authenticated_artifact(args: argparse.Namespace) -> dict[str, Any]:
    observation, payload = load_observation(args.observation, True)
    details = read_regular(args.details, "observation details", MAX_DETAILS_BYTES)
    actual_details_digest = hashlib.sha256(details).hexdigest()
    require(actual_details_digest == observation["detailsSha256"],
            "observation details do not match detailsSha256")
    require(outside_repository(args.allowed_signers),
            "allowed-signers trust root must be outside the repository")
    trust = read_regular(args.allowed_signers, "allowed-signers trust root")
    trusted_digest = args.trusted_allowed_signers_sha256
    require(type(trusted_digest) is str and len(trusted_digest) == 64
            and all(character in "0123456789abcdef" for character in trusted_digest),
            "trusted allowed-signers SHA-256 must be 64 lowercase hexadecimal characters")
    actual_trust_digest = hashlib.sha256(trust).hexdigest()
    require(actual_trust_digest == trusted_digest,
            "allowed-signers policy does not match the externally trusted SHA-256")
    signature = read_regular(args.signature, "signature")
    require(b"BEGIN SSH SIGNATURE" in signature, "signature is not an SSH signature")
    try:
        with tempfile.TemporaryDirectory(prefix="bloch-l2-evidence-") as directory:
            snapshot = Path(directory)
            trust_snapshot = snapshot / "allowed_signers"
            signature_snapshot = snapshot / "observation.sig"
            trust_snapshot.write_bytes(trust)
            signature_snapshot.write_bytes(signature)
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", str(trust_snapshot),
                 "-I", observation["observer"], "-n", NAMESPACE,
                 "-s", str(signature_snapshot)],
                input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                timeout=10,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IntakeError(f"SSH signature verification could not run: {error}") from error
    require(result.returncode == 0, "SSH signature verification failed")
    return {
        "schema": "bloch.l2.authenticated-operational-observation.v1",
        "effect": "observation-only", "authenticated": True, "qualified": False,
        "namespace": NAMESPACE,
        "observationSha256": hashlib.sha256(payload).hexdigest(),
        "detailsSha256": actual_details_digest,
        "detailsBytes": len(details),
        "detailsBoundAtIntake": True,
        "trustRootSha256": actual_trust_digest,
        "signatureSha256": hashlib.sha256(signature).hexdigest(),
        "observation": observation,
    }


def authenticate(args: argparse.Namespace) -> dict[str, Any]:
    artifact = authenticated_artifact(args)
    write_new(args.output, canonical(artifact))
    return {"authenticated": True, "qualified": False,
            "detailsBoundAtIntake": True,
            "requirementId": artifact["observation"]["requirementId"],
            "output": str(args.output)}


def verify(args: argparse.Namespace) -> dict[str, Any]:
    expected = authenticated_artifact(args)
    raw = read_regular(args.artifact, "authenticated artifact")
    try:
        actual = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntakeError(f"authenticated artifact is not valid UTF-8 JSON: {error}") from error
    require(raw == canonical(actual), "authenticated artifact is not canonical")
    require(actual == expected, "authenticated artifact does not match verified inputs")
    return {"authenticated": True, "qualified": False, "detailsBoundAtIntake": True,
            "requirementId": expected["observation"]["requirementId"],
            "artifact": str(args.artifact)}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    normalizer = commands.add_parser("normalize")
    normalizer.add_argument("--input", type=Path, required=True)
    normalizer.add_argument("--output", type=Path, required=True)
    for command in ("authenticate", "verify"):
        verifier = commands.add_parser(command)
        verifier.add_argument("--observation", type=Path, required=True)
        verifier.add_argument("--details", type=Path, required=True)
        verifier.add_argument("--signature", type=Path, required=True)
        verifier.add_argument("--allowed-signers", type=Path, required=True)
        verifier.add_argument("--trusted-allowed-signers-sha256", required=True)
        if command == "authenticate":
            verifier.add_argument("--output", type=Path, required=True)
        else:
            verifier.add_argument("--artifact", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "normalize":
            report = normalize(args)
        elif args.command == "authenticate":
            report = authenticate(args)
        else:
            report = verify(args)
    except IntakeError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
