#!/usr/bin/env python3
"""Probe an L2 RPC without treating a genesis-only tag as finality evidence.

This tool is diagnostic. Its output cannot open any product permission; the
reviewed evidence gate in network/finality.json remains authoritative.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
HASH = "0x" + "0" * 64
MAX_ANCESTRY_BLOCKS = 4096
MAX_TRANSCRIPT_BYTES = 4 * 1024 * 1024
TRANSCRIPT_SCHEMA = "bloch.l2.finalized-rpc-transcript.v1"


class RpcProbeError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RpcProbeError(message)


def parse_quantity(value: Any, field: str) -> int:
    require(
        isinstance(value, str)
        and value.startswith("0x")
        and 2 < len(value) <= 66
        and value == value.lower(),
        f"{field} must be a lowercase JSON-RPC quantity",
    )
    digits = value[2:]
    require(all(character in "0123456789abcdef" for character in digits), f"{field} is not hexadecimal")
    require(digits == "0" or not digits.startswith("0"), f"{field} is not minimally encoded")
    return int(digits, 16)


def block(value: Any, field: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{field} block is unavailable")
    number = parse_quantity(value.get("number"), f"{field}.number")
    block_hash = value.get("hash")
    parent_hash = value.get("parentHash")
    for name, candidate in [("hash", block_hash), ("parentHash", parent_hash)]:
        require(
            isinstance(candidate, str)
            and len(candidate) == 66
            and candidate.startswith("0x")
            and candidate == candidate.lower()
            and all(character in "0123456789abcdef" for character in candidate[2:]),
            f"{field}.{name} is not a canonical hash",
        )
    require(block_hash != HASH, f"{field}.hash is zero")
    require(block_hash != parent_hash, f"{field}.hash is its own parent")
    require(number == 0 or parent_hash != HASH, f"{field}.parentHash is zero above genesis")
    return {"number": number, "hash": block_hash, "parentHash": parent_hash}


def rpc_url(value: str) -> str:
    parsed = urlsplit(value)
    require(parsed.scheme in {"http", "https"}, "RPC URL must use http or https")
    require(bool(parsed.hostname), "RPC URL must include a host")
    require(parsed.username is None and parsed.password is None, "RPC URL must not contain credentials")
    require(not parsed.fragment, "RPC URL must not contain a fragment")
    return value


def http_caller(url: str, timeout: float) -> Callable[[str, list[Any]], Any]:
    sequence = 0

    def call(method: str, params: list[Any]) -> Any:
        nonlocal sequence
        sequence += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": sequence, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "bloch-l2-finality-probe/1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                require(response.status == 200, f"RPC returned HTTP {response.status}")
                require(
                    response.headers.get_content_type() == "application/json",
                    "RPC response is not JSON",
                )
                payload = response.read(1_048_577)
        except (OSError, urllib.error.URLError) as error:
            raise RpcProbeError(f"RPC request failed: {error}") from error
        require(len(payload) <= 1_048_576, "RPC response exceeds one MiB")
        decoded = decode_json(payload, "RPC response")
        require(isinstance(decoded, dict), "RPC response must be an object")
        require(decoded.get("jsonrpc") == "2.0", "RPC response has wrong protocol version")
        require(type(decoded.get("id")) is int and decoded["id"] == sequence,
                "RPC response has mismatched id")
        require("error" not in decoded, "RPC returned an error")
        require(
            set(decoded) == {"jsonrpc", "id", "result"},
            "RPC response has unexpected fields",
        )
        return decoded["result"]

    return call


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value



def decode_json(raw: bytes | str, label: str) -> Any:
    def reject_constant(_: str) -> Any:
        raise RpcProbeError(f"non-finite JSON constant in {label}")

    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except RpcProbeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        # Do not echo hostile payloads or let parser resource limits become a traceback.
        raise RpcProbeError(f"invalid or excessively complex JSON in {label}") from error

def validate_genesis_hash(value: str | None) -> str | None:
    if value is not None:
        block({"number": "0x0", "hash": value, "parentHash": HASH}, "expectedGenesis")
    return value


def probe(call: Callable[[str, list[Any]], Any], expected_chain_id: int,
          expected_genesis_hash: str | None = None,
          max_ancestry_blocks: int = 128) -> dict[str, Any]:
    """Check two source observations and their bounded header relationships.

    Hash linkage is an RPC consistency check, not header hashing, authenticated
    consensus, settlement inclusion, availability, or a proof of finality.
    """
    require(type(expected_chain_id) is int and expected_chain_id > 0,
            "expected chain id must be positive")
    validate_genesis_hash(expected_genesis_hash)
    require(type(max_ancestry_blocks) is int
            and 1 <= max_ancestry_blocks <= MAX_ANCESTRY_BLOCKS,
            f"ancestry budget must be between 1 and {MAX_ANCESTRY_BLOCKS}")
    ancestry_reads = 0
    header_identities: dict[str, tuple[int, str]] = {}

    def observed_block(value: Any, label: str) -> dict[str, Any]:
        header = block(value, label)
        identity = (header["number"], header["parentHash"])
        previous = header_identities.setdefault(header["hash"], identity)
        require(previous == identity, f"{label} reuses a block hash with contradictory header fields")
        return header

    def by_number(number: int, label: str) -> dict[str, Any]:
        value = observed_block(call("eth_getBlockByNumber", [hex(number), False]), label)
        require(value["number"] == number, f"{label} returned the wrong block number")
        return value

    def descend(upper: dict[str, Any], lower: dict[str, Any], label: str,
                waypoint: dict[str, Any] | None = None) -> None:
        nonlocal ancestry_reads
        require(upper["number"] >= lower["number"], f"{label} regressed")
        current = upper
        while True:
            if waypoint is not None and current["number"] == waypoint["number"]:
                require(current == waypoint, f"{label} safe tag is on a different branch")
            if current["number"] == lower["number"]:
                require(current == lower, f"{label} does not descend from finalized block")
                return
            require(ancestry_reads < max_ancestry_blocks,
                    "ancestry budget exhausted; narrow the observed gap or raise the explicit budget")
            ancestry_reads += 1
            parent = by_number(current["number"] - 1, label + ".ancestor")
            require(current["parentHash"] == parent["hash"],
                    f"{label} parent hash does not match its ancestor")
            current = parent

    snapshots = []
    for index in range(2):
        chain_id = parse_quantity(call("eth_chainId", []), "chainId")
        require(chain_id == expected_chain_id,
                f"wrong chain id: expected {expected_chain_id}, observed {chain_id}")
        genesis = by_number(0, "genesis")
        require(genesis["parentHash"] == HASH, "genesis parent hash must be zero")
        require(expected_genesis_hash is None or genesis["hash"] == expected_genesis_hash,
                "genesis hash differs from externally selected pin")
        latest = observed_block(call("eth_getBlockByNumber", ["latest", False]), "latest")
        safe = observed_block(call("eth_getBlockByNumber", ["safe", False]), "safe")
        finalized = observed_block(call("eth_getBlockByNumber", ["finalized", False]), "finalized")
        require(finalized["number"] > 0, "finalized tag points only to genesis")
        require(finalized["hash"] != genesis["hash"], "finalized tag reuses genesis hash")
        require(safe["number"] >= finalized["number"], "safe block precedes finalized block")
        require(latest["number"] >= safe["number"], "latest block precedes safe block")
        require(by_number(finalized["number"], "canonicalFinalized") == finalized,
                "finalized block changed when reread by number")
        descend(latest, finalized, "tag ancestry", waypoint=safe)
        snapshot = {"genesis": genesis, "latest": latest, "safe": safe, "finalized": finalized}
        if index:
            previous = snapshots[-1]
            require(genesis == previous["genesis"], "genesis changed between observations")
            descend(finalized, previous["finalized"], "finalized ancestry")
            require(by_number(previous["finalized"]["number"], "previousFinalized")
                    == previous["finalized"], "previous finalized block changed on reread")
        snapshots.append(snapshot)

    return {
        "chainId": expected_chain_id, **snapshots[-1],
        "observations": snapshots,
        "canonicalReread": True, "tagAncestryConsistent": True,
        "finalizedNonRegressing": True, "observationCount": len(snapshots),
        "finalizedProgressObserved": snapshots[-1]["finalized"]["number"]
            > snapshots[0]["finalized"]["number"],
        "ancestryBlocksRead": ancestry_reads, "ancestryBudget": max_ancestry_blocks,
        "genesisPinned": expected_genesis_hash is not None,
        "diagnosticOnly": True, "qualified": False, "permissionsOpened": False,
    }


class Recorder:
    """Retain only the header fields examined; never endpoint URLs or credentials."""

    def __init__(self, call: Callable[[str, list[Any]], Any]):
        self.call = call
        self.observations: list[dict[str, Any]] = []

    def __call__(self, method: str, params: list[Any]) -> Any:
        result = self.call(method, params)
        if method == "eth_chainId":
            parse_quantity(result, "chainId")
        else:
            block(result, "recorded block")
            result = {field: result[field] for field in ("number", "hash", "parentHash")}
        self.observations.append({"method": method, "params": params, "result": result})
        return result

    def artifact(self) -> dict[str, Any]:
        return {"schema": TRANSCRIPT_SCHEMA, "diagnosticOnly": True,
                "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds").replace("+00:00", "Z"),
                "observations": self.observations}


class Replay:
    def __init__(self, value: Any):
        require(type(value) is dict and set(value) == {
            "schema", "diagnosticOnly", "recordedAt", "observations"},
            "transcript fields are invalid")
        require(value["schema"] == TRANSCRIPT_SCHEMA and value["diagnosticOnly"] is True,
                "unsupported diagnostic transcript")
        timestamp = value["recordedAt"]
        require(type(timestamp) is str, "transcript recordedAt is invalid")
        try:
            parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as error:
            raise RpcProbeError("transcript recordedAt is invalid") from error
        require(parsed.tzinfo == datetime.timezone.utc
                and parsed.isoformat(timespec="seconds").replace("+00:00", "Z") == timestamp,
                "transcript recordedAt must use canonical UTC seconds")
        observations = value["observations"]
        require(type(observations) is list and 1 <= len(observations) <= MAX_ANCESTRY_BLOCKS + 13,
                "transcript observation count is invalid")
        self.observations = observations
        self.position = 0

    def __call__(self, method: str, params: list[Any]) -> Any:
        require(self.position < len(self.observations), "transcript ended before probe completed")
        record = self.observations[self.position]
        self.position += 1
        require(type(record) is dict and set(record) == {"method", "params", "result"},
                "transcript observation fields are invalid")
        require(type(record["params"]) is list and len(record["params"]) == len(params)
                and all(type(actual) is type(expected) and actual == expected
                        for actual, expected in zip(record["params"], params))
                and record["method"] == method,
                "transcript request differs from required probe sequence")
        result = record["result"]
        if method == "eth_getBlockByNumber":
            require(type(result) is dict and set(result) == {"number", "hash", "parentHash"},
                    "transcript header fields are invalid")
        return result

    def finish(self) -> None:
        require(self.position == len(self.observations), "transcript contains unused observations")


def read_transcript(path: Path) -> tuple[Any, str]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            require(stat.S_ISREG(metadata.st_mode), "transcript must be a regular file")
            require(metadata.st_size <= MAX_TRANSCRIPT_BYTES, "transcript exceeds four MiB")
            raw = source.read(MAX_TRANSCRIPT_BYTES + 1)
        require(len(raw) <= MAX_TRANSCRIPT_BYTES, "transcript exceeds four MiB")
        return decode_json(raw, "transcript"), hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RpcProbeError(f"cannot read transcript: {error}") from error


def write_transcript(path: Path, value: Any) -> str:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    require(len(raw) <= MAX_TRANSCRIPT_BYTES, "transcript exceeds four MiB")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
    except OSError as error:
        raise RpcProbeError(f"cannot create new transcript: {error}") from error
    return hashlib.sha256(raw).hexdigest()


def load_chain_id(path: Path) -> int:
    try:
        value = decode_json(path.read_text(encoding="utf-8"), "identity")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RpcProbeError(f"cannot load identity: {error}") from error
    require(
        isinstance(value, dict) and type(value.get("chainId")) is int,
        "identity chainId is missing",
    )
    require(value["chainId"] > 0, "identity chainId must be positive")
    return value["chainId"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--rpc-url")
    source.add_argument("--transcript", type=Path, help="Replay retained observations without RPC")
    parser.add_argument("--capture-output", type=Path, help="Create a new diagnostic transcript")
    parser.add_argument("--genesis-hash", help="Externally selected frozen genesis hash")
    parser.add_argument("--max-ancestry-blocks", type=int, default=128)
    parser.add_argument("--identity", type=Path, default=ROOT / "network" / "identity.json")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        require(0 < args.timeout <= 30, "timeout must be between zero and 30 seconds")
        require(args.transcript is None or args.capture_output is None,
                "capture-output is only available with rpc-url")
        if args.transcript is not None:
            artifact, digest = read_transcript(args.transcript)
            call = Replay(artifact)
        else:
            call = Recorder(http_caller(rpc_url(args.rpc_url), args.timeout))
        report = probe(call, load_chain_id(args.identity), args.genesis_hash,
                       args.max_ancestry_blocks)
        if isinstance(call, Replay):
            call.finish()
            report.update({"replayedOffline": True, "transcriptSha256": digest})
        elif args.capture_output is not None:
            digest = write_transcript(args.capture_output, call.artifact())
            report.update({"transcriptSha256": digest, "transcript": str(args.capture_output)})
    except RpcProbeError as error:
        print(json.dumps({"ok": False, "error": str(error), "diagnosticOnly": True,
                          "qualified": False, "permissionsOpened": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
