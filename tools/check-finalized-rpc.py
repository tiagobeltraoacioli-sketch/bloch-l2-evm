#!/usr/bin/env python3
"""Probe an L2 RPC without treating a genesis-only tag as finality evidence.

This tool is diagnostic. Its output cannot open any product permission; the
reviewed evidence gate in network/finality.json remains authoritative.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
HASH = "0x" + "0" * 64


class RpcProbeError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RpcProbeError(message)


def parse_quantity(value: Any, field: str) -> int:
    require(
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) > 2
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
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RpcProbeError("RPC response is not valid JSON") from error
        require(isinstance(decoded, dict), "RPC response must be an object")
        require(decoded.get("jsonrpc") == "2.0", "RPC response has wrong protocol version")
        require(decoded.get("id") == sequence, "RPC response has mismatched id")
        require("error" not in decoded, "RPC returned an error")
        require(
            set(decoded) == {"jsonrpc", "id", "result"},
            "RPC response has unexpected fields",
        )
        return decoded["result"]

    return call


def probe(call: Callable[[str, list[Any]], Any], expected_chain_id: int) -> dict[str, Any]:
    chain_id = parse_quantity(call("eth_chainId", []), "chainId")
    require(
        chain_id == expected_chain_id,
        f"wrong chain id: expected {expected_chain_id}, observed {chain_id}",
    )

    genesis = block(call("eth_getBlockByNumber", ["0x0", False]), "genesis")
    require(genesis["number"] == 0, "genesis query did not return block zero")
    require(genesis["parentHash"] == HASH, "genesis parent hash must be zero")
    latest = block(call("eth_getBlockByNumber", ["latest", False]), "latest")
    safe = block(call("eth_getBlockByNumber", ["safe", False]), "safe")
    finalized = block(call("eth_getBlockByNumber", ["finalized", False]), "finalized")

    require(finalized["number"] > 0, "finalized tag points only to genesis")
    require(finalized["hash"] != genesis["hash"], "finalized tag reuses genesis hash")
    require(safe["number"] >= finalized["number"], "safe block precedes finalized block")
    require(latest["number"] >= safe["number"], "latest block precedes safe block")

    canonical = block(
        call("eth_getBlockByNumber", [hex(finalized["number"]), False]),
        "canonicalFinalized",
    )
    require(canonical == finalized, "finalized block changed when reread by number")
    return {
        "chainId": chain_id,
        "genesis": genesis,
        "latest": latest,
        "safe": safe,
        "finalized": finalized,
        "canonicalReread": True,
        "diagnosticOnly": True,
        "permissionsOpened": False,
    }


def load_chain_id(path: Path) -> int:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RpcProbeError(f"cannot load identity: {error}") from error
    require(
        isinstance(value, dict) and type(value.get("chainId")) is int,
        "identity chainId is missing",
    )
    require(value["chainId"] > 0, "identity chainId must be positive")
    return value["chainId"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--identity", type=Path, default=ROOT / "network" / "identity.json")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        require(0 < args.timeout <= 30, "timeout must be between zero and 30 seconds")
        report = probe(
            http_caller(rpc_url(args.rpc_url), args.timeout),
            load_chain_id(args.identity),
        )
    except RpcProbeError as error:
        print(json.dumps({"ok": False, "error": str(error), "permissionsOpened": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
