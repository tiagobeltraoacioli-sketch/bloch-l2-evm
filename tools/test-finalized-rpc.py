#!/usr/bin/env python3
"""Adversarial tests for the diagnostic finalized-RPC probe."""

from __future__ import annotations

import importlib.util
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "finalized_rpc", ROOT / "tools" / "check-finalized-rpc.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ZERO = "0x" + "0" * 64


def hashed(byte: str) -> str:
    return "0x" + byte * 64


def fixture() -> dict[tuple[str, tuple[object, ...]], object]:
    genesis = {"number": "0x0", "hash": hashed("1"), "parentHash": ZERO}
    finalized = {"number": "0x2", "hash": hashed("3"), "parentHash": hashed("2")}
    return {
        ("eth_chainId", ()): "0xab163",
        ("eth_getBlockByNumber", ("0x0", False)): genesis,
        ("eth_getBlockByNumber", ("latest", False)): {
            "number": "0x4", "hash": hashed("5"), "parentHash": hashed("4")
        },
        ("eth_getBlockByNumber", ("safe", False)): {
            "number": "0x3", "hash": hashed("4"), "parentHash": hashed("3")
        },
        ("eth_getBlockByNumber", ("finalized", False)): finalized,
        ("eth_getBlockByNumber", ("0x2", False)): deepcopy(finalized),
    }


def caller(values: dict[tuple[str, tuple[object, ...]], object]):
    return lambda method, params: deepcopy(values[(method, tuple(params))])


class FinalizedRpcTest(unittest.TestCase):
    def test_progressed_canonical_finality_is_diagnostic_only(self) -> None:
        report = MODULE.probe(caller(fixture()), 700771)
        self.assertEqual(report["finalized"]["number"], 2)
        self.assertTrue(report["canonicalReread"])
        self.assertTrue(report["diagnosticOnly"])
        self.assertFalse(report["permissionsOpened"])

    def test_wrong_chain_and_genesis_only_finality_are_rejected(self) -> None:
        wrong = fixture()
        wrong[("eth_chainId", ())] = "0x14821"
        with self.assertRaisesRegex(MODULE.RpcProbeError, "wrong chain id"):
            MODULE.probe(caller(wrong), 700771)

        empty = fixture()
        empty[("eth_getBlockByNumber", ("finalized", False))] = deepcopy(
            empty[("eth_getBlockByNumber", ("0x0", False))]
        )
        with self.assertRaisesRegex(MODULE.RpcProbeError, "only to genesis"):
            MODULE.probe(caller(empty), 700771)

    def test_null_malformed_and_noncanonical_blocks_are_rejected(self) -> None:
        cases = []
        missing = fixture()
        missing[("eth_getBlockByNumber", ("safe", False))] = None
        cases.append(missing)
        leading_zero = fixture()
        leading_zero[("eth_getBlockByNumber", ("latest", False))]["number"] = "0x04"
        cases.append(leading_zero)
        uppercase = fixture()
        uppercase[("eth_getBlockByNumber", ("finalized", False))]["hash"] = "0x" + "A" * 64
        cases.append(uppercase)
        for values in cases:
            with self.subTest(values=values), self.assertRaises(MODULE.RpcProbeError):
                MODULE.probe(caller(values), 700771)

    def test_ordering_and_canonical_reread_are_required(self) -> None:
        regressed = fixture()
        regressed[("eth_getBlockByNumber", ("safe", False))]["number"] = "0x1"
        with self.assertRaisesRegex(MODULE.RpcProbeError, "safe block precedes"):
            MODULE.probe(caller(regressed), 700771)

        changed = fixture()
        changed[("eth_getBlockByNumber", ("0x2", False))]["hash"] = hashed("9")
        with self.assertRaisesRegex(MODULE.RpcProbeError, "changed when reread"):
            MODULE.probe(caller(changed), 700771)

    def test_url_rejects_credentials_fragments_and_non_http_schemes(self) -> None:
        for value in [
            "file:///tmp/rpc",
            "https://user:pass@example.test",
            "https://example.test/#x",
            "",
        ]:
            with self.subTest(value=value), self.assertRaises(MODULE.RpcProbeError):
                MODULE.rpc_url(value)
        self.assertEqual(
            MODULE.rpc_url("http://127.0.0.1:8545"), "http://127.0.0.1:8545"
        )


if __name__ == "__main__":
    unittest.main()
