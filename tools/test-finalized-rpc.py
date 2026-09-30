#!/usr/bin/env python3
"""Adversarial tests for the diagnostic finalized-RPC probe."""

from __future__ import annotations

import importlib.util
import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
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
    values = {
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
    for number in range(1, 8):
        values[("eth_getBlockByNumber", (hex(number), False))] = {
            "number": hex(number), "hash": hashed(str(number + 1)),
            "parentHash": hashed(str(number)),
        }
    return values


def caller(values: dict[tuple[str, tuple[object, ...]], object]):
    return lambda method, params: deepcopy(values[(method, tuple(params))])


def evolving_caller(first, second):
    snapshot = -1

    def call(method, params):
        nonlocal snapshot
        if method == "eth_chainId":
            snapshot += 1
        values = first if snapshot == 0 else second
        return deepcopy(values[(method, tuple(params))])
    return call


class FinalizedRpcTest(unittest.TestCase):
    def test_progressed_canonical_finality_is_diagnostic_only(self) -> None:
        report = MODULE.probe(caller(fixture()), 700771)
        self.assertEqual(report["finalized"]["number"], 2)
        self.assertTrue(report["canonicalReread"])
        self.assertTrue(report["diagnosticOnly"])
        self.assertFalse(report["permissionsOpened"])
        self.assertFalse(report["qualified"])
        self.assertFalse(report["genesisPinned"])
        self.assertFalse(report["finalizedProgressObserved"])
        self.assertEqual(report["observationCount"], 2)
        self.assertEqual(report["ancestryBlocksRead"], 4)
        self.assertTrue(report["tagAncestryConsistent"])

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


    def test_external_genesis_pin_is_checked_in_both_observations(self) -> None:
        report = MODULE.probe(caller(fixture()), 700771, hashed("1"))
        self.assertTrue(report["genesisPinned"])
        with self.assertRaisesRegex(MODULE.RpcProbeError, "externally selected pin"):
            MODULE.probe(caller(fixture()), 700771, hashed("9"))
        for invalid in [ZERO, "0x1", None, {}, True]:
            if invalid is None:
                continue
            with self.subTest(invalid=invalid), self.assertRaises(MODULE.RpcProbeError):
                MODULE.probe(caller(fixture()), 700771, invalid)

    def test_safe_tag_must_share_the_latest_to_finalized_branch(self) -> None:
        values = fixture()
        values[("eth_getBlockByNumber", ("safe", False))]["hash"] = hashed("9")
        with self.assertRaisesRegex(MODULE.RpcProbeError, "safe tag is on a different branch"):
            MODULE.probe(caller(values), 700771)

    def test_parent_hash_links_and_requested_ancestor_numbers_are_checked(self) -> None:
        for field, value, message in [
            ("parentHash", hashed("9"), "parent hash does not match"),
            ("number", "0x5", "contradictory header fields"),
        ]:
            values = fixture()
            values[("eth_getBlockByNumber", ("0x3", False))][field] = value
            # Match the tag to the ancestor so linkage is the failure being tested.
            if field == "parentHash":
                values[("eth_getBlockByNumber", ("safe", False))][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(MODULE.RpcProbeError, message):
                MODULE.probe(caller(values), 700771)

    def test_equal_height_tags_must_be_identical(self) -> None:
        values = fixture()
        head = values[("eth_getBlockByNumber", ("finalized", False))]
        values[("eth_getBlockByNumber", ("latest", False))] = deepcopy(head)
        values[("eth_getBlockByNumber", ("safe", False))] = deepcopy(head)
        report = MODULE.probe(caller(values), 700771)
        self.assertEqual(report["ancestryBlocksRead"], 0)
        values[("eth_getBlockByNumber", ("safe", False))]["hash"] = hashed("8")
        with self.assertRaisesRegex(MODULE.RpcProbeError, "different branch"):
            MODULE.probe(caller(values), 700771)

    def test_budget_is_shared_across_both_observations_and_fails_closed(self) -> None:
        calls = []
        source = caller(fixture())

        def bounded(method, params):
            calls.append((method, params))
            return source(method, params)

        with self.assertRaisesRegex(MODULE.RpcProbeError, "budget exhausted"):
            MODULE.probe(bounded, 700771, max_ancestry_blocks=3)
        self.assertEqual(len(calls), 15)
        for budget in [0, -1, 4097, True, 1.5]:
            with self.subTest(budget=budget), self.assertRaises(MODULE.RpcProbeError):
                MODULE.probe(caller(fixture()), 700771, max_ancestry_blocks=budget)

    def test_finalized_progress_is_linked_to_the_prior_finalized_block(self) -> None:
        second = fixture()
        second[("eth_getBlockByNumber", ("finalized", False))] = deepcopy(
            second[("eth_getBlockByNumber", ("0x3", False))])
        report = MODULE.probe(evolving_caller(fixture(), second), 700771)
        self.assertTrue(report["finalizedProgressObserved"])
        self.assertTrue(report["finalizedNonRegressing"])
        self.assertEqual(report["ancestryBlocksRead"], 4)

    def test_finalized_height_regression_is_rejected(self) -> None:
        second = fixture()
        second[("eth_getBlockByNumber", ("finalized", False))] = deepcopy(
            second[("eth_getBlockByNumber", ("0x1", False))])
        with self.assertRaisesRegex(MODULE.RpcProbeError, "finalized ancestry regressed"):
            MODULE.probe(evolving_caller(fixture(), second), 700771)

    def test_finalized_hash_equivocation_is_rejected(self) -> None:
        second = fixture()
        second[("eth_getBlockByNumber", ("0x2", False))]["hash"] = hashed("9")
        second[("eth_getBlockByNumber", ("finalized", False))]["hash"] = hashed("9")
        second[("eth_getBlockByNumber", ("0x3", False))]["parentHash"] = hashed("9")
        second[("eth_getBlockByNumber", ("safe", False))]["parentHash"] = hashed("9")
        for tag in ("safe", "0x3"):
            second[("eth_getBlockByNumber", (tag, False))]["hash"] = hashed("a")
        second[("eth_getBlockByNumber", ("latest", False))]["hash"] = hashed("b")
        second[("eth_getBlockByNumber", ("latest", False))]["parentHash"] = hashed("a")
        with self.assertRaisesRegex(MODULE.RpcProbeError, "finalized ancestry does not descend"):
            MODULE.probe(evolving_caller(fixture(), second), 700771)

    def test_genesis_and_chain_changes_between_observations_are_rejected(self) -> None:
        for key, changed, message in [
            (("eth_chainId", ()), "0x1", "wrong chain id"),
            (("eth_getBlockByNumber", ("0x0", False)),
             {"number": "0x0", "hash": hashed("9"), "parentHash": ZERO}, "genesis changed"),
        ]:
            second = fixture()
            second[key] = changed
            with self.subTest(message=message), self.assertRaisesRegex(MODULE.RpcProbeError, message):
                MODULE.probe(evolving_caller(fixture(), second), 700771)

    def test_record_replay_roundtrip_retains_only_examined_header_fields(self) -> None:
        values = fixture()
        for (method, _), value in values.items():
            if method == "eth_getBlockByNumber":
                value["transactions"] = ["irrelevant-private-content"]
        recorder = MODULE.Recorder(caller(values))
        report = MODULE.probe(recorder, 700771, hashed("1"))
        artifact = recorder.artifact()
        self.assertNotIn("irrelevant-private-content", json.dumps(artifact))
        replay = MODULE.Replay(artifact)
        self.assertEqual(MODULE.probe(replay, 700771, hashed("1")), report)
        replay.finish()
        self.assertFalse(report["qualified"])
        self.assertNotIn("rpcUrl", artifact)

    def recorded(self):
        recorder = MODULE.Recorder(caller(fixture()))
        MODULE.probe(recorder, 700771)
        return recorder.artifact()

    def test_replay_rejects_changed_method_params_and_injected_claims(self) -> None:
        mutations = [
            lambda value: value.update(qualified=True),
            lambda value: value.update(diagnosticOnly=False),
            lambda value: value.update(schema="other"),
            lambda value: value["observations"][0].update(method="eth_accounts"),
            lambda value: value["observations"][1].update(params=["0x0", 0]),
            lambda value: value["observations"][1]["result"].update(finalized=True),
            lambda value: value["observations"][0].update(verified=True),
            lambda value: value.update(recordedAt="2026-01-01T00:00:00+00:00"),
            lambda value: value["observations"].reverse(),
        ]
        for mutate in mutations:
            value = self.recorded()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(MODULE.RpcProbeError):
                replay = MODULE.Replay(value)
                MODULE.probe(replay, 700771)
                replay.finish()

    def test_replay_rejects_missing_and_unused_observations(self) -> None:
        missing = self.recorded()
        missing["observations"].pop()
        with self.assertRaisesRegex(MODULE.RpcProbeError, "ended before"):
            MODULE.probe(MODULE.Replay(missing), 700771)
        extra = self.recorded()
        extra["observations"].append(extra["observations"][-1])
        replay = MODULE.Replay(extra)
        MODULE.probe(replay, 700771)
        with self.assertRaisesRegex(MODULE.RpcProbeError, "unused observations"):
            replay.finish()

    def test_transcript_file_is_private_new_bounded_and_duplicate_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transcript.json"
            artifact = self.recorded()
            digest = MODULE.write_transcript(path, artifact)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(MODULE.read_transcript(path), (artifact, digest))
            with self.assertRaisesRegex(MODULE.RpcProbeError, "cannot create new transcript"):
                MODULE.write_transcript(path, {})
            self.assertEqual(MODULE.read_transcript(path)[0], artifact)
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaisesRegex(MODULE.RpcProbeError, "duplicate JSON key"):
                MODULE.read_transcript(path)
            path.write_bytes(b"x" * (MODULE.MAX_TRANSCRIPT_BYTES + 1))
            with self.assertRaisesRegex(MODULE.RpcProbeError, "exceeds four MiB"):
                MODULE.read_transcript(path)
            linked = Path(directory) / "linked.json"
            linked.symlink_to(path)
            with self.assertRaises(MODULE.RpcProbeError):
                MODULE.read_transcript(linked)
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(MODULE.RpcProbeError, "regular file"):
                MODULE.read_transcript(fifo)

    def test_offline_cli_replays_without_opening_a_network_connection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transcript.json"
            MODULE.write_transcript(path, self.recorded())
            output = io.StringIO()
            with mock.patch.object(MODULE.urllib.request, "urlopen", side_effect=AssertionError("network")):
                with contextlib.redirect_stdout(output):
                    result = MODULE.main(["--transcript", str(path), "--genesis-hash", hashed("1")])
            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertTrue(report["replayedOffline"])
            self.assertTrue(report["genesisPinned"])
            self.assertFalse(report["permissionsOpened"])
            self.assertFalse(report["qualified"])
            completed = subprocess.run([
                "python3", str(ROOT / "tools" / "check-finalized-rpc.py"),
                "--transcript", str(path), "--genesis-hash", hashed("9"),
            ], text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 1)
            self.assertFalse(json.loads(completed.stdout)["permissionsOpened"])

    def test_same_hash_cannot_claim_different_heights_or_parents(self) -> None:
        for field, value in [("hash", hashed("1")), ("parentHash", hashed("9"))]:
            second = fixture()
            if field == "hash":
                second[("eth_getBlockByNumber", ("latest", False))][field] = value
            else:
                # This claim changes only the parent of a retained finalized hash.
                second[("eth_getBlockByNumber", ("finalized", False))][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                MODULE.RpcProbeError, "contradictory header fields"
            ):
                MODULE.probe(evolving_caller(fixture(), second), 700771)

    def test_unfinalized_reorg_is_allowed_above_unchanged_finalized_ancestor(self) -> None:
        second = fixture()
        second[("eth_getBlockByNumber", ("latest", False))]["hash"] = hashed("a")
        second[("eth_getBlockByNumber", ("latest", False))]["parentHash"] = hashed("9")
        for tag in ("safe", "0x3"):
            second[("eth_getBlockByNumber", (tag, False))]["hash"] = hashed("9")
        report = MODULE.probe(evolving_caller(fixture(), second), 700771)
        self.assertTrue(report["finalizedNonRegressing"])
        self.assertFalse(report["finalizedProgressObserved"])
        self.assertNotEqual(report["observations"][0]["latest"], report["latest"])

    def test_self_parent_hash_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.RpcProbeError, "own parent"):
            MODULE.block({"number": "0x2", "hash": hashed("3"), "parentHash": hashed("3")}, "header")

    def test_complex_json_cli_refuses_without_traceback_or_payload_echo(self) -> None:
        for payload in ["[" * 2000 + "0" + "]" * 2000, "9" * 5000, "NaN", "{broken"]:
            with self.subTest(payload_kind=payload[:10]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "hostile.json"
                path.write_text(payload)
                result = subprocess.run([
                    "python3", str(ROOT / "tools" / "check-finalized-rpc.py"),
                    "--transcript", str(path),
                ], text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 1)
                report = json.loads(result.stdout)
                self.assertFalse(report["ok"])
                self.assertFalse(report["qualified"])
                self.assertFalse(report["permissionsOpened"])
                self.assertEqual(result.stderr, "")
                self.assertLess(len(result.stdout), 256)

    def test_transport_rejects_boolean_response_id_and_duplicate_keys(self) -> None:
        for payload, message in [
            (b'{"jsonrpc":"2.0","id":true,"result":"0xab163"}', "mismatched id"),
            (b'{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0xab163"}', "duplicate JSON key"),
        ]:
            response = mock.MagicMock()
            response.status = 200
            response.headers.get_content_type.return_value = "application/json"
            response.read.return_value = payload
            response.__enter__.return_value = response
            with mock.patch.object(MODULE.urllib.request, "urlopen", return_value=response):
                with self.subTest(payload=payload), self.assertRaisesRegex(MODULE.RpcProbeError, message):
                    MODULE.http_caller("https://example.invalid/rpc", 1)("eth_chainId", [])

    def test_uint256_quantities_are_bounded(self) -> None:
        self.assertEqual(MODULE.parse_quantity("0x" + "f" * 64, "quantity"), 2**256 - 1)
        with self.assertRaises(MODULE.RpcProbeError):
            MODULE.parse_quantity("0x" + "f" * 65, "quantity")


if __name__ == "__main__":
    unittest.main()
