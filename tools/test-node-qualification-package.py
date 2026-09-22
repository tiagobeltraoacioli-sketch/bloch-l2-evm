#!/usr/bin/env python3
"""Adversarial tests for portable node qualification packages."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "node_qualification_package", ROOT / "tools/node-qualification-package.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REVISION = "1" * 40


class NodeQualificationPackageTest(unittest.TestCase):
    def build(self, directory: str) -> Path:
        output = Path(directory) / "qualification.zip"
        MODULE.write_package(output, MODULE.package_contents(ROOT, REVISION))
        return output

    @staticmethod
    def rewrite(package: Path, mutate) -> None:
        with zipfile.ZipFile(package, "r") as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        mutate(files)
        package.unlink()
        MODULE.write_package(package, files)

    def test_checked_in_state_builds_reproducibly_and_stays_closed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = self.build(first)
            two = self.build(second)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            report = MODULE.verify_package(one)
            self.assertEqual(report["sourceRevision"], REVISION)
            self.assertEqual(report["filesVerified"], 4)
            self.assertFalse(report["identityProductionReady"])
            self.assertFalse(report["finality"]["productionFinalityReady"])
            self.assertFalse(report["node"]["bindPermitted"])
            self.assertFalse(report["activationPermitted"])

    def test_revision_must_be_exact_lowercase_git_sha(self) -> None:
        for revision in ("abc", "A" * 40, "0" * 64):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(MODULE.PackageError, "source revision"):
                    MODULE.package_contents(ROOT, revision)

    def test_tampered_file_is_rejected_by_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.build(directory)
            self.rewrite(package, lambda files: files.__setitem__(
                "network/identity.json", files["network/identity.json"] + b"\n"
            ))
            with self.assertRaisesRegex(MODULE.PackageError, "(?:size|digest) mismatch"):
                MODULE.verify_package(package)

    def test_unlisted_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.build(directory)
            self.rewrite(package, lambda files: files.__setitem__("notes.txt", b"extra"))
            with self.assertRaisesRegex(MODULE.PackageError, "unlisted files"):
                MODULE.verify_package(package)

    def test_symlink_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "qualification.zip"
            files = MODULE.package_contents(ROOT, REVISION)
            with zipfile.ZipFile(package, "w") as archive:
                for name, data in files.items():
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (
                        (stat.S_IFLNK | 0o777) if name == "network/identity.json"
                        else (stat.S_IFREG | 0o644)
                    ) << 16
                    archive.writestr(info, data)
            with self.assertRaisesRegex(MODULE.PackageError, "regular file"):
                MODULE.verify_package(package)

    def test_report_cannot_claim_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.build(directory)

            def mutate(files):
                manifest = json.loads(files[MODULE.MANIFEST_NAME])
                manifest["report"]["activationPermitted"] = True
                files[MODULE.MANIFEST_NAME] = MODULE.canonical_json(manifest)

            self.rewrite(package, mutate)
            with self.assertRaisesRegex(MODULE.PackageError, "report does not match"):
                MODULE.verify_package(package)

    def test_secret_material_and_path_escape_are_rejected(self) -> None:
        for payload in (
            b"-----BEGIN PRIVATE KEY-----",
            b'{"privateKey": "0123456789abcdef"}',
            b"mnemonic=one-two-three-four",
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(MODULE.PackageError, "secret material"):
                    MODULE.assert_secret_free("evidence.txt", payload)
        for path in ("../evidence.json", "network\\evidence.json"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(MODULE.PackageError, "unsafe package path"):
                    MODULE.safe_relative_path(path)

    def test_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.build(directory)
            before = package.read_bytes()
            with self.assertRaisesRegex(MODULE.PackageError, "refusing to overwrite"):
                MODULE.write_package(package, MODULE.package_contents(ROOT, REVISION))
            self.assertEqual(package.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
