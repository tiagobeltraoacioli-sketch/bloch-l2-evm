#!/usr/bin/env python3
"""Fetch and verify the pinned official test extension; never use personal profiles."""
import hashlib
import sys
from pathlib import Path
import urllib.request
import zipfile


def require(condition, message):
    if not condition:
        raise SystemExit(message)

VERSION = "13.48.0"
URL = f"https://github.com/MetaMask/metamask-extension/releases/download/v{VERSION}/metamask-chrome-{VERSION}.zip"
# Published GitHub release asset digest, also checked against the downloaded bytes.
SHA256 = "d95e4c23001ed7485ccdc86c879b4e944806ababdf52e0fc578e277131e48cea"
cache = Path(__file__).parent / ".cache"
cache.mkdir(exist_ok=True)
archive = cache / f"metamask-chrome-{VERSION}.zip"
if not archive.exists():
    if "--offline" in sys.argv:
        raise SystemExit("MetaMask cache missing: run prepare-metamask.py first")
    urllib.request.urlretrieve(URL, archive)
require(hashlib.sha256(archive.read_bytes()).hexdigest() == SHA256, "MetaMask archive checksum mismatch")
destination = cache / f"metamask-{VERSION}"
if not destination.exists():
    destination.mkdir()
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            target = (destination / member.filename).resolve()
            require(target.is_relative_to(destination.resolve()), "archive path escapes destination")
        package.extractall(destination)
# Existing extracted contents must still match the pinned archive, not just its ZIP.
with zipfile.ZipFile(archive) as package:
    expected = set()
    for member in package.infolist():
        if member.is_dir():
            continue
        expected.add(member.filename)
        target = destination / member.filename
        require(target.resolve().is_relative_to(destination.resolve()) and target.is_file() and not target.is_symlink(), f"missing/invalid extension file: {member.filename}")
        require(hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(package.read(member)).digest(), f"modified extension file: {member.filename}")
    actual = {str(path.relative_to(destination)) for path in destination.rglob("*") if path.is_file()}
    require(actual == expected, "unexpected files in extracted extension")
print(destination.resolve())
