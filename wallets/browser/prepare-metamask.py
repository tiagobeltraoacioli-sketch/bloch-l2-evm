#!/usr/bin/env python3
"""Fetch and verify the pinned official test extension; never use personal profiles."""
import hashlib
from pathlib import Path
import urllib.request
import zipfile

VERSION = "13.48.0"
URL = f"https://github.com/MetaMask/metamask-extension/releases/download/v{VERSION}/metamask-chrome-{VERSION}.zip"
# Published GitHub release asset digest, also checked against the downloaded bytes.
SHA256 = "d95e4c23001ed7485ccdc86c879b4e944806ababdf52e0fc578e277131e48cea"
cache = Path(__file__).parent / ".cache"
cache.mkdir(exist_ok=True)
archive = cache / f"metamask-chrome-{VERSION}.zip"
if not archive.exists():
    urllib.request.urlretrieve(URL, archive)
assert hashlib.sha256(archive.read_bytes()).hexdigest() == SHA256, "MetaMask archive checksum mismatch"
destination = cache / f"metamask-{VERSION}"
if not destination.exists():
    destination.mkdir()
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            target = (destination / member.filename).resolve()
            assert target.is_relative_to(destination.resolve()), "archive path escapes destination"
        package.extractall(destination)
print(destination.resolve())
