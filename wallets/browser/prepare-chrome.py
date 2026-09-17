#!/usr/bin/env python3
"""Prepare the pinned official mac-x64 test browser without replacing installed Chrome."""
import hashlib
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request

VERSION = "153.0.8010.47"
URL = f"https://storage.googleapis.com/chrome-for-testing-public/{VERSION}/mac-x64/chrome-mac-x64.zip"
# Locally calculated from the official download; not an independent signature.
SHA256 = "7cdb5ad92cd19c3e3e25054e4c5fed7fd42b1f27d52447bdfc7b16fca870dd95"
if platform.system() != "Darwin" or platform.machine() != "x86_64":
    raise SystemExit("This pinned download is mac-x64; set CHROME to your test browser on other platforms")
cache = Path(__file__).parent / ".cache"
cache.mkdir(exist_ok=True)
archive = cache / f"chrome-mac-x64-{VERSION}.zip"
if not archive.exists():
    if "--offline" in sys.argv:
        raise SystemExit("Chrome cache missing: run prepare-chrome.py first")
    urllib.request.urlretrieve(URL, archive)
if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
    raise SystemExit("Chrome archive checksum mismatch")
destination = cache / f"chrome-{VERSION}"
if not destination.exists():
    destination.mkdir()
    # unzip preserves the executable modes and framework symlinks in this fixed,
    # checksum-verified official archive. Partial extraction is never overwritten.
    subprocess.run(["unzip", "-q", str(archive), "-d", str(destination)], check=True)
executable = destination / "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
if not executable.is_file():
    raise SystemExit("Incomplete Chrome extraction; inspect the cache instead of overwriting it")
print(executable.resolve())
