#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Qualify a locally selected Reth artifact chain with actual SP1 proofs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "integrations/sp1-execution/host/target/release"
MIB = 1024 * 1024
MAX_CHAIN_BYTES = 128 * MIB


def snapshot(source, destination, limit):
    """Copy a bounded regular input; final symlinks and special files fail closed."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(source, flags)
    with os.fdopen(descriptor, "rb") as incoming:
        before = os.fstat(incoming.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise RuntimeError(f"Input is not a nonempty bounded regular file: {source}")
        digest = hashlib.sha256()
        total = 0
        with destination.open("xb") as outgoing:
            os.chmod(destination, 0o600)
            while chunk := incoming.read(min(MIB, limit + 1 - total)):
                total += len(chunk)
                if total > limit:
                    raise RuntimeError(f"Input grew beyond its byte limit: {source}")
                digest.update(chunk)
                outgoing.write(chunk)
            after = os.fstat(incoming.fileno())
            if total != before.st_size or (before.st_size, before.st_mtime_ns) != (
                after.st_size, after.st_mtime_ns
            ):
                raise RuntimeError(f"Input changed during snapshot: {source}")
            outgoing.flush()
            os.fsync(outgoing.fileno())
    return {"file": destination.name, "bytes": total, "sha256": digest.hexdigest()}


def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def proof_record(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 32 * MIB:
            raise RuntimeError(f"Generated proof exceeds its regular-file byte bound: {path}")
        digest = hashlib.sha256()
        total = 0
        while chunk := stream.read(min(MIB, 32 * MIB + 1 - total)):
            total += len(chunk)
            if total > 32 * MIB:
                raise RuntimeError(f"Generated proof grew beyond its byte bound: {path}")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if total != before.st_size or (before.st_size, before.st_mtime_ns) != (
            after.st_size, after.st_mtime_ns
        ):
            raise RuntimeError(f"Generated proof changed during inspection: {path}")
    return {"file": path.name, "bytes": total, "sha256": digest.hexdigest()}


def run_step(output, label, command, steps):
    log = output / f"{label}.log"
    print(f"{label}: running; log {log}", flush=True)
    started = time.monotonic()
    environment = os.environ.copy()
    environment.setdefault("RAYON_NUM_THREADS", "2")
    with log.open("x") as stream:
        result = subprocess.run(
            [str(value) for value in command],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=environment,
            check=False,
        )
        stream.flush()
        os.fsync(stream.fileno())
    elapsed = time.monotonic() - started
    steps.append({
        "step": label,
        "command": [str(value) for value in command],
        "elapsed_seconds": elapsed,
        "exit_code": result.returncode,
        "log": log.name,
    })
    if result.returncode:
        raise RuntimeError(f"{label} failed with exit {result.returncode}; inspect {log}")
    print(f"{label}: passed in {elapsed:.3f}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prove", "verify"))
    parser.add_argument("--chain-dir", type=Path, required=True,
                        help="Independently selected block-N.json (and .proof for verify)")
    parser.add_argument("--elf", type=Path, required=True, help="Independently trusted pinned guest ELF")
    parser.add_argument("--output", type=Path, required=True, help="New output directory; never overwritten")
    parser.add_argument("--blocks", type=int, default=3, choices=range(1, 17), metavar="1..16")
    parser.add_argument("--artifact-bin", type=Path, default=HOST / "bloch-evm-sp1-artifact")
    parser.add_argument("--chain-bin", type=Path, default=HOST / "bloch-evm-sp1-chain")
    args = parser.parse_args()
    for executable in (args.artifact_bin, args.chain_bin):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError(f"Build the documented node-artifact binaries first: {executable}")
    if not args.output.parent.is_dir():
        raise RuntimeError("Output parent must already exist")
    # mkdir atomically refuses existing paths, including dangling symlinks.
    args.output.mkdir(mode=0o700)
    output = args.output.resolve()
    artifact_bin = args.artifact_bin.resolve()
    chain_bin = args.chain_bin.resolve()
    elf = output / "trusted-guest.elf"
    inputs = [snapshot(args.elf, elf, 128 * MIB)]
    pairs = []
    chain_bytes = 0
    proofs = []
    for height in range(1, args.blocks + 1):
        artifact = output / f"block-{height}.json"
        proof = output / f"block-{height}.proof"
        record = snapshot(args.chain_dir / artifact.name, artifact, 64 * MIB)
        inputs.append(record)
        chain_bytes += record["bytes"]
        if args.mode == "verify":
            record = snapshot(args.chain_dir / proof.name, proof, 32 * MIB)
            inputs.append(record)
            proofs.append(record)
            chain_bytes += record["bytes"]
        if chain_bytes > MAX_CHAIN_BYTES:
            raise RuntimeError("Selected chain exceeds the CLI's 128 MiB aggregate byte bound")
        pairs.extend((artifact, proof))
    sync_directory(output)
    print("SYNTHETIC/LOCAL ONLY: independently selected inputs; no native funding or finality authority.", flush=True)
    steps = []
    for index in range(args.blocks):
        artifact, proof = pairs[index * 2:index * 2 + 2]
        if args.mode == "prove":
            run_step(output, f"execute-{index + 1}", [artifact_bin, "execute", artifact, elf], steps)
        run_step(output, f"{args.mode}-{index + 1}", [artifact_bin, args.mode, artifact, elf, proof], steps)
        if args.mode == "prove":
            record = proof_record(proof)
            proofs.append(record)
            chain_bytes += record["bytes"]
            if chain_bytes > MAX_CHAIN_BYTES:
                raise RuntimeError("Generated chain exceeds 128 MiB; no further proofs will be generated")
    journal = output / "settlement.journal"
    run_step(output, "settle-chain", [chain_bin, "settle", elf, journal, *pairs], steps)
    run_step(output, "reopen-chain", [chain_bin, "verify", elf, journal, *pairs], steps)
    report = {
        "format": "BLOCH:LOCAL:PROOF-CHAIN-REHEARSAL:1",
        "status": "passed",
        "scope": "local synthetic execution and proof-backed recovery; no native source authority",
        "mode": args.mode,
        "blocks": args.blocks,
        "inputs": inputs,
        "proofs": proofs,
        "chain_bytes": chain_bytes,
        "steps": steps,
    }
    with (output / "report.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(output)
    print(f"Proof chain and separate-process recovery passed: {output / 'report.json'}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f"Rehearsal failed: {error}", file=sys.stderr)
        sys.exit(1)
