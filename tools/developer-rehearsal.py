#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run signed contract deployment/call through the real durable operator CLI."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integrations/escrow-journal/Cargo.toml"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command, expected_code=0):
    result = subprocess.run(
        [str(part) for part in command], cwd=ROOT, capture_output=True, text=True
    )
    require(
        result.returncode == expected_code,
        f"{command[0]} exited {result.returncode}, expected {expected_code}:\n"
        f"{result.stderr}\n{result.stdout}",
    )
    return result.stdout


def read_json(path):
    return json.loads(path.read_text())


def write_new_json(path, value):
    # Each retained head has its own file; never silently replace a prior mark.
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def build(offline):
    command = [
        "cargo", "+1.94.1", "build", "--locked", "--manifest-path", MANIFEST,
        "--bin", "bloch-domain", "--example", "developer_fixture",
        "--message-format=json",
    ]
    if offline:
        command.append("--offline")
    print("Building the pinned operator and fixture generator...", flush=True)
    output = run(command)
    artifacts = {}
    for line in output.splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact" and message.get("executable"):
            artifacts[message["target"]["name"]] = Path(message["executable"])
    require(
        {"bloch-domain", "developer_fixture"} <= artifacts.keys(),
        "Cargo did not report both executable artifacts",
    )
    return artifacts


def rehearse(directory, offline):
    require(not directory.exists() and not directory.is_symlink(), "Use a new output directory")
    require(directory.parent.is_dir(), "Output parent directory must already exist")
    artifacts = build(offline)
    print(run([artifacts["developer_fixture"], directory]), end="", flush=True)
    expected = read_json(directory / "expected.json")
    config = directory / "config.json"
    journal = directory / "journal"
    trust = directory / "trust"
    minimum = directory / "minimum-head.json"

    def cli(command, head=None, proposal=None, expected_code=0):
        args = [artifacts["bloch-domain"], command, config, journal]
        if command != "init":
            args.extend([head, trust])
        if proposal is not None:
            args.append(proposal)
        output = run(args, expected_code)
        return json.loads(output) if expected_code == 0 else None

    initial = cli("init")
    require(initial["head"] == read_json(minimum), "Initial watermark differs from the journal")
    require(initial["head"]["blocks"] == 0, "Journal did not start empty")
    first = directory / "proposals/00000000000000000001.json"
    tampered = read_json(first)
    tampered["witness"]["new_state_root"] = "0x" + "00" * 32
    bad_proposal = directory / "tampered-proposal.json"
    write_new_json(bad_proposal, tampered)
    cli("apply", minimum, bad_proposal, expected_code=1)
    require(cli("status", minimum) == initial, "Rejected witness changed the journal")

    last = initial
    for number in (1, 2):
        proposal = directory / f"proposals/{number:020}.json"
        last = cli("apply", minimum, proposal)
        require(last["head"]["blocks"] == number, "Unexpected accepted block count")
        require(last["next_block"] == number + 1, "Unexpected execution cursor")
        require(last["state_root"] == expected["block_roots"][number - 1], "Block root differs from host")
        minimum = directory / f"head-after-{number}.json"
        write_new_json(minimum, last["head"])
        recovered = cli("status", minimum)
        for key in ("head", "state_root", "next_block", "next_deposit", "history_usage"):
            require(recovered[key] == last[key], f"Restart changed {key}")
        cli("apply", minimum, proposal, expected_code=1)
        require(cli("status", minimum) == recovered, "Replay changed recovered state")
        print(f"Block {number}: committed, reopened, replay rejected", flush=True)

    for key in ("state_root", "next_block", "next_deposit"):
        require(last[key] == expected[key], f"Final {key} disagrees with host execution")
    require(last["history_usage"]["records"] == 2, "Unexpected retained record count")
    report = {
        "version": 1,
        "synthetic": True,
        "final_head": last["head"],
        "state_root": last["state_root"],
        "next_block": last["next_block"],
        "next_deposit": last["next_deposit"],
        "checks": ["signed_deploy", "signed_call", "verified_recovery", "forged_root_rejected", "replay_rejected"],
    }
    write_new_json(directory / "rehearsal-report.json", report)
    print(f"PASS: synthetic local developer workflow; report: {directory / 'rehearsal-report.json'}")
    print("No network finality or settlement was established. Keep real funds out of these fixtures.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="new artifact directory (must not exist)")
    parser.add_argument("--offline", action="store_true", help="use cached Cargo dependencies only")
    args = parser.parse_args()
    # Preserve a final symlink so it can be rejected, rather than resolve through it.
    directory = Path(os.path.abspath(args.directory))
    try:
        rehearse(directory, args.offline)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"Developer rehearsal failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
