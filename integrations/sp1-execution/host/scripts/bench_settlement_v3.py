#!/usr/bin/env python3
"""Run the settlement V3 execution-only cycle benchmark and print a Markdown table.

usage: bench_settlement_v3.py BENCH_BINARY SETTLEMENT_V3_ELF [CONFIG ...]

CONFIG is KIND:N (KIND = transfers | calls); default: transfers 0/1/10/50/100
and calls 10. Each configuration runs in its own process, so the peak RSS the
binary reports (getrusage) belongs to that block alone. No proof is generated.
"""
import json
import platform
import subprocess
import sys
import time

DEFAULT = ['transfers:0', 'transfers:1', 'transfers:10', 'transfers:50', 'transfers:100', 'calls:10']


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    binary, elf, configs = argv[0], argv[1], argv[2:] or DEFAULT
    rows = []
    for config in configs:
        kind, n = config.split(':')
        start = time.monotonic()
        out = subprocess.run([binary, kind, n, elf], capture_output=True, text=True, check=True)
        row = json.loads(out.stdout.strip().splitlines()[-1])
        row['process_seconds'] = round(time.monotonic() - start, 1)
        rows.append(row)
        print(json.dumps(row), file=sys.stderr, flush=True)
    print(f'Host: {platform.machine()} {platform.system()} {platform.release()}, Python {platform.python_version()}\n')
    print('| Block | User txs | Block gas | Body bytes | Witness bytes | SP1 cycles | Syscalls | SP1 gas | Execute (s) | Peak RSS (MiB) |')
    print('|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    for r in rows:
        label = f"{r['kind']} N={r['n']}"
        print(f"| {label} | {r['user_txs']} | {r['block_gas_used']:,} | {r['body_bytes']:,} | {r['witness_bytes']:,} | "
              f"{r['cycles']:,} | {r['syscalls']:,} | {r['sp1_gas'] if r['sp1_gas'] is not None else '—'} | "
              f"{r['execute_seconds']:.2f} | {r['peak_rss_bytes'] / 2**20:,.0f} |")


if __name__ == '__main__':
    main(sys.argv[1:])
