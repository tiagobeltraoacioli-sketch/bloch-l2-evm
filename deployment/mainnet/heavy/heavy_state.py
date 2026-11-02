#!/usr/bin/env python3
"""Benchmark blocks over a populated storage trie: a contract filled across several blocks, then one 15M-gas block that
rewrites or reads its slots, proving the block above a real trie. Private, synthetic request, throwaway key.

  heavy_state.py NAME --fill-blocks N --mode rewrite|read|fresh
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

W = Path.home() / 'l2dexbridge-20261030/l2-heavy-r3'
sys.path.insert(0, str(W / 'tools'))
import heavy_gen as g  # noqa: E402

DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
NET = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
P = str(W / 'out/bloch-l2-produce-dev')


def runtime():
    reserve = 40_000
    head = bytes([0x5f, 0x35]) + bytes([0x60, 32, 0x35, 0x15])  # i = calldata[0]; iszero(calldata[32])
    write = bytes([0x5b, 0x80, 0x5f, 0x52, 0x60, 32, 0x5f, 0x20, 0x60, 32, 0x35, 0x90, 0x55, 0x60, 1, 0x01])
    read = bytes([0x5b, 0x80, 0x5f, 0x52, 0x60, 32, 0x5f, 0x20, 0x54, 0x50, 0x60, 1, 0x01])
    tail = lambda at: g.push(reserve) + bytes([0x5a, 0x11, 0x61]) + at.to_bytes(2, 'big') + bytes([0x57, 0x00])  # noqa: E731
    jump = lambda at: bytes([0x61]) + at.to_bytes(2, 'big') + bytes([0x57])  # noqa: E731
    write_at = len(head) + 4
    read_at = write_at + len(write) + len(tail(0))
    return head + jump(read_at) + write + tail(write_at) + read + tail(read_at)


def deployer():
    code = runtime()
    init = g.push(len(code)) + b'\x80' + bytes([0x60, len(g.push(len(code))) + 7]) + b'\x5f\x39\x5f\xf3'
    return init + code


def create_address(sender, nonce):
    return g.keccak(g.rlp([sender, nonce]))[12:]


def main():
    a = argparse.ArgumentParser()
    a.add_argument('name')
    a.add_argument('--fill-blocks', type=int, required=True)
    a.add_argument('--mode', choices=['rewrite', 'read', 'fresh'], required=True)
    a.add_argument('--gas', type=int, default=15_000_000)
    o = a.parse_args()
    d = W / 'runs' / o.name
    subprocess.run(['rm', '-rf', str(d)])
    d.mkdir(parents=True)
    key = int((W / 'throwaway.key').read_text().strip(), 16)
    sender = g.address(key)
    anchor, slot = (W / 'anchor').read_text().split()
    db = str(d / 'l2')

    def prod(*args):
        return json.loads(subprocess.run([P, *args, *NET], check=True, capture_output=True, text=True).stdout)
    prod('init', '--target', db)
    head = prod('head', '--target', db)['hash']
    (d / 'deposit.json').write_text(json.dumps([{'height': 1, 'tx_index': 1, 'txid': 'ab' * 32, 'vout': 0, 'sats': 100_000_000_000, 'recipient': sender.hex()}]))
    contract = create_address(sender, 0)
    nonce, total = 0, 0

    def block(raws, deposits=False):
        nonlocal head
        pool = d / 'pool.json'
        pool.write_text(json.dumps([r.hex() for r in raws]))
        args = ['extend', '--target', db, '--parent', head, '--anchor', anchor, '--timestamp-rule', '1:1786656679:30000', '--anchor-slot', slot,
                '--txs', str(pool), '--max-gas', '15000000', '--max-bytes', '114688', '--max-txs', '128']
        if deposits:
            args += ['--deposits', str(d / 'deposit.json')]
        b = prod(*args)
        if b['transactions'] != len(raws):
            raise SystemExit(f'block lost transactions: {json.dumps(b)[:800]}')
        head = b['hash']
        return b

    block([g.tx(key, 700770, 0, 1_000_000, b'', 0, deployer())], deposits=True)
    nonce = 1
    per_block = (15_000_000 - 60_000) // 22_300
    for i in range(o.fill_blocks):
        data = (total + 1).to_bytes(32, 'big') + (7).to_bytes(32, 'big')
        block([g.tx(key, 700770, nonce, 15_000_000, contract, 0, data)])
        nonce += 1
        total += per_block
    if o.mode == 'rewrite':
        data = (1).to_bytes(32, 'big') + (9).to_bytes(32, 'big')
    elif o.mode == 'read':
        data = (1).to_bytes(32, 'big') + bytes(32)
    else:
        data = (total + 1).to_bytes(32, 'big') + (9).to_bytes(32, 'big')
    final = block([g.tx(key, 700770, nonce, o.gas, contract, 0, data)])
    number = final['number']
    r = prod('export', '--target', db, '--number', str(number), '--out', str(d / 'block.artifact'))
    previous = 'cd' * 32
    (d / 'native-request.txt').write_text((W / 'source.txt').read_text() + previous + '\n1\n1\n1\n')
    (d / 'block.json').write_text(json.dumps(final))
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(W / 'home'), 'TMPDIR': str(W / 'home/tmp'), 'SP1_CIRCUIT_MODE': 'release',
           'BLOCH_NATIVE_L2_REQUEST': str(d / 'native-request.txt'), 'BLOCH_NATIVE_L2_ARTIFACT': str(d / 'block.artifact')}
    with (d / 'execute.log').open('w') as out:
        rc = subprocess.run([str(W / 'out/bloch-evm-sp1-settlement-v3'), '--mainnet', 'execute', 'native-artifact', str(W / 'elf/settlement_v3_mainnet')],
                            env=env, stdout=out, stderr=subprocess.STDOUT).returncode
    log = (d / 'execute.log').read_text()
    import re
    m = re.findall(r'(\d+) instructions', log)
    print(json.dumps({'name': o.name, 'mode': o.mode, 'fill_blocks': o.fill_blocks, 'slots': total, 'number': number, 'exit': rc,
                      'instructions': int(m[-1]) if m else None, 'artifact_bytes': os.path.getsize(d / 'block.artifact'),
                      'tail': '' if m else log[-400:]}))


if __name__ == '__main__':
    main()
