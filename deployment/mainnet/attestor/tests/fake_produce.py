#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test double of `bloch-l2-produce-dev` reconstruct / withdrawal-proof, driven by the JSON fixture
named in $FAKE_L2_FIXTURE: {"genesis": HEX, "chain_id": N, "native_blocks": N,
"blocks": [{"number", "hash", "state_root", "withdrawals": [{"l1_recipient", "sats"}]}]}.
Withdrawal leaves, roots and proofs are computed with attestor_lib (checked against native code by
the round-trip test)."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import attestor_lib as lib  # noqa: E402

NETWORK = ('--rules', '--domain', '--genesis-time')


def options(args):
    found, i = {}, 0
    while i < len(args):
        found[args[i]] = args[i + 1]
        i += 2
    return {k: v for k, v in found.items() if k not in NETWORK}


def fixture():
    return json.loads(Path(os.environ['FAKE_L2_FIXTURE']).read_text())


def withdrawals_up_to(f, number):
    out = []
    for block in f['blocks']:
        if block['number'] <= number:
            for w in block['withdrawals']:
                out.append({**w, 'l2_block': block['number']})
    return out


def main():
    command, o = sys.argv[1], options(sys.argv[2:])
    f = fixture()
    chain = f['chain_id']
    if command == 'reconstruct':
        if f.get('reconstruct_fails'):
            print('fixture: reconstruct fails', file=sys.stderr)
            return 1
        Path(o['--target']).mkdir()
        blocks = []
        for block in f['blocks']:
            ws = withdrawals_up_to(f, block['number'])
            leaves = [lib.leaf(chain, i, bytes.fromhex(w['l1_recipient']), w['sats']) for i, w in enumerate(ws)]
            blocks.append({'number': block['number'], 'hash': block['hash'], 'state_root': block['state_root'],
                           'withdrawal_root': lib.tree_root(leaves).hex(), 'withdrawal_count': len(leaves)})
        print(json.dumps({'genesis': f['genesis'], 'native_blocks': f['native_blocks'], 'settled': len(blocks),
                          'blocks': blocks}))
        return 0
    if command == 'withdrawal-proof':
        number, index = int(o['--number']), int(o['--index'])
        ws = withdrawals_up_to(f, number)
        leaves = [lib.leaf(chain, i, bytes.fromhex(w['l1_recipient']), w['sats']) for i, w in enumerate(ws)]
        root = lib.tree_root(leaves).hex()
        if o.get('--root') not in (None, root) or int(o.get('--count', len(leaves))) != len(leaves):
            print('settled withdrawal root / count differ', file=sys.stderr)
            return 1
        if index >= len(leaves):
            print(f'withdrawal {index} does not exist', file=sys.stderr)
            return 1
        w = ws[index]
        print(json.dumps({'chain_id': chain, 'number': number, 'withdrawal_root': root, 'withdrawal_count': len(leaves),
                          'index': index,
                          'withdrawal': {'nonce': index, 'l1_recipient': w['l1_recipient'], 'sats': w['sats'],
                                         'sender': '00' * 20, 'l2_block': w['l2_block'], 'leaf': leaves[index].hex()},
                          'siblings': [s.hex() for s in lib.tree_proof(leaves, index)]}))
        return 0
    print(f'unknown command {command}', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
