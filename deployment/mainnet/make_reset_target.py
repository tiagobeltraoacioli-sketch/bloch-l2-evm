#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Produce the `reset.json` that arms `ROLLBACK_HEAD_RESET` (and `HEAD_RESET`) for
an emergency L2 program rollback. Closes tabletop finding G-6 (169): the head-reset
needs the last-honest block N's accepted V3 statement AND its settlement commitment,
and nothing else emits them in a form `arm.py` can take.

The follower settlement log (`<stem>.settlements.jsonl`) holds the commitment and the
L1 block that carried the settlement, but NOT the 766-byte statement; `reset_head`
(`l2_settlement.rs`) never checks the commitment against the statement, so a wrong
`reset.json` silently freezes the L2. This tool is therefore deliberately strict:

  * it reads block N from TWO independent followers and requires every field equal;
  * it fetches the L1 block that carried N's settlement, decodes the 0x13
    settlement transaction, and extracts the statement from it;
  * it RECOMPUTES the native settlement commitment
    (SHA3-256 over the two native domains, proof policy, statement and proof)
    and requires it to equal the commitment BOTH followers logged for N;
  * it checks the statement is V3, names L2 block N, and carries the pinned
    network identities (admission domain, native genesis, L2 domain) and the
    active program's configuration/ELF/keys.

Only then does it write `{"number": N, "commitment": "<64 hex>", "statement": "<hex>"}`,
exactly the shape `arm.py --head-reset` consumes. Number 0 (L2 genesis) is written
as a zero commitment and a null statement without any L1 lookup.

The tool is read-only: it signs nothing, touches no key, and starts no process.

usage:
  make_reset_target.py --number N
      --follower-status PATH --follower-status PATH        (>= 2, independent hosts)
      [--l1-rpc URL ...]                                   (to fetch the L1 block)
      [--l1-block-hex FILE]                                (offline: raw L1 block, hex)
      [--expect-program-config HEX] [--expect-program-elf HEX]
      [--out reset.json]
"""
import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

# Native settlement statement V3 (l2_settlement.rs).
STATEMENT_V3_TAG = b'BLOCH:EVM:SETTLEMENT:3'
S = len(b'BLOCH:EVM:SETTLEMENT:2')  # 22; both tags share this length
STATEMENT_V3_BYTES = 766
PROOF_BYTES = 356
ASYNC_WIRE_TAG = 0x13
TRANSACTION_V3_BYTES = 1 + 32 + STATEMENT_V3_BYTES + PROOF_BYTES  # 1155

# Transaction::commitment() domains (l2_settlement.rs::Transaction::commitment / hash()).
COMMIT_D1 = b'BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-COMMITMENT:1'
COMMIT_D2 = b'BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-TX:1'

# V3 field offsets after the tag (l2_settlement.rs, mirrored here).
OFF_L2_NUMBER = 264     # u64 BE
OFF_CONFIG = 64         # identities[3] (configuration), 32 bytes
OFF_ELF = 96            # identities[4] (ELF keccak), 32 bytes


def die(msg):
    sys.exit(f'make_reset_target.py: REFUSED: {msg}')


def settlement_commitment(proof_policy, statement, proof):
    """Recompute Transaction::commitment() for a settlement transaction."""
    h = hashlib.sha3_256()
    for part in (COMMIT_D1, COMMIT_D2, proof_policy, statement, proof):
        h.update(part)
    return h.digest()


def decode_settlement_tx(raw):
    """(proof_policy, statement, proof) of a 0x13 V3 settlement transaction, or None."""
    if len(raw) != TRANSACTION_V3_BYTES or raw[0] != ASYNC_WIRE_TAG:
        return None
    proof_policy = raw[1:33]
    statement = raw[33:33 + STATEMENT_V3_BYTES]
    proof = raw[33 + STATEMENT_V3_BYTES:]
    if not statement.startswith(STATEMENT_V3_TAG):
        return None
    return proof_policy, statement, proof


def statement_l2_number(statement):
    return int.from_bytes(statement[S + OFF_L2_NUMBER:S + OFF_L2_NUMBER + 8], 'big')


def find_settlement(block_txs_hex, number):
    """From an L1 block's transactions (hex strings), the 0x13 settlement whose
    statement names L2 block `number`. Returns (proof_policy, statement, proof)."""
    for tx_hex in block_txs_hex:
        try:
            raw = bytes.fromhex(tx_hex.removeprefix('0x'))
        except ValueError:
            continue
        decoded = decode_settlement_tx(raw)
        if decoded and statement_l2_number(decoded[1]) == number:
            return decoded
    return None


def load_follower(path, number):
    """The logged settlement of L2 block `number` from a follower status file and its
    `.settlements.jsonl` log (schema v2 inlines the settlements; v3 points at the log)."""
    status = json.loads(Path(path).read_text())
    entries = []
    recent = status.get('finalized_settlements')
    if isinstance(recent, list):
        entries = recent
    log = status.get('settlement_log') or {}
    log_name = log.get('file')
    if log_name and '/' not in log_name:
        log_path = Path(path).with_name(log_name)
        if log_path.exists():
            entries = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    for e in status.get('finalized_settlements_recent', []) or []:
        if all(x.get('l2_number') != e.get('l2_number') for x in entries):
            entries.append(e)
    for e in entries:
        if e.get('l2_number') == number:
            return e
    die(f'follower {path} has no finalized settlement for L2 block {number}')


def agree(a, b, field, path_b):
    if a.get(field) != b.get(field):
        die(f'followers disagree on {field} for the block: {a.get(field)} vs {b.get(field)} ({path_b})')


def rpc(url, method, *params, timeout=30):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    req = urllib.request.Request(url, body, {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        reply = json.loads(resp.read())
    if 'error' in reply:
        raise RuntimeError(f'{method}: {reply["error"]}')
    return reply['result']


def l1_block_txs(urls, block_hash, slot):
    """Transactions (hex) of the L1 block that carried the settlement, from any
    endpoint that agrees. Tries by hash then by slot."""
    last = None
    for url in urls:
        for method, arg in (('getblockbyhash', block_hash), ('getblockbyslot', slot)):
            if arg is None:
                continue
            try:
                block = rpc(url, method, arg)
            except Exception as error:  # noqa: BLE001 - try the next endpoint
                last = f'{url} {method}: {error}'
                continue
            txs = block.get('transactions') or block.get('txs')
            if txs:
                return [t if isinstance(t, str) else t.get('raw', '') for t in txs]
            last = f'{url} {method}: no transactions'
    die(f'could not fetch the L1 settlement block from any endpoint ({last})')


def build(number, followers, block_txs_hex=None, expect_config=None, expect_elf=None):
    """Pure core: validate and return the reset.json dict. `followers` is a list of
    the per-block log entries (>= 2). `block_txs_hex` is the L1 block's transactions."""
    if number == 0:
        return {'number': 0, 'commitment': '0' * 64, 'statement': None}
    if len(followers) < 2:
        die('give at least two independent --follower-status files')
    first = followers[0]
    for other in followers[1:]:
        for field in ('l2_number', 'l2_hash', 'l2_state_root', 'commitment', 'configuration', 'native_block', 'native_slot'):
            agree(first, other, field, 'second follower')
    commitment_hex = first.get('commitment')
    if not commitment_hex or len(commitment_hex) != 64:
        die('follower log has no 64-hex commitment for the block')
    if block_txs_hex is None:
        die('no L1 block transactions given (use --l1-rpc or --l1-block-hex)')
    found = find_settlement(block_txs_hex, number)
    if not found:
        die(f'no 0x13 V3 settlement of L2 block {number} in the given L1 block')
    proof_policy, statement, proof = found
    recomputed = settlement_commitment(proof_policy, statement, proof).hex()
    if recomputed != commitment_hex:
        die(f'recomputed settlement commitment {recomputed} != the commitment both followers logged {commitment_hex}: '
            'the L1 block does not carry the settlement the followers finalized')
    if statement_l2_number(statement) != number:
        die('statement does not name L2 block {}'.format(number))
    config_in_stmt = statement[S + OFF_CONFIG:S + OFF_CONFIG + 32].hex()
    elf_in_stmt = statement[S + OFF_ELF:S + OFF_ELF + 32].hex()
    if expect_config and config_in_stmt != expect_config:
        die(f'statement configuration {config_in_stmt} != expected active program {expect_config}')
    if expect_elf and elf_in_stmt != expect_elf:
        die(f'statement ELF keccak {elf_in_stmt} != expected active program {expect_elf}')
    return {'number': number, 'commitment': commitment_hex, 'statement': statement.hex()}


def main():
    a = argparse.ArgumentParser()
    a.add_argument('--number', required=True, type=int, help='N, the last block to keep')
    a.add_argument('--follower-status', action='append', default=[], help='follower status file (>= 2 for N > 0)')
    a.add_argument('--l1-rpc', action='append', default=[], help='L1 RPC URL to fetch the settlement block')
    a.add_argument('--l1-block-hex', type=Path, help='offline: a file with one L1 transaction hex per line')
    a.add_argument('--expect-program-config', help='active program configuration (identities[3]) to require')
    a.add_argument('--expect-program-elf', help='active program ELF keccak (identities[4]) to require')
    a.add_argument('--out', type=Path, help='write reset.json here (default: stdout)')
    o = a.parse_args()

    followers = []
    block_txs = None
    if o.number != 0:
        if len(o.follower_status) < 2:
            die('N > 0 needs at least two --follower-status files')
        followers = [load_follower(p, o.number) for p in o.follower_status]
        if o.l1_block_hex:
            block_txs = [line.strip() for line in o.l1_block_hex.read_text().splitlines() if line.strip()]
        elif o.l1_rpc:
            block_txs = l1_block_txs(o.l1_rpc, followers[0].get('native_block'), followers[0].get('native_slot'))
        else:
            die('give --l1-rpc or --l1-block-hex so the statement can be recovered')

    reset = build(o.number, followers, block_txs, o.expect_program_config, o.expect_program_elf)
    out = json.dumps(reset, indent=1, sort_keys=True)
    if o.out:
        o.out.write_text(out + '\n')
        print(f'wrote {o.out} for L2 block {o.number}', file=sys.stderr)
    print(out)


if __name__ == '__main__':
    main()
