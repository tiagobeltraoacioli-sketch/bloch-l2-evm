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
    the same status file given twice (same path, same file through a link, or the
    same bytes) is refused, and so is one settlement log read through two status files;
  * when a follower's log holds several lines for block N (N was settled again after
    an earlier reset) it takes the NEWEST line, requires it to be the one with the
    highest L1 slot, and says so; both followers must agree on that line;
  * it fetches the L1 block that carried N's settlement, decodes the 0x13
    settlement transaction, and extracts the statement from it;
  * it RECOMPUTES the native settlement commitment
    (SHA3-256 over the two native domains, proof policy, statement and proof)
    and requires it to equal the commitment BOTH followers logged for N;
  * it checks the statement is V3, names L2 block N, and carries the pinned
    network identities (admission domain, native genesis, L2 domain: the mainnet
    values built in below, or all three given by hand for a rehearsal network) and
    the program that settled N (configuration and ELF Keccak, both REQUIRED).

Only then does it write
`{"number": N, "commitment": "<64 hex>", "statement": "<hex>", "forfeit": true|false}`,
the shape `arm.py --head-reset` consumes. Number 0 (L2 genesis) is written as a zero
commitment and a null statement without any L1 lookup.

The reset form is a REQUIRED choice (`--reset-form forfeit|plain`); the tool never
defaults it, and `arm.py` reads a missing `forfeit` key as false:

  * `forfeit` is the form decided for the rollback case G2a (forged withdrawal claims
    were paid during the bad tail): the native reset forgets those paid leaves, and it
    is NOT refused by the depth of the consumed forced-record log: it requeues the
    records that log still holds (native 92762a10);
  * `plain` is refused by the native rules over paid leaves above the target, and when
    the tail consumed more forced records than the consumed log holds.

What this tool does NOT check (it has no L1 state, only one L1 block): whether the
native `reset_head` conditions hold at the gate (paid leaves above N, the depth of the
consumed forced-record log, which a forfeit reset tolerates and a plain reset does
not). It prints that as a reminder; rehearse the armed reset before relying on it.

The tool is read-only: it signs nothing, touches no key, and starts no process.

usage:
  make_reset_target.py --number N --reset-form forfeit|plain
      --follower-status PATH --follower-status PATH        (>= 2, independent hosts)
      --expect-program-config HEX --expect-program-elf HEX (the program that settled N)
      [--l1-rpc URL ...]                                   (to fetch the L1 block)
      [--l1-block-hex FILE]                                (offline: raw L1 block, hex)
      [--rehearsal-identities ADMISSION GENESIS L2DOMAIN]  (never for mainnet)
      [--out reset.json]
"""
import argparse
import hashlib
import json
import os
import re
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

# V3 field offsets after the tag (l2_settlement.rs, mirrored here). The seven
# identities sit at S + i*32: 0 admission domain, 1 native genesis, 2 L2 domain,
# 3 configuration, 4 ELF keccak, 5 KoalaBear key, 6 BN254 key.
OFF_L2_NUMBER = 264     # u64 BE
OFF_CONFIG = 96         # identities[3] (configuration), 32 bytes
OFF_ELF = 128           # identities[4] (ELF keccak), 32 bytes

# Identities 0..2 of every Bloch L2 mainnet (chain 700770) statement: admission domain, native genesis id, L2
# domain (deployment/devnet/settler_v3.py MAINNET 'network', 'genesis', 'l2_domain'; test_make_reset_target.py
# compares the two files).
MAINNET_IDENTITIES = ('f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',
                      '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415',
                      '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733')
IDENTITY_NAMES = ('admission domain', 'native genesis', 'L2 domain')
HEX32 = re.compile(r'[0-9a-f]{64}')


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


def follower_log_path(path):
    """The `.settlements.jsonl` a status file points at (schema v3), or None."""
    try:
        status = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        die(f'follower status {path} is unreadable: {error}')
    if not isinstance(status, dict):
        die(f'follower status {path} is not a JSON object')
    log_name = (status.get('settlement_log') or {}).get('file')
    if log_name and '/' not in log_name:
        log_path = Path(path).with_name(log_name)
        if log_path.exists():
            return log_path
    return None


def require_distinct_followers(paths):
    """Two followers are two files on two hosts' copies: refuse one status file given twice (same path, the same
    file through a symbolic or hard link, or the same bytes) and one settlement log behind two status files."""
    seen = []
    for path in paths:
        try:
            body = Path(path).read_bytes()
        except OSError as error:
            die(f'follower status {path} is unreadable: {error}')
        log = follower_log_path(path)
        for other, other_body, other_log in seen:
            if os.path.samefile(path, other):
                die(f'--follower-status {path} and {other} are the same file: that is one follower, not two')
            if body == other_body:
                die(f'--follower-status {path} and {other} have the same bytes: a copy of one status file is one '
                    'follower, not two (take the status of a second, independent host)')
            if log is not None and other_log is not None and os.path.samefile(log, other_log):
                die(f'--follower-status {path} and {other} read the same settlement log {log}: one follower, not two')
        seen.append((path, body, log))


def load_follower(path, number, note=lambda text: print(text, file=sys.stderr)):
    """The logged settlement of L2 block `number` from a follower status file and its
    `.settlements.jsonl` log (schema v2 inlines the settlements; v3 points at the log).

    The log is append-only, so a block settled again after an earlier head reset has several lines: the NEWEST is
    the settlement in force. It is taken only if no older line for the block sits at a higher L1 slot (a log that
    is not in L1 order is refused), and a `finalized_settlements_recent` entry for the block must equal it."""
    status = json.loads(Path(path).read_text())
    entries = []
    recent = status.get('finalized_settlements')
    if isinstance(recent, list):
        entries = recent
    log_path = follower_log_path(path)
    if log_path is not None:
        entries = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    named = [e for e in entries if isinstance(e, dict) and e.get('l2_number') == number]
    for e in status.get('finalized_settlements_recent', []) or []:
        if isinstance(e, dict) and e.get('l2_number') == number:
            if named and e != named[-1]:
                die(f'follower {path}: finalized_settlements_recent and the newest log line disagree for L2 block '
                    f'{number}')
            if not named:
                named.append(e)
    if not named:
        die(f'follower {path} has no finalized settlement for L2 block {number}')
    newest = named[-1]
    distinct = [e for i, e in enumerate(named) if e not in named[:i]]
    if len(distinct) > 1:
        slots = [e.get('native_slot') for e in distinct]
        if not all(isinstance(s, int) and not isinstance(s, bool) for s in slots):
            die(f'follower {path}: {len(distinct)} different log lines for L2 block {number} and not every one '
                'carries a native_slot: cannot tell the newest')
        if slots[-1] != max(slots) or slots.count(slots[-1]) != 1:
            die(f'follower {path}: {len(distinct)} different log lines for L2 block {number}, and the last one '
                f'(L1 slot {slots[-1]}) is not the newest by L1 slot ({max(slots)}): the log is not in L1 order')
        note(f'make_reset_target.py: NOTE: follower {path} logged L2 block {number} {len(distinct)} times (it was '
             f'settled again after an earlier reset); taking the newest line, L1 slot {slots[-1]} (older: '
             f'{", ".join(str(s) for s in slots[:-1])})')
    return newest


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


def pin(value, name):
    """A required 64-hex pin, lowercase, or a refusal."""
    text = str(value or '').strip().lower().removeprefix('0x')
    if not HEX32.fullmatch(text):
        die(f'{name} is required as 64 hex digits (got {value!r})')
    return text


def build(number, followers, block_txs_hex=None, expect_config=None, expect_elf=None, *, forfeit=None,
          identities=MAINNET_IDENTITIES):
    """Pure core: validate and return the reset.json dict. `followers` is a list of
    the per-block log entries (>= 2). `block_txs_hex` is the L1 block's transactions.
    `forfeit` (True/False), and for N > 0 the program pins, are required; `identities` are the three network
    identities the statement must carry (mainnet unless given)."""
    if not isinstance(forfeit, bool):
        die('the reset form is required: forfeit (the decided form for G2a) or plain; it is never defaulted')
    if number == 0:
        return {'number': 0, 'commitment': '0' * 64, 'statement': None, 'forfeit': forfeit}
    if len(identities) != 3:
        die('three network identities are required: admission domain, native genesis, L2 domain')
    identities = [pin(v, f'the {name} identity') for v, name in zip(identities, IDENTITY_NAMES)]
    expect_config = pin(expect_config, '--expect-program-config (identities[3] of the program that settled N)')
    expect_elf = pin(expect_elf, '--expect-program-elf (identities[4] of the program that settled N)')
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
    for index, (want, name) in enumerate(zip(identities, IDENTITY_NAMES)):
        got = statement[S + index * 32:S + index * 32 + 32].hex()
        if got != want:
            die(f'statement {name} (identity {index}) is {got}, not the pinned {want}: this settlement belongs to '
                'another network (a rehearsal or devnet follower?); the native reset would refuse it')
    config_in_stmt = statement[S + OFF_CONFIG:S + OFF_CONFIG + 32].hex()
    elf_in_stmt = statement[S + OFF_ELF:S + OFF_ELF + 32].hex()
    if config_in_stmt != expect_config:
        die(f'statement configuration {config_in_stmt} != expected active program {expect_config}')
    if elf_in_stmt != expect_elf:
        die(f'statement ELF keccak {elf_in_stmt} != expected active program {expect_elf}')
    if first.get('configuration') not in (None, config_in_stmt):
        die(f'the followers logged configuration {first.get("configuration")} for the block but the statement '
            f'carries {config_in_stmt}')
    return {'number': number, 'commitment': commitment_hex, 'statement': statement.hex(), 'forfeit': forfeit}


FORM_NOTES = {
    True: 'reset form: FORFEIT (decided for G2a). The native reset forgets the leaves paid above the target; it is '
          'not refused by the depth of the consumed forced-record log (it requeues what that log still holds).',
    False: 'reset form: PLAIN. The native reset is refused over paid leaves above the target, and when the tail '
           'consumed more forced records than the consumed log holds; for G2a the decided form is forfeit.',
}


def main():
    a = argparse.ArgumentParser()
    a.add_argument('--number', required=True, type=int, help='N, the last block to keep')
    a.add_argument('--reset-form', required=True, choices=('forfeit', 'plain'),
                   help='forfeit: the decided form for G2a (paid forged leaves are forgotten); plain: any other reset')
    a.add_argument('--follower-status', action='append', default=[], help='follower status file (>= 2 for N > 0)')
    a.add_argument('--l1-rpc', action='append', default=[], help='L1 RPC URL to fetch the settlement block')
    a.add_argument('--l1-block-hex', type=Path, help='offline: a file with one L1 transaction hex per line')
    a.add_argument('--expect-program-config', help='configuration (identities[3]) of the program that settled N; '
                   'required for N > 0')
    a.add_argument('--expect-program-elf', help='ELF keccak (identities[4]) of the program that settled N; '
                   'required for N > 0')
    a.add_argument('--rehearsal-identities', nargs=3, metavar=('ADMISSION', 'GENESIS', 'L2DOMAIN'),
                   help='NOT mainnet: the three network identities of a rehearsal network, in place of the built-in '
                   'mainnet ones')
    a.add_argument('--out', type=Path, help='write reset.json here (default: stdout)')
    o = a.parse_args()
    if o.number < 0:
        die('--number must not be negative')

    followers = []
    block_txs = None
    identities = MAINNET_IDENTITIES
    if o.rehearsal_identities:
        identities = tuple(pin(v, f'--rehearsal-identities {name}') for v, name in zip(o.rehearsal_identities, IDENTITY_NAMES))
        if identities == MAINNET_IDENTITIES:
            die('--rehearsal-identities are the mainnet identities: drop the flag')
        print('make_reset_target.py: NOTE: REHEARSAL identities given: this reset.json is NOT for mainnet', file=sys.stderr)
    if o.number != 0:
        pin(o.expect_program_config, '--expect-program-config (identities[3] of the program that settled N)')
        pin(o.expect_program_elf, '--expect-program-elf (identities[4] of the program that settled N)')
        if len(o.follower_status) < 2:
            die('N > 0 needs at least two --follower-status files')
        require_distinct_followers(o.follower_status)
        followers = [load_follower(p, o.number) for p in o.follower_status]
        if o.l1_block_hex:
            block_txs = [line.strip() for line in o.l1_block_hex.read_text().splitlines() if line.strip()]
        elif o.l1_rpc:
            block_txs = l1_block_txs(o.l1_rpc, followers[0].get('native_block'), followers[0].get('native_slot'))
        else:
            die('give --l1-rpc or --l1-block-hex so the statement can be recovered')

    forfeit = o.reset_form == 'forfeit'
    reset = build(o.number, followers, block_txs, o.expect_program_config, o.expect_program_elf, forfeit=forfeit,
                  identities=identities)
    out = json.dumps(reset, indent=1, sort_keys=True)
    if o.out:
        temporary = o.out.with_name(o.out.name + '.tmp')
        temporary.write_text(out + '\n')
        os.replace(temporary, o.out)
        print(f'wrote {o.out} for L2 block {o.number}', file=sys.stderr)
    print(f'make_reset_target.py: {FORM_NOTES[forfeit]}', file=sys.stderr)
    print('make_reset_target.py: NOT checked here (no L1 state): paid leaves above the target and the depth of the '
          'consumed forced-record log at the gate. Rehearse the armed reset.', file=sys.stderr)
    print(out)


if __name__ == '__main__':
    main()
