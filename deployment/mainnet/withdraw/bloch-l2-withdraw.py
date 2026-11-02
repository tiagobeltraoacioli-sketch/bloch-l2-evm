#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Withdraw BLCH from the Bloch L2 to L1 without a local L2 database. Python 3 standard library only.

  burn    --recipient HEX32 | --recipient-pubkey FILE, --sats N
              Print the outbox call to sign with your own wallet. Holds no key, sends nothing.
  find    --l2-rpc URL --tx HASH
              Read the withdrawal index and fields from the burn's receipt.
  fetch   --l2-rpc URL --l1-rpc URL [--l1-rpc URL ...] --index I
          (--recipient HEX32 | --recipient-pubkey FILE | --any-recipient) [--sats N]
          --out proof.json [--wait SECONDS]
              Fetch a proof, verify it here and write it only if it is claimable on L1.
  verify  --proof proof.json [--l1-rpc URL ...] [--chain-id N]
              Check a proof file again. Without --l1-rpc only its internal consistency is checked.
              Exit 0 means the proof is valid and the withdrawal is NOT claimed yet. It is not a payment.
  status  --proof proof.json --l1-rpc URL [--l1-rpc URL ...] [--tx TXID] [--sent-height H]
              After sending a claim: has it paid? Use this one to decide whether to credit or to retry.

The L2 RPC is never trusted. A proof is accepted only if this program recomputes the leaf and the
root and the root is one the L1 itself retains as finalized (getl2settlement withdrawals). The L1
RPC is the trust anchor of this check: use your own node, or give several --l1-rpc to require
agreement. The L1 verifies the proof again when the claim is included, so a wrong anchor can cost
a rejected transaction but cannot release funds to the wrong owner.

Exit status: 0 ok (status: the claim is final); 1 refused, tampered or usage error; 3 not ready yet,
retry later; 4 this withdrawal was already claimed (status: claimed, finality of the paying output not shown);
5 (status only) still unclaimed long after sending: presumed dropped, nothing moved, build a new claim.
"""
import argparse
import hashlib
import http.client
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

MAINNET_CHAIN_ID = 700770
MAINNET_NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
MAINNET_GENESIS = '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415'
OUTBOX = '0x4200000000000000000000000000000000000102'
INITIATE_SELECTOR = 'b769844a'
WITHDRAWAL_TOPIC = 'ce2e3b3c3607f63db6a4e9c3d50ce0b37e10456bce8dcb9b5d9cecd1c28a69d2'
ATOM_SCALE = 10 ** 10
MIN_WITHDRAWAL_SATS = 1_000_000
TREE_DEPTH = 32
LEAF_DOMAIN = b'BLOCH:L2:WITHDRAW:1'
MAX_RESPONSE = 32 * 1024 * 1024
RPC_TIMEOUT = 30
POLL_SECONDS = 30

# bloch_getWithdrawalProof errors that a later try can clear.
RETRYABLE = {-32041: 'not finalized yet', -32045: 'RPC index catching up', -32042: 'RPC does not know this index yet',
             -32043: 'RPC does not know this finalized root yet', -32005: 'rate limited', -32053: 'no backend available',
             -32001: 'the RPC has closed its finality levels', -32046: 'this RPC froze its withdrawal index; another backend may hold it'}

OK, REFUSED, NOT_READY, CLAIMED, DROPPED = 0, 1, 3, 4, 5


class Refused(Exception):
    """The proof or the RPC answer must not be used."""


class NotReady(Exception):
    """Nothing is wrong, but the withdrawal cannot be claimed yet."""


class AlreadyClaimed(Exception):
    """The L1 nullifier set holds this index."""


# ---- Keccak-256 (Ethereum padding) ----
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rol(value, shift):
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & _MASK & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    padded = bytearray(data)
    pad = rate - len(padded) % rate
    padded += b'\x01' + b'\x00' * (pad - 1)
    padded[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


# ---- The withdrawal tree (native l2_settlement::withdrawal) ----
def node(left, right):
    return keccak256(left + right)


def leaf_hash(chain_id, index, recipient, sats):
    return keccak256(LEAF_DOMAIN + chain_id.to_bytes(8, 'big') + index.to_bytes(8, 'big') + recipient + sats.to_bytes(8, 'big'))


def root_from_proof(leaf, index, siblings):
    acc = leaf
    for height, sibling in enumerate(siblings):
        acc = node(sibling, acc) if (index >> height) & 1 else node(acc, sibling)
    return acc


# ---- Strict field reading: a malformed answer is a refusal, never a default ----
def unsigned(value, what, bits=64):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >> bits:
        raise Refused(f'{what} is not a {bits}-bit unsigned integer')
    return value


def hex32(value, what):
    if not isinstance(value, str):
        raise Refused(f'{what} is not a string')
    text = value[2:] if value.startswith('0x') else value
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise Refused(f'{what} is not hex') from None
    if len(raw) != 32 or len(text) != 64:
        raise Refused(f'{what} needs exactly 32 bytes')
    return raw


def no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Refused(f'duplicate JSON key {key!r}')
        out[key] = value
    return out


def check_proof(doc, chain_id):
    """Recompute everything a proof document claims. Returns its fields; raises Refused."""
    if not isinstance(doc, dict) or not isinstance(doc.get('withdrawal'), dict):
        raise Refused('the proof is not a withdrawal-proof document')
    w = doc['withdrawal']
    if unsigned(doc.get('chain_id'), 'chain_id') != chain_id:
        raise Refused(f'the proof is for chain {doc["chain_id"]}, not {chain_id}')
    index = unsigned(doc.get('index'), 'index', TREE_DEPTH)
    if unsigned(w.get('nonce'), 'withdrawal.nonce') != index:
        raise Refused('the withdrawal nonce differs from the proof index')
    count = unsigned(doc.get('withdrawal_count'), 'withdrawal_count', TREE_DEPTH + 1)
    if count > 1 << TREE_DEPTH:
        raise Refused('withdrawal_count exceeds the tree')
    if index >= count:
        raise Refused('index is not below withdrawal_count')
    recipient = hex32(w.get('l1_recipient'), 'withdrawal.l1_recipient')
    if recipient == bytes(32):
        raise Refused('the outbox never records a zero recipient')
    sats = unsigned(w.get('sats'), 'withdrawal.sats')
    if sats < MIN_WITHDRAWAL_SATS:
        raise Refused('sats is below the minimum withdrawal')
    siblings = doc.get('siblings')
    if not isinstance(siblings, list) or len(siblings) != TREE_DEPTH:
        raise Refused(f'the proof needs exactly {TREE_DEPTH} siblings')
    siblings = [hex32(s, 'sibling') for s in siblings]
    leaf = leaf_hash(chain_id, index, recipient, sats)
    if hex32(w.get('leaf'), 'withdrawal.leaf') != leaf:
        raise Refused('the proof leaf differs from the leaf of its fields')
    root = hex32(doc.get('withdrawal_root'), 'withdrawal_root')
    if root_from_proof(leaf, index, siblings) != root:
        raise Refused('the siblings do not prove the leaf against withdrawal_root')
    return {'chain_id': chain_id, 'index': index, 'count': count, 'root': root.hex(), 'sats': sats,
            'recipient': recipient.hex(), 'leaf': leaf.hex(), 'siblings': [s.hex() for s in siblings],
            'number': unsigned(doc.get('number'), 'number'), 'sender': w.get('sender'),
            'l2_block': unsigned(w.get('l2_block'), 'withdrawal.l2_block')}


def sender_text(value):
    """The sender is informational (not in the leaf): keep it only if it is an address."""
    text = value.removeprefix('0x') if isinstance(value, str) else ''
    return text if len(text) == 40 and all(c in '0123456789abcdefABCDEF' for c in text) else ''


def canonical_document(fields):
    """A clean file for `bloch-pos l2-claim prepare`, built from checked fields only (nothing else the RPC sent)."""
    return {'chain_id': fields['chain_id'], 'number': fields['number'], 'withdrawal_root': fields['root'],
            'withdrawal_count': fields['count'], 'index': fields['index'],
            'withdrawal': {'nonce': fields['index'], 'l1_recipient': fields['recipient'], 'sats': fields['sats'],
                           'sender': sender_text(fields['sender']),
                           'l2_block': fields['l2_block'], 'leaf': fields['leaf']},
            'siblings': fields['siblings']}


# ---- JSON-RPC ----
class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(f'{message} ({code})')
        self.code = code


def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(url, data=body, headers={'content-type': 'application/json', 'user-agent': 'bloch-l2-withdraw/1'})
    try:
        with urllib.request.urlopen(request, timeout=RPC_TIMEOUT) as response:
            text = response.read(MAX_RESPONSE + 1)
    except http.client.HTTPException as error:  # the answer was cut short
        raise NotReady(f'{url}: {error!r}') from None
    except urllib.error.HTTPError as error:
        text = error.read(MAX_RESPONSE + 1)
        if not text:
            raise NotReady(f'{url}: HTTP {error.code}') from None
    except (OSError, urllib.error.URLError) as error:
        raise NotReady(f'{url}: {error}') from None
    if len(text) > MAX_RESPONSE:
        raise Refused(f'{url}: answer too large')
    try:
        answer = json.loads(text, object_pairs_hook=no_duplicates)
    except ValueError:  # an edge's error page, a restart: nothing was claimed, so nothing is refused
        raise NotReady(f'{url}: the answer is not JSON') from None
    if not isinstance(answer, dict):
        raise Refused(f'{url}: the answer is not a JSON-RPC object')
    if answer.get('error') is not None:
        error = answer['error'] if isinstance(answer['error'], dict) else {}
        raise RpcError(error.get('code'), error.get('message', 'RPC error'))
    return answer.get('result')


# ---- The L1 anchor ----
def l1_view(url, pins):
    """`getl2settlement` withdrawals of one L1 RPC, after checking it serves the pinned network."""
    try:
        view = rpc(url, 'getl2settlement', [])
    except RpcError as error:
        raise NotReady(f'{url}: getl2settlement: {error}') from None
    if not isinstance(view, dict) or not isinstance(view.get('withdrawals'), dict):
        raise Refused(f'{url}: not a getl2settlement answer')
    for key, want in (('chain_id', pins['chain_id']), ('network', pins['network']), ('genesis', pins['genesis'])):
        if want is not None and view.get(key) != want:
            raise Refused(f'{url}: L1 {key} is {view.get(key)}, expected {want}')
    return view['withdrawals']


def sat_field(view, key):
    value = view.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        raise Refused(f'L1 view lacks {key}') from None


def record_of(view, root_hex):
    roots = view.get('roots')
    if not isinstance(roots, list):
        raise Refused('L1 view lacks withdrawals.roots')
    for record in reversed(roots):
        if isinstance(record, dict) and record.get('root') == root_hex:
            return record
    return None


def is_claimed(view, index):
    claimed = view.get('claimed')
    if not isinstance(claimed, dict):
        raise Refused('L1 view lacks withdrawals.claimed')
    word, position = index // 256, index % 256
    if word < unsigned(claimed.get('floor'), 'claimed.floor'):
        return True
    for entry in claimed.get('words', []):
        if entry.get('word') == word:
            bits = bytes.fromhex(entry['bits'])
            return bool(bits[position // 8] >> (position % 8) & 1)
    return False


def check_own_finality(url, view):
    """The node's warning that its chain carries a finality that is not its own: claims are unsafe."""
    checkpoint = view.get('finalized_checkpoint')
    if isinstance(checkpoint, dict) and checkpoint.get('own_root') is not None and checkpoint['own_root'] != checkpoint.get('root'):
        raise NotReady(f'{url}: the finalized checkpoint is not this chain\'s own; claims are unsafe now')


def claim_target(view, sats):
    """The record a claim of `sats` should prove against now: matured and finalized, according to the L1."""
    key = 'claimable_large' if sats >= sat_field(view, 'large_claim_sat') else 'claimable'
    return view.get(key), key


def anchor(fields, views):
    """Require the proof's root on every L1 view as a retained finalized record with the same count and L2 block."""
    for url, view in views:
        check_own_finality(url, view)
        # First: a claimed withdrawal stays claimed after its root leaves the L1's retained list.
        if is_claimed(view, fields['index']):
            raise AlreadyClaimed(f'withdrawal {fields["index"]} was already claimed on L1')
        record = record_of(view, fields['root'])
        if record is None:
            raise Refused(f'{url}: root {fields["root"]} is not a withdrawal root the L1 retains. If this proof is old, run fetch again: a claim built on it is dropped, and a large claim also needs attestations for the new root')
        if record.get('count') != fields['count']:
            raise Refused(f'{url}: the L1 record counts {record.get("count")} withdrawals, the proof claims {fields["count"]}')
        if record.get('l2_number') != fields['number']:
            raise Refused(f'{url}: the L1 record is L2 block {record.get("l2_number")}, the proof claims {fields["number"]}')
        if record.get('finalized') is not True:
            raise NotReady(f'{url}: root {fields["root"]} is not finalized on L1 yet')


# ---- Commands ----
def recipient_of(args):
    if getattr(args, 'recipient', None):
        return hex32(args.recipient, '--recipient')
    if getattr(args, 'recipient_pubkey', None):
        with open(args.recipient_pubkey, encoding='ascii') as file:
            return hashlib.sha3_256(bytes.fromhex(file.read().strip())).digest()
    return None


def pins_of(args):
    mainnet = args.chain_id == MAINNET_CHAIN_ID
    return {'chain_id': args.chain_id, 'network': args.network or (MAINNET_NETWORK if mainnet else None),
            'genesis': args.genesis_hash or (MAINNET_GENESIS if mainnet else None)}


def cmd_burn(args):
    recipient = recipient_of(args)
    if recipient is None or recipient == bytes(32):
        raise Refused('give a non-zero --recipient or --recipient-pubkey')
    if args.sats < MIN_WITHDRAWAL_SATS or args.sats >> 64:
        raise Refused(f'--sats must be at least {MIN_WITHDRAWAL_SATS}; the outbox would revert')
    wei = args.sats * ATOM_SCALE
    print(json.dumps({'to': OUTBOX, 'value_wei': str(wei), 'value_hex': hex(wei),
                      'data': f'0x{INITIATE_SELECTOR}{recipient.hex()}', 'chain_id': args.chain_id, 'gas': 100000,
                      'l1_recipient': recipient.hex(), 'sats': args.sats}, indent=1))
    print('\nThe L2 balance leaves when this transaction is included. Check that l1_recipient is yours: only that key can spend on L1.', file=sys.stderr)
    print(f'Foundry:\n  cast send {OUTBOX} "initiateWithdrawal(bytes32)" 0x{recipient.hex()} --value {wei} --gas-limit 100000 --rpc-url URL --interactive', file=sys.stderr)
    return OK


def withdrawals_in_receipt(receipt):
    found = []
    for log in receipt.get('logs', []):
        topics = log.get('topics', [])
        if str(log.get('address', '')).lower() != OUTBOX or len(topics) != 3 or topics[0].removeprefix('0x') != WITHDRAWAL_TOPIC:
            continue
        data = bytes.fromhex(log['data'].removeprefix('0x'))
        if len(data) != 64:
            raise Refused('malformed WithdrawalInitiated log')
        found.append({'index': int(topics[1], 16), 'l1_recipient': topics[2].removeprefix('0x'),
                      'sats': int.from_bytes(data[32:], 'big') // ATOM_SCALE, 'sender': '0x' + data[12:32].hex(),
                      'l2_block': int(receipt['blockNumber'], 16)})
    return found


def cmd_find(args):
    try:
        receipt = rpc(args.l2_rpc, 'eth_getTransactionReceipt', [args.tx])
    except RpcError as error:
        raise Refused(f'L2 RPC: {error}') from None
    if receipt is None:
        raise NotReady('no receipt yet')
    if receipt.get('status') != '0x1':
        raise Refused('this transaction reverted; nothing was withdrawn and the value was refunded')
    found = withdrawals_in_receipt(receipt)
    if not found:
        raise Refused('this transaction initiated no withdrawal')
    print(json.dumps(found, indent=1))
    print('This answer is a hint from the L2 RPC. fetch binds the index to these fields under an L1 root.', file=sys.stderr)
    return OK


def ask_proof(url, index, root=None):
    try:
        return rpc(url, 'bloch_getWithdrawalProof', [index] if root is None else [index, root])
    except RpcError as error:
        if error.code in RETRYABLE:
            raise NotReady(f'L2 RPC: {RETRYABLE[error.code]}: {error}') from None
        raise Refused(f'L2 RPC: {error}') from None


def fetch_once(args, expected_recipient):
    pins = pins_of(args)
    views = [(url, l1_view(url, pins)) for url in args.l1_rpc]
    if not views:
        raise Refused('--l1-rpc is required')
    # The first answer only tells the size of the withdrawal, which selects the claim delay.
    fields = check_proof(ask_proof(args.l2_rpc, args.index), args.chain_id)
    if fields['index'] != args.index:
        raise Refused(f'asked for withdrawal {args.index}, the RPC proved {fields["index"]}')
    check_expected(fields, expected_recipient, args.sats)
    primary = views[0][1]
    target, key = claim_target(primary, fields['sats'])
    if target is None or not isinstance(target, dict):
        raise NotReady(f'L1 has no {key} root yet')
    if unsigned(target.get('count'), f'{key}.count') <= args.index:
        raise NotReady(f'the L1 {key} root covers {target["count"]} withdrawals; {args.index} is not matured yet')
    wanted = target.get('root')
    if wanted != fields['root']:
        first_sats = fields['sats']
        fields = check_proof(ask_proof(args.l2_rpc, args.index, wanted), args.chain_id)
        if fields['sats'] != first_sats:
            # The delay was chosen from the first answer; only this one is under an L1 root.
            raise Refused(f'the RPC gave withdrawal {args.index} two amounts: {first_sats} and {fields["sats"]} sats')
        if fields['root'] != wanted:
            raise Refused(f'asked for a proof against {wanted}, the RPC answered {fields["root"]}')
        if fields['index'] != args.index:
            raise Refused(f'asked for withdrawal {args.index}, the RPC proved {fields["index"]}')
        check_expected(fields, expected_recipient, args.sats)
    anchor(fields, views)
    return fields, primary


def check_expected(fields, recipient, sats):
    if recipient is not None and fields['recipient'] != recipient.hex():
        raise Refused(f'withdrawal {fields["index"]} pays {fields["recipient"]}, not the expected {recipient.hex()}; wrong index?')
    if sats is not None and fields['sats'] != sats:
        raise Refused(f'withdrawal {fields["index"]} is {fields["sats"]} sats, not the expected {sats}; wrong index?')


def write_exclusive(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if os.path.exists(path):
        raise Refused(f'{path} exists; choose another --out')
    handle, temporary = tempfile.mkstemp(dir=directory, prefix='.proof-')
    try:
        with os.fdopen(handle, 'w', encoding='ascii') as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def cmd_fetch(args):
    expected = recipient_of(args)
    if expected is None and not args.any_recipient:
        raise Refused('give --recipient or --recipient-pubkey, or --any-recipient when relaying for someone else')
    deadline = time.monotonic() + args.wait
    while True:
        try:
            fields, view = fetch_once(args, expected)
            break
        except NotReady as reason:
            if time.monotonic() >= deadline:
                raise
            print(f'waiting: {reason}', file=sys.stderr)
            time.sleep(min(POLL_SECONDS, max(1, deadline - time.monotonic())))
    write_exclusive(args.out, json.dumps(canonical_document(fields), indent=1) + '\n')
    print(f'VERIFIED withdrawal {fields["index"]}: {fields["sats"]} sats to {fields["recipient"]}')
    print(f'  root {fields["root"]} (count {fields["count"]}, L2 block {fields["number"]}) is retained, matured and finalized on L1')
    print(f'  wrote {args.out}')
    large = fields['sats'] >= sat_field(view, 'attested_claim_sat') and view.get('attestor_set') is not None
    remaining = view.get('release_window', {}).get('remaining_sat')
    if large:
        print('  this claim needs the attestors: run aggregate_attestation.py for this root and add --attestors and --attestation to prepare')
    if remaining is not None and fields['sats'] > int(remaining):
        print(f'  the current release window has {remaining} sats left: this claim is dropped now. It fits only as the FIRST claim of a later window, so send it right after a window opens (windows are {view.get("release_window", {}).get("blocks")} L1 blocks); any other claim sent first takes the window')
    attest = ' --attestors attestors.set --attestation PARTIAL_1 --attestation PARTIAL_2 --attestation PARTIAL_3' if large else ''
    print('Nothing has been paid yet. Next, with base fee (getchaininfo next_base_fee_millisat_per_gas) and funding input from your L1 node, and without delay, because a claim built with an old base fee is dropped:')
    print(f'  bloch-pos l2-claim prepare --genesis genesis.bin --funding-pubkey relayer.pubkey.hex --input TXID:VOUT:SAT --proof {args.out} --base-fee NEXT_BASE_FEE --tip 0{attest} --out claim-unsigned.hex')
    print('  bloch-pos l2-claim sign --genesis genesis.bin --tx claim-unsigned.hex --dir RELAYER_KEYSTORE_DIR --out claim.hex')
    print('  bloch-pos l2-claim inspect --tx claim.hex prints the txid. Send claim.hex with sendrawtransaction. Its reply `accepted` is not a confirmation and its tx_hash is not a txid. Then:')
    print(f'  bloch-l2-withdraw.py status --proof {args.out} --l1-rpc URL --tx TXID')
    return OK


def cmd_verify(args):
    with open(args.proof, encoding='utf-8') as file:
        try:
            doc = json.load(file, object_pairs_hook=no_duplicates)
        except ValueError:
            raise Refused(f'{args.proof} is not JSON') from None
    fields = check_proof(doc, args.chain_id)
    if not args.l1_rpc:
        print(f'INTERNALLY CONSISTENT, NOT ANCHORED: withdrawal {fields["index"]}, {fields["sats"]} sats to {fields["recipient"]}, root {fields["root"]}. Give --l1-rpc to check the root.')
        return OK
    pins = pins_of(args)
    anchor(fields, [(url, l1_view(url, pins)) for url in args.l1_rpc])
    print(f'VALID, NOT CLAIMED: withdrawal {fields["index"]}, {fields["sats"]} sats to {fields["recipient"]}, root {fields["root"]} retained and finalized on L1. Nothing has been paid yet.')
    return OK


DROP_REASONS = ('the base fee moved from the one the claim was prepared with', 'the root left the L1 retained list or has not matured',
                'a large claim without a valid attestation', 'the claim did not fit the current release window', 'the funding input was spent')
# Unclaimed this many L1 blocks after sending: presumed dropped. A proposer takes a valid claim long before this on a quiet chain.
DROP_AFTER_BLOCKS = 32
UTXO_PAGE = 1024


def paying_outputs(url, recipient, sats):
    """Outputs of exactly `sats` locked to the recipient. Their txids are the only consensus ids a sender can learn:
    sendrawtransaction returns none (its tx_hash is a local handle that gettxstatus does not know)."""
    try:
        page = rpc(url, 'getutxos', [recipient, UTXO_PAGE])
    except RpcError as error:
        raise Refused(f'{url}: getutxos: {error}') from None
    if not isinstance(page, dict) or not isinstance(page.get('utxos'), list):
        raise Refused(f'{url}: not a getutxos answer')
    return [u for u in page['utxos'] if str(u.get('value_sat')) == str(sats)], bool(page.get('truncated'))


def cmd_status(args):
    with open(args.proof, encoding='utf-8') as file:
        try:
            doc = json.load(file, object_pairs_hook=no_duplicates)
        except ValueError:
            raise Refused(f'{args.proof} is not JSON') from None
    fields = check_proof(doc, args.chain_id)
    pins = pins_of(args)
    views = [(url, l1_view(url, pins)) for url in args.l1_rpc]
    for url, view in views:
        check_own_finality(url, view)
    answers = {is_claimed(view, fields['index']) for _, view in views}
    if len(answers) != 1:
        raise NotReady('the L1 nodes disagree on whether this withdrawal is claimed; wait and ask again')
    url = args.l1_rpc[0]
    claimed = answers.pop()
    tx_status = None
    if args.tx:
        answer = rpc(url, 'gettxstatus', [args.tx.removeprefix('0x')])
        tx_status = answer.get('status') if isinstance(answer, dict) else None
        if tx_status not in ('finalized', 'justified', 'included', 'pending', 'unknown'):
            raise Refused(f'{url}: unexpected gettxstatus answer {tx_status!r}')
    if not claimed:
        if tx_status == 'pending':
            raise NotReady(f'the claim is in this node\'s mempool, withdrawal {fields["index"]} is not claimed yet; ask again')
        if tx_status in ('finalized', 'justified', 'included'):
            raise Refused(f'{args.tx} is {tx_status} but withdrawal {fields["index"]} is not claimed: this transaction is not this claim')
        if tx_status == 'unknown':
            print(f'DROPPED: this node does not hold {args.tx} and withdrawal {fields["index"]} is not claimed. No claim paid and no fee was charged by a dropped claim. A new claim is safe: consensus pays an index once. Ask again first if you sent it moments ago or through another node. Possible causes: {"; ".join(DROP_REASONS)}.', file=sys.stderr)
            return DROPPED
        if args.sent_height is None:
            raise NotReady(f'withdrawal {fields["index"]} is not claimed; give --tx (the txid from l2-claim inspect) or --sent-height to tell a pending claim from a dropped one')
        info = rpc(url, 'getchaininfo', [])
        age = unsigned(info.get('height'), 'height') - args.sent_height
        if age < DROP_AFTER_BLOCKS:
            raise NotReady(f'withdrawal {fields["index"]} is not claimed, {age} blocks after sending; ask again')
        print(f'DROPPED, presumed: withdrawal {fields["index"]} is still not claimed {age} blocks after sending. No claim paid and no fee was charged by a dropped claim. A new claim is safe: consensus pays an index once. Possible causes: {"; ".join(DROP_REASONS)}.', file=sys.stderr)
        return DROPPED
    if tx_status == 'finalized':
        print(json.dumps({'index': fields['index'], 'sats': fields['sats'], 'recipient': fields['recipient'], 'claimed_at_l1_head': True, 'tx_status': tx_status}))
        print(f'FINAL: withdrawal {fields["index"]} is claimed and {args.tx} is in a finalized block')
        return OK
    if tx_status in ('included', 'justified', 'pending'):
        raise NotReady(f'withdrawal {fields["index"]} is claimed at the L1 head and {args.tx} is {tx_status}; do not credit yet')
    outputs, truncated = paying_outputs(url, fields['recipient'], fields['sats'])
    states = {}
    for output in outputs:
        answer = rpc(url, 'gettxstatus', [output['txid']])
        states[output['txid']] = answer.get('status') if isinstance(answer, dict) else None
    print(json.dumps({'index': fields['index'], 'sats': fields['sats'], 'recipient': fields['recipient'], 'claimed_at_l1_head': True, 'candidate_outputs': states, 'utxo_page_truncated': truncated}))
    if states and all(state == 'finalized' for state in states.values()):
        print(f'FINAL: withdrawal {fields["index"]} is claimed and every unspent output of {fields["sats"]} sats to the recipient is in a finalized block')
        return OK
    if any(state in ('included', 'justified') for state in states.values()):
        raise NotReady(f'withdrawal {fields["index"]} is claimed at the L1 head, in a block not finalized yet; do not credit yet')
    print(f'CLAIMED at the L1 head, finality not shown: no output of exactly {fields["sats"]} sats to the recipient could be followed (spent, on a truncated page, or unknown to this node). Check the recipient\'s ledger.', file=sys.stderr)
    return CLAIMED


def parser():
    top = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = top.add_subparsers(dest='command', required=True)

    def common(p):
        p.add_argument('--chain-id', type=int, default=MAINNET_CHAIN_ID)
        p.add_argument('--network', help='expected L1 network id (default: the mainnet pin on chain 700770)')
        p.add_argument('--genesis-hash', help='expected L1 genesis (default: the mainnet pin on chain 700770)')

    def recipient(p):
        p.add_argument('--recipient', help='L1 owner script hash, 32 bytes of hex')
        p.add_argument('--recipient-pubkey', help='file with the L1 hybrid public key in hex; the recipient is its SHA3-256')

    burn = sub.add_parser('burn')
    common(burn)
    recipient(burn)
    burn.add_argument('--sats', type=int, required=True)
    burn.set_defaults(run=cmd_burn)

    find = sub.add_parser('find')
    find.add_argument('--l2-rpc', required=True)
    find.add_argument('--tx', required=True)
    find.set_defaults(run=cmd_find)

    fetch = sub.add_parser('fetch')
    common(fetch)
    recipient(fetch)
    fetch.add_argument('--any-recipient', action='store_true')
    fetch.add_argument('--l2-rpc', required=True)
    fetch.add_argument('--l1-rpc', action='append', default=[], required=True)
    fetch.add_argument('--index', type=int, required=True)
    fetch.add_argument('--sats', type=int)
    fetch.add_argument('--out', required=True)
    fetch.add_argument('--wait', type=int, default=0, help='keep trying for this many seconds while the withdrawal is not ready')
    fetch.set_defaults(run=cmd_fetch)

    verify = sub.add_parser('verify')
    common(verify)
    verify.add_argument('--proof', required=True)
    verify.add_argument('--l1-rpc', action='append', default=[])
    verify.set_defaults(run=cmd_verify)

    status = sub.add_parser('status')
    common(status)
    status.add_argument('--proof', required=True)
    status.add_argument('--l1-rpc', action='append', default=[], required=True)
    status.add_argument('--tx', help='the txid printed by bloch-pos l2-claim inspect')
    status.add_argument('--sent-height', type=int, help='L1 height when you sent the claim; lets status report a dropped claim')
    status.set_defaults(run=cmd_status)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.run(args)
    except Refused as reason:
        print(f'REFUSED: {reason}', file=sys.stderr)
        return REFUSED
    except NotReady as reason:
        print(f'NOT READY: {reason}', file=sys.stderr)
        return NOT_READY
    except AlreadyClaimed as reason:
        print(f'ALREADY CLAIMED: {reason}', file=sys.stderr)
        return CLAIMED
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
        return REFUSED


if __name__ == '__main__':
    sys.exit(main())
