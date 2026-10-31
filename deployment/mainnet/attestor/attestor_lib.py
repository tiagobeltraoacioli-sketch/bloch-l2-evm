# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared pins and hashing for the Bloch L2 MAINNET attestor agent and the claim aggregator.

Standard library only. Every hash here mirrors native code at bloch-sis-pow 78b7343a / dd287b6c
(bloch-pos-committee l2_settlement::withdrawal): the leaf, the Merkle tree, the attestor-set
hash and the attestation digest. The round-trip test checks them against the native binary.
"""
import hashlib
import json
from pathlib import Path

# ---- Pinned mainnet identity (chain 700770, Genesis-4; SETTLER-RUNBOOK.md / sequencer_mainnet.py) ----
CHAIN_ID = 700770
NATIVE_NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
NATIVE_GENESIS = '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415'
MANIFEST_SHA256 = '7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd'
L2_DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L2_GENESIS_TIME = 1786656679
L2_GENESIS_HASH = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
TIMESTAMP_RULE = f'1:{L2_GENESIS_TIME}:30000'
NETWORK_ARGS = ['--rules', 'mainnet', '--domain', L2_DOMAIN, '--genesis-time', str(L2_GENESIS_TIME)]
# The consensus-pinned attestor set (l2_settlement::mainnet::ATTESTOR_SET, 3-of-5 hybrid PQ keys).
SET_HASH = '1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b'
SET_FILE_SHA256 = '9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0'
# Claims of at least 100 BLCH need the attestation (withdrawals.large_claim_sat).
LARGE_CLAIM_SAT = 100 * 100_000_000

TREE_DEPTH = 32
LEAF_DOMAIN = b'BLOCH:L2:WITHDRAW:1'
ATTESTOR_SET_DOMAIN = b'BLOCH:L2:ATTESTOR-SET:1'
ATTESTATION_DOMAIN = b'BLOCH:L2:WITHDRAW-ATTEST:1'
MAX_ATTESTORS = 7
# funded::ADMISSION_PQ_SIGNATURE_MAX: the consensus bound on every attestor signature inside an L2
# claim (4-byte suite header + 3309 ML-DSA-65 + 1280 Falcon-1024). Falcon-1024 signatures are
# variable length, so a valid hybrid signature can reach 4775 bytes; one longer than this bound
# verifies but makes the claim inadmissible. A signer re-signs (fresh randomness) until it fits.
ATTESTOR_SIGNATURE_MAX = 4593
# Bounded re-sign attempts before a signer gives up with an error.
SIGN_FIT_ATTEMPTS = 64


class Pins:
    """The identity an agent or aggregator enforces. Production uses MAINNET; tests build their own."""

    def __init__(self, chain_id, network, genesis, set_hash, manifest_sha256, l2_genesis_hash,
                 network_args, timestamp_rule, large_claim_sat):
        self.chain_id, self.network, self.genesis = chain_id, network, genesis
        self.set_hash, self.manifest_sha256, self.l2_genesis_hash = set_hash, manifest_sha256, l2_genesis_hash
        self.network_args, self.timestamp_rule, self.large_claim_sat = network_args, timestamp_rule, large_claim_sat


MAINNET = Pins(CHAIN_ID, NATIVE_NETWORK, NATIVE_GENESIS, SET_HASH, MANIFEST_SHA256, L2_GENESIS_HASH,
               NETWORK_ARGS, TIMESTAMP_RULE, LARGE_CLAIM_SAT)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


# ---- Keccak-256 (Ethereum padding), dependency-free; same as settler_v3.py ----
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    padded = bytearray(data) + b'\x01'
    padded += b'\x00' * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], 'little')
        state = _keccak_f(state)
    return b''.join(state[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


# ---- Withdrawal tree (l2_settlement::withdrawal) ----
SETTLEMENT_LOG_DOMAIN = b'BLOCH:L2:SETTLEMENT-LOG:1'


def follower_settlements(status, status_path, check_digest=False):
    """Every finalized settlement of a follower status, oldest first: from the list in a v2 status, or from
    the log a v3 status names. Raises ValueError unless the log matches the status. The digest is a keccak
    chain over every line, too slow in pure Python for each cycle, so only check_digest (daily) compares it."""
    schema = status.get('schema')
    if schema == 'bloch.l2.native-follower-status.v2':
        return status.get('finalized_settlements', [])
    if schema != 'bloch.l2.native-follower-status.v3':
        raise ValueError(f'unknown follower status schema {schema!r}')
    log = status['settlement_log']
    name = log['file']
    if not name or '/' in name or name in ('.', '..'):
        raise ValueError('bad settlement log name')
    path = Path(status_path).with_name(name)
    if log['entries'] == 0:
        return []
    with open(path, 'rb') as f:
        data = f.read(log['bytes'])
    if len(data) != log['bytes']:
        raise ValueError('settlement log is shorter than the status says')
    lines = data.splitlines(keepends=True)
    if not data.endswith(b'\n') or len(lines) != log['entries']:
        raise ValueError('settlement log does not match the status')
    if check_digest and settlement_log_digest(lines).hex() != log['digest']:
        raise ValueError('settlement log digest differs from the status')
    entries = [json.loads(line) for line in lines]
    for number, entry in enumerate(entries, 1):
        if entry.get('l2_number') != number:
            raise ValueError('settlement log is not contiguous')
    recent = status.get('finalized_settlements_recent') or []
    if entries[-len(recent):] != recent:
        raise ValueError('settlement log differs from the status')
    return entries


def settlement_log_digest(lines):
    """The digest of a settlement log (each line with its newline), as the follower computes it."""
    digest = keccak256(SETTLEMENT_LOG_DOMAIN)
    for line in lines:
        digest = keccak256(digest + line)
    return digest


def leaf(chain_id, nonce, l1_recipient, sats):
    return keccak256(LEAF_DOMAIN + chain_id.to_bytes(8, 'big') + nonce.to_bytes(8, 'big') + l1_recipient
                     + sats.to_bytes(8, 'big'))


def node(left, right):
    return keccak256(left + right)


def zero_hashes():
    zero = [bytes(32)]
    for _ in range(TREE_DEPTH):
        zero.append(node(zero[-1], zero[-1]))
    return zero


ZERO = zero_hashes()
EMPTY_ROOT = ZERO[TREE_DEPTH]


def tree_root(leaves):
    level = list(leaves)
    if not level:
        return EMPTY_ROOT
    for h in range(TREE_DEPTH):
        level = [node(level[i], level[i + 1] if i + 1 < len(level) else ZERO[h]) for i in range(0, len(level), 2)]
    return level[0]


def tree_proof(leaves, index):
    level, siblings = list(leaves), []
    for h in range(TREE_DEPTH):
        sibling = index ^ 1
        siblings.append(level[sibling] if sibling < len(level) else ZERO[h])
        level = [node(level[i], level[i + 1] if i + 1 < len(level) else ZERO[h]) for i in range(0, len(level), 2)]
        index >>= 1
    return siblings


def root_from_proof(leaf_hash, index, siblings):
    if index >> TREE_DEPTH or len(siblings) != TREE_DEPTH:
        return None
    acc = leaf_hash
    for h, sibling in enumerate(siblings):
        acc = node(sibling, acc) if (index >> h) & 1 else node(acc, sibling)
    return acc


def h32(text, what):
    text = str(text)
    if text.startswith('0x'):
        text = text[2:]
    try:
        value = bytes.fromhex(text)
    except ValueError:
        raise ValueError(f'{what} is not hex') from None
    if len(value) != 32:
        raise ValueError(f'{what} needs 32 bytes')
    return value


def check_proof(doc, chain_id=None):
    """The checks native `parse_proof` makes on a withdrawal-proof document; returns its fields."""
    w = doc['withdrawal']
    index, count = int(doc['index']), int(doc['withdrawal_count'])
    if int(w['nonce']) != index:
        raise ValueError('withdrawal nonce differs from the proof index')
    if chain_id is not None and int(doc['chain_id']) != chain_id:
        raise ValueError(f'proof is for chain {doc["chain_id"]}, not {chain_id}')
    recipient = h32(w['l1_recipient'], 'l1_recipient')
    own_leaf = leaf(int(doc['chain_id']), index, recipient, int(w['sats']))
    if h32(w['leaf'], 'leaf') != own_leaf:
        raise ValueError("the proof's leaf differs from the leaf of its fields")
    siblings = [h32(s, 'sibling') for s in doc['siblings']]
    root = h32(doc['withdrawal_root'], 'withdrawal_root')
    if root_from_proof(own_leaf, index, siblings) != root:
        raise ValueError('the siblings do not prove the leaf against withdrawal_root')
    if index >= count:
        raise ValueError('index is not below withdrawal_count')
    return {'chain_id': int(doc['chain_id']), 'index': index, 'count': count, 'root': root.hex(),
            'sats': int(w['sats']), 'l1_recipient': recipient.hex(), 'leaf': own_leaf.hex(),
            'l2_block': w.get('l2_block'), 'number': doc.get('number')}


# ---- Attestor set and attestation digest ----
def read_set(path):
    """`(threshold, keys)` of an `l2-claim attestor-set` file (threshold line, one hex key per line)."""
    lines = [line.strip() for line in Path(path).read_text().splitlines() if line.strip()]
    threshold, keys = int(lines[0]), [bytes.fromhex(line) for line in lines[1:]]
    if not (1 <= threshold <= len(keys) <= MAX_ATTESTORS) or len(set(keys)) != len(keys):
        raise ValueError('malformed attestor set')
    return threshold, keys


def set_hash(threshold, keys):
    return hashlib.sha3_256(ATTESTOR_SET_DOMAIN + bytes([threshold, len(keys)]) + b''.join(keys)).hexdigest()


def attestation_digest(network_hex, chain_id, root_hex):
    return hashlib.sha3_256(ATTESTATION_DOMAIN + bytes.fromhex(network_hex) + chain_id.to_bytes(8, 'big')
                            + bytes.fromhex(root_hex)).hexdigest()


class OversizedSignature(ValueError):
    """A well-formed partial whose signature exceeds ATTESTOR_SIGNATURE_MAX (re-sign it)."""


def parse_partial(text):
    """`(signer index, digest hex, signature hex)` of an `l2-claim attest` partial (3 hex lines).

    Raises OversizedSignature if the signature is longer than the claim admits."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 3:
        raise ValueError('a partial has exactly 3 lines')
    index, digest, signature = int(lines[0]), lines[1].lower(), lines[2].lower()
    bytes.fromhex(signature)
    if len(bytes.fromhex(digest)) != 32 or not 0 <= index < MAX_ATTESTORS or not 2000 <= len(signature) // 2 <= 20000:
        raise ValueError('malformed partial')
    if len(signature) // 2 > ATTESTOR_SIGNATURE_MAX:
        raise OversizedSignature(f'signature is {len(signature) // 2} bytes; a claim admits at most '
                                 f'{ATTESTOR_SIGNATURE_MAX} (re-sign)')
    return index, digest, signature


def partial_relpath(chain_id, root_hex, index):
    """Where every drop (agent outbox, HTTP, shared directory) keeps a partial."""
    return f'{chain_id}/{root_hex}/attestor-{index}.partial'


def claimed(claimed_view, index):
    """Is withdrawal `index` claimed per a getl2settlement `withdrawals.claimed` frontier?"""
    word = index // 256
    if word < int(claimed_view.get('floor', 0)):
        return True
    for entry in claimed_view.get('words', []):
        if int(entry['word']) == word:
            bits = bytes.fromhex(entry['bits'])
            byte, bit = (index % 256) // 8, index % 8
            return byte < len(bits) and bool(bits[byte] >> bit & 1)
    return False
