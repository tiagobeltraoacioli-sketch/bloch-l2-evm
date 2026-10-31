#!/usr/bin/env python3
"""Build signed EIP-1559 transactions for gas-heavy L2 benchmark blocks (throwaway key, private use only).

Every scenario is a contract-creation transaction whose init code runs a loop until the transaction's gas is
nearly spent, then stops, so state changes persist and the block reports real gas. `sign-tx` of the producer only
builds transfers and withdrawals, so this is a stand-alone signer: pure Python secp256k1 and Keccak.

  heavy_gen.py SCENARIO --key FILE --out DIR [--block-gas N] [--txs N] [--nonce N] [--chain-id N]
  heavy_gen.py list
  heavy_gen.py address --key FILE
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets

# --- Keccak-256 -------------------------------------------------------------------------------------------------
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x + 4) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & _M) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak(data):
    rate = 136
    data = bytes(data) + b'\x01' + b'\0' * ((rate - (len(data) + 1) % rate) % rate)
    data = data[:-1] + bytes([data[-1] | 0x80])
    a = [[0] * 5 for _ in range(5)]
    for i in range(0, len(data), rate):
        block = data[i:i + rate]
        for j in range(rate // 8):
            a[j % 5][j // 5] ^= int.from_bytes(block[j * 8:j * 8 + 8], 'little')
        a = _f(a)
    return b''.join(a[j % 5][j // 5].to_bytes(8, 'little') for j in range(4))


# --- secp256k1 --------------------------------------------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    s = (3 * p[0] * p[0] * pow(2 * p[1], -1, P)) % P if p == q else ((q[1] - p[1]) * pow(q[0] - p[0], -1, P)) % P
    x = (s * s - p[0] - q[0]) % P
    return x, (s * (p[0] - x) - p[1]) % P


def _mul(k):
    r, a = None, G
    while k:
        if k & 1:
            r = _add(r, a)
        a = _add(a, a)
        k >>= 1
    return r


def address(key):
    x, y = _mul(key)
    return keccak(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))[12:]


def sign(key, digest):
    z = int.from_bytes(digest, 'big')
    while True:
        k = secrets.randbelow(N - 1) + 1
        x, y = _mul(k)
        r = x % N
        s = pow(k, -1, N) * (z + r * key) % N
        if r and s:
            v = y & 1
            if s > N // 2:
                s, v = N - s, v ^ 1
            return v, r, s


# --- RLP / transaction ------------------------------------------------------------------------------------------
def _ilen(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''


def rlp(item):
    if isinstance(item, int):
        item = _ilen(item)
    if isinstance(item, (bytes, bytearray)):
        if len(item) == 1 and item[0] < 0x80:
            return bytes(item)
        return _prefix(len(item), 0x80) + bytes(item)
    body = b''.join(rlp(x) for x in item)
    return _prefix(len(body), 0xc0) + body


def _prefix(size, base):
    if size < 56:
        return bytes([base + size])
    s = _ilen(size)
    return bytes([base + 55 + len(s)]) + s


def tx(key, chain_id, nonce, gas, to, value, data, max_fee=2_000_000_000, tip=1):
    fields = [chain_id, nonce, tip, max_fee, gas, to, value, data, []]
    v, r, s = sign(key, keccak(b'\x02' + rlp(fields)))
    return b'\x02' + rlp(fields + [v, r, s])


# --- EVM assembler ----------------------------------------------------------------------------------------------
OPS = dict(STOP=0, ADD=1, MUL=2, SUB=3, DIV=4, MOD=6, ADDMOD=8, MULMOD=9, EXP=0xa, LT=0x10, GT=0x11, EQ=0x14,
           ISZERO=0x15, NOT=0x19, KECCAK=0x20, ADDRESS=0x30, BALANCE=0x31, CALLER=0x33, CALLVALUE=0x34, CODECOPY=0x39,
           EXTCODESIZE=0x3b, EXTCODEHASH=0x3f, RETURNDATASIZE=0x3d, POP=0x50, MLOAD=0x51, MSTORE=0x52, MSTORE8=0x53,
           SLOAD=0x54, SSTORE=0x55, JUMP=0x56, JUMPI=0x57, PC=0x58, MSIZE=0x59, GAS=0x5a, JUMPDEST=0x5b, TSTORE=0x5d,
           MCOPY=0x5e, PUSH0=0x5f, DUP1=0x80, DUP2=0x81, DUP3=0x82, DUP4=0x83, DUP6=0x85, SWAP1=0x90, SWAP2=0x91, SWAP3=0x92,
           LOG0=0xa0, LOG1=0xa1, CREATE=0xf0, CALL=0xf1, RETURN=0xf3, STATICCALL=0xfa, REVERT=0xfd, CREATE2=0xf5)


def push(n):
    if isinstance(n, (bytes, bytearray)):
        return bytes([0x5f + len(n)]) + bytes(n) if n else b'\x5f'
    b = _ilen(n)
    return bytes([0x5f + len(b)]) + b if b else b'\x5f'


def asm(*parts):
    out = b''
    for p in parts:
        if isinstance(p, str):
            out += bytes([OPS[p]])
        elif isinstance(p, int):
            out += push(p)
        else:
            out += p
    return out


def loop(body, reserve=60_000, prelude=b''):
    """prelude; do { body } while gas() > reserve; stop."""
    head = prelude + asm('JUMPDEST')
    start = len(prelude)
    return head + body + asm(reserve, 'GAS', 'GT', push(start), 'JUMPI', 'STOP')


def mstore_blob(blob, at=0):
    """Write blob to memory at `at` (32-byte words, right-padded)."""
    out = b''
    for i in range(0, len(blob), 32):
        word = blob[i:i + 32].ljust(32, b'\0')
        out += push(word) + push(at + i) + bytes([OPS['MSTORE']])
    return out


def call_precompile(addr, in_size, out_at, out_size, gas=None):
    """STATICCALL addr(mem[0:in_size]) -> mem[out_at:out_size], popped."""
    return asm(out_size, out_at, in_size, 0, addr, gas if gas is not None else asm('GAS'), 'STATICCALL', 'POP')


BN_G1 = (1).to_bytes(32, 'big') + (2).to_bytes(32, 'big')
BN_G2 = bytes.fromhex(
    '198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2'
    '1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed'
    '090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b'
    '12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa')
BLS_G1 = bytes.fromhex('97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58'
                       '6c55e83ff97a1aeffb3af00adb22c6bb')
BLAKE_IV = bytes.fromhex('48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5'
                         'd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b')


def modexp_input(base_len, exp, mod_len):
    mod = (b'\xff' * mod_len)
    base = (b'\xfe' * base_len)
    return ((base_len).to_bytes(32, 'big') + len(exp).to_bytes(32, 'big') + mod_len.to_bytes(32, 'big') + base + exp + mod)


def memory_blob_call(addr, blob, out_size=32, gas=None):
    return loop(call_precompile(addr, len(blob), len(blob) + 64, out_size, gas), prelude=mstore_blob(blob))


# Scenario: name -> init code. Slot counter on the stack: DUP1 DUP1 SSTORE (slot i = i) then +1.
def code_sstore_fresh(start=1):
    return loop(asm('DUP1', 'DUP1', 'SSTORE', 1, 'ADD'), prelude=push(start))


def code_sstore_keccak():
    # Spread slots over the trie: slot = keccak(counter). Same trie cost as mappings.
    return loop(asm('DUP1', 0, 'MSTORE', 32, 0, 'KECCAK', 'DUP2', 'SWAP1', 'SSTORE', 1, 'ADD'), prelude=push(1))


def code_sload_cold():
    return loop(asm('DUP1', 'SLOAD', 'POP', 1, 'ADD'), prelude=push(1))


def code_balance_cold():
    return loop(asm('DUP1', 'BALANCE', 'POP', 1, 'ADD'), prelude=push(0x10000))


def code_extcodehash_cold():
    return loop(asm('DUP1', 0, 'MSTORE', 32, 0, 'KECCAK', 'EXTCODEHASH', 'POP', 1, 'ADD'), prelude=push(0x10000))


def code_keccak_mem(size=4096):
    return loop(asm(size, 0, 'KECCAK', 'POP'), prelude=asm(1, size, 'MSTORE8'))


def code_keccak_short():
    return loop(asm(32, 0, 'KECCAK', 'POP'))


def code_mulmod():
    m = (2**256 - 189).to_bytes(32, 'big')
    a = (2**255 - 19).to_bytes(32, 'big')
    # 8 + 3*3 gas per round plus loop overhead; unroll for less loop overhead.
    body = (push(m) + push(a) + push(a) + bytes([OPS['MULMOD'], OPS['POP']])) * 50
    return loop(body)


def code_exp():
    a = (2**255 - 19).to_bytes(32, 'big')
    body = (push(a) + push(a) + bytes([OPS['EXP'], OPS['POP']])) * 20
    return loop(body)


def code_jumps():
    # Cheapest control flow: interpreter dispatch and jump-table lookups.
    return loop(asm('JUMPDEST') * 200)


def code_mcopy(words=1024):
    return loop(asm(words * 32, 0, words * 32, 'MCOPY'), prelude=asm(1, words * 64, 'MSTORE8'))


def code_mstore_growth():
    return loop(asm('MSIZE', 'DUP1', 'MSTORE'))


def code_log(size=1024):
    return loop(asm(size, 0, 'LOG0'), prelude=asm(1, size, 'MSTORE8'))


def code_create_small():
    # CREATE with empty init code: account creation and keccak of RLP(sender, nonce).
    return loop(asm(0, 0, 0, 'CREATE', 'POP'))


def code_deploy_code(size=512):
    # init: return `size` zero bytes as runtime... forbidden-free since first byte is STOP.
    init = asm(size, 0, 'RETURN')
    return loop(asm(len(init), 0, 0, 'CREATE', 'POP'), prelude=mstore_blob(init), reserve=300_000)


def code_selfcall():
    # Nested frame churn: CALL a tiny runtime (STOP-free) deployed first in the same transaction.
    init = asm(1, 0, 'RETURN')  # returns one zero byte: runtime STOP
    prelude = mstore_blob(init) + asm(len(init), 0, 0, 'CREATE')
    body = asm(0, 0, 0, 0, 0, 'DUP6', 'GAS', 'CALL', 'POP')
    return loop(body, prelude=prelude)


def code_call_depth():
    # Recursion to the 63/64 depth limit: runtime calls itself with all gas; repeated to spend the block gas.
    runtime = asm(0, 0, 0, 0, 0, 'ADDRESS', 'GAS', 'CALL', 'STOP')
    init = push(len(runtime)) + b'\x80' + b'\x60\x09' + b'\x5f\x39\x5f\xf3' + runtime
    prelude = mstore_blob(init) + asm(len(init), 0, 0, 'CREATE')
    body = asm(0, 0, 0, 0, 0, 'DUP6', 'GAS', 'CALL', 'POP')
    return loop(body, prelude=prelude, reserve=100_000)


def scenarios():
    pair = BN_G1 + BN_G2
    versioned = b'\x01' + hashlib.sha256(BLS_G1).digest()[1:]
    kzg = versioned + (1).to_bytes(32, 'big') + (1).to_bytes(32, 'big') + BLS_G1 + BLS_G1
    blake = lambda rounds: rounds.to_bytes(4, 'big') + BLAKE_IV + b'\xab' * 128 + b'\0' * 16 + b'\x01'
    return {
        'sstore-fresh': code_sstore_fresh(),
        'sstore-keccak': code_sstore_keccak(),
        'sload-cold': code_sload_cold(),
        'balance-cold': code_balance_cold(),
        'extcodehash-cold': code_extcodehash_cold(),
        'keccak-4k': code_keccak_mem(),
        'keccak-32': code_keccak_short(),
        'mulmod': code_mulmod(),
        'exp': code_exp(),
        'jumpdest': code_jumps(),
        'mcopy': code_mcopy(),
        'mstore-growth': code_mstore_growth(),
        'log-1k': code_log(),
        'create-empty': code_create_small(),
        'deploy-512': code_deploy_code(),
        'call-frame': code_selfcall(),
        'call-depth': code_call_depth(),
        'pc-ecrecover': memory_blob_call(1, bytes.fromhex(
            '456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3'
            '000000000000000000000000000000000000000000000000000000000000001c'
            '9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608'
            '4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada'), 32),
        'pc-sha256-1k': memory_blob_call(2, b'\xab' * 1024),
        'pc-sha256-64': memory_blob_call(2, b'\xab' * 64),
        'pc-ripemd-1k': memory_blob_call(3, b'\xab' * 1024),
        'pc-ripemd-64': memory_blob_call(3, b'\xab' * 64),
        'pc-identity-4k': memory_blob_call(4, b'\xab' * 4096, 4096),
        'pc-modexp-512b': memory_blob_call(5, modexp_input(64, b'\xff' * 32, 64), 64),
        'pc-modexp-1kb': memory_blob_call(5, modexp_input(128, b'\xff' * 32, 128), 128),
        'pc-modexp-small': memory_blob_call(5, modexp_input(32, b'\xff' * 3, 32), 32),
        'pc-bnadd': memory_blob_call(6, BN_G1 + BN_G1, 64),
        'pc-bnmul': memory_blob_call(7, BN_G1 + (b'\xff' * 31 + b'\x00'), 64),
        'pc-bnpair': memory_blob_call(8, pair, 32),
        'pc-blake2f': loop(call_precompile(9, 213, 256, 64), prelude=mstore_blob(blake(1_000_000))),
        'pc-blake2f-12': loop(call_precompile(9, 213, 256, 64), prelude=mstore_blob(blake(12))),
        'pc-blake2f-100k': loop(call_precompile(9, 213, 256, 64), prelude=mstore_blob(blake(100_000))),
        'pc-modexp-64-2b': memory_blob_call(5, modexp_input(64, b'\xff\xff', 64), 64),
        'pc-modexp-32-5b': memory_blob_call(5, modexp_input(32, b'\xff' * 5, 32), 32),
        'pc-kzg': memory_blob_call(0x0a, kzg, 64, 50_000),
    }


def calldata_txs(key, chain_id, nonce, txs, total_bytes):
    """Plain CALL to an empty address with random calldata; nonzero bytes (16 gas each)."""
    each = total_bytes // txs - 120
    out = []
    for i in range(txs):
        data = os.urandom(each)
        data = bytes(b or 1 for b in data)
        out.append(tx(key, chain_id, nonce + i, 21_000 + 16 * each + 1000, (0x2000 + i).to_bytes(20, 'big'), 1, data))
    return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument('scenario')
    a.add_argument('--key')
    a.add_argument('--out')
    a.add_argument('--block-gas', type=int, default=15_000_000)
    a.add_argument('--txs', type=int, default=1)
    a.add_argument('--nonce', type=int, default=0)
    a.add_argument('--chain-id', type=int, default=700770)
    a.add_argument('--bytes', type=int, default=114_000)
    o = a.parse_args()
    if o.scenario == 'list':
        print('\n'.join(list(scenarios()) + ['calldata']))
        return
    key = int(Path(o.key).read_text().strip(), 16)
    if o.scenario == 'address':
        print(address(key).hex())
        return
    if o.scenario == 'calldata':
        raws = calldata_txs(key, o.chain_id, o.nonce, o.txs, o.bytes)
    else:
        code = scenarios()[o.scenario]
        gas = o.block_gas // o.txs
        raws = [tx(key, o.chain_id, o.nonce + i, gas, b'', 0, code) for i in range(o.txs)]
    out = Path(o.out)
    out.mkdir(parents=True, exist_ok=True)
    for i, raw in enumerate(raws):
        (out / f'{o.nonce + i:05d}.tx').write_text(raw.hex() + '\n')
    print(f'{len(raws)} txs, {sum(map(len, raws))} bytes')


if __name__ == '__main__':
    main()
