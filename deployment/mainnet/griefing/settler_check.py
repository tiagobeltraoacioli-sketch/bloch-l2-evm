#!/usr/bin/env python3
"""The settler's block plan with real binaries, no proof and no L1: real producer, real guest in execute mode, a private
database, throwaway keys. Checks the path griefsim.py does not: `select`, `extend`, `export`, the host's execute output, the
spool files and the quarantine directory. Environment: SC_WORK (scratch), SC_PRODUCE, SC_HOST, SC_GUEST, SC_ANCHOR (file: anchor
hash and slot), SC_SOURCE (file: native request prefix), SC_BYTECODE, SC_LIB (dir of settler_v3.py, sequencer_policy.py, heavy_gen.py)."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, os.environ['SC_LIB'])
import heavy_gen as g  # noqa: E402
import settler_v3 as S  # noqa: E402

W = Path(os.environ['SC_WORK'])
shutil.rmtree(W, ignore_errors=True)
(W / 'txpool').mkdir(parents=True)
(W / 'work').mkdir()
(W / 'home/tmp').mkdir(parents=True)
BC = json.load(open(os.environ['SC_BYTECODE']))
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
CHAIN = 700770
anchor, slot = Path(os.environ['SC_ANCHOR']).read_text().split()
source = Path(os.environ['SC_SOURCE']).read_text()
BUDGET = int(os.environ.get('SC_BUDGET', '30000000'))

s = S.Settler.__new__(S.Settler)
s.c = {'produce': os.environ['SC_PRODUCE'], 'l2_db': str(W / 'db'), 'txpool_dir': str(W / 'txpool'), 'workdir': str(W / 'work'), 'home': str(W / 'home'),
       'user_transactions': True, 'timestamp_rule': '1:1786656679:30000', 'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 128,
       'prover': os.environ['SC_HOST'], 'guest': os.environ['SC_GUEST'], 'max_block_sp1_gas': BUDGET, 'preflight_execute_seconds': 120,
       'min_tip_wei': 100_000_000, 'max_tx_gas': 5_000_000, 'preflight_max_runs': 16, 'preflight_max_seconds': 600, 'strike_cooldown_blocks': 4}
s.run = subprocess.run
s.work = W / 'work'
s.clock = __import__('time').monotonic
s.network_args = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
s.prover_args = ['--mainnet']
s.produce('init', '--target', s.c['l2_db'])

head = s.produce('head', '--target', s.c['l2_db'])['hash']
number, consumed, dep_h = 0, 0, 1
checks = []


def check(name, ok, **fields):
    checks.append(ok)
    print(json.dumps({'check': name, 'ok': bool(ok), **fields}), flush=True)


def dep(recipient, sats=1_000_000):
    global dep_h
    dep_h += 1
    return {'height': dep_h, 'tx_index': 1, 'txid': f'{dep_h:064x}', 'vout': 1, 'sats': sats, 'recipient': recipient.hex()}


def block(deposits=()):
    global number, head, consumed
    number += 1
    d = W / 'work' / f'{number:08d}'
    d.mkdir()
    (d / 'deposits.json').write_text(json.dumps(list(deposits)))
    before = consumed
    consumed += len(deposits)
    s.preflight_source = source + 'cd' * 32 + f'\n{consumed}\n{before}\n{consumed}\n'
    b = s.extend_within_budget(head, anchor, d / 'deposits.json', slot, number)
    head = b['hash']
    return b, d


def spool(name, raw):
    (W / 'txpool' / f'{name}.tx').write_text(raw.hex() + '\n')


def quarantined_hopeful():
    return 'hopeful' in quarantined()


def names():
    return sorted(p.stem for p in (W / 'txpool').glob('*.tx'))


def quarantined():
    q = W / 'txpool-quarantine'
    return sorted(p.stem for p in q.glob('*.tx')) if q.exists() else []


attacker, honest = 0x1234567 | (1 << 200), 0x7654321 | (1 << 201)
A, H = g.address(attacker), g.address(honest)
nonce = {attacker: 0, honest: 0}


def tx(key, to, data, gas, value=0, tip=10**9):
    raw = g.tx(key, CHAIN, nonce[key], gas, to, value, data, max_fee=4 * 10**9, tip=tip)
    nonce[key] += 1
    return raw


b, _ = block([dep(A, 100_000_000_000), dep(H, 1_000_000_000)])
check('deposits only, under budget', b['deposits'] == 2 and b['transactions'] == 0)

griefer = g.keccak(g.rlp([A, 0]))[12:]
spool('deploy', tx(attacker, b'', bytes.fromhex(BC['Griefer']), 2_000_000))
b, _ = block()
check('deployment included, spool emptied, stats reported', b['transactions'] == 1 and not names() and b['tx_stats'][0]['sender'] == A.hex(), stats=b['tx_stats'])


def fill(count):
    return tx(attacker, griefer, g.keccak(b'fillRaw(uint256)')[:4] + count.to_bytes(32, 'big'), 24_000 * count + 60_000)


spool('fill', fill(180))
b, _ = block()
fresh = sum(n for _, n in b['tx_stats'][0]['fresh_slots'])
check('fresh slots of a real write', fresh == 181, fresh=fresh, stats=b['tx_stats'])

spool('low', tx(honest, A, b'', 21_000, value=1, tip=1))
spool('fine', tx(attacker, A, b'', 21_000, value=1))
b, _ = block()
check('a tip below the floor waits in the spool', names() == ['low'] and b['transactions'] == 1, spool=names())
(W / 'txpool' / 'low.tx').unlink()
nonce[honest] = 0

code = g.scenarios()['pc-modexp-512b']
spool('evil-large', tx(honest, b'', code, 14_000_000))
spool('fine2', tx(attacker, A, b'', 21_000, value=1))
b, _ = block()
check('a 14M-gas modexp transaction is quarantined by the gas cap, and the other is included', quarantined() == ['evil-large'] and b['transactions'] == 1 and not names(), quarantine=quarantined())
nonce[honest] = 0

spool('evil-small', tx(honest, b'', code, 4_900_000))
spool('fine3', tx(attacker, A, b'', 21_000, value=1))
b, _ = block()
check('a transaction within the gas cap and over the budget is quarantined by measurement, and the other is included',
      'evil-small' in quarantined() and b['transactions'] == 1 and not names(), quarantine=quarantined())
nonce[honest] = 0

# One contract cannot pass the budget: the transaction growing it touches it too. Grow two, then deposit to both.
def fill_to(target):
    grown = 0
    while True:
        raw = tx(attacker, target, g.keccak(b'fillRaw(uint256)')[:4] + (200).to_bytes(32, 'big'), 24_000 * 200 + 60_000)
        spool('fill', raw)
        b, _ = block()
        if not b['transactions']:
            for p in (W / 'txpool').glob('*.tx'):
                p.unlink()
            nonce[attacker] = int(s.produce('account', '--target', s.c['l2_db'], '--address', A.hex())['nonce'])
            for _ in range(5):  # the strike's cooldown
                block()
            return grown
        grown += 200


grown = fill_to(griefer)
second = g.keccak(g.rlp([A, nonce[attacker]]))[12:]
spool('deploy2', tx(attacker, b'', bytes.fromhex(BC['Griefer']), 2_000_000))
block()
check('second contract deployed after the cooldown', not names())
grown2 = fill_to(second)
print(json.dumps({'grown': [grown, grown2]}), flush=True)

spool('hopeful', tx(honest, A, b'', 21_000, value=1))
b, d = block([dep(griefer), dep(second)])
written = json.loads((d / 'deposits-over-budget.json').read_text()) if (d / 'deposits-over-budget.json').exists() else None
check('deposits over the budget commit alone, with a record; the transaction waits', b['deposits'] == 2 and b['transactions'] == 0 and written and written['sp1_gas'] > BUDGET and names() == ['hopeful'] and not quarantined_hopeful(), record=written, spool=names())

b, d = block()
check('the next block is normal: the transaction that waited goes in', b['transactions'] == 1 and not names(), transactions=b['transactions'])

print(json.dumps({'passed': sum(bool(c) for c in checks), 'of': len(checks)}), flush=True)
sys.exit(0 if all(checks) else 1)
