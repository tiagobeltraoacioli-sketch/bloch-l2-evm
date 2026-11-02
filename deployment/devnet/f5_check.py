#!/usr/bin/env python3
"""Review r7 F5 with real binaries, execute only: the real producer (`bloch-l2-produce-dev`, mainnet rules) on a private
database, throwaway keys, the settler's `spool_demand` and `hold_block`. No L1, no proof, no network port: L1 is two
stubs (the source age and the inbox backlog), the accepted head is the local head.

Each check states what the producer did and what the idle check said. The producer is the judge: an entry the idle check
calls demand must be one the next real block includes or prunes, and an entry it calls idle must be one the next real
block leaves in the spool.

Environment: F5_WORK (scratch, removed first), F5_PRODUCE (binary), F5_LIB (dir of settler_v3.py and test_settler_f5.py).
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ['F5_LIB'])
import settler_v3 as S  # noqa: E402
import test_settler_f5 as T  # noqa: E402

W = Path(os.environ['F5_WORK'])
shutil.rmtree(W, ignore_errors=True)
POOL = W / 'txpool'
POOL.mkdir(parents=True)
(W / 'work').mkdir()
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
GENESIS_TIME = 1786656679
RULE = f'1:{GENESIS_TIME}:30000'
CHAIN = 700770
ANCHOR = 'cd' * 32
logged = []
S.log = lambda event, **fields: logged.append((event, fields))

s = S.Settler.__new__(S.Settler)
s.c = {'produce': os.environ['F5_PRODUCE'], 'l2_db': str(W / 'db'), 'txpool_dir': str(POOL), 'user_transactions': True,
       'timestamp_rule': RULE, 'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 128,
       'min_tip_wei': 100_000_000, 'skip_idle_blocks': True, 'max_idle_seconds': 3000, 'min_block_interval_seconds': 0}
s.run = __import__('subprocess').run
s.network_args = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', str(GENESIS_TIME)]
s.spool_open, s.holding_since, s.hold_logged_at = True, None, None
s.clock = time.monotonic
s.c['l2_genesis'] = s.produce('init', '--target', s.c['l2_db'])['hash']
age = {'seconds': 30}
s.source_age = lambda view: age['seconds']  # L1 stub: a fresh source
s.inbox_backlog = lambda: 0  # L1 stub: no deposit waiting
S.statement_fields = lambda statement: {'l2_hash': statement}  # the accepted head is the local head

checks, slot, deposit_height = [], 1000, 0


def check(name, ok, **fields):
    checks.append(bool(ok))
    print(json.dumps({'check': name, 'ok': bool(ok), **fields}), flush=True)


def head():
    return s.produce('head', '--target', s.c['l2_db'])['hash']


def view():
    return {'accepted': {'statement': head()}, 'source': {'pending': []}}


def held_cycles(cycles=5):
    return sum(bool(s.hold_block(view())) for _ in range(cycles))


def block(deposits=(), spool=True):
    """One real block on the local head, with the settler's own producer arguments."""
    global slot
    slot += 1
    path = W / 'work' / f'deposits-{slot}.json'
    path.write_text(json.dumps(list(deposits)))
    return s.produce(*s.extend_arguments(head(), ANCHOR, path, slot, spool=spool))


def deposit(recipient, sats=10_000_000):
    global deposit_height
    deposit_height += 1
    return {'height': deposit_height, 'tx_index': 1, 'txid': f'{deposit_height:064x}', 'vout': 1, 'sats': sats,
            'recipient': recipient.hex()}


def key_file(name):
    path = W / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(secrets.token_hex(32))
    return path


def sign(key, nonce, name):
    out = W / 'work' / f'{name}.signed'
    report = s.produce('sign-tx', '--key', str(key), '--nonce', str(nonce), '--to', '35' * 20, '--value-wei', '1',
                       '--out', str(out))
    (POOL / f'{name}.tx').write_text(out.read_text())
    return report


def spooled():
    return sorted(p.stem for p in POOL.glob('*.tx'))


# Two throwaway keys: A signs with the producer (type 2), B with the test signer (legacy, EIP-155), funded by deposits.
key_a = key_file('throwaway-a.hex')
addr_a = bytes.fromhex(s.produce('address', '--key', str(key_a))['address'])
key_b = secrets.randbelow(S.SECP_N - 1) + 1
addr_b = T.address(key_b)
funded = block([deposit(addr_a), deposit(addr_b)], spool=False)
check('funding block', funded['number'] == 1 and funded['deposits'] == 2, block=funded)

# 1. Agent 121's case: one nonce gap.
report = sign(key_a, 3, 'a3')
raw = bytes.fromhex((POOL / 'a3.tx').read_text().strip())
recovered = S.spooled_sender_nonce(raw)
check('the producer-signed sender reads back', recovered == (addr_a, 3), producer_from=report['from'],
      read=[recovered[0].hex(), recovered[1]] if recovered else None)
check('nonce gap: not demand', s.spool_demand(head()) is False)
check('nonce gap: 5 of 5 cycles held', held_cycles() == 5)
forced = block()
check('nonce gap: the producer leaves it in the spool', forced['transactions'] == 0 and spooled() == ['a3']
      and [d['reason'] for d in forced['deferred']] == ['nonce-gap'], deferred=forced['deferred'])
check('nonce gap: still not demand on the new head', held_cycles() == 5)

# 2. The next nonce is demand, and the producer includes exactly it.
sign(key_a, 0, 'a0')
check('next nonce: demand', s.spool_demand(head()) is True and s.hold_block(view()) is False)
built = block()
check('next nonce: the producer includes it, the gap stays', built['transactions'] == 1 and spooled() == ['a3'],
      included=built['included'], spool=spooled())
check('after it: 5 of 5 cycles held', held_cycles() == 5)

# 3. Filling the gap makes the chain due again and empties the spool.
sign(key_a, 1, 'a1')
sign(key_a, 2, 'a2')
check('gap filled: demand', s.hold_block(view()) is False)
built = block()
check('gap filled: the producer includes 1, 2 and 3', built['transactions'] == 3 and spooled() == [], included=built['included'])
check('empty spool: held', held_cycles() == 5)

# 4. A legacy EIP-155 transaction signed outside the producer: gap idle, next nonce demand, both as the producer decides.
(POOL / 'b2.tx').write_text(T.legacy(key_b, 2, chain=CHAIN).hex() + '\n')
check('legacy gap: held', held_cycles() == 5)
(POOL / 'b0.tx').write_text(T.legacy(key_b, 0, chain=CHAIN).hex() + '\n')
check('legacy next nonce: demand', s.hold_block(view()) is False)
built = block()
check('legacy: the producer includes nonce 0 and defers nonce 2', built['transactions'] == 1 and spooled() == ['b2']
      and [d['reason'] for d in built['deferred']] == ['nonce-gap'], built=built)

# 5. A used nonce is idle; bytes that do not read are demand, and the producer prunes them.
(POOL / 'b0again.tx').write_text(T.legacy(key_b, 0, chain=CHAIN, gas_price=3_000_000_000).hex() + '\n')
check('used nonce: held', held_cycles() == 5)
(POOL / 'junk.tx').write_text('00\n')
check('junk: demand', s.hold_block(view()) is False)
built = block()
check('junk: the producer drops it and the used nonce, and keeps the gap', spooled() == ['b2'], dropped=built['dropped'])
check('after the prune: held', held_cycles() == 5)

# 6. Cost of the check: 16 gapped entries for each of 16 fresh senders (256 files), cold and cached.
for n in range(16):
    key = secrets.randbelow(S.SECP_N - 1) + 1
    for nonce in range(1, 17):
        (POOL / f'g{n:02d}-{nonce:02d}.tx').write_text(T.eip1559(key, nonce, chain=CHAIN).hex() + '\n')
started = time.monotonic()
cold = s.spool_demand(head())
cold_seconds = time.monotonic() - started
started = time.monotonic()
warm = s.spool_demand(head())
warm_seconds = time.monotonic() - started
check('257 gapped entries: not demand, cold and cached', cold is False and warm is False,
      cold_seconds=round(cold_seconds, 2), cached_seconds=round(warm_seconds, 3), files=len(spooled()))
built = block()
check('257 gapped entries: the producer includes none', built['transactions'] == 0 and len(spooled()) == 257,
      deferred=len(built['deferred']))
check('no spool-demand-unknown event', not [e for e in logged if e[0] == 'spool-demand-unknown'])

print(json.dumps({'passed': sum(checks), 'of': len(checks)}), flush=True)
sys.exit(0 if all(checks) else 1)
