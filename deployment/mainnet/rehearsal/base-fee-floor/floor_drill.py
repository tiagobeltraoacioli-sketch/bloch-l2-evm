#!/usr/bin/env python3
"""F387-1 (round 19): the RELEASE producer extends two chains across the base-fee floor, and the December guests
EXECUTE (SP1 executor, no proof) the blocks at the floor from the artifacts the producer exports.

usage: floor_drill.py RELEASE_DIR HOST_BIN SPARSE_ELF FALLBACK_ELF V1_SPARSE_ELF OUT_DIR
No network, no key, no proof. Writes OUT_DIR/result.json; exit 0 only if every step did what it must."""
import json, os, subprocess, sys
from pathlib import Path

release, host, sparse_elf, fallback_elf, v1_elf, out = sys.argv[1:]
out = Path(out); out.mkdir(parents=True)
P = str(Path(release) / 'bloch-l2-produce-dev')
NET = ['--rules', 'mainnet', '--domain', '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
       '--genesis-time', '1786656679']
RULE = '1:1786656679:30000'
FLOOR = 100_000_000
log = open(out / 'drill.log', 'w')


def produce(*args, ok=True):
    r = subprocess.run([P, *map(str, args), *NET], capture_output=True, text=True)
    if ok and r.returncode != 0:
        raise SystemExit(f'producer {args[:1]} failed: {r.stderr[:300]}')
    return json.loads(r.stdout) if r.returncode == 0 else r.stderr


def anchor(n):
    return (b'\xa5' * 24 + n.to_bytes(8, 'big')).hex()


class Chain:
    def __init__(self, name):
        self.dir = out / name; self.dir.mkdir()
        self.db = str(self.dir / 'db')
        self.parent = produce('init', '--target', self.db)['hash']
        self.fees_log = open(self.dir / 'fees.jsonl', 'w')

    def fees(self):
        f = produce('fees', '--target', self.db)
        self.fees_log.write(json.dumps(f, sort_keys=True) + '\n')
        return f

    def extend(self, n, rule_set=None):
        args = ['extend', '--target', self.db, '--parent', self.parent, '--anchor', anchor(n), '--timestamp-rule', RULE,
                '--anchor-slot', 100 * n]
        if rule_set:
            args += ['--rule-set', rule_set]
        block = produce(*args)
        assert block['number'] == n, block
        self.parent = block['hash']
        return block

    def execute(self, n, flags, elf, witness):
        """Export block n and run the guest on it in the SP1 executor. Returns (exit code, last output lines)."""
        art = self.dir / f'artifact-{n}-{witness}-{len(list(self.dir.glob("artifact-*")))}'
        args = ['export', '--target', self.db, '--number', n, '--out', art]
        if witness == 'sparse':
            args += ['--witness', 'sparse']
        produce(*args)
        req = self.dir / f'request-{n}.txt'
        req.write_text('\n'.join(['11' * 32, '22' * 32, anchor(n), str(100 * n), str(10 + n), '55' * 32, '66' * 32,
                                  '77' * 32 if n > 1 else '00' * 32]))
        env = {**os.environ, 'BLOCH_NATIVE_L2_REQUEST': str(req), 'BLOCH_NATIVE_L2_ARTIFACT': str(art)}
        r = subprocess.run([host, *flags, 'execute', 'native-artifact', elf], capture_output=True, text=True, env=env)
        tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
        log.write(f'execute {self.dir.name} block {n} {flags} {Path(elf).name}: rc={r.returncode}\n' + '\n'.join(tail) + '\n')
        log.flush()
        return r.returncode, tail


result = {'floor': FLOOR, 'steps': []}


def step(name, good, detail):
    result['steps'].append({'step': name, 'ok': bool(good), 'detail': detail})
    print(('PASS ' if good else 'FAIL ') + name, detail, flush=True)


# ---- chain 1: next rules from block 2, across the floor (agent 387's D1 from a fresh genesis) ----
c = Chain('next-from-2')
c.extend(1, 'base'); c.extend(2, 'next')
first = None
f = c.fees()
while True:
    n = f['number'] + 1
    expected = f['next_base_fee']
    if expected == FLOOR and first is None:
        first = n
    c.extend(n)
    f = c.fees()
    assert (f['number'], f['base_fee']) == (n, expected), f
    if first is not None and n >= first + 5:
        break
    assert n < 700
step('chain 1 extends across the floor', f['base_fee'] == FLOOR and f['next_base_fee'] == FLOOR,
     {'first_block_at_floor': first, 'head': f['number'], 'head_base_fee': f['base_fee']})
for n, flags, elf, witness in [(first - 1, ['--mainnet', '--sparse'], sparse_elf, 'sparse'),
                               (first, ['--mainnet', '--sparse'], sparse_elf, 'sparse'),
                               (first + 1, ['--mainnet', '--sparse'], sparse_elf, 'sparse'),
                               (first + 5, ['--mainnet', '--sparse'], sparse_elf, 'sparse'),
                               (first, ['--mainnet'], fallback_elf, 'complete'),
                               (first + 1, ['--mainnet'], fallback_elf, 'complete')]:
    rc, tail = c.execute(n, flags, elf, witness)
    step(f'chain 1 block {n}: guest {Path(elf).name} executes ({witness})', rc == 0, tail[-1:])
rc, tail = c.execute(first, ['--mainnet-v1', '--sparse'], v1_elf, 'sparse')
step(f'chain 1 block {first}: the activated-rules program refuses a next-rules block', rc != 0, tail[-1:])

# ---- chain 2: base rules until the fee is under the floor, then the switch ----
c = Chain('switch-under-floor')
c.extend(1, 'base')
f = c.fees()
while f['base_fee'] >= FLOOR * 98 // 100:
    n = f['number'] + 1
    expected = f['next_base_fee']
    c.extend(n)
    f = c.fees()
    assert (f['number'], f['base_fee'], f['rules']) == (n, expected, 'base'), f
    assert n < 700
under, switch = f['base_fee'], f['number'] + 1
step('chain 2 base fee under the floor before the switch', under < FLOOR and f['next_base_fee_if_switching'] == FLOOR,
     {'head': f['number'], 'base_fee': under, 'next_base_fee': f['next_base_fee']})
c.extend(switch, 'next')
f = c.fees()
step('chain 2 switch block is at the floor', (f['base_fee'], f['rules'], f['next_rules_from']) == (FLOOR, 'next', switch), f)
for n in (switch + 1, switch + 2):
    c.extend(n)
f = c.fees()
step('chain 2 goes on at the floor', (f['number'], f['base_fee']) == (switch + 2, FLOOR), f)
rc, tail = c.execute(switch - 1, ['--mainnet-v1', '--sparse'], v1_elf, 'sparse')
step(f'chain 2 block {switch - 1} (base rules, fee {under}): the activated-rules guest executes', rc == 0, tail[-1:])
for n, flags, elf, witness in [(switch, ['--mainnet', '--sparse'], sparse_elf, 'sparse'),
                               (switch + 1, ['--mainnet', '--sparse'], sparse_elf, 'sparse'),
                               (switch, ['--mainnet'], fallback_elf, 'complete')]:
    rc, tail = c.execute(n, flags, elf, witness)
    step(f'chain 2 block {n}: guest {Path(elf).name} executes ({witness})', rc == 0, tail[-1:])
rc, tail = c.execute(switch, ['--mainnet-v1', '--sparse'], v1_elf, 'sparse')
step(f'chain 2 switch block {switch}: the activated-rules program refuses it', rc != 0, tail[-1:])

result['ok'] = all(s['ok'] for s in result['steps'])
(out / 'result.json').write_text(json.dumps(result, indent=1) + '\n')
print('RESULT', 'PASS' if result['ok'] else 'FAIL', len(result['steps']), 'steps')
sys.exit(0 if result['ok'] else 1)
