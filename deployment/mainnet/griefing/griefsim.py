#!/usr/bin/env python3
"""An attacker with a budget against sequencer designs. Execute-only, private, throwaway keys, no network, no proof.

Real signed transactions run through the real block executor in the harness `bloch-evm-sp1-griefsim`, against real
bytecode: bUSDC (BridgedStablecoinV2), BlochAsset, the DEX factory, router and pair, WBLCH. Costs come from the real guest
ELFs in the SP1 executor. The block choice is the code the settler runs (`sequencer_policy.py`).

  griefsim.py DESIGN ATTACK [key=value ...]   writes one JSON line per event to stdout

Environment: GS_HARNESS, GS_COMPLETE, GS_SPARSE, GS_BYTECODE, GS_LIB (dir of heavy_gen.py and sequencer_policy.py).
"""
import json
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.environ.get('GS_LIB', os.path.dirname(os.path.abspath(__file__))))
import heavy_gen as g  # noqa: E402
import sequencer_policy as P  # noqa: E402

CHAIN = 700770
FEE_CAP = 4 * 10**9  # plus twice the tip: above any base fee these runs reach, without tying up much balance
BC = json.load(open(os.environ['GS_BYTECODE']))
MAX = 2**256 - 1
COIN = 10**18
PROVEN_SP1, FAIL_SP1, FAIL_INSTR = 235_000_000, 287_000_000, 193_000_000  # report 44: proved at 235M; OOM at 287M, 193M instr.
P.set_hash(g.keccak)

BUDGET = 150_000_000
TIP_FLOOR = 100_000_000  # next RPC default, 0.1 gwei
WRITE_PRICE = 2 * 10**14  # 200 microBLCH per new slot, see the report
LIMITS = dict(min_tip_wei=TIP_FLOOR, preflight_max_runs=16, preflight_max_seconds=600, max_tx_gas=5_000_000, strike_cooldown_blocks=32)
RATES = dict(fresh_slots_per_block=128, fresh_slots_per_sender=256, fresh_sender_window_blocks=96,
             congestion_denominator=8, congestion_target_share=0.5, fresh_slot_price_wei=WRITE_PRICE)
DESIGNS = {
    # guest, planner config. None: the settler with no budget, as v2.1 runs.
    'D0-complete-open': ('complete', None),
    'D1-complete-budget-as-merged': ('complete', dict(max_block_sp1_gas=BUDGET, legacy_deposits=True, min_tip_wei=TIP_FLOOR)),
    'D2-complete-budget-deposits': ('complete', dict(max_block_sp1_gas=BUDGET, **LIMITS)),
    'D3-complete-limits': ('complete', dict(max_block_sp1_gas=BUDGET, max_account_slots=2_000, max_deposit_exposure_slots=7_000, **LIMITS, **RATES)),
    'D4-sparse-open': ('sparse', None),
    'D5-sparse-budget': ('sparse', dict(max_block_sp1_gas=BUDGET, **LIMITS)),
    'D6-sparse-limits': ('sparse', dict(max_block_sp1_gas=BUDGET, **LIMITS, **RATES)),
}


def out(**fields):
    print(json.dumps(fields), flush=True)


def sel(s): return g.keccak(s.encode())[:4]


def w(x):
    if isinstance(x, bytes):
        return x.rjust(32, b'\0')
    return (x % 2**256).to_bytes(32, 'big')


def cat(*a): return b''.join(a)


def creat(sender, nonce): return g.keccak(g.rlp([sender, nonce]))[12:]


def abi_str(s):
    b = s.encode()
    return w(len(b)) + b.ljust((len(b) + 31) // 32 * 32, b'\0')


class Legacy(P.Planner):
    """The budget as merged from the heavy-block branch: the deposit-only block is assumed to fit."""

    def plan(self, entries, dry, measure, number, has_deposits=False):
        def assume(raws):
            return (P.Cost(0, 0), {}) if not raws else measure(raws)
        return super().plan(entries, dry, assume, number, has_deposits=False)


class Sim:
    def __init__(self, design):
        self.design = design
        self.guest, config = DESIGNS[design]
        self.p = None
        if config:
            kind = Legacy if config.get('legacy_deposits') else P.Planner
            self.p = kind(config, None, time.monotonic, lambda event, **f: out(policy=event, **f))
        args = [os.environ['GS_HARNESS'], 'mainnet', 'complete=' + os.environ['GS_COMPLETE'], 'sparse=' + os.environ['GS_SPARSE']]
        env = dict(os.environ, RAYON_NUM_THREADS='4', SP1_CIRCUIT_MODE='release')
        self.h = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
        self.nonces = {}
        self.keys = {}
        self.spent = {}  # sender hex -> fee wei
        self.main = self.new_key()
        self.attacker = set()
        self.position = 0
        self.number = 0

    # Harness

    def call(self, *words):
        self.h.stdin.write(' '.join(str(x) for x in words) + '\n')
        self.h.stdin.flush()
        reply = json.loads(self.h.stdout.readline())
        if 'error' in reply:
            raise RuntimeError(f'{words[0]}: {reply["error"]}')
        return reply

    @staticmethod
    def raws(raws): return ','.join(raws) if raws else '-'

    @staticmethod
    def deps(deposits): return ','.join(f'0x{a.hex()}:{s}' for a, s in deposits) if deposits else '-'

    def measure(self, raws, deposits=(), guests=None):
        reply = self.call('measure', guests or self.guest, self.deps(deposits), self.raws(raws))
        run = reply[self.guest] if not guests else reply
        return reply, run

    def cost(self, raws, deposits=()):
        reply, run = self.measure(raws, deposits)
        if run.get('failed'):
            return None
        return P.Cost(int(run['sp1_gas']), int(run['instructions']), run['seconds'])

    def select(self, raws, deposits=()):
        return self.call('select', 15_000_000, 114_688, 256, self.deps(deposits), self.raws(raws))

    def next_fee(self): return self.call('head')['next_base_fee']

    # Keys and transactions

    def new_key(self):
        key = secrets.randbits(255) | 1
        self.keys[g.address(key)] = key
        return key

    def tx(self, key, to, data, gas, tip=None, value=0):
        sender = g.address(key)
        nonce = self.nonces.get(sender, 0)
        self.nonces[sender] = nonce + 1
        tip = tip if tip is not None else self.tip()
        raw = g.tx(key, CHAIN, nonce, gas, to, value, data, max_fee=FEE_CAP + 2 * tip, tip=tip)
        return raw.hex()

    def tip(self):
        return self.p.required_tip() if self.p else TIP_FLOOR

    def resync(self, senders):
        for sender in senders:
            self.nonces[sender] = self.call('account', '0x' + sender.hex())['nonce']

    # One block through the sequencer

    def block(self, raws=(), deposits=(), charge=None):
        """Returns (plan-or-None, included hashes). Fees of included transactions are added to `self.spent`."""
        raws, deposits = list(raws), list(deposits)
        self.number += 1
        if self.p:
            plan = self.p.plan(raws, lambda r: self.select(r, deposits), lambda r: self._measured(r, deposits), self.number, has_deposits=bool(deposits))
            chosen, stats = plan.chosen, plan.chosen_stats
            if not chosen and raws:
                stats = []
        else:
            plan = None
            report = self.select(raws, deposits)
            stats = report['tx_stats']
            keyed = {g.keccak(bytes.fromhex(r)).hex(): r for r in raws}
            chosen = [keyed[h] for h in report['included']]
        base_fee = self.next_fee()
        reply = self.call('commit', self.deps(deposits), self.raws(chosen))
        fee = 0
        for tx, (ok, gas) in zip(stats, reply['results']):
            paid = gas * (base_fee + int(tx['effective_tip']))
            self.spent[tx['sender']] = self.spent.get(tx['sender'], 0) + paid
            fee += paid
        if self.p:
            self.p.committed(plan, self.number)
        return plan, chosen, stats, reply, fee

    def _measured(self, raws, deposits):
        """As the settler's preflight: the producer's selection first, so a nonce gap is deferred rather than an error."""
        report = self.select(raws, deposits)
        keyed = {g.keccak(bytes.fromhex(r)).hex(): r for r in raws}
        return self.cost([keyed[h] for h in report['included']], deposits), report

    def attacker_spent(self):
        return sum(v for k, v in self.spent.items() if bytes.fromhex(k) in self.attacker)

    def mark(self, key):
        self.attacker.add(g.address(key))

    # Real contracts

    def setup(self):
        policy, self.p = self.p, None  # the operator's deployments are not what is being measured
        try:
            return self._setup()
        finally:
            self.p = policy

    def _setup(self):
        c, sd = self, g.address(self.main)
        k = self.main
        c.block([], [(sd, 100_000_000_000)])
        n = {}

        def dep(name, code):
            n[name] = creat(sd, c.nonces.get(sd, 0))
            return c.tx(k, b'', bytes.fromhex(code), 8_000_000, tip=TIP_FLOOR)
        fac = BC['Factory'] + cat(w(0), w(0), w(0x80), w(0xa0), w(0), w(0)).hex()
        c.block([dep('factory', fac)])
        c.block([dep('wblch', BC['WBLCH'])])
        c.block([dep('router', BC['Router'] + cat(w(n['factory']), w(n['wblch'])).hex())])
        a = cat(w(0xa0), w(0xe0), w(18), w(10**30), w(sd), abi_str('Asset'), abi_str('AST'))
        c.block([dep('token', BC['Asset'] + a.hex())])
        off = 14 * 32
        name_b, sym_b, sign = abi_str('Bridged USDC'), abi_str('bUSDC'), cat(w(1), w(sd))
        guard = cat(w(0x60), w(0), w(0), w(0))
        o_name = off
        o_sym = o_name + len(name_b)
        o_sign = o_sym + len(sym_b)
        o_guard = o_sign + len(sign)
        vault, route = bytes.fromhex('11' * 20), bytes.fromhex('22' * 32)
        sc = 2**60
        enc = cat(w(o_name), w(o_sym), w(1), w(vault), w(route), w(o_sign), w(1), w(sc), w(sc), w(sc), w(MAX), w(0), w(1), w(o_guard), name_b, sym_b, sign, guard)
        c.block([dep('busdc', BC['BUSDC'] + enc.hex())])
        dt = g.keccak(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
        ds = g.keccak(cat(dt, g.keccak(b'Bloch Bridged Stablecoin'), g.keccak(b'2'), w(CHAIN), w(n['busdc'])))
        mt = g.keccak(b'Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,uint64 depositNonce,uint64 amount,address recipient)')
        did, amt = b'\x33' * 32, 2**59
        sh = g.keccak(cat(mt, w(1), w(vault), route, did, w(1), w(amt), w(sd)))
        v, r, s = g.sign(k, g.keccak(b'\x19\x01' + ds + sh))
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + v])
        mint = sel('mint(bytes32,uint64,uint64,address,bytes)') + cat(did, w(1), w(amt), w(sd), w(0xa0), w(65), sig.ljust(96, b'\0'))
        c.block([c.tx(k, n['busdc'], mint, 500_000, tip=TIP_FLOOR)])
        ap = lambda t, who: c.tx(k, t, sel('approve(address,uint256)') + cat(w(who), w(MAX)), 100_000, tip=TIP_FLOOR)  # noqa: E731
        add = sel('addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)') + cat(w(n['busdc']), w(n['token']), w(2**50), w(10**27), w(0), w(0), w(sd), w(2**62))
        c.block([ap(n['busdc'], n['router']), ap(n['token'], n['router']), c.tx(k, n['router'], add, 6_000_000, tip=TIP_FLOOR)])
        t0, t1 = sorted([n['busdc'], n['token']])
        n['pair'] = g.keccak(b'\xff' + n['factory'] + g.keccak(t0 + t1) + g.keccak(bytes.fromhex(BC['Pair'])))[12:]
        self.n = n
        self.honest = self.new_key()
        sender = g.address(self.honest)
        self.block([], [(sender, 10_000_000_000)])
        self.block([c.tx(k, n['busdc'], sel('transfer(address,uint256)') + cat(w(sender), w(10**12)), 100_000, tip=TIP_FLOOR)])
        self.spent.clear()
        out(event='setup', number=self.number, contracts={a: b.hex() for a, b in n.items()})
        return n

    def griefer(self, key, tip=None):
        address = creat(g.address(key), self.nonces.get(g.address(key), 0))
        plan, chosen, _, reply, _ = self.block([self.tx(key, b'', bytes.fromhex(BC['Griefer']), 2_000_000, tip=tip if tip else self.tip())])
        if not chosen:
            raise RuntimeError('griefer deployment refused')
        return address

    def funded_attacker(self, sats=10_000_000_000):
        """An attacker key with L2 balance, from a deposit. The deposit is principal, not a fee."""
        key = self.new_key()
        self.mark(key)
        self.block([], [(g.address(key), sats)])
        return key

    def honest_transfer(self, to=None):
        token = self.n['busdc']
        recipient = to or g.address(self.main)
        return self.tx(self.honest, token, sel('transfer(address,uint256)') + cat(w(recipient), w(1)), 200_000, tip=max(self.tip(), TIP_FLOOR))


def spent(sim):
    return sim.attacker_spent() / COIN


# Attacks. Each ends with one `verdict` line.

def write_tip(sim, slots, gas_per_slot=20_000):
    """The tip that passes the required tip and the write price, whatever the price."""
    price = sim.p.c.get('fresh_slot_price_wei', 0) if sim.p else 0
    return max(sim.tip(), price // gas_per_slot + 1)


class Filler:
    """One block of new slots at a time, within what the design allows, with new funded senders when a sender is at its limit."""

    def __init__(self, sim, key, griefer, data, gas_per_slot, master=None):
        self.sim, self.key, self.griefer, self.data, self.gas_per_slot = sim, key, griefer, data, gas_per_slot
        self.master = master or key
        config = sim.p.c if sim.p else {}
        self.per_block = config.get('fresh_slots_per_block')
        self.per_sender = config.get('fresh_slots_per_sender')
        self.tx_cap = config.get('max_tx_gas', 15_000_000)
        self.sender_used = 0
        self.refusals = []
        self.limit = 10**9
        self.done = False  # one new slot at a time was refused
        if config.get('strike_cooldown_blocks'):
            self.new_sender()  # the main key only funds, so a strike cannot stop the funding

    def new_sender(self):
        sim = self.sim
        fresh = sim.new_key()
        sim.mark(fresh)
        # Principal moved from the attacker's main balance, not spent.
        needed = 3 * 5_000_000 * (FEE_CAP + 2 * write_tip(sim, 1))
        sim.block([sim.tx(self.master, g.address(fresh), b'', 21_000, value=max(COIN, needed), tip=sim.tip())])
        self.key, self.sender_used = fresh, 0

    def block(self, wanted=None):
        """Returns slots added this block."""
        sim = self.sim
        room = min((15_000_000 - 3 * 60_000) // self.gas_per_slot, self.per_block or 10**9, self.limit)
        if wanted is not None:
            room = min(room, wanted)
        if self.per_sender and self.sender_used + room > self.per_sender:
            self.new_sender()
        per_tx = max(1, min(room, (self.tx_cap - 60_000) // self.gas_per_slot))
        raws, counts, left = [], [], room
        while left > 0:
            count = min(left, per_tx)
            raws.append(sim.tx(self.key, self.griefer, self.data(count), self.gas_per_slot * count + 60_000, tip=write_tip(sim, count)))
            counts.append(count)
            left -= count
        plan, chosen, stats, reply, fee = sim.block(raws)
        added = 0
        for raw, count in zip(raws, counts):
            if raw in chosen and reply['results'][chosen.index(raw)][0]:
                added += count
        self.sender_used += added
        self.reply = reply
        self.refusals = [r for _, r in (plan.held + plan.quarantine)] if plan else []
        if not added or len(chosen) < len(raws):
            sim.resync([g.address(self.key)])
        if not added:
            # A sender at its limit or cooling down: use another. Over a write limit by the griefer's own first slot: one less.
            # Near the budget a smaller transaction may still fit.
            if {'over-budget-alone', 'sender-cooldown', 'sender-write-limit'} & set(self.refusals):
                self.new_sender()
            if 'sender-write-limit' not in self.refusals:
                self.done = room <= 1
                self.limit = max(room - 1, 1) if 'larger-than-block-write-limit' in self.refusals else max(room // 2, 1)
        return added


def freeze(sim, target='busdc', max_fee=100.0, max_blocks=2_000, check_every=500, gas_per_slot=30_000, pace=None):
    """Grow a real token through `approve` until an honest `transfer` on it no longer fits a block. Needs none of the token."""
    token = sim.n[target]
    key = sim.funded_attacker(1_000_000_000_000)
    griefer = sim.griefer(key, tip=write_tip(sim, 10))
    start = sim.number
    slots, last_check, refused = 0, 0, 0
    filler = Filler(sim, key, griefer, lambda n: sel('fillApprove(address,uint256)') + cat(w(token), w(n)), gas_per_slot)
    while True:
        if spent(sim) > max_fee or sim.number - start > max_blocks:
            return out(event='verdict', attack='freeze', design=sim.design, target=target, frozen=False, reason='attacker limit', slots=slots, fee_blch=spent(sim), blocks=sim.number - start)
        added = filler.block(pace)
        slots += added
        if not added:
            refused += 1
            out(event='fill-refused', slots=slots, limit=filler.limit, number=sim.number, reasons=filler.refusals, result=filler.reply['results'])
            if filler.done or refused >= 12:
                return finish_freeze(sim, target, slots, start, filler.refusals)
        else:
            refused = 0
        if slots - last_check >= check_every:
            last_check = slots
            state = honest_state(sim)
            out(event='progress', attack='freeze', slots=slots, fee_blch=spent(sim), blocks=sim.number - start, base_fee=filler.reply['base_fee'], required_tip=sim.tip(), **state)
            if state['existing_cost'] is None or state['frozen'] or state['unprovable']:
                return finish_freeze(sim, target, slots, start, [])


def honest_state(sim):
    raw = sim.honest_transfer()
    cost = sim.cost([raw])
    sim.resync([g.address(sim.honest)])
    sp1 = cost.sp1_gas if cost else None
    budget = sim.p.budget if sim.p else None
    return dict(existing_cost=sp1, existing_instructions=cost.instructions if cost else None,
                frozen=bool(budget and (sp1 is None or sp1 > budget)), unprovable=sp1 is None or sp1 >= FAIL_SP1 or cost.instructions >= FAIL_INSTR)


def finish_freeze(sim, target, slots, start, reasons):
    state = honest_state(sim)
    # A transfer to an address that has no balance yet needs a new slot.
    fresh = sim.honest_transfer(secrets.token_bytes(20))
    gate = sim.select([fresh])
    new_slot = None
    if sim.p:
        passing, refused = sim.p.gate(gate['tx_stats'], sim.number + 1)
        new_slot = {'passes_gate': bool(passing), 'refused': {k[:12]: v for k, v in refused.items()}}
    sim.resync([g.address(sim.honest)])
    out(event='verdict', attack='freeze', design=sim.design, target=target, slots=slots, fee_blch=spent(sim), blocks=sim.number - start,
        frozen=state['frozen'], unprovable=state['unprovable'], existing_cost=state['existing_cost'], new_slot=new_slot, reasons=reasons,
        fee_per_slot_ublch=spent(sim) * 1e6 / max(slots, 1))


def halt_deposit(sim, contracts=8, per_contract=None, max_fee=100.0, chunk=None, limit_blocks=3_000):
    """Grow own contracts, then deposit to all of them in one block. L1 caps that block at 64 deposits and requires all."""
    master = key = sim.funded_attacker(1_000_000_000_000)
    griefers = []
    start = sim.number
    slots_total = 0
    deposit = 1_000_000
    cost = None
    for index in range(contracts):
        griefer = sim.griefer(master, tip=write_tip(sim, 10))
        griefers.append(griefer)
        filler = Filler(sim, master, griefer, lambda n: sel('fillRaw(uint256)') + w(n), 24_000, master=master)
        slots = 0
        while not (per_contract and slots >= per_contract):
            if spent(sim) > max_fee or sim.number - start > limit_blocks:
                break
            added = filler.block(per_contract - slots if per_contract else None)
            if not added:
                out(event='fill-refused', contract=index, slots=slots, limit=filler.limit, reasons=filler.refusals, result=filler.reply['results'])
                if filler.done:
                    break
                continue
            slots += added
            slots_total += added
        batch = [(g_, deposit) for g_ in griefers]
        cost = sim.cost([], batch)
        fail = cost is None or cost.sp1_gas >= FAIL_SP1 or cost.instructions >= FAIL_INSTR
        out(event='deposit-batch', contracts=index + 1, last_slots=slots, total_slots=slots_total, sp1_gas=cost.sp1_gas if cost else None,
            instructions=cost.instructions if cost else None, fail_class=fail, fee_blch=spent(sim), blocks=sim.number - start)
        if fail:
            plan, chosen, stats, reply, fee = sim.block([sim.honest_transfer()], batch)
            state = dict(deposits_over_budget=bool(plan and plan.deposits_over_budget), block_transactions=len(chosen))
            return out(event='verdict', attack='halt-deposit', design=sim.design, halted=True, contracts=index + 1, total_slots=slots_total,
                       fee_blch=spent(sim), deposit_principal_blch=(index + 1) * deposit / 1e8, deposit_sp1=cost.sp1_gas if cost else None,
                       deposit_instructions=cost.instructions if cost else None, blocks=sim.number - start, **state)
        if slots == 0 or spent(sim) > max_fee:
            break
    return out(event='verdict', attack='halt-deposit', design=sim.design, halted=False, contracts=len(griefers), total_slots=slots_total, fee_blch=spent(sim), deposit_sp1=cost.sp1_gas if cost else None,
               deposit_instructions=cost.instructions if cost else None, blocks=sim.number - start)


def heavy_tx(sim, scenario='pc-modexp-512b', gas=14_000_000):
    """One transaction that fits the block gas limit and not the prover."""
    key = sim.funded_attacker()
    code = g.scenarios()[scenario]
    raw = sim.tx(key, b'', code, gas, tip=sim.tip())
    honest = sim.honest_transfer()
    alone = sim.cost([raw])
    plan, chosen, stats, reply, fee = sim.block([raw, honest])
    out(event='verdict', attack='heavy-tx', design=sim.design, scenario=scenario, gas=gas, alone_sp1=alone.sp1_gas if alone else None, alone_instructions=alone.instructions if alone else None,
        alone_seconds=alone.seconds if alone else None, fee_blch=spent(sim), included=len(chosen), honest_included=honest in chosen, quarantined=[r for _, r in plan.quarantine] if plan else None,
        runs=plan.runs if plan else None, unprovable=(alone is None or alone.sp1_gas >= FAIL_SP1 or alone.instructions >= FAIL_INSTR) and not plan)


def deposits64(sim, slots=0, chunk=620):
    """The block L1 can force at most: 64 deposits, to new accounts, to real contracts, and to a grown contract."""
    key = sim.funded_attacker()
    griefer = sim.griefer(key, tip=write_tip(sim, 10))
    grown = 0
    filler = Filler(sim, key, griefer, lambda n: sel('fillRaw(uint256)') + w(n), 24_000)
    while grown < slots:
        grown += filler.block()
    d = 1_000_000
    fresh = [(secrets.token_bytes(20), d) for _ in range(64)]
    real = [sim.n[x] for x in ('busdc', 'token', 'pair', 'router', 'factory', 'wblch')]
    cases = {
        'empty': [],
        'one-new-account': fresh[:1],
        '64-new-accounts': fresh,
        'one-to-busdc': [(sim.n['busdc'], d)],
        '64-to-real-contracts': [(real[i % len(real)], d) for i in range(64)],
        f'one-to-griefer-{grown}': [(griefer, d)],
        f'64-to-griefer-{grown}': [(griefer, d)] * 64,
    }
    for name, batch in cases.items():
        reply = sim.call('measure', 'complete,sparse' if slots <= 20_000 else 'sparse', sim.deps(batch), '-')
        out(event='deposit-case', case=name, reply=reply)
    out(event='verdict', attack='deposits64', design=sim.design, slots=grown)


def deposits_code(sim, contracts=64):
    """The sparse guest's worst deposit block: 64 distinct contracts, each with the largest code the rules allow."""
    key = sim.funded_attacker()
    init = bytes.fromhex('6160005ff3')  # return 24,576 zero bytes
    addresses = []
    while len(addresses) < contracts:
        raws = []
        for _ in range(min(3, contracts - len(addresses))):
            addresses.append(creat(g.address(key), sim.nonces.get(g.address(key), 0)))
            raws.append(sim.tx(key, b'', init, 4_990_000, tip=sim.tip()))
        _, chosen, _, reply, _ = sim.block(raws)
        if len(chosen) != len(raws) or not all(r[0] for r in reply['results']):
            raise RuntimeError(f'deployment failed: {reply}')
    reply = sim.call('measure', 'complete,sparse', sim.deps([(a, 1_000_000) for a in addresses]), '-')
    out(event='verdict', attack='deposits-code', design=sim.design, contracts=contracts, fee_blch=spent(sim), reply=reply)


def congestion(sim, blocks=120, fill_slots=20_000, read_batch=None, honest_every=1):
    """Keep the proving budget full with reads of a grown real token, and send one honest transfer each block."""
    token = sim.n['busdc']
    key = sim.funded_attacker(1_000_000_000_000)
    griefer = sim.griefer(key, tip=write_tip(sim, 10))
    # Growth first, at the price of the design's own rate.
    slots = 0
    filler = Filler(sim, key, griefer, lambda n: sel('fillApprove(address,uint256)') + cat(w(token), w(n)), 30_000)
    while slots < fill_slots:
        added = filler.block()
        if not added:
            out(event='growth-stopped', slots=slots, reasons=filler.refusals)
            break
        slots += added
    key = filler.key
    grown_fee = spent(sim)
    out(event='grown', slots=slots, fee_blch=grown_fee, number=sim.number, required_tip=sim.tip())
    # Size one attacking read batch to the budget.
    room = BUDGET * 9 // 10
    batch = read_batch or 1_000
    for _ in range(5):
        raw = sim.tx(key, griefer, sel('readAllowances(address,address,uint256,uint256)') + cat(w(token), w(griefer), w(1), w(batch)), 5_000_000, tip=sim.tip())
        cost = sim.cost([raw])
        sim.resync([g.address(key)])
        if cost and abs(cost.sp1_gas - room) < room // 10:
            break
        batch = int(batch * room / (cost.sp1_gas if cost else room * 2))
    out(event='batch', batch=batch, sp1=cost.sp1_gas if cost else None)
    waits, honest_paid = [], 0
    pending = None
    pending_since = None
    for i in range(blocks):
        tip = sim.tip()
        raw = sim.tx(key, griefer, sel('readAllowances(address,address,uint256,uint256)') + cat(w(token), w(griefer), w(1), w(batch)), 5_000_000, tip=tip)
        if pending is None:
            sim.resync([g.address(sim.honest)])
            pending = sim.honest_transfer()
            pending_since = i
        before = spent(sim)
        plan, chosen, stats, reply, fee = sim.block([raw, pending])
        sim.resync([g.address(key)])
        if pending in chosen:
            waits.append(i - pending_since)
            honest_paid += next(int(t['gas_used']) * (reply['base_fee'] + int(t['effective_tip'])) for t in stats if t['hash'] == g.keccak(bytes.fromhex(pending)).hex())
            pending = None
        out(event='congestion-block', i=i, tip=tip, attacker_block_fee_blch=spent(sim) - before, attacker_in=raw in chosen, sp1=plan.cost.sp1_gas if plan else None, base_fee=reply['base_fee'], waits=len(waits))
    out(event='verdict', attack='congestion', design=sim.design, blocks=blocks, slots=slots, grown_fee_blch=grown_fee, fee_blch=spent(sim) - grown_fee, tip_end=sim.tip(), honest_mean_wait=sum(waits) / max(len(waits), 1), honest_max_wait=max(waits or [0]), honest_mean_fee_blch=honest_paid / max(len(waits), 1) / COIN, honest_included=len(waits))


def spam(sim, count=8, scenario='keccak-32', gas=4_500_000):
    """Over-budget transactions that are never included and so pay nothing, each from its own sender, with an honest one behind."""
    raws = []
    t0 = time.monotonic()
    for i in range(count):
        key = sim.funded_attacker(100_000_000)
        raws.append(sim.tx(key, b'', g.scenarios()[scenario], gas, tip=sim.tip() + 10**9 + i))
    honest = sim.honest_transfer()
    alone = sim.cost([raws[0]])
    t1 = time.monotonic()
    plan, chosen, stats, reply, fee = sim.block(raws + [honest])
    out(event='verdict', attack='spam', design=sim.design, count=count, scenario=scenario, gas=gas, alone_sp1=alone.sp1_gas if alone else None, alone_instructions=alone.instructions if alone else None,
        seconds=round(time.monotonic() - t1, 1), setup_seconds=round(t1 - t0, 1), runs=plan.runs if plan else None, exhausted=plan.exhausted if plan else None,
        honest_included=honest in chosen, included=len(chosen), quarantined=len(plan.quarantine) if plan else None, held=[r for _, r in plan.held] if plan else None, fee_blch=spent(sim))


def worst_writes(sim, slots=5_000):
    """SP1 gas per EVM gas of the real writes and reads, on a grown token, for the price of a block."""
    token = sim.n['busdc']
    key = sim.funded_attacker(1_000_000_000_000)
    griefer = sim.griefer(key, tip=write_tip(sim, 10))
    done = 0
    filler = Filler(sim, key, griefer, lambda n: sel('fillApprove(address,uint256)') + cat(w(token), w(n)), 30_000)
    while done < slots:
        added = filler.block(slots - done)
        if not added:
            raise RuntimeError(f'fill failed: {filler.refusals}')
        done += added
    key = filler.key
    for label, data, gas in (
        ('reads-100', sel('readAllowances(address,address,uint256,uint256)') + cat(w(token), w(griefer), w(1), w(100)), 5_000_000),
        ('reads-1000', sel('readAllowances(address,address,uint256,uint256)') + cat(w(token), w(griefer), w(1), w(1000)), 15_000_000),
        ('rewrites-100', sel('rewriteApprove(address,uint256,uint256,uint256)') + cat(w(token), w(1), w(100), w(2)), 5_000_000),
        ('rewrites-300', sel('rewriteApprove(address,uint256,uint256,uint256)') + cat(w(token), w(1), w(300), w(3)), 15_000_000),
        ('new-100', sel('fillApprove(address,uint256)') + cat(w(token), w(100)), 5_000_000),
        ('new-380', sel('fillApprove(address,uint256)') + cat(w(token), w(380)), 15_000_000),
        ('reads-3300', sel('readAllowances(address,address,uint256,uint256)') + cat(w(token), w(griefer), w(1), w(3300)), 15_000_000),
        ('rewrites-1600', sel('rewriteApprove(address,uint256,uint256,uint256)') + cat(w(token), w(1), w(1600), w(4)), 15_000_000),
    ):
        raw = sim.tx(key, griefer, data, gas, tip=TIP_FLOOR)
        report = sim.select([raw])
        reply = sim.call('measure', 'complete,sparse', '-', raw)
        out(event='work', label=label, slots=done, gas_used=report['tx_stats'][0]['gas_used'] if report['tx_stats'] else None, fresh=report['tx_stats'][0]['fresh_slots'] if report['tx_stats'] else None, reply=reply)
        sim.resync([g.address(key)])
    out(event='verdict', attack='worst-writes', design=sim.design, slots=done)


def base_fee(sim, idle=4_200):
    head = sim.call('head')
    out(event='fee', number=head['number'], next_base_fee=head['next_base_fee'])
    step = 100
    while head['number'] < idle:
        head = sim.call('idle', step)
        out(event='fee', number=head['number'], next_base_fee=head['next_base_fee'])
    out(event='verdict', attack='base-fee', number=head['number'], next_base_fee=head['next_base_fee'])


ATTACKS = dict(deposits_code=deposits_code, freeze=freeze, halt=halt_deposit, heavy=heavy_tx, deposits64=deposits64, congestion=congestion, spam=spam, work=worst_writes, fee=base_fee)


def main():
    design, attack = sys.argv[1:3]
    kwargs = {}
    for item in sys.argv[3:]:
        k, v = item.split('=', 1)
        kwargs[k] = v if not v.lstrip('-').replace('.', '', 1).isdigit() else (float(v) if '.' in v else int(v))
    idle = kwargs.pop('idle_before', 0)
    sim = Sim(design)
    t = time.time()
    try:
        if idle:
            sim.call('idle', idle)
            out(event='idle', **sim.call('head'))
        sim.setup()
        ATTACKS[attack](sim, **kwargs)
    finally:
        out(event='end', seconds=round(time.time() - t, 1))
        sim.h.stdin.close()
        sim.h.wait(timeout=30)


if __name__ == '__main__':
    main()
