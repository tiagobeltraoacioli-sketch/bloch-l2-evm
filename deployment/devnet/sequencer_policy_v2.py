#!/usr/bin/env python3
"""Sequencer policy v2: a reference implementation of docs/SEQUENCER-POLICY-V2.md.

Sequencer policy only. Nothing here is a block rule: replay, the guest and L1 never read it, and a foreign settler is not
bound by it. It decides which spooled user transactions go into the next block, so that the block can be proved by the
planned prover and so that griefing costs the griefer more than it costs the operator.

This module is the planning core only. It is pure: it never runs a process, reads the spool or touches the database.
The caller supplies three functions:

  dry(raws)        the producer's native selection report for these raw transactions, without committing:
                   {'included': [hash...], 'dropped': [{'hash', 'reason'}...],
                    'tx_stats': [{'hash', 'sender', 'nonce', 'gas_used', 'effective_tip', 'fresh_slots'}...]}
                   (`produce-dev select`, agent 90's e49a380/c5f341e/f6ac754, to be re-landed).
  measure(raws)    (result, report) for the block built from exactly these transactions on top of this block's
                   mandatory items (deposits, and forced envelopes after the fork). `result` is a Cost, OVER_LIMIT when
                   the guest execution hit the host's cycle limit, or None when the run gave no cost (host failure,
                   wall-clock timeout, missing cost line).
  measure_empty()  the result for an empty block with no mandatory items: the control that tells a host failure from a
                   heavy block.

and a clock in seconds (wall time, persisted across restarts). Every window is in seconds, never in blocks: block
times vary from minutes to an hour with pacing and proof time (review r7 F6, r8 N9).

What changed against agent 90's policy (042cad6), finding by finding, is in the design document, section 6.
"""
import json
import math
import os
from pathlib import Path
import time

OVER_LIMIT = 'over-limit'  # a measured fact: the guest execution exceeded the host's cycle limit

DEFAULTS = {
    # Block budget (section 3.1). Rests on agent 113's sparse-guest proofs: 93.8M SP1 gas proved at 54.8 GiB with the
    # low-memory "2c" settings in a 64 GiB scope; a 65.1M block OOMed at 64 GiB with the fast settings.
    'max_block_sp1_gas': 90_000_000,
    'max_block_instructions': 90_000_000,
    'max_block_txs': 64,
    # Per transaction (3.2).
    'max_tx_gas': 5_000_000,
    # Writes (3.3). Rates in seconds.
    'fresh_slot_price_wei': 200 * 10**12,  # 200 µBLCH per new slot
    'fresh_slots_per_block': 128,
    'fresh_slots_per_sender': 256,
    'fresh_sender_window_seconds': 48 * 3600,
    # Metering (3.4). The cycle limit is set on the host; the planner only needs to know it is at least twice the budget.
    'preflight_cycle_limit_factor': 2,
    'preflight_execute_seconds': 90,  # wall-clock backstop only; the cycle limit ends heavy runs first (agent 223 H1: 90 s on a loaded host)
    'preflight_max_runs': 24,
    'preflight_max_seconds': 180,
    'unmeasured_retry_seconds': [600, 1800],  # tries at t, t+10 min, t+40 min, then quarantine (inside the RPC's 3 h)
    'unmeasured_quarantine_after': 3,
    'failure_memory_seconds': 7 * 86400,
    'band_max_wait_seconds': 7200,
    'sender_ban_seconds': 86400,
    'standing_seconds': 7 * 86400,
    # Congestion tip (3.5).
    'min_tip_wei': 10**8,  # 0.1 gwei, the RPC floor
    'congestion_max_tip_wei': 100 * 10**9,
    'congestion_target_share': 0.5,
    'congestion_up_denominator': 8,
    'congestion_down_denominator': 16,
    'congestion_idle_grace_seconds': 4500,
    'congestion_idle_half_life_seconds': 1200,
    # Exempt senders (3.6): outside the write price and write rates, and under the block gas limit instead of
    # `max_tx_gas` (operator deployments). Never outside the SP1-gas budget, the tip or the measurement.
    'write_limit_exempt_senders': [],
    'exempt_max_tx_gas': 15_000_000,
    # Prover profiles (3.1, X17).
    'fast_profile_max_sp1_gas': 10_500_000,
    'gate_passes': 6,
    'gate_dependent_wait_seconds': 3600,
    # Places under `max_block_txs` that go by tip alone, whatever the group (agents/264 F264-5): a fresh sender's
    # large transaction at a high tip is not kept out for good by 64 small ones at the floor. They are tried last.
    'tip_reserved_txs': 8,
    # Small/large split of the try order (A243-3, A243-9). The floor rests on the smallest measured offender: a KZG
    # point-evaluation loop is over the 90M budget alone from about 245-280k gas (agents/243-evidence/gstar.out).
    'large_gas_floor': 120_000,
    'large_gas_recovery_seconds': 7 * 86400,  # the threshold doubles back once per week without a small offender  # a refusal that appeared only after an earlier one was removed (A243-12)
}

# Prover profiles by the preflight SP1 gas of the block to prove (agent 93's settings, agent 113's measurements).
PROFILES = {
    'fast': {'threads': 32, 'env': {'ELEMENT_THRESHOLD': '268435456'}, 'memory_max_gib': 48},
    'lowmem-2c': {'threads': 32, 'env': {'SP1_WORKER_NUM_CORE_WORKERS': '2', 'CORE_BUFFER_SIZE': '1',
                                         'NUM_SPLICING_WORKERS': '1', 'SPLICING_BUFFER_SIZE': '1',
                                         'GLOBAL_MEMORY_BUFFER_SIZE': '2'}, 'memory_max_gib': 64},
    'mandatory-heavy': {'threads': 32, 'env': {'SP1_WORKER_NUM_CORE_WORKERS': '2', 'CORE_BUFFER_SIZE': '1',
                                               'NUM_SPLICING_WORKERS': '1', 'SPLICING_BUFFER_SIZE': '1',
                                               'GLOBAL_MEMORY_BUFFER_SIZE': '2'}, 'memory_max_gib': 96},
}


class Cost:
    def __init__(self, sp1_gas, instructions):
        self.sp1_gas, self.instructions = int(sp1_gas), int(instructions)

    def __repr__(self):
        return f'Cost(sp1_gas={self.sp1_gas}, instructions={self.instructions})'


def measured(result):
    return isinstance(result, Cost)


class Plan:
    def __init__(self):
        self.chosen = []  # hashes, in try order: what the final extend is asked to include
        self.raws = []  # the same, raw hex
        self.quarantine = []  # (hash, reason): moved out of the spool by the settler
        self.held = []  # (hash, reason): stays in the spool
        self.finished = []  # hashes the producer dropped for good (nonce too low, undecodable)
        self.base = None  # result for the mandatory-only block
        self.cost = None  # result for the block as chosen
        self.mandatory_over_budget = False  # the block carries its mandatory items only; write the record
        self.host_unavailable = False  # no cost even for the control: no user transaction, nothing quarantined
        self.runs = 0
        self.seconds = 0.0
        self.exhausted = False
        self.profile = None
        self.gate_settled = True


class Policy:
    def __init__(self, config=None, state_path=None, clock=time.time, log=lambda event, **fields: None):
        self.c = dict(DEFAULTS)
        self.c.update(config or {})
        self.path = Path(state_path) if state_path else None
        self.clock, self.log = clock, log
        self.state = self._fresh_state()
        if self.path and self.path.exists():
            # Only limits live here: a torn or foreign file costs the counts, never a block (review r7 F7).
            try:
                loaded = json.loads(self.path.read_text())
                if not isinstance(loaded, dict):
                    raise ValueError('not an object')
                fresh = self._fresh_state()
                # `last_block_time` starts as None and is a number once a block was committed: keep it across restarts,
                # or the idle decay of the tip stops until the next block (review r9 U5 after a restart).
                kinds = {k: ((int, float) if k in ('last_block_time', 'idle_since', 'large_gas_at') else type(v)) for k, v in fresh.items()}
                fresh.update({k: v for k, v in loaded.items() if k in fresh and isinstance(v, kinds[k])
                              and not isinstance(v, bool)})
                self.state = fresh
            except (OSError, ValueError) as error:
                self.log('policy-state-unreadable', path=str(self.path), reason=str(error)[:200])

    def _fresh_state(self):
        return {'tip': self.c['min_tip_wei'], 'last_block_time': None, 'idle_since': None, 'empty_base': 0, 'bans': {}, 'waits': {},
                'failures': {}, 'writes': {}, 'standing': {}, 'large_gas': int(self.c['max_tx_gas']),
                'large_gas_at': None, 'exempt_offenders': {}}

    # Bounds

    def fits(self, result):
        return (measured(result) and result.sp1_gas <= self.c['max_block_sp1_gas']
                and result.instructions <= self.c['max_block_instructions'])

    def cycle_limit(self):
        """The host's `--cycle-limit` for preflight. At least twice the instruction budget, so that hitting it proves a
        transaction over the budget on its own, with or without this block's mandatory items (see `_classify`)."""
        return int(self.c['max_block_instructions'] * max(2, self.c['preflight_cycle_limit_factor']))

    def profile_for(self, sp1_gas):
        """Which prover settings prove a block of this preflight SP1 gas inside the planned prover's memory."""
        if sp1_gas is None or sp1_gas > self.c['max_block_sp1_gas']:
            return 'mandatory-heavy'  # over the budget: only a mandatory-only block can be, whatever the fast threshold
        if sp1_gas <= self.c['fast_profile_max_sp1_gas']:
            return 'fast'
        if sp1_gas <= self.c['max_block_sp1_gas']:
            return 'lowmem-2c'
        return 'mandatory-heavy'

    # Congestion tip (3.5)

    def required_tip(self, now=None):
        """The stored tip, decayed for the time user load has been idle beyond the grace. The settler's demand check, the
        gate and the RPC's published tip all read this, so a quiet chain returns to the floor without building a block
        (review r9 U5). Consecutive measured blocks with only mandatory work retain their first quiet timestamp.
        Time between busy blocks never decays it while the grace exceeds the slowest block time (U6)."""
        now = self.clock() if now is None else now
        floor = self.c['min_tip_wei']
        tip = max(int(self.state['tip']), floor)
        last = self.state.get('last_block_time')
        if isinstance(last, (int, float)):
            # Consecutive mandatory-only blocks do not constitute user demand.
            # Keep their quiet interval across commits, while never applying
            # again the elapsed decay already incorporated in the stored tip.
            quiet = self.state.get('idle_since')
            quiet = quiet if isinstance(quiet, (int, float)) else last
            idle = now - max(last, quiet + self.c['congestion_idle_grace_seconds'])
            if idle > 0:
                tip = int(tip * 0.5 ** (min(idle, 30 * 86400) / self.c['congestion_idle_half_life_seconds']))
        return max(min(tip, self.c['congestion_max_tip_wei']), floor)

    def _congestion(self, plan, now, fresh_in_block):
        tip = self.required_tip(now)
        if plan.mandatory_over_budget or plan.host_unavailable:
            # No user transaction could be measured in this block: it says nothing about demand, so the tip holds.
            self.state['tip'], self.state['last_block_time'] = tip, now
            self.state['idle_since'] = None
            return
        ratio = 0.0
        if measured(plan.base) and measured(plan.cost):
            room = max(self.c['max_block_sp1_gas'] - plan.base.sp1_gas, 1)
            ratio = (plan.cost.sp1_gas - plan.base.sp1_gas) / (room * self.c['congestion_target_share'])
        per_block = self.c.get('fresh_slots_per_block')
        if per_block:
            ratio = max(ratio, fresh_in_block / (per_block * self.c['congestion_target_share']))
        if ratio > 1:
            step = tip * min(ratio - 1, 1) / self.c['congestion_up_denominator']
            tip = tip + max(int(step), 1)
        else:
            tip = tip - int(tip * (1 - ratio) / self.c['congestion_down_denominator'])
        self.state['tip'] = max(min(tip, self.c['congestion_max_tip_wei']), self.c['min_tip_wei'])
        if ratio > 0:
            self.state['idle_since'] = None
        elif self.state.get('idle_since') is None:
            self.state['idle_since'] = now
        self.state['last_block_time'] = now

    # The gate (3.3, 3.4): native facts only. `demand` uses it too, so whatever waits here is no demand either.

    @staticmethod
    def key(tx):
        """Waits and failure counts follow sender and nonce, never the hash: a same-nonce replacement is the same entry
        (review r8 N3). Without a nonce in the report the whole sender is the key."""
        return f"{tx['sender']}:{tx['nonce']}" if tx.get('nonce') is not None else str(tx['sender'])

    def gate(self, stats, now, has_mandatory):
        """(passing hashes in report order, {hash: (reason, permanent)})."""
        passing, refused = [], {}
        tip_floor = self.required_tip(now)
        price = self.c['fresh_slot_price_wei']
        per_block, per_sender = self.c.get('fresh_slots_per_block'), self.c.get('fresh_slots_per_sender')
        window = self.c['fresh_sender_window_seconds']
        exempt = set(self.c['write_limit_exempt_senders'])
        in_block, by_sender, stopped = 0, {}, set()
        for tx in stats:
            name, sender, gas, tip = tx['hash'], tx['sender'], int(tx['gas_used']), int(tx['effective_tip'])
            fresh = 0 if sender in exempt else sum(int(n) for _, n in tx.get('fresh_slots', []))
            wait = self.state['waits'].get(self.key(tx))
            if wait and wait.get('hash') not in (None, name):
                # A gate-dependent wait names the bytes it refused: a replacement at the same nonce is judged on its
                # own payment (agents/264 F264-3). Bans, band and unmeasured waits follow sender and nonce as before.
                wait = None
            offender = self.state['exempt_offenders'].get(sender) if sender in exempt else None
            reason = None
            if sender in stopped:
                reason = ('behind-held-nonce', False)  # its earlier nonce waits: the producer would defer it anyway
            elif self.state['bans'].get(sender, 0) > now:
                reason = ('sender-banned', False)
            elif wait and wait['until'] > now and not (wait['kind'] == 'band' and not has_mandatory):
                reason = (f"{wait['kind']}-wait", False)
            elif gas > (self.c['exempt_max_tx_gas'] if sender in exempt else self.c['max_tx_gas']):
                reason = ('tx-gas-cap', True)
            elif offender and offender['until'] > now and gas >= offender['gas']:
                # An exempt sender is never banned (A243-5), but after a verdict its transactions of at least half
                # the offender's gas wait out the ban time unmeasured: a resent offender must not cost two
                # cycle-limit verdicts ahead of every user in every block (agents/264 F264-4).
                reason = ('exempt-offender-wait', False)
            elif tip < tip_floor:
                reason = ('below-required-tip', False)
            elif fresh and gas * tip < fresh * price:
                reason = ('below-write-price', False)
            elif per_block is not None and fresh > per_block:
                reason = ('larger-than-block-write-limit', True)
            elif per_block is not None and in_block + fresh > per_block:
                reason = ('block-write-limit', False)
            elif per_sender is not None and fresh:
                used = sum(n for at, n in self.state['writes'].get(sender, []) if at > now - window)
                used += by_sender.get(sender, 0)
                if fresh > per_sender:
                    reason = ('larger-than-sender-write-limit', True)
                elif used + fresh > per_sender:
                    reason = ('sender-write-limit', False)
            if reason:
                refused[name] = reason
                stopped.add(sender)
                continue
            in_block += fresh
            by_sender[sender] = by_sender.get(sender, 0) + fresh
            passing.append(name)
        return passing, refused

    def demand(self, stats, now, next_has_mandatory):
        """Whether the next block would take a user transaction: the same gate as `plan`, at `now`, with the decayed
        tip, and with the mandatory items the next block will really carry (review r8 N8, r9 U4, U5). `stats` is the
        native selection report of the spool (`produce-dev select`)."""
        passing, _ = self.gate(stats, now, next_has_mandatory)
        return bool(passing)

    def _gated(self, raws, dry, now, plan, has_mandatory):
        """Repeat the native selection until the gate refuses nothing in it: removing one can change what follows.

        New-slot counts depend on the transactions before (the producer's storage_growth), so a refusal can uncover
        another one pass after pass (agents/243 A243-12: senders writing the same slot at descending tips, each below
        the write price for one new slot). Such a dependent refusal (from the second pass on) also waits
        `gate_dependent_wait_seconds` by sender and nonce, so the next blocks gate it out before the native selection
        and need one pass. If the gate still has not settled after `gate_passes`, the last pass's passing set goes on
        to the measurement rather than none: an unpaid chain must never empty the block. A transaction behind the last
        refusal may then create slots it did not pay for, so `_final_gate` runs the gate again on the block as chosen
        (agents/264 F264-2)."""
        stats = []
        for number in range(self.c['gate_passes']):
            report = dry(raws)
            stats = report.get('tx_stats')
            if stats is None:
                # A producer without the per-transaction report: the gate cannot apply, so nothing goes in (r8 N6).
                plan.held.extend((h, 'no-selection-report') for h in report.get('included', []))
                return {}, []
            plan.finished.extend(d['hash'] for d in report.get('dropped', []) if d.get('hash'))
            by_hash = {t['hash']: raw for t, raw in zip(stats, _in_block_order(report, raws))}
            passing, refused = self.gate(stats, now, has_mandatory)
            if not refused:
                return by_hash, stats
            info = {t['hash']: t for t in stats}
            for name, (reason, permanent) in refused.items():
                (plan.quarantine if permanent else plan.held).append((name, reason))
                if number and reason in ('below-write-price', 'sender-write-limit'):  # its own payment, not capacity
                    self._dependent_wait(info[name], now)
            raws = [by_hash[name] for name in passing]
            if not raws:
                return {}, []
            stats = [t for t in stats if t['hash'] in set(passing)]
        self.log('gate-did-not-settle', passes=self.c['gate_passes'], used=len(raws))
        plan.gate_settled = False  # the final gate decides on the block as chosen
        return {t['hash']: raw for t, raw in zip(stats, raws)}, stats

    def _dependent_wait(self, tx, now):
        self.state['waits'][self.key(tx)] = {'until': now + self.c['gate_dependent_wait_seconds'],
                                             'kind': 'gate-dependent', 'hash': tx['hash']}

    def large_gas(self, now=None):
        """Gas used from which a transaction counts as large: half the gas of the smallest offender that counted as
        small (a measured verdict), doubling back once per `large_gas_recovery_seconds` without one, between
        `large_gas_floor` and `max_tx_gas` (agents/243 A243-3). A transaction can only be over the budget alone if its
        gas used is at least some G* fixed by the guest's worst cost per gas (about 245-280k measured, KZG), so each
        offender small enough to count as small halves the threshold: a few per week, not per block. The floor keeps one
        odd verdict (the complete fallback guest witnesses whole accounts, so a small transaction can be over there)
        from moving every transaction into the large group, where standing comes first again."""
        now = self.clock() if now is None else now
        ceiling = int(self.c['max_tx_gas'])
        value = int(self.state.get('large_gas', ceiling))
        at = self.state.get('large_gas_at')
        if isinstance(at, (int, float)) and not isinstance(at, bool) and now > at:
            value <<= min(int((now - at) // self.c['large_gas_recovery_seconds']), 32)
        return max(min(value, ceiling), min(int(self.c['large_gas_floor']), ceiling), 1)

    def try_order(self, stats, now, large_gas=None, degraded=False):
        """The order candidates are tried in (3.4; agents/243 A243-1..3 on top of agents/223 F223-4).

        - Small transactions (gas used below `large_gas()`) and every transaction of a sender with standing or an
          exempt sender first, all together, by effective tip: a higher tip buys room and a place under the
          transaction cap whoever sends it (r8 N2), so a sender with standing cannot keep a new sender out by tipping
          less (A243-1, A243-2). Standing breaks ties.
        - Then large transactions of fresh senders, which cannot be told from offenders before they are measured (r9 U1:
          a pool of fresh, funded senders cannot spend the measuring time of established users). By tip until a
          quarantine or a run without cost in this block; after one, by ascending gas used (F223-4), so further heavy
          attackers are measured last. A fresh sender whose first transaction is large is served after the small ones;
          any small paid transaction (an approve) gives it standing.
        - After a verdict in this block, large transactions of senders with standing join the large group too, ahead of
          the fresh ones: standing costs one paid transaction, so offenders with standing must not keep the rest of
          the block behind them either (A243-9).
        - Each sender's transactions stay in nonce order, so every prefix holds nonce n before n+1 (r8 N1); a sender's
          place follows its next transaction."""
        exempt = set(self.c['write_limit_exempt_senders'])
        horizon = now - self.c['standing_seconds']
        large = self.large_gas(now) if large_gas is None else large_gas

        def tier(sender):
            return 0 if sender in exempt or self.state['standing'].get(sender, -math.inf) > horizon else 1

        def key(sender, index, tx):
            gas, tip, rank = int(tx['gas_used']), int(tx['effective_tip']), tier(sender)
            if sender in exempt or gas < large or (rank == 0 and not degraded):
                return (0, -tip, rank, gas, index)
            return (1, rank, gas, -tip, index) if degraded else (1, -tip, gas, index)

        queues = {}
        for index, tx in enumerate(stats):
            queues.setdefault(tx['sender'], []).append((index, tx))
        for queue in queues.values():
            queue.sort(key=lambda item: (item[1].get('nonce') if item[1].get('nonce') is not None else item[0], item[0]))
        order = []
        while any(queues.values()):
            sender = min((s for s in queues if queues[s]), key=lambda s: key(s, *queues[s][0]))
            order.append(queues[sender].pop(0)[1]['hash'])
        return order

    def _capped(self, order, info, plan):
        """Apply `max_block_txs` to the try order. The last `tip_reserved_txs` places go to the highest tips among
        everything behind the first cut, whatever the group, and are tried last in try order (agents/264 F264-5).
        A sender's later nonce never takes a place its earlier nonce lost."""
        cap = int(self.c['max_block_txs'])
        if len(order) <= cap:
            return order
        reserve = max(0, min(int(self.c.get('tip_reserved_txs', 0)), cap))
        head, rest = order[:cap - reserve], order[cap - reserve:]
        position = {name: index for index, name in enumerate(rest)}
        taken, cut = [], set()
        for name in sorted(rest, key=lambda h: (-int(info[h]['effective_tip']), position[h])):
            sender = info[name]['sender']
            earlier = [h for h in rest[:position[name]] if info[h]['sender'] == sender]
            if len(taken) < reserve and sender not in cut and all(h in taken for h in earlier):
                taken.append(name)
            else:
                cut.add(sender)
        kept = set(taken)
        plan.held.extend((name, 'block-limits') for name in rest if name not in kept)
        return head + [name for name in rest if name in kept]

    def degraded_order(self, names, info, now, large_gas=None):
        """The try order of `names` after a quarantine or a run without cost in this block (F223-4, A243-3)."""
        return self.try_order([info[h] for h in names], now, large_gas, degraded=True)

    # One block

    def plan(self, entries, dry, measure, measure_empty, has_mandatory):
        """Choose the user transactions of the next block. `entries`: raw hex candidates from the spool."""
        plan = Plan()
        now = started = self.clock()
        control = {}

        def run(raws):
            plan.runs += 1
            before = self.clock()
            result, report = measure(raws)
            plan.seconds += self.clock() - before
            return result, report or {}

        def out_of_work():
            if plan.runs >= self.c['preflight_max_runs'] or self.clock() - started >= self.c['preflight_max_seconds']:
                plan.exhausted = True
                return True
            return False

        def host_ok():
            """The control: an empty block without mandatory items, once per block."""
            if 'ok' not in control:
                plan.runs += 1
                control['ok'] = measured(measure_empty())
            return control['ok']

        plan.base, _ = run([])
        if plan.base is None:
            plan.base, _ = run([])  # once more: a loaded host, not this block
        if plan.base is None:
            if host_ok():
                # The host measures an empty block but not this one, and the cycle limit did not end it: count the
                # mandatory block as over the budget, never as free room (r8 N6).
                plan.mandatory_over_budget = True
                self.log('mandatory-over-budget', reason='no cost for the mandatory block; the control has one')
            else:
                plan.host_unavailable = True
                self.log('budget-unavailable', reason='no cost for the control block')
            plan.profile = 'mandatory-heavy'
            return plan
        if not self.fits(plan.base):
            plan.mandatory_over_budget = True
            plan.profile = self.profile_for(plan.base.sp1_gas if measured(plan.base) else None)
            self.log('mandatory-over-budget', sp1_gas=getattr(plan.base, 'sp1_gas', None), budget=self.c['max_block_sp1_gas'])
            return plan
        if not has_mandatory:
            self.state['empty_base'] = plan.base.sp1_gas
        plan.cost = plan.base
        if not entries:
            plan.profile = self.profile_for(plan.base.sp1_gas)
            return plan

        by_hash, stats = self._gated(list(entries), dry, now, plan, has_mandatory)
        info = {t['hash']: t for t in stats}
        # `dry` runs without the block's transaction cap, so that the producer's tip order cannot push a sender with
        # standing out of the candidates before the tiers apply; the cap applies here, to the try order.
        large = self.large_gas(now)  # this block's threshold: also lowered by runs without cost, which persist nothing
        remaining = self._capped(self.try_order(stats, now, large), info, plan)
        best = []
        degraded = False
        while remaining and not out_of_work():
            if degraded:
                # A quarantine or a run without cost in this block: the full run would only hit the offenders at the
                # end of the order again (one cycle-limit verdict, 35-40 s inside the settler, agents/223). Search from
                # the front, measuring the whole rest only if every shorter prefix fits.
                found = self._first_misfit(best, remaining, by_hash, run, out_of_work, None, full_known=False)
            else:
                result, report = run([by_hash[h] for h in best + remaining])
                plan.finished.extend(d['hash'] for d in report.get('dropped', []) if d.get('hash'))
                if self.fits(result):
                    kept = set(report.get('included', best + remaining))
                    best = [h for h in best + remaining if h in kept]
                    plan.held.extend((h, 'block-limits') for h in remaining if h not in kept)
                    plan.cost = result
                    remaining = []
                    break
                found = self._first_misfit(best, remaining, by_hash, run, out_of_work, result)
            lo, lo_cost, misfit, complete = found
            if not complete:
                # Out of work inside the search: what it measured as fitting is the block (agents/264 F264-1). The rest
                # stays in the spool, not reached; the offender behind it is found by a later block's search.
                if lo:
                    best, plan.cost, remaining = best + remaining[:lo], lo_cost, remaining[lo:]
                break
            if lo == len(remaining):
                best, plan.cost, remaining = best + remaining, lo_cost, []
                break
            if lo:
                best, plan.cost = best + remaining[:lo], lo_cost
            offender = remaining[lo]
            tx = info[offender]
            remaining = [h for h in remaining[lo + 1:] if info[h]['sender'] != tx['sender']]
            if not best:
                # The misfit run was the offender alone on the mandatory base, with or without a cost: running it again
                # would only repeat a run without cost (review r8 N4; the retries come 10 and 40 minutes later).
                alone = misfit
            else:
                if out_of_work():
                    plan.held.append((offender, 'not-reached'))
                    break
                alone, _ = run([by_hash[offender]])
            spent = len(plan.quarantine), sum(1 for _, r in plan.held if r == 'unmeasured')
            if not self._classify(plan, tx, alone, now, has_mandatory, host_ok):
                break  # the host stopped measuring: keep what is known to fit, decide nothing about the rest
            if (len(plan.quarantine), sum(1 for _, r in plan.held if r == 'unmeasured')) != spent:
                # F223-4, A243-3: an offender in this block. A measured verdict lowered `large_gas` in the state; a run
                # without cost lowers it for this block only (a failing host must not move it for good).
                if int(tx['gas_used']) < large:
                    large = min(self.large_gas(now), max(int(tx['gas_used']) // 2, int(self.c['large_gas_floor'])))
                degraded = True
                remaining = self.degraded_order(remaining, info, now, large)
        plan.held.extend((h, 'not-reached') for h in remaining)
        if best and (not plan.gate_settled or set(best) != {t['hash'] for t in stats}):
            best = self._final_gate(best, by_hash, dry, measure, now, plan, has_mandatory)
        plan.chosen = best
        plan.raws = [by_hash[h] for h in best]
        plan.profile = self.profile_for(plan.cost.sp1_gas if measured(plan.cost) else None)
        return plan

    def _final_gate(self, best, by_hash, dry, measure, now, plan, has_mandatory):
        """The gate on the block as chosen (agents/264 F264-2). New-slot counts depend on the transactions before, and
        the choice is a subset of what `_gated` passed: a writer that was refused, quarantined or cut leaves the next
        writer of the same slots creating them, unpaid and outside the per-block limit. So the producer's selection
        report of exactly the chosen set goes through the gate once more. A refused transaction leaves with its
        sender's later ones, and what is left is measured again, because a block without one of its transactions is
        another block (one run per pass, at most `gate_passes`, outside the search allowance). If that run does not
        fit, or the passes run out, the block is the chosen set's prefix in block order before the first refusal,
        when that keeps at least half of it: every transaction of that prefix runs after exactly the transactions it
        ran after in the measured block, so its new-slot counts stand and its cost is within the measured one.
        Otherwise the measured block stands as it is, with the unpaid slots of its remaining chain (logged
        `final-gate-unsettled`; `committed` books them against the sender's 48 h rate): senders that never pay must
        not be able to empty a block by spooling a chain longer than the passes (A243-12 comes first). Never an
        unmeasured block. The complete remedy is the write price inside the producer's own selection loop, one pass
        and no dependency (a compiled-producer change, listed as open in agents/304)."""
        def refusals(names):
            report = dry([by_hash[h] for h in names])
            stats = report.get('tx_stats') or []
            passing, refused = self.gate(stats, now, has_mandatory)
            return stats, set(passing), refused

        def note(stats, refused):
            info = {t['hash']: t for t in stats}
            for name, (reason, _) in refused.items():
                held.append((name, reason))
                if reason in ('below-write-price', 'sender-write-limit'):
                    self._dependent_wait(info[name], now)

        def prefix(names, stats, refused):
            before = set()
            for tx in stats:
                if tx['hash'] in refused:
                    break
                before.add(tx['hash'])
            if 2 * len(before) < len(names):
                self.log('final-gate-unsettled', kept=len(names), prefix=len(before), refused=len(refused))
                return names
            plan.held.extend((h, 'behind-final-gate-refusal') for h in names if h not in before and h not in refused)
            self.log('final-gate-prefix', kept=len(before), of=len(names))
            return [h for h in names if h in before]

        held = []  # refusals of this pass: reported only for what really leaves the block

        def leave(names):
            plan.held.extend(item for item in held if item[0] not in set(names))
            return names

        for _ in range(self.c['gate_passes']):
            stats, passing, refused = refusals(best)
            if not refused:
                return leave(best)
            note(stats, refused)
            trimmed = [h for h in best if h in passing]
            if not trimmed:
                plan.cost = plan.base
                return leave([])
            plan.runs += 1
            before = self.clock()
            result, _ = measure([by_hash[h] for h in trimmed])
            plan.seconds += self.clock() - before
            if not self.fits(result):
                return leave(prefix(best, stats, refused))
            best, plan.cost = trimmed, result
        stats, passing, refused = refusals(best)
        if not refused:
            return leave(best)
        note(stats, refused)
        return leave(prefix(best, stats, refused))

    def _first_misfit(self, best, remaining, by_hash, run, out_of_work, full_result, full_known=True):
        """The shortest prefix of `remaining` that, on top of `best`, does not fit. Exponential then binary search from
        the front, so an offender at position p costs about 2·log2(p+1) runs and one at the front costs one: tip order
        puts an unpaid high tip at the front, where it is now cheapest to find (r9 U1). Returns (lo, cost of best +
        remaining[:lo] or None, result of the run of best + remaining[:lo + 1] or None, complete). `complete` is False
        when the allowance ran out inside the search: `lo` is then the longest prefix measured as fitting so far, and
        nothing is known about the transaction behind it (agents/264 F264-1).
        With `full_known` False the whole of `remaining` was not run: the search measures it last, and lo ==
        len(remaining) means all of it fits."""
        lo, lo_cost, hi, hi_result = 0, None, len(remaining), full_result
        size = 1
        while size < hi or (not full_known and lo < hi and size >= hi):
            size = min(size, hi)
            if out_of_work():
                return lo, lo_cost, None, False
            result, _ = run([by_hash[h] for h in best + remaining[:size]])
            if self.fits(result):
                lo, lo_cost = size, result
                if size == hi:
                    return lo, lo_cost, None, True
                size *= 2
            else:
                hi, hi_result = size, result
                break
        while hi - lo > 1:
            if out_of_work():
                return lo, lo_cost, None, False
            middle = (lo + hi) // 2
            result, _ = run([by_hash[h] for h in best + remaining[:middle]])
            if self.fits(result):
                lo, lo_cost = middle, result
            else:
                hi, hi_result = middle, result
        return lo, lo_cost, hi_result, True

    def _classify(self, plan, tx, alone, now, has_mandatory, host_ok):
        """What happens to a transaction that broke the budget. Returns False when the host stopped measuring."""
        name, key = tx['hash'], self.key(tx)
        if self.fits(alone):
            plan.held.append((name, 'block-full'))  # fits a block without the others: a later block
            return True
        if alone == OVER_LIMIT:
            # The run hit the cycle limit, at least twice the instruction budget, on top of a mandatory base that fits
            # the budget: the transaction's own share is over the budget in any block. A measured fact: quarantine.
            self._quarantine(plan, tx, 'over-cycle-limit', now)
            self._lower_large_gas(tx, now)
            return True
        if measured(alone):
            share_sp1 = alone.sp1_gas - plan.base.sp1_gas + int(self.state['empty_base'])
            share_instr = alone.instructions - plan.base.instructions
            if has_mandatory and share_sp1 <= self.c['max_block_sp1_gas'] and share_instr <= self.c['max_block_instructions']:
                # Over only with this block's mandatory items: wait for a block without them (r7 F1, r8 N5).
                self.state['waits'][key] = {'until': now + self.c['band_max_wait_seconds'], 'kind': 'band'}
                plan.held.append((name, 'mandatory-fills-the-block'))
                return True
            self._quarantine(plan, tx, 'over-budget-alone', now)
            self._lower_large_gas(tx, now)
            return True
        # No cost and no cycle-limit verdict.
        if not host_ok():
            plan.host_unavailable = True
            plan.held.append((name, 'host-unavailable'))
            self.log('budget-unavailable', reason='control failed after a run without cost')
            return False  # never quarantine on a failing host (r7 F2)
        failure = self.state['failures'].get(key, {'count': 0})
        count = int(failure['count']) + 1
        self.state['failures'][key] = {'count': count, 'at': now}
        if count >= self.c['unmeasured_quarantine_after']:
            self._quarantine(plan, tx, 'unmeasurable', now)
            return True
        delays = self.c['unmeasured_retry_seconds']
        self.state['waits'][key] = {'until': now + delays[min(count - 1, len(delays) - 1)], 'kind': 'unmeasured'}
        plan.held.append((name, 'unmeasured'))
        return True

    def _lower_large_gas(self, tx, now):
        """A measured verdict (over the cycle limit, or over the budget alone): from now on, transactions of at least
        half this one's gas used are tried after the small ones (A243-3). Persisted with the state. Only an offender
        that counted as small moves it: a large one was already behind every small transaction."""
        gas = int(tx['gas_used'])
        if gas < self.large_gas(now):
            self.state['large_gas'], self.state['large_gas_at'] = max(gas // 2, 1), now

    def _quarantine(self, plan, tx, reason, now):
        """Quarantine binds the sender, not the bytes: the sender is banned for `sender_ban_seconds` and loses standing,
        so sending the same nonce again or a replacement buys nothing (r9 U1, U3). Gas used plays no part (r9 U2)."""
        plan.quarantine.append((tx['hash'], reason))
        if tx['sender'] in set(self.c['write_limit_exempt_senders']):
            # An exempt sender (operator, bridge signers and relayers; TBD-owner) loses only this transaction: a ban
            # would stop its bridge mints for a day after one over-budget deployment or three runs without cost
            # (agents/243 A243-5). It stays inside the budget and the measurement.
            self.state['exempt_offenders'][tx['sender']] = {'until': now + self.c['sender_ban_seconds'],
                                                            'gas': max(int(tx['gas_used']) // 2, 1)}
            self.log('exempt-sender-not-banned', sender=tx['sender'], hash=tx['hash'], reason=reason)
        else:
            self.state['bans'][tx['sender']] = now + self.c['sender_ban_seconds']
            self.state['standing'].pop(tx['sender'], None)
        self.state['waits'].pop(self.key(tx), None)
        self.log('tx-quarantined', hash=tx['hash'], sender=tx['sender'], reason=reason)

    # After the block is committed

    def committed(self, plan, final_report, now=None):
        """Update state from the committed block's own `extend` report, and return the spool entries to remove: exactly
        what that block included or the producer dropped for good. A chosen transaction the producer deferred keeps its
        file (r8 N1). Quarantined entries are moved by the settler from `plan.quarantine`, not here."""
        now = self.clock() if now is None else now
        included = list(final_report.get('included', []))
        dropped = [d['hash'] for d in final_report.get('dropped', []) if d.get('hash')]
        stats = {t['hash']: t for t in final_report.get('tx_stats', [])}
        exempt = set(self.c['write_limit_exempt_senders'])
        fresh_in_block = 0
        for name in included:
            tx = stats.get(name)
            if not tx:
                continue
            self.state['standing'][tx['sender']] = now
            self.state['waits'].pop(self.key(tx), None)
            self.state['failures'].pop(self.key(tx), None)
            fresh = sum(int(n) for _, n in tx.get('fresh_slots', []))
            if fresh and tx['sender'] not in exempt:
                fresh_in_block += fresh
                self.state['writes'].setdefault(tx['sender'], []).append([now, fresh])
        window = self.c['fresh_sender_window_seconds']
        self.state['writes'] = {s: kept for s, entries in self.state['writes'].items()
                                if (kept := [e for e in entries if e[0] > now - window])}
        self.state['bans'] = {s: until for s, until in self.state['bans'].items() if until > now}
        self.state['exempt_offenders'] = {s: o for s, o in self.state['exempt_offenders'].items() if o['until'] > now}
        self.state['waits'] = {k: w for k, w in self.state['waits'].items() if w['until'] > now - 86400}
        memory = self.c['failure_memory_seconds']
        self.state['failures'] = {k: f for k, f in self.state['failures'].items() if f['at'] > now - memory}
        horizon = now - self.c['standing_seconds']
        self.state['standing'] = {s: at for s, at in self.state['standing'].items() if at > horizon}
        self._congestion(plan, now, fresh_in_block)
        self.save(now)
        return sorted(set(included) | set(dropped) | set(plan.finished))

    def save(self, now=None):
        """Write the state with fsync, plus `required_tip_wei` for the RPC's `--required-tip-file` (agent 118)."""
        if not self.path:
            return
        now = self.clock() if now is None else now
        required = self.required_tip(now)
        document = dict(self.state, required_tip_wei=required, admission={
            'version': 1,
            'required_tip_wei': str(required),
            'fresh_slot_price_wei': str(self.c['fresh_slot_price_wei']),
            'write_limit_exempt_senders': ['0x' + sender.removeprefix('0x')
                                         for sender in self.c['write_limit_exempt_senders']],
        })
        tmp = self.path.with_name(f'.{self.path.name}.{os.getpid()}.tmp')
        with open(tmp, 'w') as out:
            out.write(json.dumps(document, sort_keys=True))
            out.flush()
            os.fsync(out.fileno())
        tmp.replace(self.path)


def check_cost_line(probe_result):
    """Start-up check: with a budget configured, the prover must report a cost and honour the cycle limit for an empty
    block, or the settler refuses to start. A prover without the cost line would otherwise starve users silently (r7 F2)."""
    if not measured(probe_result):
        raise RuntimeError('the prover gave no cost for an empty block: a budget cannot be enforced; refusing to start')


def _in_block_order(report, raws, hash_raw=None):
    """The included raws in block order. The caller's report carries `raw` per stat, or the caller set `hash_raw`."""
    function = hash_raw or _hash_raw
    keyed = {function(raw): raw for raw in raws}
    return [keyed[name] for name in report.get('included', [])]


def _keccak_default(data):
    raise RuntimeError('sequencer_policy_v2 needs set_hash(keccak256)')


_hash = _keccak_default


def set_hash(function):
    global _hash
    _hash = function


def _hash_raw(raw):
    return _hash(bytes.fromhex(raw)).hex()
