#!/usr/bin/env python3
"""What the sequencer puts in a block, so that the block can be proved and griefing costs more.

Sequencer policy only: nothing here is a block rule. Replay, the guest and L1 never read it, and a foreign settler is not
bound by it. Everything is decided before the block is committed. The settler and the griefing simulator run this same
code; they differ in how they measure.

Bounds on one block:

  max_block_sp1_gas     the proving budget, measured by running the guest on the candidate block, deposits included.
                        Declared EVM gas does not bound proving cost (a 15M-gas block ranges from 7M to 6.9G instructions).
  max_block_instructions  optional second bound on the same measurement.
  max_tx_gas            per-transaction gas used, bounding one preflight and how much of a block one transaction can take.
  preflight_max_runs,   the work one block may spend on measuring. An over-budget transaction is never included, so it
  preflight_max_seconds pays no fee: this bound is what makes refusing it cheap. Whatever was not reached waits.

Deposits. L1 fixes the deposits of a settlement exactly: min(inbox at the anchor, consumed + 64), in order, for the block
the settlement names (`MAX_INBOX_PER_SETTLEMENT`, checked in the native settlement rule). The sequencer cannot defer, skip
or reorder one, so the deposit-only block is measured first. Over budget, the block carries deposits only and the plan
says so; proving it is the operator's exit (`local_prove_max_sp1_gas`, remote prover, `l2_stuck_block.py export-job`).
What the sequencer can do is keep that state from arising on a complete-witness guest:

  max_account_slots     a transaction that would grow any account past this waits. Contracts stay usable below the budget.
  max_deposit_exposure_slots  the same for the sum of the 64 largest accounts, which a deposit batch can touch in one block.

On a sparse-witness guest a deposit does not read the recipient's storage: both limits can stay unset.

Price and rate of storage writes:

  fresh_slot_price_wei  a transaction's tips must cover this per storage slot it adds.
  fresh_slots_per_block, fresh_slots_per_sender over fresh_sender_window_blocks  rates. Excess waits in the spool.
  min_tip_wei           floor of the required tip.
  congestion_*          the required tip rises when blocks use more than the target share of the proving budget or of the
                        write rate, and falls otherwise. The protocol base fee reacts to EVM gas above 15M only, and so
                        never saw sustained inflation; this does. Not a block rule, so it needs no guest change.
  strike_cooldown_blocks  a sender whose transaction was quarantined waits this long.
  write_limit_exempt_senders  senders outside the price, rates and caps: the operator's deployments and the bridge signers.
"""
import json
import os
from pathlib import Path
import time

DEPOSITS_PER_SETTLEMENT = 64  # MAX_INBOX_PER_SETTLEMENT in the native settlement rule


class Cost:
    """A guest execution. `sp1_gas` None means no usable measurement: treated as over any budget."""

    def __init__(self, sp1_gas, instructions=None, seconds=None):
        self.sp1_gas, self.instructions, self.seconds = sp1_gas, instructions, seconds

    def __repr__(self):
        return f'Cost(sp1_gas={self.sp1_gas}, instructions={self.instructions})'


class Plan:
    def __init__(self):
        self.chosen = []  # raw hex in block order
        self.chosen_stats = []
        self.quarantine = []  # (hash, reason)
        self.held = []  # (hash, reason): stays in the spool
        self.finished = []  # hashes the selection dropped for good
        self.base = None  # the deposit-only block
        self.cost = None  # the block as chosen
        self.deposits_over_budget = False
        self.runs = 0
        self.exhausted = False  # measuring stopped at its limit; the rest waits


class Planner:
    def __init__(self, config, state_path=None, clock=time.monotonic, log=lambda event, **fields: None):
        self.c, self.path, self.clock, self.log = config, Path(state_path) if state_path else None, clock, log
        self.budget = config['max_block_sp1_gas']
        self.state = {'tip': config.get('min_tip_wei', 0), 'senders': {}, 'strikes': {}, 'account_slots': {}}
        if self.path and self.path.exists():
            self.state.update(json.loads(self.path.read_text()))

    # Bounds

    def fits(self, cost):
        if cost is None or cost.sp1_gas is None or cost.sp1_gas > self.budget:
            return False
        limit = self.c.get('max_block_instructions')
        return limit is None or (cost.instructions is not None and cost.instructions <= limit)

    def required_tip(self):
        return max(int(self.state['tip']), self.c.get('min_tip_wei', 0))

    def exposure(self, slots):
        return sum(sorted(slots.values(), reverse=True)[:DEPOSITS_PER_SETTLEMENT])

    # The gate on each transaction, native execution only

    def gate(self, stats, number):
        """(passing hashes in order, {hash: (reason, permanent)}), walking the block in order."""
        passing, refused = [], {}
        tip_floor = self.required_tip()
        price = self.c.get('fresh_slot_price_wei', 0)
        per_block = self.c.get('fresh_slots_per_block')
        per_sender = self.c.get('fresh_slots_per_sender')
        window = self.c.get('fresh_sender_window_blocks', 1)
        max_tx_gas = self.c.get('max_tx_gas')
        account_cap = self.c.get('max_account_slots')
        exposure_cap = self.c.get('max_deposit_exposure_slots')
        exempt = set(self.c.get('write_limit_exempt_senders', []))
        in_block = 0
        by_sender = {}
        slots = {a: int(n) for a, n in self.state['account_slots'].items()}
        for tx in stats:
            name, sender, gas, tip = tx['hash'], tx['sender'], int(tx['gas_used']), int(tx['effective_tip'])
            # The operator's deployments and bridge signers are not limited or priced as writers. Their writes still count
            # towards account sizes below.
            fresh = 0 if sender in exempt else sum(int(n) for _, n in tx.get('fresh_slots', []))
            reason = None
            if self.state['strikes'].get(sender, 0) > number:
                reason = ('sender-cooldown', False)
            elif max_tx_gas and gas > max_tx_gas:
                reason = ('tx-gas-cap', True)
            elif tip < tip_floor:
                reason = ('below-required-tip', False)
            elif fresh and gas * tip < fresh * price:
                reason = ('below-write-price', False)
            elif per_block is not None and fresh > per_block:
                reason = ('larger-than-block-write-limit', True)
            elif per_block is not None and in_block + fresh > per_block:
                reason = ('block-write-limit', False)
            elif per_sender is not None and fresh:
                used = sum(n for at, n in self.state['senders'].get(sender, []) if at > number - window) + by_sender.get(sender, 0)
                if fresh > per_sender:
                    reason = ('larger-than-sender-write-limit', True)
                elif used + fresh > per_sender:
                    reason = ('sender-write-limit', False)
            if reason is None and tx.get('fresh_slots') and (account_cap is not None or exposure_cap is not None):
                after = dict(slots)
                for account, n in tx.get('fresh_slots', []):
                    after[account] = after.get(account, 0) + int(n)
                if sender in exempt:
                    slots = after
                elif account_cap is not None and any(after[a] > account_cap for a, _ in tx['fresh_slots']):
                    reason = ('account-slot-cap', False)
                elif exposure_cap is not None and self.exposure(after) > exposure_cap:
                    reason = ('deposit-exposure', False)
                else:
                    slots = after
            if reason:
                refused[name] = reason
                continue
            in_block += fresh
            by_sender[sender] = by_sender.get(sender, 0) + fresh
            passing.append(name)
        return passing, refused

    # One block

    def plan(self, entries, dry, measure, number, has_deposits=False):
        """`entries`: raw hex candidates. `dry(raws)`: the producer's selection report, native only. `measure(raws)`:
        (Cost, report) for the block built from exactly these transactions, with this block's deposits."""
        plan = Plan()
        started = self.clock()
        max_runs = self.c.get('preflight_max_runs', 16)
        max_seconds = self.c.get('preflight_max_seconds', 600)

        def run(raws):
            plan.runs += 1
            return measure(raws)

        def out_of_work():
            if plan.runs >= max_runs or self.clock() - started >= max_seconds:
                plan.exhausted = True
                return True
            return False

        plan.base, _ = run([])
        plan.cost = plan.base
        if not self.fits(plan.base):
            plan.deposits_over_budget = True
            self.log('deposits-over-budget', number=number, sp1_gas=plan.base.sp1_gas if plan.base else None,
                     instructions=plan.base.instructions if plan.base else None, budget=self.budget)
            return plan
        if not entries:
            return plan

        by_hash, stats = self._gated(entries, dry, number, plan)
        candidates = [t['hash'] for t in stats]
        best = []  # known to fit: the base block at first
        best_stats = []
        while candidates:
            if out_of_work():
                break
            sequence = best + candidates
            cost, report = run([by_hash[h] for h in sequence])
            for dropped in report.get('dropped', []):
                if dropped.get('hash'):
                    plan.finished.append(dropped['hash'])
            included = list(report.get('included', sequence))
            if self.fits(cost):
                best, best_stats, plan.cost = included, report.get('tx_stats', []), cost
                break
            low, high = len(best), len(included)
            best_report, best_cost = None, None
            while high - low > 1 and not out_of_work():
                middle = (low + high) // 2
                cost, report = run([by_hash[h] for h in included[:middle]])
                if self.fits(cost):
                    low, best_report, best_cost = middle, report, cost
                else:
                    high = middle
            if high - low > 1:
                if best_report:  # out of work inside the search: keep what was measured to fit
                    best, best_stats, plan.cost = included[:low], best_report.get('tx_stats', []), best_cost
                break
            if best_report:
                best, best_stats, plan.cost = included[:low], best_report.get('tx_stats', []), best_cost
            offender = included[low]
            rest = included[low + 1:]
            if out_of_work():
                break
            alone, alone_report = run([by_hash[offender]])
            if self.fits(alone) or has_deposits:
                # It may fit a block without these transactions, or without these deposits: deposits cost an attacker
                # next to nothing, so they must not get another sender's transaction quarantined. It waits, the rest go on.
                plan.held.append((offender, 'block-full'))
                self.log('block-full', number=number, keep=len(best), of=len(included), next=offender)
                candidates = rest
                continue
            plan.quarantine.append((offender, 'over-budget-alone'))
            for tx in alone_report.get('tx_stats', []):
                if tx['hash'] == offender and self.c.get('strike_cooldown_blocks'):
                    self.state['strikes'][tx['sender']] = number + self.c['strike_cooldown_blocks']
            self.log('tx-quarantined', number=number, hash=offender, cost=repr(alone))
            candidates = rest
        plan.chosen = [by_hash[h] for h in best]
        plan.chosen_stats = best_stats
        return plan

    def _gated(self, entries, dry, number, plan):
        """Repeat the native selection until no refused transaction is left in it: removing one can change what follows."""
        raws = list(entries)
        by_hash = {}
        for _ in range(self.c.get('gate_passes', 6)):
            report = dry(raws)
            stats = report.get('tx_stats', [])
            for dropped in report.get('dropped', []):
                if dropped.get('hash'):
                    plan.finished.append(dropped['hash'])
            by_hash = {t['hash']: raw for t, raw in zip(stats, self._in_block_order(report, raws))}
            passing, refused = self.gate(stats, number)
            if not refused:
                return by_hash, stats
            for name, (reason, permanent) in refused.items():
                (plan.quarantine if permanent else plan.held).append((name, reason))
            raws = [by_hash[name] for name in passing]
            if not raws:
                return {}, []
        # Still moving after the last pass: nothing that was not gated goes in.
        self.log('gate-did-not-settle', number=number)
        return {}, []

    @staticmethod
    def _in_block_order(report, raws):
        """The included raws in block order."""
        keyed = {_hash_raw(raw): raw for raw in raws}
        return [keyed[name] for name in report.get('included', [])]

    # After the block is committed

    def committed(self, plan, number):
        fresh_in_block = 0
        for tx in plan.chosen_stats:
            fresh = sum(int(n) for _, n in tx.get('fresh_slots', []))
            fresh_in_block += fresh
            if fresh:
                self.state['senders'].setdefault(tx['sender'], []).append([number, fresh])
            for account, n in tx.get('fresh_slots', []):
                self.state['account_slots'][account] = self.state['account_slots'].get(account, 0) + int(n)
            for account, n in tx.get('cleared_slots', []):
                self.state['account_slots'][account] = max(0, self.state['account_slots'].get(account, 0) - int(n))
        window = self.c.get('fresh_sender_window_blocks', 1)
        for sender in list(self.state['senders']):
            kept = [e for e in self.state['senders'][sender] if e[0] > number - window]
            if kept:
                self.state['senders'][sender] = kept
            else:
                del self.state['senders'][sender]
        self.state['strikes'] = {s: until for s, until in self.state['strikes'].items() if until > number}
        self._congestion(plan, fresh_in_block)
        self.save()

    def _congestion(self, plan, fresh_in_block):
        denominator = self.c.get('congestion_denominator')
        if not denominator or plan.base is None or plan.cost is None or plan.base.sp1_gas is None or plan.cost.sp1_gas is None:
            return
        share = self.c.get('congestion_target_share', 0.5)
        room = max(self.budget - plan.base.sp1_gas, 1)
        ratio = (plan.cost.sp1_gas - plan.base.sp1_gas) / (room * share)
        per_block = self.c.get('fresh_slots_per_block')
        if per_block:
            ratio = max(ratio, fresh_in_block / (per_block * share))
        floor = max(self.c.get('min_tip_wei', 0), 1)
        tip = max(int(self.state['tip']), floor)
        step = tip * (ratio - 1) / denominator
        moved = tip + (max(int(step), 1) if ratio > 1 else min(int(step), -1) if ratio < 1 else 0)
        self.state['tip'] = min(max(moved, floor), self.c.get('congestion_max_tip_wei', 10**15))

    def save(self):
        if not self.path:
            return
        tmp = self.path.with_name(f'.{self.path.name}.{os.getpid()}.tmp')
        tmp.write_text(json.dumps(self.state, sort_keys=True))
        tmp.replace(self.path)


def _keccak_default(data):
    raise RuntimeError('sequencer_policy needs set_hash(keccak256)')


_hash = _keccak_default


def set_hash(function):
    """The transaction hash of a raw transaction: keccak256, supplied by the caller's module."""
    global _hash
    _hash = function


def _hash_raw(raw):
    return _hash(bytes.fromhex(raw)).hex()
