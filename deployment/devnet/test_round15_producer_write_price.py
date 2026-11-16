#!/usr/bin/env python3
"""Round 15 (agents/304 U3, the F264-2 residual): the write price inside the producer's own selection.

The fake producer here does what `bloch-l2-produce-dev --fresh-slot-price-wei` does (integrations/settlement-recovery
tests/produce_txs.rs `write_price_leaves_a_whole_chain_of_non_payers_pending` tests the real one): the first unpaid
transaction in block order leaves, the selection runs again, and what left is reported under `unpaid`.
Run: python3 -B -m unittest -v test_round15_producer_write_price
"""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sequencer_policy_v2 as sp  # noqa: E402
from test_sequencer_policy_v2 import GWEI  # noqa: E402
from test_review_r11_policy_v2 import FLOOR, SlotWorld, sp_hash  # noqa: E402

PRICE = sp.DEFAULTS['fresh_slot_price_wei']


class PricedWorld(SlotWorld):
    def config(self):
        return {**super().config(), 'producer_write_price': True}

    def report(self, raws):
        raws, unpaid = list(raws), []
        while True:
            report = super().report(raws)
            first = next((t for t in report['tx_stats']
                          if (fresh := sum(n for _, n in t['fresh_slots'])) and int(t['gas_used']) * int(t['effective_tip']) < fresh * PRICE), None)
            if first is None:
                report['unpaid'] = unpaid
                return report
            unpaid.append({'hash': first['hash'], 'sender': first['sender'], 'nonce': first['nonce']})
            raws = [raw for raw in raws if sp_hash(raw) != first['hash']]

    def committed_reports(self):
        finals, inner = [], self.policy.committed

        def committed(plan, final_report, now=None):
            finals.append(final_report)
            return inner(plan, final_report, now)
        self.policy.committed = committed
        return finals

    def unpaid_slots(self, report):
        return [(t['sender'], fresh) for t in report['tx_stats']
                if (fresh := sum(n for _, n in t['fresh_slots'])) and int(t['gas_used']) * int(t['effective_tip']) < fresh * PRICE]


class ProducerWritePrice(PricedWorld):
    def test_a_chain_far_longer_than_the_gate_passes_leaves_in_one_selection_and_users_are_served(self):
        for i in range(30):   # thirty senders write one slot, each below the price of one new slot
            self.add_writer(f'chain{i}', f'c{i}', 0, 50_000, 1, ['s0'], tip=(39 - i) * GWEI // 10)
        for i in range(20):
            self.add(f'h{i}', f'user{i}', 0, 21_000, 1, tip=GWEI)
        finals = self.committed_reports()
        served = self.block()
        self.assertEqual(sorted(n for n in served if n.startswith('h')), sorted(f'h{i}' for i in range(20)))
        self.assertEqual([n for n in served if n.startswith('chain')], [])
        self.assertEqual(self.unpaid_slots(finals[-1]), [])
        held = dict(self.plans[-1].held)
        self.assertEqual(sum(reason == 'below-write-price' for reason in held.values()), 30)
        events = [event for event, _ in self.logged]
        self.assertNotIn('gate-did-not-settle', events)
        self.assertNotIn('final-gate-unsettled', events)
        # The non-payers wait by sender, nonce and hash: the next block gates them out before the selection.
        self.assertEqual(sum(w['kind'] == 'unpaid-sender' for w in self.policy.state['waits'].values()), 30)

    def test_the_f264_2_chains_buy_no_unpaid_slot_and_stay_under_the_block_limit(self):
        for tag, top in (('a', 39), ('b', 29)):
            slots = [f'{tag}{i}' for i in range(100)]
            for i in range(6):
                self.add_writer(f'chain{tag}{i}', f'c{tag}{i}', 0, 50_000, 1, slots, tip=(top - i) * GWEI // 10)
            self.add_writer(f'free{tag}', f'f{tag}', 0, 50_000, 1, slots, tip=FLOOR)
        finals = self.committed_reports()
        self.block()
        self.assertEqual(self.unpaid_slots(finals[-1]), [])
        self.assertLessEqual(sum(n for t in finals[-1]['tx_stats'] for _, n in t['fresh_slots']), sp.DEFAULTS['fresh_slots_per_block'])

    def test_a_payer_behind_non_payers_is_served_in_the_same_block(self):
        self.add_writer('unpaid', 'trent', 0, 50_000, 1, ['t0', 't1', 't2'], tip=5 * GWEI)  # 2.5e14 for three slots: no
        self.add_writer('payer', 'alice', 0, 50_000, 1, ['t0'], tip=4 * GWEI + GWEI // 10)  # 2.05e14 for one slot: pays
        finals = self.committed_reports()
        served = self.block()
        self.assertIn('payer', served)
        self.assertNotIn('unpaid', served)
        self.assertEqual(self.unpaid_slots(finals[-1]), [])


class UnpaidWaitsEscalate(PricedWorld):
    """Review R308-3P-2 (coordinator decision): the SENDER of an unpaid transaction waits 40 minutes, longer than a
    block interval, and twice as long after each further report, up to a day; while it waits its bytes are not
    handed to the producer. The wait follows the sender: a replacement or another nonce does not start again."""

    def given(self):
        seen = []
        inner = self.report

        def report(raws):
            seen.append({self.tx[r]['name'] for r in raws})
            return inner(raws)
        self.report = report
        return seen

    def test_waits_double_and_keep_the_non_payer_out_of_the_producer(self):
        self.add_writer('np', 'mallory', 0, 50_000, 1, ['own'], tip=GWEI)
        waits = []
        for _ in range(6):
            seen = self.given()
            self.block(advance=0)
            wait = self.policy.state['waits'].get('mallory:0')
            waits.append(round(wait['until'] - self.now))
            self.assertTrue(any('np' in names for names in seen), 'a non-payer whose wait ended is tried again')
            self.now += waits[-1] - 1          # one second before the wait ends: not handed over
            seen = self.given()
            self.block(advance=2)              # and then past it
            self.assertFalse(any('np' in names for names in seen), f'handed to the producer inside its wait {waits}')
            self.assertEqual(dict(self.plans[-1].held).get(next(iter(dict(self.plans[-1].held)))), 'unpaid-sender-wait')
        # measured from the end of the plan, which takes a few seconds of the world's clock
        self.assertTrue(all(0 <= want - got <= 30 for want, got in zip([2400, 4800, 9600, 19200, 38400, 76800], waits)), waits)

    def test_a_replacement_or_a_later_nonce_does_not_reset_the_senders_wait(self):
        self.add_writer('np', 'mallory', 0, 50_000, 1, ['own'], tip=GWEI)
        self.block(advance=0)
        first = self.policy.state['unpaid_senders']['mallory']
        self.assertEqual(first['count'], 1)
        self.assertEqual(self.policy.waiting_senders(self.now), {'mallory'})
        self.now += 2500   # past the first wait: the sender tries other bytes
        self.spool.clear()
        self.add_writer('np2', 'mallory', 0, 50_000, 1, ['own2'], tip=2 * GWEI)
        self.block(advance=0)
        second = self.policy.state['unpaid_senders']['mallory']
        self.assertEqual(second['count'], 2)
        self.assertGreaterEqual(second['until'] - second['at'], 4800)

    def test_the_producers_allowance_holds_the_rest_without_a_wait(self):
        self.add('behind', 'user', 0, 21_000, 1, tip=GWEI)
        inner = self.report

        def capped(raws):
            report = inner(raws)
            if any(self.tx[r]['name'] == 'behind' for r in raws):
                report['included'] = [n for n in report['included'] if self.tx_name(n) != 'behind']
                report['tx_stats'] = [t for t in report['tx_stats'] if self.tx_name(t['hash']) != 'behind']
                report['not_judged'] = [sp_hash(r) for r in raws if self.tx[r]['name'] == 'behind']
            return report
        self.report = capped
        self.block(advance=0)
        self.assertIn('unpaid-allowance-exhausted', dict(self.plans[-1].held).values())
        self.assertEqual(self.policy.state['waits'], {})

    def tx_name(self, name):
        return next(t['name'] for r, t in self.tx.items() if sp_hash(r) == name)


class CreditAndOwnDoing(PricedWorld):
    """Review R308-4P-1 and R308-4P-2 (agents/311 section 14). Credit is what a sender really paid in priority fees
    less the fee value of its work the producer executed and left out. A transaction the producer reports as made
    unpaid by an earlier transaction of the block (`own_doing: false`) is held without any wait."""

    def reporting(self, **fields):
        inner = self.report

        def report(raws):
            answer = inner(raws)
            for tx in answer['unpaid']:
                tx.update(fields)
            return answer
        self.report = report

    def test_credit_is_the_fees_paid_and_is_spent_by_wasted_work(self):
        self.add('pay', 'alice', 0, 21_000, 1, tip=GWEI)
        self.block(advance=0)
        self.assertEqual(self.policy.credits(self.now), {'alice': 21_000 * GWEI})
        self.spool.clear()
        self.add_writer('np', 'alice', 1, 50_000, 1, ['own'], tip=GWEI)
        self.reporting(gas_used=15_000, effective_tip=GWEI, own_doing=True)
        self.block(advance=0)
        self.assertEqual(self.policy.credits(self.now), {'alice': 6_000 * GWEI}, 'one debit per plan, whatever the passes')
        self.assertEqual(self.policy.waiting_senders(self.now), {'alice'})
        self.now += sp.DEFAULTS['credit_memory_seconds'] + 1
        self.assertEqual(self.policy.credits(self.now), {})

    def test_a_transaction_made_unpaid_by_another_one_does_not_wait_until_the_third_time(self):
        self.reporting(gas_used=30_000, effective_tip=GWEI, own_doing=False)
        for round_number in (1, 2):
            self.spool.clear()
            self.add_writer(f'v{round_number}', 'victim', 0, 50_000, 1, ['shared'], tip=GWEI)
            self.block(advance=0)
            self.assertIn('unpaid-in-this-block', dict(self.plans[-1].held).values())
            self.assertEqual(self.policy.waiting_senders(self.now), set())
            self.assertEqual(self.policy.state['waits'], {})
            self.now += 60
        self.spool.clear()
        self.add_writer('v3', 'victim', 0, 50_000, 1, ['shared'], tip=GWEI)
        self.block(advance=0)
        self.assertEqual(self.policy.waiting_senders(self.now), {'victim'}, 'the third report in the window is its own doing')

    def test_work_somebody_else_made_useless_is_not_debited_and_a_zero_tip_is_debited_at_the_floor(self):
        """Reviews R308-5P-6 and R308-5P-5."""
        self.add('pay', 'alice', 0, 21_000, 1, tip=GWEI)
        self.block(advance=0)
        before = self.policy.credits(self.now)['alice']
        self.spool.clear()
        self.add_writer('v', 'alice', 1, 50_000, 1, ['shared'], tip=GWEI)
        self.reporting(gas_used=15_000, effective_tip=GWEI, own_doing=False)
        self.block(advance=0)
        self.assertEqual(self.policy.credits(self.now)['alice'], before, 'made unpaid by another transaction: no debit')
        self.now += 60
        self.reporting(effective_tip=0, own_doing=True)
        self.block(advance=0)
        self.assertEqual(self.policy.credits(self.now)['alice'], before - 15_000 * sp.DEFAULTS['min_tip_wei'])

    def test_the_ledgers_survive_a_restart(self):
        self.add('pay', 'alice', 0, 21_000, 1, tip=GWEI)
        self.add_writer('np', 'mallory', 0, 50_000, 1, ['own'], tip=GWEI)
        self.block(advance=0)
        again = sp.Policy(self.policy.c, self.policy.path, clock=lambda: self.now)
        self.assertEqual(again.credits(self.now), self.policy.credits(self.now))
        self.assertEqual(again.waiting_senders(self.now), {'mallory'})


class ReserveHoldsOnAFullBlock(PricedWorld):
    """Agent 317 F317-3 (real stack, block 9): 128 plain transfers of eight senders with credit at 1.2 gwei and ten
    plain transfers of fresh keys at 0.2 to 1.1 gwei: the planner cut to 64 by tip before the producer's reserve
    saw anything, so 64 covered and no newcomer. Now the reserved places go to senders without credit first."""

    def test_newcomers_below_the_covered_tip_get_the_reserved_places_of_a_full_block(self):
        for sender in range(8):
            self.policy.state['credit'][f'rich{sender}'] = {'wei': 10**18, 'at': self.now}
            for nonce in range(16):
                self.add(f'r{sender}-{nonce}', f'rich{sender}', nonce, 21_000, 1, tip=12 * GWEI // 10)
        for i in range(10):
            self.add(f'new{i}', f'fresh{i}', 0, 21_000, 1, tip=(2 + i) * GWEI // 10)
        served = self.block(advance=0)
        self.assertEqual(len(served), 64)
        newcomers = sorted(n for n in served if n.startswith('new'))
        self.assertEqual(newcomers, sorted(f'new{i}' for i in range(2, 10)), 'the eight best bids among the newcomers')
        self.assertEqual(sum(n.startswith('r') for n in served), 56)

    def test_without_newcomers_every_place_goes_by_tip_as_before(self):
        for sender in range(8):
            self.policy.state['credit'][f'rich{sender}'] = {'wei': 10**18, 'at': self.now}
            for nonce in range(16):
                self.add(f'r{sender}-{nonce}', f'rich{sender}', nonce, 21_000, 1, tip=(12 + sender) * GWEI // 10)
        served = self.block(advance=0)
        self.assertEqual(len(served), 64)


def signed_bytes(kind, gas_limit, tag):
    """Hex of bytes shaped as a signed transaction of `kind` (0 legacy, 1 EIP-2930, 2 EIP-1559) that declares
    `gas_limit`; the signature is a filler, the planner reads the limit only."""
    import settler_v3 as settler
    n = lambda v: v.to_bytes((v.bit_length() + 7) // 8, 'big')  # noqa: E731
    tail = [b'\x11' * 20, n(1), tag.encode()]
    sig = [n(1), b'\x22' * 32, b'\x33' * 32]
    if kind == 0:
        return settler.rlp_encode([n(7), n(GWEI), n(gas_limit), *tail, *sig]).hex()
    head = [n(700770), n(7), n(GWEI)] + ([n(2 * GWEI)] if kind == 2 else [])
    return (bytes([kind]) + settler.rlp_encode([*head, n(gas_limit), *tail, [], *sig])).hex()


class CoveredIsTheProducersRule(PricedWorld):
    """Review R308-7P-3: the producer calls a transaction covered when the sender's credit reaches its gas LIMIT
    times its tip; the planner used the gas USED, so a sender between the two lost the reserved places."""

    def test_the_declared_gas_limit_is_read_from_the_three_envelopes(self):
        for kind in (0, 1, 2):
            for limit in (21_000, 100_000, 5_000_000):
                self.assertEqual(sp.raw_gas_limit(signed_bytes(kind, limit, 'x' * 60)), limit, (kind, limit))
        for bad in ('', '00', 'c0', '02c0', '03' + signed_bytes(2, 21_000, 'x')[2:], 'new0'.encode().hex(),
                    signed_bytes(2, 21_000, 'x')[:-2], signed_bytes(0, 21_000, 'x') + '00', 'f8'):
            self.assertIsNone(sp.raw_gas_limit(bad), bad)

    def full_block_with(self, credit):
        for sender in range(8):
            self.policy.state['credit'][f'rich{sender}'] = {'wei': 10**18, 'at': self.now}
            for nonce in range(16):
                self.add(f'r{sender}-{nonce}', f'rich{sender}', nonce, 21_000, 1, tip=12 * GWEI // 10)
        raw = signed_bytes(2, 100_000, 'between')   # a plain transfer (21,000 used) that declares 100,000
        tip = 5 * GWEI // 10
        self.tx[raw] = dict(name='between', sender='mid', nonce=0, gas=21_000, cost=1, tip=tip, fresh=[], fail_first=0)
        self.spool.append(raw)
        self.policy.state['credit']['mid'] = {'wei': credit(tip), 'at': self.now}
        served = self.block(advance=0)
        self.assertEqual(len(served), 64)
        return served

    def test_credit_between_gas_used_and_gas_limit_is_uncovered_and_gets_a_reserved_place(self):
        self.assertIn('between', self.full_block_with(lambda tip: 2 * 21_000 * tip))

    def test_credit_for_the_whole_gas_limit_is_covered_and_bids_by_tip(self):
        self.assertNotIn('between', self.full_block_with(lambda tip: 100_000 * tip))


class SettlerHandsTheLedgerToTheProducer(unittest.TestCase):
    """The settler passes the policy's credit ledger, its waiting senders and its gas cap to the producer."""

    def test_pool_arguments_carry_credits_waiting_and_the_gas_cap(self):
        import json
        import tempfile
        import settler_v3 as settler
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            worker = object.__new__(settler.Settler)
            worker.work, worker.policy_clock = work, lambda: 1_000_000
            worker.c = {'user_transactions': True, 'max_block_sp1_gas': 90_000_000, 'producer_write_price': True,
                        'max_block_gas': 15_000_000, 'max_block_bytes': 100_000, 'max_block_txs': 64, 'max_tx_gas': 5_000_000}
            policy = worker.policy()
            policy.state['credit'] = {'aa' * 20: {'wei': 42, 'at': 999_999}, 'bb' * 20: {'wei': 7, 'at': 1}}
            policy.state['unpaid_senders'] = {'cc' * 20: {'count': 1, 'at': 999_000, 'until': 1_001_000}}
            policy.save(1_000_000)
            pool = work / 'pool'
            pool.mkdir()
            args = worker.pool_arguments(pool)
            self.assertNotIn('--write-standing', args)
            self.assertEqual(args[args.index('--write-max-tx-gas') + 1], '5000000')
            self.assertEqual(json.loads(Path(args[args.index('--write-credits') + 1]).read_text()), {'aa' * 20: '42'},
                             'credit older than the memory window is not handed over')
            self.assertEqual(json.loads(Path(args[args.index('--write-waiting') + 1]).read_text()), ['cc' * 20])
            self.assertEqual(args[args.index('--write-uncovered-max-gas') + 1], '1500000')
            self.assertEqual(args[args.index('--write-reserve-divisor') + 1], '8')

    def test_the_seed_is_drawn_per_plan_and_the_plan_uses_one_set_of_inputs(self):
        """Review R308-5P-3: the seed is random, not the anchor; every producer call of one block plan gets the
        same seed and the same ledger (the measured block and the built block are selected alike), and the next
        plan gets another seed. Review R308-5P-2: what the block's order depended on is published beside it."""
        import json
        import tempfile
        import settler_v3 as settler
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            worker = object.__new__(settler.Settler)
            worker.work, worker.policy_clock = work, lambda: 1_000_000
            worker.c = {'user_transactions': True, 'max_block_sp1_gas': 90_000_000, 'producer_write_price': True,
                        'max_block_gas': 15_000_000, 'max_block_bytes': 100_000, 'max_block_txs': 64, 'max_tx_gas': 5_000_000}
            policy = worker.policy()
            policy.state['credit'] = {'aa' * 20: {'wei': 42, 'at': 999_999}, 'bb' * 20: {'wei': 9, 'at': 999_999}}
            policy.save(1_000_000)
            pool = work / 'pool.json'
            pool.write_text('[]')
            def seed(args):   # in a file of mode 0600, never on the command line (review R308-6P-3)
                self.assertNotIn('--write-seed', args)
                path = Path(args[args.index('--write-seed-file') + 1])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                return path.read_text().strip()
            outside = [seed(worker.pool_arguments(pool)) for _ in range(2)]
            self.assertNotEqual(outside[0], outside[1])
            self.assertEqual(len(bytes.fromhex(outside[0])), 32)
            worker.plan_inputs = worker.selection_inputs(policy)
            first = worker.pool_arguments(pool)
            policy.state['credit']['aa' * 20]['wei'] = 1          # a debit inside the plan, saved
            policy.save(1_000_000)
            second = worker.pool_arguments(pool)
            self.assertEqual(seed(first), seed(second))
            self.assertEqual(json.loads(Path(second[second.index('--write-credits') + 1]).read_text())['aa' * 20], '42')
            block = {'number': 7, 'hash': 'ee' * 32, 'tx_stats': [{'sender': 'aa' * 20}]}
            worker.publish_selection(work, policy, block)
            published = json.loads((work / 'selection.json').read_text())
            self.assertEqual(published['seed'], seed(first))
            self.assertEqual(published['credits'], {'aa' * 20: '42'}, 'only the senders of the block')
            self.assertEqual((published['max_gas'], published['max_txs'], published['reserve_divisor'], published['uncovered_max_gas']),
                             (15_000_000, 64, 8, 1_500_000))


class DatabaseCopyCarriesNoModeBits(unittest.TestCase):
    """Agent 312 F312-7: the settler unit has RestrictSUIDSGID=yes and the read-group database directories are
    setgid; a copy that sets a directory's mode from its source is refused there. `copy_database` never sets a mode
    (the same check under a real unit with that property: agents/311-evidence/f312-7/)."""

    def test_the_copy_calls_no_chmod_and_keeps_names_contents_and_links(self):
        import os
        import tempfile
        from unittest import mock
        import settler_v3 as settler
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'db', Path(directory) / 'copy'
            (source / 'db' / 'static').mkdir(parents=True)
            (source / 'db' / 'CURRENT').write_bytes(b'MANIFEST-000001\n')
            (source / 'db' / 'static' / '000001.sst').write_bytes(bytes(range(256)) * 64)
            os.symlink('CURRENT', source / 'db' / 'link')
            os.symlink('static', source / 'db' / 'dirlink')

            def refused(*args, **kwargs):
                raise PermissionError(1, 'Operation not permitted')
            with mock.patch('os.chmod', refused), mock.patch('shutil.copystat', refused), mock.patch('shutil.copymode', refused):
                settler.copy_database(source, target)
            self.assertEqual((target / 'db' / 'static' / '000001.sst').read_bytes(), bytes(range(256)) * 64)
            self.assertEqual(os.readlink(target / 'db' / 'link'), 'CURRENT')
            self.assertEqual(os.readlink(target / 'db' / 'dirlink'), 'static')
            self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob('*')),
                             sorted(p.relative_to(source).as_posix() for p in source.rglob('*')))


class ProducerTimeoutIsARefusal(unittest.TestCase):
    """Review R308-2P-13: a producer that does not answer is a ProducerError, which `extend` answers with the
    deposits-only block; it stays distinguishable (ProducerTimeout) for the kept-database scan of R308-22."""

    def test_a_timeout_of_the_producer_raises_the_refusal_class(self):
        import subprocess
        import settler_v3 as settler

        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))
        worker = object.__new__(settler.Settler)
        worker.c, worker.run, worker.network_args = {'produce': '/nonexistent/produce'}, run, []
        with self.assertRaises(settler.ProducerError) as caught:
            worker.produce('select', '--target', 'x')
        self.assertIsInstance(caught.exception, settler.ProducerTimeout)
        self.assertIn('timed out after 300 s for select', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
