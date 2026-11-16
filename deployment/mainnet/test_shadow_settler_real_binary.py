#!/usr/bin/env python3
"""Review R308-5P-2 (round 15): the settler's code and the shadow's code on one pool, with the REAL producer.

Skipped unless BLOCH_L2_PRODUCE_DEV names a `bloch-l2-produce-dev` binary of this tree (development rules, no
network arguments). What runs is the code of record on both sides: `settler_v3.Settler.pool_arguments`,
`selection_inputs`, `publish_selection`; `sequencer_mainnet.Sequencer.settler_transactions`, `extend_args`,
`check_order`. The pool: one sender with credit and two without (`sign-tx` gives every transaction the same
tip; the order by tip against the order by credit is tests/produce_txs.rs `r308_5p_2_…`).
Run: BLOCH_L2_PRODUCE_DEV=/path/to/bloch-l2-produce-dev python3 -B -m unittest -v test_shadow_settler_real_binary
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'devnet')]
import sequencer_mainnet as q  # noqa: E402
import settler_v3 as settler  # noqa: E402

BIN = os.environ.get('BLOCH_L2_PRODUCE_DEV')
ANCHOR = 'ab' * 32
GWEI = 10**9


def produce(*args):
    done = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True, timeout=300)
    if done.returncode:
        raise RuntimeError(f'{args[0]}: {done.stderr.strip()[:600]}')
    return json.loads(done.stdout) if done.stdout.strip().startswith('{') else done.stdout


@unittest.skipUnless(BIN, 'BLOCH_L2_PRODUCE_DEV is not set')
class SettlerAndShadowOnOnePool(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.keys, self.senders = [], []
        for i in range(3):
            key = self.root / f'k{i}.hex'
            key.write_text(f'{i + 1:064x}\n')
            key.chmod(0o600)
            self.keys.append(key)
            self.senders.append(produce('address', '--key', key)['address'])
        self.deposits = self.root / 'deposits.json'
        self.deposits.write_text(json.dumps([{'height': 3, 'tx_index': i, 'txid': f'{i + 1:064x}', 'vout': 0,
                                              'sats': 100_000_000, 'recipient': sender} for i, sender in enumerate(self.senders)]))
        # Sender 0 has credit and offers the lowest fee; senders 1 and 2 have none and offer more.
        self.raws = []
        for i, fee in enumerate((2 * GWEI, 50 * GWEI, 30 * GWEI)):
            out = self.root / f't{i}.tx'
            produce('sign-tx', '--key', self.keys[i], '--nonce', 0, '--to', '55' * 20, '--value-wei', 1000,
                    '--max-fee-wei', fee, '--out', out)
            self.raws.append(out.read_text().strip())
        self.logs = []
        original = q.log
        q.log = lambda event, **fields: self.logs.append((event, fields))
        self.addCleanup(setattr, q, 'log', original)

    def database(self, name):
        db = self.root / name
        return db, produce('init', '--target', db)['hash']

    def settler_block(self):
        """The settler's side: its own arguments, the real producer, `selection.json` and the DA batch beside the block."""
        work = self.root / 'settler-work'
        directory = work / f'{1:08d}-{ANCHOR[:16]}'
        directory.mkdir(parents=True)
        worker = object.__new__(settler.Settler)
        worker.work, worker.policy_clock = work, lambda: 1_000_000
        worker.c = {'user_transactions': True, 'max_block_sp1_gas': 90_000_000, 'producer_write_price': True,
                    'max_block_gas': 15_000_000, 'max_block_bytes': 100_000, 'max_block_txs': 64, 'max_tx_gas': 5_000_000}
        policy = worker.policy()
        policy.state['credit'] = {self.senders[0]: {'wei': 21_000 * 2 * GWEI, 'at': 999_999}}
        policy.save(1_000_000)
        worker.plan_inputs = worker.selection_inputs(policy)
        pool = directory / 'selected.json'
        pool.write_text(json.dumps(self.raws))
        db, genesis = self.database('settler-db')
        block = produce('extend', '--target', db, '--parent', genesis, '--anchor', ANCHOR, '--deposits', self.deposits,
                        *worker.pool_arguments(pool))
        worker.publish_selection(directory, policy, block)
        (directory / 'block.json').write_text(json.dumps(block))
        produce('da', '--target', db, '--number', 1, '--out', directory / 'da-payload.hex')
        return directory, block

    def shadow(self, name):
        seq = object.__new__(q.Sequencer)
        seq.work = self.root / f'{name}-work'
        seq.work.mkdir()
        db, genesis = self.database(f'{name}-db')
        seq.c = {**q.DEFAULTS, 'l2_db': str(db), 'user_transactions': False}
        seq.produce = produce
        # Development rules: no timestamp rule, no rule set (the mainnet arguments are not part of what is tested).
        seq.extend_args = lambda parent, anchor, deposits, anchor_slot, shadow_txs=None: [
            a for a in q.Sequencer.extend_args(type('C', (), {'c': {**seq.c, 'next_elf_keccak': None}})(), parent, anchor, deposits, 0, shadow_txs)
            if a not in ('--timestamp-rule', q.TIMESTAMP_RULE, '--anchor-slot', '0')]
        return seq, genesis

    def rebuild(self, seq, genesis, directory, block):
        txs = seq.work / 'settler-transactions.json'
        txs.write_text(json.dumps(seq.settler_transactions(1, directory, block)))
        seq.check_order(1, seq.work, directory, block, txs, seq.extend_args(genesis, ANCHOR, self.deposits, 0, txs))
        return produce(*seq.extend_args(genesis, ANCHOR, self.deposits, 0, txs))

    def test_the_shadow_rebuilds_the_settlers_block_and_finds_its_order_in_policy(self):
        directory, block = self.settler_block()
        self.assertEqual(block['transactions'], 3, block)
        self.assertEqual(block['tx_stats'][0]['sender'], self.senders[0], 'the sender with credit goes first, at the lowest fee')
        seq, genesis = self.shadow('shadow')
        rebuilt = self.rebuild(seq, genesis, directory, block)
        self.assertEqual((rebuilt['hash'], rebuilt['state_root']), (block['hash'], block['state_root']))
        self.assertEqual([event for event, _ in self.logs], ['shadow-order-ok'], self.logs)

    def test_a_settler_that_reorders_against_the_policy_is_reported_and_its_block_is_still_checked(self):
        directory, honest = self.settler_block()
        # The cheat: the same transactions with the sender without credit that paid most put first, published with
        # the honest inputs. It is a valid block.
        order = [self.raws[1], self.raws[0], self.raws[2]]
        listed = self.root / 'cheat.json'
        listed.write_text(json.dumps(order))
        db, genesis = self.database('cheat-db')
        cheat = produce('extend', '--target', db, '--parent', genesis, '--anchor', ANCHOR, '--deposits', self.deposits,
                        '--txs', listed, '--as-given', 'yes')
        self.assertNotEqual(cheat['hash'], honest['hash'])
        (directory / 'da-payload.hex').unlink()
        produce('da', '--target', db, '--number', 1, '--out', directory / 'da-payload.hex')
        selection = json.loads((directory / 'selection.json').read_text())
        (directory / 'selection.json').write_text(json.dumps({**selection, 'hash': cheat['hash']}))
        (directory / 'block.json').write_text(json.dumps(cheat))
        seq, genesis = self.shadow('shadow')
        rebuilt = self.rebuild(seq, genesis, directory, cheat)
        self.assertEqual(rebuilt['hash'], cheat['hash'], 'the block is rebuilt and matched as a block')
        self.assertEqual([event for event, _ in self.logs], ['shadow-policy-mismatch'], self.logs)
        self.assertEqual(self.logs[0][1]['position'], 0)


@unittest.skipUnless(BIN, 'BLOCH_L2_PRODUCE_DEV is not set')
class ReserveOnAFullBlock(unittest.TestCase):
    """Agent 317 F317-3 on the real producer, with the planner's own cut: eight senders with credit hold 128
    plain transfers, ten fresh keys one each. A block has 64 places: 56 go to the covered senders and 8 to the
    newcomers, although nobody among them bids more (before: 64 covered, no newcomer)."""

    def test_eight_places_of_a_full_block_go_to_senders_without_credit(self):
        import sequencer_policy_v2 as sp
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys, senders = [], []
            for i in range(18):
                key = root / f'k{i}.hex'
                key.write_text(f'{i + 101:064x}\n')
                key.chmod(0o600)
                keys.append(key)
                senders.append(produce('address', '--key', key)['address'])
            deposits = root / 'deposits.json'
            deposits.write_text(json.dumps([{'height': 3, 'tx_index': i, 'txid': f'{i + 1:064x}', 'vout': 0,
                                             'sats': 100_000_000, 'recipient': sender} for i, sender in enumerate(senders)]))
            raws, owner = [], {}
            for i in range(18):
                for nonce in range(16 if i < 8 else 1):
                    out = root / f't{i}-{nonce}.tx'
                    produce('sign-tx', '--key', keys[i], '--nonce', nonce, '--to', '55' * 20, '--value-wei', 1000, '--out', out)
                    raws.append(out.read_text().strip())
                    owner[raws[-1]] = i
            self.assertEqual(len(raws), 138)
            work = root / 'work'
            work.mkdir()
            worker = object.__new__(settler.Settler)
            worker.work, worker.policy_clock = work, lambda: 1_000_000
            worker.c = {'user_transactions': True, 'max_block_sp1_gas': 90_000_000, 'producer_write_price': True,
                        'max_block_gas': 15_000_000, 'max_block_bytes': 100_000, 'max_block_txs': 64, 'max_tx_gas': 5_000_000}
            policy = worker.policy()
            policy.state['credit'] = {senders[i]: {'wei': 10**18, 'at': 999_999} for i in range(8)}
            policy.save(1_000_000)
            worker.plan_inputs = worker.selection_inputs(policy)
            db = root / 'db'
            genesis = produce('init', '--target', db)['hash']
            base = ['--target', db, '--parent', genesis, '--anchor', ANCHOR, '--deposits', deposits]
            # The planner's view: the producer's own selection of the whole pool, then the cut to 64.
            dry = root / 'dry.json'
            dry.write_text(json.dumps(raws))
            report = produce('select', *base, *worker.pool_arguments(dry, selecting=True))
            self.assertEqual(len(report['tx_stats']), 138, report.get('deferred'))
            info = {tx['hash']: tx for tx in report['tx_stats']}
            by_hash = {q.keccak256(bytes.fromhex(raw)).hex(): raw for raw in raws}
            plan = sp.Plan()
            chosen = policy._capped(policy.try_order(report['tx_stats'], 1_000_000), info, plan, 1_000_000)
            self.assertEqual(len(chosen), 64)
            pool = root / 'selected.json'
            pool.write_text(json.dumps([by_hash[name] for name in chosen]))
            block = produce('extend', *base, *worker.pool_arguments(pool))
            self.assertEqual(block['transactions'], 64, block.get('deferred'))
            newcomers = [tx for tx in block['tx_stats'] if tx['sender'] in senders[8:]]
            self.assertEqual((len(newcomers), len(block['tx_stats']) - len(newcomers)), (8, 56))
            self.assertTrue(all(tx['sender'] in senders[:8] for tx in block['tx_stats'][:56]), 'covered first, then the reserve')


@unittest.skipUnless(BIN, 'BLOCH_L2_PRODUCE_DEV is not set')
class ForcedBlocksUnderTheNextRules(unittest.TestCase):
    """Agent 317 F317-4 on the real producer under the mainnet next rules (the only rules with L1 forced
    inclusion): a block whose only transaction is a forced record, built with the settler's arguments and
    rebuilt with the shadow's from the native view; then a block with a forced record and a user transaction."""
    NET = q.NETWORK_ARGS
    SLOT = 187200

    def run_net(self, *args):
        return produce(*args, *self.NET)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.keys, self.senders = [], []
        for i in range(2):
            key = self.root / f'k{i}.hex'
            key.write_text(f'{i + 201:064x}\n')
            key.chmod(0o600)
            self.keys.append(key)
            self.senders.append(self.run_net('address', '--key', key)['address'])
        self.deposits = self.root / 'deposits.json'
        self.deposits.write_text(json.dumps([{'height': 3, 'tx_index': i, 'txid': f'{i + 1:064x}', 'vout': 0,
                                              'sats': 100_000_000, 'recipient': sender} for i, sender in enumerate(self.senders)]))
        self.raws = []
        for i in range(2):
            out = self.root / f't{i}.tx'
            self.run_net('sign-tx', '--key', self.keys[i], '--nonce', 0, '--to', '55' * 20, '--value-wei', 1000, '--out', out)
            self.raws.append(out.read_text().strip())
        envelope = self.raws[0]
        self.record = {'height': 9, 'l1_txid': '1c' * 32, 'envelope_hash': q.keccak256(bytes.fromhex(envelope)).hex(),
                       'gas_limit': 21_000, 'envelope': envelope}

    def settler_side(self, users):
        """The settler's own arguments for a block with the forced record and `users` user transactions."""
        directory = self.root / 'settler-work' / f'{1:08d}-{ANCHOR[:16]}'
        directory.mkdir(parents=True)
        deposits = directory / 'deposits.json'
        deposits.write_text(self.deposits.read_text())
        (directory / 'forced.json').write_text(json.dumps([self.record], sort_keys=True))
        worker = object.__new__(settler.Settler)
        worker.c = {'l2_db': str(self.root / 'settler-db'), 'timestamp_rule': q.TIMESTAMP_RULE, 'user_transactions': True}
        worker.next_program, worker.program, worker.spool_open = {'rules': 'next'}, {'rules': 'next'}, True
        genesis = self.run_net('init', '--target', worker.c['l2_db'])['hash']
        args = worker.extend_arguments(genesis, ANCHOR, deposits, self.SLOT, spool=False)
        if users:
            pool = directory / 'selected.json'
            pool.write_text(json.dumps(self.raws[1:1 + users]))
            args += ['--txs', pool]
        block = self.run_net(*args)
        (directory / 'block.json').write_text(json.dumps(block))
        if users:
            self.run_net('da', '--target', worker.c['l2_db'], '--number', 1, '--out', directory / 'da-payload.hex')
        return directory, block, genesis

    def shadow_side(self, directory, block):
        """The shadow's own code: the due records from the native view, its arguments, the real producer."""
        seq = object.__new__(q.Sequencer)
        seq.c = {**q.DEFAULTS, 'l2_db': str(self.root / 'shadow-db'), 'next_elf_keccak': 'set'}
        seq.rule_set = 'next'
        genesis = self.run_net('init', '--target', seq.c['l2_db'])['hash']
        view = {'forced': {'due': [dict(self.record, l1_txid='0x' + self.record['l1_txid'])], 'due_hash': 'ab' * 32, 'queued': 1}}
        due = q.forced_due(q.view_projection(view))
        forced = self.root / 'shadow-forced.json'
        forced.write_text(json.dumps(due, sort_keys=True))
        txs = None
        if q.user_count(block):
            txs = self.root / 'settler-transactions.json'
            txs.write_text(json.dumps(seq.settler_transactions(1, directory, block)))
        return self.run_net(*seq.extend_args(genesis, ANCHOR, self.deposits, self.SLOT, txs, forced))

    def test_a_block_whose_only_transaction_is_a_forced_record_is_rebuilt(self):
        directory, block, _ = self.settler_side(users=0)
        self.assertEqual((block['transactions'], block.get('user_transactions')), (1, 0), block)
        self.assertFalse((directory / 'da-payload.hex').exists(), 'a forced-only block has no DA batch')
        rebuilt = self.shadow_side(directory, block)
        self.assertEqual((rebuilt['hash'], rebuilt['state_root'], rebuilt['transactions']),
                         (block['hash'], block['state_root'], 1))

    def test_a_block_with_a_forced_record_and_a_user_transaction_is_rebuilt(self):
        directory, block, _ = self.settler_side(users=1)
        self.assertEqual((block['transactions'], block.get('user_transactions')), (2, 1), block)
        rebuilt = self.shadow_side(directory, block)
        self.assertEqual((rebuilt['hash'], rebuilt['state_root'], rebuilt['transactions']),
                         (block['hash'], block['state_root'], 2))


if __name__ == '__main__':
    unittest.main()
