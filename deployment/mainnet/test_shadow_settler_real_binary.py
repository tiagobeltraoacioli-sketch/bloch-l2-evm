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


if __name__ == '__main__':
    unittest.main()
