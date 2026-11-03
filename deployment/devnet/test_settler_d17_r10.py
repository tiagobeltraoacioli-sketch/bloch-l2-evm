#!/usr/bin/env python3
"""D17 (owner decision, 2026-11-02): `foreign_recovery` ON at the deposit-only launch.

What the worker does when someone else settles a deposit-only block first, and that it cannot be used to make the
operator lose funds or pay twice. Same fake world as test_settler_foreign.py (real database directory, real swaps).

Run: python3 -m unittest discover -s deployment/devnet -p 'test_settler_d17_r10.py' -v
"""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_foreign as f  # noqa: E402
import test_settler_v3 as base  # noqa: E402

GENESIS = f.GENESIS_HASH
A1, A2, B1, B2 = f.block('a1'), f.block('a2'), f.block('b1'), f.block('b2')


class Unrelayed(f.World):
    """Endpoints that take our first settlement (`accepted`) and never get it included; a third party's block 1
    lands instead (a griefer racing the worker). Later settlements are included as usual."""

    def __init__(self, root, values, foreign):
        super().__init__(root, values)
        self.foreign_block, self.landed = foreign, False

    def rpc(self, port, method, params=()):
        if method == 'sendrawtransaction' and params[0].startswith('13') and (
                not self.landed or s.statement_fields(params[0][66:66 + 2 * s.VALUES_BYTES])['l2_number'] == 1):
            self.sent.append(bytes.fromhex(params[0]))
            if not self.landed:
                self.landed = True
                self.l1 = [self.foreign_block]
                self.foreign(1, self.foreign_block)
            return {'status': 'accepted', 'tx_hash': '00' * 32}
        return super().rpc(port, method, params)


class D17DepositOnly(unittest.TestCase):
    """The launch configuration: deposit-only, `foreign_recovery` on (installer default)."""

    def setUp(self):
        self.base = f.ForeignTest('config')  # its harness only, not its tests
        self.base.setUp()  # patches s.log (base.logged) and registers its own cleanups
        self.addCleanup(self.base.doCleanups)
        self.root = self.base.root

    def launch(self, world, **extra):
        # Idle holding and pacing (D15) only decide when the worker builds; test_settler_foreign.IdleTest covers them.
        return self.base.settler(world, **extra)

    def events(self, name):
        return self.base.events(name)

    def local(self, name='db'):
        return self.base.local(name)

    def da_sent(self, world):
        return self.base.da_sent(world)

    def settlements(self, world, number=None):
        sent = [t for t in world.sent if t[0] == s.ASYNC_SETTLEMENT_TAG]
        if number is None:
            return sent
        return [t for t in sent if s.statement_fields(t[33:33 + s.VALUES_BYTES].hex())['l2_number'] == number]

    def no_money_moved(self, world):
        self.assertEqual(self.da_sent(world), [], 'no DA transaction is ever sent')
        self.assertFalse([c for c in world.calls if Path(c[0]).name == 'bloch-pos'], 'the DA signer is never run')
        self.assertFalse(list((self.root / 'txpool').iterdir()), 'nothing enters the spool')
        self.assertFalse([c for c in world.calls if 'extend' in c and '--txs' in c], 'no block reads the spool')

    def test_a_block_settled_first_while_the_worker_holds_is_followed_without_a_halt(self):
        # The worker holds (pacing, a proof elsewhere, a restart) while a third party settles the identical block 1.
        world = f.World(self.root, b'')
        world.l1 = [A1]
        world.foreign(1, A1)
        settler = self.launch(world)
        self.assertFalse(settler.cycle(), 'waits for L1 finality of the foreign settlement; no halt')
        self.assertFalse([c for c in world.calls if 'reconstruct' in c or 'prove-groth16' in c])
        self.assertEqual(world.sent, [])
        world.finalize(A1)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [GENESIS, A1[0]], 'the rebuilt database is the settled chain')
        recovered = self.events('foreign-settlement-recovered')[0]
        self.assertEqual((recovered['orphaned_blocks'], recovered['wasted_proofs'], recovered['respooled']), ([], 0, 0))
        # The next block extends the foreign one and settles normally: the third party gained nothing.
        world.next_block, world.values = A2, f.values_for(2, A2)
        self.assertTrue(settler.cycle())
        self.assertEqual(len(self.settlements(world, 2)), 3, 'block 2 sent once to each of the three endpoints')
        self.assertEqual(self.settlements(world, 1), [], 'block 1 is never submitted by this worker')
        self.assertEqual(self.local(), [GENESIS, A1[0], A2[0]])
        self.no_money_moved(world)

    def test_the_same_situation_halts_without_foreign_recovery(self):
        world = f.World(self.root, b'')
        world.l1 = [A1]
        world.foreign(1, A1)
        with self.assertRaisesRegex(s.Halt, 'did not submit'):
            self.launch(world, recovery=False).cycle()

    def test_an_identical_block_settled_during_our_proof_is_ours_and_is_not_resubmitted(self):
        world = f.World(self.root, b'')
        world.values = f.values_for(1, A1)

        def land():
            world.l1 = [A1]
            world.accepted = {'statement': world.values.hex(), 'commitment': f.PARENT_COMMITMENT}
        world.during_prove = land
        settler = self.launch(world)
        self.assertFalse(settler.cycle(), 'the request moved during the proof: nothing is broadcast')
        self.assertEqual(world.sent, [])
        world.during_prove, world.next_block, world.values = None, A2, f.values_for(2, A2)
        self.assertTrue(settler.cycle())
        self.assertFalse([c for c in world.calls if 'reconstruct' in c], 'no rebuild: the local block is the settled one')
        self.assertEqual(self.settlements(world, 1), [])
        self.assertEqual(self.local(), [GENESIS, A1[0], A2[0]])
        self.no_money_moved(world)

    def test_a_different_block_landing_while_our_settlement_is_pending_is_recovered_not_halted(self):
        # M2 and D17 together: our block 1 was taken by every endpoint and never included; a third party's block 1
        # (another anchor or timestamp) lands instead. The worker neither halts on the refusals nor pays anything.
        world = Unrelayed(self.root, f.values_for(1, A1), B1)
        settler = self.launch(world)
        self.assertFalse(settler.cycle())
        self.assertEqual(len(self.settlements(world, 1)), 3, 'our bytes went to every endpoint once')
        self.assertEqual(self.events('halt'), [])
        world.finalize(B1)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [GENESIS, B1[0]])
        recovered = self.events('foreign-settlement-recovered')[0]
        self.assertEqual((recovered['orphaned_blocks'], recovered['wasted_proofs'], recovered['wasted_da_signed']),
                         ([1], 1, 0))
        sent_before = len(world.sent)
        world.next_block, world.values = A2, f.values_for(2, A2)
        self.assertTrue(settler.cycle())
        self.assertEqual(len(world.sent) - sent_before, 3)
        self.assertEqual(len(self.settlements(world, 1)), 3, 'the orphaned block 1 is never sent again')
        self.no_money_moved(world)

    def test_a_third_party_block_with_user_transactions_never_makes_this_worker_pay(self):
        # The third party is free to settle a block with its own user transactions and its own paid DA batch. The
        # rebuild replays them from L1; this deposit-only worker then builds on top without the spool and signs
        # nothing. Its DA key is unfunded at launch anyway (plan P6).
        world = f.World(self.root, b'')
        world.l1 = [B1]
        world.foreign(1, B1)
        world.finalize(B1)
        settler = self.launch(world, da=self.da_config_for_launch())
        self.assertTrue(settler.cycle())
        world.next_block, world.values = A2, f.values_for(2, A2)
        self.assertTrue(settler.cycle())
        self.assertEqual(self.local(), [GENESIS, B1[0], A2[0]])
        self.no_money_moved(world)

    def da_config_for_launch(self):
        # The installer writes the DA section even with user transactions off; it must stay unused.
        return {'signer': str(self.root / 'bloch-pos'), 'signer_sha256': s.digest(self.root / 'bloch-pos'),
                'genesis': 'g', 'funding_pubkey': str(self.root / 'da.pub'), 'keystore_dir': 'k', 'passphrase_file': 'p'}

    def test_repeated_griefing_costs_rebuilds_and_disk_stays_bounded(self):
        world = f.World(self.root, b'')
        settler = self.launch(world)
        chain = []
        for number, entry in enumerate((f.block('b1'), f.block('b2'), f.block('b3'), f.block('b4')), start=1):
            chain.append(entry)
            world.l1 = list(chain)
            world.foreign(number, entry)
            world.finalize(*chain)
            self.assertTrue(settler.cycle(), f'foreign block {number} recovered')
        self.assertEqual(self.local(), [GENESIS, *[e[0] for e in chain]])
        self.assertEqual(self.events('halt'), [])
        self.assertLessEqual(len(list(self.root.glob('db.orphaned-*'))), 2, 'foreign_recovery.keep bounds the disk')
        self.assertEqual(world.sent, [])
        self.no_money_moved(world)


if __name__ == '__main__':
    unittest.main()
