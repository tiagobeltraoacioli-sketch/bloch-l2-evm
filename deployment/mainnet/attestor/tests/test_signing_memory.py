#!/usr/bin/env python3
"""Review R308-18 (demonstration D6 of agent 308, kept as a regression test): the attestor's state was keyed by ROOT only. Nothing stops a second signature over a DIFFERENT withdrawal root
for an L2 block number it already signed (state['signed'] has no per-number record), and a lost state.json resets the
daily cap. The real Agent.cycle()/decide() run; only the follower, RPC view, rebuild, proof and bloch-pos are doubles."""
import importlib.util, json, os, shutil, sys, tempfile, unittest
from pathlib import Path
sys.dont_write_bytecode = True
A = str(__import__('pathlib').Path(__file__).resolve().parents[1])
sys.path.insert(0, A)
import attestor_agent as agent_mod  # noqa: E402
BLCH = 100_000_000

class SigningMemory(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
        c = {k: 'x' for k in agent_mod.REQUIRED}
        c.update(signer_index=0, state_dir=str(self.d / 'state'), rpc_urls=[], pause_file=str(self.d / 'PAUSE'),
                 approvals_file=str(self.d / 'approvals.txt'))
        self.a = agent_mod.Agent(c)
        self.signed = []
        self.root = None
        a = self.a
        a.follower = lambda: {}
        a.view = lambda: {'roots': [{'l2_number': 7, 'root': self.root, 'count': 1, 'height': 1}], 'claimed': {}}
        a.settlements = lambda status, check_digest=False: [
            {'l2_number': 7, 'l2_hash': 'h' + self.root, 'l2_state_root': 's', 'withdrawals': {'root': self.root, 'count': 1}}]
        a.rebuild = lambda work: (work, {'blocks': [{'number': 7, 'hash': 'h' + self.root, 'state_root': 's',
                                                    'withdrawal_root': self.root, 'withdrawal_count': 1}]})
        a.own_proof = lambda target, i, number, root, count: ({}, {'sats': 500 * BLCH, 'l1_recipient': 'r', 'leaf': 'l' + root, 'l2_block': number})
        a.sign = lambda doc, root: (self.signed.append(root), Path('/nonexistent'))[1]
        a.alert = lambda event, **f: print('  alert', event, f.get('l2_number'), f.get('root'))

    def test_second_different_root_for_a_signed_block_number_is_refused(self):
        self.root = 'aa' * 32; self.a.cycle()
        # the follower's finalized view of block 7 changes (binary swapped by upgrade / upgrade-rollback, state re-verified)
        self.root = 'bb' * 32; self.a.state_path.write_text(json.dumps({**self.a.load_state(), 'leaves': {}}))
        try:
            self.a.cycle()
        except agent_mod.Halt as e:   # r15 fix: the agent halts (exit 3) instead of signing
            print('  halt:', e)
        st = self.a.load_state()
        print('signed roots for L2 block 7:', self.signed, '| state keys:', {r: v['l2_number'] for r, v in st['signed'].items()})
        self.assertEqual(self.signed, ['aa' * 32], 'two different roots signed for the same L2 block number')

    def test_lost_state_keeps_the_daily_cap(self):
        self.a.c['daily_cap_sat'] = 600 * BLCH
        self.root = 'aa' * 32; self.a.cycle()                    # 500 BLCH of today's 600 used
        self.a.state_path.unlink()                               # state lost (disk, restore, reinstall of /var/lib)
        self.root = 'cc' * 32
        self.a.view = lambda: {'roots': [{'l2_number': 7, 'root': self.root, 'count': 1, 'height': 1}], 'claimed': {}}
        try:
            self.a.cycle()
        except agent_mod.Halt as e:   # r15 fix: a lost state.json halts
            print('  halt:', e)
        print('signed:', self.signed)
        self.assertEqual(self.signed, ['aa' * 32], 'the per-day cap restarted from zero after state.json was lost')

class Killed(BaseException):
    """The process dies here (SIGKILL, power, the upgrade's own stop): nothing after it runs."""


class SigningMemoryAcrossRestarts(unittest.TestCase):
    """Review R308-2P-9 (demonstrations of agent 308, second pass, kept as regression tests): sign() leaves the
    partial in the served outbox BEFORE the state is saved, and the "has signed" marker lived only in the
    directory whose loss it detects."""

    def agent(self):
        c = {k: 'x' for k in agent_mod.REQUIRED}
        c.update(signer_index=0, state_dir=str(self.d / 'state'), rpc_urls=[], pause_file=str(self.d / 'PAUSE'),
                 approvals_file=str(self.d / 'approvals.txt'), daily_cap_sat=self.cap, max_single_sat=10**18)
        a = agent_mod.Agent(c)
        a.follower = lambda: {}
        a.view = lambda: {'roots': [{'l2_number': self.number, 'root': self.root, 'count': 1, 'height': 1}], 'claimed': {}}
        a.settlements = lambda status, check_digest=False: [
            {'l2_number': self.number, 'l2_hash': 'h' + self.root, 'l2_state_root': 's', 'withdrawals': {'root': self.root, 'count': 1}}]
        a.rebuild = lambda work: (work, {'blocks': [{'number': self.number, 'hash': 'h' + self.root, 'state_root': 's',
                                                     'withdrawal_root': self.root, 'withdrawal_count': 1}]})
        a.own_proof = lambda target, i, number, root, count: ({}, {'sats': 500 * BLCH, 'l1_recipient': 'r', 'leaf': 'l' + root, 'l2_block': number})

        def sign(doc, root):
            final = a.outbox / agent_mod.lib.partial_relpath(a.pins.chain_id, root, a.index)
            final.parent.mkdir(parents=True, exist_ok=True)
            final.write_text('partial over ' + root + '\n')
            self.signed.append(root)
            return final
        a.sign = sign
        a.alert = lambda event, **f: self.on_alert(event)
        a.publish_pending = lambda state: None
        return a

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
        self.signed, self.on_alert, self.cap = [], lambda event: None, 10**18

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def die_after_the_partial(self, event):
        if event == 'signed':
            raise Killed()

    def test_death_between_the_partial_and_the_saved_state_does_not_allow_a_second_root(self):
        a = self.agent()
        self.number, self.root = 6, '66' * 32; a.cycle()
        self.number, self.root = 7, 'aa' * 32
        self.on_alert = self.die_after_the_partial
        with self.assertRaises(Killed):
            a.cycle()
        self.assertEqual(json.loads(a.state_path.read_text())['signing'], {'6': '66' * 32, '7': 'aa' * 32})
        self.assertNotIn('aa' * 32, json.loads(a.state_path.read_text())['signed'])
        b = self.agent(); self.on_alert = lambda event: None
        self.root = 'bb' * 32
        with self.assertRaisesRegex(agent_mod.Halt, 'refusing a second signature for the same L2 block'):
            b.cycle()
        self.assertEqual(self.signed, ['66' * 32, 'aa' * 32])

    def test_death_between_the_partial_and_the_saved_state_then_the_same_root_is_finished(self):
        a = self.agent()
        self.number, self.root = 7, 'aa' * 32
        self.on_alert = self.die_after_the_partial
        with self.assertRaises(Killed):
            a.cycle()
        b = self.agent(); self.on_alert = lambda event: None
        self.assertEqual(b.cycle(), 'ok')
        self.assertIn('aa' * 32, json.loads(b.state_path.read_text())['signed'])
        self.assertEqual(self.signed, ['aa' * 32, 'aa' * 32])

    def test_a_lost_state_directory_does_not_start_from_an_empty_memory(self):
        self.cap = 600 * BLCH
        a = self.agent()
        self.number, self.root = 7, 'aa' * 32; a.cycle()
        self.assertTrue((self.d / 'state-marker/state.initialized').exists())
        shutil.rmtree(a.state_dir)                        # state.json, the inner marker and the outbox go together
        b = self.agent()
        self.root = 'cc' * 32
        with self.assertRaisesRegex(agent_mod.Halt, 'never start again from an empty state'):
            b.cycle()
        self.assertEqual(self.signed, ['aa' * 32])

    def test_a_host_without_the_marker_directory_runs_as_before(self):
        """An install older than this kit: the sibling directory cannot be made. The agent logs once and goes on."""
        a = self.agent()
        (self.d / 'state-marker').write_text('not a directory\n')
        self.number, self.root = 7, 'aa' * 32
        self.assertEqual(a.cycle(), 'ok')
        self.assertEqual(self.signed, ['aa' * 32])
        self.assertTrue((a.state_dir / 'state.initialized').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
