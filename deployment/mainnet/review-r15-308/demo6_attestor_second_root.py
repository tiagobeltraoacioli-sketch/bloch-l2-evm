#!/usr/bin/env python3
"""D6: the attestor's state is keyed by ROOT only. Nothing stops a second signature over a DIFFERENT withdrawal root
for an L2 block number it already signed (state['signed'] has no per-number record), and a lost state.json resets the
daily cap. The real Agent.cycle()/decide() run; only the follower, RPC view, rebuild, proof and bloch-pos are doubles."""
import importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path
sys.dont_write_bytecode = True
A = str(__import__('pathlib').Path(__file__).resolve().parents[1] / 'attestor')
sys.path.insert(0, A)
import attestor_agent as agent_mod  # noqa: E402
BLCH = 100_000_000

class D6(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main(verbosity=2)
