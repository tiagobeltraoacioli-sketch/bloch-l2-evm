#!/usr/bin/env python3
"""Second pass on b6ebf1e (attestor signing memory). Real Agent.cycle()/decide()/load_state()/save_state(); doubles as in
tests/test_signing_memory.py, except that sign() leaves the partial in the outbox, as the real sign() does
(attestor_agent.py:462-464) BEFORE decide() records state['signed'] (:444) and cycle() saves it (:379)."""
import json, os, shutil, sys, tempfile, unittest
from pathlib import Path
sys.dont_write_bytecode = True
KIT = str(__import__('pathlib').Path(__file__).resolve().parents[1] / 'attestor')
sys.path.insert(0, KIT)
import attestor_agent as agent_mod  # noqa: E402
import attestor_lib as lib  # noqa: E402
BLCH = 100_000_000
SCRATCH = str(Path(__file__).resolve().parent / 'tmp')


class Killed(BaseException):
    """The process dies here (SIGKILL, OOM, power, `systemctl stop` of an upgrade): nothing after it runs."""


class Memory2(unittest.TestCase):
    def agent(self):
        c = {k: 'x' for k in agent_mod.REQUIRED}
        c.update(signer_index=0, state_dir=str(self.d / 'state'), rpc_urls=[], pause_file=str(self.d / 'PAUSE'),
                 approvals_file=str(self.d / 'approvals.txt'))
        a = agent_mod.Agent(c)
        a.follower = lambda: {}
        a.view = lambda: {'roots': [{'l2_number': self.number, 'root': self.root, 'count': 1, 'height': 1}], 'claimed': {}}
        a.settlements = lambda status, check_digest=False: [
            {'l2_number': self.number, 'l2_hash': 'h' + self.root, 'l2_state_root': 's', 'withdrawals': {'root': self.root, 'count': 1}}]
        a.rebuild = lambda work: (work, {'blocks': [{'number': self.number, 'hash': 'h' + self.root, 'state_root': 's',
                                                     'withdrawal_root': self.root, 'withdrawal_count': 1}]})
        a.own_proof = lambda target, i, number, root, count: ({}, {'sats': 500 * BLCH, 'l1_recipient': 'r', 'leaf': 'l' + root, 'l2_block': number})

        def sign(doc, root):   # the partial reaches the outbox (served by sigfeed.py at once), as in the real sign()
            final = a.outbox / lib.partial_relpath(a.pins.chain_id, root, a.index)
            final.parent.mkdir(parents=True, exist_ok=True)
            final.write_text('partial over ' + root + '\n')
            self.signed.append(root)
            return final
        a.sign = sign
        a.alert = lambda event, **f: self.on_alert(event)
        a.publish_pending = lambda state: None
        return a

    def setUp(self):
        os.makedirs(SCRATCH, exist_ok=True)
        self.d = Path(tempfile.mkdtemp(dir=SCRATCH))
        self.signed, self.on_alert = [], lambda event: None
        self.c = {'daily_cap_sat': 10**18, 'max_single_sat': 10**18}

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_m1_death_between_the_partial_and_the_saved_state_allows_a_second_root(self):
        a = self.agent(); a.c.update(self.c)
        self.number, self.root = 6, '66' * 32; a.cycle()                      # an earlier block: state.json exists
        self.number, self.root = 7, 'aa' * 32

        def die_on_signed(event):
            if event == 'signed':
                raise Killed()                                               # after sign(), before save_state()
        self.on_alert = die_on_signed
        with self.assertRaises(Killed):
            a.cycle()
        self.assertTrue(list(a.outbox.rglob('*.partial')), 'the partial over aa.. is in the outbox (public feed)')
        b = self.agent(); b.c.update(self.c); self.on_alert = lambda event: None   # the unit restarts
        self.root = 'bb' * 32                                                # the view of block 7 changed meanwhile
        try:
            b.cycle()
        except agent_mod.Halt as e:
            print('  halt:', e)
        print('  partials in the outbox for block 7 and 6:', sorted(p.parent.name[:4] for p in b.outbox.rglob('*.partial')))
        self.assertEqual(self.signed, ['66' * 32, 'aa' * 32], 'two different roots signed for L2 block 7')

    def test_m2_a_lost_state_directory_starts_from_an_empty_memory(self):
        a = self.agent(); a.c.update(self.c); a.c['daily_cap_sat'] = 600 * BLCH
        self.number, self.root = 7, 'aa' * 32; a.cycle()                     # 500 of today's 600 BLCH used
        shutil.rmtree(a.state_dir)                                           # /var/lib/bloch-l2-attestor lost or recreated:
        b = self.agent(); b.c.update(self.c); b.c['daily_cap_sat'] = 600 * BLCH   # state.json, the marker and the outbox go together
        self.root = 'cc' * 32
        try:
            b.cycle()
        except agent_mod.Halt as e:
            print('  halt:', e)
        self.assertEqual(self.signed, ['aa' * 32], 'second root for block 7 signed and the daily cap restarted')


if __name__ == '__main__':
    unittest.main(verbosity=2)
