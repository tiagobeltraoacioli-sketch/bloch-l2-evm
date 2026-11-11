#!/usr/bin/env python3
"""D2: `install-attestor.sh upgrade` removes a PAUSE the operator had put in place BEFORE the upgrade, and starts an
agent that was stopped before the upgrade. Uses the kit's own rehearsal harness (tests/test_upgrade.py: --prefix,
--service-cmd, --check-cmd), no root, no systemd."""
import importlib.util, sys, unittest
T = str(__import__('pathlib').Path(__file__).resolve().parents[1] / 'attestor/tests/test_upgrade.py')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('kit_test_upgrade', T)
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)

class D2(t.UpgradeScriptTest):
    def test_upgrade_keeps_an_operator_pause_and_a_stopped_agent(self):
        # The operator paused this attestor for an incident and stopped the agent (README: "Rollback per host: touch PAUSE").
        (self.etc / 'PAUSE').write_text('operator pause: incident 2026-11-10\n')
        self.assertFalse((self.root / 'agent.started').exists())          # the agent is NOT running
        done = self.upgrade(now=t.FORK_UNIX - 86_400)                       # no --no-unpause: the documented default
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        print('\n'.join(l for l in done.stdout.splitlines() if 'PAUSE' in l or 'agent' in l))
        print('PAUSE exists after upgrade:', (self.etc / 'PAUSE').exists(),
              '| agent running after upgrade:', (self.root / 'agent.started').exists())
        self.assertTrue((self.etc / 'PAUSE').exists(), 'upgrade deleted the PAUSE the operator set before it')
        self.assertFalse((self.root / 'agent.started').exists(), 'upgrade started an agent that was stopped before it')

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], 'D2.test_upgrade_keeps_an_operator_pause_and_a_stopped_agent'], verbosity=2)
