#!/usr/bin/env python3
"""Second pass on b6ebf1e (upgrade keeps the operator's PAUSE). Uses the kit's own rehearsal harness
(tests/test_upgrade.py: --prefix, fake services, fake check); everything lives under TMPDIR (this scratch dir).

`upgrade --no-unpause` ends in phase `verified`, which the script treats as an UNFINISHED upgrade for ever
(install-attestor.sh:474-476, 498-500, 508). The operator resumes signing by hand as the script tells him. At the next
incident he sets PAUSE; any later `upgrade` is refused with "use --resume", and `--resume` restores the
was_paused=0 / was_active=1 recorded weeks before (:502-503) and removes his PAUSE (:489)."""
import sys, unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1] / 'attestor/tests'))
import test_upgrade as t  # noqa: E402


class StaleVerified(t.UpgradeScriptTest):
    def test_u1_resume_after_no_unpause_removes_a_pause_set_later(self):
        done = self.upgrade('--no-unpause', now=t.FORK_UNIX + 86_400)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.state()['phase'], 'verified')
        # the operator resumes signing as the script printed: rm PAUSE; systemctl start bloch-l2-attestor
        (self.etc / 'PAUSE').unlink()
        (self.root / 'agent.started').write_text('started by the operator\n')
        # ... later: an incident, the operator pauses signing
        (self.etc / 'PAUSE').write_text('operator pause: incident\n')
        again = self.upgrade(now=t.FORK_UNIX + 30 * 86_400)
        print('  a new upgrade says:', (again.stdout + again.stderr).strip().splitlines()[-1])
        # Adapted by the developer (fix of R308-2P-8): a finished --no-unpause upgrade no longer refuses the next
        # `upgrade`; the reviewer's line was assertNotEqual(again.returncode, 0). The finding's assertion is below.
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        resumed = self.upgrade('--resume', now=t.FORK_UNIX + 30 * 86_400)
        print('  --resume ends with:', resumed.stdout.strip().splitlines()[-2:])
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertTrue((self.etc / 'PAUSE').exists(), 'upgrade --resume deleted the PAUSE the operator set for an incident')


if __name__ == '__main__':
    suite = unittest.TestSuite([StaleVerified('test_u1_resume_after_no_unpause_removes_a_pause_set_later')])
    sys.exit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
