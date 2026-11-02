#!/usr/bin/env python3
"""Review r10 (agent 152) of the settler kit at 4b7f4f7: tests for the findings in agents/152-settler-review.md.

Tests named `test_finding_*` FAIL on 4b7f4f7 and pass once the finding is fixed. Tests named `test_control_*` and
`test_evidence_*` pass on 4b7f4f7: a control shows the harness works, an evidence test pins the current behaviour that
a finding describes (a design or owner-decision point, not a code defect).

Run: python3 -m unittest discover -s deployment/devnet -p 'test_settler_review_r10.py' -v
No network, no prover, no Docker.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as t  # noqa: E402

# Runs Settler.run_bounded on a child that never ends, with SP1 segment discovery stubbed to one known file, so the
# cleanup path can be observed on any POSIX host (group_segments reads /proc, which the Mac lacks).
RUNNER = textwrap.dedent('''
    import subprocess, sys
    sys.path.insert(0, sys.argv[1])
    import settler_v3 as s
    shm, segment, pidfile, timeout = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
    s.group_segments = lambda pgid, directory: {segment}
    s.remove_leaked_segments.__defaults__ = (lambda path: False,)
    settler = s.Settler.__new__(s.Settler)
    settler.run, settler.c = subprocess.run, {'prover_shm_dir': shm}
    try:
        settler.run_bounded(['/bin/sh', '-c', 'echo $$ > ' + pidfile + '; exec sleep 600'], timeout=timeout,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        sys.exit(9)
''')


# The same for remote_prover.run_while_client_connected (the forced command on the prover host).
REMOTE_RUNNER = textwrap.dedent('''
    import subprocess, sys
    sys.path.insert(0, sys.argv[1])
    import remote_prover as rp
    shm, segment, pidfile, timeout = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
    rp.group_segments = lambda pgid, directory: {segment}
    rp.remove_leaked_segments.__defaults__ = (lambda path: False,)
    try:
        rp.run_while_client_connected(['/bin/sh', '-c', 'echo $$ > ' + pidfile + '; exec sleep 600'], {'PATH': '/usr/bin:/bin'},
                                      subprocess.DEVNULL, timeout, gone=lambda: False, poll_seconds=0.2, shm=shm)
    except SystemExit as stop:
        sys.exit(9 if stop.code == 70 else stop.code)
''')

def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    proc = Path(f'/proc/{pid}/stat')
    if proc.exists():
        return proc.read_text().split()[2] != 'Z'
    state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith('Z')


class RunBoundedSignals(unittest.TestCase):
    """F8 follow-up (finding M1): the prover group and its SP1 segments are cleaned up on a timeout, but not when the
    settler itself is stopped with SIGTERM (systemctl stop/restart, a unit stop during a proof)."""

    runner = RUNNER

    def start(self, timeout):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.segment, self.pidfile = root / 'sp1_review_r10', root / 'child.pid'
        self.segment.write_bytes(b'\0' * 64)
        runner = subprocess.Popen([sys.executable, '-c', self.runner, str(HERE), str(root), str(self.segment),
                                   str(self.pidfile), str(timeout)])
        deadline = time.monotonic() + 20
        while not (self.pidfile.exists() and self.pidfile.read_text().strip()) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.child = int(self.pidfile.read_text())
        self.addCleanup(self.kill_child)
        return runner

    def kill_child(self):
        try:
            os.killpg(self.child, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def test_control_timeout_kills_the_group_and_removes_the_segment(self):
        runner = self.start(timeout=2)
        self.assertEqual(runner.wait(30), 9)
        time.sleep(0.3)
        self.assertFalse(alive(self.child))
        self.assertFalse(self.segment.exists())

    def test_finding_sigterm_to_the_settler_cleans_up_the_prover_group_and_segments(self):
        runner = self.start(timeout=600)
        time.sleep(1.5)  # at least one poll of the group's segments
        runner.send_signal(signal.SIGTERM)
        runner.wait(30)
        time.sleep(0.3)
        self.assertFalse(self.segment.exists(), 'SIGTERM leaves the SP1 segments of the killed prover in /dev/shm')
        self.assertFalse(alive(self.child), 'SIGTERM leaves the prover group running (outside a systemd cgroup)')


class RemoteProverSignals(RunBoundedSignals):
    """The same gap on the prover host: remote_prover.py stopped by a signal (sshd or host shutdown, an operator kill)
    leaves the prover group running and its segments in /dev/shm, and its flock is released, so the next job starts
    a second prover beside the orphan."""
    runner = REMOTE_RUNNER


class ReviewR10(unittest.TestCase):
    setUp = t.SettlerV3Test.setUp
    tearDown = t.SettlerV3Test.tearDown
    config = t.SettlerV3Test.config
    settler = t.SettlerV3Test.settler
    remote = t.SettlerV3Test.remote
    quorum_settler = t.SettlerV3Test.quorum_settler
    da_config = t.SettlerV3Test.da_config

    # ---- finding M3: a prover timeout skips the fallback in `remote_prover.order` ----
    def test_finding_remote_timeout_falls_back_to_the_local_prover(self):
        fake = t.Fake(self.root, t.statement())
        inner = fake.run

        def run(argv, **kwargs):
            if Path(argv[0]).name == 'ssh':
                raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))
            return inner(argv, **kwargs)
        fake.run = run
        try:
            with mock.patch.object(s, 'log'):
                done = self.settler(fake, remote_prover=self.remote(order=['remote', 'local'])).cycle()
        except subprocess.TimeoutExpired:
            self.fail('the SSH timeout escaped prove(): "local" in remote_prover.order was never tried')
        self.assertTrue(done, 'an SSH timeout must count as a failed remote attempt, so "local" is tried next')
        provers = [c[1] for c in fake.calls if 'settlement-v3' in Path(c[0]).name]
        self.assertIn('prove-groth16', provers)

    def test_finding_local_timeout_falls_back_to_the_remote_prover(self):
        fake = t.Fake(self.root, t.statement())
        inner = fake.run

        def run(argv, **kwargs):
            if 'settlement-v3' in Path(argv[0]).name and 'prove-groth16' in argv:
                raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))
            return inner(argv, **kwargs)
        fake.run = run
        try:
            with mock.patch.object(s, 'log'):
                done = self.settler(fake, remote_prover=self.remote(order=['local', 'remote'])).cycle()
        except subprocess.TimeoutExpired:
            self.fail('the local prover timeout escaped prove(): "remote" in remote_prover.order was never tried')
        self.assertTrue(done, 'a local prover timeout must count as a failed local attempt, so "remote" is tried next')
        self.assertEqual(len(fake.remote_jobs), 1)

    # ---- finding M2: submission goes to the first endpoint that takes the bytes, only ----
    def test_finding_one_endpoint_that_accepts_and_drops_does_not_stop_settlement(self):
        fake = t.Fake(self.root, t.statement())
        ports = t.Ports(fake)
        inner = ports.rpc

        def rpc(port, method, params=()):
            if port == 1 and method == 'sendrawtransaction':
                ports.calls.append((port, method))  # a forked, partitioned or stuck node: "accepted", never relayed
                return {'status': 'accepted', 'tx_hash': '00' * 32}
            return inner(port, method, params)
        ports.rpc = rpc
        with mock.patch.object(s, 'log'):
            done = self.quorum_settler(ports).cycle()
        sent_to = sorted({p for p, m in ports.calls if m == 'sendrawtransaction'})
        self.assertTrue(done, f'the settlement was only ever sent to endpoint(s) {sent_to}; '
                              'one bad endpoint out of three stops settlement')

    # ---- finding L1: a partial quorum can never follow a real L1 reorg below the in-memory floor ----
    def test_finding_partial_quorum_behind_the_floor_does_not_stall_silently(self):
        fake = t.Fake(self.root, t.statement())
        fake.accepted = {'statement': t.statement().hex(), 'commitment': '99' * 32}
        ports = t.Ports(fake)
        settler = self.quorum_settler(ports)
        self.assertIsNotNone(settler.native_view())
        self.assertEqual(settler.accepted_floor, 1)
        ports.modes = {1: 'down'}  # one endpoint gone for good
        fake.accepted = None  # an L1 reorg removed the accepted settlement; both live endpoints agree on it
        outcomes = []
        with mock.patch.object(s, 'log'):
            for _ in range(300):
                try:
                    outcomes.append(settler.native_view())
                except Exception as error:  # noqa: BLE001 - any loud outcome (halt, exit for a restart) is fine
                    outcomes.append(error)
                    break
        self.assertFalse(all(o is None for o in outcomes),
                         '300 consistent quorum reads below the floor were all dropped: the worker waits forever '
                         'without a failure count, an exit or a halt')

    # ---- evidence for finding M4 (D17 rationale): a foreign deposit-only settlement halts the launch config ----
    def test_evidence_foreign_identical_deposit_only_settlement_halts_without_foreign_recovery(self):
        fake = t.Fake(self.root, t.statement())
        fake.accepted = {'statement': t.statement().hex(), 'commitment': '99' * 32}  # block 1, settled by a third party
        fake.head = 0  # this worker had not built block 1 yet (held idle, proving, restarting)
        with mock.patch.object(s, 'log'), self.assertRaisesRegex(s.Halt, 'did not submit'):
            self.settler(fake).cycle()


if __name__ == '__main__':
    unittest.main()
