#!/usr/bin/env python3
"""Fixes for review r10 (agents/152-settler-review.md) M1 and M2, beyond agent 152's own failing tests
(test_settler_review_r10.py), which must pass too.

M1: a stop signal (SIGTERM, SIGINT, SIGHUP) takes the F8 cleanup path in settler_v3.run_bounded and
remote_prover.run_while_client_connected; a second signal cannot interrupt that cleanup; the Gnark container of a
stopped prover is killed; the process then ends by the same signal.
M2: every settlement and DA transaction goes to every endpoint; `duplicate` counts as held; a settlement held but never
included while L1 advances halts after `max_unincluded_windows` acceptance windows.

Run: python3 -m unittest discover -s deployment/devnet -p 'test_settler_m1m2_r10.py' -v
No network, no prover, no Docker (a fake `docker` on PATH only answers which()).
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import remote_prover as rp  # noqa: E402
import settler_v3 as s  # noqa: E402
import test_settler_review_r10 as review  # noqa: E402
import test_settler_v3 as t  # noqa: E402


# ---------------------------------------------------------------- M1 ----------------------------------------------
class OtherSignals(review.RunBoundedSignals):
    """Agent 152's harness with SIGHUP and SIGINT instead of SIGTERM (sshd hangup, Ctrl-C)."""

    def stop_with(self, number):
        runner = self.start(timeout=600)
        time.sleep(1.5)
        runner.send_signal(number)
        runner.wait(30)
        time.sleep(0.3)
        self.assertFalse(self.segment.exists(), f'{signal.Signals(number).name} leaves the SP1 segments')
        self.assertFalse(review.alive(self.child), f'{signal.Signals(number).name} leaves the prover group')

    def test_sighup_cleans_up(self):
        self.stop_with(signal.SIGHUP)

    def test_sigint_cleans_up(self):
        self.stop_with(signal.SIGINT)

    # The parent's tests are run by the parent class; do not repeat them here.
    test_control_timeout_kills_the_group_and_removes_the_segment = None
    test_finding_sigterm_to_the_settler_cleans_up_the_prover_group_and_segments = None


class RemoteOtherSignals(OtherSignals):
    runner = review.REMOTE_RUNNER


# A cleanup that takes a while (slow segment removal), interrupted by a second and third signal.
SLOW_CLEANUP = textwrap.dedent('''
    import subprocess, sys, time
    sys.path.insert(0, sys.argv[1])
    import {module} as m
    shm, segment, pidfile, marker = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    m.group_segments = lambda pgid, directory: {{segment}}
    real = m.remove_leaked_segments
    def slow(paths, mapped=None):
        open(marker, 'w').write('cleanup-started')
        time.sleep(2)  # the test sends more signals now
        removed = real(paths, mapped=lambda path: False)
        open(marker, 'w').write('cleanup-finished')
        return removed
    m.remove_leaked_segments = slow
    argv = ['/bin/sh', '-c', 'echo $$ > ' + pidfile + '; exec sleep 600']
    try:
        if '{module}' == 'settler_v3':
            settler = m.Settler.__new__(m.Settler)
            settler.run, settler.c = subprocess.run, {{'prover_shm_dir': shm}}
            settler.run_bounded(argv, timeout=600, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            m.run_while_client_connected(argv, {{'PATH': '/usr/bin:/bin'}}, subprocess.DEVNULL, 600,
                                         gone=lambda: False, poll_seconds=0.2, shm=shm)
    except m.Stopped as stop:
        m.exit_by_signal(stop)
''')


class SignalDuringCleanup(unittest.TestCase):
    def run_case(self, module):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        segment, pidfile, marker = root / 'sp1_m1', root / 'child.pid', root / 'marker'
        segment.write_bytes(b'\0' * 64)
        runner = subprocess.Popen([sys.executable, '-c', SLOW_CLEANUP.format(module=module), str(HERE), str(root),
                                   str(segment), str(pidfile), str(marker)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 20
        while not (pidfile.exists() and pidfile.read_text().strip()) and time.monotonic() < deadline:
            time.sleep(0.1)
        child = int(pidfile.read_text())
        self.addCleanup(lambda: review.RunBoundedSignals.kill_child(types.SimpleNamespace(child=child)))
        time.sleep(0.5)
        runner.send_signal(signal.SIGTERM)
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        runner.send_signal(signal.SIGTERM)  # an impatient operator, or systemd's stop of the whole cgroup
        runner.send_signal(signal.SIGINT)
        code = runner.wait(30)
        self.assertEqual(marker.read_text(), 'cleanup-finished', 'a second signal interrupted the cleanup')
        self.assertFalse(segment.exists())
        self.assertFalse(review.alive(child))
        self.assertEqual(code, -signal.SIGTERM, 'the process ends by the first signal, as systemd expects')

    def test_settler(self):
        self.run_case('settler_v3')

    def test_remote_prover(self):
        self.run_case('remote_prover')


class ExitBySignal(unittest.TestCase):
    def test_main_ends_by_the_signal_after_unwinding(self):
        for module in ('settler_v3', 'remote_prover'):
            with self.subTest(module=module), tempfile.TemporaryDirectory() as tmp:
                marker = Path(tmp) / 'finally'
                code = textwrap.dedent(f'''
                    import sys, time
                    sys.path.insert(0, {str(HERE)!r})
                    import {module} as m
                    m.install_stop_handlers()
                    try:
                        try:
                            print('ready', flush=True)
                            time.sleep(30)
                        finally:
                            open({str(marker)!r}, 'w').write('ran')
                    except m.Stopped as stop:
                        m.exit_by_signal(stop)
                ''')
                proc = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                with proc.stdout:
                    self.assertEqual(proc.stdout.readline().strip(), b'ready')
                    proc.send_signal(signal.SIGTERM)
                    self.assertEqual(proc.wait(20), -signal.SIGTERM)
                self.assertEqual(marker.read_text(), 'ran', 'finally blocks run before the exit')

    def test_stopped_is_not_an_exception_the_worker_retries(self):
        self.assertFalse(issubclass(s.Stopped, Exception))
        self.assertFalse(issubclass(rp.Stopped, Exception))
        self.assertEqual(s.Stopped(signal.SIGTERM).code, 143)


class GnarkContainers(unittest.TestCase):
    """L5: the Gnark container of a killed prover is found by its bind mounts and killed; nothing else is."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'docker').write_text('#!/bin/sh\nexit 0\n')
        (self.bin / 'docker').chmod(0o755)
        self.private = self.root / 'tmp' / 'prover-abc'
        self.private.mkdir(parents=True)
        self.calls = []

    def docker(self, containers):
        def run(argv, **kwargs):
            self.calls.append(argv[1:])
            out = types.SimpleNamespace(returncode=0, stdout='', stderr='')
            if argv[1] == 'ps':
                out.stdout = ''.join(c + '\n' for c in containers)
            elif argv[1] == 'inspect':
                out.stdout = ''.join(f'{c}\t{json.dumps([{"Source": src} for src in containers[c]])}\n' for c in argv[4:])
            return out
        return run

    def test_only_containers_with_a_mount_from_this_run_are_killed(self):
        containers = {
            'aaa1': [str(self.private / 'tmpWITNESS'), str(self.private / 'tmpOUT'), '/var/lib/x/.sp1/circuits'],
            'bbb2': [str(self.root / 'tmp' / 'prover-other' / 'tmpOUT')],  # another run (a concurrent dry run)
            'ccc3': [str(self.private) + '-suffix/tmpOUT'],  # a sibling with the same prefix
            'ddd4': [],
        }
        for module in (s, rp):
            with self.subTest(module=module.__name__):
                self.calls = []
                with mock.patch.object(s, 'log'):
                    killed = module.stop_gnark_containers(str(self.private), str(self.bin), run=self.docker(containers))
                self.assertEqual(killed, ['aaa1'])
                self.assertEqual([c for c in self.calls if c[0] == 'kill'], [['kill', 'aaa1']])

    def test_no_docker_or_no_private_tmpdir_does_nothing(self):
        run = self.docker({'aaa1': [str(self.private / 'x')]})
        self.assertEqual(s.stop_gnark_containers(str(self.private), str(self.root / 'nodocker'), run=run), [])
        self.assertEqual(s.stop_gnark_containers(None, str(self.bin), run=run), [])
        self.assertEqual(rp.stop_gnark_containers('', str(self.bin), run=run), [])
        self.assertEqual(self.calls, [])

    def test_a_docker_failure_never_breaks_the_cleanup(self):
        def broken(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 15)
        with mock.patch.object(s, 'log') as logged:
            self.assertEqual(s.stop_gnark_containers(str(self.private), str(self.bin), run=broken), [])
        self.assertEqual(logged.call_args.args[0], 'prover-container-check-failed')
        self.assertEqual(rp.stop_gnark_containers(str(self.private), str(self.bin), run=broken), [])


class PrivateTmpdir(unittest.TestCase):
    """Each local prover run gets its own TMPDIR (so its container is attributable) and it is removed afterwards."""

    def test_the_prover_sees_a_private_tmpdir_that_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'tmp').mkdir()
            seen = root / 'seen'
            settler = s.Settler.__new__(s.Settler)
            settler.run, settler.c = subprocess.run, {'prover_shm_dir': str(root)}
            env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(root / 'tmp')}
            with mock.patch.object(s, 'stop_gnark_containers') as containers:
                done = settler.run_bounded(['/bin/sh', '-c', f'echo "$TMPDIR" > {seen}; touch "$TMPDIR/leftover"'],
                                           timeout=30, env=env)
                self.assertEqual(done.returncode, 0)
                private = Path(seen.read_text().strip())
                self.assertEqual(private.parent, root / 'tmp')
                self.assertTrue(private.name.startswith('prover-'))
                self.assertFalse(private.exists(), 'the private TMPDIR goes with the run')
                containers.assert_not_called()  # a normal exit: no container check
                failed = settler.run_bounded(['/bin/sh', '-c', 'exit 3'], timeout=30, env=env)
                self.assertEqual(failed.returncode, 3)
                self.assertEqual(containers.call_count, 1, 'an abnormal end checks for a left-over container')
            self.assertEqual(list((root / 'tmp').iterdir()), [])

    def test_a_missing_tmpdir_runs_as_before(self):
        with tempfile.TemporaryDirectory() as tmp:
            settler = s.Settler.__new__(s.Settler)
            settler.run, settler.c = subprocess.run, {'prover_shm_dir': tmp}
            env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(Path(tmp) / 'missing')}
            done = settler.run_bounded(['/bin/sh', '-c', 'exit 0'], timeout=30, env=env)
            self.assertEqual(done.returncode, 0)


# ---------------------------------------------------------------- M2 ----------------------------------------------
class AllEndpoints(unittest.TestCase):
    setUp = t.SettlerV3Test.setUp
    tearDown = t.SettlerV3Test.tearDown
    config = t.SettlerV3Test.config
    quorum_settler = t.SettlerV3Test.quorum_settler
    da_config = t.SettlerV3Test.da_config

    def endpoints(self, answers):
        """Endpoints 1-3; answers[port] is a dict answer or an exception."""
        calls = []

        def rpc(port, method, params=()):
            calls.append(port)
            answer = answers[port]
            if isinstance(answer, Exception):
                raise answer
            return answer
        return s.Endpoints([1, 2, 3], 2, rpc, lambda: 0), calls

    def test_every_endpoint_gets_the_bytes_and_duplicate_counts_as_held(self):
        endpoints, calls = self.endpoints({1: {'status': 'accepted'}, 2: {'status': 'duplicate'},
                                           3: ConnectionRefusedError(111, 'refused')})
        with mock.patch.object(s, 'log') as logged:
            held, first = endpoints.submit('13ab')
        self.assertEqual((held, first, calls), ([1, 2], {'status': 'accepted'}, [1, 2, 3]))
        self.assertIn('submit-partial', [c.args[0] for c in logged.call_args_list])

    def test_endpoints_in_backoff_are_still_sent_the_bytes(self):
        endpoints, calls = self.endpoints({1: {'status': 'accepted'}, 2: {'status': 'accepted'},
                                           3: {'status': 'accepted'}})
        endpoints.state[1].update(failures=3, retry_at=10 ** 9)
        with mock.patch.object(s, 'log'):
            held, _ = endpoints.submit('13ab')
        self.assertEqual((held, calls), ([1, 2, 3], [1, 2, 3]))

    def test_an_answer_without_a_held_status_is_not_counted(self):
        endpoints, _ = self.endpoints({1: {'status': 'weird'}, 2: None, 3: {'status': 'duplicate'}})
        with mock.patch.object(s, 'log'):
            held, first = endpoints.submit('13ab')
        self.assertEqual((held, first), ([3], {'status': 'duplicate'}))
        endpoints, _ = self.endpoints({1: {'status': 'weird'}, 2: [], 3: {}})
        with mock.patch.object(s, 'log'), self.assertRaises(s.SubmitRefused) as refused:
            endpoints.submit('13ab')
        self.assertEqual(refused.exception.kind(), 'retry')

    def test_terminal_only_when_every_endpoint_refused_terminally(self):
        terminal = s.RpcError(f"sendrawtransaction: {{'code': {s.TX_REFUSED}, 'message': 'policy'}}")
        endpoints, _ = self.endpoints({1: terminal, 2: terminal, 3: terminal})
        with mock.patch.object(s, 'log'), self.assertRaises(s.SubmitRefused) as refused:
            endpoints.submit('13ab')
        self.assertEqual(refused.exception.kind(), 'terminal')
        endpoints, _ = self.endpoints({1: terminal, 2: terminal, 3: {'status': 'accepted'}})
        with mock.patch.object(s, 'log'):
            self.assertEqual(endpoints.submit('13ab')[0], [3], 'one endpoint holding the bytes is enough')

    def test_da_bytes_go_to_every_endpoint_too(self):
        fake = t.Fake(self.root, t.statement(user_txs=2), produced_txs=2)
        ports = t.Ports(fake)
        with mock.patch.object(s, 'log'):
            self.assertTrue(self.quorum_settler(ports, user=True).cycle())
        sends = [p for p, m in ports.calls if m == 'sendrawtransaction']
        self.assertEqual(sends, [1, 2, 3, 1, 2, 3], 'the DA batch, then the settlement, each to all three')
        self.assertEqual([tx[0] for tx in t.broadcasts(fake.sent)], [s.DA_TAG, s.ASYNC_SETTLEMENT_TAG])
        self.assertEqual(len(fake.da_records), 1, 'one record, one fee')

    # ---- held but never included: alert, then halt ----
    def unincluded(self, advancing=True, **extra):
        fake = t.Fake(self.root, t.statement())
        ports = t.Ports(fake)
        height = [100]
        inner = ports.rpc

        def rpc(port, method, params=()):
            if method == 'sendrawtransaction':
                ports.calls.append((port, method))
                return {'status': 'duplicate', 'tx_hash': '00' * 32}  # held everywhere, never included
            if method == 'getchaininfo':
                height[0] += 1 if advancing else 0
                return {'height': height[0], 'next_base_fee_millisat_per_gas': '10'}
            return inner(port, method, params)
        ports.rpc = rpc
        return fake, ports, self.quorum_settler(ports, **extra)

    def test_a_settlement_held_but_never_included_alerts_then_halts(self):
        _, _, settler = self.unincluded()
        with mock.patch.object(s, 'log') as logged:
            for _ in range(3):
                self.assertFalse(settler.cycle())
            with self.assertRaisesRegex(s.Halt, 'held by endpoints \\[1, 2, 3\\] for 4 acceptance windows'):
                settler.cycle()
        alerts = [c.kwargs for c in logged.call_args_list if c.args[0] == 'settlement-not-included']
        self.assertEqual([a['windows'] for a in alerts], [1, 2, 3, 4])
        timeouts = [c.kwargs for c in logged.call_args_list if c.args[0] == 'acceptance-timeout']
        self.assertEqual(timeouts[0]['held_by'], [1, 2, 3])

    def test_a_stalled_l1_never_counts(self):
        _, _, settler = self.unincluded(advancing=False)
        with mock.patch.object(s, 'log') as logged:
            for _ in range(6):
                self.assertFalse(settler.cycle())
        events = [c.args[0] for c in logged.call_args_list]
        self.assertIn('l1-not-advancing', events)
        self.assertNotIn('settlement-not-included', events)

    def test_zero_only_alerts_and_the_count_follows_the_bytes(self):
        _, _, settler = self.unincluded(max_unincluded_windows=0)
        with mock.patch.object(s, 'log'):
            for _ in range(6):
                self.assertFalse(settler.cycle())
        self.assertEqual(settler.unincluded['windows'], 6)
        with mock.patch.object(s, 'log'):
            settler.not_included(2, 'ff' * 32, [1])
        self.assertEqual(settler.unincluded, {'tx': 'ff' * 32, 'windows': 1}, 'other bytes start a new count')
        for bad in (-1, True, '4'):
            with self.subTest(bad=bad), self.assertRaisesRegex(s.Halt, 'max_unincluded_windows'):
                self.quorum_settler(t.Ports(t.Fake(self.root, t.statement())), max_unincluded_windows=bad)


if __name__ == '__main__':
    unittest.main()
