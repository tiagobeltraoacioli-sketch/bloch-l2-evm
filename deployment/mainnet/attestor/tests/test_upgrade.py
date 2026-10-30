#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests of the follower pin in the agent and of `install-attestor.sh upgrade` / `upgrade-rollback`.

No native binary is needed. The upgrade runs against a `--prefix` install built here, in the layout and
config format of the pre-2026-10-30 kit (no follower pin). Stand-ins, all local:
  - the binaries are small files (only hashed);
  - `--service-cmd` is fake_services.py: `start follower` spawns a process that writes the follower's
    status.json the way the real one does (only after its re-verify, then every poll, with a rising
    native_finalized_epoch); `start agent` records the start;
  - `--check-cmd` runs the agent's own `check_identity` on the installed config.json, so a pin the
    upgrade got wrong fails the test, then prints the check-ok event.

  python3 -m unittest -v test_upgrade
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT))
import attestor_agent  # noqa: E402
import attestor_lib as lib  # noqa: E402

GENESIS, EPOCH, HF1 = 1786656679, 960, 7180
FORK_UNIX = GENESIS + HF1 * EPOCH


def sha(data):
    return hashlib.sha256(data).hexdigest()


FAKE_SERVICES = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
root, action, unit = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
fstate = root / 'var/lib/bloch-l2-attestor-follower'
pid = fstate / 'fake-follower.pid'
agent = root / 'agent.started'
log = root / 'services.log'
with open(log, 'a') as f:
    f.write(f'{action} {unit}\n')
def alive():
    try:
        os.kill(int(pid.read_text()), 0)
        return True
    except (OSError, ValueError):
        return False
if unit == 'agent':
    if action == 'start':
        agent.write_text(str(time.time()))
    elif action == 'stop':
        agent.unlink(missing_ok=True)
    sys.exit(0 if action != 'is-active' or agent.exists() else 3)
if action == 'start':
    if alive():
        sys.exit(0)
    binary = root / 'opt/bloch/l2-attestor/bloch-l2-native-follower'
    reverify = float(os.environ.get('FAKE_REVERIFY_SECONDS', '2'))
    if os.environ.get('FAKE_FOLLOWER_DIES'):
        reverify = -1
    code = ('import json,os,sys,time\n'
            'status=sys.argv[1]; d=float(sys.argv[2]); time.sleep(max(d, 1)); t0=time.time()\n'
            'if d < 0: sys.exit(1)\n'
            'while True:\n'
            '    e=100+int((time.time()-t0)/1.5)\n'
            '    tmp=status+".tmp"; open(tmp,"w").write(json.dumps({"written_at_unix":int(time.time()),'
            '"native_finalized_epoch":e,"verified_slot":e*32,"binary":sys.argv[3]}))\n'
            '    os.replace(tmp,status); time.sleep(0.3)\n')
    import hashlib
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    p = subprocess.Popen([sys.executable, '-c', code, str(fstate / 'status.json'), str(reverify), digest],
                         start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid.write_text(str(p.pid))
elif action == 'stop':
    if alive():
        os.kill(int(pid.read_text()), signal.SIGTERM)
        while alive():
            try:
                os.waitpid(int(pid.read_text()), os.WNOHANG)
            except ChildProcessError:
                pass
            time.sleep(0.05)
    pid.unlink(missing_ok=True)
elif action == 'is-active':
    sys.exit(0 if alive() else 3)
'''

FAKE_CHECK = r'''
import json, os, sys
kit, config, manifest_sha, set_hash = sys.argv[1:5]
sys.path.insert(0, kit)
import attestor_agent as a, attestor_lib as lib
if os.environ.get('FAKE_CHECK_FAIL'):
    print(json.dumps({'event': 'halt', 'reason': 'injected'})); sys.exit(3)
m = lib.MAINNET
pins = lib.Pins(m.chain_id, m.network, m.genesis, set_hash, manifest_sha, m.l2_genesis_hash, m.network_args,
                m.timestamp_rule, m.large_claim_sat)
try:
    identity = a.Agent(json.load(open(config)), pins=pins).check_identity(key='none')
except a.Halt as e:
    print(json.dumps({'event': 'halt', 'reason': str(e)})); sys.exit(3)
print(json.dumps({'event': 'check-ok', **identity}, sort_keys=True))
'''


class FollowerPinTest(unittest.TestCase):
    """check_identity with the follower pin, without native binaries (key='none')."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='follower-pin-'))
        self.files = {}
        for name in ('bloch-pos', 'produce', 'follower', 'manifest'):
            path = self.tmp / name
            path.write_text(f'{name} stand-in\n')
            self.files[name] = path
        threshold, keys = lib.read_set(KIT / 'public' / 'attestors.set')
        m = lib.MAINNET
        self.pins = lib.Pins(m.chain_id, m.network, m.genesis, lib.set_hash(threshold, keys),
                             lib.sha256_file(self.files['manifest']), m.l2_genesis_hash, m.network_args,
                             m.timestamp_rule, m.large_claim_sat)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def config(self, **extra):
        f = self.files
        c = {'signer_index': 2, 'bloch_pos': str(f['bloch-pos']), 'bloch_pos_sha256': lib.sha256_file(f['bloch-pos']),
             'produce': str(f['produce']), 'produce_sha256': lib.sha256_file(f['produce']),
             'follower': str(f['follower']), 'follower_sha256': lib.sha256_file(f['follower']),
             'manifest': str(f['manifest']), 'attestors': str(KIT / 'public' / 'attestors.set'),
             'sealed_key': 'unused', 'follower_status': 'unused', 'follower_native': 'unused',
             'state_dir': str(self.tmp / 'state'), 'rpc_urls': []}
        c.update(extra)
        return {k: v for k, v in c.items() if v is not None}

    def identity(self, **extra):
        return attestor_agent.Agent(self.config(**extra), pins=self.pins).check_identity(key='none')

    def test_pinned_follower_passes(self):
        self.assertEqual(self.identity()['signer_index'], 2)

    def test_replaced_follower_halts(self):
        config = self.config()
        self.files['follower'].write_text('#!/bin/sh\nexit 0\n')  # the agent-06 /bin/true case
        with self.assertRaisesRegex(attestor_agent.Halt, 'follower differs from its pinned SHA-256'):
            attestor_agent.Agent(config, pins=self.pins).check_identity(key='none')

    def test_missing_follower_file_halts(self):
        with self.assertRaisesRegex(attestor_agent.Halt, 'follower cannot be read'):
            self.identity(follower=str(self.tmp / 'gone'))

    def test_config_without_the_follower_pin_halts_with_instructions(self):
        for drop in (('follower_sha256',), ('follower',), ('follower', 'follower_sha256')):
            with self.subTest(drop=drop):
                with self.assertRaises(attestor_agent.Halt) as ctx:
                    self.identity(**{k: None for k in drop})
                self.assertIn('install-attestor.sh upgrade', str(ctx.exception))
                self.assertIn('not pinned', str(ctx.exception))

    def test_empty_follower_pin_is_not_a_pin(self):
        with self.assertRaisesRegex(attestor_agent.Halt, 'not pinned'):
            self.identity(follower_sha256='')

    def test_main_exits_3_on_a_config_missing_required_keys(self):
        path = self.tmp / 'config.json'
        path.write_text(json.dumps({'signer_index': 0}))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(attestor_agent.main(['check', '--config', str(path)]), 3)
        self.assertIn('"event": "halt"', out.getvalue())


@unittest.skipUnless(shutil.which('bash') and shutil.which('sha256sum'), 'needs bash and sha256sum')
class UpgradeScriptTest(unittest.TestCase):
    OLD_FOLLOWER, OLD_PRODUCE = b'old follower 821289e0\n', b'old produce 192eda33\n'
    NEW_FOLLOWER, NEW_PRODUCE = b'new follower c18752fd\n', b'new produce 7c1cc62b\n'

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='upgrade-test-'))
        self.root = self.tmp / 'host'
        opt = self.root / 'opt/bloch/l2-attestor'
        self.etc = self.root / 'etc/bloch-l2-attestor'
        self.fstate = self.root / 'var/lib/bloch-l2-attestor-follower'
        for d in (opt, self.etc / 'public', self.fstate, self.root / 'var/lib/bloch-l2-attestor'):
            d.mkdir(parents=True)
        self.opt = opt
        (opt / 'bloch-pos').write_bytes(b'bloch-pos stand-in\n')
        (opt / 'bloch-l2-native-follower').write_bytes(self.OLD_FOLLOWER)
        (opt / 'bloch-l2-produce-dev').write_bytes(self.OLD_PRODUCE)
        # The pre-2026-10-30 agent: today's code without the follower pin (what it did not check).
        old_agent = (KIT / 'attestor_agent.py').read_text()
        for new, old in (("FOLLOWER_PIN = ('follower', 'follower_sha256')", 'FOLLOWER_PIN = ()'),
                         ("for name in ('bloch_pos', 'produce', 'follower'):", "for name in ('bloch_pos', 'produce'):")):
            self.assertEqual(old_agent.count(new), 1)
            old_agent = old_agent.replace(new, old)
        (opt / 'attestor_agent.py').write_text(old_agent + '# OLD-KIT-MARKER pre-2026-10-30\n')
        for f in ('attestor_lib.py', 'aggregate_attestation.py'):
            shutil.copy(KIT / f, opt / f)
        (self.etc / 'public/mainnet.manifest').write_text('manifest stand-in\n')
        shutil.copy(KIT / 'public/attestors.set', self.etc / 'public/attestors.set')
        # config.json exactly as the pre-2026-10-30 installer wrote it: no follower pin.
        self.old_config = {
            'signer_index': 2, 'bloch_pos': str(opt / 'bloch-pos'), 'bloch_pos_sha256': sha(b'bloch-pos stand-in\n'),
            'produce': str(opt / 'bloch-l2-produce-dev'), 'produce_sha256': sha(self.OLD_PRODUCE),
            'manifest': str(self.etc / 'public/mainnet.manifest'), 'attestors': str(self.etc / 'public/attestors.set'),
            'sealed_key': str(self.etc / 'attestor.sealed'), 'passphrase_credential': 'passphrase',
            'follower_status': str(self.fstate / 'status.json'), 'follower_native': str(self.fstate / 'native'),
            'state_dir': str(self.root / 'var/lib/bloch-l2-attestor'), 'rpc_urls': ['http://127.0.0.1:1'] * 3}
        (self.etc / 'config.json').write_text(json.dumps(self.old_config, indent=1) + '\n')
        os.chmod(self.etc / 'config.json', 0o640)
        (self.fstate / 'status.json').write_text(json.dumps({'written_at_unix': 1, 'native_finalized_epoch': 1}))
        self.art = self.tmp / 'artifacts'
        self.art.mkdir()
        (self.art / 'bloch-l2-native-follower').write_bytes(self.NEW_FOLLOWER)
        (self.art / 'bloch-l2-produce-dev').write_bytes(self.NEW_PRODUCE)
        (self.art / 'SHA256SUMS').write_text(f'{sha(self.NEW_FOLLOWER)}  bloch-l2-native-follower\n'
                                             f'{sha(self.NEW_PRODUCE)}  bloch-l2-produce-dev\n')
        (self.tmp / 'services.py').write_text(FAKE_SERVICES)
        (self.tmp / 'check.py').write_text(FAKE_CHECK)
        threshold, keys = lib.read_set(KIT / 'public/attestors.set')
        self.set_hash = lib.set_hash(threshold, keys)

    def tearDown(self):
        subprocess.run([sys.executable, str(self.tmp / 'services.py'), str(self.root), 'stop', 'follower'])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def script(self, command, *args, env=None, now=None, rehearsal=True):
        argv = ['bash', str(KIT / 'install-attestor.sh'), command]
        if rehearsal:  # defaults first: a later option of the same name (from `args`) wins
            argv += ['--prefix', str(self.root), '--poll', '1', '--wait-timeout', '60', '--advance-timeout', '30',
                     '--service-cmd', f'{sys.executable} {self.tmp}/services.py {self.root}',
                     '--check-cmd', f'{sys.executable} -I {self.tmp}/check.py {self.opt} {self.etc}/config.json '
                                    f'{lib.sha256_file(self.etc / "public/mainnet.manifest")} {self.set_hash}']
        if now is not None:
            argv += ['--now-unix', str(now)]
        argv += [str(x) for x in args]
        return subprocess.run(argv, capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=300)

    def upgrade(self, *extra, **kw):
        return self.script('upgrade', '--artifacts', self.art, '--follower-sha256', sha(self.NEW_FOLLOWER),
                           '--produce-sha256', sha(self.NEW_PRODUCE), *extra, **kw)

    def config(self):
        return json.loads((self.etc / 'config.json').read_text())

    def state(self):
        return dict(line.split('=', 1) for line in (self.etc / 'upgrade.state').read_text().split())

    def test_upgrade_from_a_pre_pin_install_then_rollback(self):
        done = self.upgrade(now=FORK_UNIX - 86_400)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        c = self.config()
        self.assertEqual((c['follower'], c['follower_sha256'], c['produce_sha256']),
                         (str(self.opt / 'bloch-l2-native-follower'), sha(self.NEW_FOLLOWER), sha(self.NEW_PRODUCE)))
        self.assertEqual({k: v for k, v in c.items() if k not in ('follower', 'follower_sha256', 'produce_sha256')},
                         {k: v for k, v in self.old_config.items() if k != 'produce_sha256'})
        self.assertEqual(os.stat(self.etc / 'config.json').st_mode & 0o777, 0o640)
        self.assertEqual((self.opt / 'attestor_agent.py').read_bytes(), (KIT / 'attestor_agent.py').read_bytes())
        self.assertEqual((self.opt / 'bloch-l2-native-follower').read_bytes(), self.NEW_FOLLOWER)
        self.assertEqual((self.opt.parent / 'l2-attestor.pre-hf123/bloch-l2-native-follower').read_bytes(), self.OLD_FOLLOWER)
        self.assertEqual(json.loads((self.etc / 'config.json.pre-hf123').read_text()), self.old_config)
        self.assertEqual(json.loads((self.fstate / 'status.json.pre-hf123').read_text())['written_at_unix'], 1)
        self.assertFalse((self.etc / 'PAUSE').exists())
        self.assertTrue((self.root / 'agent.started').exists())
        self.assertEqual(self.state()['phase'], 'done')
        self.assertIn('"event": "check-ok"', done.stdout)
        self.assertRegex(done.stdout, r'REPORT: attestor 2: upgrade check-ok, epoch \d+->\d+')
        order = (self.root / 'services.log').read_text().split('\n')
        self.assertEqual(order[:3], ['stop agent', 'stop follower', 'start follower'])
        self.assertEqual([x for x in order if x.endswith('agent')][-2:], ['start agent', 'is-active agent'])

        again = self.upgrade(now=FORK_UNIX - 86_400)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn('already upgraded', again.stdout)

        back = self.script('upgrade-rollback', now=FORK_UNIX - 4_300)
        self.assertEqual(back.returncode, 0, back.stdout + back.stderr)
        self.assertEqual(self.config(), self.old_config)
        self.assertEqual((self.opt / 'bloch-l2-native-follower').read_bytes(), self.OLD_FOLLOWER)
        self.assertEqual((self.opt / 'bloch-l2-produce-dev').read_bytes(), self.OLD_PRODUCE)
        self.assertIn('OLD-KIT-MARKER', (self.opt / 'attestor_agent.py').read_text())
        self.assertEqual(self.state(), {'op': 'upgrade-rollback', 'tag': 'pre-hf123', 'phase': 'done',
                                        'moved_at': self.state()['moved_at']})
        self.assertIn('REPORT: attestor 2: upgrade-rollback check-ok', back.stdout)

    def test_rollback_is_refused_close_to_and_after_hf1(self):
        self.assertEqual(self.upgrade(now=FORK_UNIX - 86_400).returncode, 0)
        for now in (FORK_UNIX - 4_100, FORK_UNIX, FORK_UNIX + 10 * EPOCH):
            with self.subTest(now=now):
                done = self.script('upgrade-rollback', now=now)
                self.assertEqual(done.returncode, 1)
                self.assertIn('refused', done.stderr)
                self.assertIn('fix forward', done.stderr)
        self.assertEqual(self.config()['follower_sha256'], sha(self.NEW_FOLLOWER))
        self.assertFalse((self.etc / 'PAUSE').exists())

    def test_artifact_not_matching_the_published_hash_changes_nothing(self):
        (self.art / 'bloch-l2-native-follower').write_bytes(b'#!/bin/sh\nexit 0\n')
        done = self.upgrade()
        self.assertEqual(done.returncode, 1)
        self.assertIn('not the published', done.stderr)
        self.assertEqual(self.config(), self.old_config)
        self.assertFalse((self.etc / 'PAUSE').exists())
        self.assertFalse((self.opt.parent / 'l2-attestor.pre-hf123').exists())
        self.assertFalse((self.root / 'services.log').exists())

    def test_sha256sums_disagreeing_with_the_published_hash_is_refused(self):
        (self.art / 'SHA256SUMS').write_text(f'{"00" * 32}  bloch-l2-native-follower\n')
        done = self.upgrade()
        self.assertEqual(done.returncode, 1)
        self.assertIn('SHA256SUMS lists', done.stderr)

    def test_failed_check_keeps_pause_then_resume_finishes(self):
        done = self.upgrade(env={'FAKE_CHECK_FAIL': '1'})
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('STOPPED', done.stderr)
        self.assertTrue((self.etc / 'PAUSE').exists())
        self.assertFalse((self.root / 'agent.started').exists())
        self.assertEqual(self.state()['phase'], 'started')
        fresh = self.upgrade()
        self.assertEqual(fresh.returncode, 1)
        self.assertIn('use --resume', fresh.stderr)
        resumed = self.script('upgrade', '--resume')
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertFalse((self.etc / 'PAUSE').exists())
        self.assertEqual(self.state()['phase'], 'done')

    def test_rollback_of_a_failed_upgrade(self):
        self.assertEqual(self.upgrade(env={'FAKE_CHECK_FAIL': '1'}).returncode, 1)
        back = self.script('upgrade-rollback', now=FORK_UNIX - 86_400)
        self.assertEqual(back.returncode, 0, back.stdout + back.stderr)
        self.assertEqual(self.config(), self.old_config)

    def test_follower_that_dies_during_reverify_stops_the_upgrade(self):
        done = self.upgrade(env={'FAKE_FOLLOWER_DIES': '1'})
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('the follower exited during re-verify', done.stderr)
        self.assertTrue((self.etc / 'PAUSE').exists())
        self.assertFalse((self.root / 'agent.started').exists())
        resumed = self.script('upgrade', '--resume')
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)

    def test_slow_reverify_is_waited_for_and_times_out_cleanly(self):
        done = self.upgrade('--wait-timeout', '3', env={'FAKE_REVERIFY_SECONDS': '600'})
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('no new status.json after 3s', done.stderr)
        self.assertTrue((self.etc / 'PAUSE').exists())

    def test_no_unpause_keeps_the_agent_stopped(self):
        done = self.upgrade('--no-unpause')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue((self.etc / 'PAUSE').exists())
        self.assertFalse((self.root / 'agent.started').exists())
        self.assertEqual(self.state()['phase'], 'verified')

    def test_rehearsal_flags_need_prefix(self):
        done = self.script('upgrade', '--artifacts', self.art, '--service-cmd', 'true', rehearsal=False)
        self.assertEqual(done.returncode, 1)
        self.assertRegex(done.stderr, 'rehearsal-only|run as root')

    def test_without_artifacts_prints_usage(self):
        done = self.script('upgrade')
        self.assertEqual(done.returncode, 2)
        self.assertIn('upgrade --artifacts DIR', done.stdout)


if __name__ == '__main__':
    unittest.main()
