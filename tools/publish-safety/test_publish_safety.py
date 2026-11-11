#!/usr/bin/env python3
"""Tests for publish_check.py and redact_runbook.py.

Every forbidden value here is synthetic and assembled at run time, so this file itself carries no
value the checker would flag: hosts are RFC 5737 documentation addresses, addresses and keys are
derived from fixed seeds with sha256.
"""
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import publish_check as pc  # noqa: E402
import redact_runbook as rr  # noqa: E402


def h(seed, n):
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


INTERNAL = '203.0.113.7'          # stands in for an operator host
INTERNAL2 = '198.51.100.9'
DEPLOYER = h('deployer', 40)
RETIRED = h('retired', 40)
KEY = h('key', 64)
ANVIL0 = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # public Anvil account 0
TOPIC = 'zq' + 'secret-topic-' + h('t', 4)
IDENT = 'person' + h('i', 4) + '@example.lan'


def denylist(dirpath):
    path = os.path.join(dirpath, 'deny.conf')
    with open(path, 'w') as fh:
        fh.write('[rule6]\n' + TOPIC + '\n[deployer]\n0x' + DEPLOYER + '\n[retired-address]\n0x' + RETIRED +
                 '\n[internal-ip]\n' + INTERNAL + '\n' + INTERNAL2 + '\n[key-path]\nkey-folder-x\n[identity]\n' +
                 IDENT.replace('.', '\\.') + '\n')
    return path


def allowlist(dirpath):
    path = os.path.join(dirpath, 'allow.conf')
    with open(path, 'w') as fh:
        fh.write('ip 127.0.0.0/8\nip 192.0.2.1\nvalue 0x' + ANVIL0 + '\npath private-key fixtures/pem_literal.py\n')
    return path


def git(repo, *args, env=None):
    e = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', HOME=repo)
    e.update(env or {})
    return subprocess.run(['git', '-C', repo] + list(args), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=e).stdout.decode()


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = pc.main(argv)
    return code, out.getvalue(), err.getvalue()


class Classify(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = pc.Config()
        pc.load_allowlist(self.cfg, allowlist(self.dir))
        pc.load_denylist(self.cfg, denylist(self.dir))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def cats(self, line):
        return sorted({c for c, _ in pc.classify(self.cfg, line)})

    def test_rule6_case_insensitive(self):
        self.assertEqual(self.cats('see ' + TOPIC.upper() + ' here'), ['rule6'])

    def test_deployer_and_retired(self):
        self.assertEqual(self.cats('"deployer": "0x' + DEPLOYER.upper() + '"'), ['deployer'])
        self.assertEqual(self.cats('addr ' + RETIRED), ['retired-address'])
        self.assertEqual(self.cats('addr 0x' + h('other', 40)), [])

    def test_private_key_in_key_context_only(self):
        self.assertEqual(self.cats('PRIVATE_KEY=0x' + KEY), ['private-key'])
        self.assertEqual(self.cats('--private-key ' + KEY), ['private-key'])
        self.assertEqual(self.cats('sha256 ' + KEY), [])
        self.assertEqual(self.cats('| seed pool | `0x' + KEY + '` |'), [])
        self.assertEqual(self.cats('sk = 0x' + KEY), ['private-key'])
        self.assertEqual(self.cats('seed_hex: ' + KEY), ['private-key'])
        self.assertEqual(self.cats('PRIVATE_KEY=0x' + ANVIL0), [])
        self.assertEqual(self.cats('private_key = 0x' + '1' * 63 + '2'), [])

    def test_pem_mnemonic_keystore_tokens(self):
        self.assertEqual(self.cats('-----BEGIN ' + 'EC PRIVATE KEY-----'), ['private-key'])
        words = ' '.join(['abandon'] * 11 + ['about'])
        self.assertEqual(self.cats('mnemonic = "' + words + '"'), ['private-key'])
        self.assertEqual(self.cats('mnemonic: ' + ' '.join(['test'] * 11 + ['junk'])), [])
        self.assertEqual(self.cats('{"cipher' + 'text": "00"}'), ['private-key'])
        self.assertEqual(self.cats('token ghp_' + 'A' * 36), ['token'])
        self.assertEqual(self.cats('k=AKIA' + 'B' * 16), ['token'])

    def test_ips(self):
        self.assertEqual(self.cats('ssh x@' + INTERNAL), ['internal-ip'])
        self.assertEqual(self.cats('http://127.0.0.1:8080 and 192.0.2.1'), [])
        self.assertEqual(self.cats('10.1.2.3'), ['private-ip'])
        self.assertEqual(self.cats('8.8.4.4'), ['unknown-ip'])
        self.assertEqual(self.cats('version 1.2.3.4.5'), [])

    def test_paths_identity(self):
        self.assertEqual(self.cats('-i ~/Desktop/key-folder-x/id'), ['key-path', 'workspace-ref'])
        self.assertEqual(self.cats('cd /home/ubuntu/x'), ['host-path'])
        self.assertEqual(self.cats('by ' + IDENT), ['identity'])

    def test_denylist_subset_enforced(self):
        bad = os.path.join(self.dir, 'bad.conf')
        with open(bad, 'w') as fh:
            fh.write('[rule6]\n\\bword\\b\n')
        with self.assertRaises(SystemExit):
            pc.load_denylist(pc.Config(), bad)


class Repo(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.repo = os.path.join(self.dir, 'r')
        os.makedirs(self.repo)
        git(self.repo, 'init', '-q', '-b', 'main')
        self.deny = denylist(self.dir)
        self.allow = allowlist(self.dir)
        self.commit('README.md', 'clean\n', 'init', 'Pub <pub@example.org>')
        self.base = git(self.repo, 'rev-parse', 'HEAD').strip()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def commit(self, path, text, msg, ident):
        full = os.path.join(self.repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as fh:
            fh.write(text)
        git(self.repo, 'add', path)
        name, email = ident[:-1].split(' <')
        git(self.repo, 'commit', '-q', '-m', msg, env={'GIT_AUTHOR_NAME': name, 'GIT_AUTHOR_EMAIL': email,
                                                    'GIT_COMMITTER_NAME': name, 'GIT_COMMITTER_EMAIL': email})

    def args(self, *a):
        return list(a) + ['--repo', self.repo, '--denylist', self.deny, '--allowlist', self.allow]

    def test_clean_tree_passes(self):
        code, out, err = run(self.args('tree', 'HEAD'))
        self.assertEqual(code, 0, out + err)

    def test_tree_blocks_and_redacts(self):
        self.commit('cfg/x.json', '{"deployer": "0x' + DEPLOYER + '"}\n', 'add', 'Pub <pub@example.org>')
        code, out, _ = run(self.args('tree', 'HEAD'))
        self.assertEqual(code, 1)
        self.assertIn('deployer', out)
        self.assertNotIn(DEPLOYER[:12], out)
        self.assertIn('0x' + DEPLOYER[:4] + '…', out)

    def test_secret_file_name(self):
        self.commit('keys/owner.sk', 'x\n', 'add', 'Pub <pub@example.org>')
        code, out, _ = run(self.args('tree', 'HEAD'))
        self.assertEqual(code, 1)
        self.assertIn('secret-file', out)

    def test_allowlisted_path(self):
        self.commit('fixtures/pem_literal.py', 'H = "-----BEGIN ' + 'PRIVATE KEY-----"\n', 'add', 'Pub <pub@example.org>')
        code, out, err = run(self.args('tree', 'HEAD'))
        self.assertEqual(code, 0, out + err)

    def test_commits_identity_and_message(self):
        self.commit('a.txt', 'ok\n', 'host ' + INTERNAL2, 'Someone <' + IDENT + '>')
        code, out, _ = run(self.args('commits', self.base + '..HEAD'))
        self.assertEqual(code, 1)
        self.assertIn('identity', out)
        self.assertIn('(commit metadata)', out)
        self.assertIn('internal-ip', out)
        self.assertIn('(commit message)', out)

    def test_commits_added_lines_only(self):
        self.commit('b.txt', 'ip ' + INTERNAL + '\n', 'add', 'Pub <pub@example.org>')
        mid = git(self.repo, 'rev-parse', 'HEAD').strip()
        self.commit('c.txt', 'fine\n', 'more', 'Pub <pub@example.org>')
        code, out, _ = run(self.args('commits', mid + '..HEAD'))
        self.assertEqual(code, 0, out)
        code, out, _ = run(self.args('commits', self.base + '..HEAD'))
        self.assertEqual(code, 1)
        self.assertIn('b.txt:1', out)

    def test_refuses_without_denylist(self):
        code, _, err = run(['tree', 'HEAD', '--repo', self.repo, '--denylist', os.path.join(self.dir, 'absent'),
                            '--allowlist', self.allow])
        self.assertEqual(code, 2)
        self.assertIn('refusing', err)

    def test_pre_push_hook(self):
        self.commit('d.txt', 'PRIVATE_KEY=' + KEY + '\n', 'add', 'Pub <pub@example.org>')
        sha = git(self.repo, 'rev-parse', 'HEAD').strip()
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(f'refs/heads/main {sha} refs/heads/main {"0" * 40}\n')
            code, out, _ = run(self.args('pre-push', 'public', 'https://example.invalid/r.git'))
        finally:
            sys.stdin = stdin
        self.assertEqual(code, 1)
        self.assertIn('private-key', out)
        git(self.repo, 'config', 'bloch.privateRemote', 'origin')
        try:
            sys.stdin = io.StringIO(f'refs/heads/main {sha} refs/heads/main {"0" * 40}\n')
            code, out, err = run(self.args('pre-push', 'origin', 'x'))
        finally:
            sys.stdin = stdin
        self.assertEqual(code, 0, out + err)


class Redact(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = pc.Config()
        pc.load_allowlist(self.cfg, allowlist(self.dir))
        pc.load_denylist(self.cfg, denylist(self.dir))
        self.hosts = os.path.join(self.dir, 'hosts.conf')
        with open(self.hosts, 'w') as fh:
            fh.write(INTERNAL + '\tHOST_A\nre:(?<![\\w.])113\\.7(?![\\w]|\\.\\d)\tHOST_A\n4242424\tPID\n')

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_redaction(self):
        rules = rr.load_hosts(self.hosts)
        src = '\n'.join([
            f'ssh -i ~/Desktop/key-folder-x/fleet/key ubuntu@{INTERNAL} uptime',
            f'on 113.7 run; peer {INTERNAL2}:18956 and again {INTERNAL2}; rpc http://192.0.2.1:8080',
            'kill 4242424 1234567 then check height 186552',
            'height 186552 stays',
            'cp /home/ubuntu/x /Users/someone/y ~/l2dexbridge-20261030/area/out/file',
            'see agents/145-review.md and hf-kit/l2-agents/07-rpc/artifacts',
        ])
        out = rr.redact(src, rules, self.cfg).split('\n')
        self.assertEqual(out[0], 'ssh -i <KEY_PATH> <operator>@<HOST_A> uptime')
        self.assertEqual(out[1], 'on <HOST_A> run; peer <HOST_1>:18956 and again <HOST_1>; rpc http://192.0.2.1:8080')
        self.assertEqual(out[2], 'kill <PID> <PID> then check height <PID>')
        self.assertEqual(out[3], 'height 186552 stays')
        self.assertEqual(out[4], 'cp /home/<operator>/x <local-home>/y <scratch-dir>/area/out/file')
        self.assertEqual(out[5], 'see <internal-report> and hf-kit/l2-agents/07-rpc/artifacts')
        self.assertEqual(rr.unsafe_lines(self.cfg, '\n'.join(out)), [])

    def test_unsafe_output_refused(self):
        root = os.path.join(self.dir, 'root')
        os.makedirs(os.path.join(root, 'docs'))
        with open(os.path.join(root, 'docs', 'RB.md'), 'w') as fh:
            fh.write('topic ' + TOPIC + '\n')
        code = rr.main(['docs/RB.md', 'docs/public/RB.md', '--root', root, '--hosts', self.hosts,
                        '--denylist', denylist(self.dir), '--allowlist', allowlist(self.dir)])
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(root, 'docs', 'public', 'RB.md')))

    def test_check_detects_stale(self):
        root = os.path.join(self.dir, 'root')
        os.makedirs(os.path.join(root, 'docs'))
        with open(os.path.join(root, 'docs', 'RB.md'), 'w') as fh:
            fh.write('host ' + INTERNAL + '\n')
        common = ['docs/RB.md', 'docs/public/RB.md', '--root', root, '--hosts', self.hosts,
                  '--denylist', denylist(self.dir), '--allowlist', allowlist(self.dir)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(rr.main(common), 0)
            self.assertEqual(rr.main(common + ['--check']), 0)
            with open(os.path.join(root, 'docs', 'RB.md'), 'a') as fh:
                fh.write('more\n')
            self.assertEqual(rr.main(common + ['--check']), 1)
        with open(os.path.join(root, 'docs', 'public', 'RB.md')) as fh:
            self.assertIn('host <HOST_A>', fh.read())


if __name__ == '__main__':
    unittest.main()
