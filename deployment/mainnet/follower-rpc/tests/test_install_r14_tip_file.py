#!/usr/bin/env python3
"""Round 14 (agent 304; round-12 task 262): install.sh --required-tip-file puts the settler's published policy on the
settled RPC's command line for user transactions, and leaves the deposit-only command line byte for byte as it was."""
from pathlib import Path
import re
import subprocess
import unittest

HERE = Path(__file__).resolve().parents[1]
UNIT = HERE / 'bloch-l2-mainnet-rpc.service'
SCRIPT = HERE / 'install.sh'
TIP = '/var/lib/bloch-l2-mainnet-settler/work/sequencer-policy.json'
# The ExecStart of the launch kit (e7de807, release 926d2cf): the option must never change it.
LAUNCH = ('ExecStart=/opt/bloch/l2-mainnet/bloch-l2-settled-rpc --data-dir @CANONICAL@ --view-dir @STATE@/rpc-view '
          '--finality-status /var/lib/bloch-l2-mainnet-follower/status.json --network '
          'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966 --port 18955 --poll-ms 2000 --rules mainnet '
          '--domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679 '
          '--txpool @TXPOOL@')


def sed_expression():
    """The substitution install.sh applies to @REQUIRED_TIP@, evaluated by bash itself."""
    match = re.search(r'-e "(s#@REQUIRED_TIP@#[^"]*#g)"', SCRIPT.read_text())
    assert match, 'install.sh does not substitute @REQUIRED_TIP@'
    return match[1]


def render(tip_file):
    out = subprocess.run(['bash', '-c', f'TIP_FILE="$1"; sed -e "{sed_expression()}" "$2"', 'render', tip_file, str(UNIT)],
                         check=True, capture_output=True, text=True).stdout
    return next(line for line in out.splitlines() if line.startswith('ExecStart='))


def install(*extra):
    return subprocess.run(['bash', str(SCRIPT), '--artifacts', '/nonexistent', '--l1-rpc-url', 'http://127.0.0.1:1',
                           '--canonical', '/nonexistent', '--canonical-user', 'nobody', '--txpool', '/nonexistent',
                           '--dry-run', *extra], capture_output=True, text=True)


class RequiredTipFile(unittest.TestCase):
    def test_without_the_option_the_command_line_is_the_launch_one(self):
        self.assertEqual(render(''), LAUNCH)

    def test_with_the_option_only_the_flag_is_added(self):
        self.assertEqual(render(TIP), f'{LAUNCH} --required-tip-file {TIP}')

    def test_a_path_systemd_or_sed_would_expand_or_split_is_refused_before_anything_else(self):
        for bad in ('relative/policy.json', '/var/lib/x y.json', '/var/lib/%h/p.json', '/var/lib/$HOME/p.json',
                    '/var/lib/a#b.json', '/var/lib/../etc/shadow', '/var/lib/a;b', "/var/lib/a'b", '/var/lib/a\\b'):
            with self.subTest(path=bad):
                result = install('--rpc-user', 'rpc', '--read-group', 'l2read', '--required-tip-file', bad)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('--required-tip-file must be an absolute path', result.stderr)
                self.assertNotIn('+ ', result.stdout)

    def test_it_needs_the_own_rpc_user(self):
        result = install('--required-tip-file', TIP)
        self.assertEqual(result.returncode, 2)
        self.assertIn('needs --rpc-user and --read-group', result.stderr)


if __name__ == '__main__':
    unittest.main()
