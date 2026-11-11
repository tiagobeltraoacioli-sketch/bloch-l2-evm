#!/usr/bin/env python3
"""Review a308: demonstrations against revenue_monitor.py and l2_monitor.py of the review worktree.

Fake worlds are those of the kit's own tests (test_revenue_monitor.FakeWorld, test_l2_monitor.Fake/healthy).
Every test states the expected behaviour and FAILS on the current code. Nothing is written outside this directory.

  PYTHONDONTWRITEBYTECODE=1 nice -n 10 python3 -B mon_review_a308_test.py -v
"""
import copy
import io
import json
import shutil
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

KIT = str(__import__('pathlib').Path(__file__).resolve().parents[1])
HERE = Path(__file__).resolve().parent
sys.path.insert(0, KIT)
import l2_monitor as l2m  # noqa: E402
import revenue_monitor as rev  # noqa: E402
import test_l2_monitor as tl  # noqa: E402
import test_revenue_monitor as tr  # noqa: E402

BASE_VAULT, SEQ_VAULT = rev.BASE_FEE_VAULT, rev.SEQUENCER_FEE_VAULT


def names(report, level=None):
    return {c['name']: c['level'] for c in report['checks'] if level is None or c['level'] == level}


class Revenue(unittest.TestCase):
    def test_r1_truncated_state_file_is_not_reported_as_warn(self):
        """A state file cut to 0 bytes (disk full, crash): the run must end UNKNOWN or CRIT. It ends with a traceback,
        i.e. exit status 1, which the documented Nagios convention reads as WARN, on every later run too."""
        world = tr.load('world_launch.json')
        tmp = Path(tempfile.mkdtemp(prefix='r1-', dir=HERE))
        try:
            (tmp / 'revenue.json').write_text(json.dumps(world['config']))
            (tmp / 'state.json').write_text('')
            out = io.StringIO()
            try:
                with redirect_stdout(out), redirect_stderr(out):
                    code = rev.main(['--config', str(tmp / 'revenue.json'), '--state', str(tmp / 'state.json'), '--json'],
                                    transport=tr.FakeWorld(world), now=world['now'])
            except Exception as e:  # noqa: BLE001
                self.fail(f'uncaught {type(e).__name__}: {e} -> python exits 1 (= WARN), no report, no state')
            self.assertIn(code, (rev.CRIT, rev.UNKNOWN))
        finally:
            shutil.rmtree(tmp)

    def test_r2_base_fee_vault_that_never_grows_is_reported(self):
        """User transactions open, after the fork: the sequencer-fee vault grows on every run (transactions are
        included and pay tips) while the base-fee vault stays flat for 3 days (base fee burned or credited
        elsewhere). One shared `l2_last_increase` mark means no check ever says so."""
        world = tr.load('world_live.json')
        report, state, _ = tr.run_world(world)
        for day in (1, 2, 3):
            world['l2']['accounts'][SEQ_VAULT]['balance'] += 10 ** 15
            report, state, _ = tr.run_world(world, state, world['now'] + day * 86400)
        l2_bad = {k: v for k, v in names(report).items() if k.startswith('l2_') and v != 'OK'}
        self.assertTrue(l2_bad, f'base-fee vault flat for 3 days with traffic, L2 checks: '
                                f'{ {k: v for k, v in names(report).items() if k.startswith("l2_")} }')

    def test_r3_keyless_vault_losing_balance_before_the_fork_is_not_a_sweep(self):
        """Before the fork the vaults have no code: nothing can move value out. A balance that falls is an
        impossibility (wrong chain state, a lying endpoint), not revenue swept."""
        world = tr.load('world_launch.json')
        world['l2']['accounts'] = {BASE_VAULT: {'balance': 5 * 10 ** 17}}
        report, state, _ = tr.run_world(world)
        world['l2']['accounts'][BASE_VAULT]['balance'] = 10 ** 17
        report, state, _ = tr.run_world(world, state, world['now'] + 3600)
        l2 = {k: v for k, v in names(report).items() if k.startswith('l2_')}
        self.assertEqual(state['totals'].get('l2_swept_base_fee'), None,
                         f'0.4 BLCH left a keyless vault and was booked as swept revenue; L2 checks: {l2}')

    def test_r4_forced_surcharges_mostly_missing_from_the_treasury_warn(self):
        """5 new forced records owe at least 5 x BASE_SURCHARGE_SAT = 5000 sat (the monitor books that minimum
        itself). The treasury grew by 1 sat."""
        world = tr.load('world_live.json')
        report, state, _ = tr.run_world(world)
        world['l1']['forced']['queued'] += 5
        world['l1']['balances'][world['l1']['forced']['treasury']] += 1
        report, state, _ = tr.run_world(world, state, world['now'] + 3600)
        self.assertNotEqual(names(report)['forced_route'], 'OK',
                            f'forced_route: {[c for c in report["checks"] if c["name"] == "forced_route"]}')


class L2Monitor(unittest.TestCase):
    UNIT = 'bloch-l2-mainnet-settler.service'

    def test_m1_unreadable_journal_is_reported(self):
        """journalctl fails (no systemd-journal group, timeout, corrupt journal): halt, settlement-not-included and
        every other settler event are not graded, and no check says so."""
        def runner(argv):
            return (0, tl.ACTIVE) if argv[0] == 'systemctl' else (1, '')
        report, _ = tl.run(tl.healthy(), '--unit', f'settler={self.UNIT}', runner=runner)
        about = [c for c in report.checks if c['check'].startswith(('events[', 'journal')) or 'journal' in c['message']]
        self.assertTrue(about, f'status {l2m.LEVEL_NAMES[report.status]}; unit checks: '
                               f'{[(c["check"], c["level"]) for c in report.checks if "settler" in c["check"]]}')

    def test_m2_unreachable_attestation_drop_is_not_ok(self):
        """The HTTP drop does not answer (http_fetcher returns None for every error). A finalized withdrawal root,
        500 native blocks old, has no readable partial: reported OK, 'normal'. Zero live attestors look the same."""
        world = tl.healthy()
        for node in world['l1'].values():
            node['l2']['withdrawals']['roots'] = [{'root': 'ab' * 32, 'finalized': True, 'height': 33500, 'l2_number': 90}]
        report, _ = tl.run(world, '--attest-drop', 'https://drop.example/attest', fetch=lambda url: None)
        self.assertNotEqual(tl.level(report, 'attestors'), 'OK',
                            [c['message'] for c in report.checks if c['check'] == 'attestors'])

    def test_m3_one_l1_endpoint_does_not_decide_the_settlement_age(self):
        """Two of three L1 nodes: last settlement 3 h ago (CRIT at 45 min). The third, one block higher, reports
        5 min. settlement_age follows the highest node alone."""
        world = tl.healthy()
        old = (tl.NOW - 3 * 3600 - l2m.L1_GENESIS_TIME) // 30
        for url in tl.L1[:2]:
            world['l1'][url]['l2']['source']['slot'] = old
        world['l1'][tl.L1[2]]['info']['height'] += 1
        report, _ = tl.run(world)
        self.assertEqual(tl.level(report, 'settlement_age'), 'CRIT',
                         f'status {l2m.LEVEL_NAMES[report.status]}; not OK: '
                         f'{[(c["check"], c["level"]) for c in report.checks if c["level"] != "OK"]}')

    def test_m4_heartbeat_is_not_a_plain_ok_ping_when_the_alert_was_not_delivered(self):
        """A CRIT is due and the webhook/Telegram delivery fails. The dead-man ping still goes out unchanged, so the
        only outside signal says the monitoring is alive; exit 2 is a unit success (SuccessExitStatus=1 2 3)."""
        tmp = Path(tempfile.mkdtemp(prefix='m4-', dir=HERE))
        try:
            (tmp / 'alert.json').write_text(json.dumps({
                'webhook_url': 'https://hooks.example/x', 'heartbeat_url': 'https://hc.example/ping/uuid',
                'state_file': str(tmp / 'alert.state')}))
            args = types.SimpleNamespace(alert_config=str(tmp / 'alert.json'), alert_dry_run=False, timeout=1.0,
                                         profile='mainnet')
            r = l2m.Report()
            r.add('settlement_age', l2m.CRIT, 'last settlement accepted 180 min ago')
            pinged = []

            def urlopen(req, timeout=None):
                pinged.append(req.full_url)
                return io.BytesIO(b'OK')

            def sender(cfg, text, payload, timeout, dry_run):
                raise OSError('HTTP Error 401: Unauthorized')

            with mock.patch.object(l2m.urllib.request, 'urlopen', urlopen):
                decision = l2m.handle_alerts(args, r, 1_800_000_000.0, sender=sender)
            self.assertEqual(decision, 'raise')
            self.assertEqual(pinged, [], f'undelivered CRIT, yet the dead-man was told all is well: {pinged}')
        finally:
            shutil.rmtree(tmp)

    def test_m5_a_malformed_l1_field_does_not_kill_the_whole_run(self):
        """One null where a number is expected (here inbox.escrow_sat) raises out of run(): main() has no guard, so
        there is no report, no alert and no heartbeat, and python's exit 1 is a unit success meaning WARN."""
        world = tl.healthy()
        world['l1'][tl.L1[0]]['info']['height'] += 1
        world['l1'][tl.L1[0]]['l2']['inbox']['escrow_sat'] = None
        try:
            report, _ = tl.run(world)
        except Exception as e:  # noqa: BLE001
            self.fail(f'run() raised {type(e).__name__}: {e}')
        self.assertIn(report.status, (l2m.CRIT, l2m.UNKNOWN, l2m.WARN))


if __name__ == '__main__':
    unittest.main()
