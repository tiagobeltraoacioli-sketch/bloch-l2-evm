#!/usr/bin/env python3
"""Second pass on 5e2a3a8 (monitors). Real l2_monitor functions; only urllib.request.urlopen is replaced (no network)."""
import argparse, io, json, os, shutil, sys, tempfile, unittest, urllib.error, urllib.request
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))
import l2_monitor as m  # noqa: E402
SCRATCH = str(Path(__file__).resolve().parent / 'tmp')
FEEDS = [f'https://att{i}.example/attest' for i in range(5)]
ROOT = 'aa' * 32


def world(age_blocks=500):
    return [{'height': 10, 'url': 'l1', 'l2': {'native_height': 1000, 'withdrawals': {'released_sat': 0, 'roots': [
        {'root': '0x' + ROOT, 'finalized': True, 'l2_number': 5, 'height': 1000 - age_blocks}]}}}]


class Monitors2(unittest.TestCase):
    def setUp(self):
        os.makedirs(SCRATCH, exist_ok=True)
        self.d = Path(tempfile.mkdtemp(dir=SCRATCH))
        self.real = urllib.request.urlopen

    def tearDown(self):
        urllib.request.urlopen = self.real
        shutil.rmtree(self.d, ignore_errors=True)

    def attestors(self, urlopen):
        urllib.request.urlopen = urlopen
        r = m.Report()
        m.check_attestors(FEEDS, world(), dict(m.PROFILES['mainnet']), m.http_fetcher(1.0), r, 'live')
        return [c for c in r.checks if c['check'] == 'attestors'][0]

    def test_a1_feeds_that_answer_403_to_everything_are_not_reported(self):
        """All five feeds behind a proxy/WAF that answers 403 (or 401, 429) to the monitor: /healthz and every
        partial. http_fetcher records only >= 500 and transport errors, so each feed is "reachable" and each
        partial "missing"."""
        def urlopen(url, timeout=None):
            raise urllib.error.HTTPError(url, 403, 'Forbidden', {}, io.BytesIO(b''))
        c = self.attestors(urlopen)
        print('  403 everywhere ->', c['level'], '|', c['message'])
        self.assertNotEqual(c['level'], 'OK', 'five feeds that refuse the monitor read as "no partial": OK')

    def test_a2_partials_that_time_out_behind_a_healthy_healthz_are_not_reported(self):
        """/healthz answers; every partial request times out (or 502/503). Only the /healthz URL is looked up in
        fetch.errors (probe_drops), the partial URLs never are."""
        def urlopen(url, timeout=None):
            if str(url).endswith('/healthz'):
                return io.BytesIO(b'ok\n')
            raise urllib.error.URLError('timed out')
        c = self.attestors(urlopen)
        print('  partials time out ->', c['level'], '|', c['message'])
        self.assertNotEqual(c['level'], 'OK', 'partials that cannot be fetched read as "no partial": OK')

    def test_a3_alert_delivered_by_webhook_but_telegram_down_withholds_the_ping_and_repeats(self):
        """send_alert raises when ANY target fails, after the webhook already delivered. handle_alerts then treats
        the alert as not delivered: no dead-man ping (the dead-man fires although the operator was told), and no
        state written, so the webhook gets the same alert again on every run."""
        token = self.d / 'token'; token.write_text('123:abc\n')
        cfg = self.d / 'alert.json'
        cfg.write_text(json.dumps({'webhook_url': 'https://hooks.example/x', 'heartbeat_url': 'https://hc.example/ping',
                                   'telegram': {'bot_token_file': str(token), 'chat_id': '1'},
                                   'state_file': str(self.d / 'alert.state')}))
        seen = []

        def urlopen(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            seen.append(url.split('/')[2])
            if 'telegram' in url:
                raise urllib.error.URLError('telegram unreachable')
            return io.BytesIO(b'ok')
        urllib.request.urlopen = urlopen
        args = argparse.Namespace(alert_config=str(cfg), alert_dry_run=False, timeout=1.0, profile='mainnet', phase='live')
        for run in range(3):
            r = m.Report(); r.facts['checked_at'] = 1_800_000_000
            r.add('settlement_age', m.CRIT, 'no settlement for 3 h')
            m.handle_alerts(args, r, 1_800_000_000 + 300 * run)
        print('  three runs, 5 min apart:', seen)
        self.assertEqual(seen.count('hooks.example'), 1, 'the same alert went to the webhook on every run')
        self.assertIn('hc.example', seen, 'the dead-man ping was withheld although the webhook delivered the alert')


if __name__ == '__main__':
    unittest.main(verbosity=2)
