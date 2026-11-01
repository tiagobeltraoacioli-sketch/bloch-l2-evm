#!/usr/bin/env python3
"""Provoke every alert a live L2 needs on a private net and record which fired (loopback only, throwaway keys).

Uses the drill harness (codex/l2-drills-20261030, drills/drillctl.py) with ports moved to 25800-25899. Writes one
JSON document per observation to FS/alerts/ and the verdict table to FS/alerts/VERDICT.json, then stops the net.
Thresholds are the mainnet defaults except where a step records its --set values.

  FS=DIR alert_exercise.py STEP...     steps: bringup window prover da stop
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

R = Path(os.environ['FS'])
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(R / 'src/rehearsal/drills'))
sys.path.insert(0, str(R / 'src/rehearsal'))
import drillctl as d  # noqa: E402
import fullstack as fs  # noqa: E402

RUN, OUT = d.RUN, R / 'alerts'
OUT.mkdir(exist_ok=True)
HOOK_PORT, RPC_S_PORT = 25895, 25893
FILL = R / 'diskfill'
hooks = []
fired = {}
SEEN = OUT / 'fired.json'
if SEEN.exists():
    fired = json.loads(SEEN.read_text())
seq = [0]
SERVING = []


def say(*a):
    print(time.strftime('%H:%M:%SZ', time.gmtime()), *a, flush=True)


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0)))
        hooks.append(json.loads(body))
        with (OUT / 'webhook.jsonl').open('ab') as f:
            f.write(body + b'\n')
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def serve_hook():
    if SERVING:
        return
    SERVING.append(1)
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', HOOK_PORT), Hook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def monitor(label, *extra):
    """One real monitor run; records its JSON and every check at WARN or worse."""
    cfg = OUT / 'alert.json'
    if not cfg.exists():
        cfg.write_text(json.dumps({'webhook_url': f'http://127.0.0.1:{HOOK_PORT}/', 'min_level': 'WARN', 'realert_seconds': 3600,
                                   'state_file': str(OUT / 'alert.state')}))
    s = fs.state()
    argv = [sys.executable, str(HERE / 'monitor_private.py'), str(fs.STATE), str(d.RPC[0]), '--profile', 'mainnet', '--phase', 'live',
            '--l2-rpc', f'A=http://127.0.0.1:{d.L2_RPC}', *sum((['--l1-rpc', f'http://127.0.0.1:{p}'] for p in d.RPC[:3]), []),
            '--follower-status', f'A={RUN}/follower-status.json', '--event-log', f'settler={RUN}/settler.log',
            '--da-script', f'da={s["da_script"]}', '--disk', f'state={R}', '--alert-config', str(cfg), '--json', *extra]
    done = subprocess.run(argv, capture_output=True, text=True)
    try:
        doc = json.loads(done.stdout)
    except ValueError:
        doc = {'checks': [], 'unparsed': done.stdout[-800:], 'stderr': done.stderr[-800:]}
    seq[0] += 1
    (OUT / f'{int(time.time())}-{label}.json').write_text(json.dumps(doc, indent=1))
    bad = {c['check']: (c['level'], c['message'][:150]) for c in doc.get('checks', []) if c['level'] != 'OK'}
    say(f'monitor[{label}] exit {done.returncode}', json.dumps(bad)[:1500])
    return bad


def note(alert, level, check, how, evidence=None):
    fired.setdefault(alert, []).append({'level': level, 'check': check, 'how': how, 'evidence': evidence,
                                        'time': time.strftime('%H:%M:%SZ', time.gmtime())})
    SEEN.write_text(json.dumps(fired, indent=1))
    say('FIRED', alert, level, check)


def watch(alert, label, check_prefix, want, deadline, how, *extra):
    """Poll the monitor until check_prefix reaches a level in `want`; records it, or records that it never fired."""
    end, t0 = time.time() + deadline, time.time()
    while time.time() < end:
        bad = monitor(label, *extra)
        hit = {k: v for k, v in bad.items() if k.startswith(check_prefix) and v[0] in want}
        if hit:
            note(alert, next(iter(hit.values()))[0], next(iter(hit)), how, {'after_s': int(time.time() - t0), 'checks': hit})
            return True
        time.sleep(45)
    note(alert, 'NOT-FIRED', check_prefix, how, {'after_s': int(time.time() - t0)})
    return False


def bringup():
    d.net()
    d.l2init()
    (R / 'bin/docker').unlink(missing_ok=True)  # this host has the pinned image and a real daemon
    (RUN / 'prover.cap').write_text('56G\n')
    config = json.loads((RUN / 'settler.json').read_text())
    config['da']['low_balance_sat'] = 4000
    config['prover_threads'] = 16
    (RUN / 'settler.json').write_text(json.dumps(config, indent=2))
    fs.l2key('user')
    while not (isinstance(d.safe_rpc('getl2settlement'), dict) and (d.safe_rpc('getchaininfo').get('height') or 0) > 5):
        time.sleep(5)
    for _ in range(60):
        try:
            fs.deposit('user', 2_000_000_000)
            break
        except SystemExit:
            time.sleep(5)
    time.sleep(10)
    d.up('follower'), d.up('rpc'), d.up('settler')
    d.wait('accepted', 1, 3600)
    while not d.safe_rpc('eth_getBalance', ['0x' + fs.state()['l2_address_user'], 'latest'], port=d.L2_RPC) not in ('0x0', None):
        time.sleep(5)
    say('accepted 1')
    monitor('baseline', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    (R / 'bringup.done').write_text('ok\n')


def status_pad(source, target, size):
    """Synthetic: a copy of the real status with a padding field, to reach a size no private net can."""
    doc = json.loads(source.read_text())
    doc['_pad'] = ''
    base = len(json.dumps(doc))
    doc['_pad'] = 'x' * max(0, size - base)
    tmp = target.with_suffix('.tmp')
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, target)


def rpc_finalized(port):
    b = d.safe_rpc('eth_getBlockByNumber', ['finalized', False], port=port)
    return int(b['number'], 16) if isinstance(b, dict) and 'number' in b else str(b)[:80]


def status_size():
    """A second settled RPC reads a padded copy of the real status. Entry k is added only when the copy is over the limit
    (does `finalized` follow it?) and again just under it (it must). Padding is synthetic; the entries and RPC are real."""
    src = RUN / 'follower-status.json'
    pad, s = OUT / 'status-pad.json', fs.state()
    end = time.time() + 1800
    while time.time() < end and len(json.loads(src.read_text()).get('finalized_settlements', [])) < 2:
        time.sleep(15)
    full = json.loads(src.read_text())
    entries = full.get('finalized_settlements', [])
    older = RUN / 'status-older.json'
    older.write_text(json.dumps({**full, 'finalized_settlements': entries[:-1]}))
    status_pad(older, pad, 1000)
    log = (OUT / 'rpc-status-size.log').open('a')
    proc = subprocess.Popen([os.environ.get('DRILL_RPC_BIN', str(R / 'out/bloch-l2-settled-rpc')), '--data-dir', str(RUN / 'canonical'),
                             '--view-dir', str(RUN / 'rpcs-view'), '--finality-status', str(pad), '--network', s['network_domain'],
                             '--port', str(RPC_S_PORT), '--poll-ms', '2000', *fs.NET_ARGS], stdout=log, stderr=subprocess.STDOUT)
    result = {'entries': len(entries), 'newest': entries[-1].get('l2_number') if entries else None}
    try:
        time.sleep(15)
        result['finalized_small_older'] = rpc_finalized(RPC_S_PORT)
        for mib, source in ((9, older), (15, older), (17, src)):
            status_pad(source, pad, mib << 20)
            time.sleep(10)
            bad = monitor(f'status-{mib}mib', '--follower-status', f'pad={pad}')
            hit = bad.get('follower_status_size[pad]')
            note('status file size', hit[0] if hit else 'NOT-FIRED', 'follower_status_size[pad]', f'synthetic padding to {mib} MiB', hit)
            result[f'finalized_at_{mib}mib'] = rpc_finalized(RPC_S_PORT)
        status_pad(src, pad, 15 << 20)
        time.sleep(10)
        result['finalized_back_at_15mib_with_newest'] = rpc_finalized(RPC_S_PORT)
        (OUT / 'status-size-result.json').write_text(json.dumps(result, indent=1))
        say('status size', json.dumps(result))
    finally:
        proc.terminate()
        proc.wait(20)


def disk_fill():
    """A real small filesystem: real free-space percentages and real ENOSPC. Scratch tmpfs, unmounted afterwards."""
    FILL.mkdir(exist_ok=True)
    subprocess.run(['sudo', '-n', 'mount', '-t', 'tmpfs', '-o', 'size=64m,nosuid,nodev,noexec', 'tmpfs', str(FILL)], check=True)
    try:
        args = ('--disk', f'fill={FILL}', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
        hit = monitor('disk-empty', *args)
        note('disk baseline', hit.get('disk[fill]', ['OK'])[0], 'disk[fill]', 'empty tmpfs, expected OK')
        for mb, label in ((56, 'WARN'), (62, 'CRIT')):
            subprocess.run(['dd', 'if=/dev/zero', f'of={FILL}/fill', 'bs=1M', f'count={mb}'], capture_output=True)
            hit = monitor(f'disk-{mb}m', *args)
            note('disk', hit.get('disk[fill]', ['NOT-FIRED'])[0], 'disk[fill]', f'{mb} of 64 MB used on a tmpfs', hit.get('disk[fill]'))
        done = subprocess.run(['dd', 'if=/dev/zero', f'of={FILL}/more', 'bs=1M', 'count=8'], capture_output=True, text=True)
        (OUT / 'disk-enospc.txt').write_text(done.stderr)
    finally:
        subprocess.run(['sudo', '-n', 'umount', str(FILL)], check=False)


def attestor_halt():
    """The real agent with a follower that differs from its pin (no key is involved: identity halts first)."""
    kit = R / 'src/mainnet/attestor'
    work = OUT / 'attestor'
    work.mkdir(exist_ok=True)
    follower = R / 'out/bloch-l2-native-follower'
    config = {'signer_index': 0, 'bloch_pos': str(R / 'out/bloch-pos'), 'bloch_pos_sha256': fs.sha(R / 'out/bloch-pos'),
              'produce': str(fs.PRODUCE), 'produce_sha256': fs.sha(fs.PRODUCE), 'follower': str(follower), 'follower_sha256': '00' * 32,
              'manifest': str(RUN / 'genesis.blg'), 'attestors': str(work / 'none'), 'sealed_key': str(work / 'none'),
              'follower_status': str(RUN / 'follower-status.json'), 'follower_native': str(RUN / 'follower'),
              'state_dir': str(work / 'state'), 'rpc_urls': []}
    (work / 'config.json').write_text(json.dumps(config))
    log = work / 'agent.log'
    with log.open('a') as f:
        done = subprocess.run([sys.executable, '-I', str(kit / 'attestor_agent.py'), 'once', '--config', str(work / 'config.json')],
                              stdout=f, stderr=subprocess.STDOUT)
    (work / 'agent.exit').write_text(f'{done.returncode}\n')
    hit = monitor('attestor-halt', '--event-log', f'attestor={log}', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    note('attestor halt', hit.get('events[attestor]', ['NOT-FIRED'])[0], 'events[attestor]', f'real agent, follower pin mismatch, exit {done.returncode}',
         hit.get('events[attestor]'))


def window():
    """Settler down for the whole window, 2 of 5 validators down: settlement, head and finality alerts at mainnet thresholds."""
    serve_hook()
    n0 = d.safe_rpc('getchaininfo')
    d.down('settler')
    # The worker's prover keeps running after a stop only if orphaned; the group is stopped by the unit rule.
    time.sleep(5)
    status_size()
    disk_fill()
    attestor_halt()
    t0 = time.time()
    d.down('node3'), d.down('node4')
    say('stalled from', json.dumps({k: n0.get(k) for k in ('height', 'finalized_height', 'epoch')}))
    a = threading.Thread(target=watch, args=('finality lag (L1)', 'finality', 'l1_finality_lag', ('CRIT',), 1500,
                                             '2 of 5 validators down, mainnet threshold 8 epochs', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0'))
    a.start()
    a.join()
    say('finality CRIT after', int(time.time() - t0))
    # Restore finality; the settlement age keeps growing, because the settler stays down.
    d.up('node3'), d.up('node4')
    watch('settlement lag', 'settlement', 'settlement_age', ('WARN', 'CRIT'), 1800, 'settler stopped, mainnet thresholds 25/45 min',
          '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    watch('settlement lag', 'settlement', 'settlement_age', ('CRIT',), 1800, 'settler stopped, mainnet threshold 45 min',
          '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    (R / 'window.done').write_text('ok\n')


def prover():
    """A real OOM of the real prover at a 4G cgroup cap, twice; the repeat threshold is lowered to 2 so CRIT can be seen."""
    serve_hook()
    (RUN / 'prover.cap').write_text('4G\n')
    d.up('settler')
    since = len(d.events())
    first = d.wait('prover-failed', None, 3600, since=since)
    bad = monitor('prover-1', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    note('prover failure', bad.get('events[settler]', ['NOT-FIRED'])[0], 'events[settler]', f'real OOM, exit {first.get("exit_code")}', bad.get('events[settler]'))
    since = len(d.events())
    d.wait('prover-failed', None, 3600, since=since)
    bad = monitor('prover-2', '--set', 'event_repeat_crit=2', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    note('prover failure', bad.get('events[settler]', ['NOT-FIRED'])[0], 'events[settler]', 'second real OOM, event_repeat_crit lowered to 2', bad.get('events[settler]'))
    (RUN / 'prover.cap').write_text('56G\n')
    (R / 'prover.done').write_text('ok\n')


def da():
    """Real DA spending from a 5000 sat key: each user-transaction block pays about 2200 sat."""
    serve_hook()
    args = ('--set', 'da_balance_warn_sat=4000', '--set', 'da_balance_crit_sat=1000', '--set', 'disk_free_gib_warn=0', '--set', 'disk_free_gib_crit=0')
    bad = monitor('da-start', *args)
    note('DA balance baseline', bad.get('da_balance[da]', ['OK'])[0], 'da_balance[da]', 'before any DA transaction, scaled thresholds')
    for label in ('first', 'second'):
        since = len(d.events())
        d.send(1)
        d.wait('da-included', None, 3600, since=since)
        bad = monitor(f'da-{label}', *args)
        note('DA balance', bad.get('da_balance[da]', ['OK'])[0], 'da_balance[da]', f'{label} DA transaction included', bad.get('da_balance[da]'))
        d.wait('accepted', None, 1800, since=since)
    evs = [e for e in d.events() if e.get('event') == 'da-funding-low']
    note('DA worker event', 'WARN' if evs else 'NOT-FIRED', 'da-funding-low', 'the worker event, seen only when a DA batch is prepared', evs[-1:])
    since = len(d.events())
    d.send(1)
    end = time.time() + 3000
    outcome = None
    while time.time() < end and outcome is None:
        for e in d.events()[since:]:
            if e.get('event') in ('halt', 'retry') and 'DA' in str(e.get('reason', '')) + str(e.get('event')):
                outcome = e
            elif e.get('event') == 'halt':
                outcome = e
        time.sleep(10)
    (OUT / 'da-exhausted.json').write_text(json.dumps(outcome, indent=1))
    monitor('da-exhausted', *args)
    (R / 'da.done').write_text('ok\n')


def stop():
    d.stop()


if __name__ == '__main__':
    for step in sys.argv[1:]:
        say('STEP', step)
        try:
            {'bringup': bringup, 'window': window, 'prover': prover, 'da': da, 'stop': stop}[step]()
        except BaseException as e:  # noqa: BLE001 - the marker must always say how a step ended
            (R / f'{step}.failed').write_text(f'{type(e).__name__}: {e}\n')
            say('FAILED', step, repr(e)[:800])
            raise
    (R / 'EXERCISE-DONE').write_text('ok\n')
