#!/usr/bin/env python3
"""Real settled RPC on a private net with a frozen, then deleted, then restored follower status; real monitor each time.

The RPC reads a copy of the status, so the live follower is untouched. Loopback only.

  finality_status_exercise.py FS RPC_BINARY PORT L1_PORT
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

R, BIN, PORT, L1 = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
HERE = Path(__file__).resolve().parent
RUN, OUT = R / 'run', R / 'alerts/finality-status'
OUT.mkdir(parents=True, exist_ok=True)
state = json.loads((RUN / 'state.json').read_text())
copy = OUT / 'status.json'
shutil.copy2(RUN / 'follower-status.json', copy)
rpc = subprocess.Popen([BIN, '--data-dir', str(RUN / 'canonical'), '--view-dir', str(OUT / 'view'), '--finality-status', str(copy),
                        '--network', state['network_domain'], '--port', PORT, '--poll-ms', '2000', '--rules', 'mainnet', '--domain',
                        '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733', '--genesis-time', '1786656679'],
                       stdout=(OUT / 'rpc.log').open('a'), stderr=subprocess.STDOUT)


def look(label):
    done = subprocess.run([sys.executable, str(HERE / 'monitor_private.py'), str(RUN / 'state.json'), L1, '--profile', 'mainnet', '--phase', 'live',
                           '--l2-rpc', f'C=http://127.0.0.1:{PORT}', '--l1-rpc', f'http://127.0.0.1:{L1}', '--json'], capture_output=True, text=True)
    doc = json.loads(done.stdout)
    rows = [(c['level'], c['check'], c['message'][:130]) for c in doc['checks']
            if c['check'] in ('l2_rpc[C]', 'l2_finality_closed[C]', 'l2_finality_status[C]', 'l2_backends')]
    print(time.strftime('%H:%M:%SZ', time.gmtime()), label, json.dumps(rows), flush=True)


try:
    time.sleep(10)
    look('fresh copy')
    for label, wait in (('frozen 5+ min', 310), ('frozen 15+ min', 600)):
        time.sleep(wait)
        look(label)
    os.unlink(copy)
    time.sleep(8)
    look('deleted')
    shutil.copy2(RUN / 'follower-status.json', copy)
    time.sleep(8)
    look('restored')
finally:
    rpc.terminate()
    rpc.wait(20)
(OUT / 'DONE').write_text('ok\n')
