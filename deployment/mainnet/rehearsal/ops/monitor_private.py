#!/usr/bin/env python3
"""Run the real l2_monitor.py against a private net: the identity pins and the slot clock come from that net.

Only module constants change. Every check, threshold and alert decision is the production code.
Private-net rehearsals only; the state file names the private genesis.

  monitor_private.py STATE.JSON L1_PORT MONITOR_ARGS...
"""
import json
from pathlib import Path
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import l2_monitor as m  # noqa: E402


def main():
    state, port, argv = json.loads(Path(sys.argv[1]).read_text()), sys.argv[2], sys.argv[3:]
    req = urllib.request.Request(f'http://127.0.0.1:{port}', headers={'Content-Type': 'application/json'},
                                 data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'getl2settlement', 'params': []}).encode())
    view = json.loads(urllib.request.urlopen(req, timeout=10).read())['result']
    m.L1_GENESIS_TIME, m.SLOT_SECONDS, m.EPOCH_SECONDS = state['genesis_secs_approx'], 2, 64
    m.MAINNET_PINS.update(network=m.strip0x(view['network']), genesis=m.strip0x(view['genesis']),
                          attestor_set=m.strip0x(view['withdrawals']['attestor_set']))
    m.V2_COMPILED_GATES.clear()  # the private build forces its gates early
    sys.exit(m.main(argv))


if __name__ == '__main__':
    main()
