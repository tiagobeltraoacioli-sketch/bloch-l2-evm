#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent re-review, round 4: new ways finality can read wrong or stay closed after the C1-C10 fixes.

Same rig and same limits as review_r4_levels.py: real settled RPC and private DB, synthetic status and log.
A FAIL is a finding, reported with its output.

  review_r4b_fixes.py --work NEW_DIR --rpc BIN --produce BIN [--big-chain DIR --big-blocks FILE --big-root HEX] --port 27740
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_r4_levels as L  # noqa: E402
from review_r4_levels import Chain, Rpc, call, check, closed_code, note, small_chain, wait_for  # noqa: E402


def state(rpc):
    return (rpc.finality().get('status') or {}).get('state')


def ahead_of(entries, number):
    return {**entries[-1], 'l2_number': number, 'l2_hash': 'aa' * 32}


def small(a, work):
    db, entries = small_chain(a, work)
    last = len(entries)
    run = work / 'run'
    run.mkdir()
    chain = Chain(run, entries)
    chain.write(last - 1)
    rpc = Rpc(a.rpc, db, chain.status, a.port, run)
    try:
        wait_for(lambda: (rpc.finality() or {}).get('finalized_height') == last - 1)

        # 1. A settled block that contradicts this database, with a newer tip this database lacks. This is the
        # sequencer's database on an orphaned branch once a foreign settlement finalized and the next one followed.
        wrong = [dict(entries[0], l2_hash='ee' * 32), *entries[1:]]
        forked = Chain(run, wrong)
        forked.write(last, extra=[ahead_of(entries, last + 1)])
        time.sleep(3)
        view = rpc.finality()
        check('a finalized settlement that contradicts this database closes finalized, even when the tip is ahead of it',
              closed_code(rpc.finalized()) == -32001, {'status': view.get('status'), 'finalized_height': view.get('finalized_height')})

        # 2. The same with a status for another L2 genesis.
        chain.write(last - 1)
        wait_for(lambda: state(rpc) == 'ok')
        chain.write(last, extra=[ahead_of(entries, last + 1)])
        doc = json.loads(chain.status.read_text())
        doc['l2_genesis']['hash'] = '12' * 32
        chain.status.write_text(json.dumps(doc))
        time.sleep(3)
        check('a status for another L2 genesis closes finalized, even when the tip is ahead of this database',
              closed_code(rpc.finalized()) == -32001, rpc.finality().get('status'))

        # 3. The log gone, with the tip ahead.
        chain.write(last - 1)
        wait_for(lambda: state(rpc) == 'ok')
        chain.write(last, extra=[ahead_of(entries, last + 1)])
        os.remove(chain.log)
        time.sleep(3)
        check('a status whose log is gone closes finalized, even when the tip is ahead of this database',
              closed_code(rpc.finalized()) == -32001, rpc.finality().get('status'))

        # 4. Schema flip under a running RPC, both ways ("needs only a restart, in either direction").
        chain.write(last)
        wait_for(lambda: state(rpc) == 'ok' and (rpc.finality() or {}).get('finalized_height') == last)
        L.SCHEMA_V2 = True
        chain.write(last)
        samples = []
        for _ in range(30):
            samples.append(closed_code(rpc.finalized()) or 'open')
            time.sleep(0.1)
        L.SCHEMA_V2 = False
        chain.write(last)
        for _ in range(30):
            samples.append(closed_code(rpc.finalized()) or 'open')
            time.sleep(0.1)
        check('follower schema flip v3 to v2 to v3 never closes a running RPC', samples.count(-32001) == 0,
              {'closed_samples': samples.count(-32001), 'of': len(samples), 'status': rpc.finality().get('status')})

        # 5. The follower rewrites the same settlements in other bytes (a new follower build's JSON).
        lines = chain.log.read_bytes().splitlines()
        other = [json.dumps(json.loads(x), separators=(', ', ': '), sort_keys=True).encode() + b'\n' for x in lines]
        chain.log.write_bytes(b''.join(other))
        doc = json.loads(chain.status.read_text())
        doc['settlement_log']['bytes'] = sum(map(len, other))
        doc['settlement_log']['digest'] = L.digest(other)
        doc['written_at_unix'] = int(time.time())
        chain.status.write_text(json.dumps(doc))
        time.sleep(3)
        note('same settlements in other bytes, running RPC', {'finalized': rpc.finalized().get('error') or 'open', 'status': rpc.finality().get('status')})
        check('the same settlements in other bytes, consistent with their status, do not need an RPC restart',
              closed_code(rpc.finalized()) != -32001, rpc.finality().get('status'))
    finally:
        rpc.stop()

    # 6. A log refused on the first read for a reason that then goes away, with nothing in the log changing.
    chain.write(last)
    os.chmod(chain.log, 0)
    rpc = Rpc(a.rpc, db, chain.status, a.port, run)
    try:
        time.sleep(2)
        first = rpc.finality().get('status')
        os.chmod(chain.log, 0o644)
        reopened = wait_for(lambda: closed_code(rpc.finalized()) != -32001, 15)
        # The follower keeps rewriting the status, with the log unchanged.
        for _ in range(6):
            chain.write(last, rewrite_log=False)
            time.sleep(1)
        check('a log read refused for a transient reason reopens once the log can be read',
              reopened or closed_code(rpc.finalized()) != -32001,
              {'while_unreadable': first, 'after_fixing_it_21_s': rpc.finality().get('status'), 'finalized': rpc.finalized().get('error')})
    finally:
        os.chmod(chain.log, 0o644)
        rpc.stop()

    # 7. Started behind: the state and the levels must agree.
    chain.write(last, extra=[ahead_of(entries, last + 1)])
    rpc = Rpc(a.rpc, db, chain.status, a.port, run)
    try:
        time.sleep(2)
        view, answer = rpc.finality(), rpc.finalized()
        note('started behind', {'status': view.get('status'), 'finalized_height': view.get('finalized_height'), 'finalized': answer.get('error') or answer.get('result')})
        check('started behind its status: "lagging" (documented as closing nothing) does not hide closed levels',
              closed_code(answer) != -32001 or view.get('status', {}).get('state') != 'lagging',
              {'status': view.get('status'), 'finalized_tag': answer.get('error'), 'proof': call(rpc.port, 'bloch_getWithdrawalProof', [0]).get('error')})
    finally:
        rpc.stop()

    # 8. Before any finality: a status with nothing final, then the file is lost. "A missing status always closes."
    doc_chain = Chain(run, [])
    doc_chain.write(0)
    doc = json.loads(doc_chain.status.read_text())
    doc['l2_genesis']['finalized'] = False
    doc_chain.status.write_text(json.dumps(doc))
    rpc = Rpc(a.rpc, db, doc_chain.status, a.port, run)
    try:
        wait_for(lambda: state(rpc) == 'ok')
        os.remove(doc_chain.status)
        time.sleep(2)
        check('a status lost before anything was final closes too', closed_code(rpc.finalized()) == -32001 and state(rpc) != 'ok',
              {'finalized': rpc.finalized(), 'status': rpc.finality().get('status')})
    finally:
        rpc.stop()


def big(a, work):
    blocks = [json.loads(line) for line in open(a.big_blocks)]
    entries = [{'commitment': f'{b["number"]:064x}'[::-1], 'l2_hash': b['hash'], 'l2_number': b['number'], 'l2_state_root': b['state_root'],
                'native_block': f'{b["number"]:064x}', 'native_slot': 300000 + b['number'],
                'withdrawals': {'count': 0, 'root': a.big_root}} for b in blocks]
    # 9. A process started on a database that left the finalized chain at the tip: the log reads fine, so it is
    # not remembered as refused, and the hash comparison fails after the whole read, at every poll.
    wrong = entries[:-1] + [dict(entries[-1], l2_hash='ee' * 32)]
    run = work / 'big-run'
    run.mkdir()
    chain = Chain(run, wrong)
    chain.write(len(wrong))
    rpc = Rpc(a.rpc, a.big_chain, chain.status, a.port + 1, run, poll_ms=2000)
    try:
        wait_for(lambda: closed_code(rpc.finalized()) == -32001, 30)
        time.sleep(10)
        cpu, t = rpc.cpu(), time.time()
        time.sleep(30)
        rate = (rpc.cpu() - cpu) / (time.time() - t)
        check('started on a database off the finalized chain, a closed poll does not reread the log', rate < 0.05,
              {'entries': len(wrong), 'cpu_cores': round(rate, 3), 'status': rpc.finality().get('status')})
    finally:
        rpc.stop()


def main():
    p = argparse.ArgumentParser()
    for name in ('work', 'rpc', 'produce'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--big-chain')
    p.add_argument('--big-blocks')
    p.add_argument('--big-root', default='')
    p.add_argument('--port', type=int, default=27740)
    a = p.parse_args()
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    small(a, work)
    if a.big_chain:
        big(a, work)
    failed = [n for n, ok in L.results if not ok]
    print(f'{len(L.results) - len(failed)} passed, {len(failed)} failed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
