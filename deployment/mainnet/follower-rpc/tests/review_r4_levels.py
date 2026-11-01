#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent review, round 4: how the settled RPC behaves when its follower status goes wrong.

Real here: the settled RPC binary, the private L2 database, blocks and receipts written by
bloch-l2-produce-dev under mainnet rules. Synthetic: this script writes the follower status and its
log (no L1, no follower). Loopback ports, throwaway keys.

Each check states the behaviour a reader of the levels needs. A FAIL is a finding, reported with its
output. It does not fix anything.

  review_r4_levels.py --work NEW_DIR --rpc BIN --produce BIN [--big-chain DIR --big-blocks FILE] --port 27710
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / 'attestor'))
import attestor_lib as L  # noqa: E402

NET = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
DOM = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L1_GENESIS_TIME = 1786656679
RULES = ['--rules', 'mainnet', '--domain', DOM, '--genesis-time', str(L1_GENESIS_TIME)]
GEN = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
ME = '11' * 32
results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok)))
    print(f'{"PASS" if ok else "FAIL"} {name}: {json.dumps(detail)[:600]}', flush=True)


def note(name, detail):
    print(f'NOTE {name}: {json.dumps(detail)[:600]}', flush=True)


class Chain:
    """A status file and log for a database, written as the follower writes them."""

    def __init__(self, work, entries):
        self.work, self.entries = Path(work), entries
        self.status = self.work / 'status.json'
        self.log = self.work / 'status.settlements.jsonl'

    def write(self, count, written_at=None, safe=None, extra=None, rewrite_log=True):
        chosen = self.entries[:count] + (extra or [])
        lines = [json.dumps(e, separators=(',', ':')).encode() + b'\n' for e in chosen]
        if rewrite_log:
            tmp = self.log.with_suffix('.new')
            tmp.write_bytes(b''.join(lines))
            tmp.replace(self.log)
        doc = {'schema': L_V3, 'written_at_unix': written_at or int(time.time()), 'network': NET, 'chain_id': 700770,
               'settlement_policy': 'ef' * 32, 'verified_blocks': 200000, 'verified_slot': 224100, 'verified_tip': '12' * 32,
               'native_finalized_block': 'cd' * 32, 'native_finalized_epoch': 7000, 'native_finalized_slot': 224000,
               'l2_genesis': {'activation_block': 'ab' * 32, 'activation_slot': 187200, 'finalized': True, 'hash': GEN,
                              'state_root': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'},
               'finalized_settlements_count': len(lines), 'finalized_settlements_recent': chosen[-64:],
               'settlement_log': {'file': self.log.name, 'entries': len(lines), 'bytes': sum(map(len, lines)),
                                  'digest': digest(lines)},
               'safe_settlement': safe, 'production_finality': False}
        if SCHEMA_V2:  # the closed v2.1 build reads only this form
            for key in ('finalized_settlements_count', 'finalized_settlements_recent', 'settlement_log'):
                del doc[key]
            doc.update(schema='bloch.l2.native-follower-status.v2', finalized_settlements=chosen)
        tmp = self.status.with_suffix('.new')
        tmp.write_text(json.dumps(doc))
        tmp.replace(self.status)


L_V3 = 'bloch.l2.native-follower-status.v3'
SCHEMA_V2 = False
DIGESTS = {}


def digest(lines):
    d = L.keccak256(L.SETTLEMENT_LOG_DOMAIN)
    for line in lines:
        d = L.keccak256(d + line)
    return d.hex()


def call(port, method, params=()):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}', data=body, headers={'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


class Rpc:
    def __init__(self, binary, data, status, port, work, poll_ms=200):
        self.port, self.log = port, Path(work) / f'rpc-{port}.log'
        view = Path(work) / f'view-{time.time_ns()}'
        self.process = subprocess.Popen([binary, '--data-dir', data, '--view-dir', view, '--finality-status', status, '--network', NET,
                                         '--port', str(port), '--poll-ms', str(poll_ms), *RULES],
                                        stdout=open(self.log, 'a'), stderr=subprocess.STDOUT)
        self.started = time.time()
        deadline = time.time() + 120
        while True:
            if self.process.poll() is not None:
                raise SystemExit(f'the RPC exited; see {self.log}')
            try:
                call(port, 'eth_chainId')
                self.up = time.time()
                return
            except OSError:
                if time.time() > deadline:
                    raise SystemExit('the RPC did not start')
                time.sleep(0.02)

    def stop(self):
        self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def cpu(self):
        f = Path(f'/proc/{self.process.pid}/stat').read_text().rsplit(')', 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf('SC_CLK_TCK')

    def finality(self):
        return call(self.port, 'bloch_finality').get('result')

    def finalized(self):
        return call(self.port, 'eth_getBlockByNumber', ['finalized', False])


def small_chain(a, work):
    """A private chain with withdrawals: a deposit block, then blocks that add withdrawals."""
    db = work / 'small'
    produce = lambda *argv: subprocess.run([a.produce, *map(str, argv)], capture_output=True, text=True, check=True).stdout
    produce('init', '--target', db, *RULES)
    key = work / 'throwaway.key'
    key.touch(mode=0o600)
    key.write_text(secrets.token_hex(32))
    out = produce('address', '--key', key).strip()
    address = json.loads(out)['address'] if out.startswith('{') else out
    blocks, slot = [], 0

    def extend(*extra):
        nonlocal slot
        parent = json.loads(produce('head', '--target', db, *RULES))['hash']
        slot += 1
        now_slot = (int(time.time()) - L1_GENESIS_TIME) // 30 + slot
        block = json.loads(produce('extend', '--target', db, '--parent', parent, '--anchor', 'ab' * 32, '--timestamp-rule',
                                   f'1:{L1_GENESIS_TIME}:30000', '--anchor-slot', now_slot, *RULES, *extra))
        blocks.append(block)
        return block

    deposits = work / 'deposits.json'
    deposits.write_text(json.dumps([{'height': 1, 'tx_index': 0, 'txid': '0x' + '01' * 32, 'vout': 0, 'sats': 5_000_000_000_000,
                                     'recipient': address}]))
    extend('--deposits', deposits)
    for nonce in range(3):
        tx = work / f'tx-{nonce}.hex'
        produce('sign-tx', '--key', key, '--nonce', nonce, '--withdraw-to', ME, '--sats', 2_000_000 + nonce, '--out', tx, *RULES)
        pool = work / 'pool.json'
        pool.write_text(json.dumps([tx.read_text().strip()]))
        extend('--txs', pool)
    return db, [{'l2_number': b['number'], 'l2_hash': b['hash'], 'l2_state_root': b.get('state_root', ''),
                 'withdrawals': {'root': b['withdrawal_root'], 'count': b['withdrawal_count']},
                 'native_slot': 300000 + b['number'], 'native_block': 'cd' * 32, 'commitment': 'ef' * 32} for b in blocks]


def wait_for(condition, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def closed_code(answer):
    return (answer.get('error') or {}).get('code')


def scenario_small(a, work):
    db, entries = small_chain(a, work)
    last = len(entries)
    note('small chain', {'blocks': last, 'head': entries[-1]['l2_hash'], 'withdrawals': entries[-1]['withdrawals']})
    dir_ = work / 'small-run'
    dir_.mkdir()
    chain = Chain(dir_, entries)

    # 1. A status that names a block this database has not reached.
    chain.write(last)
    rpc = Rpc(a.rpc, db, chain.status, a.port, dir_)
    try:
        wait_for(lambda: (rpc.finality() or {}).get('finalized_height') == last)
        before = rpc.finality()['status']
        check('baseline: an open RPC reports a young status', before['state'] == 'ok' and before['age_s'] < 30, before)
        ahead = {'l2_number': last + 1, 'l2_hash': 'aa' * 32, 'l2_state_root': 'bb' * 32, 'withdrawals': entries[-1]['withdrawals'],
                 'native_slot': 1, 'native_block': 'cd' * 32, 'commitment': 'ef' * 32}
        written = int(time.time()) - 7200
        chain.write(last, written_at=written, extra=[ahead])
        time.sleep(4)
        view = rpc.finality()
        check('lagging database: age_s follows the file, 2 h old, or the state stops being ok',
              view['status']['state'] != 'ok' or (view['status']['age_s'] or 0) >= 7200,
              {'file_written_at': written, 'file_age_s': int(time.time()) - written, 'bloch_finality.status': view['status']})
        for _ in range(3):
            time.sleep(3)
        again = rpc.finality()
        check('lagging database: age_s does not stand still while the status file ages',
              again['status']['age_s'] != view['status']['age_s'] or again['status']['written_at_unix'] == written,
              {'first': view['status'], 'nine_s_later': again['status'],
               'log_lines': subprocess.run(['grep', '-c', 'finality not advanced', rpc.log], capture_output=True, text=True).stdout.strip()})

        # 2. Lost status: the levels close. Does the method that says "finalized": true close with them?
        chain.write(last)
        wait_for(lambda: (rpc.finality() or {}).get('status', {}).get('age_s', 9e9) < 30)
        wait_for(lambda: 'result' in call(rpc.port, 'bloch_getWithdrawalProof', [0]))
        proof = call(rpc.port, 'bloch_getWithdrawalProof', [0])
        check('baseline: a finalized withdrawal has a proof', (proof.get('result') or {}).get('finalized') is True, proof.get('error'))
        os.remove(chain.status)
        wait_for(lambda: closed_code(rpc.finalized()) == -32001)
        closed = rpc.finalized()
        check('baseline: a lost status closes finalized', closed_code(closed) == -32001, closed)
        answer = call(rpc.port, 'bloch_getWithdrawalProof', [0])
        check('closed levels: bloch_getWithdrawalProof does not assert finalized:true',
              (answer.get('result') or {}).get('finalized') is not True,
              {'finalized_tag': closed.get('error'), 'proof_keys': {k: answer['result'][k] for k in ('number', 'finalized', 'withdrawal_count')} if 'result' in answer else answer})
        settlement = call(rpc.port, 'bloch_settlement', [1])
        check('closed levels: bloch_settlement says closed, not "no settlement"', closed_code(settlement) == -32001,
              settlement)
        # Methods behind the loopback port (replica consumers) that take a tag and are not in the closed list.
        for method, params in (('eth_getAccountInfo', ['0x' + '00' * 20, 'finalized']),
                               ('eth_simulateV1', [{'blockStateCalls': []}, 'finalized']),
                               ('eth_callMany', [[{'transactions': []}], {'blockNumber': 'finalized'}]),
                               ('eth_getBlockByNumber', ['finalized', False]),
                               ('eth_getBalance', ['0x' + '00' * 20, {'blockNumber': 'safe'}])):
            answer = call(rpc.port, method, params)
            served = 'result' in answer
            check(f'closed levels: {method} at a closed tag is refused', not served or answer.get('result') is None,
                  {'params': params, 'answer': str(answer)[:240]})
        chain.write(last)
        wait_for(lambda: 'result' in rpc.finalized())

        # 3. The follower's list shrinks: a restored backup, a truncated replay.
        chain.write(last)
        time.sleep(1)
        chain.write(1)
        states, deadline = [], time.time() + 3
        while time.time() < deadline:
            states.append(closed_code(rpc.finalized()) or 'open')
            time.sleep(0.05)
        final = rpc.finality()
        check('a regressed log keeps the levels closed until an operator looks ("restart this RPC only after checking the follower")',
              states[-1] == -32001, {'samples': len(states), 'closed_samples': states.count(-32001), 'last': states[-1],
                                     'status': final.get('status')})
        settled = call(rpc.port, 'bloch_settlement', [last])
        check('after a regressed log, a level the RPC still publishes keeps its settlement record',
              settled.get('result') is not None or final.get('finalized_height') != last,
              {'finalized_height': final.get('finalized_height'), 'bloch_settlement(tip)': settled.get('result')})
        chain.write(last)
        wait_for(lambda: call(rpc.port, 'bloch_settlement', [last]).get('result') is not None)

        # 4. A settlement accepted at the L1 head that this database does not hold (a third party settled).
        foreign = dict(entries[-1], l2_hash='ee' * 32)
        chain.write(last - 1, safe=foreign)
        wait_for(lambda: closed_code(rpc.finalized()) == -32001, 5)
        answer = rpc.finalized()
        check('a foreign, not yet finalized settlement at the L1 head does not close the verified finalized prefix',
              closed_code(answer) != -32001, {'finalized': answer.get('error') or (answer.get('result') or {}).get('number'),
                                              'status': rpc.finality().get('status')})
    finally:
        rpc.stop()

    # 5. Started while the status file is missing: no history in this process, so nothing "closes".
    os.remove(chain.status)
    rpc = Rpc(a.rpc, db, chain.status, a.port, dir_)
    try:
        time.sleep(2)
        answer = rpc.finalized()
        view = rpc.finality()
        check('started without a status: finalized answers closed (-32001), as it does when the file is lost later',
              closed_code(answer) == -32001, {'finalized': answer, 'bloch_finality': view})
        check('started without a status: bloch_finality names the state, so a gateway can tell',
              isinstance(view, dict) and (view.get('status') or {}).get('state') not in (None, 'ok'), view)
    finally:
        rpc.stop()


def scenario_big(a, work):
    blocks = [json.loads(line) for line in open(a.big_blocks)]
    entries = [{'commitment': f'{b["number"]:064x}'[::-1], 'l2_hash': b['hash'], 'l2_number': b['number'], 'l2_state_root': b['state_root'],
                'native_block': f'{b["number"]:064x}', 'native_slot': 300000 + b['number'],
                'withdrawals': {'count': 0, 'root': a.big_root}} for b in blocks]
    count = len(entries)
    lines = [json.dumps(e, separators=(',', ':')).encode() + b'\n' for e in entries]
    dir_ = work / 'big-run'
    dir_.mkdir()
    chain = Chain(dir_, entries)
    start = time.time()
    chain.write(count)
    note('big log', {'entries': count, 'bytes': sum(map(len, lines)), 'written_in_s': round(time.time() - start, 1)})

    # 6. The window after a restart. Foreign recovery and the replica's refresh both restart the RPC.
    rpc = Rpc(a.rpc, a.big_chain, chain.status, a.port + 1, dir_, poll_ms=2000)
    try:
        first_up = rpc.up - rpc.started
        samples = []
        while True:
            finalized, view = rpc.finalized(), rpc.finality()
            settlement = call(rpc.port, 'bloch_settlement', [1]).get('result')
            samples.append({'t': round(time.time() - rpc.up, 3), 'finalized': (finalized.get('result') or {}).get('number'),
                            'error': (finalized.get('error') or {}).get('code'), 'view_null': view is None, 'settlement_1': settlement is not None})
            if view is not None and view.get('finalized_height') == count:
                break
            if time.time() - rpc.up > 240:
                break
            time.sleep(0.2)
        nulls = [s for s in samples if s['finalized'] is None and s['error'] is None]
        check('after a restart, finalized does not answer null ("nothing final") while the settlements are being read',
              not nulls, {'rpc_listening_after_s': round(first_up, 2), 'samples': len(samples), 'null_samples': len(nulls),
                          'null_window_s': nulls[-1]['t'] if nulls else 0, 'first': samples[0], 'last': samples[-1]})

        # 7. Cost of one poll: open, then closed by a mismatching safe settlement.
        time.sleep(5)
        cpu, t = rpc.cpu(), time.time()
        time.sleep(20)
        open_rate = (rpc.cpu() - cpu) / (time.time() - t)
        chain_safe = dict(entries[-1], l2_hash='ee' * 32)
        chain.write(count, safe=chain_safe)
        wait_for(lambda: closed_code(rpc.finalized()) == -32001, 60)
        time.sleep(5)
        cpu, t = rpc.cpu(), time.time()
        time.sleep(30)
        closed_rate = (rpc.cpu() - cpu) / (time.time() - t)
        check('while closed, a poll does not cost much more than while open ("the cost of one poll does not grow with the history")',
              closed_rate < max(5 * open_rate, 0.05),
              {'entries': count, 'cpu_cores_open': round(open_rate, 3), 'cpu_cores_closed': round(closed_rate, 3)})
    finally:
        rpc.stop()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--work', required=True)
    p.add_argument('--rpc', required=True)
    p.add_argument('--produce', required=True)
    p.add_argument('--big-chain')
    p.add_argument('--big-blocks')
    p.add_argument('--big-root', default='')
    p.add_argument('--port', type=int, default=27710)
    p.add_argument('--schema-v2', action='store_true', help='write status schema v2, for the closed v2.1 binary')
    a = p.parse_args()
    global SCHEMA_V2
    SCHEMA_V2 = a.schema_v2
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    scenario_small(a, work)
    if a.big_chain:
        scenario_big(a, work)
    failed = [n for n, ok in results if not ok]
    print(f'{len(results) - len(failed)} passed, {len(failed)} failed')
    for name in failed:
        print('  FAILED', name)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
