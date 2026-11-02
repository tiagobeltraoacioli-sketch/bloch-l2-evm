#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Withdrawal flow against a real settled RPC over a PRIVATE L2 database. Loopback ports and throwaway keys only.

SYNTHETIC FINALITY, MOCK L1. Real here: the settled RPC binary, blocks and receipts written by
bloch-l2-produce-dev under mainnet rules, the client tool, the native `bloch-pos l2-claim prepare`
parser, and (--live-l1) one read of a public L1 RPC. Not real: this script writes the follower
status file and answers `getl2settlement` from a snapshot it patches, so no L1 settlement or
proof is involved.

  live_private_l2.py --work DIR --rpc BIN --produce BIN --canonical DIR --status FILE
                     --bloch-pos BIN --genesis FILE [--live-l1 URL] [--port-base 19761]
"""
import argparse
import atexit
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve()
TOOL = HERE.parent.parent / 'bloch-l2-withdraw.py'
sys.path.insert(0, str(HERE.parents[2] / 'attestor'))
import attestor_lib  # noqa: E402
NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
GENESIS = '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415'
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L1_GENESIS_TIME = 1786656679
RULES = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', str(L1_GENESIS_TIME)]
ME = '11' * 32
OTHER = '22' * 32

results = []


def check(name, ok, detail=''):
    results.append(bool(ok))
    print(f'{"PASS" if ok else "FAIL"} {name}{"" if ok else f": {detail}"}', flush=True)


class Rig:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work).resolve()
        self.canonical = self.work / 'canonical'
        self.status = self.work / 'status.json'
        self.base_status = json.loads(Path(args.status).read_text())
        self.blocks = []
        self.rpc_process = None
        self.rpc_port = args.port_base
        self.url = f'http://127.0.0.1:{self.rpc_port}'
        self.nonce = 0
        self.slot_offset = 0

    def produce(self, *argv):
        done = subprocess.run([self.args.produce, *map(str, argv)], capture_output=True, text=True)
        if done.returncode:
            raise SystemExit(f'produce-dev {argv[0]}: {done.stderr}')
        return done.stdout

    def setup(self):
        self.work.mkdir(parents=True, exist_ok=False)
        shutil.copytree(self.args.canonical, self.canonical)
        self.key = self.work / 'throwaway.key'
        self.key.touch(mode=0o600)
        self.key.write_text(secrets.token_hex(32))
        out = self.produce('address', '--key', self.key).strip()
        try:
            self.address = json.loads(out)['address']
        except ValueError:
            self.address = out
        self.write_status(0)

    def head(self):
        return json.loads(self.produce('head', '--target', self.canonical, *RULES))

    def extend(self, *extra):
        parent = self.head()['hash']
        self.slot_offset += 1
        slot = (int(time.time()) - L1_GENESIS_TIME) // 30 + self.slot_offset
        out = json.loads(self.produce('extend', '--target', self.canonical, '--parent', parent, '--anchor', 'ab' * 32,
                                      '--timestamp-rule', f'1:{L1_GENESIS_TIME}:30000', '--anchor-slot', slot, *RULES, *extra))
        self.blocks.append(out)
        return out

    def deposit(self):
        path = self.work / 'deposits.json'
        path.write_text(json.dumps([{'height': 1, 'tx_index': 0, 'txid': '0x' + '01' * 32, 'vout': 0, 'sats': 5_000_000_000_000,
                                     'recipient': self.address}]))
        return self.extend('--deposits', path)

    def sign(self, recipient, sats):
        path = self.work / f'tx-{self.nonce}.hex'
        self.produce('sign-tx', '--key', self.key, '--nonce', self.nonce, '--withdraw-to', recipient, '--sats', sats, '--out', path, *RULES)
        self.nonce += 1
        return path.read_text().strip()

    def transfer(self):
        path = self.work / f'tx-{self.nonce}.hex'
        self.produce('sign-tx', '--key', self.key, '--nonce', self.nonce, '--to', '0x' + '77' * 20, '--value-wei', 1, '--out', path, *RULES)
        self.nonce += 1
        return path.read_text().strip()

    def block_with(self, transactions):
        pool = self.work / 'pool.json'
        pool.write_text(json.dumps(transactions))
        out = self.extend('--txs', pool)
        return out

    def entry(self, block):
        return {'l2_number': block['number'], 'l2_hash': block['hash'], 'l2_state_root': block.get('state_root', ''),
                'withdrawals': {'root': block['withdrawal_root'], 'count': block['withdrawal_count']},
                'native_slot': 300000 + block['number'], 'native_block': 'cd' * 32, 'commitment': 'ef' * 32}

    def write_status(self, finalized, mutate=None):
        status = dict(self.base_status)
        status['finalized_settlements'] = [self.entry(b) for b in self.blocks[:finalized]]
        if mutate:
            mutate(status)
        if self.args.status_schema == 'v3':
            entries = status.pop('finalized_settlements')
            lines = [json.dumps(e, separators=(',', ':')).encode() + b'\n' for e in entries]
            name = self.status.stem + '.settlements.jsonl'
            self.status.with_name(name).write_bytes(b''.join(lines))
            status.update(schema='bloch.l2.native-follower-status.v3', finalized_settlements_count=len(lines),
                          finalized_settlements_recent=entries[-64:],
                          settlement_log={'file': name, 'entries': len(lines), 'bytes': sum(map(len, lines)),
                                          'digest': attestor_lib.settlement_log_digest(lines).hex()})
        temporary = self.status.with_suffix('.tmp')
        temporary.write_text(json.dumps(status))
        temporary.replace(self.status)

    def start_rpc(self):
        view = self.work / f'view-{time.time_ns()}'
        log = open(self.work / 'rpc.log', 'a')
        self.rpc_process = subprocess.Popen(
            [self.args.rpc, '--data-dir', self.canonical, '--view-dir', view, '--finality-status', self.status, '--network', NETWORK,
             '--port', str(self.rpc_port), '--poll-ms', '200', *RULES], stdout=log, stderr=log)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.rpc_process.poll() is not None:
                raise SystemExit(f'the settled RPC exited; see {self.work}/rpc.log')
            try:
                call(self.url, 'eth_chainId')
                return
            except OSError:
                time.sleep(0.2)
        raise SystemExit('the settled RPC did not start')

    def stop_rpc(self):
        if self.rpc_process:
            self.rpc_process.send_signal(signal.SIGINT)
            self.rpc_process.wait(timeout=30)
            self.rpc_process = None

    def wait_head(self, number):
        wait_for(lambda: int(call(self.url, 'eth_blockNumber')['result'], 16) >= number, f'head {number}')

    def wait_finalized(self, count_at_least_block):
        """Wait until the RPC's own finality level reached the block; the index follows in the same tick."""
        wait_for(lambda: (call(self.url, 'bloch_finality').get('result') or {}).get('finalized_height', -1) >= count_at_least_block,
                 f'finalized {count_at_least_block}')
        time.sleep(1)


def wait_for(condition, what, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise SystemExit(f'timeout waiting for {what}')


def call(url, method, params=()):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def error_code(answer):
    return (answer.get('error') or {}).get('code')


class Mock(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['content-length'])))
        body = json.dumps(self.server.answer(request)).encode()
        self.send_response(200)
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def mock(port, answer):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Mock)
    server.answer = answer
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class L1:
    """getl2settlement in the live shape; only the withdrawal records are scripted."""

    def __init__(self):
        self.view = {'network': NETWORK, 'genesis': GENESIS, 'chain_id': 700770, 'asynchronous': True, 'withdrawals': {
            'roots': [], 'claimable': None, 'claimable_large': None, 'matured': None, 'large_claim_sat': '10000000000',
            'attested_claim_sat': '10000000000', 'attestor_set': '1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b',
            'delay_blocks': 64, 'finalized_checkpoint': {'epoch': 1, 'root': 'aa' * 32, 'own_root': None, 'own_chain_rule_active': False},
            'claimed': {'count': 0, 'floor': 0, 'words': []}, 'release_window': {'remaining_sat': '1000000000'}}}

    def answer(self, request):
        return {'jsonrpc': '2.0', 'id': request['id'], 'result': self.view}

    def set(self, blocks, finalized=True, claimable=None):
        records = [{'l2_number': b['number'], 'root': b['withdrawal_root'], 'count': b['withdrawal_count'], 'height': 1000 + b['number'],
                    'finalized': finalized} for b in blocks]
        self.view['withdrawals']['roots'] = records
        self.view['withdrawals']['claimable'] = records[claimable] if claimable is not None else None


def tool(*argv):
    done = subprocess.run([sys.executable, '-I', str(TOOL), *map(str, argv)], capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    parser = argparse.ArgumentParser()
    for name in ('--work', '--rpc', '--produce', '--canonical', '--status', '--bloch-pos', '--genesis'):
        parser.add_argument(name, required=True)
    parser.add_argument('--live-l1')
    parser.add_argument('--port-base', type=int, default=19761)
    parser.add_argument('--status-schema', choices=('v2', 'v3'), default='v2')
    args = parser.parse_args()

    rig = Rig(args)
    atexit.register(rig.stop_rpc)
    rig.setup()
    rig.start_rpc()
    l1 = L1()
    l1_url = f'http://127.0.0.1:{args.port_base + 1}'
    mock(args.port_base + 1, l1.answer)
    out = lambda name: rig.work / name
    fetch = lambda index, name, l2=rig.url, *extra: tool('fetch', '--l2-rpc', l2, '--l1-rpc', l1_url, '--index', index, '--recipient', ME, '--out', out(name), *extra)

    print('SYNTHETIC FINALITY, MOCK L1 (see the module docstring)', flush=True)
    code, text = tool('burn', '--recipient', ME, '--sats', 1_000_000)
    check('burn prints the outbox call', code == 0 and '0xb769844a' + ME in text and '10000000000000000' in text, text)

    # Nothing finalized, nothing burned yet.
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0])
    check('no withdrawal yet: unknown index', error_code(answer) == -32042, answer)

    deposit = rig.deposit()  # block 1
    w0 = rig.block_with([rig.sign(ME, 2_000_000), rig.sign(OTHER, 3_000_000)])  # block 2: withdrawals 0, 1
    plain = rig.block_with([rig.transfer()])  # block 3: no withdrawal
    w2 = rig.block_with([rig.sign(ME, 4_000_000)])  # block 4: withdrawal 2
    w3 = rig.block_with([rig.sign(ME, 5_000_000)])  # block 5: withdrawal 3, stays unfinalized
    check('producer wrote the withdrawals', [w0['withdrawal_count'], plain['withdrawal_count'], w2['withdrawal_count'], w3['withdrawal_count']] == [2, 2, 3, 4],
          rig.blocks)
    rig.wait_head(5)

    answer = call(rig.url, 'bloch_getWithdrawalProof', [0])
    check('no finalized settlement: not finalized', error_code(answer) == -32041, answer)
    code, text = fetch(0, 'none.json')
    check('client: not finalized is NOT READY (exit 3), no file', code == 3 and not out('none.json').exists(), text)

    # Finalize blocks 1-2 only (status file written by this script).
    rig.write_status(2)
    rig.wait_finalized(2)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0])
    doc = answer.get('result') or {}
    check('finalized withdrawal served', doc.get('finalized') is True and doc.get('withdrawal_count') == 2 and doc.get('number') == 2, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [2])
    check('withdrawal in unfinalized block 4: not finalized', error_code(answer) == -32041, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [3])
    check('withdrawal in unfinalized block 5: not finalized', error_code(answer) == -32041, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [4])
    check('unknown index', error_code(answer) == -32042, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', ['0xffffffffffffffff'])
    check('absurd index', error_code(answer) == -32042, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0, w3['withdrawal_root']])
    check('root of an unfinalized block is refused', error_code(answer) == -32043, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', ['bad'])
    check('malformed index', error_code(answer) == -32602, answer)
    code, text = fetch(2, 'unfin.json')
    check('client: unfinalized index exit 3', code == 3 and 'not finalized' in text, text)
    code, text = fetch(9, 'unknown.json')
    check('client: unknown index exit 3 and named', code == 3 and 'does not know' in text, text)

    # Same document as the local database tool, field for field.
    reference = json.loads(rig.produce('withdrawal-proof', '--target', rig.canonical, '--index', 1, '--number', 2,
                                       '--root', w0['withdrawal_root'], '--count', 2, *RULES))
    served = call(rig.url, 'bloch_getWithdrawalProof', [1])['result']
    same = all(served[key] == reference[key] for key in reference)
    check('RPC document equals produce-dev withdrawal-proof', same, (served, reference))

    # The L1 anchor decides.
    code, text = fetch(0, 'early.json')
    check('client: finalized on L2 but not claimable on L1 is exit 3', code == 3 and 'claimable' in text, text)
    l1.set([w0], finalized=False, claimable=0)
    code, text = fetch(0, 'l1unfinal.json')
    check('client: L1 record not finalized is exit 3', code == 3 and not out('l1unfinal.json').exists(), text)
    l1.set([w0], claimable=0)
    code, text = fetch(0, 'p0.json')
    check('client: burn to verified proof, exit 0', code == 0 and 'VERIFIED' in text and out('p0.json').exists(), text)
    code, text = tool('fetch', '--l2-rpc', rig.url, '--l1-rpc', l1_url, '--index', 1, '--recipient', ME, '--out', out('other.json'))
    check('client: another owner\'s withdrawal is refused', code == 1 and 'pays' in text, text)
    code, text = tool('fetch', '--l2-rpc', rig.url, '--l1-rpc', l1_url, '--index', 1, '--any-recipient', '--out', out('relay.json'))
    check('client: a relayer may fetch it', code == 0, text)

    # Native parser and builder, unchanged 78d4921c binary.
    done = subprocess.run([args.bloch_pos, 'ws-keygen', '--out', str(out('funding'))], capture_output=True, text=True)
    pubkey = out('funding.pk')
    check('throwaway funding key generated', done.returncode == 0 and pubkey.exists(), done.stdout + done.stderr)
    prepare = lambda proof, result: subprocess.run(
        [args.bloch_pos, 'l2-claim', 'prepare', '--genesis', args.genesis, '--funding-pubkey', str(pubkey), '--input', f'{"ab" * 32}:0:100000000',
         '--proof', str(proof), '--base-fee', '1000', '--tip', '0', '--out', str(result)], capture_output=True, text=True)
    done = prepare(out('p0.json'), out('claim.hex'))
    check('native l2-claim prepare accepts the proof file', done.returncode == 0 and out('claim.hex').exists(), done.stderr)
    done = subprocess.run([args.bloch_pos, 'l2-claim', 'inspect', '--tx', str(out('claim.hex'))], capture_output=True, text=True)
    check('native l2-claim inspect shows the claim', done.returncode == 0 and ME in done.stdout + done.stderr, done.stdout + done.stderr)

    # A lying L2 RPC: real answers from the real RPC, altered on the way.
    tamper = {'fn': None}

    def proxy(request):
        with urllib.request.urlopen(urllib.request.Request(rig.url, data=json.dumps(request).encode(), headers={'content-type': 'application/json'}), timeout=30) as response:
            answer = json.loads(response.read())
        if tamper['fn'] and answer.get('result'):
            tamper['fn'](answer['result'])
        return answer

    mock(args.port_base + 2, proxy)
    liar = f'http://127.0.0.1:{args.port_base + 2}'
    flip = lambda text: ('0' if text[0] != '0' else '1') + text[1:]
    forgeries = {
        'sibling': lambda d: d['siblings'].__setitem__(3, flip(d['siblings'][3])),
        'root': lambda d: d.__setitem__('withdrawal_root', flip(d['withdrawal_root'])),
        'leaf': lambda d: d['withdrawal'].__setitem__('leaf', flip(d['withdrawal']['leaf'])),
        'sats': lambda d: d['withdrawal'].__setitem__('sats', d['withdrawal']['sats'] * 1000),
        'recipient': lambda d: d['withdrawal'].__setitem__('l1_recipient', ME if d['withdrawal']['l1_recipient'] != ME else OTHER),
        'index': lambda d: d.__setitem__('index', d['index'] + 1),
        'siblings cut': lambda d: d['siblings'].pop(),
        'chain': lambda d: d.__setitem__('chain_id', 700771),
    }
    for name, change in forgeries.items():
        tamper['fn'] = change
        path = out(f'forged-{name.replace(" ", "-")}.json')
        code, text = tool('fetch', '--l2-rpc', liar, '--l1-rpc', l1_url, '--index', 0, '--recipient', ME, '--out', path)
        check(f'tampered {name}: client refuses, no file', code == 1 and not path.exists(), text)
    tamper['fn'] = None
    code, text = fetch(0, 'via-proxy.json', liar)
    check('the honest proxy passes (the tampering is what was refused)', code == 0, text)

    # A tampered proof handed to the native tool directly: its own parser refuses too.
    doc = json.loads(out('p0.json').read_text())
    doc['siblings'][0] = flip(doc['siblings'][0])
    out('tampered.json').write_text(json.dumps(doc))
    done = prepare(out('tampered.json'), out('tampered.hex'))
    check('native prepare refuses the tampered file', done.returncode != 0 and not out('tampered.hex').exists(), done.stderr)
    code, text = tool('verify', '--proof', out('tampered.json'))
    check('client verify refuses the tampered file', code == 1, text)
    code, text = tool('verify', '--proof', out('p0.json'), '--l1-rpc', l1_url)
    check('client verify re-anchors the good file', code == 0 and 'VERIFIED' in text, text)

    # The finalized level moves; older roots stay served, and the client proves against the matured one.
    rig.write_status(5)
    rig.wait_finalized(5)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [3])
    check('newly finalized withdrawal served', (answer.get('result') or {}).get('withdrawal_count') == 4, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0])
    check('default root is the newest finalized', answer['result']['withdrawal_root'] == w3['withdrawal_root'], answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0, '0x' + w0['withdrawal_root']])
    check('older finalized root is served', answer['result']['withdrawal_count'] == 2 and answer['result']['withdrawal_root'] == w0['withdrawal_root'], answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [3, w0['withdrawal_root']])
    check('withdrawal newer than the requested root', error_code(answer) == -32044, answer)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0, plain['withdrawal_root']])
    check('a block that added nothing keeps its parent\'s root', answer['result']['number'] == 2, answer)
    l1.set([w0, w2, w3], claimable=1)
    code, text = fetch(0, 'matured.json')
    written = json.loads(out('matured.json').read_text()) if code == 0 else {}
    check('client proves against the matured root, not the newest', written.get('withdrawal_root') == w2['withdrawal_root'] and written.get('withdrawal_count') == 3, text)
    done = prepare(out('matured.json'), out('matured.hex'))
    check('native prepare accepts the older-root proof', done.returncode == 0, done.stderr)
    code, text = fetch(3, 'not-matured.json')
    check('client: finalized on L2, older than the matured root: exit 3', code == 3, text)
    l1.view['withdrawals']['claimed'] = {'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '01' + '00' * 31}]}
    code, text = fetch(0, 'claimed.json')
    check('client: already claimed is exit 4', code == 4, text)
    l1.view['withdrawals']['claimed'] = {'count': 0, 'floor': 0, 'words': []}

    # Index rebuilt from finalized blocks after a restart, and the receipts of a settlement that lies freeze it.
    rig.stop_rpc()
    rig.start_rpc()
    rig.wait_finalized(5)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [2])
    check('restart: the index is rebuilt', (answer.get('result') or {}).get('withdrawal_count') == 4, answer)
    rig.stop_rpc()

    def wrong_root(status):
        status['finalized_settlements'][1]['withdrawals']['root'] = 'ee' * 32

    rig.write_status(5, wrong_root)
    rig.start_rpc()
    rig.wait_finalized(5)
    answer = call(rig.url, 'bloch_getWithdrawalProof', [0])
    check('a settled root that disagrees with the receipts freezes the method', error_code(answer) == -32046, answer)
    answer = call(rig.url, 'eth_blockNumber')
    check('the rest of the RPC keeps serving', 'result' in answer, answer)
    log = (rig.work / 'rpc.log').read_text()
    check('the freeze is logged', 'withdrawal proofs FROZEN' in log, log[-500:])
    code, text = fetch(0, 'frozen.json')
    check('client: frozen RPC is refused', code == 1, text)
    rig.stop_rpc()
    rig.write_status(5)

    # The read path: one million lookups are not the point, a batch at the gateway's cap is.
    rig.start_rpc()
    rig.wait_finalized(5)
    started = time.time()
    for _ in range(200):
        call(rig.url, 'bloch_getWithdrawalProof', [0])
    print(f'INFO 200 sequential proofs in {time.time() - started:.3f} s', flush=True)
    if args.live_l1:
        l1_live = args.live_l1
        code, text = tool('fetch', '--l2-rpc', rig.url, '--l1-rpc', l1_live, '--index', 0, '--recipient', ME, '--out', out('live.json'))
        check('live public L1 (read-only): the private proof is not anchored', code in (1, 3) and not out('live.json').exists(), text)
        print(f'INFO live L1 said: {text.strip()[:200]}', flush=True)
    if os.environ.get('HOLD'):
        print(f'HOLD: RPC stays up on {rig.url}; touch {rig.work}/release to continue', flush=True)
        wait_for(lambda: (rig.work / 'release').exists(), 'release', int(os.environ['HOLD']))
    rig.stop_rpc()
    print(f'{sum(results)}/{len(results)} passed', flush=True)
    return 0 if all(results) else 1


if __name__ == '__main__':
    sys.exit(main())
