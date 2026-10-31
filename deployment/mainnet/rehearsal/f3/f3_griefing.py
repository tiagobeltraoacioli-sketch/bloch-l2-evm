#!/usr/bin/env python3
"""Private flag-day rehearsal of security finding F3: a real third party settles rule-conforming L2 blocks.

Real settlement: 4 validators on loopback, the L2 installed at epoch 4 of a running private L1 (so chain height and
L2 height differ), the pinned mainnet guest, real Groth16 proofs under the host's PROVING.lock, real DA transactions.
The griefer is a second settler_v3 process image with its own database, follower store, spool, L2 account and DA key.

One rehearsal-only device: the sequencer's prover wrapper waits while `run/hold-settler` exists. It stands in for a
griefer with a faster prover, so the order of events is reproducible. It does not alter any settler code path.

Ports 24201-24230 on loopback. Throwaway keys only. Verdict: results/VERDICT.json, then results/DONE.
  f3_griefing.py setup | campaign | stop
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request

R = Path(os.environ.get('F3_ROOT', str(Path.home() / 'l2dexbridge-20261030/l2-f3-r3')))
SHARED = Path.home() / 'l2dexbridge-20261030'
BIN, RUN, RES = R / 'bin', R / 'run', R / 'results'
POS, PRODUCE, ELF = BIN / 'bloch-pos', BIN / 'bloch-l2-produce-dev', BIN / 'settlement_v3_mainnet'
PROVER, LOCKED, GATED = (BIN / n for n in ('bloch-evm-sp1-settlement-v3', 'bloch-evm-sp1-settlement-v3-locked',
                                           'bloch-evm-sp1-settlement-v3-gated'))
SETTLER = Path(os.environ.get('F3_SETTLER', str(R / 'src/settler_v3.py')))
N = 4
RPC = [24201 + i for i in range(N)]
P2P = [24211 + i for i in range(N)]
L2_RPC = 24220
SLOT_MS = 2000
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L2_GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
L2_GENESIS_STATE = '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'
NET_ARGS = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
GNARK = 'ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d'
PASS = RUN / 'keystore.passphrase'
HOLD = RUN / 'hold-settler'
WAITING = RUN / 'gate-waiting'
START = time.time()


def ev(event, **fields):
    line = json.dumps({'t': round(time.time() - START, 1), 'time': time.strftime('%H:%M:%SZ', time.gmtime()), 'event': event, **fields})
    print(line, flush=True)
    with (RES / 'timeline.jsonl').open('a') as f:
        f.write(line + '\n')


def env(**extra):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(R / 'home'), 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(PASS), **extra}


def run(argv):
    done = subprocess.run([str(a) for a in argv], env=env(), capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f'{Path(str(argv[0])).name} {argv[1:3]} refused: {done.stderr.strip()[-1500:]}')
    return done.stdout


def produce(*args):
    return json.loads(run([PRODUCE, *args, *NET_ARGS]))


def rpc(method, params=(), port=RPC[0]):
    req = urllib.request.Request(f'http://127.0.0.1:{port}', headers={'Content-Type': 'application/json'},
                                 data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode())
    with urllib.request.urlopen(req, timeout=15) as r:
        body = json.loads(r.read())
    if 'error' in body:
        raise RuntimeError(f'{method}: {body["error"]}')
    return body['result']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def spawn(name, argv, extra=None):
    logf = (RUN / f'{name}.log').open('a')
    p = subprocess.Popen([str(a) for a in argv], env=env(**(extra or {})), stdout=logf, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True, cwd=RUN)
    (RUN / f'{name}.pid').write_text(f'{p.pid}\n')
    return p


def keystore(directory, index):
    directory.mkdir(mode=0o700)
    run([POS, 'keygen', '--dir', directory, '--index', index])
    return bytes.fromhex(run([POS, 'keygen-public', '--dir', directory]).split('\t')[1].strip())


def setup():
    """Binaries from the F2 build (agent 28) and the fixed settled RPC (agent 35); wrappers around the pinned prover."""
    SEC, DRL = SHARED / 'l2-security', SHARED / 'l2-drills'
    BIN.mkdir(parents=True, exist_ok=True)
    (BIN / 'shim').mkdir(exist_ok=True)
    (R / 'home/tmp').mkdir(parents=True, exist_ok=True)
    RES.mkdir(exist_ok=True)
    for source in (SEC / 'out-pos/bloch-pos', SEC / 'out-post/reh/bloch-l2-produce-dev', SEC / 'out-post/reh/bloch-l2-native-follower',
                   SEC / 'bin/bloch-evm-sp1-settlement-v3', SEC / 'bin/settlement_v3_mainnet', SEC / 'bin/gnark-cli',
                   DRL / 'out/identity.json'):
        shutil.copy2(source, BIN / source.name)
    shutil.copy2(DRL / 'out/bloch-l2-settled-rpc-fixed', BIN / 'bloch-l2-settled-rpc')
    if not (R / 'home/.sp1').exists():
        subprocess.run(['cp', '-al', str(DRL / 'home/.sp1'), str(R / 'home/.sp1')], check=True)
    (BIN / 'shim/docker').write_text((SEC / 'bin/shim/docker').read_text().replace(str(SEC / 'bin'), str(BIN)))
    (BIN / 'shim/docker').chmod(0o755)
    LOCKED.write_text(f"""#!/bin/bash
REAL={PROVER}
case " $* " in *" prove-groth16 "*) ;; *) exec "$REAL" "$@";; esac
export XDG_RUNTIME_DIR=/run/user/$(id -u)
exec /usr/bin/flock {SHARED}/PROVING.lock /usr/bin/systemd-run --user --scope -q -p MemoryMax=64G -p MemorySwapMax=0 /usr/bin/nice -n 10 "$REAL" "$@"
""")
    LOCKED.chmod(0o755)
    GATED.write_text(f"""#!/bin/bash
case " $* " in *" prove-groth16 "*) ;; *) exec {LOCKED} "$@";; esac
echo "$BLOCH_NATIVE_L2_ARTIFACT" > {WAITING}
while [ -e {HOLD} ]; do sleep 1; done
rm -f {WAITING}
exec {LOCKED} "$@"
""")
    GATED.chmod(0o755)
    print(subprocess.run(f'sha256sum {BIN}/* {SETTLER}', shell=True, capture_output=True, text=True).stdout)


def net():
    RUN.mkdir(mode=0o700)
    PASS.write_text(os.urandom(32).hex() + '\n')
    PASS.chmod(0o600)
    keys = [RUN / f'key{i}' for i in range(N)]
    for i, k in enumerate(keys):
        keystore(k, i)
    scripts = {}
    for name in ('wallet', 'da', 'gda'):
        pk = keystore(RUN / name, 0)
        (RUN / f'{name}.pubkey.hex').write_text(pk.hex() + '\n')
        scripts[name] = hashlib.sha3_256(pk).hexdigest()
    genesis_secs = int(time.time()) + 40
    run([POS, 'genesis', '--keys', ','.join(map(str, keys)), '--out', RUN / 'genesis.blg', '--slot-ms', SLOT_MS,
         '--start-in', 40, '--bind-genesis', '--alloc', f"{scripts['wallet']}:{1_000 * 10**8}",
         '--alloc', f"{scripts['da']}:{100 * 10**8}", '--alloc', f"{scripts['gda']}:{100 * 10**8}"])
    domain = hashlib.sha3_256((RUN / 'genesis.blg').read_bytes()).hexdigest()
    for i in range(N):
        data = RUN / f'node{i}'
        data.mkdir(mode=0o700)
        shutil.copy2(keys[i] / 'validator.key', data / 'validator.key')
        peers = ','.join(f'127.0.0.1:{P2P[j]}' for j in range(N) if j != i)
        spawn(f'node{i}', [POS, 'run', '--data-dir', data, '--genesis', RUN / 'genesis.blg', '--transport', 'devnet',
                           '--listen', P2P[i], '--listen-addr', '127.0.0.1', '--peers', peers,
                           '--rpc-bind', '127.0.0.1', '--rpc-port', RPC[i]])
        time.sleep(1)
    return {'domain': domain, 'genesis_secs': genesis_secs, 'scripts': scripts}


def l2_config():
    identity = json.loads((BIN / 'identity.json').read_text())
    cfg = b''.join(bytes.fromhex(identity[k]) for k in ('domain', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'))
    cfg += bytes.fromhex(identity['proof_policy_v3']) + (700770).to_bytes(8, 'little') + bytes.fromhex(L2_GENESIS) + bytes.fromhex(L2_GENESIS_STATE)
    assert len(cfg) == 264
    (RUN / 'l2-config.bin').write_bytes(cfg)


def settler_config(net_info, name, prover, follower, da_key, ports):
    db, work, pool = RUN / f'{name}-db', RUN / f'{name}-work', RUN / f'{name}-txpool'
    produce('init', '--target', db)
    work.mkdir()
    pool.mkdir()
    return {
        'network': net_info['domain'], 'network_kind': 'mainnet-rehearsal', 'chain_id': 700770, 'network_args': NET_ARGS,
        'l2_genesis': L2_GENESIS, 'rpc_ports': ports, 'produce': str(PRODUCE), 'l2_db': str(db), 'workdir': str(work),
        'home': str(R / 'home'), 'prover_path': f'{BIN}/shim:/usr/bin:/bin', 'prover': str(prover), 'prover_sha256': sha(prover),
        'guest': str(ELF), 'guest_sha256': sha(ELF), 'l2_config': str(RUN / 'l2-config.bin'),
        'l2_config_sha256': sha(RUN / 'l2-config.bin'), 'gnark_image': GNARK, 'prover_threads': 24,
        'timestamp_rule': f"1:{net_info['genesis_secs']}:{SLOT_MS}", 'acceptance_timeout_seconds': 900, 'idle_seconds': 10,
        'max_consecutive_failures': 100, 'user_transactions': True, 'txpool_dir': str(pool),
        'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 256,
        'da': {'signer': str(POS), 'signer_sha256': sha(POS), 'genesis': str(RUN / 'genesis.blg'),
               'funding_pubkey': str(RUN / f'{da_key}.pubkey.hex'), 'keystore_dir': str(RUN / da_key),
               'passphrase_file': str(PASS), 'tip_millisat_per_gas': 0, 'inclusion_timeout_seconds': 300},
        'foreign_recovery': {'follower_state': str(RUN / follower), 'follower_status': str(RUN / f'{follower}-status.json')},
    }


def follower(net_info, name, port):
    spawn(name, [BIN / 'bloch-l2-native-follower', '--manifest', RUN / 'genesis.blg', '--network-pin', net_info['domain'],
                 '--rpc-port', port, '--state', RUN / name, '--status', RUN / f'{name}-status.json', '--poll-seconds', 5])


def start_rpc(net_info):
    shutil.rmtree(RUN / 'rpc-view', ignore_errors=True)
    return spawn('rpc', [BIN / 'bloch-l2-settled-rpc', '--data-dir', RUN / 'seq-db', '--view-dir', RUN / 'rpc-view',
                         '--finality-status', RUN / 'followerA-status.json', '--network', net_info['domain'],
                         '--port', L2_RPC, '--poll-ms', 2000, *NET_ARGS, '--txpool', RUN / 'seq-txpool'])


class RpcKeeper(threading.Thread):
    """What the production systemd path unit does: restart the settled RPC when l2-db-generation.json changes."""

    def __init__(self, net_info):
        super().__init__(daemon=True)
        self.net_info, self.proc, self.seen, self.restarts = net_info, start_rpc(net_info), None, 0

    def run(self):
        path = RUN / 'l2-db-generation.json'
        while True:
            time.sleep(1)
            text = path.read_text() if path.exists() else None
            if text != self.seen:
                self.seen = text
                if text is not None:
                    self.proc.terminate()
                    self.proc.wait(30)
                    self.proc = start_rpc(self.net_info)
                    self.restarts += 1
                    ev('rpc-restarted-after-rebuild', generation=json.loads(text))


def load_settler():
    spec = importlib.util.spec_from_file_location('settler_v3', SETTLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def settler_events(name='settler'):
    out = []
    path = RUN / f'{name}.log'
    if path.exists():
        for line in path.read_text(errors='replace').splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def wait_for(what, check, timeout=5400, every=2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = check()
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            result, last = None, error
        if result:
            return result
        time.sleep(every)
    raise TimeoutError(f'timeout waiting for {what}')


def accepted_fields(S, port=RPC[0]):
    v = rpc('getl2settlement', port=port)
    return S.statement_fields(v['accepted']['statement']) if v.get('accepted') else None


class Griefer:
    """A real, independent settler: its own database rebuilt from its own follower store, one L2 transaction of its
    own per block (so the block differs from the sequencer's) and its own DA payment."""

    def __init__(self, S, config):
        self.S = S

        class Instance(S.Settler):
            gate, won = None, None

            def submit_and_wait(inner, number, directory, tx, view):
                if inner.gate:
                    inner.gate(number)
                return super().submit_and_wait(number, directory, tx, view)

            def record_accepted(inner, number, directory, accepted):
                inner.won = {'number': number, 'hash': S.statement_fields(accepted['statement'])['l2_hash'],
                             'directory': str(directory)}
                return super().record_accepted(number, directory, accepted)

        self.g, self.config = Instance(config), config

    def sign(self):
        db, pool = self.config['l2_db'], Path(self.config['txpool_dir'])
        account = produce('account', '--target', db, '--address', self.address)
        staged = pool / f'grief-{time.time_ns()}.tx'
        produce('sign-tx', '--key', RUN / 'griefer.l2.key', '--nonce', account['nonce'], '--to', '00' * 19 + '66',
                '--value-wei', '1000000000000', '--out', staged)
        return account['nonce']

    def block(self, gate=None):
        """Settle one foreign block; returns what it cost."""
        S, g = self.S, self.g
        g.gate, g.won = gate, None
        started = time.time()
        while True:
            view = g.native_view()
            if view is None or view.get('source') is None:
                time.sleep(5)
                continue
            accepted = view.get('accepted')
            fields = S.statement_fields(accepted['statement']) if accepted else {'l2_number': 0, 'l2_hash': L2_GENESIS}
            head = g.produce('head', '--target', g.c['l2_db'])
            current = head['number'] >= fields['l2_number'] and g.local_hash(fields['l2_number']) == fields['l2_hash'] \
                and head['number'] <= fields['l2_number'] + 1
            if not current:
                g.recover_foreign('griefer catching up')
                time.sleep(5)
                continue
            if head['number'] == fields['l2_number'] and not list(Path(g.c['txpool_dir']).iterdir()):
                self.sign()
            g.cycle()
            if g.won:
                statement = bytes.fromhex(rpc('getl2settlement')['accepted']['statement'])
                users = int.from_bytes(statement[S.T + S.USER_TX_COUNT:S.T + S.USER_TX_COUNT + 8], 'big')
                proved = json.loads((Path(g.won['directory']) / 'proved.json').read_text())
                return {**g.won, 'user_tx_count': users, 'seconds': round(time.time() - started, 1),
                        'proof_steps': proved['steps'], 'l1_height': rpc('getchaininfo')['height']}
            time.sleep(2)


def wallet_input(script):
    u = max(rpc('getutxos', [script, 64]).get('utxos', []), key=lambda u: int(u['value_sat']))
    return f"{u['txid']}:{u['vout']}:{u['value_sat']}"


def script_balance(script):
    return sum(int(u['value_sat']) for u in rpc('getutxos', [script, 64]).get('utxos', []))


def deposit(net_info, sats, recipient):
    stamp = time.time_ns()
    unsigned, signed = RUN / f'deposit-{stamp}-unsigned.hex', RUN / f'deposit-{stamp}.hex'
    run([POS, 'l2-deposit', 'prepare', '--genesis', RUN / 'genesis.blg', '--funding-pubkey', RUN / 'wallet.pubkey.hex',
         '--input', wallet_input(net_info['scripts']['wallet']), '--amount', sats, '--recipient', recipient,
         '--base-fee', str(rpc('getchaininfo')['next_base_fee_millisat_per_gas']), '--tip', '0', '--out', unsigned])
    run([POS, 'l2-deposit', 'sign', '--genesis', RUN / 'genesis.blg', '--tx', unsigned, '--dir', RUN / 'wallet', '--out', signed])
    before = rpc('getl2settlement')['inbox']['count']
    result = rpc('sendrawtransaction', [signed.read_text().strip()])
    wait_for('deposit in the inbox', lambda: rpc('getl2settlement')['inbox']['count'] > before, timeout=300)
    ev('deposit', sats=sats, recipient=recipient, tx=result.get('tx_hash'), inbox=rpc('getl2settlement')['inbox'])


def user_tx(address):
    nonce = int(wait_for('the settled RPC', lambda: rpc('eth_getTransactionCount', ['0x' + address, 'pending'], port=L2_RPC), timeout=120), 16)
    staged = RUN / f'user-{time.time_ns()}.tx'
    produce('sign-tx', '--key', RUN / 'user.l2.key', '--nonce', nonce, '--to', '00' * 19 + '55', '--value-wei', '1000000000000', '--out', staged)
    raw = staged.read_text().strip()
    raw = raw if raw.startswith('0x') else '0x' + raw
    tx_hash = wait_for('the settled RPC', lambda: rpc('eth_sendRawTransaction', [raw], port=L2_RPC), timeout=120)
    ev('user-tx-sent', hash=tx_hash, nonce=nonce)
    return {'hash': tx_hash, 'sent': time.time()}


def receipt(tx):
    return wait_for('the settled RPC', lambda: [rpc('eth_getTransactionReceipt', [tx['hash']], port=L2_RPC)], timeout=120)[0]


def block_at_gate():
    """The sequencer's block now waiting at the gate: (number, block.json)."""
    if not WAITING.exists():
        return None
    directory = Path(WAITING.read_text().strip()).parent
    return int(directory.name.split('-')[0]), json.loads((directory / 'block.json').read_text())


def next_recovery(after):
    found = [e for e in settler_events() if e.get('event') == 'foreign-settlement-recovered']
    return found[after] if len(found) > after else None


def alive(settler_proc):
    if settler_proc.poll() is not None:
        raise SystemExit(f'the settler exited with code {settler_proc.returncode}: unaided recovery failed')


def hold_with_user_tx_at_gate(settler_proc, address, txs):
    """Bring the sequencer to the gate holding a block with a user transaction (real extra proofs if it was empty)."""
    while True:
        HOLD.touch()
        state = wait_for('the sequencer at the gate', lambda: alive(settler_proc) or block_at_gate(), every=3)
        if state[1].get('transactions'):
            return state
        ev('gate-block-is-empty-releasing', number=state[0])
        if not any(not receipt(t) for t in txs):
            txs.append(user_tx(address))
        HOLD.unlink()
        wait_for('the block through the gate', lambda: alive(settler_proc) or next(
            (e for e in reversed(settler_events()) if e.get('event') == 'accepted' and e['number'] == state[0]), None))


def compare_with_follower(S):
    """Fresh rebuild from follower B's verified store, against the sequencer's database, block by block."""
    target = RUN / 'compare-db'
    shutil.rmtree(target, ignore_errors=True)
    rule = json.loads((RUN / 'settler.json').read_text())['timestamp_rule']
    document = produce('reconstruct', '--target', target, '--l1-follower', RUN / 'followerB', '--timestamp-rule', rule)
    mismatches, compared = [], 0
    for b in document['blocks']:
        probe = RUN / f'.cmp-{b["number"]}'
        local = produce('export', '--target', RUN / 'seq-db', '--number', b['number'], '--out', probe)
        probe.unlink()
        compared += 1
        if local['hash'] != b['hash']:
            mismatches.append(b['number'])
    head = produce('head', '--target', target)
    seq_head = produce('head', '--target', RUN / 'seq-db')
    accounts = {}
    for name in ('user', 'griefer'):
        address = json.loads((RES / 'net.json').read_text())[f'{name}_address']
        accounts[name] = {'rebuilt': produce('account', '--target', target, '--address', address),
                          'sequencer': produce('account', '--target', RUN / 'seq-db', '--address', address)}
    return {'compared_blocks': compared, 'mismatches': mismatches, 'follower_head': head, 'sequencer_head': seq_head,
            'accounts': accounts, 'native_blocks': document['native_blocks'],
            'deposit_blocks': [(b['number'], b['deposits']) for b in document['blocks'] if b['deposits']],
            'user_tx_blocks': [(b['number'], b['transactions']) for b in document['blocks'] if b['transactions']]}


def campaign():
    S = load_settler()
    RES.mkdir(exist_ok=True)
    verdict = {'scenario': 'real settlement on a private flag-day net at e4; hold gate on the sequencer prover', 'griefs': []}
    try:
        info = net()
        l2_config()
        follower(info, 'followerA', RPC[1])
        follower(info, 'followerB', RPC[2])
        for name in ('user', 'griefer'):
            fd = os.open(RUN / f'{name}.l2.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, (os.urandom(32).hex() + '\n').encode())
            os.close(fd)
        addresses = {n: produce('address', '--key', RUN / f'{n}.l2.key')['address'] for n in ('user', 'griefer')}
        seq = settler_config(info, 'seq', GATED, 'followerA', 'da', RPC[:3])
        (RUN / 'settler.json').write_text(json.dumps(seq, indent=2) + '\n')
        griefer_cfg = settler_config(info, 'griefer', LOCKED, 'followerB', 'gda', RPC[:3])
        (RES / 'net.json').write_text(json.dumps({**info, 'user_address': addresses['user'], 'griefer_address': addresses['griefer']}, indent=1))
        wait_for('activation', lambda: (rpc('getl2settlement').get('native_height') or 0) >= 3, timeout=900, every=3)
        chain, l2 = rpc('getchaininfo'), rpc('getl2settlement')
        verdict['flag_day'] = {'chain_height': chain['height'], 'epoch': chain['epoch'], 'native_height': l2['native_height'],
                               'offset': chain['height'] - l2['native_height']}
        ev('activated', **verdict['flag_day'])
        keeper = RpcKeeper(info)
        keeper.start()
        deposit(info, 2_000_000_000, addresses['user'])
        deposit(info, 2_000_000_000, addresses['griefer'])
        settler_proc = spawn('settler', ['/usr/bin/python3', '-u', SETTLER], {'BLOCH_SETTLER_CONFIG': str(RUN / 'settler.json')})
        ev('settler-started', pid=settler_proc.pid)
        funded = lambda: int(rpc('eth_getBalance', ['0x' + addresses['griefer'], 'latest'], port=L2_RPC), 16) > 0  # noqa: E731
        wait_for('the deposits on L2', lambda: alive(settler_proc) or funded(), every=5)
        ev('deposits-on-l2', head=rpc('eth_blockNumber', port=L2_RPC))
        grief = Griefer(S, griefer_cfg)
        grief.address = addresses['griefer']
        txs = [user_tx(addresses['user'])]
        da = info['scripts']
        balances = {'seq_da_start': script_balance(da['da']), 'griefer_da_start': script_balance(da['gda'])}

        def record(label, result, began):
            recoveries = len([e for e in settler_events() if e.get('event') == 'foreign-settlement-recovered'])
            ev('foreign-accepted', label=label, **{k: result[k] for k in ('number', 'hash', 'user_tx_count', 'seconds', 'l1_height')})
            verdict['griefs'].append({'label': label, 'foreign': result, 'recoveries_before': recoveries, 'accepted_at': time.time() - START})
            return recoveries

        def recovered(entry, recoveries):
            found = wait_for('the sequencer recovery', lambda: alive(settler_proc) or next_recovery(recoveries), every=3)
            entry['recovery'] = found
            entry['recovered_after_foreign_s'] = round(time.time() - START - entry['accepted_at'], 1)
            ev('sequencer-recovered', label=entry['label'], **{k: found.get(k) for k in (
                'number', 'orphaned_blocks', 'respooled', 'wasted_proofs', 'wasted_da_signed', 'rebuild_seconds', 'native_blocks')})

        # G1: the foreign block lands while the sequencer is proving its own block (user transaction inside).
        state = hold_with_user_tx_at_gate(settler_proc, addresses['user'], txs)
        ev('g1-sequencer-at-gate', number=state[0], transactions=state[1]['transactions'])

        def g1_gate(number):
            HOLD.unlink(missing_ok=True)
            ev('g1-gate-released', number=number)
            time.sleep(30)  # the sequencer now takes the proof lock the griefer just released
        began = time.time()
        result = grief.block(g1_gate)
        HOLD.touch()
        recoveries = record('G1 foreign during the sequencer proof', result, began)
        recovered(verdict['griefs'][-1], recoveries)

        # A third deposit while under attack: the inbox numbering must survive the rebuilds.
        deposit(info, 1_500_000_000, addresses['user'])

        # G2, in a row: the foreign block lands right after the sequencer paid DA for its own block.
        state = hold_with_user_tx_at_gate(settler_proc, addresses['user'], txs)
        ev('g2-sequencer-at-gate', number=state[0], transactions=state[1]['transactions'])

        def g2_gate(number):
            HOLD.unlink(missing_ok=True)
            ev('g2-gate-released', number=number)
            wait_for('the sequencer DA payment', lambda: alive(settler_proc) or next(
                (e for e in settler_events() if e.get('event') == 'da-submitted' and e['number'] == number), None), every=0.3)
            ev('g2-sequencer-paid-da', number=number)
        began = time.time()
        result = grief.block(g2_gate)
        HOLD.touch()
        recoveries = record('G2 foreign right after the sequencer DA payment', result, began)
        recovered(verdict['griefs'][-1], recoveries)

        # G3, in a row: two foreign blocks back to back, the second before the sequencer recovered from the first.
        state = wait_for('the sequencer at the gate', lambda: alive(settler_proc) or block_at_gate(), every=3)
        ev('g3-sequencer-at-gate', number=state[0], transactions=state[1].get('transactions'))
        began = time.time()
        result = grief.block(None)
        recoveries = record('G3a first of two back to back', result, began)
        HOLD.unlink(missing_ok=True)
        began = time.time()
        result = grief.block(None)
        record('G3b second of two back to back', result, began)
        recovered(verdict['griefs'][-1], recoveries)
        balances['griefer_da_end'] = script_balance(da['gda'])
        verdict['griefer_proofs'] = len(verdict['griefs'])

        # The griefer stops. Every user transaction must now go through, unaided.
        HOLD.unlink(missing_ok=True)
        txs.append(user_tx(addresses['user']))
        for tx in txs:
            found = wait_for('a user transaction', lambda: alive(settler_proc) or receipt(tx), every=5)
            tx['latency_s'] = round(time.time() - tx['sent'], 1)
            tx['block'] = int(found['blockNumber'], 16)
            ev('user-tx-included', **tx)
        final_number = max(t['block'] for t in txs)
        wait_for('finality of the last user block', lambda: alive(settler_proc) or any(
            x['l2_number'] >= final_number for x in json.loads((RUN / 'followerB-status.json').read_text())['finalized_settlements']), every=5)
        accepted_before = accepted_fields(S)['l2_number']
        wait_for('one more sequencer settlement', lambda: alive(settler_proc) or accepted_fields(S)['l2_number'] > accepted_before, every=5)
        verdict['rpc_finality'] = wait_for('the RPC finality level', lambda: rpc('bloch_finality', port=L2_RPC), timeout=120)
        verdict['rpc_restarts'] = keeper.restarts
        balances['seq_da_end'] = script_balance(da['da'])
        os.killpg(settler_proc.pid, signal.SIGTERM)
        settler_proc.wait(60)

        last = accepted_fields(S)['l2_number']
        wait_for('followers at the last settlement', lambda: any(
            x['l2_number'] >= last for x in json.loads((RUN / 'followerB-status.json').read_text())['finalized_settlements']), timeout=900, every=5)
        verdict['comparison'] = compare_with_follower(S)
        verdict['l2_view'] = {k: rpc('getl2settlement').get(k) for k in ('native_height', 'inbox')}
        events = settler_events()
        da_events = [(e['number'], e['commitment']) for e in events if e.get('event') == 'da-submitted' and e.get('response') != 'duplicate']
        verdict['sequencer'] = {
            'halts': [e for e in events if e.get('event') == 'halt'],
            'accepted': [e['number'] for e in events if e.get('event') == 'accepted'],
            'proofs': [e['seconds'] for e in events if e.get('event') == 'proof-generated'],
            'da_submitted': da_events, 'da_paid_twice': len(da_events) != len(set(da_events)),
            'moved_after_proof': len([e for e in events if e.get('event') == 'request-moved-after-proof']),
            'waiting_finality': len([e for e in events if e.get('event') == 'foreign-settlement-waiting-finality'])}
        verdict['balances'] = balances
        verdict['user_txs'] = txs
        c = verdict['comparison']
        verdict['pass'] = bool(not verdict['sequencer']['halts'] and not c['mismatches'] and c['compared_blocks'] > 0
                               and not verdict['sequencer']['da_paid_twice'] and verdict['flag_day']['offset'] > 0
                               and sum(d for _, d in c['deposit_blocks']) >= 3 and all(g.get('recovery') for g in verdict['griefs'] if g['label'] != 'G3a first of two back to back')
                               and c['accounts']['user']['rebuilt'] == c['accounts']['user']['sequencer'])
    except BaseException as error:  # noqa: BLE001 - every outcome ends in a verdict file
        verdict['pass'] = False
        verdict['error'] = f'{type(error).__name__}: {error}'
    finally:
        (RES / 'VERDICT.json').write_text(json.dumps(verdict, indent=1, default=str) + '\n')
        stop()
        (RES / 'DONE').write_text('passed\n' if verdict.get('pass') else 'failed\n')


def stop():
    for pid in RUN.glob('*.pid'):
        try:
            os.killpg(int(pid.read_text()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass


if __name__ == '__main__':
    {'setup': setup, 'campaign': campaign, 'stop': stop}[sys.argv[1]]()
