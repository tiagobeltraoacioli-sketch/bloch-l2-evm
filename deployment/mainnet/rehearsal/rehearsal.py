#!/usr/bin/env python3
"""Private MAINNET-path L2 rehearsal on 45.77 (ubuntu, loopback ports 19301-19320, scratch only).

L1: 4 validators from a fresh genesis, bloch-pos dd287b6c (= release 78b7343a) built with
l2-activation-rehearsal-mainnet-policy at epoch 4: the boundary installs the approved MAINNET
policy (chain 700770, async, 3-of-5 attestor set hash 1c06adbb..., mainnet LIMITS, PROGRAM
identities 2..6, proof policy, L2 genesis 632e45ae...), only identities 0..1 are this network's.
L2: the pinned settlement_v3_mainnet ELF, producer/settler/follower/settled RPC with --rules mainnet.

  rehearsal.py net | l2init | follower | rpc | settler | l2key | deposit SATS | txs TO_WEI WITHDRAW_SATS
               | claim INDEX | status | stop
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

R = Path.home() / 'l2-mainnet-rehearsal-20261018'
OUT, RUN = R / 'out', R / 'run'
BIN = OUT / 'bloch-pos'
PRODUCE = OUT / 'bloch-l2-produce-dev'
PROVER = OUT / 'bloch-evm-sp1-settlement-v3'
GUARDED = OUT / 'bloch-evm-sp1-settlement-v3-guarded'  # memory guard around PROVER (45.77 is shared)
ELF = OUT / 'settlement_v3_mainnet'
N = 4
RPC = [19301 + i for i in range(N)]
P2P = [19311 + i for i in range(N)]
L2_RPC = 19320
SLOT_MS = 2000
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L2_GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
L2_GENESIS_STATE = '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'
NET_ARGS = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
PROGRAM = {  # l2_settlement::mainnet::PROGRAM identities 2..6 + proof policy
    'domain': DOMAIN,
    'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',
    'elf_keccak': '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',
    'vkey_koalabear': '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',
    'vkey_bn254': '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e',
    'proof_policy_v3': '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d',
}
GNARK = 'ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d'
PASS = RUN / 'keystore.passphrase'
STATE = RUN / 'state.json'


def log(event, **f):
    print(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event, **f}), flush=True)


def env(**extra):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(R / 'home'), 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(PASS), **extra}


def run(argv, **kw):
    done = subprocess.run([str(a) for a in argv], env=kw.pop('env', env()), capture_output=True, text=True, **kw)
    if done.returncode:
        raise SystemExit(f'{Path(str(argv[0])).name} {argv[1] if len(argv) > 1 else ""} refused:\n{done.stderr.strip()[-2000:]}')
    return done.stdout


def produce(*args):
    for _ in range(10):
        done = subprocess.run([str(PRODUCE), *map(str, args), *NET_ARGS], capture_output=True, text=True)
        if done.returncode == 0:
            return json.loads(done.stdout)
        time.sleep(3)
    raise SystemExit(f'produce {args[0]} refused: {done.stderr.strip()[:1500]}')


def rpc(method, params=(), port=RPC[0]):
    req = urllib.request.Request(f'http://127.0.0.1:{port}', headers={'Content-Type': 'application/json'},
                                 data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode())
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read())
    if 'error' in body:
        raise SystemExit(f'{method}: {body["error"]}')
    return body['result']


def state():
    return json.loads(STATE.read_text())


def save(**kw):
    s = state() if STATE.exists() else {}
    s.update(kw)
    STATE.write_text(json.dumps(s, indent=2) + '\n')


def spawn(name, argv, extra_env=None):
    logf = (RUN / f'{name}.log').open('a')
    p = subprocess.Popen([str(a) for a in argv], env=env(**(extra_env or {})), stdout=logf, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True, cwd=RUN)
    (RUN / f'{name}.pid').write_text(f'{p.pid}\n')
    log('spawned', name=name, pid=p.pid)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def keystore(directory, index):
    directory.mkdir(mode=0o700)
    run([BIN, 'keygen', '--dir', directory, '--index', index])
    return bytes.fromhex(run([BIN, 'keygen-public', '--dir', directory]).split('\t')[1].strip())


def net():
    RUN.mkdir(mode=0o700)
    (R / 'home/tmp').mkdir(parents=True, exist_ok=True)
    with PASS.open('x') as f:
        f.write(os.urandom(32).hex() + '\n')
    PASS.chmod(0o600)
    keys = [RUN / f'key{i}' for i in range(N)]
    for i, k in enumerate(keys):
        keystore(k, i)
    wallet_pk, da_pk = keystore(RUN / 'wallet', 0), keystore(RUN / 'da', 0)
    for name, pk in (('wallet', wallet_pk), ('da', da_pk)):
        (RUN / f'{name}.pubkey.hex').write_text(pk.hex() + '\n')
    wallet_script, da_script = hashlib.sha3_256(wallet_pk).hexdigest(), hashlib.sha3_256(da_pk).hexdigest()
    t0 = time.time()
    out = run([BIN, 'genesis', '--keys', ','.join(map(str, keys)), '--out', RUN / 'genesis.blg', '--slot-ms', SLOT_MS,
               '--start-in', 40, '--bind-genesis', '--alloc', f'{wallet_script}:{1_000 * 10**8}',
               '--alloc', f'{da_script}:{100 * 10**8}'])
    digest = hashlib.sha3_256((RUN / 'genesis.blg').read_bytes()).hexdigest()
    save(genesis_output=out, network_domain=digest, genesis_secs_approx=int(t0) + 40, wallet_script=wallet_script, da_script=da_script,
         bloch_pos_version=run([BIN, '--version']).splitlines()[0], bloch_pos_sha256=sha(BIN),
         genesis_sha256=sha(RUN / 'genesis.blg'))
    log('genesis', output=out.strip().splitlines()[:3], network=digest)
    for i in range(N):
        data = RUN / f'node{i}'
        data.mkdir(mode=0o700)
        shutil.copy2(keys[i] / 'validator.key', data / 'validator.key')
        peers = ','.join(f'127.0.0.1:{P2P[j]}' for j in range(N) if j != i)
        spawn(f'node{i}', [BIN, 'run', '--data-dir', data, '--genesis', RUN / 'genesis.blg', '--transport', 'devnet',
                           '--listen', P2P[i], '--listen-addr', '127.0.0.1', '--peers', peers,
                           '--rpc-bind', '127.0.0.1', '--rpc-port', RPC[i]])
        time.sleep(1)


def l2init():
    identity = json.loads((OUT / 'identity.json').read_text())
    bad = {k: (identity.get(k), v) for k, v in PROGRAM.items() if identity.get(k) != v}
    if bad or identity.get('chain_id') != 700770:
        raise SystemExit(f'prover identity differs from the pinned mainnet PROGRAM: {bad} chain {identity.get("chain_id")}')
    db = RUN / 'canonical'
    produce('init', '--target', db)
    head = produce('head', '--target', db)
    if head['hash'] != L2_GENESIS or head['state_root'] != L2_GENESIS_STATE:
        raise SystemExit(f'L2 genesis differs from the pin: {head}')
    cfg = b''.join(bytes.fromhex(PROGRAM[k]) for k in ('domain', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'))
    cfg += bytes.fromhex(PROGRAM['proof_policy_v3']) + (700770).to_bytes(8, 'little') + bytes.fromhex(L2_GENESIS) + bytes.fromhex(L2_GENESIS_STATE)
    assert len(cfg) == 264
    (RUN / 'l2-config.bin').write_bytes(cfg)
    (RUN / 'txpool').mkdir(exist_ok=True)
    save(l2_genesis=head, identity=identity)
    log('l2-genesis', head=head)


def follower():
    s = state()
    spawn('follower', [OUT / 'bloch-l2-native-follower', '--manifest', RUN / 'genesis.blg', '--network-pin', s['network_domain'],
                       '--rpc-port', RPC[1], '--state', RUN / 'follower', '--status', RUN / 'follower-status.json',
                       '--poll-seconds', 5])


def rpcd():
    s = state()
    spawn('settled-rpc', [OUT / 'bloch-l2-settled-rpc', '--data-dir', RUN / 'canonical', '--view-dir', RUN / 'rpc-view',
                          '--finality-status', RUN / 'follower-status.json', '--network', s['network_domain'],
                          '--port', L2_RPC, '--poll-ms', 2000, *NET_ARGS, '--txpool', RUN / 'txpool'])


def settler():
    s = state()
    genesis_secs = s['genesis_secs_approx']
    config = {
        'network': s['network_domain'], 'network_kind': 'mainnet-rehearsal', 'chain_id': 700770, 'network_args': NET_ARGS,
        'l2_genesis': L2_GENESIS, 'rpc_ports': RPC, 'produce': str(PRODUCE), 'l2_db': str(RUN / 'canonical'),
        'workdir': str(RUN / 'work'), 'home': str(R / 'home'), 'prover_path': f'{R}/shim:/usr/bin:/bin',
        'prover': str(GUARDED), 'prover_sha256': sha(GUARDED), 'guest': str(ELF), 'guest_sha256': sha(ELF),
        'l2_config': str(RUN / 'l2-config.bin'), 'l2_config_sha256': sha(RUN / 'l2-config.bin'),
        'gnark_image': GNARK, 'prover_threads': 20, 'timestamp_rule': f'1:{genesis_secs}:{SLOT_MS}',
        'acceptance_timeout_seconds': 900, 'idle_seconds': 10, 'max_consecutive_failures': 100,
        'user_transactions': True, 'txpool_dir': str(RUN / 'txpool'),
        'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 256,
        'da': {'signer': str(BIN), 'signer_sha256': sha(BIN), 'genesis': str(RUN / 'genesis.blg'),
               'funding_pubkey': str(RUN / 'da.pubkey.hex'), 'keystore_dir': str(RUN / 'da'),
               'passphrase_file': str(PASS), 'tip_millisat_per_gas': 0, 'inclusion_timeout_seconds': 300},
    }
    (RUN / 'work').mkdir(exist_ok=True)
    (RUN / 'settler.json').write_text(json.dumps(config, indent=2) + '\n')
    spawn('settler', ['/usr/bin/python3', '-u', R / 'src/bloch-l2-evm/deployment/devnet/settler_v3.py'],
          {'BLOCH_SETTLER_CONFIG': str(RUN / 'settler.json')})


def l2key():
    key = RUN / 'l2.key'
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, (os.urandom(32).hex() + '\n').encode())
    os.close(fd)
    a = produce('address', '--key', key)
    save(l2_address=a['address'])
    log('l2-key', **a)


def wallet_input():
    utxos = rpc('getutxos', [state()['wallet_script'], 64]).get('utxos', [])
    u = max(utxos, key=lambda u: int(u['value_sat']))
    return f"{u['txid']}:{u['vout']}:{u['value_sat']}"


def base_fee():
    return str(rpc('getchaininfo')['next_base_fee_millisat_per_gas'])


def send(path):
    result = rpc('sendrawtransaction', [path.read_text().strip()])
    log('sent', file=path.name, result=result)
    return result


def deposit(sats):
    s, stamp = state(), time.strftime('%H%M%S')
    unsigned, signed = RUN / f'deposit-{stamp}-unsigned.hex', RUN / f'deposit-{stamp}.hex'
    run([BIN, 'l2-deposit', 'prepare', '--genesis', RUN / 'genesis.blg', '--funding-pubkey', RUN / 'wallet.pubkey.hex',
         '--input', wallet_input(), '--amount', sats, '--recipient', s['l2_address'], '--base-fee', base_fee(), '--tip', '0',
         '--out', unsigned])
    run([BIN, 'l2-deposit', 'sign', '--genesis', RUN / 'genesis.blg', '--tx', unsigned, '--dir', RUN / 'wallet', '--out', signed])
    send(signed)


def txs(to_wei, withdraw_sats):
    s, stamp = state(), time.strftime('%H%M%S')
    nonce = produce('account', '--target', RUN / 'canonical', '--address', s['l2_address'])['nonce']
    made = []
    for i, args in enumerate((['--to', '00' * 19 + '55', '--value-wei', str(to_wei)],
                              ['--withdraw-to', s['wallet_script'], '--sats', str(withdraw_sats)])):
        staged = RUN / f'tx-{stamp}-{i}.tx'
        info = produce('sign-tx', '--key', RUN / 'l2.key', '--nonce', nonce + i, *args, '--out', staged)
        raw = staged.read_text().strip()
        raw = raw if raw.startswith('0x') else '0x' + raw
        # The public path: eth_sendRawTransaction on the settled RPC (writes the settler's txpool).
        try:
            res = rpc('eth_sendRawTransaction', [raw], port=L2_RPC)
        except SystemExit as e:
            res = f'refused: {e}'
        made.append({'file': staged.name, 'rpc_result': res, **info})
    log('l2-txs', txs=made)


def claim(index):
    db = RUN / 'canonical'
    w = rpc('getl2settlement')['withdrawals']
    head = produce('head', '--target', db)
    leaf = produce('withdrawal-proof', '--target', db, '--index', index, '--number', head['number'])['withdrawal']
    record = w['matured_large' if leaf['sats'] >= int(w['large_claim_sat']) else 'matured']
    if record is None or record['count'] <= index:
        raise SystemExit(f'withdrawal {index} not matured: {json.dumps(w)[:1500]}')
    proof = RUN / f'claim-{index}-proof.json'
    proof.write_text(json.dumps(produce('withdrawal-proof', '--target', db, '--index', index, '--number', record['l2_number'],
                                        '--root', record['root'], '--count', record['count'])) + '\n')
    unsigned, signed = RUN / f'claim-{index}-unsigned.hex', RUN / f'claim-{index}.hex'
    run([BIN, 'l2-claim', 'prepare', '--genesis', RUN / 'genesis.blg', '--funding-pubkey', RUN / 'wallet.pubkey.hex',
         '--input', wallet_input(), '--proof', proof, '--base-fee', base_fee(), '--tip', '0', '--out', unsigned])
    run([BIN, 'l2-claim', 'sign', '--genesis', RUN / 'genesis.blg', '--tx', unsigned, '--dir', RUN / 'wallet', '--out', signed])
    before = int(rpc('getl2settlement')['inbox']['escrow_sat'])
    log('claim', index=index, leaf=leaf, record=record, escrow_before=before, height=rpc('getchaininfo')['height'])
    send(signed)
    for _ in range(40):
        time.sleep(3)
        v = rpc('getl2settlement')
        if int(v['inbox']['escrow_sat']) != before:
            log('claimed', escrow_after=v['inbox']['escrow_sat'], claimed=v['withdrawals']['claimed'],
                height=rpc('getchaininfo')['height'])
            return
    log('claim-not-included')


def status():
    out = {}
    for p in RPC:
        try:
            i = rpc('getchaininfo', port=p)
            out[p] = {k: i.get(k) for k in ('slot', 'height', 'justified', 'finalized', 'finalized_height')}
        except Exception as e:  # noqa: BLE001
            out[p] = str(e)[:100]
    try:
        v = rpc('getl2settlement')
        out['l2'] = {k: v.get(k) for k in ('network', 'genesis', 'chain_id', 'asynchronous', 'profile', 'native_height', 'inbox')}
        out['l2']['accepted_prefix'] = v.get('accepted') and v['accepted']['statement'][:80]
        out['l2']['withdrawals'] = {k: v['withdrawals'].get(k) for k in ('count', 'root', 'matured', 'delay_blocks',
                                                                          'large_claim_sat', 'release_window', 'attestor_set',
                                                                          'claimed', 'escrow_conserved')} if v.get('withdrawals') else None
        out['l2']['policy'] = {k: v.get(k) for k in ('proof_policy', 'identities', 'limits', 'attestor_set') if k in v}
    except Exception as e:  # noqa: BLE001
        out['l2'] = str(e)[:200]
    try:
        out['utxos_wallet'] = [u['value_sat'] for u in rpc('getutxos', [state()['wallet_script'], 64]).get('utxos', [])]
    except Exception:  # noqa: BLE001
        pass
    print(json.dumps(out, indent=1))


def stop():
    for pid in RUN.glob('*.pid'):
        try:
            os.killpg(int(pid.read_text()), signal.SIGTERM)
            log('stopped', name=pid.stem)
        except ProcessLookupError:
            pass


if __name__ == '__main__':
    cmd, args = sys.argv[1], sys.argv[2:]
    {'net': net, 'l2init': l2init, 'follower': follower, 'rpc': rpcd, 'settler': settler, 'l2key': l2key,
     'deposit': lambda: deposit(int(args[0])), 'txs': lambda: txs(int(args[0]), int(args[1])),
     'claim': lambda: claim(int(args[0])), 'status': status, 'stop': stop}[cmd]()
