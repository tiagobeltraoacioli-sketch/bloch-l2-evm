#!/usr/bin/env python3
"""Private rehearsal of the L2 program swap with L1 forced inclusion: real L1 nodes, follower, settled RPC, settler and Groth16
proofs on both sides, and after the swap a censoring sequencer whose censored user gets its transaction in through L1.

  crossing.py stream GATE   a settlement stream crossing the swap at epoch GATE, where forced inclusion is enabled too
  crossing.py reset GATE    an off-rule block settled before the gate, recovered by the optional head reset (forced build B)
  crossing.py stop          stop everything this harness started

Agent 137 copy of agents 81/115/116's harness (deployment/mainnet/rehearsal/next-consensus/sparse/crossing.py). The next program
is the sparse-witness guest with forced inclusion; its identities are read from $NC/elf/next-program.json. The settler censors
the L2 sender `censored` (rehearsal-only `censor_senders`); the user then submits the same signed envelope as an L1 0x1C
forced transaction, after one with a nonce gap that must be skipped and consumed, and the harness checks the inclusion bound:
the L2 block that carries it is settled no later than the second settlement accepted after the L1 transaction.

Rehearsal only: loopback ports 33700-33799 (agent 137), throwaway keys under $NC/run-*, a forced L1 build. It talks to no
public network. Each check is one line in results/verdicts.jsonl; results/RUN-DONE holds the overall verdict.
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
import time
import urllib.error
import urllib.request

A = Path(os.environ.get('NC', str(Path.home() / 'l2dexbridge-20261030/forced-guest-r8')))
V = {'stream': 'A', 'reset': 'B'}.get(sys.argv[1] if len(sys.argv) > 1 else '', os.environ.get('NC_VARIANT', 'A'))
R = A / f'run-{V}'
OUT = A / f'out-{V}'
RES = R / 'results'
BIN = OUT / 'bloch-pos'
PRODUCE = OUT / 'bloch-l2-produce-dev'
FOLLOWER = OUT / 'bloch-l2-native-follower'
SETTLED = OUT / 'bloch-l2-settled-rpc'
PROVER = OUT / 'bloch-evm-sp1-settlement-v3'
GUARDED = OUT / 'bloch-evm-sp1-settlement-v3-locked'
ELF_BASE = A / 'elf/settlement_v3_mainnet.v1'
ELF_NEXT = A / 'elf/settlement_v3_mainnet.next'
SHIM = A / 'tools/bin'
SETTLER = A / 'src/bloch-l2-evm/deployment/devnet/settler_v3.py'
N = 5
BASE_PORT = 33700 if V == 'A' else 33750
RPC = [BASE_PORT + 1 + i for i in range(N)]
P2P = [BASE_PORT + 11 + i for i in range(N)]
L2_PORT = BASE_PORT + 20
SLOT_MS, SLOTS_PER_EPOCH = 2000, 32
SAT = 10 ** 8
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L2_GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
L2_GENESIS_STATE = '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'
NET_ARGS = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
TIMESTAMP_RULE = '1:1786656679:30000'  # the mainnet rule: the next program binds exactly this
GNARK = 'ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d'
BASE_PROGRAM = {'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',
                'elf_keccak': '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',
                'vkey_koalabear': '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',
                'vkey_bn254': '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e'}
# a137: the next program is the sparse-witness guest with forced inclusion, built in agent 115's pinned container. Its
# identities (configuration, ELF Keccak, both vkeys) are those of native PROGRAM_NEXT on the candidate branch.
NEXT_PROGRAM_FILE = A / 'elf/next-program.json'
NEXT_PROGRAM = ({k: json.loads(NEXT_PROGRAM_FILE.read_text())[k] for k in ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254')}
                if NEXT_PROGRAM_FILE.exists() else {})
POLICY = '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d'
VAULTS = {'base': '4200000000000000000000000000000000000019', 'sequencer': '4200000000000000000000000000000000000011'}
SWEEP_RECIPIENT = '775a993f09bd80aecf8f8c2ade0c84158e3a0544'
SWEEP_CODE = '5f5f5f5f4773' + SWEEP_RECIPIENT + '5af11560215700' + '5b5f5ffd'
LOCK = A.parent / 'PROVING.lock'
# Rehearsal knobs of the forced-inclusion scenario.
CENSOR_RECIPIENT = '00' * 19 + '77'
CENSORED_VALUE_WEI = 3 * 10 ** 15
FORCED_GAS = 21_000
FORCED_BOUND = 2  # the record must be in an L2 block settled by the 2nd settlement accepted after its L1 transaction
PASS = R / 'keystore.passphrase'
fails = []
# Every wait on settlements; the shared proof lock can hold a proof back for an hour or more (agent 137).
WAIT = int(os.environ.get('NC_WAIT', '10800'))


def now():
    return time.strftime('%FT%TZ', time.gmtime())


def note(event, **fields):
    line = json.dumps({'at': now(), 'event': event, **fields})
    print(line, flush=True)
    with (RES / 'events.jsonl').open('a') as out:
        out.write(line + '\n')


def check(name, ok, detail=None):
    line = {'at': now(), 'check': name, 'verdict': 'PASS' if ok else 'FAIL'}
    if detail is not None:
        line['detail'] = detail
    print(json.dumps(line), flush=True)
    with (RES / 'verdicts.jsonl').open('a') as out:
        out.write(json.dumps(line) + '\n')
    if not ok:
        fails.append(name)
    return ok


def env(**extra):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(R / 'home'), 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(PASS), **extra}


def run(*argv, ok=True, **kwargs):
    done = subprocess.run([str(a) for a in argv], env=kwargs.pop('env', env()), capture_output=True, text=True, **kwargs)
    if ok and done.returncode:
        raise RuntimeError(f'{Path(str(argv[0])).name} {argv[1] if len(argv) > 1 else ""}: {done.stderr[-1500:]}')
    return done.stdout


def http(port, method, *params, timeout=30):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}', body, {'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        reply = json.loads(response.read())
    if 'error' in reply:
        raise RuntimeError(f'{method}: {reply["error"]}')
    return reply['result']


def l1(method, *params, port=None):
    return http(port or RPC[0], method, *params)


def l2(method, *params):
    return http(L2_PORT, method, *params)


def produce(*args, target_retry=30):
    last = None
    for _ in range(target_retry):
        done = subprocess.run([str(PRODUCE), *map(str, args), *NET_ARGS], capture_output=True, text=True)
        if done.returncode == 0:
            return json.loads(done.stdout)
        last = done.stderr
        if 'refused' in last and 'database' not in last.lower() and 'lock' not in last.lower():
            break
        time.sleep(3)
    raise RuntimeError(f'produce {args[0]}: {last[:1200]}')


def until(what, condition, timeout, every=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = condition()
        except (RuntimeError, OSError, ValueError, urllib.error.URLError, TimeoutError) as error:
            value, _ = None, error
        if value:
            return value
        time.sleep(every)
    raise TimeoutError(f'timed out: {what}')


def state():
    return json.loads((R / 'state.json').read_text()) if (R / 'state.json').exists() else {}


def save(**fields):
    (R / 'state.json').write_text(json.dumps({**state(), **fields}, indent=1))


# ── processes ─────────────────────────────────────────────────────────────────
def spawn(name, *argv, **extra):
    logf = (R / 'logs' / f'{name}.log').open('a')
    process = subprocess.Popen([str(a) for a in argv], env=env(**extra), stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                               start_new_session=True, cwd=R)
    (R / 'pids' / f'{name}').write_text(str(process.pid))
    note('spawned', name=name, pid=process.pid)
    return process


def alive(name):
    path = R / 'pids' / name
    if not path.exists():
        return False
    try:
        os.kill(int(path.read_text()), 0)
    except (ProcessLookupError, ValueError):
        return False
    state_path = Path(f'/proc/{path.read_text()}/stat')
    return state_path.exists() and state_path.read_text().split(') ')[-1][0] != 'Z'


def halt(name):
    path = R / 'pids' / name
    if path.exists():
        try:
            os.killpg(int(path.read_text()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
        for _ in range(100):
            if not alive(name):
                break
            time.sleep(0.2)
        path.unlink(missing_ok=True)


def stop_all():
    for path in (R / 'pids').glob('*'):
        halt(path.name)


# ── setup ─────────────────────────────────────────────────────────────────────
def keystore(directory, index):
    directory.mkdir(mode=0o700)
    run(BIN, 'keygen', '--dir', directory, '--index', index)
    return bytes.fromhex(run(BIN, 'keygen-public', '--dir', directory).split('\t')[1].strip())


def start_net():
    R.mkdir(mode=0o700)
    for sub in ('logs', 'pids', 'results', 'home/tmp', 'work', 'txpool'):
        (R / sub).mkdir(parents=True)
    (R / 'home/.sp1').mkdir()
    (R / 'home/.sp1/circuits').symlink_to(Path.home() / '.sp1/circuits')
    with PASS.open('x') as out:
        out.write(os.urandom(32).hex() + '\n')
    PASS.chmod(0o600)
    keys = [R / f'key{i}' for i in range(N)]
    for i, key in enumerate(keys):
        keystore(key, i)
    wallet, da = keystore(R / 'wallet', 0), keystore(R / 'da', 0)
    (R / 'wallet.pubkey.hex').write_text(wallet.hex() + '\n')
    (R / 'da.pubkey.hex').write_text(da.hex() + '\n')
    wallet_script, da_script = hashlib.sha3_256(wallet).hexdigest(), hashlib.sha3_256(da).hexdigest()
    run(BIN, 'genesis', '--keys', ','.join(map(str, keys)), '--out', R / 'genesis.blg', '--slot-ms', SLOT_MS, '--start-in', 40, '--bind-genesis',
        '--alloc', f'{wallet_script}:{5_000 * SAT}', '--alloc', f'{da_script}:{100 * SAT}')
    save(network=hashlib.sha3_256((R / 'genesis.blg').read_bytes()).hexdigest(), wallet_script=wallet_script, version=run(BIN, '--version').splitlines()[:2])
    for i in range(N):
        data = R / f'node{i}'
        data.mkdir(mode=0o700)
        shutil.copy2(keys[i] / 'validator.key', data / 'validator.key')
        peers = ','.join(f'127.0.0.1:{P2P[j]}' for j in range(N) if j != i)
        spawn(f'node{i}', BIN, 'run', '--data-dir', data, '--genesis', R / 'genesis.blg', '--transport', 'devnet', '--listen', P2P[i], '--listen-addr', '127.0.0.1',
              '--peers', peers, '--rpc-bind', '127.0.0.1', '--rpc-port', RPC[i])


def config_bytes(program):
    out = bytes.fromhex(DOMAIN) + b''.join(bytes.fromhex(program[k]) for k in ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'))
    return out + bytes.fromhex(POLICY) + (700770).to_bytes(8, 'little') + bytes.fromhex(L2_GENESIS) + bytes.fromhex(L2_GENESIS_STATE)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def guarded_prover():
    GUARDED.write_text(f"""#!/bin/bash
REAL={PROVER}
export PATH={SHIM}:$PATH
case " $* " in *" prove-groth16 "*) ;; *) exec "$REAL" "$@";; esac
case " $* " in *" --sparse "*) CAP=48;; *) CAP=64;; esac
export ELEMENT_THRESHOLD=268435456
# Wait for memory before the lock, never while holding it.
while [ "$(awk '/MemAvailable/ {{print int($2/1048576)}}' /proc/meminfo)" -lt $((CAP + 2)) ]; do echo "prover: waiting for $((CAP + 2)) GB available" >&2; sleep 20; done
export XDG_RUNTIME_DIR=/run/user/$(id -u)
echo "wait $(date +%s)" >> {R}/logs/proof-queue.log
exec /usr/bin/flock {LOCK} /bin/bash -c 'echo "got $(date +%s) $1" >> {R}/logs/proof-queue.log; /usr/bin/systemd-run --user --scope -q -p MemoryMax='$CAP'G -p MemorySwapMax=0 /usr/bin/nice -n 10 "$@"; rc=$?; echo "done $(date +%s) rc=$rc" >> {R}/logs/proof-queue.log; exit $rc' _ "$REAL" "$@"
""")
    GUARDED.chmod(0o755)


def settler_config(timestamp_rule=TIMESTAMP_RULE):
    s = state()
    base_cfg, next_cfg = R / 'l2-config.base.bin', R / 'l2-config.next.bin'
    base_cfg.write_bytes(config_bytes(BASE_PROGRAM))
    next_cfg.write_bytes(config_bytes(NEXT_PROGRAM))
    config = {
        'network': s['network'], 'network_kind': 'mainnet-rehearsal', 'chain_id': 700770, 'network_args': NET_ARGS, 'l2_genesis': L2_GENESIS,
        'rpc_ports': RPC[:3], 'rpc_quorum': 2, 'produce': str(PRODUCE), 'l2_db': str(R / 'canonical'), 'workdir': str(R / 'work'), 'home': str(R / 'home'),
        'prover_path': f'{SHIM}:/usr/bin:/bin', 'prover': str(GUARDED), 'prover_sha256': sha(GUARDED), 'prover_args': ['--mainnet-v1'],
        'guest': str(ELF_BASE), 'guest_sha256': sha(ELF_BASE), 'l2_config': str(base_cfg), 'l2_config_sha256': sha(base_cfg),
        'next_program': {'prover': str(GUARDED), 'prover_sha256': sha(GUARDED), 'guest': str(ELF_NEXT), 'guest_sha256': sha(ELF_NEXT),
                         'l2_config': str(next_cfg), 'l2_config_sha256': sha(next_cfg), 'witness': 'sparse'},
        'gnark_image': GNARK, 'prover_threads': 32, 'timestamp_rule': timestamp_rule, 'acceptance_timeout_seconds': 1800, 'idle_seconds': 10,
        'max_consecutive_failures': 100, 'user_transactions': True, 'txpool_dir': str(R / 'txpool'), 'max_block_gas': 15_000_000, 'max_block_bytes': 114_688,
        'max_block_txs': 64, 'censor_senders': [s['l2_censored']] if 'l2_censored' in s else [],
        'da': {'signer': str(BIN), 'signer_sha256': sha(BIN), 'genesis': str(R / 'genesis.blg'), 'funding_pubkey': str(R / 'da.pubkey.hex'),
               'keystore_dir': str(R / 'da'), 'passphrase_file': str(PASS), 'tip_millisat_per_gas': 0, 'inclusion_timeout_seconds': 300},
    }
    (R / 'settler.json').write_text(json.dumps(config, indent=1))


def start_follower(name='follower', node=1):
    (R / name).mkdir(exist_ok=True)
    spawn(name, FOLLOWER, '--manifest', R / 'genesis.blg', '--network-pin', state()['network'], '--rpc-port', RPC[node], '--state', R / name / 'native',
          '--status', R / name / 'status.json', '--poll-seconds', 5)


def start_rpc():
    shutil.rmtree(R / 'rpc-view', ignore_errors=True)
    spawn('rpc', SETTLED, '--data-dir', R / 'canonical', '--view-dir', R / 'rpc-view', '--finality-status', R / 'follower/status.json', '--network', state()['network'],
          '--port', L2_PORT, '--poll-ms', 2000, *NET_ARGS, '--txpool', R / 'txpool')


def start_settler():
    spawn('settler', '/usr/bin/python3', '-u', SETTLER, BLOCH_SETTLER_CONFIG=str(R / 'settler.json'))


def init_l2():
    guarded_prover()
    head = produce('init', '--target', R / 'canonical')
    head = produce('head', '--target', R / 'canonical')
    if head['hash'] != L2_GENESIS or head['state_root'] != L2_GENESIS_STATE or head.get('rules') != 'base':
        raise SystemExit(f'L2 genesis differs from the pin: {head}')


# ── actions ───────────────────────────────────────────────────────────────────
def l2key(name):
    key = R / f'{name}.l2.key'
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, (os.urandom(32).hex() + '\n').encode())
    os.close(fd)
    save(**{f'l2_{name}': produce('address', '--key', key)['address']})


def settler_module():
    spec = importlib.util.spec_from_file_location('settler_v3_a137', SETTLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sign_envelope(name, nonce, label, *args):
    """A signed L2 transfer of `name`, written to a file and not sent anywhere."""
    path = R / f'envelope-{label}.tx'
    info = produce('sign-tx', '--key', R / f'{name}.l2.key', '--nonce', nonce, *args, '--out', path)
    return path, info['hash'].removeprefix('0x')


def forced_view():
    return view().get('forced')


def forced_submit(envelope, label, gas=FORCED_GAS):
    """Wrap a signed L2 envelope in an L1 0x1C forced transaction, paid by the wallet, and wait for its inclusion."""
    before = wallet_input()
    queue = forced_view()
    unit, depth = queue['next_surcharge_sat'], queue['pending_weight']
    unsigned, signed = R / f'forced-{label}-unsigned.hex', R / f'forced-{label}.hex'
    run(BIN, 'l2-forced', 'prepare', '--genesis', R / 'genesis.blg', '--funding-pubkey', R / 'wallet.pubkey.hex',
        '--input', f"{before['txid']}:{before['vout']}:{before['value_sat']}", '--envelope', envelope, '--gas', gas,
        '--pending-weight', depth, '--base-fee', l1('getchaininfo')['next_base_fee_millisat_per_gas'], '--tip', 0,
        '--out', unsigned)
    run(BIN, 'l2-forced', 'sign', '--genesis', R / 'genesis.blg', '--tx', unsigned, '--dir', R / 'wallet', '--out', signed)
    result = l1('sendrawtransaction', signed.read_text().strip())
    until(f'forced transaction {label} included', lambda: wallet_input() != before, 300, 2)
    note('forced transaction included', label=label, result=result, height=l1('getchaininfo')['height'], surcharge_unit=unit,
         pending_weight=depth)
    return result


def receipt(tx_hash):
    return l2('eth_getTransactionReceipt', '0x' + tx_hash.removeprefix('0x'))


def block_directory(number):
    live = [d for d in sorted((R / 'work').glob(f'{number:08d}-*')) if '.superseded-' not in d.name and d.is_dir()]
    return live[-1] if live else None


def wallet_input():
    return max(l1('getutxos', state()['wallet_script'], 64).get('utxos', []), key=lambda u: int(u['value_sat']))


def deposit(name, sats):
    stamp = time.strftime('%H%M%S')
    before = wallet_input()
    unsigned, signed = R / f'deposit-{stamp}-unsigned.hex', R / f'deposit-{stamp}.hex'
    run(BIN, 'l2-deposit', 'prepare', '--genesis', R / 'genesis.blg', '--funding-pubkey', R / 'wallet.pubkey.hex',
        '--input', f"{before['txid']}:{before['vout']}:{before['value_sat']}", '--amount', sats, '--recipient', state()[f'l2_{name}'],
        '--base-fee', l1('getchaininfo')['next_base_fee_millisat_per_gas'], '--tip', 0, '--out', unsigned)
    run(BIN, 'l2-deposit', 'sign', '--genesis', R / 'genesis.blg', '--tx', unsigned, '--dir', R / 'wallet', '--out', signed)
    l1('sendrawtransaction', signed.read_text().strip())
    until('deposit included', lambda: wallet_input() != before, 300, 2)


def nonce_of(name):
    return int(l2('eth_getTransactionCount', '0x' + state()[f'l2_{name}'], 'pending'), 16)


def send_tx(name, *args):
    staged = R / f"tx-{time.time_ns()}.tx.tmp"
    info = produce('sign-tx', '--key', R / f'{name}.l2.key', '--nonce', nonce_of(name), *args, '--out', staged)
    raw = staged.read_text().strip()
    staged.unlink()
    l2('eth_sendRawTransaction', '0x' + raw.removeprefix('0x'))
    return info['hash']


def settler_events(kind=None):
    path = R / 'logs/settler.log'
    out = []
    for line in path.read_text(errors='replace').splitlines() if path.exists() else []:
        if line.startswith('{'):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if kind is None or event.get('event') == kind:
                out.append(event)
    return out


def view():
    return l1('getl2settlement')


def accepted_number():
    accepted = view().get('accepted')
    if not accepted:
        return 0
    return int.from_bytes(bytes.fromhex(accepted['statement'])[22 + 264:22 + 272], 'big')


def program_is(report, program):
    return all(report.get(k) == v for k, v in program.items()) and report.get('proof_policy') == POLICY


def slot():
    return l1('getchaininfo')['slot']


def status():
    return json.loads((R / 'follower/status.json').read_text())


def rebuild(follower='follower', label='rebuild', rule=TIMESTAMP_RULE):
    target = R / f'{label}-{int(time.time())}'
    return target, produce('reconstruct', '--target', target, '--l1-follower', R / follower / 'native', '--timestamp-rule', rule, target_retry=1)


def claim(index, record, label):
    proof = R / f'claim-{label}.json'
    proof.write_text(json.dumps(produce('withdrawal-proof', '--target', R / 'canonical', '--index', index, '--number', record['l2_number'],
                                        '--root', record['root'], '--count', record['count'])) + '\n')
    utxo = wallet_input()
    unsigned, signed = R / f'claim-{label}-unsigned.hex', R / f'claim-{label}.hex'
    run(BIN, 'l2-claim', 'prepare', '--genesis', R / 'genesis.blg', '--funding-pubkey', R / 'wallet.pubkey.hex', '--input', f"{utxo['txid']}:{utxo['vout']}:{utxo['value_sat']}",
        '--proof', proof, '--base-fee', l1('getchaininfo')['next_base_fee_millisat_per_gas'], '--tip', 0, '--out', unsigned)
    run(BIN, 'l2-claim', 'sign', '--genesis', R / 'genesis.blg', '--tx', unsigned, '--dir', R / 'wallet', '--out', signed)
    return l1('sendrawtransaction', signed.read_text().strip())


def code_at(address, block):
    return l2('eth_getCode', '0x' + address, block).removeprefix('0x')


def balance_at(address, block='latest'):
    return int(l2('eth_getBalance', '0x' + address, block), 16)


def proof_table():
    path = R / 'logs/proof-queue.log'
    entries, wait, got = [], None, None
    for line in path.read_text().splitlines() if path.exists() else []:
        parts = line.split()
        if parts[0] == 'wait':
            wait = int(parts[1])
        elif parts[0] == 'got':
            got = int(parts[1])
        elif parts[0] == 'done' and got:
            entries.append({'queue_s': got - (wait or got), 'prove_s': int(parts[1]) - got, 'rc': parts[2]})
            wait = got = None
    return entries


def common_checks(gate, base_upto):
    """After the stream crossed: finality, RPC levels, follower restart, rebuilds and the program pins."""
    info = l1('getchaininfo')
    roots = {l1('getchaininfo', port=p)['finalized']['root'] for p in RPC}
    note('final L1', slot=info['slot'], finalized=info['finalized'], roots=len(roots))
    check('L1 program is the next one', program_is(view()['program'], NEXT_PROGRAM), view()['program'])
    check('all nodes hold one finalized root', len(roots) <= 2, len(roots))
    st = status()
    entries = st['finalized_settlements']
    configurations = [e['configuration'] for e in entries]
    switch = next((e['l2_number'] for e in entries if e['configuration'] == NEXT_PROGRAM['configuration']), None)
    note('follower status', settlements=[(e['l2_number'], e['configuration'][:8], e['l2_hash'][:12], e['native_slot']) for e in entries], active=st['active_program'])
    check('the follower reports the next program', st['active_program']['elf_keccak'] == NEXT_PROGRAM['elf_keccak'], st['active_program'])
    check('finalized settlements cross the configuration exactly once',
          switch is not None and configurations == sorted(configurations, key=lambda c: c == NEXT_PROGRAM['configuration']), switch)
    if base_upto:
        check('the follower saw settlements of the activated program', any(c == BASE_PROGRAM['configuration'] for c in configurations))
    # A fresh rebuild from the follower's verified L1 blocks, with no rule set given.
    target, report = rebuild()
    rules = [(b['number'], b['rules']) for b in report['blocks']]
    note('rebuild', settled=report['settled'], next_rules_from=report['next_rules_from'], rules=rules)
    rebuilt = {b['number']: b for b in report['blocks']}
    wrong = [e['l2_number'] for e in entries if rebuilt.get(e['l2_number'], {}).get('hash') != e['l2_hash'] or rebuilt[e['l2_number']]['state_root'] != e['l2_state_root']]
    check('a rebuild from L1 matches every finalized settlement across the swap', not wrong and report['settled'] >= len(entries), wrong)
    if state().get('forced_block'):
        forced_block = state()['forced_block']
        check('the rebuild from L1 holds the block with the forced envelope (read from the 0x1C transaction)',
              rebuilt.get(forced_block, {}).get('hash') == next((e['l2_hash'] for e in entries if e['l2_number'] == forced_block), None),
              {'block': forced_block, 'rebuilt': rebuilt.get(forced_block)})
    check('the rebuild switches rules at the first next-program settlement', report['next_rules_from'] == switch, (report['next_rules_from'], switch))
    head = produce('head', '--target', target)
    check('the rebuilt database derives the same switch', head['next_rules_from'] == switch, head)
    # A second, independent follower replaying the whole L1 from the pinned genesis, on another node.
    start_follower('follower2', 2)
    until('the second follower catches up', lambda: json.loads((R / 'follower2/status.json').read_text())['finalized_settlements'][:len(entries)] == entries, 900, 5)
    check('a late follower replays the gate and reports the same settlements', True)
    # A restart re-verifies retained history across the gate.
    halt('follower')
    start_follower()
    until('the restarted follower reports again', lambda: len(status()['finalized_settlements']) >= len(entries), 600, 5)
    log = (R / 'logs/follower.log').read_text(errors='replace')
    check('a restarted follower re-verifies retained blocks across the gate', 're-verified' in log and 'halted' not in log)
    # The RPC: levels on both sides, and a restart on a fresh view.
    finalized = until('the RPC reaches the finalized switch', lambda: (lambda b: b if int(b['number'], 16) >= switch else None)(l2('eth_getBlockByNumber', 'finalized', False)), 600, 5)
    check('RPC finalized is past the switch', int(finalized['number'], 16) >= switch, finalized['number'])
    safe = l2('eth_getBlockByNumber', 'safe', False)
    check('RPC safe is at or above finalized', int(safe['number'], 16) >= int(finalized['number'], 16), safe['number'])
    for e in entries:
        block = l2('eth_getBlockByNumber', hex(e['l2_number']), False)
        if block['hash'].removeprefix('0x') != e['l2_hash']:
            check('RPC serves each settled block', False, e['l2_number'])
            break
    else:
        check('RPC serves each settled block', True, len(entries))
    halt('rpc')
    start_rpc()
    until('the restarted RPC answers', lambda: l2('eth_blockNumber'), 300, 3)
    log = (R / 'logs/rpc.log').read_text(errors='replace')
    check('a restarted RPC derives the switch from the database', f'rules: next from block {switch}' in log)
    return switch, entries


# ── scenario A: the stream crosses ─────────────────────────────────────────────
def stream(gate):
    gate_slot = gate * SLOTS_PER_EPOCH
    # The settler's pinned sparse next program must be the one this run proves with.
    if not NEXT_PROGRAM or not ELF_NEXT.exists():
        raise SystemExit(f'place the next guest at {ELF_NEXT} and its identities in {NEXT_PROGRAM_FILE} first')
    pin = settler_module().MAINNET_NEXT_SPARSE
    if any(pin[k] != v for k, v in NEXT_PROGRAM.items()) or pin['guest_sha256'] != sha(ELF_NEXT):
        raise SystemExit(f'settler MAINNET_NEXT_SPARSE {pin} differs from {A}/elf/next-program.json or the ELF {sha(ELF_NEXT)}')
    start_net()
    until('L1 past HF3', lambda: slot() >= SLOTS_PER_EPOCH * 11, 1800)
    check('L1 is the forced flag-day build', any('rehearsal' in line for line in state()['version']), state()['version'])
    for name in ('user', 'late', 'censored'):
        l2key(name)
    init_l2()
    settler_config()
    start_follower()
    start_rpc()
    report = view()['program']
    check('before the gate L1 reports the activated program', program_is(report, BASE_PROGRAM), report)
    check('before the gate L1 has no forced queue (the gate is inert until the swap)', 'forced' not in view(), sorted(view()))
    start_settler()
    save(gate=gate, gate_slot=gate_slot)
    deposit('user', 500 * SAT)
    deposit('censored', 20 * SAT)
    until('L2 credits the deposit', lambda: balance_at(state()['l2_user']) > 0, WAIT, 10)
    until('L2 credits the censored user', lambda: balance_at(state()['l2_censored']) > 0, WAIT, 10)

    # User traffic before the gate, and one withdrawal that will be claimed after it.
    first = send_tx('user', '--withdraw-to', state()['wallet_script'], '--sats', 3 * SAT)
    save(withdrawal_before=first)
    last_tx = time.time()
    while slot() < gate_slot - 6:
        if time.time() - last_tx > 90:
            send_tx('user', '--to', '00' * 19 + '55', '--value-wei', 1_000_000_000_000)
            last_tx = time.time()
        time.sleep(5)
    base_upto = accepted_number()
    pre_vault = {k: balance_at(a) for k, a in VAULTS.items()}
    note('just before the gate', slot=slot(), accepted=base_upto, vaults=pre_vault, proofs=proof_table())
    check('blocks settled under the activated program before the gate', base_upto >= 1, base_upto)
    for k, a in VAULTS.items():
        check(f'{k} vault has no sweep code before the gate', code_at(a, 'latest') != SWEEP_CODE)
    # The moment of the swap, read every 500 ms from one node.
    until('L1 reports the next program', lambda: program_is(view()['program'], NEXT_PROGRAM), 300, 0.5)
    crossed = slot()
    note('swap observed', slot=crossed, gate_slot=gate_slot, accepted=accepted_number(), height=l1('getchaininfo')['height'])
    check('the program moved at the gate epoch boundary', gate_slot <= crossed <= gate_slot + 4, (crossed, gate_slot))
    check('the settler survived the crossing', alive('settler'))
    send_tx('user', '--to', '00' * 19 + '55', '--value-wei', 1_000_000_000_000)
    deposit('late', 7 * SAT)
    after = base_upto
    until('first settlement under the next program', lambda: accepted_number() > base_upto and view()['accepted'] and
          bytes.fromhex(view()['accepted']['statement'])[22 + 96:22 + 128].hex() == NEXT_PROGRAM['configuration'], WAIT, 10)
    first_next = accepted_number()
    note('first next settlement', number=first_next, slot=slot(), proofs=proof_table())
    rewinds, moved = settler_events('l2-block-rewound-at-swap'), settler_events('program-moved-before-submit') + settler_events('program-moved-after-submit')
    note('swap handling', rewinds=rewinds, moved=moved)
    check('the settler handled the swap without a halt', not settler_events('halt'))
    forced = forced_view()
    check('after the gate L1 holds an enabled, empty forced queue', forced is not None and forced['pending'] == 0, forced)
    censored_nonce = nonce_of('censored')
    censored_path, censored_hash = sign_envelope('censored', censored_nonce, 'censored', '--to', CENSOR_RECIPIENT,
                                                 '--value-wei', CENSORED_VALUE_WEI)
    l2('eth_sendRawTransaction', '0x' + censored_path.read_text().strip().removeprefix('0x'))
    censored_from = accepted_number()
    save(censored_hash=censored_hash, censored_nonce=censored_nonce, censored_from=censored_from)
    note('censored transaction sent to the sequencer', hash=censored_hash, nonce=censored_nonce, accepted=censored_from)
    # A block in flight at the gate: its old-program proof must be refused by L1 now.
    stale = sorted((R / 'work').glob('*.superseded-*/transaction.bin'))
    if stale:
        try:
            result = l1('sendrawtransaction', stale[-1].read_bytes().hex())
            refused = False
        except RuntimeError as error:
            result, refused = str(error), True
        note('old-program settlement sent after the gate', result=str(result)[:300])
        check('L1 refuses the old-program settlement after the gate', refused, str(result)[:200])
    else:
        note('no old-program transaction to replay', superseded=[p.name for p in (R / 'work').glob('*.superseded-*')], rewinds=len(rewinds))
    # The fee vaults: code at the switch, balances kept, and a real sweep under the next rules.
    for k, a in VAULTS.items():
        check(f'{k} vault holds the sweep code after the switch', code_at(a, 'latest') == SWEEP_CODE, code_at(a, 'latest'))
        check(f'{k} vault kept its balance across the install', balance_at(a, hex(first_next)) >= pre_vault[k], (balance_at(a, hex(first_next)), pre_vault[k]))
    settled_vault = balance_at(VAULTS['base'])
    recipient_before = balance_at(SWEEP_RECIPIENT)
    second = send_tx('user', '--withdraw-to', state()['wallet_script'], '--sats', 2 * SAT)
    save(withdrawal_after=second)
    sweep = send_tx('user', '--to', VAULTS['base'], '--value-wei', 0, '--gas', 200_000)
    note('sweep sent', tx=sweep, vault=settled_vault)
    until('three settlements under the next program', lambda: accepted_number() >= first_next + 2, WAIT, 15)
    until('two settlements after the censored transaction', lambda: accepted_number() >= censored_from + 2, WAIT, 15)
    check('the sequencer censored the transaction over two settlements', receipt(censored_hash) is None
          and balance_at(CENSOR_RECIPIENT) == 0 and bool(settler_events('tx-censored'))
          and (Path(str(R / 'txpool') + '-censored') / f'{censored_hash}.tx').exists(),
          {'events': len(settler_events('tx-censored')), 'accepted': accepted_number(), 'from': censored_from})
    forced_scenario(censored_path, censored_hash, censored_nonce)
    sweep_receipt = until('the sweep is mined', lambda: l2('eth_getTransactionReceipt', '0x' + sweep.removeprefix('0x')), WAIT, 10)
    check('the sweep transaction succeeded', sweep_receipt['status'] == '0x1', sweep_receipt['status'])
    check('the sweep moved the vault balance to the recipient', balance_at(SWEEP_RECIPIENT) > recipient_before, balance_at(SWEEP_RECIPIENT))
    check('a deposit made after the gate is minted', balance_at(state()['l2_late']) >= 7 * SAT * 10 ** 10, balance_at(state()['l2_late']))
    # Claims of a withdrawal from each side of the switch.
    tree = until('the withdrawals are claimable', lambda: (lambda w: w if w.get('claimable') and w['claimable']['count'] >= 2 and w['claimable']['l2_number'] >= first_next else None)(view()['withdrawals']), WAIT, 15)
    note('withdrawals view', claimable=tree['claimable'])
    for index, sats, label in ((0, 3 * SAT, 'before'), (1, 2 * SAT, 'after')):
        escrow = int(view()['inbox']['escrow_sat'])
        result = claim(index, tree['claimable'], label)
        note('claim', label=label, result=result)
        until(f'claim {label} is included', lambda: int(view()['inbox']['escrow_sat']) != escrow, 600, 3)
        check(f'claim of the withdrawal from {label} the switch moves exactly its amount', escrow - int(view()['inbox']['escrow_sat']) == sats)
    check('escrow conserved', view()['withdrawals'].get('escrow_conserved') is True)
    # Finality past the switch, then the common checks.
    until('L2 finalized passes the switch', lambda: any(e['l2_number'] >= first_next + 1 for e in status()['finalized_settlements']), WAIT, 15)
    if state().get('forced_block'):
        until('L2 finalized passes the forced block',
              lambda: any(e['l2_number'] >= state()['forced_block'] for e in status()['finalized_settlements']), WAIT, 15)
    switch, _ = common_checks(gate, base_upto)
    check('the switch is the first block not settled before the gate', switch == base_upto + 1 or switch > after, (switch, base_upto))
    events = {k: len(settler_events(k)) for k in ('accepted', 'proof-generated', 'da-included', 'halt', 'retry', 'l2-block-rewound-at-swap', 'program-moved-before-submit', 'program-moved-after-submit')}
    accepted = settler_events('accepted')
    times = [time.mktime(time.strptime(e['time'], '%Y-%m-%dT%H:%M:%SZ')) for e in accepted]
    gaps = [int(b - a) for a, b in zip(times, times[1:])]
    note('settler totals', events=events, accepted=[(e['number'], e['time']) for e in accepted], gaps=gaps, proofs=proof_table())
    check('no settler halt and the process never restarted', events['halt'] == 0 and alive('settler'), events)
    check('every accepted number follows the last', [e['number'] for e in accepted] == list(range(1, len(accepted) + 1)), [e['number'] for e in accepted])


def forced_scenario(censored_path, censored_hash, censored_nonce):
    """The censored transaction through L1: a skipped record first (nonce gap), then the censored envelope itself."""
    before = forced_view()
    gap_path, gap_hash = sign_envelope('censored', censored_nonce + 5, 'nonce-gap', '--to', CENSOR_RECIPIENT, '--value-wei', 1)
    forced_submit(gap_path, 'nonce-gap')
    submitted = time.time()
    forced_submit(censored_path, 'censored')
    queued_at = accepted_number()
    after = forced_view()
    save(forced_queued_at=queued_at)
    note('forced transactions queued', accepted=queued_at, forced=after)
    check('L1 queued both forced transactions', after['queued'] == before['queued'] + 2 and after['pending'] >= 1, after)
    check('the next surcharge is still the base unit (two transfers queued)', int(after['next_surcharge_sat']) == 1000, after)
    mined = until('the forced transaction is in an L2 block', lambda: receipt(censored_hash), WAIT, 10)
    number = int(mined['blockNumber'], 16)
    until('the block with the forced transaction is settled', lambda: accepted_number() >= number, WAIT, 10)
    waited = time.time() - submitted
    note('forced transaction settled', l2_block=number, queued_at=queued_at, seconds=int(waited))
    check(f'the forced transaction is settled within {FORCED_BOUND} settlements of its L1 transaction',
          number <= queued_at + FORCED_BOUND, {'l2_block': number, 'accepted_at_submission': queued_at, 'seconds': int(waited)})
    check('the forced transaction succeeded on L2', mined['status'] == '0x1', mined['status'])
    check('the forced transfer moved exactly its value', balance_at(CENSOR_RECIPIENT) == CENSORED_VALUE_WEI,
          balance_at(CENSOR_RECIPIENT))
    check('the nonce-gap envelope was skipped (no trace on L2)', receipt(gap_hash) is None)
    # The settled statement: deposits slot bound to the forced records, user count without them.
    directory = block_directory(number)
    detail = {'directory': directory.name if directory else None}
    try:
        st = settler_module()
        due = json.loads((directory / 'forced.json').read_text())
        deposits = json.loads((directory / 'deposits.json').read_text())
        block = json.loads((directory / 'block.json').read_text())
        values = (directory / 'transaction.bin').read_bytes()[33:33 + st.VALUES_BYTES]
        slot_value = values[st.T + st.DEPOSITS_HASH:st.T + st.DEPOSITS_HASH + 32]
        users = int.from_bytes(values[st.T + st.USER_TX_COUNT:st.T + st.USER_TX_COUNT + 8], 'big')
        hashes = [r['envelope_hash'] for r in due]
        gap_record, censored_record = (st.keccak256(bytes.fromhex(p.read_text().strip())).hex() for p in (gap_path, censored_path))
        detail.update(due=len(due), forced=block.get('forced'), users=users, transactions=block.get('transactions'),
                      user_transactions=block.get('user_transactions'))
        check('the consuming block ran its due records and included the censored envelope',
              censored_record in hashes and block['forced']['due'] == len(due)
              and hashes.index(censored_record) not in [x[0] for x in block['forced']['skipped']], detail)
        # The nonce-gap record: consumed by this block or an earlier one, and skipped there.
        skipped_in = None
        for other in sorted((R / 'work').glob('*-*')):
            if '.superseded-' in other.name or not (other / 'forced.json').exists() or not (other / 'block.json').exists():
                continue
            records = [r['envelope_hash'] for r in json.loads((other / 'forced.json').read_text())]
            if gap_record in records:
                report = json.loads((other / 'block.json').read_text()).get('forced') or {}
                if records.index(gap_record) in [x[0] for x in report.get('skipped', [])]:
                    skipped_in = other.name
        check('the nonce-gap record was consumed as a skip, before the censored one', skipped_in is not None
              and skipped_in <= directory.name, skipped_in)
        check('the statement deposits_hash slot is inbox_hash(deposits, forced records)',
              slot_value == st.inbox_hash(st.deposits_hash(deposits), due) and slot_value != st.deposits_hash(deposits), slot_value.hex())
        check('the statement user_tx_count excludes the forced envelope',
              users == block['user_transactions'] == block['transactions'] - block['forced']['included'], detail)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        check('the consuming block work directory holds the forced records and the settlement', False,
              f'{type(error).__name__}: {error}'[:400])
    drained = until('the forced queue drains',
                    lambda: (lambda f: f if f['pending'] == 0 and f['consumed'] >= after['queued'] else None)(forced_view()), 1800, 10)
    check('L1 consumed both records and the queue is empty', drained['consumed'] == drained['queued'] and drained['pending'] == 0, drained)
    check('the settler never halted on a forced record', not settler_events('halt'))
    save(forced_block=number)


# ── scenario B: an off-rule block, recovered by the optional head reset ────────
def reset(gate):
    gate_slot = gate * SLOTS_PER_EPOCH
    start_net()
    until('L1 past HF3', lambda: slot() >= SLOTS_PER_EPOCH * 11, 1800)
    check('L1 is the forced flag-day build with the reset', any('rehearsal' in line for line in state()['version']), state()['version'])
    l2key('user')
    init_l2()
    # The settler stands in for an attacker: the block's timestamp departs from the rule, a real proof of the activated program.
    settler_config('1:1786657679:30000')
    start_follower()
    start_settler()
    deposit('user', 50 * SAT)
    # Block 1 is anchored at the flag day and empty; block 2 consumes the deposit.
    until('two off-rule blocks settle under the activated program', lambda: accepted_number() >= 2, 2 * 3600, 10)
    halt('settler')
    off_rule = settler_events('l2-block-produced')[:2]
    note('off-rule blocks settled', blocks=off_rule, proofs=proof_table(), inbox=view()['inbox'])
    check('L1 accepted the off-rule blocks', accepted_number() >= 2)
    check('the off-rule blocks consumed the deposit', view()['inbox']['consumed'] >= 1, view()['inbox'])
    number = accepted_number()
    until('the follower finalizes it', lambda: status()['finalized_settlements'] and status()['finalized_settlements'][-1]['l2_number'] == number, 1800, 10)
    check('the follower reports the off-rule settlement as finalized', True)
    try:
        rebuild(label='rebuild-before-reset')
        refused = None
    except RuntimeError as error:
        refused = str(error)
    note('rebuild before the gate', result=(refused or 'no refusal')[:400])
    check('an honest rebuild cannot reproduce the off-rule block: this is F1', refused is not None and 'differ from settled' in refused, (refused or '')[:200])
    before = view()
    check('before the gate the head is the off-rule block', before['accepted'] is not None)
    until('L1 reports the next program', lambda: program_is(view()['program'], NEXT_PROGRAM), gate_slot * 3 + 7200, 1)
    after = view()
    note('after the gate', accepted=after['accepted'], inbox=after['inbox'], source=after.get('source'))
    check('the gate reset the head to the L2 genesis', after['accepted'] is None, after['accepted'])
    check('the inbox cursor went back, so the deposit mints again', after['inbox']['consumed'] == 0, after['inbox'])
    check('escrow unchanged by the reset', after['inbox']['escrow_sat'] == before['inbox']['escrow_sat'], after['inbox'])
    # Recovery needs no attacker: a fresh database, the honest rule, and the same settler.
    shutil.rmtree(R / 'canonical')
    shutil.move(str(R / 'work'), str(R / 'work-off-rule'))
    (R / 'work').mkdir()
    init_l2()
    settler_config()
    start_settler()
    start_rpc()
    until('block 1 settles again under the next program', lambda: accepted_number() >= 1 and view()['accepted'] and
          bytes.fromhex(view()['accepted']['statement'])[22 + 96:22 + 128].hex() == NEXT_PROGRAM['configuration'], WAIT, 10)
    until('a second block settles', lambda: accepted_number() >= 2, WAIT, 15)
    check('the settlement stream continues from the genesis under the next program', accepted_number() >= 2, accepted_number())
    check('the deposit is minted on the recovered chain', balance_at(state()['l2_user']) >= 50 * SAT * 10 ** 10, balance_at(state()['l2_user']))
    until('L2 finalized passes the reset', lambda: any(e['configuration'] == NEXT_PROGRAM['configuration'] and e['l2_number'] >= 1 for e in status()['finalized_settlements']), WAIT, 15)
    st = status()['finalized_settlements']
    check('the follower dropped the discarded block', all(e['configuration'] == NEXT_PROGRAM['configuration'] for e in st) and [e['l2_number'] for e in st] == list(range(1, len(st) + 1)), [(e['l2_number'], e['configuration'][:8]) for e in st])
    target, report = rebuild(label='rebuild-after-reset')
    check('a rebuild from L1 now succeeds, across the reset', report['settled'] >= len(st) and report['next_rules_from'] == 1, {k: report[k] for k in ('settled', 'next_rules_from')})
    finalized = until('the RPC serves finalized on the recovered chain', lambda: l2('eth_getBlockByNumber', 'finalized', False), 600, 5)
    check('the RPC serves finalized on the recovered chain', int(finalized['number'], 16) >= 1, finalized['number'])
    note('totals', proofs=proof_table())


def main():
    command = sys.argv[1]
    if command == 'stop':
        stop_all()
        return
    gate = int(sys.argv[2])
    if R.exists():
        raise SystemExit(f'{R} exists')
    verdict = 'FAIL'
    try:
        os.makedirs(A / 'tmp-run', exist_ok=True)
        {'stream': stream, 'reset': reset}[command](gate)
        verdict = 'PASS' if not fails else 'FAIL'
    except Exception as error:  # noqa: BLE001 - the verdict file must always be written
        check('scenario ran to the end', False, f'{type(error).__name__}: {error}'[:1500])
    finally:
        (RES / 'RUN-DONE').write_text(json.dumps({'at': now(), 'verdict': verdict, 'fails': fails, 'proofs': proof_table()}) + '\n')
        stop_all()


if __name__ == '__main__':
    main()
