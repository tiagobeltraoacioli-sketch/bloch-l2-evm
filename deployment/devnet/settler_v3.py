#!/usr/bin/env python3
"""Continuous L2 settlement worker for settlement V3 (development networks only).

Derived from the devnet3 worker (l2-devnet3-20261006/settler.py, 0x0F + V2,
sha256 690427337c5109f536d807e39ee2cb88093c738245565fd6448ebf8b0bc2b32a).
Differences, all deliberate:

* settles the 766-byte V3 statement (BLOCH:EVM:SETTLEMENT:3) with the
  `bloch-evm-sp1-settlement-v3` prover and the `settlement_v3` guest;
* builds the 1155-byte native transaction under the renumbered asynchronous
  tag 0x13 (`tag || config[160:192] || values || proof`);
* checks the V3 fields before submitting: deposits_hash equals keccak over the
  native pending records, transactions/receipts roots are non-zero, the
  reserved withdrawal_root / withdrawal_count are zero, user_tx_count matches
  what the producer put in the block, and da_commitment is zero without user
  transactions or else the commitment of the block's batch (`produce da`);
* data availability (M3): before settling a block with user transactions it
  publishes the block's batch in a native `L2DataAvailability` (0x15)
  transaction and waits until `getl2settlement.data_availability` shows the
  record (the native verifier refuses the settlement otherwise). The DA
  transaction pays ordinary fees from a dedicated development funding key: it
  is prepared and signed by the pinned `bloch-pos l2-da` tool, which alone
  opens that keystore;
* `user_transactions` (default false). False: every block is deposit-only
  (`produce extend` without `--txs`) and a statement reporting any user
  transaction stops the worker. True: blocks also take pending transactions
  from `txpool_dir` within `max_block_gas` / `max_block_bytes` / `max_block_txs`.
  True is refused unless the network is a development network
  (`network_kind == "devnet"`): user transactions stay off elsewhere until L1
  data availability (milestone M3) exists. The native verifier enforces the
  same rule independently (feature `devnet-l2-user-txs`).

Each cycle: read the native request all validators agree on, extend the
canonical L2 database by exactly one block anchored to it, prove it, build the
settlement transaction, submit it and wait for native acceptance. The worker
never reads signing keys and never publishes L2 finality. Any divergence stops
the worker (exit 3) for operator review. Dependency-free Python 3.9+. The
worker never reads signing keys itself; with user transactions it invokes the
pinned DA signer (whose keystore holds only DA fee funds).
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import urllib.request

CONFIG = Path(os.environ.get('BLOCH_SETTLER_CONFIG', '/etc/bloch-l2-devnet4-settler/config.json'))
TAG = b'BLOCH:EVM:SETTLEMENT:3'
T = len(TAG)
VALUES_BYTES = 766
PROOF_BYTES = 356
ASYNC_SETTLEMENT_TAG = 0x13  # native L2SettlementAsync after the 2026-10-10 renumbering
TRANSACTION_BYTES = 1 + 32 + VALUES_BYTES + PROOF_BYTES  # 1155
SP1_CIRCUIT_VERSION = b'v6.1.0'
CHAIN_ID = 700771
# V3 field offsets after the tag (bloch_l2_evm::proof_statement::settlement_v3_layout).
DEPOSITS_HASH, TRANSACTIONS_ROOT, RECEIPTS_ROOT, USER_TX_COUNT = 568, 600, 632, 664
WITHDRAWAL_ROOT, WITHDRAWAL_COUNT, DA_COMMITMENT, V3_END = 672, 704, 712, 744
assert T + V3_END == VALUES_BYTES
# L1 data availability (bloch_l2_evm::data_availability, native l2_settlement::da).
DA_TAG = 0x15
DA_DOMAIN = b'BLOCH:L2:DA:1'
DA_MAX_PAYLOAD_BYTES = 114_688
DA_MAX_INPUTS = 16
DEFAULTS = {'user_transactions': False, 'network_kind': 'devnet', 'max_block_gas': 15_000_000,
            'max_block_bytes': 114_688, 'max_block_txs': 256}  # bytes: one native DA batch


class Halt(Exception):
    """Divergence that requires an operator; the unit must not auto-repair it."""


def log(event, **fields):
    print(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event, **fields}), flush=True)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ---- Keccak-256 (original padding, as in Ethereum), dependency-free ----
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    padded = bytearray(data) + b'\x01'
    padded += b'\x00' * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], 'little')
        state = _keccak_f(state)
    return b''.join(state[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


def deposits_hash(records):
    """bloch_l2_evm::executor::deposits_hash of the deposits minted for these
    native inbox records: keccak(recipient || height BE8 || tx_index BE4 ||
    txid || vout BE4 || sats BE8) over the records in order."""
    preimage = b''
    for r in records:
        recipient, txid = bytes.fromhex(r['recipient'].removeprefix('0x')), bytes.fromhex(r['txid'].removeprefix('0x'))
        if len(recipient) != 20 or len(txid) != 32:
            raise Halt('malformed native pending deposit')
        preimage += (recipient + int(r['height']).to_bytes(8, 'big') + int(r['tx_index']).to_bytes(4, 'big') + txid
                     + int(r['vout']).to_bytes(4, 'big') + int(r['sats']).to_bytes(8, 'big'))
    return keccak256(preimage)


def da_commitment(number, payload):
    """keccak256("BLOCH:L2:DA:1" || chain_id BE8 || l2_block_number BE8 || payload)."""
    return keccak256(DA_DOMAIN + CHAIN_ID.to_bytes(8, 'big') + int(number).to_bytes(8, 'big') + payload)


def da_batch_count(payload):
    """Number of transactions in a canonical DA batch, or None."""
    if not 4 <= len(payload) <= DA_MAX_PAYLOAD_BYTES:
        return None
    count, at = int.from_bytes(payload[:4], 'big'), 4
    for _ in range(count):
        if at + 4 > len(payload):
            return None
        size = int.from_bytes(payload[at:at + 4], 'big')
        at += 4 + size
        if size == 0 or at > len(payload):
            return None
    return count if count and at == len(payload) else None


def da_frame_fields(tx):
    """(l2_chain_id, l2_block_number, payload) of a native 0x15 wire frame:
    tag || domain[32] || u32 LE key len || key || u32 LE inputs || 36 B each ||
    chain u64 LE || number u64 LE || u32 LE payload len || payload || ...
    (bloch_pos_committee::transition::l2_da; pinned by tx-0x15.hex)."""
    def take(at, size):
        if size < 0 or at + size > len(tx):
            raise Halt('malformed DA transaction')
        return tx[at:at + size]
    if not tx or tx[0] != DA_TAG:
        raise Halt('not a DA transaction')
    at = 33
    key = int.from_bytes(take(at, 4), 'little')
    at += 4 + key
    inputs = int.from_bytes(take(at, 4), 'little')
    at += 4 + 36 * inputs
    chain, number = int.from_bytes(take(at, 8), 'little'), int.from_bytes(take(at + 8, 8), 'little')
    size = int.from_bytes(take(at + 16, 4), 'little')
    return chain, number, take(at + 20, size)


def rpc(port, method, params=()):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}', data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.loads(response.read())
    if 'error' in reply:
        raise RuntimeError(f'{method}: {reply["error"]}')
    return reply['result']


def statement_fields(hex_statement):
    s = bytes.fromhex(hex_statement)
    return {'l2_number': int.from_bytes(s[T + 264:T + 272], 'big'), 'l2_hash': s[T + 336:T + 368].hex(),
            'l2_state_root': s[T + 368:T + 400].hex(), 'source_block': s[T + 400:T + 432].hex()}


def parse_proof_artifact(data):
    """Return (values, 356-byte proof) from a persisted SP1 Groth16 proof (bincode)."""
    if len(data) > 32768 + 4096:
        raise Halt('proof artifact too large')
    position = 0

    def take(size):
        nonlocal position
        if not 0 <= size <= len(data) - position:
            raise Halt('malformed proof artifact')
        value = data[position:position + size]
        position += size
        return value

    def vector(bound):
        size = struct.unpack('<Q', take(8))[0]
        if size > bound:
            raise Halt('malformed proof artifact')
        return take(size)

    if struct.unpack('<I', take(4))[0] != 3:
        raise Halt('unexpected proof artifact version')
    for _ in range(5):
        vector(128)
    encoded = vector(704).decode('ascii')
    vector(32768)
    wrapper = take(32)
    values = vector(VALUES_BYTES)
    if (vector(64) != SP1_CIRCUIT_VERSION or take(1) != b'\0' or position != len(data) or len(values) != VALUES_BYTES
            or not values.startswith(TAG)):
        raise Halt('unexpected proof artifact framing')
    try:
        proof = wrapper[:4] + bytes.fromhex(encoded)
    except ValueError:
        raise Halt('malformed proof artifact') from None
    if len(proof) != PROOF_BYTES:
        raise Halt('unexpected proof length')
    return values, proof


class Settler:
    def __init__(self, config, rpc=rpc, run=subprocess.run, sleep=time.sleep, clock=time.monotonic):
        self.c = {**DEFAULTS, **config}
        self.rpc, self.run, self.sleep, self.clock = rpc, run, sleep, clock
        for key in ('prover', 'guest', 'l2_config'):
            if digest(self.c[key]) != self.c[key + '_sha256']:
                raise Halt(f'{key} differs from its pin')
        if 'settlement-v3' not in Path(self.c['prover']).name or 'settlement_v3' not in Path(self.c['guest']).name:
            raise Halt('settler_v3 requires the settlement V3 prover and guest')
        if not isinstance(self.c['user_transactions'], bool):
            raise Halt('user_transactions must be true or false')
        if self.c['user_transactions']:
            # Production guard (M2.6): user transactions stay on development networks only.
            if self.c['network_kind'] != 'devnet':
                raise Halt('user_transactions is refused outside development networks')
            pool = Path(self.c.get('txpool_dir', ''))
            if not self.c.get('txpool_dir') or not pool.is_dir():
                raise Halt('user_transactions requires an existing txpool_dir')
            for key in ('max_block_gas', 'max_block_bytes', 'max_block_txs'):
                if not isinstance(self.c[key], int) or self.c[key] <= 0:
                    raise Halt(f'{key} must be a positive integer')
            da = self.c.get('da')
            if not isinstance(da, dict):
                raise Halt('user_transactions requires the da signer configuration')
            for key in ('signer', 'signer_sha256', 'genesis', 'funding_pubkey', 'keystore_dir', 'passphrase_file'):
                if not da.get(key):
                    raise Halt(f'da.{key} is required')
            if digest(da['signer']) != da['signer_sha256']:
                raise Halt('da signer differs from its pin')
            self.da_script = hashlib.sha3_256(bytes.fromhex(Path(da['funding_pubkey']).read_text().strip())).hexdigest()
        self.work = Path(self.c['workdir'])

    def native_view(self):
        views = [self.rpc(p, 'getl2settlement') for p in self.c['rpc_ports']]
        if len({json.dumps(v, sort_keys=True) for v in views}) != 1:
            return None  # validators momentarily disagree; retry later
        view = views[0]
        if view['network'] != self.c['network'] or view['chain_id'] != CHAIN_ID:
            raise Halt('native network identity changed')
        return view

    def produce(self, *args):
        result = self.run([self.c['produce'], *args], capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise Halt(f'producer refused {args[0]}: {result.stderr.strip()[:400]}')
        return json.loads(result.stdout)

    def extend_arguments(self, parent, anchor, deposits):
        args = ['extend', '--target', self.c['l2_db'], '--parent', parent, '--anchor', anchor, '--deposits', str(deposits)]
        if self.c['user_transactions']:
            args += ['--txs', self.c['txpool_dir'], '--max-gas', str(self.c['max_block_gas']),
                     '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs'])]
        return args

    def prepare_block(self, view):
        """Return (number, directory) for the next block, reusing a crash-left block."""
        accepted = view.get('accepted')
        number = statement_fields(accepted['statement'])['l2_number'] + 1 if accepted else 1
        parent = statement_fields(accepted['statement'])['l2_hash'] if accepted else self.c['l2_genesis']
        anchor = view['source']['block']
        directory = self.work / f'{number:08d}-{anchor[:16]}'
        directory.mkdir(parents=True, exist_ok=True)
        source = view['source']
        pending = source.get('pending', [])
        if len(pending) != source.get('consumed_end', 0) - source.get('consumed_start', 0):
            raise Halt('native pending deposits do not match the consumed range')
        deposits = directory / 'deposits.json'
        deposits_text = json.dumps(pending, sort_keys=True)
        if deposits.exists() and deposits.read_text() != deposits_text:
            raise Halt(f'{deposits} already holds different deposits')
        deposits.write_text(deposits_text)
        head = self.produce('head', '--target', self.c['l2_db'])
        produced = directory / 'block.json'
        if head['number'] == number - 1:
            if head['hash'] != parent:
                raise Halt(f'L2 head {head["hash"]} is not the accepted parent {parent}')
            block = self.produce(*self.extend_arguments(parent, anchor, deposits))
            if block.get('transactions', 0) and not self.c['user_transactions']:
                raise Halt('producer included user transactions while user_transactions is false')
            produced.write_text(json.dumps(block, sort_keys=True) + '\n')
            log('l2-block-produced', **{k: block[k] for k in ('number', 'hash', 'deposits', 'transactions') if k in block},
                deferred=len(block.get('deferred', [])), dropped=block.get('dropped', []))
        elif head['number'] == number:
            # Crash after extend: reuse only the block built on this exact parent and anchor.
            probe = self.work / f'.probe-{number}.artifact'
            probe.unlink(missing_ok=True)
            info = self.produce('export', '--target', self.c['l2_db'], '--number', str(number), '--out', str(probe))
            probe.unlink()
            if info['anchor'] != anchor:
                raise Halt(f'unsettled L2 block {number} has anchor {info["anchor"]}, native now requests {anchor}')
            log('l2-block-reused', number=number, hash=info['hash'])
        else:
            raise Halt(f'L2 head {head["number"]} cannot extend accepted settlement {number - 1}')
        artifact = directory / 'block.artifact'
        if not artifact.exists():
            self.produce('export', '--target', self.c['l2_db'], '--number', str(number), '--out', str(artifact))
        request = directory / 'native-request.txt'
        text = view['source']['request'] + (accepted['commitment'] if accepted else '0' * 64) + '\n'
        if 'inbox_count' in source:
            text += f"{source['inbox_count']}\n{source['consumed_start']}\n{source['consumed_end']}\n"
        if request.exists() and request.read_text() != text:
            raise Halt(f'{request} already holds a different request')
        request.write_text(text)
        return number, directory

    def prove(self, directory):
        proof = directory / 'settlement.proof'
        if (directory / 'proved.json').exists():
            return proof
        # Docker mounts host paths: temporary files must live in a host-visible directory.
        env = {'PATH': '/usr/bin:/bin', 'HOME': self.c['home'], 'TMPDIR': self.c['home'] + '/tmp',
               'RAYON_NUM_THREADS': str(self.c['prover_threads']), 'SP1_CIRCUIT_MODE': 'release',
               'SP1_GNARK_IMAGE': self.c['gnark_image'],
               'BLOCH_NATIVE_L2_REQUEST': str(directory / 'native-request.txt'),
               'BLOCH_NATIVE_L2_ARTIFACT': str(directory / 'block.artifact')}
        steps = []
        for name, args in (('execute', ['execute']), ('prove', ['prove-groth16']), ('verify', ['verify-groth16'])):
            argv = [self.c['prover'], *args, 'native-artifact', self.c['guest']] + ([] if name == 'execute' else [str(proof)])
            if name == 'prove':
                proof.unlink(missing_ok=True)
            start = self.clock()
            with (directory / f'{name}.log').open('w') as out:
                result = self.run(argv, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=3600)
            steps.append({'name': name, 'exit_code': result.returncode, 'seconds': round(self.clock() - start, 1)})
            if result.returncode:
                raise RuntimeError(f'prover {name} failed: see {directory}/{name}.log')
        (directory / 'proved.json').write_text(json.dumps({'steps': steps, 'proof_sha256': digest(proof)}, indent=2) + '\n')
        log('proof-generated', directory=str(directory), seconds=sum(s['seconds'] for s in steps))
        return proof

    def check_v3(self, values, directory):
        """V3-only pre-submit checks (the V2-prefix checks are in transaction())."""
        field = lambda offset: values[T + offset:T + offset + 32]  # noqa: E731
        number = lambda offset: int.from_bytes(values[T + offset:T + offset + 8], 'big')  # noqa: E731
        pending = json.loads((directory / 'deposits.json').read_text())
        if field(DEPOSITS_HASH) != deposits_hash(pending):
            raise Halt('statement deposits_hash does not match the native pending deposits')
        if field(TRANSACTIONS_ROOT) == bytes(32) or field(RECEIPTS_ROOT) == bytes(32):
            raise Halt('statement has a zero transactions or receipts root')
        if field(WITHDRAWAL_ROOT) != bytes(32) or number(WITHDRAWAL_COUNT):
            raise Halt('statement reserved V3 fields are not zero')
        users = number(USER_TX_COUNT)
        if users and not self.c['user_transactions']:
            raise Halt(f'statement reports {users} user transactions while user_transactions is false')
        produced = directory / 'block.json'
        if produced.exists():
            expected = json.loads(produced.read_text()).get('transactions', 0)
            if users != expected:
                raise Halt(f'statement reports {users} user transactions, the producer included {expected}')
        if not users:
            if field(DA_COMMITMENT) != bytes(32):
                raise Halt('statement da_commitment is not zero without user transactions')
            return users
        payload = self.da_payload(number(264), directory)
        if da_batch_count(payload) != users:
            raise Halt('DA batch does not hold exactly the statement user transactions')
        if field(DA_COMMITMENT) != da_commitment(number(264), payload):
            raise Halt('statement da_commitment does not match the block DA batch')
        return users

    def da_payload(self, number, directory):
        """The block's canonical DA batch, exported once by the producer."""
        path = directory / 'da-payload.hex'
        if not path.exists():
            info = self.produce('da', '--target', self.c['l2_db'], '--number', str(number), '--out', str(path))
            if info.get('number') != number:
                raise Halt('producer exported the DA batch of another block')
        payload = bytes.fromhex(path.read_text().strip())
        if len(payload) > DA_MAX_PAYLOAD_BYTES:
            raise Halt('DA batch exceeds the native size cap')
        return payload

    def da_recorded(self, number, commitment):
        view = self.native_view()
        return bool(view) and any(r.get('l2_number') == number and r.get('commitment') == commitment.hex()
                                  for r in view.get('data_availability', []))

    def publish_da(self, number, directory, values):
        """Publish the block's batch on L1 and wait until the record is committed."""
        commitment = values[T + DA_COMMITMENT:T + DA_COMMITMENT + 32]
        if self.da_recorded(number, commitment):
            return True
        da = self.c['da']
        port = self.c['rpc_ports'][0]
        base_fee = str(self.rpc(port, 'getchaininfo')['next_base_fee_millisat_per_gas'])
        utxos = self.rpc(port, 'getutxos', [self.da_script, 64]).get('utxos', [])
        utxos = sorted(utxos, key=lambda u: (-int(u['value_sat']), u['txid'], u['vout']))[:DA_MAX_INPUTS]
        if not utxos:
            raise Halt('the DA funding key has no spendable outputs')
        env = {'PATH': '/usr/bin:/bin', 'HOME': self.c['home'], 'BLOCH_KEYSTORE_PASSPHRASE_FILE': da['passphrase_file']}
        attempt = 0
        while (directory / f'da-unsigned-{attempt}.hex').exists():
            attempt += 1
        unsigned, signed = directory / f'da-unsigned-{attempt}.hex', directory / f'da-signed-{attempt}.hex'
        result = None
        for count in range(1, len(utxos) + 1):
            unsigned.unlink(missing_ok=True)
            argv = [da['signer'], 'l2-da', 'prepare', '--genesis', da['genesis'], '--funding-pubkey', da['funding_pubkey'],
                    '--chain-id', str(CHAIN_ID), '--number', str(number), '--payload', str(directory / 'da-payload.hex'),
                    '--base-fee', base_fee, '--tip', str(da.get('tip_millisat_per_gas', 0)), '--out', str(unsigned)]
            for u in utxos[:count]:
                argv[3:3] = ['--input', f"{u['txid']}:{u['vout']}:{u['value_sat']}"]
            result = self.run(argv, env=env, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                break
        if result is None or result.returncode:
            raise Halt(f'DA prepare failed: {(result.stderr if result else "").strip()[:400]}')
        result = self.run([da['signer'], 'l2-da', 'sign', '--genesis', da['genesis'], '--tx', str(unsigned),
                           '--dir', da['keystore_dir'], '--out', str(signed)],
                          env=env, capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise Halt(f'DA signer refused: {result.stderr.strip()[:400]}')
        tx = bytes.fromhex(signed.read_text().strip())
        payload = bytes.fromhex((directory / 'da-payload.hex').read_text().strip())
        if da_frame_fields(tx) != (CHAIN_ID, number, payload):
            raise Halt('signed DA transaction does not carry this block batch')
        response = self.rpc(port, 'sendrawtransaction', [tx.hex()])
        log('da-submitted', number=number, bytes=len(tx), commitment=commitment.hex(), response=response.get('status'))
        deadline = self.clock() + da.get('inclusion_timeout_seconds', 300)
        while self.clock() < deadline:
            self.sleep(6)
            if self.da_recorded(number, commitment):
                log('da-included', number=number, commitment=commitment.hex())
                return True
        log('da-inclusion-timeout', number=number)
        return False

    def transaction(self, directory, proof_path):
        values, proof = parse_proof_artifact(proof_path.read_bytes())
        config = Path(self.c['l2_config']).read_bytes()
        request = (directory / 'native-request.txt').read_text().splitlines()
        checks = [values[T:T + 32].hex() == request[0], values[T + 32:T + 64].hex() == request[1],
                  values[T + 400:T + 432].hex() == request[2], int.from_bytes(values[T + 432:T + 440], 'big') == int(request[3]),
                  int.from_bytes(values[T + 440:T + 448], 'big') == int(request[4]),
                  values[T + 448:T + 480].hex() == request[5], values[T + 480:T + 512].hex() == request[6],
                  values[T + 224:T + 256].hex() == request[7], values[T + 64:T + 224] == config[:160]]
        inbox = [int(x) for x in request[8:11]] if len(request) == 11 else [0, 0, 0]
        checks += [int.from_bytes(values[T + 512 + 8 * i:T + 520 + 8 * i], 'big') == inbox[i] for i in range(3)]
        if not all(checks):
            raise Halt('proof public values do not match the native request')
        users = self.check_v3(values, directory)
        tx = bytes([ASYNC_SETTLEMENT_TAG]) + config[160:192] + values + proof
        if len(tx) != TRANSACTION_BYTES:
            raise Halt('settlement transaction has the wrong length')
        (directory / 'transaction.bin').write_bytes(tx)
        log('transaction-built', directory=str(directory), user_transactions=users, bytes=len(tx))
        return tx

    def submit_and_wait(self, number, directory, tx, view):
        current = self.native_view()
        if current is None or current['source'] != view['source'] or current.get('accepted') != view.get('accepted'):
            log('request-moved-before-submit', number=number)
            return False
        response = self.rpc(self.c['rpc_ports'][0], 'sendrawtransaction', [tx.hex()])
        log('submitted', number=number, response=response.get('status'), tx_hash=response.get('tx_hash'))
        deadline = self.clock() + self.c['acceptance_timeout_seconds']
        while self.clock() < deadline:
            self.sleep(6)
            current = self.native_view()
            accepted = current and current.get('accepted')
            if accepted and statement_fields(accepted['statement'])['l2_number'] == number:
                (directory / 'accepted.json').write_text(json.dumps(accepted, indent=2) + '\n')
                log('accepted', number=number, commitment=accepted['commitment'],
                    l2_hash=statement_fields(accepted['statement'])['l2_hash'])
                return True
        log('acceptance-timeout', number=number)
        return False

    def cycle(self):
        view = self.native_view()
        if view is None or view.get('source') is None:
            return False
        number, directory = self.prepare_block(view)
        proof = self.prove(directory)
        tx = self.transaction(directory, proof)
        values = tx[33:33 + VALUES_BYTES]
        if int.from_bytes(values[T + USER_TX_COUNT:T + USER_TX_COUNT + 8], 'big') and \
                not self.publish_da(number, directory, values):
            return False
        return self.submit_and_wait(number, directory, tx, view)


def main():
    config = json.loads(CONFIG.read_text())
    try:
        settler = Settler(config)
    except Halt as error:
        log('halt', reason=str(error))
        sys.exit(3)
    log('started', network=config['network'], user_transactions=settler.c['user_transactions'])
    failures = 0
    while True:
        try:
            progressed = settler.cycle()
            failures = 0
            time.sleep(1 if progressed else config['idle_seconds'])
        except Halt as error:
            log('halt', reason=str(error))
            sys.exit(3)  # RestartPreventExitStatus=3: wait for an operator
        except Exception as error:  # transient RPC/prover failure: bounded retry
            failures += 1
            log('retry', reason=f'{type(error).__name__}: {error}'[:500], failures=failures)
            if failures >= config['max_consecutive_failures']:
                sys.exit(1)
            time.sleep(min(300, 15 * failures))


if __name__ == '__main__':
    main()
