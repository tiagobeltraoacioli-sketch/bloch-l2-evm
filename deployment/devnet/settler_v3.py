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
  native pending records, transactions/receipts roots are non-zero,
  user_tx_count matches what the producer put in the block, da_commitment is
  zero without user transactions or else the commitment of the block's batch
  (`produce da`), and (M4) withdrawal_root / withdrawal_count equal what the
  producer reported for the block and follow the native rules against the
  accepted head: the count never decreases and the root changes exactly when
  the count does (the empty tree before any withdrawal);
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

* `remote_prover` (optional, devnet4): the Groth16 proof may be generated on
  a second CPU host over SSH (`remote_prover.py`, a forced command bound to a
  dedicated key). Only the request and the execution artifact leave this host;
  `execute` before and `verify-groth16` after still run here with the pinned
  local prover and guest, so a wrong or foreign remote proof is never
  submitted. `order` lists where to prove, tried in turn until one succeeds:
  ["local", "remote"] (default) keeps the remote host as a fallback,
  ["remote", "local"] prefers it, ["remote"] never proves here.
  `local_prove_max_instructions` (optional): a local proof is refused when
  the block's `execute` count is above it or unknown, so a block that cannot
  be proved within this unit's memory cap is never tried here (proof memory
  grows with instructions; an OOM would only delay the retry).

* native RPC quorum (devnet4, 2026-10-16): the worker no longer needs every
  validator RPC in `rpc_ports`. Safety-relevant reads (the `getl2settlement`
  view: request, accepted head, pending deposits, DA records) are used only
  when at least `rpc_quorum` endpoints (default: a strict majority, 2 of 3)
  return the identical answer; a minority answer is never used. Submission
  (`sendrawtransaction`) goes to the first usable endpoint that takes it, since
  L1 consensus validates the transaction itself. The DA base fee and funding
  outputs also need a quorum of answers. A failing endpoint is skipped with
  exponential backoff; with every endpoint healthy and in agreement the worker
  behaves as before. `getl2settlement` takes no block argument (it answers from
  each node's head), so the quorum compares only the fields the worker uses
  (`SETTLEMENT_VIEW_FIELDS`), not the per-block `native_height` or withdrawal
  bookkeeping, and a split read is retried a few times within seconds before
  it counts as no quorum. `--check-rpc` prints the per-endpoint view and the quorum
  decision and exits without producing, proving or submitting anything.

* mainnet profile (`network_kind: "mainnet"`, Bloch L2 chain 700770, native
  activation at epoch 5850): every identity is pinned in `MAINNET` and checked
  against the configuration and, by quorum, against the live network
  (admission domain, native genesis, chain id, async mode, activated profile,
  3-of-5 attestor set hash); the 264-byte l2-config.bin must equal the bytes
  `mainnet_l2_config()` derives from the pins (proof policy V3 154869964f…);
  the guest must be `settlement_v3_mainnet` (SHA-256 203114bf…); the producer
  gets `--rules mainnet --domain … --genesis-time …` and the wall-clock
  timestamp rule from block 1, the prover `--mainnet`. The native RPCs are
  `rpc_urls` (at least three distinct hosts, quorum at least two) instead of
  loopback `rpc_ports`. User transactions are admitted by the activated
  profile and stay a configuration switch (DA fees are paid by the dedicated
  fee key; the 0x13 settlement itself pays no fee).

* mainnet-rehearsal profile (`network_kind: "mainnet-rehearsal"`): the private
  mainnet-path rehearsal of 2026-10-18 (native qualification build
  `l2-activation-rehearsal-mainnet-policy`). Same program path as mainnet
  (chain 700770, pinned l2-config, guest and L2 genesis, producer `--rules
  mainnet`, prover `--mainnet`) on a private network whose identity, RPC ports
  and timestamp rule come from the configuration; refused on Genesis-4.
  `prover_path` sets the prover's PATH (e.g. a docker shim directory).

* producer failures (security review 2026-10-18, finding 2): a producer
  refusal is retryable, never a permanent halt. When an extend with the
  user-transaction spool fails, the same block is retried once without the
  spool (deposits only), so a poisoned spool cannot stop settlement; any other
  producer failure is retried with backoff up to `max_consecutive_failures`,
  then the process exits 1 and its unit restarts it (Restart=on-failure).

* submission robustness (2026-10-18; devnet4 looped on block 231 while its L1
  was halted): the signed bytes of a block are reused until it is accepted or
  its request moves; a `duplicate` answer means the node already holds or
  recently included those bytes; "one L2 proof is already pending" and
  retryable refusals wait; the same bytes are rebroadcast every
  `resubmit_seconds`; an acceptance timeout records whether the L1 head moved
  (`l1-not-advancing`) and never counts as a worker failure; a terminal
  refusal (policy/source/successor/proof) is re-checked against the quorum
  view and halts unless the request moved; a different statement accepted
  for the same L2 block halts (another settler).

* foreign settlements (security review 2026-10-30, F3; optional `foreign_recovery`): settling needs no
  authorization, so a third party can settle a rule-conforming block the local database does not hold.
  With `foreign_recovery` the worker waits until the native follower has finalized the accepted
  settlement, rebuilds a NEW database from verified L1 blocks (`produce reconstruct`, which refuses an
  off-rule block), requires its head to be the accepted hash, returns the user transactions of orphaned
  local blocks to the spool, moves their work directories aside (so no DA batch of theirs is ever paid
  again), swaps the databases and continues. A refused rebuild still halts (exit 3): that is an off-rule
  block or local damage. Without `foreign_recovery` any foreign statement halts, as before. Readers of
  the database must reopen it after a swap: the worker rewrites `<workdir>/../l2-db-generation.json`,
  which a systemd path unit watches to restart the settled RPC.
* program swap (`next_program`, candidate; native `L2_NEXT_PROGRAM_EPOCH` inert):
  L1 replaces the program at a compiled epoch boundary and reports it in
  `getl2settlement.program`. Each cycle follows that report: the block, the prover,
  the guest and the l2-config are those of the program L1 holds now. A block built
  under the old rules and not settled when the program moved can never settle: it
  is rewound (its user transactions go back to the spool), its work directory is
  kept aside as `.superseded-*`, and the same number is built, proved and submitted
  under the new rules. Nothing stops and no operator is needed. `prover_args`
  selects the host flag of each program: the release host takes `--mainnet` for the
  activated program; a host that serves both takes `--mainnet-v1` for it and
  `--mainnet` for the next one. Without `next_program` the worker behaves as before.

* L1 forced inclusion (candidate; native `L2_FORCED_INCLUSION_EPOCH` inert): once the native queue is enabled,
  `getl2settlement.forced.due` names the forced records (with their envelopes) the next settlement must consume.
  The worker writes them to `forced.json` beside `deposits.json` (a crash-left file must match), passes
  `--forced` to the producer, which runs them first after the deposits and outside every sequencer limit
  (including the SP1-gas budget, like deposits), and checks before submission that the statement's
  `deposits_hash` slot is `inbox_hash(deposits_hash, due)` and `user_tx_count` the sequencer's part only; the DA
  batch covers only that part, so a forced-only block publishes none. A due or queued record makes a block due
  under `skip_idle_blocks`. A record whose envelope the node cannot read is waited for, never guessed.
  `censor_senders` (rehearsal only, refused on mainnet) moves the spool entries of listed L2 senders aside, to
  rehearse a censoring sequencer.

* `--dry-run [--prove]`: builds the next settlement against the live network
  in a scratch copy of the L2 database and validates it (identity, request,
  producer, SP1 execute; with --prove also Groth16 + every pre-submit check)
  without ever calling sendrawtransaction or signing anything.

Each cycle: read the native request all validators agree on, extend the
canonical L2 database by exactly one block anchored to it, prove it, build the
settlement transaction, submit it and wait for native acceptance. The worker
never reads signing keys and never publishes L2 finality. Any divergence stops
the worker (exit 3) for operator review. Dependency-free Python 3.9+. The
worker never reads signing keys itself; with user transactions it invokes the
pinned DA signer (whose keystore holds only DA fee funds).
"""
import itertools
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import types
import urllib.parse
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
# L2 -> L1 withdrawals (bloch_l2_evm::withdrawal, native l2_settlement::withdrawal).
WITHDRAWAL_DOMAIN = b'BLOCH:L2:WITHDRAW:1'
WITHDRAWAL_TREE_DEPTH = 32
# remote_prover.py framing: magic, u32 request length, request, u64 artifact length, artifact.
REMOTE_MAGIC = b'BLOCH:L2:PROVE:1\n'
REMOTE_MAX_PROOF_BYTES = 1 << 20
RPC_BACKOFF_SECONDS, RPC_MAX_BACKOFF_SECONDS = 10, 300
RPC_DIVERGED_LOG_AFTER = 3  # consecutive reads outside the quorum before an endpoint is reported
QUORUM_READ_ATTEMPTS, QUORUM_RETRY_SECONDS = 3, 1  # fresh re-reads when healthy endpoints straddle a block
# The getl2settlement fields the worker reads; everything else (native_height,
# inbox totals, withdrawal bookkeeping) moves with every head and is not used.
FRESH_SOURCE_SECONDS = 600  # skip_idle_blocks: a source older than this (above the pacing) takes no user transaction
SETTLEMENT_VIEW_FIELDS = ('network', 'genesis', 'chain_id', 'asynchronous', 'accepted', 'source', 'data_availability', 'program',
                          'forced')
# Of `getl2settlement.forced` (present only once L1 forced inclusion is enabled) the worker reads the records the next
# settlement must consume; queue totals and the surcharge move with every L1 block and are not part of the quorum.
FORCED_VIEW_FIELDS = ('due', 'due_hash')
# L1 forced inclusion (candidate; native l2_settlement::forced, bloch_l2_evm::forced_inclusion).
INBOX_DOMAIN = b'BLOCH:L2:INBOX:2'
FORCED_MAX_PER_SETTLEMENT, FORCED_MAX_GAS_PER_SETTLEMENT = 16, 300_000
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sequencer_policy  # noqa: E402  (installed beside this file)

SPOOL_READ_LIMIT = 16_384  # the producer's MAX_POOL_ENTRIES
DEFAULTS = {'user_transactions': False, 'network_kind': 'devnet', 'max_block_gas': 15_000_000,
            'max_block_bytes': 114_688, 'max_block_txs': 128,  # bytes: one native DA batch
            'poll_seconds': 6, 'resubmit_seconds': 120}
NETWORK_KINDS = ('devnet', 'mainnet', 'mainnet-rehearsal')
# Kinds that run the mainnet L2 program path (chain 700770, --rules mainnet, prover --mainnet).
MAINNET_PATH_KINDS = ('mainnet', 'mainnet-rehearsal')

# ---- Bloch L2 mainnet (chain 700770), activated on Genesis-4 at epoch 5850 ----
# Sources: bloch-sis-pow l2_settlement::mainnet (release 78b7343a), docs/MAINNET-PROGRAM.md.
MAINNET = {
    'chain_id': 700770,
    'network': 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',  # admission domain
    'genesis': '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415',  # native genesis id
    'l2_domain': '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
    'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',
    'elf_keccak': '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',
    'vkey_koalabear': '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',
    'vkey_bn254': '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e',
    'proof_policy': '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d',
    'l2_genesis': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
    'l2_genesis_state': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d',
    'guest_sha256': '203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473',  # settlement_v3_mainnet
    'genesis_time': 1786656679,
    'slot_ms': 30_000,
    'attestor_set': '1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b',  # 3-of-5
}
MAINNET_L2_CONFIG_SHA256 = '292f4fa8d5a949a26c20317cfc9360d53afda4779b298f1841107985ca5c4f6b'
MAINNET_TIMESTAMP_RULE = f"1:{MAINNET['genesis_time']}:{MAINNET['slot_ms']}"
MAINNET_PRODUCE_ARGS = ('--rules', 'mainnet', '--domain', MAINNET['l2_domain'],
                        '--genesis-time', str(MAINNET['genesis_time']))
MAINNET_DEFAULTS = {'poll_seconds': 15, 'resubmit_seconds': 300, 'timestamp_rule': MAINNET_TIMESTAMP_RULE}


def mainnet_l2_config(program=None):
    """The 264-byte l2-config.bin of chain 700770 (layout of devnet4/make_l2_config.py)."""
    pins = {**MAINNET, **(program or {})}
    out = b''.join(bytes.fromhex(pins[k]) for k in ('l2_domain', 'configuration', 'elf_keccak',
                                                    'vkey_koalabear', 'vkey_bn254', 'proof_policy'))
    out += MAINNET['chain_id'].to_bytes(8, 'little')
    return out + bytes.fromhex(MAINNET['l2_genesis']) + bytes.fromhex(MAINNET['l2_genesis_state'])


# CANDIDATE, not scheduled: the program native `l2_settlement::mainnet::PROGRAM_NEXT` installs at the
# gate. Its configuration carries a placeholder fee-sweep recipient (TBD-owner), so all of these move
# when the recipient is fixed. The proof policy, the L2 genesis and the attestor set stay.
MAINNET_NEXT = {
    'configuration': '975ec2585246abeaea86421dd5726918b632dd91a246f635fe74990b68bcd878',
    'elf_keccak': 'f3c20f71b84bb09cbab76a75c83a62c507fbefff4b347f787ef2d89aceb6f2b8',
    'vkey_koalabear': '50bd69a513f2463e748a8a62277bc25a08df69a4420a660e2a2ee3f957dca9f7',
    'vkey_bn254': '00a17ad34a4fc918fba454531277bc25a11bed3490829983951771fcd7dca9f7',
    'guest_sha256': '44d4c9d7b828c13ee6edc06fa499a53dc3594243bf599d517432c5076cb6ce47',
}

# CANDIDATE, not scheduled: the same next rules proved by the sparse-witness guest
# (`settlement_v3_mainnet_sparse` bc35e838, the pinned container build of bloch-l2-evm
# codex/forced-guest-r8-20261102 595d914: code-by-hash witness and L1 forced inclusion, artifact
# format SPARSE:3). The native candidate (bloch-sis-pow codex/forced-guest-native-r8-20261102) names
# this ELF in `PROGRAM_NEXT`. Its configuration is the next rules with forced inclusion (tag 4,
# b4663ab8); the complete-witness fallback keeps 975ec258 and does not implement forced inclusion.
# A `next_program` with `"witness": "sparse"` must match this pin, exports the sparse artifact
# (`produce export --witness sparse`) and runs the prover with `--mainnet --sparse`.
MAINNET_NEXT_SPARSE = {
    'configuration': 'b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d',
    'elf_keccak': '1f744da8d3e0302cd39152e24e91071d7f0cfec7639245566a471cd6083a6b18',
    'vkey_koalabear': '6a140f117b84dd524b3681b9447422e5281451295144b5747197d0df5db6afc9',
    'vkey_bn254': '00d4281e23ee13754a59b40dcc47422e55028a2534512d5d38cbe86fddb6afc9',
    'guest_sha256': 'bc35e8383e08dbe86376564387ab98a903a188cbc2f4c686051b6cd560a7b048',
}

# CANDIDATE, not scheduled: native `PROGRAM_FALLBACK`, which `L2_PROGRAM_ROLLBACK_EPOCH` (inert) installs
# in place of the sparse `PROGRAM_NEXT`: the same next rules proved by the complete-witness guest, so its
# pins are those of MAINNET_NEXT. A `fallback_program` must match them; it needs a sparse `next_program`.
# At a rollback the rules do not change: no block is rewound, the block in flight is only proved again.
MAINNET_FALLBACK = MAINNET_NEXT


# ---- L1 fee estimate for the DA (0x15) transaction (bloch-pos-committee fee_market, l2_da) ----
GAS_PER_BYTE, TX_FLAT_GAS, HYBRID_VERIFY_GAS = 16, 5_000, 72_748
PQ_KEY_BYTES, PQ_SIGNATURE_MAX = 3_749, 4_593
MIN_BASE_FEE_MILLISAT_PER_GAS = 10


def da_fee_sat(payload_bytes, inputs=1, base_fee_millisat_per_gas=MIN_BASE_FEE_MILLISAT_PER_GAS, tip=0):
    """Satoshis a 0x15 transaction pays: declared bytes = the witness-free encoding
    plus the worst-case signature (what `bloch-pos l2-da prepare` declares),
    gas = flat + 16/byte + one hybrid verification per input, rounded up."""
    tx_bytes = 1 + 32 + 4 + PQ_KEY_BYTES + 4 + 36 * inputs + 8 + 8 + 4 + payload_bytes + 8 + 32 + 8 + 16 + 4 \
        + PQ_SIGNATURE_MAX
    gas = TX_FLAT_GAS + GAS_PER_BYTE * tx_bytes + HYBRID_VERIFY_GAS * inputs
    part = lambda price: -(-gas * price // 1000)  # noqa: E731
    return part(base_fee_millisat_per_gas) + part(tip)


class WaitForProgram(RuntimeError):
    """L1 reports the old program while the L2 head already runs the next rules: an L1 reorganization
    across the gate. The next epoch boundary on any branch installs it again, so this only waits."""


class WaitForForcedEnvelope(WaitForProgram):
    """A due forced record whose envelope the node could not read from its L1 block (`"envelope": null`): retried,
    because no settlement on this source can be built without it."""


class ProducerError(RuntimeError):
    """bloch-l2-produce-dev refused a command: retryable (bounded), never a permanent halt."""


def follower_verified_tip(status_path):
    """How far the follower has verified, to tell whether a rebuild has new input."""
    return json.loads(Path(status_path).read_text()).get('verified_tip')


def follower_finals(status_path):
    """{L2 number: L2 hash} of every finalized settlement in a follower status file: the list in schema v2, or
    the log a schema v3 status names (the part the status covers; a crash can leave more after it)."""
    status = json.loads(Path(status_path).read_text())
    log_doc = status.get('settlement_log')
    if log_doc is None:
        return {x['l2_number']: x['l2_hash'] for x in status.get('finalized_settlements', [])}
    name = log_doc['file']
    if not name or '/' in name or name in ('.', '..'):
        raise Halt('the follower status names a bad settlement log')
    if not log_doc['entries']:
        return {}
    with open(Path(status_path).with_name(name), 'rb') as f:
        data = f.read(log_doc['bytes'])
    lines = data.splitlines()
    if len(data) != log_doc['bytes'] or len(lines) != log_doc['entries']:
        raise Halt('the follower settlement log does not match its status')
    entries = [json.loads(line) for line in lines]
    return {x['l2_number']: x['l2_hash'] for x in entries}


class Halt(Exception):
    """Divergence that requires an operator; the unit must not auto-repair it."""


class RpcError(RuntimeError):
    """The endpoint answered with a JSON-RPC error."""


class ForeignSettlement(Exception):
    """L1 accepted a settlement the local database does not hold: recoverable with `foreign_recovery`."""


def log(event, **fields):
    print(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event, **fields}), flush=True)


def atomic_write(path, data):
    """Replace `path` whole or not at all: a crash or a full disk never leaves a truncated state file,
    which the next cycle would read as a conflicting request or as corrupt JSON."""
    path = Path(path)
    temporary = path.with_name(f'.{path.name}.tmp')
    payload = data.encode() if isinstance(data, str) else data
    try:
        with temporary.open('wb') as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


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


# ---- rehearsal-only: the sender of an L2 envelope (the `censor_senders` knob, never on mainnet) ----
SECP_P = 2 ** 256 - 2 ** 32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SECP_P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, SECP_P)
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, SECP_P)
    x = (m * m - a[0] - b[0]) % SECP_P
    return x, (m * (a[0] - x) - a[1]) % SECP_P


def _ec_mul(k, point):
    out = None
    while k:
        if k & 1:
            out = _ec_add(out, point)
        point, k = _ec_add(point, point), k >> 1
    return out


def rlp_decode(data):
    """Minimal RLP decoder: bytes or nested lists of bytes. Refuses trailing bytes."""
    def item(at):
        b = data[at]
        if b < 0x80:
            return data[at:at + 1], at + 1
        if b < 0xb8:
            return data[at + 1:at + 1 + b - 0x80], at + 1 + b - 0x80
        if b < 0xc0:
            n = b - 0xb7
            size = int.from_bytes(data[at + 1:at + 1 + n], 'big')
            return data[at + 1 + n:at + 1 + n + size], at + 1 + n + size
        if b < 0xf8:
            start, end = at + 1, at + 1 + b - 0xc0
        else:
            n = b - 0xf7
            start = at + 1 + n
            end = start + int.from_bytes(data[at + 1:at + 1 + n], 'big')
        out, cursor = [], start
        while cursor < end:
            value, cursor = item(cursor)
            out.append(value)
        if cursor != end:
            raise ValueError('rlp list length')
        return out, end
    value, end = item(0)
    if end != len(data):
        raise ValueError('rlp trailing bytes')
    return value


def rlp_encode(value):
    if isinstance(value, list):
        body = b''.join(rlp_encode(v) for v in value)
        return (bytes([0xc0 + len(body)]) if len(body) < 56 else
                bytes([0xf7 + (len(body).bit_length() + 7) // 8]) + len(body).to_bytes((len(body).bit_length() + 7) // 8, 'big')) + body
    if len(value) == 1 and value[0] < 0x80:
        return value
    return (bytes([0x80 + len(value)]) if len(value) < 56 else
            bytes([0xb7 + (len(value).bit_length() + 7) // 8]) + len(value).to_bytes((len(value).bit_length() + 7) // 8, 'big')) + value


def ecrecover_address(digest, recid, r, s):
    """The 20-byte address that signed `digest`, or None."""
    if not (0 < r < SECP_N and 0 < s < SECP_N) or recid not in (0, 1):
        return None
    y = pow((r ** 3 + 7) % SECP_P, (SECP_P + 1) // 4, SECP_P)
    if (r ** 3 + 7 - y * y) % SECP_P:
        return None
    if (y & 1) != recid:
        y = SECP_P - y
    e = int.from_bytes(digest, 'big')
    inv = pow(r, -1, SECP_N)
    q = _ec_add(_ec_mul(s * inv % SECP_N, (r, y)), _ec_mul((-e * inv) % SECP_N, SECP_G))
    if q is None:
        return None
    return keccak256(q[0].to_bytes(32, 'big') + q[1].to_bytes(32, 'big'))[12:]


def envelope_sender(raw):
    """The sender of a signed L2 envelope (legacy/EIP-155, EIP-2930 or EIP-1559), or None if it does not parse.
    Rehearsal tooling only: the producer, not this, authenticates what a block contains."""
    try:
        num = lambda b: int.from_bytes(b, 'big')  # noqa: E731
        if raw and raw[0] in (1, 2):
            fields = rlp_decode(raw[1:])
            unsigned, (parity, r, s) = fields[:-3], fields[-3:]
            return ecrecover_address(keccak256(raw[:1] + rlp_encode(unsigned)), num(parity), num(r), num(s))
        fields = rlp_decode(raw)
        v, r, s = num(fields[6]), num(fields[7]), num(fields[8])
        if v in (27, 28):
            return ecrecover_address(keccak256(rlp_encode(fields[:6])), v - 27, r, s)
        chain_id = (v - 35) // 2
        unsigned = fields[:6] + [chain_id.to_bytes((chain_id.bit_length() + 7) // 8, 'big'), b'', b'']
        return ecrecover_address(keccak256(rlp_encode(unsigned)), (v - 35) % 2, r, s)
    except (ValueError, IndexError, TypeError):
        return None


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


def forced_record(r):
    """The 80-byte native record: height BE8 || l1_txid || envelope_hash || gas_limit BE8."""
    txid, envelope_hash = bytes.fromhex(strip0x(r['l1_txid'])), bytes.fromhex(strip0x(r['envelope_hash']))
    if len(txid) != 32 or len(envelope_hash) != 32:
        raise Halt('malformed native forced record')
    return int(r['height']).to_bytes(8, 'big') + txid + envelope_hash + int(r['gas_limit']).to_bytes(8, 'big')


def forced_hash(records):
    """keccak256 of the concatenated forced records (keccak256(b'') when empty)."""
    return keccak256(b''.join(forced_record(r) for r in records))


def inbox_hash(deposit_hash, records):
    """The V3 `deposits_hash` slot under forced inclusion: the deposits hash itself when no forced record is consumed,
    else keccak256("BLOCH:L2:INBOX:2" || deposits_hash || forced_hash)."""
    if not records:
        return deposit_hash
    return keccak256(INBOX_DOMAIN + deposit_hash + forced_hash(records))


def strip0x(value):
    return str(value).removeprefix('0x')


def forced_due(view):
    """The forced records the next settlement must consume, normalised (hex without 0x), or None while the native
    queue is not enabled. Each record keeps the envelope the producer needs. Refuses a malformed or over-cap list."""
    forced = view.get('forced') if isinstance(view, dict) else None
    if forced is None:
        return None
    due = forced.get('due')
    if not isinstance(due, list) or len(due) > FORCED_MAX_PER_SETTLEMENT:
        raise Halt('native forced.due is malformed or above the per-settlement cap')
    out = []
    for r in due:
        if isinstance(r, dict) and r.get('envelope') is None:
            raise WaitForForcedEnvelope(f'the node reports no envelope for forced record {r.get("l1_txid")}')
        try:
            record = {'height': int(r['height']), 'l1_txid': strip0x(r['l1_txid']).lower(),
                      'envelope_hash': strip0x(r['envelope_hash']).lower(), 'gas_limit': int(r['gas_limit']),
                      'envelope': strip0x(r['envelope']).lower()}
            envelope = bytes.fromhex(record['envelope'])
        except (KeyError, TypeError, ValueError):
            raise Halt('native forced record is malformed or carries no envelope') from None
        forced_record(record)
        if keccak256(envelope).hex() != record['envelope_hash']:
            raise Halt('native forced record envelope does not hash to its envelope_hash')
        out.append(record)
    if sum(r['gas_limit'] for r in out) > FORCED_MAX_GAS_PER_SETTLEMENT:
        raise Halt('native forced.due declares more gas than one settlement consumes')
    if 'due_hash' in forced and strip0x(forced['due_hash']).lower() != forced_hash(out).hex():
        raise Halt('native forced.due_hash does not match its records')
    return out


def user_count(block):
    """The sequencer's transactions in a producer block report: `user_transactions` when the block ran forced
    envelopes (they are not user transactions of the statement and not in its DA batch), else `transactions`."""
    return int(block.get('user_transactions', block.get('transactions', 0)))


def check_forced_block(block, due):
    """The producer consumed exactly the due forced records: every one was run first, included or skipped."""
    report = block.get('forced')
    if not due:
        if report and int(report.get('due', 0)):
            raise Halt('producer consumed forced records the native view does not name')
        return
    if not isinstance(report, dict) or int(report.get('due', -1)) != len(due):
        raise Halt(f'producer did not consume the {len(due)} due forced records')
    included, skipped = int(report.get('included', -1)), len(report.get('skipped', []))
    if included < 0 or included + skipped != len(due):
        raise Halt('producer forced report does not account for every due record')
    if int(block.get('transactions', 0)) - included != user_count(block):
        raise Halt('producer user_transactions is not the body minus the included forced envelopes')


def read_forced(directory):
    """The forced records a block directory was built with (forced.json), [] without the file."""
    path = Path(directory) / 'forced.json'
    return json.loads(path.read_text()) if path.exists() else []


def withdrawal_leaf(chain_id, nonce, l1_recipient, sats):
    """keccak256("BLOCH:L2:WITHDRAW:1" || chain_id BE8 || nonce BE8 || l1_recipient || sats BE8)."""
    if len(l1_recipient) != 32:
        raise ValueError('l1_recipient must be 32 bytes')
    return keccak256(WITHDRAWAL_DOMAIN + chain_id.to_bytes(8, 'big') + nonce.to_bytes(8, 'big') + l1_recipient
                     + sats.to_bytes(8, 'big'))


def _zero_hashes():
    zero = [bytes(32)]
    for _ in range(WITHDRAWAL_TREE_DEPTH):
        zero.append(keccak256(zero[-1] + zero[-1]))
    return zero


ZERO_HASHES = _zero_hashes()
EMPTY_WITHDRAWAL_ROOT = ZERO_HASHES[WITHDRAWAL_TREE_DEPTH]


def withdrawal_tree_root(leaves):
    """Root of the depth-32 keccak tree over `leaves` (empty leaves are zero)."""
    level = list(leaves)
    if len(level) > 1 << WITHDRAWAL_TREE_DEPTH:
        raise ValueError('too many leaves')
    for h in range(WITHDRAWAL_TREE_DEPTH):
        if not level:
            return EMPTY_WITHDRAWAL_ROOT
        if len(level) % 2:
            level.append(ZERO_HASHES[h])
        level = [keccak256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def withdrawal_root_from_proof(leaf, index, siblings):
    """Fold a leaf with its 32 bottom-up siblings into the root it proves."""
    if len(siblings) != WITHDRAWAL_TREE_DEPTH or not 0 <= index < 1 << WITHDRAWAL_TREE_DEPTH:
        return None
    node = leaf
    for h, sibling in enumerate(siblings):
        node = keccak256(sibling + node) if (index >> h) & 1 else keccak256(node + sibling)
    return node


def withdrawal_fields(values):
    """(root, count) of a V3 statement; the empty tree for a V2 statement or none."""
    if values is None or len(values) != VALUES_BYTES or not values.startswith(TAG):
        return EMPTY_WITHDRAWAL_ROOT, 0
    return (values[T + WITHDRAWAL_ROOT:T + WITHDRAWAL_ROOT + 32],
            int.from_bytes(values[T + WITHDRAWAL_COUNT:T + WITHDRAWAL_COUNT + 8], 'big'))


def check_withdrawals(values, previous):
    """The native acceptance rule: the withdrawal count never decreases and the
    root changes exactly when the count does. Returns (root, count)."""
    root, count = withdrawal_fields(values)
    previous_root, previous_count = withdrawal_fields(previous)
    if count < previous_count:
        raise Halt(f'statement withdrawal count {count} is below the accepted {previous_count}')
    if (count == previous_count) != (root == previous_root):
        raise Halt('statement withdrawal root must change exactly when the withdrawal count does')
    return root, count


def da_commitment(number, payload, chain_id=CHAIN_ID):
    """keccak256("BLOCH:L2:DA:1" || chain_id BE8 || l2_block_number BE8 || payload)."""
    return keccak256(DA_DOMAIN + chain_id.to_bytes(8, 'big') + int(number).to_bytes(8, 'big') + payload)


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


def da_frame_key(tx):
    """The funding public key of a native 0x15 wire frame (the spend authority that paid its fee)."""
    if len(tx) < 37 or tx[0] != DA_TAG:
        raise Halt('not a DA transaction')
    size = int.from_bytes(tx[33:37], 'little')
    if 37 + size > len(tx):
        raise Halt('malformed DA transaction')
    return tx[37:37 + size]


def follower_block_files(state_dir):
    """The follower's verified native blocks, in index order: [Path]."""
    state = Path(state_dir)
    lines = (state / 'index').read_text().split()
    return [state / 'blocks' / f'{line.strip().lower()}.bin' for line in lines if line.strip()]


def scan_da_frames(data, chain_id, wanted):
    """{(number, commitment hex): (funding key, payload)} of the 0x15 frames inside raw block bytes whose
    (l2 number, commitment) is in `wanted`. Candidate offsets are only a search: a hit is the frame whose payload
    hashes to a recorded commitment, so a false match is impossible."""
    found, at = {}, data.find(bytes([DA_TAG]))
    numbers = {number for number, _ in wanted}
    while at >= 0 and len(found) < len(wanted):
        try:
            frame = data[at:]
            chain, number, payload = da_frame_fields(frame)
            if chain == chain_id and number in numbers and da_batch_count(payload) is not None:
                key = (number, da_commitment(number, payload, chain_id).hex())
                if key in wanted and key not in found:
                    found[key] = (da_frame_key(frame), payload)
        except Halt:
            pass
        at = data.find(bytes([DA_TAG]), at + 1)
    return found


def recorded_da_batches(state_dir, chain_id, records, window=8):
    """{(number, commitment hex): (funding key, payload)} for DA `records` (getl2settlement entries with
    l2_number, commitment, height), read from the follower's verified L1 blocks near each record's height. Records
    whose block is not (yet) in the follower store are left out."""
    wanted = {(int(r['l2_number']), r['commitment']) for r in records}
    if not wanted:
        return {}
    files = follower_block_files(state_dir)
    heights = sorted({int(r['height']) for r in records})
    seen, found = set(), {}
    # The index lists blocks from height 1 in order; a store that started later is covered by the tail scan.
    candidates = [i for h in heights for i in range(max(0, h - 1 - window), min(len(files), h + window))]
    candidates += list(range(len(files) - 1, max(-1, len(files) - 1 - 4 * window), -1))
    for index in candidates:
        if index in seen or len(found) == len(wanted):
            continue
        seen.add(index)
        try:
            data = files[index].read_bytes()
        except OSError:
            continue
        found.update(scan_da_frames(data, chain_id, wanted - set(found)))
    return found


def da_batch_transactions(payload):
    """The raw transactions of a canonical DA batch (u32 BE count, then u32 BE length + bytes each)."""
    if da_batch_count(payload) is None:
        raise Halt('malformed DA batch in an orphaned block')
    out, at = [], 4
    for _ in range(int.from_bytes(payload[:4], 'big')):
        size = int.from_bytes(payload[at:at + 4], 'big')
        out.append(payload[at + 4:at + 4 + size])
        at += 4 + size
    return out


def endpoint_url(endpoint):
    """A loopback port (devnets) or an http(s) URL (mainnet `rpc_urls`)."""
    return endpoint if isinstance(endpoint, str) else f'http://127.0.0.1:{endpoint}'


def rpc(port, method, params=()):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(endpoint_url(port), data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.loads(response.read())
    if 'error' in reply:
        raise RpcError(f'{method}: {reply["error"]}')
    return reply['result']


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def settlement_view(view):
    """The safety-relevant projection of a getl2settlement answer."""
    if not isinstance(view, dict):
        return view
    out = {k: view[k] for k in SETTLEMENT_VIEW_FIELDS if k in view}
    if isinstance(out.get('forced'), dict):
        out['forced'] = {k: out['forced'][k] for k in FORCED_VIEW_FIELDS if k in out['forced']}
    return out


def identity_view(view):
    """The static identity fields of a getl2settlement answer (checked once at start)."""
    if not isinstance(view, dict):
        return view
    profile, withdrawals = view.get('profile') or {}, view.get('withdrawals') or {}
    return {'network': view.get('network'), 'genesis': view.get('genesis'), 'chain_id': view.get('chain_id'),
            'asynchronous': view.get('asynchronous'), 'activated': profile.get('activated'),
            'user_transactions': profile.get('user_transactions'), 'attestor_set': withdrawals.get('attestor_set')}


def check_mainnet_config(c):
    """Every mainnet pin the configuration can get wrong, before any RPC."""
    if 'censor_senders' in c:
        raise Halt('censor_senders is a rehearsal knob and never runs on mainnet')
    if c.get('network') != MAINNET['network']:
        raise Halt('mainnet network must be the Genesis-4 admission domain')
    if c.get('l2_genesis') != MAINNET['l2_genesis']:
        raise Halt('mainnet l2_genesis differs from the pinned L2 genesis')
    if Path(c['l2_config']).read_bytes() != mainnet_l2_config():
        raise Halt('mainnet l2_config differs from the pinned program (proof policy V3)')
    if c.get('guest_sha256') != MAINNET['guest_sha256'] or 'settlement_v3_mainnet' not in Path(c['guest']).name:
        raise Halt('mainnet guest must be the pinned settlement_v3_mainnet ELF')
    if c.get('timestamp_rule') != MAINNET_TIMESTAMP_RULE:
        raise Halt(f'mainnet timestamp_rule must be {MAINNET_TIMESTAMP_RULE}')
    if 'rpc_urls' not in c:
        raise Halt('mainnet needs rpc_urls on independent hosts')
    endpoints = rpc_endpoints(c)
    if len(endpoints) < 3 or rpc_quorum(c) < 2:
        raise Halt('mainnet needs at least three rpc_urls and a quorum of at least two')
    for key in ('poll_seconds', 'resubmit_seconds', 'acceptance_timeout_seconds'):
        if not isinstance(c.get(key), int) or c[key] <= 0:
            raise Halt(f'{key} must be a positive integer')


def check_rehearsal_config(c):
    """mainnet-rehearsal: the mainnet program and L2 genesis on a private network, never Genesis-4."""
    if c.get('network') == MAINNET['network']:
        raise Halt('mainnet-rehearsal never runs on the Genesis-4 network; use network_kind "mainnet"')
    if c.get('l2_genesis') != MAINNET['l2_genesis']:
        raise Halt('mainnet-rehearsal l2_genesis differs from the pinned L2 genesis')
    if Path(c['l2_config']).read_bytes() != mainnet_l2_config():
        raise Halt('mainnet-rehearsal l2_config differs from the pinned program (proof policy V3)')
    if c.get('guest_sha256') != MAINNET['guest_sha256']:
        raise Halt('mainnet-rehearsal guest must be the pinned settlement_v3_mainnet ELF')


def check_next_program(c):
    """`next_program` of a mainnet-path worker: exactly the candidate the native gate would install."""
    program = c.get('next_program')
    if program is None:
        return
    if not isinstance(program, dict):
        raise Halt('next_program must be an object')
    witness = program.get('witness', 'complete')
    if witness not in ('complete', 'sparse'):
        raise Halt('next_program witness must be complete or sparse')
    pin, args = (MAINNET_NEXT_SPARSE, ['--mainnet', '--sparse']) if witness == 'sparse' else (MAINNET_NEXT, ['--mainnet'])
    if Path(program['l2_config']).read_bytes() != mainnet_l2_config(pin):
        raise Halt('next_program l2_config differs from the pinned next program')
    if program.get('guest_sha256') != pin['guest_sha256']:
        raise Halt('next_program guest must be the pinned next settlement_v3_mainnet ELF')
    if list(program.get('prover_args', args)) != args:
        raise Halt('next_program prover_args must select the next rules and its witness')
    if list(c.get('prover_args', ['--mainnet'])) not in (['--mainnet'], ['--mainnet-v1']):
        raise Halt('prover_args must select the activated rules')
    fallback = c.get('fallback_program')
    if fallback is None:
        return
    if not isinstance(fallback, dict):
        raise Halt('fallback_program must be an object')
    if witness != 'sparse':
        raise Halt('fallback_program needs a sparse next_program: the rollback replaces the sparse guest')
    if fallback.get('witness', 'complete') != 'complete':
        raise Halt('fallback_program is proved by the complete-witness guest')
    if Path(fallback['l2_config']).read_bytes() != mainnet_l2_config(MAINNET_FALLBACK):
        raise Halt('fallback_program l2_config differs from the pinned fallback program')
    if fallback.get('guest_sha256') != MAINNET_FALLBACK['guest_sha256']:
        raise Halt('fallback_program guest must be the pinned complete-witness settlement_v3_mainnet ELF')
    if list(fallback.get('prover_args', ['--mainnet'])) != ['--mainnet']:
        raise Halt('fallback_program prover_args must select the next rules')


def check_chain_overrides(c, chain_id, network_args):
    """`chain_id` / `network_args` (written by the 2026-10-18 rehearsal driver) are derived from
    network_kind; they may be repeated in a configuration, never changed."""
    if 'chain_id' in c and c['chain_id'] != chain_id:
        raise Halt(f'chain_id {c["chain_id"]} does not match network_kind (chain {chain_id})')
    if 'network_args' in c and list(c['network_args']) != list(network_args):
        raise Halt('network_args do not match network_kind (only the mainnet path takes --rules mainnet)')


def rpc_endpoints(config):
    """The native RPC endpoints: `rpc_urls` (http(s) URLs, one per host) or loopback `rpc_ports`."""
    if 'rpc_urls' in config:
        if 'rpc_ports' in config:
            raise Halt('configure rpc_urls or rpc_ports, not both')
        urls = config['rpc_urls']
        if not isinstance(urls, list) or not urls or not all(isinstance(u, str) for u in urls):
            raise Halt('rpc_urls must list http(s) URLs')
        hosts = [urllib.parse.urlsplit(u).hostname for u in urls]
        if not all(urllib.parse.urlsplit(u).scheme in ('http', 'https') and h for u, h in zip(urls, hosts)):
            raise Halt('rpc_urls must list http(s) URLs')
        if len(set(hosts)) != len(hosts):
            raise Halt('rpc_urls must name distinct hosts (one failure domain each)')
        return list(urls)
    ports = config.get('rpc_ports')
    if not isinstance(ports, list) or not ports or len(set(ports)) != len(ports) \
            or not all(isinstance(p, int) and not isinstance(p, bool) for p in ports):
        raise Halt('rpc_ports must list distinct integer ports')
    return list(ports)


def rpc_quorum(config):
    """`rpc_quorum` from the configuration (default: strict majority of the endpoints)."""
    ports = rpc_endpoints(config)
    quorum = config.get('rpc_quorum', len(ports) // 2 + 1)
    if not isinstance(quorum, int) or isinstance(quorum, bool) or not len(ports) < 2 * quorum <= 2 * len(ports):
        raise Halt('rpc_quorum must be a strict majority of rpc_ports')
    return quorum


class Endpoints:
    """The native validator RPCs: quorum for safety-relevant reads, any one for submission.

    `agreed` returns an answer only when at least `quorum` endpoints returned
    the identical value; a value reported by fewer endpoints is never used.
    Because the quorum is a strict majority, two different answers can never
    both reach it. An endpoint that raises (transport or JSON-RPC error) is
    skipped for an exponential backoff; an endpoint that answers outside the
    quorum (lagging, replaying, forked) is reported but still queried. When
    fewer than `quorum` endpoints are out of backoff, all are probed.
    """

    def __init__(self, ports, quorum, rpc, clock, sleep=time.sleep):
        self.ports, self.quorum, self.rpc, self.clock, self.sleep = list(ports), quorum, rpc, clock, sleep
        self.faults = len(self.ports) - quorum  # endpoints that may be wrong or missing
        self.state = {p: {'failures': 0, 'retry_at': 0.0, 'diverged': 0} for p in self.ports}
        self.split = False

    def usable(self):
        ready, now = [], None
        for port in self.ports:
            state = self.state[port]
            if state['failures']:
                now = self.clock() if now is None else now
                if now < state['retry_at']:
                    continue
            ready.append(port)
        return ready if len(ready) >= self.quorum else list(self.ports)

    def call(self, port, method, params=()):
        try:
            result = self.rpc(port, method, params)
        except Exception as error:
            state = self.state[port]
            state['failures'] += 1
            delay = min(RPC_MAX_BACKOFF_SECONDS, RPC_BACKOFF_SECONDS << min(state['failures'] - 1, 16))
            state['retry_at'] = self.clock() + delay
            log('rpc-endpoint-failed', port=port, method=method, failures=state['failures'], backoff_seconds=delay,
                reason=f'{type(error).__name__}: {error}'[:300])
            raise
        state = self.state[port]
        if state['failures']:
            log('rpc-endpoint-recovered', port=port, method=method, after_failures=state['failures'])
            state['failures'], state['retry_at'] = 0, 0.0
        return result

    def gather(self, method, params=(), need=None):
        """{port: answer} from the usable endpoints; raises unless `need` (default quorum) answered."""
        answers = {}
        for port in self.usable():
            try:
                answers[port] = self.call(port, method, params)
            except Exception:  # logged by call(); the quorum decides below
                pass
        need = self.quorum if need is None else need
        if len(answers) < need:
            raise RuntimeError(f'{method}: {len(answers)} of {len(self.ports)} RPC endpoints answered, '
                               f'{need} needed')
        return answers

    def agreed(self, method, params=(), project=lambda answer: answer):
        """(projected answer, supporting ports) when a quorum returned the identical
        projected answer, else (None, []). A split is re-read (all endpoints, fresh)
        up to QUORUM_READ_ATTEMPTS times: answers from different reads are never mixed."""
        for attempt in range(QUORUM_READ_ATTEMPTS):
            if attempt:
                self.sleep(QUORUM_RETRY_SECONDS)
            answers = {port: project(answer) for port, answer in self.gather(method, params).items()}
            groups = {}
            for port, answer in answers.items():
                groups.setdefault(canonical(answer), []).append(port)
            support = max(groups.values(), key=len)
            if len(support) >= self.quorum:
                break
        else:
            if not self.split:
                log('rpc-no-quorum', method=method, quorum=self.quorum, attempts=QUORUM_READ_ATTEMPTS,
                    groups=sorted((sorted(g) for g in groups.values()), key=len, reverse=True))
            self.split = True
            return None, []
        if self.split:
            log('rpc-quorum-restored', method=method, ports=sorted(support))
            self.split = False
        for port in answers:
            state = self.state[port]
            if port in support:
                if state['diverged'] >= RPC_DIVERGED_LOG_AFTER:
                    log('rpc-endpoint-agrees', port=port, method=method)
                state['diverged'] = 0
            else:
                state['diverged'] += 1
                if state['diverged'] == RPC_DIVERGED_LOG_AFTER:
                    log('rpc-endpoint-diverged', port=port, method=method, quorum_ports=sorted(support))
        return answers[support[0]], sorted(support)

    def bounded_value(self, method, field):
        """An integer field no larger than one reported by an honest endpoint: the
        (faults + 1)-th largest of at least `quorum` answers (the median of three)."""
        values = sorted(int(a[field]) for a in self.gather(method).values())
        return values[max(0, len(values) - 1 - self.faults)]

    def common_utxos(self, script):
        """Outputs that at least `quorum` endpoints report as unspent."""
        seen, first = {}, {}
        for answer in self.gather('getutxos', [script, 64]).values():
            for key, u in {(u['txid'], int(u['vout']), str(u['value_sat'])): u
                           for u in answer.get('utxos', [])}.items():
                seen[key] = seen.get(key, 0) + 1
                first.setdefault(key, u)
        return [first[k] for k in seen if seen[k] >= self.quorum]

    def submit(self, tx_hex):
        """sendrawtransaction on the first usable endpoint that accepts it: (port, response).
        Raises SubmitRefused with every endpoint's reason when none does."""
        errors = []
        for port in self.usable():
            try:
                return port, self.call(port, 'sendrawtransaction', [tx_hex])
            except Exception as error:
                errors.append((port, f'{type(error).__name__}: {error}'[:300]))
        raise SubmitRefused(errors)


# Native sendrawtransaction refusals (bloch-pos-node rpc.rs / engine.rs, release 78b7343a).
TX_REFUSED, TX_REFUSED_RETRYABLE, MEMPOOL_FULL, TX_REFUSED_SOURCE_CAP = -32008, -32009, -32003, -32010
ONE_PROOF_PENDING = 'one L2 proof is already pending'


class SubmitRefused(RuntimeError):
    """No endpoint took the transaction. `kind()` is 'terminal' only when every
    endpoint that answered judged these bytes invalid for a reason other than
    another proof already pending; anything else (transport failure, full
    mempool, retryable bar, a pending proof) is 'retry'."""

    def __init__(self, errors):
        self.errors = errors
        super().__init__('sendrawtransaction failed on every RPC endpoint: '
                         + '; '.join(f'{p}: {e}'[:200] for p, e in errors))

    def kind(self):
        refusals = [e for _, e in self.errors if e.startswith('RpcError')]
        if not refusals or len(refusals) < len(self.errors):
            return 'retry'
        terminal = [e for e in refusals if f"'code': {TX_REFUSED}," in e and ONE_PROOF_PENDING not in e]
        return 'terminal' if len(terminal) == len(refusals) else 'retry'


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


def group_segments(pgid, directory):
    """The SP1 shared-memory files (`sp1_*`, `sem.sp1_*` under `directory`) that processes of group `pgid` map or hold."""
    found, prefix = set(), str(directory).rstrip('/') + '/'
    for proc in Path('/proc').iterdir() if Path('/proc').is_dir() else ():
        if not proc.name.isdigit():
            continue
        try:
            stat = (proc / 'stat').read_text()
            if int(stat.rsplit(')', 1)[1].split()[2]) != pgid:
                continue
            paths = [line.split(None, 5)[5] for line in (proc / 'maps').read_text().splitlines() if len(line.split(None, 5)) == 6]
            paths += [os.readlink(fd) for fd in (proc / 'fd').iterdir()]
        except (OSError, ValueError, IndexError):
            continue
        for path in paths:
            path = path.replace(' (deleted)', '')
            name = path[len(prefix):] if path.startswith(prefix) else ''
            if name.startswith(('sp1_', 'sem.sp1_')) and '/' not in name:
                found.add(path)
    return found


def segment_mapped(path):
    """Whether any process we can see maps or holds `path`. Processes of other users cannot be read; they cannot have
    opened this user's segment either (mode 0600), unless they run as root."""
    target = str(path)
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if target in (proc / 'maps').read_text():
                return True
            if any(os.readlink(fd) == target for fd in (proc / 'fd').iterdir()):
                return True
        except OSError:
            continue
    return False


def remove_leaked_segments(paths, mapped=segment_mapped):
    """Remove the given segments, which this run's prover processes mapped, once no process maps them. A killed SP1 native
    runner never unlinks its segments (4.7 GB each in /dev/shm), and a full /dev/shm makes every later SP1 run on the
    host crash. Only segments seen mapped by this run's own process group are candidates: nothing another job created."""
    removed, paths = [], set(paths)
    for path in list(paths):  # the semaphores of a segment this group used carry its name: sem.sp1_<id>_t_empty, _filled
        head, name = os.path.split(path)
        if name.startswith('sp1_'):
            paths |= {os.path.join(head, f'sem.{name}_{end}') for end in ('empty', 'filled')}
    for path in sorted(paths):
        try:
            if not os.path.exists(path) or mapped(path):
                continue
            os.unlink(path)
            removed.append(os.path.basename(path))
        except OSError:
            continue
    if removed:
        log('prover-shm-removed', segments=removed)
    return removed


class Settler:
    def __init__(self, config, rpc=rpc, run=subprocess.run, sleep=time.sleep, clock=time.monotonic):
        kind = config.get('network_kind', DEFAULTS['network_kind'])
        if kind not in NETWORK_KINDS:
            raise Halt('network_kind must be "devnet", "mainnet" or "mainnet-rehearsal"')
        self.mainnet = kind == 'mainnet'
        # mainnet-rehearsal: the private mainnet-path rehearsal (native qualification build
        # l2-activation-rehearsal-mainnet-policy): the mainnet program, chain id, producer and
        # prover arguments, on a private network whose identity comes from the configuration.
        self.rehearsal = kind == 'mainnet-rehearsal'
        self.mainnet_path = kind in MAINNET_PATH_KINDS
        self.c = {**DEFAULTS, **(MAINNET_DEFAULTS if self.mainnet else {}), **config}
        self.rpc, self.run, self.sleep, self.clock = rpc, run, sleep, clock
        self.wall = time.time  # wall time persisted in DA attempt records (clock is monotonic)
        self.chain_id = MAINNET['chain_id'] if self.mainnet_path else CHAIN_ID
        self.network_args = list(MAINNET_PRODUCE_ARGS) if self.mainnet_path else []
        self.prover_args = list(self.c.get('prover_args', ['--mainnet'] if self.mainnet_path else []))
        check_chain_overrides(self.c, self.chain_id, self.network_args)
        for key in ('prover', 'guest', 'l2_config'):
            if digest(self.c[key]) != self.c[key + '_sha256']:
                raise Halt(f'{key} differs from its pin')
        if 'settlement-v3' not in Path(self.c['prover']).name or 'settlement_v3' not in Path(self.c['guest']).name:
            raise Halt('settler_v3 requires the settlement V3 prover and guest')
        if not isinstance(self.c['user_transactions'], bool):
            raise Halt('user_transactions must be true or false')
        if self.mainnet:
            check_mainnet_config(self.c)
        elif self.rehearsal:
            check_rehearsal_config(self.c)
        self.base_program = {'name': 'base', 'rules': 'base', 'prover': self.c['prover'], 'guest': self.c['guest'],
                             'l2_config': self.c['l2_config'], 'prover_args': self.prover_args,
                             'remote_prover': self.c.get('remote_prover'), 'witness': 'complete'}
        self.next_program = self.fallback_program = None
        if self.c.get('next_program') is not None:
            if not self.mainnet_path:
                raise Halt('next_program applies only to the mainnet program path')
            check_next_program(self.c)
            n = self.c['next_program']
            for key in ('prover', 'guest', 'l2_config'):
                if digest(n[key]) != n[key + '_sha256']:
                    raise Halt(f'next_program {key} differs from its pin')
            witness = n.get('witness', 'complete')
            default_args = ['--mainnet', '--sparse'] if witness == 'sparse' else ['--mainnet']
            self.next_program = {'name': 'next', 'rules': 'next', 'prover': n['prover'], 'guest': n['guest'],
                                 'l2_config': n['l2_config'], 'prover_args': list(n.get('prover_args', default_args)),
                                 'remote_prover': n.get('remote_prover'), 'witness': witness}
            f = self.c.get('fallback_program')
            if f is not None:
                for key in ('prover', 'guest', 'l2_config'):
                    if digest(f[key]) != f[key + '_sha256']:
                        raise Halt(f'fallback_program {key} differs from its pin')
                self.fallback_program = {'name': 'fallback', 'rules': 'next', 'prover': f['prover'], 'guest': f['guest'],
                                         'l2_config': f['l2_config'], 'prover_args': list(f.get('prover_args', ['--mainnet'])),
                                         'remote_prover': f.get('remote_prover'), 'witness': 'complete'}
        self.program = self.base_program
        if self.c['user_transactions']:
            # Production guard (M2.6, M8): user transactions only where the native L2 admits them:
            # development networks and the activated mainnet profile (checked live as well).
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
        remote = self.c.get('remote_prover')
        if remote is not None:
            if not isinstance(remote, dict):
                raise Halt('remote_prover must be an object')
            for key in ('target', 'key', 'known_hosts'):
                if not remote.get(key):
                    raise Halt(f'remote_prover.{key} is required')
            if not Path(remote['known_hosts']).is_file():
                raise Halt('remote_prover.known_hosts must pin the prover host key')
            order = remote.setdefault('order', ['local', 'remote'])
            if not isinstance(order, list) or not order or len(set(order)) != len(order) \
                    or not set(order) <= {'local', 'remote'}:
                raise Halt('remote_prover.order must list "local" and/or "remote" once each')
        limit = self.c.get('local_prove_max_instructions')
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0):
            raise Halt('local_prove_max_instructions must be a positive integer')
        recovery = self.c.get('foreign_recovery')
        if recovery is not None:
            if not isinstance(recovery, dict) or not recovery.get('follower_state') or not recovery.get('follower_status'):
                raise Halt('foreign_recovery needs follower_state and follower_status')
            if not isinstance(recovery.get('keep', 2), int) or recovery.get('keep', 2) < 1:
                raise Halt('foreign_recovery.keep must be a positive integer')
        if not isinstance(self.c.get('skip_idle_blocks', False), bool):
            raise Halt('skip_idle_blocks must be true or false')
        if self.c.get('skip_idle_blocks'):
            limit = self.c.get('max_idle_seconds')
            if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise Halt('skip_idle_blocks requires max_idle_seconds, a positive integer')
        pace = self.c.get('min_block_interval_seconds', 0)
        if not isinstance(pace, int) or isinstance(pace, bool) or pace < 0:
            raise Halt('min_block_interval_seconds must be a non-negative integer')
        if pace and not self.c.get('skip_idle_blocks'):
            raise Halt('min_block_interval_seconds requires skip_idle_blocks')
        censor = self.c.get('censor_senders')
        if censor is not None:
            # Rehearsal only: a sequencer that censors these L2 senders, to show the L1 forced-inclusion path.
            if self.mainnet:
                raise Halt('censor_senders is a rehearsal knob and never runs on mainnet')
            if not self.c['user_transactions']:
                raise Halt('censor_senders needs user_transactions')
            if not isinstance(censor, list) or not all(isinstance(a, str) and re.fullmatch(r'(0x)?[0-9a-fA-F]{40}', a)
                                                       for a in censor):
                raise Halt('censor_senders must list 20-byte hex L2 addresses')
        self.censor = {a.lower().removeprefix('0x') for a in censor or []}
        self.spool_open = True  # false: the next block is built without the spool (see hold_block)
        self.holding_since = None  # monotonic time this worker began to hold; None while it builds
        self.hold_logged_at = None
        for key in ('max_block_sp1_gas', 'max_block_instructions', 'local_prove_max_sp1_gas'):
            value = self.c.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
                raise Halt(f'{key} must be a positive integer')
        if self.c.get('max_block_instructions') and not self.c.get('max_block_sp1_gas'):
            raise Halt('max_block_instructions needs max_block_sp1_gas: the budget is in SP1 gas')
        self.work = Path(self.c['workdir'])
        self.rebuild_discarded_at = None
        self.waiting_for = None  # the accepted settlement a recovery last reported waiting on
        self.native = Endpoints(rpc_endpoints(self.c), rpc_quorum(self.c), self.rpc, self.clock, self.sleep)
        self.accepted_floor = 0  # highest accepted L2 number seen in a quorum view
        self.identity_checked = False
        self.dry_run = False

    def check_identity(self):
        """Once per process: the network a quorum reports is the configured one;
        on mainnet also the async, activated profile with the pinned attestor set."""
        if self.identity_checked:
            return True
        view, _ = self.native.agreed('getl2settlement', project=identity_view)
        if view is None:
            return False
        if view.get('network') != self.c['network'] or view.get('chain_id') != self.chain_id:
            raise Halt('native network identity differs from the configuration')
        if self.mainnet:
            expected = {'network': MAINNET['network'], 'genesis': MAINNET['genesis'], 'chain_id': MAINNET['chain_id'],
                        'asynchronous': True, 'activated': True, 'attestor_set': MAINNET['attestor_set']}
            got = {k: view.get(k) for k in expected}
            if got != expected:
                raise Halt(f'mainnet L2 identity differs from the pins: {got}')
            if self.c['user_transactions'] and view.get('user_transactions') is not True:
                raise Halt('the native L2 profile does not admit user transactions')
        elif self.rehearsal and view.get('asynchronous') is not True:
            raise Halt('the rehearsal network does not run the asynchronous mainnet profile')
        self.identity_checked = True
        log('identity-checked', network=view['network'], chain_id=view['chain_id'], mainnet=self.mainnet)
        return True

    def native_view(self):
        """The settlement view a quorum of validator RPCs reports identically, or None."""
        view, support = self.native.agreed('getl2settlement', project=settlement_view)
        if view is None:
            return None  # validators momentarily disagree; retry later
        if view['network'] != self.c['network'] or view['chain_id'] != self.chain_id:
            raise Halt('native network identity changed')
        accepted = view.get('accepted')
        number = statement_fields(accepted['statement'])['l2_number'] if accepted else 0
        unanimous = len(support) == len(self.native.ports)
        if not unanimous and number < self.accepted_floor:
            # A partial quorum must not move the accepted head backwards (two stale
            # endpoints); a unanimous view is trusted as before.
            log('rpc-quorum-view-behind', accepted=number, seen=self.accepted_floor, ports=support)
            return None
        self.accepted_floor = number if unanimous else max(self.accepted_floor, number)
        return view

    def program_of(self, view):
        """The program L1 holds now, from a quorum view. A node without the report is on the activated one."""
        reported = view.get('program')
        if self.next_program is None or reported is None:
            return self.base_program
        fields = ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254', 'proof_policy')
        identity = b''.join(bytes.fromhex(reported[k]) for k in fields)
        for program in (self.base_program, self.next_program, self.fallback_program):
            if program is not None and Path(program['l2_config']).read_bytes()[32:192] == identity:
                return program
        raise Halt(f'L1 reports a program this worker is not configured for: {reported}')

    def produce(self, *args):
        result = self.run([self.c['produce'], *args, *self.network_args], capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise ProducerError(f'producer refused {args[0]}: {result.stderr.strip()[:400]}')
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise ProducerError(f'producer printed no JSON for {args[0]}') from None

    def extend(self, parent, anchor, deposits, anchor_slot, number, spool=True):
        """Extend by one block. With the user-transaction spool, a producer refusal is retried once
        without it (deposits only): the spool is untrusted input and must not stop settlement."""
        try:
            # A batch this DA key already paid is rebuilt exactly (its spool), never re-chosen by the budget.
            if self.c.get('max_block_sp1_gas') and spool is True:
                return self.extend_within_budget(parent, anchor, deposits, anchor_slot, number)
            return self.produce(*self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=spool))
        except ProducerError as error:
            if not self.c['user_transactions']:
                raise
            head = self.produce('head', '--target', self.c['l2_db'])
            if head['number'] != number - 1:
                raise  # the block was committed before the failure; the next cycle reuses it
            log('producer-refused-spool', number=number, reason=str(error)[:400])
            return self.produce(*self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False))

    def spool_entries(self):
        """The spool as (path, raw hex), in name order. An unreadable or malformed entry is left to the producer's rules."""
        entries = []
        for path in sorted(Path(self.c['txpool_dir']).glob('*.tx'))[:SPOOL_READ_LIMIT]:
            try:
                raw = path.read_text().strip().removeprefix('0x')
                bytes.fromhex(raw)
            except (OSError, ValueError):
                continue
            entries.append((path, raw))
        return entries

    def select_block(self, parent, anchor, deposits, anchor_slot, raws, directory):
        """What the producer's selection would do with these transactions. Native execution, nothing is committed."""
        pool = directory / 'dry.json'
        pool.write_text(json.dumps(raws))
        args = self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False)
        args[0] = 'select'
        return self.produce(*args, '--txs', str(pool), '--max-gas', str(self.c['max_block_gas']),
                            '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs']))

    def measure_block(self, parent, anchor, deposits, anchor_slot, number, raws, tag):
        """Build the block from exactly these transactions, deposits included, on a throwaway copy of the database and run
        the guest in execute mode. Returns (Cost, or None when the time limit was hit, producer report). No proof, no lock."""
        scratch = deposits.parent / f'preflight-{tag}'
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        try:
            db = scratch / 'db'
            shutil.copytree(self.c['l2_db'], db, symlinks=True)
            pool = scratch / 'pool.json'
            pool.write_text(json.dumps(raws))
            args = self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False)
            args[args.index('--target') + 1] = str(db)
            block = self.produce(*args, '--txs', str(pool), '--max-gas', str(self.c['max_block_gas']),
                                 '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs']))
            self.produce('export', '--target', str(db), '--number', str(number), '--out', str(scratch / 'block.artifact'),
                         *self.export_witness())
            request = scratch / 'native-request.txt'
            request.write_text(self.preflight_request)
            env = {'PATH': self.c.get('prover_path', '/usr/bin:/bin'), 'HOME': self.c['home'], 'TMPDIR': self.c['home'] + '/tmp',
                   'SP1_CIRCUIT_MODE': 'release', 'BLOCH_NATIVE_L2_REQUEST': str(request),
                   'BLOCH_NATIVE_L2_ARTIFACT': str(scratch / 'block.artifact')}
            # The guest of the program L1 holds now, on the witness that guest reads: the budget is that guest's cost.
            argv = [self.program['prover'], *self.program['prover_args'], 'execute', 'native-artifact', self.program['guest']]
            try:
                with (scratch / 'execute.log').open('w') as out:
                    result = self.run(argv, env=env, stdout=out, stderr=subprocess.STDOUT,
                                      timeout=self.c.get('preflight_execute_seconds', 120))
            except subprocess.TimeoutExpired:
                return None, block
            text = (scratch / 'execute.log').read_text(errors='replace')
            gas = re.findall(r'Settlement V3 cost: gas=(\d+)', text)
            instructions = re.findall(r'(\d+) instructions', text)
            if result.returncode or not gas or not instructions:
                return None, block  # no cost from this guest and host: treat the block as over any budget
            return sequencer_policy.Cost(int(gas[-1]), int(instructions[-1])), block
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def extend_within_budget(self, parent, anchor, deposits, anchor_slot, number):
        """Commit only a block the policy of `sequencer_policy.py` chose: measured in SP1 gas with its deposits.

        A block whose deposits alone are over the budget still commits, because L1 names exactly those deposits for the next
        settlement; it carries nothing else, and the operator's exit is a bigger prover. See that module."""
        entries = self.spool_entries() if self.c['user_transactions'] else []
        pending = json.loads(deposits.read_text())
        # Forced records bypass the budget like deposits: L1 names them for this settlement (agent 122, tip 3).
        forced = read_forced(deposits.parent)
        by_hash = {keccak256(bytes.fromhex(raw)).hex(): (path, raw) for path, raw in entries}
        if not entries and not pending and not forced:
            return self.produce(*self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False))
        self.preflight_request = self.preflight_source
        tags = itertools.count()
        planner = self.planner()
        plan = planner.plan(
            [raw for _, raw in entries],
            lambda raws: self.select_block(parent, anchor, deposits, anchor_slot, raws, deposits.parent),
            lambda raws: self.measure_block(parent, anchor, deposits, anchor_slot, number, raws, next(tags)),
            number, has_deposits=bool(pending) or bool(forced))
        if plan.deposits_over_budget:
            atomic_write(deposits.parent / 'deposits-over-budget.json', json.dumps(
                {'number': number, 'sp1_gas': plan.base.sp1_gas if plan.base else None,
                 'instructions': plan.base.instructions if plan.base else None, 'budget': planner.budget,
                 'deposits': len(pending), 'forced': len(forced)}, sort_keys=True) + '\n')
        quarantine = Path(self.c['txpool_dir']).with_name(Path(self.c['txpool_dir']).name + '-quarantine')
        for name, reason in plan.quarantine:
            if name in by_hash:
                quarantine.mkdir(exist_ok=True, mode=0o700)
                try:
                    by_hash[name][0].replace(quarantine / by_hash[name][0].name)
                except FileNotFoundError:
                    pass
                log('tx-quarantined', number=number, hash=name, reason=reason)
        if plan.held:
            log('txs-held', number=number, held=[{'hash': h, 'reason': r} for h, r in plan.held[:32]], count=len(plan.held))
        pool = deposits.parent / 'selected.json'
        atomic_write(pool, json.dumps(plan.chosen))
        args = self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False)
        block = self.produce(*args, '--txs', str(pool), '--max-gas', str(self.c['max_block_gas']),
                             '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs']))
        chosen_hashes = [keccak256(bytes.fromhex(raw)).hex() for raw in plan.chosen]
        for name in chosen_hashes + plan.finished:  # committed: what the producer does for a spool directory
            if name in by_hash:
                by_hash[name][0].unlink(missing_ok=True)
        planner.committed(plan, number)
        log('block-plan', number=number, runs=plan.runs, exhausted=plan.exhausted, transactions=len(plan.chosen),
            sp1_gas=plan.cost.sp1_gas if plan.cost else None, base_sp1_gas=plan.base.sp1_gas if plan.base else None,
            required_tip=planner.required_tip())
        return block

    def planner(self):
        sequencer_policy.set_hash(keccak256)
        return sequencer_policy.Planner(self.c, self.work / 'sequencer-policy.json', self.clock, log)

    def extend_arguments(self, parent, anchor, deposits, anchor_slot=None, spool=True):
        args = ['extend', '--target', self.c['l2_db'], '--parent', parent, '--anchor', anchor, '--deposits', str(deposits)]
        if read_forced(Path(deposits).parent):
            # L1 forced inclusion: the producer runs these first, after the deposits, outside every sequencer limit.
            args += ['--forced', str(Path(deposits).parent / 'forced.json')]
        if self.c.get('timestamp_rule'):
            # L2 time follows the anchored native slot (rollup rule); attestors rebuild with the same rule.
            args += ['--timestamp-rule', self.c['timestamp_rule'], '--anchor-slot', str(anchor_slot)]
        if self.c['user_transactions'] and spool and self.spool_open:
            pool = spool if isinstance(spool, (str, Path)) else self.c['txpool_dir']
            args += ['--txs', str(pool), '--max-gas', str(self.c['max_block_gas']),
                     '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs'])]
            if self.c.get('min_tip_wei'):
                args += ['--min-tip-wei', str(self.c['min_tip_wei'])]
        if self.next_program is not None:
            args += ['--rule-set', self.program['rules']]
        return args

    def source_age(self, view):
        """Seconds of L1 time since the frozen source, which is the block right after the last acceptance. The L1 head
        slot is bounded by an honest endpoint's, so a lying endpoint cannot age the source. An L1 that stops stops this
        clock too: no block is due while nothing could settle it."""
        rule = self.c.get('timestamp_rule')
        slot_seconds = int(rule.split(':')[2]) / 1000 if rule else 30
        return (self.native.bounded_value('getchaininfo', 'slot') - int(view['source']['slot'])) * slot_seconds

    def inbox_backlog(self):
        """Deposits L1 holds and no settlement has consumed. `source.pending` cannot show this: the source freezes the
        inbox count right after an acceptance, so a deposit made later appears there only after one more settlement.
        Bounded by an honest endpoint's answer, so a lying endpoint cannot force a block."""
        values = sorted(int(a['inbox']['count']) - int(a['inbox']['consumed'])
                        for a in self.native.gather('getl2settlement').values())
        return values[max(0, len(values) - 1 - self.native.faults)]

    def forced_backlog(self):
        """Forced records L1 holds and no settlement has consumed (0 while the queue is not enabled). Like the inbox, the
        queue freezes with the source, so a record queued later is due only one settlement after the next. Bounded by an
        honest endpoint's answer."""
        values = sorted(int((a.get('forced') or {}).get('pending', 0)) for a in self.native.gather('getl2settlement').values())
        return values[max(0, len(values) - 1 - self.native.faults)] if values else 0

    def censor_spool(self, number):
        """Rehearsal only (`censor_senders`): move the spool entries of censored senders aside, so no block of this
        worker carries them. The L1 forced-inclusion path must still get them in."""
        if not self.censor:
            return
        aside = Path(self.c['txpool_dir']).with_name(Path(self.c['txpool_dir']).name + '-censored')
        for path, raw in self.spool_entries():
            sender = envelope_sender(bytes.fromhex(raw))
            if sender is not None and sender.hex() in self.censor:
                aside.mkdir(exist_ok=True, mode=0o700)
                try:
                    path.replace(aside / path.name)
                except FileNotFoundError:
                    continue
                log('tx-censored', number=number, hash=keccak256(bytes.fromhex(raw)).hex(), sender=sender.hex())

    def hold_block(self, view):
        """With `skip_idle_blocks`: whether to build no block in this cycle. Not a block rule: L1, the guest, the follower
        and every rebuild only see fewer blocks, each with an older anchor. See SETTLER-RUNBOOK.md, "Idle blocks".

        A block is due when L1 holds an unconsumed deposit, the spool holds a transaction, or the source reached
        `max_idle_seconds`, which proves the whole path while nothing else does. `min_block_interval_seconds` then delays
        a due block, so that deposits cannot make the height grow faster than that: a deposit costs 0.01 BLCH, and the
        recipient keeps it. A deposit that arrived while idle needs two blocks: L1 keeps the source frozen until the next
        settlement, so the first block is anchored to the old source and cannot mint it."""
        accepted = view.get('accepted')
        expected = statement_fields(accepted['statement'])['l2_hash'] if accepted else self.c['l2_genesis']
        if not Path(self.c['l2_db']).exists() or self.produce('head', '--target', self.c['l2_db'])['hash'] != expected:
            return False  # a block left by a crash is finished first; a foreign settlement is handled by prepare_block
        try:
            age = self.source_age(view)
            backlog = self.inbox_backlog()
            forced = self.forced_backlog() if 'forced' in view else 0
        except Exception as error:  # noqa: BLE001 - the quorum view just passed: try again next cycle
            log('idle-check-failed', reason=f'{type(error).__name__}: {error}'[:300])
            return True
        spooled = bool(self.c['user_transactions'] and any(Path(self.c['txpool_dir']).glob('*.tx')))
        pace = self.c.get('min_block_interval_seconds', 0)
        # A due forced record is never held: every settlement on this source must consume it, whoever settles.
        reason = ('forced' if forced or (view.get('forced') or {}).get('due') else
                  'deposits' if backlog or view['source'].get('pending') else 'transactions' if spooled
                  else 'max-idle' if age >= self.c['max_idle_seconds'] else None)
        if reason is None or age < pace:
            now = self.clock()
            if self.holding_since is None:
                self.holding_since, self.hold_logged_at = now, None
            if self.hold_logged_at is None or now - self.hold_logged_at >= 3600:
                self.hold_logged_at = now
                log('idle-hold', source_age_seconds=int(age), backlog=backlog, due=reason)
            return True
        # An L2 block takes its time from its anchor. A transaction in a block on an old source would run at the old time,
        # so an expired deadline would pass. Build this block without the spool; the next one has a fresh source.
        self.spool_open = age < pace + FRESH_SOURCE_SECONDS
        if self.holding_since is not None or not self.spool_open:
            log('idle-end', reason=reason, source_age_seconds=int(age), backlog=backlog, spool_open=self.spool_open)
        self.holding_since = None
        return False

    def export_witness(self):
        """The export option of the witness the current program's guest reads (none for the complete one,
        so an older producer keeps working)."""
        return ['--witness', 'sparse'] if self.program.get('witness') == 'sparse' else []

    def supersede(self, directory):
        """Keep the work of a block that can no longer settle, under a name no later cycle reuses."""
        if directory.exists():
            directory.rename(directory.with_name(f'{directory.name}.superseded-{int(time.time())}'))

    def follow_program(self, number, directory):
        """Make the database and the work directory fit the program L1 holds now."""
        if self.next_program is None:
            return
        head = self.produce('head', '--target', self.c['l2_db'])
        head_next = head.get('rules') == 'next'
        if self.program is self.base_program:
            if head_next:
                raise WaitForProgram(f'L2 head {head["number"]} runs the next rules, L1 reports the activated program')
            return
        if head['number'] == number and not head_next:
            pool = ['--respool', self.c['txpool_dir']] if self.c['user_transactions'] else []
            rewound = self.produce('rewind', '--target', self.c['l2_db'], '--number', str(number), '--hash', head['hash'], *pool)
            log('l2-block-rewound-at-swap', number=number, hash=head['hash'], respooled=rewound.get('respooled', 0))
        produced = directory / 'block.json'
        if produced.exists() and json.loads(produced.read_text()).get('rules') != 'next':
            self.supersede(directory)
        elif directory.exists() and not produced.exists() and (directory / 'proved.json').exists():
            self.supersede(directory)
        elif (directory / 'program.json').exists() and \
                json.loads((directory / 'program.json').read_text()).get('name') != self.program['name']:
            # Same rules, other guest (the rollback): the block stays, its artifact and proof are made again.
            log('l2-block-reproved-for-program', number=number, program=self.program['name'])
            self.supersede(directory)

    def follower_state_dir(self):
        """The native follower's verified block store, when configured (`follower_state`, or the one of
        `foreign_recovery`)."""
        recovery = self.c.get('foreign_recovery') or {}
        return self.c.get('follower_state') or recovery.get('follower_state')

    def paid_batch_spool(self, number, view, directory):
        """A spool holding exactly the batch this worker's DA key already paid for L2 block `number`, or None.

        A database restored to the accepted head (an old backup, a rebuild from L1) no longer holds the unsettled
        block whose batch is on L1, and the spool may no longer hold its transactions. Building the block from
        whatever the spool holds now would publish another batch for the same number and pay a second DA fee,
        while the paid transactions are dropped. Built from exactly the paid batch, the block carries the recorded
        commitment and publish_da finds it already on L1. Only batches signed by this worker's own funding key are
        reused: anyone can publish a DA record for any number, and a block must never be filled with a third
        party's choice of transactions. The transactions also go back to the main spool, so none is lost if the
        rebuilt block differs."""
        if not self.c['user_transactions']:
            return None
        records = [r for r in view.get('data_availability', []) if r.get('l2_number') == number]
        if not records:
            return None
        local = {}
        for other in sorted(self.work.glob(f'{number:08d}-*')):
            payload_file = other / 'da-payload.hex'
            if payload_file.exists():
                payload = bytes.fromhex(payload_file.read_text().strip())
                local[da_commitment(number, payload, self.chain_id).hex()] = payload
        own = bytes.fromhex(Path(self.c['da']['funding_pubkey']).read_text().strip())
        batches = {}
        state = self.follower_state_dir()
        if state:
            try:
                batches = recorded_da_batches(state, self.chain_id, records)
            except (OSError, ValueError) as error:
                log('da-batch-unrecoverable', number=number, reason=f'follower store: {error}'[:300])
        payload = None
        for record in sorted(records, key=lambda r: (int(r['height']), r['commitment'])):
            key = (number, record['commitment'])
            if key in batches and batches[key][0] == own:
                payload, source = batches[key][1], 'follower'
                break
            if record['commitment'] in local:
                payload, source = local[record['commitment']], 'work'
                break
        if payload is None:
            log('da-batch-unrecoverable', number=number, records=[r['commitment'] for r in records],
                follower_state=bool(state), reason='no recorded batch of this DA key found')
            return None
        transactions = da_batch_transactions(payload)
        pool = directory / 'da-reuse-spool'
        shutil.rmtree(pool, ignore_errors=True)
        pool.mkdir()
        main = Path(self.c['txpool_dir'])
        returned = 0
        for raw in transactions:
            name = f'{keccak256(raw).hex()}.tx'
            atomic_write(pool / name, raw.hex() + '\n')
            if not (main / name).exists():
                atomic_write(main / name, raw.hex() + '\n')
                returned += 1
        log('da-batch-reused', number=number, commitment=da_commitment(number, payload, self.chain_id).hex(),
            transactions=len(transactions), returned_to_spool=returned, source=source)
        return pool

    def prepare_block(self, view):
        """Return (number, directory) for the next block, reusing a crash-left block."""
        self.program = self.program_of(view)
        accepted = view.get('accepted')
        number = statement_fields(accepted['statement'])['l2_number'] + 1 if accepted else 1
        parent = statement_fields(accepted['statement'])['l2_hash'] if accepted else self.c['l2_genesis']
        anchor = view['source']['block']
        directory = self.work / f'{number:08d}-{anchor[:16]}'
        self.follow_program(number, directory)
        directory.mkdir(parents=True, exist_ok=True)
        source = view['source']
        pending = source.get('pending', [])
        if len(pending) != source.get('consumed_end', 0) - source.get('consumed_start', 0):
            raise Halt('native pending deposits do not match the consumed range')
        deposits = directory / 'deposits.json'
        deposits_text = json.dumps(pending, sort_keys=True)
        if deposits.exists() and deposits.read_text() != deposits_text:
            raise Halt(f'{deposits} already holds different deposits')
        atomic_write(deposits, deposits_text)
        due = forced_due(view)
        forced = directory / 'forced.json'
        if due is not None:
            forced_text = json.dumps(due, sort_keys=True)
            if forced.exists() and forced.read_text() != forced_text:
                raise Halt(f'{forced} already holds different forced records')
            atomic_write(forced, forced_text)
        elif forced.exists() and json.loads(forced.read_text()):
            raise Halt(f'{forced} holds forced records, the native view has no forced queue')
        head = self.produce('head', '--target', self.c['l2_db'])
        produced = directory / 'block.json'
        if head['number'] < number - 1:
            raise ForeignSettlement(f'native accepted L2 block {number - 1} with a statement this worker did not '
                                    f'submit (another settler?): the local head is {head["number"]}')
        if head['number'] == number - 1:
            if head['hash'] != parent:
                raise ForeignSettlement(f'L2 head {head["hash"]} is not the accepted parent {parent} '
                                        f'of block {number} (another settler?)')
            anchor_slot = int(source['request'].splitlines()[3])
            self.preflight_source = view['source']['request'] + (accepted['commitment'] if accepted else '0' * 64) + '\n' + (
                f"{source['inbox_count']}\n{source['consumed_start']}\n{source['consumed_end']}\n" if 'inbox_count' in source else '')
            reuse = self.paid_batch_spool(number, view, directory)
            if not reuse:
                self.censor_spool(number)
            block = self.extend(parent, anchor, deposits, anchor_slot, number, spool=reuse or True)
            check_forced_block(block, due or [])
            if user_count(block) and not self.c['user_transactions']:
                raise Halt('producer included user transactions while user_transactions is false')
            if reuse:
                atomic_write(directory / 'da-reuse.json', json.dumps({'transactions': user_count(block),
                                                                       'hash': block.get('hash')}) + '\n')
            atomic_write(produced, json.dumps(block, sort_keys=True) + '\n')
            log('l2-block-produced', **{k: block[k] for k in ('number', 'hash', 'deposits', 'transactions', 'user_transactions',
                                                               'forced', 'withdrawal_count', 'rules', 'timestamp') if k in block},
                deferred=len(block.get('deferred', [])), dropped=block.get('dropped', []))
        elif head['number'] == number:
            # Crash after extend: reuse only the block built on this exact parent and anchor.
            if self.local_hash(number - 1) != parent:
                raise ForeignSettlement(f'unsettled L2 block {number} does not extend the accepted parent {parent} '
                                        '(another settler?)')
            probe = self.work / f'.probe-{number}.artifact'
            probe.unlink(missing_ok=True)
            info = self.produce('export', '--target', self.c['l2_db'], '--number', str(number), '--out', str(probe),
                                *self.export_witness())
            probe.unlink()
            if info['anchor'] != anchor:
                raise Halt(f'unsettled L2 block {number} has anchor {info["anchor"]}, native now requests {anchor}')
            log('l2-block-reused', number=number, hash=info['hash'])
        else:
            raise Halt(f'L2 head {head["number"]} cannot extend accepted settlement {number - 1}')
        artifact = directory / 'block.artifact'
        if not artifact.exists():
            self.produce('export', '--target', self.c['l2_db'], '--number', str(number), '--out', str(artifact),
                         *self.export_witness())
            if self.next_program is not None:
                atomic_write(directory / 'program.json', json.dumps({'name': self.program['name']}) + '\n')
        request = directory / 'native-request.txt'
        text = view['source']['request'] + (accepted['commitment'] if accepted else '0' * 64) + '\n'
        if 'inbox_count' in source:
            text += f"{source['inbox_count']}\n{source['consumed_start']}\n{source['consumed_end']}\n"
        if request.exists() and request.read_text() != text:
            raise Halt(f'{request} already holds a different request')
        atomic_write(request, text)
        return number, directory

    def local_hash(self, number):
        """The hash of block `number` in the local database."""
        if number == 0:
            return self.c['l2_genesis']
        return self.produce('hash', '--target', self.c['l2_db'], '--number', str(number))['hash']

    def request_moved(self, view):
        """Whether a settlement was accepted or the request changed since `view` (None view: unknown, not moved)."""
        current = self.native_view()
        return current is not None and (current.get('accepted') != view.get('accepted')
                                        or current['source'] != view['source'])

    def prove(self, directory, stages=('execute', 'prove', 'verify'), view=None):
        """The proof path. None when `view` is given and went stale after execute: no Groth16 for a dead block."""
        proof = directory / 'settlement.proof'
        if (directory / 'proved.json').exists():
            return proof
        # Docker mounts host paths: temporary files must live in a host-visible directory.
        env = {'PATH': self.c.get('prover_path', '/usr/bin:/bin'), 'HOME': self.c['home'], 'TMPDIR': self.c['home'] + '/tmp',
               'RAYON_NUM_THREADS': str(self.c['prover_threads']), 'SP1_CIRCUIT_MODE': 'release',
               'SP1_GNARK_IMAGE': self.c['gnark_image'],
               'BLOCH_NATIVE_L2_REQUEST': str(directory / 'native-request.txt'),
               'BLOCH_NATIVE_L2_ARTIFACT': str(directory / 'block.artifact')}
        steps = []
        for name, args in (('execute', ['execute']), ('prove', ['prove-groth16']), ('verify', ['verify-groth16'])):
            if name not in stages:
                continue
            argv = [self.program['prover'], *self.program['prover_args'], *args, 'native-artifact', self.program['guest']] \
                + ([] if name == 'execute' else [str(proof)])
            if name == 'prove':
                proof.unlink(missing_ok=True)
            start = self.clock()
            order = self.program['remote_prover']['order'] if name == 'prove' and self.program.get('remote_prover') else ['local']
            for where in order:
                if name == 'prove':
                    proof.unlink(missing_ok=True)
                if where == 'remote':
                    result = self.prove_remote(directory, proof)
                elif name == 'prove' and not self.local_proof_fits(directory):
                    result = types.SimpleNamespace(returncode=75)
                else:
                    with (directory / f'{name}.log').open('w') as out:
                        result = self.run_bounded(argv, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=3600)
                if result.returncode == 0:
                    break
                if name == 'prove':
                    log('prover-failed', directory=str(directory), where=where, exit_code=result.returncode)
            steps.append({'name': name, 'where': where, 'exit_code': result.returncode,
                          'seconds': round(self.clock() - start, 1)})
            if result.returncode:
                raise RuntimeError(f'prover {name} failed: see {directory}/{name}.log')
            if name == 'execute' and view is not None and self.request_moved(view):
                log('request-moved-before-proof', directory=str(directory))
                return None
        if 'verify' not in stages:
            log('prover-stages-done', directory=str(directory), steps=steps)
            return None
        atomic_write(directory / 'proved.json', json.dumps({'steps': steps, 'proof_sha256': digest(proof)}, indent=2) + '\n')
        log('proof-generated', directory=str(directory), seconds=sum(s['seconds'] for s in steps), program=self.program['name'])
        return proof

    def local_proof_fits(self, directory):
        """Whether the local prover may try this block: `local_prove_max_sp1_gas` and `local_prove_max_instructions`
        against what the guest reported in this block's execute stage. A deposit-only block over the budget comes here too:
        it goes to the remote prover, or waits for `l2_stuck_block.py import-proof`, without running the host out of memory."""
        log_file = directory / 'execute.log'
        limit = self.c.get('local_prove_max_sp1_gas')
        if limit is not None:
            gas = re.findall(r'Settlement V3 cost: gas=(\d+)', log_file.read_text(errors='replace')) if log_file.exists() else []
            if not gas or int(gas[-1]) > limit:
                log('local-proof-refused', directory=str(directory), sp1_gas=int(gas[-1]) if gas else None, limit=limit)
                return False
        limit = self.c.get('local_prove_max_instructions')
        if limit is None:
            return True
        found = re.findall(r'(\d+) instructions', log_file.read_text()) if log_file.exists() else []
        instructions = int(found[-1]) if found else None
        if instructions is not None and instructions <= limit:
            return True
        log('local-proof-refused', directory=str(directory), instructions=instructions, limit=limit)
        return False

    def run_bounded(self, argv, timeout, **kwargs):
        """Run a prover with a time limit that holds for everything it starts. subprocess.run kills only the direct child
        on a timeout: the SP1 native runner it spawned would live on and keep its memory. So the prover gets its own
        process group, which is killed on a timeout and after every exit. An injected runner (tests) is used as given."""
        if self.run is not subprocess.run:
            return self.run(argv, timeout=timeout, **kwargs)
        shm = str(Path(self.c.get('prover_shm_dir', '/dev/shm')) if hasattr(self, 'c') else Path('/dev/shm'))
        process = subprocess.Popen(argv, start_new_session=True, **kwargs)
        ours = set()  # segments a process of this run's group mapped: only these may be removed afterwards
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                ours |= group_segments(process.pid, shm)
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                time.sleep(0.5)
        except BaseException:
            ours |= group_segments(process.pid, shm)
            self.kill_group(process.pid)
            process.wait()
            time.sleep(0.2)
            remove_leaked_segments(ours)
            raise
        ours |= group_segments(process.pid, shm)
        self.kill_group(process.pid)  # whatever it left running
        time.sleep(0.2)  # let the kernel tear down the killed processes' mappings
        remove_leaked_segments(ours)
        return subprocess.CompletedProcess(argv, process.returncode)

    @staticmethod
    def kill_group(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def prove_remote(self, directory, proof):
        """Groth16 on the remote prover; the caller still verifies it locally."""
        r = self.program['remote_prover']
        request = (directory / 'native-request.txt').read_bytes()
        artifact = (directory / 'block.artifact').read_bytes()
        frame = (REMOTE_MAGIC + struct.pack('>I', len(request)) + request
                 + struct.pack('>Q', len(artifact)) + artifact)
        argv = [r.get('ssh', '/usr/bin/ssh'), '-i', r['key'], '-p', str(r.get('port', 22)),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + r['known_hosts'], '-o', 'ConnectTimeout=20',
                '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=6', r['target'], 'prove']
        partial = directory / 'settlement.proof.partial'
        with partial.open('wb') as out, (directory / 'prove-remote.log').open('w') as err:
            result = self.run(argv, input=frame, stdout=out, stderr=err,
                              timeout=r.get('timeout_seconds', 3600))
        size = partial.stat().st_size
        if result.returncode == 0 and not 0 < size <= REMOTE_MAX_PROOF_BYTES:
            result.returncode = 70
        if result.returncode == 0:
            partial.replace(proof)
        else:
            partial.unlink(missing_ok=True)
        log('remote-proof', target=r['target'], exit_code=result.returncode, bytes=size)
        return result

    def check_v3(self, values, directory, previous=None):
        """V3-only pre-submit checks (the V2-prefix checks are in transaction()).
        `previous` is the accepted head statement (bytes) or None."""
        field = lambda offset: values[T + offset:T + offset + 32]  # noqa: E731
        number = lambda offset: int.from_bytes(values[T + offset:T + offset + 8], 'big')  # noqa: E731
        pending = json.loads((directory / 'deposits.json').read_text())
        forced = read_forced(directory)
        # Under L1 forced inclusion the slot binds the consumed deposits and the due forced records together.
        if field(DEPOSITS_HASH) != inbox_hash(deposits_hash(pending), forced):
            raise Halt('statement deposits_hash does not match the native pending deposits' +
                       (' and forced records' if forced else ''))
        if field(TRANSACTIONS_ROOT) == bytes(32) or field(RECEIPTS_ROOT) == bytes(32):
            raise Halt('statement has a zero transactions or receipts root')
        root, count = check_withdrawals(values, previous)
        users = number(USER_TX_COUNT)
        if users and not self.c['user_transactions']:
            raise Halt(f'statement reports {users} user transactions while user_transactions is false')
        produced = directory / 'block.json'
        if produced.exists():
            block = json.loads(produced.read_text())
            check_forced_block(block, forced)
            expected = user_count(block)
            if users != expected:
                raise Halt(f'statement reports {users} user transactions, the producer included {expected}')
            if 'withdrawal_count' in block and (block['withdrawal_root'] != root.hex()
                                                or block['withdrawal_count'] != count):
                raise Halt('statement withdrawal root/count differ from the producer block')
        if not users:
            if field(DA_COMMITMENT) != bytes(32):
                raise Halt('statement da_commitment is not zero without user transactions')
            return users
        payload = self.da_payload(number(264), directory)
        if da_batch_count(payload) != users:
            raise Halt('DA batch does not hold exactly the statement user transactions')
        if field(DA_COMMITMENT) != da_commitment(number(264), payload, self.chain_id):
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
        """Publish the block's batch on L1 and wait until the record is committed.

        A DA transaction is valid only in a block whose base fee is the one it was signed for (exact fee
        conservation). Once the next base fee moves, the signed bytes can no longer be included, so the batch is
        re-signed at the new fee at once instead of waiting `inclusion_timeout_seconds`. Every attempt spends the
        inputs of the previous one (they are put first), so at most one attempt can ever be included and the fee is
        paid once. Stale attempts stay in node mempools until their TTL and count against the per-source mempool
        cap (MEMPOOL_MAX_PER_SOURCE 64, TTL 100 slots): at most `da.max_attempts_per_window` (default 32) attempts
        are signed per `da.attempt_window_seconds` (default 3000 s, 100 slots of 30 s); past that the worker waits
        on the last attempt as before."""
        commitment = values[T + DA_COMMITMENT:T + DA_COMMITMENT + 32]
        while True:
            outcome = self.publish_da_attempt(number, directory, commitment)
            if outcome != 'fee-moved':
                return outcome

    def da_attempts_in_window(self, directory):
        """Signed attempts of this block within the mempool-retention window."""
        window = int(self.c['da'].get('attempt_window_seconds', 3000))
        now, count = self.wall(), 0
        for meta in directory.glob('da-meta-*.json'):
            try:
                signed = json.loads(meta.read_text()).get('signed_unix')
            except ValueError:
                continue
            count += signed is None or now - signed < window
        return count

    def publish_da_attempt(self, number, directory, commitment):
        """One sign-or-rebroadcast and wait. True: recorded; False: give up this cycle; 'fee-moved': re-sign now."""
        if self.da_recorded(number, commitment):
            return True
        da = self.c['da']
        base_fee = str(self.native.bounded_value('getchaininfo', 'next_base_fee_millisat_per_gas'))
        utxos = self.native.common_utxos(self.da_script)
        balance = sum(int(u['value_sat']) for u in utxos)
        payload_bytes = len((directory / 'da-payload.hex').read_text().strip()) // 2
        estimate = da_fee_sat(payload_bytes, 1, int(base_fee), int(da.get('tip_millisat_per_gas', 0)))
        if balance < int(da.get('low_balance_sat', 0)):
            log('da-funding-low', balance_sat=balance, low_balance_sat=int(da['low_balance_sat']),
                funding_script=self.da_script)
        utxos = sorted(utxos, key=lambda u: (-int(u['value_sat']), u['txid'], u['vout']))
        if self.dry_run:
            raise Halt(f'dry run never signs or broadcasts the DA batch (fee estimate {estimate} sat)')
        form = self.da_signature_form()
        if form is None:
            return False
        attempt = 0
        while (directory / f'da-unsigned-{attempt}.hex').exists():
            attempt += 1
        # Rebroadcast the last signed bytes while they can still be included: consensus needs exact
        # conservation at the including block's base fee, and every input must still be unspent.
        last = directory / f'da-meta-{attempt - 1}.json'
        meta = json.loads(last.read_text()) if attempt and last.exists() else None
        unspent = {f"{u['txid']}:{u['vout']}:{u['value_sat']}" for u in utxos}
        if meta and (directory / f'da-signed-{attempt - 1}.hex').exists() and set(meta['inputs']) <= unspent:
            # A new attempt spends the previous one's inputs first, so two attempts can never both be included.
            first = {item: i for i, item in enumerate(meta['inputs'])}
            utxos.sort(key=lambda u: first.get(f"{u['txid']}:{u['vout']}:{u['value_sat']}", len(first)))
            tx = bytes.fromhex((directory / f'da-signed-{attempt - 1}.hex').read_text().strip())
            limited = self.da_attempts_in_window(directory) >= int(da.get('max_attempts_per_window', 32))
            if (meta['base_fee'] == base_fee and meta.get('form', []) == form) or (limited and meta.get('form', []) == form):
                if limited and meta['base_fee'] != base_fee:
                    log('da-resign-limited', number=number, attempts=attempt, signed_base_fee=meta['base_fee'],
                        base_fee=base_fee)
                return self.submit_da(number, directory, tx, commitment, attempt - 1, estimate,
                                      None if limited else meta['base_fee'])
        utxos = utxos[:DA_MAX_INPUTS]
        if not utxos:
            raise Halt('the DA funding key has no spendable outputs')
        env = {'PATH': '/usr/bin:/bin', 'HOME': self.c['home'], 'BLOCH_KEYSTORE_PASSPHRASE_FILE': da['passphrase_file']}
        unsigned, signed = directory / f'da-unsigned-{attempt}.hex', directory / f'da-signed-{attempt}.hex'
        result, inputs = None, []
        for count in range(1, len(utxos) + 1):
            unsigned.unlink(missing_ok=True)
            argv = [da['signer'], 'l2-da', 'prepare', '--genesis', da['genesis'], '--funding-pubkey', da['funding_pubkey'],
                    '--chain-id', str(self.chain_id), '--number', str(number), '--payload', str(directory / 'da-payload.hex'),
                    '--base-fee', base_fee, '--tip', str(da.get('tip_millisat_per_gas', 0)), '--out', str(unsigned)]
            inputs = [f"{u['txid']}:{u['vout']}:{u['value_sat']}" for u in utxos[:count]]
            for item in inputs:
                argv[3:3] = ['--input', item]
            result = self.run(argv, env=env, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                break
        if result is None or result.returncode:
            raise Halt(f'DA prepare failed: {(result.stderr if result else "").strip()[:400]}')
        result = self.run([da['signer'], 'l2-da', 'sign', '--genesis', da['genesis'], '--tx', str(unsigned),
                           '--dir', da['keystore_dir'], *form, '--out', str(signed)],
                          env=env, capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise Halt(f'DA signer refused: {result.stderr.strip()[:400]}')
        tx = bytes.fromhex(signed.read_text().strip())
        payload = bytes.fromhex((directory / 'da-payload.hex').read_text().strip())
        if da_frame_fields(tx) != (self.chain_id, number, payload):
            raise Halt('signed DA transaction does not carry this block batch')
        atomic_write(directory / f'da-meta-{attempt}.json', json.dumps({'base_fee': base_fee, 'inputs': inputs,
                                                                        'form': form, 'signed_unix': int(self.wall())}) + '\n')
        return self.submit_da(number, directory, tx, commitment, attempt, estimate, base_fee)

    def da_signature_form(self):
        """The `l2-da sign` signature flags for the next DA transaction (L1 hard fork
        SIG_CANONICAL_ACTIVATION_EPOCH, read from the pinned signer): [] while the gate is inert or the
        signer predates it (the pre-fork command line), else `--for-epoch <L1 head epoch>`. None = wait:
        from one epoch before the activation until it, a transaction signed now could be included on
        either side of the fork, so the DA batch (and with it this block's settlement) waits, at most
        about one epoch. Signed bytes are reused only in the form they were signed for."""
        da = self.c['da']
        result = self.run([da['signer'], 'l2-da', 'signature-forms'], capture_output=True, text=True, timeout=60)
        if result.returncode:
            return []
        activation = None
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == 'sig_canonical_activation_epoch' and parts[1] != 'inert':
                activation = int(parts[1])
        if activation is None:
            return []
        epoch = self.native.bounded_value('getchaininfo', 'epoch')
        if activation - 1 <= epoch < activation:
            log('da-paused-signature-fork', epoch=epoch, activation_epoch=activation)
            return None
        return ['--for-epoch', str(epoch)]

    def submit_da(self, number, directory, tx, commitment, attempt, estimate, signed_base_fee=None):
        """Send the DA bytes and wait for the record. With `signed_base_fee`, return 'fee-moved' as soon as the
        next base fee differs from it: those bytes can then no longer be included, and waiting is pointless."""
        da = self.c['da']
        port, response = self.native.submit(tx.hex())
        log('da-submitted', number=number, bytes=len(tx), commitment=commitment.hex(), response=response.get('status'),
            port=port, attempt=attempt, fee_estimate_sat=estimate, signed_base_fee=signed_base_fee)
        deadline = self.clock() + da.get('inclusion_timeout_seconds', 300)
        while self.clock() < deadline:
            self.sleep(self.c['poll_seconds'])
            if self.da_recorded(number, commitment):
                log('da-included', number=number, commitment=commitment.hex(), attempt=attempt)
                return True
            # Settling a block removes its DA records: this one will never show up, so do not wait for it.
            view = self.native_view()
            accepted = view and view.get('accepted')
            if accepted and statement_fields(accepted['statement'])['l2_number'] >= number:
                log('da-wait-ended-block-settled', number=number)
                return False
            if signed_base_fee is not None:
                try:
                    now = str(self.native.bounded_value('getchaininfo', 'next_base_fee_millisat_per_gas'))
                except Exception:  # noqa: BLE001 - no fee read this poll; keep waiting
                    continue
                if now != signed_base_fee:
                    log('da-fee-moved', number=number, attempt=attempt, signed_base_fee=signed_base_fee, base_fee=now)
                    return 'fee-moved'
        log('da-inclusion-timeout', number=number)
        return False

    def transaction(self, directory, proof_path, accepted=None):
        values, proof = parse_proof_artifact(proof_path.read_bytes())
        config = Path(self.program['l2_config']).read_bytes()
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
        previous = bytes.fromhex(accepted['statement']) if accepted else None
        users = self.check_v3(values, directory, previous)
        tx = bytes([ASYNC_SETTLEMENT_TAG]) + config[160:192] + values + proof
        if len(tx) != TRANSACTION_BYTES:
            raise Halt('settlement transaction has the wrong length')
        if self.mainnet_path and (tx[1:33].hex() != MAINNET['proof_policy']
                             or int.from_bytes(values[T + 256:T + 264], 'big') != MAINNET['chain_id']):
            raise Halt('settlement does not carry the mainnet proof policy and chain id')
        atomic_write(directory / 'transaction.bin', tx)
        root, count = withdrawal_fields(values)
        log('transaction-built', directory=str(directory), user_transactions=users, bytes=len(tx),
            withdrawal_root=root.hex(), withdrawal_count=count)
        return tx

    def l1_height(self):
        """The native head height no larger than an honest endpoint reports, or None."""
        try:
            return self.native.bounded_value('getchaininfo', 'height')
        except Exception:  # noqa: BLE001 - only a diagnostic
            return None

    def accepted_outcome(self, number, values, current):
        """'ours' when the quorum view accepted exactly these values for `number`,
        None while it has not; halts when anything else was accepted there."""
        accepted = current and current.get('accepted')
        if not accepted:
            return None
        seen = statement_fields(accepted['statement'])['l2_number']
        if seen < number:
            return None
        if seen == number and bytes.fromhex(accepted['statement']) == values:
            return 'ours'
        raise ForeignSettlement(f'native accepted L2 block {seen} with a statement this worker did not submit '
                                f'(another settler?) while settling {number}')

    def broadcast(self, number, directory, tx, record):
        """Submit (or rebroadcast) the same bytes. True when some endpoint holds them,
        False when every refusal was transient; a terminal refusal returns 'terminal'."""
        try:
            port, response = self.native.submit(tx.hex())
        except SubmitRefused as refused:
            kind = refused.kind()
            log('submit-refused', number=number, kind=kind, errors=[f'{p}: {e}'[:300] for p, e in refused.errors])
            return 'terminal' if kind == 'terminal' else False
        record['attempts'] = record.get('attempts', 0) + 1
        record.setdefault('first_unix', int(time.time()))
        record['last_status'] = response.get('status')
        atomic_write(directory / 'submitted.json', json.dumps(record, indent=2) + '\n')
        log('submitted' if response.get('status') != 'duplicate' else 'submitted-duplicate', number=number,
            response=response.get('status'), tx_hash=response.get('tx_hash'), port=port, attempt=record['attempts'])
        return True

    def submit_and_wait(self, number, directory, tx, view):
        values = tx[33:33 + VALUES_BYTES]
        current = self.native_view()
        if current is not None and self.accepted_outcome(number, values, current) == 'ours':
            return self.record_accepted(number, directory, current['accepted'])
        if current is None or current['source'] != view['source'] or current.get('accepted') != view.get('accepted'):
            log('request-moved-before-submit', number=number)
            return False
        if current.get('program') != view.get('program'):
            # The proof is of the old program: L1 refuses it from here on. The next cycle rebuilds this block.
            log('program-moved-before-submit', number=number, program=current.get('program'))
            return False
        path = directory / 'submitted.json'
        record = json.loads(path.read_text()) if path.exists() else {}
        if record.get('tx_sha256') not in (None, hashlib.sha256(tx).hexdigest()):
            raise Halt(f'{directory} was submitted with other settlement bytes')
        record['tx_sha256'] = hashlib.sha256(tx).hexdigest()
        if self.dry_run:
            raise Halt('dry run never broadcasts')
        height = self.l1_height()
        sent = self.broadcast(number, directory, tx, record)
        last_sent = self.clock()
        deadline = self.clock() + self.c['acceptance_timeout_seconds']
        while self.clock() < deadline:
            self.sleep(self.c['poll_seconds'])
            current = self.native_view()
            if current is None:
                continue
            if self.accepted_outcome(number, values, current) == 'ours':
                return self.record_accepted(number, directory, current['accepted'])
            if current['source'] != view['source']:
                log('request-moved-after-submit', number=number)
                return False
            if current.get('program') != view.get('program'):
                log('program-moved-after-submit', number=number, program=current.get('program'))
                return False
            if sent == 'terminal':
                # The bytes are invalid against the request they were built for: never loop on them.
                raise Halt(f'native nodes refuse the settlement of L2 block {number} '
                           '(policy, source, successor or proof) while its request is unchanged')
            if self.clock() - last_sent >= self.c['resubmit_seconds'] or not sent:
                sent, last_sent = self.broadcast(number, directory, tx, record), self.clock()
        now = self.l1_height()
        log('acceptance-timeout', number=number, l1_height_at_submit=height, l1_height_now=now,
            submitted=bool(sent))
        if height is not None and now is not None and now <= height:
            log('l1-not-advancing', number=number, l1_height=now)  # the L1 is stalled; nothing to fix here
        return False

    def record_accepted(self, number, directory, accepted):
        atomic_write(directory / 'accepted.json', json.dumps(accepted, indent=2) + '\n')
        log('accepted', number=number, commitment=accepted['commitment'],
            l2_hash=statement_fields(accepted['statement'])['l2_hash'])
        return True

    def cycle(self):
        self.finish_swap()
        if not self.check_identity():
            return False
        view = self.native_view()
        if view is None or view.get('source') is None:
            return False
        try:
            if self.c.get('skip_idle_blocks') and self.hold_block(view):
                return False
            try:
                number, directory = self.prepare_block(view)
            except WaitForProgram as wait:
                log('waiting-for-program', reason=str(wait))
                return False
            proof = self.prove(directory, view=view)
            # A proof takes many minutes: never pay DA for a block another settlement made stale meanwhile.
            if proof is None:
                return False
            if self.request_moved(view):
                log('request-moved-after-proof', number=number)
                return False
            tx = self.transaction(directory, proof, view.get('accepted'))
            values = tx[33:33 + VALUES_BYTES]
            if int.from_bytes(values[T + USER_TX_COUNT:T + USER_TX_COUNT + 8], 'big') and \
                    not self.publish_da(number, directory, values):
                return False
            return self.submit_and_wait(number, directory, tx, view)
        except ForeignSettlement as foreign:
            return self.recover_foreign(str(foreign))

    # ---- foreign settlements: rebuild from L1 and continue ----
    def recover_foreign(self, reason):
        """Replace a database that does not hold the accepted settlement with one rebuilt from finalized L1
        blocks. False while waiting; True once swapped. Halts when L1 data cannot reproduce the block."""
        recovery = self.c.get('foreign_recovery')
        if not recovery or self.dry_run:
            raise Halt(reason)
        view = self.native_view()
        accepted = view and view.get('accepted')
        if not accepted:
            return False
        fields = statement_fields(accepted['statement'])
        number, l2_hash = fields['l2_number'], fields['l2_hash']
        finals = follower_finals(recovery['follower_status'])
        expected_root = fields['l2_state_root']
        if finals.get(number) != l2_hash:
            if self.waiting_for != l2_hash:
                self.waiting_for = l2_hash
                log('foreign-settlement-waiting-finality', number=number, l2_hash=l2_hash, finalized_prefix=max(finals, default=0),
                    reason=reason[:300])
            # A tip that keeps moving must not hold back the finalized prefix: rebuild to it when the
            # database has left it. A database on the prefix has nothing to gain, so it waits.
            prefix = max(finals, default=0)
            if not prefix or self.holds_block(prefix, finals[prefix]):
                return False
            number, l2_hash, expected_root = prefix, finals[prefix], None
        # One rebuild per input: a rebuild that did not hold the target is not repeated until the follower has more.
        tip = follower_verified_tip(recovery['follower_status'])
        if self.rebuild_discarded_at is not None and self.rebuild_discarded_at == tip:
            return False
        db = Path(self.c['l2_db'])
        rebuilding = db.with_name(db.name + '.rebuilding')
        shutil.rmtree(rebuilding, ignore_errors=True)
        args = [self.c['produce'], 'reconstruct', '--target', str(rebuilding), '--l1-follower', recovery['follower_state']]
        if self.c.get('timestamp_rule'):
            args += ['--timestamp-rule', self.c['timestamp_rule']]
        start = self.clock()
        result = self.run([*args, *self.network_args], capture_output=True, text=True,
                          timeout=recovery.get('rebuild_timeout_seconds', 3600))
        if result.returncode:
            shutil.rmtree(rebuilding, ignore_errors=True)
            raise Halt(f'rebuild from L1 refused while recovering from a foreign settlement of L2 block {number}: the '
                       f'block is off-rule, or the follower store is damaged: {result.stderr.strip()[:400]}')
        document = json.loads(result.stdout)
        blocks = {b['number']: b for b in document.get('blocks', [])}
        rebuilt = blocks.get(number)
        # `reconstruct` replays everything the follower verified, so the head can lie above the target. The target
        # must be there; the worker then holds the newest settled block and competes from it. A later reorg of that
        # unfinalized tail on L1 is one more divergence, recovered the same way.
        if rebuilt is None or rebuilt['hash'] != l2_hash or expected_root not in (None, rebuilt['state_root']):
            shutil.rmtree(rebuilding, ignore_errors=True)
            self.rebuild_discarded_at = tip
            log('foreign-rebuild-behind-view', number=number, rebuilt_head=document.get('head'))
            return False
        self.rebuild_discarded_at = None
        number, l2_hash = max(blocks), blocks[max(blocks)]['hash']
        wrong = [n for n, h in finals.items() if n in blocks and blocks[n]['hash'] != h]
        if wrong:
            shutil.rmtree(rebuilding, ignore_errors=True)
            raise Halt(f'rebuilt blocks {wrong[:8]} differ from the finalized settlements')
        common, old_head = self.common_ancestor(blocks, number)
        orphans = list(range(common + 1, old_head + 1))
        respooled = self.respool_orphans(orphans)
        stale = self.stale_directories(common, old_head, number)
        proofs = sum((d / 'proved.json').exists() for d in stale)
        da_paid = sum(len(list(d.glob('da-signed-*.hex'))) for d in stale)
        stamp = time.time_ns()
        ready = db.with_name(f'{db.name}.rebuilt-{stamp}')
        rebuilding.rename(ready)
        journal = {'rebuilt': str(ready), 'kept': str(db.with_name(f'{db.name}.orphaned-{stamp}')),
                   'work_aside': str(self.work.parent / f'{self.work.name}-orphaned-{stamp}'),
                   'stale': [d.name for d in stale], 'number': number, 'l2_hash': l2_hash}
        atomic_write(self.recovery_journal(), json.dumps(journal, indent=2) + '\n')
        self.finish_swap()
        self.waiting_for = None
        log('foreign-settlement-recovered', number=number, l2_hash=l2_hash, common_ancestor=common,
            orphaned_blocks=orphans, respooled=respooled, wasted_proofs=proofs, wasted_da_signed=da_paid,
            rebuild_seconds=round(self.clock() - start, 1), native_blocks=document.get('native_blocks'))
        return True

    def holds_block(self, number, l2_hash):
        """Whether the local database has this hash at this number."""
        try:
            head = self.produce('head', '--target', self.c['l2_db'])['number']
            return head >= number and self.local_hash(number) == l2_hash
        except ProducerError:
            return False

    def recovery_journal(self):
        return Path(self.c['l2_db']).with_name(Path(self.c['l2_db']).name + '.recovery.json')

    def common_ancestor(self, blocks, number):
        """(highest local block on the rebuilt chain, local head). A missing database counts as genesis."""
        if not Path(self.c['l2_db']).exists():
            return 0, 0
        old_head = self.produce('head', '--target', self.c['l2_db'])['number']
        for candidate in range(min(old_head, number), 0, -1):
            if self.local_hash(candidate) == blocks[candidate]['hash']:
                return candidate, old_head
        return 0, old_head

    def respool_orphans(self, orphans):
        """Return the user transactions of orphaned local blocks to the spool (whole files; idempotent). The
        producer drops any of them the settled chain already executed. Returns the number of files written."""
        if not self.c.get('txpool_dir'):
            return 0
        written = 0
        for number in orphans:
            path = self.work / f'.orphan-{number}.hex'
            path.unlink(missing_ok=True)
            try:
                self.produce('da', '--target', self.c['l2_db'], '--number', str(number), '--out', str(path))
            except ProducerError as error:
                if 'no user transactions' in str(error):
                    continue
                raise
            for raw in da_batch_transactions(bytes.fromhex(path.read_text().strip())):
                target = Path(self.c['txpool_dir']) / f'{keccak256(raw).hex()}.tx'
                if not target.exists():
                    atomic_write(target, raw.hex() + '\n')
                    written += 1
            path.unlink()
        return written

    def stale_directories(self, common, old_head, accepted):
        """Work directories of orphaned local blocks, and of blocks this worker never got accepted at or below
        the accepted number. Their proofs and signed DA bytes must never be used again."""
        stale = []
        for path in sorted(self.work.iterdir()) if self.work.is_dir() else []:
            head = path.name.split('-')[0]
            if path.is_dir() and len(head) == 8 and head.isdigit():
                number = int(head)
                if common < number <= old_head or (number <= accepted and not (path / 'accepted.json').exists()):
                    stale.append(path)
        return stale

    def finish_swap(self):
        """Complete a journalled swap; every step is skipped once done, so a crash at any point resumes here."""
        journal = self.recovery_journal()
        if not journal.exists():
            return
        state = json.loads(journal.read_text())
        db, rebuilt, kept = Path(self.c['l2_db']), Path(state['rebuilt']), Path(state['kept'])
        if rebuilt.exists():
            if db.exists():
                db.rename(kept)
            rebuilt.rename(db)
        aside = Path(state['work_aside'])
        aside.mkdir(exist_ok=True)
        for name in state['stale']:
            if (self.work / name).exists():
                (self.work / name).rename(aside / name)
        keep = self.c['foreign_recovery'].get('keep', 2) if self.c.get('foreign_recovery') else 2
        for prefix, parent in ((f'{db.name}.orphaned-', db.parent), (f'{self.work.name}-orphaned-', self.work.parent)):
            old = sorted((p for p in parent.iterdir() if p.name.startswith(prefix)), key=lambda p: int(p.name[len(prefix):]))
            for path in old[:-keep]:
                shutil.rmtree(path, ignore_errors=True)
        atomic_write(self.work.parent / 'l2-db-generation.json', json.dumps(
            {'database': str(db), 'number': state['number'], 'l2_hash': state['l2_hash'], 'time': int(time.time())}) + '\n')
        journal.unlink()


def check_rpc(config, rpc=rpc, sleep=time.sleep):
    """Read-only: print each endpoint's settlement view and the quorum decision."""
    try:
        endpoints = Endpoints(rpc_endpoints(config), rpc_quorum(config), rpc, time.monotonic, sleep)
    except Halt as error:
        log('halt', reason=str(error))
        return 3
    for port in endpoints.ports:
        try:
            view = rpc(port, 'getl2settlement')
            accepted = view.get('accepted')
            log('rpc-endpoint-view', port=port,
                view_sha256=hashlib.sha256(canonical(settlement_view(view)).encode()).hexdigest(),
                native_height=view.get('native_height'), source_height=(view.get('source') or {}).get('height'),
                accepted=statement_fields(accepted['statement'])['l2_number'] if accepted else None)
        except Exception as error:
            log('rpc-endpoint-view', port=port, error=f'{type(error).__name__}: {error}'[:300])
    try:
        view, support = endpoints.agreed('getl2settlement', project=settlement_view)
    except RuntimeError as error:
        log('rpc-check', quorum=endpoints.quorum, ok=False, reason=str(error))
        return 2
    chain_id = MAINNET['chain_id'] if config.get('network_kind') in MAINNET_PATH_KINDS else CHAIN_ID
    ok = view is not None and view['network'] == config['network'] and view['chain_id'] == chain_id
    log('rpc-check', quorum=endpoints.quorum, ok=ok, ports=support)
    return 0 if ok else 2


def dry_run(config, prove=False, out=None, rpc=rpc, run=subprocess.run, sleep=time.sleep, clock=time.monotonic):
    """Build and validate the next settlement against the live network in a scratch
    directory. Never signs, never calls sendrawtransaction, never writes the live
    L2 database or work directory. Exit 0 when everything checked passes."""
    base = Path(out) if out else Path(config['workdir']).parent / time.strftime('dry-run-%Y%m%dT%H%M%SZ', time.gmtime())
    base.mkdir(parents=True)
    report = {'dry_run': True, 'broadcast': False, 'network_kind': config.get('network_kind', 'devnet'),
              'directory': str(base)}

    def done(ok, **fields):
        report.update(ok=ok, **fields)
        (base / 'dry-run-report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        log('dry-run', **report)
        return 0 if ok else 2

    class NoBroadcast:
        def __init__(self, inner):
            self.inner = inner

        def __call__(self, port, method, params=()):
            if method == 'sendrawtransaction':
                raise Halt('dry run never broadcasts')
            return self.inner(port, method, params)

    try:
        settler = Settler({**config, 'workdir': str(base / 'work'), 'l2_db': str(base / 'canonical')},
                          rpc=NoBroadcast(rpc), run=run, sleep=sleep, clock=clock)
        settler.dry_run = True
        report['chain_id'] = settler.chain_id
        if not settler.check_identity():
            return done(False, reason='no RPC quorum on the network identity')
        view = settler.native_view()
        if view is None or view.get('source') is None:
            return done(False, reason='no RPC quorum on the settlement view, or no source yet')
        source, accepted = view['source'], view.get('accepted')
        report['native'] = {'source_height': source.get('height'), 'source_slot': source.get('slot'),
                            'source_block': source.get('block'), 'inbox_count': source.get('inbox_count'),
                            'pending_deposits': len(source.get('pending', [])),
                            'accepted_l2_number': statement_fields(accepted['statement'])['l2_number'] if accepted else 0,
                            'data_availability_records': len(view.get('data_availability', []))}
        live = Path(config['l2_db'])
        if accepted:
            if not live.is_dir():
                return done(False, reason=f'native accepted L2 block {report["native"]["accepted_l2_number"]}: '
                                          'the dry run needs a copy of the settled L2 database (l2_db)')
            shutil.copytree(live, base / 'canonical')  # stop the settler first: a live RocksDB copy may be torn
        else:
            settler.produce('init', '--target', str(base / 'canonical'))
            head = settler.produce('head', '--target', str(base / 'canonical'))
            if head.get('number') != 0 or head.get('hash') != config['l2_genesis']:
                return done(False, reason=f'producer L2 genesis {head.get("hash")} differs from {config["l2_genesis"]}')
        number, directory = settler.prepare_block(view)
        block = json.loads((directory / 'block.json').read_text()) if (directory / 'block.json').exists() else {}
        report['l2_block'] = {'number': number, **{k: block[k] for k in ('hash', 'deposits', 'transactions', 'user_transactions', 'forced',
                                                                          'withdrawal_count') if k in block}}
        report['native_request'] = (directory / 'native-request.txt').read_text().splitlines()
        if not prove:
            settler.prove(directory, stages=('execute',))
            return done(True, sp1_execute='matched', proof='skipped: --prove also builds and verifies Groth16',
                        settlement_fee_sat=0)
        proof = settler.prove(directory)
        tx = settler.transaction(directory, proof, accepted)
        values = tx[33:33 + VALUES_BYTES]
        users = int.from_bytes(values[T + USER_TX_COUNT:T + USER_TX_COUNT + 8], 'big')
        fee = {'settlement_fee_sat': 0}
        if users:
            payload = settler.da_payload(number, directory)
            base_fee = settler.native.bounded_value('getchaininfo', 'next_base_fee_millisat_per_gas')
            fee['da_fee_estimate_sat'] = da_fee_sat(len(payload), 1, base_fee)
            fee['da_payload_bytes'] = len(payload)
        (base / 'settlement-tx.hex').write_text(tx.hex() + '\n')
        return done(True, sp1_execute='matched', proof='groth16 verified locally',
                    transaction={'tag': hex(tx[0]), 'bytes': len(tx), 'sha256': hashlib.sha256(tx).hexdigest(),
                                 'proof_policy': tx[1:33].hex(), 'user_transactions': users,
                                 'file': str(base / 'settlement-tx.hex')}, **fee)
    except (Halt, ProducerError, ForeignSettlement, WaitForProgram) as error:
        return done(False, reason=str(error))


def main():
    config = json.loads(CONFIG.read_text())
    if sys.argv[1:] == ['--check-rpc']:
        sys.exit(check_rpc(config))
    if sys.argv[1:2] == ['--dry-run']:
        extra = sys.argv[2:]
        out = extra[extra.index('--out') + 1] if '--out' in extra else None
        if not set(extra) - {out} <= {'--prove', '--out'}:
            raise SystemExit('usage: settler_v3.py --dry-run [--prove] [--out NEW_DIR]')
        sys.exit(dry_run(config, prove='--prove' in extra, out=out))
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
