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
  for the same L2 block halts (another settler). Review r10 M2: every
  broadcast (settlement and DA) goes to every configured endpoint, not only
  the first that answers, and `accepted` or `duplicate` from any of them
  counts as held; when an acceptance window ends with the bytes held and the
  L1 head advancing, `settlement-not-included` is logged, and after
  `max_unincluded_windows` such windows in a row (default 4, 0 = alert only)
  the worker halts for the operator. Review r10 L1: a partial quorum that
  stays below the in-memory accepted floor (one endpoint down for good during
  a real L1 reorg) is no longer a silent wait: after
  `quorum_floor_stall_seconds` (default 1200, 0 = off) it logs
  `rpc-quorum-behind-floor` and raises, so the bounded retry exits 1 and the
  restart resets the floor. Review r10 L6: a prover timeout is a failed
  attempt at that location, so the next one in `remote_prover.order` is tried.

* stop signals (review r10 M1): SIGTERM, SIGINT and SIGHUP take the same
  cleanup path as a prover timeout: the prover's process group is killed,
  the SP1 segments it mapped are removed from /dev/shm, and a Gnark container
  it left (found by its bind mounts from the run's private TMPDIR) is killed.
  A second signal does not interrupt that cleanup. The process then ends by
  the signal it received.

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

* `--dry-run [--prove]`: builds the next settlement against the live network
  in a scratch copy of the L2 database and validates it (identity, request,
  producer, SP1 execute; with --prove also Groth16 + every pre-submit check)
  without ever calling sendrawtransaction or signing anything.

* settler authorization (audit AUDIT-L1L2-20261123, L2N-01; optional `settler_authorization`): behind the L1 gate
  `L2_SETTLER_AUTHORIZATION_ACTIVATION_EPOCH` a settlement is accepted only with a trailer signed by a registered
  settler key over the exact settlement (native `l2_settlement::settler`). Before the gate's epoch nothing changes:
  the worker broadcasts the 1155 bytes it broadcasts today, and a trailer would be refused. From that epoch on it
  asks the pinned `bloch-pos l2-settler authorize` tool, which alone opens the sealed settler keystore, for the
  trailer and broadcasts `settlement || signer || signature || next set`. The epoch is read from the L1
  (`getchaininfo.hard_forks`, by quorum) or configured; the form is decided at every broadcast, so a settlement
  proved before the boundary is sent in the form the block that includes it requires. The registered set is the
  set file (the text the L1 release pins); a rotation request (a set file dropped at `rotation_request`) rides on
  the next authorized settlement and the set file is replaced when that settlement is accepted.
* program switch (L2N-01, optional `program_switch`): from the L1 program-switch epoch on the settlement is proved
  with the bound guest (`settlement_v3_mainnet_bound`, prover `--mainnet-bound`) and carries its l2-config
  identities; before it, the deployed program. A proof is started under the bound program `lead_epochs` (default 1)
  before the switch and held until the switch; a deployed-program proof not included by then is proved again.
* DA with the settler key (L1X-04, `da.settler_key`): with the L1 DA settler-slot rule armed one DA place per
  block is kept for batches funded by a registered settler key; the DA transaction is then funded and signed by
  the settler keystore, and a funding key outside the registered set is reported (`da-funding-key-not-registered`).

Each cycle: read the native request all validators agree on, extend the
canonical L2 database by exactly one block anchored to it, prove it, build the
settlement transaction, submit it and wait for native acceptance. The worker
never reads signing keys and never publishes L2 finality. Any divergence stops
the worker (exit 3) for operator review. Dependency-free Python 3.9+. The
worker never reads signing keys itself; with user transactions it invokes the
pinned DA signer (whose keystore holds only DA fee funds), and behind the
settler gate the pinned settler signer (`bloch-pos l2-settler`).
"""
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.parse

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
# DA tip policy defaults (audit L1X-04): the cap is 100 times the base fee floor, about 0.02 BLCH of tip on a full
# batch; a batch not recorded within 4 native blocks (2 minutes) gets twice the tip; 8 blocks without it is an alert.
DA_DEFAULT_MAX_TIP_MILLISAT_PER_GAS, DA_TIP_ESCALATION_BLOCKS, DA_NOT_INCLUDED_ALERT_BLOCKS = 1_000, 4, 8
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
SETTLEMENT_VIEW_FIELDS = ('network', 'genesis', 'chain_id', 'asynchronous', 'accepted', 'source', 'data_availability')
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
# The bound program `settlement_v3_mainnet_bound` (audit L2N-01, docs/MAINNET-PROGRAM.md). CANDIDATE values of
# 2026-11-23 (commit 21ec80c), not a release: nothing on L1 pins them, and the release that carries the L1 program
# switch replaces them with the values of the ELF built at the release commit (a test keeps them equal to the
# document's table). They differ from the deployed program in the configuration commitment, the ELF and its keys.
MAINNET_BOUND = {**MAINNET,
                 'configuration': '41ddb4dd4aae492e04f500d40be8471ac785e1264d32346dc0f1620d67cc928d',
                 'elf_keccak': 'c1dd6066941c83fc691f6b325b51ca771c680431df54d54d508c8593fcb6da6d',
                 'vkey_koalabear': '72730d65162c55a9604a8d905e125a1f332bec342419058167520c455dea4112',
                 'vkey_bn254': '00e4e61aca58b156a702546c85e125a1f6657d868906416073a90622ddea4112',
                 'guest_sha256': 'ac2e1ca568fe28ffef7f2e55d4bc493d6348882b2e786bf3e5a10fefa9b38892'}
MAINNET_BOUND_STATUS = 'candidate'  # 'release' once the values above are the released program's
MAINNET_L2_CONFIG_SHA256 = '292f4fa8d5a949a26c20317cfc9360d53afda4779b298f1841107985ca5c4f6b'
MAINNET_TIMESTAMP_RULE = f"1:{MAINNET['genesis_time']}:{MAINNET['slot_ms']}"
MAINNET_PRODUCE_ARGS = ('--rules', 'mainnet', '--domain', MAINNET['l2_domain'],
                        '--genesis-time', str(MAINNET['genesis_time']))
MAINNET_DEFAULTS = {'poll_seconds': 15, 'resubmit_seconds': 300, 'timestamp_rule': MAINNET_TIMESTAMP_RULE}


def mainnet_l2_config(program=None):
    """The 264-byte l2-config.bin of chain 700770 (layout of devnet4/make_l2_config.py), of the deployed program
    or of `program` (MAINNET_BOUND)."""
    program = MAINNET if program is None else program
    out = b''.join(bytes.fromhex(program[k]) for k in ('l2_domain', 'configuration', 'elf_keccak',
                                                         'vkey_koalabear', 'vkey_bn254', 'proof_policy'))
    out += MAINNET['chain_id'].to_bytes(8, 'little')
    return out + bytes.fromhex(MAINNET['l2_genesis']) + bytes.fromhex(MAINNET['l2_genesis_state'])


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


TIMEOUT_EXIT = 124  # exit code recorded for a prover attempt that ran out of time (as timeout(1) reports it)


class QuorumFloorStall(RuntimeError):
    """Review r10 L1: a partial quorum has reported the same accepted number below the in-memory floor for
    `quorum_floor_stall_seconds`. Raised every cycle until `max_consecutive_failures` makes the process exit 1;
    the restart resets the floor, so a real L1 reorg is followed (or halts with its own reason) instead of a
    silent wait."""


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


# secp256k1, only to read the sender of a spooled transaction (idle-block demand). Never signs, never decides a block.
SECP_P = 2 ** 256 - 2 ** 32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _jacobian_double(p):
    x, y, z = p
    if not y:
        return 0, 1, 0
    yy = y * y % SECP_P
    s = 4 * x * yy % SECP_P
    m = 3 * x * x % SECP_P
    nx = (m * m - 2 * s) % SECP_P
    return nx, (m * (s - nx) - 8 * yy * yy) % SECP_P, 2 * y * z % SECP_P


def _jacobian_add(p, q):
    if not p[2]:
        return q
    if not q[2]:
        return p
    z1z1, z2z2 = p[2] * p[2] % SECP_P, q[2] * q[2] % SECP_P
    u1, u2 = p[0] * z2z2 % SECP_P, q[0] * z1z1 % SECP_P
    s1, s2 = p[1] * z2z2 * q[2] % SECP_P, q[1] * z1z1 * p[2] % SECP_P
    if u1 == u2:
        return _jacobian_double(p) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % SECP_P, (s2 - s1) % SECP_P
    hh = h * h % SECP_P
    hhh, v = h * hh % SECP_P, u1 * hh % SECP_P
    nx = (r * r - hhh - 2 * v) % SECP_P
    return nx, (r * (v - nx) - s1 * hhh) % SECP_P, h * p[2] * q[2] % SECP_P


def secp_mul(k, point, k2=0, point2=None):
    """k * point (+ k2 * point2), affine in and out; None is the point at infinity."""
    pairs = [(k, (point[0], point[1], 1))] + ([(k2, (point2[0], point2[1], 1))] if point2 else [])
    both = _jacobian_add(pairs[0][1], pairs[1][1]) if point2 else None
    result = (0, 1, 0)
    for bit in range(max(k, k2).bit_length() - 1, -1, -1):
        result = _jacobian_double(result)
        first, second = k >> bit & 1, point2 is not None and k2 >> bit & 1
        if first or second:
            result = _jacobian_add(result, both if first and second else pairs[0][1] if first else pairs[1][1])
    if not result[2]:
        return None
    zi = pow(result[2], -1, SECP_P)
    return result[0] * zi * zi % SECP_P, result[1] * zi * zi * zi % SECP_P


def rlp_items(data):
    """The top-level RLP list `data` as [(raw encoding, payload)]; ValueError unless `data` is exactly one list."""
    def header(at):
        first = data[at]
        if first < 0x80:
            return at, at + 1, False
        if first < 0xb8 or 0xc0 <= first < 0xf8:
            short = first - (0x80 if first < 0xc0 else 0xc0)
            return at + 1, at + 1 + short, first >= 0xc0
        size_len = first - (0xb7 if first < 0xc0 else 0xf7)
        size = int.from_bytes(data[at + 1:at + 1 + size_len], 'big')
        start = at + 1 + size_len
        return start, start + size, first >= 0xc0
    start, end, is_list = header(0)
    if not is_list or end != len(data):
        raise ValueError('not one RLP list')
    items, at = [], start
    while at < end:
        body, stop, _ = header(at)
        if stop > end:
            raise ValueError('RLP item overruns its list')
        items.append((data[at:stop], data[body:stop]))
        at = stop
    return items


def rlp_list(encoded_items):
    payload = b''.join(encoded_items)
    if len(payload) < 56:
        return bytes([0xc0 + len(payload)]) + payload
    size = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, 'big')
    return bytes([0xf7 + len(size)]) + size + payload


def rlp_uint(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return raw if len(raw) == 1 and raw[0] < 0x80 else bytes([0x80 + len(raw)]) + raw


def spooled_sender_nonce(raw):
    """(sender, nonce) of a signed type 0 (EIP-155), 1 or 2 envelope, or None when these bytes do not read as one. Not
    an authentication: the producer decides inclusion. This only tells a nonce gap from what the next block may take."""
    try:
        if raw[0] in (1, 2):
            items = rlp_items(raw[1:])
            if len(items) != (11 if raw[0] == 1 else 12):
                return None
            signed = items[:-3]
            digest = keccak256(raw[:1] + rlp_list([item for item, _ in signed]))
            parity = int.from_bytes(items[-3][1], 'big')
            nonce = int.from_bytes(items[1][1], 'big')
        elif raw[0] >= 0xc0:
            items = rlp_items(raw)
            if len(items) != 9:
                return None
            v = int.from_bytes(items[6][1], 'big')
            if v < 35:
                return None  # unprotected: the producer refuses it
            parity = (v - 35) % 2
            digest = keccak256(rlp_list([item for item, _ in items[:6]] + [rlp_uint((v - 35) // 2), b'\x80', b'\x80']))
            nonce = int.from_bytes(items[0][1], 'big')
        else:
            return None
        r, s = (int.from_bytes(items[i][1], 'big') for i in (-2, -1))
        if parity > 1 or not (0 < r < SECP_N and 0 < s < SECP_N):
            return None
        y = pow((r ** 3 + 7) % SECP_P, (SECP_P + 1) // 4, SECP_P)
        if y * y % SECP_P != (r ** 3 + 7) % SECP_P:
            return None
        point = (r, y if y % 2 == parity else SECP_P - y)
        inverse = pow(r, -1, SECP_N)
        e = int.from_bytes(digest, 'big')
        key = secp_mul(s * inverse % SECP_N, point, (-e * inverse) % SECP_N, SECP_G)
        if key is None:
            return None
        return keccak256(key[0].to_bytes(32, 'big') + key[1].to_bytes(32, 'big'))[12:], nonce
    except (IndexError, ValueError):
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


# ---- settler authorization (audit AUDIT-L1L2-20261123 L2N-01; native l2_settlement::settler, commit 5312e209) ----
SETTLER_AUTH_DOMAIN = b'BLOCH:L2:SETTLER-AUTH:1'
SETTLER_SET_DOMAIN = b'BLOCH:L2:SETTLER-SET:1'
SETTLER_MAX_KEYS = 3
PQ_KEY_BYTES, PQ_SIGNATURE_MAX = 3_749, 4_593  # funded::ADMISSION_PQ_KEY_BYTES / ADMISSION_PQ_SIGNATURE_MAX
SETTLER_MAX_AUTHORIZATION_BYTES = 1 + 4 + PQ_SIGNATURE_MAX + 1 + SETTLER_MAX_KEYS * PQ_KEY_BYTES
SETTLEMENT_COMMITMENT_DOMAIN = (b'BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-COMMITMENT:1'
                                b'BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-TX:1')
# getchaininfo.hard_forks keys of the L1 gates (a gate without an RPC alias is reported under its lowercased
# constant name, native rpc/consensus_gates.rs). The program switch is native commit 3a97df51
# (L2_SETTLEMENT_PROGRAM_SWITCH_ACTIVATION_EPOCH, docs/L2-PROGRAM-SWITCH.md there), which also reports the program
# in force and the pinned successor in getl2settlement.program; `l1_gate` in a configuration block overrides a name.
SETTLER_GATE = 'l2_settler_authorization_activation_epoch'
DA_SETTLER_SLOT_GATE = 'l2_da_settler_slot_activation_epoch'
PROGRAM_SWITCH_GATE = 'l2_settlement_program_switch_activation_epoch'
PROGRAM_IDENTITY_FIELDS = ('configuration', 'elf', 'vkey_koalabear', 'vkey_bn254')  # getl2settlement.program
GATE_CACHE_SECONDS = 60


def settlement_commitment(tx):
    """native l2_settlement::Transaction::commitment of a settlement's first 1155 bytes: SHA3-256 over the two
    domain tags, the proof policy, the statement and the proof. The trailer is not part of it."""
    return hashlib.sha3_256(SETTLEMENT_COMMITMENT_DOMAIN + tx[1:TRANSACTION_BYTES]).digest()


def parse_settler_set(text):
    """The keys of a settler set text (one enveloped hybrid public key in hex per line, the text the L1 release
    pins in mainnet::SETTLER_SET), or None when it is not 1 to 3 distinct keys of the exact size."""
    try:
        keys = [bytes.fromhex(line.strip()) for line in text.splitlines() if line.strip()]
    except ValueError:
        return None
    if not 1 <= len(keys) <= SETTLER_MAX_KEYS or any(len(k) != PQ_KEY_BYTES for k in keys) \
            or len(set(keys)) != len(keys):
        return None
    return keys


def settler_set_hash(keys):
    return hashlib.sha3_256(SETTLER_SET_DOMAIN + bytes([len(keys)]) + b''.join(keys)).digest()


def settler_digest(network, chain_id, commitment, next_set=None):
    """What a registered key signs (native settler::digest): bound to the network, the chain, this exact
    settlement (policy, statement, proof) and the next set."""
    return hashlib.sha3_256(SETTLER_AUTH_DOMAIN + network + chain_id.to_bytes(8, 'big') + commitment
                            + (settler_set_hash(next_set) if next_set else bytes(32))).digest()


def encode_authorization(signer, signature, next_set=None):
    """native settler::Authorization::encode: signer (u8) || signature length (u32 LE) || signature ||
    next-set key count (u8, 0 = keep the set) || keys."""
    return (bytes([signer]) + len(signature).to_bytes(4, 'little') + signature
            + bytes([len(next_set or [])]) + b''.join(next_set or []))


def decode_authorization(trailer):
    """(signer, signature, next set or None) of a trailer, or None unless it is the one canonical encoding within
    every bound of native settler::Authorization::decode."""
    if len(trailer) < 6 or len(trailer) > SETTLER_MAX_AUTHORIZATION_BYTES:
        return None
    signer, length = trailer[0], int.from_bytes(trailer[1:5], 'little')
    if signer >= SETTLER_MAX_KEYS or not 0 < length <= PQ_SIGNATURE_MAX or len(trailer) < 5 + length + 1:
        return None
    signature, count, rest = trailer[5:5 + length], trailer[5 + length], trailer[6 + length:]
    if count > SETTLER_MAX_KEYS or len(rest) != count * PQ_KEY_BYTES:
        return None
    keys = [rest[i:i + PQ_KEY_BYTES] for i in range(0, len(rest), PQ_KEY_BYTES)]
    if len(set(keys)) != len(keys):
        return None
    return signer, signature, (keys or None)


def gate_field(info, key):
    """The activation epoch a getchaininfo answer reports for an L1 gate: an integer, None while the gate is
    inert, 'absent' when the node does not report the gate (a release that predates it)."""
    forks = info.get('hard_forks') if isinstance(info, dict) else None
    entry = forks.get(key) if isinstance(forks, dict) else None
    if not isinstance(entry, dict) or 'activation_epoch' not in entry:
        return 'absent'
    epoch = entry['activation_epoch']
    if epoch is None:
        return None
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        return 'malformed'
    return epoch


def l2_config_program(config):
    """The four program identities of an l2-config.bin (configuration, ELF Keccak, KoalaBear key, BN254 key), as the
    L1 reports them in getl2settlement.program."""
    return {name: config[32 + 32 * i:64 + 32 * i].hex() for i, name in enumerate(PROGRAM_IDENTITY_FIELDS)}


def program_view(view):
    """The program part of a getl2settlement answer (native 3a97df51): the identities in force and the pinned
    successor with its epoch. None when the node does not report it (a release that predates the switch)."""
    program = view.get('program') if isinstance(view, dict) else None
    if not isinstance(program, dict):
        return None
    switch = program.get('switch') if isinstance(program.get('switch'), dict) else None
    to = (switch or {}).get('to') if isinstance((switch or {}).get('to'), dict) else {}
    return {'in_force': {k: program.get(k) for k in PROGRAM_IDENTITY_FIELDS},
            'switch': None if switch is None else {'activation_epoch': switch.get('activation_epoch'),
                                                   'taken': switch.get('taken'), 'final': switch.get('final'),
                                                   'to': {k: to.get(k) for k in PROGRAM_IDENTITY_FIELDS}}}


def check_activation(value, name):
    """An activation setting: absent/None (never), "l1" (read from the L1 by quorum) or an epoch."""
    if value is None or value == 'l1' or (isinstance(value, int) and not isinstance(value, bool) and value >= 0):
        return value
    raise Halt(f'{name} must be "l1", a non-negative epoch or absent')


def endpoint_url(endpoint):
    """A loopback port (devnets) or an http(s) URL (mainnet `rpc_urls`)."""
    return endpoint if isinstance(endpoint, str) else f'http://127.0.0.1:{endpoint}'


# One native RPC exchange: the whole of it must fit in this time and this many bytes. The largest honest answers
# (getl2settlement with its retained records, getutxos of 64 outputs) are far below a megabyte.
RPC_DEADLINE_SECONDS, RPC_MAX_RESPONSE_BYTES = 30, 16 << 20


def bounded_post(url, body, deadline, max_bytes, headers):
    """POST `body` and return the whole answer, under ONE wall-clock deadline for the exchange (connect, send,
    headers, body) and a byte cap. `urlopen(timeout=)` bounds each socket call, not the request: an endpoint that
    sends one byte just inside every timeout holds the caller for as long as it likes, and `read()` has no size
    limit (audit AUDIT-L1L2-20261123, L2N-20). Here a timer shuts the socket down at the deadline. The socket is
    kept in a list because `http.client` sets `conn.sock = None` as soon as a `Connection: close` answer starts,
    so a timer that looks at `conn.sock` then closes nothing (L2N-21)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError(f'not an http(s) URL: {url!r}')
    factory = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
    conn = factory(parts.hostname, parts.port, timeout=min(15, deadline))
    fired, held = threading.Event(), []

    def expire():
        fired.set()
        for sock in held + [conn.sock]:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    killer = threading.Timer(deadline, expire)
    killer.daemon = True
    killer.start()
    try:
        conn.connect()
        held.append(conn.sock)
        if fired.is_set():  # the deadline passed while connecting: the timer found no socket to shut
            raise TimeoutError(f'no complete answer within {deadline} s')
        conn.request('POST', (parts.path or '/') + (f'?{parts.query}' if parts.query else ''), body=body,
                     headers={**headers, 'Connection': 'close'})
        response = conn.getresponse()
        chunks, total = [], 0
        while not fired.is_set():
            chunk = response.read1(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f'answer larger than {max_bytes} bytes')
            chunks.append(chunk)
        if fired.is_set():
            raise TimeoutError(f'no complete answer within {deadline} s')
        if response.status != 200:
            raise ValueError(f'HTTP status {response.status}')
        return b''.join(chunks)
    except (OSError, http.client.HTTPException) as error:
        if isinstance(error, TimeoutError):
            raise
        if fired.is_set():
            raise TimeoutError(f'no complete answer within {deadline} s') from error
        if isinstance(error, socket.timeout):  # one socket call waited out its own timeout
            raise TimeoutError(f'endpoint silent for {min(15, deadline)} s') from error
        raise
    finally:
        killer.cancel()
        conn.close()


def rpc(port, method, params=(), deadline=None, max_bytes=None):
    """One JSON-RPC call. An endpoint that drips or floods its answer is a failed endpoint (the caller's backoff
    applies), never a stalled worker."""
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    try:
        answer = bounded_post(endpoint_url(port), body, RPC_DEADLINE_SECONDS if deadline is None else deadline,
                              RPC_MAX_RESPONSE_BYTES if max_bytes is None else max_bytes,
                              {'Content-Type': 'application/json'})
    except TimeoutError as error:
        raise TimeoutError(f'{method}: {error}') from error
    reply = json.loads(answer)
    if not isinstance(reply, dict):
        raise RpcError(f'{method}: answer is not a JSON-RPC object')
    if 'error' in reply:
        raise RpcError(f'{method}: {reply["error"]}')
    return reply['result']


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def settlement_view(view):
    """The safety-relevant projection of a getl2settlement answer."""
    if not isinstance(view, dict):
        return view
    return {k: view[k] for k in SETTLEMENT_VIEW_FIELDS if k in view}


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
        return self.bounded(method, lambda answer: int(answer[field]))

    def bounded(self, method, extract, params=()):
        """The (faults + 1)-th largest of the integers `extract` reads from at least `quorum` usable answers.
        An answer `extract` cannot read is a missing vote (logged), like an endpoint that failed: one endpoint that
        answers the quorum-checked fields honestly and garbage here cannot fail the read for the others (audit
        L2N-20). The bound stays the conservative one: no larger than a value an honest endpoint reported."""
        values = []
        for port, answer in self.gather(method, params).items():
            try:
                value = extract(answer)
                if isinstance(value, bool) or not isinstance(value, int):
                    raise TypeError('not an integer')
                values.append(value)
            except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
                log('rpc-endpoint-malformed', port=port, method=method,
                    reason=f'{type(error).__name__}: {error}'[:200])
        if len(values) < self.quorum:
            raise RuntimeError(f'{method}: {len(values)} of {len(self.ports)} RPC endpoints gave a usable answer, '
                               f'{self.quorum} needed')
        values.sort()
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
        """sendrawtransaction on EVERY configured endpoint, in order: (ports that hold the bytes, first answer).

        Writes are not quorum reads: one endpoint that answers `accepted` but never gets the transaction into a
        block (a node on a minority fork, partitioned, or stuck with parked blocks) must not be the only one that
        ever sees it (review r10 M2). Sending the same bytes to all endpoints is harmless: consensus validates them,
        and a node that already holds or recently included them answers `duplicate`, which counts as held, like
        `accepted`. Endpoints in backoff are tried too: a write is rare and must reach every node it can.
        Raises SubmitRefused with every endpoint's reason when none holds them."""
        held, first, errors = [], None, []
        for port in self.ports:
            try:
                response = self.call(port, 'sendrawtransaction', [tx_hex])
            except Exception as error:  # logged by call() as rpc-endpoint-failed
                errors.append((port, f'{type(error).__name__}: {error}'[:300]))
                continue
            if not isinstance(response, dict) or response.get('status') not in SUBMIT_HELD:
                errors.append((port, f'UnexpectedAnswer: {canonical(response)}'[:300]))
                continue
            held.append(port)
            first = response if first is None else first
        if not held:
            raise SubmitRefused(errors)
        if errors:
            log('submit-partial', held_by=held, errors=[f'{p}: {e}'[:300] for p, e in errors])
        return held, first


# Native sendrawtransaction refusals (bloch-pos-node rpc.rs / engine.rs, release 78b7343a).
TX_REFUSED, TX_REFUSED_RETRYABLE, MEMPOOL_FULL, TX_REFUSED_SOURCE_CAP = -32008, -32009, -32003, -32010
ONE_PROOF_PENDING = 'one L2 proof is already pending'
# sendrawtransaction answers that mean the node holds the bytes (native rpc.rs Admitted::New / Duplicate).
SUBMIT_HELD = ('accepted', 'duplicate')


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


# ---- stop signals (review r10 M1): the F8 cleanup also runs on systemctl stop/restart, Ctrl-C and hangup ----
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
_STOP = {'signum': None, 'raised': False, 'deferred': 0}


class Stopped(SystemExit):
    """A stop signal turned into an exception. Python's default SIGTERM action ends the process without unwinding,
    so neither the prover group nor its SP1 segments nor its Gnark container would be cleaned up. As an exception it
    takes the same path as a timeout; main() then ends the process by the same signal, so systemd sees the stop it
    asked for. A SystemExit, so `except Exception` never swallows it."""

    def __init__(self, signum):
        super().__init__(128 + signum)
        self.signum = signum


def _on_stop_signal(signum, _frame):
    if _STOP['signum'] is not None:
        return  # already stopping: a second signal must not abort the cleanup the first one started
    _STOP['signum'] = signum
    if _STOP['deferred']:
        return  # inside a cleanup: raised when it ends (deferred_stop)
    _STOP['raised'] = True
    raise Stopped(signum)


def install_stop_handlers():
    """Route SIGTERM, SIGINT and SIGHUP to Stopped. Returns the handlers it replaced ({} off the main thread, where
    Python cannot install handlers, and where they are already installed)."""
    if threading.current_thread() is not threading.main_thread():
        return {}
    previous = {}
    for number in STOP_SIGNALS:
        current = signal.getsignal(number)
        if current is not _on_stop_signal:
            previous[number] = current
            signal.signal(number, _on_stop_signal)
    return previous


@contextlib.contextmanager
def stop_signals():
    """Stop signals raise Stopped inside the block (a prover run), then the previous handlers come back."""
    previous = install_stop_handlers()
    try:
        yield
    finally:
        for number, handler in previous.items():
            if handler is not None:
                signal.signal(number, handler)


@contextlib.contextmanager
def deferred_stop():
    """Run a cleanup to its end: a stop signal that arrives inside it is raised once the cleanup is done."""
    _STOP['deferred'] += 1
    try:
        yield
    finally:
        _STOP['deferred'] -= 1
        if not _STOP['deferred'] and _STOP['signum'] is not None and not _STOP['raised']:
            _STOP['raised'] = True
            raise Stopped(_STOP['signum'])


def exit_by_signal(stop):
    """End the process by the signal that stopped it (after the cleanup), as the default action would have."""
    log('stopped', signal=signal.Signals(stop.signum).name)
    signal.signal(stop.signum, signal.SIG_DFL)
    os.kill(os.getpid(), stop.signum)
    sys.exit(stop.code)  # not reached for TERM, INT and HUP


def stop_gnark_containers(tmpdir, path='/usr/bin:/bin', run=subprocess.run, report=None):
    """Kill the Gnark containers that a killed prover left running (review r10 L5). SP1 runs Groth16 wrapping as
    `docker run --rm` without a name: killing the prover's process group kills the docker CLI only, while the
    container, a child of containerd, runs on outside every memory cap (~18.5 GB) until its proof ends. Only
    containers with a bind mount from `tmpdir` are touched: SP1 mounts its witness and output temporary files from
    TMPDIR, which is private to this prover run. Returns the container ids killed."""
    report = report or log
    docker = shutil.which('docker', path=path) if tmpdir else None
    if not docker:
        return []
    prefix = str(tmpdir).rstrip('/') + '/'
    try:
        ids = run([docker, 'ps', '-q', '--no-trunc'], capture_output=True, text=True, timeout=15).stdout.split()
        found = run([docker, 'inspect', '--format', '{{.Id}}\t{{json .Mounts}}', *ids], capture_output=True,
                    text=True, timeout=15).stdout if ids else ''
    except (OSError, subprocess.SubprocessError) as error:
        report('prover-container-check-failed', reason=f'{type(error).__name__}: {error}'[:300])
        return []
    ours = []
    for line in found.splitlines():
        container, _, mounts = line.partition('\t')
        try:
            sources = [str(m.get('Source', '')) for m in json.loads(mounts) or []]
        except (ValueError, AttributeError):
            continue
        if any(source.startswith(prefix) for source in sources):
            ours.append(container)
    for container in ours:
        try:
            run([docker, 'kill', container], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
    if ours:
        report('prover-container-killed', containers=[c[:12] for c in ours], tmpdir=str(tmpdir))
    return ours


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
        self.prover_args = ['--mainnet'] if self.mainnet_path else []
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
        self.gate_cache, self.gate_absent_logged = {}, set()
        self.settler_key_checked = False
        self.da_slot_warned = None
        self.init_programs()
        self.init_settler_authorization()
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
            if da.get('settler_key'):
                # Audit L1X-04 (L1 rule 1ada9df7): the reserved DA place belongs to batches funded by a registered
                # settler key, so the DA transaction is funded and signed by the settler keystore itself.
                auth = self.c.get('settler_authorization')
                if not auth:
                    raise Halt('da.settler_key requires settler_authorization')
                own = {'signer': auth['signer'], 'signer_sha256': auth['signer_sha256'], 'genesis': auth['genesis'],
                       'funding_pubkey': auth['pubkey'], 'keystore_dir': auth['keystore_dir'],
                       'passphrase_file': auth['passphrase_file']}
                for key, value in own.items():
                    if da.get(key, value) != value:
                        raise Halt(f'da.settler_key: da.{key} must be the settler key\'s or absent')
                da = self.c['da'] = {**da, **own}
            check_activation(da.get('settler_slot_activation_epoch'), 'da.settler_slot_activation_epoch')
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
        self.spool_open = True  # false: the next block is built without the spool (see hold_block)
        self.holding_since = None  # monotonic time this worker began to hold; None while it builds
        self.hold_logged_at = None
        self.work = Path(self.c['workdir'])
        self.rebuild_discarded_at = None
        self.waiting_for = None  # the accepted settlement a recovery last reported waiting on
        self.native = Endpoints(rpc_endpoints(self.c), rpc_quorum(self.c), self.rpc, self.clock, self.sleep)
        self.accepted_floor = 0  # highest accepted L2 number seen in a quorum view
        self.floor_stall = None  # (number, first seen, reads) while a partial quorum stays behind the floor
        stall = self.c.get('quorum_floor_stall_seconds', 1200)
        if not isinstance(stall, int) or isinstance(stall, bool) or stall < 0:
            raise Halt('quorum_floor_stall_seconds must be a non-negative integer')
        self.unincluded = {}  # consecutive acceptance windows the same bytes were held but not included
        limit = self.c.get('max_unincluded_windows', 4)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise Halt('max_unincluded_windows must be a non-negative integer')
        self.identity_checked = False
        self.dry_run = False
        # Whether any L1 gate of the 2026-11-23 audit fixes is configured: without one, no gate is read.
        self.gated = self.c.get('settler_authorization') is not None or self.c.get('program_switch') is not None

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
            self.floor_stall_check(number, support)
            return None
        self.floor_stall = None
        self.accepted_floor = number if unanimous else max(self.accepted_floor, number)
        return view

    def floor_stall_check(self, number, support):
        """Review r10 L1. With one endpoint down for good, a real L1 reorg below the floor never reaches a
        unanimous view. After `quorum_floor_stall_seconds` (default 1200, 0 = off) of the same behind-floor
        quorum answer, raise so that the bounded retry exits 1 and the restart resets the in-memory floor.
        Two stale endpoints after that restart meet the database and anchor checks in prepare_block, or the
        `settlement-not-included` limit; each ends in a logged halt."""
        limit = self.c.get('quorum_floor_stall_seconds', 1200)
        now = self.clock()
        if self.floor_stall is None or self.floor_stall[0] != number:
            self.floor_stall = (number, now, 1)
            return
        _, since, reads = self.floor_stall
        self.floor_stall = (number, since, reads + 1)
        if limit and now - since >= limit and reads + 1 >= 3:
            log('rpc-quorum-behind-floor', accepted=number, seen=self.accepted_floor, ports=support,
                seconds=round(now - since))
            raise QuorumFloorStall(f'a partial quorum has reported accepted L2 {number} below the floor '
                                   f'{self.accepted_floor} for {round(now - since)} s')

    def produce(self, *args, timeout=300):
        result = self.run([self.c['produce'], *args, *self.network_args], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise ProducerError(f'producer refused {args[0]}: {result.stderr.strip()[:400]}')
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise ProducerError(f'producer printed no JSON for {args[0]}') from None

    def extend(self, parent, anchor, deposits, anchor_slot, number):
        """Extend by one block. With the user-transaction spool, a producer refusal is retried once
        without it (deposits only): the spool is untrusted input and must not stop settlement."""
        try:
            return self.produce(*self.extend_arguments(parent, anchor, deposits, anchor_slot))
        except ProducerError as error:
            if not self.c['user_transactions']:
                raise
            head = self.produce('head', '--target', self.c['l2_db'])
            if head['number'] != number - 1:
                raise  # the block was committed before the failure; the next cycle reuses it
            log('producer-refused-spool', number=number, reason=str(error)[:400])
            return self.produce(*self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False))

    def extend_arguments(self, parent, anchor, deposits, anchor_slot=None, spool=True):
        args = ['extend', '--target', self.c['l2_db'], '--parent', parent, '--anchor', anchor, '--deposits', str(deposits)]
        if self.c.get('timestamp_rule'):
            # L2 time follows the anchored native slot (rollup rule); attestors rebuild with the same rule.
            args += ['--timestamp-rule', self.c['timestamp_rule'], '--anchor-slot', str(anchor_slot)]
        if self.c['user_transactions'] and spool and self.spool_open:
            args += ['--txs', self.c['txpool_dir'], '--max-gas', str(self.c['max_block_gas']),
                     '--max-bytes', str(self.c['max_block_bytes']), '--max-txs', str(self.c['max_block_txs'])]
            if self.c.get('min_tip_wei'):
                args += ['--min-tip-wei', str(self.c['min_tip_wei'])]
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
        return self.native.bounded('getl2settlement',
                                   lambda a: int(a['inbox']['count']) - int(a['inbox']['consumed']))

    def spool_demand(self, head):
        """Whether a spooled transaction may go into the next block on `head`. A file alone is not demand: the RPC admits
        nonces up to 16 ahead and keeps them 3 hours, and the producer defers a nonce gap without dropping it, so one such
        entry would make every cycle due (review r7 F5). Demand is an entry whose nonce is its sender's next nonce at the
        head. Bytes that do not read as a transaction, and a sender whose nonce the producer cannot tell, count as demand:
        the producer drops what it cannot decode, and a block too many costs less than a transaction never served.
        Fees are not checked: the RPC admits only a fee cap over the next base fee and a tip over the floor."""
        if not self.c['user_transactions']:
            return False
        files = sorted(Path(self.c['txpool_dir']).glob('*.tx'))
        if not files:
            return False
        known = getattr(self, 'spool_senders', {})
        self.spool_senders = {}
        nonces = getattr(self, 'spool_nonces', (None, {}))
        nonces = nonces if nonces[0] == head else (head, {})
        self.spool_nonces = nonces
        for path in files:
            try:
                stat = path.stat()
                key = (path.name, stat.st_size, stat.st_mtime_ns)
                entry = known[key] if key in known else spooled_sender_nonce(bytes.fromhex(path.read_text().strip()))
            except FileNotFoundError:
                continue  # included, pruned or evicted meanwhile
            except (OSError, ValueError):
                return True
            self.spool_senders[key] = entry
            if entry is None:
                return True
            sender, nonce = entry
            if sender not in nonces[1]:
                try:
                    nonces[1][sender] = int(self.produce('account', '--target', self.c['l2_db'],
                                                         '--address', sender.hex())['nonce'])
                except Exception as error:  # noqa: BLE001
                    log('spool-demand-unknown', reason=f'{type(error).__name__}: {error}'[:300])
                    return True
            if nonce == nonces[1][sender]:
                return True
        return False

    def hold_block(self, view):
        """With `skip_idle_blocks`: whether to build no block in this cycle. Not a block rule: L1, the guest, the follower
        and every rebuild only see fewer blocks, each with an older anchor. See SETTLER-RUNBOOK.md, "Idle blocks".

        A block is due when L1 holds an unconsumed deposit, the spool holds a transaction the next block may take
        (`spool_demand`), or the source reached `max_idle_seconds`, which proves the whole path while nothing else does. `min_block_interval_seconds` then delays
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
        except Exception as error:  # noqa: BLE001 - the quorum view just passed: try again next cycle
            log('idle-check-failed', reason=f'{type(error).__name__}: {error}'[:300])
            return True
        pace = self.c.get('min_block_interval_seconds', 0)
        reason = ('deposits' if backlog or view['source'].get('pending') else 'transactions' if self.spool_demand(expected)
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
        atomic_write(deposits, deposits_text)
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
            block = self.extend(parent, anchor, deposits, anchor_slot, number)
            if block.get('transactions', 0) and not self.c['user_transactions']:
                raise Halt('producer included user transactions while user_transactions is false')
            atomic_write(produced, json.dumps(block, sort_keys=True) + '\n')
            log('l2-block-produced', **{k: block[k] for k in ('number', 'hash', 'deposits', 'transactions',
                                                               'withdrawal_count') if k in block},
                deferred=len(block.get('deferred', [])), dropped=block.get('dropped', []))
        elif head['number'] == number:
            # Crash after extend: reuse only the block built on this exact parent and anchor.
            if self.local_hash(number - 1) != parent:
                raise ForeignSettlement(f'unsettled L2 block {number} does not extend the accepted parent {parent} '
                                        '(another settler?)')
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
            argv = [self.c['prover'], *self.program['prover_args'], *args, 'native-artifact', self.program['guest']] \
                + ([] if name == 'execute' else [str(proof)])
            if name == 'prove':
                proof.unlink(missing_ok=True)
            start = self.clock()
            order = self.c['remote_prover']['order'] if name == 'prove' and self.c.get('remote_prover') else ['local']
            for where in order:
                if name == 'prove':
                    proof.unlink(missing_ok=True)
                timed_out = False
                try:
                    if where == 'remote':
                        result = self.prove_remote(directory, proof)
                    elif name == 'prove' and not self.local_proof_fits(directory):
                        result = types.SimpleNamespace(returncode=75)
                    else:
                        with (directory / f'{name}.log').open('w') as out:
                            result = self.run_bounded(argv, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=3600)
                except subprocess.TimeoutExpired:
                    # Review r10 L6: a timeout is a failed attempt at this location, so the next one in
                    # `remote_prover.order` is still tried. run_bounded has already killed and cleaned the group.
                    result, timed_out = types.SimpleNamespace(returncode=TIMEOUT_EXIT), True
                if result.returncode == 0:
                    break
                if name == 'prove':
                    log('prover-failed', directory=str(directory), where=where, exit_code=result.returncode,
                        **({'timeout': True} if timed_out else {}))
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
        proved = {'steps': steps, 'proof_sha256': digest(proof)}
        if self.c.get('program_switch'):
            proved['program'] = self.program['name']
        atomic_write(directory / 'proved.json', json.dumps(proved, indent=2) + '\n')
        log('proof-generated', directory=str(directory), seconds=sum(s['seconds'] for s in steps))
        return proof

    def local_proof_fits(self, directory):
        """Whether the local prover may try this block: `local_prove_max_instructions`
        against the count the guest reported in this block's execute stage."""
        limit = self.c.get('local_prove_max_instructions')
        if limit is None:
            return True
        log_file = directory / 'execute.log'
        found = re.findall(r'(\d+) instructions', log_file.read_text()) if log_file.exists() else []
        instructions = int(found[-1]) if found else None
        if instructions is not None and instructions <= limit:
            return True
        log('local-proof-refused', directory=str(directory), instructions=instructions, limit=limit)
        return False

    def run_bounded(self, argv, timeout, **kwargs):
        """Run a prover with a time limit that holds for everything it starts. subprocess.run kills only the direct child
        on a timeout: the SP1 native runner it spawned would live on and keep its memory. So the prover gets its own
        process group, which is killed on a timeout and after every exit. An injected runner (tests) is used as given.

        A stop signal (systemctl stop/restart, Ctrl-C, hangup) takes the timeout path (review r10 M1): the group is
        killed, the SP1 segments it mapped are removed, and a Gnark container it left is killed. A second signal
        during that cleanup does not interrupt it. Each run gets its own TMPDIR under the configured one, so its
        container is found by its bind mounts, and its temporary files go with it."""
        if self.run is not subprocess.run:
            return self.run(argv, timeout=timeout, **kwargs)
        shm = str(Path(self.c.get('prover_shm_dir', '/dev/shm')) if hasattr(self, 'c') else Path('/dev/shm'))
        docker_path = (self.c.get('prover_path') if hasattr(self, 'c') else None) or '/usr/bin:/bin'
        env = kwargs.get('env')
        with stop_signals():
            process, ours, private = None, set(), None  # ours: segments this run's group mapped; only these go
            try:
                with deferred_stop():
                    if env and env.get('TMPDIR'):
                        try:
                            private = tempfile.mkdtemp(prefix='prover-', dir=env['TMPDIR'])
                            kwargs['env'] = {**env, 'TMPDIR': private}
                        except OSError:  # no usable TMPDIR: run as before, without the container check
                            private = None
                    process = subprocess.Popen(argv, start_new_session=True, **kwargs)
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    ours |= group_segments(process.pid, shm)
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    time.sleep(0.5)
            except BaseException:
                with deferred_stop():
                    self.clean_up_prover(process, ours, shm, private, docker_path, abnormal=True)
                raise
            with deferred_stop():
                self.clean_up_prover(process, ours, shm, private, docker_path, abnormal=process.returncode != 0)
            return subprocess.CompletedProcess(argv, process.returncode)

    def clean_up_prover(self, process, ours, shm, private, docker_path, abnormal):
        """Kill the prover group, remove the SP1 segments it mapped, kill its Gnark container after an abnormal end,
        and remove its private TMPDIR. Runs inside deferred_stop(); every step tolerates a group already gone."""
        if process is not None:
            ours |= group_segments(process.pid, shm)
            self.kill_group(process.pid)  # whatever it left running
            if process.returncode is None:
                try:
                    process.wait(30)
                except subprocess.TimeoutExpired:
                    pass
            time.sleep(0.2)  # let the kernel tear down the killed processes' mappings
            remove_leaked_segments(ours)
        if private:
            if abnormal:
                stop_gnark_containers(private, docker_path)
            shutil.rmtree(private, ignore_errors=True)

    @staticmethod
    def kill_group(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def prove_remote(self, directory, proof):
        """Groth16 on the remote prover; the caller still verifies it locally."""
        r = self.c['remote_prover']
        request = (directory / 'native-request.txt').read_bytes()
        artifact = (directory / 'block.artifact').read_bytes()
        frame = (REMOTE_MAGIC + struct.pack('>I', len(request)) + request
                 + struct.pack('>Q', len(artifact)) + artifact)
        argv = [r.get('ssh', '/usr/bin/ssh'), '-i', r['key'], '-p', str(r.get('port', 22)),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + r['known_hosts'], '-o', 'ConnectTimeout=20',
                '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=6', r['target'],
                self.program['remote_command']]
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
        if field(DEPOSITS_HASH) != deposits_hash(pending):
            raise Halt('statement deposits_hash does not match the native pending deposits')
        if field(TRANSACTIONS_ROOT) == bytes(32) or field(RECEIPTS_ROOT) == bytes(32):
            raise Halt('statement has a zero transactions or receipts root')
        root, count = check_withdrawals(values, previous)
        users = number(USER_TX_COUNT)
        if users and not self.c['user_transactions']:
            raise Halt(f'statement reports {users} user transactions while user_transactions is false')
        produced = directory / 'block.json'
        if produced.exists():
            block = json.loads(produced.read_text())
            expected = block.get('transactions', 0)
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
            if outcome not in ('fee-moved', 'tip-raised'):
                return outcome

    # ---- DA tip policy (audit AUDIT-L1L2-20261123, L1X-04) ----
    # Consensus admits four 0x15 transactions per native block and the proposer gives the slots to the highest
    # tip rates, so anyone can keep this batch off L1 by out-tipping it with four junk batches per block. The
    # answer on this side is a price: a batch that is not recorded within `da.tip_escalation_blocks` native
    # blocks is re-signed at twice the tip (from `da.tip_step_millisat_per_gas` when it started at zero), up to
    # `da.max_tip_millisat_per_gas`, and `da-not-included` is logged every `da.not_included_alert_blocks` blocks
    # it has waited. Holding the slots then costs the attacker four times the junk gas at more than that cap in
    # every block; the settler pays the raised tip once, on the attempt that is included.

    def da_tip_policy(self):
        """(start, step, cap, escalation blocks, alert blocks) in millisat per gas and native blocks."""
        da = self.c['da']
        start = int(da.get('tip_millisat_per_gas', 0))
        step = max(1, int(da.get('tip_step_millisat_per_gas', MIN_BASE_FEE_MILLISAT_PER_GAS)))
        cap = max(start, int(da.get('max_tip_millisat_per_gas', DA_DEFAULT_MAX_TIP_MILLISAT_PER_GAS)))
        return (start, step, cap, int(da.get('tip_escalation_blocks', DA_TIP_ESCALATION_BLOCKS)),
                int(da.get('not_included_alert_blocks', DA_NOT_INCLUDED_ALERT_BLOCKS)))

    def da_next_tip(self, meta, height):
        """The tip the next attempt is signed with: the last attempt's, doubled when that attempt has waited
        `tip_escalation_blocks` native blocks, never above the cap. `meta` is the last attempt's (None: first)."""
        start, step, cap, blocks, _ = self.da_tip_policy()
        if meta is None:
            return start
        tip = int(meta.get('tip', start))
        signed_at = meta.get('height')
        if blocks <= 0 or height is None or signed_at is None or height - int(signed_at) < blocks:
            return tip
        return min(cap, max(step, 2 * tip))

    def da_waited_blocks(self, directory, height):
        """Native blocks since the first attempt of this block's batch was signed, or None when unknown."""
        try:
            first = json.loads((directory / 'da-meta-0.json').read_text()).get('height')
        except (OSError, ValueError):
            return None
        return None if first is None or height is None else max(0, height - int(first))

    def da_alert_not_included(self, number, directory, height, tip, attempt):
        """`da-not-included`, once per `not_included_alert_blocks` native blocks the batch has waited."""
        _, _, cap, _, alert_blocks = self.da_tip_policy()
        waited = self.da_waited_blocks(directory, height)
        if alert_blocks <= 0 or waited is None or waited < alert_blocks:
            return
        last = getattr(self, 'da_alerted', None)
        if last and last[0] == number and waited - last[1] < alert_blocks:
            return
        self.da_alerted = (number, waited)
        log('da-not-included', number=number, waited_blocks=waited, attempt=attempt, tip_millisat_per_gas=tip,
            max_tip_millisat_per_gas=cap, at_max_tip=tip >= cap)

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

    def da_settler_slot_check(self, number):
        """Audit L1X-04. With the L1 DA settler-slot rule armed (L2_DA_SETTLER_SLOT_ACTIVATION_EPOCH) one DA place per
        block is kept for batches funded by a registered settler key. A funding key outside the registered set
        still publishes, but competes for the other three places by tip: reported once per block, never a halt."""
        da = self.c['da']
        setting = da.get('settler_slot_activation_epoch')
        if setting is None or self.da_slot_warned == number:
            return
        activation = self.gate(setting, da.get('settler_slot_l1_gate', DA_SETTLER_SLOT_GATE))
        if activation is None or self.l1_epoch() < activation:
            return
        keys = self.settler_set() if self.c.get('settler_authorization') else []
        funding = bytes.fromhex(Path(da['funding_pubkey']).read_text().strip())
        if funding not in keys:
            self.da_slot_warned = number
            log('da-funding-key-not-registered', number=number, funding_script=self.da_script,
                registered_keys=len(keys), activation_epoch=activation)

    def publish_da_attempt(self, number, directory, commitment):
        """One sign-or-rebroadcast and wait. True: recorded; False: give up this cycle; 'fee-moved': re-sign now."""
        if self.da_recorded(number, commitment):
            return True
        da = self.c['da']
        self.da_settler_slot_check(number)
        base_fee = str(self.native.bounded_value('getchaininfo', 'next_base_fee_millisat_per_gas'))
        utxos = self.native.common_utxos(self.da_script)
        balance = sum(int(u['value_sat']) for u in utxos)
        payload_bytes = len((directory / 'da-payload.hex').read_text().strip()) // 2
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
        height = self.l1_height()
        held_tip = int(meta.get('tip', da.get('tip_millisat_per_gas', 0))) if meta else None
        tip = self.da_next_tip(meta, height)
        estimate = da_fee_sat(payload_bytes, 1, int(base_fee), tip)
        unspent = {f"{u['txid']}:{u['vout']}:{u['value_sat']}" for u in utxos}
        if meta and (directory / f'da-signed-{attempt - 1}.hex').exists() and set(meta['inputs']) <= unspent:
            # A new attempt spends the previous one's inputs first, so two attempts can never both be included.
            first = {item: i for i, item in enumerate(meta['inputs'])}
            utxos.sort(key=lambda u: first.get(f"{u['txid']}:{u['vout']}:{u['value_sat']}", len(first)))
            tx = bytes.fromhex((directory / f'da-signed-{attempt - 1}.hex').read_text().strip())
            limited = self.da_attempts_in_window(directory) >= int(da.get('max_attempts_per_window', 32))
            same = meta['base_fee'] == base_fee and tip == held_tip
            if (same and meta.get('form', []) == form) or (limited and meta.get('form', []) == form):
                if limited and not same:
                    log('da-resign-limited', number=number, attempts=attempt, signed_base_fee=meta['base_fee'],
                        base_fee=base_fee, tip_millisat_per_gas=held_tip, wanted_tip_millisat_per_gas=tip)
                return self.submit_da(number, directory, tx, commitment, attempt - 1,
                                      da_fee_sat(payload_bytes, 1, int(meta['base_fee']), held_tip),
                                      None if limited else meta['base_fee'], None if limited else meta)
            if tip != held_tip:
                log('da-tip-raised', number=number, attempt=attempt, tip_millisat_per_gas=tip,
                    previous_tip_millisat_per_gas=held_tip, waited_blocks=self.da_waited_blocks(directory, height))
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
                    '--base-fee', base_fee, '--tip', str(tip), '--out', str(unsigned)]
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
        meta = {'base_fee': base_fee, 'inputs': inputs, 'form': form, 'signed_unix': int(self.wall()), 'tip': tip,
                'height': height}
        atomic_write(directory / f'da-meta-{attempt}.json', json.dumps(meta) + '\n')
        return self.submit_da(number, directory, tx, commitment, attempt, estimate, base_fee, meta)

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

    def submit_da(self, number, directory, tx, commitment, attempt, estimate, signed_base_fee=None, meta=None):
        """Send the DA bytes and wait for the record. With `signed_base_fee`, return 'fee-moved' as soon as the
        next base fee differs from it: those bytes can then no longer be included, and waiting is pointless.
        With `meta` (the attempt's record), return 'tip-raised' as soon as the tip policy asks for a higher tip
        than this attempt carries; without it (the attempt window is used up) the worker only waits and alerts."""
        da = self.c['da']
        tip = int((meta or {}).get('tip', da.get('tip_millisat_per_gas', 0)))
        ports, response = self.native.submit(tx.hex())
        log('da-submitted', number=number, bytes=len(tx), commitment=commitment.hex(), response=response.get('status'),
            ports=ports, attempt=attempt, fee_estimate_sat=estimate, signed_base_fee=signed_base_fee)
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
            height = self.l1_height()
            self.da_alert_not_included(number, directory, height, tip, attempt)
            if meta is not None and self.da_next_tip(meta, height) != tip:
                return 'tip-raised'
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

    # ---- L1 gates, the program switch and the settler authorization (audit L2N-01, L1X-04) ----
    def gate(self, setting, key):
        """The activation epoch of an L1 gate, or None while it does not apply. `setting` is None (never), "l1"
        (what a quorum of endpoints reports in getchaininfo.hard_forks) or a configured epoch, which must agree
        with what the L1 reports whenever it reports the gate. No quorum raises: the gate is never guessed."""
        if setting is None:
            return None
        now, cached = self.clock(), self.gate_cache.get(key)
        if cached is not None and now - cached[0] < GATE_CACHE_SECONDS:
            reported = cached[1]
        else:
            view, _ = self.native.agreed('getchaininfo', project=lambda info: {'gate': gate_field(info, key)})
            if view is None:
                raise RuntimeError(f'no RPC quorum on the L1 gate {key}')
            reported = view['gate']
            self.gate_cache[key] = (now, reported)
        if reported == 'malformed':
            raise Halt(f'the L1 reports a malformed activation epoch for {key}')
        if reported == 'absent':
            if key not in self.gate_absent_logged:
                self.gate_absent_logged.add(key)
                log('l1-gate-not-reported', gate=key, configured=setting)
            return None if setting == 'l1' else setting
        if setting != 'l1' and reported != setting:
            raise Halt(f'{key}: the configuration says epoch {setting}, the L1 reports '
                       f'{"inert" if reported is None else reported}')
        return reported

    def l1_epoch(self):
        """The L1 head epoch, no larger than an honest endpoint reports."""
        return self.native.bounded_value('getchaininfo', 'epoch')

    def init_programs(self):
        """The deployed program and, with `program_switch`, the bound program that replaces it from the L1
        program-switch epoch on (audit L2N-01, docs/MAINNET-PROGRAM.md)."""
        self.programs = {'deployed': {'name': 'deployed', 'prover_args': list(self.prover_args),
                                      'guest': self.c['guest'], 'l2_config': self.c['l2_config'],
                                      'remote_command': 'prove'}}
        self.l1_program_missing_logged = False
        self.program = self.programs['deployed']
        switch = self.c.get('program_switch')
        if switch is None:
            return
        if not isinstance(switch, dict):
            raise Halt('program_switch must be an object')
        for key in ('guest', 'guest_sha256', 'l2_config', 'l2_config_sha256'):
            if not switch.get(key):
                raise Halt(f'program_switch.{key} is required')
        for key in ('guest', 'l2_config'):
            if digest(switch[key]) != switch[key + '_sha256']:
                raise Halt(f'program_switch.{key} differs from its pin')
        check_activation(switch.get('activation_epoch'), 'program_switch.activation_epoch')
        lead = switch.get('lead_epochs', 1)
        if not isinstance(lead, int) or isinstance(lead, bool) or lead < 0:
            raise Halt('program_switch.lead_epochs must be a non-negative integer')
        if self.mainnet_path:
            if 'prover_args' in switch:
                raise Halt('program_switch.prover_args is fixed on the mainnet path (--mainnet-bound)')
            if switch['guest_sha256'] != MAINNET_BOUND['guest_sha256'] \
                    or 'settlement_v3_mainnet_bound' not in Path(switch['guest']).name:
                raise Halt('program_switch.guest must be the pinned settlement_v3_mainnet_bound ELF')
            if Path(switch['l2_config']).read_bytes() != mainnet_l2_config(MAINNET_BOUND):
                raise Halt('program_switch.l2_config differs from the pinned bound program')
            args = ['--mainnet-bound']
        else:
            args = switch.get('prover_args', [])
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args) \
                    or 'settlement_v3' not in Path(switch['guest']).name:
                raise Halt('program_switch needs a settlement V3 guest and prover_args as a list')
        self.programs['bound'] = {'name': 'bound', 'prover_args': list(args), 'guest': switch['guest'],
                                  'l2_config': switch['l2_config'], 'remote_command': 'prove-bound'}

    def program_switch_epoch(self):
        switch = self.c.get('program_switch')
        if switch is None:
            return None
        return self.gate(switch.get('activation_epoch'), switch.get('l1_gate', PROGRAM_SWITCH_GATE))

    def l1_program(self):
        """What a quorum of the L1 reports about the settlement program (getl2settlement.program): the name of the
        program in force ('deployed' or 'bound') and the switch epoch it pins, or None when the L1 does not report
        it. The L1 is the authority here: a program in force that this worker does not hold, a pinned successor
        other than this worker's bound program, or an epoch other than the gate's is a halt, never a guess."""
        view, _ = self.native.agreed('getl2settlement', project=lambda v: {'program': program_view(v)})
        if view is None:
            raise RuntimeError('no RPC quorum on the L1 settlement program')
        reported = view['program']
        if reported is None:
            if not self.l1_program_missing_logged:
                self.l1_program_missing_logged = True
                log('l1-program-not-reported')
            return None
        held = {name: l2_config_program(Path(program['l2_config']).read_bytes())
                for name, program in self.programs.items()}
        in_force = next((name for name, identities in held.items() if identities == reported['in_force']), None)
        if in_force is None:
            raise Halt(f'the L1 settles under a program this worker does not hold: {reported["in_force"]}')
        switch = reported['switch']
        if switch is not None and switch['to'] != held['bound']:
            raise Halt('the successor program the L1 pins is not this worker\'s bound program '
                       f'(L1 {switch["to"]}, worker {held["bound"]}): the pins of one side are out of date')
        return {'in_force': in_force, 'activation_epoch': switch['activation_epoch'] if switch else None,
                'final': bool(switch and switch.get('final'))}

    def select_program(self, number, directory):
        """Choose the program this block is proved with and remember it in the directory. Before the switch epoch
        the L1 accepts only the deployed program, from it on only the bound one. A proof takes about one epoch, so
        a NEW proof is started under the bound program `lead_epochs` before the switch (and is held until the
        switch); a finished deployed-program proof is still submitted until the switch and proved again after it.
        The choice only moves forward. Without `program_switch` nothing is read or written."""
        if self.c.get('program_switch') is None:
            return
        record = directory / 'program.json'
        proved = (directory / 'proved.json').exists()
        held = json.loads(record.read_text())['program'] if record.exists() else ('deployed' if proved else None)
        activation, l1 = self.program_switch_epoch(), self.l1_program()
        if l1 is not None and l1['activation_epoch'] != activation and not (activation is None and l1['in_force'] == 'bound'):
            raise Halt(f'program switch: the gate says epoch {activation}, getl2settlement.program says '
                       f'{l1["activation_epoch"]}')
        if l1 is not None and l1['in_force'] == 'bound':
            wanted, epoch = 'bound', None  # the switch was taken: nothing but the bound program settles
        elif activation is None:
            if held == 'bound':
                raise Halt(f'{directory} was prepared for the bound program, and the program switch is no longer '
                           'scheduled (configuration or L1 release changed)')
            wanted, epoch = 'deployed', None
        else:
            epoch = self.l1_epoch()
            lead = self.c['program_switch'].get('lead_epochs', 1)
            if held == 'bound' or (l1 is None and epoch >= activation):
                wanted = 'bound'
            elif l1 is not None and epoch >= activation and not proved:
                wanted = 'bound'  # the gate's epoch has begun; the boundary block is not the head yet
            elif held == 'deployed' and proved:
                wanted = 'deployed'  # valid until the switch: submit it, do not throw the proof away
            else:
                wanted = 'bound' if epoch + lead >= activation else 'deployed'
        if held is not None and held != wanted:
            self.discard_proof(directory, held)
            log('program-switch-reprove', number=number, directory=str(directory), previous=held, program=wanted,
                activation_epoch=activation, l1_epoch=epoch)
        if held != wanted:
            atomic_write(record, json.dumps({'program': wanted, 'activation_epoch': activation}) + '\n')
            if wanted == 'bound':
                log('program-selected', number=number, program=wanted, activation_epoch=activation, l1_epoch=epoch)
        self.program = self.programs[wanted]

    @staticmethod
    def discard_proof(directory, program):
        """Set aside everything derived from a proof of `program` (kept beside the block for the record)."""
        for name in ('settlement.proof', 'proved.json', 'transaction.bin', 'submitted.json', 'execute.log',
                     'prove.log', 'verify.log', 'prove-remote.log', 'transaction-authorized.bin',
                     'authorization.json'):
            path = directory / name
            if path.exists():
                path.replace(directory / f'{name}.{program}')

    def program_submittable(self, number):
        """False while a bound-program settlement waits for the switch (the L1 would refuse it). When the L1 reports
        the program in force, that decides: the settlement goes out once the boundary block is the head. Otherwise
        the head epoch does."""
        if self.program['name'] != 'bound':
            return True
        l1 = self.l1_program()
        activation, epoch = self.program_switch_epoch(), self.l1_epoch()
        if (l1['in_force'] == 'bound') if l1 is not None else (activation is not None and epoch >= activation):
            return True
        log('settlement-waiting-program-switch', number=number, activation_epoch=activation, l1_epoch=epoch)
        return False

    def program_switch_missed(self):
        """Whether the L1 no longer accepts the deployed program while this block was proved under it."""
        if self.program['name'] != 'deployed' or self.c.get('program_switch') is None:
            return False
        l1 = self.l1_program()
        if l1 is not None:
            return l1['in_force'] == 'bound'
        activation = self.program_switch_epoch()
        return activation is not None and activation <= self.l1_epoch()

    def init_settler_authorization(self):
        auth = self.c.get('settler_authorization')
        if auth is None:
            return
        if not isinstance(auth, dict):
            raise Halt('settler_authorization must be an object')
        for key in ('signer', 'signer_sha256', 'genesis', 'keystore_dir', 'passphrase_file', 'pubkey', 'set'):
            if not auth.get(key):
                raise Halt(f'settler_authorization.{key} is required')
        if digest(auth['signer']) != auth['signer_sha256']:
            raise Halt('settler signer differs from its pin')
        check_activation(auth.get('activation_epoch'), 'settler_authorization.activation_epoch')
        self.settler_pubkey = self.read_settler_pubkey()
        if self.settler_pubkey not in self.settler_set():
            raise Halt('the settler key is not in the settler set file (after a rotation that removed it, a '
                       'registered key must settle)')

    def read_settler_pubkey(self):
        try:
            key = bytes.fromhex(Path(self.c['settler_authorization']['pubkey']).read_text().strip())
        except (OSError, ValueError) as error:
            raise Halt(f'settler_authorization.pubkey: {error}')
        if len(key) != PQ_KEY_BYTES:
            raise Halt(f'settler_authorization.pubkey must be a {PQ_KEY_BYTES}-byte enveloped hybrid public key')
        return key

    def settler_set(self):
        """The registered settler set as this worker knows it: the set file (public data), read every time."""
        path = Path(self.c['settler_authorization']['set'])
        try:
            keys = parse_settler_set(path.read_text())
        except OSError as error:
            raise Halt(f'settler set file: {error}')
        if keys is None:
            raise Halt(f'{path} is not a settler set (1 to {SETTLER_MAX_KEYS} distinct keys, hex, one per line)')
        return keys

    def settler_env(self):
        auth = self.c['settler_authorization']
        return {'PATH': '/usr/bin:/bin', 'HOME': self.c['home'], 'BLOCH_KEYSTORE_PASSPHRASE_FILE': auth['passphrase_file']}

    def check_settler_key(self):
        """Once per process, before the gate matters: the pinned signer opens the sealed keystore, finds its key in
        the set and signs and verifies a self-test value (`bloch-pos l2-settler check`). A key that cannot sign is
        found on the day the unit starts, not at the gate's epoch."""
        auth = self.c.get('settler_authorization')
        if auth is None or self.settler_key_checked or self.dry_run:
            return
        result = self.run([auth['signer'], 'l2-settler', 'check', '--set', auth['set'], '--dir', auth['keystore_dir']],
                          env=self.settler_env(), capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise Halt(f'settler key check failed: {(result.stderr or "").strip()[:400]}')
        self.settler_key_checked = True
        keys = self.settler_set()
        log('settler-key-checked', signer=keys.index(self.settler_pubkey), keys=len(keys),
            set_hash=settler_set_hash(keys).hex())

    def settler_gate(self):
        """(authorize, boundary): whether a settlement broadcast now must carry the authorization trailer, and
        whether the L1 head is within one epoch of the gate (a node may then judge it on the other side)."""
        auth = self.c.get('settler_authorization')
        if auth is None:
            return False, False
        activation = self.gate(auth.get('activation_epoch'), auth.get('l1_gate', SETTLER_GATE))
        if activation is None:
            return False, False
        epoch = self.l1_epoch()
        return epoch >= activation, activation - 1 <= epoch <= activation

    def gate_boundary(self):
        """Whether a refusal may come from a node on the other side of the settler gate or the program switch."""
        _, boundary = self.settler_gate()
        if boundary:
            return True
        activation = self.program_switch_epoch()
        return activation is not None and activation - 1 <= self.l1_epoch() <= activation

    def rotation_request(self, keys):
        """The next settler set an operator asked for (a set file at `rotation_request`, default `<set>.next`),
        or (None, None). An unreadable or invalid request is reported and ignored: settlement goes on."""
        auth = self.c['settler_authorization']
        path = Path(auth.get('rotation_request', auth['set'] + '.next'))
        if not path.exists():
            return None, None
        try:
            wanted = parse_settler_set(path.read_text())
        except OSError:
            wanted = None
        if wanted is None:
            log('settler-rotation-invalid', request=str(path))
            return None, None
        if wanted == keys:
            return None, None  # already the registered set
        return wanted, path

    def rotation_journal(self):
        return Path(self.c['settler_authorization']['set'] + '.rotation.json')

    def authorize(self, number, directory, tx):
        """The settlement with its authorization trailer. The pinned signer alone opens the keystore; it signs
        the exact bytes of `tx` (and the next set of a rotation) and verifies before it writes. What it returns
        is checked here byte for byte except the signature: the 1155 unsigned bytes first, one canonical trailer,
        this key's index in the set file, the requested next set and nothing else. An authorized settlement is
        reused while the set is unchanged, so one block is never signed in two forms."""
        auth = self.c['settler_authorization']
        keys = self.settler_set()
        if self.settler_pubkey not in keys:
            raise Halt('the settler key is not in the settler set file: a registered key must settle '
                       '(SETTLER-RUNBOOK.md, settler key procedures)')
        set_hash = settler_set_hash(keys).hex()
        wire_path, meta_path = directory / 'transaction-authorized.bin', directory / 'authorization.json'
        if wire_path.exists() and meta_path.exists():
            meta, wire = json.loads(meta_path.read_text()), wire_path.read_bytes()
            if meta.get('set_hash') == set_hash and meta.get('tx_sha256') == hashlib.sha256(tx).hexdigest() \
                    and wire[:TRANSACTION_BYTES] == tx:
                return wire
        next_set, request = self.rotation_request(keys)
        unsigned, signed = directory / 'transaction-unsigned.hex', directory / 'transaction-authorized.hex'
        atomic_write(unsigned, tx.hex() + '\n')
        signed.unlink(missing_ok=True)
        argv = [auth['signer'], 'l2-settler', 'authorize', '--genesis', auth['genesis'], '--chain-id', str(self.chain_id),
                '--tx', str(unsigned), '--set', auth['set'], '--dir', auth['keystore_dir'], '--out', str(signed)]
        if next_set is not None:
            argv[-2:-2] = ['--next-set', str(request)]
        result = self.run(argv, env=self.settler_env(), capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise Halt(f'settler signer refused: {(result.stderr or "").strip()[:400]}')
        try:
            wire = bytes.fromhex(signed.read_text().strip())
        except (OSError, ValueError) as error:
            raise Halt(f'settler signer wrote no authorized settlement: {error}')
        signed.unlink(missing_ok=True)
        decoded = decode_authorization(wire[TRANSACTION_BYTES:]) if wire[:TRANSACTION_BYTES] == tx else None
        if decoded is None:
            raise Halt('the signed settlement is not this settlement followed by one canonical authorization')
        signer, signature, signed_next = decoded
        if signer != keys.index(self.settler_pubkey) or signed_next != next_set:
            raise Halt('the authorization names another signer or another next set than requested')
        commitment = settlement_commitment(tx)
        digest = settler_digest(bytes.fromhex(self.c['network']), self.chain_id, commitment, next_set).hex()
        # The signer prints what it signed. The worker derives the digest itself (network, chain, this settlement,
        # the next set): a signer that signed anything else, for example on another genesis, is not broadcast.
        reported = re.findall(r'^\s*digest\s*:\s*([0-9a-f]{64})\s*$', result.stdout or '', re.M)
        if reported != [digest]:
            raise Halt(f'the settler signer signed {reported or "an unreported digest"}, this settlement on this '
                       f'network is {digest}')
        meta = {'number': number, 'tx_sha256': hashlib.sha256(tx).hexdigest(), 'commitment': commitment.hex(),
                'set_hash': set_hash, 'signer': signer, 'signature_bytes': len(signature),
                'next_set_hash': settler_set_hash(next_set).hex() if next_set else None, 'digest': digest}
        atomic_write(wire_path, wire)
        atomic_write(meta_path, json.dumps(meta, indent=2) + '\n')
        if next_set is not None:
            atomic_write(self.rotation_journal(), json.dumps({
                'number': number, 'directory': str(directory),
                'statement_sha256': hashlib.sha256(tx[33:33 + VALUES_BYTES]).hexdigest(),
                'from': set_hash, 'to': meta['next_set_hash'], 'request': str(request),
                'next_set': ''.join(k.hex() + '\n' for k in next_set)}, indent=2) + '\n')
            log('settler-rotation-signed', number=number, signer=signer, set_hash=set_hash,
                next_set_hash=meta['next_set_hash'], next_keys=len(next_set))
        log('settlement-authorized', number=number, signer=signer, set_hash=set_hash,
            next_set_hash=meta['next_set_hash'], bytes=len(wire))
        return wire

    def settlement_wire(self, number, directory, tx):
        """(bytes to broadcast now, authorized): `tx` as it is deployed today while the settler gate is not in
        force, `tx` with the authorization trailer from the gate's epoch on."""
        authorize, _ = self.settler_gate()
        return (self.authorize(number, directory, tx), True) if authorize else (tx, False)

    def reconcile_rotation(self, accepted):
        """Apply a signed rotation once its settlement is the accepted head (or behind it): the set file becomes
        the next set, the request is retired. A rotation whose block was settled with another statement did not
        happen; its request stays for the next settlement."""
        if self.c.get('settler_authorization') is None or not accepted:
            return
        journal = self.rotation_journal()
        if not journal.exists():
            return
        j = json.loads(journal.read_text())
        seen = statement_fields(accepted['statement'])['l2_number']
        if seen < j['number']:
            return
        auth = self.c['settler_authorization']
        if settler_set_hash(self.settler_set()).hex() == j['to']:
            journal.unlink()
            return
        if seen == j['number']:
            statement = accepted['statement']
        else:
            record = Path(j['directory']) / 'accepted.json'
            if not record.exists():
                raise Halt(f'a settler set rotation was signed for L2 block {j["number"]} and the head is now '
                           f'{seen}, but this worker holds no record of which settlement was accepted there: check '
                           f'the registered set on L1, correct {auth["set"]} and remove {journal}')
            statement = json.loads(record.read_text())['statement']
        if hashlib.sha256(bytes.fromhex(statement)).hexdigest() != j['statement_sha256']:
            journal.unlink()
            log('settler-rotation-not-applied', number=j['number'], reason='another statement was accepted there')
            return
        set_path = Path(auth['set'])
        atomic_write(Path(auth['set'] + '.previous'), set_path.read_text())
        atomic_write(set_path, j['next_set'])
        request = Path(j['request'])
        if request.exists() and parse_settler_set(request.read_text()) == parse_settler_set(j['next_set']):
            request.replace(Path(str(request) + '.applied'))
        journal.unlink()
        keys = self.settler_set()
        log('settler-set-rotated', number=j['number'], previous_set_hash=j['from'], set_hash=j['to'], keys=len(keys),
            this_key_registered=self.settler_pubkey in keys)

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
        """Submit (or rebroadcast) the same bytes to every endpoint. The list of endpoints that hold them
        (true) when at least one does, False when every refusal was transient; a terminal refusal returns
        'terminal'."""
        try:
            ports, response = self.native.submit(tx.hex())
        except SubmitRefused as refused:
            kind = refused.kind()
            log('submit-refused', number=number, kind=kind, errors=[f'{p}: {e}'[:300] for p, e in refused.errors])
            return 'terminal' if kind == 'terminal' else False
        record['attempts'] = record.get('attempts', 0) + 1
        record.setdefault('first_unix', int(time.time()))
        record['last_status'] = response.get('status')
        atomic_write(directory / 'submitted.json', json.dumps(record, indent=2) + '\n')
        log('submitted' if response.get('status') != 'duplicate' else 'submitted-duplicate', number=number,
            response=response.get('status'), tx_hash=response.get('tx_hash'), ports=ports, attempt=record['attempts'])
        return ports

    def submit_and_wait(self, number, directory, tx, view):
        values = tx[33:33 + VALUES_BYTES]
        current = self.native_view()
        if current is not None and self.accepted_outcome(number, values, current) == 'ours':
            return self.record_accepted(number, directory, current['accepted'])
        if current is None or current['source'] != view['source'] or current.get('accepted') != view.get('accepted'):
            log('request-moved-before-submit', number=number)
            return False
        path = directory / 'submitted.json'
        record = json.loads(path.read_text()) if path.exists() else {}
        if record.get('tx_sha256') not in (None, hashlib.sha256(tx).hexdigest()):
            raise Halt(f'{directory} was submitted with other settlement bytes')
        record['tx_sha256'] = hashlib.sha256(tx).hexdigest()
        if self.dry_run:
            raise Halt('dry run never broadcasts')
        height = self.l1_height()
        wire, authorized = self.settlement_wire(number, directory, tx)
        if self.c.get('settler_authorization') is not None:
            record['authorized'], record['wire_sha256'] = authorized, hashlib.sha256(wire).hexdigest()
        sent = self.broadcast(number, directory, wire, record)
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
            if sent == 'terminal':
                if self.gated and self.gate_boundary():
                    # Within one epoch of the settler gate or the program switch the refusing nodes may judge the
                    # bytes on the other side of the boundary: send again in the form the head now requires.
                    log('settlement-refused-at-gate-boundary', number=number, authorized=authorized,
                        program=self.program['name'])
                    sent = False
                else:
                    # The bytes are invalid against the request they were built for: never loop on them.
                    raise Halt(f'native nodes refuse the settlement of L2 block {number} '
                               '(policy, source, successor or proof' + (', or the settler authorization: is this '
                               'key in the registered set?' if authorized else '') + ') while its request is unchanged')
            if self.gated:
                if self.program_switch_missed():
                    log('settlement-missed-program-switch', number=number)
                    return False  # the next cycle proves this block again under the bound program
                now_wire, now_authorized = self.settlement_wire(number, directory, tx)
                if now_wire != wire:
                    wire, authorized, sent = now_wire, now_authorized, False
                    record['authorized'], record['wire_sha256'] = authorized, hashlib.sha256(wire).hexdigest()
                    log('settlement-form-changed', number=number, authorized=authorized)
            if self.clock() - last_sent >= self.c['resubmit_seconds'] or not sent:
                sent, last_sent = self.broadcast(number, directory, wire, record), self.clock()
        now = self.l1_height()
        held = sent if isinstance(sent, list) else []
        log('acceptance-timeout', number=number, l1_height_at_submit=height, l1_height_now=now,
            submitted=bool(sent), held_by=held)
        if height is not None and now is not None and now <= height:
            log('l1-not-advancing', number=number, l1_height=now)  # the L1 is stalled; nothing to fix here
        elif held and height is not None and now is not None:
            self.not_included(number, record['tx_sha256'], held)
        return False

    def not_included(self, number, tx_sha256, held):
        """An acceptance window ended while endpoints held these bytes and L1 advanced: no endpoint relayed them to
        a proposer that would include them, or proposers refuse them. Counted per settlement bytes; after
        `max_unincluded_windows` consecutive windows (default 4, 0 = alert only) the worker halts for the operator
        instead of looping silently (review r10 M2). A restart changes nothing here: the bytes come from proved.json."""
        if self.unincluded.get('tx') != tx_sha256:
            self.unincluded = {'tx': tx_sha256, 'windows': 0}
        self.unincluded['windows'] += 1
        windows, limit = self.unincluded['windows'], self.c.get('max_unincluded_windows', 4)
        log('settlement-not-included', number=number, held_by=held, windows=windows, halt_after=limit)
        if limit and windows >= limit:
            raise Halt(f'the settlement of L2 block {number} was held by endpoints {held} for {windows} acceptance '
                       'windows while L1 advanced, and was never included: check that the endpoints relay to the '
                       'validators (fork, partition, stuck node) and the proposers\' refusals')

    def record_accepted(self, number, directory, accepted):
        atomic_write(directory / 'accepted.json', json.dumps(accepted, indent=2) + '\n')
        log('accepted', number=number, commitment=accepted['commitment'],
            l2_hash=statement_fields(accepted['statement'])['l2_hash'])
        self.reconcile_rotation(accepted)
        return True

    def cycle(self):
        self.finish_swap()
        if not self.check_identity():
            return False
        self.check_settler_key()
        view = self.native_view()
        if view is None or view.get('source') is None:
            return False
        self.reconcile_rotation(view.get('accepted'))
        try:
            if self.c.get('skip_idle_blocks') and self.hold_block(view):
                return False
            number, directory = self.prepare_block(view)
            self.select_program(number, directory)
            proof = self.prove(directory, view=view)
            # A proof takes many minutes: never pay DA for a block another settlement made stale meanwhile.
            if proof is None:
                return False
            if self.request_moved(view):
                log('request-moved-after-proof', number=number)
                return False
            tx = self.transaction(directory, proof, view.get('accepted'))
            values = tx[33:33 + VALUES_BYTES]
            if not self.program_submittable(number):
                return False
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
        settler.select_program(number, directory)  # the program the L1 expects now (deployed, or bound at the switch)
        report['program'] = settler.program['name']
        block = json.loads((directory / 'block.json').read_text()) if (directory / 'block.json').exists() else {}
        report['l2_block'] = {'number': number, **{k: block[k] for k in ('hash', 'deposits', 'transactions',
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
    except (Halt, ProducerError, ForeignSettlement) as error:
        return done(False, reason=str(error))


def main():
    install_stop_handlers()
    try:
        run_main()
    except Stopped as stop:
        exit_by_signal(stop)


def run_main():
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
