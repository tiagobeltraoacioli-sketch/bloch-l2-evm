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
  block or local damage. Without `foreign_recovery` any foreign statement halts, as before
  (`reorg_recovery` cannot be set without it: review R308-22). Readers of
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
* program schedule (`getl2settlement.program_schedule`, agent 89; candidate): L1 also lists the compiled program
  changes still ahead, as (epoch, program). A worker with `next_program` picks the program for the epoch its
  settlement would land in: the L1 head slot plus `program_switch_lead_seconds` (default 1800, the expected time
  from the start of a proof to acceptance), divided by `slots_per_epoch` (default 32). When a change falls inside
  that window, the block is built and proved for the program L1 will hold then (swap: the block in flight is
  rewound and built under the next rules; rollback: the same block is proved by the fallback guest), and nothing
  is published or submitted until L1 holds that program. No proof is started for a program that cannot land
  before the gate. A finished proof of the current program is still submitted while its gate is ahead. If the
  schedule is missing or malformed, names a program this worker does not know, or the L1 head slot cannot be
  read, the worker logs `program-schedule-unusable` and uses the program L1 holds now (the behaviour before the
  schedule): at worst one proof is wasted at a gate, and a proof of a program L1 does not hold is never sent.

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

* reorgs of this worker's own settlements (drills 2026-10-31 and 2026-11-02, "L2 head N cannot extend accepted
  settlement M"; optional `reorg_recovery`, off by default): an L1 reorg can remove an accepted settlement of this
  worker while the next block is already built. The database then holds the accepted block M and unsettled blocks
  above it that no request can use. Without `reorg_recovery` this halts (exit 3) for `l2_reorg_recover.py`, as
  before. With it the worker does what that tool does, unattended: it waits until the same accepted settlement and
  the same local head were seen for `stable_seconds` (a flapping view never triggers a rebuild), and, unless
  `wait_for_finality` is false, until the native follower has finalized M (a finalized settlement cannot be
  reorged away, so a rebuild can never be undone by L1); it rebuilds a NEW database from verified L1 blocks
  (`produce reconstruct`), requires block M to be the accepted hash, returns the user transactions of the orphaned
  blocks to the spool, moves their work directories aside, swaps the databases (the journalled swap of
  `foreign_recovery`, which also restarts the settled RPC through `l2-db-generation.json`) and continues. While the
  native request of M+1 is unchanged, the worker's own proved settlement of M+1 is rebroadcast first
  (`resubmit_window_seconds`), and a database kept aside is swapped back if those bytes land after a rebuild
  (agent 206, review 153 M2). A partial quorum below the highest accepted settlement seen reaches these gates too
  (153 M1), but never builds, proves or pays DA. No paid DA batch is ever read from L1 (kit 4b7f4f7). More than `max_recoveries` within `window_seconds` (kept on disk across restarts) halts
  for the operator. Every step is an alert: a `reorg-*` log line, a JSON line in `alert_file` (default
  `<workdir>/../l2-reorg-alerts.jsonl`) and, when set, `alert_command` with the alert on its standard input.
  A database whose block M is not the accepted hash is a foreign settlement, never this case.

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
import contextlib
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
import tempfile
import threading
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
                          'forced', 'program_schedule')
# Of `getl2settlement.forced` (present only once L1 forced inclusion is enabled) the worker reads the records the next
# settlement must consume; queue totals and the surcharge move with every L1 block and are not part of the quorum.
FORCED_VIEW_FIELDS = ('due', 'due_hash')
# L1 forced inclusion (candidate; native l2_settlement::forced, bloch_l2_evm::forced_inclusion).
INBOX_DOMAIN = b'BLOCH:L2:INBOX:2'
FORCED_MAX_PER_SETTLEMENT, FORCED_MAX_GAS_PER_SETTLEMENT = 16, 300_000
sys.path.insert(0, str(Path(__file__).resolve().parent))

SPOOL_READ_LIMIT = 16_384  # the producer's MAX_POOL_ENTRIES
DEFAULTS = {'user_transactions': False, 'network_kind': 'devnet', 'max_block_gas': 15_000_000,
            'max_block_bytes': 114_688, 'max_block_txs': 128,  # bytes: one native DA batch
            'poll_seconds': 6, 'resubmit_seconds': 120}
# reorg_recovery (off unless configured). stable_seconds: how long the same accepted settlement and local head must be
# seen before a rebuild; max_recoveries per window_seconds: past that the worker halts for the operator.
# resubmit_window_seconds: while the native request of M+1 is unchanged, the worker's own proved settlement of M+1 is
# still valid on L1; it is rebroadcast for this long (from first sight) before a rebuild may start (0: never).
# max_finality_lag: with wait_for_finality false (never on the mainnet path), no rebuild while L1 finality lags the
# head by more than this many blocks (a fork whose finality is stalled).
REORG_DEFAULTS = {'wait_for_finality': True, 'stable_seconds': 120, 'max_recoveries': 3, 'window_seconds': 6 * 3600,
                  'keep': 2, 'rebuild_timeout_seconds': 3600, 'resubmit_window_seconds': 1800, 'max_finality_lag': 256}
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


# CANDIDATE, not scheduled: the next rules, L1 forced inclusion included (configuration b4663ab8), proved by
# the complete-witness fallback guest (`settlement_v3_mainnet` of integrations/sp1-execution/guest-fallback,
# 7fd7f3c0, the pinned container build, guest-fallback/build-container.sh, of bloch-l2-evm
# codex/fallback-forced-r11-20261103; agent 216). It replaces 3ad3a4f0, which did not run the forced rule.
# The prover reads the forced records from the complete artifact (`produce export --witness complete`).
# Native `l2_settlement::mainnet::PROGRAM_FALLBACK` names it (MAINNET_FALLBACK below). Its configuration
# carries a placeholder fee-sweep recipient (TBD-owner), so all of these move when the recipient is fixed.
# The proof policy, the L2 genesis and the attestor set stay.
MAINNET_NEXT = {
    'configuration': 'b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d',
    'elf_keccak': 'd95185a60668b0d4e1da49be00d85b9c550b412f13c5155be454e72889f90bf1',
    'vkey_koalabear': '432fa77548114c6431d3d64a09c851e8178e83b4744681fb73c3e2d368b11546',
    'vkey_bn254': '00865f4eeb204531918e9eb2509c851e82f1d0769d11a07ef9e1f169e8b11546',
    'guest_sha256': '7fd7f3c0fb572ca1d9cfc1caa70ba4be09f306bb6d7274782ae517b59b1b5303',
}

# CANDIDATE, not scheduled: the same next rules proved by the sparse-witness guest
# (`settlement_v3_mainnet_sparse` bc35e838, the pinned container build of bloch-l2-evm
# codex/forced-guest-r8-20261102 595d914: code-by-hash witness and L1 forced inclusion, artifact
# format SPARSE:3). The native candidate (bloch-sis-pow codex/forced-guest-native-r8-20261102) names
# this ELF in `PROGRAM_NEXT`. Its configuration is the next rules with forced inclusion (tag 4,
# b4663ab8), the configuration of the complete-witness fallback as well (MAINNET_NEXT, agent 216).
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


TIMEOUT_EXIT = 124  # exit code recorded for a prover attempt that ran out of time (as timeout(1) reports it)


class LocalAhead(Exception):
    """The local database holds the accepted settlement but has unsettled blocks above it that cannot be used: an
    L1 reorg removed a later settlement of this worker (or the request it was anchored to) while the next block was
    already built. Recoverable with `reorg_recovery`; without it this halts with the same reason as before."""

    def __init__(self, reason, accepted, head, kind):
        super().__init__(reason)
        self.accepted, self.head, self.kind = accepted, head, kind


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


# secp256k1, only to read the sender of an L2 envelope: the sender and nonce of a spooled transaction (idle-block
# demand), and the rehearsal-only `censor_senders` knob (never on mainnet). Never signs, never decides a block.
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


def check_policy_config(c):
    """The sequencer policy v2 limits this settler accepts (sequencer_policy_v2.DEFAULTS; docs/SEQUENCER-POLICY-V2.md)."""
    for key in ('max_tx_gas', 'exempt_max_tx_gas', 'fresh_slot_price_wei', 'min_tip_wei', 'congestion_max_tip_wei',
                'preflight_execute_seconds', 'preflight_max_runs', 'preflight_max_seconds', 'sender_ban_seconds',
                'standing_seconds', 'band_max_wait_seconds', 'local_prove_max_memory_gib', 'large_gas_floor',
                'large_gas_recovery_seconds', 'gate_dependent_wait_seconds'):
        if key in c and (not isinstance(c[key], int) or isinstance(c[key], bool) or c[key] <= 0):
            raise Halt(f'{key} must be a positive integer')
    reserved = c.get('tip_reserved_txs', 0)
    if not isinstance(reserved, int) or isinstance(reserved, bool) or not 0 <= reserved <= c.get('max_block_txs', 64):
        raise Halt('tip_reserved_txs must be an integer from 0 to max_block_txs')
    if c.get('preflight_database', 'rewind') not in ('rewind', 'copy'):
        raise Halt('preflight_database must be "rewind" (one copy per block plan) or "copy" (one per run)')
    if c.get('max_block_txs', 1) > 64 and c.get('user_transactions'):
        raise Halt('with the policy budget, max_block_txs is at most 64 (docs/SEQUENCER-POLICY-V2.md 3.1)')
    if c.get('preflight_cycle_limit_factor', 2) < 2:
        raise Halt('preflight_cycle_limit_factor must be at least 2: a cycle-limit verdict proves a transaction over budget')
    if c.get('min_tip_wei') and c.get('congestion_max_tip_wei') and c['congestion_max_tip_wei'] < c['min_tip_wei']:
        raise Halt('congestion_max_tip_wei is below min_tip_wei')
    exempt = c.get('write_limit_exempt_senders', [])
    if not isinstance(exempt, list) or not all(isinstance(a, str) and re.fullmatch(r'[0-9a-f]{40}', a) for a in exempt):
        raise Halt('write_limit_exempt_senders must be a list of 40-character lowercase hex addresses without 0x')


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
            raise SubmitRefused(errors, self.quorum)
        if errors:
            log('submit-partial', held_by=held, errors=[f'{p}: {e}'[:300] for p, e in errors])
        return held, first


# Native sendrawtransaction refusals (bloch-pos-node rpc.rs / engine.rs, release 78b7343a).
TX_REFUSED, TX_REFUSED_RETRYABLE, MEMPOOL_FULL, TX_REFUSED_SOURCE_CAP = -32008, -32009, -32003, -32010
ONE_PROOF_PENDING = 'one L2 proof is already pending'
# Cycles in a row a producer timeout on a kept database means "wait" before it means "unusable" (R308-22).
KEPT_SCAN_TIMEOUTS = 3
# sendrawtransaction answers that mean the node holds the bytes (native rpc.rs Admitted::New / Duplicate).
SUBMIT_HELD = ('accepted', 'duplicate')


class SubmitRefused(RuntimeError):
    """No endpoint took the transaction. `kind()` is 'terminal' only when every
    endpoint that answered judged these bytes invalid for a reason other than
    another proof already pending; anything else (transport failure, full
    mempool, retryable bar, a pending proof) is 'retry'."""

    def __init__(self, errors, quorum=None):
        self.errors, self.quorum = errors, quorum
        super().__init__('sendrawtransaction failed on every RPC endpoint: '
                         + '; '.join(f'{p}: {e}'[:200] for p, e in errors))

    def kind(self):
        refusals = [e for _, e in self.errors if e.startswith('RpcError')]
        if not refusals or len(refusals) < len(self.errors):
            return 'retry'
        terminal = [e for e in refusals if f"'code': {TX_REFUSED}," in e and ONE_PROOF_PENDING not in e]
        return 'terminal' if len(terminal) == len(refusals) else 'retry'

    def refused_by_quorum(self):
        """Whether at least a quorum of endpoints answered and every answer was a terminal refusal, while the rest
        gave no answer at all (R308-25: one endpoint down, the tolerated fault). `kind()` stays 'retry' for that
        mix, because the silent endpoint might have taken the bytes; the worker counts such acceptance windows and
        halts after `max_unincluded_windows` of them instead of rebroadcasting for ever."""
        if self.quorum is None or self.kind() == 'terminal':
            return False
        refusals = [e for _, e in self.errors if e.startswith('RpcError')]
        if len(refusals) < self.quorum or any(e.startswith('UnexpectedAnswer') for _, e in self.errors):
            return False
        return all(f"'code': {TX_REFUSED}," in e and ONE_PROOF_PENDING not in e for e in refusals)


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
        self.schedule_problem = None  # the last reason program_schedule could not be used, logged once
        self.scheduled_logged = None  # the last (gate, program) logged as program-scheduled
        for key, default in (('program_switch_lead_seconds', 1800), ('slots_per_epoch', 32)):
            value = self.c.setdefault(key, default)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise Halt(f'{key} must be a positive integer')
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
        reorg = self.c.get('reorg_recovery')
        if reorg is not None:
            if not isinstance(reorg, dict):
                raise Halt('reorg_recovery must be an object')
            if recovery is None:
                # R308-22: an own settlement that lands after a rebuild, with no kept database left that holds it,
                # can only be followed by the foreign rebuild; without it that case is a Halt.
                raise Halt('reorg_recovery needs foreign_recovery as well')
            reorg = self.c['reorg_recovery'] = {**REORG_DEFAULTS, **reorg}
            for key in ('follower_state', 'follower_status'):
                reorg[key] = reorg.get(key) or (recovery or {}).get(key) or self.c.get(key)
                if not reorg[key]:
                    raise Halt(f'reorg_recovery needs {key} (here, in foreign_recovery or at the top level)')
            for key in ('stable_seconds', 'max_recoveries', 'window_seconds', 'keep', 'rebuild_timeout_seconds',
                        'resubmit_window_seconds', 'max_finality_lag'):
                value = reorg[key]
                zero = key in ('stable_seconds', 'resubmit_window_seconds')
                if not isinstance(value, int) or isinstance(value, bool) or value < (0 if zero else 1):
                    raise Halt(f'reorg_recovery.{key} must be a {"non-negative" if zero else "positive"} integer')
            if not isinstance(reorg['wait_for_finality'], bool):
                raise Halt('reorg_recovery.wait_for_finality must be true or false')
            if self.mainnet_path and not reorg['wait_for_finality']:
                # Without the finality wait a 2-of-3 view on a fork whose finality has stopped is rebuilt onto
                # (report 94's dead fork): never on the mainnet program path.
                raise Halt('reorg_recovery.wait_for_finality false is refused on the mainnet path')
            command = reorg.get('alert_command')
            if command is not None and (not isinstance(command, list) or not command
                                        or not all(isinstance(a, str) for a in command)):
                raise Halt('reorg_recovery.alert_command must be a non-empty list of strings')
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
        budgets = [self.c.get(key) for key in ('max_block_instructions', 'max_block_sp1_gas')]
        if budgets != [None, None] and not all(isinstance(b, int) and not isinstance(b, bool) and b > 0 for b in budgets):
            raise Halt('max_block_instructions and max_block_sp1_gas go together, as positive integers')
        self.policy_clock = time.time  # the policy's windows are wall seconds, persisted across restarts
        if budgets != [None, None]:
            check_policy_config(self.c)
        local_gas = self.c.get('local_prove_max_sp1_gas')
        if local_gas is not None and (type(local_gas) is not int or local_gas <= 0):
            raise Halt('local_prove_max_sp1_gas must be a positive integer')
        self.work = Path(self.c['workdir'])
        self.rebuild_discarded_at = None
        self.waiting_for = None  # the accepted settlement a recovery last reported waiting on
        self.reorg_seen = None  # (accepted number, hash, local head, head hash) of a reorg case being watched
        self.reorg_since = None  # monotonic time that case was first seen
        self.reorg_l1_height = None  # L1 chain height when that case was first seen
        self.reorg_resubmit = None  # {'case', 'number', 'last', 'state'}: rebroadcast of a still-valid own settlement
        self.view_behind = False  # the last native_view was a partial quorum below accepted_floor (reorg_recovery)
        self.view_support = []  # ports that formed the last native_view
        self.reorg_reported = set()  # (alert kind, case) already alerted, so each alert fires once per case
        self.native = Endpoints(rpc_endpoints(self.c), rpc_quorum(self.c), self.rpc, self.clock, self.sleep)
        self.accepted_floor = 0  # highest accepted L2 number seen in a quorum view
        self.floor_stall = None  # (number, first seen, reads) while a partial quorum stays behind the floor
        stall = self.c.get('quorum_floor_stall_seconds', 1200)
        if not isinstance(stall, int) or isinstance(stall, bool) or stall < 0:
            raise Halt('quorum_floor_stall_seconds must be a non-negative integer')
        self.quorum_refused = False  # the last broadcast was refused for good by a quorum, the rest silent
        self.refused = {}  # consecutive acceptance windows that ended so, per settlement bytes (R308-25)
        self.kept_scan_timeouts = 0  # consecutive cycles a kept database timed out in restore_own_settlement
        self.unincluded = {}  # consecutive acceptance windows the same bytes were held but not included
        limit = self.c.get('max_unincluded_windows', 4)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise Halt('max_unincluded_windows must be a non-negative integer')
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

    def native_view(self, allow_behind=False):
        """The settlement view a quorum of validator RPCs reports identically, or None.

        A partial quorum below `accepted_floor` is None, except with `allow_behind` (reorg detection only): then it
        is returned and `view_behind` is set. Such a view never builds, proves or pays DA; it can only reach
        `recover_reorg`, whose gates decide whether the reorg is real (153 M1: one endpoint stuck on the losing
        fork must not hide a real reorg). The floor-stall restart is then not needed and not used."""
        self.view_behind = False
        view, support = self.native.agreed('getl2settlement', project=settlement_view)
        if view is None:
            return None  # validators momentarily disagree; retry later
        if view['network'] != self.c['network'] or view['chain_id'] != self.chain_id:
            raise Halt('native network identity changed')
        accepted = view.get('accepted')
        number = statement_fields(accepted['statement'])['l2_number'] if accepted else 0
        unanimous = len(support) == len(self.native.ports)
        self.view_support = support
        if not unanimous and number < self.accepted_floor:
            # A partial quorum must not move the accepted head backwards (two stale
            # endpoints); a unanimous view is trusted as before.
            log('rpc-quorum-view-behind', accepted=number, seen=self.accepted_floor, ports=support)
            if allow_behind:
                self.view_behind = True
                return view
            self.floor_stall_check(number, support)
            return None
        self.floor_stall = None
        self.accepted_floor = number if unanimous else max(self.accepted_floor, number)
        return view

    def program_named(self, reported):
        """The configured program whose identity L1 reports (a `program` or `program_schedule` entry), or None."""
        fields = ('configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254', 'proof_policy')
        identity = b''.join(bytes.fromhex(reported[k]) for k in fields)
        if len(identity) != 160:
            raise ValueError('a program identity is five 32-byte fields')
        for program in (self.base_program, self.next_program, self.fallback_program):
            if program is not None and Path(program['l2_config']).read_bytes()[32:192] == identity:
                return program
        return None

    def program_of(self, view):
        """The program L1 holds now, from a quorum view. A node without the report is on the activated one."""
        reported = view.get('program')
        if self.next_program is None or reported is None:
            return self.base_program
        program = self.program_named(reported)
        if program is None:
            raise Halt(f'L1 reports a program this worker is not configured for: {reported}')
        return program

    def schedule_unusable(self, reason):
        """Fail safe: no program change is anticipated. Logged once per distinct reason."""
        if self.schedule_problem != reason:
            log('program-schedule-unusable', reason=reason[:300])
        self.schedule_problem = reason
        return None

    def scheduled_program(self, view, directory):
        """The program a settlement started now would land under, from `program_schedule`, or None to use the
        program L1 holds now (no change inside the window, or the schedule cannot be used: see the module notes).
        A finished proof of the current program for `directory` keeps that program while its gate is ahead."""
        if self.next_program is None:
            return None
        schedule = view.get('program_schedule')
        if not isinstance(schedule, list):
            return self.schedule_unusable('getl2settlement has no program_schedule list')
        entries, last = [], -1
        try:
            for entry in schedule:
                epoch = entry['epoch']
                if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= last:
                    raise ValueError(f'epochs must be increasing integers: {epoch!r}')
                program = self.program_named(entry)
                if program is None:
                    raise ValueError(f'a scheduled program this worker is not configured for at epoch {epoch}')
                entries.append((epoch, program))
                last = epoch
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            return self.schedule_unusable(f'program_schedule: {error}')
        if not entries:
            self.schedule_problem = None
            return None
        try:
            slot = self.native.bounded_value('getchaininfo', 'slot')
            if not isinstance(slot, int) or slot < 0:
                raise ValueError(f'bad slot {slot!r}')
        except Exception as error:  # noqa: BLE001 - fail safe: no anticipation without a clock
            return self.schedule_unusable(f'L1 head slot unreadable: {type(error).__name__}: {error}')
        self.schedule_problem = None
        rule = self.c.get('timestamp_rule')
        slot_ms = int(rule.split(':')[2]) if rule else 30_000
        spe = self.c['slots_per_epoch']
        now_epoch = slot // spe
        landing_epoch = (slot - (-self.c['program_switch_lead_seconds'] * 1000 // slot_ms)) // spe
        due = [(epoch, program) for epoch, program in entries if epoch <= landing_epoch]
        if not due:
            return None
        gate, target = due[-1]
        marker = directory / 'program.json'
        if (directory / 'proved.json').exists() and marker.exists() and entries[0][0] > now_epoch \
                and json.loads(marker.read_text()).get('name') == self.program_of(view)['name']:
            return None  # a finished proof of the program L1 holds: send it before the gate
        if target is not self.program_of(view) and self.scheduled_logged != (gate, target['name']):
            self.scheduled_logged = (gate, target['name'])
            log('program-scheduled', program=target['name'], gate_epoch=gate, l1_slot=slot, landing_epoch=landing_epoch)
        return target

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
            if self.budget_on():
                return self.extend_within_budget(parent, anchor, deposits, anchor_slot, number)
            return self.produce(*self.extend_arguments(parent, anchor, deposits, anchor_slot))
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

    def budget_on(self):
        """Sequencer policy v2 (sequencer_policy_v2.py, docs/SEQUENCER-POLICY-V2.md) decides the user transactions of
        each block: user transactions on and a block budget in SP1 gas configured."""
        return bool(self.c.get('user_transactions') and self.c.get('max_block_sp1_gas'))

    def policy(self):
        """The v2 planner with this settler's limits. Its state (bans, waits, standing, congestion tip) lives in
        `<workdir>/sequencer-policy.json`, which the settled RPC reads with `--required-tip-file`. Windows are wall
        seconds, persisted across restarts."""
        import sequencer_policy_v2 as policy_v2
        policy_v2.set_hash(keccak256)
        config = {key: self.c[key] for key in policy_v2.DEFAULTS if key in self.c}
        work = getattr(self, 'work', None)
        clock = getattr(self, 'policy_clock', None) or getattr(self, 'clock', time.time)
        return policy_v2.Policy(config, work / 'sequencer-policy.json' if work else None, clock, log)

    def publish_admission_policy(self):
        """Refresh RPC admission independently of whether a cycle examines the spool or builds a block."""
        if self.budget_on():
            work = getattr(self, 'work', None)
            if work is not None:
                work.mkdir(parents=True, exist_ok=True)
            self.policy().save()

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

    def pool_arguments(self, pool, selecting=False):
        """The producer's limits for the spool, a preflight list or the selected list. `select` (the policy's native
        report) runs without the per-block transaction cap: the policy applies `max_block_txs` to its own try order, so the
        producer's tip order cannot drop a sender with standing before the tiers apply (agents/166 §1.5)."""
        args = ['--txs', str(pool), '--max-gas', str(self.c['max_block_gas']), '--max-bytes', str(self.c['max_block_bytes'])]
        if not selecting:
            args += ['--max-txs', str(self.c['max_block_txs'])]
        if self.c.get('min_tip_wei'):
            args += ['--min-tip-wei', str(self.c['min_tip_wei'])]
        if self.c.get('producer_write_price') and self.budget_on():
            # The write price inside the producer's own selection (round 15, agents/304 U3): `select` and `extend`
            # leave pending a transaction that adds storage slots it does not pay for, judged on the block as built,
            # and report it under `unpaid`. No block of this producer then holds an unpaid slot, whatever the gate did.
            policy = self.policy()
            args += ['--fresh-slot-price-wei', str(policy.c['fresh_slot_price_wei'])]
            if policy.c['write_limit_exempt_senders']:
                args += ['--write-exempt', ','.join(policy.c['write_limit_exempt_senders'])]
        return args

    def select_block(self, parent, anchor, deposits, anchor_slot, raws, directory):
        """What the producer's selection would do with these transactions on this parent and these deposits, per
        transaction (`produce-dev select`): native execution, nothing committed or pruned."""
        pool = directory / 'dry.json'
        pool.write_text(json.dumps(raws))
        args = self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False)
        args[0] = 'select'
        return self.produce(*args, *self.pool_arguments(pool, selecting=True))

    def measure_block(self, parent, anchor, deposits, anchor_slot, number, raws, tag):
        """Build the block from exactly these transactions, with these deposits, on a throwaway copy of the database and
        run the guest in execute mode under the host's cycle limit. Returns (result, producer report): result is a
        `Cost`, `OVER_LIMIT` when the two-stage host's gas-off count reached `BLOCH_PREFLIGHT_CYCLE_LIMIT` (it prints
        `Settlement V3 over cycle limit` and exits 3; `preflight_result`), or None when the run gave no cost
        (wall-clock backstop, crash, OOM, missing or disagreeing lines, a single-stage host). No proof, no lock.

        The copy is made once per block plan and rewound to the parent after each run (`preflight_database`,
        agents/264 F264-6): a plan takes up to 24 runs plus the control, and a copy per run grows with the chain's
        state inside the 180 s allowance. A copy that does not read back as the parent after the rewind is thrown
        away, and the next run copies again."""
        scratch = deposits.parent / f'preflight-{tag}'
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        db = None
        try:
            db = self.preflight_database(deposits.parent, scratch)
            pool = scratch / 'pool.json'
            pool.write_text(json.dumps(raws))
            args = self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False)
            args[args.index('--target') + 1] = str(db)
            block = self.produce(*args, *self.pool_arguments(pool))
            self.produce('export', '--target', str(db), '--number', str(number), '--out', str(scratch / 'block.artifact'),
                         *self.export_witness())
            request = scratch / 'native-request.txt'
            request.write_text(self.preflight_request)
            env = {'PATH': self.c.get('prover_path', '/usr/bin:/bin'), 'HOME': self.c['home'], 'TMPDIR': self.c['home'] + '/tmp',
                   'SP1_CIRCUIT_MODE': 'release', 'BLOCH_NATIVE_L2_REQUEST': str(request),
                   'BLOCH_NATIVE_L2_ARTIFACT': str(scratch / 'block.artifact'),
                   'BLOCH_PREFLIGHT_CYCLE_LIMIT': str(self.policy().cycle_limit())}
            argv = [self.program['prover'], *self.program['prover_args'], 'execute', 'native-artifact', self.program['guest']]
            try:
                with (scratch / 'execute.log').open('w') as out:
                    # In its own process group, killed with its SP1 segments on a timeout (F8, as the proof stages).
                    result = self.run_bounded(argv, env=env, stdout=out, stderr=subprocess.STDOUT,
                                              timeout=self.c.get('preflight_execute_seconds', 90))
            except subprocess.TimeoutExpired:
                return None, block
            return self.preflight_result(result.returncode, (scratch / 'execute.log').read_text(errors='replace'),
                                         int(env['BLOCH_PREFLIGHT_CYCLE_LIMIT'])), block
        finally:
            if db is not None and db.parent != scratch:
                self.preflight_rewind(db, parent, number)
            shutil.rmtree(scratch, ignore_errors=True)

    def preflight_database(self, directory, scratch):
        """The database a preflight run builds on: this plan's one copy (`preflight-db` beside the block's files), or
        a copy of its own when `preflight_database` is `copy` or no plan is open (the start-up probe)."""
        shared = getattr(self, 'preflight_shared', None)
        if self.c.get('preflight_database', 'rewind') != 'rewind' or shared is None:
            db = scratch / 'db'
            shutil.copytree(self.c['l2_db'], db, symlinks=True)
            return db
        if not shared.exists():
            partial = shared.with_name(shared.name + '.partial')
            shutil.rmtree(partial, ignore_errors=True)
            shutil.copytree(self.c['l2_db'], partial, symlinks=True)
            partial.replace(shared)
        return shared

    def preflight_rewind(self, db, parent, number):
        """Take the measured block off the plan's copy again. The copy is kept only when the producer then reads the
        parent as its head; anything else (a rewind the producer refuses, a run killed mid-write) removes the copy."""
        try:
            head = self.produce('head', '--target', str(db))
            if head.get('number') == number:
                # `rewind` names the head block it removes, by number and hash.
                self.produce('rewind', '--target', str(db), '--number', str(number), '--hash', head['hash'])
                head = self.produce('head', '--target', str(db))
            if head.get('number') == number - 1 and head.get('hash') == parent:
                return
            reason = f'head {head.get("number")} after the rewind'
        except (ProducerError, OSError, ValueError, AttributeError, subprocess.TimeoutExpired) as error:
            reason = str(error)[:200]
        log('preflight-copy-discarded', number=number, reason=reason)
        shutil.rmtree(db, ignore_errors=True)

    def preflight_result(self, returncode, text, limit):
        """Read a two-stage preflight run (agent 257, on agent 224's recommendation 2). The host first counts the
        guest's instructions with SP1 gas off (`Settlement V3 preflight stage 1: instructions=N`); at or over the limit
        that count is the verdict (`over cycle limit: limit=<n> instructions=N stage=1`, exit 3, no gas run); under it,
        the gas run gives the cost line with the same count. Anything else, including a single-stage host's late
        gas-path verdict, is no cost: a host failure for the policy, never a verdict on a transaction."""
        import sequencer_policy_v2 as policy_v2
        prefixes = ('Settlement V3 preflight stage 1:', 'Settlement V3 cost:',
                    'Settlement V3 guest matched the independent host statement:', 'Settlement V3 over cycle limit:')
        records = [[(position, line) for position, line in enumerate(text.splitlines()) if line.startswith(prefix)]
                   for prefix in prefixes]
        stage_one, gas_lines, instruction_lines, over_lines = records
        self.preflight_single_stage = not stage_one
        if type(limit) is not int or not 0 < limit <= 2**64 - 1 or type(returncode) is not int or len(stage_one) != 1:
            return None
        integer = r'(0|[1-9][0-9]{0,19})'
        first = re.fullmatch(prefixes[0] + r' instructions=' + integer + r' elapsed_ms=' + integer, stage_one[0][1])
        if first is None or any(int(value) > 2**64 - 1 for value in first.groups()):
            return None
        counted = int(first[1])
        if returncode == 3:
            expected = f'{prefixes[3]} limit={limit} instructions={counted} stage=1'
            if (len(over_lines) == 1 and over_lines[0][1] == expected and counted >= limit
                    and over_lines[0][0] > stage_one[0][0] and not gas_lines and not instruction_lines):
                return policy_v2.OVER_LIMIT
            return None
        if returncode or over_lines or len(gas_lines) != 1 or len(instruction_lines) != 1 or counted >= limit:
            return None
        gas = re.fullmatch(prefixes[1] + r' gas=' + integer + r' touched_memory=[0-9]+ record_bytes=[0-9]+ syscalls=.*',
                           gas_lines[0][1])
        instructions = re.fullmatch(prefixes[2] + ' ' + integer + r' instructions in .+', instruction_lines[0][1])
        if (gas is None or instructions is None or int(gas[1]) > 2**64 - 1 or int(instructions[1]) != counted
                or not stage_one[0][0] < gas_lines[0][0] < instruction_lines[0][0]):
            return None
        return policy_v2.Cost(int(gas[1]), counted)

    def measure_empty(self, parent, anchor, deposits, anchor_slot, number, tag):
        """The control: the same block without deposits or transactions, so the request names no consumed deposit. A
        cost here and none for the block tells a heavy block from a failing host."""
        # Give the control its own directory: extend_arguments reads forced.json beside deposits.
        # Leaving it beside the real deposits would accidentally include mandatory forced work.
        control = Path(tempfile.mkdtemp(prefix=f'.empty-control-{tag}-', dir=deposits.parent))
        empty = control / 'deposits.json'
        empty.write_text('[]')
        request = getattr(self, 'preflight_request', None)
        try:
            if request:
                lines = request.split('\n')
                if len(lines) >= 4 and lines[-1] == '':
                    lines[-2] = lines[-3]  # consumed_end = consumed_start: no deposit consumed
                self.preflight_request = '\n'.join(lines)
            return self.measure_block(parent, anchor, empty, anchor_slot, number, [], tag)[0]
        finally:
            self.preflight_request = request
            shutil.rmtree(control)

    def extend_within_budget(self, parent, anchor, deposits, anchor_slot, number):
        """Commit only the block sequencer policy v2 chose (sequencer_policy_v2.py, docs/SEQUENCER-POLICY-V2.md).

        Declared EVM gas does not bound proving cost, so candidate blocks are built on a copy of the database and run in
        execute mode under the host's cycle limit (twice the instruction budget). A block whose mandatory items (deposits or forced records)
        alone are over the budget still commits, because L1 names exactly those deposits; it carries nothing else and
        writes `deposits-over-budget.json` for the operator's exit (STUCK-BLOCK-RUNBOOK.md). Only what the committed
        block's own report included, or what the producer dropped for good, leaves the spool (review r8 N1)."""
        # hold_block closes the spool for a block on a stale source: this path reads the spool itself, so it must too.
        entries = self.spool_entries() if getattr(self, 'spool_open', True) else []
        pending = json.loads(deposits.read_text())
        forced = read_forced(deposits.parent)
        self.preflight_request = self.preflight_source
        tags = iter(range(1 << 30))
        policy = self.policy()
        program_key = (self.program['prover'], tuple(self.program['prover_args']), self.program['guest'],
                       self.program.get('witness', 'complete'), policy.cycle_limit())
        if not getattr(self, 'cost_line_checked', False) or getattr(self, 'cost_line_program', None) != program_key:
            # With a budget, the prover must give a cost for an empty block, or users would be starved silently (r7 F2).
            probe = self.measure_empty(parent, anchor, deposits, anchor_slot, number, 'probe')
            try:
                import sequencer_policy_v2 as policy_v2
                policy_v2.check_cost_line(probe)
            except RuntimeError as error:
                if getattr(self, 'preflight_single_stage', False):
                    raise Halt('the prover is not a two-stage preflight host (no "Settlement V3 preflight stage 1" line): '
                               'a single-stage host gives its cycle-limit verdict 20-30 s late (agent 224); refusing to '
                               'start with max_block_sp1_gas set') from None
                raise Halt(f'{error} (max_block_sp1_gas is set: the prover must print the Settlement V3 cost line)') from None
            self.cost_line_checked = True
            self.cost_line_program = program_key
        by_hash = {keccak256(bytes.fromhex(raw)).hex(): (path, raw) for path, raw in entries}
        self.preflight_shared = deposits.parent / 'preflight-db'
        shutil.rmtree(self.preflight_shared, ignore_errors=True)  # never a copy from an earlier plan or process
        try:
            plan = policy.plan(
                [raw for _, raw in entries],
                lambda raws: self.select_block(parent, anchor, deposits, anchor_slot, raws, deposits.parent),
                lambda raws: self.measure_block(parent, anchor, deposits, anchor_slot, number, raws, next(tags)),
                lambda: self.measure_empty(parent, anchor, deposits, anchor_slot, number, next(tags)),
                has_mandatory=bool(pending) or bool(forced))
        finally:
            shutil.rmtree(self.preflight_shared, ignore_errors=True)
            self.preflight_shared = None
        base = plan.base if hasattr(plan.base, 'sp1_gas') else None
        if plan.mandatory_over_budget:
            atomic_write(deposits.parent / 'deposits-over-budget.json', json.dumps(
                {'number': number, 'sp1_gas': base.sp1_gas if base else None,
                 'instructions': base.instructions if base else None, 'over_cycle_limit': plan.base == 'over-limit',
                 'budget_sp1_gas': policy.c['max_block_sp1_gas'], 'budget_instructions': policy.c['max_block_instructions'],
                 'deposits': len(pending), 'forced': len(forced), 'profile': plan.profile}, sort_keys=True) + '\n')
        # The plan's verdicts (bans, failure counts, waits) are saved before anything moves: a refused final extend
        # falls back to a deposit-only block without `committed`, and a crash can come anywhere (agents/243 A243-8).
        policy.save()
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
        atomic_write(pool, json.dumps(plan.raws))
        args = self.extend_arguments(parent, anchor, deposits, anchor_slot, spool=False)
        block = self.produce(*args, *self.pool_arguments(pool))
        for name in policy.committed(plan, block):  # committed: only what this block's own report names
            if name in by_hash:
                by_hash[name][0].unlink(missing_ok=True)
        cost = plan.cost if hasattr(plan.cost, 'sp1_gas') else None
        atomic_write(deposits.parent / 'prover-profile.json', json.dumps(
            {'number': number, 'profile': plan.profile, 'sp1_gas': cost.sp1_gas if cost else None,
             'instructions': cost.instructions if cost else None}, sort_keys=True) + '\n')
        log('block-plan', number=number, runs=plan.runs, seconds=round(plan.seconds, 1), exhausted=plan.exhausted,
            transactions=len(plan.chosen), sp1_gas=cost.sp1_gas if cost else None,
            base_sp1_gas=base.sp1_gas if base else None, profile=plan.profile,
            mandatory_over_budget=plan.mandatory_over_budget, host_unavailable=plan.host_unavailable,
            required_tip=policy.required_tip())
        return block

    def extend_arguments(self, parent, anchor, deposits, anchor_slot=None, spool=True):
        args = ['extend', '--target', self.c['l2_db'], '--parent', parent, '--anchor', anchor, '--deposits', str(deposits)]
        if read_forced(Path(deposits).parent):
            # L1 forced inclusion: the producer runs these first, after the deposits, outside every sequencer limit.
            args += ['--forced', str(Path(deposits).parent / 'forced.json')]
        if self.c.get('timestamp_rule'):
            # L2 time follows the anchored native slot (rollup rule); attestors rebuild with the same rule.
            args += ['--timestamp-rule', self.c['timestamp_rule'], '--anchor-slot', str(anchor_slot)]
        if self.c['user_transactions'] and spool and self.spool_open:
            args += self.pool_arguments(self.c['txpool_dir'])
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

    def spool_demand(self, head, view=None):
        """Whether a spooled transaction may go into the next block on `head`. A file alone is not demand: the RPC admits
        nonces up to 16 ahead and keeps them 3 hours, and the producer defers a nonce gap without dropping it, so one such
        entry would make every cycle due (review r7 F5). Demand is an entry whose nonce is its sender's next nonce at the
        head. Bytes that do not read as a transaction, and a sender whose nonce the producer cannot tell, count as demand:
        the producer drops what it cannot decode, and a block too many costs less than a transaction never served.
        Fees are not checked: the RPC admits only a fee cap over the next base fee and a tip over the floor."""
        if not self.c['user_transactions']:
            return False
        # Direct demand checks also publish before examining an empty spool.
        self.publish_admission_policy()
        files = sorted(Path(self.c['txpool_dir']).glob('*.tx'))
        if not files:
            return False
        if self.budget_on() and view is not None:
            return self.policy_demand(head, view)
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

    def policy_demand(self, head, view):
        """Demand under sequencer policy v2: the producer's native selection of the spool on `head` (`select`, nothing
        committed), then the policy's own gate at the current time, with the decayed tip and with no mandatory item, since
        a block with deposits is due anyway (review r8 N8, r9 U4, U5). The policy state is saved, so the tip the RPC
        publishes decays while the chain is idle. If this cannot be answered, the spool counts as demand."""
        directory = self.work / '.demand'
        try:
            directory.mkdir(parents=True, exist_ok=True)
            deposits = directory / 'deposits.json'
            deposits.write_text('[]')
            request = view['source'].get('request')
            slot = int(request.splitlines()[3]) if request else None
            args = self.extend_arguments(head, view['source']['block'], deposits, slot, spool=False)
            args[0] = 'select'
            report = self.produce(*args, *self.pool_arguments(self.c['txpool_dir'], selecting=True))
            policy = self.policy()
            due = policy.demand(report.get('tx_stats') or [], policy.clock(), False)
            policy.save()
            return due
        except Exception as error:  # noqa: BLE001
            log('spool-demand-unknown', reason=f'{type(error).__name__}: {error}'[:300])
            return True

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
            forced = self.forced_backlog() if 'forced' in view else 0
        except Exception as error:  # noqa: BLE001 - the quorum view just passed: try again next cycle
            log('idle-check-failed', reason=f'{type(error).__name__}: {error}'[:300])
            return True
        pace = self.c.get('min_block_interval_seconds', 0)
        reason = ('forced' if forced or (view.get('forced') or {}).get('due') else
                  'deposits' if backlog or view['source'].get('pending') else 'transactions' if self.spool_demand(expected, view)
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
        marker = directory / 'program.json'
        if produced.exists() and json.loads(produced.read_text()).get('rules') != 'next':
            self.supersede(directory)
        elif marker.exists():
            # The work of a reused block (no block.json) is kept while it was made for this program: a block
            # re-proved for the rollback, or proved ahead of a scheduled gate, is not proved a second time.
            if json.loads(marker.read_text()).get('name') != self.program['name']:
                # Same rules, other guest (the rollback): the block stays, its artifact and proof are made again.
                log('l2-block-reproved-for-program', number=number, program=self.program['name'])
                self.supersede(directory)
        elif directory.exists() and not produced.exists() and (directory / 'proved.json').exists():
            self.supersede(directory)  # proved before the program was recorded: of the old program

    def prepare_block(self, view):
        """Return (number, directory) for the next block, reusing a crash-left block."""
        self.program = self.program_of(view)
        accepted = view.get('accepted')
        number = statement_fields(accepted['statement'])['l2_number'] + 1 if accepted else 1
        parent = statement_fields(accepted['statement'])['l2_hash'] if accepted else self.c['l2_genesis']
        anchor = view['source']['block']
        directory = self.work / f'{number:08d}-{anchor[:16]}'
        self.program = self.scheduled_program(view, directory) or self.program
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
            self.censor_spool(number)
            block = self.extend(parent, anchor, deposits, anchor_slot, number)
            check_forced_block(block, due or [])
            if user_count(block) and not self.c['user_transactions']:
                raise Halt('producer included user transactions while user_transactions is false')
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
                reason = f'unsettled L2 block {number} has anchor {info["anchor"]}, native now requests {anchor}'
                if self.c.get('reorg_recovery'):
                    raise LocalAhead(reason, number - 1, head, 'anchor')
                raise Halt(reason)
            log('l2-block-reused', number=number, hash=info['hash'])
        else:
            reason = f'L2 head {head["number"]} cannot extend accepted settlement {number - 1}'
            if self.c.get('reorg_recovery'):
                if self.local_hash(number - 1) != parent:
                    raise ForeignSettlement(f'{reason}: local block {number - 1} is not the accepted {parent} '
                                            '(another settler?)')
                raise LocalAhead(reason, number - 1, head, 'ahead')
            raise Halt(reason)
        artifact = directory / 'block.artifact'
        if not artifact.exists():
            self.produce('export', '--target', self.c['l2_db'], '--number', str(number), '--out', str(artifact),
                         *self.export_witness())
            if self.next_program is not None:
                atomic_write(directory / 'program.json', json.dumps({'name': self.program['name']}) + '\n')
        request = directory / 'native-request.txt'
        text = self.request_text(view)
        if request.exists() and request.read_text() != text:
            raise Halt(f'{request} already holds a different request')
        atomic_write(request, text)
        return number, directory

    @staticmethod
    def request_text(view):
        """The native request of the next block as `native-request.txt` holds it (what the proof binds to)."""
        accepted, source = view.get('accepted'), view['source']
        text = source['request'] + (accepted['commitment'] if accepted else '0' * 64) + '\n'
        if 'inbox_count' in source:
            text += f"{source['inbox_count']}\n{source['consumed_start']}\n{source['consumed_end']}\n"
        return text

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
        profile = self.prover_profile(directory)
        if profile:
            env.update(profile['env'])
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
                timed_out = False
                try:
                    if where == 'remote':
                        result = self.prove_remote(directory, proof)
                    elif name == 'prove' and not (self.local_proof_fits(directory)
                                                  and self.local_profile_fits(directory, profile)):
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
        atomic_write(directory / 'proved.json', json.dumps({'steps': steps, 'proof_sha256': digest(proof)}, indent=2) + '\n')
        log('proof-generated', directory=str(directory), seconds=sum(s['seconds'] for s in steps), program=self.program['name'])
        return proof

    def prover_profile(self, directory):
        """The prover settings sequencer policy v2 chose for this block by its preflight SP1 gas (`prover-profile.json`,
        written when the block was built): `fast`, `lowmem-2c` or `mandatory-heavy` (sequencer_policy_v2.PROFILES). None
        without a budget or for a block built without the policy."""
        if not self.budget_on():
            return None
        try:
            name = json.loads((directory / 'prover-profile.json').read_text())['profile']
        except (OSError, ValueError, KeyError, TypeError):
            return None
        import sequencer_policy_v2 as policy_v2
        profile = policy_v2.PROFILES.get(name)
        return dict(profile, name=name) if profile else None

    def local_profile_fits(self, directory, profile):
        """`local_prove_max_memory_gib` (optional): the local prover is not tried for a block whose profile needs a larger
        memory scope than this unit has; the remote prover, if configured, takes it."""
        limit = self.c.get('local_prove_max_memory_gib')
        if limit is None or profile is None or profile['memory_max_gib'] <= limit:
            return True
        log('local-proof-refused', directory=str(directory), profile=profile['name'],
            memory_max_gib=profile['memory_max_gib'], limit=limit)
        return False

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
        """Submit (or rebroadcast) the same bytes to every endpoint. The list of endpoints that hold them
        (true) when at least one does, False when every refusal was transient; a terminal refusal returns
        'terminal'."""
        try:
            ports, response = self.native.submit(tx.hex())
        except SubmitRefused as refused:
            kind = refused.kind()
            by_quorum = refused.refused_by_quorum()
            self.quorum_refused = self.quorum_refused or by_quorum
            log('submit-refused', number=number, kind=kind, errors=[f'{p}: {e}'[:300] for p, e in refused.errors],
                **({'refused_by_quorum': True} if by_quorum else {}))
            return 'terminal' if kind == 'terminal' else False
        self.quorum_refused = False
        self.refused = {}
        record['attempts'] = record.get('attempts', 0) + 1
        record.setdefault('first_unix', int(time.time()))
        record['last_status'] = response.get('status')
        atomic_write(directory / 'submitted.json', json.dumps(record, indent=2) + '\n')
        log('submitted' if response.get('status') != 'duplicate' else 'submitted-duplicate', number=number,
            response=response.get('status'), tx_hash=response.get('tx_hash'), ports=ports, attempt=record['attempts'])
        return ports

    def submitted_record(self, directory):
        """The broadcast record of a work directory ({} before the first broadcast). The file is written
        atomically, so an empty, cut or non-object one is outside damage: a named halt for the operator (R308-24),
        not a decode error that restarts the unit every minute with the proved block never rebroadcast."""
        path = directory / 'submitted.json'
        if not path.exists():
            return {}
        try:
            record = json.loads(path.read_text())
            if not isinstance(record, dict):
                raise ValueError(f'a JSON {type(record).__name__}, not an object')
        except (OSError, ValueError) as error:
            raise Halt(f'{path} is unreadable ({type(error).__name__}: {str(error)[:200]}): it records which '
                       'settlement bytes were broadcast for this block. Operator review: compare transaction.bin '
                       'with what L1 holds, then remove the file so the same proved bytes are broadcast again') from None
        return record

    def submit_and_wait(self, number, directory, tx, view):
        values = tx[33:33 + VALUES_BYTES]
        current = self.native_view()
        if current is not None and self.accepted_outcome(number, values, current) == 'ours':
            return self.record_accepted(number, directory, current['accepted'])
        if current is None or current['source'] != view['source'] or current.get('accepted') != view.get('accepted'):
            log('request-moved-before-submit', number=number)
            return False
        if self.program_moved(current, view):
            # The proof is of another program than L1 holds: L1 refuses it. The next cycle rebuilds this block.
            log('program-moved-before-submit', number=number, program=current.get('program'))
            return False
        record = self.submitted_record(directory)
        if record.get('tx_sha256') not in (None, hashlib.sha256(tx).hexdigest()):
            raise Halt(f'{directory} was submitted with other settlement bytes')
        record['tx_sha256'] = hashlib.sha256(tx).hexdigest()
        if self.dry_run:
            raise Halt('dry run never broadcasts')
        height = self.l1_height()
        self.quorum_refused = False
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
            if self.program_moved(current, view):
                log('program-moved-after-submit', number=number, program=current.get('program'))
                return False
            if sent == 'terminal':
                # The bytes are invalid against the request they were built for: never loop on them.
                raise Halt(f'native nodes refuse the settlement of L2 block {number} '
                           '(policy, source, successor or proof) while its request is unchanged')
            if self.clock() - last_sent >= self.c['resubmit_seconds'] or not sent:
                sent, last_sent = self.broadcast(number, directory, tx, record), self.clock()
        now = self.l1_height()
        held = sent if isinstance(sent, list) else []
        log('acceptance-timeout', number=number, l1_height_at_submit=height, l1_height_now=now,
            submitted=bool(sent), held_by=held)
        if height is not None and now is not None and now <= height:
            log('l1-not-advancing', number=number, l1_height=now)  # the L1 is stalled; nothing to fix here
        elif held and height is not None and now is not None:
            self.not_included(number, record['tx_sha256'], held)
        if not held and self.quorum_refused:
            self.refused_window(number, record['tx_sha256'])
        return False

    def refused_window(self, number, tx_sha256):
        """An acceptance window ended in which no endpoint held these bytes and the last broadcast was refused for
        good by a quorum of endpoints while the others did not answer (R308-25). Such a settlement will not be
        taken; with an endpoint down the refusal is classed `retry`, so without this count the worker would
        rebroadcast for ever. Same limit and counter shape as `not_included` (`max_unincluded_windows`, 0 = alert
        only); a held broadcast or other bytes reset it."""
        if self.refused.get('tx') != tx_sha256:
            self.refused = {'tx': tx_sha256, 'windows': 0}
        self.refused['windows'] += 1
        windows, limit = self.refused['windows'], self.c.get('max_unincluded_windows', 4)
        log('settlement-refused-by-quorum', number=number, windows=windows, halt_after=limit)
        if limit and windows >= limit:
            raise Halt(f'a quorum of native endpoints refused the settlement of L2 block {number} for good (policy, '
                       f'source, successor or proof) in {windows} acceptance windows in a row while the other '
                       'endpoints did not answer, and its request is unchanged: operator review')

    def program_moved(self, current, view):
        """Whether L1 no longer holds the program this block was proved for. With `next_program` that is the
        program this cycle selected (it may be a scheduled one, proved ahead of its gate); without it, any change
        of the report since `view`."""
        if self.next_program is None:
            return current.get('program') != view.get('program')
        return self.program_of(current) is not self.program

    def program_pending(self, current):
        """Whether the program this cycle selected is still ahead in `current`'s schedule (proved before its gate)."""
        try:
            return any(self.program_named(e) is self.program for e in current.get('program_schedule') or [])
        except (KeyError, TypeError, ValueError, AttributeError):
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
        return True

    def cycle(self):
        self.finish_swap()
        if not self.check_identity():
            return False
        view = self.native_view(allow_behind=bool(self.c.get('reorg_recovery')))
        if view is None or view.get('source') is None:
            return False
        # Mandatory backlog can bypass spool_demand, and pacing or an existing
        # block can postpone selection. Publish before those branches so cold
        # startup and idle fee decay do not wait for the next proof or heartbeat.
        self.publish_admission_policy()
        try:
            if self.view_behind:
                return self.behind_floor_case(view)
            if self.c.get('skip_idle_blocks') and self.hold_block(view):
                return False
            number, directory = self.prepare_block(view)
            if self.reorg_seen is not None:
                # The reorg case being watched went away without a rebuild (L1 flipped back, the own settlement was
                # resubmitted and landed, or a new settlement): nothing was changed. A return alerts again.
                self.reorg_alert('resolved', accepted=self.reorg_seen[0], database_head=self.reorg_seen[2],
                                 next_block=number, resubmitted=bool(self.reorg_resubmit and self.reorg_resubmit['last']))
                self.reorg_seen = self.reorg_since = self.reorg_resubmit = None
                self.reorg_reported.clear()
            proof = self.prove(directory, view=view)
            # A proof takes many minutes: never pay DA for a block another settlement made stale meanwhile.
            if proof is None:
                return False
            if self.request_moved(view):
                log('request-moved-after-proof', number=number)
                return False
            if self.next_program is not None:
                # Proved ahead of a scheduled gate: no DA fee and no settlement until L1 holds this program.
                current = self.native_view()
                if current is None:
                    return False
                holds = self.program_of(current)
                if holds is not self.program:
                    if self.program_pending(current):
                        log('program-gate-pending', number=number, program=self.program['name'], holds=holds['name'])
                    else:
                        # The proof is of a program L1 no longer holds: the next cycle rebuilds this block.
                        log('program-moved-before-submit', number=number, program=current.get('program'))
                    return False
            tx = self.transaction(directory, proof, view.get('accepted'))
            values = tx[33:33 + VALUES_BYTES]
            if int.from_bytes(values[T + USER_TX_COUNT:T + USER_TX_COUNT + 8], 'big') and \
                    not self.publish_da(number, directory, values):
                return False
            return self.submit_and_wait(number, directory, tx, view)
        except WaitForProgram as wait:
            # L1 can temporarily return to the activated program across a
            # reorganization while our unaccepted local block uses next rules.
            # This is a wait, not a worker failure or permission to send it.
            log('waiting-for-program', reason=str(wait))
            return False
        except ForeignSettlement as foreign:
            return self.recover_foreign(str(foreign))
        except LocalAhead as ahead:
            return self.recover_reorg(ahead)

    # ---- reorgs of this worker's own settlements: rebuild from L1 and continue ----
    def reorg_alert(self, kind, case=None, **fields):
        """One operator alert: a `reorg-<kind>` log line, a line in the alert file, and the alert command. With
        `case`, an alert fires once per (kind, case). Alert delivery never stops the worker."""
        if case is not None:
            if (kind, case) in self.reorg_reported:
                return
            self.reorg_reported.add((kind, case))
        reorg = self.c['reorg_recovery']
        alert = {'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': f'reorg-{kind}', **fields}
        log(f'reorg-{kind}', **fields)
        path = Path(reorg.get('alert_file') or self.work.parent / 'l2-reorg-alerts.jsonl')
        try:
            with path.open('a') as f:
                f.write(json.dumps(alert, sort_keys=True) + '\n')
        except OSError as error:
            log('reorg-alert-failed', target=str(path), reason=str(error)[:200])
        if reorg.get('alert_command'):
            try:
                done = self.run(reorg['alert_command'], input=json.dumps(alert, sort_keys=True) + '\n',
                                capture_output=True, text=True, timeout=30)
                if done.returncode:
                    log('reorg-alert-failed', target='alert_command', code=done.returncode,
                        reason=(done.stderr or '').strip()[:200])
            except Exception as error:  # noqa: BLE001 - an alert hook must never stop settlement
                log('reorg-alert-failed', target='alert_command', reason=f'{type(error).__name__}: {error}'[:200])

    def reorg_history(self):
        return Path(self.c['l2_db']).with_name(Path(self.c['l2_db']).name + '.reorg-recoveries.json')

    def read_reorg_history(self):
        """The persisted recovery history (the loop guard). Unreadable or malformed: halt for the operator, never a
        retry (a retry would end in a restart loop that re-alerts on every start; 153 L4)."""
        path = self.reorg_history()
        if not path.exists():
            return []
        try:
            history = json.loads(path.read_text())
            if not isinstance(history, list) or not all(isinstance(h, dict) and isinstance(h.get('unix'), int)
                                                        for h in history):
                raise ValueError('not a list of records with an integer "unix"')
        except (OSError, ValueError) as error:
            raise Halt(f'reorg recovery history {path} is unreadable ({type(error).__name__}: {str(error)[:200]}): '
                       'operator review (l2_reorg_recover.py), then repair or remove the file') from None
        return history

    def recent_recoveries(self, reorg, case=None, brief=None, reason='', restores=False):
        """The history entries within the window; halts (alert `reorg-limit`) when the limit is reached. Rebuilds
        and restores are limited separately (`max_recoveries` each): a restore whose kept tail has a stale anchor
        is followed by one gated rebuild, and the pair is one reorg. Returns the entries of the window (both kinds)."""
        recent = [h for h in self.read_reorg_history() if h['unix'] > time.time() - reorg['window_seconds']]
        same = sum(('restored' in h) == restores for h in recent)
        if same >= reorg['max_recoveries']:
            self.reorg_alert('limit', case, recoveries=same, restores=restores, window_seconds=reorg['window_seconds'],
                             **(brief or {}))
            raise Halt(f'{reason}: {same} automatic reorg {"restores" if restores else "recoveries"} within '
                       f'{reorg["window_seconds"]} s, the limit: operator review (l2_reorg_recover.py)')
        return recent

    def first_sight_height(self):
        """The L1 height at which the current view was seen: the upper median of the heights reported by every
        answering endpoint, inside or outside the view (the larger of two). It gates the rebuild from below
        (`l1_final < reorg_l1_height` waits), so it must not be lowered by one endpoint (R308-23: with a
        two-endpoint view the old (faults + 1)-th largest was the smaller of the two); with three or more answers one
        endpoint cannot push it out of reach either (153 L2). With two answers one endpoint can raise it: that only
        delays the rebuild until L1 finality passes the height it named. None when no endpoint of the view
        answered."""
        answers = self.native.gather('getchaininfo')
        heights = {}
        for port, answer in answers.items():
            try:
                heights[port] = int(answer['height'])
            except (KeyError, TypeError, ValueError):
                continue
        if not any(port in self.view_support for port in heights):
            return None
        ordered = sorted(heights.values())
        return ordered[len(ordered) // 2]

    def behind_floor_case(self, view):
        """A partial quorum shows an accepted settlement below the highest one seen (`accepted_floor`): two stale
        endpoints, or a real reorg while one endpoint stays on the losing fork (153 M1). Nothing is built, proved or
        paid on such a view. When the database holds the view's accepted block and unsettled blocks above it, the
        case goes to `recover_reorg`, whose gates (stable time, follower finality, L1 finality past first sight,
        exact rebuild) tell a stale pair from a reorg. Anything else waits, as before, including the floor-stall
        restart (review r10 L1) when it lasts."""
        accepted = view.get('accepted')
        if not accepted:
            log('reorg-behind-floor-waiting', reason='the partial quorum shows no accepted settlement',
                floor=self.accepted_floor)
            self.floor_stall_check(0, self.view_support)
            return False
        fields = statement_fields(accepted['statement'])
        number, parent = fields['l2_number'], fields['l2_hash']
        head = self.produce('head', '--target', self.c['l2_db'])
        if head['number'] <= number or self.local_hash(number) != parent:
            log('reorg-behind-floor-waiting', accepted=number, floor=self.accepted_floor, database_head=head['number'])
            self.floor_stall_check(number, self.view_support)
            return False
        kind = 'ahead'
        if head['number'] == number + 1:
            probe = self.work / f'.probe-{number + 1}.artifact'
            probe.unlink(missing_ok=True)
            info = self.produce('export', '--target', self.c['l2_db'], '--number', str(number + 1), '--out', str(probe))
            probe.unlink(missing_ok=True)
            kind = 'anchor' if info['anchor'] != view['source']['block'] else 'reuse'
        raise LocalAhead(f'partial quorum {self.view_support} accepts L2 block {number}, below the accepted '
                         f'{self.accepted_floor} seen before; L2 head {head["number"]}', number, head, kind)

    def still_valid_settlement(self, view, number):
        """(directory, transaction bytes) of this worker's own proved settlement of block number + 1 when it is still
        valid against the current native request (153 M2): the request it was proved for equals the request now,
        and it settles the local block number + 1. A reorg that removed the acceptance of M+1 but kept the block
        that accepted M leaves that request byte-identical. Else None."""
        directory = self.work / f'{number + 1:08d}-{view["source"]["block"][:16]}'
        tx_path, request = directory / 'transaction.bin', directory / 'native-request.txt'
        if not tx_path.is_file() or not request.is_file() or request.read_text() != self.request_text(view):
            return None
        tx = tx_path.read_bytes()
        values = tx[33:33 + VALUES_BYTES]
        if len(values) != VALUES_BYTES:
            return None
        fields = statement_fields(values.hex())
        if fields['l2_number'] != number + 1 or fields['l2_hash'] != self.local_hash(number + 1):
            return None
        submitted = directory / 'submitted.json'
        try:
            recorded = json.loads(submitted.read_text()).get('tx_sha256') if submitted.exists() else None
        except (OSError, ValueError, AttributeError):
            return None  # an unreadable record: never resubmit on it; the rebuild gates decide
        if recorded not in (None, hashlib.sha256(tx).hexdigest()):
            return None
        return directory, tx

    def resubmit_own_settlement(self, view, case, number, brief):
        """Rebroadcast the still-valid settlement of number + 1 (no finality wait: it can only land the block the
        database already holds). True while that is under way, which holds back any rebuild; False when there is
        nothing to resubmit, the window has passed, or the nodes refuse the bytes for good."""
        reorg = self.c['reorg_recovery']
        window, now = reorg['resubmit_window_seconds'], self.clock()
        state = self.reorg_resubmit
        if state is None or state['case'] != case:
            found = self.still_valid_settlement(view, number) if window else None
            state = self.reorg_resubmit = {'case': case, 'found': found, 'since': now, 'last': None,
                                           'state': 'open' if found else 'none'}
            if found:
                self.reorg_alert('resubmitting', case, next_block=number + 1, directory=found[0].name,
                                 window_seconds=window, **brief)
        if state['state'] != 'open':
            return False
        if now - state['since'] >= window:
            state['state'] = 'expired'
            self.reorg_alert('resubmit-expired', case, next_block=number + 1, window_seconds=window, **brief)
            return False
        if state['last'] is not None and now - state['last'] < self.c['resubmit_seconds']:
            return True
        directory, tx = state['found']
        values = tx[33:33 + VALUES_BYTES]
        if int.from_bytes(values[T + USER_TX_COUNT:T + USER_TX_COUNT + 8], 'big'):
            commitment = values[T + DA_COMMITMENT:T + DA_COMMITMENT + 32].hex()
            if not any(r.get('l2_number') == number + 1 and r.get('commitment') == commitment
                       for r in view.get('data_availability', [])):
                if self.view_behind:
                    # publish_da reads the full-quorum view; on a partial view below the floor it could pay again.
                    state['state'] = 'da-missing'
                    self.reorg_alert('resubmit-expired', case, next_block=number + 1, reason='DA record missing on '
                                     'a partial view', **brief)
                    return False
                self.da_payload(number + 1, directory)
                if not self.publish_da(number + 1, directory, values):
                    state['last'] = self.clock()
                    return True
        record = self.submitted_record(directory)  # read and checked in still_valid_settlement
        record['tx_sha256'] = hashlib.sha256(tx).hexdigest()
        sent = self.broadcast(number + 1, directory, tx, record)
        state['last'] = self.clock()
        if sent == 'terminal':
            state['state'] = 'refused'
            self.reorg_alert('resubmit-refused', case, next_block=number + 1, **brief)
            return False
        return True

    def same_case(self, case):
        """Re-read the view (153 L1): the case still holds, else forget it (alert `reorg-resolved`)."""
        view = self.native_view(allow_behind=True)
        accepted = view and view.get('accepted')
        if accepted:
            fields = statement_fields(accepted['statement'])
            if (fields['l2_number'], fields['l2_hash']) == case[:2]:
                return True
        if self.reorg_seen is not None:
            self.reorg_alert('resolved', accepted=self.reorg_seen[0], database_head=self.reorg_seen[2])
        self.reorg_seen = self.reorg_since = self.reorg_resubmit = None
        self.reorg_reported.clear()
        return False

    def recover_reorg(self, ahead):
        """The database holds the accepted settlement M and unusable unsettled blocks above it. False while waiting
        (own settlement of M+1 being resubmitted, view not stable yet, M not finalized yet, follower behind); True
        once the rebuilt database is swapped in. Halts when disabled (the reason of old), when the recovery limit is
        reached, or when L1 data cannot rebuild M."""
        reorg = self.c.get('reorg_recovery')
        if not reorg or self.dry_run:
            raise Halt(str(ahead))
        if ahead.accepted == 0:
            raise Halt(f'{ahead}: L1 holds no accepted settlement any more; rebuild the initial database by hand')
        view = self.native_view(allow_behind=True)
        accepted = view and view.get('accepted')
        if not accepted or statement_fields(accepted['statement'])['l2_number'] != ahead.accepted:
            # The view moved since the cycle read it: forget the case (a return alerts and waits again).
            if self.reorg_seen is not None:
                self.reorg_alert('resolved', accepted=self.reorg_seen[0], database_head=self.reorg_seen[2])
            self.reorg_seen = self.reorg_since = self.reorg_resubmit = None
            self.reorg_reported.clear()
            return False
        fields = statement_fields(accepted['statement'])
        number, l2_hash = fields['l2_number'], fields['l2_hash']
        case = (number, l2_hash, ahead.head['number'], ahead.head['hash'])
        brief = {'accepted': number, 'accepted_hash': l2_hash, 'database_head': ahead.head['number'],
                 'database_head_hash': ahead.head['hash'], 'shape': ahead.kind}
        if self.view_behind:
            brief.update(behind_floor=self.accepted_floor, view_ports=self.view_support)
        now = self.clock()
        if self.reorg_seen != case:
            # The L1 height at first sight: the reorg that removed M+1 is final once L1 finality passes it.
            try:
                height = self.first_sight_height()
            except Exception:  # noqa: BLE001 - no quorum: look again next cycle
                return False
            if height is None:
                return False
            self.reorg_l1_height = height
            self.reorg_seen, self.reorg_since, self.reorg_resubmit = case, now, None
            self.reorg_alert('detected', case, reason=str(ahead)[:300], stable_seconds=reorg['stable_seconds'],
                             l1_height=self.reorg_l1_height, **brief)
        if ahead.kind in ('ahead', 'reuse') and self.resubmit_own_settlement(view, case, number, brief):
            return False
        if now - self.reorg_since < reorg['stable_seconds']:
            return False
        finals = follower_finals(reorg['follower_status'])
        if number in finals and finals[number] != l2_hash:
            raise Halt(f'reorg recovery: the follower finalized L2 block {number} as {finals[number]}, the native '
                       f'quorum accepts {l2_hash}: operator review')
        if max(finals, default=0) > number:
            # The follower finalized more than the quorum view shows: a stale view. Wait, never rebuild on it.
            self.reorg_alert('waiting-follower', case, follower_finalized=max(finals), **brief)
            return False
        try:
            l1_final = self.native.bounded_value('getchaininfo', 'finalized_height')
            l1_head = None if reorg['wait_for_finality'] else self.native.bounded_value('getchaininfo', 'height')
        except Exception:  # noqa: BLE001 - no quorum: wait
            return False
        if reorg['wait_for_finality']:
            # Finality of M alone is not enough: the reorg that removed M+1 can itself be undone until L1 finality
            # passes the height at which it was seen. Then the rebuild can never be reversed by L1.
            if finals.get(number) != l2_hash or l1_final < self.reorg_l1_height:
                self.reorg_alert('waiting-finality', case, finalized_prefix=max(finals, default=0),
                                 l1_finalized_height=l1_final, l1_height_seen=self.reorg_l1_height, **brief)
                return False
        elif l1_head - l1_final > reorg['max_finality_lag']:
            # Off the mainnet path only: still never rebuild onto a fork whose finality has stopped (153 L3).
            self.reorg_alert('waiting-finality', case, reason='L1 finality stalled', l1_height=l1_head,
                             l1_finalized_height=l1_final, max_finality_lag=reorg['max_finality_lag'], **brief)
            return False
        recent = self.recent_recoveries(reorg, case, brief, str(ahead))
        if not self.same_case(case):
            return False
        entry = {'unix': int(time.time()), 'accepted': number, 'accepted_hash': l2_hash,
                 'database_head': ahead.head['number']}

        def count(outcome):
            # Written before the swap (153 L5): a crash between the two can only over-count.
            atomic_write(self.reorg_history(), json.dumps([*recent, {**entry, 'rebuilt_head': outcome['number']}],
                                                          indent=1) + '\n')
        outcome = self.rebuild_from_l1(number, l2_hash, fields['l2_state_root'], reorg, 'reorg', exact=True,
                                       finals=finals, before_swap=count)
        if outcome is None:
            self.reorg_alert('waiting-follower', case, **brief)
            return False
        self.reorg_seen = self.reorg_since = self.reorg_resubmit = None
        self.accepted_floor = number  # acted on: the view at M is the chain now
        self.reorg_alert('recovered', recoveries_in_window=len(recent) + 1, max_recoveries=reorg['max_recoveries'],
                         finalized=finals.get(number) == l2_hash, **brief, **outcome)
        return True

    def restore_own_settlement(self):
        """After a rebuild, this worker's old settlement of M+1 can still land (its bytes are public and the request
        was unchanged; 153 M2). Then a database kept aside by an earlier swap holds the accepted block: swap it back
        (journalled, with its work directories) instead of a second reconstruct. None when no kept database holds the
        accepted block; True once swapped. Counts against the recovery limit.

        False (wait, scan again next cycle) when the producer timed out on a kept database (R308-22): a loaded host
        is not "no kept database holds the block", and reading it so starts a second reconstruct that discards the
        kept work and proofs. After `KEPT_SCAN_TIMEOUTS` cycles in a row the database is read as unusable."""
        reorg = self.c['reorg_recovery']
        view = self.native_view()
        accepted = view and view.get('accepted')
        if not accepted:
            return None
        fields = statement_fields(accepted['statement'])
        number, l2_hash = fields['l2_number'], fields['l2_hash']
        db = Path(self.c['l2_db'])
        prefix = f'{db.name}.orphaned-'
        kept = sorted((p for p in db.parent.iterdir() if p.name.startswith(prefix) and p.name[len(prefix):].isdigit()),
                      key=lambda p: int(p.name[len(prefix):]), reverse=True)
        slow = []
        for candidate in kept:
            try:
                head = self.produce('head', '--target', str(candidate))
                if head['number'] < number or self.produce('hash', '--target', str(candidate), '--number',
                                                           str(number))['hash'] != l2_hash:
                    continue
            except subprocess.TimeoutExpired:
                slow.append(candidate.name)
                continue
            except (ProducerError, KeyError, ValueError):
                continue
            break
        else:
            if slow and self.kept_scan_timeouts < KEPT_SCAN_TIMEOUTS:
                self.kept_scan_timeouts += 1
                log('kept-database-scan-timeout', accepted=number, databases=slow, cycles=self.kept_scan_timeouts,
                    give_up_after=KEPT_SCAN_TIMEOUTS)
                return False
            if slow:
                log('kept-database-unreadable', accepted=number, databases=slow, cycles=self.kept_scan_timeouts)
            self.kept_scan_timeouts = 0
            return None
        self.kept_scan_timeouts = 0
        brief = {'accepted': number, 'accepted_hash': l2_hash, 'restored': candidate.name,
                 'restored_head': head['number']}
        recent = self.recent_recoveries(reorg, None, brief, f'own settlement {number} landed after a rebuild',
                                        restores=True)
        current = self.produce('head', '--target', str(db))['number'] if db.exists() else 0
        common = 0
        for n in range(min(current, head['number']), 0, -1):
            if self.local_hash(n) == self.produce('hash', '--target', str(candidate), '--number', str(n))['hash']:
                common = n
                break
        orphans = list(range(common + 1, current + 1))
        respooled = self.respool_orphans(orphans)
        source = self.work.parent / f'{self.work.name}-orphaned-{candidate.name[len(prefix):]}'
        names = sorted(p.name for p in source.iterdir() if p.is_dir() and p.name[:8].isdigit()
                       and common < int(p.name[:8]) <= head['number']) if source.is_dir() else []
        stale = {d.name for d in self.stale_directories(common, current, number)}
        stale |= {n for n in names if (self.work / n).exists()}
        stamp = self.swap_stamp()
        atomic_write(self.reorg_history(), json.dumps([*recent, {'unix': int(time.time()), 'accepted': number,
                                                                 'accepted_hash': l2_hash, 'restored': candidate.name,
                                                                 'rebuilt_head': head['number']}], indent=1) + '\n')
        journal = {'rebuilt': str(candidate), 'kept': str(db.with_name(f'{db.name}.orphaned-{stamp}')),
                   'work_aside': str(self.work.parent / f'{self.work.name}-orphaned-{stamp}'),
                   'stale': sorted(stale), 'number': head['number'], 'l2_hash': head['hash'],
                   'restore_work': {'from': str(source), 'names': names}}
        atomic_write(self.recovery_journal(), json.dumps(journal, indent=2) + '\n')
        self.finish_swap()
        self.reorg_seen = self.reorg_since = self.reorg_resubmit = None
        self.reorg_reported.clear()
        self.reorg_alert('restored', recoveries_in_window=len(recent) + 1, max_recoveries=reorg['max_recoveries'],
                         common_ancestor=common, orphaned_blocks=orphans, respooled=respooled,
                         restored_work=names, **brief)
        return True

    # ---- foreign settlements: rebuild from L1 and continue ----
    def recover_foreign(self, reason):
        """Replace a database that does not hold the accepted settlement with one rebuilt from finalized L1
        blocks. False while waiting; True once swapped. Halts when L1 data cannot reproduce the block."""
        if self.c.get('reorg_recovery') and not self.dry_run:
            restored = self.restore_own_settlement()
            if restored is not None:
                return restored
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
        outcome = self.rebuild_from_l1(number, l2_hash, expected_root, recovery, 'foreign', finals=finals)
        if outcome is None:
            return False
        self.waiting_for = None
        log('foreign-settlement-recovered', **outcome)
        return True

    def rebuild_from_l1(self, number, l2_hash, expected_root, recovery, label, exact=False, finals=None,
                        before_swap=None):
        """Rebuild a NEW database from the follower's verified L1 blocks, require block `number` to be `l2_hash`
        (and `expected_root` unless None), return orphaned user transactions to the spool, move stale work aside and
        swap the databases through the journal. None when the rebuild does not reach the target yet (the follower is
        behind the view); then a dict describing the swap. Halts when L1 data cannot be rebuilt or contradicts the
        follower's finalized settlements. Shared by `foreign_recovery` and `reorg_recovery`. With `exact`, the
        rebuild must also end at `number`: a follower still on the losing fork holds settlements above it that L1
        no longer has, and a database rebuilt from them would only be reorged again."""
        finals = follower_finals(recovery['follower_status']) if finals is None else finals
        # One rebuild per input: a rebuild that did not hold the target is not repeated until the follower has more.
        tip = follower_verified_tip(recovery['follower_status'])
        if self.rebuild_discarded_at is not None and self.rebuild_discarded_at == tip:
            return None
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
            what = 'a foreign settlement' if label == 'foreign' else 'a reorg of the accepted settlement'
            raise Halt(f'rebuild from L1 refused while recovering from {what} of L2 block {number}: the '
                       f'block is off-rule, or the follower store is damaged: {result.stderr.strip()[:400]}')
        document = json.loads(result.stdout)
        blocks = {b['number']: b for b in document.get('blocks', [])}
        rebuilt = blocks.get(number)
        # `reconstruct` replays everything the follower verified, so the head can lie above the target. The target
        # must be there; the worker then holds the newest settled block and competes from it. A later reorg of that
        # unfinalized tail on L1 is one more divergence, recovered the same way.
        if rebuilt is None or rebuilt['hash'] != l2_hash or expected_root not in (None, rebuilt['state_root']) \
                or (exact and max(blocks) != number):
            shutil.rmtree(rebuilding, ignore_errors=True)
            self.rebuild_discarded_at = tip
            log(f'{label}-rebuild-behind-view', number=number, rebuilt_head=document.get('head'))
            return None
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
        if before_swap is not None:
            before_swap({'number': number, 'l2_hash': l2_hash})
        stamp = self.swap_stamp()
        ready = db.with_name(f'{db.name}.rebuilt-{stamp}')
        rebuilding.rename(ready)
        journal = {'rebuilt': str(ready), 'kept': str(db.with_name(f'{db.name}.orphaned-{stamp}')),
                   'work_aside': str(self.work.parent / f'{self.work.name}-orphaned-{stamp}'),
                   'stale': [d.name for d in stale], 'number': number, 'l2_hash': l2_hash}
        atomic_write(self.recovery_journal(), json.dumps(journal, indent=2) + '\n')
        self.finish_swap()
        return {'number': number, 'l2_hash': l2_hash, 'common_ancestor': common, 'orphaned_blocks': orphans,
                'respooled': respooled, 'wasted_proofs': proofs, 'wasted_da_signed': da_paid,
                'rebuild_seconds': round(self.clock() - start, 1), 'native_blocks': document.get('native_blocks')}

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

    def swap_stamp(self):
        """The number that names what a swap keeps aside: the wall clock in nanoseconds, but always above every
        number already used by a kept database or work directory, so that the names stay in swap order when the
        clock steps back (R308-26)."""
        db = Path(self.c['l2_db'])
        used = [0]
        for prefix, parent in ((f'{db.name}.orphaned-', db.parent), (f'{self.work.name}-orphaned-', self.work.parent)):
            if parent.is_dir():
                used += [int(p.name[len(prefix):]) for p in parent.iterdir()
                         if p.name.startswith(prefix) and p.name[len(prefix):].isdigit()]
        return max(time.time_ns(), max(used) + 1)

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
        restore = state.get('restore_work')  # a kept database swapped back: its work directories come back too
        if restore:
            source = Path(restore['from'])
            for name in restore['names']:
                if (source / name).exists() and not (self.work / name).exists():
                    (source / name).rename(self.work / name)
        keeps = [self.c[k].get('keep', 2) for k in ('foreign_recovery', 'reorg_recovery') if self.c.get(k)]
        keep = max(keeps) if keeps else 2
        # What this swap has just kept is never pruned, whatever its number says (R308-26: a journal written before
        # a backward clock step, or by an older worker); it takes one of the `keep` places. Names whose suffix is
        # not a number (an operator's copy, `*.orphaned-N.bak`) are not this worker's and are left alone (R308-24).
        for prefix, parent, mine in ((f'{db.name}.orphaned-', db.parent, kept),
                                     (f'{self.work.name}-orphaned-', self.work.parent, aside)):
            old = sorted((p for p in parent.iterdir() if p.name.startswith(prefix) and p.name[len(prefix):].isdigit()
                          and p != mine), key=lambda p: int(p.name[len(prefix):]))
            room = keep - 1 if mine.parent == parent and mine.exists() else keep
            for path in old[:len(old) - room]:
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
        report['program'] = settler.program['name']  # the scheduled one near a gate (program_schedule)
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
    except (Halt, ProducerError, ForeignSettlement, LocalAhead) as error:
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
