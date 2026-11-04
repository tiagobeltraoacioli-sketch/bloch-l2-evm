# Bloch L2 mainnet: execution and RPC readiness

Status on 2026-10-14, branch `feat/l2-mainnet-rpc-20261014` (from `bacd9d2`,
which already contains the devnet4 settled RPC `888b62a` and the
Ethereum-client header fields `a86708f`).

The requirements come from the DEX and bridge mainnet work
(`postern-dex` `docs/MAINNET-READINESS.md`, items D4, D5, D13, D15 and F3)
and from the devnet4 workaround `scripts/devnet4/rpc_compat_proxy.py`.
Nothing here deploys, restarts a service or regenerates a proof.

Legend: **Done** = implemented and tested in this branch; **Doc** = needs a
running service, the prover or a ceremony decision, documented below.

Line numbers in "Before" refer to `bacd9d2`.

## Summary

| # | Requirement | Status |
|---|---|---|
| R1 | Ethereum-shaped blocks and receipts without the compat proxy | Done (headers since `a86708f`; Cancun fields added here; receipts verified) |
| R2 | `latest` / `safe` / `finalized` / `pending` tags | Done (`pending` implemented here; `safe`/`finalized` unchanged, from native FFG replay) |
| R3 | `BLOCKHASH` over the last 256 L2 blocks | Done (already implemented; mainnet regression test added) |
| R4 | Block gas limit fits the ~3.9M-gas router creation | Done (30M; test executes a 4M-gas creation) |
| R5 | Wall-clock timestamps from genesis on mainnet | Done (mainnet profile requires a wall-clock genesis and the slot-time rule from block 1) |
| R6 | Mainnet chain id 700770 next to devnet 700771 | Done in the execution/RPC/producer code; Doc for the SP1 guest/vkey and the ceremony |

## R1. Ethereum-shaped JSON-RPC

**Before.** `integrations/reth-execution/src/rpc_types.rs` serialized the V2
header with `sha3Uncles` and `nonce` since `a86708f` (lines 72, 110, 139), so
forge/cast decode blocks without the proxy. Receipts use reth's standard
`EthReceiptConverter` with `alloy_rpc_types_eth::TransactionReceipt`
(`rpc_types.rs:20`, `rpc.rs`). Checked read-only against devnet4
(`127.0.0.1:18945`, block `0xe7`, receipts of blocks 216 and 227): blocks carry
`sha3Uncles`, `nonce`, `uncles: []`, `difficulty`, `mixHash`, `miner`;
receipts carry `from`, `to`, `contractAddress`, `effectiveGasPrice`, `type`,
and logs carry `blockHash`, `blockNumber`, `transactionIndex`, `logIndex`,
`removed`. The proxy (`rpc_compat_proxy.py`) is therefore not needed by any
node built from `a86708f` or later.

Remaining gap: block headers had no Cancun fields (`blobGasUsed`,
`excessBlobGas`, `parentBeaconBlockRoot`), which Cancun-aware clients read
(e.g. blob base fee from `excessBlobGas`).

**Fix (this branch).** `rpc_types.rs` emits `blobGasUsed = 0x0`,
`excessBlobGas = 0x0` (no blobs are ever carried) and
`parentBeaconBlockRoot = anchorRoot` (the value the EIP-4788 system call
writes). They are RPC projections only: the V2 consensus encoding and the
header hash are unchanged. Decoding refuses non-zero blob values or a
`parentBeaconBlockRoot` different from `anchorRoot`, and still accepts older
responses without them. Test:
`rpc_types::tests::rpc_json_preserves_every_v2_field_and_canonical_hash`
(decodes as a standard alloy Cancun header).

Note: the Ethereum header hash computed by a client from these fields is not
the block hash; `hash` is the V2 header hash (`NodeHeaderV2::hash`). No
mainstream client recomputes it.

## R2. Block tags

**`latest` / `safe` / `finalized`** (unchanged, verified on devnet4).
`bloch-l2-settled-rpc` publishes them in memory from the native follower's
status (`bin/bloch-l2-settled-rpc.rs:325`/`341`): `finalized` = highest L2
block whose settlement lies in the native FFG-finalized prefix the follower
verified by replay from the pinned genesis (no checkpoint signatures);
`safe` = the settlement the operator's own native node holds at its head;
neither regresses; `bloch_finality` reports both with their L1 anchors.

**`pending` before.** `rpc.rs:29-38` (`NoDerivedPending`) refused every
pending environment, so `eth_getBlockByNumber("pending")`,
`eth_estimateGas(…, "pending")`, `eth_call(…, "pending")` and
`eth_getBalance(…, "pending")` failed on devnet4 with
`pending Bloch derivation is unavailable: authenticated anchor and deposits are required`
(observed read-only). forge/cast/ethers/wallets ask for `pending`.

**Fix (this branch)**, `integrations/reth-execution/src/rpc.rs`:

- `LatestDerivedPending`: an RPC-only pending environment = the next block on
  the latest canonical header (`number + 1`), no deposits, the parent's
  anchor root and prevrandao, timestamp `max(parent + 1, now)` once the chain
  is on wall-clock time (`parent + 1` below 2020-01-01, i.e. devnet history).
  Explicit `time`/`random`/`beaconRoot` block overrides are honoured. It never
  builds, stores or announces a block; settlement, attestors and canonical
  execution never see it.
- `PendingPolicy::LatestDerived` (`build_eth_api_with`) installs it with
  `PendingBlockKind::None`: state at `pending` = latest state; calls and
  estimates at `pending` run on the latest state in the derived next-block
  environment, so `BLOCKHASH(latest)` is the real hash, as it will be at
  inclusion (anchored swaps that commit to the latest block estimate
  correctly).
- `serve_pending_blocks_as_latest`: block-shaped methods
  (`eth_getBlockByNumber`, `eth_getHeaderByNumber`, `eth_getBlockReceipts`,
  `eth_getBlockTransactionCountByNumber`,
  `eth_get(Raw)TransactionByBlockNumberAndIndex`) answer `pending` with the
  latest block (the rollup convention when no pending block is published)
  instead of `null`.
- `bloch-l2-settled-rpc` with `--txpool`: `eth_getTransactionCount(addr,
  "pending")` returns the latest nonce plus the sender's consecutive nonces
  already waiting in the spool (the sequencer's view), so wallets sending
  several transactions in a row get increasing nonces. Entries are decoded
  under the served chain id; other chain ids, malformed files and partial
  files never count.
- `build_eth_api` (development node and its tests) keeps
  `PendingPolicy::Unavailable`, unchanged.

Tests: `rpc::tests::pending_env_is_the_next_block_on_latest_without_deposits`,
`rpc::tests::only_a_pending_first_parameter_is_rewritten`,
`rpc::tests::block_methods_answer_pending_with_the_latest_handler`,
`bloch-l2-settled-rpc` `tests::pending_nonce_counts_only_the_senders_consecutive_spool_entries`.

**Needs the running service (Doc).** A live check of forge
`create`/`script --slow` against the settled RPC without the proxy needs the
new binary on a host (devnet4 or the mainnet rehearsal). Until then keep the
proxy on devnet4 if the deployed binary predates `a86708f`.

## R3. BLOCKHASH over the last 256 L2 blocks

**Already implemented.** Canonical execution serves `BLOCKHASH(n)` for
`n ∈ [N-256, N-1]` from a committed 256-entry ring of real L2 header hashes
in the `BLOCK_INFO` system account (`src/state.rs:213-220`,
`src/node_execution/mod.rs:121-127`, `src/executor.rs:783-800`), part of the
state root and re-checked by the stateless guest. RPC calls use provider
ancestry with the same window (`integrations/reth-execution/src/factory.rs:26`,
test `tests/rpc_blockhash.rs`).

**Added.** `tests/mainnet_profile.rs`
`blockhash_serves_exactly_the_last_256_blocks_and_a_router_sized_create_fits`:
300 V2 blocks under `ChainSpec::mainnet`; at block 300 `BLOCKHASH` returns the
committed header hash for 299, 200 and 44 and zero for 43, 300 and 0.

## R4. Block gas limit

`ChainSpec::testnet` and `ChainSpec::mainnet` use `gas_limit = 30_000_000`
(`src/chainspec.rs:190`); per-block selection defaults to the spec limit
(`SelectionLimits::protocol`) and the devnet settler's default
`max_block_gas` is 15M (`deployment/devnet/settler_v3.py:87`). One raw
transaction may be 128 KiB and a DA payload 114,688 bytes, far above the
router's init code. The mainnet test above executes a 4,000,000-gas creation
with 3.6M gas of code deposit in one block. Operators must keep any
`--max-gas`/`max_block_gas` override ≥ 4M.

## R5. Wall-clock timestamps

**Before.** Blocks are stamped `parent + 1` unless the producer gets
`--timestamp-rule FROM:L1_GENESIS_SECS:SLOT_MS`
(`integrations/settlement-recovery/src/timestamp.rs:49`); devnet4 switched at
block 228. The genesis timestamp is 0 (`bloch-l2-produce-dev.rs:182`).

**Fix (this branch).**

- `L2Network` (`integrations/reth-execution/src/network.rs`): the mainnet
  profile refuses a genesis timestamp below 2020-01-01, so block 0 is
  wall-clock seconds.
- `TimestampRule::from_genesis` / `require_from_genesis`: the mainnet rule
  must apply from L2 block 1.
- `bloch-l2-produce-dev --rules mainnet` refuses `extend` and `reconstruct`
  without `--timestamp-rule 1:L1_GENESIS_UNIX_SECS:L1_SLOT_MILLIS`, so every
  mainnet block takes the start time of its anchored native slot (never less
  than parent + 1) and every rebuilder (reconstruct, attestors) derives the
  same timestamp. Devnet behaviour (no rule, or devnet4's rule from 228) is
  unchanged.

Tests: `timestamp::tests::mainnet_rule_starts_at_block_one`,
`tests/produce_mainnet.rs`.

**Ceremony input (Doc).** `L1_GENESIS_UNIX_SECS` and `L1_SLOT_MILLIS` are the
pinned Bloch L1 mainnet genesis values (`genesis_time_ms / 1000` and
`slot_ms` in the native genesis file, `bloch-sis-pow`
`crates/bloch-pos-node/src/genesis.rs`). The settler/attestor configs must
pass the same rule (`timestamp_rule: "1:<secs>:<slot_ms>"`).

The settlement guest already accepts any non-decreasing timestamp, so no
guest change is needed for the rule itself.

## R6. Chain id 700770

**Before.** One chain id, 700771, in `ChainSpec::testnet` (`src/chainspec.rs:188`);
every binary hard-codes `testnet_v3()` with domain `0xd3…d3` and genesis
timestamp 0 (`bloch-l2-settled-rpc.rs:261-262`, `bloch-l2-produce-dev.rs:173-182`).

**Fix (this branch).**

- `ChainSpec::mainnet()` = the settlement V3 rules with
  `MAINNET_CHAIN_ID = 700_770`; `TESTNET_CHAIN_ID = 700_771` names the devnet
  id. `testnet()`/`testnet_v3()` are unchanged (tests
  `chainspec::tests::mainnet_is_the_v3_rules_under_its_own_chain_id`,
  `mainnet_profile::chain_ids_do_not_cross_between_mainnet_and_devnets`).
- `L2Network::parse("v3"|"v2"|"mainnet", --domain, --genesis-time)`:
  development rules keep their identity and refuse the mainnet knobs (test:
  the v3 genesis hash equals the one devnet4 was initialized with); mainnet
  requires the ceremony's domain (not zero, not `0xd3…d3`) and a wall-clock
  genesis.
- `bloch-l2-settled-rpc --rules mainnet --domain HEX --genesis-time SECS` and
  `bloch-l2-produce-dev … --rules mainnet --domain HEX --genesis-time SECS`
  (every command; `sign-tx` then signs for 700770). A database opens only
  under the network it was created for.

**Program identity (Doc, needs the SP1 prover).** The chain id is part of the
execution configuration, so mainnet needs its own settlement guest:
`integrations/sp1-execution/guest/src/bin/settlement_v3.rs:24` builds
`ChainSpec::testnet_v3()`. A `settlement_v3_mainnet` guest (same source with
`ChainSpec::mainnet()`) must be built with the pinned SP1 toolchain
(`docs/SP1-TOOLCHAIN.md`); its vkey becomes the mainnet program identity
registered in the native activation policy (other agent: `bloch-sis-pow`
activation gate). No proof or vkey was regenerated here. The devnet guests
call only `testnet`/`testnet_v3`, which are unchanged; the new constructor is
dead code for them. To confirm the devnet vkeys are bit-identical, rebuild
the devnet guest ELFs from this branch and compare their vkeys with the
pinned ones (needs the SP1 toolchain).

**Update (same day):** the program and genesis are now derived and pinned,
see [MAINNET-PROGRAM.md](MAINNET-PROGRAM.md): guest `settlement_v3_mainnet`
(ELF `203114bf…`, BN254 vkey `007139f7…`), domain `MAINNET_DOMAIN`
(`1c3f8772…`, derived from the chain id and the Genesis-4 network), genesis
timestamp 1786656679 (Genesis-4 slot 0), L2 genesis `632e45ae…` / state
`2ad7e807…`, no premine; the devnet ELFs and vkeys were rebuilt from this
branch and are bit-identical to the pinned ones.

Other mainnet inputs still undecided (ceremony / M9): the native activation epoch and attestor set, a
`network/eip155-700770.json` registration entry, and the prevrandao source
(the development producer uses the constant `0x07…07`,
`bloch-l2-produce-dev.rs:267`; contracts must not use `prevrandao` as
randomness on this L2 either way).

## R7. Spool and RPC resource limits (2026-10-30 rehearsal)

`eth_sendRawTransaction` admits a transaction into the settlement worker's
spool only if the worker could include it and the sender could pay for it:

- the sender holds `value + gas_limit * max_fee` summed over this transaction
  and its other live spool entries (a same-nonce replacement counts once);
- the encoded transaction plus its DA framing fits one native DA batch
  (114,688 bytes); larger ones are dropped by the producer without a fee;
- the declared gas is at most 15,000,000 (the worker's `max_block_gas`) and at
  least the intrinsic gas; the priority fee is not above the fee cap; CREATE
  initcode is at most 49,152 bytes (EIP-3860);
- unchanged: nonce window 16, 16 entries per sender, 10% replacement bump,
  4,096 entries, stale sweep every 60 s.

Expiry follows settlement progress, not the clock alone (agents/55 finding 3,
agents/133, review agents/146): an entry expires when it is older than 3 h
**and** the canonical database gained 4 blocks since its first sighting (the
settler passed it over 4 times: fee or block budget), or when it is 24 h old and
no block came for 24 h. An entry behind a nonce gap of its sender expires at
3 h, blocks or not: no block can include it, and it is no demand for one, so an
idle settler (`skip_idle_blocks`) would otherwise build only its 24 h heartbeat
and keep it for days. A block that takes hours to prove no longer evicts the
acknowledged transactions waiting for the next one.

Restarts never extend a lifetime. The RPC keeps each entry's first-seen head in
a sidecar `.<hash>.head` beside it, and the head with the wall time it was first
seen in `.spool-progress`. Both live in the spool directory, which the producer
reads only as `*.tx`. An entry's age after a restart comes from its file time.
While the process runs, ages and the stall use the monotonic clock. The caps
above do not rest on expiry: a full spool still displaces the cheapest entry, or
one behind a nonce gap, only for a better-paying newcomer.

Before this, a funded sender could fill the whole spool with entries whose
gas was above the worker's 15M block budget. Every block deferred them, so
they held the spool for 3 h without paying, and newcomers paying no more than
the attacker's fee were refused with `txpool full`. In the rehearsal every block
after the flood was empty.

RPC-wide limits: a JSON-RPC batch holds at most 100 calls
(`RPC_MAX_BATCH_CALLS`), and `eth_call`, `eth_estimateGas`,
`eth_createAccessList`, `eth_callMany` and `eth_simulateV1` share 4 permits.
A caller that waits 10 s for a permit gets error -32005. Since the rpc-limits
build (agent 195, owner decision on review 154), the settled RPC's simulation
gas cap is 15,000,000 (the spool's `max_tx_gas`; it was the 30,000,000 block
gas limit, reth's default is 50,000,000) on every gas path of `eth_call`,
`eth_estimateGas` and `eth_createAccessList`, including the caller-allowance
fallback and a block override of the gas limit (reth snapshot patch,
`integrations/reth-execution/RETH-SNAPSHOT.md`). A caller is answered
`execution aborted (timeout = 5s)` after 5 s with its permit; estimates and
access lists stop their next EVM run then, and the permit stays taken until
the running EVM ends. A spool scan stats
only new files, so `eth_getTransactionCount(…, "pending")` and admissions stay
cheap with a full spool.

The settled RPC still accepts at most 100 concurrent connections (the jsonrpsee
default) and has no timeout for request bodies. The public gateway must buffer
request bodies (nginx does by default, with `client_body_timeout 10s`) so that
slow or idle clients cannot hold the origin's connections.

## What needs the user or other terminals

1. Build and deploy the new `bloch-l2-settled-rpc` where a live check is
   wanted; then forge/cast against it without the proxy (R1, R2).
2. Ceremony values: mainnet domain, L2 genesis timestamp, L1 genesis seconds
   and slot milliseconds for the timestamp rule (R5, R6).
3. SP1: build the mainnet settlement guest and register its vkey; confirm the
   devnet vkeys are unchanged (R6).
4. Native activation gate and attestor set: `bloch-sis-pow` workstream.

## Tests run on this branch (2026-10-14, macOS)

Build environment: `../reth-bloch-rpc-snapshot` = the prepared snapshot
(`8eb21017` + `reth-snapshot.patch`, verified byte-identical), with
`VERGEN_GIT_SHA/DESCRIBE/DIRTY` set as `prepare-reth.py` does;
`../bloch-validator-payout` = the native checkout with the `devnet-kes`
feature (`native-kes-20261014`, `a3003098`); settlement-recovery built with
`cargo +1.98.1`.

- core (`cargo test --features serde`): 286 passed, 0 failed (includes
  `tests/mainnet_profile.rs`, `chainspec::tests::mainnet_*`).
- `integrations/reth-execution` (`cargo test`): 134 passed, 0 failed
  (includes `rpc::tests::*`, `network::tests::*`, `rpc_types::tests::*`,
  the settled RPC's spool test, and the existing `rpc_developer_flow` /
  `node_rpc` checks that the development node still refuses `pending`).
- `integrations/settlement-recovery` (`cargo +1.98.1 test`): 46 passed,
  8 failed, all in `tests/ffg_recovery.rs` (e.g. line 86:
  ``called `Result::unwrap()` on an `Err` value: Encoding``; line 104:
  `insufficient`). The same 8 fail identically on the base commit `bacd9d2`
  against the same native checkout: the committed native FFG fixtures do not
  match that native revision. Not caused by this branch; regenerate the
  fixtures or pin the native revision they were made with.

## Mainnet release candidate build (2026-10-18)

`deployment/mainnet/build-release.sh WORK [OUT]` is the single pinned build of
`bloch-l2-native-follower`, `bloch-l2-produce-dev` and `bloch-l2-settled-rpc`
against native `78b7343a` (inert devnet feature shim and the mainnet
`settlement-recovery` lock applied once, restored afterwards); it checks the
built producer reproduces the pinned L2 genesis and writes `SHA256SUMS` and
`build.json`. `follower-rpc/build.sh` and `build-sequencer.sh` are wrappers.

Source verification added on 2026-11-04 requires a committed, clean L2
worktree, including untracked files, before the release recipe starts. The
native checkout may differ from its selected commit only by the exact inert
feature shim; unrelated edits in those same manifests are refused. Reth must
match its pinned commit plus the recorded patch byte for byte. Hidden index
flags, staged changes and source-root symlinks are refused. Sources are checked
again after building, and `build.json` includes the Reth patch SHA-256. These
checks establish source identity; they do not qualify the candidate guest,
replace the genesis check, or generate an approved deployment pin.

## Mainnet follower and settled RPC (2026-10-18)

Branch `codex/l2-mainnet-follower-rpc-20261018`. Package:
`deployment/mainnet/follower-rpc/` (`build.sh`, `install.sh`, two units, the
native feature shim and the mainnet `settlement-recovery` lock).

- **Follower on Genesis-4.** `bloch-l2-native-follower` accepts the funded
  `BPOSMAN1` mainnet manifest with `--carryover` (the decompressed
  `carryover.tsv`; checked against the manifest commitment by the native
  loader) and `--network-pin f47d3e49…1966` (SHA3-256 of the file). The genesis
  has no L2 registry: `IncrementalNativeVerifierV1::new_flag_day` replays with
  real signatures and FFG and halts unless the native transition installs
  exactly the pinned policy (`settlement_recovery::mainnet`, = native
  `l2_settlement::mainnet::PROGRAM` + attestor set `1c06adbb…`). Status gains
  `chain_id` and `l2_genesis` (activation block/slot, `finalized`).
- **Remote L1 source.** `--rpc-url http://HOST:PORT` (read-only
  `getchaininfo`/`getblockraw`/`getl2settlement`); the source cannot forge
  finality, only stall it. `safe` still comes from that node's head.
- **Settled RPC.** Publishes block 0 as `safe`/`finalized` once the activation
  is inside the verified finalized prefix; refuses a status for another chain
  id or L2 genesis; adds `net_version`/`net_listening`/`net_peerCount`/
  `web3_clientVersion`/`web3_sha3` and `bloch_settlement(number)` (finalized
  settlement of an L2 block: commitment, native slot/block).
- **Native build.** Against `bloch-sis-pow` `78b7343a` the crate needs the two
  devnet feature names added empty (`native-feature-shim.py`) and a lock with
  three extra entries (`settlement-recovery.mainnet.Cargo.lock`).

Live run on 45.77.142.123 (scratch, loopback 19145, L1 source
`http://80.240.16.185:8080`): genesis + carryover load 59 s; 154,767 blocks
fetched (~3 ms/block) and verified from Genesis-4 in ~56 min (~2.7–5.5k
blocks/min), RSS < 0.6 GB; activation `618c9b80…` at slot 187200 matched the
pin; FFG finalized epoch 5943; L2 `latest`/`safe`/`finalized` = block 0
`632e45ae…f468`.

**Finality lag.** The follower fetches up to the node's finalized root, and its
own replayed state proves finality ~2–3 epochs behind that root (observed:
node finalized epoch 5946, follower 5943), i.e. ≈ 50 min on top of L1 finality.
Replaying to the node's head would be equally sound (finality is still what
the replayed FFG state says), but the verifier holds one branch: a reorg of the
unfinalized tip would halt it. Doing it needs a retained state at the
finalized block and a rollback/re-replay of the new branch. Not done here.

## Next RPC build: settled history and minimum tip

**Follower status schema v3.** `bloch-l2-native-follower --status-schema v3` (the default is `v2`). `status.json` keeps its scalar fields and adds `finalized_settlements_count`,
`finalized_settlements_recent` (newest 64) and `settlement_log` (`file`, `entries`, `bytes`, `digest`). Every settlement
is one line of the append-only `<status stem>.settlements.jsonl` beside it. The follower syncs the log before the status
names it, and rewrites it from the replay at each start.

- The settled RPC reads only the part it has not read. It compares new entries and the newest 64 with the local chain.
- The RPC still accepts schema v2, up to 256 MiB. An RPC on a v2 status above the old 16 MiB limit recovers by upgrading
  the RPC alone. An RPC of v2.1 closes `safe` and `finalized` on a v3 status, so the order below matters.
- `bloch_finality.status.schema` names the schema; a settled RPC of v2.1 does not have the field.
- A log that disagrees with the status stops finality from advancing on that RPC, and the rest keeps serving. Restart
  the RPC only after checking the follower.
- The attestor agent and `l2_reorg_recover.py` read both schemas. The attestor checks the log digest in its daily
  rebuild check.

**Rolling from schema v2 to v3.** Each step is safe alone, and each host moves on its own:

| Step | What | State if you stop here |
|---|---|---|
| 1 | Next settled RPC on every host that serves this status, including the signers' private RPC pin | v2 up to 256 MiB, finality open |
| 2 | Readers of the follower's file on that host: attestor kit, replica kit, bridge signers (`load_status`) | They read both schemas |
| 3 | New follower binary, schema still v2 (the default) | Nothing changes for readers |
| 4 | `BLOCH_L2_STATUS_SCHEMA=v3` in `follower.env`, restart that follower. One host at a time; check `bloch_finality.status.schema` | `status.json` falls to about 37 KB |

Going back is a restart with `v2`: the follower rewrites the whole list and the RPC stays open. Doing step 4 before step 1
closes `safe` and `finalized` on that host, and doing it before step 2 stops that host's signer, attestor or replica. None
of them serves anything wrong. `tools/signatario-gnb` in the bridge repository does not read v3.

**Minimum tip.** `bloch-l2-settled-rpc --min-tip-wei` (default 100000000, 0.1 gwei) refuses an effective priority fee
below it at the spool, evicts older spool entries below it at the sweep, and floors `eth_maxPriorityFeePerGas`,
`eth_gasPrice` and the `eth_feeHistory` rewards. `bloch-l2-produce-dev extend --min-tip-wei` holds such entries in the
spool; the mainnet settler installer sets `min_tip_wei`. This is operator policy, not a consensus rule: blocks with a
lower tip stay valid, and replay never consults it. Priority fees stay in the keyless vault until a later program change.

**Transaction-specific storage price (candidate, local validation).** With both `--txpool` and
`--required-tip-file`, `eth_sendRawTransaction` reads the policy v2 file's versioned `admission` object. For the
sender's current canonical nonce, it runs the producer's selector against a disposable state cache and checks
`gas_used * effective_tip >= charged_fresh_slots * fresh_slot_price_wei`, as well as the current required tip.
The effective tip is capped by `maxFeePerGas - nextBaseFee`. Exempt senders have zero charged fresh slots.
This does not change a consensus rule, a price, a guest, or global wallet fee suggestions.

A refusal has JSON-RPC code `-32000` and `error.data.kind = "sequencer-fee-underpriced"`. Its data contains
`transactionHash`, `headHash`, and the following Ethereum hex quantities: `headNumber`, `baseFeePerGas`,
`requiredPriorityFeePerGas`, `requiredMaxFeePerGas`, `effectivePriorityFeePerGas`, `gasUsed`, `freshSlots`,
`chargedFreshSlots`, and `freshSlotPriceWei`. `scope` is `"latest-state-next-block"`.
The required priority fee is the integer ceiling of storage price divided by measured gas, or the policy's
required tip, whichever is greater. `requiredMaxFeePerGas` is exactly that value plus `baseFeePerGas`.
Clients should bind the error to the hash they submitted and show the quote before requesting a new signature;
they must not raise a budget, re-sign or retry automatically.

That specific refusal is emitted before any spool write or eviction. An already spooled hash returns its hash,
even if policy prices later rise. The head and policy are rechecked before using a measurement; drift, missing
or malformed policy, and timeout produce retryable errors without a fee quote. RPC overload is `-32005`.
Admitting a transaction is still not a promise of inclusion. The simulation uses latest state and the RPC's
derived next-block environment, without upcoming deposits, forced transactions or other spooled transactions.
Future nonces are admitted using the existing cheap rules and are not simulated independently; policy may hold
them later. Capacity, sender cooldowns, proving cost and changes to state can also delay inclusion.

Admission shares the same four permits as all other EVM simulations, with a ten-second queue bound, a five-second
execution deadline and the existing 15M declared-gas cap. The permit remains held until the blocking execution
ends. A timed-out preflight checks its deadline before any publication and cannot later spool its result.

Upgrade the settler's Python policy first and confirm that `sequencer-policy.json` contains `admission.version=1`
with decimal-string `required_tip_wei`, decimal-string `fresh_slot_price_wei`, and a complete array
`write_limit_exempt_senders` of `0x` addresses before starting this RPC with `--required-tip-file`. An older
tip-only file is insufficient for transaction admission and is refused explicitly. Without that flag, the
existing static-floor admission remains available. Local regressions execute the DEX's compiled TestToken
`approve`, check exact rounding and fee-cap clipping, and verify no state/spool change on a fee refusal.
The worker publishes this snapshot even when its spool is empty, before checking demand; cold starts, older
state files and an idle decaying tip do not require a transaction or SP1 execution to refresh the RPC policy.

For an optional cross-product HTTP rehearsal, run the ignored Rust test
`admission::tests::serve_disposable_admission_rehearsal` with `BLOCH_ADMISSION_REHEARSAL_FILE` naming a new
temporary JSON file and `BLOCH_ADMISSION_REHEARSAL_SECONDS` between 1 and 1800 (default 300).
It creates a fresh canonical database, deploys the DEX TestToken, and listens only on IPv4 loopback.
`python3 deployment/devnet/rehearse_admission.py FIXTURE --cast PATH_TO_CAST --out RESULT` then checks the real
fee refusal, explicitly signs the same approve at exactly the quoted fees, and verifies hash, spool bytes,
idempotence and pending nonce 2. Canonical nonce stays 1, head stays unchanged and receipt stays null:
the test establishes admission, not inclusion. The driver accepts only this devnet fixture and public test key.

**Level states (`bloch_finality.status.state`).** `starting`: no first read yet, both levels closed (-32001). `ok`. `lagging`: the status names a settlement this database lacks (`missing_settlement`), and nothing it can check contradicts it (genesis, the newest settlements this database holds, the log's presence and size). Levels stay open at their old height, and `age_s` is the file's real age, computed at the call. `behind`: the same, when nothing was published yet in this process, so both levels are closed. A database more than 64 settlements behind cannot be compared until it reaches them. `missing` or `invalid`: both levels closed. While `finalized` is closed, `bloch_settlement` and `bloch_getWithdrawalProof` answer -32001 too. A `safe` settlement that contradicts the local chain closes `safe` only.

A regressed or damaged log stays closed until the follower's log again holds what this RPC verified, or the RPC is restarted. A log with the same settlements in other bytes is read once from its start and compared with the local chain, so a follower upgrade needs no RPC restart. A poll while closed does not read the history again: the cursor stays, and a log refused on a read from its start is not re-read until it or its status changes.

`safe` follows the settlement at the local L1 node's head, down as well as up after an L1 reorg, and never below `finalized`. `finalized` never goes down.
