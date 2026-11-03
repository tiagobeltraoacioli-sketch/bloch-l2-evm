# Reth transaction snapshot correction

The host uses upstream Reth `v2.4.1`, base commit
`8eb210175687c9f0c889a3b6795c16781d830e3a`, plus the local
[`reth-snapshot.patch`](reth-snapshot.patch). This is a qualified Bloch host
integration change, not a claim that upstream's published release contains it.

Patch SHA-256: `e6d960cfbded40ce1cef42c024a362f53e0d6d77b94159358631cb04fdd83a41`.
Patched files (SHA-256):

| file | SHA-256 |
|---|---|
| `crates/storage/provider/src/providers/consistent.rs` | `1e3b23b5ba0444faf9bb903ba6dc7e65bb928430ded2024869a772e842e91ffa` (unchanged since `fe1f293c…`) |
| `crates/rpc/rpc-eth-api/src/helpers/call.rs` | `95ee7a628e32d1bfb3d2b3ddda06fa73924d29c68e4695fb01387cf3aefa505e` |
| `crates/rpc/rpc-eth-api/src/helpers/estimate.rs` | `a50853b04a9b9918fd2eeb718e2149453fd4b88e7f78476e8010ef3ce2e3e913` |

The patch has two independent parts: the transaction snapshot correction
below, and the RPC simulation limits (2026-11-03, review 154 G2/G8, owner
decision 2), described after it. The previous patch, with the first part only,
was `fe1f293c58cf45281c208e90950c1b9221887459640c031d61c5aed9489d0977`.

## Failure and correction

With automatic mining, a successful contract event followed by a bounded
`eth_getLogs` query could return `-32603: block meta not found for block #29`,
even when the requested range contained only block 17. The filter needs the
transaction hash for each matching receipt. Its transaction lookup uses Reth's
`ConsistentProvider`, which opens a real MDBX read snapshot.

When there is no in-memory executed-block overlay, the individual and range
transaction helpers selected their storage boundary with `last_block_number()`.
That reads the shared static-file tip, which can advance after the MDBX snapshot
opens. Looking up the newer tip's body indices in the older snapshot then fails.
The canonical coordinator publishes only after its commit, but static-file
visibility and an already-open MDBX read transaction do not advance atomically.

The patch changes those two boundary selections to `best_block_number()`, which
reads the completed `Finish` checkpoint from the same MDBX snapshot. In-memory
anchor selection is unchanged. No RPC retry, synthetic response, provisional
block publication or serialization of all clients is introduced.

The patch is deliberately about transaction lookup boundaries. Other upstream
uses of `last_block_number()` and broader snapshot/reorganization behavior are
outside this correction. It does not make all storage backends crash-atomic.

## RPC simulation limits

Upstream applies the RPC gas cap (`EthApiBuilder::gas_cap`, `Call::call_gas_limit`)
only to an explicit `eth_call` gas. Three other paths took a larger limit:

| path | upstream limit | reachable with |
|---|---|---|
| `eth_call` without gas, with a fee and a funded (or state-overridden) sender | the caller's allowance, capped by the block gas limit, which a block override sets freely | `[tx, tag, {from: {balance}}, {gasLimit: 1e9}]` |
| `eth_estimateGas` | the block gas limit (or EIP-7825's cap), also open to a block override | `[tx, tag, state, {gasLimit: 1e9}]` |
| `eth_createAccessList` | the explicit gas, with the block gas limit and EIP-7825's cap disabled | `[{gas: 1e9, ...}]` |

So one anonymous request could run the EVM for hours, holding one of the
settled RPC's 4 simulation permits; four requests stopped every simulation of
that backend until a restart. The patch caps all three at `call_gas_limit()`
(`gas_within_cap`). The settled RPC builds its API with a cap of 15,000,000,
the spool's `max_tx_gas` (`build_eth_api_capped`); `build_eth_api` and
`build_eth_api_with` keep the block gas limit.

It also adds a process-wide wall-clock budget for a request that runs the EVM
more than once (`set_simulation_time_limit`, default none). `eth_estimateGas`
checks it before its optimistic run and before every binary-search run, and
`eth_createAccessList` before its second run; when it is spent they answer
`execution aborted (timeout = …)` (`EthApiError::ExecutionTimedOut`, code
-32000 as upstream's tracing timeout). A single EVM run is not interrupted:
it is bounded by the gas cap. The settled RPC sets 5 s.

Only RPC code changes. The canonical executor, the native follower and the
block producer do not instantiate these methods; their release binaries are
byte-identical to the previous build (PINS-NEXT, agent 195).

## Reproduce and inspect

From the modular execution repository root, with the clean base checkout above:

```sh
python3 integrations/reth-execution/prepare-reth.py
python3 integrations/reth-execution/prepare-reth.py --check
git -C ../reth-bloch-rpc-snapshot diff -- crates/storage/provider/src/providers/consistent.rs
```

The helper creates `../reth-bloch-rpc-snapshot` as a detached worktree, applies
only the recorded patch, and compares the entire tracked diff byte-for-byte
against that patch. Staged changes, untracked files or another HEAD are refused.
It does not reset or overwrite unrelated existing changes. `--check` performs no
worktree creation or patching. The original sibling checkout remains unchanged.
All host Reth path dependencies resolve through the prepared worktree; the
portable core, SP1 guest and native consensus checkout are unaffected.

An optional command after `--` runs only after that source verification. The
helper supplies `VERGEN_GIT_SHA` and `VERGEN_GIT_DESCRIBE` obtained from native
Git and `VERGEN_GIT_DIRTY=true` for the verified patch. This avoids the upstream
build's libgit2 describe traversal failing on a missing parent object in a
shallow worktree. The build reports the actual base and a development suffix;
it is not labelled as a clean upstream binary.

## Regression

Two tests in `tests/canonical_coordinator.rs` hold a `ConsistentProvider` created
at genesis, then commit another block through the real coordinator. They exercise
transaction-ID and transaction/receipt-range queries using the old snapshot.
The unmodified base fails both tests deterministically with
`BlockBodyIndicesNotFound(1)`, without a timing loop or injected provider errors.
The expected result is an empty query response from that original snapshot.
A third regression retains a snapshot after a funded, signed transaction, then
commits another signed transaction. The old snapshot must preserve its original
transaction and receipt while excluding the new transaction; a fresh query sees
both. This also checks snapshot content, beyond avoiding the original error.

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml \
    --test canonical_coordinator --test devnode_process
npm --prefix wallets run test:devnode
```

The ethers acceptance queries the real persisted event by exact block range,
address and topic before and after restart. Wrong-topic queries must be empty.
An occasional passing run on the unmodified source does not close this race;
the held-snapshot tests are the deterministic regression boundary.

Recorded host validation on 2026-09-17: the prepared source passed all eight
canonical-coordinator tests (7.74 seconds) and all five developer-process tests
(9.57 seconds), including the three snapshot regressions and HTTP filter/revert
flows. Ethers acceptance passed on the corrected executable (10.349 seconds),
including positive and wrong-topic queries before/after restart. Clippy passed
for the binary and both affected Rust test targets with `-D warnings`; upstream
ECIES deprecation and build-metadata notices remain separate dependency warnings.
These results qualify this host integration; they are not a full upstream
Reth workspace test result or a production crash-consistency claim.
