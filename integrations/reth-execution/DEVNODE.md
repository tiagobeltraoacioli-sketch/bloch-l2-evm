# Isolated Bloch EVM developer node

`bloch-evm-dev` serves the actual Reth Ethereum RPC and filter handlers on IPv4 loopback,
admits signed transactions into the Bloch pool, mines periodically through the
canonical coordinator and persists blocks/state. It is an explicitly synthetic
local domain: no native deposit verification, P2P, production consensus, settlement
or proof backend is started.

## Build and start

Use the pinned sibling Reth checkout and native build prerequisites from
[README.md](README.md). From the modular execution repository root:

```sh
python3 integrations/reth-execution/prepare-reth.py
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 build --locked --manifest-path integrations/reth-execution/Cargo.toml --bin bloch-evm-dev
```

Create a local test account in your signing tool and assign its address below.
The binary accepts an address, never a private key. Choose a data directory that
does not exist; its parent directory must exist.

```sh
DEV_ACCOUNT='replace-with-your-local-test-account-address'
integrations/reth-execution/target/debug/bloch-evm-dev \
  --synthetic-dev --data-dir /tmp/bloch-evm-local --init \
  --fund "$DEV_ACCOUNT" --port 8545 --block-interval-ms 1000
```

`--fund` applies one synthetic deposit with `l1_sats=100000000`, converted under
the testnet kernel's normal mint rules. It is allowed only during initialization.
Omit it for an unfunded domain. The fixed synthetic domain and chain configuration
are printed at startup, along with the head hash. `--port 0` selects an available
port; the `RPC listening at ...` line reports the actual endpoint.

Add `--ws-port 8546` to enable the separate loopback WebSocket endpoint for
`eth_subscribe` and `eth_unsubscribe`. Use `--ws-port 0` for an available port;
the `WS listening at ...` line reports it. HTTP and WebSocket can both request
port zero, but identical fixed ports are rejected. See
[WebSocket subscriptions](WEBSOCKET.md) for event types, reconnect behavior and
client tests.

```sh
curl -s http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
curl -s http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"eth_getBlockByNumber","params":["latest",false]}'
```

The [RPC compatibility matrix](RPC-COMPATIBILITY.md) records the exercised
methods, client behavior and current limits.

Sign transactions with the reported chain ID and submit through
`eth_sendRawTransaction`. The node mines selected transactions automatically;
use `eth_getTransactionReceipt` to observe inclusion. For execution queries use
an explicit `latest` or historical block. Synthesized `pending` is unsupported,
so tools relying on it need configuration or further integration. Pool-aware
`eth_getTransactionCount(address, "pending")` remains available; it does not
provide a pending block or execution environment. No browser
wallet compatibility is claimed by the process test.

## Stop and reopen

Ctrl-C stops the RPC transports and background services. Reopen the same directory without
`--init` or `--fund`:

```sh
integrations/reth-execution/target/debug/bloch-evm-dev \
  --synthetic-dev --data-dir /tmp/bloch-evm-local --port 8545
```

The node checks genesis/domain, head seal and committed metadata/state root, and
historical genesis allocations before serving. Initialization refuses any
existing directory. If initialization/funding succeeded but binding an RPC
port failed, the database is already initialized: use reopen with a free port.
A partially initialized directory is not automatically overwritten or repaired.

## Recover by replay into another directory

Stop the source node first. If its canonical headers and complete bodies are
readable, reconstruct its last completed MDBX checkpoint into a new directory:

```sh
integrations/reth-execution/target/debug/bloch-evm-dev \
  --synthetic-dev --data-dir /tmp/bloch-evm-recovered --init \
  --replay-from /tmp/bloch-evm-local --port 8545
```

`--replay-from` requires `--init`, forbids `--fund`, and opens the source datasets
read-only. It re-executes each block and checks its full V2 header/commitments,
including state and receipts, rather than copying potentially damaged current
state or history indices. The new service starts only after replay and attachment
validation succeed. Existing target directories are refused.

Recovery now has explicit cumulative limits: `--replay-max-blocks` defaults to
10,000 non-genesis blocks and `--replay-max-bytes` to 268,435,456 bytes (256 MiB).
Bytes are the sum of canonical V2 block RLP lengths, including headers, signed
transactions and deposits; genesis is excluded. Exact limits are accepted, and
zero limits allow a genesis-only source. These bounds do not limit decoded heap,
backend reads, state size or EVM execution time.

To reject a valid but rolled-back source copy, provide a block number and exact
hash retained independently before the incident:

```sh
integrations/reth-execution/target/debug/bloch-evm-dev \
  --synthetic-dev --data-dir /tmp/bloch-evm-recovered --init \
  --replay-from /tmp/bloch-evm-local \
  --replay-min-block "$RETAINED_L2_BLOCK" \
  --replay-min-hash "$RETAINED_L2_HASH" \
  --replay-max-blocks 10000 --replay-max-bytes 268435456 --port 8545
```

The floor is a minimum: later complete commits can be recovered after a lost
acknowledgement. An older source or a conflicting hash at the retained height is
refused. Both floor arguments must be supplied together; a requested floor is
never dropped or replaced with a value from the source. Reading the floor from
the same backup being inspected does not provide rollback protection. Without a
floor the startup diagnostic explicitly says `rollback_floor=not-supplied`;
suffix deletion remains undetectable. The floor selects local acknowledged
history and does not establish native settlement, consensus or finality.

The CLI resolves source/target paths and rejects existing targets, nested paths,
and overlaps through symlink aliases. It opens the source read-only and checks
identity, the optional floor, block count, available bodies/header linkage and
cumulative bytes **before creating the target directory**. It then repeats
inspection under the same retained MDBX read transaction used for actual replay,
checks byte accounting again, and publishes RPC only after full execution and
attachment validation. Keep the source node stopped throughout; the read
transaction does not lock independent static-file writers. Use trusted parent
directories; this is not a filesystem sandbox against concurrent path replacement.

The library exposes `inspect_canonical_prefix` for source-only preflight and
`replay_canonical_prefix_with_limits` for explicit `ReplayFloor`/`ReplayLimits`.
The existing `replay_canonical_prefix` signature remains available and now uses
the same 10,000-block/256-MiB defaults without a floor. Library callers must
provide a fresh target and keep it separate from the source. A floor or budget
refusal leaves target genesis unwritten. An execution or publication error after
preflight can leave an incomplete separate target; inspect it and choose another
new target rather than automatically retrying over it. Successful replay returns
the exact recovered head, block/byte totals and supplied floor.

Static-file rows ahead of the completed MDBX checkpoint are excluded; the source
is not truncated or repaired. Missing/corrupt canonical bodies or inconsistent
headers stop recovery instead of inventing replacement blocks. An error leaves
the separate target incomplete. Preserve the source and inspect the error before
attempting another new target. This local synthetic recovery trusts the recorded
canonical selection; it does not authenticate native/L1 derivation or establish
finality.

## Evidence and limits

`tests/devnode_process.rs` launches the executable as a separate process, sends
signed deployment and storage mutation over HTTP, stops it, reopens the database,
checks receipt identity/nonce/storage and mines the next signed transaction.
It also checks mandatory synthetic mode and preservation of an existing directory.
The process suite additionally exercises logs by block hash, address and topic,
polling-filter changes/removal, and a transaction that writes storage and emits
a log before reverting. That transaction retains its failed receipt, nonce and
exact gas charge while storage/logs roll back; call/estimate preserve the revert
bytes. The failed receipt survives restart, and later valid transactions still mine.
The process/signal test currently runs on Unix and needs permission to bind local
ports. Run it with:

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml --test devnode_process
```

The separate ethers acceptance test uses ethers 6.17.0 with automatic nonce, gas
estimation and fee discovery; it does not prefill these fields to bypass client
compatibility. It starts its own temporary node and tests signing, deployment,
calls, logs/state queries and orderly restart. After building the binary:

```sh
npm ci --prefix wallets --ignore-scripts
npm --prefix wallets run test:devnode
```

Use `BLOCH_DEVNODE_BIN` to select another build of the executable. The RPC header
exposes zero difficulty and empty extra data, matching its Reth header traits,
while retaining the tagged Bloch V2 hash and domain/commitment fields. This is an
RPC representation; it is not an Ethereum consensus-header encoding.

The separate [MetaMask acceptance](../../wallets/browser/README.md) now qualifies
real UI connection, rejection, signing, deployment/call and state queries after
restart with a pinned official browser and extension. It uses a fresh profile
and public synthetic fixture, and independently recovers both signed transactions.
Run `npm --prefix wallets run test:browser` after the documented preparation.

Empty blocks are mined too. Timestamps advance synthetically by one per block,
independently of the wall-clock interval. Selection conservatively reserves each
transaction's declared gas limit and stops at the first resource limit. An
execution/persistence error terminates the service; it does not silently discard
transactions or retry partially persisted work. Pool contents are in memory and
are not restored after restart; already mined transactions remain queryable.

Recovery tests cover SIGKILL between writes after a completed commit, replay of
signed contracts into another directory, and a reproduced commit boundary where
static files are finalized but MDBX aborts. Startup rejects that mismatch; replay
recovers only the completed prefix. Separate tests rebuild missing genesis history
indices and reject a missing required block body. `tests/recovery_limits.rs`
reexecutes a signed contract through real MDBX/static/RocksDB storage, checks its
receipts/nonce/storage after reopening, and continues execution. It also checks
retained floors, exact/cumulative resource limits and refusal before target
creation. The process replay test supplies the exact block retained from an
acknowledged transaction receipt. These are specific failure
models, not exhaustive crash/power-loss qualification.

Storage spans MDBX, static files and RocksDB; broader crash recovery, fork choice,
reorganizations, native derivation/finality, authenticated pending environments,
broader wallet qualification and native proof-verifier integration remain open.
The stopped node's selected blocks can be [exported](PROOF-EXPORT.md) for the
separate [SP1 proof-chain workflow](../../docs/PROOF-CHAIN-REHEARSAL.md); the
developer service itself does not start a prover or settle native transactions.
