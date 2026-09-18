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
indices and reject a missing required block body. These are specific failure
models, not exhaustive crash/power-loss qualification.

Storage spans MDBX, static files and RocksDB; broader crash recovery, fork choice,
reorganizations, native derivation/finality, authenticated pending environments,
broader wallet qualification and native proof-verifier integration remain open.
The stopped node's selected blocks can be [exported](PROOF-EXPORT.md) for the
separate [SP1 proof-chain workflow](../../docs/PROOF-CHAIN-REHEARSAL.md); the
developer service itself does not start a prover or settle native transactions.
