# Isolated Bloch EVM developer node

`bloch-evm-dev` serves the actual Reth Ethereum RPC handlers on IPv4 loopback,
admits signed transactions into the Bloch pool, mines periodically through the
canonical coordinator and persists blocks/state. It is an explicitly synthetic
local domain: no native deposit verification, P2P, production consensus, settlement
or proof backend is started.

## Build and start

Use the pinned sibling Reth checkout and native build prerequisites from
[README.md](README.md). From the modular execution repository root:

```sh
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

```sh
curl -s http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
curl -s http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"eth_getBlockByNumber","params":["latest",false]}'
```

Sign transactions with the reported chain ID and submit through
`eth_sendRawTransaction`. The node mines selected transactions automatically;
use `eth_getTransactionReceipt` to observe inclusion. For execution queries use
an explicit `latest` or historical block. Synthesized `pending` is unsupported,
so tools relying on it need configuration or further integration. No browser
wallet compatibility is claimed by the process test.

## Stop and reopen

Ctrl-C stops HTTP and background services. Reopen the same directory without
`--init` or `--fund`:

```sh
integrations/reth-execution/target/debug/bloch-evm-dev \
  --synthetic-dev --data-dir /tmp/bloch-evm-local --port 8545
```

The node checks genesis/domain, head seal and committed metadata/state root, and
historical genesis allocations before serving. Initialization refuses any
existing directory. If initialization/funding succeeded but binding the HTTP
port failed, the database is already initialized: use reopen with a free port.
A partially initialized directory is not automatically overwritten or repaired.

## Evidence and limits

`tests/devnode_process.rs` launches the executable as a separate process, sends
signed deployment and storage mutation over HTTP, stops it, reopens the database,
checks receipt identity/nonce/storage and mines the next signed transaction.
It also checks mandatory synthetic mode and preservation of an existing directory.
The process/signal test currently runs on Unix and needs permission to bind local
ports. Run it with:

```sh
cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml --test devnode_process
```

Empty blocks are mined too. Timestamps advance synthetically by one per block,
independently of the wall-clock interval. Selection conservatively reserves each
transaction's declared gas limit and stops at the first resource limit. An
execution/persistence error terminates the service; it does not silently discard
transactions or retry partially persisted work. Pool contents are in memory and
are not restored after restart; already mined transactions remain queryable.

The restart test establishes orderly shutdown/reopen, not crash recovery. Storage
spans MDBX, static files and RocksDB; cross-backend crash recovery, fork choice,
reorganizations, native derivation/finality, authenticated pending environments,
browser-wallet qualification and the proof backend remain open delivery work.
