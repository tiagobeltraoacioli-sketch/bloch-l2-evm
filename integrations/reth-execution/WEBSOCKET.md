# Optional developer WebSocket subscriptions

The isolated synthetic developer node can expose the pinned upstream Reth
`EthPubSub` service through a real jsonrpsee WebSocket server. It uses the same
provider, transaction pool, execution configuration and canonical notifications
as the existing HTTP node; there are no manually generated subscription events.

```sh
integrations/reth-execution/target/debug/bloch-evm-dev \
  --synthetic-dev --data-dir /new/disposable/node --init \
  --port 8545 --ws-port 8546
```

Both endpoints bind to loopback. WebSocket is optional; omit `--ws-port` for the
existing HTTP-only mode. Set both ports to `0` for separately allocated ephemeral
ports. Two identical nonzero ports are rejected before startup. The node prints
`RPC listening at http://127.0.0.1:PORT` and
`WS listening at ws://127.0.0.1:PORT` when ready. Each connection is limited to 64
subscriptions. Shutdown stops both transport handles.

Use the upstream `eth_subscribe`/`eth_unsubscribe` methods with `newHeads`,
`newPendingTransactions` or filtered `logs`. Headers retain Bloch V2 identity;
they do not substitute an Ethereum header hash. A pending-transaction event means
local pool admission, not inclusion or finality. Subscriptions are connection
state: reconnecting or restarting requires subscribing again. Historical logs
remain available through the existing filter/query methods; this transport does
not provide a durable event-consumer checkpoint.

This remains a loopback, synthetic-funding, isolated-network developer service.
It does not add P2P, native deposit authentication, public endpoint hardening,
native finality or a production subscription delivery guarantee. Existing pending
block execution restrictions remain unchanged.

## Process acceptance

`tests/websocket_process.rs` launches the actual developer executable with HTTP
and WebSocket enabled. A real WebSocket client subscribes before submitting
canonical signed transactions over HTTP. It checks:

- `newHeads` V2 hash, parent hash, state root and height against HTTP block data;
- a pending event matching the exact signed transaction hash;
- a filtered contract log matching the persisted call receipt;
- invalid subscription rejection and explicit unsubscribe;
- reconnect/resubscribe, process restart, persisted receipt/storage, and a further
  signed call producing a new subscribed log and updated storage.

Only a public test key and explicit synthetic funding are used. No browser wallet
or remote service is involved in this transport test.

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --locked --offline \
  --manifest-path integrations/reth-execution/Cargo.toml --test websocket_process
```

The test requires local socket-binding permission. It must run against the real
server; an in-process RPC module or mocked notification is not equivalent.
