# Developer RPC compatibility

The synthetic developer executable serves the pinned Reth EthApi and EthFilter handlers over
IPv4 loopback HTTP. This table records exercised behavior, rather than promising
every method exposed by that upstream module. Start and recover the service with
the commands in [DEVNODE.md](DEVNODE.md).

| Developer operation | Exercised behavior | Evidence |
| --- | --- | --- |
| Identify the network | `eth_chainId` returns 700771 (`0xab163`) | `tests/rpc_transport.rs`, `tests/rpc_developer_flow.rs` |
| Submit a signed transaction | `eth_sendRawTransaction` authenticates signed envelopes and admits them to the real pool; malformed and wrong-chain transactions are rejected | `tests/rpc_developer_flow.rs` |
| Populate a transaction in ethers | ethers 6.17.0 discovers nonce, gas and fee fields, then signs and sends deployment and call transactions | `../../wallets/devnode-ethers.test.mjs` |
| Read included transactions | Receipts, full block transactions and raw transaction-by-block-hash/index retain signed transaction identity and canonical block metadata | `tests/rpc_developer_flow.rs` |
| Read contract state | Balance, nonce, code and storage queries reflect mined state and survive orderly restart | `tests/devnode_process.rs`, `../../wallets/devnode-ethers.test.mjs` |
| Query and poll contract logs | `eth_getLogs` filters persisted logs by block, address and topic; `eth_newFilter`, `eth_getFilterChanges`, `eth_getFilterLogs` and `eth_uninstallFilter` use Reth's real filter implementation | `tests/devnode_process.rs`, `../../wallets/devnode-ethers.test.mjs` |
| Handle execution reverts | Call/estimate return RPC error 3 and the exact revert data; included failures consume nonce and gas, roll back storage/logs, and retain their receipt across restart | `tests/devnode_process.rs` |
| Simulate calls | `eth_call` and `eth_estimateGas` use the selected latest/historical state and Bloch BLOCKHASH context; simulations do not commit writes | `tests/rpc_blockhash.rs` |
| Inspect access lists and overrides | The tested access-list, state-override and block-override requests use the same historical execution context | `tests/rpc_blockhash.rs` |
| Read a pool-aware nonce | `eth_getTransactionCount(address, "pending")` is available; ethers exercises this during transaction population | `../../wallets/devnode-ethers.test.mjs` |
| Read a synthesized pending block | `eth_getBlockByNumber("pending", false)` returns an error | `tests/rpc_developer_flow.rs`, `../../wallets/devnode-ethers.test.mjs` |
| Recover readable canonical history | Fresh-directory replay re-executes the completed source prefix and preserves transaction receipts and state | `tests/devnode_process.rs`, `tests/canonical_coordinator.rs` |
| Use compiled Solidity through ethers | Pinned solc 0.8.30 targeting Cancun deploys a contract, decodes indexed ABI events and custom errors, and reads persisted code/state/logs after restart | [Solidity acceptance](../../wallets/SOLIDITY.md) |
| Use MetaMask approval and signing | The pinned real extension connects, rejects, deploys, calls and reads state after restart, with observed UI clicks and independently recovered transaction signatures | [Browser acceptance](../../wallets/browser/README.md) |

The process tests use public fixture keys and synthetic initial funding. They do
not establish native deposit provenance, finality or production consensus.
The `safe` and `finalized` tags are not authenticated native-finality interfaces.
WebSocket subscriptions, tracing, complete Ethereum RPC conformance and broad
third-party tool compatibility have not been qualified by these tests.

## Pending and signing

Pool-aware nonce selection does not construct a pending execution environment.
Use `latest` or an explicit historical block for calls and state queries. A
pending nonce query is not a promise that every admitted transaction will be
included, nor that queued pool contents survive a process restart.

The service accepts signed bytes. The CLI does not accept private keys or unlock
accounts. EIP-1193 `eth_sendTransaction` is a request to a client wallet to obtain
approval and sign; it is not evidence that the node offers account management.
The separately qualified MetaMask UI flow uses the pinned extension/browser
described in the browser acceptance document; this is not blanket wallet support.

Polling filters are process-local and expire under the upstream stale-filter
policy. The node uses `EthConfig::default().filter_config()` for Reth's query
limits and expiry settings. Recreate filter IDs after restart; persisted logs
remain available through a new `eth_getLogs` query. WebSocket subscriptions are
not enabled by registering these HTTP filter methods.

## Bloch block identity

RPC blocks preserve the tagged Bloch V2 header hash and domain commitments.
Neutral `difficulty = 0` and empty `extraData` fields make the projection parseable
by the tested client, consistently with the Reth header traits. Reconstructing an
Ethereum RLP header and hashing it does not reproduce a Bloch V2 block hash.

The execution core uses Cancun rules. Enabling the point-evaluation precompile
does not enable blob transaction admission: the developer pool explicitly
disables EIP-4844 and EIP-7702. The [KZG backend qualification](../../docs/KZG-BACKENDS.md)
covers that precompile separately from RPC transaction support.

## Reproduction

Run the targeted Rust tests with the pinned sibling Reth checkout and toolchain:

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml \
    --test rpc_transport --test rpc_developer_flow --test rpc_blockhash --test devnode_process
```

After building the executable, `npm --prefix wallets run test:devnode` runs the
ethers acceptance test. See [DEVNODE.md](DEVNODE.md) for dependency installation
and the `BLOCH_DEVNODE_BIN` override. Socket/process tests require local port and
process permissions.
