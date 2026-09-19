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

The synthetic developer node also exposes the read-only
`bloch_chainIdentity` method. It returns the versioned
`bloch-chain-identity-v1` tuple (`chainId`, `domain`, `genesisHash` and
`headerFormat`) derived from its immutable chain specification. The method
accepts no parameters. Its response is not a trust root: clients must compare
every field with an independently reviewed deployment manifest before enabling
privileged actions.

`bloch_chainStatus(challenge)` adds a read-only, versioned canonical-head
snapshot. It accepts exactly one nonzero 32-byte challenge, echoes it, and
returns the immutable identity plus the persisted head number, hash and state
root. The provider is sampled before and after the header read; a concurrent
canonical change fails rather than returning a torn tuple. A fresh challenge
prevents ordinary intermediary caches from replaying another request's response,
but the response is not signed and does not prove native finality. Clients still
need authenticated transport and an independently trusted deployment manifest.
The reference EIP-1193 adapter generates a fresh 256-bit challenge for every
network check, requires the exact status schema and cross-checks its head hash
and state root against `eth_getBlockByNumber`. It refuses account access or
signing when secure randomness is unavailable or either view disagrees. Within
one wallet instance, the highest checked head is a monotonic session checkpoint:
a lower height or a different hash/state root at the same height fails closed.
This intentionally treats reorganization as a new-session/review event; it is
not itself finality. After a successful check the adapter exposes a versioned,
immutable checkpoint. A caller may persist it in an independently authenticated
store and pass it back as `minimumCheckpoint` to reject rollback or same-height
equivocation across wallet instances. The adapter deliberately does not trust or
write browser storage automatically; an unauthenticated checkpoint store would
not strengthen the RPC trust boundary. Applications may instead provide a
`trustedCheckpointStore` with asynchronous `load(identity)` and
`advance(identity, previous, next)` methods. The adapter loads it before making
any provider request, validates the exact checkpoint schema, and requires
`advance` to return exactly `true` after an atomic authenticated compare-and-set
before account access or signing can continue. Store rollback below an explicit
`minimumCheckpoint`, same-height equivocation, malformed data, failed writes and
ambiguous write results all fail closed. The store remains a caller-supplied trust
boundary: it must authenticate the chain-identity namespace and durably prevent
rollback; ordinary `localStorage` is insufficient. Before accepting a higher
head, the adapter also reads the canonical block at the trusted checkpoint
height, requires its exact hash and state root, and brackets that historical
lookup with two identical fresh `bloch_chainStatus` snapshots. This proves
continuity within the authenticated RPC view and fails closed on a concurrent
canonical change. It is not independent native-finality evidence: a dishonest
or unauthenticated RPC can still fabricate a self-consistent history, and higher
heads remain unfinalized. Accordingly, read-only `connect()` may expose that
view but `sendTransaction()` requires a caller-supplied
`trustedFinalityVerifier.verify(identity, checkpoint)` boundary. The exact
fresh, immutable checkpoint is passed immediately before signing, and only the
literal result `true` permits `eth_sendTransaction`; absence, rejection,
exceptions and ambiguous results fail closed. The verifier must independently
authenticate native settlement/finality. Merely asking the same L2 RPC whether
its own head is final does not satisfy this trust boundary. The reference
`createEd25519FinalityVerifier` helper pins a raw Ed25519 public key and an
expected finality protocol, then verifies an exact, short-lived signed envelope
covering the complete chain identity, checkpoint and an auditable finality
reference. Its caller still has to operate an independent attestor whose signing
policy derives from real native settlement; the helper intentionally contains no
private key and treats its transport callback as untrusted.

The companion offline CLI uses the same canonical payload bytes and verifier:

```sh
chmod 600 finality-ed25519-private.pem
node wallets/finality-attestation-cli.mjs sign \
  --private-key finality-ed25519-private.pem \
  --input finality-payload.json --output finality-envelope.json
node wallets/finality-attestation-cli.mjs verify \
  --public-key finality-ed25519-public.pem \
  --protocol bloch-native-checkpoint-v1 --input finality-envelope.json
node wallets/finality-attestation-cli.mjs verify-advance \
  --public-key finality-ed25519-public.pem \
  --protocol bloch-native-checkpoint-v1 --input finality-envelope.json \
  --store retained-finality-state.json --expected-state-hash none
```

Signing refuses group/world-readable, linked or non-regular private-key files
and creates the envelope once with read-only permissions. This is release
tooling, not a finality oracle: the offline operator must construct the payload
only after independently validating native settlement and must protect the key
outside the L2 RPC and web application failure domains.

`verify-advance` additionally verifies the envelope and atomically creates or
advances a protected checkpoint state. Each successful invocation prints a
`stateHash`; the next invocation must receive that exact value through
`--expected-state-hash`. It rejects a missing or substituted external anchor,
non-increasing height, replay, same-height equivocation, authority/identity
changes, a corrupt or writable state file, an unsafe writable/symlinked store
directory, and concurrent writers. The update uses an exclusive lock, a synced
temporary file, atomic rename and directory
sync. `none` is valid only for the first checkpoint. Retain the printed hash in
an independent privileged or append-only system before accepting the next
advance. A file and hash kept on the same rollback-capable disk are not an
anti-rollback boundary; the CLI does not replace HSM-backed signing policy,
native-finality verification or replicated witness consensus.

For deployments that must not trust one finality key, the separate
`createEd25519FinalityQuorumVerifier` accepts a canonical, sorted configuration
of 2–32 distinct Ed25519 public keys and a threshold of at least two. The
domain-separated `quorumId` commits to the complete key set and threshold.
Every signer signs that ID, its stable signer ID, the exact chain identity and
checkpoint, freshness interval, protocol and evidence reference. Consequently,
an otherwise valid signature cannot be moved to another quorum, signer or
checkpoint, and duplicate keys never count twice.

```sh
node wallets/finality-quorum-cli.mjs sign \
  --config finality-quorum.json --signer-id settlement-a \
  --private-key settlement-a.pem --input finality-payload.json \
  --output settlement-a-envelope.json
node wallets/finality-quorum-cli.mjs verify \
  --config finality-quorum.json --protocol bloch-native-checkpoint-v1 \
  --expected finality-payload.json --input finality-quorum-bundle.json
node wallets/finality-quorum-cli.mjs verify-advance \
  --config finality-quorum.json --protocol bloch-native-checkpoint-v1 \
  --expected finality-payload.json --input finality-quorum-bundle.json \
  --store retained-quorum-state.json --expected-state-hash none
```

The bundle verifier rejects unknown or duplicate signers, threshold shortfall,
config substitution, stale claims, foreign checkpoints and any malformed or
invalid signature. Operators must assemble the bundle out of independently
obtained envelopes and pin the public configuration outside the L2 RPC/web
failure domain. Threshold signatures reduce single-key compromise risk; they
do not prove that the signers are independent, that their native-finality
policy is correct, or that the bundle was globally published. Key/config
rotation and durable quorum checkpoint advancement remain explicit operational
steps rather than implicit browser authority. The `verify-advance` form performs
that advancement after threshold verification. It stores the quorum ID,
threshold, exact identity/checkpoint and canonical bundle hash behind an
exclusive lock and expected external state hash, then uses file sync, atomic
rename, directory sync and readback. It rejects authority changes, rollback,
replay, same-height equivocation, corruption, unsafe paths and concurrent
writers. The store directory and every path ancestor must resolve without
symlinks, remain owned by the invoking account and deny group/world writes;
state, temporary and lock files must also remain private, current-user-owned
regular files with exactly one link. Retain each returned `stateHash` and the
referenced bundle outside the rollback domain. An orphan lock or ambiguous cleanup requires operator
inspection; automatic lock deletion or blind retry is intentionally absent.

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
