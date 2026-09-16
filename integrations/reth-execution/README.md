# Bloch execution over a Reth state provider

This host integration uses the real `reth_revm::database::StateProviderDatabase`
to run Bloch's signed whole-block executor against an `EvmStateProvider`. Reth's
`StateProvider` has an upstream blanket implementation of that interface.
It provides the storage-read boundary for future node integration, not a node,
RPC endpoint, pool, proof backend or durable database writer.

## Reproduce

Use a sibling `reth-bloch-integration` checkout at exactly:

```text
https://github.com/paradigmxyz/reth
8eb210175687c9f0c889a3b6795c16781d830e3a (v2.4.1)
```

The path dependency does not enforce its Git revision; verify the checkout before
building. The host integration uses Rust **1.98.1** and its own committed lockfile.
The portable EVM core retains its separate Rust 1.94.1 toolchain and lockfile.
Storage tests additionally build MDBX and RocksDB. Install a C/C++ toolchain,
Clang/libclang, CMake and pkg-config (on macOS, use the Xcode command-line tools
and a discoverable libclang). The first native build can take substantially
longer than the execution-only build.
From the modular execution repository root:

```sh
git -C ../reth-bloch-integration rev-parse HEAD
cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml
cargo +1.98.1 clippy --locked --manifest-path integrations/reth-execution/Cargo.toml --all-targets -- -D warnings
```

Add `--offline` once dependencies are cached. Upstream's original lock resolves
older Alloy consensus/ruint versions; this integration's graph resolves the core's
exact Alloy consensus 2.2.0, primitives 1.6.1, trie 0.9.5, ruint 1.20.0 and revm
41.0.0. It is a separately qualified host build, not the unchanged upstream
release binary or an attested execution artifact.
The storage provider also enables Alloy's `secp256k1` recovery feature through
Reth. `tests/signed_boundary.rs` reuses the portable signature/authentication
regressions under this host graph; the core's `serde` wire regression remains in
the portable all-features job.

## Execution boundary

`execute_on_provider(spec, provider, previous_root, signed_input)` wraps the
provider and calls `execute_signed_block_on_database` in the portable core.
That function authenticates the original signed envelopes and calls the same
`run_block` kernel used by host state execution and witness verification.
Deposit metering, supply/cursor updates, fee-vault routing, EIP-4788 and the
committed Bloch `BLOCKHASH` ring therefore share one implementation.

Successful execution returns `DatabaseBlockExecution`. Its `overlay()` exposes
the successful read/change cache without writing the provider. On execution
failure no candidate is returned. The backing provider can perform internal
read caching, but the execution adapter does not call a storage commit method.

`begin_on_provider(spec, provider, previous_root, context, deposits)` returns
the core's `SignedBlockBuilder` over that same reader. It supports authenticated
incremental candidate selection with conditional inclusion, then returns the
accepted signed input and execution overlay. Its protocol prefix runs once;
each candidate stages state/accounting before publication. See
[the incremental API](../../docs/DATABASE-EXECUTION.md#incremental-signed-construction)
for attempt budgets and host trust requirements. This is not yet a Reth SDK
executor factory or payload builder.

The caller must hold a consistent pre-state snapshot and supply its correct root,
derive/authenticate deposits and L1 context independently, calculate the complete
post-state MPT root, then atomically persist the matching overlay. Passing that
root to `finalize` attaches it to the outcome; **finalize does not verify the
root**. A wrong supplied pre-root can change parent and `BLOCKHASH` commitments.
This adapter must never replace authenticated witness/domain verification for an
untrusted proposal.

The overlay is sparse. Read-only cached accounts are not necessarily changes;
untouched storage survives unless cleared, and destroyed/empty accounts must be
handled consistently with revm/EIP-161. Simply replacing full backing accounts
with partial overlay entries is incorrect.

`execution_bundle(&execution)` converts a successful execution to upstream
`BundleState`, including one block of reverts. It compares cached entries with
the unchanged backing snapshot, retains explicit zero writes, preserves storage
wipes and includes newly deployed bytecode. It does not scan untouched accounts
or their storage. Conversion may fail on a backing read or missing new bytecode;
no partial bundle is returned and no backing writes occur.

Use the bundle to calculate the complete post-state root and pass it to the
storage writer in the same host transaction. Deleted storage that was never read
is deliberately absent from this sparse bundle. Reth's writer must capture that
account's original storage while processing wipe reverts **before** applying
forward changes. The bundle alone is not a complete historical snapshot.
The storage test below exercises actual Reth trie calculation, state writes,
commit/abort and orderly reopening. These operations currently live in the test
harness; this adapter does not yet expose a node storage service. Canonical
block unwind and crash recovery remain unqualified.

## Remaining node work

The existing V1 header retains its fixed-width identity. The separate V2 path now
provides committed transaction/receipt roots, full Reth primitive adapters,
configuration and assembly. A complete node still needs authenticated domain
initialization, crash recovery, canonical-tip coordination and launched import,
payload service/node/pool/RPC wiring and authenticated deposit derivation.
Launching a vanilla Ethereum Reth node would not satisfy these requirements.

## Validation scope

`tests/provider.rs` supplies a fixture implementing upstream's `EvmStateProvider`
and executes through the real Reth database reader. Read counters exercise
account, storage-key and bytecode conversion. Its deliberately incorrect external
block hashes are never read: Bloch's committed ring supplies `BLOCKHASH`.
The fixture enumerates complete local state to calculate an independent MPT root
and compares it with direct core execution over signed deployment/call and revert.
Provider errors propagate and malformed signed input fails before provider reads.
The tests also apply upstream plain changes and reverts to a fixture store,
checking both the forward root and the restored pre-state root for every block.
This fixture provider is not MDBX or a live node; its tests establish conversion
semantics. The portable core has separate generic-adapter tests,
including a valid first transaction followed by an invalid nonce, which must
leave its borrowed backing snapshot unchanged.

Both test suites also execute a signed creation that destroys a prefunded account
in the same transaction. They assert the exact nonzero EIP-6780 burn, account
deletion and supply conservation. The portable Rust 1.94.1 and host Rust 1.98.1
builds agree on the following fixture roots, now pinned in both suites:

| Fixture | Final state root |
| --- | --- |
| Four-block deploy/call/revert | `0xcaa54b319b1297820f2e71093a55156bb19225c76eec4c9f40672c6b4e6453f3` |
| Two-block prefunding/burn/deletion | `0x8d248f2fca24dad8c10537c898904ab52a031c765cb8e6a41f465dff2ef57873` |

These vectors check cross-build agreement for the exercised scenarios, not full
EVM conformance or equivalence of every dependency/compiler configuration.

## Real storage qualification

`tests/persistence.rs` uses upstream's provider factory with actual MDBX,
RocksDB and static-file handles. It seeds the Bloch genesis state without
inserting an Ethereum genesis/header. Synthetic deposits fund signed contract
deployment, a call storing `42`, and a call clearing the slot. Incremental
construction skips each signed candidate once before including it. For each block,
Reth's trie independently calculates the same root as portable core execution;
the writer persists plain/hashed state, bytecode, changesets and trie updates.
Fresh snapshots expose the expected balances, nonces and storage.

The test drops a fully staged writer without committing and checks the previous
root survives. It then commits, checks original values in persisted changesets,
closes all storage handles, opens the same disposable directory with new handles,
and checks state, root, bytecode and change history again. This is orderly
close/reopen evidence, not forced-process/power-loss recovery. Receipts and block
metadata are deliberately outside this storage test; canonical chain unwind,
real native derivation and a running RPC/node still require their own gates.

A second storage test executes signed creation/self-destruction at a prefunded
address with an old storage slot that execution never reads. The sparse bundle
contains only a wipe marker for that slot; the real writer saves its old value
in durable changesets before deletion. After reopening, the test reconstructs
an inverse delta using only disk changesets and current state, restores the
original root/account/storage and reopens again. It deliberately retains history
and does not remove block metadata: this establishes storage restoration, not
Reth's canonical chain unwind.

## Supplied EVM preparation

`tests/sdk_preparation.rs` uses the exact upstream `EthEvmFactory` to construct
an inspector-bearing EVM over revm `State<InMemoryDB>`. It authenticates signed
bytes, executes through that EVM, and calls the core's shared
`prepare_transaction_effects` with the same mutable database. Dropping the
prepared effects leaves state unchanged; retrying and committing updates that
same state/cache/bundle. Inspector counters confirm that execution occurs in the
supplied EVM. A second test covers vault self-destruction followed by protocol
fee credit, including storage wiping and the original value in the bundle.

These tests qualify the transaction-accounting phase against the real SDK types.
They do not implement `BlockExecutorFactory`, the block lifecycle, custom
primitives/receipts or a node. The prepared API is a
trusted-backend interface; the future adapter must reject stale or foreign
prepared results and preserve signature authentication.

## Bloch SDK transaction host

`BlochEvmFactory::new(&spec)` creates an actual SDK EVM with the exact supplied
database and inspector. `BlochContext` overrides only the block-hash source;
upstream opcode gas/window checks, handlers and precompiles remain in use.
History comes from the configured block-info account, not external header
lookups, and these protocol reads do not warm journal accounts or slots.
A missing committed head returns zero; provider errors propagate.

`blockhash_context` covers window boundaries, custom block-info addresses,
missing heads, provider errors, inspector callbacks and upstream gas parity.
`core_history` compares signed transaction results against the core using its
real generated history despite a conflicting database hash cache. It stages the
protocol prefix with an empty core block; it does not qualify a complete SDK
block executor. The separate lifecycle qualification below covers those phases.

## Supplied EVM block phases

`tests/sdk_lifecycle.rs` drives the core staged lifecycle through an actual
`BlochEvmFactory` EVM with its original inspector/database. Five signed blocks
cover deposit funding, deployment, storage writes/clears, committed BLOCKHASH,
self-destruction burns and a reverted transaction. Every candidate is skipped
and retried before inclusion. Full roots, headers, fee/burn accounting and
execution results match the portable signed kernel. The same phases also run
on revm `State`; its plain account/storage/code changes match the portable bundle.

This establishes shared protocol phases, not an implementation of the SDK's
`BlockExecutorFactory`, receipts, custom primitives, assembler, pool or RPC.
Callers must discard provisional block state after a later phase failure;
prepared commits cannot undo earlier phases on a generic mutable database.
See [the lifecycle contract](../../docs/DATABASE-EXECUTION.md#protocol-lifecycle-on-a-mutable-database).

## SDK block executor factory

`BlochBlockExecutorFactory::new(&spec)` implements the pinned Alloy
`BlockExecutorFactory`, preserving its supplied Bloch EVM, database and inspector.
Provide `BlochBlockExecutionCtx { previous_root, context, deposits }` from a
consistent provisional state and independently authenticated L1 derivation.
The supplied EVM configuration must match the canonical Bloch environment.

The executor uses the shared lifecycle, reauthenticates signed envelopes instead
of trusting recovered senders/prebuilt TxEnv values, and limits total candidate
attempts and bytes. `execute_transaction_without_commit` returns an owned result;
dropping it skips the candidate. Prefer `checked_commit_transaction` for an
immediate Result. The SDK infallible commit returns zero gas and poisons the
executor on a stale/foreign token; later execution and finalization must fail.
Mutable EVM access and accepted commits invalidate older results.

The core prefix supplies an immutable BLOCKHASH window captured before any
beacon/deposit/user execution. The executor restores this window and canonical
upstream precompiles before each candidate. The standalone EVM factory also
supports trusted `install_block_hashes` for lifecycle consumers; without an
installed window it reads the live committed ring for isolated simulations.

Typed user receipts contain status/logs and cumulative user gas. Total block gas
also includes deposits, so it can exceed the last user receipt; there are no
fabricated deposit receipts. `finish_bloch` returns the SDK EVM/block result plus
the core FinishedBlock, to which the caller attaches the calculated root.
The SDK trait's `finish` returns its normal EVM/block result only.

`tests/block_executor.rs` exercises the actual traits, multiple signed blocks,
receipts/logs, supplied inspector, forged recovery/environment inputs, skipped
candidates, stale/foreign/mutable-access tokens, environment rejection,
canonical precompiles and a contract mutating the block-info ring during a block.
`tests/block_executor_bounds.rs` checks rejected/skipped candidate budgets,
oversized preflight, and disabled validation or wrong block-info configuration
without original-database reads. Full node storage, consensus, pool and RPC
integration remain open. Existing production/
domain formats are unchanged and no live chain is activated.

## Explicit V2 SDK factory

`BlochNodeBlockExecutorFactory::new(&spec, trusted_domain)` uses the V2 genesis/head
format through the same supplied-EVM executor. Provide the same
`BlochBlockExecutionCtx`; V1 genesis and a zero domain fail before prefix writes.
Candidates retain their canonical signed bytes, which enter the final body only
on a successful checked commit. Skipping or rejecting a candidate cannot add it
to the committed transaction root.

`finish_node` prepares V2 head metadata from the accepted body and actual results,
compares core-derived receipts with the SDK receipts, then commits the read-complete
final changes. It returns the supplied EVM, SDK result and `FinishedNodeBlock`.
Calculate the full post-state root and pass it to `finalize(root)` to obtain the
actual `NodeExecutionOutcome`. The generic SDK `finish` selects the correct version
and returns its standard result; it does not invent a root. Calling the wrong
version-specific finalizer is rejected.

`tests/node_block_executor.rs` compares supplied-EVM execution against portable,
recorded and stateless V2 results across signed deployment, logs, reverts and
BLOCKHASH. It exercises accepted/skipped candidates, stale tokens and invalid
prefixes. A separate test drives the generic trait's finish over actual revm
`State`, materializes its plain bundle changes, and reconstructs the matching V2
root/head. Trusted domain initialization, node storage/consensus, pool/RPC and
the end-to-end developer workflow remain open.

## Full Reth primitive/configuration adapters

`BlochNodePrimitives` supplies tagged V2 headers, bodies and blocks. Header sealing
uses the existing V2 golden hash. Internal serde uses bounded canonical RLP bytes;
header Compact storage uses the same tagged RLP. The infallible Compact interface
panics on corrupt input; the database Decompress implementation is fallible and
rejects malformed/trailing bytes, as do network and serde decoding.
These are internal representations, not an Ethereum JSON-RPC response schema.

Reth's compactable signed transaction is `EthereumTxEnvelope<TxEip4844>` and its
receipt is `EthereumReceipt`. `BlochRethBlockExecutorFactory` adapts these through
the existing V2 executor, preserving supported signed bytes, typed receipt roots
and session/generation checks. It does not enable blob transactions or sidecars.

`BlochEvmConfig` implements actual `ConfigureEvm` with `BlochNextBlockEnvCtx`
attributes. `BlochNodeBlockAssembler` reconstructs the head already committed in
the bundle over original provider storage, verifies parent/body/receipts/context,
and attaches the independently calculated root. It does not modify state after
root calculation. `tests/node_config.rs` exercises these interfaces against a real
signed execution and State bundle, with a fixture provider for original state.
`tests/node_primitives.rs` qualifies canonical bytes, sealing, bounded decoding,
serde, Compact and receipt conversions.

`BlochChainStorage` now supplies custom `BlockBodyReader`/`BlockBodyWriter`
integration to persist deposits alongside the separately stored transactions.
The Ethereum body projection omits those deposits and must never replace the
canonical Bloch body in storage.
Launched import/fork-choice integration, process-crash recovery and developer workflows
remain unqualified.

## Durable V2 body storage

Initialize the database with `reth_db::mdbx::init_db_for::<_, BlochTables>` before
sharing it; this registers the standard Reth tables and `BlochV2Deposits` together.
Reopen using the same table set. `BlochChainStorage` implements the actual provider
chain-storage trait and stores deposits in the surrounding Reth transaction.
Signed transactions remain the responsibility of Reth's transaction storage.

Records are bounded canonical deposits-only body encodings, keyed by height.
An empty deposit list is written explicitly. Missing/corrupt rows are errors;
reads reconstruct the body and compare transaction/deposit roots with the header.
Duplicate heights or conflicting existing deposits fail before body writes;
identical records are idempotent. Replacing a different body requires prior unwind.
These checks do not establish L1 provenance or replace consensus validation.

`remove_block_bodies_above` deletes only deposit rows and propagates decode/cursor
errors. Abort the entire database transaction on a write/removal error. It does not
remove headers, transaction indices, receipts or execution state by itself.
`tests/node_storage.rs` uses actual MDBX and close/reopen to qualify persisted V2
headers/transactions/deposits, reconstructed body commitments, dropped writers/removals,
committed removals and corrupt records. The full canonical test described below
covers orderly unwind; process-crash recovery and a launched node remain open.

## Complete provider types and genesis

`BlochChainSpec::new(kernel_spec, domain, timestamp)` derives an immutable,
zero-issuance genesis allocation with system bytecode and V2 head storage. Its
header/hash use the custom V2 format; base-fee calculation delegates to the
kernel, including saturation at the integer boundary. Cancun describes EVM
semantics without enabling blobs or Ethereum withdrawals. The caller must
authenticate the domain and L1 inputs separately.

`BlochNodeTypes` selects those rules, Bloch primitives, `BlochChainStorage` and
`BlochPayloadTypes` for a real Reth ProviderFactory. `tests/node_provider.rs`
loads the advertised allocation through Reth's actual trie, verifies its root,
persists the V2 genesis and state, closes all handles and verifies the block,
root and storage after reopening MDBX, RocksDB and static files.

`BlochBuiltPayload` and `BlochExecutionPayload` retain the canonical block and
deposits. `BlochPayloadAttributes` uses bounded deposits-only serialization and
a tagged build identifier binding the domain, parent, timestamp, randomness,
anchor and complete deposit sequence. Optional transport sidecars remain bounded
and unsupported by V2 execution. Payload traits do not constitute an Engine API,
payload-building service, consensus validation or signed developer workflow.

## Executed blocks for canonical persistence

`prepare_genesis(spec, provider)` derives the configured allocation on an empty
state snapshot, verifies its actual trie root and returns a complete executed
genesis. Save it through `SaveBlocksMode::Full`, including its empty receipts:
writing only the genesis block and state leaves receipt-file boundaries absent
and prevents the next full block save. The caller must also check that there is
no existing chain history; the state-root check alone does not prove that.

`execute_next_block(config, provider, parent, attributes, transactions)` runs the
signed V2 lifecycle on a consistent Reth snapshot and returns an actual
`ExecutedBlock<BlochNodePrimitives>`. It checks transaction resource bounds, the
parent's canonical seal and the snapshot root, executes authenticated transactions,
retains state reverts, computes the database trie root and assembles the block
from committed execution metadata. The returned block contains user receipts,
the state bundle and sorted hashed-state/trie updates for Reth's full writer.

The caller authenticates the parent, domain and deposit/anchor provenance before
calling this API. Failed preparation discards its provisional state. A successful
return does not commit storage or select a canonical head: those are separate
operations. The result does not reserve the canonical tip; the persistence
coordinator must ensure its snapshot's parent is still current before saving.
Use the complete Reth writer with `SaveBlocksMode::Full` to persist
all block and execution data together; body-only writes are insufficient.
Static files, RocksDB and MDBX have separate durability boundaries, so dropping
a writer after a full save is not a claim of cross-backend atomic rollback.

`tests/node_canonical.rs` uses these APIs with actual MDBX, static files and
RocksDB. It saves two signed V2 blocks containing deposits, contract deployment,
storage writes, logs, BLOCKHASH and a revert; compares their headers/receipts
with portable execution; reopens; calls `remove_block_and_execution_above(1)`;
commits and reopens again. It verifies the prior root, head, balance, nonce,
storage and bytecode, retained block/transaction/receipt data and removal of the
second block's hashes, transactions, receipts and deposits. Wrong snapshots,
invalid cached parent seals and late transaction failure leave persistent state
unchanged. This qualifies orderly persistence/unwind, not process-crash recovery.

## Received-block validation

`BlochConsensus` implements Reth's actual `HeaderValidator`, `Consensus` and
`FullConsensus` interfaces for Bloch primitives. It binds the exact configured
genesis/domain, verifies canonical seals and parent rules, authenticates bounded
signed bodies, checks deposit gas, and reconciles actual receipts, total/user gas,
receipt root and bloom. Unsupported requests, blob gas and block access lists are
rejected. Optional cached transaction/receipt commitments cannot override the
independently recomputed commitments. These traits do not establish L1 finality,
select fork choice or check an execution state root that is absent from their
post-execution inputs.

`validate_and_execute_block(spec, provider, parent, block, expected_attributes)`
adds received-block re-execution using the actual provider and compares the entire
header, including its state root. The expected timestamp, randomness, anchor and
deposit sequence must come from authenticated derivation outside the received
block. Passing the block's own fields as those expected inputs does not establish
their authenticity. Success returns an executed block for the full writer;
failure commits nothing. The caller still coordinates the canonical tip at save.

The canonical storage test now imports re-executed blocks before saving them and
rejects forged state/receipt roots and mismatched expected derivation inputs.
Trait tests separately cover malformed parent/genesis/body data, invalid receipts,
unsupported extensions and poisoned commitment hints. A launched import pipeline,
authenticated L1 derivation and fork-choice integration remain required.
