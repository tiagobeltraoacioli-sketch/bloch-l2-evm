# Generic signed database execution

`execute_signed_block_on_database` allows node/storage integrations to use the
existing Bloch execution kernel without copying the entire backing database into
`L2State` or duplicating its state-transition rules. It requires `DatabaseRef`,
an immutable pre-state snapshot and its trusted root, plus the original signed
block input. It performs the existing signature/resource validation before
calling the same kernel as `execute_signed_block` and witness re-execution.

The returned `DatabaseBlockExecution` owns a fresh `CacheDB` overlay. Errors
discard that overlay; no backing commit method is called. The public interface
offers read-only overlay inspection and consuming `finalize(post_state_root)` to
return the overlay and the usual `ExecutionOutcome`. Accounting and header
context are private and cannot be replaced after execution.

Both roots are host trust boundaries: this API neither proves the pre-state nor
checks the supplied post-state root. The host must calculate the full MPT root,
respect deletion/storage-clearing/EIP-161 semantics and commit the matching state
atomically. Interior read-cache updates in a `DatabaseRef` implementation remain
possible; the host must prevent concurrent changes to logical snapshot state.
Deposits and L1 context likewise require authentication outside this interface.
Use witness/domain verification for untrusted inputs needing authenticated roots.

Differential tests in `tests/database_execution.rs` reconstruct a complete fixture
state through overlay reads and independently calculate its root before comparing
the ordinary host execution. The fixture spans signed deployment and a storage
call reading `BLOCKHASH`, another contract deployment, and a reverting call.
They compare roots, custom header hashes, gas, outcomes, fee vaults and supply.
A second scenario prefunds a future contract address and executes signed
creation with self-destruction, checking nonzero burn and deletion. Both scenario
roots are pinned across the portable and Reth-host builds. Separately,
late invalid transactions and malformed signatures must leave backing state
unchanged. This full-fixture enumeration is a test oracle, not a scalable node
state-root implementation.

The [Reth provider adapter](../integrations/reth-execution/README.md) uses this
entry point with upstream's actual database reader. Its `execution_bundle`
converts the successful overlay to upstream state changes and reverts; fixture
tests check both forward and restored roots. A separate real-storage test checks
Reth trie calculation, commit/abort and orderly close/reopen against signed
execution. These storage operations are test-harness plumbing, not a node
service; canonical unwind and crash recovery remain unqualified. Neither layer implements
a transaction pool or RPC. The API does not change
the existing header hash, domain identity or portable dependency/toolchain pins.

## Incremental signed construction

`SignedBlockBuilder::new(spec, database, previous_root, context, deposits)`
begins a block over an immutable host snapshot. It validates the header and runs
system/deposit transitions once. `try_push(raw)` authenticates original signed
bytes and includes a valid candidate. `try_push_with_condition(raw, include)`
lets the caller inspect its outcome and decline inclusion. Reverted EVM
transactions are valid candidates and pay gas if included.

Every candidate executes in a fresh sparse overlay over the accepted state.
Conservation and fee-vault reads/credits complete before that overlay is merged.
An error or declined inclusion preserves nonce, storage, gas, fees and burn
accounting. Merge retains untouched slots and deletion/clear markers; it does
not clone the entire block cache or re-execute the accepted transaction prefix.
The EVM context is rebuilt per candidate; no throughput claim is made here.

`finish()` performs final ledger/head writes and returns the exact accepted
`SignedBlockInput` plus `DatabaseBlockExecution`. Compute and persist its root
through the same host boundary as whole-block execution. Finishing does not
authenticate a root, and dropping the builder never writes the backing store.

The whole-block verifier now uses this same incremental kernel, while retaining
whole-input preflight and failing the entire block on any invalid transaction.
The builder instead allows selection to continue after a rejected candidate.
Its lifetime decoding budgets count rejected and skipped candidates too: at
most `MAX_SIGNED_TRANSACTIONS` decoding attempts and `MAX_SIGNED_BLOCK_BYTES`
candidate bytes, after per-transaction size preflight. Exhaustion stops further
decoding but still permits finishing the accepted block. Pool scheduling and
network rate limiting are separate host responsibilities.

`tests/incremental_builder.rs` checks selection, skips, reverted execution,
invalid nonce, gas-budget recovery, self-destruction and bounded authentication
work against whole-block execution. Executor units cover sparse merge flags
and a late provider failure during fee-vault credit. The real Reth persistence
test uses `begin_on_provider`, skips and then includes the same signed candidates,
and checks independently calculated/persisted roots and orderly reopening.
