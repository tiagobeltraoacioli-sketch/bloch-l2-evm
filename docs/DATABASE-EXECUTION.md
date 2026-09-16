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
tests check both forward and restored roots. Actual Reth trie calculation and
durable database commits/recovery remain unimplemented. Neither layer implements
incremental block building, a transaction pool or RPC. The API does not change
the existing header hash, domain identity or portable dependency/toolchain pins.
