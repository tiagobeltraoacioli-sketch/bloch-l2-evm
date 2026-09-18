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

## Preparing effects for a supplied EVM

`prepare_transaction_effects` separates protocol accounting from ownership of
the EVM. It accepts an actual matching revm `ResultAndState`, transaction,
base fee and mutable `Database`, reads the original balances, checks conservation
and prepares vault credits. It returns an owned `PreparedTransaction` without
committing anything. `outcome()` permits inspection; dropping the value discards
the effects. `commit(db)` performs no reads and returns `CommittedTransaction`
with the outcome and fee accounting.

Two ordered state updates preserve the case where the EVM destroys the fee
vault and the protocol then recreates it to receive fees. A vault created by the
transaction keeps its new storage when the subsequent fee credit is applied.
`BlockSession` uses this same preparation path; a host executor must not duplicate
its fee and burn rules.

This is a low-level trusted-backend interface. It does not authenticate signed
bytes, prove the result, enforce block gas limits, or bind a prepared value to a
particular database/session. The caller must keep the logical pre-state unchanged
between execution, preparation and commit. A split SDK execute/commit adapter
must also reject stale or foreign prepared results before publishing effects.

`tests/prepared_execution.rs` uses a database that implements `Database` and
`DatabaseCommit` but intentionally not `DatabaseRef`. It checks preparation/drop,
read-free commit, late read failure, vault destruction/recreation and preservation
of newly created vault storage. This supplies the mutable database boundary
required by Alloy without introducing a second hidden EVM.
The host integration also exercises this phase using an actual Alloy factory,
inspector and revm `State`, including bundle generation. That test does not
establish a complete SDK executor factory or node lifecycle.

## Protocol lifecycle on a mutable database

`executor::lifecycle::prepare_block_start` validates the supplied `BlockInput`
and stages header/ring updates plus beacon-account installation. Committing it
returns `PendingSystemCall`. Install its `block_hashes()` snapshot in the supplied
EVM before any system call: the portable kernel freezes this window before
beacon/deposit/user execution, so later writes to the live ring must not change
BLOCKHASH results. Run EIP-4788 through that actual supplied EVM, then
pass its uncommitted result to `complete`: a successful result commits before
all deposits are staged and committed together. This returns `ActiveBlock`.

For each authenticated candidate, call `validate_transaction` before execution,
then `prepare_transaction` with its matching result. The prepared candidate
borrows the originating block's accounting until it is dropped or committed;
commit advances gas, fees and burns once. `prepare_finish` stages burned supply
and the final head together; commit returns `FinishedBlock`, whose `finalize`
attaches the independently calculated post-state root.

These phases share header, deposit, fee, burn and final-head helpers with the
portable kernel. A private mutable-read bridge temporarily stages the existing
CacheDB helpers, then emits sparse owned state transitions. It preserves original
storage, zero writes, code and deletion/recreation; commits perform no reads.
Unchanged canonical entries are filtered, while loaded EIP-161-empty records
are pruned consistently with the portable overlay merge.

The caller must use a provisional database and discard the whole block on any
later failure. Arbitrary `DatabaseCommit` cannot roll back a previously committed
phase, and beacon execution needs the preceding installation to be visible.
The types enforce phase order, not EVM/result authenticity or database identity.
The borrowed candidate prevents reuse across accounting sessions, but callers
must still preserve its logical database pre-state. An SDK adapter requiring
owned `'static` candidate results needs its own session/generation protection.

`tests/protocol_lifecycle.rs` covers start/drop/read failure, unsuccessful actual
system execution, a late deposit failure without partial mint/cursor writes,
and final-head read failure without publishing a staged burn. The host's
`sdk_lifecycle` executes five signed blocks using the real Bloch SDK factory,
inspector and both InMemoryDB and revm State. Roots, headers, accounting and
results match the portable kernel, and State's account/storage/code changes
match the portable execution bundle. This is not a BlockExecutorFactory or node.

## Owned SDK candidates

`ActiveBlock::prepare_owned_transaction` returns the same read-complete
`PreparedTransaction` without borrowing block accounting. This is a trusted
adapter API: `commit_prepared_transaction` assumes the adapter has checked the
originating session and unchanged database generation. The borrowed API delegates
to these shared methods. `result_and_state` and `into_result_and_state` expose the
original EVM result before protocol fee routing; extracting it consumes the token
and discards the prepared fee effects. The original EvmState is stored once;
only execution-result metadata is cloned for the existing TxOutcome view.

The real host `BlochBlockExecutorFactory` supplies the required owned-token
checks with an Arc session identity and checked generation. Results are Send and
'static, but cannot be constructed or cloned externally. Mutable EVM access and
accepted commits invalidate outstanding results. A rejected commit poisons the
executor so its finalization cannot silently succeed. Direct callers of the low
level core API must provide equivalent protection themselves.

## Explicit V2 lifecycle

`prepare_node_block_start(spec, domain, db, previous_root, input)` selects V2
header reconstruction and returns the same staged system-call/deposit/candidate
phases. Its `ActiveBlock` must be finalized with `prepare_node_finish(db, body)`;
V1 and V2 finalizers reject each other's active blocks before any final writes.
The accepted signed body is authenticated again, and its deposit commitment and
transaction count must match the run. Low-level backend callers remain responsible
for pairing the exact signed bytes with the committed execution results.

The finish preparation derives receipts and commits their roots, transaction root,
user gas and bloom in the V2 head before a post-state root is calculated. Both burn
accounting and head writes are staged together. `PreparedNodeBlockFinish::receipts`
allows the SDK adapter to compare its accumulated receipts before committing;
commit performs no database reads. `FinishedNodeBlock::finalize(root)` trusts the
caller's independently calculated root. Tests cover late head-read failure after
burn preparation, wrong final body, cross-version finalization and read-free commit.
