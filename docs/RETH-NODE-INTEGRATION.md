# Reth node integration boundaries

This is an implementation dependency map, not evidence that a node exists.
It refers to Reth revision `8eb210175687c9f0c889a3b6795c16781d830e3a` and the
separately pinned host integration in `integrations/reth-execution`.

## Storage before node launch

The implemented boundary executes original signed envelopes over
`StateProviderDatabase` and converts successful execution to `BundleState`.
The storage test now uses Reth's actual database provider to
calculate `state_root_with_updates` over the hashed bundle, write plain
state and reverts, write hashed state and trie updates, and commit the same
transaction. Fresh and reopened providers expose the identical root and values
for the exercised signed deploy/set/clear scenario. This remains test harness
plumbing rather than a node storage service.

Retain the original snapshot until root calculation and revert capture finish.
On any error, abort the candidate transaction. Uncommitted transaction drop,
successful commit and orderly close/reopen are exercised. A signed self-destruct
test also deletes unread storage, then restores the original state root using
only persisted changesets after reopening. It retains history; canonical unwind
still needs block metadata and custom primitives. Existing execution-boundary tests
reject malformed input but do not replace those storage gates. A new
read transaction proves visibility after commit but does not prove process
restart recovery. Synthetic funding in these tests is not authenticated native
derivation.

## Executor and builder

Reth's `ConfigureEvm` requires a `BlockExecutorFactory`, a `BlockAssembler`,
custom node primitives and block/next-block context. The pinned Alloy executor
also exposes transaction execution before conditional commitment. Bloch's
current whole-block entry point cannot simply be substituted for that interface.

Extract an incremental implementation from the shared core kernel, then retain
whole-block execution as a consumer of it. The same implementation must perform
header validation, committed `BLOCKHASH` history, EIP-4788, ordered deposits,
fee-vault credits, burn accounting and final head writes. Do not duplicate these
rules in a host-only Ethereum executor. A rejected candidate must leave nonce,
storage, gas, receipts, fees and supply unchanged; a reverted EVM transaction is
instead included and pays gas. Compare whole-block and incremental execution on
the existing signed fixtures before wiring payload selection.

The current whole-block kernel can discard its entire overlay after a late
accounting error. It commits each revm transaction result before checking
conservation and crediting the base-fee vault; that ordering is safe only under
the enclosing all-or-nothing block boundary. The incremental API must validate
and prepare all effects before publishing a candidate, including provider reads
needed by fee accounting. Do not copy that commit ordering into Reth's
infallible `commit_transaction` method or continue a builder after a partially
applied accounting failure.

Pool recovery is not an authentication boundary. Admission and execution must
retain canonical signed bytes; reauthenticate them rather than trusting a
cached sender or an independently supplied transaction environment. RPC call
simulation must use the same hardfork, fee recipient and Bloch block context,
while keeping its state changes ephemeral.

## Header and receipts require a new domain

The current `L2Header::hash` hashes a fixed-width 200-byte encoding, including
deposits and state roots. `HeadRecord` stores the fields needed to reconstruct
that hash using the containing state root. It does not store transaction or
receipt roots. Ethereum's ordinary RLP header has a different identity.

Custom primitives must preserve the existing identity for the existing domain.
Adding transaction/receipt commitments requires a separately versioned execution
domain and explicit migration, including head storage, reconstruction, witness
execution and public inputs. Extra RPC fields cannot supply those commitments.
No current domain or production consensus is activated by this integration.

Define the new header/body/receipt format before implementing its assembler.
In particular, Bloch block gas currently includes deposit gas, while deposits
are not Ethereum signed transactions. The new format must specify deposit body
representation, receipt indexing and cumulative gas semantics together. Do not
invent ordinary Ethereum receipts for deposits, or silently omit deposit gas to
fit an Ethereum header. Logs and outputs are already available in `TxOutcome`;
they still need canonical receipt encoding and committed ordering.

## Acceptance evidence

A developer acceptance run must start the custom Reth node, submit a signed
deployment through its real RPC/pool, call the contract, inspect receipts/logs
and storage, restart, and repeat the reads. It must reject malformed/replayed
transactions, preserve state after rejected payloads, and exercise reorg/unwind.
The native derivation and proof gates in [the delivery plan](EVM-DELIVERY-PLAN.md)
remain separate requirements. Compiling or launching upstream's `custom-evm`
example does not close any Bloch-specific node gate.
