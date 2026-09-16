# Experimental V2 node format

`node_primitives::{NodeHeaderV2, NodeBodyV2, NodeBlockV2}` defines an independent
format for the developer node. It is not activated by an existing execution
domain. The current executor, head record, BLOCKHASH and witness verifier still
use the unchanged V1 200-byte header. These codecs and consistency checks do not
establish V2 execution, L1 provenance, state-root correctness or node readiness.

## Canonical encoding

All containers use canonical RLP lists. Integers are unsigned and minimally
encoded (zero is the empty byte string); addresses, hashes and bloom values use
their exact byte widths. Tags are literal UTF-8 byte strings. Unsupported tags,
noncanonical RLP, extra fields and truncated items fail. Decoders consume exactly
one item from a stream and leave the caller's input unchanged on error. A network
message decoder must additionally reject a remaining tail when one item is expected.

The header list contains these items in this exact order:

| Item | Encoding / meaning |
| --- | --- |
| `BLOCH:EVM:HEADER:2` | Format tag |
| `domain` | 32-byte separately configured V2 domain identity |
| `chain_id` | u64 signed-transaction replay domain |
| `number` | u64 block number |
| `timestamp` | u64 timestamp |
| `base_fee_per_gas` | u64 Bloch EIP-1559 base fee |
| `gas_limit` | u64 total block budget |
| `gas_used` | u64 deposits plus user gas |
| `user_gas_used` | u64 cumulative user gas |
| `beneficiary` | 20-byte sequencer fee vault |
| `prevrandao` | 32 bytes |
| `anchor_root` | 32-byte Bloch anchor for EIP-4788 |
| `parent_hash` | 32-byte V2 parent header hash |
| `parent_state_root` | 32-byte parent post-state root |
| `transactions_root` | 32-byte ordered transaction MPT root |
| `receipts_root` | 32-byte ordered user receipt MPT root |
| `deposits_hash` | Existing canonical Bloch deposit-list commitment |
| `logs_bloom` | 256 bytes |
| `state_root` | 32-byte post-state MPT root |

The block hash is Keccak-256 of this entire tagged header RLP. An Ethereum header
projection is not the block's identity. The fixed-width header decoder has a
1024-byte payload ceiling and never allocates from a declared field length.

The body is `[BLOCH:EVM:BODY:2, deposits, transactions]`. Each deposit is a list
`[recipient, l1_height, l1_tx_index, l1_txid, l1_vout, l1_sats]`, with widths
20 bytes, u64, u32, 32 bytes, u32 and u64 respectively. Transaction entries are
RLP **byte strings** containing canonical signed EIP-2718 envelopes, including
legacy transactions. This is deliberately a custom body, not an Ethereum body
list. The body has at most 4096 transactions, 128 KiB per envelope, 16 MiB of
aggregate envelope bytes, and 65535 deposits; chain-specific deposit gas limits
also apply. Declared lengths and counts are checked before copying entries.

The block is `[BLOCH:EVM:BLOCK:2, header, body]`. The outer bound includes both
bounded nested containers and framing. RLP is the implemented wire codec;
the host adapters additionally implement Reth primitive traits and bounded internal
serde. Header `Compact` storage is exactly the tagged header RLP, without a second
hash or field layout. The infallible upstream Compact reader panics on corrupt input. The database
`Decompress` implementation instead returns an error on malformed or trailing
bytes; network/serde decoders also return errors.

## Commitments and validation

The transaction root is an ordered Keccak MPT with RLP-encoded indices as keys
and exact signed envelope bytes as values. The receipt root uses the same ordered
trie rule with canonical typed receipt envelopes. Deposits retain the existing
`deposits_hash` function and are not disguised as signed Ethereum transactions.

`validate_commitments` authenticates the body through the shared bounded signed
decoder, checks deposit order/caps, and reconciles transaction/deposit roots,
receipt count and types, boolean receipt status, blooms and gas. Each user receipt
must advance cumulative user gas by a positive amount no greater than the signed
transaction gas limit. Total header gas equals final cumulative user gas plus
`deposit_count * spec.deposit_gas`, within the block limit. A deposit-only block
has no user receipts. Receipt/state execution correctness still requires actual
re-execution; internally consistent synthetic receipts are not a proof.

`validate_parent` checks parent hash and state root, domain/configuration, height,
timestamp and next base fee. It assumes an already authenticated parent and
does not invent a genesis or migration rule. The explicit `parent_state_root`
allows Reth's provider-free `ConfigureEvm::context_for_block` to obtain the core
lifecycle's previous root. Consensus must compare it with the actual parent.

The header golden encoding is independently generated in
[`node_header_v2.hex`](../tests/fixtures/node_header_v2.hex), with hash
`a2aac0c50e8af78ca7781c6e7fcc62bdf2f85e9f5a3f656834aad348bed967e9`.
Tests bind every header field, exercise stream boundaries and malformed inputs,
check body golden vectors and trie roots, and reject commitment/gas mutations.

## Explicit V2 execution and state

`node_execution::genesis_v2(spec, timestamp)` creates zero-issuance block-zero
metadata before calculating the genesis root. Slot 0 at `spec.block_info` is
exactly 2. Slots 1–8 retain the V1 field order; slot 9 stores user gas, slot 10
parent state root, slots 11–12 transaction and receipt roots, and slots 13–20
the bloom's eight big-endian words. The history ring remains at 0x100–0x1ff.
V2 reads reject missing/wrong version flags and integers wider than u64.
V1 decoding and hashing rules remain unchanged.

Genesis has initial base fee, zero gas, empty transaction/receipt tries and an
empty parent state root. Its first child uses `next_base_fee(initial_base_fee, 0)`.
Use `node_head(spec, domain, &state)` to reconstruct its V2 header; V1
`L2Header` helpers do not define the V2 identity. Domain is supplied by trusted
configuration and is not stored in genesis. Domain
initialization must bind the resulting genesis root without introducing a cycle.
The execution API does not authenticate an arbitrary caller-supplied domain.

`execute_node_block` authenticates bounded signed bytes and uses the shared
transaction kernel, deposit rules, system call, fee routing and burn accounting.
It reconstructs the V2 parent from committed metadata and the previous root,
then freezes the BLOCKHASH window before executing system calls and transactions.
Typed receipts come from actual execution. Transaction/receipt roots, user gas
and bloom are committed in head storage before calculating the post-state root.
Any execution failure discards the overlay without publishing partial changes.
Neither a block's own hash nor its own post-state root is stored in that state.

`generate_node_batch_witness` records a sparse execution and self-checks it with
`verify_node_batch`. These explicit V2 entry points share proof hydration and
root reconstruction with V1, but execute the V2 header policy. The verifier
reauthenticates signed bytes, rejects reads outside the witness and recomputes
the root containing the V2 metadata. This is a verifier procedure, not an SP1
proof implementation; callers must authenticate L1 deposit provenance.

## Supplied-EVM lifecycle

`executor::lifecycle::prepare_node_block_start` selects the same V2 parent policy
for a caller-owned provisional database. The pending system-call phase exports
the frozen BLOCKHASH window. Candidate preparation and fee accounting reuse the
same `ActiveBlock` as V1. `prepare_node_finish` authenticates the accepted body,
checks deposit commitment and transaction count, builds receipts from committed
execution results, and stages burn-ledger/head changes together. The caller must
retain the exact signed bytes corresponding to those results; this low-level API
is a trusted backend interface. Using the wrong version's finalizer is rejected.

`PreparedNodeBlockFinish` exposes derived receipts before its read-free commit.
`FinishedNodeBlock::finalize(root)` attaches an independently calculated root.
Dropping prepared changes publishes nothing; after any failure following an
already committed phase, discard the entire provisional block database.

The host `BlochNodeBlockExecutorFactory` binds a trusted domain and connects these
phases to the actual supplied Alloy EVM and inspector. It retains canonical signed
bytes only for accepted candidates and verifies SDK receipts against core receipts
before publishing final metadata. `finish_node` preserves the V2 root-pending
outcome; the SDK trait's `finish` executes the same writes and returns its normal
EVM/block result. The candidate budgets, lease/generation guards, environment
checks and immutable BLOCKHASH window are shared with the V1 factory.

## Reth primitive and assembler boundary

The host exports `BlochNodeHeader`, `BlochNodeBody`, `BlochNodeBlock` and
`BlochNodePrimitives`. Their encodings match the portable V2 codecs byte-for-byte;
sealing invokes the V2 hash. The body retains immutable original signed bytes
alongside parsed transactions. Its Ethereum RPC projection omits deposits and
must never be used for storage or hashing. A deposit-only header is not empty.

Reth full-node traits require `EthereumTxEnvelope<TxEip4844>` and
`EthereumReceipt`, rather than the standalone executor's sidecar-capable
`TxEnvelope` and `ReceiptEnvelope`. `BlochRethBlockExecutorFactory` adapts these
representations through the same signed authentication and owned-token checks.
Supported transaction bytes and typed receipt roots remain identical. These
representation types do not enable blob transactions on Bloch.

Internal serde serializes bounded canonical RLP bytes, not Ethereum JSON objects.
Decode checks the byte cap and rejects trailing content. The header uses the
existing golden vector across RLP, sealing, serde and Compact. Custom RPC response
conversion remains separate from the durable body storage described below.

`BlochEvmConfig` implements pinned Reth `ConfigureEvm`: environments use trusted
specification/domain and canonical Bloch fields; incoming contexts use the explicit
parent state root and authenticate body commitments. Next-block attributes carry
host-authenticated timestamp, randomness, anchor and deposits. This does not
independently authenticate L1 provenance or import consensus.

`BlochNodeBlockAssembler` reads the final head through the execution bundle over
the original provider, including storage wipe/deletion semantics. It compares that
committed header against parent, environment, accepted body, receipts and total
gas, then attaches the builder's independently calculated root. It never writes
metadata after root calculation. Tests assemble an actual signed execution bundle
and reject inconsistent environment, metadata, body and execution output. The
assembler trusts the supplied root; imported-block post-execution validation is
still a separate consensus gate.

## Durable body records

`BlochChainStorage` implements Reth's chain storage and body reader/writer traits.
`BlochTables` registers standard Reth tables plus `BlochV2Deposits`, keyed by block
number. Its value is canonical V2 body RLP with an empty transaction list and a
strict deposits-only byte/count bound. Every available body has a record, including
an explicit empty deposit list. Missing or corrupt records are errors.

The reader combines persisted deposits with the transactions prefetched by Reth,
checks transaction/deposit roots against the supplied header, and reconstructs the
canonical body. Storage checks do not authenticate signatures, L1 provenance or
header consensus; those remain admission/execution/consensus responsibilities.
The writer preflights duplicate heights and conflicts before mutations. Identical
replay is idempotent; replacing different deposits requires explicit prior unwind.

`remove_block_bodies_above` removes only deposit rows above the requested height,
propagating cursor and decode errors. It does not silently interpret corruption as
successful removal. The caller must abort the surrounding database transaction on
any failure. Real MDBX tests qualify close/reopen, reconstructing the body from persisted
headers, signed transactions and deposits, transaction rollback, commitment
mismatches and committed body removal. This is
not a complete canonical state/header/receipt unwind or process-crash qualification.

## Remaining integration

Required next steps are authenticated execution-domain initialization, full
provider/node wiring, custom consensus and receipt/RPC semantics,
durable canonical unwind, and the full signed developer workflow. V1 identities
and production consensus remain unchanged. Format changes require distinct
version and domain commitments rather than silently reinterpreting existing blocks.
