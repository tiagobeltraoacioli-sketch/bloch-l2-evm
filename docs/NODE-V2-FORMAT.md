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
serde/Compact and Reth primitive traits still require separate qualification.

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

## Remaining integration

V2 finalization must calculate transaction/receipt commitments and store the
metadata needed to reconstruct this exact header **before** calculating the
post-state root. The assembler receives an already-calculated root and cannot
repair missing commitments afterwards. Neither the current block hash nor its
post-state root may be stored inside that same post-state, which would create a
hash cycle. Domain identity can come from authenticated configuration; persisting
an identity that itself commits the genesis root inside genesis state would also
create a cycle and must be avoided.

Required next steps are a V2 genesis/head layout and execution-domain identity,
portable and witness lifecycle integration, Reth primitive/Compact traits,
configuration and assembler, custom consensus and receipt/RPC semantics, durable
canonical unwind, and the full signed developer workflow. V1 identities and
production consensus remain unchanged. Format changes require distinct version
and domain commitments rather than silently reinterpreting existing blocks.
