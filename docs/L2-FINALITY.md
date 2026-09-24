# L2 finality boundary

`eth_getBlockByNumber("finalized")` must remain `null` until a native Bloch
checkpoint proves a consensus-enforced settlement of a specific L2 block. An L2
header merely referencing an old native block is not settlement of that L2
header.

The implemented `l1::authenticate_ancestry` verifies the complete 304-byte
Genesis-4 parent path from a selected native anchor to an externally
authenticated checkpoint. `l1_context::authenticate_l1_context` then binds the
exact V2 L2 header hash, state root, chain ID 700771 and execution domain to that
anchor. Its result is deliberately named `AuthenticatedL1Context`, not a
finalized L2 block.

## Required path to a standard finalized tag

1. Pin native network/genesis identity and authenticate a non-regressing native
   checkpoint independently of the proposer and public L2 RPC.
2. Obtain all raw native headers from the L2 anchor through that checkpoint and
   verify their hashes, parent links and slots with `authenticate_ancestry`.
3. Qualify a consensus-available proof transport. Current saved SP1 Core proofs
   are approximately 2.8 MiB, while the native block transaction budget is at
   most 512 KiB; a proof hash or node-local RPC side channel is not data
   availability. Use a reviewed succinct proof, a consensus-committed DA
   sidecar, or a separately qualified coordinated block-format change.
4. Verify a consensus-enforced native settlement record that commits the exact
   L2 V2 header hash, post-state root, execution domain, proof/program identity
   and consumed source cursor. A plain native transfer or arbitrary hash in a
   transaction is not such a record.
5. Verify the execution proof and source/deposit mapping, then atomically append
   the settlement to a durable, rollback-detecting monotonic cursor.
6. Expose only the exact cursor tip and its ancestors through Ethereum's
   `finalized` tag. Missing, stale, conflicting or regressing evidence returns
   `null` and disables bridge mint/release, DEX liquidity and aggregator
   execution.

## Current status (2026-09-23)

The public Genesis-4 RPC reports a corroborated finalized block and exposes its
ID, slot, height and header commitments. Its `getblockbyid` response does not
provide the canonical 304-byte header, complete body, validator votes or a proof
of the checkpoint authority required by the local verifier. More importantly,
no active native transaction/state transition currently settles the L2 header
and proof. Operational RPC agreement therefore remains diagnostic evidence only.

The currently published `https://blochdex.com/rpc` endpoint identifies chain
84001 and remains at block zero. It returns the same genesis block for `latest`,
`safe` and `finalized`; that is not progress or production finality. The server
reserved for chain 700771 has no L2 node or RPC listener running. Do not replace
authenticated settlement with `latest`, a fixed depth, an L1 anchor
classification, a genesis-only tag or a threshold signature that lacks native
settlement inclusion.

The pinned SP1 6.8.0 SDK exposes a Groth16 wrapper whose encoded proof is 352
bytes (356 bytes with the verifier-key prefix), so a succinct in-block route is
plausible without raising the native block cap. The optional host now contains
a concrete `SettlementProofVerifierV1` adapter that pins the complete wrapper
key, trusted guest identity, exact 590-byte public values and canonical proof
transport, and invokes the real Groth16 verifier. A separate V2 journal provides
bounded fsync-before-publication framing and full Groth16/source replay, while
the synthetic settlement V2 harness can request and verify a wrapper offline.
These pieces have not passed the required genuine native source, validator and
complete operational qualification. The harness is not a native transaction or
consensus verifier, and its fixed source/anchor inputs are not authenticated
native state. The native consensus path still has no activated deterministic
transition. The `settlement-proof-transport-qualified` requirement therefore
remains false until completed generation, tamper, replay, resource and validator
tests are retained as reviewed production evidence.

On 2026-09-21 the release-only local CPU harness generated, persisted and
independently reverified a real Groth16 wrapper for the exact reviewed host
revision with a digest-pinned Gnark container. The non-authorizing artifact
record is retained in
[`network/evidence/settlement-v2-synthetic-groth16-20260921.json`](../network/evidence/settlement-v2-synthetic-groth16-20260921.json).
It improves toolchain evidence only: the fixture has an empty synthetic source,
so it does not satisfy any readiness requirement or permit activation.

On 2026-09-22 the pinned harness also generated and independently verified a
nonempty synthetic `source-contract` proof with one inbox item and consumed
cursor `0..1`. Its record is retained in
[`network/evidence/settlement-v2-synthetic-source-contract-groth16-20260922.json`](../network/evidence/settlement-v2-synthetic-source-contract-groth16-20260922.json).
The source, ancestry and escrow remain synthetic, so this still does not satisfy
native authentication, proof transport, inclusion, validator replay or public
finality requirements.

The machine-readable gate is [`network/finality.json`](../network/finality.json).
Every satisfied requirement must carry a dated SHA-256 evidence reference;
product permissions cannot become true while any requirement is open. Validate
the checked-in state with:

```sh
python3 tools/check-finality-readiness.py
python3 tools/check-finality-readiness.py --require-ready  # expected to fail now
```

## Exact native transaction inclusion primitive

`l1::authenticate_exact_transaction` now derives an
`AuthenticatedTransactionInclusion` only from a complete body already checked
by `authenticate_body`. It requires nonempty exact bytes, one and only one
occurrence, and retains the committed block, slot, transaction index and
checkpoint. The capability is deliberately non-cloneable; durable replay
prevention still requires a consensus-owned settlement nullifier. Missing
bytes, duplicates and bodies changed by omission, reorder
or mutation fail closed.

This closes only the byte-inclusion subproblem. The primitive deliberately does
not hash the bytes under an invented transaction-ID rule and does not interpret
the dormant experimental settlement payload. Until native consensus assigns a
reviewed settlement transaction/state transition and validators execute its
proof, inclusion of arbitrary bytes is not `native-settlement-consensus-active`
or `l2-settlement-inclusion-verified`, cannot advance a finality cursor and must
not populate Reth's `finalized` head.

The dormant `native_settlement` V1 kernel closes a narrower transition-shape
gap: it has fixed canonical framing, pinned policy/program identities, exact
consensus-selected statement comparison, deterministic proof-verifier input,
replay-safe predecessor/cursor checks and atomic in-memory publication. The
`settlement_admission` adapter composes that kernel with exact authenticated body
inclusion and binds the distinct earlier source anchor to the later containing
block. The optional Unix store adds single-writer, create-once snapshots, CAS
marks and an externally retained rollback floor. Neither component supplies a
Genesis-4 transaction decoder/state key, checkpoint authority, consensus-owned
expectation construction, validator execution, distributed durability, reorg
handling or conformance evidence. Consequently they do not satisfy
`native-settlement-consensus-active`, `l2-settlement-inclusion-verified` or
`settlement-cursor-durable`, and RPC `finalized` remains `null`.

The separate native-PQ integration can now consume its real hybrid-quorum
`VerifiedCheckpoint` and produce a non-cloneable settlement package only when
that signed anchor matches the complete ancestry/body envelope and exact
settlement expectation. It also emits a fixed audit receipt binding policy,
checkpoint digest and freshness epoch. This closes an in-process capability
composition gap. The authority receipt and complete inclusion evidence are now
atomic in `BLSTRC04` and dual-store recovery rechecks the independent signed
checkpoint history. That history remains a separate rollback domain and the
signer policy is still a weak-subjectivity trust input, not consensus activation
or independent FFG proof. This changes no readiness requirement or product
permission.

## RPC tag qualification

The presence of `safe` or `finalized` tags is not finality evidence by itself.
A static or genesis-only endpoint can return block zero for all three tags while
making no progress and authenticating no settlement. The diagnostic probe:

```sh
python3 tools/check-finalized-rpc.py --rpc-url https://example.invalid/rpc
```

requires the reviewed chain ID, a finalized block strictly above genesis,
`latest >= safe >= finalized`, and a stable reread of the finalized block by
number. It never changes `network/finality.json`, always reports
`permissionsOpened: false`, and does not replace native checkpoint,
settlement-proof, inclusion or consensus evidence.
