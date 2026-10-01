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
checkpoint history at the receipt's original freshness epoch, even after newer
checkpoints advance. That audit-only path rejects future-dated claims and cannot
produce a current anchor. The history remains a separate rollback domain and
the signer policy is still a weak-subjectivity trust input, not consensus
activation or independent FFG proof. This changes no readiness requirement or
product permission.

The integration now also has one fail-closed startup boundary that requires both
independently retained floors and exposes neither checkpoint nor settlement
store until their V4 authority relationship is reverified. This avoids a caller
accidentally recovering one rollback domain without the other; it is still local
recovery plumbing, not validator consensus or production finality.

## Proof-verified recovery (2026-09-30)

`SettlementStoreV1::open_verified` adds a strict recovery path that reruns
`verify_and_apply` with an independently selected `SettlementProofVerifierV1`
for every retained settlement. It checks the pinned policy, execution proof,
predecessor, consumed cursor and resulting head, including records before the
externally retained rollback floor. A valid floor does not skip earlier proofs.
The existing `open` API remains structural recovery and does not repeat proof
verification.

The caller supplies `maximum_proofs` in `0..=10_000`. Recovery refuses a larger
history before invoking the proof verifier; zero permits only the empty store.
Any invalid proof, inconsistent record or absent floor releases the recovery
lock without returning a handle or rewriting the stored history. The limit
bounds invocation count, not the runtime or resource usage of an arbitrary
verifier implementation.

The native-PQ integration's `open_proof_verified_authority_stores` composes this
path with the independently pinned checkpoint history. It now checks **every**
retained V4 authority receipt at its original freshness epoch, replacing the
earlier latest-receipt-only check. Both rollback floors are mandatory. Neither
store is exposed if any proof or historical authority binding fails. This is
weak-subjectivity authority replay, not a consensus execution audit.

The core `open_verified_with_audit` boundary exposes a borrowed record only
after proof, record-integrity and complete-inclusion checks. The PQ adapter
requires that record's receipt, independently retained signed checkpoint and
inclusion anchor to agree. Older V2/V3 entries are refused; a legitimate newest
receipt cannot conceal unauthenticated earlier entries. Refusal identifies the
record generation, releases both writer locks and preserves both histories.
The audit callback never publishes intermediate heads. An old checkpoint that
was valid at acceptance remains historical evidence only: current freshness is
still checked separately and no RPC finality capability is returned.

Replay derives each execution expectation from its retained statement and the
preceding registry head. It does not independently authenticate the source of
that statement, native consensus, or availability of a consensus proof
transport. Tests use a deterministic proof-verifier double to establish call
coverage and rejection, plus real hybrid signatures from disposable keys in
the PQ integration. A two-settlement regression covers a valid history and
eleven variants with unauthenticated or altered first records despite a valid
last record and rollback floors at the latest entries. No new genuine
Groth16/native-settlement proof was generated by this change. These results
qualify recovery behavior only and do not change
`network/finality.json` or grant a finalized-block capability.

The read-only server observation on 2026-09-30 found the isolated, unfunded
development node for chain 700771 running at block 212 with `finalized: null`.
Its pinned genesis is
`0xaec9844384415c8ba7157298fa13f7e6c951a6ba9332f516180a4aa22208fefa`.
This supersedes the September 23 observation that its reserved server had no
running node; it does not establish production deployment or native finality.

## Native consensus and real-proof rehearsal (2026-10-01)

The native development branch `codex/native-l2-settlement-20261001` now connects
a bounded settlement transaction to the actual native state transition and a
CPU-only SP1 6.8.0 Groth16 verifier. Policy, native height and accepted cursor are
committed in native state. Parent/source selection comes from that state; the
first version accepts an empty inbox only. Existing network manifests keep the
policy absent, and the shipping mempool rejects the new transaction.

The `native-empty` SP1 harness reads seven public fixture fields exported by the
native transition through `BLOCH_NATIVE_L2_REQUEST`. It reexecutes the empty L2
block at that exact anchor, generates the existing V2 public statement and can
prove/reverify it using the already pinned guest ELF. This is an isolated
qualification fixture, not a native checkpoint or production source authority.
The earlier genuine `source-contract` proof remains synthetic source evidence:
cryptographic validity does not authorize that source in native consensus.
The generated `native-empty` proof has also been persisted, reverified by the SDK
and accepted by the actual native `apply_block` test using the real CPU proof
verifier. Native validator signatures in this rehearsal are test doubles; this
does not qualify a live quorum. The proof and public values are retained in the
native `bloch-l2-proof` fixtures with artifact, guest and host provenance hashes.

The new native wire envelope uses `0x0E` with 32-byte proof policy, 590-byte public
values and the complete 356-byte proof. Existing recovery/admission adapters must
be qualified for that exact native envelope before it can advance production
finality. Network activation, validator fault/replay evidence, checkpoint authority
and RPC publication remain separately gated. No readiness flag changes here.

## RPC tag qualification

### Durable preparation before RPC publication

The combined adapter's `recover_and_stage_finality_candidate` now persists an
exact candidate in a dedicated MDBX singleton after complete proof/PQ/canonical
replay. It compares the independently retained candidate commitment, rechecks
the previous candidate's exact historical settlement and checkpoint, requires
a fresh checkpoint and fences the canonical tip in the committing transaction.
Lost evidence suffixes, regressing generations, conflicting records, ignored
external marks or concurrent cursor replacement prevent staging.

The fixed-size candidate is durable preparation, not a finalized-block
capability. It never writes Reth's numeric safe/finalized keys. The current
canonical coordinator refuses startup when such unverified keys are present,
including block zero, preserving them for review. Production finality cannot
be bootstrapped from a stored height or a well-formed candidate. Native
consensus-enforced settlement and proof transport qualification remain required;
no production gate is changed by this implementation.

The Reth integration now has a read-only
[canonical settlement correspondence boundary](../integrations/reth-execution/SETTLEMENT-BINDING.md).
It inspects the complete acknowledged V2 prefix under a separate L2 floor and
explicit budgets, then compares each recovered settlement with the exact local
header, complete body and consumed deposit count. The native-PQ strict recovery
hook runs this additional check only after that record's proof and authority
have passed. Missing bodies, mismatched earlier records, skipped generations,
ignored failures and a changed canonical tip prevent a recovery result from
escaping. The returned accounting is not a finalized-block capability.

Tests use real local Reth storage and kernel execution with synthetic native
provenance and a proof-verifier double. They establish correspondence and
failure handling, not production proof transport, native settlement consensus
or RPC finality. All production requirements remain independently gated.

The separate AGPL [combined recovery adapter](../integrations/settlement-recovery/README.md)
now exercises both integrations in one process. Its entrypoint requires matching
native genesis policies and all three independent recovery floors, always runs
the mandatory canonical callback, and checks complete generation/head coverage
before exposing either locked history. Tests cover real PQ signatures together
with actual Reth storage, late failures and changed canonical tips. This closes
the local composition test gap; production proof transport and consensus
activation are still required before any finalized-RPC publication.

The presence of `safe` or `finalized` tags is not finality evidence by itself.
A static or genesis-only endpoint can return block zero for all three tags while
making no progress and authenticating no settlement. The diagnostic probe:

```sh
python3 tools/check-finalized-rpc.py --rpc-url https://example.invalid/rpc
```

takes two consecutive observations of the reviewed chain ID, genesis and
`latest`, `safe`, and `finalized` tags. Each observation requires a finalized
block strictly above genesis, `latest >= safe >= finalized`, and an identical
reread of the finalized block by number. It walks numbered headers from `latest`
to `finalized`, checks every parent-hash link, and requires `safe` to be the exact
header on that branch. A block hash cannot claim different heights or parents.
Between observations the finalized head must retain its identity or descend
from the previously observed finalized block; its old numbered block is read
again. Reorganizations strictly above the retained finalized head are allowed.

An externally selected frozen genesis can be supplied with `--genesis-hash`.
Without that argument the report explicitly returns `genesisPinned: false`;
matching a chain ID is insufficient to select a deployment. Both observations
must return the same genesis. Two equal finalized observations are permitted and
report `finalizedProgressObserved: false`: this is a short consistency probe,
not a liveness or durability qualification.

Successful observations can be retained and replayed without network access:

```sh
# Run only against an independently selected endpoint and genesis.
python3 tools/check-finalized-rpc.py \
  --rpc-url https://example.invalid/rpc \
  --genesis-hash "$REVIEWED_GENESIS_HASH" \
  --capture-output /secure/intake/finalized-rpc-transcript.json

python3 tools/check-finalized-rpc.py \
  --transcript /secure/intake/finalized-rpc-transcript.json \
  --genesis-hash "$REVIEWED_GENESIS_HASH"
```

The new transcript file uses mode `0600`, cannot overwrite an existing path,
and contains the exact ordered method/parameters and examined result fields.
Block results retain only number, hash and parent hash. Endpoint URLs,
credentials, transaction bodies and unrelated RPC fields are excluded. Replay
validates the schema, exact call sequence, header fields and every consistency
check; missing, extra or reordered calls are rejected. `transcriptSha256` binds
the retained bytes, but does not authenticate their origin. The local
`recordedAt` timestamp is capture metadata, not a source timestamp or freshness
proof. If an operator authenticates these details through operational evidence
intake, that separate signature authenticates the observation only.

The default ancestry budget is **128 numbered ancestor reads shared across
both observations and the inter-observation finality check**. A caller can set
`--max-ancestry-blocks` between 1 and 4096. The total request bound is that budget
plus 13; responses are limited to one MiB each and transcripts to four MiB.
`--timeout` bounds each request to at most 30 seconds. Missing/pruned headers,
transient tag ordering changes or gaps exceeding the budget cause a diagnostic
refusal; they do not establish an operational outage or an invalid chain.

The probe checks relationships asserted by one RPC. It does not recompute block
hashes, establish native settlement inclusion, independently authenticate the
chain, or link a non-genesis finalized head all the way back to genesis. It
never changes `network/finality.json` and always reports `diagnosticOnly: true`,
`qualified: false`, and `permissionsOpened: false`. Native checkpoint,
settlement-proof, inclusion, consensus, persistence and operational evidence
remain separate prerequisites.
