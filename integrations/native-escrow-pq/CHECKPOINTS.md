# Hybrid-PQ weak-subjectivity checkpoint authentication

The `checkpoint` module authenticates the native checkpoint envelope using the
official committee quorum verifier and the real ML-DSA-65 AND Falcon-1024
primitives. It returns a private `VerifiedCheckpoint`, whose anchor can feed
`bloch_l2_evm::l1::authenticate_body` and the native state-proof integration.
No production signing keys, network requests or signing ceremony are included.

## Pinned trust policy

Construct `CheckpointPolicy` from an independently authenticated signer set,
network ID, genesis root and explicit phase. The policy is immutable. It cannot
learn a weaker threshold from an incoming envelope:

| Policy | Threshold | Set size | Required external signatures |
| --- | --- | --- | --- |
| Phase A | 2 | 3 | 1 |
| Phase B | 3 | 5 | 2 |

The values come from the native `ws` constants. Construction rejects an invalid
shape, duplicate public keys, the reserved genesis signer-set ID, a zero genesis
identity and overflowing arrangement review/grace clocks. The externally flagged
keys remain organizational trust assertions: signatures cannot prove that two
people or organizations actually operate independently.

## Verification path

The adapter bounds the header to 304 bytes, signature count to the pinned set
size and each signature to 8,192 bytes before cryptographic work. The checkpoint
must not be in the future relative to the caller's independently determined
current epoch. Its age must be strictly below the native weak-subjectivity
period, and it cannot predate adoption of its signing arrangement.

`verify_envelope_with_shape_policy` then checks format, chain identity, signer
set ID, arrangement expiry, signer indices, quorum and external minimum. The
native `staking::verify_hybrid` requires both algorithms for every listed
signature; the adapter supplies real primitive implementations, never a caller
callback or success flag. Signatures and public keys use the native raw hybrid
checkpoint encoding, not the wallet's four-byte suite envelope.

The supplied canonical header must have the Genesis-4 version, match the signed
block identity and contain exactly the signed state root. The output anchor's
slot comes from this header. The signed epoch is retained separately; neither
epoch nor slot is silently converted into block height. Header linkage does not
execute the block or validate its proposer/FFG signatures.

`settlement_authority::bind_settlement_checkpoint_authority` consumes this
private verified capability together with a complete canonical inclusion
envelope and an independently selected settlement expectation. It returns a
non-cloneable package only when the PQ-signed anchor, ancestry endpoint, body,
exact transaction index and settlement statement all agree. The accompanying
129-byte `CheckpointAuthorityReceiptV1` binds the immutable policy identity,
signed checkpoint digest, checkpoint/freshness epochs, block, slot and review
warning. Decoding the receipt is audit transport only and cannot recreate PQ
verification.

If a previously verified checkpoint is supplied, its chain identity must match.
An older incoming epoch is refused. A different digest at the same epoch raises
a conflict; an identical checkpoint is accepted idempotently. A newer checkpoint
can advance the bootstrap anchor. The result exposes the native arrangement
review-due warning; callers must surface it rather than treating grace as an
unreviewed permanent arrangement.

## Remaining trust and operational boundaries

This authenticates a weak-subjectivity assertion by trusted signers. It is not
an independent proof of historical FFG finality. Colluding trusted signers can
still attest a fabricated history. Signer-key distribution, ceremony procedures,
organizational independence, revocation/rotation and cross-channel verification
remain required operator/release responsibilities. No claim about current
publication of mainnet checkpoints follows from the disposable-key tests.

`current_epoch` is supplied from a trusted local clock and authenticated chain
schedule; it must not come from the checkpoint's informational `issued_at` field
or from an untrusted RPC. The API is a bootstrap verifier, not a replacement for
a running node's local finality or native `cross_check`/reconciliation policy.
Callers must never use a signed envelope to override conflicting local finality.

The pure verifier does not automatically persist the last accepted checkpoint.
The [Unix checkpoint store](CHECKPOINT-STORE.md) now handles durable history and
reverification, retaining stale checkpoints only as rollback evidence and
checking current freshness before exposing an anchor. Keep its latest watermark
independently protected. Direct verifier callers must still retain/reverify the
signed artifact and supply `previous`; omitting it starts a fresh bootstrap
trust decision. This module does not wire the operator
CLI's trusted inbox files to consensus: the experimental inbox still needs a
native committed representation and activation.

The authority-bound commit path embeds that receipt beside the complete
inclusion envelope in one `BLSTRC04` settlement record. Coordinated recovery
reopens both stores under independently retained marks, rereads the exact
historical checkpoint, reverifies its PQ authority at the receipt's recorded
freshness epoch, rejects future-dated checks, and requires policy, digest, epoch,
block and slot to match. The audit-only result cannot become a current anchor;
`current` still performs that separate check. The checkpoint history remains a
separate rollback domain, so both marks are mandatory. This is still
weak-subjectivity authentication, not production FFG finality.

`open_authority_bound_stores` is the structural compatibility boundary: it requires
both non-optional external floors, opens both stores under their exclusive locks,
checks the latest historical V4/PQ receipt, and exposes neither handle if any
step fails. The V4 receipt already binds the two identities, so this API does not
invent a third unsigned manifest or collapse the independently protected floors.

For complete evidence recovery, `open_proof_verified_authority_stores` now
reverifies every execution proof and every authority receipt in record order,
including records before either external floor. Every nonempty settlement must
retain its complete V4 inclusion and authority data; mixed V2/V3 histories need
explicit reconstruction from independently authenticated artifacts, never
automatic receipt backfilling. The callback to
`SettlementStoreV1::open_verified_with_audit` keeps both stores locked until the
whole replay succeeds. `History { generation, error }` reports an authority
failure without returning a partial handle or changing retained bytes. An
otherwise valid latest record cannot hide an earlier invalid receipt.

The caller's `maximum_proofs` bounds settlement proof/audit invocations and
does not replace the checkpoint store's separate history limit. Signer policy,
current epoch and both floors remain independent trust inputs. Reverification
of a historical acceptance epoch does not grant a fresh checkpoint capability,
establish native settlement consensus or authorize the `finalized` RPC tag.

`open_proof_verified_authority_stores_with_audit` additionally accepts a
read-only per-record check after mandatory proof, inclusion and PQ authority
verification. For example, a host can bind every verified record to a stopped
[Reth canonical snapshot](../reth-execution/SETTLEMENT-BINDING.md). Invalid
authority never reaches this callback. `AdditionalAudit` refusals retain their
record generation and release both stores without returning a handle. This
hook is additive; it cannot replace the mandatory verifiers. The original
strict opener preserves its behavior by supplying a no-op additional audit.

The separate AGPL [combined recovery adapter](../settlement-recovery/README.md)
links that strict opener with the Reth audit behind one entrypoint. It compares
the selected native genesis identities, exposes no caller-controlled audit
callback and returns locked stores only after full coverage and a stable local
canonical tip. Combined tests exercise real PQ signatures and real Reth storage;
the proof verifier remains an explicit test double in those fixtures.

## Validation

The checkpoint and settlement-authority tests use disposable locally generated
hybrid keys. They cover
real Phase-A and Phase-B signatures, successful header/body authentication,
corruption/removal of signature components, weakened or duplicate-key policies,
missing external quorum, duplicate signer indices, freshness boundaries,
adoption/review/expiry clocks, network/genesis/state/header/version mismatch,
rollback, same-epoch conflict, identical retry and resource bounds. The eight
existing escrow authorization tests also pass. The authority suite additionally
covers V4 atomic publication, recovery after a newer checkpoint advances,
historical expiry, future audit claims, predecessor relinking and receipt
tampering. Coordinated-open tests also reject either incorrect floor and prove
that failed admission releases both locks. Keys are not printed or saved.
Full-history replay additionally covers a valid two-record history and eleven
invalid first-record variants under a legitimate latest receipt: V2/V3 missing
authority, changed policy/digest/block/slot/review flag, an absent signed
checkpoint, future or stale-at-acceptance clocks, and a truncated receipt. The
execution-proof verifier in these recovery regressions is a fixed test double;
the checkpoint signatures are real ML-DSA-65 and Falcon-1024 signatures.

```sh
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-escrow-pq/Cargo.toml
```

The sibling native checkout remains `5af78a04a27dcb2c2253c32134fca888a8a965f9`;
the path dependency must be checked explicitly as described in [README](README.md).
