# Canonical settlement correspondence

`settlement_binding::with_canonical_settlement_audit` compares recovered native
settlement statements with the exact acknowledged V2 blocks in Reth storage.
This is a read-only qualification boundary. It never sets `safe` or `finalized`,
authenticates native consensus, or authorizes bridge withdrawals.

The operator selects the provider's chain configuration, the settlement policy,
an independently retained L2 rollback floor, and block/byte budgets. All source
writers, including static-file writers, must be stopped for the operation.
An L2 floor copied from the inspected database cannot detect a lost suffix.
It is separate from the checkpoint and settlement-store rollback floors.

Before opening settlement history, one MDBX reader inspects the complete
acknowledged prefix from the configured genesis. The audit checks canonical
header seals, full parent/state linkage, configuration, signed-body validity,
transaction/deposit commitments, the L2 floor and the policy's initial parent.
The limit is at most 10,000 non-genesis blocks, plus the caller's cumulative
encoded-block byte budget. Only headers, hashes, body commitments and deposit
counts remain cached during settlement replay. These limits do not bound native
cryptography time or replace the settlement/checkpoint stores' own limits.

`CanonicalSettlementAuditV1::audit_record` requires generation order starting at
one and consecutive L2 blocks starting at the policy's `first_l2_number`. It
checks every native network/program/proof-policy identity against the selected
settlement policy, then compares the retained transaction and accepted head with the selected block's
domain, chain ID, configuration, number, complete header hash, parent hash,
parent state root, post-state root, native anchor, complete body commitment and
consumed deposit count. Header hashing also commits timestamp, fee/gas context,
transaction/receipt roots, bloom and the remaining V2 fields.

Any mismatch poisons the audit. Swallowing a record error, auditing no records,
or changing the acknowledged canonical tip during replay prevents the outer
function from returning the consumer result. A fresh reader checks the tip
after replay; this catches ordinary concurrent advancement, not arbitrary
host compromise or violations of the stopped-writer contract. The callback
must not publish intermediate handles or heads.

## Composition with proof and PQ authority recovery

The separate AGPL native-PQ adapter exposes
`open_proof_verified_authority_stores_with_audit`. Its additional callback runs
only after each record has passed execution-proof, complete-inclusion and
historical checkpoint-authority verification. The callback cannot relax those
checks.

The separate AGPL [settlement recovery adapter](../settlement-recovery/README.md)
now provides this closed composition as `recover_canonical_settlements`, with
joint storage/PQ integration tests and a final check of full replay coverage.
Hosts can use that entrypoint instead of implementing the callback composition
themselves. Its runtime proof verifier and production qualification remain
independent requirements.

The equivalent callback composition is:

```rust
with_canonical_settlement_audit(
    &stopped_l2_provider, settlement_policy, independent_l2_floor, limits,
    |canonical| {
        open_proof_verified_authority_stores_with_audit(
            checkpoint_path, checkpoint_policy, independent_checkpoint_floor,
            settlement_path, settlement_policy, independent_settlement_floor,
            current_epoch, maximum_proofs, &pinned_proof_verifier,
            |record| canonical.audit_record(record).map_err(|error| {
                SettlementAuthorityStoreErrorV1::AdditionalAudit(error.to_string())
            }),
        )
    },
)
```

The returned accounting binds the complete policy commitment and names the inspected canonical tip and last matched
settlement. It is audit data, not a finalized-block capability. The public
record view can be constructed as data; `audit_record` alone proves neither
execution nor authority. Always keep it inside mandatory proof/authority
recovery. Genuine native settlement consensus and proof transport qualification
remain required before any RPC finality publication.

## Validation

`tests/settlement_binding.rs` uses actual MDBX, RocksDB and static-file storage,
kernel-executed deposits and a real signed EVM transaction. It checks orderly
reopening, an older mismatched settlement beneath a valid latest one, exact
field binding, missing complete bodies, wrong policies/floors, budgets, ignored
errors and concurrent tip advancement. Successful audits leave safe/finalized
markers absent. Native provenance is synthetic and the execution-proof verifier
is an explicit test double. The PQ integration separately exercises real
disposable hybrid signatures, callback ordering and callback refusal.

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --offline --locked \
  --manifest-path integrations/reth-execution/Cargo.toml --test settlement_binding
cargo +1.94.1 test --offline --locked \
  --manifest-path integrations/native-escrow-pq/Cargo.toml --test settlement_authority
```

Use the pinned Reth base/patch and native revision documented in the respective
integration READMEs. No operational key, live checkpoint payload or finalized
RPC marker is created by these tests.
