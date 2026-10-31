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
cryptography time.

`CanonicalSettlementAuditV1::audit_transaction` requires generation order starting at
one and consecutive L2 blocks starting at the policy's `first_l2_number`. It
checks every native network/program/proof-policy identity against the selected
settlement policy, then compares the transaction with the selected block's
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

## Consumers

`settlement-recovery::native::audit_finalized_async_settlements` runs this audit
over the finalized settlements of a complete native replay, one
`audit_transaction` per settlement. The accounting binds the complete policy
commitment and names the inspected canonical tip and last matched settlement. It
is audit data, not a finalized-block capability. `audit_transaction` alone proves
neither execution nor authority.

The earlier composition with the WS-checkpoint settlement store and its
`audit_record` method were retired on 2026-10-30.

## Validation

`tests/settlement_binding.rs` uses actual MDBX, RocksDB and static-file storage,
kernel-executed deposits and a real signed EVM transaction. It checks orderly
reopening, an older mismatched settlement, exact field binding, missing complete
bodies, wrong policies/floors, budgets, ignored errors and concurrent tip
advancement. Successful audits leave safe/finalized markers absent. Native
provenance and the settlement transactions are synthetic.

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --offline --locked \
  --manifest-path integrations/reth-execution/Cargo.toml --test settlement_binding
```

Use the pinned Reth base/patch and native revision documented in the respective
integration READMEs. No operational key, live checkpoint payload or finalized
RPC marker is created by these tests.
