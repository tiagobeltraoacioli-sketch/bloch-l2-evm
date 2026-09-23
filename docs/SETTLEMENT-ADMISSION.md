# Authenticated settlement-admission boundary

`settlement_admission` composes two deliberately separate primitives without
claiming that either one supplies finality:

1. `l1::AuthenticatedTransactionInclusion` proves that exact bytes occur once
   at a fixed index in a complete Genesis-4 body on an ancestry path ending at
   an externally supplied checkpoint.
2. `native_settlement::SettlementRegistryV1` checks the fixed V1 codec, pinned
   execution/proof policy, exact consensus-selected statement, proof and
   replay-safe successor transition.

`SettlementAdmissionRegistryV1::verify_inclusion_and_apply` consumes the
non-cloneable inclusion capability. It requires exact expected block, slot,
checkpoint and transaction index; round-trips the canonical fixed-width codec;
and only then invokes the settlement kernel. Its admission commitment binds all
those coordinates and the exact transaction bytes to the accepted settlement
commitment.

The proof statement's `l1_block`/`l1_slot` identify the source anchor selected
for L2 execution, while the admission block/slot identify the later native
block containing the settlement transaction. They are intentionally distinct:
requiring a transaction to contain the hash of its own containing block would
create an impossible circular body/block commitment. The adapter binds both
facts in one record without substituting one for the other, rejects an equal
block hash and requires the source slot to precede the containing block slot.

The adapter owns its kernel and exposes no mutable inner registry, preventing a
kernel head from advancing without a corresponding admission record. Errors
before or inside verification leave both heads unchanged.

## What this does not establish

The checkpoint is an external trust input. Inclusion under it does not prove
the checkpoint's voting authority, validator-set transitions or non-regression.
This in-memory adapter also provides no Genesis-4 transaction tag or state key,
validator execution, durable atomic commit, reorg recovery, SP1 verifier
implementation, RPC finality or product permission. It must not populate
`eth_getBlockByNumber("finalized")`, open bridge/DEX permissions or be described
as production settlement evidence.

Activation requires a separately reviewed native consensus integration to
derive the expectation from committed state, authenticate the checkpoint,
execute this transition identically on validators, persist it atomically and
prove reorg/fault behavior. This module intentionally performs none of those
steps.
