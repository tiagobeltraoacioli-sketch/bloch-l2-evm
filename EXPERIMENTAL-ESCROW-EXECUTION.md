# Experimental ordered deposit consumption and EVM execution

`EscrowEvmDomain` adds a local derivation boundary around `EvmDomain`. It owns
both the execution cursor and the next unconsumed inbox sequence. There is no
mutable accessor exposing the underlying domain. The feature remains
`experimental-escrow`, disabled by default, with no mainnet deployment.

## Acceptance rule

For a host-authenticated finalized inbox snapshot, each EVM block must consume
exactly the next `min(remaining, gas_limit / deposit_gas, 4096)` deposits. Missing,
extra, duplicate or reordered proofs are rejected. An empty deposit list is
accepted only when that snapshot has no remaining deposits. This deterministic
policy prioritizes deposits; a full deposit chunk can leave no gas for user
transactions. Pin it as part of a new runtime artifact identity.

Each inclusion proof must match the independently supplied network, domain,
inbox root and total count. Its sequence must match the local cursor. The
derived recipient and satoshi amount must exactly match the proposed EVM mint.
Amounts use the existing exact satoshi-to-wei conversion and supply cap.

The inbox does not authenticate actual native block positions: those must come
from `TrustedLockLocation`, an explicitly trusted host mapping between intent ID,
sequence, native transaction ID, block height, transaction index and output
index. Native transaction ID and intent ID are distinct fields. An inbox
sequence or a Genesis-4 slot is never substituted for block height. Escrow
positions cannot be later than the finalized execution anchor. The existing
EVM state-committed deposit cursor checks canonical position order across blocks.

After these checks the domain verifies the complete input commitment, signatures,
execution witness, previous root, block continuity and re-executed result. Only
successful verification advances the EVM cursor and inbox cursor. No fallible
step follows the EVM cursor update. A rejected execution leaves both unchanged
and permits a corrected retry. The returned receipt commits the execution
receipt, inbox root/count and consumed half-open sequence range.

Snapshot counts cannot shrink. An unchanged count cannot change root, and an
unchanged L1 height cannot change block/root/count. Anchor rollback is rejected
by the underlying execution domain. Larger snapshots still require external
authentication of append-only ancestry; membership proofs alone cannot prove
that the new tree preserves the old prefix.

## What remains trusted or unimplemented

`TrustedEscrowBatch` is not a certificate and MUST NOT be populated directly
from an untrusted proposer or RPC response. The host must authenticate L1
finality, inbox commitments, mappings, ancestry and ordered execution input.
Genesis-4 does not currently commit this experimental inbox format. This module
does not implement its consensus activation or a verifier for those host claims.

Construction is for a fresh domain with a trusted initial EVM root containing
no credits for this inbox. The cursor starts at zero. Restarting from an arbitrary
later root is unsupported; there is no recovery/import API. Atomicity is local
and in-memory: durable state, inbox cursor, snapshot and receipt must eventually
be committed and recovered in one transaction. The additional inbox cursor is
bound by the composite receipt, not inserted into the legacy EVM state layout.
The low-level EVM API remains usable independently and still trusts its own
derivation caller; only this facade enforces the additional inclusion checks.

Receipts are re-execution results, not succinct proofs or withdrawal authority.
This step provides no production bridge, L1 release, SVM runtime or sequencer.

## Validation

Seven new integration tests cover exact conserved credit across chunks of 2/2/1,
empty blocks after consumption, replay, mandatory-prefix omissions, extra and
reordered proofs, forged leaves/mappings/mints, snapshot conflicts and rollback
of both cursors after a bad execution witness. A corrected witness is accepted
after rejection. Receipt mutation changes its commitment. A growing snapshot at
a newer anchor resumes after the already-consumed prefix.

The fixtures use actual escrow transitions and actual EVM witness generation
and verification, with synthetic host-trusted L1 mappings and anchors. Real PQ
funding authorization remains separately tested in `integrations/native-escrow-pq`.

```sh
cargo +1.94.1 test --offline --locked --features experimental-escrow
cargo +1.94.1 check --offline --locked --no-default-features --features experimental-escrow
```
