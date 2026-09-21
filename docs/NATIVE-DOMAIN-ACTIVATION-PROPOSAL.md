# Native execution-domain activation proposal

Status: design proposal for an isolated development network. No native
transaction tag, state component, activation epoch or production deployment is
assigned here. Existing developer funding and source commitments remain
explicitly synthetic or externally trusted.

## State that native consensus must own

The existing native EVM singleton is not this domain registry. A new versioned
registry must commit the following together under the native consensus state
root; a relayer's database or RPC response cannot substitute for that inclusion.

| Record | Required committed data |
| --- | --- |
| Domain policy | Native genesis/network, domain, EVM configuration commitment, exact accepted guest/program verification identity, derivation version, capacity and proof-admission rules |
| Escrow | Consumed native funding outpoints, locked liability, separately accounted fees/change, ordered lock identities and recipients |
| Source snapshot | Complete inbox root/count, canonical lock transaction mapping and prior-source linkage; block identity is bound by header inclusion after the state root is known |
| Settlement | Full accepted V2 header hash, state root, execution height, consumed inbox position, accepted source identity and program policy |
| Release | Verified withdrawal identity, native recipient and exact amount, consumed release nullifiers and resulting native outputs |

The native state codec and its component key require a separate reviewed native
implementation. Reusing component `0x10`, treating a script hash as a message,
or reading a transfer to an operator key does not implement this registry.

The native source leaf must not contain the hash of the same header whose state
root commits that leaf. That would create a circular hash dependency. The current
`SourceBatch` is a host envelope that binds an already identified anchor block;
its entire commitment cannot simply be inserted into that anchor's state tree.
The native codec must instead commit the inbox/mapping data independently, then
derive the anchored envelope from authenticated header/state inclusion. The
[experimental post-genesis payload](../integrations/native-domain-devnet/PAYLOAD.md)
now provides a bounded codec and typed-height binding without the current block
hash. Its byte vectors and branch/identity tests pass. It excludes height zero
because the stored native genesis identity would otherwise reintroduce a cycle.
Native component assignment, state inclusion, accepted source authority and
activation conformance remain required; the codec alone supplies none of them.

## Lock transition

A lock transaction must authenticate its owner with the native hybrid signature
policy and bind the entire intent: network/domain, ordered funding inputs,
recipient, principal, fees/change, and replay identity. Consensus must consume
the real native inputs and publish the escrow liability and inbox entry in one
atomic transition. No ordinary key may retain a spendable copy of that principal.

The existing experimental `EscrowLedger` and `PqEscrow` exercise authorization,
conservation, replay and atomic ordered batches on explicitly allocated local
funding. They do not import ordinary native UTXOs as locked collateral. A native
implementation must connect those checks to the canonical native transaction
and state transition, including invalid-block rejection and reorganization rules.

Before releases exist, each native transition must preserve:

```text
spendable native value + locked liabilities + accounted fees = initial value
```

All additions and subtractions require checked arithmetic in the specified units.
The EVM conversion is exactly 10^10 wei per native satoshi. Source locations use
height derived from parent links; slots are a separate field.

## Settlement transition

Native consensus must select and authenticate the source snapshot independently
of the proposer. The source's complete ordered mapping must extend the accepted
native ancestry and preserve every historical inbox leaf. The current bounded
prototype verifies every leaf and retains at most 4096 locks; that is not a
production-scale accumulator policy.

For a proposed V2 successor, validators must check all of these before publishing
any new settlement or consumption state:

1. The configured guest/program key, permitted proof format, resource bounds and
   successful cryptographic execution proof.
2. Exact expected configuration, domain, previous state root and full V2 header
   hash; the parent hash/root, number and header rules must extend the accepted head.
3. The body commitments and exact mandatory deposit prefix selected from the
   authenticated source at the retained consumption cursor. Execution validity
   alone does not establish deposit authority.
4. The proof-bound anchor and source selection, including native genesis,
   source commitment, inbox root/count and consumed range.
5. Atomic publication of the execution head and consumed inbox position.

The [dormant settlement payload](../integrations/native-domain-devnet/SETTLEMENT.md)
provides a canonical bounded message binding all of those inputs, including the
program/proof identities and predecessor. It assigns no native tag or activation
and implements none of the checks or atomic publication described above.
Only a proof digest is present: the current host permits 32 MiB proof artifacts,
which exceed the audited 512 KiB native block limit. Proof availability and
validator verification therefore remain an unresolved activation requirement;
the payload does not imply that proof bytes are carried by a native block.

An accepted proof for another program, domain, configuration, parent, source,
body or consumed range must fail without advancing either cursor. Replaying the
same proof must fail after its first acceptance. A local append-only proof
journal establishes local recovery; it does not make this transition a native
consensus rule.

## Release remains disabled

The current execution statement does not define a native withdrawal protocol.
General EVM burn accounting, a transfer receipt, a log selected by a relayer, or
a valid execution proof cannot be interpreted as a withdrawal authorization.

A future reviewed rule must specify a balance-debiting EVM operation and its
proof-bound withdrawal commitment, including domain, unique identity, exact
native recipient and amount. Native release must verify that commitment under
an accepted finalized settlement, consume its nullifier once, reduce the locked
liability and create the native output atomically. A failed proof or payout must
not consume the nullifier. Fees, rounding and any unrepresentable fractional
amount require explicit rules; no implicit rounding is allowed.

This requires a new documented execution/derivation policy and pinned program
upgrade where semantics change. An administrator must not bypass the proof or
create backing assets. `EscrowLedger::release` stays unavailable until that path
has been implemented and tested.

## Evidence required before an activation decision

An isolated native devnet must exercise actual block acceptance/rejection,
authenticated lock derivation, valid and invalid proofs, duplicate consumption,
cross-domain replay, conservation, release replay, restart and interrupted
atomic commits. It must also qualify checkpoint bootstrap/finality, transaction
data availability, proof CPU/memory/concurrency limits and reproducible program
upgrades. Test fixtures must distinguish native consensus evidence from local
trusted inputs.

The reviewed codecs, deployment configuration, migration behavior and rollback
limits must accompany that evidence before selecting any activation epoch. This
proposal and the [delivery plan](EVM-DELIVERY-PLAN.md) record the remaining work;
neither authorizes a production activation.
