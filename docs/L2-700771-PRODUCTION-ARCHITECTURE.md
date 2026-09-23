# Chain 700771 production-node architecture

Status: implementation plan, non-authorizing. This document does not select a
genesis, register a node binary, establish finality, or permit a listener.

## Trust boundary

The L2 executes Bloch V2 blocks with Reth components, but its canonical inputs
come from authenticated Bloch native L1 checkpoints. An RPC assertion, a local
database head, a sequencer signature, or the legacy chain-8400 process is not a
finality source. The node may publish a finalized L2 head only after the exact L2
commitment is included below a currently accepted native checkpoint and the
complete checkpoint ancestry has been authenticated.

The production process consumes four independently selected immutable inputs:

1. a reviewed chain-700771 genesis artifact and its externally distributed
   digest;
2. a content-addressed node image and independently reproduced build digest;
3. the native checkpoint authority manifest and retained rotation history;
4. the operational policy fixing peer identities, derivation bounds, block
   production, reorganization limits, RPC methods, and shutdown behavior.

No input can authenticate itself by placing its own digest next to its bytes.

## Components

The entrypoint owns, in order:

1. **Release admission** verifies the binary/image, configuration, genesis and
   policy against externally retained pins before opening storage.
2. **Recovery supervisor** opens a single data directory, checks the durable
   journal, database head, state root, receipts and native settlement cursor,
   then either proves one exact recoverable state or enters quarantine.
3. **Native checkpoint intake** verifies the configured PQ authority, checkpoint
   freshness and rotation continuity. It supplies authenticated checkpoints,
   never booleans copied from RPC.
4. **Derivation pipeline** authenticates complete native header ancestry and the
   relevant transaction bodies, applies deposit/source-conservation rules, and
   advances a durable cursor exactly once.
5. **Block producer/fork choice** deterministically selects the next parent and
   inputs under one reviewed policy. A single initial producer is an availability
   choice, not an independent finality authority.
6. **Execution coordinator** validates and executes Bloch V2 blocks using the
   frozen chain spec. It cannot choose finality or repair storage.
7. **Atomic publication journal** binds the L2 block, execution state root,
   receipts, derivation cursor and native settlement reference. Publication is
   acknowledged only after restart-verifiable durability.
8. **Finality projector** advances monotonically only when a settled L2
   commitment is authenticated below an accepted native checkpoint. Regressions,
   equivocation and unknown gaps quarantine publication.
9. **RPC and P2P gates** bind sockets last. RPC exposes a bounded method policy;
   `finalized` reads only the retained finality projector. P2P peers are bound to
   the chain domain and reviewed identity policy.

## Lifecycle

The only permitted state progression is:

```text
sealed -> admitted -> storage-verified -> l1-synchronized
       -> read-only -> producing -> finality-publishing
```

Every transition is represented by a versioned receipt linked to the preceding
receipt and the exact configuration digests. Failure moves to `quarantined`.
There is no transition from `quarantined` back to serving through automatic
repair; an operator must supply a separately reviewed recovery plan.

RPC and P2P remain unbound in `sealed`, `admitted`, `storage-verified`,
`l1-synchronized`, or `quarantined`. Read-only RPC may bind only after all
identity, storage, checkpoint and method-policy gates pass. Transaction admission
and block production require the additional producer and persistence gates.

## Durable commit boundary

Each canonical commit records at least:

- sequence and previous journal digest;
- chain ID and frozen genesis digest;
- parent and new L2 block number/hash;
- post-execution state root and receipts root;
- authenticated native checkpoint block/slot/digest;
- previous and new derivation cursor;
- exact derived-input digest;
- finality state before and after the commit;
- node release and policy digests.

The commit is rejected if a number regresses, a predecessor is skipped, an L2
parent changes, a native cursor forks, or any database observation disagrees.
Ambiguous persistence poisons the running coordinator and requires restart
reconciliation. Retrying block production from the same process is forbidden.

## Shutdown and recovery

Graceful shutdown first stops transaction and derivation admission, drains the
sole canonical writer, persists a shutdown receipt, closes storage, reopens it
read-only and verifies the exact retained head/cursor. Only that verified receipt
is a clean shutdown.

On startup after an unclean stop, recovery compares the journal with every
backend. It may perform only a reviewed deterministic replay or rollback whose
expected before/after digests are included in the recovery plan. Missing receipts,
multiple plausible states, database state ahead of the journal, native cursor
equivocation, or an unrecognized release leaves the node quarantined.

## Implementation order

1. Frozen-genesis selection and release-admission verifier.
2. Restart-verifiable journal for head/state/receipts/native cursor.
3. Authenticated checkpoint intake and continuous derivation service.
4. Deterministic producer and fork-choice policy.
5. Settlement-bound monotonically finalized head.
6. Authenticated P2P transport and peer policy.
7. Read-only RPC, followed by separately gated transaction admission.
8. Fault-injection matrix covering every persistence boundary and shutdown step.
9. Reproducible image, SBOM, independent builds and operational qualification.

Until every item has production evidence, `productionReady`, `build`, `start`,
`bindRpc`, `bindP2p`, and `publishFinalized` remain false.
