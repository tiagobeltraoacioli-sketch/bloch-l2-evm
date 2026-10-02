# Combined settlement recovery

This separate, experimental Unix AGPL-3.0-or-later host adapter composes real PQ
checkpoint recovery with the Reth canonical settlement audit. It closes the
previous gap between separately exercised integrations: the caller receives
both locked histories only after the complete combined recovery succeeds.
Neither the portable EVM crate nor the Reth integration gains this dependency.

`recover_canonical_settlements` takes a stopped local provider, explicit
`SettlementRecoveryRequestV1` inputs and an independently qualified execution
proof verifier. It performs these checks in order:

1. The checkpoint and settlement policies must name the same native genesis.
2. Inspect the bounded complete canonical L2 prefix against its independently
   retained rollback floor and selected configuration.
3. Open and reverify the checkpoint history while holding its exclusive lock.
4. Recover every settlement, including records before the supplied settlement
   floor, repeating execution-proof, complete-inclusion and historical PQ
   authority verification before exact local header/body correspondence.
5. Recheck the acknowledged canonical tip and require audit coverage of every
   recovered generation and the exact recovered settlement head.

No caller callback can skip or swallow a per-record correspondence failure.
Refusal drops both history handles; recovery never rewrites their files. The
returned value exposes immutable history views and informational accounting.
`into_stores` consumes that result before mutable store access is possible;
later appends require their own validation. Locks protect the two audit stores,
not the Reth writer lifecycle.

## Durable finality candidate

`cursor::recover_and_stage_finality_candidate` adds a durable preparation step
after mandatory combined recovery. The 296-byte candidate in the separate
`BlochFinalityCandidate` MDBX table binds the L2 genesis, policy identities,
settlement generation/digest/state commitment, exact L2 header and state root,
checkpoint digest/epoch and observation epoch. It is distinct from Reth's
numeric `safe`/`finalized` markers and cannot authorize either RPC tag.

The caller supplies an exact candidate commitment retained outside this database;
`None` permits only an empty table. During full recovery, the previous candidate's
settlement must match its retained record, including records before the selected
floor. Its checkpoint is independently reauthenticated at its recorded epoch.
A currently fresh checkpoint is required to stage a new observation. The final
MDBX transaction compares the prior cursor and canonical tip before replacing
the singleton. Generations, heights and epochs cannot regress. Both evidence
stores stay locked until the returned value is dropped or consumed.

The external candidate mark is an exact CAS value, not a minimum. Retain the
returned commitment independently before acknowledging the update. A lost suffix,
unknown newer cursor, missing row or inconsistent mark requires independent
recovery; it is never silently adopted. A commit error is potentially uncertain
and must not be retried as though no write occurred. This is single-host MDBX
durability, not distributed durability, and cannot defeat a compromised host
that replaces both data and all independently retained trust inputs.

Decoding a cursor validates bounded framing only. Recovery repeats proof, PQ,
inclusion and canonical checks even when cursor bytes and their supplied hash
match. Candidate staging never writes Reth's numeric finality keys. The current
canonical coordinator refuses those keys at startup because no qualified native
settlement publisher is registered. Refusal preserves the data for review.

Combined tests exercise candidate advancement, restart, lost evidence suffixes,
forged fields, deletion, foreign rows, stale external marks, checkpoint expiry,
proof refusal and a competing candidate update. Successful staging leaves RPC
safe/finalized markers absent. Production publication still requires native
consensus acceptance and the remaining release qualifications.

## Exact native recovery and real-proof/PQ qualification

`recover_canonical_native_settlements` and
`cursor::recover_and_stage_native_finality_candidate` select the real native
Groth16 verifier internally. Its guest BN254 key comes from the independently
trusted settlement policy. These entry points refuse experimental framing in
**every** historical record, including records before the retained floor.
An earlier candidate or a genuine signature cannot bypass this requirement.
The generic APIs remain available for explicitly selected historical integrations.

The portable codec now recognizes the exact 979-byte native `0x0E` envelope.
Its original experimental decoder remains strict. Admission compares the source
to the authenticated containing header's parent and preserves the complete native
bytes. It never proves inclusion of a normalized payload or a substring.
Native records rederive the versioned empty-source commitment from policy,
parent coordinates and the previously accepted source. Nonempty inboxes remain
unsupported by this version of native consensus.

New `BLSTRC05` records retain the native envelope in the existing fixed transaction
slot, with discriminator 2 and canonical zero padding. V5 always includes the
complete body/ancestry evidence and an authority audit receipt. V2/V3/V4 bytes and
interpretation are unchanged. Downgrades, nonzero padding, substituted transports
and missing authority fail before a recovered handle or candidate is published.
The record digest, admission commitment and external floor cover the exact bytes.

`tests/native_recovery.rs` combines the retained real Groth16 proof, an actual
header/body exported after native `apply_block`, an empty block independently
executed and persisted by Reth, and real ML-DSA-65/Falcon-1024 checkpoint signatures.
The test arrangement exercises Phase A's 2-of-3 threshold with the required
external marker and a 3-of-3 envelope. It rejects insufficient quorums, missing
external participation, duplicate signers, corruption of either signature half,
foreign networks, expiry, lost history, envelope substitution and late proof
refusal. It reopens both evidence histories and the durable candidate and leaves
numeric RPC finality markers absent. All signer keys are disposable and remain
in test-process memory; their identities/independence are synthetic trust inputs.

These are real **weak-subjectivity checkpoint signatures**, not an operational
validator FFG quorum. The exported native block's proposer signatures still use
the original test scheme. This qualification does not establish live FFG finality,
organizational independence, production checkpoint authority or funded escrow.

## Native consensus and FFG recovery

`native::verify_native_finality` adds complete native replay from an independently
pinned genesis state root and settlement policy. The policy binds the native
network/genesis, L2 identities and the compiled Groth16 policy. The supplied state
must be the initial state, with no accepted settlement. A constructor or a root
copied from the submitted data is not independent genesis authentication.

The replay entry point fixes real ML-DSA/Falcon and Groth16 verification internally.
It reexecutes each complete native block, checks proposer and attester signatures
against the committed registry, and derives justification/finality through the
actual native transition. Full history retains epoch accounting and the leak
ledger. It does not bootstrap finality from a bare quorum, header flag or a WS
snapshot. The adapter also requires vote heads/checkpoints and finalized roots
to belong to the replayed branch, following the node's checkpoint convention:
the last block strictly before the epoch boundary, including skipped slots.

Blocks, epochs, attestations, transactions, proof calls and supplied bytes have
explicit budgets and hard ceilings, checked before signature/proof work. This is
a host API over decoded data; network/file decoding must enforce its own input
allocation limits. The initial state and its manifest are trusted host inputs.
This version replays one complete branch from genesis; it does not run network
fork choice, fetch missing blocks or authenticate a state-sync snapshot.

`recover_canonical_ffg_settlements` composes the resulting private-constructor
capability with full proof/PQ/Reth recovery. Every retained settlement must match
the exact bytes executed in a native block inside the finalized prefix. Each
authority receipt's checkpoint epoch/root must agree with native replay, including
old records before the external rollback floor. A valid WS signature cannot
replace missing FFG finality or change the native checkpoint convention.

`cursor::recover_and_stage_ffg_finality_candidate` applies the same requirements
to candidate staging and rechecks both previous and current checkpoint bindings.
A native tip from a future epoch is refused against the independently supplied
current epoch. The existing candidate encoding remains unchanged; it is not a
saved native-finality capability. Restart requires fresh native replay as well as
L2/history recovery. Generic compatibility APIs make no FFG claim.

The additional `ffg_recovery.rs` qualification uses a new genuine Groth16 proof,
real proposer signatures and real FFG votes from three disposable test validators.
Public fixtures retain the signed blocks, attestations and proof provenance;
private keys remain in the generator process. Tests cover 2/3 and 3/3 agreement,
two-round finalization, insufficient/duplicated/conflicting votes, branch and
signature changes, bounds, stale checkpoint claims and recovery after restart.
These tests cover epochs 0–3 of the isolated fixture, not a live network or all
activation/leak/fault regimes. Native consensus rules and their historical
activation gates are replayed unchanged; this is not a new economic-finality
guarantee or evidence of independent operational validators.

## Trust and remaining production work

The host must stop all Reth and static-file writers, independently retain all
three rollback floors, select both policies and supply a trusted current epoch.
Copying a floor from the directory under inspection cannot detect a lost suffix.
The 32-byte settlement network identity and native checkpoint network number
have distinct formats; their association remains an explicit host configuration
input. This adapter does not invent a conversion between them. The native
genesis identity is compared directly.

The execution-proof verifier is a required trusted host dependency; an arbitrary
implementation of the verifier trait is not evidence of proof soundness. The
native and FFG entry points select the real verifier internally. Native
checkpoint signatures authenticate the selected weak-subjectivity arrangement,
not an independent FFG history or organizational independence of its members.
Historical receipts can be recovered after expiry but cannot become fresh
checkpoint capabilities. Current use still requires the checkpoint freshness
check.

The report is not a finalized-block capability. This library does not set Reth
`safe`/`finalized`, activate native settlement consensus, establish operational
validator authority, start a production service or authorize DEX liquidity or
bridge payouts. The seven production gates in `network/finality.json` remain unchanged.

## Reproduce

Use Rust 1.98.1, the committed lockfile and these independently checked sources:

- Native consensus revision `2b808ca370276d3415a24d20e1892d79fed2a750` in the
  sibling `bloch-validator-payout` directory, without local changes.
- Reth base `8eb210175687c9f0c889a3b6795c16781d830e3a` plus the exact recorded
  `../reth-execution/reth-snapshot.patch`, prepared with its existing tool.

The Cargo path declarations do not enforce the native Git revision. Verify it
before building; a clean archive of that revision is also suitable. The root
manifest repeats the native `pqcrypto-internals` patch because Cargo ignores
patch declarations from transitive dependencies. Registry packages are locked.

From the L2 repository root, after preparing the pinned Reth worktree:

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --offline --locked \
  --manifest-path integrations/settlement-recovery/Cargo.toml
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 clippy --offline --locked \
  --manifest-path integrations/settlement-recovery/Cargo.toml \
  --all-targets -- -D warnings
```

The combined tests use actual MDBX, RocksDB and static-file storage, kernel
execution of a synthetic deposit and a genuinely signed EVM transaction, real
disposable hybrid PQ signatures, complete synthetic native bodies and retained
V4 authority receipts. They reopen all histories, preserve independent floors,
reject an older bad record beneath a valid latest record, reject a corrupted
PQ signature before proof replay, exercise late proof refusal and detect L2
advancement during recovery. They check lock release, unchanged audit-history
bytes and absent safe/finalized markers. The older `recovery.rs` suite retains its
explicit proof double for fault injection; the additional `native_recovery.rs`
suite uses the retained real Groth16 proof and the pinned native verifier.
Neither uses operational keys.


## Asynchronous native development settlement

`audit_finalized_async_settlements` consumes only the private-constructor result
of full native replay and checks every finalized `0x0F` settlement against the
canonical L2 prefix in order. The native `BPOSMAN3` genesis pins a public source
across blocks while a real proof is generated. The existing `0x0E` immediate
parent admission and WS stores remain unchanged; changing a wire tag does not
turn an older admission receipt into asynchronous authority.

`qualify_live_async` imports a public native manifest pinned independently by
its SHA3 network identity, decodes the node's exact canonical envelopes, verifies
real proposer/attester signatures, Groth16 and FFG, and executes/binds the first
empty-inbox L2 block in an isolated persistent database. Run `init` once in a
fresh directory and `recover` in a separate process against that same database.
It refuses altered proof/body bytes, altered proposer signatures and inclusion
before finality. File counts, encoded bytes, epochs and proof work are bounded.
The current qualification worker supports one empty-inbox block, not continuous
production, native deposits, bridge withdrawals or operational checkpoints.

```sh
# Build with the pinned native and Reth sources above.
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 build --offline --locked \
  --manifest-path integrations/settlement-recovery/Cargo.toml \
  --example qualify_live_async
# Supply the retained installation pin, never a network value from submitted history.
qualify_live_async init genesis.blg "$PINNED_MANIFEST_SHA3" history fresh-l2-db init.json
qualify_live_async recover genesis.blg "$PINNED_MANIFEST_SHA3" history fresh-l2-db recovered.json
```

Neither the report nor the new correspondence-only audit method authorizes
RPC finality publication. Production readiness and same-host validator fault
independence remain separate operational requirements.
