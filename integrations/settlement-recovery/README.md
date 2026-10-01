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

## Trust and remaining production work

The host must stop all Reth and static-file writers, independently retain all
three rollback floors, select both policies and supply a trusted current epoch.
Copying a floor from the directory under inspection cannot detect a lost suffix.
The 32-byte settlement network identity and native checkpoint network number
have distinct formats; their association remains an explicit host configuration
input. This adapter does not invent a conversion between them. The native
genesis identity is compared directly.

The execution-proof verifier is a required trusted host dependency; an arbitrary
implementation of the verifier trait is not evidence of proof soundness. Native
checkpoint signatures authenticate the selected weak-subjectivity arrangement,
not an independent FFG history or organizational independence of its members.
Historical receipts can be recovered after expiry but cannot become fresh
checkpoint capabilities. Current use still requires the checkpoint freshness
check.

The report is not a finalized-block capability. This library does not set Reth
`safe`/`finalized`, activate native settlement consensus, qualify proof transport,
start a production service or authorize DEX liquidity or bridge payouts. The
seven production gates in `network/finality.json` remain unchanged.

## Reproduce

Use Rust 1.98.1, the committed lockfile and these independently checked sources:

- Native consensus revision `5af78a04a27dcb2c2253c32134fca888a8a965f9` in the
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
bytes and absent safe/finalized markers. The execution-proof verifier is an
explicit test double; these tests do not generate a real Groth16 proof or use
operational signing keys.
