# Native settlement recovery

This separate, experimental Unix AGPL-3.0-or-later host crate holds the native
FFG replay used by `bloch-l2-native-follower`, the L2 reconstruction used by
`bloch-l2-produce-dev` and the durable asynchronous finality candidates.
Neither the portable EVM crate nor the Reth integration gains this dependency.

## Retired: WS-checkpoint settlement recovery

The legacy composition of weak-subjectivity checkpoints with the `0x0E`
settlement store was retired on 2026-10-30. `recover_canonical_settlements`,
`recover_canonical_native_settlements`, `recover_canonical_ffg_settlements`, the
`cursor` module, the `proof` module, the portable `native_settlement::store` module
and `native-escrow-pq::settlement_authority` no longer exist. The portable
`settlement_admission` module stays, with no consumer outside its own tests: the
pinned SP1 guests compile it, and removing it changes the `settlement_v3_mainnet`
ELF (`203114bf...` to `919ebe5b...`), which chain 700770 would refuse.

That path could not admit a settlement from a current native chain: its store
accepted only the historical `0x0E` envelope (devnet1-3 history), while native
consensus now uses `0x12` (async `0x13`) and assigns `0x0E` to funded delegation.
No release binary linked it. L1 finality comes from FFG replay, with no checkpoint
signatures (see `docs/L2-FINALITY.md`, "Ethereum-rollup finality"). The code and
its history remain available in version control.

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

The production follower replays with `native::IncrementalNativeVerifierV1` and
binds finalized asynchronous settlements through `async_cursor`.

The additional `ffg_recovery.rs` qualification uses a genuine Groth16 proof,
real proposer signatures and real FFG votes from three disposable test validators.
Public fixtures retain the signed blocks, attestations and proof provenance;
private keys remain in the generator process. Tests cover 2/3 and 3/3 agreement,
two-round finalization, insufficient/duplicated/conflicting votes, branch and
signature changes, bounds and restart-stable replay of the exact finalized
settlement bytes. The
fixtures were regenerated on 2026-10-30 against native `78d4921c` because the
native genesis state commitment and the settlement wire tag had changed since the
original `7eb58904` fixtures; regenerate them with `examples/qualify_native_ffg.rs`
whenever the pinned native state commitment or wire format changes.
These tests cover epochs 0–3 of the isolated fixture, not a live network or all
activation/leak/fault regimes. Native consensus rules and their historical
activation gates are replayed unchanged; this is not a new economic-finality
guarantee or evidence of independent operational validators.

## Trust and remaining production work

The host must stop all Reth and static-file writers, independently retain its
rollback floors, pin the genesis and policy and supply a trusted current epoch.
Copying a floor from the directory under inspection cannot detect a lost suffix.

The report is not a finalized-block capability. This library does not set Reth
`safe`/`finalized`, activate native settlement consensus, establish operational
validator authority, start a production service or authorize DEX liquidity or
bridge payouts. The seven production gates in `network/finality.json` remain unchanged.

## Reproduce

Use Rust 1.98.1, the committed lockfile and these independently checked sources:

- Native consensus revision `15a5f4f62f6d1993bfcd7ab1c5c4aa9d7e632e18` in the
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

## Asynchronous native development settlement

`audit_finalized_async_settlements` consumes only the private-constructor result
of full native replay and checks every finalized `0x0F` settlement against the
canonical L2 prefix in order. The native `BPOSMAN3` genesis pins a public source
across blocks while a real proof is generated.

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
qualify_live_async init genesis.blg "$PINNED_MANIFEST_SHA3" history fresh-l2-db init.json none "$CURRENT_EPOCH"
qualify_live_async recover genesis.blg "$PINNED_MANIFEST_SHA3" history fresh-l2-db recovered.json "$RETAINED_CANDIDATE_COMMITMENT" "$CURRENT_EPOCH"
```

Neither the report nor the new correspondence-only audit method authorizes
RPC finality publication. Production readiness and same-host validator fault
independence remain separate operational requirements.

### Durable asynchronous candidate

`async_cursor::recover_and_stage_async_finality_candidate` now persists the
asynchronous audit result in a separate `BlochAsyncFinalityCandidate` MDBX table.
It accepts only the private result of full real native replay, audits every
finalized `0x0F` settlement against canonical L2, and rederives the complete saved
candidate before replacing it. No checkpoint receipt or signer policy is involved.
The retired WS-authorized cursor's `BlochFinalityCandidate` table stays declared
in the Reth database schema, so existing databases keep opening; nothing writes it.

The `BLAFNC01` record is exactly 344 bytes. It binds the native genesis state
root and settlement policy, finalized native checkpoint, last settlement block
and exact transaction digest, ordered settlement-prefix digest, L2 genesis,
number, hash and state root, settlement count, and observation epoch. The digest
includes the original transaction tag and proof bytes. These hashes describe a
local audit record, not new native consensus commitments.

The exact prior cursor commitment must be retained independently; `None` allows
only an empty singleton table. Recovery refuses missing rows, extra rows,
unknown newer cursors, forged fields and truncated or conflicting finalized
history. It reconstructs the old settlement and complete prefix even if the
supplied cursor checksum matches. The previous finalized checkpoint must remain
on the verified branch. An unfinalized native tail may reorganize because its
tip is deliberately not the rollback floor.

After validation, one MDBX transaction compares the previous cursor, the
acknowledged canonical L2 tip and absence of numeric finality markers, then
publishes the candidate. All Reth and static-file writers must remain stopped.
Commit uncertainty or failure to retain the returned mark requires independent
recovery; never adopt the inspected database's own checksum as its trusted floor.
Every restart still requires full native replay and canonical L2 verification.

The qualification example now requires the externally retained mark for
`recover` and reports `candidate_commitment` for independent retention. It also
requires a trusted current epoch and rejects a replayed native tip from the
future. The recorded epoch is an observation bound, not proof of current network
freshness. This remains offline candidate preparation; `safe` and `finalized`
are not written or published.

The candidate storage tests use real MDBX and executed Reth blocks with a
deliberately synthetic native capability confined to `cfg(test)`. They cover
restart, monotonic advancement, tampering, rollback, canonical mismatches and
commit races. The separate `ffg_recovery` suite exercises genuine native
signatures, proofs and FFG with the retained fixture. These
tests do not substitute for an end-to-end signed asynchronous-history rehearsal
of the new candidate API or qualify production publication.

Reproduce the separate codec tests with the same prepared sources:

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --offline --locked \
  --manifest-path integrations/reth-execution/Cargo.toml --lib async_finality_cursor
```
