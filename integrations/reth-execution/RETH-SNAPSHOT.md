# Reth transaction snapshot correction

The host uses upstream Reth `v2.4.1`, base commit
`8eb210175687c9f0c889a3b6795c16781d830e3a`, plus the local
[`reth-snapshot.patch`](reth-snapshot.patch). This is a qualified Bloch host
integration change, not a claim that upstream's published release contains it.

Patch SHA-256: `fe1f293c58cf45281c208e90950c1b9221887459640c031d61c5aed9489d0977`.
Patched `consistent.rs` SHA-256:
`1e3b23b5ba0444faf9bb903ba6dc7e65bb928430ded2024869a772e842e91ffa`.

## Failure and correction

With automatic mining, a successful contract event followed by a bounded
`eth_getLogs` query could return `-32603: block meta not found for block #29`,
even when the requested range contained only block 17. The filter needs the
transaction hash for each matching receipt. Its transaction lookup uses Reth's
`ConsistentProvider`, which opens a real MDBX read snapshot.

When there is no in-memory executed-block overlay, the individual and range
transaction helpers selected their storage boundary with `last_block_number()`.
That reads the shared static-file tip, which can advance after the MDBX snapshot
opens. Looking up the newer tip's body indices in the older snapshot then fails.
The canonical coordinator publishes only after its commit, but static-file
visibility and an already-open MDBX read transaction do not advance atomically.

The patch changes those two boundary selections to `best_block_number()`, which
reads the completed `Finish` checkpoint from the same MDBX snapshot. In-memory
anchor selection is unchanged. No RPC retry, synthetic response, provisional
block publication or serialization of all clients is introduced.

The patch is deliberately about transaction lookup boundaries. Other upstream
uses of `last_block_number()` and broader snapshot/reorganization behavior are
outside this correction. It does not make all storage backends crash-atomic.

## Reproduce and inspect

From the modular execution repository root, with the clean base checkout above:

```sh
python3 integrations/reth-execution/prepare-reth.py
python3 integrations/reth-execution/prepare-reth.py --check
git -C ../reth-bloch-rpc-snapshot diff -- crates/storage/provider/src/providers/consistent.rs
```

The helper creates `../reth-bloch-rpc-snapshot` as a detached worktree, applies
only the recorded patch, and compares the entire tracked diff byte-for-byte
against that patch. Staged changes, untracked files or another HEAD are refused.
It does not reset or overwrite unrelated existing changes. `--check` performs no
worktree creation or patching. The original sibling checkout remains unchanged.
All host Reth path dependencies resolve through the prepared worktree; the
portable core, SP1 guest and native consensus checkout are unaffected.

An optional command after `--` runs only after that source verification. The
helper supplies `VERGEN_GIT_SHA` and `VERGEN_GIT_DESCRIBE` obtained from native
Git and `VERGEN_GIT_DIRTY=true` for the verified patch. This avoids the upstream
build's libgit2 describe traversal failing on a missing parent object in a
shallow worktree. The build reports the actual base and a development suffix;
it is not labelled as a clean upstream binary.

## Regression

Two tests in `tests/canonical_coordinator.rs` hold a `ConsistentProvider` created
at genesis, then commit another block through the real coordinator. They exercise
transaction-ID and transaction/receipt-range queries using the old snapshot.
The unmodified base fails both tests deterministically with
`BlockBodyIndicesNotFound(1)`, without a timing loop or injected provider errors.
The expected result is an empty query response from that original snapshot.
A third regression retains a snapshot after a funded, signed transaction, then
commits another signed transaction. The old snapshot must preserve its original
transaction and receipt while excluding the new transaction; a fresh query sees
both. This also checks snapshot content, beyond avoiding the original error.

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml \
    --test canonical_coordinator --test devnode_process
npm --prefix wallets run test:devnode
```

The ethers acceptance queries the real persisted event by exact block range,
address and topic before and after restart. Wrong-topic queries must be empty.
An occasional passing run on the unmodified source does not close this race;
the held-snapshot tests are the deterministic regression boundary.

Recorded host validation on 2026-09-17: the prepared source passed all eight
canonical-coordinator tests (7.74 seconds) and all five developer-process tests
(9.57 seconds), including the three snapshot regressions and HTTP filter/revert
flows. Ethers acceptance passed on the corrected executable (10.349 seconds),
including positive and wrong-topic queries before/after restart. Clippy passed
for the binary and both affected Rust test targets with `-D warnings`; upstream
ECIES deprecation and build-metadata notices remain separate dependency warnings.
These results qualify this host integration; they are not a full upstream
Reth workspace test result or a production crash-consistency claim.
