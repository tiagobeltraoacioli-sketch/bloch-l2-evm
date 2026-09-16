# Bloch execution over a Reth state provider

This host integration uses the real `reth_revm::database::StateProviderDatabase`
to run Bloch's signed whole-block executor against an `EvmStateProvider`. Reth's
`StateProvider` has an upstream blanket implementation of that interface.
It provides the storage-read boundary for future node integration, not a node,
RPC endpoint, pool, proof backend or durable database writer.

## Reproduce

Use a sibling `reth-bloch-integration` checkout at exactly:

```text
https://github.com/paradigmxyz/reth
8eb210175687c9f0c889a3b6795c16781d830e3a (v2.4.1)
```

The path dependency does not enforce its Git revision; verify the checkout before
building. The host integration uses Rust **1.98.1** and its own committed lockfile.
The portable EVM core retains its separate Rust 1.94.1 toolchain and lockfile.
From the modular execution repository root:

```sh
git -C ../reth-bloch-integration rev-parse HEAD
cargo +1.98.1 test --locked --manifest-path integrations/reth-execution/Cargo.toml
cargo +1.98.1 clippy --locked --manifest-path integrations/reth-execution/Cargo.toml --all-targets -- -D warnings
```

Add `--offline` once dependencies are cached. Upstream's original lock resolves
older Alloy consensus/ruint versions; this integration's graph resolves the core's
exact Alloy consensus 2.2.0, primitives 1.6.1, trie 0.9.5, ruint 1.20.0 and revm
41.0.0. It is a separately qualified host build, not the unchanged upstream
release binary or an attested execution artifact.

## Execution boundary

`execute_on_provider(spec, provider, previous_root, signed_input)` wraps the
provider and calls `execute_signed_block_on_database` in the portable core.
That function authenticates the original signed envelopes and calls the same
`run_block` kernel used by host state execution and witness verification.
Deposit metering, supply/cursor updates, fee-vault routing, EIP-4788 and the
committed Bloch `BLOCKHASH` ring therefore share one implementation.

Successful execution returns `DatabaseBlockExecution`. Its `overlay()` exposes
the successful read/change cache without writing the provider. On execution
failure no candidate is returned. The backing provider can perform internal
read caching, but the execution adapter does not call a storage commit method.

The caller must hold a consistent pre-state snapshot and supply its correct root,
derive/authenticate deposits and L1 context independently, calculate the complete
post-state MPT root, then atomically persist the matching overlay. Passing that
root to `finalize` attaches it to the outcome; **finalize does not verify the
root**. A wrong supplied pre-root can change parent and `BLOCKHASH` commitments.
This adapter must never replace authenticated witness/domain verification for an
untrusted proposal.

The overlay is sparse. Read-only cached accounts are not necessarily changes;
untouched storage survives unless cleared, and destroyed/empty accounts must be
handled consistently with revm/EIP-161. Simply replacing full backing accounts
with partial overlay entries is incorrect.

`execution_bundle(&execution)` converts a successful execution to upstream
`BundleState`, including one block of reverts. It compares cached entries with
the unchanged backing snapshot, retains explicit zero writes, preserves storage
wipes and includes newly deployed bytecode. It does not scan untouched accounts
or their storage. Conversion may fail on a backing read or missing new bytecode;
no partial bundle is returned and no backing writes occur.

Use the bundle to calculate the complete post-state root and pass it to the
storage writer in the same host transaction. Deleted storage that was never read
is deliberately absent from this sparse bundle. Reth's writer must capture that
account's original storage while processing wipe reverts **before** applying
forward changes. The bundle alone is not a complete historical snapshot.
Actual Reth trie calculation, atomic database writes, reopening and unwind remain
integration work; this adapter does not provide those operations.

## Remaining node work

The current Bloch header uses its existing fixed-width hash, not Ethereum RLP.
It also lacks signed-transaction and receipt-root commitments. A complete node
needs custom block/header primitives and a versioned protocol upgrade for those
commitments, together with the appropriate Reth assembler, receipts, incremental
payload builder, pool/RPC wiring and authenticated deposit derivation. Launching
a vanilla Ethereum Reth node would not satisfy these requirements.

## Validation scope

`tests/provider.rs` supplies a fixture implementing upstream's `EvmStateProvider`
and executes through the real Reth database reader. Read counters exercise
account, storage-key and bytecode conversion. Its deliberately incorrect external
block hashes are never read: Bloch's committed ring supplies `BLOCKHASH`.
The fixture enumerates complete local state to calculate an independent MPT root
and compares it with direct core execution over signed deployment/call and revert.
Provider errors propagate and malformed signed input fails before provider reads.
The tests also apply upstream plain changes and reverts to a fixture store,
checking both the forward root and the restored pre-state root for every block.
The fixture provider is not MDBX or a live node; no persistence qualification
follows from these tests. The portable core has separate generic-adapter tests,
including a valid first transaction followed by an invalid nonce, which must
leave its borrowed backing snapshot unchanged.

Both test suites also execute a signed creation that destroys a prefunded account
in the same transaction. They assert the exact nonzero EIP-6780 burn, account
deletion and supply conservation. The portable Rust 1.94.1 and host Rust 1.98.1
builds agree on the following fixture roots, now pinned in both suites:

| Fixture | Final state root |
| --- | --- |
| Four-block deploy/call/revert | `0xcaa54b319b1297820f2e71093a55156bb19225c76eec4c9f40672c6b4e6453f3` |
| Two-block prefunding/burn/deletion | `0x8d248f2fca24dad8c10537c898904ab52a031c765cb8e6a41f465dff2ef57873` |

These vectors check cross-build agreement for the exercised scenarios, not full
EVM conformance or equivalence of every dependency/compiler configuration.
