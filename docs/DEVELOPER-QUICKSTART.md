# Run a signed contract locally

This quickstart deploys and calls a contract using the Bloch EVM library. It uses
the real pinned Cancun executor, signed Ethereum transactions and authenticated
state witnesses. Funding and L1 anchors are synthetic fixtures. No node, RPC
endpoint, wallet connection, proof backend or live blockchain is required.

## Run

From the repository root, with the pinned Rust 1.94.1 toolchain:

```sh
cargo +1.94.1 run --locked --example developer_contract
```

Add `--offline` when the dependencies are already cached. The example uses only
dependencies in the committed lockfile; it needs no Solidity compiler. Source:
[`examples/developer_contract.rs`](../examples/developer_contract.rs).

A successful run prints the synthetic-context notice, gas and state roots for
two blocks, the sender and deployed contract addresses, followed by:

```text
storage[0]: 42; sender nonce: 2
Host, witness and domain roots agree. Tampering and replay rejected without advancing cursors.
```

Assertions run in both debug and release builds. Any failed check terminates the
example with a nonzero exit code. CI executes the example's `main`; merely
compiling the example would not exercise these assertions.

## What executes

1. Start from the zero-credit EVM genesis and bind it into a local execution
   domain with fixed network/module/runtime fixture identities.
2. Include one synthetic 100,000,000-satoshi deposit in the first block and sign
   an EIP-1559 creation transaction with nonce zero. The deposit credits exactly
   one simulated BLCH (10^18 wei) under the library's conversion rules.
3. Generate the pre-state witness, verify the signed block through the domain
   and execute it against host state. All three post-state roots must agree.
4. Sign a second-block call with nonce one and a 32-byte big-endian value of 42.
   The deployed bytecode writes that word to storage slot zero. Check the stored
   value, successful execution, gas consumption and sender nonce two.
5. In each block, reject a forged witness root, malformed transaction bytes and
   replay; check that rejected work preserves the relevant state/cursors. Check
   the final minted/native supply as well.

The runtime is a minimal raw EVM setter, not a Solidity ABI contract: it reads
calldata word zero directly and does not dispatch on a four-byte selector. The
return value is not exposed by this example; the assertion reads the resulting
storage from the host database.

## Adapt the example

Change `value` to exercise another storage value. Replace `initcode` with your
compiler's deployment bytecode and the call input with the appropriate ABI
calldata to try a different contract; update the example's storage/address
assertions to match its behavior. For Solidity, compile for **Cancun**: this
executor does not enable later hardfork opcodes. The small initcode wrapper used
here supports only a runtime whose length fits in one byte; use the compiler's
full creation bytecode for larger contracts.

Every transaction is encoded and signed using the configured chain ID. Preserve
those signed bytes when extending the flow. The published fixture private key
is disposable and must never control real assets.

## Use a persistent node and wallet

The [isolated Reth developer node](../integrations/reth-execution/DEVNODE.md)
provides RPC, automatic mining and a persistent contract database with explicit
synthetic funding. The [RPC compatibility matrix](../integrations/reth-execution/RPC-COMPATIBILITY.md)
lists exercised methods. Use the documented
[ethers/Solidity](../wallets/SOLIDITY.md) or
[MetaMask](../wallets/browser/README.md) workflows for actual client deployment.

Selected persisted blocks can be
[exported as sparse execution artifacts](../integrations/reth-execution/PROOF-EXPORT.md)
for the separately pinned SP1 host. The
[proof-chain rehearsal](PROOF-CHAIN-REHEARSAL.md) verifies actual proofs and
reopens a local journal from independently selected inputs. Native funding and
finality authentication remain separate from those execution checks.

## Rehearse the escrow operator

To run the same deployment/call pattern through the durable operator CLI:

```sh
python3 tools/developer-rehearsal.py /tmp/bloch-developer-rehearsal --offline
```

The output directory must not exist and its parent must exist. Omit `--offline`
when Cargo needs to download dependencies. This uses Python 3's standard library
and the pinned Rust toolchain. The script builds the CLI and fixture generator,
then invokes a separate CLI process for each apply/status operation. It checks
the two expected state roots, retains each accepted head in a separate file,
reopens and verifies the journal, rejects replay and rejects a forged witness
root before any valid commit. A successful run writes `rehearsal-report.json`.

The fixture generator first executes signed deploy/call against host state and
checks contract storage equals 42. Journal recovery independently re-executes the
saved witnesses and must reach those same roots and cursors. It recovers the
verifier's commitment/cursors, not a queryable persistent contract database.

Generated files include:

| Path | Purpose |
| --- | --- |
| `config.json` | Fixed local profile and expected escrow execution domain |
| `trust/` | **Synthetic** L1 derivation inputs, one file per L2 block |
| `proposals/` | Signed transactions, witnesses and required inbox proofs |
| `minimum-head.json` | Initial genesis watermark |
| `head-after-1.json`, `head-after-2.json` | Accepted heads retained outside the journal |
| `expected.json` | Host-checked contract/address, storage value and roots |
| `journal/` | Actual durable records created by the operator CLI |
| `rehearsal-report.json` | Results emitted only after all rehearsal checks pass |

The common parent directory is convenient for this disposable demonstration;
watermarks there cannot detect rollback of the entire directory. Production
operators must retain accepted watermarks in an independent durable location.
The generator creates a local escrow inclusion proof but assumes synthetic
funding authorization; it does not produce PQ authorization or native finality.

To generate inputs without running the CLI:

```sh
cargo +1.94.1 run --locked --manifest-path integrations/escrow-journal/Cargo.toml --example developer_fixture -- /tmp/bloch-developer-inputs
```

Use a new destination for each run. Files from failed runs are kept for
inspection; neither tool resets an existing journal or overwrites an old run.

The [durable operator CLI](../integrations/escrow-journal/CLI.md) verifies,
commits and replays escrow-domain proposals generated by this rehearsal. The
standalone Rust example at the start uses the in-memory `EvmDomain`; the Python
rehearsal exercises the persistent operator path.

Here, `TrustedL1Batch` is assembled from the same local fixture as the proposal.
That is useful for local execution testing and is **not** independent L1
authentication. Likewise, a configured runtime hash identifies a fixture, not
an attested program. See the [full delivery gates](EVM-DELIVERY-PLAN.md) and
[modular trust boundary](../MODULAR-EXECUTION.md) for the remaining native
derivation, settlement and proof work.
