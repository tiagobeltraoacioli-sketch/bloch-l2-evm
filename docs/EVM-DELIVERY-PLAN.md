# Bloch developer EVM delivery plan

The objective is a developer-usable EVM integrated with Bloch. A successful
library test or local example alone does not complete that objective. Production
activation and movement of real funds are outside the currently authorized work.

## Current evidence and completion gates

| Deliverable | Current implementation | Evidence required to close the remaining work |
| --- | --- | --- |
| Signed contract execution | `developer_contract` executes signed deploy/call with storage, gas, nonce, root agreement and adversarial assertions | Local example gate exercised; wider conformance remains under compatibility below |
| Reproducible local operator workflow | `tools/developer-rehearsal.py` generates synthetic escrow/deploy/call proposals and drives separate `bloch-domain` processes | Local two-block recovery/replay/tamper gate exercised; this recovers commitments/cursors, not a queryable node database |
| Developer node and wallet workflow | EIP-1193 client adapter; Reth RPC, pool and node are stubs | Real Reth integration preserving signed bytes through admission/execution; wallet deployment/call, receipts, logs, state queries and restart tests |
| Authenticated native derivation | Header/body verification, PQ checkpoints and typed native state observations | Consensus-defined domain/inbox commitments and source mapping; reject forged, incomplete, stale, conflicting and replayed derivation; no mint from UTXO membership alone |
| Native settlement and escrow | Experimental lock/inbox kernel and durable PQ facade | Implemented consensus-enforced lock/settle/withdraw transitions with conservation, replay and invalid-proof tests in an isolated devnet; documented activation proposal |
| Proof backend | Host witness verifier; SP1 entrypoint and prover are stubs | Reproducible pinned guest/prover/verifier build, real accepted and rejected proofs binding all public inputs, measured proving cost and documented cryptographic assumptions |
| Compatibility and release evidence | Focused core regressions and wallet adapter tests | Applicable EVM conformance fixtures, end-to-end developer acceptance tests and an honest supported/unsupported surface; deployment and recovery instructions |

## Execution order

1. Make signed deployment and storage mutation reproducible from a fresh local
   checkout. Keep synthetic funding and finality visible in both output and docs.
2. Provide fixture generation for the durable operator flow and verify restart
   and replay protection. Do not make generated trust files appear authenticated.
3. Integrate the specified Reth RPC/pool/node stack, with an explicit dependency
   compatibility decision for the pinned executor. Do not replace its Ethereum
   API with a handwritten compatibility layer or successful placeholder replies.
4. Implement the native derivation and settlement format in an isolated devnet,
   preserving the existing mainnet rules. Review the existing native EVM singleton
   separately from the new experimental inbox: they are not interchangeable.
5. Integrate the real proof backend over the same execution/public-input semantics
   and run the combined developer, recovery, compatibility and settlement gates.

The external design file referenced by the original scaffold,
`docs/specs/BLOCH-L2-EVM-DESIGN.md`, was not found in the local repositories during
this resumption. Existing explicit constraints in `src/stubs.rs`, the wallet
compatibility document and the modular integration documents remain applicable.
Missing source material is not permission to silently change those constraints.

## Work tracking

Keep implementation and validation evidence in the relevant component documents
and the version-control diff. Leave a gate open until its required behavior has
actually been exercised; synthetic tests establish local correctness, not live
finality, proof-system security or production activation.

### Reth dependency inspection

The initial integration candidate is upstream tag `v2.4.1`, commit
`8eb210175687c9f0c889a3b6795c16781d830e3a`, inspected in a separate checkout
`../reth-bloch-integration`. Its
[manifest](https://github.com/paradigmxyz/reth/blob/8eb210175687c9f0c889a3b6795c16781d830e3a/Cargo.toml)
declares Rust 1.95, revm 41.0.0, Alloy primitives 1.6.1 and Alloy consensus 2.1.1.
The portable core remains on Rust 1.94.1 and exact Alloy consensus 2.2.0. Version
ranges alone do not prove a common resolved dependency graph or equal semantics.
No toolchain or dependency upgrade has been applied to the portable core.

Upstream's `examples/custom-evm` demonstrates an executor factory and node builder,
but its ordinary Ethereum block executor does not implement Bloch deposits,
base-fee vault routing, supply accounting or domain commitments. Launching that
example would not complete the Bloch node. Before integrating, build a separately
pinned host crate and compare its state transitions with the existing core;
ensure RPC calls and payload execution use the same Bloch execution rules.
The upstream `example-custom-evm` passed `cargo +stable check --locked` with the
locally installed Rust 1.98.1. This is upstream compile evidence only: no Bloch
adapter was linked, no node was launched, and neither core dependencies nor its
pinned compiler changed. The upstream lock also resolves older Alloy/ruint
versions than the core; a combined dependency graph still needs qualification.

The next code boundary is the core's existing generic `run_block<DatabaseRef>`
kernel: expose a signed read-only-database adapter with a successful overlay and
explicit host-supplied root finalization, then differential-test a Reth storage
adapter against `execute_signed_block`. Preserve the core's fixed-width header
hash and committed `BLOCKHASH` ring. Vanilla Ethereum RLP headers have different
identities. The current header also lacks transaction/receipt-root commitments;
adding them requires a versioned execution-domain upgrade, not extra uncommitted
RPC fields. A full node additionally needs the incremental block-building path,
custom primitives/assembler, receipts and authenticated deposit context.
