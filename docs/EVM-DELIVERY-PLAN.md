# Bloch developer EVM delivery plan

The objective is a developer-usable EVM integrated with Bloch. A successful
library test or local example alone does not complete that objective. Production
activation and movement of real funds are outside the currently authorized work.

## Current evidence and completion gates

| Deliverable | Current implementation | Evidence required to close the remaining work |
| --- | --- | --- |
| Signed contract execution | `developer_contract` executes signed deploy/call with storage, gas, nonce, root agreement and adversarial assertions | Local example gate exercised; wider conformance remains under compatibility below |
| Reproducible local operator workflow | `tools/developer-rehearsal.py` generates synthetic escrow/deploy/call proposals and drives separate `bloch-domain` processes | Local two-block recovery/replay/tamper gate exercised; this recovers commitments/cursors, not a queryable node database |
| Developer node and wallet workflow | Isolated synthetic executable with Reth HTTP/log filters, mining, canonical persistence and pool maintenance; ethers and real MetaMask deploy/call/restart exercised, plus rejection, revert and log-query tests | Broader wallet compatibility, authenticated pending/native derivation, crash recovery and complete supported RPC qualification |
| Authenticated native derivation | Header/body verification, PQ checkpoints and typed native state observations with genesis-derived height identification | Consensus-defined domain/inbox commitments and source mapping; reject forged, incomplete, stale, conflicting and replayed derivation; no mint from UTXO membership alone |
| Native settlement and escrow | Experimental lock/inbox kernel and durable PQ facade | Implemented consensus-enforced lock/settle/withdraw transitions with conservation, replay and invalid-proof tests in an isolated devnet; documented activation proposal |
| Proof backend | Canonical execution statement; SP1 6.8.0 synthetic guest linked and executed for empty and signed-contract fixtures, with invalid guest inputs rejected; local core-proof harness under validation | Reproducible pinned guest/prover/verifier build, real accepted and rejected proofs binding all public inputs, measured proving cost and documented cryptographic assumptions |
| Compatibility and release evidence | Focused core regressions, all 122 pinned Ethereum KZG verification vectors passing on both backends, wallet adapter tests and a documented exercised RPC surface | Wider applicable EVM conformance fixtures, end-to-end developer acceptance tests and complete deployment/recovery qualification |

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

The current host source additionally applies a recorded two-site Reth transaction
snapshot correction in a separate prepared worktree. The upstream base remains
pinned and clean; see [source preparation and regression](../integrations/reth-execution/RETH-SNAPSHOT.md).
The patch addresses concurrent log queries observing a newer static-file tip than
their MDBX read snapshot. It does not change the portable executor or SP1 program.

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

The core's existing generic `run_block<DatabaseRef>` kernel now has a
[signed database adapter](DATABASE-EXECUTION.md) returning a successful overlay
and explicit host-supplied root finalization. The separate
[Reth provider integration](../integrations/reth-execution/README.md) wraps the
actual upstream database reader; its own lockfile resolves the core's exact EVM
and signed-envelope versions. This is not the node or persistence layer.
The adapter now converts successful overlays to upstream `BundleState` with
storage wipes, new bytecode and one block of reverts. Fixture tests apply its
plain changes and reverts and compare forward and restored roots. A real Reth
storage test also checks trie roots, committed state/bytecode/changesets,
uncommitted writer abort and orderly close/reopen. Those operations remain test
harness plumbing. A deleted account's unread storage is also restored solely
from persisted changesets after reopening, recovering the original root. This
does not prune history or unwind block metadata; the separate V2 canonical test
below covers orderly full unwind. Crash recovery and the node storage service
remain open. Incremental signed
construction now shares the core kernel with whole-block verification and runs
through the real Reth provider in storage tests. The real SDK executor factory
now uses the shared lifecycle with supplied inspectors, bounded signed candidates
and a frozen committed BLOCKHASH window. Payload builder and custom node wiring
remain required. Preserve the core's fixed-width header hash and domain identity.
Vanilla Ethereum RLP headers have different
identities. The V1 header lacks transaction/receipt-root commitments; the separate
V2 format below adds those commitments without changing V1 identities. A full
node still needs authenticated deposit context and the remaining node services.
The [node integration dependency map](RETH-NODE-INTEGRATION.md) records the
inspected Reth interfaces, storage qualification and versioning requirements.

### SDK block factory qualification

The host now implements the real Alloy `BlockExecutorFactory` using the supplied
Bloch EVM, the shared protocol lifecycle and canonical signed reauthentication.
It produces typed user receipts, preserves deposit gas in the block total, and
rejects stale/foreign owned results before publication. The core captures the
immutable BLOCKHASH window before system calls; an adversarial contract mutation
fixture verifies parity. Multi-block roots, receipts/logs and inspector tests
qualify this factory. The V2 primitives, assembler and canonical storage coverage
below build on it. Consensus, pool/RPC, crash recovery and the independent
native/prover gates still prevent closure of the developer node gate.

### Independent V2 primitives

The [V2 node format](NODE-V2-FORMAT.md) now has bounded, version-tagged header,
body and block RLP codecs plus signature, commitment, parent and receipt/gas
consistency validation. Golden vectors and malformed-input tests preserve its
wire identity; actual SDK user receipts pass the new consistency checks.
The explicit V2 execution path now includes zero-issuance genesis/head storage,
actual typed receipts committed before the post-state root, parent reconstruction,
and signed host/witness re-execution using the shared kernel. The explicit V2
SDK factory now runs staged finalization and accepted-candidate construction on
the actual supplied EVM, retaining exact signed bytes and checking derived receipts
before final writes. The host now implements full Reth primitive traits, bounded
internal serde, header Compact, ConfigureEvm and an assembler that checks metadata
already committed by execution. The chain storage adapter now persists bounded
deposit records, verifies reconstructed body commitments and supports transactional
body removal in real MDBX reopen tests. The full Reth ProviderFactory now uses
custom chain-spec, payload and node types; a real-backend test independently
computes the genesis allocation root and persists/reopens the V2 genesis and state.
The host now prepares genesis/child executed blocks with real trie data and
retained reverts; signed full-save and canonical-unwind/reopen tests verify state,
bytecode, block/transaction/receipt indices and deposit rows. Process-crash
recovery remains unqualified. Reth validation traits now check configured V2
headers/bodies/receipts; received-block import additionally checks externally
expected derivation inputs and re-executes to verify the full header/state root.
The actual Reth pool now authenticates canonical signed bytes before upstream
state-dependent admission. Real-provider tests cover queued nonces, selection,
contract deployment/call, mined removal and reorg readmission. Automatic pool
maintenance now consumes canonical provider notifications, retains unmined
transactions and reinserts displaced transactions after reorgs. A local adaptation
of the pinned Reth maintainer rejects account reloads from an obsolete head;
unit and real-provider regression tests cover the stale-reload race. Domain
initialization, fork choice, launched import/payload services, RPC transport and
end-to-end node operation remain open. No existing V1 execution or production
consensus has changed.

Upstream Reth EthApi handler construction and a V2 RPC header converter now connect
the canonical provider and authenticated pool. A real-provider JSON-RPC fixture
targets raw signed admission, receipts/log metadata, block identity and state reads.
The developer-node gate still requires execution-query qualification, transport,
wallet tools and restart tests; handler construction alone does not close it.

Latest/historical call and gas-estimate tests now cover BLOCKHASH context, explicit
overrides, access-list inspection and transient writes. Historical RPC testing
also exposed missing genesis history indices; genesis preparation now supplies
the allocation reverts that full persistence needs, with independent portable-core
checks across reopen and unwind. Previously initialized databases are not migrated
automatically. Authenticated pending derivation, broader simulation/tracing,
WebSocket transport and the launched developer workflow remain open.

The HTTP helper now serves the upstream EthApi module using Reth's server builder
on IPv4 loopback. A real-client test covers persisted genesis chain ID, V2 block
identity, storage and listener release on shutdown. Canonical coordination,
restart orchestration and wallet deployment over a running developer node remain
separate requirements; the HTTP helper alone does not close the node gate.

Canonical extension now has a sole-writer coordinator: validate the initialized
head, execute, revalidate the durable parent under the writer, persist, then
publish the canonical notification. Persistence errors prevent further writes
through that coordinator. Real-provider tests cover rejection without publication,
orderly reopen/continuation and domain mismatch. Genesis initialization policy,
historical-index validation, crash recovery and reorganization orchestration
remain startup/node work; a successful orderly reopen is not crash qualification.

Attachment now validates every configured genesis allocation through historical
account, bytecode and storage reads. Independent account/storage-index deletion
tests establish rejection without automatic repair. A real HTTP developer-flow
fixture now connects signed deploy/call submission, the pool, canonical extension,
automatic mined removal and receipt/log/state queries. Its funding and block
production remain synthetic and test-driven; a launched developer executable,
wallet integration and crash recovery are still required.

`bloch-evm-dev` now launches the isolated synthetic service with explicit mode
selection, exclusive new-directory initialization, optional synthetic funding,
loopback HTTP, periodic mining and signal-driven shutdown. A subprocess test
deploys/calls, stops and reopens the database, checks the same receipt and state,
then mines the next nonce. It also verifies rejection of an existing init target
and missing synthetic-mode consent. This closes the local executable/orderly
restart subtask, not wallet compatibility, native authentication or crash recovery.
Usage and concrete limits are in `integrations/reth-execution/DEVNODE.md`.

Real ethers 6.17.0 acceptance now exercises automatic nonce, gas and fee filling,
signed deploy/call, receipts/logs/state/block parsing and orderly restart. It
exposed omitted neutral RPC header projections (`difficulty`, `extraData`), now
serialized consistently with the existing Reth header traits without changing V2
hashes. The separately pinned real MetaMask UI flow now passes network/account
approval, rejection, deployment/call and state queries after node restart, with
observed UI clicks and independent signature recovery. See the
[browser acceptance](../wallets/browser/README.md) for exact versions and limits.

The executable now registers Reth's real `EthFilter` module alongside `EthApi`,
fixing `eth_getLogs` previously returning method-not-found. Process tests cover
persisted log queries, polling filters and removal across normal operation, and
log reconstruction after reopen/replay. A revert fixture verifies exact RPC error
data, failed receipt persistence, nonce/gas accounting, storage/log rollback and
continued mining. The [RPC matrix](../integrations/reth-execution/RPC-COMPATIBILITY.md)
distinguishes exercised methods and clients from the remaining RPC surface.

Local recovery now replays the completed MDBX canonical prefix into a separate
fresh directory, with source datasets opened read-only by the developer CLI.
Tests cover SIGKILL between writes, signed contract replay/continued mining,
static-file finalization before MDBX abort, genesis-index reconstruction and
rejection of missing bodies. Broader crash/power-loss and native-finality recovery
remain open; this path trusts the synthetic source's canonical selection.
