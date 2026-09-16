# Modular execution: verified EVM domains

Status: implemented local verification boundary, not consensus-active, not a
working rollup. This document describes the September 16, 2026 increment. It
supersedes neither the L1 consensus nor the incomplete prover/node integration.
Older PoW finality descriptions in this repository do not describe Genesis-4;
no security conclusion about the live PoS chain follows from those passages.

## Implemented flow

`domain::EvmDomain` connects the existing signed Ethereum ingress and stateless
EVM witness verifier to a private, sequential state cursor:

1. Instantiate an immutable domain from a network identity, module identity,
   pinned runtime artifact identity, complete Cancun ChainSpec and trusted
   initial state root. Each is bound into a domain-separated commitment.
2. The host supplies an independently authenticated `TrustedL1Batch`, including
   the expected domain and ordered input commitment from inbox/DA derivation.
3. Bound input/witness payloads, check the pre-root and block sequence, reject
   L1 height rollback or a conflicting block at the same accepted height.
4. Recover Ethereum signers, authenticate the pre-state witness, re-execute the
   EVM and derive the post-state root. A claimed post-root is never sufficient.
5. Advance the local cursor only after success and return a canonical receipt.
   Rejected proposals leave the cursor unchanged. Replay is rejected.

`input_commitment` binds the full header context, deposit commitment and exact
ordered, length-prefixed signed envelopes. `ExecutionReceipt::commitment` binds
both roots, domain, block number/hash and L1 derivation context. Encoding is
explicit; JSON and Debug output never define the commitment. Runtime upgrades
require a new domain and a separately specified migration; there is no arbitrary
plugin loader or administrative bypass in this implementation.

Run the zero-value example:

```sh
cargo +1.94.1 run --locked --example modular_evm
```

The example uses a synthetic L1 context and an empty block. Integration tests
also exercise a cryptographically signed value transfer, signature corruption,
contiguous blocks, altered roots/inputs, resource bounds and replay rejection.

## Trust boundary and limitations

`TrustedL1Batch` is a host trust boundary, not a certificate. An untrusted RPC
client MUST NOT be allowed to populate it. This crate does not yet authenticate
L1 headers, finality, module registration, escrow provenance or inbox inclusion.
A fabricated but internally consistent context can pass local execution; that
is precisely why receipts MUST NOT release mainnet funds. Nondecreasing anchor
heights do not prove ancestry. An authenticated canonical L1 reader must supply
that guarantee and define recovery if its finality assumptions fail.

Witness limits account for payload, not allocator overhead. The future decoder
must bound message size before allocation, and its worker must have CPU, memory
and request concurrency budgets. The accepted cursor is in-memory; persistence,
crash recovery and atomic durable state/receipt commits are not implemented.
The complete ordered input is supplied locally: this is not network data
availability. Runtime hashes identify configured artifacts; they do not attest
which host binary ran. The verifier currently re-executes the pinned EVM rather
than verifying a succinct proof. No SVM runtime, bridge withdrawal, cross-domain
message, consensus upgrade or production deployment is included.

Ethereum ECDSA authorization remains an L2 compatibility boundary. Bloch's PQ
L1 signatures do not make those ECDSA accounts post-quantum secure. A future
proof backend must be evaluated with its complete assumptions and wrappers;
FRI/STARK terminology alone does not establish end-to-end PQ security.

## Next implementation boundaries

The target is isolated execution domains settling to Bloch through verified
state transitions. Develop these boundaries in order, with adversarial tests:

1. Authenticated Genesis-4 derivation: finalized header/state references,
   authenticated inbox positions, escrow ownership and canonical deposit data.
   Establish the exact L1 commitment format and activation rule before wiring
   to mainnet; a plain transaction carrying a hash does not enforce settlement.
2. Bounded transport and durable local domain service, including atomic commit,
   recovery and reproducible re-execution. Preserve signed envelopes end to end.
3. A real proof backend over the same execution semantics, binding all public
   inputs above. Pin the guest/program/verifier versions; benchmark proving
   cost. Never substitute a successful host execution for proof verification.
4. L1 verifier and escrow state machine, with explicit consensus activation,
   replay-protected deposit/withdrawal messages and sufficient data availability.
   Test unavailable data, invalid proofs, reorg assumptions and sequencer failure.
5. SVM runtime as a separately versioned domain after concrete SBF program tests
   establish its supported compatibility surface. Account scheduling alone is
   not Solana compatibility. Cross-domain messages are asynchronous unless an
   explicit atomicity protocol is implemented and verified.

The local boundary intentionally introduces no generic accept-all verifier and
no artificial "proof verified" flag. EVM is the first implemented execution
adapter; other runtimes must supply real validation before being registered.

## Validation of this increment

Rust 1.94.1, locked dependencies: 135 tests passed, one pre-existing ignored
regression. Ten new tests cover the execution-domain boundary (nine dedicated
cases plus one signed-transfer integration). `cargo check --no-default-features`
passed and the `modular_evm` example executed successfully. These checks are
local correctness evidence, not a mainnet qualification or external audit.

## Genesis-4 authentication increment

`l1::authenticate_body` now verifies canonical 304-byte Genesis-4 headers,
SHA3-256 block IDs, parent links and strictly increasing slots up to an externally
trusted finalized checkpoint. It verifies the COMPLETE ordered transaction body
against the target header's body root. Empty trees, leaf lengths, node/leaf domain
separation and odd-node promotion follow the authoritative Genesis-4 commitment.
It does not confuse SHA3-256 with Ethereum Keccak or slot with block height.

The returned `AuthenticatedBody` has private fields and can only be constructed
by successful verification. The local bounds are 2,048 headers, 4,096 transactions
and 16 MiB of transaction payload; these are verifier resource limits, not claims
about consensus limits. Fetch nearer authenticated checkpoints for longer paths.
This approach authenticates the whole body so a caller cannot silently select
only convenient transactions. It does not prove network-wide data availability.

`examples/verify_l1_body.rs` is a bounded offline tool. Its JSON input contains
`headers` and `transactions` arrays of hexadecimal strings. The expected block
ID and slot are separate arguments, taken from the host's trusted finality source:

```sh
cargo +1.94.1 run --locked --example verify_l1_body --   body.json TRUSTED_FINALIZED_BLOCK_ID TRUSTED_FINALIZED_SLOT
```

Do not take those trusted arguments from the same untrusted response you are
checking. No RPC `finalized: true` flag is accepted as cryptographic evidence.
The tool does not verify validator votes, proposer signatures, validator-set
transitions or checkpoint signatures. Finality authenticity remains external.
Header inclusion alone also cannot prove that a transaction locked coins in an
escrow: canonical transaction decoding and the escrow/inbox rules remain pending.
Consequently, this increment does not manufacture `TrustedL1Batch` values from
arbitrary transaction bytes and does not authorize deposits or withdrawals.

Seven commitment fixtures (0, 1, 2, 3, 5, 17 and 32 transactions) were generated
by linking `tools/generate-g4-fixtures.rs` against `bloch-pos-committee` at commit
`5af78a04a27dcb2c2253c32134fca888a8a965f9`. File hashes and fixture provenance are
recorded in `tests/fixtures/genesis4-bodies.provenance.json`. The generator is a
separate development tool; the execution library does not link the consensus
crate or require a sibling checkout. These are synthetic encoding vectors, not
finalized mainnet blocks. To regenerate, create a temporary Rust binary project,
use that file as `src/main.rs`, and add a path dependency named
`bloch-pos-committee` pointing to the pinned consensus crate; capture stdout as
the JSON fixture and compare it before replacing any checked-in vector.

Eight additional tests cover official vectors, omitted/reordered/duplicated
transactions, tampered headers, wrong checkpoints, malformed encodings, missing
intermediate headers and input work limits.

Validation after the Genesis-4 increment: 143 tests passed, one pre-existing test
ignored; no-default-features compilation passed. The offline CLI accepted the
five-transaction consensus fixture and rejected an incorrect checkpoint slot.

## Native transfer observation increment

`l1_transfer` now decodes authenticated Genesis-4 transfers, preserves output
indices and derives consensus txids. The offline body verifier can emit script
payment observations. These are not mint authorizations.
See [GENESIS4-BRIDGE-DERIVATION.md](GENESIS4-BRIDGE-DERIVATION.md) for the discovered
legacy-envelope incompatibility and required native escrow rules.

## Experimental native lock kernel

A default-disabled native escrow transition model now consumes synthetic funding
outputs and conserves spendable value, liabilities, change and fees. It assumes
funding authorization from the consensus host and cannot release or mint assets.
See [EXPERIMENTAL-NATIVE-ESCROW.md](EXPERIMENTAL-NATIVE-ESCROW.md) for executable
examples, tested invariants and the remaining consensus integration boundary.
