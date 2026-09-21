# L2 finality boundary

`eth_getBlockByNumber("finalized")` must remain `null` until a native Bloch
checkpoint proves a consensus-enforced settlement of a specific L2 block. An L2
header merely referencing an old native block is not settlement of that L2
header.

The implemented `l1::authenticate_ancestry` verifies the complete 304-byte
Genesis-4 parent path from a selected native anchor to an externally
authenticated checkpoint. `l1_context::authenticate_l1_context` then binds the
exact V2 L2 header hash, state root, chain ID 700771 and execution domain to that
anchor. Its result is deliberately named `AuthenticatedL1Context`, not a
finalized L2 block.

## Required path to a standard finalized tag

1. Pin native network/genesis identity and authenticate a non-regressing native
   checkpoint independently of the proposer and public L2 RPC.
2. Obtain all raw native headers from the L2 anchor through that checkpoint and
   verify their hashes, parent links and slots with `authenticate_ancestry`.
3. Qualify a consensus-available proof transport. Current saved SP1 Core proofs
   are approximately 2.8 MiB, while the native block transaction budget is at
   most 512 KiB; a proof hash or node-local RPC side channel is not data
   availability. Use a reviewed succinct proof, a consensus-committed DA
   sidecar, or a separately qualified coordinated block-format change.
4. Verify a consensus-enforced native settlement record that commits the exact
   L2 V2 header hash, post-state root, execution domain, proof/program identity
   and consumed source cursor. A plain native transfer or arbitrary hash in a
   transaction is not such a record.
5. Verify the execution proof and source/deposit mapping, then atomically append
   the settlement to a durable, rollback-detecting monotonic cursor.
6. Expose only the exact cursor tip and its ancestors through Ethereum's
   `finalized` tag. Missing, stale, conflicting or regressing evidence returns
   `null` and disables bridge mint/release, DEX liquidity and aggregator
   execution.

## Current status (2026-09-20)

The public Genesis-4 RPC reports a corroborated finalized block and exposes its
ID, slot, height and header commitments. Its `getblockbyid` response does not
provide the canonical 304-byte header, complete body, validator votes or a proof
of the checkpoint authority required by the local verifier. More importantly,
no active native transaction/state transition currently settles the L2 header
and proof. Operational RPC agreement therefore remains diagnostic evidence only.

The Reth development node continues to return `null` for `finalized`. This is the
correct fail-closed behavior. Do not replace it with `latest`, a fixed depth, an
L1 anchor classification, or a threshold signature that lacks native settlement
inclusion.

The pinned SP1 6.8.0 SDK exposes a Groth16 wrapper whose encoded proof is 352
bytes (356 bytes with the verifier-key prefix), so a succinct in-block route is
plausible without raising the native block cap. It is not qualified here: the
Bloch host currently requests Core proofs only, no real Groth16 Bloch artifact
has been produced, and the native consensus path has no reviewed deterministic
verifier. The `settlement-proof-transport-qualified` requirement therefore
remains false until generation, tamper, replay, resource and validator tests are
recorded as evidence.

The machine-readable gate is [`network/finality.json`](../network/finality.json).
Every satisfied requirement must carry a dated SHA-256 evidence reference;
product permissions cannot become true while any requirement is open. Validate
the checked-in state with:

```sh
python3 tools/check-finality-readiness.py
python3 tools/check-finality-readiness.py --require-ready  # expected to fail now
```
