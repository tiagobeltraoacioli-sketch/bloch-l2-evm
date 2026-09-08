<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Color-Changing Chameleon — feasibility and proposed architecture

Status: **design proposal, 2026-09-08; no bridge or CLI implemented**.
The signed L2 wallet boundary in this PR is executable. Chameleon is a distinct
feature requiring native L1 escrow support, destination adapters and settlement.

## Product behavior

One origin asset can have a representation suited to a supported destination:
native PQ-authorized Ustav/BLCH in Bloch, an ERC-20 on an Ethereum/EVM chain, or
an SPL token on Solana. The software selects a registered, versioned adapter;
it does not interpret an arbitrary new language or change live bytecode by itself.
The basic lock/mint and burn/release pattern is established bridge technology.
The proposed contribution is a shared asset identity and policy-aware adapter
contract, with explicit PQ native authorization and machine-checkable admission
rules. Novelty or equivalence of policies is not proven by this proposal.

| Location | Representation | Account authorization |
|---|---|---|
| Bloch L1 | Original BLCH or registered Ustav asset | Native ML-DSA-65 AND Falcon-1024 |
| Ethereum / selected EVM chain | ERC-20 representation backed by locked origin units | Destination EVM account rules; standard EOAs use ECDSA |
| Solana | SPL or a supported Token-2022 representation | Solana account/program rules; standard transaction signatures use Ed25519 |

Ethereum is a separate L1, not Bloch L2. This route can be direct from Bloch;
passing through Bloch L2 is optional and adds another bridge/security boundary.
Ethereum, BNB Chain and each EVM rollup must be separate registered destinations.

## Movement and conservation

1. The holder signs a PQ export on Bloch, binding asset, exact amount, origin
   domain, destination chain, receiver, adapter/code version and unique nonce.
2. The native protocol moves that amount into a segregated bridge escrow. It
   remains locked, cannot be spent locally and is not a second issuance of BLCH.
3. Only a valid finalized export permits an equal normalized amount to be minted
   by the registered destination contract/program, exactly once.
4. Destination wallets and applications transfer the representation under that
   adapter's enforced token rules. Ordinary transfers do not unlock origin funds.
5. A destination return operation burns the representation and commits the Bloch
   PQ destination, exact amount, origin asset, route and unique return identifier.
6. Bloch verifies the finalized burn through the selected verification mechanism,
   consumes the identifier once, requires the corresponding native PQ claim
   authorization, and releases only that route's escrow into a PQ-owned output.

PQ claim authorization must be a protocol-defined escrow release path. The current
Ustav v3 owner-only UTXO ledger has no such path. Replacing a PQ-owned escrow with
an operator key is a custodial design, not an implementation of verified release.

Per route, outstanding representations plus pending mint/return claims must remain
covered by segregated locked origin units. At all times aggregate redeemable
claims across all destinations must not exceed backing; an asset cannot appear
spendable in both the native ledger and a representation. Reorgs, reordered or
duplicate messages, partial returns and route upgrades need explicit state
transitions. A timeout alone must NEVER refund an export that might still mint;
refund requires authenticated cancellation/non-execution that disables minting.

Use origin atomic units for accounting and checked exact conversions. Native
BLCH has 8 decimals; ERC-20 can retain 8, whereas the current Bloch L2 gas token
uses 18 with a factor of 10^10. An SPL BLCH representation can retain 8; its u64
amount capacity must be respected. Ustav's current charter does not declare
decimals: a future immutable asset manifest must define them. Never infer
decimals from a symbol or round away dust on return.

## What the PQ boundary guarantees

ECDSA/Ed25519 cannot substitute for a native PQ authorization. Nevertheless the
economic value exported to a classical destination is exposed to that destination
and the bridge. A thief controlling an Ethereum representation could burn it to
the thief's own PQ address and sign a perfectly valid PQ claim. Requiring PQ on
return cannot retroactively protect the prior Ethereum owner or reverse the theft.

Fixing redemption to the original exporter's key prevents that substitution but
also prevents a legitimate later buyer from redeeming independently; it is not
a freely fungible, generally composable DeFi asset. The proposed interoperable
mode must state this tradeoff instead of claiming end-to-end PQ security.

Verification of Ethereum/Solana consensus also inherits their own cryptographic
assumptions. A PQ-signed relayer attestation is not evidence of a real burn by
itself. Two candidate mechanisms require separate evaluation:

- Authenticated light-client/proof verification against accepted finalized roots,
  including consensus updates, replay protection and bounded verification cost.
- A PQ-authorized quorum attesting to externally verified events, explicitly
  described as a trusted committee, with its own custody/collusion assumptions.

No production choice, threshold or trustless claim is made here. Route-level
limits and segregated escrow can bound exposure without suggesting that bridge
compromise cannot affect exported funds. The unexported native authorization
path must remain independent of classical external signatures.

## Ustav policy preservation and application compatibility

An ERC-20 facade alone does not preserve a programmable charter. Each adapter
must declare what semantics it implements and how updates are authenticated.

| Native rule | Required destination behavior / constraint |
|---|---|
| Supply cap | Bridge mint authority only; normalized global backing across routes |
| Freeze / transfer authority | Enforced transfer checks with authenticated policy revision/freshness; stale policy behavior specified |
| KYC membership | Destination identity/address mapping and current authenticated membership checks; AMM/router addresses may also need eligibility |
| Vesting | Define origin-height versus destination-time meaning; do not silently replace one with the other |
| Governance or custody quorum on every movement | The destination must preserve required approvals; ordinary unmodified AMM paths may be incompatible |

Unsupported rules **block activation/export** for that adapter. A separate asset
with weaker rules cannot be advertised as the same preserved charter. Kernel v3
charters are immutable: adding export permission to an existing asset needs an
explicit versioned migration/authorization design, not a silent admin toggle.

An ordinary ERC-20 representation can be integrated with Uniswap or PancakeSwap
on a network where the relevant protocol is deployed, subject to token behavior,
liquidity/pool creation and that interface's discovery rules. It is not automatic
compatibility with every application. Fees on transfer, rebasing, transfer gates
and unusual allowance behavior can break integrations. Solana requires its own
adapter and program integration; Token-2022 transfer hooks require clients to
provide additional accounts, so support is not universal either.

## Proposed integration surface

A versioned manifest would bind origin genesis/asset ID, issuer-authorized policy
hash/revision, amount unit, destination domain, concrete contract/program address,
code/upgrade authority, adapter version and verification mechanism. The origin
mapping is authoritative; names such as BLCH alone do not identify an asset.

These are proposed commands, **not commands provided by this repository**:

```text
bloch chameleon inspect <asset> --target ethereum --network <network>
bloch chameleon enable <asset> --adapter <registered-version>
bloch chameleon export <asset> --amount <amount> --to <destination>
bloch chameleon return <representation> --amount <amount> --pq-to <bloch-address>
```

`inspect` reports enforceable rules and incompatibilities. `enable` requires the
asset/protocol's legitimate authority and a compatible registered adapter; any
holder still has to authorize their own export with PQ. BLCH has no token issuer
who may unilaterally change native protocol rules. A UI may hide network-specific
steps but must show the destination security model and the actual signing request.

## Development sequence and Kirpich

1. Define the export/claim state machine and model conservation, finality/reorgs,
   duplicate events, route substitution, cancellation and policy-update ordering.
2. Extend the native protocol with PQ export/claim semantics, escrow commitments,
   exact units, authenticated external events and canonical replay identifiers.
3. Implement one Ethereum testnet adapter for an explicitly exportable, unrestricted
   test asset; use an ERC-20 with narrowly scoped mint/burn authority and tested
   standard transfer/allowance behavior. Measure verifier costs and trust choices.
4. Add Kirpich adapter-admission rules and differential policy tests. The current
   Kirpich ruleset audits EUVM charters, not Solidity, SPL programs, bridge safety
   or equivalence across VMs. No certification claim follows from current checks.
5. Test the round trip, backing invariants and an actual AMM pool, then review
   contracts/protocol before any value-bearing deployment. Add Solana as a
   distinct adapter only after the first route and its policy model are stable.

References: [Ethereum bridge models](https://ethereum.org/developers/docs/bridges/),
[Uniswap token integration examples](https://developers.uniswap.org/docs/protocols/v2/guides/troubleshooting),
[Solana transfer-hook integration](https://solana.com/docs/tokens/extensions/transfer-hook-integration),
[PancakeSwap crosschain interface](https://docs.pancakeswap.finance/trade/crosschain-swaps).
