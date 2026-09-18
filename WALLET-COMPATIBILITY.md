<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# L2 wallet compatibility and the native L1 boundary

The 2026-09-08 architecture decision assigns standard Ethereum ECDSA accounts
to this L2. Native Bloch L1 Ustav v3 uses ML-DSA-65 **AND** Falcon-1024.
An adapter cannot turn an ECDSA signature into a PQ signature. A future direct
L1 SDK/Snap must obtain an actual native PQ authorization from the owner.

| Interface | Authorization | Implemented here |
|---|---|---|
| Native L1 Ustav | PQ hybrid signatures, including PQ custody quorums | Separate `bloch-sis-pow/crates/bloch-ustav` reference kernel |
| L2 user transaction | Classical ECDSA/secp256k1, EIP-155 replay domain | Canonical signed-byte decoding and sender recovery |
| Application → wallet | EIP-1193 requests to the user-selected provider | Network selection and transaction-request adapter |
| Wallet → L2 node | Ethereum JSON-RPC and Reth txpool | Isolated synthetic developer executable with signed admission, mining, receipts/state and orderly restart |
| L1 ↔ L2 | Finalized deposits, proof/settlement and withdrawal rules | Not implemented by this wallet boundary |

L2 accounts are **not post-quantum**. A PQ L1 or a PQ-compatible proof system
does not protect an L2 ECDSA key against forgery. A bridge also needs an explicit
policy for compromised L2 accounts and withdrawal destinations; this PR creates
no route for an ECDSA signature to authorize a native L1 UTXO.

The proposed [Color-Changing Chameleon](docs/COLOR-CHANGING-CHAMELEON.md)
extends this architecture to representations on external Ethereum/Solana networks.
It is a feasibility/design document; this PR implements no cross-chain bridge.

## Rust integration

`decode_signed_transaction(&spec, raw)` returns an `AuthenticatedTransaction`
with private fields, recovered sender, canonical transaction hash and read-only
execution fields. It does not accept a claimed sender or a deserialized `TxEnv`.
It uses pinned upstream Alloy 2.2.0 and the pure-Rust k256 backend, requires full
RLP consumption and canonical re-encoding, rejects high-S and invalid scalars,
and rejects missing/foreign chain IDs. Only types 0 (EIP-155 protected legacy),
1 (EIP-2930) and 2 (EIP-1559) are admitted. Blob, EIP-7702 and deposit-shaped
user envelopes cannot enter through this path.

The raw-byte limits are 128 KiB per transaction, 16 MiB of user bytes per block,
and 4,096 signatures per block. Size/count preflight precedes decoding/recovery;
normal EVM gas limits still apply. These are explicit reference protocol limits,
not a live chain activation. A node must additionally enforce request limits
**before deserialization/allocation**, pool capacity/rate limits, and the same
limits in its guest input decoder.

Use `SignedBlockInput { context, deposits, transactions }` with:

- `execute_signed_block(&spec, &mut state, &input)` for atomic execution;
- `generate_signed_batch_witness(&pre, &spec, &input)` on the proving host;
- `verify_signed_batch(&spec, &witness, &input)` **inside** the future guest.

The `serde` feature carries original raw transactions across the host/guest
boundary. Deserialization grants no authentication: verification recovers every
sender again. Preserve the bytes from RPC through pool, block builder and guest.
Do not recover only at RPC ingress and pass unsigned environments to the prover.
The historical `execute_block`/`verify_batch` functions remain trusted engine
primitives for tests and internal use; their public `TxEnv.caller` is not a safe
network boundary. Deposits always come from trusted finalized-L1 derivation,
never from a wallet's `eth_sendRawTransaction` request.

Nonce, balance, fee and intrinsic-gas validity remain the executor's job. Recovery
of a modified message can produce a different valid Ethereum address: the funded
owner's balance cannot then be spent. Both host and guest enforce this behavior.

## Application integration (MetaMask and other EVM providers)

Use the provider the user selected (for example via EIP-6963 or MetaMask Connect).
The adapter accepts any compatible EIP-1193 provider and has no wallet vendor
dependency. Display `wallet.security.notice` when offering the network:

```js
import { createBlochL2Wallet } from "./wallets/bloch-l2.mjs";

const wallet = createBlochL2Wallet(selectedProvider, {
  rpcUrl: applicationConfig.blochL2RpcUrl,
  chainId: applicationConfig.blochL2ChainId,
  genesisHash: applicationConfig.blochL2GenesisHash,
  domain: applicationConfig.blochL2Domain,
});
networkNotice.textContent = wallet.security.notice;
const { accounts } = await wallet.connect();
const hash = await wallet.sendTransaction({
  from: accounts[0],
  to: recipientAddress,
  value: "0x1",
  type: "0x2",
});
```

The registered wallet network is named **Bloch L2 (ECDSA)**, with bridged BLCH
at 18 decimals. The crate's test configuration is chain ID **700771**, hex
**0xab163**; this is an unregistered placeholder, not an advertised public
network. Supply the node's actual chain ID, genesis block hash, V2 execution
domain and endpoint from one reviewed deployment manifest. No production
identity, endpoint, explorer,
faucet or token is invented by this adapter.

The adapter requests `wallet_switchEthereumChain`, adds the chain only on error
4902, then explicitly switches again (adding need not select it). It respects
user rejection, checks the active chain ID, exact block-zero hash and the
versioned `bloch_chainIdentity` response (chain ID, genesis, execution domain and
fixed-width V2 header format)
before obtaining accounts and before sending, includes the chain ID in signing
requests, and accepts only an authorized sender. The selected provider's request method is captured once at
construction so later property replacement cannot split checks and signing
between implementations. The adapter conservatively accounts for calldata,
access lists and maximum envelope overhead against the node's 128 KiB encoded
transaction limit, bounds provider-returned account and access-list collections,
and rejects inconsistent
legacy/EIP-2930/EIP-1559 fee fields before opening a signing request. Nonce and
gas quantities are bounded to the node's `u64` transaction fields, and fee
quantities to its `u128` fields. Private keys remain in the wallet. This is an
integrable client component, not a completed MetaMask end-to-end deployment.

## Remaining node and settlement work

The [developer executable](integrations/reth-execution/DEVNODE.md) now connects
the real Reth RPC/txpool stack to Bloch execution and canonical persistence.
Process tests exercise signed contract deployment/call and database restart.
Its funding, anchor and block production are explicitly synthetic.

1. Complete RPC/wallet qualification beyond the tested surface. Wallets need functioning
   `eth_chainId`, nonce/balance/code/storage queries, `eth_call`, gas estimation,
   fee suggestions/fee history, `eth_sendRawTransaction`, transaction/receipt
   lookup, blocks/logs and appropriate subscription support.
   The V2 RPC header retains its tagged Bloch hash, and exposes zero `difficulty`
   and empty `extraData` consistently with its existing Reth header traits. These
   neutral compatibility fields are not new consensus fields. Synthesized pending
   blocks remain unsupported; pending account nonces use the upstream pool path.
2. V2 headers already bind ordered transaction and receipt roots. Integrate the
   real proof backend and bind those commitments at native settlement. Pin the
   accepted pre-state root, chain configuration and guest/program identity at
   settlement; running the Rust verification procedure alone is not a zk proof.
3. Implement and test finalized-L1 escrow derivation, anchor/reorg handling,
   deposit authentication and withdrawals. PQ native authorization is not a
   substitute for a correct bridge policy.
4. Register/select a collision-free public chain ID and exercise real MetaMask
   and other browser wallets. The EIP-1193 adapter tests still use a mock.
   `wallets/devnode-ethers.test.mjs` separately exercises the real ethers signing
   client and automatic nonce/gas/fee population over HTTP; it does not exercise
   browser account approval or an injected wallet provider.

## Verification

```sh
cargo test --locked --test signed_transactions
cargo test --locked --features serde --test signed_transactions
cargo test --locked --no-default-features
cargo test --locked --release --test signed_transactions
node --test wallets/bloch-l2.test.mjs
# Build the developer binary as documented in DEVNODE.md first.
npm ci --prefix wallets --ignore-scripts
npm --prefix wallets run test:devnode
```

Upstream interface references: [EIP-1193](https://eips.ethereum.org/EIPS/eip-1193),
[EIP-3085](https://eips.ethereum.org/EIPS/eip-3085),
[EIP-3326](https://eips.ethereum.org/EIPS/eip-3326),
[MetaMask JSON-RPC](https://docs.metamask.io/metamask-connect/evm/reference/json-rpc-api/).
