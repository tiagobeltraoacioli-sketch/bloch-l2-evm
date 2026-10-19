# Bloch L2 mainnet: exchange and custodian integration

Status 2026-10-18. The L2 was installed by Bloch L1 (Genesis-4) at the first
block of epoch 5850 (2026-10-17 21:31 UTC). Values marked **{{…}}** are
published by the operators of the public endpoints; everything else is fixed
by the activated consensus rules or the code cited.

## 1. Network parameters

| Parameter | Value |
|---|---|
| Network name | Bloch L2 |
| Chain ID | **700770** (hex `0xab162`) |
| Currency symbol | **BLCH** |
| Decimals | **18** |
| Asset type | Native coin (gas coin). No token contract. |
| Public HTTP JSON-RPC | {{PUBLIC_L2_RPC_URL}} |
| Block explorer | {{L2_EXPLORER_URL}} |
| Addresses | Standard 20-byte EVM addresses (EIP-55 checksums), secp256k1 keys |
| Transaction types | Legacy (EIP-155), EIP-2930, EIP-1559. Blob (EIP-4844) transactions are refused. |
| Settlement | Every L2 block is proved (SP1 Groth16) and settled on Bloch L1 |

MetaMask: *Settings → Networks → Add a network manually* with the name, RPC
URL, chain ID 700770 and currency symbol BLCH above. MetaMask reads
`eth_chainId`; the endpoint does not implement `net_version` or
`web3_clientVersion`, which current wallets do not need.

### Units: L1 BLCH and L2 BLCH are the same asset

BLCH on L1 has 8 decimals (base unit "sat", `10^8` sat = 1 BLCH). On the L2
it has 18 decimals so wallets display it like ETH. The bridge scales exactly
by `10^10` in both directions (`src/scale.rs`: `ATOM_SCALE = 10^10`,
`SATS_PER_BLCH = 10^8`, `WEI_PER_BLCH = 10^18`):

- a deposit of `s` sat on L1 mints exactly `s × 10^10` wei on L2
  (`DepositMint::mint_wei`);
- a withdrawal to L1 must be a whole number of sat (a multiple of `10^10`
  wei) and at least 0.01 BLCH (`MIN_WITHDRAWAL_SATS = 1 000 000`, equal to the
  native `MIN_L2_DEPOSIT_SAT`); anything else reverts and is refunded. Never
  rounded.

There is no premine on the L2 (genesis has no balances). Every L2 BLCH was
deposited from L1 and is backed 1:1 by the L1 consensus escrow, which every
L1 node checks on every block (`getl2settlement` →
`withdrawals.escrow_conserved`).

L1 BLCH and L2 BLCH use different address formats (L1: post-quantum script
hashes; L2: `0x…` addresses). List the L2 as its own deposit network
("BLCH — Bloch L2 (EVM)") and never accept an L1 address for an L2
withdrawal or the reverse.

## 2. How blocks, `safe` and `finalized` work

The L2 is a settled rollup with one block per settlement:

1. The sequencer builds L2 block *N* from pending transactions and pending L1
   deposits (`latest` advances).
2. Block *N* is proved and its batch published on L1 (data availability),
   then the settlement transaction is included in an L1 block. When the
   operator's L1 node accepts it at its head, block *N* becomes **`safe`**.
   Block *N+1* is built only after that, so `latest − safe` is normally 1.
3. When the L1 block containing the settlement is FFG-finalized and the
   independent follower has verified that by replaying L1 from the pinned
   genesis (real post-quantum signatures, Groth16 and FFG), block *N* becomes
   **`finalized`**. Neither tag ever goes backwards.

`finalized` is the standard Ethereum block tag:

```
eth_getBlockByNumber("finalized", false)   → number F
bloch_finality                             → latest / safe / finalized + their L1 anchors
```

**A transaction is irreversible when its block number is ≤ F.** That is the
only rule an integration needs.

### Measured and expected timings

Measured on the public test network devnet4 (chain 700771, same code; L1 slot
2 s, epoch 32 slots = 64 s), over L2 blocks 585–685 (2026-10-18 03:19–22:33
UTC), from the RPC's own publication log:

| Interval | p50 | p95 | max |
|---|---|---|---|
| L2 block interval | 11.5 min | 12.0 min | 12.5 min |
| block appears → `safe` | 11.7 min | 12.2 min | 18.3 min |
| `safe` → `finalized` | 5.7 min (≈ 5.3 L1 epochs) | 6.4 min (≈ 6.0 epochs) | 6.4 min |
| block appears → `finalized` | 17.5 min | 18.2 min | 18.5 min |

The block interval is set by proof generation, not by the L1 slot. The
`safe → finalized` step is measured in L1 epochs: L1 finalizes about 2–3
epochs behind its head (mainnet `getchaininfo` on 2026-10-18: epoch 5944,
finalized epoch 5942), and the follower proves finality only from blocks
already inside the finalized prefix, so about 5–6 epochs in total.

Mainnet L1 epochs are 32 × 30 s = 16 min. Expected mainnet values (to be
re-measured on the first mainnet blocks and this table updated):

| Interval | Expected on mainnet |
|---|---|
| L2 block interval | ≈ 12–15 min (proving plus DA and settlement inclusion in 30 s L1 slots) |
| transaction sent → included (`latest`) | 0 to one block interval |
| included → `safe` | ≈ one block interval (12–15 min) |
| `safe` → `finalized` | ≈ 85 min typical, ≈ 96 min p95 (5.3–6 epochs × 16 min) |
| included → `finalized` | **≈ 100 min typical, up to ≈ 2 h** |

### Confirmation count for systems that need a number

Credit by the `finalized` tag whenever your system supports it (any
integration built for post-Merge Ethereum does). If your system can only be
configured with a confirmation count, use **12 L2 blocks** and keep a check
that the block is ≤ `finalized` before crediting:

- `finalized` trails `latest` by about 7–9 blocks (≈ 100–115 min at 12–15 min
  per block);
- 12 blocks ≈ 144 min at a 12-minute interval, ≥ 25 % above the expected p95;
- a count alone is not a guarantee: if L1 finality stalls, the L2 keeps
  producing `safe` blocks while `finalized` stops. The tag catches that, a
  count does not.

## 3. Detecting deposits to your L2 addresses

BLCH reaches an address on the L2 in three ways:

| Way | Visible as | Detect with |
|---|---|---|
| Plain transfer from a wallet (the normal case) | a transaction with `to` = your address and `value` > 0 | scan blocks, check the receipt |
| Transfer made by a contract (smart wallet, DEX, multisig) | no top-level transaction to you (internal call) | balance reconciliation |
| Bridge deposit from L1 (`bloch-pos l2-deposit`) | balance credited at the end of the L2 block, **no L2 transaction** | balance reconciliation |

The node exposes no `debug_*`/`trace_*` methods, so internal transfers and
bridge mints cannot be seen in transaction lists. Recommended procedure:

1. Poll `eth_getBlockByNumber("finalized", false)` → `F`.
2. For each new block `n ≤ F`: `eth_getBlockByNumber(n, true)`; for
   transactions whose `to` is one of your addresses, take
   `eth_getTransactionReceipt(hash)` and credit only `status = 0x1`
   (`eth_getBlockReceipts(n)` returns all receipts of the block in one call).
3. Reconcile: `eth_getBalance(address, F)` must equal the previous finalized
   balance + credited deposits − your own outgoing value and fees. Any
   positive difference is an internal or bridge deposit; credit it, or flag it
   for review, according to your policy. Historical state is served
   (`eth_getBalance(address, <number>)`).
4. Sweep with ordinary transactions.

Available methods: `eth_chainId`, `eth_blockNumber`,
`eth_getBlockByNumber`/`ByHash`, `eth_getBlockReceipts`,
`eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBalance`,
`eth_getTransactionCount`, `eth_getLogs`, `eth_call`, `eth_estimateGas`,
`eth_gasPrice`, `eth_feeHistory`, `eth_maxPriorityFeePerGas`,
`eth_sendRawTransaction`, `bloch_finality`, `bloch_chainIdentity`. HTTP
only; poll instead of subscribing.

## 4. Sending (withdrawals from your hot wallet to users)

A user withdrawal on the L2 is an ordinary L2 transfer.

- Fees follow EIP-1559 with Bloch's constants: initial base fee 1 gwei,
  elasticity 2, base-fee change at most ±0.4 % per block (denominator 250),
  30 000 000 gas per block. A 21 000-gas transfer costs about
  `21 000 × base fee` (0.000021 BLCH at 1 gwei; less while blocks are empty).
  Use `eth_feeHistory` / `eth_gasPrice`; a priority fee of 0 is accepted.
  Base fees go to the base-fee vault `0x4200…0019` and priority fees to
  `0x4200…0011` (the block's `COINBASE`); nothing is burned.
- A sent transaction is spooled by the sequencer and included in the next
  block, so a receipt can take up to one block interval (≈ 12–15 min) to
  appear. `eth_getTransactionCount(addr, "pending")` counts the spooled
  nonces. Do not replace or rebroadcast a transaction that is not yet
  included unless it is still missing after two block intervals.
- Per-block capacity is set by the sequencer (on devnet4: 256 transactions,
  15 M gas, 112 KiB of batch data per block). Batch hot-wallet payouts
  accordingly.

## 5. Moving BLCH between L2 and L1 (rebalancing)

**L1 → L2 (deposit).** An L1 deposit transaction (`bloch-pos l2-deposit`,
minimum 0.01 BLCH) locks the BLCH in the L1 escrow; the next L2 block mints it
to the given L2 address. Expect it at `latest` within one block interval of
L1 inclusion and at `finalized` about 100 min later.

**L2 → L1 (withdrawal).** Call the outbox predeploy
`0x4200000000000000000000000000000000000102`,
`initiateWithdrawal(bytes32 l1Recipient)` with the amount as `value`
(multiple of `10^10` wei, ≥ 0.01 BLCH). After the L2 block is settled, the
L1 claim (`bloch-pos l2-claim`, an L1 transaction whose fees the claimant
pays) is accepted only when all of these hold (consensus rules of the
activation):

| Amount | Requirement | Earliest claim |
|---|---|---|
| < 100 BLCH | settlement FFG-finalized on L1 and 64 L1 blocks after it | ≈ 1 h after the L2 block (64 blocks ≈ 32 min at full slot occupancy, ≈ 40 min at the 2026-10 occupancy of ≈ 81 %; finality overlaps it) |
| ≥ 100 BLCH | the above, plus 3-of-5 attestor signatures, and 2 880 L1 blocks | ≈ 24 h at full occupancy (≈ 30 h at 81 %) |

**Rate limit.** In every window of 2 880 L1 blocks the total released to L1
is capped at 10 % of the escrow, with a floor of 10 BLCH; a claim over the
cap waits for the next window (`getl2settlement` →
`withdrawals.release_window.remaining_sat`). While the escrow is small, large
L2 → L1 rebalancing takes several windows. Keep separate L1 and L2 float.

## 6. Node and RPC options

1. **Public RPC** {{PUBLIC_L2_RPC_URL}}: simplest. The `finalized` tag it
   serves is the operator's follower view.
2. **Own L1 node** (`bloch-pos` 0.1.0-mainnet or later, required since epoch
   5850): lets you check independently that the settlements exist
   (`getl2settlement` → `accepted`, `withdrawals.escrow_conserved`) and
   that the L2 is installed (`profile.activated = true`).
3. **Own L2 follower + RPC** (`bloch-l2-native-follower` +
   `bloch-l2-settled-rpc`): `finalized` derived by your own replay of L1 from
   the pinned genesis, with no trust in the L2 operator. Operator guide:
   {{L2_NODE_GUIDE_URL}}.

Identity checks for any endpoint: `eth_chainId` = `0xab162`;
`bloch_chainIdentity` → `chainId 0xab162`, `domain
0x1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733`
(the mainnet L2 domain; devnet4 answers `0xd3…d3`).

## 7. Integration checklist

- [ ] Network added with chain ID 700770, symbol BLCH, 18 decimals.
- [ ] Deposits credited only at blocks ≤ `finalized` (or 12 confirmations
      *and* ≤ `finalized`).
- [ ] Receipts checked (`status = 0x1`), not just transaction presence.
- [ ] Balance reconciliation at the finalized block for every deposit
      address (catches contract and bridge deposits).
- [ ] L1 and L2 BLCH listed as separate networks; address formats validated.
- [ ] Withdrawal amounts to L1 in whole sat, ≥ 0.01 BLCH; rate limit known.
