# Withdrawing from the Bloch L2 without a local L2 database

`bloch-l2-withdraw.py` takes a user from a burn on L2 to `bloch-pos l2-claim prepare` on L1. It needs Python 3.9 or newer and nothing else. It holds no key and sends no transaction.

## The flow

1. **Burn.** Print the outbox call, then sign it with your own wallet. Withdrawals below 0.01 BLCH revert. The recipient is your L1 owner script hash (SHA3-256 of your hybrid public key). Check it: only that key can spend on L1.

   ```
   bloch-l2-withdraw.py burn --recipient-pubkey me.pubkey.hex --sats 2000000
   ```

2. **Find the index** in the burn's receipt.

   ```
   bloch-l2-withdraw.py find --l2-rpc https://l2rpc.blochl1.com --tx 0xBURN_TX_HASH
   ```

3. **Wait, fetch and verify.** This keeps trying for up to `--wait` seconds. A claim of less than 100 BLCH needs 64 L1 blocks after an FFG-finalized settlement. A larger one needs 2,880 blocks plus the attestors.

   ```
   bloch-l2-withdraw.py fetch --l2-rpc https://l2rpc.blochl1.com --l1-rpc http://YOUR_L1_NODE:8080 --index I --recipient-pubkey me.pubkey.hex --sats 2000000 --out proof.json --wait 7200
   ```

4. **Prepare the claim** with the command that `fetch` prints, then `l2-claim sign` and `sendrawtransaction`, as before. A claim of 100 BLCH or more also needs `attestor/aggregate_attestation.py`, run with the attestor `bloch-pos` `093909a2…`: the node build has no `verify-attestation`, and every set then reads as refused.

5. **Confirm from the claimed set, not from the reply.** `sendrawtransaction` answering `accepted` or `duplicate` means only that the node's mempool took the bytes. Admission does not check the nullifier, so a repeated claim is answered the same way and is then dropped by consensus: nothing moves and no second payment is possible. To confirm, run `bloch-l2-withdraw.py verify --proof proof.json --l1-rpc URL`, which exits 4 once the index is claimed and the record is on L1.

Exit status: 0 ok; 1 refused (bad proof, wrong owner, wrong network); 3 not ready yet; 4 already claimed.

## What is verified, and against what

| check | where |
|---|---|
| leaf recomputed from chain id, index, recipient and sats | client |
| 32 siblings fold the leaf to the root; index below count | client |
| recipient and sats are the ones the user expects (`--any-recipient` for relayers) | client |
| the root is in the L1's `getl2settlement` `withdrawals.roots` with the same count and L2 block, `finalized: true` | client, against each `--l1-rpc` |
| the root is the L1's `claimable` (or `claimable_large`) record, which already includes the delay | client |
| the index is not in the L1 nullifier set; the L1 network, genesis and chain id match the pins | client |
| the node does not report a finality that is not the chain's own | client |
| everything above, and the delay, the nullifier, escrow and the release window | L1 consensus, when the claim is included |

`proof.json` is rebuilt from checked fields only, so nothing else the RPC sent reaches the native tool.

**Trust.** The L2 RPC is not trusted at all. A lying L2 RPC can only waste a user's time. The L1 RPC is the anchor of the client-side check, so use your own node, or give several `--l1-rpc` values to require that they agree. A lying L1 RPC can get the client to write a proof that consensus later refuses. It cannot release funds, because the L1 verifies the claim itself.

## `bloch_getWithdrawalProof(index, root?)`

Read-only, on the settled RPC. `index` is a hex quantity or an integer. `root` is optional, 32 bytes of hex, and selects a finalized settlement that added withdrawals; the default is the newest one. A claim must prove against a root that has matured on L1, which is usually not the newest, so the client always passes the root the L1 reports.

The answer has the `bloch-l2-produce-dev withdrawal-proof` fields (`chain_id`, `number`, `withdrawal_root`, `withdrawal_count`, `index`, `withdrawal`, `siblings`) plus `finalized`, `l2_hash`, `native_slot` and `native_block`.

| code | meaning | what the client does |
|---|---|---|
| -32041 | the withdrawal exists on this RPC's chain, no finalized settlement covers it yet | retry |
| -32042 | no withdrawal with this index on this RPC's chain | retry within `--wait`: the RPC may lag |
| -32043 | the root is not that of a finalized settlement known here | retry within `--wait` |
| -32044 | the withdrawal is newer than the requested root | refuse |
| -32045 | the index is still reading finalized blocks | retry |
| -32046 | frozen: a finalized settlement disagrees with this RPC's receipts | refuse; the operator must investigate |
| -32602 | malformed parameters | refuse |

**Operation.** The index holds only finalized data. It reads a block's receipts only after a finalized settlement raised the withdrawal count, and it publishes the new leaves only if they fold to that settlement's root and count. A mismatch logs `withdrawal proofs FROZEN` and stops the method until a restart; the rest of the RPC keeps serving. Requests are answered from memory, without a database read. Memory is about 170 bytes per withdrawal, and the index is rebuilt at start from the finalized blocks that added withdrawals. The method exists only under rules with an outbox (`v3`, `mainnet`).

## Tests

```
python3 deployment/mainnet/withdraw/tests/test_withdraw.py
```

```
cargo +1.98.1 test --release --locked --manifest-path integrations/reth-execution/Cargo.toml --bin bloch-l2-settled-rpc
```

`tests/live_private_l2.py` runs the whole flow against a real settled RPC over a private L2 database. Its finality is synthetic and its L1 is a mock, and it says so; see its docstring.
