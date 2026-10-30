# Bloch L2 mainnet settler: install and first settlement

Chain 700770, activated on Genesis-4 at epoch 5850 (slot 187200, 2026-10-17 21:31 UTC).
The worker is `deployment/devnet/settler_v3.py` with `network_kind: "mainnet"`. The installer
is `deployment/mainnet/install-settler-mainnet.py`. Every step that can reach mainnet is
marked **MAINNET WRITE**. Nothing else signs or broadcasts.

## What the worker does

Each cycle it:

1. reads `getl2settlement` from three mainnet RPCs and acts only on a 2-of-3 identical answer;
2. extends the L2 by one block anchored to the native source (`bloch-l2-produce-dev --rules mainnet`);
3. proves the block with `settlement_v3_mainnet` (`bloch-evm-sp1-settlement-v3 --mainnet`:
   execute, then Groth16, then a local verify);
4. checks every public value against the request and the pins;
5. with user transactions only: publishes the batch in a 0x15 DA transaction signed by the DA
   fee key, and waits for the DA record;
6. submits the 1155-byte 0x13 settlement and waits for `accepted`.

Pins enforced at start and checked live by quorum:

| Pin | Value |
| --- | --- |
| admission domain | `f47d3e49…311966` |
| native genesis | `9953da73…e415` |
| async mode, activated profile | yes |
| attestor set | `1c06adbb…cc4b` (3-of-5) |
| guest | `settlement_v3_mainnet`, SHA-256 `203114bf…c473` |
| proof policy V3 | `15486996…747d` |
| L2 genesis | `632e45ae…f468` |
| `l2-config.bin` | 264 bytes, SHA-256 `292f4fa8…4f6b`, derived in code (`mainnet_l2_config()`) |
| timestamp rule | `1:1786656679:30000` |

## Host

Do **not** run this on the three 128 GB mainnet validator hosts. They ran out of memory on
2026-10-12. Requirements:

- 8 or more cores, 32 GB RAM for the worker's cgroup (`MemoryMax=32G`), and Docker (pinned gnark image).
- About 50 GB of disk, plus the SP1 Groth16 v6.1.0 circuit artifacts in `$HOME/.sp1`. These are
  downloaded on the first proof. To avoid the download, copy them from a devnet4 settler home.
- If the Groth16 proof runs on a remote prover, use `configure --remote-prover` with
  `remote_prover.py` and `"mainnet": true` in its config. The worker still runs execute and verify
  locally.

**Only one settler may run.** A second one is halted the first time the other's statement is
accepted ("another settler?").

## 0. Release directory (on the operator host)

Put these in `DIR`. `prepare` checks each pin and refuses a mismatch.

| File | Source | SHA-256 |
| --- | --- | --- |
| `settler_v3.py` | this branch, `deployment/devnet/` | (recorded in the `/opt` path) |
| `bloch-evm-sp1-settlement-v3` | `build-program.sh` host step (any path; v2 build `3a24c36d…973a`, 10-19 build `505500af…aa07`) | not a pin: its `--mainnet identity` must equal the native program pins (`identity.json` `22571783…659e`) |
| `bloch-l2-produce-dev` | `build-release.sh` against native 78d4921c (v2 `7c1cc62b…5a3c`) | not a pin |
| `settlement_v3_mainnet` | reproducible guest | `203114bf…c473` (enforced) |
| `bloch-pos` | armed mainnet release 78d4921c (canonical container) | `700631b0…794e` (enforced) |
| `mainnet.manifest` | `bloch-sis-pow genesis/mainnet.manifest` | `7eef82a7…b2dd` (enforced) |

## 1. Prepare (local only)

```
sudo python3 install-settler-mainnet.py prepare --release DIR
```

This creates the user `bloch-l2-mainnet-settler`, the directories and the pinned `l2-config.bin`.
It also generates a **new DA fee key**:

- a sealed hybrid keystore in `/var/lib/bloch-l2-mainnet-da` (0700, owned by the settler);
- a random passphrase in `/var/lib/bloch-l2-mainnet-settler/da.passphrase` (0400), never printed.

The output includes `da_funding_script_hash`.

Back up the keystore directory and the passphrase **separately**, for example on two
age-encrypted media. The key only ever holds DA fee money.

### Funding the DA fee key

0x13 settlements pay **no fee**. They are protocol-only, but each one fills a whole L1 block's
gas, so the base fee rises one step after each settlement.

0x15 DA transactions pay the ordinary eUTXO price. That price is
`5000 + 16 × (8471 + 36·inputs + payload) + 72748·inputs` gas at the base fee (rounded up to whole
satoshis):

| DA payload | Fee at 10 msat/gas (floor, today) | At 100× floor |
| --- | --- | --- |
| 1 small tx (~200 B) | ≈ 2,170 sat | ≈ 0.0022 BLCH |
| full batch 114,688 B | 20,489 sat (0.0002 BLCH) | 0.0205 BLCH |

Recommendation:

- Fund **5 BLCH in two outputs**, which covers about 240 full batches at 100× the floor price.
- The worker logs `da-funding-low` below 1 BLCH.
- With `user_transactions: false` (the default), no funding is needed: empty and deposit-only
  blocks need no DA.

## 2. Configure, then run the read-only checks (no transaction)

```
sudo python3 install-settler-mainnet.py configure --prover-threads 6
```

This writes `/etc/bloch-l2-mainnet-settler/config.json`:

- RPCs `80.240.16.185`, `199.247.22.8` and `45.77.67.251` on port 8080, quorum 2;
- acceptance timeout 1800 s, rebroadcast every 300 s, polling every 15 s;
- user transactions **off**.

It then runs:

- `settler_v3.py --check-rpc`: the per-endpoint view hash and the quorum;
- `settler_v3.py --dry-run`: identity by quorum, a scratch L2 genesis, L2 block 1 against the
  live request, and SP1 **execute**. Report: `/var/lib/bloch-l2-mainnet-settler/dry-run-*/dry-run-report.json`.

Reference result: on 2026-10-18 22:55 UTC this was run from 45.77.142.123 as `ubuntu` with the
pinned host and guest.

- quorum 3/3: source height 1, slot 187200, block `618c9b80…dc9f`, nothing accepted;
- L2 block 1 = `0ff59c1194f6d81be26dc288e4ba9bb721e46181787f3f9cffb0b029b281ab25`;
- SP1 execute matched;
- settlement fee 0.

## 3. Dry run with the Groth16 proof (no transaction)

```
sudo python3 install-settler-mainnet.py dry-run --prove
```

This takes about 15 minutes and peaks at about 20 GB at 6 threads. It writes
`settlement-tx.hex`, the exact 1155-byte 0x13 settlement the worker would submit, plus its SHA-256
in the report. Check these fields:

- `ok: true`
- `transaction.tag 0x13`
- `bytes 1155`
- `proof_policy 154869964f…747d`

Nothing is broadcast. Any `sendrawtransaction` is refused in code.

## 4. First settlement — **MAINNET WRITE**

```
sudo python3 install-settler-mainnet.py start --confirm-mainnet
journalctl -u bloch-l2-mainnet-settler.service -f -o cat
```

Expected events, in order:

1. `identity-checked` (`mainnet: true`)
2. `l2-block-produced` (number 1)
3. `proof-generated`
4. `transaction-built`
5. `submitted`
6. `accepted`

Then verify it independently. In the output of
`curl -s http://80.240.16.185:8080 -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}'`:

- `accepted.statement` L2 number = 1, on all three nodes;
- `source.height` moves past 1.

Wait for FFG finality of that native block (`getchaininfo.finalized_height`) before telling
followers or exchanges.

Enable user transactions only after these steps:

1. the first settlements are accepted and finalized;
2. the DA key is funded;
3. the follower and RPC can rebuild from L1 DA.

Then edit `user_transactions: true` in `config.json` and run
`systemctl restart bloch-l2-mainnet-settler`. The worker refuses this if the live profile does
not admit user transactions.

## 5. Rollback

```
sudo python3 install-settler-mainnet.py rollback
```

This stops and disables the unit and removes the unit file. It keeps the L2 database, the work
directory, the keystore, the passphrase and the config.

An accepted L1 settlement cannot be undone. The L2 simply stops advancing until a settler runs
again. Restart with `start --confirm-mainnet` (the unit file is recreated). The worker resumes
from the accepted head; it reuses a block left by a crash if its anchor is unchanged.

## Operations

| Log event | Meaning / action |
| --- | --- |
| `submitted-duplicate` | The node already holds or recently included these bytes. The worker keeps waiting. |
| `submit-refused` kind `retry` | Another proof is pending, the mempool is full, or a retryable bar. The worker rebroadcasts the **same bytes**. |
| `acceptance-timeout` + `l1-not-advancing` | The L1 is stalled (the devnet4 block-231 case). Nothing to fix in the settler: the next cycle reuses the same proof and bytes. |
| `rpc-no-quorum` / `rpc-endpoint-diverged` | The RPCs disagree. The worker waits and never uses a minority answer. |
| `da-funding-low` | Top up the DA fee key. |
| `halt` (exit 3, no auto-restart) | Operator review. Causes: a foreign statement accepted for the same block (another settler), a terminal native refusal with an unchanged request, pin or identity mismatch, or producer or DB divergence. |

## Attestor signatures (3-of-5): when and how

**When they are needed.** Only for L2→L1 withdrawal **claims of ≥ 100 BLCH**. They are not
needed for any of these:

- settlements (0x13);
- DA (0x15);
- deposits (0x14);
- claims under 100 BLCH, which only need the proof against an FFG-finalized settlement plus
  64 blocks.

For a large claim:

- The settlement carrying the withdrawal must be FFG-finalized.
- The claim pays only after **2,880 blocks**.
- Three distinct attestors of set `1c06adbb…` must sign the withdrawal proof
  (`bloch-pos l2-claim attest`, hybrid key) before the claim is submitted.
- The release window caps payouts per 2,880 blocks at 10 % of escrow, with a 10 BLCH floor.
  Only an attested first claim of a window may exceed it.

Nothing needs signing until the first ≥ 100 BLCH withdrawal exists.

**Implemented:** `deployment/mainnet/attestor/` (agent, hardened units, install/rollback, claimant
aggregator, key handoff kit). Its README describes the cycle; the notes below are the original design.

**Signing without recurring manual work.** Each of the five operators runs an *attestor agent*
on their own host, with their own key. The keys stay in `~/Desktop/L2-MAINNET-ATESTADORES` until
each one is moved to its operator; they never sit on the settler host. The agent has these parts:

1. **Its own follower.** A Genesis-4 node or the native follower replays L1 from the pinned
   genesis. The agent trusts no RPC.
2. **A watcher.** It polls a public claim-request queue: an HTTPS directory, or the L2 RPC's
   list of outbox withdrawals ≥ 100 BLCH.
3. **Rebuild and sign.** For each request whose settlement is finalized, it runs the devnet4
   `atestador.py` logic:
   - rebuild the L2 from L1 DA only (`produce reconstruct --l1-follower --rules mainnet`);
   - derive its own Merkle proof;
   - require that proof to equal the claim;
   - sign with `l2-claim attest`.

   It then publishes the partial signature to the queue. The relayer (deposit/withdraw tooling)
   collects any 3 and submits the claim.
4. **Key custody.** The key is sealed (age or passphrase) and given to the agent through systemd
   `LoadCredential=`. The agent runs under an unprivileged user with no network listener.
5. **Guards in the agent.** A per-day amount cap, a pause file, refusal of any claim not rebuilt
   from L1, and an alert on every signature.

With these in place, operators act only on alerts. There are no periodic signatures and no key
rotation: the attestor set is set-once. A new set requires a new activation.
