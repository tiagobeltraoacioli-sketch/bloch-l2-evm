# Bloch L2 mainnet: operations runbook and monitoring

Scope: the operator side of the L2 installed on Bloch L1 at epoch 5850
(chain id 700770). Exchange-facing behaviour is in
[MAINNET-EXCHANGE-INTEGRATION.md](MAINNET-EXCHANGE-INTEGRATION.md).

## 1. Components and what "healthy" means

| Component | Role | Healthy when |
|---|---|---|
| L1 nodes (`bloch-pos` 0.1.0-mainnet, 3 RPCs) | settlement, DA, deposits, claims, escrow | same head ± a few blocks, L1 finalized epoch = epoch − 2, `getl2settlement.profile.activated = true` |
| Sequencer / settlement worker | builds one L2 block per cycle, publishes DA, submits the settlement | a new L2 block every ≈ 12–15 min; `latest − safe = 1` |
| Prover (SP1 Groth16) | proves each block | one proof per cycle; the cycle time is the block interval |
| Native follower | replays L1 from the pinned genesis, derives `finalized` | `verified_blocks` = L1 finalized height (within a poll) |
| Settled RPC (`bloch-l2-settled-rpc`) | serves `latest`/`safe`/`finalized`, spools transactions | answers; tags ordered; `bloch_finality` current |
| Public RPC gateway, explorer | public access | out of scope here; probe them with the same monitor |
| Escrow | L1 consensus escrow backing L2 supply | `escrow_conserved = true` on every L1 node; escrow + released ≥ L2 minted − burned |

## 2. Monitor

`deployment/mainnet/l2_monitor.py` is a read-only checker (Python 3.9+, no
dependencies, no keys). It calls only `eth_chainId`, `eth_blockNumber`,
`eth_getBlockByNumber`, `eth_getStorageAt`, `bloch_finality`,
`getchaininfo`, `getblockcount` and `getl2settlement`; any other method is
refused before a request is made. Exit status: 0 OK, 1 WARN, 2 CRIT,
3 UNKNOWN (Nagios/Prometheus-textfile friendly).

```
python3 deployment/mainnet/l2_monitor.py --profile mainnet \
  --l2-rpc http://127.0.0.1:18945 \
  --l1-rpc http://127.0.0.1:PORT_A --l1-rpc http://127.0.0.1:PORT_B --l1-rpc http://127.0.0.1:PORT_C \
  --file prover=/path/to/prover-heartbeat:900 --json
```

`--file NAME=PATH[:SECONDS]` age-checks any heartbeat or status file (for
example the follower `status.json`, or a prover/settler heartbeat), WARN
above SECONDS and CRIT above 5×SECONDS. `--set KEY=VALUE` overrides a
threshold. Tests: `python3 -m unittest discover -s deployment/mainnet -p
'test_l2_monitor.py' -v`. Run it every minute from cron or a timer under an
unprivileged user; it needs only loopback HTTP access.

Run on devnet4 (2026-10-18 22:48 UTC, `--profile devnet4`, three L1 RPCs,
through an SSH port forward): status OK; latest 686, safe 685, finalized 684;
L1 epoch 8165 / finalized 8163; follower 0 blocks behind; escrow 123.98 BLCH +
released 176.02 BLCH = minted 300 BLCH.

## 3. Checks and alert thresholds (mainnet profile)

Baselines measured on devnet4 over L2 blocks 585–685 (see the exchange doc);
mainnet L1 epochs are 16 min (32 × 30 s).

| Check | Measures | WARN | CRIT | Why these numbers |
|---|---|---|---|---|
| `l2_rpc`, `l2_chain_id` | RPC up, chain id 700770 | – | down / wrong id | a wrong id means the wrong binary or profile |
| `l2_head_age` | now − timestamp of `latest` | 25 min | 45 min | normal interval 12–15 min; 25 min ≈ one missed cycle, 45 min ≈ three |
| `l2_unsafe_depth` | `latest − safe` | 2 | 4 | 1 is normal (the block being proved); ≥ 2 means settlements are not landing on L1 |
| `l2_finalized_age` | now − timestamp of `finalized` | 150 min | 240 min | normal ≈ 100–130 min (one interval + ≈ 85 min finality + one interval of age) |
| `l2_tag_order` | finalized ≤ safe ≤ latest | – | violated | the RPC must never publish this; stop public crediting |
| `l2_safe`, `l2_finalized` | tag present | missing | – | expected only before the first settlement / first finalization |
| `l1_nodes` | L1 RPCs answering | one down | half or more down | the settler needs a 2-of-3 quorum |
| `l1_height_spread` | max − min L1 height | 3 | 32 | > one epoch apart = a node is stuck or on a fork |
| `l1_finality_lag` | L1 epoch − finalized epoch | 4 | 8 | 2 is normal; 4 = finality stalling (the 2026-10-13 incident) |
| `l1_accepted_agreement` | `getl2settlement.accepted` equal on all nodes | differs | – | transient during a block; persistent = fork, see 4.5 |
| `escrow_conserved` | flag on every L1 node | missing | false | consensus invariant; false is never expected |
| `escrow_backing` | (escrow + released) × 10^10 ≥ L2 minted − burned | – | violated | every minted wei came from an escrowed deposit |
| `claims_vs_withdrawn` | L1 released ≤ L2 withdrawn | – | violated | claims can only pay withdrawn value |
| `inbox_backlog` | L1 deposits not consumed by the L2 | 50 | 500 | each L2 block consumes all pending deposits; a backlog means the sequencer is not reading L1 |
| `da_backlog` | DA records awaiting settlement | 3 | 10 | one per block with user transactions; growth = settlements failing after DA |
| `release_window` | remaining release in the current window | 0 left | – | exchanges' L2 → L1 claims will wait for the next window |
| `follower_lag` | L1 finalized height − follower verified blocks | 64 | 320 | 64 = two epochs; 320 ≈ 10 epochs (≈ 2.7 h) |
| `file:*` | heartbeat file age | given | 5 × given | prover/settler/follower liveness |

The `devnet4` profile keeps the same structure with devnet values (2 s
slots: finalized age 40/90 min, height spread 15/160, follower lag 160/960).

## 4. Playbooks

### 4.1 `l2_head_age` WARN/CRIT, `l2_unsafe_depth` normal

The sequencer/settlement worker is not producing. Check, in order: the worker
process and its log (a divergence makes it exit 3 for operator review: do
not restart blindly, read the reason); the prover (memory: a Groth16 proof
needs ≈ 20 GB peak RSS; host OOMs stalled devnets before); the L1 RPC quorum
(`settler --check-rpc` prints the per-endpoint view, read-only).

### 4.2 `l2_unsafe_depth` ≥ 2

Blocks are produced but settlements are not accepted at the L1 head. Check
the DA record and settlement transaction in the L1 mempool
(`getl2settlement.data_availability`, `accepted`), the DA fee funding key
balance, and L1 block production. Never submit a settlement by hand for a
block the worker refused.

### 4.3 `l2_finalized_age` high, `safe` advancing

Either L1 finality is stalled (`l1_finality_lag` WARN/CRIT) or the follower
is behind (`follower_lag`).

- L1 finality stall: this is an L1 incident (validator liveness, memory,
  forks). Tell exchanges that deposits will be credited late; do **not**
  advise crediting on `safe` or on a confirmation count.
- Follower behind while L1 finalizes: check its process, disk and the L1
  RPC it reads. On restart it re-verifies its retained history from genesis
  (slow but safe). `finalized` resumes by itself; it never regresses.

### 4.4 `escrow_conserved` false, `escrow_backing` or `claims_vs_withdrawn` CRIT

Treat as a security incident. Stop the public bridge tooling and attestor
signing, keep the RPC read-only, notify exchanges to pause L2 deposits and
withdrawals, preserve logs and node data, and escalate. Do not restart L1
nodes before the data is preserved.

### 4.5 L1 nodes disagree (`l1_height_spread`, `l1_accepted_agreement`)

Compare `getchaininfo` block ids and finalized roots across the nodes and
against the archivals. A node on a minority branch must be resynced; the
settler already ignores minority answers (2-of-3 quorum), so production
continues while two nodes agree.

### 4.6 `inbox_backlog` growing

The sequencer is not consuming L1 deposits. Users' L1 BLCH is locked in the
escrow and safe, but not yet minted on L2. Check the worker log for refused
deposit records and that it reads the same L1 request as the quorum.

### 4.7 `release_window` exhausted

Not a fault: the consensus rate limit (10 % of the escrow, floor 10 BLCH,
per 2 880 L1 blocks) is reached. Claims wait for the next window. Inform
exchanges that are rebalancing L2 → L1.

## 5. Routine

- Every minute: the monitor (alerts on WARN for > 5 min and on any CRIT).
- Daily: compare the measured block interval and `safe → finalized` time with
  the exchange doc; update its table after the first mainnet week.
- Before any binary change: run the monitor before and after; `latest`,
  `safe`, `finalized` must keep advancing and never regress.
- Keep all keys (sequencer DA funding key, attestor keys) off the monitoring
  host; the monitor needs none.

## 6. Known gap: finality latency

The follower fetches L1 blocks only up to the node-reported finalized root
and then derives finality by replaying them, so it can prove only the
finality already contained in that prefix. The result is about twice the L1
finality lag (devnet4: `safe → finalized` ≈ 5.3 L1 epochs against an L1 lag
of 2–3 epochs; on mainnet ≈ 85 min instead of ≈ 40 min). Fetching and
replaying up to the L1 head (still deriving finality only by replay) would
roughly halve the exchange confirmation time without changing the trust
model.
