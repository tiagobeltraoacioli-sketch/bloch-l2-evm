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
dependencies, no keys) for the v2.1 L2 build `bloch-l2-2026-10-30-v21-native-78d4921c` (follower
`c18752fd…`, produce-dev `fb0d5313…`, settled-rpc `18be911a…`). Its JSON-RPC
calls are limited to `eth_chainId`, `eth_blockNumber`,
`eth_getBlockByNumber`, `eth_getStorageAt`, `bloch_finality`,
`getchaininfo`, `getblockcount` and `getl2settlement`; any other method is
refused before a request is made. Its only other commands are
`systemctl show` and `journalctl` (read-only). Exit status: 0 OK, 1 WARN,
2 CRIT, 3 UNKNOWN (Nagios/Prometheus-textfile friendly).

```
python3 deployment/mainnet/l2_monitor.py --profile mainnet --phase live \
  --l2-rpc A=http://127.0.0.1:18955 --l2-rpc B=http://BACKEND_B:18955 \
  --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://45.77.67.251:8080 \
  --follower-status A=/var/lib/bloch-l2-mainnet-follower/status.json \
  --unit settler=bloch-l2-mainnet-settler.service --unit shadow=bloch-l2-mainnet-shadow.service \
  --attest-drop https://drop.example/attest --alert-config /etc/bloch-l2-monitor/alert.json --json
```

Options:

- `--phase prelaunch` (until the first settlement is accepted): an L2 at its
  pinned genesis with `accepted = null` is expected, not an alert. Switch to
  `--phase live` at go-live; with a settlement present, `prelaunch` warns.
- `--l2-rpc NAME=URL` once per settled-RPC backend (A on 136, B on
  45.77): each is checked, and they must agree on every common block.
- `--follower-status NAME=PATH`: a follower `status.json` (age, pins,
  verified lag, epoch lag). The file must be readable by the monitor user.
- `--unit NAME=UNIT`: unit state (a failed unit with exit 3 is a halt) and
  the failure events of its JSON journal in the last hour (settler: `halt`,
  `prover-failed`, a non-zero `remote-proof`, `acceptance-timeout`,
  `rpc-no-quorum`, `da-funding-low`, …; shadow: `halt`, `native-no-quorum`;
  attestor: `refused-*`, `held`, `publish-failed`). `--event-log
  NAME=PATH` does the same for a log file.
- `--attest-drop DIR_OR_URL`: the attestation drop, for signatures per round.
- `--binary PATH`: the installed binary must equal its v2 pin.
- `--build-json PATH`: compare the L1 gates with this build's compiled
  epochs (default: the v2 epochs compiled into the monitor).
- `--file NAME=PATH[:SECONDS]`: heartbeat age, WARN above SECONDS and CRIT
  above 5×SECONDS. `--set KEY=VALUE` overrides a threshold.
- `--alert-config FILE` (`monitor/alert.json.example`): `webhook_url`
  (JSON POST with `text`, `status`, `checks`), `telegram.bot_token_file` +
  `telegram.chat_id`, `min_level`, `realert_seconds`. It alerts on a new or
  worse check, repeats every `realert_seconds` while unhealthy, and sends one
  recovery. Values containing `TBD` count as unset (the run then reports
  `alert_delivery` WARN). `--alert-dry-run` decides without sending.

Tests: `python3 -m unittest discover -s deployment/mainnet -p
'test_l2_monitor.py' -v`. Run it every minute under an unprivileged user
(`monitor/bloch-l2-mainnet-monitor.{service,timer}`); it needs only HTTP
access to the RPCs and, for alerts, to the webhook / api.telegram.org.

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
| `follower_verified_lag[*]` | L1 finalized height − follower verified blocks | 64 | 320 | 64 = two epochs; 320 ≈ 10 epochs (≈ 2.7 h) |
| `follower_epoch_lag[*]` | L1 finalized epoch − follower's own FFG-finalized epoch | 5 | 8 | a constant 3 is structural: the votes finalizing the newest checkpoints are in blocks after the node's finalized root |
| `follower_status[*]` | `status.json` age and pins | 300 s | 900 s | the attestor agent treats > 900 s as a stalled follower |
| `l2_backends`, `l2_backends_agree` | backends up; same hash for every common block; finalized spread | one down / spread 2 | all down / any hash differs / spread 8 | two followers replaying the same L1 must agree exactly |
| `l2_genesis[*]` | block 0 = `632e45ae…f468` | – | differs | wrong database or profile |
| `settlement_age` | now − time of `getl2settlement.source.slot` (frozen right after each acceptance) | 25 min | 45 min | same cadence as `l2_head_age`; `live` phase only |
| `l1_l2_identity` | network, genesis, chain id and attestor set of `getl2settlement` | – | differs | pins |
| `l1_gates` | epochs to the next pending L1 gate (`getchaininfo.hard_forks`) | 96 (≈ 1 day) | 6 | upgrades must land before the gate |
| `l1_gates_vs_l2_build` | L1 gate epochs = epochs compiled into the L2 build | – | differs | a follower/producer built for other epochs halts at the gate |
| `attestors` | per finalized withdrawal root with at least one partial, older than 120 L1 blocks: signatures | < 5 | < 3 | agents sign only roots covering a ≥ 100 BLCH withdrawal; once one signs, all live agents sign within a few cycles. The message names silent signers |
| `unit[*]`, `events[*]` | unit state; failure events in the last hour | warn events; ≥ 5 restarts | `halt`, refusals, a stopped unit; any warn event ≥ 5 times | |
| `binary[*]` | installed sha256 = v2 pin | – | differs | |
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
