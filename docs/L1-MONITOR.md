# L1 monitor (`deployment/mainnet/l1_monitor.py`)

A read-only monitor for the bloch-pos nodes the L2 depends on and for our own fleet. It packages agent 70's stuck-node rule (`l1_stuck_check.py`) with the other L1 signs operators need, and delivers alerts the same way `l2_monitor.py` does. What to do once it fires is in `docs/L1-STUCK-NODE-RUNBOOK.md` and in `docs/L2-MAINNET-GO-LIVE.md` (refill section). Do not wipe a mainnet node's data.

## What it checks

| Check | Level | Meaning | First action |
|---|---|---|---|
| `l1_stuck[NAME]` | CRIT | Parked at 32 or more, finalized frozen below the reference, reference head not on the node's chain, all held while the reference finalized 3 more epochs (agent 70's rule, unchanged) | Stuck-node runbook. Stop reading from that node |
| `l1_stuck[NAME]` | WARN | Not following the reference, but parked is unknown (no metrics) or low | Read the node's metrics |
| `l1_finality` | WARN 4, CRIT 8 | Epochs from now (wall clock and the nodes' `slot`/`wall_slot`) to the best finalized epoch. 2 is normal | A network-wide stall: no node is "stuck" in that case, so `l1_stuck` stays quiet by design |
| `l1_parked[NAME]` | WARN | `bloch_pos_blocks_parked` held at 32 or more while the reference gained 3 finalized epochs, on a node that is not already CRIT | Watch for `l1_stuck` |
| `l1_peers[NAME]` | WARN at 2 or less, or a fall to half of the recent maximum (from a maximum of at least 4); CRIT at 0 | Peer count from `/metrics` or, without metrics, from `getchaininfo.transport.peers`. Graded only after 2 runs in a row (a restarted node shows 0 for a moment) | Check the transport and firewall |
| `l1_metrics[NAME]` | WARN | A configured metrics URL does not answer | Without metrics, `l1_stuck` stops at WARN |
| `l1_finality_conflict` | CRIT | Nodes at the same finalized epoch report different finalized roots: two branches are final (agent 205, drill a: after a 15 min 2\|3 split each side finalized its own branch; `l1_split` only saw a tie) | Stop the L2 settler, name the branch every L2 reader follows, then the stuck-node runbook |
| `l1_split` | WARN | Nodes on a branch apart from the one finalizing furthest, or two branches tied on (finalized, justified) | Find which side the L2 readers are on |
| `l1_settler_sources` | CRIT | A quorum of the settler's `rpc_urls` is on a branch apart from the one finalizing furthest, for 2 runs in a row (report 94: the settler settled L2 blocks 6-8 on a dead fork) | Repoint the settler's `rpc_urls` at nodes on the finalizing branch; then `l2_reorg_recover.py` if it accepted settlements there |
| `l1_settler_sources` | WARN | One source apart; or no quorum on the finalizing branch; or a split not yet decided with the settler's quorum on one side | Prepare a replacement source |
| `l1_nodes` | WARN / CRIT | Some / none of the configured nodes answer | |

How branches are compared: two nodes are on one branch when either has the other's head on its canonical chain (`getblockbyid`, and an answer of `finality: not_canonical` counts as not on it). The branch that counts is the one with the highest (finalized, justified) epoch. When two branches tie on both, the split is reported as undecided; the script never picks a side by counting nodes, because a handful of RPCs says nothing about stake.

It calls only `getchaininfo` and `getblockbyid`, plus a GET of each metrics URL. It holds no key, opens no node file, and reads the settler's `config.json` only for `rpc_urls` and `rpc_quorum`.

## Install (no unit)

The script is one file with no dependencies (Python 3.9+), run with `python3 -I`. Keep it next to `l2_monitor.py`. The config is JSON: start from `deployment/mainnet/monitor/l1-monitor.json.example`.

- `nodes`: every node to watch, with `name`, `rpc` and, where the node runs `--metrics-port`, `metrics` (`http://HOST:PORT/metrics`). Settler sources missing from `nodes` are added automatically, named `host:port`.
- `references`: optional list of node names to judge others against. Default: every other node.
- `settler`: `{"config_file": "/etc/bloch-l2-mainnet-settler/config.json"}` on the settler host, or `{"rpc_urls": [...], "rpc_quorum": 2}` elsewhere. Leave it out on hosts that do not care about the settler.
- `state_file`: required for anything held over time (without it, `l1_stuck` cannot reach CRIT). `report_file`: the JSON report for `l2_monitor --report`.
- `alert_config`: optional, the same schema as `l2_monitor`'s `alert.json`. Give it its own `state_file`.
- `thresholds`: optional overrides of the defaults at the top of the script. `network`: only for private nets.

Run it every minute from cron as the monitor user, or in a terminal with `--watch 60`. A run that finds the previous one still holding the state lock exits UNKNOWN without touching the state.

## Alerts: one path

Recommended on the L2 host: no `alert_config` here. Add `--report l1=/var/lib/bloch-l2-monitor/l1-monitor.report.json:180` to `MONITOR_ARGS` of the L2 monitor. Its WARN and CRIT checks then go out through `l2_monitor`'s webhook, `alert_command`, Telegram and heartbeat as `l1/<check>`, with one deduplication, and a report older than 180 s (CRIT at 540 s) means this script has stopped.

On a host with no `l2_monitor` (a validator operator's), set `alert_config`. Delivery is the same code as `l2_monitor` (agent 105): `alert_command` gets `{event}` and `{status}` as arguments and the JSON on stdin, with `"source": "l1_monitor"` in it; a check that clears must stay clear for `recover_runs` runs before a recovery is sent.

## Limits

- Alarm time for a stuck node is agent 70's: about 48 minutes on mainnet after parked reaches 32 (3 finalized epochs of the reference), plus one run. A settler quorum on a dead branch is graded as soon as the branches differ in (finalized, justified) epoch, which on mainnet can take up to one or two epochs (16 to 32 minutes) after a split; before that the split shows as undecided (WARN).
- Production peer counts and metrics ports are not known to the author: the peer floors only catch a node that is nearly isolated.
- The recorded fixtures come from private 1 s-slot nets on the devnet transport, sampled about 3 epochs apart; nothing here ran against mainnet.
