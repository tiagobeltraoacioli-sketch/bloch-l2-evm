# Bloch L2 mainnet: operator runbook per failure

Scope: what the on-call operator does for each failure of a live L2 (chain 700770). Checks and thresholds are in
[MAINNET-OPS-RUNBOOK.md](MAINNET-OPS-RUNBOOK.md); this file starts from the alert.

**Evidence.** Each entry names what backs it.

- **Drill**: a private-net failure drill with real Groth16 and real private L1 verification
  (`deployment/mainnet/rehearsal/drills/`). Most ran with the flag day at e2, where chain height and L2 height have no
  offset, so they say nothing about rebuilds at mainnet heights.
- **Alert**: the alert was provoked on a private net through the production monitor.
- **Code**: read from the code, not rehearsed.

Nothing here has run on mainnet, and no L2 has been operated with live users.

**Rules for every entry.**

- A unit that exited 3 is a halt. It does not restart by itself, on purpose. Read the reason before anything else.
- Never submit a settlement or a DA transaction by hand. Never edit a database or a work directory by hand.
- Only one settler may run. A second one is halted when the other's statement is accepted.
- Do not restart a follower close to an L1 gate. A restart re-verifies the chain from Genesis-4, about an hour, and
  `finalized` stays frozen meanwhile.
- Keep logs and data of a halted component before changing them.

## Units and paths

| Role | Unit | State |
|---|---|---|
| Settler (worker) | `bloch-l2-mainnet-settler` | `/var/lib/bloch-l2-mainnet-settler`, config `/etc/bloch-l2-mainnet-settler/config.json` |
| Follower | `bloch-l2-mainnet-follower` | `/var/lib/bloch-l2-mainnet-follower` |
| Settled RPC | `bloch-l2-mainnet-rpc` | `/var/lib/bloch-l2-mainnet-rpc` |
| Attestor | `bloch-l2-attestor`, `bloch-l2-attestor-follower`, `bloch-l2-attestor-feed` | `/var/lib/bloch-l2-attestor` |
| Replica | `bloch-l2-replica-follower`, `-rpc`, `-refresh.timer`, `-rpc-reload.path` | `/var/lib/bloch-l2-replica` |

Read a worker's reason with:

```
journalctl -u bloch-l2-mainnet-settler -o cat --no-pager -n 50
```

## Which entry to open

| Alert | Entry |
|---|---|
| `settlement_age`, `l2_head_age`, `l2_unsafe_depth` | 1, then 2, 3, 4 |
| `events[settler]` `prover-failed` | 3 |
| `events[settler]` or `unit[settler]` `halt` | 4 |
| `l1_finality_lag`, `l2_finalized_age`, `follower_epoch_lag` | 5 |
| `l2_finality_closed`, `l2_finality_status`, `follower_status` | 6 |
| `follower_status_size` | 7 |
| `da_balance`, `da-funding-low` | 8 |
| `disk[*]` | 9 |
| `l2_rpc[*]`, `l2_backends` | 10 |
| `unit[attestor]`, `events[attestor]`, `attestors` | 11 |
| `unit[replica-*]` | 12 |

## 1. Settlements stopped, no halt

Effect: `safe` and `finalized` stop advancing. Funds are safe, and deposits are credited late.

Check the unit and the worker's last events. If the unit is simply stopped, start it. A settler killed at any stage resumes by itself: it reuses the block and pays no second fee.

```
systemctl status bloch-l2-mainnet-settler --no-pager
```

```
sudo systemctl start bloch-l2-mainnet-settler
```

Evidence: Alert, mainnet thresholds (25/45 min), settler stopped: WARN seen at 31 min and CRIT at 57 min, the samples taken; the exact crossings were not sampled. Drill PASS, unaided, no double payment: SIGKILL mid-proof (worker; group), after extend, and all 7 crash points around DA and submission.

A settler killed alone leaves its prover running. Its replacement queues behind it, which costs up to one extra proof time. Do not kill the prover by hand unless memory requires it.

## 2. A long proof or a full queue

`prove.log` in the block's work directory shows progress. Proof times from report 05: 11 min for an empty block, 28 min for 200 transfers at 8 threads. On a shared host, the wait for the proving lock adds to this: on the shared rehearsal host one proof waited 13 min, and later ones over an hour. On a dedicated prover this should not occur.

## 3. Prover failure

Alert: `events[settler]` WARN on `prover-failed`, CRIT at 5 in an hour. The worker retries by itself.

Effect: the block waits. Nothing is paid until a proof exists.

Read `exit_code` in the event. 137 is an out-of-memory kill: compare the block's instructions with the memory table in `L2-MAINNET-GO-LIVE.md`. The unit's `MemoryMax=32G` holds about 4M instructions; larger blocks need the remote prover and log `local-proof-refused`.

```
journalctl -u bloch-l2-mainnet-settler -o cat --no-pager --since "1 hour ago" --grep prover-failed
```

Evidence: Drill PASS (real cgroup OOM at 4G then 12G, then proved with no repair). Alert: real OOMs at a 4G cap through the production monitor: WARN on the first; CRIT on the second with the repeat threshold lowered to 2. The default of 5 has unit tests only.

Remote prover: since a3af936 it stops its proof group when the client disconnects. Live retest: not finished; the fix has 41 unit tests, and the drill before it showed the bug.

## 4. Settler halt (exit 3)

It will not restart. Read the reason, then match it:

| Reason | Meaning | Action |
|---|---|---|
| `L2 head N cannot extend accepted settlement M`, or an unsettled block with another anchor | An L1 reorg removed an accepted, unfinalized settlement | Below |
| `... already holds different ...` | State file conflict. A pre-5352c61 settler left truncated files after a full disk | Keep the data and escalate. Do not delete files |
| `the DA funding key has no spendable outputs`, `DA prepare failed` | Entry 8 | Fund the key |
| `another settler?` | Two settlers ran | Stop the extra one, then escalate |
| Pin or identity mismatch | Wrong binary or network | Compare against the signed release |

### Reorg recovery

Any reorg of an accepted, unfinalized settlement causes this, shallow or deep. Effect while halted: no settlement. The RPC keeps serving the orphaned blocks as `latest` and `safe` (drill: `safe` stayed on a block L1 had dropped), and a DA fee for an orphaned block may already be spent. **Tell integrators that `latest` and `safe` are unreliable until this is done.** `finalized` was not affected in the drill.

`install-settler-mainnet.py prepare` installs the tool next to the worker as `REL/l2_reorg_recover.py`, pinned `2a0cfabd…` (kit 4b7f4f7); `REL` is `/opt/bloch/l2-mainnet-settler/<digest>`. Its stdout is one JSON document; worker log lines go to stderr.

Then, during the incident:

```
sudo systemctl stop bloch-l2-mainnet-settler bloch-l2-mainnet-rpc
```

Plan, which changes nothing:

```
sudo -u bloch-l2-mainnet-settler python3 REL/l2_reorg_recover.py --config /etc/bloch-l2-mainnet-settler/config.json --follower-state /var/lib/bloch-l2-mainnet-follower/native --follower-status /var/lib/bloch-l2-mainnet-follower/status.json
```

`--follower-status` is required: the installed config does not name that file. Exit 75 means the accepted settlement is not finalized by the follower yet. Keep the follower running and run it again later. Exit 3 means refused: do not force it, escalate. Exit 0 prints the plan: check `accepted_number`, `database_head` and `orphaned_blocks`.

Apply with the same command plus `--apply`. It rebuilds a new database from L1, returns orphaned user transactions to the spool, moves orphaned work aside and keeps the old database.

```
sudo -u bloch-l2-mainnet-settler python3 REL/l2_reorg_recover.py --config /etc/bloch-l2-mainnet-settler/config.json --follower-state /var/lib/bloch-l2-mainnet-follower/native --follower-status /var/lib/bloch-l2-mainnet-follower/status.json --apply
```

```
sudo systemctl start bloch-l2-mainnet-rpc bloch-l2-mainnet-settler
```

The shadow halts too after a reorg (`job N exists but the L2 head is M`). Repair it before the settler's next block: `install-shadow.sh --rollback`, then reinstall as in the go-live plan P7. After an accepted settlement the installer rebuilds the shadow database from L1 (`reconstruct --l1-follower`), so it starts at the accepted head.

Evidence: Drill FAIL for the deep reorg without the tool (the halt above). Tool: 4 unit tests. Live drill: **none yet**, it was still queued on the drill host at the time of writing. Shallow reorgs halt the same way (drill FAIL: `L2 head 7 cannot extend accepted settlement 5`). Rehearse this procedure before relying on it. Whether the settler user can read the follower's `native` directory comes from the units' `UMask=0022`, and has not been run on an installed host.

## 5. L1 finality stall

This is an L1 incident. Nothing on the L2 repairs it. `safe` continues; `finalized` waits.

Tell exchanges deposits will be credited late. Do not advise crediting on `safe`. Do not restart L2 followers: they catch up by themselves.

Evidence: Alert: 3 of 5 validators stopped, mainnet thresholds: `l1_finality_lag` WARN, then CRIT at 8 epochs, and back to 2 epochs after restart. With only 2 of 5 stopped, this private net kept finalizing for 25 minutes and no alert fired. Drill PASS (e2): settlement continued, finality resumed, no divergence from an L1 rebuild.

## 6. Follower status lost or stale

| Alert | Meaning |
|---|---|
| `l2_finality_status` WARN at 300 s, CRIT at 900 s | The follower stopped writing. The RPC keeps serving its last finality |
| `l2_finality_closed`, `l2_finality_status` state not `ok` | The status file is missing or invalid. The RPC answers `-32001` for `safe` and `finalized`, and `latest` still works |

Check the follower first. Do not restart it near an L1 gate.

**Follower exit 3, `node's finalized chain does not descend from the verified head`:** its single L1 RPC regressed, for example a node resynced or restored from older data (agent 86). It is not a verifier disagreement. Wait until that node shows the same finalized root as the other two, then restart the follower once (`sudo systemctl restart bloch-l2-mainnet-follower`). A second halt with the node caught up is a real incident: keep the state. The unit does not restart on exit 3 by design; do not change that. To avoid it, keep the follower's L1 node out of resyncs, or point the follower at another node first.

```
systemctl status bloch-l2-mainnet-follower --no-pager
```

```
ls -l /var/lib/bloch-l2-mainnet-follower/status.json
```

A follower restart re-verifies from Genesis-4: no new status for about an hour, so the age alert stays on during that time. Levels reopen by themselves when a valid status appears. Exit 3 on the follower is a verification halt: keep the data and escalate.

Evidence: Alert, real settled-rpc `18be911a…` with a frozen, deleted and restored status copy: WARN at 321 s, CRIT at 921 s, `l2_finality_closed` on deletion with `l2_rpc` still OK, reopened within 8 s of restoring. Drill PASS (e2): follower killed 6 times.

## 7. Status file size

`follower_status_size` WARN at 8 MiB, CRIT at 12 MiB. The settled RPC refuses a status file above 16 MiB. `finalized` then stops following new settlements, and the only sign is a log line. At about 475 bytes per settlement that is about 35,000 settlements.

There is no operator repair in this build. Upgrade to a build with the settlement log before the limit.

Evidence: Alert, synthetic padding on a real status with a real RPC: WARN at 9 MiB, CRIT at 15 and 17 MiB. At 17 MiB a new finalized settlement was not followed (`finalized` stayed 0). At 15 MiB with the same settlement it was (`finalized` 1).

## 8. DA fee key low or empty

Only with user transactions on. `da_balance` reads the key directly, WARN below 1 BLCH, CRIT below 0.1 BLCH. The worker's own `da-funding-low` appears only when it prepares a batch.

Fund the `da_funding_script_hash` printed by `prepare`, in two outputs. See `SETTLER-RUNBOOK.md`.

Evidence: Alert: `da_balance` CRIT at mainnet thresholds on a really underfunded key (5000 sat), WARN with a raised threshold. **A falling balance, the worker event and an empty key were not rehearsed:** those need proofs. Plain spends sent from the key on the private net were accepted by the RPC and then did not land, for a reason not established.

### DA fee key lost

The keystore or its passphrase is gone, or the key is suspected compromised. Batches with user transactions stop at the next DA signature. Its balance is lost; the protocol does not pin the DA key, so a new one works at once. Paths are the installer's; `REL` is the release directory with the pinned `bloch-pos`. As root:

```
systemctl stop bloch-l2-mainnet-settler
mv /var/lib/bloch-l2-mainnet-da /var/lib/bloch-l2-mainnet-da.lost-$(date +%s)
mv /var/lib/bloch-l2-mainnet-settler/da.passphrase /var/lib/bloch-l2-mainnet-settler/da.passphrase.lost-$(date +%s)
install -d -m 0700 -o bloch-l2-mainnet-settler -g bloch-l2-mainnet-settler /var/lib/bloch-l2-mainnet-da
(umask 377; openssl rand -hex 48 > /var/lib/bloch-l2-mainnet-settler/da.passphrase)
chown bloch-l2-mainnet-settler: /var/lib/bloch-l2-mainnet-settler/da.passphrase
sudo -u bloch-l2-mainnet-settler env BLOCH_KEYSTORE_PASSPHRASE_FILE=/var/lib/bloch-l2-mainnet-settler/da.passphrase REL/bloch-pos keygen --dir /var/lib/bloch-l2-mainnet-da --index 0
sudo -u bloch-l2-mainnet-settler REL/bloch-pos keygen-public --dir /var/lib/bloch-l2-mainnet-da | cut -f2 > /etc/bloch-l2-mainnet-settler/public/da.pubkey.hex
python3 -c "import hashlib; print(hashlib.sha3_256(bytes.fromhex(open('/etc/bloch-l2-mainnet-settler/public/da.pubkey.hex').read().strip())).hexdigest())"
```

The last line prints the new `da_funding_script_hash`. Fund it in two outputs, back up the new keystore and passphrase separately, then `systemctl start bloch-l2-mainnet-settler`. The config needs no change: it names the same paths.

Evidence: Drill on a private net: keystore moved away, new throwaway key, one transfer to its script hash included in 6 s, settler restarted with no config change; the next user-transaction block (3 transactions) paid its DA fee from the new key, one fee of 2196 sat, and settled. The old key kept its balance, out of reach. On mainnet the keygen and the funding transfer are owner steps; the commands above were not run on a mainnet host.

## 9. Disk

`disk[*]` WARN below 15% or 20 GiB free, CRIT below 5% or 5 GiB. Point it at each role's state filesystem.

Free space on the filesystem. Never delete from `work/`, the database or the spool to do so. The settler retries while full and resumes; the RPC refuses new transactions with `txpool write failed` and stays up.

Evidence: Alert on a real small tmpfs: OK empty, WARN at 56 of 64 MB, CRIT at 62 of 64 MB. Drill PASS: real ENOSPC on the spool (clean refusals, later transactions included), and on the settler workdir with atomic writes (retried, settled with no repair). A settler before 5352c61 halts permanently here (FAIL); the v2.1 `settler_v3.py` has the fix.

## 10. RPC backend down

`l2_rpc[X]` CRIT `unreachable or malformed` means no answer. The gateway fails over by itself. Reads continue from the other backend, which lags by design. Sends answer `-32053` with `submitted: false` while the sequencer is down.

```
sudo systemctl restart bloch-l2-mainnet-rpc
```

An RPC restart takes seconds, and acknowledged spool entries survive it.

Evidence: Drill PASS: 0 bad reads of 199 during failover. PASS: RPC SIGKILL with 8 entries in the spool, 12 of 12 transactions included. Clock steps: a forward step on a pre-9b8aaef RPC evicted acknowledged transactions (FAIL); fix in v2.1, live retest: not finished. Keep NTP on, and alert on clock steps separately.

## 11. Attestor halt or silence

`unit[attestor]` CRIT `exit 3` or `events[attestor]` `halt`: a pin or identity mismatch. No restart, on purpose. A halted attestor signs nothing; 3 of 5 still sign.

The operator reads the reason and compares binaries against the published pins. Do not edit the pins in `config.json` to match the file. Follow `attestor/README.md`.

```
journalctl -u bloch-l2-attestor -o cat --no-pager -n 20
```

**The owner's monitor does not see an operator's host.** Each operator runs the monitor with `--unit`. From outside, the only sign is `attestors`: missing partials per round, WARN below 5 of 5, CRIT below 3 of 5, and only after a large withdrawal exists.

Evidence: Alert, real agent under the real unit in a container with its own systemd, follower pin set wrong: exit 3, `failed/failed`, no restart after 70 s, `unit[attestor]` and `events[attestor]` CRIT. Same on a private net through `--event-log`. No key was involved.

## 12. Replica

| Sign | Meaning | Action |
|---|---|---|
| Follower exit 3 | A block or activation does not verify | Keep data, escalate. Compare with another follower |
| Refresh exit 3 | The rebuild contradicts a published block | The current database stays in place. Escalate |
| `ExecStartPre` fails, `activating/auto-restart` | The release does not match its `SHA256SUMS` | Reinstall the release. It loops every 10 s until fixed |
| `bpf-firewall ... failed` in the journal | The unit started **without** its IP allow-list | Fix the host or container. Nothing else reports this |

After `upgrade` or `rollback`, restart only what the script prints. Restarting the follower costs about an hour.

Evidence: run in a container with its own systemd against L1 mainnet (read-only): replay 78 min, RSS peak 625 MB, 0 restarts. The refresh published, the path unit started the RPC, `replica_check.py verify` passed 16/16, upgrade to `18be911a…`, rollback and upgrade again each passed verify, and a tampered `SHA256SUMS` stopped the RPC with `unit[rpc]` CRIT. The IP allow-list held only with BPF capabilities. Mainnet has no settlement, so only an empty L2 was published.

## 13. Lost host or lost state

What to keep, what is rebuilt, and how long it takes. Measured 2026-11-02 in agents/106-recovery.md; see each row's evidence.

### Back up these, and only these

| Item | Path | Why |
|---|---|---|
| DA fee keystore | `/var/lib/bloch-l2-mainnet-da/validator.key` | Holds the DA fee money. `LOCK` is not needed |
| DA passphrase | `/var/lib/bloch-l2-mainnet-settler/da.passphrase` | Without it the keystore does not open. Store apart from the keystore |
| Settler config and release | `/etc/bloch-l2-mainnet-settler/config.json`, the signed release directory | Reinstall |
| SSH identity to the remote prover | `/var/lib/bloch-l2-mainnet-settler/ssh/id_ed25519` | Or make a new one and authorize it on the prover |

**Never back up, and never restore, the settler's L2 database or its `work/` directory.** Both are rebuilt from L1. An old copy is worse than none: see "Settler state restored from an old backup" below.

### Recovery table

| Failure | Time to recover | Data needed | Who acts |
|---|---|---|---|
| Settler L2 database lost or restored from an old backup | Seconds to rebuild from L1 (0.16 s for 3 blocks on a private net), plus the next proof | Follower state on the same host; the newer `work/` if it survived | Settler operator |
| Settler `work/` lost, database intact | One proof: the next cycle re-exports the unsettled block from the database and proves it again (Code, not rehearsed) | Nothing | Unaided |
| Settler host lost | Follower rebuild (about 75 min) + install + one proof | Backup list above | Settler operator; owner funds a new DA key if the old one is lost |
| Follower state lost | Full re-verification from Genesis-4: 57 min to the e6596 copy with the pinned `c18752fd…` (173,967 blocks, 3.1 GB of state, 516 MB RSS); about 75 min for today's chain. `safe` and `finalized` stay closed meanwhile | An L1 RPC that serves full history | Operator of that host |
| Settled RPC view (`rpc-view`) lost | Under 1 s on a 3-block L2: it is rebuilt from the database at start | The database | Unaided after restart |
| Prover host lost | Install on a new host + one proof (11 to 28 min, entry 2). Nothing is paid meanwhile | Signed prover release; SSH identity | Settler operator |
| DA fee keystore or passphrase lost | Minutes: new key, one transfer to fund it (included in 6 s on the private net), restart; see entry 8 | Funds for the new key. The old key's balance is lost | Owner (funds), settler operator |
| DA keystore and passphrase restored from backup | Milliseconds; the restored key signs | `validator.key` and the passphrase file. `LOCK` is not needed | Key holder |

### Settler state restored from an old backup

Restoring the database (and `work/`) from a backup older than the accepted settlement does not double-pay and does not fork the settled chain. The worker halts with `L2 head N cannot extend accepted settlement M`, N below M, and pays nothing. It cannot spend a DA input twice either: inputs come from the L1 UTXO set at signing time, and a signed batch is reused only while its inputs are unspent. L1 accepts only settlements that extend the accepted one, so an old state cannot replace a settled block. A restored settler started while the old host still runs is the two-settler case of entry 4 (`another settler?`).

The repair tool does not cover this case: `l2_reorg_recover.py` refuses with `database head N is not ahead of accepted M: nothing to recover`. Rebuild by hand, with the settler and the RPC stopped. `RULE` is `timestamp_rule` from the config:

```
sudo systemctl stop bloch-l2-mainnet-settler bloch-l2-mainnet-rpc
```

```
sudo -u bloch-l2-mainnet-settler REL/bloch-l2-produce-dev reconstruct --target /var/lib/bloch-l2-mainnet-settler/canonical.rebuilt --l1-follower /var/lib/bloch-l2-mainnet-follower/native --timestamp-rule RULE --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

These are the arguments the worker itself passes (`MAINNET_PRODUCE_ARGS` in `settler_v3.py`). Check that the printed `head` is the accepted L2 hash (`getl2settlement` on the native RPC); if not, stop and escalate. Then swap, keeping the restored copy:

```
sudo mv /var/lib/bloch-l2-mainnet-settler/canonical /var/lib/bloch-l2-mainnet-settler/canonical.restored
sudo mv /var/lib/bloch-l2-mainnet-settler/canonical.rebuilt /var/lib/bloch-l2-mainnet-settler/canonical
sudo systemctl start bloch-l2-mainnet-rpc bloch-l2-mainnet-settler
```

Proposed for the next build: let `l2_reorg_recover.py` handle a database behind the accepted head (rebuild, no orphans) instead of refusing. It is pinned (`678482bf…`), so this branch does not change it.

**User transactions of the unsettled block are dropped.** If, before the restore, a block above the accepted number had been built and its DA batch published, the restored worker rebuilds that number from the current spool, which no longer holds those transactions: they vanish from `latest`, and the DA fee already paid for them is lost. On the private net the restored worker rebuilt block 4 empty, with another hash, while L1 held the DA record of the first block 4 (3 transactions, 2196 sat). To return them, keep the pre-restore `work/` (here `OLD_WORK`) and, before starting the settler, re-spool the transactions of its blocks above the accepted number `M`:

```
sudo -u bloch-l2-mainnet-settler python3 -c "import sys; from pathlib import Path; sys.path.insert(0, 'REL'); import l2_reorg_recover as t; print(t.respool(t.orphaned_dirs(Path('OLD_WORK'), M), '/var/lib/bloch-l2-mainnet-settler/txpool'))"
```

It prints the spool files it wrote. If that `work/` is gone too, the batch exists only in the L1 DA transaction.

**A backup whose head equals the accepted number does not halt.** The worker then rebuilds the next block from the spool with no warning: the transactions of a block already published are dropped the same way, and if the spool holds others, a second DA fee is paid for the same L2 number (a different commitment, so consensus accepts both). This follows from the code (`prepare_block`, `publish_da`); the drill ran the halting case. So: before starting a settler on any restored or copied state, compare `produce head` with the accepted number, and rebuild from L1 as above unless they are equal and no newer `work/` directory exists.

Evidence: Drill on a private net, real Groth16, settled-rpc `18be911a…`, settler `3ddb260a…`: backup at accepted 1 (head 2), live run to accepted 3 with block 4's DA included and its settlement held, then restore. Halt at once, DA spend unchanged (2196 sat, one fee), no settlement sent. Tool exit 3 as quoted. Manual rebuild head equal to the accepted hash. Worker resumed and rebuilt block 4 empty.
