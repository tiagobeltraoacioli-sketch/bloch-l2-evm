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

**Run one settler.** Nothing on L1 gives it exclusivity, so see "Foreign settlements" below for what
happens when anyone else settles a block.

## 0. Release directory (on the operator host)

Put these in `DIR`. `prepare` checks each pin and refuses a mismatch.

| File | Source | SHA-256 |
| --- | --- | --- |
| `settler_v3.py` | this branch, `deployment/devnet/` | the `PINS` value in `install-settler-mainnet.py` of this tree (fork candidate: it moves with every settler change; enforced since agent 155; also recorded in the `/opt` path) |
| `sequencer_policy_v2.py` | this branch, `deployment/devnet/` | the `PINS` value in `install-settler-mainnet.py` (enforced) |
| `bloch-evm-sp1-settlement-v3` | `build-program.sh` host step with `sparse-witness` (serves `--mainnet-v1`, `--mainnet` and `--mainnet --sparse`) | **not pinned yet (fork candidate)**: `prepare` refuses every host until the December release build is pinned; the launch host `3a24c36d…973a` does not serve the next rules. Its `--mainnet-v1 identity` must equal the native program pins |
| `bloch-l2-produce-dev` | fork candidate v2 `out/` (agent 143, native f12b4113, reproduced on two hosts): `425d4fe8…`; it moves with the final December build | `425d4fe8…4cc78` (enforced) |
| `settlement_v3_mainnet` | reproducible guest | `203114bf…c473` (enforced) |
| `bloch-pos` | armed mainnet release 78d4921c (canonical container) | `700631b0…794e` (enforced) |
| `mainnet.manifest` | `bloch-sis-pow genesis/mainnet.manifest` | `7eef82a7…b2dd` (enforced) |
| `l2_reorg_recover.py` | `deployment/mainnet/l2_reorg_recover.py` | `2a648b31…9a53` (enforced) |
| `settlement_v3_mainnet_sparse` | sparse-witness guest (CANDIDATE, the program swap's `PROGRAM_NEXT`) | `78c533fa…7bea` (enforced) |
| `settlement_v3_mainnet_fallback` | complete-witness guest under the next rules with forced inclusion (CANDIDATE, the rollback's `PROGRAM_FALLBACK`; pinned container build of `guest-fallback`, agent 216) | `7fd7f3c0…5303` (enforced) |

**Program swap (fork candidate, native `L2_NEXT_PROGRAM_EPOCH` inert).** The host of this kit serves both programs: `--mainnet-v1` proves the activated program and `--mainnet --sparse` the next one, so `configure` writes `prover_args: ["--mainnet-v1"]` and a `next_program` with the sparse guest and `l2-config.next.bin`. Until L1 reports the next program the worker passes `--rule-set base` and nothing else changes. With `--remote-prover`, `configure` also makes a second key, `ssh/id_ed25519_next`, for the next program's forced command (`install-prover-mainnet.py install --program next`). `configure` also writes a `fallback_program` (the complete-witness guest `settlement_v3_mainnet_fallback` `7fd7f3c0…`, pinned to `MAINNET_FALLBACK` = `MAINNET_NEXT`, `--mainnet`, `l2-config.fallback.bin`), which only matters if L1 installs native `PROGRAM_FALLBACK` at the inert rollback gate; with `--remote-prover` it gets a third key, `ssh/id_ed25519_fallback` (`install-prover-mainnet.py install --program fallback`).

**Shadow across the gate (agent 218).** `install-shadow.sh` writes `next_elf_keccak` (the sparse `PROGRAM_NEXT`) and `fallback_elf_keccak` (the complete `PROGRAM_FALLBACK`) and copies this worker's `program_switch_lead_seconds` into the shadow config (`install-shadow.sh --print-config` shows it without changing anything). The shadow then accepts a block built under the next rules ahead of the gate when L1's `program_schedule` names that gate inside the window, waits (`shadow-rules-wait`, WARN) on a block the worker is about to rebuild, re-verifies a block the worker rebuilt at the swap (`shadow-reverify`), and keeps the same block at a rollback. Any other rule set halts it (exit 3).

## 1. Prepare (local only)

```
sudo python3 install-settler-mainnet.py prepare --release DIR
```

This creates the user `bloch-l2-mainnet-settler`, the read group `bloch-l2-mainnet-l2read`, the directories and the
pinned `l2-config.bin`. It also generates a **new DA fee key**:

- a sealed hybrid keystore in `/var/lib/bloch-l2-mainnet-da` (0700, owned by the settler);
- a random passphrase in `/etc/bloch-l2-mainnet-settler/da.passphrase` (`root:root` 0400), never printed. The settler
  user cannot read, change or delete it. At every start the unit copies it into its private runtime directory
  `/run/bloch-l2-mainnet-settler/da.passphrase` (0700 directory, 0400 file of the settler, removed when the unit
  stops), and `da.passphrase_file` points there (review r10 M-4). Not `LoadCredential`: systemd 255 hands a
  credential to a `User=` service as mode 0440, and `bloch-pos` refuses any passphrase file with a group or other bit
  (agents/204-installers-systemd.md).

State layout (review r10 decision 4): `/var/lib/bloch-l2-mainnet-settler` is `settler:bloch-l2-mainnet-l2read` 2710,
`work` 2750, `txpool` 2770, `tmp` 2700 (setgid, so what the worker writes with its `UMask=0027` belongs to the read
group), `ssh` 0700. The settled RPC (`bloch-l2-mainnet-rpc`) and the shadow (`bloch-l2-mainnet-shadow`) run as their
own users in the read group: they read the canonical database and the work directory, and nothing else of the
settler (not its DA key, passphrase, SSH key or the Docker socket).

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
sudo python3 install-settler-mainnet.py configure --rpc-urls http://80.240.16.185:8080,http://199.247.22.8:8080,THIRD_L1_RPC_URL --prover-threads 6
```

`THIRD_L1_RPC_URL` is the third L1 RPC the owner chose (go-live plan L1-8); replace it with its
`http://HOST:8080` URL. The installer compiles in no L1 host. It takes the URLs from `--rpc-urls`
(or `L1_RPC_URLS` in the environment of the `python3` process, `sudo L1_RPC_URLS=... python3 ...`)
and refuses, before any check: no URL, fewer than three, a repeated host, a URL that is not
`http(s)://HOST:PORT`, and a placeholder (`TBD-owner`, `THIRD_L1_RPC_URL`, `<...>`).

This writes `/etc/bloch-l2-mainnet-settler/config.json`:

- RPCs: the `--rpc-urls` list, quorum a strict majority (2 of 3);
- acceptance timeout 1800 s, rebroadcast every 300 s, polling every 15 s; every broadcast goes to all
  three RPCs (review r10 M2);
- user transactions **off**;
- foreign settlement recovery **on** (owner decision D17, 2026-11-02), reading the local follower
  `/var/lib/bloch-l2-mainnet-follower/native` and `status.json`. `configure` first checks, as the settler
  user, that both are readable, so start the follower first. `--follower-state DIR --follower-status FILE`
  names other paths; `--no-foreign-recovery` turns it off (a foreign settlement then halts the worker).

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

This build does not reuse a DA batch it finds on L1 (agents/145 F1: L1 does not show who paid for a
batch). So a settler database restored at the accepted head builds the next block again from the spool and
may pay one more DA fee (about 2,200 sat), and the transactions of that unsettled block come back only if you
re-spool them from the pre-restore `work/` (`l2_reorg_recover.py --respool-from OLD_WORK`, or the entry-13
one-liner of `docs/L2-OPERATOR-RUNBOOK.md`). A database behind the accepted head halts the worker; repair it
with `l2_reorg_recover.py` and `--respool-from`. Never back up or restore `canonical/` or `work/`.

Then edit `user_transactions: true` in `config.json` and run
`systemctl restart bloch-l2-mainnet-settler`. The worker refuses this if the live profile does
not admit user transactions.

## 5. Rollback

```
sudo python3 install-settler-mainnet.py rollback
```

This stops and disables the unit and removes the unit file. It keeps the L2 database, the work
directory, the keystore, the passphrase and the config.

Stopping the unit (rollback, `systemctl stop` or `restart`) during a proof is safe since review r10 M1: the
unit sends SIGTERM to the worker only (`KillMode=mixed`), the worker kills its prover group, removes the SP1
segments it mapped and kills its Gnark container, then exits by the signal; systemd then kills anything left
(`TimeoutStopSec=120`). `RemoveIPC=yes` removes any POSIX shared memory of the settler user when the unit stops,
so do not run `dry-run --prove` while stopping the unit. systemd does this only when no other unit of the same user
runs: the RPC and the shadow run as their own users (decision 4) for this reason too; measured under systemd in
agents/204-installers-systemd.md. To confirm after a stop (no output expected):

```
ls -l /dev/shm | grep bloch-l2-mainnet-settler
```

An accepted L1 settlement cannot be undone. The L2 simply stops advancing until a settler runs
again. Restart with `start --confirm-mainnet` (the unit file is recreated). The worker resumes
from the accepted head; it reuses a block left by a crash if its anchor is unchanged.

## 6. Upgrade the worker (review r10 M-3)

A new worker release (a new `settler_v3.py`, producer, SP1 host or `bloch-pos`) comes with a new installer whose
`PINS` name it. Stage the release directory as in section 0, then, with the new installer:

```
sudo python3 install-settler-mainnet.py upgrade --release DIR --confirm-mainnet
```

It copies the files into `/opt/bloch/l2-mainnet-settler/<new digest>` beside the running release and checks every
pin on the copies, writes a pending config with only the release fields changed (`produce`, `prover`,
`prover_sha256`, `guest`, `guest_sha256`, `da.signer`, `da.signer_sha256`, `da.genesis`), stops the unit, runs
`--check-rpc` and the dry run of the new release on that pending config, and only then keeps the old config as
`config.json.<old digest>`, switches `config.json` and the unit's `ExecStart`, records `upgrade.json` and starts the
unit again (if it was running). Any failed check leaves the old release, config and unit as they were, removes the
new copy and starts the old worker again. To go back:

```
sudo python3 install-settler-mainnet.py upgrade --rollback --confirm-mainnet
```

The rollback re-hashes the kept release against its kept config before switching. Both commands ran under a real
systemd 255 (agents/204-installers-systemd.md); the success path there replaced the dry run with a no-op, because
the private stub has no native source to build a block from.

## Operations

| Log event | Meaning / action |
| --- | --- |
| `submitted-duplicate` | The node already holds or recently included these bytes. The worker keeps waiting. |
| `submitted` / `submitted-duplicate` `ports` | The endpoints that hold the bytes. Every broadcast goes to all three RPCs (review r10 M2); `accepted` or `duplicate` from any of them counts. |
| `submit-partial` | Some RPCs refused or failed while others hold the bytes. Look at the named endpoint if it repeats. |
| `acceptance-timeout` (`held_by` set, L1 advancing) + `settlement-not-included` | RPCs hold the settlement but no block includes it: an endpoint on a fork or partition, or proposers refusing it. After `max_unincluded_windows` windows in a row (default 4, 2 h on mainnet) the worker halts. |
| `stopped` | The worker ended on a signal (`systemctl stop`/`restart`) after cleaning up its prover: the process group is killed, its SP1 segments are removed from `/dev/shm`, and its Gnark container is killed (review r10 M1). |
| `prover-shm-removed`, `prover-container-killed` | Cleanup after a prover timeout, failure or stop. `prover-container-check-failed`: Docker did not answer; check `docker ps` for a left-over `sp1-gnark` container. |
| `submit-refused` kind `retry` | Another proof is pending, the mempool is full, or a retryable bar. The worker rebroadcasts the **same bytes**. |
| `acceptance-timeout` + `l1-not-advancing` | The L1 is stalled (the devnet4 block-231 case). Nothing to fix in the settler: the next cycle reuses the same proof and bytes. |
| `rpc-no-quorum` / `rpc-endpoint-diverged` | The RPCs disagree. The worker waits and never uses a minority answer. |
| `rpc-quorum-view-behind` | Two RPCs agree on an accepted L2 number below one this process already saw (two stale endpoints, or a real L1 reorg while the third endpoint is down). The worker waits. |
| `rpc-quorum-behind-floor` then `retry` and exit 1 | The same behind-floor answer has lasted `quorum_floor_stall_seconds` (default 1200 s; review r10 L1). The worker exits 1 after `max_consecutive_failures` retries and systemd restarts it, which resets the in-memory floor. If L1 really reorged, the restarted worker resubmits its block at the accepted number + 1 when the anchor is unchanged, or halts with its own reason (then use `l2_reorg_recover.py`). If two endpoints are stale, fix them: after the restart the worker halts on a database or anchor check, or after `max_unincluded_windows` of `settlement-not-included`. With `reorg_recovery` on, a behind-floor view goes to the reorg gates instead (see "Automatic reorg recovery") and this restart is not used. |
| `reorg-detected`, `reorg-resubmitting`, `reorg-resubmit-expired`, `reorg-resubmit-refused`, `reorg-waiting-finality`, `reorg-waiting-follower`, `reorg-recovered`, `reorg-restored`, `reorg-resolved` | An L1 reorg removed an own accepted settlement while the next block was built (`reorg_recovery` on). See "Automatic reorg recovery". Each one is an alert; review the reorg on L1. |
| `reorg-behind-floor-waiting` | A partial quorum shows an accepted settlement below the highest one seen, and the database does not hold unsettled blocks above it: the worker waits, as without `reorg_recovery`. |
| `reorg-limit` (then `halt`) | Too many automatic recoveries in the window: run `l2_reorg_recover.py` and find out why L1 keeps reorging. |
| `prover-failed` `timeout: true` | A prover attempt ran out of time (exit 124 recorded). The next location in `remote_prover.order` is tried (review r10 L6). |
| `da-funding-low` | Top up the DA fee key. |
| `foreign-settlement-waiting-finality`, `foreign-settlement-recovered` | Another party settled a block. See "Foreign settlements". No action unless they repeat. |
| `halt` (exit 3, no auto-restart) | Operator review. Causes: a settlement held by the RPCs but not included for `max_unincluded_windows` windows, a foreign statement accepted for the same block without `foreign_recovery`, a foreign block that cannot be rebuilt from L1 (off-rule, finding F1), a terminal native refusal with an unchanged request, pin or identity mismatch, or producer or DB divergence. |

## Idle blocks

Off by default. `configure --skip-idle-blocks [--max-idle-seconds 86400] [--min-block-interval 0]` sets `skip_idle_blocks`, `max_idle_seconds` and `min_block_interval_seconds`. The height then grows with demand, which matters because each block raises the cost of every later block and the export stops at block 4097 on v2.1.

No consensus rule changes. L1 accepts the next L2 block at any time, against the source it froze right after the last acceptance.

A block is due when L1 holds an unconsumed deposit, the spool holds a transaction at its sender's next nonce, or the source is `max_idle_seconds` old. The last one proves prover, proof and submission while no demand does, and sets how late a broken prover is found.

**What changes for users and operators:**

- **A deposit made while idle takes two blocks and two proofs.** The frozen source does not list it, so the first block carries nothing and only the next can mint it.
- **L2 time stands still while idle.** `latest` shows the last block's time, and the next block carries the time of the old source, up to `max_idle_seconds` behind. Its transactions would run at that time, so a block on a source older than 600 s above the pacing is built without the spool, and the transactions go in the next one. This also costs a block.
- **Pacing.** `min_block_interval_seconds` delays a due block, measured from the last acceptance. It is the only limit on a depositor forcing blocks. A deposit may then wait two intervals plus two proofs.
- **Only an entry the next block may take forces a block.** A spooled transaction is demand when its nonce is its sender's next nonce at the head (the producer's `account`). A nonce gap, which the RPC admits up to 16 ahead and keeps 3 h, is not. Bytes that do not read as a transaction, and a sender whose nonce cannot be read, still count (`spool-demand-unknown` in the log); the producer prunes the first at the next block. Fees are not checked here, because the RPC admits only entries that cover the next base fee and the tip floor. The first check after a restart reads every entry's sender, about 10 ms each (40 s for a full 4,096-entry spool); later checks read only new files. Set pacing before user transactions are on.

**Set with the option, or they raise false alerts:**

| Where | Setting |
|---|---|
| `l2_monitor.py` | `--max-idle-seconds N --backlog-state FILE`. Adds `deposit_wait`. `--set deposit_wait_warn=...` if pacing is on |
| Guardian | `l2_stall_alert_s` above N, on bridge deployments |
| DEX UI | The "L2 finality looks stalled" notice appears once the finalized block is older than `FINALIZED_AGE_WARN_SECONDS`, also on a healthy idle chain |

Follower, settled RPC, attestors and claims do not depend on block cadence.

## Foreign settlements

Settling needs no authorization. A deposit-only block built by the rules is identical whoever builds
it, so only a block with other user transactions, and its own paid DA batch, differs from ours.

Even a deposit-only block can differ, or arrive first: a third party may settle the identical block
while this worker holds (D15 pacing) or proves, or use another anchor. Without `foreign_recovery`, such
a block halts the worker (exit 3); agent 152 (M4) showed anyone who can prove can do that at proving cost.
So `foreign_recovery` is **on at launch** (owner decision D17, 2026-11-02): `configure` sets it by default
(`--follower-state DIR --follower-status FILE` for other paths, `--no-foreign-recovery` to opt out). With it, the worker:

1. stops working on its own block, and pays no DA for a block that went stale during the proof;
2. waits until the native follower has finalized the accepted settlement. The rehearsal measured about
   2.5 epochs of lag, which is about 40 min at 960 s epochs. A running proof must return first;
3. rebuilds a new database from verified L1 blocks and requires its head to be the accepted hash;
4. returns the user transactions of its orphaned blocks to the spool;
5. moves the orphaned work directories aside, swaps the databases and continues. It keeps the last 2
   old databases and work directories (`foreign_recovery.keep`).

The follower's state directory and status file must be outside `/home` and readable by the settler
user. A rebuild that L1 cannot reproduce still halts: that is an off-rule block (finding F1) or local
damage, and it needs an operator.

**The settled RPC must restart after a swap**, because it keeps the old database open. Until then it
serves the orphaned head as `latest`. The worker rewrites `/var/lib/bloch-l2-mainnet-settler/l2-db-generation.json`
at each swap. The worker's unit has `NoNewPrivileges`, so it cannot restart anything itself.
`follower-rpc/bloch-l2-mainnet-rpc-restart.path` watches the file and restarts the RPC service: install.sh
installs it, and turning `foreign_recovery` on needs `sudo systemctl enable --now bloch-l2-mainnet-rpc-restart.path`.
`foreign-settlement-recovered` reports the block, the orphans, `wasted_proofs` and `wasted_da_signed`.

A tip that keeps moving does not hold recovery back: when the database has left the finalized prefix, the worker rebuilds
from everything the follower verified, which holds the prefix and any settled blocks above it, and competes from that head.
A database already on the prefix just waits, and a rebuild that did not hold the target is not repeated until the follower has
verified more. Griefing stays a liveness cost: the worker can still lose every race.

Repeated events are an attack on liveness, not on funds. `l2_monitor.py` counts recovered and waited-on settlements over
24 h from `--unit` or `--event-log`: `foreign_settlements` is WARN at one and CRIT above one per day. Meanwhile `safe` is
closed on this RPC and `finalized` stands.

## L2 reorg recovery

If an L1 reorg removed an accepted, unfinalized settlement, the settler halts (exit 3) because its database is ahead of what L1 can accept. Stop the settler and every settled RPC on that database, then run the plan, which changes nothing:

```
sudo systemctl stop bloch-l2-mainnet-settler bloch-l2-mainnet-rpc
```

`prepare` installs the tool next to the worker. `REL` is that release directory, `/opt/bloch/l2-mainnet-settler/<digest>`. Run it as the settler user, so the new database keeps the right owner:

```
sudo -u bloch-l2-mainnet-settler python3 REL/l2_reorg_recover.py --config /etc/bloch-l2-mainnet-settler/config.json --follower-state /var/lib/bloch-l2-mainnet-follower/native --follower-status /var/lib/bloch-l2-mainnet-follower/status.json
```

`--follower-status` is required: the tool does not read it from the config. `prepare` refuses any file but the pinned tool `2a648b31…`. Its stdout is exactly one JSON document; worker log lines go to stderr. An install prepared before this tool shipped does not have it in `REL`: copy `deployment/mainnet/l2_reorg_recover.py` there first.

Exit 75 means the accepted settlement is not finalized yet: run it again later. Exit 3 means refused. When the plan is right, run the same command with `--apply`. It rebuilds a new database from L1, returns the user transactions of orphaned blocks to the spool (and, with `--respool-from OLD_WORK`, those of the pre-restore `work/` above the accepted number; never batches read from L1), and keeps the old database for review.

Since the round-10 kit (agent 152 L2-L4, fixed by agent 198):

- Orphaned blocks are every local block off the accepted chain, found from the common ancestor (the rebuild's blocks, then the follower's finalized settlements); a database that was replaced at the accepted number (`forked`) or left the chain below its head (`ahead` after a deeper reorg) also respools those blocks. The report names `common_ancestor` (with `common_ancestor_assumed` when no canonical hash was known below it).
- The rebuild gets `--rebuild-timeout SECONDS` (default `foreign_recovery.rebuild_timeout_seconds`, else 3600), not the 300 s of other producer commands. A rebuild that runs out of time is refused cleanly (exit 3); run again with a larger value.
- The swap is journalled in `<l2_db>.recovery.json`, in the worker's format. If `--apply` is interrupted between its renames, the next `--apply` finishes it (a run without `--apply` refuses and says so), and so does the worker at its next start.

### Automatic reorg recovery (`reorg_recovery`, off by default)

The worker can do the tool's work itself for exactly this case: its database holds the accepted settlement M and
unsettled blocks above it (`L2 head N cannot extend accepted settlement M`, or `unsettled L2 block M+1 has anchor …`).
It stays off in the launch kit. Turn it on at configure time with `--reorg-recovery` (it reads the follower of D17's
`foreign_recovery` and is refused with `--no-foreign-recovery`), and enable
the RPC restart path unit as for `foreign_recovery`. The worker then:

1. alerts `reorg-detected`. The case is also seen when only two of the three endpoints show it (one endpoint down
   or still on the losing fork): such a partial view below the highest accepted settlement seen never builds,
   proves or pays DA, it only reaches the gates below;
2. when the native request of M+1 is unchanged (the reorg removed the acceptance of M+1 but kept the block that
   accepted M), its own proved settlement of M+1 is still valid: it rebroadcasts those bytes every
   `resubmit_seconds` (`reorg-resubmitting`; the DA batch first if its record is gone, on a full-quorum view only)
   for `resubmit_window_seconds` (default 1800) before any rebuild may start. When they land, the worker goes on
   from M+1 with no rebuild and no new proof (`reorg-resolved`). A refusal of the bytes for good
   (`reorg-resubmit-refused`) or the end of the window (`reorg-resubmit-expired`) lets the steps below go on;
3. waits until the same accepted settlement and the same local head were seen for `stable_seconds` (default 120).
   If L1 flips back meanwhile, nothing is changed (`reorg-resolved`);
4. waits until the follower has finalized M **and** L1 `finalized_height` has passed the L1 height at which the
   reorg was first seen (`reorg-waiting-finality`; about 40 min on mainnet). Then neither M nor the removal of M+1
   can be undone by L1. `wait_for_finality: false` is refused on mainnet and in the mainnet rehearsal; on a devnet
   it skips this wait but still never rebuilds while L1 finality lags the head by more than `max_finality_lag`
   (default 256) blocks;
5. re-reads the view, which must still show the same case, then rebuilds a new database from verified L1 blocks.
   It must end exactly at M with the accepted hash; a follower still on the losing fork is waited for
   (`reorg-waiting-follower`);
6. records the recovery in the history, returns the orphaned user transactions to the spool, moves the orphaned work
   aside, swaps the databases (the path unit restarts the RPC) and continues (`reorg-recovered`, with the orphans,
   `wasted_proofs` and `wasted_da_signed`).

If the old settlement of M+1 still lands after the rebuild, the database kept aside (`<l2_db>.orphaned-*`) holds the
accepted block: the worker swaps it back with its work directories, through the same journal (`reorg-restored`),
instead of a second rebuild from L1. Restores are limited apart from rebuilds (`max_recoveries` each per window). When the old
settlement landed in a new L1 block, the kept block above it has a stale anchor and is dropped by one gated rebuild
(shape `anchor`): the same single reconstruct the foreign path would have cost, after the finality wait.

No DA batch is ever read from L1 (kit `4b7f4f7`): the next block is built from the spool, which holds the orphaned
transactions again, so a block whose DA batch was paid on the losing fork pays its DA once more on the winning chain
(the cost recorded in `wasted_da_signed`). More than `max_recoveries` (default 3) recoveries within `window_seconds` (default 6 h) halt
the worker (`reorg-limit`, exit 3): then use the tool above. The count is kept in `<l2_db>.reorg-recoveries.json`, so a
restart does not reset it; an unreadable or malformed history file halts the worker (exit 3) for the operator. A local block M that is not the accepted hash is a foreign settlement, never this case.

Each alert is a journal line, a JSON line in `/var/lib/bloch-l2-mainnet-settler/l2-reorg-alerts.jsonl`
(`reorg_recovery.alert_file`), and, when `reorg_recovery.alert_command` is set, that command with the alert on its
standard input (30 s limit; a failing hook never stops the worker). `l2_monitor.py` grades `reorg_recoveries`: WARN at
each recovery or waiting alert, CRIT at two in 24 h or at the limit.

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
