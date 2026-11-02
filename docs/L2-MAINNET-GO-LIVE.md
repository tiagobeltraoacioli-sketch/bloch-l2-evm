# Bloch L2 mainnet (chain 700770): go-live plan for the next build (17383fe)

Status: **plan only, written 2026-11-02 for the next build.** Nothing in this document has been installed, started or broadcast. Every step that writes to a public chain is marked **MAINNET WRITE**, every publication **PUBLISH**, and every step that installs or starts something on a host is for the owner to run.

The v2.1 plan is kept as `docs/L2-MAINNET-GO-LIVE-V21.md`. Do not mix the two: the kit pins in this tree name the next build and refuse v2.1 artifacts.

**The build.** L2 build commit (`l2_commit`) `17383feb88602926c26559802b95dee273484cd5`, native 78d4921c, settlement-recovery lock `a3c38a46…`. Built reproducibly on three hosts (209 twice, 136, and independently 45.77 by agent 124). **Unsigned.** Release `bloch-l2-2026-11-02-next-native-78d4921c`, assembled independently on 209 and 136 with the same result; its `SHA256SUMS` is the signing target `116bfaba85cfc3e7db2589a97e2ac2ac76c9006b3091f6cd98a13732ebff4821` (D7). Source of every hash: `agents/PINS-NEXT.md`; if it disagrees with this file, it wins, and this file must be fixed.

**Kit tip moved after this plan was written:** see the newest change notice in `agents/PINS-NEXT.md` for the tip and the kit-file pins (F8 port, prover pins, release target in `GO-LIVE-PINS.sha256`). Binaries and the signing target `116bfaba…` did not move.

**Kit source.** `~/worktrees/go-live-next-r7-20261102`, branch `codex/go-live-next-r7-20261102`: kit tip `9645efc` (583d8ec plus agent 118's gateway commits 3de3a3e and 51cbda1) plus documentation only. Check before staging that no kit file differs from 9645efc:

```
git -C ~/worktrees/go-live-next-r7-20261102 diff --stat 9645efc -- deployment
```

GO: empty output. **Never build a release from 9645efc or from this branch**: its `build.json` would name another `l2_commit`. Binaries come only from the 17383fe build output.

**What this build changes from v2.1:**

- the export stop at L2 block 4097 is gone (8a77bf4); `MAX_L1_BLOCKS` is 5,000,000;
- `bloch_getWithdrawalProof` in the settled RPC, so the withdraw tool `deployment/mainnet/withdraw/bloch-l2-withdraw.py` works against our RPC (`fetch`);
- the clock-step and `.partial` fix (2782f5a, the same change as `9b8aaef`, so D14 of the v2.1 plan is done);
- `safe` follows an L1 reorg down and never below `finalized`; by-hash reads check the canonical hash;
- the follower can write status schema v3, but **defaults to v2** (unit `BLOCH_L2_STATUS_SCHEMA=v2`);
- `--min-tip-wei` (0.1 gwei by default) in the RPC and the producer;
- the settler's idle-block option (agent 92, 503757d; **not** 724bf4c, which wedges deposits), DA re-sign on a fee move and the database-behind-the-accepted-head recovery (agent 118, 738399f);
- `LimitNOFILE=65536` in the RPC unit.

The guest (`203114bf…`, the dense guest), the program identity, the proof policy and the activation do not change. The sparse witness guest (agents 81, 89) is **not** in this build.

Related documents:

- `deployment/mainnet/SETTLER-RUNBOOK.md`: settler worker and installer, idle blocks, foreign settlements, reorg recovery.
- `deployment/mainnet/follower-rpc/install.sh`: follower and settled-RPC units.
- `deployment/mainnet/attestor/README.md`: attestor kit.
- `deployment/mainnet/public-rpc/README.md`: the public RPC gateway.
- `deployment/mainnet/withdraw/README.md`: the withdraw tool.
- `docs/MAINNET-RPC-READINESS.md`: RPC limits and the status-schema rollout order.
- `docs/MAINNET-OPS-RUNBOOK.md`: the monitor and its thresholds.
- `docs/L2-OPERATOR-RUNBOOK.md`: what to do per failure.
- `docs/L1-STUCK-NODE-RUNBOOK.md`: stuck L1 nodes. At 9645efc its wipe step was wrong for mainnet (§6.1); the fix from `codex/recovery-r6-20261102` (28c2b5f, 7554681) is merged since kit tip 2087b40: refill from a healthy node.
- `docs/MAINNET-EXCHANGE-INTEGRATION.md`: exchange-facing behaviour.

## 0. Where things stand

Last read-only readings are in the v2.1 plan §0 (2026-10-30). Since then HF1 (e7180) and HF2 (e7270, 2026-11-02 about 16:11 UTC) were scheduled to activate; HF3 is e7360 (2026-11-03 16:11 UTC). Nothing in this plan relies on those readings: G0 re-reads everything. The L2 is activated (e5850, slot 187200) and has never been settled. No production L2 unit, user or directory exists on any host.

## 1. Owner decisions

Nothing here may be filled in by an operator or an agent. `TBD-OWNER` means the owner supplies the value.

| # | Decision | Recommendation | Blocks phase |
| --- | --- | --- | --- |
| **D1** | Go-live start epoch | Not before G0 holds. Earliest e7365 (2026-11-03 17:31 UTC). Recommended **e7450 (2026-11-04 16:11 UTC)**, after one day of clean finality after HF3. | all |
| **D2** | Prover host | 136.244.93.186, co-located with the settler, while user transactions are off. Before D10, a dedicated 32 vCPU / 128 GB prover (§2). | P5, D10 |
| **D3** | Follower B / replica RPC host | A small dedicated VPS (4 vCPU, 8 GB, 80 GB). 45.77.142.123 works but is the shared build host. | P3, P4, P11 |
| **D4** | L1 RPC each follower reads | A → 80.240.16.185, B → 199.247.22.8. | P3 |
| **D5** | Attestor operators: five people, five hosts, one index each, feed URLs | `TBD-OWNER`. No operator holds more than one key or shares a host with a validator, the settler or another attestor. | P10 |
| **D6** | Addresses | The L2 core needs none. Still `TBD-OWNER`: (a) the wallet that funds the DA key (only for D10); (b) the wallet and L2 recipient of the test deposit and withdrawal. | P12 |
| **D7** | Release signature | Sign release `SHA256SUMS` `116bfaba85cfc3e7db2589a97e2ac2ac76c9006b3091f6cd98a13732ebff4821` (`bloch-l2-2026-11-02-next-native-78d4921c`, in `~/l2dexbridge-20261030/next-rpc-r4/release/` on 209 and 136) with the owner's minisign key, after G0 gate 7 and before P2. | P2 |
| **D8** | Retire the 10-18 scratch follower/RPC on 45.77 | As in the v2.1 plan: check `ps -o pid,cmd -p 1452988,1304666` first, then `kill 1452988 1304666`. | none |
| **D9** | Public gateway | nginx + njs on A and B; do not deploy the Worker. Open: DNS timing and failover (manual switch to B by default). | P11 |
| **D10** | When to enable user transactions | **Not with this build while F5 is open** (K13): F5 fires only with idle blocks and user transactions together, so the deposit-only launch keeps `skip_idle_blocks` on and user transactions off, and user transactions stay off until F5 is fixed in a later build. Then only after: the P12 deposit test; R2 (DA after HF2) on a private net; the gas-heavy 15M measurement; the stuck-block rehearsal; a dedicated prover (D2); **and with `foreign_recovery` on** (D17). | P12 |
| **D11** | Alert destinations | **`TBD-OWNER`**: webhook URL (and bearer file), Telegram bot token file and chat id, or an `alert_command`; plus a `heartbeat_url` (dead-man service). Until set, alerts are not delivered and WARN `alert_delivery` is expected. | P9 |
| **D12** | DA signer `bloch-pos` | 78d4921c `700631b0…`, enforced by the installer. | P6 |
| **D13** | L2 finding F1 (timestamp and prevrandao not bound in the guest) | Do not delay block 1. Cap deposits and bridge value at what the owner accepts seeing frozen during an emergency fork. | P8, P12 |
| **D15** | **Idle blocks and pacing (deposit-only launch)** | `configure --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800` (agent 92): no block without demand, a heartbeat block at most every 24 h, at most one block per 30 min. Deposits then wait about 40–70 min to mint (two blocks after an idle stretch), longer as proofs slow with height. It is the only protection of the height against a depositor who forces blocks. `configure` runs once, so decide before P6. | P6, P9 |
| **D16** | Block interval for the monitor's `l2_proof_cost` | `--set block_interval_seconds=1800`, equal to D15's pacing: WARN when the slowest logged proof passes 70 % (1,260 s), CRIT at 100 % (1,800 s). Expect WARN around L2 block 4,000 and CRIT before 8,191 (agent 93: 1,417–1,563 s at 4097, 2,731–2,809 s at 8191). At that point raise the interval, or get faster proving (§2). | P9 |
| **D17** | Foreign settlement recovery | **Off at launch** (no `--follower-state`/`--follower-status` at P6, restart path unit not enabled). A deposit-only block is identical whoever builds it, so there is nothing to recover. Turn it on together with user transactions (P12 step 2), as agent 66 recommends. | P6, P12 |
| **D18** | Monitor thresholds under idle | `l2_head_age` went CRIT with `--max-idle-seconds` on agent 92's rehearsal (the head's time is its anchor, older than its acceptance by the proof time). Choose N + 45 min, or N + 45 min + proof time. `deposit_wait` defaults (45/90 min) are short with 30 min pacing: suggested `--set deposit_wait_warn=5400 --set deposit_wait_crit=10800` (my value, not measured). | P9 |
| **D19** | Weak-subjectivity checkpoint | Whether to publish one younger than 2,016 epochs. Without it, a broken mainnet L1 node recovers only by refill from a healthy node (§6.1). | §6 |

## 2. Host specification per role

The v2.1 plan §2 numbers for the follower (about 600 MB RSS, about one core, 55–80 min replay at about 198k L1 blocks), producer and unit caps still hold: no follower or producer execution rule changed (agent 124).

**Prover, from agent 93 (real proofs, 32 vCPU hosts, guest `203114bf…`):** empty-block cost grows with height up to block 8,191 (227.7M instructions; the EIP-4788 ring is then full and cost stops growing). With SP1 defaults block 8191 is OOM-killed at a 100 GiB cap. With `--threads 32` and `ELEMENT_THRESHOLD=268435456` it proved twice, in 2,731 s at 85.4 GiB and 2,809 s at 84.2 GiB. At 2048: 814–944 s at about 87–95 GiB (32 threads); at 4097: 1,563 s at 72.8 GiB with the threshold. The installer defaults are now `--memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400`; the settler's remote timeout is 5,700 s, above the prover's limit.

Without the 4097 stop, the limit at high heights is proof time, not a hard stop: about 46 min per block at 8191 on 32 vCPU. 12–15 min per block there needs about 64 physical cores / 128 threads and 256 GB (agent 93 estimate, not measured). With D15 the height grows with demand: agent 92's model gives months to years before block 4096 at a few deposits a day, and about 100 days under a griefer at 30 min pacing.

| Role | Host | vCPU | RAM | Disk | Notes |
| --- | --- | --- | --- | --- | --- |
| A: settler + prover + follower A + RPC A + shadow + monitor + nginx (user transactions off) | 136.244.93.186 | 32 | 125 GiB | ≥ 200 GB | The prover cap check of the v2.1 plan §2 applies unchanged: fine while blocks are empty or deposit-only. |
| Dedicated prover (before D10) | `TBD-OWNER` | 32 (16 physical cores) | 128 GB | ≥ 200 GB NVMe, Docker | 100 G slice + gnark 18.5 G outside it |
| B: follower B + replica RPC + nginx | D3 | 4 | 8 GB | ≥ 80 GB | |
| Attestor host (×5, inbound TCP 8787 open) | D5 | 4 | 8 GB | ≥ 80 GB | |

The prover installer requires MemAvailable ≥ cap + 20 GiB (120 GiB for 100). If it refuses, stop the settled RPC for the install rather than lowering the cap. **Do not roll the prover back while the settler must keep running on a busy host** (agent 86, G6): the reinstall is refused until the memory is free again, and the settler has no remote prover meanwhile.

Rule from the 2026-10-12 incident: never run validators on host A while the settler and prover run. The 30 `bloch-expansion@` units on 136 stay disabled.

### Layout of host B

B runs the `deployment/mainnet/follower-rpc` units, not the replica kit, because the gateway (P11) reads its backend on 127.0.0.1:18955 and the replica kit serves 18965. B holds no settler, no key, no spool in use and no prover.

| Item | Value on B |
| --- | --- |
| Staged files | `/home/ubuntu/l2-golive-next/artifacts` and `/home/ubuntu/l2-golive-next/kit` |
| Database owner | user `bloch-l2-mainnet-replica` |
| Database | `/var/lib/bloch-l2-mainnet-replica/canonical`, replaced by the P4 refresh; old copies stay as `canonical.prev-*` |
| Txpool directory | `/var/lib/bloch-l2-mainnet-replica/txpool`, required by `install.sh`, never passed to the RPC (`no-txpool.conf` is permanent on B) |
| Producer tool | `/opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev` |
| Binaries, units | `/opt/bloch/l2-mainnet`, `bloch-l2-mainnet-follower`, `bloch-l2-mainnet-rpc` |
| Follower data | `/var/lib/bloch-l2-mainnet-follower` |
| L1 source | `http://199.247.22.8:8080` (D4) |
| RPC | `127.0.0.1:18955`, published only through the P11 gateway |

Rule from the 2026-10-12 incident: never run validators on host A while the settler and prover run.
The 30 `bloch-expansion@` units on 136 are disabled and must stay so.

## 3. Pins

### 3.1 The next build (build commit 17383fe)

Build output on 209: `~/l2dexbridge-20261030/next-rpc-r4/rel4/work-a/out/` (identical copy in `work-b/out/`), six files.

| Artifact | SHA-256 | v2.1 | Used by |
| --- | --- | --- | --- |
| `bloch-l2-settled-rpc` | `e5754d05a1d6b217374a652d6959acf1fcd9323703d82226e07aa1d77a1754e8` | `18be911a…` | RPC A, RPC B (P4) |
| `bloch-l2-native-follower` | `cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2` | `c18752fd…` | followers (P3), attestors (P10) |
| `bloch-l2-produce-dev` | `e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69` | `fb0d5313…` | DB init, settler, shadow, replica, attestors |
| `sequencer_mainnet.py` | `15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2` | same | shadow (P7) |
| `build.json` | `c745e7aae828b8213143bc8cc6c15e170d671a878768d6051c3e14d414382b10` | `b12ed2b6…` | check `l2_commit` 17383feb, `l2_tracked_changes: 0`, lock `a3c38a46…`, HF epochs |
| `out/SHA256SUMS` | `1bad88bad33043200ceabfb0ac4438cf21b464c945167565cfd9ce0a0f58fb08` | | build output only; not in the release dir. `install.sh` checks the release `SHA256SUMS` |
| Lock `settlement-recovery.native-78d4921c.Cargo.lock` | `a3c38a462a273fc07b618ebb2a6dda51377ea7d2deb8530c44a17bc4bf3908a9` | `26bf4453…` | rebuilds |
| Release `SHA256SUMS` (signing target, D7) | `116bfaba85cfc3e7db2589a97e2ac2ac76c9006b3091f6cd98a13732ebff4821` | `dded10b9…` | owner signature. BUILD-INFO `1aca646b…`, `release.json` `25ce440a…` |

To reproduce: L2 17383fe, native 78d4921c, reth 8eb21017 plus `reth-snapshot.patch`, `build-release.sh` at the WORK path `/home/ubuntu/hf-release-kit-20261020/l2-78d4921c-v2`.

### 3.2 Kit files at 6a96dc8

| File | SHA-256 |
| --- | --- |
| `deployment/mainnet/GO-LIVE-PINS.sha256` | `8c87718fbab960571afa0348941ffb02e1a64e38e16d8df52c1b1b91704a1bb4` |
| `deployment/mainnet/GO-LIVE-PINS-PROVER.sha256` | `65715d136c401eec751cbf1677a6691ffca281b5d47667b7c8f4885aa607c91d` |
| `deployment/mainnet/install-shadow.sh` | `1ec041afb7d0c1463680252bdb2e3e420f1ff9881d1f851170c6f3780eb937f3` |
| `deployment/mainnet/l2_monitor.py` | `71f14a645601a07054822021574c1ce557bfb0beeda9ee0f4f71d8c2a58b3820` |
| `deployment/mainnet/install-settler-mainnet.py` | `0fefcbf47092f3383538a9db6e17cd44a5526c2bf50d89794fcbd749198b9215` |
| `deployment/mainnet/l2_reorg_recover.py` | `7c918bb719edf7dd844d50575b1736932993b22c8c230327ee16f1fa02ab9a57` (the settler installer pins it) |
| `deployment/mainnet/prover/install-prover-mainnet.py` | `f342deab986b419dccd89070bb1ac0088729c90258cc57a646b83e9a31787e39` |
| `deployment/devnet/remote_prover.py` | `183bd65509780ed7e222d0aadd2b0be8550c91428cada948c468ffb3b592cdab` (the prover installer pins it; **not** `3c11d9be…` as the PINS-NEXT kit table implies, agent 124 D1) |
| `deployment/devnet/settler_v3.py` | `334230e5970108daff2e2e778b55605bc520a9699f86bc0574b31791bb534ede` |
| `deployment/mainnet/withdraw/bloch-l2-withdraw.py` | `1791d8cad3dc6b6a7e6b281a835aac72f69d0de8c0a4290a41d080ba60846ffc` |
| `deployment/mainnet/public-rpc/l2rpc-gateway.js` | `d1229ca15a3ae6921726631356eff9ed67d417228b23f08de7fac16493090d49` (9645efc; `00f6c6a5…` at 583d8ec) |
| `deployment/mainnet/follower-rpc/bloch-l2-mainnet-rpc.service` | `24aa5cb8d76e5fc8ff926bd49a21497635959c032783fbfdeee38dd2917aac48` (`LimitNOFILE=65536`) |
| `deployment/mainnet/attestor/install-attestor.sh` | `ab24bda0770a1e196f8ffe4340e46520c81f2dd891dd4b1413b6bbec9bee0780` |
| `deployment/mainnet/attestor/keykit/operator-pins-v2.sha256` | `359892b706d936e9b30f0a57d97b85caee3b1d3c1b3d96bbbe2752d3ab9f914a` |
| `deployment/mainnet/replica/PINS.sha256` | `bd1855c8bbb04cb76eecb3f1669e69c07188305496ce2e6004a104037c60a20a` |
| `deployment/mainnet/attestor/sigfeed.py` | `6b6c15a7ced5a7414024502e12a360b61aaedf155a03ffb68005df32299cdce5` |

`GO-LIVE-PINS.sha256` lists `artifacts/SHA256SUMS` as the build's `out/SHA256SUMS` (`1bad88ba…`), not the release `SHA256SUMS` `116bfaba…`. P2 stages the release, so that one line fails by design and P2 checks it separately. A kit commit should move it.

### 3.3 Pins that do not change

As in the v2.1 plan §3.2: guest `settlement_v3_mainnet` `203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473`; proof policy `154869964f…747d`; SP1 host `bloch-evm-sp1-settlement-v3` `3a24c36d9e761b02f6da05b43647c2513768e80c055941c5c0df2420a504973a`; settler `bloch-pos` `700631b040a3a4b2299017162dd4a2c5f521bb49d5fa3c9ed677ba285673794e`; `mainnet.manifest` `7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd`; `carryover.tsv.gz` `4d1e2738baec39ec25e2e33968f72a47abb261f271de62fb48a33be55bfc83be`; gnark image `sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d`; SP1 circuits v6.1.0; L2 genesis `632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468`; network pin `f47d3e49…1966`; domain `1c3f8772…0733`; attestor set `1c06adbb…cc4b` (3-of-5); attestor `bloch-pos` `093909a2…` (rehearsal; production hash `TBD-OWNER`).

**Do not use:** any v2.1 binary (`18be911a…`, `c18752fd…`, `fb0d5313…`) with this kit; the superseded next candidates `d49bcb88…` (72ed5bd), `87aa896f…`, `6052d4bb…`; `remote_prover.py` `99bbc1bc…` or `3c11d9be…`; the staging `release-prover/` and its installer `ed9a001d…`; `settler_v3.py` `3ddb260a…`, `8589d5e2…`, `4059d3a6…`, `0ad4900f…`; produce-dev `7c1cc62b…`; anything built from 724bf4c; the 10-19 runbooks and staging binaries.

### 3.4 Known gaps and residual risks of this build

| # | Item | Effect | What to do |
| --- | --- | --- | --- |
| K5 | Replica B advances only by a manual `reconstruct` | B leaves the gateway rotation when > 16 blocks behind; never serves wrong data | Run the P4 refresh after each finalized settlement |
| K8 | Per-transaction gas limit is a constant 15M, equal to `max_block_gas` | Lowering `max_block_gas` alone reopens the spool squat | Do not lower it without a new RPC build |
| K12 | `spool-step-restart` residual (report 62) | After a restart under a wrong clock, held spool entries expire; users resend. No funds move | Accept; keep host clocks on NTP |
| K13 | F5 (agent 121): held nonce-gap entries count as demand, so every cycle is due (5 of 5 on 17383fe) | Needs both `skip_idle_blocks` and user transactions. Junk in the spool forces blocks | **The deposit-only launch keeps idle blocks on and user transactions off. User transactions stay off until F5 is fixed**; turning idle blocks off instead gives up the height protection of D15 |
| K14 | Agent 118's required-tip file | `--required-tip-file` is inert: nothing writes it, no unit passes it. The gateway commits 3de3a3e and 51cbda1 are in this kit | None at launch |
| K15 | Two low findings of agent 124 on DA re-sign and paid-batch reuse | Worst case one extra DA fee | Only with D10 |
| R1 | First real crossing of HF1–HF3 by this follower | Any halt in P3 is an absolute NO-GO | P3 |
| R2 | DA signature after HF2 | Untested; inferred from code | Rehearse one 0x15 on a private net before D10 |
| R3 | Gas-heavy 15M blocks unmeasured; stuck-block recovery not rehearsed | A proof that OOMs makes the settler retry the same committed block forever | Before D10 |
| R4 | Statement and block-1 references of P6 were measured on v2.1 (`fb0d5313…`) | **Re-measured equal on `e3f1a290…`** (agent 65, recorded view, execute only); the live P6 read stays the owner's | A difference is NO-GO until explained |

## 4. G0: HF3 finalized cleanly (entry gate for everything below)

Run from any machine, at or after the D1 epoch. Repeat for `199.247.22.8` and `45.77.67.251`.

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' http://80.240.16.185:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080
```

**GO only if all of these hold:**

1. On all three nodes, `hard_forks` shows every HF1, HF2 and HF3 entry `active: true`. `hf3_kes_enforce`
   (8620) and `hf3_lattice_emergency` (null) stay inactive.
2. `finalized.epoch` ≥ 7362. `epoch − finalized.epoch` ≤ 3. The same `finalized.root` on all three.
   Heights within 3 blocks.
3. No finality stall since e7180. Run the command below against each of the three nodes. It reads every finished epoch's last block header and the block its `finalized_root` names. It takes one call per epoch or more. GO on exit 0 with `"ok": true`, `empty_epochs` empty and `over_limit` empty. Header lag reads higher than the lag of gate 2: a healthy private net read 3 to 4 where `getchaininfo` read 2, so the default limit is 5. Any epoch at 5 or near it deserves a look. An epoch with no block at all is reported in `empty_epochs` and fails the gate.
4. No L1 release after fa980367 changed a crate the L2 links (see `L2-HARD-FORK-OPERATOR-STEPS.md`
   §0). If one did, rebuild the L2 against it first: NO-GO with this build.
5. `getl2settlement`: `accepted` = `null`, source height 1, slot 187200, `profile.activated` true.
   Record `inbox` (expected `count` 0, `consumed` 0, `escrow_sat` "0"). If deposits arrived in the meantime, L2 block 1 will differ from
   `0ff59c11…ab25` and the P6 dry-run reference changes accordingly.
6. D1, D2, D3, D4, D7, D13, D15, D16 and D17 are decided, and release `SHA256SUMS` `116bfaba…` is signed.
7. The items that block go-live in the owner's guide (`GO-LIVE-L2-PT.md` §1) have a result. If one required a binary change, the build and the signing target changed: stop and re-pin first (`agents/PINS-NEXT.md` change notices).

**NO-GO:** any HF entry not active, a finality lag > 3, nodes on different finalized roots, or an L1
hotfix pending. Wait, and re-run G0.

```
python3 ~/worktrees/go-live-next-r7-20261102/deployment/mainnet/l1_finality_history.py --rpc http://80.240.16.185:8080 --from-epoch 7180
```

Rollback: nothing is installed yet.

## P1. Hosts

Actions (owner):

- 136 (A): confirm idle, the 30 `bloch-expansion@` units disabled, Docker present, the gnark image
  present.
- B (D3): if it is a new VPS, Ubuntu 24.04, ufw on, SSH key only.
- D8: retire the 45.77 scratch processes.

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 'nproc; free -g; df -h /; systemctl list-units --all "bloch-*" --no-legend | grep -c running; sudo docker images --digests | grep sp1-gnark'
```

GO when: 32 vCPU, ≥ 120 GiB available, ≥ 200 GB free, 0 running `bloch-*` units, and the gnark digest
is `e1a1cd62…`. B: ≥ 4 vCPU, ≥ 8 GB, ≥ 80 GB free.

Rollback: none needed.

## P2. Stage and verify the build (no install)

1. The owner signs the release `SHA256SUMS` (D7) and keeps the `.minisig` with the release dir. After the copy, verify on A with `minisign -Vm /home/ubuntu/l2-golive-next/artifacts/SHA256SUMS -P <owner public key>`, and confirm that `sha256sum SHA256SUMS` prints `116bfaba…`.
2. Stage on A, from the Mac. Each command is one block. The release comes from 209 (identical copy on 136); `manifest` and `carryover` from 45.77 as before.

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 mkdir -p l2-golive-next/artifacts l2-golive-next/release-settler-v2
```

```
scp -3 -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@209.250.236.240:l2dexbridge-20261030/next-rpc-r4/release/bloch-l2-2026-11-02-next-native-78d4921c/*' ubuntu@136.244.93.186:l2-golive-next/artifacts/
```

```
scp -3 -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/carryover.tsv.gz*' ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/mainnet.manifest ubuntu@136.244.93.186:l2-golive-next/artifacts/
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/go-live-next-r7-20261102/deployment/mainnet ubuntu@136.244.93.186:l2-golive-next/kit
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/go-live-next-r7-20261102/deployment/devnet/settler_v3.py ubuntu@136.244.93.186:l2-golive-next/release-settler-v2/
```

`scp -r` nests the tree inside `kit` if `kit` already exists, and the old files stay in use. On a second run, remove `l2-golive-next/kit` first. The release on 209 sits in agent scratch: copy it to a kept location before go-live (the v2.1 plan's W4 applies to it and to the staging files below).

Stage B the same way (D3, layout in §2), with `ubuntu@B` as the destination, and check on B:

```
cd /home/ubuntu/l2-golive-next && grep ' artifacts/' kit/GO-LIVE-PINS.sha256 | grep -v ' artifacts/SHA256SUMS$' | sha256sum -c && sha256sum artifacts/SHA256SUMS
```

3. On A, check the build and assemble the settler release dir. The guest, the SP1 host and the 78d4921c `bloch-pos` still come from the settler-v2 staging on 136.

```
cd /home/ubuntu/l2-golive-next/artifacts && sha256sum -c --strict SHA256SUMS
```

```
cp /home/ubuntu/l2-golive-next/artifacts/bloch-l2-produce-dev /home/ubuntu/l2-golive-next/artifacts/mainnet.manifest /home/ubuntu/l2-golive-next/kit/install-settler-mainnet.py /home/ubuntu/l2-golive-next/kit/l2_reorg_recover.py /home/ubuntu/l2-golive-next/release-settler-v2/
```

```
cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/settlement_v3_mainnet /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-pos /home/ubuntu/l2-golive-next/release-settler-v2/
```

```
cd /home/ubuntu/l2-golive-next && sha256sum kit/GO-LIVE-PINS.sha256 artifacts/SHA256SUMS && grep -v ' artifacts/SHA256SUMS$' kit/GO-LIVE-PINS.sha256 | sha256sum -c
```

```
bash /home/ubuntu/l2-golive-next/kit/install-shadow.sh --verify /home/ubuntu/l2-golive-next/artifacts
```

**GO when:**

- `SHA256SUMS` is OK;
- `kit/GO-LIVE-PINS.sha256` hashes to `442beec339f88574af4245ec1733bc84ba10256c561aa5ca3f63fdc847d0de52`, `artifacts/SHA256SUMS` to `116bfaba…`, and every other pin line is `OK`;
- `install-shadow.sh --verify` prints `build.json OK: L2 17383feb, native 78d4921c, HF1 7180/7186, HF2 7270, HF3 7360, KES enforce 8620` and `verify OK` (agent 124 ran it on a 45.77 build; agent 65 on both 209 builds);
- `build.json` shows `l2_commit` 17383feb…, `l2_tracked_changes: 0`.

**NO-GO:** any mismatch. `install-shadow.sh --verify` refuses 72ed5bd's output and every v2.1 artifact by design.

Rollback: `rm -rf /home/ubuntu/l2-golive-next` on A.

## P3. Follower A and follower B (first real crossing of HF1–HF3, R1)

**Status schema.** Keep the follower on schema v2 (the unit default `BLOCH_L2_STATUS_SCHEMA=v2`) for the launch. Readers of the status (the settled RPC, attestors, the replica tools, bridge signers on other branches) must be upgraded **before** any follower writes v3: a v2.1 RPC on a v3 status closes `safe`/`finalized` (agent 76). The order, each step safe to stop at: (1) next RPC on every host that serves the status; (2) readers on that host; (3) the new follower binary, still v2; (4) `BLOCH_L2_STATUS_SCHEMA=v3` in `/etc/bloch-l2-mainnet/follower.env` and a restart, one host at a time. Going back is a restart with v2. On a fresh install all hosts already run this build, so (1)–(3) hold; do (4) only after the bridge signers read v3.

### A (136)

Prerequisite: `install.sh` requires the settler user, the canonical DB and the txpool. So the settler
`prepare` (P6 step 1) runs first. It writes nothing to L1, but it **generates the DA fee key**: back it
up as in P6.

1. P6 step 1 (`prepare`), then the backup.
2. Canonical DB at the pinned genesis:

```
sudo install -D -m 0755 /home/ubuntu/l2-golive-next/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev
```

```
sudo runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev init --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

```
sudo runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev head --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

   GO: `number 0`, hash `632e45ae…f468`, state root `2ad7e807…c05d`.

3. Install the units: dry-run first, then the same command without `--dry-run`.

```
sudo bash /home/ubuntu/l2-golive-next/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-next/artifacts --l1-rpc-url http://80.240.16.185:8080 --canonical /var/lib/bloch-l2-mainnet-settler/canonical --canonical-user bloch-l2-mainnet-settler --txpool /var/lib/bloch-l2-mainnet-settler/txpool --dry-run
```

4. Keep RPC A without the txpool until D10. Create the drop-in:

```
sudo install -d /etc/systemd/system/bloch-l2-mainnet-rpc.service.d
```

```
printf '[Service]\nExecStart=\nExecStart=/opt/bloch/l2-mainnet/bloch-l2-settled-rpc --data-dir /var/lib/bloch-l2-mainnet-settler/canonical --view-dir /var/lib/bloch-l2-mainnet-rpc/rpc-view --finality-status /var/lib/bloch-l2-mainnet-follower/status.json --network f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966 --port 18955 --poll-ms 2000 --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679\n' | sudo tee /etc/systemd/system/bloch-l2-mainnet-rpc.service.d/no-txpool.conf
```

```
sudo systemctl daemon-reload
```

5. Start the follower only:

```
sudo systemctl enable --now bloch-l2-mainnet-follower
```

### B (D3 host)

B has no settler, so `prepare` does not apply. Each command is one block.

```
sudo useradd --system --user-group --no-create-home --home-dir /var/lib/bloch-l2-mainnet-replica --shell /usr/sbin/nologin bloch-l2-mainnet-replica
```

```
sudo install -d -m 0700 -o bloch-l2-mainnet-replica -g bloch-l2-mainnet-replica /var/lib/bloch-l2-mainnet-replica /var/lib/bloch-l2-mainnet-replica/txpool
```

```
sudo install -D -m 0755 /home/ubuntu/l2-golive-next/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev
```

```
sudo runuser -u bloch-l2-mainnet-replica -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev init --target /var/lib/bloch-l2-mainnet-replica/canonical --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

Dry-run first, then the same command without `--dry-run`:

```
sudo bash /home/ubuntu/l2-golive-next/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-next/artifacts --l1-rpc-url http://199.247.22.8:8080 --canonical /var/lib/bloch-l2-mainnet-replica/canonical --canonical-user bloch-l2-mainnet-replica --txpool /var/lib/bloch-l2-mainnet-replica/txpool --dry-run
```

```
sudo install -d /etc/systemd/system/bloch-l2-mainnet-rpc.service.d
```

```
printf '[Service]\nExecStart=\nExecStart=/opt/bloch/l2-mainnet/bloch-l2-settled-rpc --data-dir /var/lib/bloch-l2-mainnet-replica/canonical --view-dir /var/lib/bloch-l2-mainnet-rpc/rpc-view --finality-status /var/lib/bloch-l2-mainnet-follower/status.json --network f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966 --port 18955 --poll-ms 2000 --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679\n' | sudo tee /etc/systemd/system/bloch-l2-mainnet-rpc.service.d/no-txpool.conf
```

```
sudo systemctl daemon-reload
```

```
sudo systemctl enable --now bloch-l2-mainnet-follower
```

**Do not** seed B from the 10-18 scratch state. It replays from zero, so that A and B verify the forks independently.

The no-txpool drop-in replaces only `ExecStart`; the unit's `LimitNOFILE=65536` stays. `install.sh` prints a hint to enable `bloch-l2-mainnet-rpc-restart.path`: **do not enable it** until `foreign_recovery` is on (D17, P12 step 2).

### Go / no-go (both hosts, after about 65–80 min)

```
sudo python3 -c "import json; s=json.load(open('/var/lib/bloch-l2-mainnet-follower/status.json')); print(s['l2_genesis']['finalized'], s['verified_blocks'], s['native_finalized_epoch'], s['verified_slot'])"
```

GO when:

- `l2_genesis.finalized` is `True`;
- `native_finalized_epoch` ≥ 7360 and advancing (read twice, 16+ min apart). It trails the node's
  finalized epoch by about 3 by design;
- `verified_blocks` equals `getchaininfo.finalized_height` within a poll;
- the follower journal has 0 `halted` and 0 `Transition`/`StateRootMismatch` lines.

```
sudo journalctl -u bloch-l2-mainnet-follower --no-pager | grep -cE 'halted|StateRootMismatch|Transition'
```

**NO-GO (stop the whole go-live):** any halt on a post-fork block. It means the verifier disagrees with the L1. Keep the state for analysis and do not skip a block.

One halt is not a verifier disagreement: `node's finalized chain does not descend from the verified head`, exit 3, when the follower's single L1 RPC regressed (a node resynced or restored from older data; agent 86). Check that node first: `getchaininfo` on it must again show the finalized root the other two nodes show. Then restart the follower once (`sudo systemctl restart bloch-l2-mainnet-follower`; it re-verifies from Genesis-4, about an hour). If it halts again with that node caught up, it is a NO-GO. The unit does not restart on exit 3 by design. To avoid the case, keep each follower's L1 node out of resyncs during go-live, or move that follower to its other D4-style source before a planned resync.

Rollback, as root on each host: `systemctl disable --now bloch-l2-mainnet-rpc bloch-l2-mainnet-follower`, then remove
`/etc/systemd/system/bloch-l2-mainnet-rpc.service.d`, `/etc/systemd/system/bloch-l2-mainnet-follower.service.d` and the two
unit files, and run `systemctl daemon-reload`. To reinstall, move `/opt/bloch/l2-mainnet` aside first, because `install.sh`
refuses a populated directory. The data stays. The settler `prepare` state stays (see P6 rollback).

## P4. Settled RPC A and B

```
sudo systemctl enable --now bloch-l2-mainnet-rpc
```

```
curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
```

```
curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["finalized",false]}'
```

```
curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_finality","params":[]}'
```

```
curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_getWithdrawalProof","params":[0]}'
```

GO when:

- `eth_chainId` is `0xab162`;
- `finalized` and `safe` are block 0, `0x632e45ae…f468`;
- `bloch_finality` shows `l2_genesis.finalized: true` with activation `618c9b80…` at slot 187200, and `status.state: ok` with a small `age_s`;
- `systemctl show -p ExecStart bloch-l2-mainnet-rpc` has no `--txpool`;
- `systemctl show -p LimitNOFILE bloch-l2-mainnet-rpc` is `65536` (at 1024, about 1,000 idle connections close finality, agent 65);
- `bloch_finality.status.schema` is `v2`;
- `bloch_getWithdrawalProof` answers (an error about the missing withdrawal, not -32601).

NO-GO: `safe`/`finalized` `null` after the follower is ready, or a wrong chain id.

Replica refresh on B (K5; after every finalized settlement from P8 on), one command per block:

```
sudo runuser -u bloch-l2-mainnet-replica -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev reconstruct --target /var/lib/bloch-l2-mainnet-replica/canonical.next --l1-follower /var/lib/bloch-l2-mainnet-follower/native --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679 --timestamp-rule 1:1786656679:30000
```

```
sudo systemctl stop bloch-l2-mainnet-rpc
```

```
sudo mv /var/lib/bloch-l2-mainnet-replica/canonical /var/lib/bloch-l2-mainnet-replica/canonical.prev-$(date -u +%Y%m%dT%H%M%SZ)
```

```
sudo mv /var/lib/bloch-l2-mainnet-replica/canonical.next /var/lib/bloch-l2-mainnet-replica/canonical
```

```
sudo systemctl start bloch-l2-mainnet-rpc
```

Rollback: `sudo systemctl disable --now bloch-l2-mainnet-rpc`. Nothing depends on it until P10.

## P5. Prover (D2; on A unless decided otherwise)

**Do not install from the settler-v2 staging `release-prover/`.** It holds the forbidden `remote_prover.py` `99bbc1bc…` and the old installer `ed9a001d…`, and its own `SHA256SUMS` passes. That `SHA256SUMS` proves nothing. Two checks reject a wrong file: the pin file below, and the installer, which refuses any `remote_prover.py` but `183bd655…`. Assemble a new directory. The host and the guest come from the staging, the installer from the kit. `remote_prover.py` is under `deployment/devnet`, outside the P2 kit copy, so copy it from the Mac first:

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/go-live-next-r7-20261102/deployment/devnet/remote_prover.py ubuntu@136.244.93.186:l2-golive-next/
```

```
mkdir -p /home/ubuntu/l2-golive-next/release-prover-v2
```

```
cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/settlement_v3_mainnet /home/ubuntu/l2-golive-next/kit/prover/install-prover-mainnet.py /home/ubuntu/l2-golive-next/remote_prover.py /home/ubuntu/l2-golive-next/release-prover-v2/
```

```
cd /home/ubuntu/l2-golive-next && sha256sum -c kit/GO-LIVE-PINS-PROVER.sha256 && cd release-prover-v2 && sha256sum bloch-evm-sp1-settlement-v3 settlement_v3_mainnet remote_prover.py > SHA256SUMS
```

GO only if that exits 0 with four `OK` lines. `SHA256SUMS` is written only after they pass. On any `FAILED`: NO-GO, and do not write `SHA256SUMS` by hand.

Install after the settler `configure` (P6 step 2) has created the settler SSH key. Dry-run first, then the same
command without `--dry-run`:

```
sudo python3 /home/ubuntu/l2-golive-next/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /var/lib/bloch-l2-mainnet-settler/ssh/id_ed25519.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400 --dry-run
```

GO when:

- the dry-run prints `memory_ok: true`, the identity equals the pins (ELF keccak `6e4c8440…`, policy
  `154869964f…747d`) the slice is 100 G / 32 threads, `prover_env` is `ELEMENT_THRESHOLD: 268435456` and `timeout_seconds` 5400;
- `authorized_keys` ends in `bloch-l2-mainnet-settler` with `from="127.0.0.1"`;
- the `sha256` block shows `remote_prover.py` `183bd655…`.

NO-GO: an identity mismatch, `remote_prover.py is … not the pinned …`, or MemAvailable < 120 GiB.

Rollback (refuses while a proof runs):

```
sudo python3 /home/ubuntu/l2-golive-next/release-prover-v2/install-prover-mainnet.py rollback
```

## P6. Settler: prepare, configure, dry-run, then dry-run with the proof

1. **prepare** (local only; creates the DA key; done during P3):

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py prepare --release /home/ubuntu/l2-golive-next/release-settler-v2
```

   Record `da_funding_script_hash`. Back up the DA keystore and the passphrase **separately**. Each `gpg` asks for a
   passphrase on the terminal; use a different one for each. Copy both files off the host, to different media, then delete them there.

```
sudo tar czf - -C /var/lib bloch-l2-mainnet-da | gpg --symmetric --pinentry-mode loopback -o /home/ubuntu/da-keystore.tgz.gpg
```

```
sudo cat /var/lib/bloch-l2-mainnet-settler/da.passphrase | gpg --symmetric --pinentry-mode loopback -o /home/ubuntu/da-passphrase.gpg
```

   Copy the SP1 circuits for the local fallback:

```
sudo cp -a /home/ubuntu/l2-mainnet-install-20261019/circuits /var/lib/bloch-l2-mainnet-settler/.sp1-circuits-tmp
```

```
sudo mkdir -p /var/lib/bloch-l2-mainnet-settler/.sp1
```

```
sudo mv /var/lib/bloch-l2-mainnet-settler/.sp1-circuits-tmp /var/lib/bloch-l2-mainnet-settler/.sp1/circuits
```

```
sudo chown -R bloch-l2-mainnet-settler:bloch-l2-mainnet-settler /var/lib/bloch-l2-mainnet-settler/.sp1
```

2. **configure** with the local prover and the read-only checks.

   `configure` runs its checks on `config.json.pending` and creates `config.json` only after they pass, so after a failure
   `start` stays refused. Fix the cause and run the same command again; nothing needs removing. A failed `prepare` is different:
   `rollback` does not undo it, so inspect what it created before you remove anything. Never remove a DA keystore that may already hold funds.

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py configure --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800
```

   This is D15. Leave out `--follower-state` and `--follower-status` (D17: foreign recovery off). `configure` runs once, so check the result before going on:

```
sudo python3 -c "import json;c=json.load(open('/etc/bloch-l2-mainnet-settler/config.json'));print(c.get('skip_idle_blocks'),c.get('max_idle_seconds'),c.get('min_block_interval_seconds'),c['user_transactions'],'foreign_recovery' in c,c['remote_prover']['timeout_seconds'])"
```

   GO: `True 86400 1800 False False 5700`. The flags are covered by the installer and settler unit tests; this exact command line was not run on a container.

   GO (the state root is in `dry-run-*/work/*/block.json`, not in the printed report):
   - the last line is `{"configured": "/etc/bloch-l2-mainnet-settler/config.json"}`;
   - `rpc-check` `ok: true` (3/3 same view, quorum 2);
   - dry-run `ok: true`, identity checked (mainnet, async, activated, attestor set);
   - with an empty inbox: L2 block 1 = `0ff59c1194f6d81be26dc288e4ba9bb721e46181787f3f9cffb0b029b281ab25`,
     state root `8a1c475a…136c`, SP1 execute matched. These references were measured with v2.1's producer and re-measured on 2026-11-02 with this build's producer `e3f1a290…` and the kit `settler_v3.py`, mainnet kind, against stubs replaying the recorded view: same block 1, same state root, same native request, same `block.artifact`, the same expected statement line, 529,004 instructions (agent 65; execute only, no proof, no live mainnet read).

3. Then P5 (prover install), then **dry-run with the Groth16 proof** (about 5–15 min for this empty block, about
   20 GiB prover RSS plus 18.5 GiB gnark):

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py dry-run --prove
```

```
sudo sh -c 'cat "$(ls -d /var/lib/bloch-l2-mainnet-settler/dry-run-* | tail -1)/dry-run-report.json"' | grep -E '"ok"|"tag"|"bytes"|"proof_policy"'
```

   Each dry run leaves its own directory, so read only the newest. The report has no `where` field, and a dry run that
   fell back to a local proof still ends `ok: true`. Read the stage from `proved.json`:

```
sudo sh -c 'cat "$(ls -d /var/lib/bloch-l2-mainnet-settler/dry-run-* | tail -1)"/work/*/proved.json' | grep -E '"name"|"where"'
```

   If it fell back, the reason is in `work/*/prove-remote.log` in the same directory.

   GO:
   - `ok: true`, tag `0x13`, 1155 bytes, `proof_policy 154869964f…747d`;
   - the `prove` stage `"where": "remote"`;
   - with an unchanged source, the statement SHA-256 is `42779c77…7426`, which is bytes 33 to 798 of `work/*/transaction.bin`
     (the transaction bytes differ between runs, because Groth16 is randomized):

```
sudo sh -c 'python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],\"rb\").read()[33:799]).hexdigest())" "$(ls -d /var/lib/bloch-l2-mainnet-settler/dry-run-* | tail -1)"/work/*/transaction.bin'
```

NO-GO:

- any `halt` or an identity mismatch;
- a `prove` stage `"where": "local"` (the SSH path is broken: fix it before going live).

Rollback: `install-settler-mainnet.py rollback`. It removes the unit only and keeps the DB, the
keystore, the passphrase and the config. Nothing has been written to L1.

## P7. Shadow producer (before the first live settlement)

The shadow rebuilds every block the settler produces and halts (exit 3) on any difference, before the
proof reaches L1. That is why it goes **before** P8, although the original order listed it later.

```
sudo bash /home/ubuntu/l2-golive-next/kit/install-shadow.sh /home/ubuntu/l2-golive-next/artifacts --start
```

GO:

- the `init` hash is `632e45ae…` / `2ad7e807…`;
- `check` ok against the 3 RPCs;
- the unit is active, and the command below prints `0`. A plain `grep halt` always matches, because the unit description contains "halts".

```
sudo journalctl -u bloch-l2-mainnet-shadow -o cat --no-pager | grep -c '"event": "halt"'
```


NO-GO: a pin refusal (wrong release or kit) or a check failure.

Rollback:

```
sudo bash /home/ubuntu/l2-golive-next/kit/install-shadow.sh --rollback
```

Reinstall after P8, and repair after `l2_reorg_recover.py --apply`: run the rollback above, then the install command of this phase again. Once a settlement is accepted, `install-shadow.sh` no longer creates its database at genesis: it rebuilds it from L1 with `produce reconstruct --l1-follower` over the local follower, so its head is the accepted settlement and `check` passes. The follower must have reached that settlement. Its old data is kept as `*.rollback-<time>`.

## P8. Settler live: first settlement (L2 block 1) — **MAINNET WRITE**

Preconditions: P3 to P7 all GO on the same day. G0 re-checked within the last hour. Only one settler
exists anywhere.

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py start --confirm-mainnet
```

```
journalctl -u bloch-l2-mainnet-settler.service -f -o cat
```

Expected, in order: `identity-checked` (mainnet true), `idle-end` with reason `max-idle` (the activation source is far older than 24 h), `l2-block-produced` 1, `proof-generated`,
`remote-proof` with exit code 0, `transaction-built`, `submitted`, `accepted`. With D15 the worker does **not** start block 2 at once: it logs `idle-hold` (at most hourly) until a deposit arrives, 24 h pass, and in any case at least 30 min after the acceptance. When scripting waits on this journal, filter with `--since` the last restart: after a reorg an old `accepted` event of the same number matches (agent 86, G10).

Independent check, on each of the three RPCs:

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080
```

GO (the L2 is live):

- `accepted.statement` L2 number 1 on all three nodes;
- `source.height` greater than 1 (it follows the L1 chain, it is not the L2 number);
- the P7 `grep -c` still prints `0`;
- after FFG finality of the including block (`getchaininfo.finalized_height` ≥ that block, about
  2–3 epochs), RPC A and RPC B show `safe` → block 1, then `finalized` → block 1. On B this happens
  after the K5 refresh.

**NO-GO / stop** (`install-settler-mainnet.py rollback`; the accepted settlement stays, the L2 just
stops advancing):

- a settler `halt`;
- a shadow `halt` (a producer divergence: do not restart the settler before analysis);
- `acceptance-timeout` with `l1-not-advancing` for more than 3 cycles;
- RPC `safe`/`finalized` disagreeing with `getl2settlement`.

Rollback limits: **an accepted L1 settlement cannot be undone.** Restarting with `start --confirm-mainnet`
resumes from the accepted head.

## P9. Monitor

Run once by hand as a gate, then install the 60 s timer (units in `kit/monitor/`; D11 sets the alert targets). The env file drops `--l2-rpc B=`: the settled RPC binds loopback only, so A cannot reach B on 18955. Each command is one block:

```
sudo useradd --system --user-group --no-create-home --home-dir /var/lib/bloch-l2-monitor --shell /usr/sbin/nologin bloch-l2-monitor
```

```
sudo install -D -m 0644 /home/ubuntu/l2-golive-next/kit/l2_monitor.py /opt/bloch/l2-monitor/l2_monitor.py
```

```
sudo install -d -m 0755 /etc/bloch-l2-monitor
```

```
sed -e 's/--phase prelaunch/--phase live/' -e 's# --l2-rpc B=http://TBD-owner:18955##' -e 's#$# --max-idle-seconds 86400 --backlog-state /var/lib/bloch-l2-monitor/backlog.json --set block_interval_seconds=1800#' /home/ubuntu/l2-golive-next/kit/monitor/monitor.env.example | sudo tee /etc/bloch-l2-monitor/monitor.env
```

The added flags are D15 and D16: `--max-idle-seconds` adds the idle allowance to the age checks and needs `--backlog-state` for `deposit_wait`; `block_interval_seconds=1800` grades `l2_proof_cost` (WARN at 1,260 s, CRIT at 1,800 s). Add the D18 `--set` values the owner picks. The env example also carries `--report dex=…`: remove it if the DEX monitor does not run on A.

**Alert destinations are `TBD-OWNER` (D11).** In `/etc/bloch-l2-monitor/alert.json` they are `webhook_url` (+ `webhook_bearer_file`), `telegram.bot_token_file` and `telegram.chat_id`, `alert_command`, and `heartbeat_url`; every one is `TBD-OWNER` in the example. Until D11 is decided, install the example unchanged: nothing is delivered and WARN `alert_delivery` is expected. Nobody but the owner fills these in.

```
sudo install -m 0644 /home/ubuntu/l2-golive-next/kit/monitor/alert.json.example /etc/bloch-l2-monitor/alert.json
```

```
sudo install -m 0644 /home/ubuntu/l2-golive-next/kit/monitor/bloch-l2-mainnet-monitor.service /home/ubuntu/l2-golive-next/kit/monitor/bloch-l2-mainnet-monitor.timer /etc/systemd/system/
```

```
sudo systemctl daemon-reload
```

```
sudo systemctl enable --now bloch-l2-mainnet-monitor.timer
```

```
sudo systemctl start bloch-l2-mainnet-monitor.service
```

```
sudo journalctl -u bloch-l2-mainnet-monitor.service -o cat --no-pager -n 40
```

The command below needs root for `status.json` only if that file is not world-readable:

```
python3 /home/ubuntu/l2-golive-next/kit/l2_monitor.py --profile mainnet --phase live --max-idle-seconds 86400 --backlog-state /tmp/backlog.json --set block_interval_seconds=1800 --l2-rpc A=http://127.0.0.1:18955 --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://45.77.67.251:8080 --follower-status A=/var/lib/bloch-l2-mainnet-follower/status.json --unit settler=bloch-l2-mainnet-settler.service --unit shadow=bloch-l2-mainnet-shadow.service --binary /opt/bloch/l2-mainnet/bloch-l2-settled-rpc --build-json /home/ubuntu/l2-golive-next/artifacts/build.json --json
```

GO, after the first L2 finalization: exit 0, or 1 with only the expected WARN `alert_delivery` before D11. Between P8 and that
finalization, `--phase live` exits 2 with `l2_finalized_age` CRIT, because the finalized block is still the old genesis. That CRIT alone is expected.
Before P8, use `--phase prelaunch`; there `unit[settler]` is CRIT until the unit exists. A CRIT on `--binary` means an installed binary is not this build's pin. Known false alarm (D18): `l2_head_age` may go CRIT on a healthy idle chain. Thresholds:
`MAINNET-OPS-RUNBOOK.md` §3. Also watch `age_s` in `bloch_finality.status` (check `l2_finality_status`): a stopped follower keeps serving its last finality.

Rollback: `sudo systemctl disable --now bloch-l2-mainnet-monitor.timer`. It is read-only.

## P10. Attestor sealing and distribution (D5)

Not needed for settlements, deposits or claims under 100 BLCH. It is **required before any claim of
100 BLCH or more**, and therefore before the exchange notice (P13).

1. Run the custody flow on the owner's Mac, offline: `deployment/mainnet/attestor/keykit/make-operator-bundles.sh`
   `preflight`, `seal`, `verify`, `package`, `backup-check` on two media, then `shred-originals`
   (`keykit/KEY-HANDOFF-CHECKLIST.md`). The keys never travel unsealed. The
   originals are now destroyed before the handoff, gated on verified bundles and two read-back media.
2. Each operator host (§2 spec) gets an `ARTEFATOS` dir with:
   - `bloch-l2-native-follower` `cdf5da5c…` and `bloch-l2-produce-dev` `e3f1a290…` (from this build; the kit's `install-attestor.sh` `ab24bda0…` and `operator-pins-v2.sha256` `359892b7…` refuse the v2.1 ones);
   - the attestor `bloch-pos` (e7d2c8b2 Linux build; `keykit/operator-pins-v2.sha256` pins `093909a2…`, owner to confirm);
   - `mainnet.manifest`, `carryover.tsv.gz` and `.sha256`;
   - `SHA256SUMS` over the three binaries;
   - the kit `deployment/mainnet/attestor` from this plan's kit (9645efc, which contains ff839ba's package fixes with the pins moved to this build). Not `codex/attestor-packages-r4-20261101` ff839ba alone: it pins v2.1. Not `attestor-custody-20261030`.

   Not the RC binaries `821289e0…` / `192eda33…`: they halt.
3. `check-operator-bundle.sh --open`, then `install-attestor.sh install … --l1-rpc-url <D4-style L1 RPC>`.
   The installer pins the follower in `config.json` (K2). As operator root, also compare the files:

```
sha256sum /opt/bloch/l2-attestor/bloch-l2-native-follower /opt/bloch/l2-attestor/bloch-l2-produce-dev
```

   Pass `--feed-port 8787`, open inbound TCP 8787, and enable `bloch-l2-attestor-feed`. Build the operator packages from this kit; `IDENTITY.txt` records the kit commit. Attestor followers stay on status schema v2 (P3).
4. Start the follower and wait about 65–80 min. Then run `attestor_agent.py check`, then start the
   agent. The printed `check` command passes the passphrase with systemd `LoadCredential`. It has run only in containers, where systemd 255 does not mount credentials (`/run/credentials/…/passphrase: No such file`); with a stand-in `CREDENTIALS_DIRECTORY` all three operators reported `check-ok` (agent 86). Run it once on a real VM before relying on it, and report a failure there as a kit defect. Fresh installs may run in parallel: there is no existing quorum to protect.

GO:

- ≥ 3 operators (target 5) report `check-ok` with their `signer_index` and set `1c06adbb…`, plus
  `rebuild-check-ok`;
- the follower `native_finalized_epoch` advances;
- each operator has re-sealed their backup under their own passphrase, and `release-owner-copy` has
  run for at least three indexes, so the owner holds fewer than 3 of 5 (`keykit/KEY-HANDOFF-CHECKLIST.md`).

NO-GO: fewer than 3 `check-ok`, or a `halt … produce differs`.

Rollback per host: `touch /etc/bloch-l2-attestor/PAUSE`. A lost host is reinstalled from the
operator's USB copy. Changing the set needs a hard fork.

## P11. Public gateway (D9) — **PUBLISH (owner only)**

The nginx + njs gateway on A (role `sequencer`) and B (role `replica`) replaces the 10-19 Cloudflare
Worker and its plain-HTTP `:2095` origin guard. It removes the unencrypted hop and the shared key
header, and keeps all policy on our hosts. **Do not deploy both.** The explorer Function `/l2rpc` keeps
working against `https://l2rpc.blochl1.com/`.

Prerequisites: P4 on both hosts, and the gateway package from the kit. On each host, as root:

- `apt-get install nginx libnginx-mod-http-js`; nginx must be running, since `apply` reloads it.
- Place `/etc/ssl/bloch-l2rpc/origin.pem` and `origin.key` (Cloudflare Origin CA) and `/etc/ssl/bloch-l2rpc/cloudflare-aop-ca.pem` (Authenticated Origin Pulls CA).
- Run `setup-gateway.sh peer-cert`, then copy each host's `/etc/nginx/bloch-l2rpc/peer/self.crt` to the other host as `/etc/nginx/bloch-l2rpc/peer/peer.crt`.

`setup-gateway.sh` renders with CORS open to any origin and `--backend-conns 400`, below the RPC's 1,024 HTTP connection limit. Gateway `l2rpc-gateway.js` `d1229ca1…`, with agent 118's fee routing to the sequencer and HTTP 503 for an unanswered split batch. The `plan` command only renders, and it exits 0 even when it prints `MISSING:` lines, so read its output. `apply` installs.

On A:

```
sudo ROLE=sequencer NAME=l2rpc-a PEER=45.77.142.123:18956 PEER_ALLOW=45.77.142.123 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh plan
```

```
sudo ROLE=sequencer NAME=l2rpc-a PEER=45.77.142.123:18956 PEER_ALLOW=45.77.142.123 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh apply
```

On B (the commands assume 45.77; for a D3 VPS use its IP in both hosts' `PEER` and `PEER_ALLOW`):

```
sudo ROLE=replica NAME=l2rpc-b PEER=136.244.93.186:18956 PEER_ALLOW=136.244.93.186 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh plan
```

```
sudo ROLE=replica NAME=l2rpc-b PEER=136.244.93.186:18956 PEER_ALLOW=136.244.93.186 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh apply
```

Then in the Cloudflare dashboard (zone blochl1.com): add the proxied A record `l2rpc` → 136.244.93.186, set
SSL to Full (strict) for that hostname only, and turn Authenticated Origin Pulls on. Deploy the explorer last.
Before that, re-check that the site still serves the bundle `index-D4WLsMRL.js`. If not, rebase.

```
curl -s http://127.0.0.1:18958/health
```

```
curl -s https://l2rpc.blochl1.com/health
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' https://l2rpc.blochl1.com
```

```
curl -s -i -X OPTIONS -H 'Origin: https://example.com' -H 'Access-Control-Request-Method: POST' https://l2rpc.blochl1.com
```

GO:

- both backends show `"ok":true` on the loopback `/health` of each host;
- `eth_chainId` through the gateway is `0xab162`;
- the preflight is `204` with `access-control-allow-origin: *`;
- a direct request to the origin without the Cloudflare client certificate is refused.

NO-GO: either origin unreachable, a wrong chain id, or a backend `ok: false`.

Manual failover (A down): point the `l2rpc` A record at B. Reads are served from the replica, and
transactions return -32053 until A is back, by design.

Rollback, on each host, then delete the DNS record:

```
sudo PEER_ALLOW=45.77.142.123 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh rollback
```

(on B use `PEER_ALLOW=136.244.93.186`).

## P12. First deposit and settlement test — **MAINNET WRITE (owner funds, D6)**

1. **Deposit** (works with user transactions off). Send a small deposit, for example 1 BLCH
   (minimum 0.01 BLCH), from the D6(b) L1 wallet with `bloch-pos l2-deposit` (fa980367 fleet binary)
   to the D6(b) L2 address: `l2-deposit prepare --genesis MANIFEST --funding-pubkey FILE --input TXID:VOUT:SATS --amount SATS --recipient L2_ADDRESS --base-fee N --tip 0 --out UNSIGNED`,
   then `l2-deposit sign --genesis MANIFEST --tx UNSIGNED --dir WALLET_DIR --out SIGNED`, then `sendrawtransaction` with the contents of SIGNED.
   `--base-fee` is `next_base_fee_millisat_per_gas` from `getchaininfo`.

   GO:
   - `getl2settlement.inbox` shows it pending;
   - the next L2 block produced after it consumes it and settles. A block already committed settles first without it, so it can take one more block;
   - after finality, `eth_getBalance` on RPC A and B (and the gateway) at `finalized` equals
     amount × 10¹⁰ wei;
   - the monitor `escrow_backing` is OK and `escrow_conserved` is true.
   With D15 the deposit made while idle takes two blocks: the first carries nothing, the next mints it, each after the 30 min pacing. Expect 40–70 min at low heights.

2. **Enable user transactions (D10) and foreign recovery (D17).** **Not on this build while F5 is open (K13).** Only after:
   - the deposit block is finalized;
   - R2 has been rehearsed on a private network;
   - gas-heavy 15M blocks have been measured and stuck-block recovery has been rehearsed (R3);
   - the dedicated prover is in place (D2);
   - the DA key is funded: 5 BLCH to `da_funding_script_hash` from the D6(a) wallet. The plan says two outputs; the wallet's `transfer-v2` makes one output per transaction, so that is two transactions (agent 86). No command is given here: use the D6(a) wallet's own tool;
   - replica B has been rebuilt from L1 DA (K5).

   With the txpool on, the settled RPC enforces its limits (K8; `docs/MAINNET-RPC-READINESS.md` R7) and refuses effective tips below 0.1 gwei. Signed L2 transactions need `--rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679` in `produce-dev sign-tx`, or the RPC refuses them with `WrongChain` (agent 86, G4).

   Then, on A, one command per block. The first sets both switches; the follower paths are outside `/home` and must be readable by the settler user (check with `sudo -u bloch-l2-mainnet-settler test -r /var/lib/bloch-l2-mainnet-follower/status.json && echo ok`):

```
sudo python3 -c "import json;p='/etc/bloch-l2-mainnet-settler/config.json';c=json.load(open(p));c['user_transactions']=True;c['foreign_recovery']={'follower_state':'/var/lib/bloch-l2-mainnet-follower/native','follower_status':'/var/lib/bloch-l2-mainnet-follower/status.json'};json.dump(c,open(p,'w'),indent=2)"
```

```
sudo systemctl enable --now bloch-l2-mainnet-rpc-restart.path
```

```
sudo systemctl restart bloch-l2-mainnet-settler
```

```
sudo rm /etc/systemd/system/bloch-l2-mainnet-rpc.service.d/no-txpool.conf
```

```
sudo systemctl daemon-reload
```

```
sudo systemctl restart bloch-l2-mainnet-rpc
```

   `no-txpool.conf` stays on B.

   **Never** do this inside e7269–e7271 of a future signature fork.
3. **Withdrawal test** (needs step 2: a burn is an L2 transaction). Withdraw 0.5 BLCH (under 100 BLCH, so no attestors are needed) from the test L2 address. **The withdraw tool now works**: this build's RPC serves `bloch_getWithdrawalProof`, so `deployment/mainnet/withdraw/bloch-l2-withdraw.py` (`1791d8ca…`) runs `burn`, `find`, `fetch`, `verify` and `status` without an L2 database (README in the same directory). On A, against RPC A:

```
python3 /home/ubuntu/l2-golive-next/kit/withdraw/bloch-l2-withdraw.py find --l2-rpc http://127.0.0.1:18955 --tx 0xBURN_TX_HASH
```

```
python3 /home/ubuntu/l2-golive-next/kit/withdraw/bloch-l2-withdraw.py fetch --l2-rpc http://127.0.0.1:18955 --l1-rpc http://80.240.16.185:8080 --index I --recipient-pubkey me.pubkey.hex --sats 50000000 --out /home/ubuntu/claim-0.proof.json --wait 7200
```

   Then prepare, sign and send with the commands `fetch` prints (as below), and decide with `status --proof … --tx TXID` (exit 0 = claimed and finalized). Agent 67 ran the tool against a next-build RPC and a forced L1, not against `e5754d05…` on mainnet. Fallback, as on v2.1 (agent 86): build the proof from the settler's database. First read the claimable settlement:

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080 | python3 -c 'import json,sys;w=json.load(sys.stdin)["result"]["withdrawals"];print(w["claimable"], w["claimed"])'
```

   When `claimable` is not `None`, use its `l2_number`, `root` and `count`, and the withdrawal's index (0 for the first):

```
sudo runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev withdrawal-proof --target /var/lib/bloch-l2-mainnet-settler/canonical --index 0 --number L2_NUMBER --root ROOT --count COUNT --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679 > /home/ubuntu/claim-0.proof.json
```

```
bloch-pos l2-claim prepare --genesis /home/ubuntu/l2-golive-next/artifacts/mainnet.manifest --funding-pubkey FUNDING_PUBKEY --input TXID:VOUT:SATS --proof /home/ubuntu/claim-0.proof.json --base-fee N --tip 0 --out claim-unsigned.hex
```

```
bloch-pos l2-claim sign --genesis /home/ubuntu/l2-golive-next/artifacts/mainnet.manifest --tx claim-unsigned.hex --dir WALLET_DIR --out claim-signed.hex
```

   Then `sendrawtransaction` with the contents of `claim-signed.hex`. **The `accepted` reply is not a confirmation:** a claim over the release-window cap is answered `accepted` and refused afterwards with `RateLimited` (agent 67). Re-run the first command until the `claimed` bitmap has the withdrawal's bit set.

   GO:
   - the 0x15 DA record and the settlement are accepted;
   - the `claimed` bitmap has bit 0 set;
   - `inbox.escrow_sat` fell by exactly the claim, and `withdrawals.release_window.released_sat` rose by it;
   - the recipient has the output (`getutxos`), and `escrow_conserved` is true;
   - the monitor's `claims_vs_withdrawn` is OK.

NO-GO: any escrow invariant warning, a deposit not consumed within 2 cycles, a DA refusal (R2) or a
claim refused as anything but `NotFinalized` timing.

Rollback: set `user_transactions` back to `false`, restart the settler and put `no-txpool.conf` back.
Deposits and settlements continue.

## P13. Exchange notice — **PUBLISH (owner only)**

Only after P8 to the P12 deposit are GO and at least three attestors are live. Fill
`docs/MAINNET-EXCHANGE-INTEGRATION.md`:

- `{{PUBLIC_L2_RPC_URL}}` = `https://l2rpc.blochl1.com`;
- `{{L2_EXPLORER_URL}}` = `https://blochl1.com/l2`;
- `{{L2_NODE_GUIDE_URL}}` = `TBD-owner`;
- the measured `safe`/`finalized` latency from P8/P12.

Do not resend earlier notices about a pause in claims across HF1: they are historical by then. State that the L2 is live with deposits, that a deposit mints in about 40–70 min (D15), and that `latest` time stands still while the chain is idle. Point integrators to the withdraw tool README for claims, and state that a `sendrawtransaction` `accepted` reply is not a confirmation (the notice still says a claim over the cap "waits": fix that text, agent 86 G8). Announce transfers only once D10 is done, and withdrawals only once the P12 step 3 is GO. When you announce withdrawals, state that claims of 100 BLCH or
more need 3-of-5 attestation and 2,880 blocks, and the release window limits.

Rollback: a correction notice. The chain state is unaffected.

## 5. Timeline (assuming D1 = e7450)

| When (UTC) | Phase |
| --- | --- |
| Before 2026-11-03 | D2–D9, D13, D15–D17 decided. No host changes. |
| After G0 gate 7, before P2 | Release signed (D7). |
| 2026-11-03 16:11 (e7360) | HF3. Observe only. |
| 2026-11-04 16:11 (e7450) | G0, P1, P2 |
| +0:30 | P6 step 1 (prepare + DA key backup), P3 A and B (replay about 65–80 min) |
| +2:00 | P3 go/no-go, P4 |
| +2:30 | P6 configure (with D15), P5, P6 dry-run `--prove` (about 20 min) |
| +3:15 | P7 shadow, then P8 (block 1 as a `max-idle` heartbeat); finality about 1 h later |
| +4:30 | P9 monitor. L2 core live, idle until demand. |
| Day +1 to +3 | P10 attestors, P11 gateway, P12 deposit test (about 40–70 min to mint) |
| After F5 is fixed in a later build, R2, R3, D2 and DA funding | P12 step 2 (user transactions + foreign recovery) and step 3 (withdrawal test with the tool) |
| After all GO | P13 exchange notice |
| Before e8620 (2026-11-17) | KES enforce. Settlement after a KES period change has not been exercised: have that result first. |
| When `l2_proof_cost` WARNs (around L2 block 4,000) | Raise the interval (D16) or add proving capacity (§2). |

## 6. Recovery steps (agent 106, measured 2026-11-02)

### 6.1 An L1 node that does not come back (refill from a healthy node)

Applies to any L1 node the L2 reads (D4) or any node of our fleet. Symptom: `bloch_pos_blocks_parked` at 32 or more and a finalized epoch that does not move while peers advance; detector `deployment/mainnet/l1_stuck_check.py`.

**Wiping the data alone does not work on mainnet.** The fa980367 binary `01c98b68…` with an empty data dir exits at once with `ERR_WS_REQUIRE_CHECKPOINT` (genesis beyond the 2,016-epoch weak-subjectivity window); keeping `ws_latest.bin` does not help. `docs/L1-STUCK-NODE-RUNBOOK.md` at 9645efc still says to wipe: follow this section instead.

Order: (1) one restart (it helped 1 time in 3); (2) refill from a healthy node of our own, below (97 s to serve the copied head with `state.cache`; 51–54 min replay without it); (3) only with a published checkpoint (D19), wipe and start from it (about 11.5–15 h).

Refill. Pick a node that `l1_stuck_check.py` reports OK and that follows the reference head, preferably one that does not validate, with no proposal due. `HEALTHY_UNIT`, `HEALTHY_DATA_DIR`, `UNIT`, `DATA_DIR` and `NODE_USER` are that node's and the stuck node's. On the healthy host, copy by name, never with a glob:

```
sudo systemctl stop HEALTHY_UNIT
```

```
sudo tar -C HEALTHY_DATA_DIR -cf /tmp/chain.tar blocks.log blocks.idx meta.bin ws_latest.bin state.cache
```

```
sudo systemctl start HEALTHY_UNIT
```

```
tar -tf /tmp/chain.tar
```

GO to move it only if the list holds exactly those five names: no `validator.key`, `validator.kes`, `slashing_protection.bin` or `mesh_identity.bin`. On the stuck host, with `UNIT` stopped, move the old chain files aside (do not delete them), then:

```
sudo tar -C DATA_DIR -xf /tmp/chain.tar
```

```
sudo chown -R NODE_USER: DATA_DIR
```

```
sudo ls -l DATA_DIR/validator.key DATA_DIR/slashing_protection.bin
```

```
sudo systemctl start UNIT
```

**Never delete or overwrite `validator.key`, `validator.kes` or `slashing_protection.bin`.** Without its slashing protection a node refuses to start (`SIGNING ROLLBACK REFUSED`), which is correct. Restart validators in waves with doppelganger protection on. Limits: measured on a copy of mainnet to e6596 over a loopback devnet transport, not libp2p across hosts; a copy between hosts adds the transfer of about 3 GB.

If the refilled node is a follower's only L1 source, the follower may have halted with exit 3 (P3): restart it once after the node shows the common finalized root.

### 6.2 L2 side

| Loss | Recovery | Time measured |
| --- | --- | --- |
| Follower host | Reinstall (P3) and replay from L1 | 57 min to e6596, about 75 min today |
| Settled RPC view | Restart; it rebuilds the view | 0.8 s (small L2) |
| Settler database | **Never back up or restore `canonical/` or `work/`.** Rebuild from L1 with `produce-dev reconstruct --l1-follower`, then re-spool from the pre-restore `work/` (`docs/L2-OPERATOR-RUNBOOK.md` entry 13 on `codex/recovery-r6-20261102`). An old backup halts the worker at once (`L2 head N cannot extend accepted settlement M`); no double spend and no fork, but user transactions of the unsettled block are dropped and one DA fee is lost. This build's `l2_reorg_recover.py` `7c918bb7…` can rebuild a database behind the accepted head once the follower has finalized that settlement (agent 118). | 0.16 s rebuild (3 blocks) |
| DA fee key | New key, fund it, restart with the same paths; the old key's balance is lost. Hence the separate backups in P6 | 6 s funding |
| Prover host | Reinstall P5 and prove the next block | 11–28 min plus install (not run) |
