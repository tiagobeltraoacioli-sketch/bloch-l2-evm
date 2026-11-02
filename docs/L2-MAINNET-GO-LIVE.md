# Bloch L2 mainnet (chain 700770): go-live plan for the v2.1 build

Status: **plan only, updated for v2.1 on 2026-10-30 (L1 epoch ~7030).** Nothing in this document has been installed,
started or broadcast. Every step that writes to a public chain is marked **MAINNET WRITE**, and every
step that installs or starts something on a host is for the owner to run.

This plan replaces the 2026-10-19 owner runbooks. Their binaries were built before the hard forks and
**halt at HF1 (epoch 7180)**. Do not open or install from them: every command an operator needs is in this document, in English.

Kit source: `~/worktrees/go-live-fixes-r4-20261101`, branch `codex/go-live-fixes-r4-20261101`, on the owner's Mac. It is the v2.1 kit (`7531526`) plus the installer fixes of §3.5. No v2.1 release artifact differs. Operator packages for P10 come from another branch: see P10.

**What v2.1 changes from v2:** a new `bloch-l2-settled-rpc` with the spool and simulation limits and
the receipt/`latest` fix; an nginx gateway on our own hosts that replaces the Cloudflare Worker (P11);
kit gaps K1, K2 and K6 closed; one pinned settlement-recovery lock (`26bf4453…`). The follower, the
producer, the guest, the program identity and the activation do not change.

Related documents:

- `deployment/mainnet/SETTLER-RUNBOOK.md`: settler worker and installer.
- `deployment/mainnet/follower-rpc/install.sh`: follower and settled-RPC units.
- `deployment/mainnet/attestor/README.md`: attestor kit.
- `deployment/mainnet/public-rpc/README.md`: the public RPC gateway.
- `docs/L2-HARD-FORK-OPERATOR-STEPS.md`: the L2 across HF1/HF2/HF3.
- `docs/MAINNET-OPS-RUNBOOK.md`: the monitor and its thresholds.
- `docs/L2-OPERATOR-RUNBOOK.md`: what to do per failure.
- `docs/MAINNET-EXCHANGE-INTEGRATION.md`: exchange-facing behaviour.

## 0. Where things stand (read-only checks, 2026-10-30 22:06 UTC)

- **L1.** All three L2-facing RPCs (80.240.16.185, 199.247.22.8 and 45.77.67.251, port 8080) are at
  height 186552, epoch 7022, finalized epoch 7020, with the same finalized root `d65248bb…11ba`.
  - `getchaininfo.hard_forks` lists HF1 7180/7180/7186, HF2 7270 ×4, HF3 7360 ×3 and KES enforce 8620,
    all `active: false`.
  - The RPCs now refuse requests without `Content-Type: application/json`. Every `curl` below sets it.
- **L2.** It is activated (e5850, slot 187200) but has **never been settled**. `getl2settlement`
  returns `accepted: null` with source height 1, slot 187200. The L2 head is the genesis
  `632e45ae…f468`. No production L2 unit, user or directory exists on any host.
- **Hosts.**

  | Host | vCPU | RAM | Free disk | Notes |
  | --- | --- | --- | --- | --- |
  | 136.244.93.186 | 32 (Cascade Lake) | 125 GiB, 123 GiB available | 2.7 TB | Idle. No `bloch-l2*` units. The pinned gnark image `e1a1cd62…` is present. The 10-19 staging dir `~/l2-mainnet-install-20261019` is present, including the SP1 circuits (7.9 GB). |
  | 45.77.142.123 | 32 | 125 GiB | 2.2 TB | Shared build host. It still runs the 10-18 scratch follower and RPC (127.0.0.1:19145, pre-HF build, PIDs 1304666 and 1452988). The unsigned v2.1 release is in `~/l2dexbridge-20261030/l2-close-r3/release/bloch-l2-2026-10-30-v21-native-78d4921c`. `manifest` and `carryover` come from `~/hf-release-kit-20261020/l2-agents/07-rpc/artifacts`. |

## 1. Owner decisions (all open)

Nothing marked here may be filled in by an operator or an agent. `TBD-owner` means the owner supplies
the value.

| # | Decision | Recommendation | Blocks phase |
| --- | --- | --- | --- |
| **D1** | Go-live start epoch | Not before G0 (§4) holds. Earliest e7365 (2026-11-03 17:31 UTC). Recommended **e7450 (2026-11-04 16:11 UTC)**, after one full day (90 epochs) of clean finality following HF3. | all |
| **D2** | **Prover host** | While user transactions are off, 136.244.93.186 co-located with the settler works (blocks are empty or deposit-only). Before user transactions (D10), a dedicated prover host is recommended: the worst-case caps do not fit on 136 (§2). `TBD-owner`. | P5, D10 |
| **D3** | Follower B / replica RPC host | 45.77.142.123 works (light load) but it is the shared build host. Recommended: a small dedicated VPS (§2, "follower B"). `TBD-owner`. | P3, P4, P11 |
| **D4** | L1 RPC each follower reads | A → 80.240.16.185, B → 199.247.22.8 (different sources on purpose). | P3 |
| **D5** | **Attestor operators**: five people, five hosts, one index each, plus each operator's feed URL | `TBD-owner` (none chosen). No operator may hold more than one key or share a host with a validator, the settler or another attestor. | P10 |
| **D6** | **Bloch Inc addresses** | **None is needed for the L2 core.** L2 fees go to the predeploy `0x4200…0011`, settlements pay no L1 fee, and the DA key is generated on the host. Still `TBD-owner`: (a) the L1 wallet that funds the DA key (5 BLCH, only when user transactions are enabled); (b) the L1 wallet and L2 recipient for the test deposit and test withdrawal; (c) the Bloch Inc Safe and bridge guardian addresses, which the DEX and bridge need later. Those are not part of this plan. | P12 |
| **D7** | Release signature | Sign the reproducible release `bloch-l2-2026-10-30-v21-native-78d4921c` (its `SHA256SUMS` has SHA-256 `dded10b9b49a862d1b31f0667b945016b5da54e6c497eba123c42b32e0cd11f9`) with the owner's minisign key, after G0 gate 7 holds (an open item may change a binary and so the target) and before any install. `TBD-owner` key. | P2 |
| **D8** | Retire the 10-18 scratch follower/RPC on 45.77 (they halt at HF1 anyway) | Stop them before or at G0. PIDs change after a restart, so first confirm with `ps -o pid,cmd -p 1452988,1304666` that they are the scratch follower and RPC, then the owner runs `kill 1452988 1304666`. | none (hygiene) |
| **D9** | Public gateway | `l2rpc.blochl1.com` through the nginx + njs gateway on A and B (`deployment/mainnet/public-rpc/`). The Worker of `codex/l2-mainnet-public-20261019` is retired: do not deploy it. CORS is open to any origin (decided 2026-10-30). Still open: DNS timing, and origin failover: one proxied A record with a manual switch to B (default), or paid Cloudflare Load Balancing. `TBD-owner`. | P11 |
| **D10** | When to enable user transactions | Only after the P12 deposit test, the DA rehearsal R2, the gas-heavy measurement, the stuck-block rehearsal (§3.4) and the next RPC build (D14). `18be911a…` does not carry `9b8aaef`. Until then deposits mint on the L2 but nobody can transact or withdraw. | P12 |
| **D11** | Alert channel for the monitor | `TBD-owner`. | P9 |
| **D13** | L2 finding F1 (timestamp and prevrandao not bound in the guest) | Do not delay block 1. Start with a deposit cap and a bridge value the owner would accept seeing frozen during an emergency fork. | P8, P12 |
| **D14** | Adopt `9b8aaef` (clock step and `.partial` sweep fix, not in v2.1) | Yes, in the next RPC build, before user transactions. D10 depends on it. | D10 |
| **D12** | DA signer `bloch-pos` | Use the 78d4921c `bloch-pos` (`700631b0…`), which `install-settler-mainnet.py` now enforces. It only generates and signs for the DA key; it judges no consensus. It has no `signature-forms` command, so the settler uses the v1 DA form (R2). Do not pin the `codex/hf-l2-compat-20261020` signer (its `--for-epoch` form is likely refused after HF2). | P6 |

## 2. Host specification per role

Measured numbers (sources: l2-agents reports 03, 05, 06, 07 of 2026-10-28 and the prover installer's
own measurement of 2026-10-18):

- **Native follower.** Peak RSS 602 MB on an offline replay of 174,031 blocks and 594 MB live. It uses
  about one core.
  - Replay from Genesis-4: 57 min 11 s offline; 46.0 min re-verify on restart, plus 58 s genesis
    load. A fresh install also fetches all blocks first: about 10 min for 180k blocks, about 65 min
    in total for 181k.
  - The native state is 3.1–3.3 GB at 174–181k blocks, about 18 KB per block. At about 2,400 blocks
    per day that is about 45 MB per day.
- **Producer.** `reconstruct` over 181k blocks: 4.4 s and 107 MB. `rebuild-check`: about 2.5 s and 110 MB.
- **Prover (SP1).** Peak RSS grows with block size, at 8 threads (2026-10-30, report 05):

  | Block | Instructions | Peak RSS | Proof time |
  | --- | ---: | ---: | ---: |
  | empty | 0.53M | 20.4 GiB | 11 min |
  | 1 deposit, 4 transfers, 1 withdrawal | 1.57M | 25.5 GiB | 13 min |
  | 1 deposit, 50 transfers | 8.86M | 45.2 GiB | 16 min |
  | 1 deposit, 200 transfers | 33.6M | 96.5 GiB | 28 min |

  A 40 GiB slice holds only about 38 transfers. The kit defaults are now `--memory-gib 100 --threads 24`
  and `max_block_txs` 128. A 128-transfer block is about 22M instructions and **about 72 GiB by
  extrapolation; it has not been proved.** No block above 5.3M instructions has been proved at 24 threads.
- **gnark Groth16 container.** About 18.5 GB, under dockerd, outside every slice. The installer
  requires 20 GiB of headroom above the prover slice.
- **Settler unit.** `MemoryMax=32G`. It runs execute and verify, and a local proof only if the remote
  prover fails and the block's `execute` count is at most `local_prove_max_instructions` (3,000,000;
  32 GiB is about 4M). Larger blocks log `local-proof-refused` and wait for the prover.
- **Unit caps.** Follower 6 G with `CPUQuota=200%`. Settled RPC 4 G. Shadow 4 G with
  `CPUQuota=400%`.

At the recommended start (e7450) L1 holds about 198k blocks. Plan for **about 55–65 min to re-verify
on restart and about 65–80 min for a fresh install**, more on a busy host.

| Role | Host | vCPU | RAM | Disk (SSD) | Memory budget |
| --- | --- | --- | --- | --- | --- |
| **A: settler + prover + follower A + RPC A + shadow + monitor + nginx origin** (user transactions off) | 136.244.93.186 (D2) | **32** (min 24) | **125 GiB** (136's real size) | **≥ 200 GB** (circuits 7.9 GB, settler about 50 GB, follower about 3.5 GB growing about 16 GB a year, Docker). 136 has 2.7 TB. | See the cap check below. |
| **Dedicated prover** (recommended before D10) | `TBD-owner` | **32** (24 threads in the slice) | **128 GB** (100 G slice + 18.5 G gnark outside it + OS) | ≥ 200 GB NVMe, Docker | 118.5 G worst case |
| Settler alone (prover remote) | 136 | 8 | 32 GB, or 56 GB if the local proof fallback stays enabled (32 G unit + about 20 G gnark) | ≥ 100 GB | |
| **B: follower B + replica RPC + nginx origin** | 45.77.142.123 or a dedicated VPS (D3) | **4** | **8 GB** | **≥ 80 GB** | Follower 6 G cap (0.6 GB used) + RPC 4 G cap. Replica rebuild about 110 MB. |
| **Attestor host** (×5, one per operator; **inbound TCP 8787 open to everyone** for the read-only feed) | `TBD-owner` (D5) | **4** (kit minimum 2) | **8 GB** | **≥ 80 GB** (kit minimum 40 GB) | Follower 0.6 GB + rebuild-check 0.1 GB + `bloch-pos` signing |
| Monitor | runs on A (and optionally on B) | n/a | < 50 MB | n/a | |

**Cap check for all roles on 136 (125 GiB; the prover's `--memory-gib 100`, gnark 18.5 GiB outside the prover cgroup):**

| Case | Sum | Fits 125 GiB? |
| --- | ---: | --- |
| All caps at once: prover 100 + gnark 18.5 + settler 32 + follower 6 + RPC 4 + shadow 4 | 164.5 GiB | **No, over by 39.5** |
| Proofs are serial, so the settler holds about 2 GiB while the prover runs: 100 + 18.5 + 2 + 14 | 134.5 GiB | **No, over by 9.5** |
| As above, with gnark not overlapping the prover's peak (one measurement: 200 transfers, 96.5 GiB RSS, 92.0 GiB host drop) | 116 GiB | Yes, by 9, on that single observation |
| Expected at full transfer load: about 72 + 3 | about 75 GiB | Yes, extrapolated |
| Expected with user transactions off: 26 + 18.5 + 3 | under 50 GiB | Yes |

So the hard caps on 136 do not exclude a global OOM, the failure of the 2026-10-12 incident. Co-location is
acceptable while user transactions are off. A dedicated prover removes the overcommit: 118.5 GiB there, and
at most 64.5 GiB (settler fallback + gnark + follower + RPC + shadow) on 136.

The prover installer also requires MemAvailable ≥ cap + 20 GiB, that is 120 GiB for 100, which leaves little
room on 136 at P5. If it refuses, stop the settled RPC for the install rather than lowering the cap.

### Layout of host B

B runs the `deployment/mainnet/follower-rpc` units, not the replica kit, because the gateway (P11) reads its backend on 127.0.0.1:18955 and the replica kit serves 18965. B holds no settler, no key, no spool in use and no prover.

| Item | Value on B |
| --- | --- |
| Staged files | `/home/ubuntu/l2-golive-v2/artifacts` and `/home/ubuntu/l2-golive-v2/kit` |
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

## 3. Pins: the v2.1 build and what stays

### 3.1 v2.1 artifacts (L2 commit `a39b04e4`, native 78d4921c, valid for the fa980367 fleet)

Built twice from fresh trees and fresh targets at the reference WORK path
`/home/ubuntu/hf-release-kit-20261020/l2-78d4921c-v2` (a bind mount in a private mount namespace).
Both builds are byte-identical. Source: `45.77.142.123:~/l2dexbridge-20261030/l2-close-r3/release/bloch-l2-2026-10-30-v21-native-78d4921c/`.

| Artifact | SHA-256 | v2 | Used by (phase) |
| --- | --- | --- | --- |
| `bloch-l2-native-follower` | `c18752fd4c6942678bcb45d8d36436bcd644b1ee6e48416d67e4999e7c7cf29a` | unchanged, byte-identical | follower A, follower B (P3), attestor hosts (P10) |
| `bloch-l2-produce-dev` | `fb0d531311d4f19a97f0839968146f5737acf57eb313fc93972ec215de950be9` | **changed**, was `7c1cc62b…` (see below) | canonical DB init A/B (P3), settler release (P6), shadow (P7), replica rebuild B (P4), attestors (P10) |
| `bloch-l2-settled-rpc` | `18be911a47f0ab8975e1f079c860adef08dfc43c4b5062eca7b040e2e6eee83f` | **changed**, was `4fc9fa1e…` | RPC A, RPC B (P4) |
| `sequencer_mainnet.py` | `15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2` | unchanged | shadow (P7) |
| `build.json` | `b12ed2b6d643896f98c2792663de0cdf6779f6a5b613a2168b51c79decc03cb4` | changed | check `l2_commit` `a39b04e4`, `l1_activation_epochs` 7180/7180/7186/7270×4/7360×3/8620 and `l2_tracked_changes: 0` |
| `out/SHA256SUMS` | `c07531b7e92d05e356648815a43a8529ec15e6e2b30caaa856c0789ddc34da4b` | changed | Build output only. It is not in the release directory. `install.sh` checks the release `SHA256SUMS` below. |
| release `SHA256SUMS` (signing target, D7) | `dded10b9b49a862d1b31f0667b945016b5da54e6c497eba123c42b32e0cd11f9` | changed | owner signature |
| `NATIVE_LOCK` (settlement-recovery, 78d4921c) | `26bf44539b996809bd75164a488d8a30137507716d06990721056a213364aef8` | unchanged | rebuilds. Committed as `deployment/mainnet/follower-rpc/settlement-recovery.native-78d4921c.Cargo.lock`, and `build-release.sh` refuses any other lock for this native commit. |

Why the producer hash changed: `reconstruct` now numbers follower blocks on the L2 registry's count. Before this fix, the first settled deposit made every rebuild fail with `Deposits`. A block built by `extend` is unchanged: v2 and v2.1 produce the same hash and state root for the same inputs (one comparison, an empty block on a synthetic anchor). The guest and the consensus code are not touched.

To reproduce: check out L2 `a39b04e435b11bd2316dffe94d78df0163153c56`, native 78d4921c and reth 8eb21017 plus
`reth-snapshot.patch`, then run `build-release.sh` at the WORK path above. A different WORK path gives
different hashes, because cargo hashes the absolute paths of the native path dependencies.

### 3.2 Pins that do not change (the HF forks do not touch the guest, the proof or the settlement format)

The L2 source the guest compiles from has no diff against v2.

| Item | Value | Used by |
| --- | --- | --- |
| Guest `settlement_v3_mainnet` | `203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473` | settler, prover |
| Proof policy V3 | `154869964f…747d` | settler dry-run report |
| SP1 host `bloch-evm-sp1-settlement-v3` | `3a24c36d…973a` (the settler-v2 staging on 136). The file hash depends on the build path and is not the pin; the identity is. Earlier builds `617d191f…86b3` and `505500af…aa07` print the same `--mainnet identity` (ELF keccak `6e4c8440…`, vkeys `389cfbde…` / `007139f7…`). | settler, prover |
| `remote_prover.py` | `3c11d9be0ee6c2abaaacd94768e90080ad89abad61428c29bb060d098141d8e5` (**the kit**; stops the prover on client disconnect. The v2 tree and the 10-19 staging hold the old `99bbc1bc…`, which must not be used) | prover |
| `settler_v3.py` | `3ddb260a1caaadb3f874d436282715900c640cb410a458ee94609ea1bf3fdfe4` (**the kit**; adds the local-proof limit and atomic state files. v2 `875f4cca…` and the settler-v2 staging on 136 must not be used) | settler |
| Settler `bloch-pos` (DA key only) | `700631b040a3a4b2299017162dd4a2c5f521bb49d5fa3c9ed677ba285673794e` (78d4921c; rebuilt with `--no-cache`, byte-identical). Enforced by `install-settler-mainnet.py`. | settler (D12) |
| `mainnet.manifest` | `7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd` | all |
| `carryover.tsv.gz` / `carryover.tsv` | `4d1e2738baec39ec25e2e33968f72a47abb261f271de62fb48a33be55bfc83be` / `84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6` | followers, attestors |
| `l2-config.bin` | 264 B, `292f4fa8…4f6b` (derived in code) | settler |
| gnark image | `ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d` | prover, settler fallback |
| SP1 circuits v6.1.0 | `groth16_vk.bin` `4388a21c…e696` (7.9 GB tree on 136) | prover, settler fallback |
| L2 genesis / state root | `632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468` / `2ad7e807…c05d` | all |
| Network pin / domain | `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966` / `1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733` | all |
| Attestor set | `1c06adbb…cc4b` (3-of-5); set file `9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0` | attestors |
| Attestor `bloch-pos` (signing only) | Linux build of bloch-sis-pow `codex/l2-attestor-keystore-20261019` e7d2c8b2. The rehearsal binary was `093909a2…`. The production hash is `TBD-owner` (recorded at build). | attestors |

### 3.3 Kit gaps found while writing this plan

| # | Gap | Effect | Fix | Phase |
| --- | --- | --- | --- | --- |
| K1 | **Closed in v2.1.** `install-shadow.sh` pinned the pre-HF RC producer `192eda33…`. | It now pins the v2.1 producer, and `--verify` also checks `SHA256SUMS` and `build.json` (commit, native, lock, genesis, gates). | Stage the kit from this branch. | P7 |
| K2 | **Closed in v2.1.** The attestor agent did not pin the follower binary (report 06). | `config.json` now carries `follower_sha256`, the agent checks it, and `install-attestor.sh upgrade` covers older configs. | Stage the kit from this branch. | P10 |
| K4 | `install.sh` prints "~155k blocks, 30–40 min" | Cosmetic. The real figure is in §2. | none | P3 |
| K5 | Replica B advances only by a manual `reconstruct`. `deployment/mainnet/replica/` has a refresh timer, but it serves port 18965 and the gateway reads 18955, so it is not used on B (§2) | B drops out of the gateway rotation when it is more than 16 blocks behind A. It never serves wrong data. | Run the P4 refresh after each finalized settlement until a timer exists. | P4, P11 |
| K6 | **Closed in v2.1.** The 8 `tests/ffg_recovery.rs` failures were stale fixtures, not a follower bug: the native genesis commitment changed, and the settlement wire tag moved from 0x0E to 0x12. | Fixtures regenerated against 78d4921c with a real proof. All 8 pass, and settlement-recovery passes 67 of 67. No library or follower code changed. The legacy WS-checkpoint store fails closed on current chains, the release follower does not use it, and it is retired (owner decision). | none | P6 |
| K10 | **Closed on the kit branch, §3.5.** `install-settler-mainnet.py` `16aba9b6…` called `runuser` with `PATH=/usr/bin:/bin`, so `configure` and `dry-run` failed on Ubuntu 24.04, with `config.json` already written. | The installer uses `/usr/sbin/runuser` and writes `config.json` only after its checks pass. | Stage the kit from the kit branch. | P6 |
| K11 | **Closed on the kit branch, §3.5.** The staging `release-prover/` holds `remote_prover.py` `99bbc1bc…` with a passing `SHA256SUMS`. | The prover installer pins the file, and P5 checks against `GO-LIVE-PINS-PROVER.sha256`. | P5. | P5 |
| K7 | `docs/L2-HARD-FORK-OPERATOR-STEPS.md` §4.2 step 2 still says to pin the compat-branch DA signer | Wrong for 78d4921c (report 05). | Follow D12. | P12 |
| K8 | The per-transaction gas limit in the settled RPC is a constant, 15,000,000, equal to the settler's `max_block_gas` | If `max_block_gas` is lowered without changing the constant, the spool squat reopens below it. | Do not lower `max_block_gas` without a new settled-RPC build. | P12 |
| K9 | A settler `extend` over a maximal spool needs about 1.5 GB RSS for about 5 s | Only relevant with user transactions on; the unit cap of 32 G covers it. | Keep it in mind when sizing a separate settler host. | P12 |

### 3.5 Which pins move for the kit fixes

Kit files only. **The signing target `dded10b9…` does not move**: the release `SHA256SUMS` lists BUILD-INFO, the three binaries, `build.json`, `release.json`, the sequencer and the lock, and no installer or kit file. `build.json`, `out/SHA256SUMS`, the guest, the identity and the build commit `a39b04e` do not move either.

| File | From | To | Why |
| --- | --- | --- | --- |
| `install-settler-mainnet.py` | `16aba9b60c1de6e71869bf90d4f3ab2e53132a64f11bbc5b27d86811fab8e37e` | `124a0bdabfa37c73ace27bfee27c4c8a942ac29a3c9922144343a4a5a2d22d96` | `runuser` path, configure retry, installs and pins the reorg tool |
| `prover/install-prover-mainnet.py` | `f0b847260e236527c13556bde2aa0b2955f20cd31e0a6b36d4bfaddf81434482` | `3f9fbb55576960e10187d5dc645af25e3c3174d7526df13854f229f7ec11d98b` | pins `remote_prover.py` |
| `l2_reorg_recover.py` | `d688e59fa61c93294f60778e2e9e19a6445c8f6f1ceb05bc03e327bbca645623` | `678482bfcd3c782b4b6dee2295572c283992f0e1927ea28393a11c1f6aec98b2` | stdout is exactly one JSON document |

New kit files, with no earlier pin: `l1_finality_history.py` (G0), `GO-LIVE-PINS.sha256`, `GO-LIVE-PINS-PROVER.sha256`.

### 3.4 Residual risks the go/no-go checks cover

- **R1. Real post-fork blocks.** No v2 follower has yet verified blocks produced under HF1/HF2/HF3. The
  forced-gate qualification could not cross real history. The **first real proof is P3**: a fresh
  replay after G0 crosses e7180, e7270 and e7360 on mainnet. Any halt there is an absolute no-go.
- **User transactions stay off (D10) until both of these are done:**
  - **Gas-heavy 15M blocks are unmeasured.** Every sizing number above is for transfers. `max_block_txs`
    does not bound cost: 5 contract transactions cost as much as about 30 transfers. Measure instructions
    for a real 15M-gas block with an execute-only run first.
  - **Stuck-block recovery is not rehearsed.** A block is committed before its proof. If the proof runs out
    of memory, the settler retries the same block and restarts indefinitely; settlement, deposits and
    withdrawals stop until an operator acts. No path shrinks or replaces a committed block. Rehearse
    proving a stuck block on a bigger machine and returning it to the settler.
- **R2. The DA signature after HF2** (relevant only when user transactions are enabled). The analysis
  says a v1 DA signature from the 78b7343a/78d4921c signer stays valid (`CompatiblePinned`). That was
  inferred from code, not tested. Before D10, rehearse one 0x15 on a **private** network running a
  78d4921c node with the gates forced into the past. Build it from a fresh build context and check
  that its `source_digest` differs from `35c2b943…`.

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
3. No finality stall since e7180. Run the command below against each of the three nodes. It reads every finished epoch's last block header and the block its `finalized_root` names. It takes one call per epoch or more. GO on exit 0 with `"ok": true`, `empty_epochs` empty and `over_limit` empty. The limit of 4 is the lag ≤ 3 of gate 2 plus 1, because a checkpoint with an empty first slot names an earlier block.
4. No L1 release after fa980367 changed a crate the L2 links (see `L2-HARD-FORK-OPERATOR-STEPS.md`
   §0). If one did, rebuild the L2 against it first: NO-GO with v2.1.
5. `getl2settlement`: `accepted` = `null`, source height 1, slot 187200, `profile.activated` true.
   Record `inbox` (expected `count` 0, `consumed` 0, `escrow_sat` "0"). If deposits arrived in the meantime, L2 block 1 will differ from
   `0ff59c11…ab25` and the P6 dry-run reference changes accordingly.
6. D1, D2, D3, D4, D13 and D7 are decided, and the v2.1 release is signed.
7. The items that block go-live in the owner's guide (`GO-LIVE-L2-PT.md` §1) have a result: the settlement-reorg procedure has been trained, and real proofs per height exist to set the cadence. If one required a binary change, the signing target changed: stop and re-pin first.

**NO-GO:** any HF entry not active, a finality lag > 3, nodes on different finalized roots, or an L1
hotfix pending. Wait, and re-run G0.

```
python3 ~/worktrees/go-live-fixes-r4-20261101/deployment/mainnet/l1_finality_history.py --rpc http://80.240.16.185:8080 --from-epoch 7180
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

## P2. Stage and verify the v2.1 release (no install)

1. Owner signs the release `SHA256SUMS` (D7) and keeps the `.minisig` with the release dir. After the copy in step 2, verify it on A with `minisign -Vm /home/ubuntu/l2-golive-v2/artifacts/SHA256SUMS -P <owner public key>`, and confirm that `sha256sum SHA256SUMS` prints `dded10b9…`. `minisign` is not installed by default.
2. Stage on A, from the Mac. Each command is one block.

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 mkdir -p l2-golive-v2/artifacts l2-golive-v2/release-settler-v2
```

```
scp -3 -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@45.77.142.123:l2dexbridge-20261030/l2-close-r3/release/bloch-l2-2026-10-30-v21-native-78d4921c/*' ubuntu@136.244.93.186:l2-golive-v2/artifacts/
```

```
scp -3 -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/carryover.tsv.gz*' ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/mainnet.manifest ubuntu@136.244.93.186:l2-golive-v2/artifacts/
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/go-live-fixes-r4-20261101/deployment/mainnet ubuntu@136.244.93.186:l2-golive-v2/kit
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/go-live-fixes-r4-20261101/deployment/devnet/settler_v3.py ubuntu@136.244.93.186:l2-golive-v2/release-settler-v2/
```

`scp -r` nests the tree inside `kit` if `kit` already exists, and the old files stay in use. On a second run, remove `l2-golive-v2/kit` first. The kit copy takes about 4 minutes over a long link.

Stage B the same way (D3, layout in §2). `B` below stands for its IP. Run the `mkdir`, the two `scp -3` and the kit `scp -r` with `ubuntu@B` as the destination, and check on B, which holds no settler directory:

```
cd /home/ubuntu/l2-golive-v2 && grep ' artifacts/' kit/GO-LIVE-PINS.sha256 | sha256sum -c
```

3. On A, check the release and assemble the settler release dir. `bloch-l2-produce-dev`, the kit
   installer and the settler come from this release. The guest, the SP1 host and the 78d4921c
   `bloch-pos` come from the settler-v2 staging on 136. The 10-19 staging is not usable: the installer
   refuses its `bloch-pos`.

```
cd /home/ubuntu/l2-golive-v2/artifacts && sha256sum -c --ignore-missing SHA256SUMS
```

```
cp /home/ubuntu/l2-golive-v2/artifacts/bloch-l2-produce-dev /home/ubuntu/l2-golive-v2/artifacts/mainnet.manifest /home/ubuntu/l2-golive-v2/kit/install-settler-mainnet.py /home/ubuntu/l2-golive-v2/kit/l2_reorg_recover.py /home/ubuntu/l2-golive-v2/release-settler-v2/
```

```
cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/settlement_v3_mainnet /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-pos /home/ubuntu/l2-golive-v2/release-settler-v2/
```

```
cd /home/ubuntu/l2-golive-v2 && sha256sum -c kit/GO-LIVE-PINS.sha256
```

```
bash /home/ubuntu/l2-golive-v2/kit/install-shadow.sh --verify /home/ubuntu/l2-golive-v2/artifacts
```

**GO when:**

- `SHA256SUMS` is OK.
- `install-shadow.sh --verify` prints `verify OK`.
- `sha256sum -c kit/GO-LIVE-PINS.sha256` exits 0 with every line `OK`. Those are the §3.1, §3.2 and §3.5 pins, in full. Before trusting the file, compare it: `sha256sum kit/GO-LIVE-PINS.sha256` must be `b8ac87cbc5ff7ad2c3b6b7ff3072a7912043379aa25e565b962667c3fe38323e`.
- `artifacts/build.json` shows `l2_commit` `a39b04e4`, `l2_tracked_changes: 0` and the HF epochs.

**NO-GO:** any mismatch. Re-copy from the build host. Never use `~/l2-mainnet-install-20261019/out-release`
or `release-settler/bloch-l2-produce-dev` (`3736860e…`, pre-HF), and never `4fc9fa1e…` (the settled RPC
with the spool squat).

Rollback: `rm -rf /home/ubuntu/l2-golive-v2` on A.

## P3. Follower A and follower B (first real crossing of HF1–HF3, R1)

### A (136)

Prerequisite: `install.sh` requires the settler user, the canonical DB and the txpool. So the settler
`prepare` (P6 step 1) runs first. It writes nothing to L1, but it **generates the DA fee key**: back it
up as in P6.

1. P6 step 1 (`prepare`), then the backup.
2. Canonical DB at the pinned genesis:

```
sudo install -D -m 0755 /home/ubuntu/l2-golive-v2/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev
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
sudo bash /home/ubuntu/l2-golive-v2/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-v2/artifacts --l1-rpc-url http://80.240.16.185:8080 --canonical /var/lib/bloch-l2-mainnet-settler/canonical --canonical-user bloch-l2-mainnet-settler --txpool /var/lib/bloch-l2-mainnet-settler/txpool --dry-run
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
sudo install -D -m 0755 /home/ubuntu/l2-golive-v2/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev
```

```
sudo runuser -u bloch-l2-mainnet-replica -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev init --target /var/lib/bloch-l2-mainnet-replica/canonical --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

Dry-run first, then the same command without `--dry-run`:

```
sudo bash /home/ubuntu/l2-golive-v2/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-v2/artifacts --l1-rpc-url http://199.247.22.8:8080 --canonical /var/lib/bloch-l2-mainnet-replica/canonical --canonical-user bloch-l2-mainnet-replica --txpool /var/lib/bloch-l2-mainnet-replica/txpool --dry-run
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

**NO-GO (stop the whole go-live):** any halt. It means the verifier disagrees with the L1 on a
post-fork block. Keep the state for analysis and do not skip a block.

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

GO when:

- `eth_chainId` is `0xab162`;
- `finalized` and `safe` are block 0, `0x632e45ae…f468`;
- `bloch_finality` shows `l2_genesis.finalized: true` with activation `618c9b80…` at slot 187200, and `status.state: ok` with a small `age_s`;
- `systemctl show -p ExecStart bloch-l2-mainnet-rpc` has no `--txpool`.

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

**Do not install from the settler-v2 staging `release-prover/`.** It holds the forbidden `remote_prover.py` `99bbc1bc…` and the old installer `ed9a001d…`, and its own `SHA256SUMS` passes. That `SHA256SUMS` proves nothing. Two checks reject a wrong file: the pin file below, and the installer, which refuses any `remote_prover.py` but `3c11d9be…`. Assemble a new directory. The host and the guest come from the staging, the installer from the kit. `remote_prover.py` is under `deployment/devnet`, outside the P2 kit copy, so copy it from the Mac first:

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/go-live-fixes-r4-20261101/deployment/devnet/remote_prover.py ubuntu@136.244.93.186:l2-golive-v2/
```

```
mkdir -p /home/ubuntu/l2-golive-v2/release-prover-v2
```

```
cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/settlement_v3_mainnet /home/ubuntu/l2-golive-v2/kit/prover/install-prover-mainnet.py /home/ubuntu/l2-golive-v2/remote_prover.py /home/ubuntu/l2-golive-v2/release-prover-v2/
```

```
cd /home/ubuntu/l2-golive-v2 && sha256sum -c kit/GO-LIVE-PINS-PROVER.sha256 && cd release-prover-v2 && sha256sum bloch-evm-sp1-settlement-v3 settlement_v3_mainnet remote_prover.py > SHA256SUMS
```

GO only if that exits 0 with four `OK` lines. `SHA256SUMS` is written only after they pass. On any `FAILED`: NO-GO, and do not write `SHA256SUMS` by hand.

Install after the settler `configure` (P6 step 2) has created the settler SSH key. Dry-run first, then the same
command without `--dry-run`:

```
sudo python3 /home/ubuntu/l2-golive-v2/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /var/lib/bloch-l2-mainnet-settler/ssh/id_ed25519.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 24 --dry-run
```

GO when:

- the dry-run prints `memory_ok: true`, the identity equals the pins (ELF keccak `6e4c8440…`, policy
  `154869964f…747d`) and the slice is 100 G / 24 threads;
- `authorized_keys` ends in `bloch-l2-mainnet-settler` with `from="127.0.0.1"`;
- the `sha256` block shows `remote_prover.py` `3c11d9be…`.

NO-GO: an identity mismatch, `remote_prover.py is … not the pinned …`, or MemAvailable < 120 GiB.

Rollback (refuses while a proof runs):

```
sudo python3 /home/ubuntu/l2-golive-v2/release-prover-v2/install-prover-mainnet.py rollback
```

## P6. Settler: prepare, configure, dry-run, then dry-run with the proof

1. **prepare** (local only; creates the DA key; done during P3):

```
sudo python3 /home/ubuntu/l2-golive-v2/release-settler-v2/install-settler-mainnet.py prepare --release /home/ubuntu/l2-golive-v2/release-settler-v2
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
sudo python3 /home/ubuntu/l2-golive-v2/release-settler-v2/install-settler-mainnet.py configure --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub
```

   GO (the state root is in `dry-run-*/work/*/block.json`, not in the printed report):
   - the last line is `{"configured": "/etc/bloch-l2-mainnet-settler/config.json"}`;
   - `rpc-check` `ok: true` (3/3 same view, quorum 2);
   - dry-run `ok: true`, identity checked (mainnet, async, activated, attestor set);
   - with an empty inbox: L2 block 1 = `0ff59c1194f6d81be26dc288e4ba9bb721e46181787f3f9cffb0b029b281ab25`,
     state root `8a1c475a…136c`, SP1 execute matched.

3. Then P5 (prover install), then **dry-run with the Groth16 proof** (about 5–15 min for this empty block, about
   20 GiB prover RSS plus 18.5 GiB gnark):

```
sudo python3 /home/ubuntu/l2-golive-v2/release-settler-v2/install-settler-mainnet.py dry-run --prove
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
sudo bash /home/ubuntu/l2-golive-v2/kit/install-shadow.sh /home/ubuntu/l2-golive-v2/artifacts --start
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
sudo bash /home/ubuntu/l2-golive-v2/kit/install-shadow.sh --rollback
```

## P8. Settler live: first settlement (L2 block 1) — **MAINNET WRITE**

Preconditions: P3 to P7 all GO on the same day. G0 re-checked within the last hour. Only one settler
exists anywhere.

```
sudo python3 /home/ubuntu/l2-golive-v2/release-settler-v2/install-settler-mainnet.py start --confirm-mainnet
```

```
journalctl -u bloch-l2-mainnet-settler.service -f -o cat
```

Expected, in order: `identity-checked` (mainnet true), `l2-block-produced` 1, `proof-generated`,
`remote-proof` with exit code 0, `transaction-built`, `submitted`, `accepted`. The worker then starts block 2 at once.

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
sudo install -D -m 0644 /home/ubuntu/l2-golive-v2/kit/l2_monitor.py /opt/bloch/l2-monitor/l2_monitor.py
```

```
sudo install -d -m 0755 /etc/bloch-l2-monitor
```

```
sed -e 's/--phase prelaunch/--phase live/' -e 's# --l2-rpc B=http://TBD-owner:18955##' /home/ubuntu/l2-golive-v2/kit/monitor/monitor.env.example | sudo tee /etc/bloch-l2-monitor/monitor.env
```

Write the D11 targets into `/etc/bloch-l2-monitor/alert.json`, starting from `kit/monitor/alert.json.example`. Until D11 is decided, use the example unchanged: alerts are not delivered and the WARN `alert_delivery` is expected.

```
sudo install -m 0644 /home/ubuntu/l2-golive-v2/kit/monitor/alert.json.example /etc/bloch-l2-monitor/alert.json
```

```
sudo install -m 0644 /home/ubuntu/l2-golive-v2/kit/monitor/bloch-l2-mainnet-monitor.service /home/ubuntu/l2-golive-v2/kit/monitor/bloch-l2-mainnet-monitor.timer /etc/systemd/system/
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
python3 /home/ubuntu/l2-golive-v2/kit/l2_monitor.py --profile mainnet --phase live --l2-rpc A=http://127.0.0.1:18955 --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://45.77.67.251:8080 --follower-status A=/var/lib/bloch-l2-mainnet-follower/status.json --unit settler=bloch-l2-mainnet-settler.service --unit shadow=bloch-l2-mainnet-shadow.service --binary /opt/bloch/l2-mainnet/bloch-l2-settled-rpc --build-json /home/ubuntu/l2-golive-v2/artifacts/build.json --json
```

GO, after the first L2 finalization: exit 0, or 1 with only the expected WARN `alert_delivery` before D11. Between P8 and that
finalization, `--phase live` exits 2 with `l2_finalized_age` CRIT, because the finalized block is still the old genesis. That CRIT alone is expected.
Before P8, use `--phase prelaunch`; there `unit[settler]` is CRIT until the unit exists. A CRIT on `--binary` means an installed binary is not the v2.1 pin. Thresholds:
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
   - `bloch-l2-native-follower` `c18752fd…` and `bloch-l2-produce-dev` `fb0d5313…`;
   - the attestor `bloch-pos` (e7d2c8b2 Linux build; `keykit/operator-pins-v2.sha256` pins `093909a2…`, owner to confirm);
   - `mainnet.manifest`, `carryover.tsv.gz` and `.sha256`;
   - `SHA256SUMS` over the three binaries;
   - the kit `deployment/mainnet/attestor` from `codex/attestor-packages-r4-20261101` ff839ba, not from the kit branch of this plan: the kit at `7531526` leaves operators publishing nothing.

   Not the RC binaries `821289e0…` / `192eda33…`: they halt.
3. `check-operator-bundle.sh --open`, then `install-attestor.sh install … --l1-rpc-url <D4-style L1 RPC>`.
   The installer pins the follower in `config.json` (K2). As operator root, also compare the files:

```
sha256sum /opt/bloch/l2-attestor/bloch-l2-native-follower /opt/bloch/l2-attestor/bloch-l2-produce-dev
```

   Pass `--feed-port 8787`, open inbound TCP 8787, and enable `bloch-l2-attestor-feed`. Build the operator packages from `codex/attestor-packages-r4-20261101`: the agent's re-sign on an oversized signature is in its scripts, and `IDENTITY.txt` records the kit commit.
4. Start the follower and wait about 65–80 min. Then run `attestor_agent.py check`, then start the
   agent. Fresh installs may run in parallel: there is no existing quorum to protect.

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

`setup-gateway.sh` renders with CORS open to any origin and `--backend-conns 400`, which is correct
for settled RPC v2.1. The `plan` command only renders, and it exits 0 even when it prints `MISSING:` lines, so read its output. `apply` installs.

On A:

```
sudo ROLE=sequencer NAME=l2rpc-a PEER=45.77.142.123:18956 PEER_ALLOW=45.77.142.123 bash /home/ubuntu/l2-golive-v2/kit/public-rpc/setup-gateway.sh plan
```

```
sudo ROLE=sequencer NAME=l2rpc-a PEER=45.77.142.123:18956 PEER_ALLOW=45.77.142.123 bash /home/ubuntu/l2-golive-v2/kit/public-rpc/setup-gateway.sh apply
```

On B (the commands assume 45.77; for a D3 VPS use its IP in both hosts' `PEER` and `PEER_ALLOW`):

```
sudo ROLE=replica NAME=l2rpc-b PEER=136.244.93.186:18956 PEER_ALLOW=136.244.93.186 bash /home/ubuntu/l2-golive-v2/kit/public-rpc/setup-gateway.sh plan
```

```
sudo ROLE=replica NAME=l2rpc-b PEER=136.244.93.186:18956 PEER_ALLOW=136.244.93.186 bash /home/ubuntu/l2-golive-v2/kit/public-rpc/setup-gateway.sh apply
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
sudo PEER_ALLOW=45.77.142.123 bash /home/ubuntu/l2-golive-v2/kit/public-rpc/setup-gateway.sh rollback
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
2. **Enable user transactions (D10).** Only after:
   - the deposit block is finalized;
   - R2 has been rehearsed on a private network;
   - gas-heavy 15M blocks have been measured and stuck-block recovery has been rehearsed (§3.4);
   - the DA key is funded (5 BLCH in two outputs to `da_funding_script_hash`, from the D6(a) wallet);
   - replica B has been rebuilt from L1 DA (K5);
   - the next RPC build is installed (D14).

   With the txpool on, the settled RPC enforces the v2.1 limits (§3.3 K8; `docs/MAINNET-RPC-READINESS.md` R7).

   Then, on A, one command per block:

```
sudo python3 -c "import json;p='/etc/bloch-l2-mainnet-settler/config.json';c=json.load(open(p));c['user_transactions']=True;json.dump(c,open(p,'w'),indent=2)"
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
3. **Withdrawal test.** The v2.1 settled RPC has no `bloch_getWithdrawalProof`, which the withdraw tool needs, so this step waits for the next RPC build and for an L1 claim shown with the tool. Withdraw 0.5 BLCH (under 100 BLCH, so no attestors are needed) from the test
   L2 address.

   GO:
   - the 0x15 DA record and the settlement are accepted;
   - after FFG finality + 64 blocks, `l2-claim prepare/sign` succeeds and the L1 output appears;
   - `claims_vs_withdrawn` is OK.

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

Do not resend earlier notices about a pause in claims across HF1: they are historical by then. State that the L2 is live with deposits. Announce transfers only once D10 is done, and withdrawals only once the P12 step 3 is GO. When you announce withdrawals, state that claims of 100 BLCH or
more need 3-of-5 attestation and 2,880 blocks, and the release window limits.

Rollback: a correction notice. The chain state is unaffected.

## 5. Timeline (assuming D1 = e7450)

| When (UTC) | Phase |
| --- | --- |
| Before 2026-11-03 | D2–D9 and D13 decided. No host changes. |
| After G0 gate 7, before P2 | Release v2.1 signed (D7). |
| 2026-11-03 16:11 (e7360) | HF3. Observe only. |
| 2026-11-04 16:11 (e7450) | G0, P1, P2 |
| +0:30 | P6 step 1 (prepare + DA key backup), P3 A and B start (replay about 65–80 min) |
| +2:00 | P3 go/no-go, P4 |
| +2:30 | P6 configure, P5, P6 dry-run `--prove` (about 20 min) |
| +3:15 | P7 shadow, then P8 (first settlement); finality about 1 h later |
| +4:30 | P9 monitor. L2 core live. |
| Day +1 to +3 | P10 attestors (about 65–80 min per host, in parallel), P11 gateway, P12 deposit test |
| After R2 + DA funding | P12 user transactions and the withdrawal test |
| After all GO | P13 exchange notice |
| Before e8620 (2026-11-17) | KES enforce. Settlement after a KES period change has not been exercised: have that result first. |
