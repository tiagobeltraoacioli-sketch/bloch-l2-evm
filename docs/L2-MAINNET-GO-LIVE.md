# Bloch L2 mainnet (chain 700770): go-live plan for the v2.1 build

Status: **plan only, updated for v2.1 on 2026-10-30 (L1 epoch ~7030).** Nothing in this document has been installed,
started or broadcast. Every step that writes to a public chain is marked **MAINNET WRITE**, and every
step that installs or starts something on a host is for the owner to run.

This plan supersedes the 2026-10-19 owner runbooks (`PASSOS.md`, `FOLLOWER-RPC.md`,
`ATESTADORES.md`, `DEPLOY-PUBLICO.md`). Those were built for native 78b7343a, the release before the
hard forks. Their follower, producer and settled-RPC binaries **halt at HF1 (epoch 7180)** and must not
be installed. Their structure (host roles, unit names, ports, paths) is kept. What changes is the
binaries, the start condition and a few kit pins (§3).

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
- `docs/MAINNET-EXCHANGE-INTEGRATION.md`: exchange-facing behaviour.

## 0. Where things stand (read-only checks, 2026-10-30 22:06 UTC)

- **L1.** All three L2-facing RPCs (80.240.16.185, 199.247.22.8 and 45.77.67.251, port 8080) are at
  height 186552, epoch 7022, finalized epoch 7020, with the same finalized root `d65248bb…11ba`.
  - `getchaininfo.hard_forks` lists HF1 7180/7180/7186, HF2 7270 ×4, HF3 7360 ×3 and KES enforce 8620,
    all `active: false`.
  - The RPCs now refuse requests without `Content-Type: application/json`. The `curl` lines in the
    10-19 runbooks lack that header and fail. Every `curl` below sets it.
- **L2.** It is activated (e5850, slot 187200) but has **never been settled**. `getl2settlement`
  returns `accepted: null` with source height 1, slot 187200. The L2 head is the genesis
  `632e45ae…f468`. No production L2 unit, user or directory exists on any host.
- **Hosts.**

  | Host | vCPU | RAM | Free disk | Notes |
  | --- | --- | --- | --- | --- |
  | 136.244.93.186 | 32 (Cascade Lake) | 125 GiB, 123 GiB available | 2.7 TB | Idle. No `bloch-l2*` units. The pinned gnark image `e1a1cd62…` is present. The 10-19 staging dir `~/l2-mainnet-install-20261019` is present, including the SP1 circuits (7.9 GB). |
  | 45.77.142.123 | 32 | 125 GiB | 2.2 TB | Shared build host. It still runs the 10-18 scratch follower and RPC (127.0.0.1:19145, pre-HF build, PIDs 1304666 and 1452988). The unsigned v2.1 release is in `~/l2dexbridge-20261030/l2-v21/release/bloch-l2-2026-10-30-v21-native-78d4921c`. `manifest` and `carryover` come from `~/hf-release-kit-20261020/l2-agents/07-rpc/artifacts`. |

## 1. Owner decisions (all open)

Nothing marked here may be filled in by an operator or an agent. `TBD-owner` means the owner supplies
the value.

| # | Decision | Recommendation | Blocks phase |
| --- | --- | --- | --- |
| **D1** | Go-live start epoch | Not before G0 (§4) holds. Earliest e7365 (2026-11-03 17:31 UTC). Recommended **e7450 (2026-11-04 16:11 UTC)**, after one full day (90 epochs) of clean finality following HF3. | all |
| **D2** | **Prover host** | While user transactions are off, 136.244.93.186 co-located with the settler works (blocks are empty or deposit-only). Before user transactions (D10), a dedicated prover host is recommended: the worst-case caps do not fit on 136 (§2). `TBD-owner`. | P5, D10 |
| **D3** | Follower B / replica RPC host | 45.77.142.123 works (light load) but it is the shared build host. Recommended: a small dedicated VPS (§2, "follower B"). `TBD-owner`. | P3, P4, P11 |
| **D4** | L1 RPC each follower reads | A → 80.240.16.185, B → 199.247.22.8 (different sources on purpose). | P3 |
| **D5** | **Attestor operators**: five people, five hosts, one index each, plus the publish URL and token for partials | `TBD-owner` (none chosen). No operator may hold more than one key or share a host with a validator, the settler or another attestor. | P10 |
| **D6** | **Bloch Inc addresses** | **None is needed for the L2 core.** L2 fees go to the predeploy `0x4200…0011`, settlements pay no L1 fee, and the DA key is generated on the host. Still `TBD-owner`: (a) the L1 wallet that funds the DA key (5 BLCH, only when user transactions are enabled); (b) the L1 wallet and L2 recipient for the test deposit and test withdrawal; (c) the Bloch Inc Safe and bridge guardian addresses, which the DEX and bridge need later. Those are not part of this plan. | P12 |
| **D7** | Release signature | Sign the reproducible release `bloch-l2-2026-10-30-v21-native-78d4921c` (its `SHA256SUMS` has SHA-256 `c2a55ba8e179585ea84f22d6e45f1e2f2c55215243585bf1b3eabc8425fa325c`) with the owner's minisign key before any install. `TBD-owner` key. | P2 |
| **D8** | Retire the 10-18 scratch follower/RPC on 45.77 (they halt at HF1 anyway) | Stop them before or at G0. The owner runs `kill 1452988 1304666`. | none (hygiene) |
| **D9** | Public gateway | `l2rpc.blochl1.com` through the nginx + njs gateway on A and B (`deployment/mainnet/public-rpc/`). The Worker of `codex/l2-mainnet-public-20261019` is retired: do not deploy it. CORS is open to any origin (decided 2026-10-30). Still open: DNS timing, and origin failover: one proxied A record with a manual switch to B (default), or paid Cloudflare Load Balancing. `TBD-owner`. | P11 |
| **D10** | When to enable user transactions | Only after the P12 deposit test, the DA rehearsal R2, the gas-heavy measurement and the stuck-block rehearsal (§3.4). Until then deposits mint on the L2 but nobody can transact or withdraw. | P12 |
| **D11** | Alert channel for the monitor | `TBD-owner`. | P9 |
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
| **Attestor host** (×5, one per operator) | `TBD-owner` (D5) | **4** (kit minimum 2) | **8 GB** | **≥ 80 GB** (kit minimum 40 GB) | Follower 0.6 GB + rebuild-check 0.1 GB + `bloch-pos` signing |
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

Rule from the 2026-10-12 incident: never run validators on host A while the settler and prover run.
The 30 `bloch-expansion@` units on 136 are disabled and must stay so.

## 3. Pins: the v2.1 build and what stays

### 3.1 v2.1 artifacts (L2 commit `18b9e1d1`, native 78d4921c, valid for the fa980367 fleet)

Built twice from fresh trees and fresh targets at the reference WORK path
`/home/ubuntu/hf-release-kit-20261020/l2-78d4921c-v2` (a bind mount in a private mount namespace).
Both builds are byte-identical. Source: `45.77.142.123:~/l2dexbridge-20261030/l2-v21/release/bloch-l2-2026-10-30-v21-native-78d4921c/`.

| Artifact | SHA-256 | v2 | Used by (phase) |
| --- | --- | --- | --- |
| `bloch-l2-native-follower` | `c18752fd4c6942678bcb45d8d36436bcd644b1ee6e48416d67e4999e7c7cf29a` | unchanged, byte-identical | follower A, follower B (P3), attestor hosts (P10) |
| `bloch-l2-produce-dev` | `fb0d531311d4f19a97f0839968146f5737acf57eb313fc93972ec215de950be9` | **changed**, was `7c1cc62b…` (see below) | canonical DB init A/B (P3), settler release (P6), shadow (P7), replica rebuild B (P4), attestors (P10) |
| `bloch-l2-settled-rpc` | `1e76b99ad2a57dd6cfae1f4086529714d1bf3372cb578a348f4cfe9a37a91d38` | **changed**, was `4fc9fa1e…` | RPC A, RPC B (P4) |
| `sequencer_mainnet.py` | `15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2` | unchanged | shadow (P7) |
| `build.json` | `7baba441dba3adf9b24d4c90344d3a1fdea1b7b52c85126e64d58c64ec25c1a0` | changed | check `l2_commit` `18b9e1d1`, `l1_activation_epochs` 7180/7180/7186/7270×4/7360×3/8620 and `l2_tracked_changes: 0` |
| `out/SHA256SUMS` | `0f3fae169e493df000c5fda7f476202bf6366ec4c4459efeec55eec2339ce0cd` | changed | install.sh `sha256sum -c` |
| release `SHA256SUMS` (signing target, D7) | `c2a55ba8e179585ea84f22d6e45f1e2f2c55215243585bf1b3eabc8425fa325c` | changed | owner signature |
| `NATIVE_LOCK` (settlement-recovery, 78d4921c) | `26bf44539b996809bd75164a488d8a30137507716d06990721056a213364aef8` | unchanged | rebuilds. Committed as `deployment/mainnet/follower-rpc/settlement-recovery.native-78d4921c.Cargo.lock`, and `build-release.sh` refuses any other lock for this native commit. |

Why the producer hash changed: `reconstruct` now numbers follower blocks on the L2 registry's count. Before this fix, the first settled deposit made every rebuild fail with `Deposits`. A block built by `extend` is unchanged: v2 and v2.1 produce the same hash and state root for the same inputs (one comparison, an empty block on a synthetic anchor). The guest and the consensus code are not touched.

To reproduce: check out L2 `18b9e1d1645782b8c3cb2c095161f7649dd32d72`, native 78d4921c and reth 8eb21017 plus
`reth-snapshot.patch`, then run `build-release.sh` at the WORK path above. A different WORK path gives
different hashes, because cargo hashes the absolute paths of the native path dependencies.

### 3.2 Pins that do not change (the HF forks do not touch the guest, the proof or the settlement format)

The L2 source the guest compiles from has no diff against v2.

| Item | Value | Used by |
| --- | --- | --- |
| Guest `settlement_v3_mainnet` | `203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473` | settler, prover |
| Proof policy V3 | `154869964f…747d` | settler dry-run report |
| SP1 host `bloch-evm-sp1-settlement-v3` | `3a24c36d…973a` (the settler-v2 staging on 136). The file hash depends on the build path and is not the pin; the identity is. Earlier builds `617d191f…86b3` and `505500af…aa07` print the same `--mainnet identity` (ELF keccak `6e4c8440…`, vkeys `389cfbde…` / `007139f7…`). | settler, prover |
| `remote_prover.py` | `99bbc1bcec7db7cf3f56c361a6af6253e461d13ebab2ffc5a190df0fc2feb9bd` (same in the v2 tree and in the 10-19 staging) | prover |
| `settler_v3.py` | `8589d5e2bd8ddde7f2dff03f784e6a4e3095890a784c9222a0bdf058b90b3ef5` (**this branch**; adds the local-proof limit. v2 `875f4cca…` and the settler-v2 staging on 136 must not be used) | settler |
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
| K3 | 10-19 runbook `curl` lines lack `Content-Type` | The L1 RPC refuses them. | Use the commands in this document. | all |
| K4 | `install.sh` prints "~155k blocks, 30–40 min" | Cosmetic. The real figure is in §2. | none | P3 |
| K5 | Replica B's canonical DB advances only by a manual `reconstruct` (no timer) | B drops out of the gateway rotation when it is more than 16 blocks behind A. It never serves wrong data. | Run the P4 refresh after each finalized settlement until a timer exists. | P4, P11 |
| K6 | **Closed in v2.1.** The 8 `tests/ffg_recovery.rs` failures were stale fixtures, not a follower bug: the native genesis commitment changed, and the settlement wire tag moved from 0x0E to 0x12. | Fixtures regenerated against 78d4921c with a real proof. All 8 pass, and settlement-recovery passes 67 of 67. No library or follower code changed. The legacy WS-checkpoint store fails closed on current chains, the release follower does not use it, and it is retired (owner decision). | none | P6 |
| K7 | `docs/L2-HARD-FORK-OPERATOR-STEPS.md` §4.2 step 2 still says to pin the compat-branch DA signer | Wrong for 78d4921c (report 05). | Follow D12. | P12 |
| K8 | The per-transaction gas limit in the settled RPC is a constant, 15,000,000, equal to the settler's `max_block_gas` | If `max_block_gas` is lowered without changing the constant, the spool squat reopens below it. | Do not lower `max_block_gas` without a new settled-RPC build. | P12 |
| K9 | A settler `extend` over a maximal spool needs about 1.5 GB RSS for about 5 s | Only relevant with user transactions on; the unit cap of 32 G covers it. | Keep it in mind when sizing a separate settler host. | P12 |

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
3. No finality stall since e7180. Use the L1 operators' monitoring; when D1 = e7450, check that the lag
   stayed ≤ 3 for the whole day.
4. No L1 release after fa980367 changed a crate the L2 links (see `L2-HARD-FORK-OPERATOR-STEPS.md`
   §0). If one did, rebuild the L2 against it first: NO-GO with v2.1.
5. `getl2settlement`: `accepted` = `null`, source height 1, slot 187200, `profile.activated` true.
   Record `inbox` (expected 0). If deposits arrived in the meantime, L2 block 1 will differ from
   `0ff59c11…ab25` and the P6 dry-run reference changes accordingly.
6. D1, D2, D3, D4 and D7 are decided, and the v2.1 release is signed.

**NO-GO:** any HF entry not active, a finality lag > 3, nodes on different finalized roots, or an L1
hotfix pending. Wait, and re-run G0.

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

1. Owner signs the release `SHA256SUMS` (D7) and keeps the `.minisig` with the release dir.
2. Stage on A, from the Mac. Each command is one block.

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 mkdir -p l2-golive-v2/artifacts l2-golive-v2/release-settler-v2
```

```
scp -3 -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@45.77.142.123:l2dexbridge-20261030/l2-v21/release/bloch-l2-2026-10-30-v21-native-78d4921c/*' ubuntu@136.244.93.186:l2-golive-v2/artifacts/
```

```
scp -3 -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/carryover.tsv.gz*' ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/mainnet.manifest ubuntu@136.244.93.186:l2-golive-v2/artifacts/
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/l2-v21-20261030/deployment/mainnet ubuntu@136.244.93.186:l2-golive-v2/kit
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/l2-v21-20261030/deployment/devnet/settler_v3.py ubuntu@136.244.93.186:l2-golive-v2/release-settler-v2/
```

3. On A, check the release and assemble the settler release dir. `bloch-l2-produce-dev`, the kit
   installer and the settler come from this release. The guest, the SP1 host and the 78d4921c
   `bloch-pos` come from the settler-v2 staging on 136. The 10-19 staging is not usable: the installer
   refuses its `bloch-pos`.

```
cd /home/ubuntu/l2-golive-v2/artifacts && sha256sum -c --ignore-missing SHA256SUMS
```

```
cp /home/ubuntu/l2-golive-v2/artifacts/bloch-l2-produce-dev /home/ubuntu/l2-golive-v2/artifacts/mainnet.manifest /home/ubuntu/l2-golive-v2/kit/install-settler-mainnet.py /home/ubuntu/l2-golive-v2/release-settler-v2/
```

```
cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/settlement_v3_mainnet /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-pos /home/ubuntu/l2-golive-v2/release-settler-v2/
```

```
sha256sum /home/ubuntu/l2-golive-v2/release-settler-v2/* /home/ubuntu/l2-golive-v2/artifacts/*
```

```
bash /home/ubuntu/l2-golive-v2/kit/install-shadow.sh --verify /home/ubuntu/l2-golive-v2/artifacts
```

**GO when:**

- `SHA256SUMS` is OK.
- `install-shadow.sh --verify` prints `verify OK`.
- The printed hashes match §3.1/§3.2: produce-dev `fb0d5313…`, follower `c18752fd…`, settled-rpc
  `1e76b99a…`, sequencer `15daa26f…`, `settler_v3.py` `8589d5e2…`, `install-settler-mainnet.py` `16aba9b6…`, guest `203114bf…`, `bloch-pos`
  `700631b0…`, manifest `7eef82a7…`, `carryover.tsv.gz` `4d1e2738…`.
- `artifacts/build.json` shows `l2_commit` `18b9e1d1`, `l2_tracked_changes: 0` and the HF epochs.

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

4. Keep RPC A without the txpool until D10 (drop-in `no-txpool.conf`; the content is in
   `FOLLOWER-RPC.md` §3.6, unchanged).
5. Start the follower only:

```
sudo systemctl enable --now bloch-l2-mainnet-follower
```

### B (D3 host)

Same steps with the replica user `bloch-l2-mainnet-replica`, canonical
`/var/lib/bloch-l2-mainnet-replica/canonical`, `--l1-rpc-url http://199.247.22.8:8080` and the
permanent `no-txpool.conf` (`FOLLOWER-RPC.md` §4.2–4.4, with the v2.1 artifacts). **Do not** seed B from
the 10-18 scratch state (the old §4.5). Let it replay from zero, so that A and B verify the forks
independently.

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

Rollback: `FOLLOWER-RPC.md` §6. The settler `prepare` state stays (see P6 rollback).

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
- `bloch_finality` shows `l2_genesis.finalized: true` with activation `618c9b80…` at slot 187200;
- `systemctl show -p ExecStart bloch-l2-mainnet-rpc` has no `--txpool`.

NO-GO: `safe`/`finalized` `null` after the follower is ready, or a wrong chain id.

Replica refresh on B (K5; after every finalized settlement from P8 on). The full command block is in
`FOLLOWER-RPC.md` §4.7. Use the v2.1 `produce-dev` at `/opt/bloch/l2-mainnet-tools/`.

Rollback: `sudo systemctl disable --now bloch-l2-mainnet-rpc`. Nothing depends on it until P10.

## P5. Prover (D2; on A unless decided otherwise)

Prover release dir: the settler-v2 staging `release-prover/` (host `3a24c36d…`, guest,
`remote_prover.py` `99bbc1bc…`, `SHA256SUMS`). Verify:

```
cd /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover && sha256sum -c SHA256SUMS
```

Install after the settler `configure` (P6 step 2) has created the settler SSH key. Run the dry-run, then
the real install. Both commands are in `PASSOS.md` §5, with `--memory-gib 100 --threads 24` and
`--circuits /home/ubuntu/l2-mainnet-install-20261019/circuits`.

GO when:

- the dry-run prints `memory_ok: true`, the identity equals the pins (ELF keccak `6e4c8440…`, policy
  `154869964f…747d`) and the slice is 100 G / 24 threads;
- `authorized_keys` ends in `bloch-l2-mainnet-settler` with `from="127.0.0.1"`.

NO-GO: an identity mismatch, or MemAvailable < 120 GiB.

Rollback (refuses while a proof runs):

```
sudo python3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/install-prover-mainnet.py rollback
```

## P6. Settler: prepare, configure, dry-run, then dry-run with the proof

1. **prepare** (local only; creates the DA key; done during P3):

```
sudo python3 /home/ubuntu/l2-golive-v2/release-settler-v2/install-settler-mainnet.py prepare --release /home/ubuntu/l2-golive-v2/release-settler-v2
```

   Record `da_funding_script_hash`. Back up the DA keystore and the passphrase **separately**
   (`PASSOS.md` §2, unchanged). Copy the SP1 circuits for the local fallback (`PASSOS.md` §3).

2. **configure** with the local prover and the read-only checks:

```
sudo python3 /home/ubuntu/l2-golive-v2/release-settler-v2/install-settler-mainnet.py configure --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub
```

   GO:
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
sudo sh -c 'cat /var/lib/bloch-l2-mainnet-settler/dry-run-*/dry-run-report.json' | grep -E '"ok"|"tag"|"bytes"|"proof_policy"|"where"'
```

   GO:
   - `ok: true`, tag `0x13`, 1155 bytes, `proof_policy 154869964f…747d`;
   - the `prove` stage `"where": "remote"`;
   - with an unchanged source, the statement SHA-256 is `42779c77…7426` (report 05; the transaction
     bytes differ, because Groth16 is randomized).

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
- the unit is active, with no `halt` in `journalctl -u bloch-l2-mainnet-shadow`.

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
`transaction-built`, `submitted`, `accepted`.

Independent check, on each of the three RPCs:

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080
```

GO (the L2 is live):

- `accepted.statement` L2 number 1 on all three nodes;
- `source.height` 2;
- the shadow is silent (no `halt`);
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

Run once by hand as a gate, then install the 60 s timer (units in `deployment/mainnet/monitor/`, commands in
`docs/MAINNET-OPS-RUNBOOK.md`; D11 sets the alert targets):

```
python3 /home/ubuntu/l2-golive-v2/kit/l2_monitor.py --profile mainnet --phase live --l2-rpc A=http://127.0.0.1:18955 --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://45.77.67.251:8080 --follower-status A=/var/lib/bloch-l2-mainnet-follower/status.json --unit settler=bloch-l2-mainnet-settler.service --unit shadow=bloch-l2-mainnet-shadow.service --binary /opt/bloch/l2-mainnet/bloch-l2-settled-rpc --build-json /home/ubuntu/l2-golive-v2/artifacts/build.json --json
```

GO: exit 0, or 1 with only expected WARNs (`l2_finalized` before the first finality, `alert_delivery`
before D11). A CRIT on `--binary` means an installed binary is not the v2.1 pin. Thresholds:
`MAINNET-OPS-RUNBOOK.md` §3.

Rollback: `sudo systemctl disable --now bloch-l2-mainnet-monitor.timer`. It is read-only.

## P10. Attestor sealing and distribution (D5)

Not needed for settlements, deposits or claims under 100 BLCH. It is **required before any claim of
100 BLCH or more**, and therefore before the exchange notice (P13).

1. Run the custody flow on the owner's Mac, offline: `deployment/mainnet/attestor/keykit/make-operator-bundles.sh`
   `preflight`, `seal`, `verify`, `package`, `backup-check` on two media, then `shred-originals`
   (`keykit/KEY-HANDOFF-CHECKLIST.md`). The keys never travel unsealed. This replaces `ATESTADORES.md`:
   the originals are now destroyed before the handoff, gated on verified bundles and two read-back media.
2. Each operator host (§2 spec) gets an `ARTEFATOS` dir with:
   - `bloch-l2-native-follower` `c18752fd…` and `bloch-l2-produce-dev` `fb0d5313…`;
   - the attestor `bloch-pos` (e7d2c8b2 Linux build; `keykit/operator-pins-v2.sha256` pins `093909a2…`, owner to confirm);
   - `mainnet.manifest`, `carryover.tsv.gz` and `.sha256`;
   - `SHA256SUMS` over the three binaries;
   - the kit `deployment/mainnet/attestor` from this branch.

   Not the RC binaries `821289e0…` / `192eda33…`: they halt.
3. `check-operator-bundle.sh --open`, then `install-attestor.sh install … --l1-rpc-url <D4-style L1 RPC>`.
   The installer pins the follower in `config.json` (K2). As operator root, also compare the files:

```
sha256sum /opt/bloch/l2-attestor/bloch-l2-native-follower /opt/bloch/l2-attestor/bloch-l2-produce-dev
```

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

Prerequisites: P4 on both hosts, and the gateway package from this branch. The certificate and peer
steps are in the rpc-gateway report (Cloudflare Origin CA, Authenticated Origin Pulls CA, `peer-cert`
on each host, exchange of the public peer certificates).

`setup-gateway.sh` renders with CORS open to any origin and `--backend-conns 400`, which is correct
for settled RPC v2.1. The `plan` command only renders; `apply` installs.

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
   to the D6(b) L2 address.

   GO:
   - `getl2settlement.inbox` shows it pending;
   - the next L2 block consumes it and settles;
   - after finality, `eth_getBalance` on RPC A and B (and the gateway) at `finalized` equals
     amount × 10¹⁰ wei;
   - the monitor `escrow_backing` is OK and `escrow_conserved` is true.
2. **Enable user transactions (D10).** Only after:
   - the deposit block is finalized;
   - R2 has been rehearsed on a private network;
   - gas-heavy 15M blocks have been measured and stuck-block recovery has been rehearsed (§3.4);
   - the DA key is funded (5 BLCH in two outputs to `da_funding_script_hash`, from the D6(a) wallet);
   - replica B has been rebuilt from L1 DA (K5).

   With the txpool on, the settled RPC enforces the v2.1 limits (§3.3 K8; `docs/MAINNET-RPC-READINESS.md` R7).

   Then: `user_transactions: true` in the settler config, restart the settler, and remove
   `no-txpool.conf` on A only (`PASSOS.md` §9, `FOLLOWER-RPC.md` §3.9).

   **Never** do this inside e7269–e7271 of a future signature fork.
3. **Withdrawal test.** Withdraw 0.5 BLCH (under 100 BLCH, so no attestors are needed) from the test
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

Only after P8 to P12 are GO and at least three attestors are live. Fill
`docs/MAINNET-EXCHANGE-INTEGRATION.md`:

- `{{PUBLIC_L2_RPC_URL}}` = `https://l2rpc.blochl1.com`;
- `{{L2_EXPLORER_URL}}` = `https://blochl1.com/l2`;
- the measured `safe`/`finalized` latency from P8/P12.

The HF1 claim-pause paragraphs in `l2-agents/10-l2-notices-EN.md` are historical by then; do not resend
them. State that the L2 is live with deposits, transfers and withdrawals, that claims of 100 BLCH or
more need 3-of-5 attestation and 2,880 blocks, and the release window limits.

Rollback: a correction notice. The chain state is unaffected.

## 5. Timeline (assuming D1 = e7450)

| When (UTC) | Phase |
| --- | --- |
| Before 2026-11-03 | D2–D9 decided, release v2.1 signed (D7). No host changes. |
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
