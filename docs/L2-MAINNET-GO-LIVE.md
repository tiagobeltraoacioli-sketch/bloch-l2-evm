# Bloch L2 mainnet (chain 700770): go-live plan for the v2 build

Status: **plan only, 2026-10-30 (L1 epoch ~7022).** Nothing in this document has been installed,
started or broadcast. Every step that writes to a public chain is marked **MAINNET WRITE**, and every
step that installs or starts something on a host is for the owner to run.

This plan supersedes the 2026-10-19 owner runbooks (`PASSOS.md`, `FOLLOWER-RPC.md`,
`ATESTADORES.md`, `DEPLOY-PUBLICO.md`). Those were built for native 78b7343a, the release before the
hard forks. Their follower, producer and settled-RPC binaries **halt at HF1 (epoch 7180)** and must not
be installed. Their structure (host roles, unit names, ports, paths) is kept. What changes is the
binaries, the start condition and a few kit pins (§3).

Related documents:

- `deployment/mainnet/SETTLER-RUNBOOK.md`: settler worker and installer.
- `deployment/mainnet/follower-rpc/install.sh`: follower and settled-RPC units.
- `deployment/mainnet/attestor/README.md`: attestor kit.
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
  | 45.77.142.123 | 32 | 125 GiB | 2.2 TB | Shared build host. It still runs the 10-18 scratch follower and RPC (127.0.0.1:19145, pre-HF build, PIDs 1304666 and 1452988). The v2 release is in `~/hf-release-kit-20261020/l2-78d4921c-v2/out`. A complete follower/RPC artifact set (v2 binaries + manifest + carryover) is in `~/hf-release-kit-20261020/l2-agents/07-rpc/artifacts`. |

## 1. Owner decisions (all open)

Nothing marked here may be filled in by an operator or an agent. `TBD-owner` means the owner supplies
the value.

| # | Decision | Recommendation | Blocks phase |
| --- | --- | --- | --- |
| **D1** | Go-live start epoch | Not before G0 (§4) holds. Earliest e7365 (2026-11-03 17:31 UTC). Recommended **e7450 (2026-11-04 16:11 UTC)**, after one full day (90 epochs) of clean finality following HF3. | all |
| **D2** | **Prover host** | 136.244.93.186, co-located with the settler and prover reached over SSH on 127.0.0.1, as decided on 10-19. Alternative: a dedicated host meeting the prover row of §2. `TBD-owner` to confirm. | P5 |
| **D3** | Follower B / replica RPC host | 45.77.142.123 works (light load) but it is the shared build host. Recommended: a small dedicated VPS (§2, "follower B"). `TBD-owner`. | P3, P4, P11 |
| **D4** | L1 RPC each follower reads | A → 80.240.16.185, B → 199.247.22.8 (different sources on purpose). | P3 |
| **D5** | **Attestor operators**: five people, five hosts, one index each, plus the publish URL and token for partials | `TBD-owner` (none chosen). No operator may hold more than one key or share a host with a validator, the settler or another attestor. | P10 |
| **D6** | **Bloch Inc addresses** | **None is needed for the L2 core.** L2 fees go to the predeploy `0x4200…0011`, settlements pay no L1 fee, and the DA key is generated on the host. Still `TBD-owner`: (a) the L1 wallet that funds the DA key (5 BLCH, only when user transactions are enabled); (b) the L1 wallet and L2 recipient for the test deposit and test withdrawal; (c) the Bloch Inc Safe and bridge guardian addresses, which the DEX and bridge need later. Those are not part of this plan. | P12 |
| **D7** | Release signature | Sign the reproducible release `bloch-l2-2026-10-28-hf123-native-78d4921c` (its `SHA256SUMS` has SHA-256 `28d452d5fb82f619ddf1eab49b43845cfd0abe2a892650419e8a1dd9e389c09d`) with the owner's minisign key before any install. `TBD-owner` key. | P2 |
| **D8** | Retire the 10-18 scratch follower/RPC on 45.77 (they halt at HF1 anyway) | Stop them before or at G0. The owner runs `kill 1452988 1304666`. | none (hygiene) |
| **D9** | Public gateway | `l2rpc.blochl1.com` through the Cloudflare Worker, with the nginx :2095 origins on A and B (bloch-explorer `codex/l2-mainnet-public-20261019`). Choose the plain-HTTP origin hop (as built) or Cloudflare Tunnel. Choose DNS timing. `TBD-owner`. | P11 |
| **D10** | When to enable user transactions | Only after the P12 deposit test and the DA rehearsal R2 (§3). Until then deposits mint on the L2 but nobody can transact or withdraw. | P12 |
| **D11** | Alert channel for the monitor | `TBD-owner`. | P9 |
| **D12** | DA signer `bloch-pos` | Keep the settler's pinned 78b7343a `bloch-pos` (`fa9996ed…`). It only generates and signs for the DA key; it judges no consensus. Do not pin the `codex/hf-l2-compat-20261020` signer (its `--for-epoch` form is likely refused after HF2). | P6 |

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
- **Prover (SP1).** Peak RSS 20.4 GB for an empty block and 30.8 GB for a 5-tx block, at 8 threads.
  The installer refuses a slice below 32 GiB. A Groth16 proof takes about 15 min.
- **gnark Groth16 container.** About 18.5 GB, under dockerd, outside every slice. The installer
  requires 20 GiB of headroom above the prover slice.
- **Settler unit.** `MemoryMax=32G`. It runs execute and verify, and a local proof only if the remote
  prover fails.
- **Unit caps.** Follower 6 G with `CPUQuota=200%`. Settled RPC 4 G. Shadow 4 G with
  `CPUQuota=400%`.

At the recommended start (e7450) L1 holds about 198k blocks. Plan for **about 55–65 min to re-verify
on restart and about 65–80 min for a fresh install**, more on a busy host.

| Role | Host | vCPU | RAM | Disk (SSD) | Memory budget |
| --- | --- | --- | --- | --- | --- |
| **A: settler + prover + follower A + RPC A + shadow + monitor + nginx origin** | 136.244.93.186 (D2) | **32** (min 16) | **128 GB** (125 GiB usable). Hard minimum with all roles: 96 GB. | **≥ 200 GB** (circuits 7.9 GB, settler about 50 GB, follower about 3.5 GB growing about 16 GB a year, Docker). 136 has 2.7 TB. | Prover slice 40 G (measured peak 20.4–30.8 GB) + gnark about 18.5 G + settler 32 G (local fallback only) + follower 6 G + RPC 4 G + shadow 4 G = 104.5 G worst case of caps. Expected peak during a proof is about 50 GB. |
| Prover alone (if D2 picks a separate host) | `TBD-owner` | **32** (min 16; 12 threads in the slice) | **64 GB** minimum (40 G slice + 20 G gnark headroom + OS) | ≥ 100 GB (circuits 7.9 GB + work) | as above, without the settler, follower, RPC and shadow |
| Settler alone (prover remote) | 136 | 8 | 32 GB, or 56 GB if the local proof fallback stays enabled (32 G unit + about 20 G gnark) | ≥ 100 GB | |
| **B: follower B + replica RPC + nginx origin** | 45.77.142.123 or a dedicated VPS (D3) | **4** | **8 GB** | **≥ 80 GB** | Follower 6 G cap (0.6 GB used) + RPC 4 G cap. Replica rebuild about 110 MB. |
| **Attestor host** (×5, one per operator) | `TBD-owner` (D5) | **4** (kit minimum 2) | **8 GB** | **≥ 80 GB** (kit minimum 40 GB) | Follower 0.6 GB + rebuild-check 0.1 GB + `bloch-pos` signing |
| Monitor | runs on A (and optionally on B) | n/a | < 50 MB | n/a | |

Rule from the 2026-10-12 incident: never run validators on host A while the settler and prover run.
The 30 `bloch-expansion@` units on 136 are disabled and must stay so.

## 3. Pins: the v2 build and what stays

### 3.1 v2 artifacts (L2 commit `1aad0a20`, native 78d4921c, valid for the fa980367 fleet)

Reproduced byte for byte by an independent rebuild (report 08-repro). Source:
`45.77.142.123:~/hf-release-kit-20261020/l2-78d4921c-v2/out`, or the signable release dir
`~/hf-release-kit-20261020/l2-agents/08-repro/release/bloch-l2-2026-10-28-hf123-native-78d4921c/`.

| Artifact | SHA-256 | Used by (phase) |
| --- | --- | --- |
| `bloch-l2-native-follower` | `c18752fd4c6942678bcb45d8d36436bcd644b1ee6e48416d67e4999e7c7cf29a` | follower A, follower B (P3), attestor hosts (P10) |
| `bloch-l2-produce-dev` | `7c1cc62bf5fb5aa142dced01156e3a51ddb6239096034400558ef46586025a3c` | canonical DB init A/B (P3), settler release (P6), shadow (P7), replica rebuild B (P4), attestors (P10) |
| `bloch-l2-settled-rpc` | `4fc9fa1ecc2b75dec8c918e77cefb81fe7fc216c5baead133e17c15fc4c54534` | RPC A, RPC B (P4) |
| `sequencer_mainnet.py` | `15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2` | shadow (P7) |
| `build.json` | `1fb56c7b09d40dad73a1b0a5d382ac72bf949268d18f6ccd3cf6df10155dea32` | check `l1_activation_epochs` 7180/7180/7186/7270×4/7360×3/8620 and `l2_tracked_changes: 0` |
| `out/SHA256SUMS` | `0cdf633ea51383c6569df2e90edfb2562cc465725e985d44f59f157288c11e98` | install.sh `sha256sum -c` |
| release `SHA256SUMS` (signing target, D7) | `28d452d5fb82f619ddf1eab49b43845cfd0abe2a892650419e8a1dd9e389c09d` | owner signature |
| `NATIVE_LOCK` (settlement-recovery, 78d4921c) | `26bf44539b996809bd75164a488d8a30137507716d06990721056a213364aef8` | rebuilds only. It is not committed in this repo; it is copied in the release dir. |

### 3.2 Pins that do not change (the HF forks do not touch the guest, the proof or the settlement format)

| Item | Value | Used by |
| --- | --- | --- |
| Guest `settlement_v3_mainnet` | `203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473` | settler, prover |
| Proof policy V3 | `154869964f…747d` | settler dry-run report |
| SP1 host `bloch-evm-sp1-settlement-v3` | `617d191f…86b3` (45.77 build) or `505500af…aa07` (136 build). Both print the same `--mainnet identity` (ELF keccak `6e4c8440…`, vkeys `389cfbde…` / `007139f7…`). | settler, prover |
| `remote_prover.py` | `99bbc1bcec7db7cf3f56c361a6af6253e461d13ebab2ffc5a190df0fc2feb9bd` (same in the v2 tree and in the 10-19 staging) | prover |
| `settler_v3.py` | `875f4cca4dd0f5c2031137a56cdffcd99e8976a54e77ab5a8728fac6c5288bdd` (**v2 tree**; the 10-19 staged copy `9640d288…` predates the DA-form code) | settler |
| Settler `bloch-pos` (DA key only) | `fa9996eda48a8d3a5beff249c1c7d9f666d9e8207c4f0a1825ba3dba3889fc18` (78b7343a). Enforced by `install-settler-mainnet.py`. | settler (D12) |
| `mainnet.manifest` | `7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd` | all |
| `carryover.tsv.gz` / `carryover.tsv` | `4d1e2738baec39ec25e2e33968f72a47abb261f271de62fb48a33be55bfc83be` / `84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6` | followers, attestors |
| `l2-config.bin` | 264 B, `292f4fa8…4f6b` (derived in code) | settler |
| gnark image | `ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d` | prover, settler fallback |
| SP1 circuits v6.1.0 | `groth16_vk.bin` `4388a21c…e696` (7.9 GB tree on 136) | prover, settler fallback |
| L2 genesis / state root | `632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468` / `2ad7e807…c05d` | all |
| Network pin / domain | `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966` / `1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733` | all |
| Attestor set | `1c06adbb…cc4b` (3-of-5); set file `9bb94e333f76de0c726d4d3ae7f619b447b41def18b01615b51ac1261d13cde0` | attestors |
| Attestor `bloch-pos` (signing only) | Linux build of bloch-sis-pow `codex/l2-attestor-keystore-20261019` e7d2c8b2. The rehearsal binary was `093909a2…`. The production hash is `TBD-owner` (recorded at build). | attestors |

### 3.3 Kit gaps found while writing this plan (fix before the phase named)

| # | Gap | Effect | Fix | Phase |
| --- | --- | --- | --- | --- |
| **K1** | `deployment/mainnet/install-shadow.sh` pins `PRODUCE_SHA256=192eda33…` (the pre-HF RC) | With the v2 OUT it refuses (`sha256sum -c` fails). With the RC producer the shadow would decode post-HF blocks with pre-HF code. | Set `PRODUCE_SHA256=7c1cc62bf5fb5aa142dced01156e3a51ddb6239096034400558ef46586025a3c` in a reviewed commit and stage that copy. | **P7 (blocker)** |
| K2 | The attestor agent does not pin the follower binary (report 06) | A wrong follower goes unnoticed by `check`. | Check the follower SHA-256 by hand at install (P10 step 3), or use a kit with a `follower_sha256` pin. | P10 |
| K3 | 10-19 runbook `curl` lines lack `Content-Type` | The L1 RPC refuses them. | Use the commands in this document. | all |
| K4 | `install.sh` prints "~155k blocks, 30–40 min" | Cosmetic. The real figure is in §2. | none | P3 |
| K5 | Replica B's canonical DB advances only by a manual `reconstruct` (no timer) | B drops out of the gateway rotation when it is more than 16 blocks behind A. It never serves wrong data. | Run the P4 refresh after each finalized settlement until a timer exists. | P4, P11 |
| K6 | 8 `tests/ffg_recovery.rs` integration failures (`Err(Trust)`) seen in an earlier v2 test run (report 03) | Not explained yet. Outside `--lib`. | Explain them before P6 (no-go item). | P6 |
| K7 | `docs/L2-HARD-FORK-OPERATOR-STEPS.md` §4.2 step 2 still says to pin the compat-branch DA signer | Wrong for 78d4921c (report 05). | Follow D12. | P12 |

### 3.4 Residual risks the go/no-go checks cover

- **R1. Real post-fork blocks.** No v2 follower has yet verified blocks produced under HF1/HF2/HF3. The
  forced-gate qualification could not cross real history. The **first real proof is P3**: a fresh
  replay after G0 crosses e7180, e7270 and e7360 on mainnet. Any halt there is an absolute no-go.
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
   §0). If one did, rebuild the L2 against it first: NO-GO with v2.
5. `getl2settlement`: `accepted` = `null`, source height 1, slot 187200, `profile.activated` true.
   Record `inbox` (expected 0). If deposits arrived in the meantime, L2 block 1 will differ from
   `0ff59c11…ab25` and the P6 dry-run reference changes accordingly.
6. D1, D2, D3, D4 and D7 are decided. K1 is fixed before P7, and K6 is explained before P6.

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

## P2. Stage and verify the v2 release (no install)

1. Owner signs the release `SHA256SUMS` (D7) and keeps the `.minisig` with the release dir.
2. Stage on A, from the Mac. Each command is one block.

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 mkdir -p l2-golive-v2/release-settler-v2
```

```
scp -3 -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts ubuntu@136.244.93.186:l2-golive-v2/
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/golive-plan-20261030/deployment/mainnet ubuntu@136.244.93.186:l2-golive-v2/kit
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/golive-plan-20261030/deployment/devnet/settler_v3.py ubuntu@136.244.93.186:l2-golive-v2/release-settler-v2/
```

   (After K1 is fixed, stage the kit from the commit that carries the fix rather than from this
   branch.)

3. On A, assemble the settler release dir. The settler needs six files. `bloch-l2-produce-dev` comes
   from v2. The guest, the SP1 host, the 78b7343a `bloch-pos` and the manifest come from the verified
   10-19 staging.

```
cd /home/ubuntu/l2-golive-v2/artifacts && sha256sum -c --strict SHA256SUMS
```

```
cp /home/ubuntu/l2-golive-v2/artifacts/bloch-l2-produce-dev /home/ubuntu/l2-golive-v2/artifacts/mainnet.manifest /home/ubuntu/l2-golive-v2/kit/install-settler-mainnet.py /home/ubuntu/l2-golive-v2/release-settler-v2/
```

```
cp /home/ubuntu/l2-mainnet-install-20261019/release-settler/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2-mainnet-install-20261019/release-settler/settlement_v3_mainnet /home/ubuntu/l2-mainnet-install-20261019/release-settler/bloch-pos /home/ubuntu/l2-golive-v2/release-settler-v2/
```

```
sha256sum /home/ubuntu/l2-golive-v2/release-settler-v2/* /home/ubuntu/l2-golive-v2/artifacts/*
```

**GO when:**

- `SHA256SUMS` is OK (four files).
- The printed hashes match §3.1/§3.2: produce-dev `7c1cc62b…`, follower `c18752fd…`, settled-rpc
  `4fc9fa1e…`, sequencer `15daa26f…`, `settler_v3.py` `875f4cca…`, guest `203114bf…`, `bloch-pos`
  `fa9996ed…`, manifest `7eef82a7…`, `carryover.tsv.gz` `4d1e2738…`.
- `artifacts/build.json` shows `l2_tracked_changes: 0` and the HF epochs.

**NO-GO:** any mismatch. Re-copy from the build host. Never use `~/l2-mainnet-install-20261019/out-release`
or `release-settler/bloch-l2-produce-dev` (`3736860e…`, pre-HF).

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
permanent `no-txpool.conf` (`FOLLOWER-RPC.md` §4.2–4.4, with the v2 artifacts). **Do not** seed B from
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

**NO-GO (stop the whole go-live):** any halt. It means the v2 verifier disagrees with the L1 on a
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
`FOLLOWER-RPC.md` §4.7. Use the v2 `produce-dev` at `/opt/bloch/l2-mainnet-tools/`.

Rollback: `sudo systemctl disable --now bloch-l2-mainnet-rpc`. Nothing depends on it until P10.

## P5. Prover (D2; on A unless decided otherwise)

Prover release dir: the 10-19 `release-prover/` (host, guest, `remote_prover.py` `99bbc1bc…`,
`SHA256SUMS`). These files are unchanged by v2. Verify:

```
cd /home/ubuntu/l2-mainnet-install-20261019/release-prover && sha256sum -c SHA256SUMS
```

Install after the settler `configure` (P6 step 2) has created the settler SSH key. Run the dry-run, then
the real install. Both commands are in `PASSOS.md` §5, with `--memory-gib 40 --threads 12` and
`--circuits /home/ubuntu/l2-mainnet-install-20261019/circuits`.

GO when:

- the dry-run prints `memory_ok: true`, the identity equals the pins (ELF keccak `6e4c8440…`, policy
  `154869964f…747d`) and the slice is 40 G / 12 threads;
- `authorized_keys` ends in `bloch-l2-mainnet-settler` with `from="127.0.0.1"`.

NO-GO: an identity mismatch, or MemAvailable < 60 GiB.

Rollback (refuses while a proof runs):

```
sudo python3 /home/ubuntu/l2-mainnet-install-20261019/release-prover/install-prover-mainnet.py rollback
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

3. Then P5 (prover install), then **dry-run with the Groth16 proof** (about 15–20 min, peak about 50 GB
   on A):

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
- a `prove` stage `"where": "local"` (the SSH path is broken: fix it before going live);
- K6 not explained.

Rollback: `install-settler-mainnet.py rollback`. It removes the unit only and keeps the DB, the
keystore, the passphrase and the config. Nothing has been written to L1.

## P7. Shadow producer (before the first live settlement)

The shadow rebuilds every block the settler produces and halts (exit 3) on any difference, before the
proof reaches L1. That is why it goes **before** P8, although the original order listed it later.
Blocker: **K1**.

```
sudo bash /home/ubuntu/l2-golive-v2/kit/install-shadow.sh /home/ubuntu/l2-golive-v2/artifacts --start
```

GO:

- the `init` hash is `632e45ae…` / `2ad7e807…`;
- `check` ok against the 3 RPCs;
- the unit is active, with no `halt` in `journalctl -u bloch-l2-mainnet-shadow`.

NO-GO: a pin refusal (K1 not applied) or a check failure.

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

Run once by hand as a gate, then schedule it (D11; the kit ships no unit, so use a cron job or a
systemd timer under an unprivileged user):

```
python3 /home/ubuntu/l2-golive-v2/kit/l2_monitor.py --profile mainnet --l2-rpc http://127.0.0.1:18955 --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://45.77.67.251:8080 --file follower=/var/lib/bloch-l2-mainnet-follower/status.json:900 --json
```

GO: exit 0, or 1 with only expected WARNs (`l2_finalized` before the first finality). Thresholds:
`MAINNET-OPS-RUNBOOK.md` §3.

Rollback: remove the cron entry or timer. It is read-only.

## P10. Attestor sealing and distribution (D5)

Not needed for settlements, deposits or claims under 100 BLCH. It is **required before any claim of
100 BLCH or more**, and therefore before the exchange notice (P13).

1. Seal, verify and back up the five keys on the owner's Mac, offline (`ATESTADORES.md` §0–4,
   unchanged). The keys never travel unsealed. The originals are destroyed only after 3 operators
   have `check-ok` (§7 there).
2. Each operator host (§2 spec) gets an `ARTEFATOS` dir with:
   - **v2** `bloch-l2-native-follower` `c18752fd…` and `bloch-l2-produce-dev` `7c1cc62b…`;
   - the attestor `bloch-pos` (e7d2c8b2 Linux build, hash `TBD-owner`);
   - `mainnet.manifest`, `carryover.tsv.gz` and `.sha256`;
   - `SHA256SUMS` over the three binaries;
   - the kit `deployment/mainnet/attestor` from this branch.

   Not the RC binaries `821289e0…` / `192eda33…`: they halt.
3. `install-attestor.sh install … --l1-rpc-url <D4-style L1 RPC>`. Then, as operator root, check the
   follower by hand (K2):

```
sha256sum /opt/bloch/l2-attestor/bloch-l2-native-follower /opt/bloch/l2-attestor/bloch-l2-produce-dev
```

4. Start the follower and wait about 65–80 min. Then run `attestor_agent.py check`, then start the
   agent. Fresh installs may run in parallel: there is no existing quorum to protect.

GO:

- ≥ 3 operators (target 5) report `check-ok` with their `signer_index` and set `1c06adbb…`, plus
  `rebuild-check-ok`;
- the follower `native_finalized_epoch` advances;
- the originals are shredded on the Mac (`ATESTADORES.md` §7).

NO-GO: fewer than 3 `check-ok`, or a `halt … produce differs`.

Rollback per host: `touch /etc/bloch-l2-attestor/PAUSE`. A lost host is reinstalled from the
operator's USB copy. Changing the set needs a hard fork.

## P11. Public gateway (D9) — **PUBLISH (owner only)**

Follow `DEPLOY-PUBLICO.md` (bloch-explorer `codex/l2-mainnet-public-20261019`, `073b3df`) with
`PORTA_RPC=18955`:

1. Run the nginx origin guard on A and B.
2. Deploy the Worker `l2rpc.blochl1.com`.
3. Deploy the explorer last.

Before step 3, re-check that the site still serves the bundle `index-D4WLsMRL.js`. If not, rebase.

GO:

- `curl -s https://l2rpc.blochl1.com/health` is OK;
- `eth_chainId` through the gateway is `0xab162`;
- `node l2rpc/dev/live-check.mjs https://l2rpc.blochl1.com 700770 --no-tx` passes;
- the origin answers 403 without the key.

NO-GO: either origin unreachable, a wrong chain id or a failing live-check.

Rollback: `./l2rpc/rollback.sh disable` (first deploy) and `rollback-origin.sh apply` on each host.

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
   - the DA key is funded (5 BLCH in two outputs to `da_funding_script_hash`, from the D6(a) wallet);
   - replica B has been rebuilt from L1 DA (K5).

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
| Before 2026-11-03 | D2–D9 decided, K1 fixed in a reviewed commit, K6 explained, release signed (D7). No host changes. |
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
