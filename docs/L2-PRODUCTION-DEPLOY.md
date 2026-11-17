# Bloch L2 mainnet (chain 700770): production deployment kit, owner-run (round 18)

Status: **kit for the owner; nothing in it has been run on a production host.** Written 2026-11-17 by agent 385
(round 18) on branch `codex/l2-prod-deploy-r18-20261117`. Every step that writes to Bloch L1 mainnet is marked
**MAINNET WRITE**, every publication **PUBLISH**, and every step that installs or starts something on a host is for
the owner (or an operator the owner names) to run. No agent signs, installs, enables, starts or publishes anything
in this document.

**What this document is.** The production procedure for the deposit-only launch of the L2 with the launch kit
**rebuilt against L1 node release `906336fd`** (agent 383's line, from `codex/l2-launch-rebuild-r17-20261117`). It
does not replace the reviewed launch plan `docs/L2-MAINNET-GO-LIVE.md` (G0, P1 to P13, the K and R residual lists,
D1 to D19); it **keeps every gate, cap, check and refusal of that plan** and adds what a production install needs
on top of it:

- the identity of the rebuilt release and where each value comes from (section 1);
- the decisions only the owner can take, updated for 2026-11-17 (section 2);
- the hosts: host A on 136.244.93.186 and an exact specification for host B and the attestor hosts (section 3);
- the release signing step with `~/.cargo/bin/rsign` on the owner's Mac (section 4);
- G0 restated for the chain after epoch 8620 (section 5);
- the install on host A (section 6) and host B (section 7), one command per block;
- attestor bundle distribution to the five operators (section 8);
- the public RPC gateway and the explorer hookup (section 9);
- monitoring and alerting (section 10);
- one go / no-go checklist (section 11) and one rollback table (section 12);
- the container dry runs of every install script, with how to repeat them (section 13);
- what is not done or not proven (section 14).

Where this document and `docs/L2-MAINNET-GO-LIVE.md` disagree on a gate, **the stricter one applies**. Where they
disagree on an identity, the rebuilt line's `deployment/mainnet/GO-LIVE-PINS.sha256` and agent 383's report
(`agents/348-l2-launch-rebuild-r17.md`) win, and this document must be fixed.

Conventions: every command is one block with no comment inside it. `THIRD_L1_RPC_URL` is the third L1 RPC the owner
chooses (`http://HOST:8080`), `IP_OF_B` is host B, the rebuilt release's values are filled in from bloch-l2-evm `main` `b17b3ae` (383's final launch line, reviewed by 384) (section 1); replace every remaining placeholder before
running a command. The settler installer refuses any
`--rpc-urls` value that still contains `TBD`, `THIRD_L1` or `IP_OF` (measured in the dry run, section 13), so a
forgotten placeholder in that command fails closed.

## 1. Identity of the rebuilt release

Source of each value: `agents/348-l2-launch-rebuild-r17.md` (agents 348 and 383), measured on 45.77.142.123 and
136.244.93.186; the rebuilt kit's `deployment/mainnet/GO-LIVE-PINS.sha256` once 383 commits it. State at
2026-11-17 19:40 UTC: install from bloch-l2-evm `main` `b17b3ae` (coordinator); 383 published the release and the
re-pinned kit in commit `716a9e9` (branch
`codex/l2-launch-rebuild-r17-20261117`), reviewed by 384 and merged into `main`. Check 383's report for its real-proof
rehearsal and mainnet replay past e8620 before G0 (section 11, gate 2).

| Item | Value | Source / state |
| --- | --- | --- |
| L1 node release the L2 links | `906336fd` (tag `node-906336fd-kes-followups`, "mandatory release before epoch 8620") | 348/383 report 1.1, decided |
| L2 build commit | `3d35a0f` (bloch-l2-evm) | 383 report 1.2 |
| Settlement-recovery lock | `settlement-recovery.native-906336fd.Cargo.lock`, `ab7b3a09…cafa` | 383 report 1.2 |
| `bloch-l2-native-follower` | `d4d2b99a20f6093cbaf2b9cebead41b3c6b4bf5aad37f2a091752746a659fe96` | 383 report 1.2 (moved: was `cdf5da5c…`) |
| `bloch-l2-produce-dev` | `598873aef6770002297a710387969218dd7d684ea8e9d8bdcf067d43123b37db` | 383 report 1.2 (moved: was `e3f1a290…`) |
| `bloch-l2-settled-rpc` | `53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d` | 383 report 1.2 (unchanged) |
| `sequencer_mainnet.py` | `15daa26fe52d0f3c39befcfc43e68b660678826973fb72ed24190339ae6b88e2` | 383 report 1.2 (unchanged) |
| `build.json` | `9131838921a728fe3a03f0d2b7bd28e6a48d24fda2041fa49b95b5ea7a0d8693` | 383 report 1.2; names L2 genesis `632e45ae…f468` and the two new L1 gates at 8620 |
| Release name | `bloch-l2-2026-11-17-launch-native-906336fd`, folder `~/l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd` on 45.77 and 136 (byte-identical, `diff -r` empty on the Mac, 2026-11-17) | 383 `716a9e9` |
| Release `SHA256SUMS` (signing target) | `4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb` | 383 `716a9e9`; re-measured on both copies |
| Kit tip (frozen, detached checkout) | `b17b3ae44051d6c7676606476adf28caf21c3698` (bloch-l2-evm `main`: 383's launch line `716a9e9` reviewed by 384, plus the publication-hygiene merge: attestor custody tool needs `--keys-dir`, runbook host placeholders, licences) | 383 |
| `deployment/mainnet/GO-LIVE-PINS.sha256` | `38a0d1b499fc8ef646fd00717a6cd4f98358a4aa080408c93f8407bdff6f7511` | `main` `b17b3ae`; re-measured (`26df766b…` at `716a9e9`: moved by the hygiene commits, no binary pin moved) |
| `deployment/mainnet/GO-LIVE-PINS-PROVER.sha256` | `b0fd684c92609f27a8ac9782ca6d5ca41e586eb78499c203dab8c461e6e0cf57` (unchanged by the rebuild) | re-measured at `b17b3ae`; was `716a9e9` |
| Guest `settlement_v3_mainnet`, SP1 host, program identity, proof policy | unchanged: `203114bf…c473`, `3a24c36d…973a`, ELF keccak `6e4c8440…c073`, policy `154869964f…747d` | 383 `716a9e9` states them unchanged; the dry run on the rebuild read the same identity from the prover installer (section 13) |
| L2 genesis / state root | `632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468` / `2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d` | unchanged; re-measured by `produce-dev init`/`head` in the dry run |
| Settler DA signer `bloch-pos` | `700631b0…` (78d4921c) | unchanged by 383 `716a9e9` (decision recorded in its commit); reviewer 384 to confirm it signs DA after e8620 |
| Attestor `bloch-pos` | `093909a2…` (rehearsal pin; production hash `TBD-OWNER`) | unchanged by the rebuild |

**Pins the rebuild had to move**: inventory by `git grep` of the old hashes (`cdf5da5c`, `e3f1a290`, `6d3bd628`,
`926d2cf5`, `a3c38a46`) outside tests, at `521a538` and again at `716a9e9`. At `521a538` they were in
`GO-LIVE-PINS.sha256`, `follower-rpc/install.sh`, `install-settler-mainnet.py`, `install-shadow.sh`, `l2_monitor.py`,
`replica/PINS.sha256`, `attestor/install-attestor.sh`, `attestor/keykit/operator-pins-v2.sha256`, the operator texts
and the runbooks. At `716a9e9` every remaining occurrence is a comment or text naming the earlier build as the one
that halts after the KES bind, plus the 78d4921c lock line that `build-release.sh` and the pin list keep for the
earlier native commit; no installer or pin list accepts the earlier release. Demonstrated the other way round as
well: kit `521a538` given the rebuilt binaries refuses them at P2 (four pin lines), at `install-shadow.sh --verify`
and at the settler's `prepare` (`bloch-l2-produce-dev differs from its pin e3f1a290…`) (section 13).

## 2. Owner decisions and inputs

Nothing here may be filled in by an operator or an agent. The D-numbers are those of `docs/L2-MAINNET-GO-LIVE.md`
section 1; only what changed since 2026-11-03 or what production adds is written out.

| # | Decision | Recommendation (reason) | Blocks |
| --- | --- | --- | --- |
| D1 | Go-live epoch | **Not before e8710 (2026-11-18 16:11 UTC)**: one day of clean finality after KES enforcement at e8620 (2026-11-17 16:11 UTC), the same one-day margin the plan used after HF3; and not before 383's replay of mainnet L1 from genesis past e8620 with the rebuilt follower is PASS | everything |
| D2 | Prover host | 136.244.93.186 (co-located with the settler) while user transactions are off. See section 3.1: the prover installer refuses `--memory-gib 100` on 136 today | P5 |
| D3 | Host B | **A dedicated VPS, not 45.77.142.123** (shared build host with many `sudo` users; `public-rpc/README.md` "Host users"), not 209.250.236.240 (unreachable since 2026-11-16), not a validator host. Exact size in section 3.2 | P3, P4, P11 |
| D4 | L1 RPC per follower | A reads 80.240.16.185, B reads 199.247.22.8 (unchanged). The replica kit refuses B reading the settler's first L1 host (measured, section 13) | P3 |
| D5 | Five attestor operators: people, hosts, index each, feed URLs | `TBD-OWNER`. One key per operator, no shared host with a validator, the settler or another attestor | P10 |
| D6 | Test deposit wallet and L2 recipient | `TBD-OWNER` | P12 |
| D7 | Release signature | Sign `4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb` with key `1A5D96A5C4955EF7` (section 4) after G0 gates 1 to 5 and 7 | P2 |
| D8 | Retire the 10-18 scratch RPC on 45.77 | `ps -o pid,cmd -p 1452988` first, then `kill 1452988` (its follower is dead since HF1: agent 340) | none |
| D9 | Public gateway | nginx + njs on A (role `sequencer`) and B (role `replica`), no Worker. DNS and Authenticated Origin Pulls: section 9 | P11 |
| D10 | User transactions | **Off** for this launch (K13, F312-5 unchanged by the rebuild) | P12 |
| D11 | Alert destinations | `TBD-OWNER`: webhook URL and bearer file, or Telegram bot token file and chat id, or an `alert_command`; plus `heartbeat_url` and `heartbeat_fail_url` | P9 |
| D13, D15 to D19 | As in the plan | `--skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800`; `block_interval_seconds=1800`; foreign recovery on; D18 `deposit_wait_warn=5400`, `deposit_wait_crit=10800` | P6, P9 |
| **D20** | **The `r202-*` containers on 136** (agent 202's round-11 rehearsal rig: a private L1 and L2 running since 2026-11-03) | **Done 2026-11-17**: removed by the coordinator on the owner's authorization (inspect output and last logs in `~/l2dexbridge-20261030/r202-removed-20261117/` on 136); MemAvailable 122 GiB afterwards | P5 |
| **D21** | **KES registration (the bind at 90% of stake)** | Keep to the agreed order (`KES bind plan`: fixed releases, then externals, then register). The rebuilt follower is what makes a late first registration safe for the L2 (agent 340: the 926d2cf follower halts at it); never install an older L2 release on any host | all |
| **D22** | Explorer site | Which explorer tree blochl1.com is deployed from (section 9.3): the live site serves `index-DU1i6x2j.js` and has no `/l2rpc` or `/l2status` Function today (read 2026-11-17 05:00 UTC) | P11 |
| **D23** | `l2rpc.blochl1.com` DNS | A proxied record to A, Full (strict), per-hostname AOP (section 9). No record exists today (`dig` empty, 2026-11-17) | P11 |

## 3. Hosts

### 3.1 Host A: 136.244.93.186 (settler, prover, follower A, RPC A, shadow, monitor, gateway origin)

Read-only on 2026-11-17 04:05 UTC: 32 vCPU, 125 GiB RAM, 2.2 TB free on `/`, Ubuntu 24.04.5, systemd 255, 0 running
`bloch-*` units, Docker present without sudo for `ubuntu`, five `r202-*` containers running (not ours).

Memory budget (unit caps; sources: `docs/L2-MAINNET-GO-LIVE-V21.md` section 2 and the unit files): prover slice 100
GiB (`MemoryMax=100G`, `MemoryHigh=96G`) plus gnark about 18.5 GiB outside it, settler 32 GiB (its local fallback),
follower 6 GiB, RPC 4 GiB, shadow 4 GiB, monitor 256 MiB. All caps at once exceed the host; the plan accepts it only
because the prover's peak and gnark do not overlap (one measurement) and blocks are empty or deposit-only. Keep it so:
no user transactions on A (D10).

**Measured in the dry run (section 13): `install-prover-mainnet.py install --memory-gib 100 … --dry-run` on 136
printed `mem_available_gib: 119`, `memory_ok: false` while the `r202-*` containers ran; after their removal (D20,
done) the host read 122 GiB available and the same dry run (kit `b17b3ae`) printed `mem_available_gib: 121`,
`memory_ok: true` (the dry-run container itself holds about 1 GiB).** The real install refuses below `cap + 20 GiB` =
120 GiB, so the margin is 1 to 2 GiB: start nothing else on A before P5, and re-read `free -g` right before it. Do not lower the cap to fit: the plan's cap is what lets block 8,191 prove (agent 93: 84.2 to 85.4 GiB with
`ELEMENT_THRESHOLD=268435456`). Rule kept from the 2026-10-12 incident: no validator on A; the 30 `bloch-expansion@`
units on 136 stay disabled.

### 3.2 Host B: second follower, replica RPC, gateway origin (recommendation)

| Resource | Recommendation | Why (source) |
| --- | --- | --- |
| CPU | **4 dedicated vCPU** (x86-64) | follower `CPUQuota=200%` (`follower-rpc/bloch-l2-mainnet-follower.service:42`), RPC under its own cap, nginx workers 4 (`public-rpc/README.md`), the P4 `reconstruct` refresh |
| RAM | **16 GiB** | sum of the unit caps on B: follower `MemoryMax=6G` (`…-follower.service:41`) + RPC `MemoryMax=4G` (`…-rpc.service:48`) + refresh (`produce-dev reconstruct`; the replica kit caps it at 3 G, `replica/systemd/bloch-l2-replica-refresh.service:45`) + nginx + the OS ≈ 14.5 GiB. Measured use is far lower (follower RSS 0.6 GB, `replica/README.md:82`; reconstruct 107 MB, v2.1 plan section 2), but a host smaller than its caps can be driven into a global OOM, the 2026-10-12 failure. The plan's 8 GB (D3) is below the caps: finding F385-1, section 14 |
| Disk | **160 GB NVMe** | follower state 3.5 GiB at 191,319 verified L1 blocks (the 45.77 scratch follower, `du`, 2026-11-17); L1 height 231,239 at e8576 (`getchaininfo`, 2026-11-17 04:27 UTC) → about 4.2 GiB now; growth about 2,560 blocks a day (39,920 blocks over 1,399 epochs) ≈ 47 MB a day ≈ 17 GiB a year at today's block fill; every P4 refresh keeps `canonical.prev-*`; journals |
| Network | public IPv4, inbound 443 from Cloudflare ranges only, 18956 from A only, SSH by key | `public-rpc/setup-gateway.sh` firewall rules |
| OS | Ubuntu 24.04 LTS, systemd 255, ufw on, NTP on (K12) | the dry run's base image; K12 |
| Where | a **different provider and region from A** and from 199.247.22.8 (B's L1 source), not 45.77, not 209, not a validator host, no other user with `sudo` | a failure of A's provider must leave B serving; `public-rpc/README.md` "Host users" |

Examples that meet it (check the current offer before renting): Hetzner Cloud CCX23 (4 dedicated vCPU, 16 GB, 160 GB),
OVHcloud or Vultr dedicated-CPU 4 vCPU / 16 GB plans in a region other than A's.

### 3.3 Attestor hosts (five, one per operator)

**4 vCPU, 16 GiB, 80 GB NVMe**, inbound TCP 8787 for the feed. RAM: the attestor follower `MemoryMax=6G`
(`attestor/systemd/bloch-l2-attestor-follower.service:39`) + agent `MemoryMax=8G` (`attestor/systemd/bloch-l2-attestor.service:57`)
+ feed 128 MiB = 14.1 GiB of caps; the plan's 8 GB is below them (F385-1). Disk as B's follower plus the agent's
work directory.

## 4. Release signing (owner's Mac, `~/.cargo/bin/rsign`)

The procedure is `docs/RELEASE-SIGNING.md` sections 2 to 5 with the rebuilt release's values. The tool on the
owner's Mac is `~/.cargo/bin/rsign` (`rsign2 0.6.7`, checked 2026-11-17). The key is the Bloch release key
`1A5D96A5C4955EF7` (`RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6`), pinned in
`verify_release_signature.py`. Run in Terminal (rsign reads the password from the terminal: it fails with "Device
not configured" when there is none). `KIT` below is the frozen kit checkout of section 6.1.

Fetch both copies and compare (online). The release directory is the one 383 names; `l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd` stands for it.

```
mkdir -p ~/bloch-l2-signing-r18
```

Neither copy may exist yet (`scp -r` would nest into an existing folder); this must say "No such file" twice:

```
ls -d ~/bloch-l2-signing-r18/from-4577 ~/bloch-l2-signing-r18/from-136
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@45.77.142.123:l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd ~/bloch-l2-signing-r18/from-4577
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186:l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd ~/bloch-l2-signing-r18/from-136
```

Must print nothing:

```
diff -r ~/bloch-l2-signing-r18/from-4577 ~/bloch-l2-signing-r18/from-136
```

```
cd ~/bloch-l2-signing-r18/from-4577
```

Every line `OK`:

```
shasum -a 256 -c SHA256SUMS
```

Must print `4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb  SHA256SUMS`:

```
shasum -a 256 SHA256SUMS
```

The frozen kit must pin the same value:

```
grep 'artifacts/SHA256SUMS$' ~/worktrees/l2-prod-kit-r18/deployment/mainnet/GO-LIVE-PINS.sha256
```

Must say "No such file":

```
ls -l SHA256SUMS.minisig
```

```
cp ~/worktrees/publish-node-78d4921c-20261029/releases/bloch-pos-2026-10-29-hf123/bloch-release-20260922.pub ~/bloch-l2-signing-r18/
```

Must print `77a18b65d75508752100bdef83ed09bcf5ec0a203a1b3de1831548b4521ae243`:

```
shasum -a 256 ~/bloch-l2-signing-r18/bloch-release-20260922.pub
```

The trusted comment, derived from `release.json` and the hash of `SHA256SUMS`; copy its output into the `-t` value
of the sign command below, exactly, on one line:

```
python3 -I ~/worktrees/l2-prod-kit-r18/deployment/mainnet/verify_release_signature.py --print-trusted-comment ~/bloch-l2-signing-r18/from-4577
```

Sign offline: Wi-Fi off, cable out, mount the key volume if the key is not in `~/.rsign`; change only the `-s` path
if your key file is elsewhere. `rsign` asks for the key's password. Never use `-W` with the release key.

```
~/.cargo/bin/rsign sign -s ~/.rsign/rsign.key -p ~/bloch-l2-signing-r18/bloch-release-20260922.pub -x SHA256SUMS.minisig -c "signature from Bloch release key 1A5D96A5C4955EF7" -t "TRUSTED_COMMENT_PRINTED_ABOVE" SHA256SUMS
```

If it fails ("Could not verify signature with the provided public key ID" means another key was used), rsign leaves
an empty `SHA256SUMS.minisig`; remove it before trying again (measured in the dry run):

```
rm SHA256SUMS.minisig
```

Verify, still offline. Must print `Signature and comment signature verified`:

```
~/.cargo/bin/rsign verify -p ~/bloch-l2-signing-r18/bloch-release-20260922.pub -x SHA256SUMS.minisig SHA256SUMS
```

Must end with `signature OK`:

```
python3 -I ~/worktrees/l2-prod-kit-r18/deployment/mainnet/verify_release_signature.py --release-dir ~/bloch-l2-signing-r18/from-4577 --expect-sha256 4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb
```

```
cp SHA256SUMS.minisig ~/bloch-l2-signing-r18/from-136/
```

```
python3 -I ~/worktrees/l2-prod-kit-r18/deployment/mainnet/verify_release_signature.py --release-dir ~/bloch-l2-signing-r18/from-136 --expect-sha256 4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb
```

Record this hash next to D7:

```
shasum -a 256 SHA256SUMS.minisig
```

Then, online again, put the signature next to both build-host copies (`docs/RELEASE-SIGNING.md` section 5):

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing-r18/from-4577/SHA256SUMS.minisig ubuntu@45.77.142.123:l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd/
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing-r18/from-4577/SHA256SUMS.minisig ubuntu@136.244.93.186:l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd/
```

Keep `~/bloch-l2-signing-r18/from-4577` as the archive copy; sections 6 and 7 stage from it.

## 5. G0: the L1 is healthy after KES enforcement (entry gate)

The plan's G0 with three changes for a date after e8620: (1) `hf3_kes_enforce` is now **expected active** (it was a
NO-GO before e8620); (2) gate 4 reads "no L1 release after `906336fd` changed a crate the L2 links" (383 report 1.1
lists the method: `git diff 906336fd <new> --` over `crates/bloch-pos-committee`, `crates/bloch-crypto`,
`crates/bloch-l2-proof`, `crates/pqcrypto-internals`, `crates/bloch-pos-node/src/{lib,codec,genesis}.rs`); (3) gate 3
runs from epoch 8620 as well as from 7180. Run from any machine, at or after D1.

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' http://80.240.16.185:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' http://199.247.22.8:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' THIRD_L1_RPC_URL
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://199.247.22.8:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' THIRD_L1_RPC_URL
```

```
python3 ~/worktrees/l2-prod-kit-r18/deployment/mainnet/l1_finality_history.py --rpc http://80.240.16.185:8080 --from-epoch 8620
```

```
python3 ~/worktrees/l2-prod-kit-r18/deployment/mainnet/l1_finality_history.py --rpc http://199.247.22.8:8080 --from-epoch 8620
```

```
python3 ~/worktrees/l2-prod-kit-r18/deployment/mainnet/l1_finality_history.py --rpc THIRD_L1_RPC_URL --from-epoch 8620
```

GO only if: every HF1, HF2, HF3 entry and `hf3_kes_enforce` are `active: true` on all three, `hf3_lattice_emergency`
inactive; `finalized.epoch` ≥ 8710 (D1), lag ≤ 3, the same `finalized.root` on all three, heights within 3;
`l1_finality_history.py` exits 0 with `ok: true`, `empty_epochs` and `over_limit` empty, on all three (and once from
7180 on one node); gate 4 holds; `getl2settlement` shows `accepted` `null`, source height 1, slot 187200,
`profile.activated` true, and an `inbox` accounted for (a non-empty inbox changes the P6 block-1 reference); D1, D2,
D3, D4, D7, D13, D15 to D17, D20 decided and the release signed. **NO-GO** otherwise; wait and re-run.

## 6. Host A (136.244.93.186)

### 6.1 The frozen kit on the Mac

```
git -C ~/worktrees/l2-prod-deploy-r18-20261117 fetch origin
```

```
git -C ~/worktrees/l2-prod-deploy-r18-20261117 worktree add --detach ~/worktrees/l2-prod-kit-r18 b17b3ae44051d6c7676606476adf28caf21c3698
```

```
git -C ~/worktrees/l2-prod-kit-r18 status --porcelain -- deployment docs
```

Must print `38a0d1b499fc8ef646fd00717a6cd4f98358a4aa080408c93f8407bdff6f7511`:

```
shasum -a 256 ~/worktrees/l2-prod-kit-r18/deployment/mainnet/GO-LIVE-PINS.sha256
```

GO: empty `status` output and that hash. The kit is `main` `b17b3ae`, not `716a9e9` (same release, same signing
target; `main` adds the reviewed hygiene changes: the attestor custody tool's `--keys-dir`, host placeholders in the
runbooks, licences). Never build a release from the kit tip; binaries come only from the signed release.

### 6.2 P1: the host

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 'nproc; free -g; df -h /; systemctl list-units --all "bloch-*" --no-legend | grep -c running; docker ps --format "{{.Names}}"; sudo docker images --digests | grep sp1-gnark'
```

GO: 32, ≥ 120 GiB available, ≥ 200 GB free, 0 running `bloch-*` units, no `r202-*` container (D20), gnark digest
`e1a1cd62…`.

### 6.3 P2: stage and verify (no install)

From the Mac; `manifest` and `carryover` come from 45.77 through the Mac, never host to host. Re-run a copy that
stops with `lost connection`: the pin check after it refuses a short file.

```
mkdir -p ~/bloch-l2-signing-r18/staging
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 'ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/carryover.tsv.gz*' ubuntu@45.77.142.123:hf-release-kit-20261020/l2-agents/07-rpc/artifacts/mainnet.manifest ~/bloch-l2-signing-r18/staging/
```

Must print `7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd` for the manifest and
`4d1e2738baec39ec25e2e33968f72a47abb261f271de62fb48a33be55bfc83be` for the carryover (both measured 2026-11-17):

```
shasum -a 256 ~/bloch-l2-signing-r18/staging/mainnet.manifest ~/bloch-l2-signing-r18/staging/carryover.tsv.gz
```

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186 mkdir -p l2-golive-next/artifacts l2-golive-next/release-settler-v2
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing-r18/from-4577/* ubuntu@136.244.93.186:l2-golive-next/artifacts/
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing-r18/staging/* ubuntu@136.244.93.186:l2-golive-next/artifacts/
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/l2-prod-kit-r18/deployment/mainnet ubuntu@136.244.93.186:l2-golive-next/kit
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/l2-prod-kit-r18/deployment/devnet/settler_v3.py ubuntu@136.244.93.186:l2-golive-next/release-settler-v2/
```

On a second run remove `l2-golive-next/kit` on A first (`scp -r` nests into an existing directory). Then on A:

```
python3 -I /home/ubuntu/l2-golive-next/kit/verify_release_signature.py --release-dir /home/ubuntu/l2-golive-next/artifacts --expect-sha256 4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb
```

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

GO: `signature OK`; every line `OK`; `kit/GO-LIVE-PINS.sha256` = `38a0d1b499fc8ef646fd00717a6cd4f98358a4aa080408c93f8407bdff6f7511`; `artifacts/SHA256SUMS` =
`4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb`; `install-shadow.sh --verify` prints `build.json OK: L2 3d35a0f4, native 906336fd, HF1 7180/7186, HF2
7270, HF3 7360, KES enforce, slot-epoch binding and first-key floor 8620` and `verify OK (nothing installed)`
(measured in the dry run on the rebuild). The `settler-v2` staging and the release folders sit in agent scratch: copy them to a
kept location before go-live. NO-GO: any mismatch. Rollback: `rm -rf /home/ubuntu/l2-golive-next` on A.

### 6.4 P6 step 1: prepare the settler (creates the DA fee key; nothing on L1)

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py prepare --release /home/ubuntu/l2-golive-next/release-settler-v2
```

Record `da_funding_script_hash`. Back up the keystore and the passphrase separately, each with its own `gpg`
passphrase typed at the terminal; copy both files off the host to different media, then delete them on the host.

```
sudo tar czf - -C /var/lib bloch-l2-mainnet-da | gpg --symmetric --pinentry-mode loopback -o /home/ubuntu/da-keystore.tgz.gpg
```

```
sudo cat /etc/bloch-l2-mainnet-settler/da.passphrase | gpg --symmetric --pinentry-mode loopback -o /home/ubuntu/da-passphrase.gpg
```

Read the backup back before deleting it from the host (lists the keystore directory; asks the first passphrase):

```
gpg --pinentry-mode loopback -d /home/ubuntu/da-keystore.tgz.gpg | tar tzf -
```

The SP1 circuits for the local fallback:

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

GO: `prepare` exits 0; a second `prepare` is refused; `/etc/bloch-l2-mainnet-settler/da.passphrase` is `400 root`
and `/var/lib/bloch-l2-mainnet-da` is `700` owned by the settler user (all four measured in the dry run). Rollback:
`rollback` does not undo `prepare`; never remove a DA keystore that may hold funds.

### 6.5 P3 A: follower A and RPC A (installed, then only the follower started)

```
sudo install -D -m 0755 /home/ubuntu/l2-golive-next/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev
```

```
sudo runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev init --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

```
sudo runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev head --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679
```

GO: number 0, hash `632e45ae…f468`, state root `2ad7e807…c05d`. Dry run first, then the same command without
`--dry-run`:

```
sudo bash /home/ubuntu/l2-golive-next/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-next/artifacts --l1-rpc-url http://80.240.16.185:8080 --canonical /var/lib/bloch-l2-mainnet-settler/canonical --canonical-user bloch-l2-mainnet-settler --txpool /var/lib/bloch-l2-mainnet-settler/txpool --rpc-user bloch-l2-mainnet-rpc --read-group bloch-l2-mainnet-l2read --dry-run
```

```
sudo bash /home/ubuntu/l2-golive-next/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-next/artifacts --l1-rpc-url http://80.240.16.185:8080 --canonical /var/lib/bloch-l2-mainnet-settler/canonical --canonical-user bloch-l2-mainnet-settler --txpool /var/lib/bloch-l2-mainnet-settler/txpool --rpc-user bloch-l2-mainnet-rpc --read-group bloch-l2-mainnet-l2read
```

RPC A without the txpool (deposit-only):

```
sudo install -d /etc/systemd/system/bloch-l2-mainnet-rpc.service.d
```

```
printf '[Service]\nExecStart=\nExecStart=/opt/bloch/l2-mainnet/bloch-l2-settled-rpc --data-dir /var/lib/bloch-l2-mainnet-settler/canonical --view-dir /var/lib/bloch-l2-mainnet-rpc/rpc-view --finality-status /var/lib/bloch-l2-mainnet-follower/status.json --network f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966 --port 18955 --poll-ms 2000 --rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679\n' | sudo tee /etc/systemd/system/bloch-l2-mainnet-rpc.service.d/no-txpool.conf
```

```
sudo systemctl daemon-reload
```

Check before starting anything (each measured in the dry run): no `--txpool`, `LimitNOFILE=65536`, `User=bloch-l2-mainnet-rpc`
in `bloch-l2-mainnet-l2read`:

```
systemctl show -p ExecStart -p LimitNOFILE -p User -p SupplementaryGroups bloch-l2-mainnet-rpc
```

```
sudo systemctl enable --now bloch-l2-mainnet-follower
```

Note: the 1 gwei tip floor of the coordinator's decision (`3855ec2`, cross-area line of agent 339) belongs to the
December line; the launch kit (`716a9e9`, unchanged there in `b17b3ae`) carries no `--min-tip-wei` in `follower-rpc/install.sh`, the RPC unit or the
settler installer (checked by `git show`). With the txpool off (D10) no tip floor applies on A or B.

### 6.6 P3 GO (after about 65 to 80 minutes; both hosts)

```
sudo python3 -c "import json; s=json.load(open('/var/lib/bloch-l2-mainnet-follower/status.json')); print(s['l2_genesis']['finalized'], s['verified_blocks'], s['native_finalized_epoch'], s['verified_slot'])"
```

```
sudo journalctl -u bloch-l2-mainnet-follower --no-pager | grep -cE 'halted|StateRootMismatch|Transition'
```

GO: `True`; `native_finalized_epoch` ≥ 8707 (it trails the node by about 3) and advancing over 16 minutes;
`verified_blocks` equals `getchaininfo.finalized_height` within a poll; `0` halts. This is the first production
crossing of HF1, HF2, HF3, e8620 and the KES bind rules by the rebuilt follower: **any halt on a post-fork block is
an absolute NO-GO** (keep the state; do not skip a block). The one non-verifier halt (`node's finalized chain does
not descend from the verified head`, exit 3, after the single L1 source regressed) is handled as in the plan P3.

### 6.7 P4: RPC A

```
sudo systemctl enable --now bloch-l2-mainnet-rpc
```

```
curl -s --retry 30 --retry-delay 1 --retry-connrefused -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
```

```
curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["finalized",false]}'
```

```
curl -s -XPOST 127.0.0.1:18955 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_finality","params":[]}'
```

GO: `0xab162`; `finalized` and `safe` = block 0 `0x632e45ae…f468`; `bloch_finality` `l2_genesis.finalized: true`,
activation `618c9b80…` at slot 187200, `status.state: ok`, small `age_s`, schema `v2`. NO-GO: as in the plan P4.

### 6.8 P6 step 2: configure (read-only checks; nothing broadcast)

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py configure --rpc-urls http://80.240.16.185:8080,http://199.247.22.8:8080,THIRD_L1_RPC_URL --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800
```

```
sudo python3 -c "import json;c=json.load(open('/etc/bloch-l2-mainnet-settler/config.json'));print(c.get('skip_idle_blocks'),c.get('max_idle_seconds'),c.get('min_block_interval_seconds'),c['user_transactions'],'foreign_recovery' in c,c['remote_prover']['timeout_seconds'])"
```

GO: `True 86400 1800 False True 5700`, the last configure line `{"configured": …}`, `rpc-check` 3/3 with quorum 2,
dry run `ok: true`, block 1 `0ff59c11…ab25` with an empty inbox. Refusals measured in the dry run (each left no
`config.json`, so `start` stayed refused): a placeholder third URL, two URLs, a repeated host, an unreachable
quorum. Then the RPC restart oneshot and its path unit:

```
sudo systemctl start bloch-l2-mainnet-rpc-restart.service
```

```
systemctl show bloch-l2-mainnet-rpc-restart.service -p Result -p ExecMainStatus
```

```
sudo systemctl enable --now bloch-l2-mainnet-rpc-restart.path
```

### 6.9 P5: prover (after D20 and configure)

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/l2-prod-kit-r18/deployment/devnet/remote_prover.py ubuntu@136.244.93.186:l2-golive-next/
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

```
sudo python3 /home/ubuntu/l2-golive-next/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /var/lib/bloch-l2-mainnet-settler/ssh/id_ed25519.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400 --dry-run
```

GO: four `OK` lines before `SHA256SUMS` is written; the dry run prints `memory_ok: true` (it printed `false` at 119
GiB on 2026-11-17 with the `r202-*` containers running), the identity (ELF keccak `6e4c8440…`, policy
`154869964f…747d`), slice `MemoryMax=100G`, 32 threads, `ELEMENT_THRESHOLD: 268435456`, `timeout_seconds` 5400,
`authorized_keys` `restrict,from="127.0.0.1",command="… remote_prover.py …"` and `remote_prover.py` `601a52f4…`.
Then the same command without `--dry-run`. NO-GO: an identity mismatch, a `remote_prover.py` other than the pin (a
one-byte change was refused in the dry run), MemAvailable < 120 GiB.

### 6.10 P6 step 3: dry run with the Groth16 proof

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py dry-run --prove
```

```
sudo sh -c 'cat "$(ls -d /var/lib/bloch-l2-mainnet-settler/dry-run-* | tail -1)/dry-run-report.json"' | grep -E '"ok"|"tag"|"bytes"|"proof_policy"'
```

```
sudo sh -c 'cat "$(ls -d /var/lib/bloch-l2-mainnet-settler/dry-run-* | tail -1)"/work/*/proved.json' | grep -E '"name"|"where"'
```

GO: `ok: true`, tag `0x13`, 1155 bytes, policy `154869964f…747d`, `prove` `"where": "remote"`. NO-GO: `"where":
"local"`, any `halt`, an identity mismatch.

### 6.11 P7: shadow (before the first settlement)

```
sudo bash /home/ubuntu/l2-golive-next/kit/install-shadow.sh /home/ubuntu/l2-golive-next/artifacts --start
```

```
sudo journalctl -u bloch-l2-mainnet-shadow -o cat --no-pager | grep -c '"event": "halt"'
```

GO: `init` `632e45ae…`/`2ad7e807…`, `check` ok against the 3 RPCs, unit active, `0`. Measured in the dry run: with
no reachable quorum the installer prints `cannot read the accepted settlement; unit NOT installed` and installs
nothing.

### 6.12 P8: first settlement, **MAINNET WRITE**

Preconditions: 6.3 to 6.11 GO the same day; G0 re-read within the hour; one settler anywhere. Gate R-1, right
before `start`:

```
pgrep -af '[r]emote_prover'
```

```
sudo docker ps
```

GO: nothing printed by `pgrep`, no `sp1-gnark` container.

```
sudo python3 /home/ubuntu/l2-golive-next/release-settler-v2/install-settler-mainnet.py start --confirm-mainnet
```

```
sudo journalctl -u bloch-l2-mainnet-settler.service -f -o cat
```

Expected: `identity-checked`, `idle-end` `max-idle`, `l2-block-produced` 1, `proof-generated`, `remote-proof` exit 0,
`transaction-built`, `submitted`, `accepted`; then `idle-hold`. Independent check on each of the three RPCs:

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://199.247.22.8:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' THIRD_L1_RPC_URL
```

GO: `accepted.statement` L2 number 1 on all three; the shadow count still `0`; after FFG finality RPC A shows `safe`
then `finalized` = block 1. Stop conditions and limits as in the plan P8 (an accepted settlement cannot be undone).

### 6.13 P9: monitor (section 10 for alerting)

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
sed -e 's/--phase prelaunch/--phase live/' -e 's# --l2-rpc B=http://TBD-owner:18955##' -e 's#http://TBD-owner:8080#THIRD_L1_RPC_URL#' -e 's#$# --max-idle-seconds 86400 --backlog-state /var/lib/bloch-l2-monitor/backlog.json --set block_interval_seconds=1800 --set deposit_wait_warn=5400 --set deposit_wait_crit=10800#' /home/ubuntu/l2-golive-next/kit/monitor/monitor.env.example | sudo tee /etc/bloch-l2-monitor/monitor.env
```

Must print `0`:

```
grep -c TBD-owner /etc/bloch-l2-monitor/monitor.env
```

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

GO after the first L2 finalization: exit 0, or 1 with only WARN `alert_delivery` / `heartbeat` before D11. Remove
`--report dex=…` from `monitor.env` if the DEX monitor does not run on A. The L1 monitor (`kit/l1_monitor.py`) as
`docs/L1-MONITOR.md`, fed in with `--report l1=/var/lib/bloch-l2-monitor/l1-monitor.report.json:180`.

## 7. Host B (`IP_OF_B`, section 3.2)

Prepare the VPS: Ubuntu 24.04, ufw on with SSH allowed, SSH key only, NTP on. Stage from the Mac copies:

```
ssh -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@IP_OF_B mkdir -p l2-golive-next/artifacts
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing-r18/from-4577/* ubuntu@IP_OF_B:l2-golive-next/artifacts/
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing-r18/staging/* ubuntu@IP_OF_B:l2-golive-next/artifacts/
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/worktrees/l2-prod-kit-r18/deployment/mainnet ubuntu@IP_OF_B:l2-golive-next/kit
```

On B:

```
python3 -I /home/ubuntu/l2-golive-next/kit/verify_release_signature.py --release-dir /home/ubuntu/l2-golive-next/artifacts --expect-sha256 4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb
```

```
cd /home/ubuntu/l2-golive-next && grep ' artifacts/' kit/GO-LIVE-PINS.sha256 | grep -v ' artifacts/SHA256SUMS$' | sha256sum -c && sha256sum artifacts/SHA256SUMS kit/GO-LIVE-PINS.sha256
```

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

```
sudo bash /home/ubuntu/l2-golive-next/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-next/artifacts --l1-rpc-url http://199.247.22.8:8080 --canonical /var/lib/bloch-l2-mainnet-replica/canonical --canonical-user bloch-l2-mainnet-replica --txpool /var/lib/bloch-l2-mainnet-replica/txpool --dry-run
```

```
sudo bash /home/ubuntu/l2-golive-next/kit/follower-rpc/install.sh --artifacts /home/ubuntu/l2-golive-next/artifacts --l1-rpc-url http://199.247.22.8:8080 --canonical /var/lib/bloch-l2-mainnet-replica/canonical --canonical-user bloch-l2-mainnet-replica --txpool /var/lib/bloch-l2-mainnet-replica/txpool
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

B replays from zero (never seed it from another host), then 6.6's GO, then:

```
sudo systemctl enable --now bloch-l2-mainnet-rpc
```

GO as 6.7. After every finalized settlement (K5), the replica refresh, one command per block, as in the plan P4:

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

## 8. Attestors (P10): bundle distribution to the five operators

Required before any claim of 100 BLCH or more and before the exchange notice; not for settlements or deposits. The
custody tooling is `deployment/mainnet/attestor/keykit/` (rehearsed with throwaway keys by agents 203 and 311 under
real systemd 255 in `--network none` containers; `agents/203-attestor-final.md`, `agents/311-l2-r15.md`). The keys
never travel unsealed and are never handled by an agent.

1. **Owner, on the Mac or an air-gapped machine, offline**, in `KEY-HANDOFF-CHECKLIST.md` order:
   `make-operator-bundles.sh` with `--keys-dir DIR` on every mode (or `BLOCH_ATTESTOR_KEYS_DIR=DIR`; since `b17b3ae`
   the tool names no key folder and refuses without one): `preflight`, `seal` (one distinct passphrase per operator, 6+ random words), `verify`,
   `package --artifacts DIR` (DIR holds the rebuilt follower `d4d2b99a…` and producer `598873ae…`, the attestor
   `bloch-pos`, `mainnet.manifest`, `carryover.tsv.gz` and its `.sha256`, `SHA256SUMS` over the three binaries; the
   package step refuses binaries that are not the pins of 383's rebuilt `operator-pins-v2.sha256`), `backup-check`
   on two media, `shred-originals`. Each package's `IDENTITY.txt` records the kit commit: it must be
   `b17b3ae44051d6c7676606476adf28caf21c3698`.
2. **Send** each operator their `operator-I.tar` over one channel and its passphrase over a different one
   (`keykit/OWNER-SEND-LIST.md`); send the `PACKAGES.sha256` line for that tar over a third, or read it out.
3. **Each operator**, on their own host (section 3.3): `check-operator-bundle.sh --open`, then
   `install-attestor.sh install --artifacts DIR --index I --bundle attestor-I.sealed --l1-rpc-url http://L1:8080
   --feed-port 8787`, open inbound TCP 8787, compare `sha256sum /opt/bloch/l2-attestor/bloch-l2-native-follower
   /opt/bloch/l2-attestor/bloch-l2-produce-dev` with `d4d2b99a…` and `598873ae…`, enable the follower, wait 65 to
   80 minutes, `attestor_agent.py check`, then start the agent and the feed (`keykit/OPERATOR-INSTALL.template.md`).
   Each operator chooses an L1 RPC that is not A's or B's where possible.
4. **Owner, on A**, once per feed (five in the end), append ` --attest-drop http://FEED_HOST:8787` to `MONITOR_ARGS`
   in `/etc/bloch-l2-monitor/monitor.env`.
5. **Owner**: `release-owner-copy` for at least three indexes, so the owner holds fewer than 3 of 5.

GO: at least 3 operators (target 5) report `check-ok` with their `signer_index` and set `1c06adbb…`, plus
`rebuild-check-ok`; each follower's `native_finalized_epoch` advances; every operator re-sealed the backup under their
own passphrase; the monitor's `attestors` check lists every feed. NO-GO: fewer than 3 `check-ok`, or `halt … produce
differs`. Rollback per host: `touch /etc/bloch-l2-attestor/PAUSE`. Changing the set needs a hard fork.

## 9. Public RPC gateway and explorer (P11), **PUBLISH**

### 9.1 Certificates (owner)

On each of A and B, as root: `apt-get install nginx libnginx-mod-http-js`; set `worker_processes 4;` in
`/etc/nginx/nginx.conf` (the dry run's `plan` printed `NOTE: worker_processes is not a number` on a stock Ubuntu
nginx, which ships `auto`); place `/etc/ssl/bloch-l2rpc/origin.pem` and `origin.key` (Cloudflare Origin CA for
`l2rpc.blochl1.com`) and `/etc/ssl/bloch-l2rpc/aop-client-ca.pem` (the owner's own per-hostname Authenticated Origin
Pulls CA certificate, never Cloudflare's shared one: `render.py` refuses it, measured). The per-hostname AOP steps are
in `deployment/mainnet/public-rpc/README.md`, "Authenticated Origin Pulls with the owner's own certificate".

```
sudo bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh peer-cert
```

Copy each host's `/etc/nginx/bloch-l2rpc/peer/self.crt` to the other host as `/etc/nginx/bloch-l2rpc/peer/peer.crt`
(a host's own certificate as `peer.crt` is refused: `WRONG: peer.crt is this host's own certificate`, measured).

### 9.2 Gateway on A and B

On A:

```
sudo ROLE=sequencer NAME=l2rpc-a PEER=IP_OF_B:18956 PEER_ALLOW=IP_OF_B bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh plan
```

```
sudo ROLE=sequencer NAME=l2rpc-a PEER=IP_OF_B:18956 PEER_ALLOW=IP_OF_B bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh apply
```

On B:

```
sudo ROLE=replica NAME=l2rpc-b PEER=136.244.93.186:18956 PEER_ALLOW=136.244.93.186 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh plan
```

```
sudo ROLE=replica NAME=l2rpc-b PEER=136.244.93.186:18956 PEER_ALLOW=136.244.93.186 bash /home/ubuntu/l2-golive-next/kit/public-rpc/setup-gateway.sh apply
```

`plan` exits 0 even when it prints `MISSING:` lines: read them. `apply` refuses while the settled RPC does not answer
`0xab162` on 127.0.0.1:18955 (measured), runs `nginx -t` before reloading, and ends with a `curl -f` of `/health`
that fails (exit 22) while the backend has no head: then the gateway is installed but not healthy, and is not to be
put behind DNS (measured with a stub backend: `/health` said `"local":{"ok":false,"head":null…}`).

Then, in the Cloudflare dashboard (zone `blochl1.com`, D23): the proxied A record `l2rpc` → 136.244.93.186, SSL Full
(strict) for that hostname, per-hostname AOP enabled. Checks:

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

GO: both `/health` `"ok":true`; `0xab162` through the gateway; preflight `204` with `access-control-allow-origin: *`;
a direct request to the origin without the Cloudflare client certificate refused. Failover (A down): point `l2rpc`
at B by hand; reads continue, transactions return -32053.

### 9.3 Explorer hookup (D22)

Read on 2026-11-17 05:00 UTC: `https://blochl1.com/l2` answers the site's single-page app, `POST /l2rpc` answers an
empty body and `/l2status` the app's HTML, the page bundle is `index-DU1i6x2j.js`: the live site does **not** carry
the L2 explorer's Functions (`functions/l2rpc.js`, `functions/l2status.js` of `~/worktrees/explorer-r4-20261101`,
whose `wrangler.toml` sets `L2_RPC_URL = "https://l2rpc.blochl1.com/"`). `scripts/deploy-l2-explorer.sh deploy`
publishes the **whole** Pages project from its tree, so it must first be rebased onto the tree blochl1.com is
currently deployed from (another session worked on explorer branches today: `explorer-wallet-origin-pins-20261117`).
The owner or the explorer's maintainer, after 9.2 is GO:

```
cd ~/worktrees/explorer-r4-20261101
```

```
bash scripts/deploy-l2-explorer.sh check
```

```
bash scripts/deploy-l2-explorer.sh deploy
```

```
bash scripts/deploy-l2-explorer.sh verify
```

GO: `check` reads `0xab162` from `L2_RPC_URL`, `verify` passes on the live site, `/l2` shows the settlement record and
the L2 head. Open question carried from `agents/64-owner-checklist.md` C2: whether a Pages Function of the
`blochl1.com` zone may call a proxied hostname of the same zone; `verify` answers it on the live site; if it fails,
roll back the Pages deployment from the dashboard and decide D23 again.

## 10. Monitoring and alerting

What runs (section 6.13): the L2 monitor timer every 60 s on A (`l2_monitor.py --phase live` with D15, D16, D18), the
L1 monitor feeding it, `--attest-drop` probes of each attestor feed, the settler, shadow, follower and RPC units
watched through `events[UNIT]` and `unit[UNIT]`, `--binary` pins of installed files. B is watched through the
gateway's `/health` (A's monitor cannot reach B's loopback RPC; the env drops `--l2-rpc B=`).

Alert targets (D11), all `TBD-OWNER` in `/etc/bloch-l2-monitor/alert.json`: `webhook_url` with
`webhook_bearer_file`, `telegram.bot_token_file` and `telegram.chat_id`, `alert_command`, `heartbeat_url` (a dead-man
service; nothing else reports a dead monitor or host A down) and `heartbeat_fail_url`. Until set, WARN
`alert_delivery` and WARN `heartbeat` are expected and **nothing reaches anyone**. Recommended minimum: one push
channel (Telegram) plus one dead-man heartbeat on a service outside A's provider, plus an external HTTPS probe of
`https://l2rpc.blochl1.com/health` from that service (it covers B and the gateway, which A's monitor does not see).

Thresholds: `docs/MAINNET-OPS-RUNBOOK.md` section 3; expected false alarm D18 (`l2_head_age` on a healthy idle
chain). What each alert means and what to do: `docs/L2-OPERATOR-RUNBOOK.md` and `deployment/mainnet/KNOWN-ISSUES.md`.
Test the path once before P8: run the monitor service by hand with the targets set and confirm one alert and one
heartbeat arrive.

## 11. Go / no-go checklist

| # | Gate | GO | Section |
| --- | --- | --- | --- |
| 1 | Rebuilt release identity published by 383 and reviewed by 384 | `main` `b17b3ae` (383's line reviewed by 384); if `main`'s `deployment/` moves again, section 1 and the dry runs are redone first | 1 |
| 2 | 383's mainnet replay with the rebuilt follower past e8620 | PASS, recorded in 383's report | 1 |
| 3 | Dry runs of section 13 on the rebuilt release and kit | every step PASS | 13 |
| 4 | G0 after D1 (≥ e8710) | all conditions of section 5 | 5 |
| 5 | Release signed | `signature OK` on both copies; minisig hash recorded | 4 |
| 6 | Host A ready (D20) | P1 GO | 6.2 |
| 7 | Staging | P2 GO on A and B | 6.3, 7 |
| 8 | DA key backed up | two encrypted files on two media, read back | 6.4 |
| 9 | Followers A and B cross every fork | P3 GO, 0 halts | 6.6 |
| 10 | RPC A and B | P4 GO | 6.7, 7 |
| 11 | Configure | `True 86400 1800 False True 5700` | 6.8 |
| 12 | Prover | `memory_ok: true`, identity, pins | 6.9 |
| 13 | Proof dry run | `ok`, 0x13, 1155 bytes, `remote` | 6.10 |
| 14 | Shadow | active, 0 halts | 6.11 |
| 15 | R-1 | no proof job, no gnark container | 6.12 |
| 16 | **MAINNET WRITE** block 1 | accepted on all three RPCs; shadow 0 halts; finalized on RPC A | 6.12 |
| 17 | Monitor and alerts | exit 0 (or 1 with only the D11 WARNs); a test alert and heartbeat delivered | 6.13, 10 |
| 18 | Attestors | ≥ 3 `check-ok` | 8 |
| 19 | Gateway and explorer | section 9 GO | 9 |
| 20 | First deposit (P12 step 1 of the plan) | consumed, minted, escrow conserved | plan P12 |
| 21 | Exchange notice (plan P13), **PUBLISH** | only after 16 to 20 | plan P13 |

Any NO-GO stops the line at that gate. Gates 1 to 15 change nothing on L1 and can be repeated.

## 12. Rollback

| Phase | Rollback (as root on the host) | What stays |
| --- | --- | --- |
| Staging (6.3, 7) | `rm -rf /home/ubuntu/l2-golive-next` | nothing installed |
| Prepare (6.4) | none by tool; inspect before removing anything; never remove a DA keystore that may hold funds | user, DA key, passphrase |
| Follower and RPC (6.5, 7) | `systemctl disable --now bloch-l2-mainnet-rpc bloch-l2-mainnet-follower`, remove the two unit files and their `.service.d` directories, `systemctl daemon-reload`; move `/opt/bloch/l2-mainnet` aside before a reinstall | data directories |
| Configure (6.8) | a failed configure leaves no `config.json` (measured); re-run after fixing the cause | pending config |
| Prover (6.9) | `install-prover-mainnet.py rollback` (refuses while a proof runs; refuses with nothing recorded, measured) | circuits copy |
| Settler (6.12) | `install-settler-mainnet.py rollback`: unit removed, DB, keystore, passphrase, config kept (measured). **An accepted settlement cannot be undone**; a restart resumes from the accepted head after R-1 | everything on L1 |
| Shadow (6.11) | `install-shadow.sh --rollback` (moves its directories aside) | settler untouched |
| Monitor (6.13) | `systemctl disable --now bloch-l2-mainnet-monitor.timer` | read-only |
| Attestor (8) | `touch /etc/bloch-l2-attestor/PAUSE` | the key |
| Gateway (9) | `PEER_ALLOW=… setup-gateway.sh rollback` on each host (measured: removes the include, keeps the peer key), then delete the DNS record | peer key |
| Explorer (9.3) | roll back the Pages deployment in the dashboard | |

## 13. Dry runs (agent 385, 2026-11-17)

Harness: `deployment/prod-dryrun/` (this branch; outside `deployment/mainnet`, so no kit file or kit pin moves). It
builds `a385-dryrun:r18` from the host's `ubuntu:24.04` with systemd, Python 3, OpenSSH, nginx with njs and gpg, and
runs `dryrun-a.sh` (host A) and `dryrun-b.sh` (host B and the gateway) in containers named `a385-*` with systemd as
PID 1 and `--network none` (plus a dummy interface on TEST-NET-1 192.0.2.85/24 so IPv4 literals resolve; no route
anywhere). The 7.9 GiB circuits and the `settler-v2` staging are mounted read-only. The containers are removed after
each run; nothing was installed, enabled or started on 136 itself.

Deviations, each its own step: the release is signed with a THROWAWAY rsign key (`025480D2EC383A03`, generated
passwordless with `~/.cargo/bin/rsign generate -W` in agent scratch) so every check against the pinned key
`1A5D96A5C4955EF7` must FAIL and is counted as PASS when it does; `follower-rpc/install.sh` then runs with
`--allow-unsigned`; no unit is enabled or started; `configure` and the shadow's `check` cannot reach L1, so their
refusals are what is verified; the prover dry run takes a throwaway SSH public key instead of the one `configure`
creates; `docker` is a shim answering only the pinned gnark image check; the gateway's backend check is answered by a
stub returning `0xab162`; the certificates are throwaway self-signed files.

The signing step itself was dry-run on the Mac with the throwaway key, on both releases: both copies fetched (45.77:
49 s, 136: 39 s for `926d2cf`), `diff -r` empty, 8 `OK`, target `6d3bd628…` and, for the rebuild, `4039f26a…`, which
the kit `716a9e9` pins; sign, `rsign verify`, the kit verifier with the throwaway
key (`signature OK`, both copies) and against the pinned key (`signature key ID 025480D2EC383A03 is not the pinned
key 1A5D96A5C4955EF7`); signing with a different secret key than `-p` names is refused ("Could not verify signature
with the provided public key ID") and leaves an empty `SHA256SUMS.minisig`, as `docs/RELEASE-SIGNING.md` says.

| Run | Kit / release | Steps | Result |
| --- | --- | --- | --- |
| host A, 2026-11-17 04:29 UTC | kit `521a538`, release `bloch-l2-2026-11-03-next-native-78d4921c` (`6d3bd628…`) | 84 | **84 PASS, 0 FAIL** (5 INFO records: recorded, not graded) |
| host B + gateway, 04:33 UTC | same | 46 | **46 PASS, 0 FAIL** |
| host A, 2026-11-17 19:35 UTC | **kit `main` `b17b3ae`, release `bloch-l2-2026-11-17-launch-native-906336fd` (`4039f26a…`), after the `r202-*` removal** | 84 | **84 PASS, 0 FAIL**; `memory_ok: true` (121 GiB) |
| host B + gateway, 19:38 UTC | same (`b17b3ae`) | 46 | **46 PASS, 0 FAIL** |
| host A, 2026-11-17 04:53 UTC | kit `716a9e9`, release `bloch-l2-2026-11-17-launch-native-906336fd` (`4039f26a…`) | 84 | **84 PASS, 0 FAIL** (5 INFO) |
| host B + gateway, 04:57 UTC | **same (rebuild)** | 46 | **46 PASS, 0 FAIL** |
| negative control, 04:48 UTC | kit `521a538` with the rebuilt binaries (a scratch release `DRYRUN-385-rebuild-NOT-A-RELEASE`, throwaway-signed) | 84 | 60 PASS, 24 FAIL, as intended: refused at P2 (4 pin lines), `install-shadow.sh --verify`, `prepare` (`bloch-l2-produce-dev differs from its pin e3f1a290…`); every later step then fails for lack of the settler user |

What the 130 steps of each pair of runs covered (the same on both releases): P2 (signature refusal and acceptance, wrong target refused, every `SHA256SUMS` and pin
line, the pin-list hash, a one-byte kit change caught, `install-shadow.sh --verify`); P6 prepare (a second prepare
refused, passphrase `400 root`, DA directory `700`, both `gpg` backups made and read back); P3 (genesis
`632e45ae…`/`2ad7e807…` from `init`/`head`; `install.sh` refused without the owner's signature, dry run, install, a
second install refused; drop-in; no `--txpool`; `LimitNOFILE=65536`; the RPC's own user and read group; units
disabled; installed binaries equal the release); configure's four refusals with no `config.json` and `start` refused;
P5 (pin file, identity `6e4c8440…`, the forced `authorized_keys` line, `remote_prover.py` tamper refused, rollback
with nothing recorded refused, no prover user created; MemAvailable 119 GiB → `memory_ok: false`, recorded); P7
(no L1 RPCs refused, the unit not installed without quorum, rollback); P9 (files, env without `TBD-owner`, timer
disabled, a manual prelaunch run exits 2 with no network); rollbacks (settler keeps key and passphrase; units
removed; no active `bloch-*` unit left). B: signature, pins, replica user and database at genesis, install, drop-in,
`LimitNOFILE`, follower L1 = 199.247.22.8; the replica kit refuses the settler's L1 host and fails closed on its
identity preflight; gateway `plan` with missing files, `apply` refused without a backend, `peer-cert`, own
certificate as peer refused, shared-AOP-marked CA refused, `plan` clean, `apply` renders and passes `nginx -t`, the
unix hop `750 root www-data`, `/health` not ok with a headless backend, rollback removes the include.

Evidence: `~/Desktop/BLOCH-L2-DEX-BRIDGE-20261030/agents/385-evidence/dryrun-{a,b}-926d2cf/`, `dryrun-{a,b}-716a9e9/` and
`dryrun-{a,b}-b17b3ae/` (the rebuild) and `dryrun-a-rebuild-oldkit/` (the negative control) (`steps.jsonl` one line
per step with exit code, verdict and output tail; `log.txt` full output; `container-env.txt`).

To repeat on a host (as `ubuntu`, from a checkout of this branch copied to the host):

```
bash deployment/prod-dryrun/harness.sh build
```

```
bash deployment/prod-dryrun/harness.sh run a STAGE_DIR OUT_DIR_A
```

```
bash deployment/prod-dryrun/harness.sh run b STAGE_DIR OUT_DIR_B
```

`STAGE_DIR` holds `l2-golive-next/{artifacts,kit,release-settler-v2/settler_v3.py}` and
`dryrun/{rehearsal.pub,expect-sha256sums,expect-golive-pins,remote_prover.py}` (header of `harness.sh`).

## 14. Findings, not done, not proven

| ID | Severity | Where | Finding | Demonstration |
| --- | --- | --- | --- | --- |
| F385-1 | Low | `docs/L2-MAINNET-GO-LIVE.md` section 2 (D3, attestor row: 8 GB) vs `follower-rpc/bloch-l2-mainnet-follower.service:41`, `follower-rpc/bloch-l2-mainnet-rpc.service:48`, `attestor/systemd/bloch-l2-attestor.service:57`, `attestor/systemd/bloch-l2-attestor-follower.service:39` | The recommended 8 GB hosts are smaller than the sum of their units' memory caps (B about 10 GiB plus refresh and nginx; attestor 14.1 GiB). Measured use is low, but a host smaller than its caps can be driven into a global OOM, the failure of 2026-10-12. Fixed here by recommendation (16 GiB), no kit change | Argument (file:line) |
| F385-2 | Medium (operational), **resolved** | host 136, 2026-11-17 | The prover install refused the plan's 100 GiB cap: `mem_available_gib: 119`, `memory_ok: false` with the five `r202-*` containers running. Resolved: containers removed (owner authorization, coordinator); rerun 19:35 UTC: `121`, `memory_ok: true` | Test: dry-run step `P5.memory-gate` |
| F385-3 | Info | `public-rpc/setup-gateway.sh` `apply` | `apply` installs and reloads nginx, then exits 22 when `/health` is not ok; the include stays in place. Correct fail-loud behaviour, but an operator must read it as "installed, not healthy" (section 9.2 says so) | Test: dry-run steps `B7.apply`, `B7.health-not-ok` |
| F385-4 | Info | live explorer | blochl1.com has no `/l2rpc` or `/l2status` Function and no `l2rpc` DNS record (2026-11-17); the explorer hookup is a deploy of the explorer tree, not a configuration change (section 9.3) | Read-only `curl`, `dig` |

Not done / not proven:

- The final dry runs used `main` `b17b3ae`; a later kit change needs them run again (section 13).
- Nothing ran with network: `configure`'s RPC check and dry run, the shadow's `check`, the replica preflight, the
  gateway behind a real backend, the follower's replay, a real proof, P8. Those are covered by the real-proof
  launch rehearsal (task 250; agent 202 in round 11, 312 in round 15, and 383's rehearsal of the rebuild on a private
  chain of the released node, not yet run), not by this kit's dry runs.
- The attestor install (`install-attestor.sh`) and the custody flow (`make-operator-bundles.sh`) were not dry-run here:
  they need a sealed bundle made with the attestor `bloch-pos`; the earlier rehearsals (203, 311) are cited, not
  repeated on the rebuilt binaries.
- The L1 monitor install (`docs/L1-MONITOR.md`) and the alert targets (D11) were not exercised.
- Host B's numbers are a recommendation from unit caps and one footprint measurement on a scratch follower stopped
  at L1 height 191,319; no B host exists.
- Whether the settler's DA signer `bloch-pos` 78d4921c (`700631b0…`) stays valid after e8620 is for 383 and 384.
- The explorer's same-zone Function call (`agents/64-owner-checklist.md` C2) is unresolved until a live `verify`.
- The Portuguese owner copy of this document is outside the repository (English is the repository's language):
  `~/Desktop/BLOCH-L2-DEX-BRIDGE-20261030/agents/385-evidence/L2-PRODUCAO-DONO-PT.md`.
