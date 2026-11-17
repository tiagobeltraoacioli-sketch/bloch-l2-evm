# The launch build rebuilt against node release 906336fd: what changes for the owner

Round 18 (2026-11-17), agents 348 and 383. Release `bloch-l2-2026-11-17-launch-native-906336fd`, build commit
`3d35a0f42f9b5f1a8657ee892dc3239a789a50ae`, native `906336fd35f157dac380523b59dee8a5a325175a`. **Unsigned.**
Signing target: release `SHA256SUMS` `4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb`.

## 1. Why

The earlier launch release (build `926d2cf`, native `78d4921c`, signing target `6d3bd628…`) follows mainnet today,
but once KES binds on L1 (90% of stake registered) the first validator that registers its FIRST KES key afterwards
signs with its static key under node release 906336fd's first-key floor, which native 78d4921c refuses. From that
block every follower, producer, settler, shadow and attestor feed of 926d2cf halts for good
(`docs/L2-FOLLOWER-NODE-906336FD.md`, agent 340, reproduced on a private chain). The L2 sources need no change: only
the native commit they link and its pinned lock.

## 2. What moved and what did not

| Item | Earlier (926d2cf / 78d4921c) | Launch (3d35a0f / 906336fd) |
|---|---|---|
| `bloch-l2-native-follower` | `cdf5da5c…` | `d4d2b99a20f6093cbaf2b9cebead41b3c6b4bf5aad37f2a091752746a659fe96` |
| `bloch-l2-produce-dev` | `e3f1a290…` | `598873aef6770002297a710387969218dd7d684ea8e9d8bdcf067d43123b37db` |
| `bloch-l2-settled-rpc` | `53e88565…` | same bytes |
| `sequencer_mainnet.py` | `15daa26f…` | same bytes |
| `build.json` | `6ec47c0c…` | `9131838921a728fe3a03f0d2b7bd28e6a48d24fda2041fa49b95b5ea7a0d8693` (adds the two 8620 gates) |
| settlement-recovery lock | `a3c38a46…` | `ab7b3a0901f142d5e2a3905c68cf97eb69eb5cc968407621e55f21f14668cafa` |
| release `SHA256SUMS` (signing target) | `6d3bd628…` (**never sign**) | `4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb` |
| guest `settlement_v3_mainnet`, SP1 host, program keys, proof policy | `203114bf…`, `3a24c36d…`, BN254 `007139f7…`, policy `15486996…` | unchanged (re-derived) |
| L2 genesis, `mainnet.manifest`, `carryover.tsv.gz`, attestor set | `632e45ae…`, `7eef82a7…`, `4d1e2738…`, `1c06adbb…` | unchanged |
| DA signer `bloch-pos` (settler) | `700631b0…` (78d4921c) | unchanged: it builds and signs DA transactions only, whose format and L1 checks did not change |

Every kit pin of the moved items moved with them (`GO-LIVE-PINS.sha256` `614026a0…` at the kit commit that pins
this release; `deployment/mainnet/test_launch_release_906336fd.py` checks every pinning file against the release's
metadata in `deployment/mainnet/testdata/release-906336fd/`).

## 3. The owner's procedure, step by step: the delta to the plan

The go-live plan (`docs/L2-MAINNET-GO-LIVE.md`) and the signing ceremony (`docs/RELEASE-SIGNING.md`) are updated
in place; their commands are textually those of the earlier kit except for the hashes, the release name and path,
and two added checks. What the owner does differently:

1. Check out the kit at the bloch-l2-evm `main` commit that contains this document (not the earlier kit tip named in
   `agents/PINS-NEXT.md`).
2. Sign `4039f26a…`, following `docs/RELEASE-SIGNING.md` from section 2. The release folders are at
   `~/l2dexbridge-20261030/l2-launch-rebuild-r17/release/bloch-l2-2026-11-17-launch-native-906336fd/` on 45.77 and 136.
   New check before the copy: `~/bloch-l2-signing/from-4577` and `from-136` must not exist (an earlier copy would
   take the new one inside it).
3. Plan P2 GO lines now read `artifacts/SHA256SUMS` = `4039f26a…` and `install-shadow.sh --verify` prints
   `build.json OK: L2 3d35a0f4, native 906336fd, HF1 7180/7186, HF2 7270, HF3 7360, KES enforce, slot-epoch binding and
   first-key floor 8620`.
4. Attestor operator packages are cut from this kit (`make-operator-bundles.sh package`); packages cut before carry
   the earlier follower and producer and are refused by the installer of this kit.
5. P7: the shadow halt count is taken since the unit's last start (the F312-4 repair line, already in the kit).
6. Order with the L1: the KES plan of 2026-11-15 (releases, external validators, then the owner's registration that
   binds KES) is safe for the L2 only if no L2 host runs the 926d2cf release when KES binds. With this release that
   constraint is gone: install this release, never the earlier one.

## 4. Evidence

- Build byte-equal on both hosts, release folders byte-equal, program identity re-derived: agent 348/383 report
  (`agents/348-l2-launch-rebuild-r17.md` in the coordination folder), sections 1.1 to 1.6.
- Replay of real mainnet L1 history from genesis with the release follower `d4d2b99a…`, and the real-proof launch
  rehearsal with the KES late-registration case on a private chain of 906336fd: same report, sections 3 and 4.

## Not done / not proven here

- The release is not signed (owner, D7).
- The guest was not rebuilt with its own macOS recipe (Rust is not built on the coordination Mac); unchanged guest
  inputs are proven by an identical Linux rebuild of `f0d53fe`, `926d2cf` and `3d35a0f` and by the source diff.
- `docs/public/L2-MAINNET-GO-LIVE.md` still carries the earlier hashes (its redaction tool needs private lists).
