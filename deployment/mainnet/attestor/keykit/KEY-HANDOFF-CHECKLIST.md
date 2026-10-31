# Mainnet attestor key custody and handoff checklist

Applies to the five keys of set `1c06adbb…cc4b` (3-of-5) in `~/Desktop/L2-MAINNET-ATESTADORES`.

**Goal:** each key is sealed for one operator and installed on that operator's host. Each operator
holds an offline backup under a passphrase only they know. No plaintext `.sk` file is left anywhere,
and the key holder ends with no key.

**Rule:** after the handoff, no single person, machine or storage place holds three keys.

Tool: `keykit/make-operator-bundles.sh` (owner side) and `keykit/check-operator-bundle.sh` (operator
side, shipped inside each bundle). Rehearsal with throwaway keys: `tests/rehearse_custody_flow.sh`.

## The risk until the handoff is done

Today the key holder alone holds **5 of 5** keys in plaintext, in one folder on one Mac. The
threshold is 3. Until at least three keys have left the holder's control, one compromised laptop,
backup or person can sign any large withdrawal root. The set cannot be rotated without an L1 hard fork.

The flow below shrinks that exposure in steps:

| After | Plaintext keys | Keys the holder can still use alone |
| --- | --- | --- |
| today | 5 | 5 (plaintext) |
| seal + verify + package + backups + shred (one sitting, offline) | 0 | 5 (sealed bundles + the five transport passphrases) |
| operator I installs, re-seals its backup, holder runs `release-owner-copy I` | 0 | one fewer per operator |
| three operators released | 0 | 2 (below the threshold) |
| all five released | 0 | 0 |

`status` prints the last column at any time and warns while it is 3 or more.

## Recommended order

1. **Choose the five operators and hosts first** (section 0). Do not seal before you know who
   receives each index: sealing starts the clock.
2. **Seal, verify, package, back up and shred in one offline sitting** (sections 1–5). The plaintext
   then exists for hours, not days. Shredding before the handoff is safe because `verify` proved each
   bundle opens and signs, `backup-check` proved two read-back copies, and the rehearsal proved a
   bundle sealed on the Mac opens with the Linux `bloch-pos` on an operator host.
3. **Hand off the first three operators as soon as they are ready**, one index at a time
   (section 6). Release each index (section 7) as soon as that operator reports `check-ok` and a
   re-sealed backup. After the third release you are below the threshold.
4. **Then the last two.** Five running attestors tolerate two hosts down.
5. Never give two indices to one person, one host, one hosting account, or one backup location.

While you still hold three or more bundles:

- keep the five passphrases on paper, in a different place from the bundles, never in a password
  manager or a file on the same Mac;
- keep the Mac offline when the bundles folder is mounted, and keep the backup media apart;
- do not travel with all bundles together.

## 0. Before you start

- [ ] Five operators chosen, one index each. Each one has a dedicated Ubuntu 24.04 x86_64 host that is
      not a mainnet validator, the settler, or another attestor (see `OPERATOR-ONBOARDING.md`).
- [ ] Build `bloch-pos` on the Mac from bloch-sis-pow `codex/l2-attestor-keystore-20261019`
      (e7d2c8b2): `cargo build --release --bin bloch-pos` in `crates/bloch-pos-node` of
      `~/worktrees/l2-attestor-keystore-20261019`. The rehearsal used the Mac build `1d69e683…`.
      Operators use the Linux build pinned in `operator-pins-v2.sha256` (`093909a2…`).
- [ ] Wi-Fi off. Then run `preflight`: it must show no `FAIL`.

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh preflight
```

- [ ] Choose five **different** passphrases (6+ random words each). Write each on its own paper slip,
      labelled with the index only.

## 1. Seal

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh seal
```

- [ ] It prints `set 1c06adbb7fef042f… 3-of-5: public keys ['0', '1', '2', '3', '4'] match`.
- [ ] For each I, type passphrase I at `New sealed-key passphrase:` and `Repeat passphrase:`.
      Each index prints `sealed attestor I of 3-of-5 set 1c06adbb…`.
- [ ] A mistyped repeat stops the script; re-run with only the rest, e.g. `seal --index 3 --index 4`.

## 2. Verify (the decrypt test)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh verify
```

- [ ] Type each passphrase once. Each index prints
      `ok: sealed key opens and signs for attestor I of 3-of-5 set 1c06adbb…`.

## 3. Package

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh package
```

- [ ] Each index prints `packaged attestor I: …/operator-I.tar (SHA-256)`. `PACKAGES.sha256` is public.
- [ ] Each package holds the sealed key, the public key, the set, `IDENTITY.txt`,
      `ARTIFACTS.sha256` (v2 follower `c18752fd…`, producer `55dda83b…`, `bloch-pos` `093909a2…`,
      manifest `7eef82a7…`, carryover `4d1e2738…`), `INSTALL.md`, `ONBOARDING.md`, the kit and
      `check-operator-bundle.sh`, all listed in `CONTENTS.sha256`.
- [ ] Optional: `--artifacts DIR` embeds the Linux binaries after checking them against the pins.

## 4. Two offline backups

- [ ] Copy every `operator-I.tar` and `PACKAGES.sha256` to two USB drives. Then, for each drive:

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh backup-check --media /Volumes/USB-A --label USB-A
```

- [ ] Each index prints `ok: USB-A holds operator-I.tar`. Repeat with the second drive and a
      different label. Store the drives in two different places, away from the passphrase slips.

## 5. Destroy the plaintext originals (same sitting)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh shred-originals
```

- [ ] It refuses an index that is not verified, not packaged, or not on two checked media.
- [ ] Type `DESTROY I` for each index. It then runs `post-shred-check`: the keys folder must hold only
      `.pk` files and `attestors.set`; nothing named `attestor-I.sk` in the Trash or Spotlight.
- [ ] Empty the Trash. Check Downloads, AirDrop, mail drafts, chats and other disks by hand.

## 6. Hand each bundle to its operator

For each operator I:

- [ ] Send `operator-I.tar` over one channel (in person, encrypted transfer, `scp`). Record it:
      `record --index I --event bundle-delivered --note "channel"`.
- [ ] Send passphrase I over a **different** channel (in person, phone, disappearing Signal message).
      `record --index I --event passphrase-delivered`.
- [ ] Read the `operator-I.tar` line of `PACKAGES.sha256` over a third channel.
      `record --index I --event hash-confirmed`.
- [ ] The operator follows `INSTALL.md` in the bundle: check, install, follower replay, `check-ok`,
      agent start, re-seal of their backup under their own passphrase, delete the bundle copy.
- [ ] The operator sends the reply from `ONBOARDING.md` section 6. Record it:
      `record --index I --event operator-check-ok --note "host IP, epoch X->Y"` and
      `record --index I --event endpoint-received --note "endpoint"`.

## 7. Release your copy of index I

Only after operator I has `check-ok` **and** has re-sealed their backup:

- [ ] Delete `operator-I.tar` from both USB drives. (If you decided to keep an escrow copy of index I,
      it goes to a custodian that holds no other index: `record --index I --event backup-to-escrow`.)
- [ ] Destroy the paper slip with passphrase I.

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh release-owner-copy --index I
```

- [ ] Type `RELEASE I`. The Mac copies of bundle I are deleted. `status` shows one fewer key under
      your control. When all five are released, wipe both drives.

## 8. Afterwards

- [ ] Keep `PACKAGES.sha256`, `CUSTODY-LEDGER.tsv` and a table: index → operator → host → endpoint.
      None of these is secret.
- [ ] Host lost: the operator reinstalls from their own re-sealed backup (`install-attestor.sh
      install --bundle attestor-I.operator.sealed`), typing their own passphrase.
- [ ] A bundle **and** its passphrase compromised: `sudo touch /etc/bloch-l2-attestor/PAUSE` on that
      host and plan the set-rotation hard fork before a second key is at risk.

Overwriting a file on an APFS SSD is best effort. FileVault keeps any leftover blocks encrypted at rest.
