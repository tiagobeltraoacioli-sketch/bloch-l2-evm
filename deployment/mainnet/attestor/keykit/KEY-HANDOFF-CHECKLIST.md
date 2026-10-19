# Mainnet attestor key handoff checklist

Applies to the five keys of set `1c06adbb…cc4b` (3-of-5) in `~/Desktop/L2-MAINNET-ATESTADORES`.

**Goal:** each key is sealed for one operator and installed on that operator's host, with an offline
backup. No plaintext `.sk` file is left on the Mac.

**Rule:** no single person or machine ever holds three keys again after this handoff.

## 0. Before you start

- [ ] Use the Mac, offline if you can (Wi‑Fi off).
- [ ] FileVault is on (`fdesetup status`).
- [ ] Desktop & Documents are not synced to iCloud (`defaults read com.apple.finder FXICloudDriveDesktop` prints `0`).
- [ ] Time Machine has no destination, or you will exclude the folder.
- [ ] Build `bloch-pos` from bloch-sis-pow `codex/l2-attestor-keystore-20261019`:
      `cargo build --release --bin bloch-pos` in `crates/bloch-pos-node`.
      Record its SHA-256.
- [ ] Choose five **different** passphrases, one per operator. Use 6 or more random words (diceware).
      Never reuse one, never write one next to its bundle, and never send one over the channel that
      carries the bundle.
- [ ] For each index 0–4, agree who the operator is and which host they will use. A host must not
      be a mainnet validator, the settler, or the host of another attestor.

## 1. Seal (on the Mac)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh seal
```

- [ ] The script prints `public keys ['0', '1', '2', '3', '4'] match`. This compares public keys
      only, against the pinned set.
- [ ] For each operator, type that operator's passphrase twice.
- [ ] Bundles appear in `~/L2-ATTESTOR-BUNDLES/attestor-I.sealed`, mode 0600. The folder is outside
      Desktop and Documents.

## 2. Verify (on the Mac)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh verify
```

- [ ] For each operator, type the passphrase once more. Every index prints
      `ok: sealed key opens and signs for attestor I`.
- [ ] `~/L2-ATTESTOR-BUNDLES/BUNDLES.sha256` lists the five bundle hashes. This file is public.

## 3. Offline backups (before anything leaves the Mac)

- [ ] For each operator, copy `attestor-I.sealed` and `BUNDLES.sha256` to **two** offline media,
      such as USB drives, kept in different places.
- [ ] Label each medium with the index only. Never write a passphrase on it.
- [ ] The media can be kept by you or by the operator. Decide which and write it down.
- [ ] On another machine, check that the media read back:
      `shasum -a 256 attestor-I.sealed` must match `BUNDLES.sha256`.

## 4. Hand each bundle to its operator

For each operator I:

- [ ] Send the bundle file `attestor-I.sealed` over one channel, for example in person, by encrypted
      file transfer, or with `scp` to the operator.
- [ ] Send the passphrase over a **different** channel, for example in person, by phone, or in a
      Signal message that disappears.
- [ ] The operator checks the bundle hash against your `BUNDLES.sha256` line, read to them over a
      third channel.
- [ ] The operator runs `install-attestor.sh install … --index I --bundle attestor-I.sealed` on
      their host (see `../README.md`) and types the passphrase once. The host key is re-sealed under
      a random host passphrase.
- [ ] The operator runs `check`. It must print `check-ok`, including `signer_index I` and `set_hash 1c06adbb…`.
- [ ] The operator starts the agent and deletes the copy of the bundle they brought to the host.
- [ ] The operator confirms by a message that does not include the passphrase.

**Gate before step 5:** at least three operators have `check-ok` on separate hosts. The first large
claim needs three. Five is the target.

## 5. Destroy the plaintext originals (on the Mac, only after steps 1–4)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh shred-originals
```

- [ ] For each index, type `DESTROY I`. The script refuses an index whose bundle has not been
      verified, or that changed after verification.
- [ ] Afterwards `ls ~/Desktop/L2-MAINNET-ATESTADORES` shows only `.pk` files and `attestors.set`.
- [ ] Empty the Trash. Make sure no other copy exists: AirDrop, Downloads, Time Machine, an external
      disk, or an earlier `cp`.
- [ ] `~/L2-ATTESTOR-BUNDLES` may stay on the Mac, since it holds only sealed bundles. Delete it
      after the offline backups are confirmed if you prefer.

Overwriting a file on an APFS SSD is best effort. FileVault keeps any leftover blocks encrypted at rest.

## 6. Afterwards

- [ ] Keep `BUNDLES.sha256` and a record of which operator holds which index, and where its backups are.
- [ ] If an operator's host is lost, they reinstall from their offline bundle with their passphrase.
- [ ] If a bundle **and** its passphrase are compromised, pause that agent. The set cannot be rotated
      without a hard fork, so plan the fork before two keys are at risk.
