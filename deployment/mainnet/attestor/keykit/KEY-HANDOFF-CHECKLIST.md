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
- [ ] Build `bloch-pos` from bloch-sis-pow `codex/l2-attestor-keystore-20261019` (e7d2c8b2):
      `cargo build --release --bin bloch-pos` in `crates/bloch-pos-node` of the worktree
      `~/worktrees/l2-attestor-keystore-20261019`. The kit's default `--bloch-pos` is
      `~/worktrees/l2-attestor-keystore-20261019/target/release/bloch-pos`. Record its SHA-256.
      This Mac binary is only for sealing; each operator host needs a **Linux** `bloch-pos` built
      from the same commit, in its artifacts directory (step 4).
- [ ] `~/L2-ATTESTOR-BUNDLES` does not exist yet (`seal` refuses to overwrite a bundle).
- [ ] Run every command from the repository root (`cd ~/worktrees/l2-mainnet-attestor-20261019`),
      or give the script's full path. The script needs no `sudo`.
- [ ] Optional: rehearse the whole flow with throwaway keys on a Linux box first:
      `tests/rehearse_owner_flow.sh` (see its header). It never reads the real key folder.
- [ ] Choose five **different** passphrases, one per operator. Use 6 or more random words (diceware).
      Never reuse one, never write one next to its bundle, and never send one over the channel that
      carries the bundle.
- [ ] For each index 0–4, agree who the operator is and which host they will use. A host must not
      be a mainnet validator, the settler, or the host of another attestor.

## 1. Seal (on the Mac)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh seal
```

- [ ] The script prints `set 1c06adbb7fef042f… 3-of-5: public keys ['0', '1', '2', '3', '4'] match`.
      This compares public keys only, against the pinned set.
- [ ] For each operator, after `== attestor I: choose the passphrase for operator I`, type that
      operator's passphrase at `New sealed-key passphrase:` and again at `Repeat passphrase:`.
      Each index prints `sealed attestor I of 3-of-5 set 1c06adbb…`. Argon2id takes a few seconds
      per key.
- [ ] If a passphrase is mistyped (`passphrases do not match`), the script stops; the indices already
      sealed stay. Re-run with only the rest, e.g. `seal --index 3 --index 4`.
- [ ] Bundles appear in `~/L2-ATTESTOR-BUNDLES/attestor-I.sealed`, mode 0600. The folder is outside
      Desktop and Documents.

## 2. Verify (on the Mac)

```
deployment/mainnet/attestor/keykit/make-operator-bundles.sh verify
```

- [ ] For each operator, type the passphrase once more at `Sealed attestor key passphrase:`. Every
      index prints `ok: sealed key opens and signs for attestor I of 3-of-5 set 1c06adbb…`.
      A wrong passphrase prints `authentication failed` and stops; nothing is recorded for that index.
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
- [ ] The operator has an artifacts directory on the host (Linux `bloch-pos` from e7d2c8b2, the RC
      `bloch-l2-native-follower` and `bloch-l2-produce-dev`, `mainnet.manifest`,
      `carryover.tsv.gz` + `.sha256`, and `SHA256SUMS` over the three binaries). See `../README.md`.
- [ ] Before installing, the operator checks the bundle on the host:
      `grep ' attestor-I.sealed$' BUNDLES.sha256 | sha256sum -c` prints `attestor-I.sealed: OK`.
- [ ] The operator runs, as root, from `deployment/mainnet/attestor`:
      `./install-attestor.sh install --artifacts DIR --index I --bundle /path/attestor-I.sealed --l1-rpc-url http://HOST:8080`
      (plus `--publish-url`/`--publish-command`). It prints `Type the TRANSPORT passphrase…`; the
      operator types it once at `Sealed attestor key passphrase:`. The key is re-sealed under a random
      host passphrase and checked (`ok: sealed key opens and signs for attestor I …`). Nothing starts.
- [ ] The operator starts **only the follower** and waits for its first replay (30–60 min) until
      `status.json` shows `l2_genesis.finalized=true`. `check` before that ends in `check-not-ready`.
- [ ] The operator runs `check` (the `systemd-run … attestor_agent.py check` line the installer
      prints). It must print `check-ok`, including `signer_index I` and `set_hash 1c06adbb…`.
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
