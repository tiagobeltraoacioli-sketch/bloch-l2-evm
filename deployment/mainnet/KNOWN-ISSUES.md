# Bloch L2 mainnet, deposit-only launch: known issues

Release `926d2cf` (signing target `SHA256SUMS` `6d3bd628…`), launch kit of round 15.

Each entry below stays open for the deposit-only launch by decision of the coordinator: closing it
needs a new release build, or it does not affect a launch without user transactions. Each entry
says what the issue is, what the operator sees, and what the operator does.

Identifiers: `R308-…` is the review `agents/308-l2-review-r15.md`, `F312-…` is the real-proof
rehearsal `agents/312-l2-proof-rehearsal-r15.md`.

Monitor check names are those of `l2_monitor.py` (`unit[settler]`, `unit[shadow]`,
`events[settler]`, `settlement_age`, `foreign_settlements`, `attestors`). Paths are those the
installers use on host A.

| # | Issue | Area | First sign |
|---|---|---|---|
| 1 | F312-4: a foreign settlement stops the shadow producer for good | shadow | `unit[shadow]` CRIT after `foreign_settlements` WARN |
| 2 | F312-5: user transactions cannot be enabled on this release | settled RPC, settler | `producer-refused-spool … Permission denied`, empty blocks |
| 3 | R308-24: a damaged `submitted.json` or a stray `orphaned` name restarts the settler for ever | settler | `retry` events, `unit[settler]` restarts, no `halt` |
| 4 | R308-25: a settlement L1 refuses for good is rebroadcast for ever while one L1 RPC is down | settler | `submit-refused` with `"kind": "retry"` repeating |
| 5 | R308-26: kept databases are pruned by wall-clock stamp | settler | a kept `canonical.orphaned-*` copy is missing |
| 6 | R308-19: the release build inherits ambient Cargo configuration | build | none on screen |
| 7 | R308-2P-6: enough client keys with requests in flight still fill the gateway | public RPC | HTTP 429, `-32005` "Busy" for everyone |
| 8 | R308-2P-9, R308-18: limits of the attestor's signing memory | attestor | `halt` "refusing a second signature", `marker-not-written` |
| 9 | R308-2P-12: address rules of the installers | shadow, attestor | no new `shadow-match` after a DNS change |
| 10 | R308-21: what `upgrade` and rollback do not cover | attestor, settler, follower installers | see the entry |

## 1. F312-4: a foreign settlement stops the shadow producer for good

**What it is.** Anyone may settle an L2 block (it needs a valid proof of a block the rules allow).
The settler recovers alone. The shadow producer does not: its database does not hold the foreign
block, so it halts and is not restarted. The settler's later blocks are then built without the
independent check. No funds move and the L2 does not stop.

**What the operator sees.**

- Settler journal: `foreign-settlement-waiting-finality`, then `foreign-settlement-recovered`.
- Shadow journal: `{"event": "halt", "reason": "L2 head N cannot extend accepted settlement N+1"}`,
  exit 3, unit `failed`.
- Monitor: `foreign_settlements` WARN, then `unit[shadow]` CRIT and `events[shadow]` CRIT.

**What the operator does.** Reinstall the shadow, each time, after the settler logged
`foreign-settlement-recovered`. The two commands and the halt count that is valid afterwards are in
`SETTLER-RUNBOOK.md`, section "Foreign settlements". Do not stop or restart the settler for this.

## 2. F312-5: user transactions cannot be enabled on this release

**What it is.** The settled RPC of release `926d2cf`, running as its own user
`bloch-l2-mainnet-rpc`, writes every spool file with mode 0600. The settler is only in the file's
group and cannot read it. The launch is deposit-only, so the spool is not used. Decision D10 (user
transactions) is therefore not a configuration switch on this release: it needs the next build.

**What the operator sees**, only if step 2 of P12 in the go-live plan is run on this release:

- Settler journal: `{"event": "producer-refused-spool", "number": N, "reason": "producer refused
  extend: … /var/lib/bloch-l2-mainnet-settler/txpool/….tx: Permission denied (os error 13)"}`.
- The settler proves and settles an empty block at every pacing interval while a transaction
  waits. `eth_sendRawTransaction` returned a hash, and the transaction is in no block.

**What the operator does.** Do not run step 2 of P12 on this release. If it was run, turn the
switch off again and restart the settler:

```
sudo python3 -c "import json;p='/etc/bloch-l2-mainnet-settler/config.json';c=json.load(open(p));c['user_transactions']=False;json.dump(c,open(p,'w'),indent=2)"
```

```
sudo systemctl restart bloch-l2-mainnet-settler
```

Then restore the drop-in `no-txpool.conf` of P3 step 4 and restart the settled RPC. Changing the
mode of spool files by hand is what the rehearsal did to go on; it is not a launch procedure.

## 3. R308-24: a damaged `submitted.json` or a stray `orphaned` name restarts the settler for ever

**What it is.** Two damaged-state cases end in a restart loop without a `halt` event. Both need
outside damage or an operator's own copy; the settler writes these files atomically.

- (a) `/var/lib/bloch-l2-mainnet-settler/work/N/submitted.json` is empty, cut short or not a JSON
  object.
- (b) After a foreign-settlement recovery, a directory whose name starts with `canonical.orphaned-`
  or `work-orphaned-` and does not end in a number (for example an operator's `.bak` copy) sits in
  `/var/lib/bloch-l2-mainnet-settler`. The swap journal `canonical.recovery.json` then never
  finishes.

**What the operator sees.**

- Settler journal: `{"event": "retry", "reason": "JSONDecodeError: …"}` or
  `"AttributeError: 'list' object has no attribute 'get'"` for (a);
  `"ValueError: invalid literal for int() with base 10: '….bak'"` for (b). The same reason every
  time, `failures` counting up, then the unit exits 1 and systemd starts it again after 60 s.
- No `halt` event. No settlement goes out; deposits wait.
- Monitor: `events[settler]` (repeated `retry`), `unit[settler]` WARN from 5 restarts,
  `settlement_age` WARN after 25 min and CRIT after 45 min.

**What the operator does.** Stop the settler:

```
sudo systemctl stop bloch-l2-mainnet-settler
```

For (a), move the damaged record out of the work directory and keep it (replace `N` by the block
number of the `retry` line):

```
sudo mv /var/lib/bloch-l2-mainnet-settler/work/N/submitted.json /root/submitted.json.damaged-N
```

For (b), move the stray copy out of `/var/lib/bloch-l2-mainnet-settler` (replace `NAME` by the
name in the `retry` line). Never remove a name that ends in a number: the settler manages those.

```
sudo mv /var/lib/bloch-l2-mainnet-settler/NAME /root/NAME
```

Start the settler and watch for `submitted` and `accepted`:

```
sudo systemctl start bloch-l2-mainnet-settler
```

## 4. R308-25: a settlement L1 refuses for good is rebroadcast for ever while one L1 RPC is down

**What it is.** With one L1 RPC down (the fault the quorum tolerates) and every live RPC refusing
the settlement bytes for good, the refusal is classed as temporary. The settler rebroadcasts and
never halts by itself. Nothing is spent: a refused send costs nothing.

**What the operator sees.**

- Settler journal: `{"event": "submit-refused", "number": N, "kind": "retry", "errors": […]}`
  repeating for the same `N`, one of the errors a connection failure, the others an `RpcError`.
  No `halt`.
- Monitor: `settlement_age` WARN after 25 min, CRIT after 45 min; deposits wait.

**What the operator does.** Read the `errors` of the `submit-refused` line. Bring the L1 RPC that
does not answer back, or replace it with `install-settler-mainnet.py configure --rpc-urls` as in P6
of the plan. Once every configured RPC answers, a refusal for good is classed `terminal` and the
settler halts (exit 3): continue with the `halt` row of the event table in `SETTLER-RUNBOOK.md`. Do
not delete anything from the work directory.

## 5. R308-26: kept databases are pruned by wall-clock stamp

**What it is.** After a foreign-settlement recovery the settler keeps the replaced database as
`canonical.orphaned-STAMP` (two copies at most) and orders them by the wall-clock stamp. After a
backward step of the host clock, the copy made a moment ago can sort oldest and be deleted. On this
release only that review copy is lost; the settler does not need it.

**What the operator sees.** No log line. After `foreign-settlement-recovered`, the directory
`/var/lib/bloch-l2-mainnet-settler` holds no `canonical.orphaned-*` newer than the recovery.

**What the operator does.** Nothing for operation. Keep host A's clock disciplined without steps
(chrony or systemd-timesyncd running). If a foreign settlement is to be analysed, copy the newest
`canonical.orphaned-*` away right after the recovery.

## 6. R308-19: the release build inherits ambient Cargo configuration

**What it is.** `verify-build-sources.py` trusts git's own view of the three checkouts and looks
only inside them. The build takes Cargo configuration and environment from around them: a
`.cargo/config.toml` in a parent directory or in the home directory, `RUSTFLAGS`, `RUSTC_WRAPPER`,
a reused target directory, a `git replace` object.

**What the operator sees.** Nothing: the check prints "Verified" and `build.json` records zero
changes. The only sign is a release whose `SHA256SUMS` is not the published one.

**What the operator does.** For this launch: nothing is built. Stage only the signed release whose
`SHA256SUMS` hashes to `6d3bd628…`; it was reproduced on two hosts. For any later build: build in a
clean environment, that is from a fresh `git archive` of the pinned commits, under `env -i`, with
`GIT_NO_REPLACE_OBJECTS=1`, an empty `CARGO_HOME` and a new target directory, on a host with no
Cargo configuration outside the checkouts; then compare `SHA256SUMS` with a second host.

## 7. R308-2P-6: enough client keys with requests in flight still fill the gateway

**What it is.** The public gateway runs at most 8 EVM calls at a time (5 simulations, 3 slots kept
for transactions, one transaction admission in flight per client). The pool is bounded on purpose,
so a set of clients that keeps it full refuses the others: with the defaults, six client keys that
each keep a slow call in flight (four before round 15). At the deposit-only launch this affects
`eth_call`, `eth_estimateGas` and `eth_createAccessList` on the public RPC; deposits and
withdrawals do not go through the gateway's transaction path.

**What the operator sees.** Clients get HTTP 429 with JSON-RPC `-32005` and the message `Busy: too
many EVM simulations or transaction admissions in flight; retry shortly.` and `Retry-After: 1`. In
the gateway's access log the same few client addresses hold the `eth_call` requests with long
request times.

**What the operator does.** Find those addresses in the access log and block or rate-limit them at
the edge (Cloudflare). The limits are options of `public-rpc/render.py` (`--sim-total`,
`--tx-reserve`, `--sim-floor`, `--sim-per-ip`, `--tx-per-ip`); raise `--sim-total` only together
with the settled RPC's own permits.

## 8. R308-2P-9, R308-18: limits of the attestor's signing memory

**What it is.** Since round 15 the agent saves, before it signs, which root it is about to sign for
which L2 block, and keeps a second "has saved state" marker in
`/var/lib/bloch-l2-attestor-marker`. Three limits remain.

- The marker directory is on the same disk as the state: a lost disk loses both.
- A host installed before this kit has no marker directory until `install-attestor.sh upgrade` is
  run.
- An agent that died after saving its intent, on a host whose finalized view then changed, halts
  instead of signing.

**What the operator sees.**

- Agent journal, once per start, on a host without the directory:
  `{"event": "marker-not-written", "marker": "/var/lib/bloch-l2-attestor-marker/state.initialized", …}`.
- Agent journal: `{"event": "halt", "reason": "L2 block N now shows withdrawal root …, but this
  attestor already signed … for it: refusing a second signature for the same L2 block"}`, or
  `"… state.json is missing on a host that has signed or saved state before …"`. Exit 3, no
  restart. Monitor: that attestor is listed as silent under `attestors`.

**What the operator does.** For `marker-not-written`: run `install-attestor.sh upgrade` with this
kit. For a `halt`: leave the agent stopped, do not delete or recreate `state.json`, the marker or
the outbox, and report the line to the coordinator; the other attestors' partials decide which root
is right. A lost state is restored from the operator's backup of `/var/lib/bloch-l2-attestor`, never
started empty.

## 9. R308-2P-12: address rules of the installers

**What it is.**

- `install-shadow.sh` resolves the L1 RPC names once and writes every address into the unit's
  allow-list. Its own quorum check runs outside that filter, and a second install on a running unit
  keeps the old filter until the unit restarts.
- `install-attestor.sh upgrade-rollback --follower-sha256 HEX` accepts any hash the operator names
  as "the published post-fork follower".

**What the operator sees.** After an L1 RPC name changed its address the shadow cannot reach that
RPC any more. With fewer than the quorum reachable its journal shows no new `shadow-match` and the
monitor raises `unit[shadow]` or `events[shadow]`. For the attestor: nothing on screen.

**What the operator does.** After any change of an L1 RPC address, roll the shadow back and install
it again with the two commands of `SETTLER-RUNBOOK.md`, section "Foreign settlements". Pass
`--follower-sha256` only with a hash the coordinator published for a corrected build.

## 10. R308-21: what `upgrade` and rollback do not cover

**What it is.**

- Attestor `upgrade-rollback` restores binaries, agent scripts, `config.json`, the agent unit, the
  feed unit and `feed.env`. It checks the restored binaries against the restored pins, not the
  restored scripts.
- Settler `install-settler-mainnet.py upgrade` replaces `config.json` before the new unit has run,
  and `upgrade --rollback` re-hashes four kept files but not `bloch-l2-produce-dev`.
- `follower-rpc/install.sh` says it resumes an interrupted run; that holds for the copy of the
  binaries, not for a run interrupted while it wrote the units.

**What the operator sees.** Nothing by itself. After a settler `upgrade` that failed, the settler's
start prints a pin or identity `halt` (exit 3). After an interrupted follower install, a second run
prints `install.sh: FAILED at line …` or refuses because unit files exist.

**What the operator does.** No upgrade of the settler is part of the deposit-only launch. If one is
run and fails: `sudo python3 install-settler-mainnet.py upgrade --rollback --confirm-mainnet`, then
compare `sha256sum` of the kept `bloch-l2-produce-dev` with its pin in `SETTLER-RUNBOOK.md`
section 0 before starting. After an interrupted follower install nothing was started or enabled:
remove the unit files that the refusal names and run the installer again from the start. After an
attestor `upgrade-rollback`, run `install-attestor.sh status` and read the agent's `check-ok` line
that the rollback prints.
