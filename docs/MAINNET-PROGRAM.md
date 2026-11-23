# Bloch L2 mainnet program and genesis (chain id 700770)

> **Host placeholders (publication review H398-6, 2026-11-17):** `HOST_A` = the IPv4 address of the settler, prover and follower-A host; `HOST_B` = that of the build host and follower-B host; `HOST_C`, `HOST_D` = the other project hosts named in older measurements; `SSH_KEY_FILE` = the path of the owner's SSH identity file. The values are in the owner's private copy; replace them before running a command.

Status 2026-10-14: **values derived, nothing deployed.** These are the inputs
of the native activation `l2_settlement::mainnet::PROGRAM` (bloch-sis-pow,
`crates/bloch-pos-committee/src/l2_settlement.rs`). The activation epoch, the
attestor set and the arming commit are separate (native workstream).

## Pinned values

| Native field | Meaning | Value |
|---|---|---|
| `identities[0]` | Genesis-4 admission network domain: SHA3-256 of the canonical encoding of `genesis/mainnet.manifest` (file SHA-256 `7eef82a7…b2dd`); `getvalidatoradmission.network_domain` on the live chain | `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966` |
| `identities[1]` | Genesis-4 native genesis block id (V1 manifest; epoch-0 checkpoint root) | `9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415` |
| `identities[2]` | L2 V2 domain `MAINNET_DOMAIN` | `1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733` |
| `identities[3]` | execution configuration commitment of `ChainSpec::mainnet` | `8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b` |
| `identities[4]` | `settlement_v3_mainnet` ELF Keccak-256 | `6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073` |
| `identities[5]` | SP1 KoalaBear verifying-key hash | `389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e` |
| `identities[6]` | SP1 BN254 verifying-key hash (Groth16 program key) | `007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e` |
| `proof_policy` | V3 policy (`policy_commitment_v3()` native == `proof_policy_v3` host): SP1 circuit v6.1.0, Groth16 wrapper VK SHA-256 `4388a21c…e696`, tag `BLOCH:EVM:SETTLEMENT:3` | `154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d` |
| `initial_l2_parent` | L2 genesis header hash | `632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468` |
| `initial_l2_state` | L2 genesis state root | `2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d` |

Guest ELF `settlement_v3_mainnet`: SHA-256
`203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473`, 3 070 744
bytes, built from `f0d53fe` with `build-reproducible.sh` (fixed root
`/tmp/bloch-guest-build`), SP1 CLI 6.8.0 (`cargo-prove sp1 (58c4aea
2026-09-11)`, archive SHA-256 `7c585d64…49d5`), compiler
`succinct-1.96.0-64bit-v2` (`rustc 1.96.0-dev`, archive SHA-256
`a5909912…5228`), host macOS x86_64. `verify-reproducible.sh f0d53fe` built it
byte-identically from two checkouts, and the same build reproduced the pinned
devnet ELFs (`settlement_v3` `6fa44f9c…`, `settlement_v2` `2b63bb74…`,
synthetic `63994ed7…`), so the devnet programs are unchanged.

Host (`bloch-evm-sp1-settlement-v3`, rustc 1.98.1, Linux x86_64) SHA-256
`617d191f22881cd235aa020b8151539b9ae5cf8cc38925526b369400e7b686b3`; producer
`bloch-l2-produce-dev` `41ff7160ebc1b704ab995d033bf4539b33820c6bf2ec9f11891a65942d524937` (the build that made the fixture; the producer is not a pin).
The same host prints the devnet4 identity unchanged (`c3004c33…` /
`001f7e7e…`).

## Decisions (recommendations, conservative)

These were not fixed by an earlier decision; each is the most conservative
choice and is documented here so it can be reviewed before the arming commit.

1. **L2 domain** — derived, not chosen:
   `keccak256("BLOCH:L2:MAINNET-DOMAIN:1" || 700770 (u64 BE) || identities[0])`.
   Public inputs only, binds the L2 to its chain id and to the L1 network it
   settles on; differs from zero and from the devnet `0xd3…d3`. Changing it
   changes the guest (it is compiled in), the configuration-independent
   header hashes and every key.
2. **L2 genesis timestamp** — the Genesis-4 slot-0 time,
   `genesis_time_ms / 1000 = 1786656679` (`MAINNET_GENESIS_TIMESTAMP`): a fixed
   public value, wall-clock (the mainnet profile requires ≥ 2020-01-01), and no
   later than any native slot an L2 block can anchor to, so the wall-clock
   rule from block 1 (`--timestamp-rule 1:1786656679:30000`) never needs
   `parent + 1` to override it.
3. **No premine.** `BlochChainSpec::new` accepts no arbitrary allocation; the
   genesis is the zero-issuance kernel genesis. Full allocation (pinned by
   `network::tests::pinned_mainnet_genesis_has_no_premine`), identical in
   shape to the devnet genesis:
   - `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02` — EIP-4788 beacon-roots
     predeploy (Cancun system contract; the anchor root is written there each
     block), code only, balance 0, nonce 1;
   - `0x4200000000000000000000000000000000000101` — `BLOCK_INFO`, the
     committed head record (number, timestamp, base fee, parent hash, the
     256-entry `BLOCKHASH` ring), storage only, balance 0, nonce 1.
   Not in genesis: the withdrawal outbox `0x4200…0102` (installed by block 1),
   the fee vaults `0x4200…0011` / `0x4200…0019` and the supply ledger
   `0x4200…0100` (created on first use). L2 supply starts at 0 and only native
   deposits mint it.
4. **Gas limit, base fee, fee curve** — unchanged from `ChainSpec::mainnet`
   (= the devnet4 V3 rules): 30 000 000 gas per block (Ethereum mainnet's
   long-standing limit; the DEX router creation needs ~3.9 M), initial base fee
   1 gwei, elasticity 2, base-fee change denominator 250 (slower than
   Ethereum's 8: ±0.4 % per block instead of ±12.5 %), zero block reward.
   Changing any of them changes the configuration commitment and the program.

## Reproduce

```sh
# 1. Guest (macOS x86_64 with the SP1 toolchain of docs/SP1-TOOLCHAIN.md)
cd integrations/sp1-execution/guest
CARGO_PROVE="cargo-prove prove" ./scripts/build-reproducible.sh --commit <COMMIT> --out pinned
./scripts/verify-reproducible.sh <COMMIT>   # two checkouts, identical ELFs

# 2. Host, producer, native policy, identity, L2 genesis, PROGRAM literal
#    WORK/src = bloch-l2-evm + bloch-validator-payout + reth-bloch-rpc-snapshot
deployment/mainnet/build-program.sh WORK pinned/settlement_v3_mainnet NATIVE_TREE

# 3. Native fixture (needs Docker with the pinned gnark image, ~20 GB RAM)
#    REQUEST from the native helper print_mainnet_program_fixture_request,
#    run on the tree that carries the final PROGRAM.
deployment/mainnet/prove-native-fixture.sh WORK pinned/settlement_v3_mainnet REQUEST OUT
```

Runtime flags for every mainnet binary: `--rules mainnet --domain
1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
--genesis-time 1786656679`, and for `extend`/`reconstruct` (settler,
attestors) `--timestamp-rule 1:1786656679:30000`. The prover takes
`--mainnet` before its mode.

## Real Groth16 fixture

`mainnet-empty.{values,proof,request,provenance.json}` in bloch-sis-pow
`crates/bloch-l2-proof/tests/fixtures`: a real proof of
`settlement_v3_mainnet` for L2 block 1 (empty, on the pinned genesis) anchored
to the frozen async source of the deterministic native test chain that
crosses the flag day with the pinned PROGRAM. The native test
`mainnet_program_real_groth16_settles_on_the_activated_l2` applies it in the
actual transition with the real verifier. The source block id depends on the
whole committed policy (the boundary block's state root carries the L2 leaf),
so the fixture must be regenerated whenever the PROGRAM or the native test
chain changes. Proving took 14 min wall and 20 GB peak RSS at 6 threads on
HOST_B.

## Mainnet prover (2026-10-18)

Reproduced on 2026-10-18 from `codex/l2-mainnet-ops-20261018` (75c238b; the guest
sources are unchanged since f0d53fe): `build-reproducible.sh --clean` on macOS
x86_64 rebuilt `settlement_v3_mainnet` byte-identically (SHA-256 `203114bf…c473`,
174 s; the devnet ELFs `6fa44f9c…`, `2b63bb74…`, `63994ed7…` also identical). The
host built from the same commit (`bloch-evm-sp1-settlement-v3` SHA-256
`df63301f…6348`, rustc 1.98.1, Linux) prints with `--mainnet identity` exactly the
values the native activation pins (release 78b7343a `l2_settlement::mainnet::PROGRAM`):
ELF Keccak `6e4c8440…c073`, KoalaBear `389cfbde…ac0e`, BN254 `007139f7…ac0e`, policy
`15486996…747d`, configuration `8ec1c804…8f2b`.

### Measured proofs (HOST_B, Intel Cascade Lake, 32 vCPU, 125 GB, shared)

`deployment/mainnet/prover/bench-prove-blocks.sh` (real Groth16, SP1 circuit v6.1.0,
pinned Gnark image; prover in a `systemd --user` scope with MemoryMax and CPUQuota):

| Block | Content | Guest cycles | Prove wall | Prover peak RSS | Gnark container |
|---|---|---|---|---|---|
| A | mainnet L2 block 1 as the live chain requests it (empty; hash `0ff59c11…ab25`) | 529 004 | 13 min 58 s | 20.4 GB | ~18.5 GB |
| B | 1 deposit + 4 transfers + 1 withdrawal | 1 573 036 | 13 min 57 s | 30.8 GB | ~18.5 GB |
| C | 1 deposit + 200 transfers (4.2 M gas) | 33 565 458 | not measured (see below) | ≥ 28.6 GB after 90 s | |

8 threads, 800 % quota (530–634 % used). Block C executed (3.0 s) but its proof
was stopped three times by the benchmark's guard (kill the mainnet prover when
host MemAvailable < 32 GB, then < 24 GB on the first try) because devnet4's own
settler proof was running at the same time; C's prover already held 28.6 GB 90 s
in, so a 200-transfer block needs the full 40 GB slice and must be measured on the
dedicated host. Wall time is dominated by the fixed
recursion/wrap/Gnark cost, not by the block's EVM work. The Gnark Groth16 step runs
in a Docker container under dockerd, OUTSIDE the prover's cgroup, and peaks at
~18.5 GB: a proof needs ~50 GB at its peak (prover + container), not "a few GB".

Block A is the real block the mainnet settler will prove first (request = live
`getl2settlement` source + zero previous settlement + inbox 0/0/0): proof SHA-256
`85c92a55…52e3`, canonical public values `42779c77…7426` (766 B), canonical proof
`5dbe0322…7f71` (356 B); it verifies offline with the pinned host. It goes stale
as soon as the native source moves (a new deposit) or block 1 settles.

### Sizing

Settlement is sequential: block n+1's request carries block n's accepted
settlement, so proofs cannot be parallelised across machines; the L2 block period
is bounded by one proof plus L1 inclusion. On this CPU class: one L2 block per
~15 min with 8 threads, ~12–13 min with 16 (devnet4's settler measures 700–860 s at
16 threads). Recommended dedicated prover host: 32 vCPU (x86_64, AVX-512 helps),
64 GB RAM (peak ~50 GB: 40 GB slice + ~18.5 GB container), 100 GB SSD (7.9 GB Groth16
circuits + Docker image + work), Docker with the pinned image pulled. Minimum: 16
vCPU / 64 GB (one block per ~13–15 min).

HOST_B must NOT host mainnet proving: devnet4's settler already proves
there continuously (16 threads, local first, ~28 GB + ~18.5 GB Gnark, back to back),
on top of ~33 GB of validators and services. During this benchmark MemAvailable
fell to 13.6 GB when proofs overlapped, and the guard stopped every attempt at
block C (23.7, 28.9 and 31.9 GB available). HOST_D (devnet4's remote prover) runs mainnet
validators and is also not suitable.

### Install (prover host; not executed)

Wiring as devnet4: the settler sends one framed job over SSH to a forced command
(`remote_prover.py --config /etc/bloch-l2-mainnet-prover/config.json`, `"mainnet":
true`) and re-runs `execute`/`verify-groth16` locally before submitting.

```sh
# on the new prover host, as root, with docker installed and the image pulled:
docker pull ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d
# copy bloch-evm-sp1-settlement-v3, settlement_v3_mainnet, remote_prover.py and
# install-prover-mainnet.py into one directory; write SHA256SUMS of the first three
sha256sum bloch-evm-sp1-settlement-v3 settlement_v3_mainnet remote_prover.py > SHA256SUMS
python3 install-prover-mainnet.py install --settler-pubkey settler-prover.pub \
  --settler-host SETTLER_IP --circuits /path/to/.sp1/circuits --memory-gib 100 --threads 24 --dry-run
python3 install-prover-mainnet.py install --settler-pubkey settler-prover.pub \
  --settler-host SETTLER_IP --circuits /path/to/.sp1/circuits --memory-gib 100 --threads 24
# settler host: install-settler-mainnet.py configure --remote-prover bloch-l2-prover-mainnet@PROVER_IP ...
# then one end-to-end check (proves and verifies, submits nothing):
selfcheck-remote-prover.sh bloch-l2-prover-mainnet@PROVER_IP KEY KNOWN_HOSTS A/native-request.txt \
  A/block.artifact /opt/.../bloch-evm-sp1-settlement-v3 /opt/.../settlement_v3_mainnet /tmp/selfcheck.proof
# rollback (refuses while a proof runs; new jobs are cut first):
python3 install-prover-mainnet.py rollback --dry-run && python3 install-prover-mainnet.py rollback
```

## Bound program `settlement_v3_mainnet_bound` (audit L2N-01, 2026-11-23): candidate, NOT deployed

The deployed program accepts any `timestamp >= parent` and any `prevrandao`. Both
reach the state root through the `BLOCK_INFO` head record and neither is a
statement field, and a settlement transaction carries no sender, so one outside
proof can settle a block nobody else can rebuild or extend (audit
AUDIT-L1L2-20261123, L2N-01). `settlement_v3_mainnet_bound`
(`integrations/sp1-execution/guest/src/bin/settlement_v3_mainnet_bound.rs`) is
the same program with one more check, made before execution against the parent
head read from the witnessed pre-state
(`bloch_l2_evm::node_execution::bound`):

- `timestamp == max(parent.timestamp + 1, 1786656679 + l1_slot * 30000 / 1000)`,
  `l1_slot` being the statement's anchor slot, which L1 compares with the block
  it pinned. This is `--timestamp-rule 1:1786656679:30000`, the rule the
  producer and every rebuilder already apply;
- `prevrandao == 0x07…07` below block `MAINNET_DERIVED_PREVRANDAO_FROM_BLOCK`
  and `keccak256(l2_parent_hash || l1_block)` from it on. The constant ships as
  `u64::MAX` (never), so the bound program accepts exactly the blocks honest
  nodes build today: same header hash and state root, and a statement that
  differs from the deployed program's only in the configuration commitment
  (tests `l2n01_a_prover_chosen_context_no_longer_settles`,
  `the_candidate_program_statement_differs_from_the_deployed_one_only_in_the_configuration`).

The same program also carries the guest half of L2N-02: it compiles
`ChainSpec::mainnet_outstanding_cap`, whose deposit cap bounds the outstanding
supply (ledger slot 0 minus slot 3, minted minus withdrawn) instead of
everything ever minted. The deployed rule refuses the first deposit after
cumulative deposits reach 100 billion BLCH, a deposit L1 accepts and then
requires every settlement to consume. The outstanding supply equals the L1
escrow, which a conserving L1 never lets pass its supply, so the new cap cannot
refuse a deposit L1 accepted. EIP-6780 burns are not subtracted (their sats
stay in the escrow). State, headers and block hashes are identical under both
rule sets until the gross counter passes the cap.

Statement format and domain are unchanged. Different: the configuration
commitment (`identities[3]`,
`41ddb4dd4aae492e04f500d40be8471ac785e1264d32346dc0f1620d67cc928d`, tag
`BLOCH:EVM:CONFIG:3:CANCUN`), the ELF and the two verifying keys
(`identities[4..6]`). The proof policy `15486996…747d` stays as long as the SP1
circuit version, the Groth16 wrapper key and the statement tag stay.

Candidate values (2026-11-23, commit `21ec80c`; NOT a release, nothing pins them):

| Field | Deployed `settlement_v3_mainnet` | Candidate `settlement_v3_mainnet_bound` |
|---|---|---|
| ELF SHA-256 | `203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473` | `ac2e1ca568fe28ffef7f2e55d4bc493d6348882b2e786bf3e5a10fefa9b38892` (3 101 968 bytes) |
| `identities[3]` configuration | `8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b` | `41ddb4dd4aae492e04f500d40be8471ac785e1264d32346dc0f1620d67cc928d` |
| `identities[4]` ELF Keccak-256 | `6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073` | `c1dd6066941c83fc691f6b325b51ca771c680431df54d54d508c8593fcb6da6d` |
| `identities[5]` KoalaBear key | `389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e` | `72730d65162c55a9604a8d905e125a1f332bec342419058167520c455dea4112` |
| `identities[6]` BN254 key | `007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e` | `00e4e61aca58b156a702546c85e125a1f6657d868906416073a90622ddea4112` |

Built with `build-reproducible.sh` (macOS x86_64, SP1 CLI 6.8.0, `succinct-1.96.0-64bit-v2`); two
builds agree. The keys are from `bloch-evm-sp1-settlement-v3 --mainnet-bound identity` of a host
built from the same commit; as a control the same host prints the deployed column for the ELF
rebuilt from `b17b3ae`. `verify-reproducible.sh` from two checkouts was not run, and any later
change to the core crate changes every value in the right column. The proof policy was not
re-derived (the host was built without `source-settlement`).

The candidate ELF was executed in the SP1 executor (no proof) on L2 block 1 as the real producer
builds it with the mainnet parameters: 660 226 instructions, the committed statement equal to the
host's. For a request that names another anchor slot than the one the block was stamped for, the
candidate ELF aborts, and the deployed ELF commits a statement.

A node artifact names the configuration of the rules it was exported under. The host accepts,
for the candidate program, an artifact exported under the deployed mainnet rules: blocks and
witnesses are the same under both rule sets, so the node need not change rules at the switch.

What it takes before it protects mainnet (nothing below is done):

1. Build the ELF with `build-reproducible.sh` at the release commit, verify it
   from two checkouts, derive the keys with `bloch-evm-sp1-settlement-v3
   --mainnet-bound identity ELF`, and prove one real block
   (`--mainnet-bound prove-groth16 native-artifact`) for the native fixture.
2. Native release: a gated program switch. From an activation epoch the L1
   accepts settlements whose statement names the new `identities[3..6]` and
   refuses the old ones (today `l2_settlement::mainnet::PROGRAM` is one
   constant with no switch). The gate ships inert and is armed by the owner.
   The follower pins the policy the flag day installs (`src/mainnet.rs`), so
   the L2 release must know the switch epoch and both program identities.
3. L2 release (signed, pins refreshed): prover host with the new ELF, settler
   configuration with the new `guest_sha256`, configuration commitment and
   program keys (the node rule set can stay `ChainSpec::mainnet`: it gives the
   same blocks until the gross counter passes the cap, and must become
   `ChainSpec::mainnet_outstanding_cap` in a release well before that), prover invoked
   with `--mainnet-bound` from the switch on, follower and attestors linked to
   the native release that carries the switch.
4. Order: L2 release on every operator host and native release on the
   validator fleet first, both inert; then the owner arms the epoch. At the
   switch the settler must submit only bound-program proofs; a proof of the old
   program made before the switch and still pending is refused by L1 and is
   re-proved.

Because honest blocks are identical under both programs, the L2 block at which
the switch lands does not matter and no L2 block needs to be rebuilt. That
holds only while the switch block stays `u64::MAX`. Choosing a block from
which `prevrandao` is derived is an owner decision; it must be compiled into
the ELF and into the node release that builds blocks, with a block number
still in the future when both are deployed (the old program accepts the
derived value, the new one requires it from that block).

Reproducibility (measured 2026-11-23, macOS x86_64, SP1 CLI 6.8.0, compiler
`succinct-1.96.0-64bit-v2`, fixed root `/tmp/bloch-guest-build`):
`build-reproducible.sh --commit b17b3ae` gives the four pinned ELFs byte for
byte (`63994ed7…`, `2b63bb74…`, `6fa44f9c…`, `203114bf…`). From the first
commit of this work on, the same script gives other bytes for those four
programs although none of their source lines changed: any addition to the
core crate moves the compiled layout. The deployed programs are pinned by
hash and are rebuilt from `b17b3ae` or earlier, never from a later commit.

### Settler and prover wiring for the switch (2026-11-23, in source, not deployed)

The interface the L2 side expects of the L1 program switch, and what the L2 side does with it:

- **The gate.** One activation epoch, constant `L2_PROGRAM_SWITCH_ACTIVATION_EPOCH`, listed in
  `HARD_FORK_GATES` so that `getchaininfo.hard_forks` reports it as
  `l2_program_switch_activation_epoch: {"activation_epoch": N | null, "active": bool}` (the row a gate
  without an RPC alias gets). `null` is inert. A settlement in a block of an epoch below N must name the
  deployed `identities[3..6]`, from N on the bound ones; the proof policy, the statement format, the
  domain and the L2 genesis do not change. If the L1 gate gets another name, `program_switch.l1_gate`
  in the settler configuration names it; nothing else depends on the name.
- **The settler** (`settler_v3.py`, `program_switch`): holds both programs, each with its guest and its
  264-byte l2-config, both pinned (`MAINNET`, `MAINNET_BOUND`). It reads N from the L1 by quorum or from
  its configuration (and halts if the two differ), proves under the bound program from `N - lead_epochs`
  on, never submits a bound settlement before N, and proves a deployed-program settlement again if it was
  not included before N. `MAINNET_BOUND` holds the candidate column of the table above; the release
  replaces it with the released values (test `test_the_bound_pins_are_the_documented_candidate_values`
  keeps the code and this table equal, and `MAINNET_BOUND_STATUS` says `candidate`).
- **The prover**: locally `bloch-evm-sp1-settlement-v3 --mainnet-bound …` with the bound guest; on the
  remote prover the command `prove-bound`, served only when its configuration pins the bound guest
  (`"bound": {"guest", "guest_sha256"}`). `install-prover-mainnet.py` and the settler installer do not
  install the bound guest yet: they pin files by hash, and the bound ELF has no release hash.
- **Readers** (follower, replica, shadow, attestors): must link the native release that carries the
  switch; their pinned policy (`settlement-recovery/src/mainnet.rs`) is still the deployed program only.
  That change is not written.

Until step 4, the only protection is the L1 stop-gap (settlements accepted
from a registered settler key, native fix branch) and the D13 exposure cap.
