# devnet4 — reproducible preparation recipe (settlement V3)

Status: **prepared, not run.** Nothing in this document has been executed on a
server. It is the recipe an operator follows later on the L2 host
`45.77.142.123`. Development network only: three validators on one host (one
failure domain), development allocation, no production finality.

## Why a new network

devnet3 cannot carry settlement V3:

* the native branch renumbered the L2 wire tags past the mainnet transaction
  space (`0x12` settlement, `0x13` async settlement, `0x14` deposit; devnet3 used
  `0x0E/0x0F/0x10`), so the new build cannot replay devnet3 history;
* a genesis pins exactly one proof policy (V2 *or* V3), and V3 needs
  `policy_commitment_v3()` and the `settlement_v3` program identities.

## Sources (pin all of them)

| Component | Branch | Commit |
|---|---|---|
| Native node (`bloch-validator-payout`) | `codex/native-l2-v3-m4-20261010` | the reviewed HEAD of that branch |
| L2 (`bloch-l2-evm`) | `codex/l2-v3-m4-20261010` | the reviewed HEAD of that branch |
| Reth snapshot (`reth-bloch-rpc-snapshot`) | as used by devnet3 | `8eb210175687c9f0c889a3b6795c16781d830e3a` |

The L2 integration crates resolve the native and Reth trees as siblings
(`../../../bloch-validator-payout`, `../../../reth-bloch-rpc-snapshot`), so the
three checkouts must sit side by side in one directory.

## What must be pinned (record every value in `plan.json` before install)

| Pin | How it is obtained | Checked by |
|---|---|---|
| Native binary SHA-256 and `--version` (commit, `+devnet-randao-recommit+devnet-l2-deposits+devnet-l2-user-txs`, source digest) | step 1 | install script |
| `settlement_v3` ELF SHA-256 and Keccak-256 (reproducible build) | step 2 | settler (`guest_sha256`), statement field `program_elf_keccak` |
| SP1 KoalaBear vkey and BN254 vkey of that ELF | step 3 (`identity`) | statement fields; native verifier uses the BN254 key from the policy |
| SP1 circuit version (`v6.1.0`) and full Groth16 wrapper VK SHA-256 | bound inside `proof_policy_v3` | native `bloch_l2_proof::verify` |
| `proof_policy_v3` (native `policy_commitment_v3()` == L2 host value) | step 3 + step 4 | `make_l2_config.py` refuses a mismatch |
| Gnark image `ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d` | fixed in the V3 host (`QUALIFICATION_GNARK_IMAGE`) | prover refuses any other `SP1_GNARK_IMAGE` |
| L2 genesis hash and state root | step 5 (`produce init` + `head`) | `l2-config.bin` bytes 200..264 |
| `l2-config.bin` SHA-256 (264 bytes) | step 6 | install script, settler (`l2_config_sha256`) |
| Producer and prover binary SHA-256 | steps 2–3 | settler (`prover_sha256`), installer |
| Settler source SHA-256 (`deployment/devnet/settler_v3.py`) | `sha256sum` | installer |
| DA signer (`bloch-pos` binary used for `l2-da prepare/sign`) SHA-256 | = the native binary of step 1 | settler (`da.signer_sha256`) |
| DA funding public key (hex file, exported like the `l2-deposit` funding key) and its script hash (SHA3-256 of the key) | a dedicated keystore (`bloch-pos keygen`, then `keys seal`) | settler (`da.funding_pubkey`), dev allocation |

Reference values computed on the development Mac (2026-10-10), **to be
recomputed from the artifacts actually deployed**. Since M3 the guest is built
with `integrations/sp1-execution/guest/scripts/build-reproducible.sh`, which
builds the commit in the fixed root `/tmp/bloch-guest-build/bloch-l2-evm` with
remapped paths: the ELF no longer depends on the checkout directory
(`verify-reproducible.sh` checks two checkouts). It still depends on the
compiler host platform; pin the ELF built where the keys are derived.

* `settlement_v3` ELF (M4, withdrawal outbox, reproducible build of `codex/l2-v3-m4-20261010`):
  SHA-256 `6fa44f9cd5c3b5461db115725692b4b6277cf441edf72e89343c5dc71ab3c259`,
  Keccak `c3004c33cd7c77aeb23eac42bc3553102241b6f715fc76bdd013707ae9ca464f`,
  KoalaBear vkey `0fbf3f4334530ec9108d6b640b01fb6836e7f05d7dd982fb6d476f841d4c34ba`,
  BN254 vkey `001f7e7e86d14c3b24846b5b20b01fb686dcfe0bbf7660bef6a3b7c21d4c34ba`.
  (Superseded: M3 ELF `853ecdcb…` / vkey `0022320a…`, M2 ELF `a80aa3a5…`.
  The same build also changes `settlement_v2` to `2b63bb74…` and the synthetic
  guest to `63994ed7…`, because the shared execution core changed; devnet3
  keeps its own pinned V2 artifacts.)
* `configuration` `deeee918393658e5edd6616d7dc062d00ba21979520f44a3991f6a7bd8ad0f63`
  (tag `BLOCH:EVM:CONFIG:2:CANCUN`: `ChainSpec::testnet_v3()`, the testnet
  parameters plus the outbox address and minimum withdrawal; M3 value
  `d8bda583…` superseded), domain `0xd3…d3`.
* `proof_policy_v3` `154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d`
  (L2 host and native build agree).
* L2 genesis (reproduced locally with the M2, M3 and M4 producers; the outbox is
  installed by block 1, not at genesis): hash
  `aec9844384415c8ba7157298fa13f7e6c951a6ba9332f516180a4aa22208fefa`, state root
  `8f329e1ce3b48212f1e8bf8eb25d567433f872a8ef1493257e1bcfcd289d1ae7`.
* A sample `l2-config.bin` from these values: SHA-256
  `27e26debdea078997ff725d4180a64dcf7554a1a4100a438175b3dfad4b03ea0` (264 bytes;
  M3 sample `e1ae001b…` and M2 sample `a2dfc21b…` superseded).
* Empty withdrawal root (block 1 onwards until the first withdrawal):
  `27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757`.

## Steps (build machine; no keys involved)

```sh
# 0. Side-by-side checkouts at the reviewed commits
mkdir devnet4-src && cd devnet4-src
git clone <native repo> bloch-validator-payout && git -C bloch-validator-payout checkout <NATIVE_COMMIT>
git clone <l2 repo> bloch-l2-evm && git -C bloch-l2-evm checkout <L2_COMMIT>
git clone <reth snapshot> reth-bloch-rpc-snapshot && git -C reth-bloch-rpc-snapshot checkout 8eb210175687c9f0c889a3b6795c16781d830e3a

# 1. Native node (devnet features; user transactions admitted by the verifier
#    only because of devnet-l2-user-txs — the settler still starts deposit-only)
cd bloch-validator-payout
BLOCH_BUILD_COMMIT=<NATIVE_COMMIT> cargo +1.94.1 build --locked --release \
  -p bloch-pos-node --bin bloch-pos \
  --features devnet-randao-recommit,devnet-l2-deposits,devnet-l2-user-txs
sha256sum target/release/bloch-pos && target/release/bloch-pos --version
cd ..

# 2. Guest ELF (SP1 6.8.0 CLI, succinct toolchain; see docs/SP1-TOOLCHAIN.md).
#    Path-independent build; optionally verify two paths give the same ELF.
cd bloch-l2-evm/integrations/sp1-execution/guest
./scripts/build-reproducible.sh --out "$PWD/pinned"   # prints sha256 of each program
./scripts/verify-reproducible.sh HEAD                 # optional, two checkouts, clean builds
ELF=$PWD/pinned/settlement_v3

# 3. V3 prover host + program identity (runs SP1 setup, no proof)
cd ../host
cargo +1.98.1 build --locked --release --features node-artifact,source-settlement \
  --bin bloch-evm-sp1-settlement-v3
target/release/bloch-evm-sp1-settlement-v3 identity "$ELF" > identity.json
target/release/bloch-evm-sp1-settlement-v3 execute empty "$ELF"      # sanity, no proof

# 4. Native V3 policy (must equal identity.json proof_policy_v3)
#    printed by the native test helper; record the hex as NATIVE_POLICY
( cd ../../../../bloch-validator-payout && \
  cargo +1.94.1 test -p bloch-l2-proof --locked print_policy_commitment_v3 -- --ignored --nocapture )
# reference (native M2 build, 2026-10-10): policy_commitment_v3 154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d

# 5. Producer and L2 genesis (deterministic for ChainSpec::testnet / domain 0xd3)
cd ../../settlement-recovery
VERGEN_IDEMPOTENT=1 cargo +1.98.1 build --locked --release --bin bloch-l2-produce-dev
target/release/bloch-l2-produce-dev init --target /tmp/devnet4-l2-genesis
target/release/bloch-l2-produce-dev head --target /tmp/devnet4-l2-genesis > genesis.json
# devnet2/devnet3 used the same L2 genesis: aec9844384415c8ba7157298fa13f7e6c951a6ba9332f516180a4aa22208fefa

# 6. l2-config.bin (264 bytes) — refuses any policy disagreement
python3 ../../deployment/devnet/devnet4/make_l2_config.py \
  --identity ../sp1-execution/host/identity.json --genesis genesis.json \
  --native-policy "$NATIVE_POLICY" --out l2-config.bin
```

Step 4 requires the ignored helper test `print_policy_commitment_v3` in
`bloch-l2-proof`, which prints `policy_commitment_v3()`; it is part of the
native M2 branch.

## Operator checklist on 45.77.142.123 (later; not executed here)

Preconditions (read-only):

- [ ] `uname -m`, free disk ≥ 60 GB, RAM ≥ 64 GB (proof peak ~60 GB at 8 threads), Docker running, the pinned gnark image pulled by digest.
- [ ] devnet3 services status recorded (`bloch-l2-devnet3-*`): decide retire vs. coexist. Coexisting needs new ports: proposal RPC `18940-18942`, P2P `19940-19942`, metrics `19950-19952`; bind-check every port.
- [ ] No existing `/etc/bloch-l2-devnet4*`, `/var/lib/bloch-l2-devnet4*`, `/opt/bloch/l2-devnet4*`, users `bloch-l2-devnet4-*`, units `bloch-l2-devnet4-*`.
- [ ] Copied artifacts match every pin above (`sha256sum`), and `bloch-pos --version` shows the reviewed commit, the three devnet features and the source digest.

Install (adapt `l2-devnet3-20261006/remote-install.py`, changing only names, ports and pins):

- [ ] keygen ×3 validators + development wallet (sealed; passphrase file root-only, never exported).
- [ ] `bloch-pos genesis --keys … --bind-genesis --l2-settlement-config l2-config.bin --dev-allocation <wallet_script>:<sat> --slot-ms 2000` (the native decoder accepts the V3 policy and pins it for this genesis).
- [ ] systemd units with the devnet3 hardening; liveness: every node finalizes and `behind_by_slots ≤ 2` within 7 minutes.
- [ ] `getl2settlement` shows the V3 policy (`proof_policy` = `proof_policy_v3`), `accepted: null`, `data_availability: []`.

Settler (adapt `install-settler.py`):

- [ ] Copy `bloch-l2-produce-dev`, `bloch-evm-sp1-settlement-v3`, `settlement_v3`, `settler_v3.py`; verify SHA-256.
- [ ] `produce init` on the server must reproduce the pinned L2 genesis hash.
- [ ] `config.json`: `network`, `network_kind: "devnet"`, `l2_genesis`, `rpc_ports`, `prover`/`guest`/`l2_config` + SHA-256, `gnark_image`, `prover_threads: 8`, **`user_transactions: false`**, `txpool_dir` (created, owned by the settler user), `max_block_gas`, `max_block_bytes`, `max_block_txs`.
- [ ] Unit as devnet3 (`RestartPreventExitStatus=3`, `MemoryMax` sized for the prover).
- [ ] First cycle: block 1 deposit-only, proof verified, 1155-byte `0x13` transaction accepted (`getl2settlement.accepted.statement` starts with `BLOCH:EVM:SETTLEMENT:3`).
- [ ] One native deposit (`0x14`) minted by the next settlement (`deposits_hash` check passes).
- [ ] `getl2settlement.withdrawals` shows `count: 0` and the empty root above, `roots: []`; `produce head` reports the same `withdrawal_root` / `withdrawal_count`.

Enabling user transactions (only after the deposit-only path is stable):

- [ ] Native build has `devnet-l2-user-txs` (otherwise every V3 statement with `user_tx_count > 0` is refused with `Reject::UserTransactions`, and every `0x15` DA transaction with `NotActive`).
- [ ] DA fee key: a separate keystore (`bloch-pos keys`) sealed with its own passphrase file readable only by the settler user; fund its script hash from the development wallet (a few outputs; each DA transaction spends 1–16 of them and returns change). It holds only DA fee money, never escrow.
- [ ] Settler `config.json` gains `"da": {"signer": "<bloch-pos>", "signer_sha256": "…", "genesis": "<manifest>", "funding_pubkey": "<hex file>", "keystore_dir": "…", "passphrase_file": "…", "tip_millisat_per_gas": 0, "inclusion_timeout_seconds": 300}`; the settler refuses `user_transactions: true` without it or with a signer that differs from its pin.
- [ ] Set `user_transactions: true` and restart; place signed transactions in `txpool_dir` as `*.tx` (one hex envelope per file). `produce extend --txs` prunes included and dropped entries after commit; a block never selects more bytes than one DA batch (112 KiB with framing).
- [ ] First user-transaction cycle: the log shows `da-submitted` then `da-included` before `submitted`; `getl2settlement.data_availability` lists `{l2_number, commitment, height}` until the settlement lands, then the record disappears.
- [ ] Measure proof time and peak RSS per block against the cycle benchmark before raising `max_block_txs`.

## Withdrawals, L2 side (M4)

Execution rules: `ChainSpec::testnet_v3()` everywhere devnet4 executes
(`settlement_v3` guest, V3 prover host, `bloch-l2-produce-dev`). The outbox
`L2ToL1MessagePasser` is installed at `0x4200000000000000000000000000000000000102`
by the first block (code hash = keccak of the 132-byte `OUTBOX_CODE`).

* Call `initiateWithdrawal(bytes32 l1Recipient)` (selector `0xb769844a`) with
  the amount as value: a multiple of `10^10` wei (one sat), at least
  `1,000,000` sats (0.01 BLCH), recipient = the native owner script hash
  (SHA3-256 of the hybrid public key), non-zero. Anything else reverts and
  refunds. Event `WithdrawalInitiated(uint256 indexed nonce, bytes32 indexed
  l1Recipient, address sender, uint256 amountWei)`.
* At block end the protocol appends one leaf per outbox event to the depth-32
  keccak tree (`keccak256("BLOCH:L2:WITHDRAW:1" || chain_id BE8 || nonce BE8 ||
  l1_recipient || sats BE8)`), removes the value from the outbox balance and
  adds it to the supply ledger (slot 3): L2 supply = minted − burned − withdrawn.
* V3 publishes the post-block `withdrawal_root` / `withdrawal_count` (offsets
  672/704), read from the authenticated outbox storage. The native chain
  requires the count never to decrease and the root to change exactly when the
  count does (`Reject::Withdrawals`), and keeps `(l2_number, root, count,
  height)` of settlements that added withdrawals (1,024 native blocks plus the
  newest older record), shown under `getl2settlement.withdrawals`.
* Claim input (for M5): `bloch-l2-produce-dev withdrawal-proof --target DB
  --index I [--number N] [--root HEX --count N]` rebuilds the tree from
  receipts, checks it against the outbox state after block N and the settled
  root, and prints the 32 siblings and the leaf fields.
* The settler checks each statement's withdrawal fields against the producer
  block and the accepted head and logs them (`transaction-built`).
* **No L1 release yet (M5).** Withdrawn value leaves the L2 supply but
  `escrow_sat` on L1 is unchanged: it is locked until the claim exists. Keep
  withdrawals to development amounts.

## Data availability (M3)

A V3 settlement with `user_tx_count > 0` is accepted only if, in a strictly
earlier native block, an `L2DataAvailability` (`0x15`) transaction published
that block's user-transaction batch (`da_commitment` =
`keccak256("BLOCH:L2:DA:1" || chain_id || l2_number || payload)`). The native
state keeps only `(l2_number, commitment, inclusion height)`; the batch stays in
the native block. Limits: payload ≤ 114,688 bytes, ≤ 4 DA transactions per
native block, records retained 1,024 native blocks and only for the next 64
unsettled L2 blocks; ordinary eUTXO fees (16 gas/byte). Full rules:
`docs/specs/BLOCH-NATIVE-L2-SETTLEMENT.md` (native repository).

Settler cycle with user transactions: produce → prove → check the statement
(`da_commitment` equals the commitment of `produce da` output) → if the record
is not yet on L1: `getutxos` for the DA key, `bloch-pos l2-da prepare` at the
current `next_base_fee_millisat_per_gas`, `bloch-pos l2-da sign` (keystore +
passphrase file), `sendrawtransaction`, wait for the record → submit the
settlement. A timeout leaves the block for the next cycle, which builds a fresh
DA transaction (`da-unsigned-N.hex`) if the record is still missing (e.g. the
base fee moved and conservation failed, or the record expired).

## Rebuilding the L2 from L1 (M3)

`bloch-l2-produce-dev reconstruct --target NEW_DIR --l1-follower FOLLOWER_STATE`
creates a fresh L2 database at genesis and replays every settled L2 block using
only native data: inbox deposits (`0x14`), DA batches (`0x15`) and settlements
(`0x12`/`0x13`) from the native follower's verified block store (`index` +
`blocks/*.bin`; `--l1 FILE` takes a JSON fixture instead). Each rebuilt block
must reproduce the settled header hash and state root (and V3 `deposits_hash` /
`transactions_root`), otherwise it stops with the first divergence. Rehearse it
on devnet4 after the first user-transaction settlements, and compare its head
with `produce head` of the settler database.

## Known gaps (not addressed by this recipe)

* Data availability uses a fee-paying, permissionless DA transaction. A
  spammer can compete for the 4 DA slots per native block (fee auction) but can
  neither evict nor overwrite a recorded batch; a single-sequencer key or bond
  is a later decision (M8/M9). Compression is not used (raw canonical batch).
* `reconstruct --l1-follower` reads the follower store as-is (it trusts that
  the follower verified it). `tests/reconstruct.rs` covers both inputs with a
  synthetic store (unsigned envelopes), not a store written by a live follower.
* Withdrawals: the L1 claim (`L2WithdrawClaim`, nullifiers, delay, escrow
  release) is M5; until then withdrawn value is locked in the escrow.
  `bloch-l2-settled-rpc`, `bloch-evm-export`, `bloch-evm-dev` and
  `bloch-l2-audit-dev` still construct `ChainSpec::testnet()`: they read the
  devnet4 database (same genesis) but would re-execute blocks under the rules
  without the outbox; switch them to `testnet_v3()` before using them on devnet4.
* `withdrawal-proof` scans every block's receipts since genesis (bounded at
  10^6 blocks); an indexer is needed beyond development.
* Every host that replays native blocks (native follower, audit tools,
  `produce reconstruct`) must be built with `--features devnet-l2-user-txs`
  (settlement-recovery), or it refuses the first block carrying a `0x15` DA
  transaction exactly as a non-devnet native build does.
* The native follower / settled RPC still decode only the V2 (979-byte) frame;
  following devnet4 V3 settlements needs the V3 frame (`NativeSettlementFrameV3`)
  wired into `settlement-recovery`.
* The settled RPC has no transaction submission (Noop pool): the txpool spool
  is filled by an operator tool, not by `eth_sendRawTransaction`.
* Guest ELF reproducibility is established across checkout paths on one
  machine (`verify-reproducible.sh`), not across host platforms.
* Prover sizing: see `docs/benchmarks/settlement-v3-cycles-20261010.md` (M2,
  no precompiles) and `docs/benchmarks/settlement-v3-cycles-precompiles-20261010.md`
  (M3, SP1 Keccak/secp256k1 precompiles); keep `max_block_txs` small until a
  real proof is measured.
