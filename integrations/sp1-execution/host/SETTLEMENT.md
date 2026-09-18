# Local verified V2 settlement cursor

This host library connects actual SP1 core-proof verification to a local V2
head and proof journal. It changes no native consensus state, liability,
consensus inbox consumption or withdrawal permission. Its existing fixtures remain synthetic. A successful
append is a local acknowledgment, not native consensus settlement.

## Verification capability

`TrustedProgram::from_trusted_elf` derives the verifying key from an independently
selected ELF and constructs the concrete SDK `LightProver`. No caller-supplied
`Prover` implementation or success callback can produce a capability, so a mock
verifier cannot be substituted. `verify` checks core mode, shard/public-byte
bounds, successful guest exit and cryptographic proof validity before comparing
every byte with the independently expected execution statement.

The resulting `VerifiedExecutionStatement` has private fields, no public
constructor/deserializer and no mutable proof access. It owns the exact proof
that passed verification. Its identity binds both Keccak-256 of the complete ELF
artifact and the SDK's raw `HashableKey::hash_bytes` verifying-key digest. This
deliberately distinguishes different ELF artifacts even if they derive the same
VM verifying key. It is not the SDK's BN254/on-chain key projection.

`SettlementCursor::from_trusted_anchor` requires independently trusted chain
configuration, domain, program identity and full V2 anchor header. Structural
validation does not prove the anchor's execution or finality. For a selected
successor, `expected_for_selected_header` checks continuity and derives the
expected statement. Header selection remains the application's responsibility.
`advance` checks program identity, configuration, domain, full header hash,
parent hash/root, height and V2 parent rules before publishing the new head.
Replay, sibling-fork submission and mismatched statements leave it unchanged.

## Durable local acknowledgment

`SettlementJournal::create` exclusively creates a new file, locks it, writes the
trusted anchor/identity prefix and synchronizes the file and containing directory.
`append` validates a private candidate cursor, serializes the proof retained by
the verified token and appends one bounded record. It synchronizes the record
before publishing the candidate cursor. It cannot pair a verified token with an
unrelated supplied proof. Failures before writing preserve the previous head;
I/O failures after writing begins poison the instance. An unexpected file-length
change also poisons it. Further appends fail until it is dropped and recovered.

`open` holds an exclusive advisory lock and checks the prefix against the supplied
trusted program/configuration/anchor. It rechecks every checksum, strict header
codec, parent link and complete cryptographic proof before recovering a head.
It requires an independently retained `SettlementMark` containing height, header
hash and state root to occur in that history. A missing, conflicting or rolled-back
acknowledged prefix fails. Taking this floor from the same potentially rolled-back
file defeats that protection. Records beyond the floor are recovered as durable
local selection; proof validity alone does not authenticate network canonicality.

Partial writes, trailing garbage, invalid proofs and corrupted records fail
closed. There is no automatic truncation, salvage, migration or rollback-floor
store. A caller must retain acknowledgment floors separately and must not publish
an acknowledgment until `append` returns successfully. Arbitrary power-loss and
filesystem fault behavior has not been qualified by these local tests.

The journal prefix is the ASCII tag `BLOCH:LOCAL:SP1:SETTLEMENT:1`, then four
32-byte fields (ELF Keccak, raw VK digest, configuration commitment, domain),
then a big-endian u32 anchor-header length and its canonical V2 RLP bytes.
Each record is a big-endian u32 frame length, the frame and its 32-byte Keccak
checksum. A frame contains a big-endian u32 header length, canonical V2 RLP
header and the SDK 6.8.0 fixed-integer bincode proof. The checksum detects local
corruption; only the proof verifier authenticates execution. This is a versioned
local format, not a newly assigned native consensus codec or transaction tag.

## Admission and filesystem limits

- Proof file: 32 MiB; core shard count: 1–256. SDK 6.8.0's fixed-integer core
  tag/count prefix is checked before deserialization reserves its outer vector.
- Strict bincode uses a byte limit and rejects trailing bytes. No SDK network
  proof fallback is accepted. Nested SDK allocations and verification work are
  not a complete hostile-input memory/CPU sandbox.
- Header bytes: at most 2,048; frame: at most `4 + 2,048 + 32 MiB` bytes.
- Journal: at most 256 records and 256 MiB cumulatively. Recovery checks limits
  before frame allocation; append checks capacity before writing.
- Existing proof/journal files use `O_NOFOLLOW | O_NONBLOCK` and must be regular
  files. Symlinks at the final component and FIFOs are rejected without blocking.
  Implementations are provided for macOS and Linux x86_64; qualification is on
  macOS. Ancestor directories are trusted. Locks are advisory, not protection
  against hostile writers that replace paths or ignore locking.

## Commands and test artifacts

After building the host and generating the two documented qualification proofs:

```sh
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host settle empty "$BLOCH_GUEST_ELF" target/qualification-empty.proof target/empty-settlement.journal
RAYON_NUM_THREADS=2 target/release/bloch-evm-sp1-host verify-settlement empty "$BLOCH_GUEST_ELF" target/empty-settlement.journal
```

`settle` requires a new journal path. It verifies the selected fixture proof,
appends the successor, closes the file and reopens/reverifies it. The separate
`verify-settlement` command rebuilds its anchor and acknowledgment floor from
native execution of the selected fixture, independently of the stored journal.
Using the opposite fixture must fail even when every stored proof is valid.

The integration suite requires existing genuine proof artifacts; it does not
generate replacements, skip missing artifacts or use mocks:

```sh
RAYON_NUM_THREADS=2 CARGO_BUILD_JOBS=2 cargo test --release --locked --offline --test settlement_proofs -- --test-threads=1
```

Default paths are the guest ELF and `target/qualification-{empty,contract}.proof`.
Override them with `BLOCH_SP1_ELF`, `BLOCH_SP1_EMPTY_PROOF` and
`BLOCH_SP1_CONTRACT_PROOF`. The two fixtures are alternative first blocks; these
tests do not claim proof qualification of a longer consecutive block sequence.
Actual validation results are recorded in [README.md](README.md).

## Optional source selection coordinator

Build with `--features source-settlement` for `SourceSettlement`. This owns the
experimental `SourceRegistry`, execution cursor and consumed sequence privately.
Bootstrap requires the canonical V2 genesis derived from the configured spec,
domain and genesis timestamp, plus an empty native genesis registry with pinned
network/genesis/domain identities. Arbitrary precredited height-zero headers and
already advanced registries are rejected. Source updates require an independently
trusted commitment and the complete ancestry/mapping/inbox proof checks of the
registry. The application must authenticate that commitment; receiving a batch
and computing its hash does not establish native authority.

`advance` selects the exact mandatory prefix in its own registry, compares the
selected statement to the cryptographically verified token, and checks trusted
program identity and execution continuity before publishing the execution head
and consumed sequence together. An invalid body, stale source, mismatched proof
or replay cannot consume deposits. Source updates do not consume deposits.
This coordinator is in-memory only; the ordinary `SettlementJournal` does not
persist or recover source history or consumption. Native consensus activation
and withdrawal authorization remain separate gates.

The optional `source-contract` fixture retains the signed deployment and call
from `contract`, but binds the execution anchor to a canonical synthetic native
header hash. It allocates local fixture funding into `EscrowLedger`, builds the
full inbox inclusion and source mapping, and independently executes the V2 body.
The synthetic native source commitment is constructed by the fixture as a trust
input; it is not included in a real native consensus state root. The guest ELF
and all dependency versions remain unchanged. `sha3` and `libc` use versions
already present in the lockfile; only the optional native-domain path package is
added.

```sh
cargo build --release --locked --offline --features source-settlement
target/release/bloch-evm-sp1-host fixture source-contract
target/release/bloch-evm-sp1-host execute source-contract "$TRUSTED_ELF"
target/release/bloch-evm-sp1-host prove source-contract "$TRUSTED_ELF" target/qualification-source-contract.proof
target/release/bloch-evm-sp1-host verify-source source-contract "$TRUSTED_ELF" target/qualification-source-contract.proof
```

Use the same `PROTOC`, `CARGO_BUILD_JOBS=2`, `CARGO_NET_OFFLINE=true` and
`RAYON_NUM_THREADS=2` environment from the host README. `verify-source` verifies
against the independently executed fixture, applies the independently selected
source to the owned registry, advances both cursors once, and rejects replay.
The feature's real-proof tests require `BLOCH_SP1_SOURCE_PROOF` or the default
proof path shown above; missing proof artifacts fail rather than skip.
