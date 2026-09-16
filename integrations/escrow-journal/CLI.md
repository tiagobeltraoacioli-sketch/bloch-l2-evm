# Local operator CLI: bloch-domain

Status: experimental Unix command-line tool. No RPC listener, networking, wallet
access, broadcast, mainnet consensus activation or automatic finality verifier.
The CLI exercises the real inclusion/EVM verifier and durable journal. Trusted
L1 context must be supplied independently by the operator's authentication layer.

## Build and commands

From the modular execution repository root:

```sh
cargo +1.94.1 build --offline --locked --manifest-path integrations/escrow-journal/Cargo.toml --bin bloch-domain
integrations/escrow-journal/target/debug/bloch-domain --help
```

Offline builds require cached dependencies. The commands are:

```text
bloch-domain init CONFIG JOURNAL
bloch-domain status CONFIG JOURNAL MINIMUM_HEAD TRUST_DIRECTORY
bloch-domain apply CONFIG JOURNAL MINIMUM_HEAD TRUST_DIRECTORY PROPOSAL
```

`init` creates a new private journal. `status` exclusively locks it, replays every
committed block using fresh host-trusted derivation, completes directory sync and
reports its recovered head. It is not a cheap unauthenticated file-status query.
`apply` performs that recovery, requires the next sequential block, loads its
separate L1 derivation, verifies inclusion/execution and durably commits it.

Exit 0 indicates success. Exit 1 indicates invalid input, configuration, missing
derivation or verification/open failure. Exit 3 indicates uncertain publication
or failure to deliver the output: use `status` to resolve the recovered head
before retrying. A failed command does not universally mean nothing was written;
for example, an output failure can follow a successful durable commit.

## Configuration and profile

CONFIG is a strict JSON object with exactly these fields:

| Field | Type / requirement |
| --- | --- |
| `version` | integer 1 |
| `profile` | `bloch-evm-cancun-local-v1` |
| `network`, `module`, `runtime` | nonzero 32-byte hex identities |
| `expected_domain` | independently pinned 32-byte domain identity |
| `witness_limit` | positive integer, at most 16,777,216 bytes |

This initial CLI supports only the library's default Cancun ChainSpec and its
fresh zero-credit EVM genesis. It cannot import arbitrary account allocations or
deposit cursors. Compute/pin the expected identity with `EscrowEvmDomain::new`
using those exact parameters and `L2State::genesis(&spec).commit_root()`. Every
command recomputes and checks the identity before opening or creating a journal.
Changes to execution settings must not silently reuse an existing domain.
The configured runtime hash is an identifier; the CLI does not attest its own
binary. Artifact verification and authenticated configuration distribution remain
operator responsibilities. This local profile is not mainnet configuration.

MINIMUM_HEAD is a strict JSON object `{ "blocks": u64, "digest": B256 }`.
Retain the `head` object from successful output independently and durably. For
initial recovery, use the head returned by `init`. The journal never overwrites
this external watermark. Choosing an old minimum permits recovery beyond that
minimum but cannot detect deletion of records newer than it.

## Separate trust input

TRUST_DIRECTORY contains one JSON file per EVM block, named with 20 decimal
digits, for example `00000000000000000001.json`. This filename is the EVM block
number; it is not an L1 height. Each strict object contains:

```text
version: 1
height: actual finalized L1 height
block: finalized L1 block commitment (B256)
domain: expected execution domain (B256)
input: independently derived ordered execution input commitment (B256)
inbox_root: authenticated inbox root (B256)
count: total inbox record count (u64)
locations: [
  { sequence, intent, height, transaction_index, output_index, transaction }
]
```

Locations refer to the mandatory deposit prefix for that EVM block. They map
inbox sequences/intent IDs to actual L1 heights, transaction IDs and output
positions. See [the execution boundary](../../EXPERIMENTAL-ESCROW-EXECUTION.md).
There may be at most 4,096 locations. All historical files required for replay
must remain available and authenticated, including blocks with no new deposits.

File separation is an API boundary, not cryptographic authentication. A proposer
must not control these files. In particular, the operator must not obtain the
`input` commitment solely by hashing an untrusted proposal and calling it trusted.
The authentication layer still has to verify L1 finality, inbox commitments,
source locations, ordered derivation and append-only ancestry. Missing or
inconsistent files stop recovery/application. The CLI never invents a checkpoint.

## Proposal and output

PROPOSAL contains only `version: 1`, `proofs: InboxProof[]`, `input:
SignedBlockInput` and `witness: BatchWitness`, using the library's serde encoding.
The top-level schema rejects extra fields, including embedded `trusted` or
finality claims. Version mismatches and more than 4,096 proofs are rejected.
Witness generation remains a separate host task; this CLI verifies supplied
witnesses and stores the accepted recovery record.

Successful stdout is one JSON object containing `version`, `experimental: true`,
`domain`, `head`, `state_root`, `next_block`, `next_deposit` and `receipt`.
The receipt is the composite local receipt commitment for `apply`, otherwise
null. It is not a succinct proof or withdrawal authority. Errors go to stderr.

## Resource and filesystem boundaries

Before decoding, regular-file reads are bounded to 8 KiB for configuration,
4 KiB for the watermark, 4 MiB per trust file and 64 MiB per proposal. Symlink
input files and symlink trust directories are refused. JSON objects can expand
in memory beyond their wire size; decoded arrays also face verifier limits.
Private operator-controlled parent directories remain required: these checks
are not a sandbox against concurrent filesystem replacement by an attacker.
The process handles one command and exposes no network service or concurrency
queue. Replay cost remains proportional to the entire journal history.

## Validation

Three subprocess integration tests cover `init → apply → status`, retained head
output, replay refusal, missing historical L1 inputs, forged embedded trust,
wrong derived input commitments, incorrect domain identity, symlink proposals
and oversized proposal files. They use synthetic trusted L1 fixtures and actual
EVM witness verification. The journal's existing 18 tests also pass.
