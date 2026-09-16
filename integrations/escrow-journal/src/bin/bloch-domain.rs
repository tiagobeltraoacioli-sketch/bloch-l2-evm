// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local operator CLI. Trusted L1 files must come from an independent authenticator.
use alloy_primitives::B256;
use bloch_escrow_journal::{Journal, JournalError, JournalHead, RecoveryLimits, MAX_RECORD_BYTES};
use bloch_l2_evm::{
    domain::TrustedL1Batch,
    escrow_execution::{EscrowEvmDomain, TrustedEscrowBatch, TrustedLockLocation},
    escrow_inbox::InboxProof,
    BatchWitness, ChainSpec, DepositPosition, L2State, SignedBlockInput,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const PROFILE: &str = "bloch-evm-cancun-local-v1";
const MAX_TRUST_BYTES: usize = 4 * 1024 * 1024;
const USAGE: &str = "Experimental local EVM operator; no mainnet finality verifier.\n\
Usage:\n  bloch-domain init CONFIG JOURNAL\n  bloch-domain status CONFIG JOURNAL MINIMUM_HEAD TRUST_DIRECTORY\n  bloch-domain apply CONFIG JOURNAL MINIMUM_HEAD TRUST_DIRECTORY PROPOSAL\n\
CONFIG pins the expected domain and local Cancun profile. TRUST_DIRECTORY must\n\
contain independently authenticated L1 inputs, never proposer-supplied claims.\n\
Successful output includes a new head to retain independently. Exit 3 means the\n\
commit outcome is uncertain: recover with status before retrying.\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    profile: String,
    network: B256,
    module: B256,
    runtime: B256,
    expected_domain: B256,
    witness_limit: usize,
    #[serde(default)]
    recovery: Option<RecoveryConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryConfig {
    max_records: u64,
    max_bytes: u64,
}
impl Config {
    fn domain(self) -> Result<EscrowEvmDomain, Failure> {
        if self.version != 1
            || self.profile != PROFILE
            || self.witness_limit == 0
            || self.witness_limit > 16 * 1024 * 1024
        {
            return Err(fail("unsupported configuration or witness limit"));
        }
        // Fresh zero-credit genesis only. No arbitrary imported balances/cursors.
        let spec = ChainSpec::default();
        let genesis = L2State::genesis(&spec).commit_root();
        let domain = EscrowEvmDomain::new(
            self.network,
            self.module,
            self.runtime,
            spec,
            genesis,
            self.witness_limit,
        )
        .map_err(|e| fail(format!("invalid domain: {e:?}")))?;
        if domain.id() != self.expected_domain {
            return Err(fail("configured domain identity mismatch"));
        }
        Ok(domain)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadFile {
    blocks: u64,
    digest: B256,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    version: u32,
    #[serde(deserialize_with = "bloch_l2_evm::serde_bounded::vector::<_, _, 4096>")]
    proofs: Vec<InboxProof>,
    input: SignedBlockInput,
    witness: BatchWitness,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Location {
    sequence: u64,
    intent: B256,
    height: u64,
    transaction_index: u32,
    output_index: u32,
    transaction: B256,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedFile {
    version: u32,
    height: u64,
    block: B256,
    domain: B256,
    input: B256,
    inbox_root: B256,
    count: u64,
    #[serde(deserialize_with = "bloch_l2_evm::serde_bounded::vector::<_, _, 4096>")]
    locations: Vec<Location>,
}
impl TrustedFile {
    fn batch(self) -> io::Result<TrustedEscrowBatch> {
        if self.version != 1 || self.locations.len() > 4096 {
            return Err(io::Error::other("unsupported or oversized L1 derivation"));
        }
        Ok(TrustedEscrowBatch {
            execution: TrustedL1Batch {
                height: self.height,
                block: self.block,
                domain: self.domain,
                input: self.input,
            },
            inbox_root: self.inbox_root,
            count: self.count,
            locations: self
                .locations
                .into_iter()
                .map(|l| TrustedLockLocation {
                    sequence: l.sequence,
                    intent: l.intent,
                    transaction: l.transaction,
                    position: DepositPosition {
                        l1_height: l.height,
                        l1_tx_index: l.transaction_index,
                        l1_vout: l.output_index,
                    },
                })
                .collect(),
        })
    }
}

struct Failure {
    code: i32,
    message: String,
}
fn fail(message: impl Into<String>) -> Failure {
    Failure {
        code: 1,
        message: message.into(),
    }
}
fn journal_failure(error: JournalError) -> Failure {
    let code = if matches!(error, JournalError::CommitUncertain(_) | JournalError::Poisoned) {
        3
    } else {
        1
    };
    Failure {
        code,
        message: format!("journal: {error:?}"),
    }
}
fn load<T: DeserializeOwned>(path: &Path, limit: usize) -> io::Result<T> {
    // Private operator-controlled parent directories remain a trust requirement.
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::other("input must be a regular file"));
    }
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(io::Error::other("input size limit exceeded"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("input size limit exceeded"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
fn trusted(directory: &Path, number: u64) -> io::Result<TrustedEscrowBatch> {
    load::<TrustedFile>(&directory.join(format!("{number:020}.json")), MAX_TRUST_BYTES)?.batch()
}
fn output(journal: &Journal, domain: B256, receipt: Option<B256>) -> Result<(), Failure> {
    let head = journal.head();
    let value = json!({ "version": 1, "experimental": true, "domain": domain,
        "head": { "blocks": head.blocks, "digest": head.digest },
        "state_root": journal.state_root(), "next_block": journal.next_block(),
        "next_deposit": journal.next_deposit(), "receipt": receipt });
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value).map_err(|e| Failure {
        code: 3,
        message: format!("output failed; recover before retrying: {e}"),
    })?;
    out.write_all(b"\n").and_then(|_| out.flush()).map_err(|e| Failure {
        code: 3,
        message: format!("output failed; recover before retrying: {e}"),
    })
}
fn run() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        io::stdout()
            .write_all(USAGE.as_bytes())
            .map_err(|e| fail(e.to_string()))?;
        return Ok(());
    }
    let command = args.first().and_then(|s| s.to_str()).unwrap_or("");
    let required = match command {
        "init" => 3,
        "status" => 5,
        "apply" => 6,
        _ => return Err(fail(USAGE)),
    };
    if args.len() != required {
        return Err(fail(USAGE));
    }
    let config: Config = load(Path::new(&args[1]), 8192).map_err(|e| fail(format!("configuration: {e}")))?;
    let limits = config
        .recovery
        .as_ref()
        .map_or_else(RecoveryLimits::default, |r| RecoveryLimits {
            records: r.max_records,
            bytes: r.max_bytes,
        });
    let domain = config.domain()?;
    let id = domain.id();
    let directory = Path::new(&args[2]);
    if command == "init" {
        let journal = Journal::create(directory, domain).map_err(journal_failure)?;
        return output(&journal, id, None);
    }
    let minimum: HeadFile = load(Path::new(&args[3]), 4096).map_err(|e| fail(format!("minimum head: {e}")))?;
    let trust = PathBuf::from(&args[4]);
    if !fs::symlink_metadata(&trust)
        .map_err(|e| fail(e.to_string()))?
        .file_type()
        .is_dir()
    {
        return Err(fail("trust directory must be a directory, not a symlink"));
    }
    let trust = fs::canonicalize(trust).map_err(|e| fail(e.to_string()))?;
    // Bound/decode the proposal before recovery work. It contains no trust inputs.
    let proposal: Option<Proposal> = if command == "apply" {
        let proposal: Proposal =
            load(Path::new(&args[5]), MAX_RECORD_BYTES).map_err(|e| fail(format!("proposal: {e}")))?;
        if proposal.version != 1 || proposal.proofs.len() > 4096 {
            return Err(fail("unsupported or oversized proposal"));
        }
        Some(proposal)
    } else {
        None
    };
    let mut journal = Journal::open_with_limits(
        directory,
        domain,
        JournalHead {
            blocks: minimum.blocks,
            digest: minimum.digest,
        },
        limits,
        |number| trusted(&trust, number),
    )
    .map_err(journal_failure)?;
    let receipt = if let Some(proposal) = proposal {
        if proposal.input.context.number != journal.next_block() {
            return Err(fail("proposal does not extend recovered head"));
        }
        let anchor =
            trusted(&trust, journal.next_block()).map_err(|e| fail(format!("L1 derivation unavailable: {e}")))?;
        Some(
            journal
                .commit(&anchor, &proposal.proofs, &proposal.input, &proposal.witness)
                .map_err(journal_failure)?
                .commitment(),
        )
    } else {
        None
    };
    output(&journal, id, receipt)
}
fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr().lock(), "{}", error.message);
        std::process::exit(error.code);
    }
}
