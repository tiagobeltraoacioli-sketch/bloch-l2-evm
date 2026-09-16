// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental Unix host journal: durable publication followed by cursor advance.
//! Recovery re-executes every record with freshly host-authenticated L1 inputs.
#![cfg(unix)]
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{
    escrow_execution::{EscrowEvmDomain, EscrowExecutionError, EscrowExecutionReceipt, TrustedEscrowBatch},
    escrow_inbox::InboxProof,
    BatchWitness, SignedBlockInput,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Serialized JSON payload limit; decoded objects can consume more memory.
pub const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
/// Prototype journal bound; compaction/checkpointing is not implemented.
pub const MAX_RECORDS: u64 = 1_000_000;
const RECORD_MAGIC: &[u8; 8] = b"BLOCHJ01";
const MANIFEST_MAGIC: &[u8; 8] = b"BLOCHM01";

/// Independently retain this watermark to detect deletion of an accepted suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHead {
    pub blocks: u64,
    pub digest: B256,
}
impl JournalHead {
    /// Empty journal commitment, bound to the configured domain/genesis/runtime.
    pub fn genesis(domain: B256) -> Self {
        Self {
            blocks: 0,
            digest: keccak256(manifest(domain)),
        }
    }
}

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    Locked,
    Format,
    WrongDomain,
    NotFresh,
    Rollback,
    Derivation(io::Error),
    Verification(EscrowExecutionError),
    Limit,
    /// An I/O commit error requires closing and recovering before further writes.
    CommitUncertain(io::Error),
    Poisoned,
}
impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    domain: B256,
    number: u64,
    previous: B256,
    proofs: Vec<InboxProof>,
    input: SignedBlockInput,
    witness: BatchWitness,
    receipt: B256,
}

/// Single writer; the private domain can advance only through a durable commit.
pub struct Journal {
    directory: PathBuf,
    _lock: File,
    domain: EscrowEvmDomain,
    head: JournalHead,
    poisoned: bool,
}
impl Journal {
    /// Create a new private directory. Existing paths are never overwritten.
    pub fn create(path: impl AsRef<Path>, domain: EscrowEvmDomain) -> Result<Self, JournalError> {
        require_fresh(&domain)?;
        let path = path.as_ref();
        fs::DirBuilder::new().mode(0o700).create(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("LOCK"))?;
        lock.try_lock().map_err(|_| JournalError::Locked)?;
        lock.sync_all()?;
        publish(path, "MANIFEST", &manifest(domain.id()))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(Self {
            directory: path.to_owned(),
            _lock: lock,
            head: JournalHead::genesis(domain.id()),
            domain,
            poisoned: false,
        })
    }

    /// Recover by re-execution from a fresh trusted genesis domain.
    /// `derive` must independently authenticate each block's L1 context and mapping.
    /// The journal contains no trusted-finality flags and cannot supply this input.
    /// A minimum watermark permits recovery of a commit whose acknowledgment was lost.
    pub fn open(
        path: impl AsRef<Path>,
        mut domain: EscrowEvmDomain,
        minimum: JournalHead,
        mut derive: impl FnMut(u64) -> io::Result<TrustedEscrowBatch>,
    ) -> Result<Self, JournalError> {
        require_fresh(&domain)?;
        let path = path.as_ref();
        if !fs::symlink_metadata(path)?.file_type().is_dir() {
            return Err(JournalError::Format);
        }
        regular(&path.join("LOCK"))?;
        let lock = OpenOptions::new().read(true).write(true).open(path.join("LOCK"))?;
        lock.try_lock().map_err(|_| JournalError::Locked)?;
        regular(&path.join("MANIFEST"))?;
        let bytes = read_bounded(&path.join("MANIFEST"), 40)?;
        if bytes != manifest(domain.id()) {
            return Err(JournalError::WrongDomain);
        }
        let mut head = JournalHead::genesis(domain.id());
        let mut watermark_seen = minimum == head;
        let mut numbers = Vec::new();
        for item in fs::read_dir(path)? {
            let item = item?;
            let name = item.file_name().into_string().map_err(|_| JournalError::Format)?;
            if name == "LOCK" || name == "MANIFEST" || name.starts_with(".pending-") {
                continue;
            }
            if name.len() != 24 || !name.ends_with(".blj") || !name.as_bytes()[..20].iter().all(|b| b.is_ascii_digit())
            {
                return Err(JournalError::Format);
            }
            let number: u64 = name[..20].parse().map_err(|_| JournalError::Format)?;
            numbers.push(number);
            if numbers.len() as u64 > MAX_RECORDS {
                return Err(JournalError::Limit);
            }
        }
        numbers.sort_unstable();
        for number in numbers {
            if number != head.blocks + 1 {
                return Err(JournalError::Format);
            }
            let file = path.join(record_name(number));
            regular(&file)?;
            let bytes = read_bounded(&file, MAX_RECORD_BYTES + 48)?;
            let (record, digest) = decode(&bytes)?;
            if record.domain != domain.id() || record.number != number || record.previous != head.digest {
                return Err(JournalError::Format);
            }
            let trusted = derive(number).map_err(JournalError::Derivation)?;
            let receipt = domain
                .verify_and_advance(&trusted, &record.proofs, &record.input, &record.witness)
                .map_err(JournalError::Verification)?;
            if receipt.commitment() != record.receipt {
                return Err(JournalError::Format);
            }
            head = JournalHead { blocks: number, digest };
            if minimum.blocks == number {
                if minimum != head {
                    return Err(JournalError::Rollback);
                }
                watermark_seen = true;
            }
        }
        if !watermark_seen {
            return Err(JournalError::Rollback);
        }
        // Complete durability of any visible rename left by an interrupted writer.
        File::open(path)?.sync_all()?;
        Ok(Self {
            directory: path.to_owned(),
            _lock: lock,
            domain,
            head,
            poisoned: false,
        })
    }

    /// Re-execute in an isolated candidate, publish+sync one complete record, then
    /// advance both in-memory cursors. Failed verification writes nothing.
    pub fn commit(
        &mut self,
        trusted: &TrustedEscrowBatch,
        proofs: &[InboxProof],
        input: &SignedBlockInput,
        witness: &BatchWitness,
    ) -> Result<EscrowExecutionReceipt, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if self.head.blocks >= MAX_RECORDS {
            return Err(JournalError::Limit);
        }
        let mut candidate = self.domain.clone();
        let receipt = candidate
            .verify_and_advance(trusted, proofs, input, witness)
            .map_err(JournalError::Verification)?;
        let record = Record {
            domain: candidate.id(),
            number: self.head.blocks + 1,
            previous: self.head.digest,
            proofs: proofs.to_vec(),
            input: input.clone(),
            witness: witness.clone(),
            receipt: receipt.commitment(),
        };
        let (bytes, digest) = encode(&record)?;
        // A rename may succeed even when the subsequent directory sync fails.
        // Never retry with this in-memory cursor after any publication error.
        self.poisoned = true;
        publish(&self.directory, &record_name(record.number), &bytes).map_err(JournalError::CommitUncertain)?;
        self.domain = candidate;
        self.head = JournalHead {
            blocks: record.number,
            digest,
        };
        self.poisoned = false;
        Ok(receipt)
    }
    /// Watermark to retain independently after an acknowledged commit.
    pub fn head(&self) -> JournalHead {
        self.head
    }
    pub fn state_root(&self) -> B256 {
        self.domain.state_root()
    }
    pub fn next_block(&self) -> u64 {
        self.domain.next_block()
    }
    pub fn next_deposit(&self) -> u64 {
        self.domain.next_deposit()
    }
}

fn require_fresh(domain: &EscrowEvmDomain) -> Result<(), JournalError> {
    if domain.next_block() != 1 || domain.next_deposit() != 0 {
        return Err(JournalError::NotFresh);
    }
    Ok(())
}
fn manifest(domain: B256) -> Vec<u8> {
    let mut bytes = MANIFEST_MAGIC.to_vec();
    bytes.extend_from_slice(domain.as_slice());
    bytes
}
fn record_name(number: u64) -> String {
    format!("{number:020}.blj")
}
fn regular(path: &Path) -> Result<(), JournalError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(JournalError::Format);
    }
    Ok(())
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, JournalError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(JournalError::Limit);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(JournalError::Limit);
    }
    Ok(bytes)
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES - self.0.len() {
            return Err(io::Error::other("journal record limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(record: &Record) -> Result<(Vec<u8>, B256), JournalError> {
    let mut payload = Bounded(Vec::new());
    serde_json::to_writer(&mut payload, record).map_err(|_| JournalError::Limit)?;
    let digest = keccak256(&payload.0);
    let mut bytes = RECORD_MAGIC.to_vec();
    bytes.extend_from_slice(&(payload.0.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&payload.0);
    bytes.extend_from_slice(digest.as_slice());
    Ok((bytes, digest))
}
fn decode(bytes: &[u8]) -> Result<(Record, B256), JournalError> {
    if bytes.len() < 48 || &bytes[..8] != RECORD_MAGIC {
        return Err(JournalError::Format);
    }
    let length = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if length > MAX_RECORD_BYTES as u64 || length != (bytes.len() - 48) as u64 {
        return Err(JournalError::Format);
    }
    let payload = &bytes[16..bytes.len() - 32];
    let digest = keccak256(payload);
    if digest.as_slice() != &bytes[bytes.len() - 32..] {
        return Err(JournalError::Format);
    }
    let record = serde_json::from_slice(payload).map_err(|_| JournalError::Format)?;
    Ok((record, digest))
}
fn publish(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let destination = directory.join(name);
    if destination.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "journal destination exists",
        ));
    }
    let temporary = directory.join(format!(
        ".pending-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, destination)?;
    File::open(directory)?.sync_all()
}
