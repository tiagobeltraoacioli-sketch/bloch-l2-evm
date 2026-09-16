// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable experimental lock batches. Replay always rechecks hybrid signatures.
use crate::{AuthorizationError, PqEscrow, SignedLock};
use alloy_primitives::B256;
use bloch_l2_evm::escrow::{LockIntent, LockedDeposit};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCHES: u64 = 10_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockMark {
    pub batches: u64,
    pub digest: B256,
}
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Locked,
    Format,
    Limit,
    Baseline,
    Rollback,
    Authorization(AuthorizationError),
    CommitUncertain(io::Error),
    Poisoned,
}
impl From<io::Error> for StoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedLock {
    intent: LockIntent,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    previous: B256,
    after: B256,
    locks: Vec<OwnedLock>,
}
/// Exclusive local writer. Private ledger prevents bypassing durable submission.
/// The caller supplies and independently trusts the same baseline on every open.
pub struct LockStore {
    directory: PathBuf,
    _lock: File,
    escrow: PqEscrow,
    mark: LockMark,
    poisoned: bool,
}
impl LockStore {
    pub fn create(path: impl AsRef<Path>, baseline: PqEscrow) -> Result<Self, StoreError> {
        fs::DirBuilder::new().mode(0o700).create(path.as_ref())?;
        let directory = fs::canonicalize(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| StoreError::Locked)?;
        lock.sync_all()?;
        let digest = baseline.commitment();
        publish(&directory, "BASELINE", digest.as_slice())?;
        File::open(directory.parent().ok_or(StoreError::Format)?)?.sync_all()?;
        Ok(Self {
            directory,
            _lock: lock,
            escrow: baseline,
            mark: LockMark { batches: 0, digest },
            poisoned: false,
        })
    }
    /// Minimum must be retained outside this directory. No local-only mechanism
    /// can detect replacement with an older valid prefix without such a floor.
    pub fn open(path: impl AsRef<Path>, mut baseline: PqEscrow, minimum: LockMark) -> Result<Self, StoreError> {
        if !fs::symlink_metadata(path.as_ref())?.file_type().is_dir() {
            return Err(StoreError::Format);
        }
        let directory = fs::canonicalize(path)?;
        regular(&directory.join("LOCK"))?;
        let lock = OpenOptions::new().read(true).write(true).open(directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| StoreError::Locked)?;
        let digest = baseline.commitment();
        if read(&directory.join("BASELINE"))? != digest.as_slice() {
            return Err(StoreError::Baseline);
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let name = entry?.file_name().into_string().map_err(|_| StoreError::Format)?;
            if name == "LOCK" || name == "BASELINE" || name.starts_with(".pending-") {
                continue;
            }
            if names.len() >= MAX_BATCHES as usize {
                return Err(StoreError::Limit);
            }
            names.push(name);
        }
        names.sort();
        let mut mark = LockMark { batches: 0, digest };
        let mut found = mark == minimum;
        for (index, filename) in names.iter().enumerate() {
            if *filename != name(index as u64 + 1) {
                return Err(StoreError::Format);
            }
            let bytes = read(&directory.join(filename))?;
            let record: Record = serde_json::from_slice(&bytes).map_err(|_| StoreError::Format)?;
            if record.version != 1 || record.previous != mark.digest {
                return Err(StoreError::Format);
            }
            let requests: Vec<_> = record
                .locks
                .iter()
                .map(|r| SignedLock {
                    intent: &r.intent,
                    public_key: &r.public_key,
                    signature: &r.signature,
                })
                .collect();
            baseline.submit_batch(&requests).map_err(StoreError::Authorization)?;
            if baseline.commitment() != record.after {
                return Err(StoreError::Format);
            }
            mark = LockMark {
                batches: index as u64 + 1,
                digest: hash(&bytes),
            };
            found |= mark == minimum;
        }
        if !found {
            return Err(StoreError::Rollback);
        }
        Ok(Self {
            directory,
            _lock: lock,
            escrow: baseline,
            mark,
            poisoned: false,
        })
    }
    /// Publish disk state before memory. On any publication error, reopen and
    /// recover: the batch might already be committed, so blind retries are unsafe.
    pub fn submit_batch(&mut self, requests: &[SignedLock<'_>]) -> Result<Vec<LockedDeposit>, StoreError> {
        self.submit_staged(requests, |_| Ok(()))
    }
    fn submit_staged(
        &mut self,
        requests: &[SignedLock<'_>],
        after: impl FnMut(PublicationStage) -> io::Result<()>,
    ) -> Result<Vec<LockedDeposit>, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if self.mark.batches >= MAX_BATCHES {
            return Err(StoreError::Limit);
        }
        let (candidate, records) = self.escrow.prepare_batch(requests).map_err(StoreError::Authorization)?;
        let record = Record {
            version: 1,
            previous: self.mark.digest,
            after: candidate.commitment(),
            locks: requests
                .iter()
                .map(|r| OwnedLock {
                    intent: r.intent.clone(),
                    public_key: r.public_key.to_vec(),
                    signature: r.signature.to_vec(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| StoreError::Format)?;
        if bytes.len() > MAX_BYTES {
            return Err(StoreError::Limit);
        }
        let mark = LockMark {
            batches: self.mark.batches + 1,
            digest: hash(&bytes),
        };
        self.poisoned = true;
        publish_staged(&self.directory, &name(mark.batches), &bytes, after).map_err(StoreError::CommitUncertain)?;
        self.escrow = candidate;
        self.mark = mark;
        self.poisoned = false;
        Ok(records)
    }
    pub fn mark(&self) -> Result<LockMark, StoreError> {
        if self.poisoned {
            Err(StoreError::Poisoned)
        } else {
            Ok(self.mark)
        }
    }
    pub fn escrow(&self) -> Result<&PqEscrow, StoreError> {
        if self.poisoned {
            Err(StoreError::Poisoned)
        } else {
            Ok(&self.escrow)
        }
    }
}
fn name(n: u64) -> String {
    format!("{n:020}.locks")
}
fn hash(bytes: &[u8]) -> B256 {
    let mut h = Sha3_256::new();
    h.update(b"BLOCH:EXPERIMENTAL:LOCK:JOURNAL:1");
    h.update(bytes);
    B256::from_slice(&h.finalize())
}
fn regular(path: &Path) -> Result<(), StoreError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(StoreError::Format);
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>, StoreError> {
    regular(path)?;
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_BYTES as u64 {
        return Err(StoreError::Limit);
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(StoreError::Limit);
    }
    Ok(bytes)
}
fn publish(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    publish_staged(directory, name, bytes, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationStage {
    Created,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

// Private instrumentation: production has no environment-controlled fault hook.
fn publish_staged(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    mut after: impl FnMut(PublicationStage) -> io::Result<()>,
) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let pending = directory.join(format!(
        ".pending-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let target = directory.join(name);
    if fs::symlink_metadata(&target).is_ok() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "committed record exists"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    after(PublicationStage::Created)?;
    file.write_all(bytes)?;
    after(PublicationStage::Written)?;
    file.sync_all()?;
    after(PublicationStage::FileSynced)?;
    fs::rename(pending, target)?;
    after(PublicationStage::Renamed)?;
    File::open(directory)?.sync_all()?;
    after(PublicationStage::DirectorySynced)
}

#[cfg(test)]
mod fault_tests;
