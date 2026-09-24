// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded Unix checkpoint history. Old signatures establish a rollback floor,
//! never current freshness. The signer arrangement remains independently trusted.
use crate::checkpoint::{CheckpointError, CheckpointPolicy, VerifiedCheckpoint};
use alloy_primitives::B256;
use bloch_pos_committee::ws::{CheckpointEnvelope, WeakSubjectivityCheckpoint, WS_CHECKPOINT_BYTES};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 10_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointMark {
    pub epoch: u64,
    pub digest: B256,
}
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Locked,
    Format,
    Limit,
    Rollback,
    Policy,
    Verify(CheckpointError),
    CommitUncertain(io::Error),
    Poisoned,
    Empty,
    Missing,
}
impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
struct Stored {
    envelope: CheckpointEnvelope,
    header: Vec<u8>,
    verified: VerifiedCheckpoint,
}
/// Reverified historical checkpoint identity for audit/recovery only. This is
/// deliberately a distinct type from `VerifiedCheckpoint` and cannot be used
/// as a currently fresh checkpoint capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoricalCheckpointAuditV1 {
    policy_identity: B256,
    checkpoint_digest: B256,
    checkpoint_epoch: u64,
    checked_at_epoch: u64,
    anchor: bloch_l2_evm::l1::FinalizedCheckpoint,
    arrangement_review_due: bool,
}
impl HistoricalCheckpointAuditV1 {
    pub const fn policy_identity(&self) -> B256 {
        self.policy_identity
    }
    pub const fn checkpoint_digest(&self) -> B256 {
        self.checkpoint_digest
    }
    pub const fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }
    pub const fn checked_at_epoch(&self) -> u64 {
        self.checked_at_epoch
    }
    pub const fn anchor(&self) -> bloch_l2_evm::l1::FinalizedCheckpoint {
        self.anchor
    }
    pub const fn arrangement_review_due(&self) -> bool {
        self.arrangement_review_due
    }
}
pub struct CheckpointStore {
    directory: PathBuf,
    _lock: File,
    policy: CheckpointPolicy,
    latest: Option<Stored>,
    history: Vec<CheckpointMark>,
    count: usize,
    poisoned: bool,
}
impl CheckpointStore {
    /// Create a new private history. Existing directories are never replaced.
    pub fn create(path: impl AsRef<Path>, policy: CheckpointPolicy) -> Result<Self, StoreError> {
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
        publish(&directory, "POLICY", policy.storage_identity().as_slice())?;
        File::open(directory.parent().ok_or(StoreError::Format)?)?.sync_all()?;
        Ok(Self {
            directory,
            _lock: lock,
            policy,
            latest: None,
            history: Vec::new(),
            count: 0,
            poisoned: false,
        })
    }
    /// Reverify signed history, allowing stale entries only as rollback evidence.
    /// An independently retained minimum detects loss of an acknowledged suffix.
    /// Recovered anchors are available only through `current`, which checks age.
    pub fn open(
        path: impl AsRef<Path>,
        policy: CheckpointPolicy,
        minimum: Option<CheckpointMark>,
    ) -> Result<Self, StoreError> {
        if !fs::symlink_metadata(path.as_ref())?.file_type().is_dir() {
            return Err(StoreError::Format);
        }
        let directory = fs::canonicalize(path)?;
        regular(&directory.join("LOCK"))?;
        let lock = OpenOptions::new().read(true).write(true).open(directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| StoreError::Locked)?;
        if read(&directory.join("POLICY"))? != policy.storage_identity().as_slice() {
            return Err(StoreError::Policy);
        }
        let mut epochs = Vec::new();
        for item in fs::read_dir(&directory)? {
            let name = item?.file_name().into_string().map_err(|_| StoreError::Format)?;
            if name == "LOCK" || name == "POLICY" || name.starts_with(".pending-") {
                continue;
            }
            if name.len() != 24 || !name.ends_with(".ckp") || !name.as_bytes()[..20].iter().all(u8::is_ascii_digit) {
                return Err(StoreError::Format);
            }
            epochs.push(name[..20].parse::<u64>().map_err(|_| StoreError::Format)?);
            if epochs.len() > MAX_RECORDS {
                return Err(StoreError::Limit);
            }
        }
        epochs.sort_unstable();
        let mut store = Self {
            directory,
            _lock: lock,
            policy,
            latest: None,
            history: Vec::new(),
            count: 0,
            poisoned: false,
        };
        let mut found = minimum.is_none();
        for epoch in epochs {
            let (previous, envelope, header) = decode(&read(&store.directory.join(name(epoch)))?)?;
            if envelope.checkpoint.epoch != epoch || previous != store.previous_digest() {
                return Err(StoreError::Format);
            }
            if store.mark().is_some_and(|m| epoch <= m.epoch) {
                return Err(StoreError::Rollback);
            }
            // Historical authentication, not a public fresh anchor. No caller gets
            // this object without a separate current-epoch freshness check.
            let verified = store
                .policy
                .verify(&envelope, &header, epoch, store.latest.as_ref().map(|s| &s.verified))
                .map_err(StoreError::Verify)?;
            let mark = CheckpointMark {
                epoch,
                digest: verified.digest(),
            };
            if let Some(minimum) = minimum {
                if minimum.epoch == epoch {
                    if minimum != mark {
                        return Err(StoreError::Rollback);
                    }
                    found = true;
                }
            }
            store.latest = Some(Stored {
                envelope,
                header,
                verified,
            });
            store.history.push(mark);
            store.count += 1;
        }
        if !found {
            return Err(StoreError::Rollback);
        }
        File::open(&store.directory)?.sync_all()?;
        Ok(store)
    }
    /// Informational durable floor, not a current trust anchor.
    pub fn mark(&self) -> Option<CheckpointMark> {
        self.latest.as_ref().map(|s| CheckpointMark {
            epoch: s.verified.epoch(),
            digest: s.verified.digest(),
        })
    }
    fn previous_digest(&self) -> B256 {
        self.mark()
            .map(|m| m.digest)
            .unwrap_or_else(|| self.policy.storage_identity())
    }
    /// Return a freshly reverified anchor or refuse stale/future state.
    pub fn current(&self, current_epoch: u64) -> Result<VerifiedCheckpoint, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let latest = self.latest.as_ref().ok_or(StoreError::Empty)?;
        self.policy
            .verify(&latest.envelope, &latest.header, current_epoch, None)
            .map_err(StoreError::Verify)
    }
    /// Reverify one retained checkpoint exactly at the historical epoch recorded
    /// by a durable audit receipt. `observed_current_epoch` prevents a forged
    /// receipt from claiming that verification happened in the future. The
    /// result is audit-only and is never a current checkpoint capability.
    pub fn historical_audit(
        &self,
        epoch: u64,
        checked_at_epoch: u64,
        observed_current_epoch: u64,
    ) -> Result<HistoricalCheckpointAuditV1, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if checked_at_epoch > observed_current_epoch {
            return Err(StoreError::Verify(CheckpointError::Future));
        }
        let index = self
            .history
            .binary_search_by_key(&epoch, |mark| mark.epoch)
            .ok()
            .ok_or(StoreError::Missing)?;
        let retained = self.history[index];
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| self.history[previous].digest)
            .unwrap_or_else(|| self.policy.storage_identity());
        let (previous, envelope, header) = decode(&read(&self.directory.join(name(epoch)))?)?;
        if previous != expected_previous || envelope.checkpoint.epoch != epoch {
            return Err(StoreError::Format);
        }
        let verified = self
            .policy
            .verify(&envelope, &header, checked_at_epoch, None)
            .map_err(StoreError::Verify)?;
        if verified.digest() != retained.digest {
            return Err(StoreError::Rollback);
        }
        Ok(HistoricalCheckpointAuditV1 {
            policy_identity: verified.policy_identity(),
            checkpoint_digest: verified.digest(),
            checkpoint_epoch: verified.epoch(),
            checked_at_epoch: verified.checked_at_epoch(),
            anchor: verified.anchor(),
            arrangement_review_due: verified.arrangement_review_due(),
        })
    }
    /// Verify first, durably publish, then advance the in-memory floor. Identical
    /// fresh checkpoints are idempotent. I/O ambiguity requires closing/recovery.
    pub fn accept(
        &mut self,
        envelope: &CheckpointEnvelope,
        header: &[u8],
        current_epoch: u64,
    ) -> Result<CheckpointMark, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let verified = self
            .policy
            .verify(
                envelope,
                header,
                current_epoch,
                self.latest.as_ref().map(|s| &s.verified),
            )
            .map_err(StoreError::Verify)?;
        let mark = CheckpointMark {
            epoch: verified.epoch(),
            digest: verified.digest(),
        };
        if self.mark() == Some(mark) {
            return Ok(mark);
        }
        if self.count >= MAX_RECORDS {
            return Err(StoreError::Limit);
        }
        let bytes = encode(self.previous_digest(), envelope, header);
        if bytes.len() > MAX_BYTES {
            return Err(StoreError::Limit);
        }
        self.poisoned = true;
        publish(&self.directory, &name(mark.epoch), &bytes).map_err(StoreError::CommitUncertain)?;
        self.latest = Some(Stored {
            envelope: envelope.clone(),
            header: header.to_vec(),
            verified,
        });
        self.history.push(mark);
        self.count += 1;
        self.poisoned = false;
        Ok(mark)
    }
}
fn name(epoch: u64) -> String {
    format!("{epoch:020}.ckp")
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
fn encode(previous: B256, envelope: &CheckpointEnvelope, header: &[u8]) -> Vec<u8> {
    let mut bytes = b"BLCHCP01".to_vec();
    bytes.extend_from_slice(previous.as_slice());
    bytes.extend_from_slice(&envelope.checkpoint.canonical_serialize());
    bytes.extend_from_slice(header);
    bytes.push(envelope.signatures.len() as u8);
    for (index, signature) in &envelope.signatures {
        bytes.push(*index);
        bytes.extend_from_slice(&(signature.len() as u32).to_le_bytes());
        bytes.extend_from_slice(signature);
    }
    bytes
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if n > self.0.len() {
            return Err(StoreError::Format);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?.try_into().map_err(|_| StoreError::Format)
    }
}
fn decode(bytes: &[u8]) -> Result<(B256, CheckpointEnvelope, Vec<u8>), StoreError> {
    let mut r = Reader(bytes);
    if r.take(8)? != b"BLCHCP01" {
        return Err(StoreError::Format);
    }
    let previous = B256::from(r.array::<32>()?);
    let canonical = r.take(WS_CHECKPOINT_BYTES)?;
    let mut c = Reader(canonical);
    let cp = WeakSubjectivityCheckpoint {
        version: u16::from_le_bytes(c.array()?),
        network_id: u32::from_le_bytes(c.array()?),
        genesis_root: c.array()?,
        epoch: u64::from_le_bytes(c.array()?),
        block_root: c.array()?,
        state_root: c.array()?,
        validator_set_root: c.array()?,
        issued_at: u64::from_le_bytes(c.array()?),
        signer_set_id: u32::from_le_bytes(c.array()?),
    };
    if !c.0.is_empty() || cp.canonical_serialize() != canonical {
        return Err(StoreError::Format);
    }
    let header = r.take(304)?.to_vec();
    let count = r.take(1)?[0] as usize;
    if count > 5 {
        return Err(StoreError::Limit);
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        let index = r.take(1)?[0];
        let len = u32::from_le_bytes(r.array()?) as usize;
        if len > 8192 {
            return Err(StoreError::Limit);
        }
        signatures.push((index, r.take(len)?.to_vec()));
    }
    if !r.0.is_empty() {
        return Err(StoreError::Format);
    }
    Ok((
        previous,
        CheckpointEnvelope {
            checkpoint: cp,
            signatures,
        },
        header,
    ))
}
fn publish(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let destination = directory.join(name);
    if destination.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "checkpoint destination exists",
        ));
    }
    let temp = directory.join(format!(
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
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temp, destination)?;
    File::open(directory)?.sync_all()
}
