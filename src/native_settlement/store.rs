// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fail-closed, single-host persistence for the dormant settlement registry.
//!
//! This is a local crash-recovery primitive, not consensus, HA, WORM storage,
//! finality, or an authenticated publication service. The rollback floor must
//! be retained independently from this directory.

use super::{
    AcceptedSettlementV1, SettlementError, SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1,
    SettlementRegistryV1,
};
use alloy_primitives::B256;
use sha3::{Digest, Sha3_256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const POLICY_TAG: &[u8; 8] = b"BLSTPL01";
const RECORD_TAG: &[u8; 8] = b"BLSTRC01";
const MARK_TAG: &[u8; 8] = b"BLSTMK01";
const RECORD_BYTES: usize = 8 + 8 + 32 + 32 + 32 + 1 + 6 * 32 + 5 * 8;
/// Exact canonical byte length of an external settlement-store mark.
pub const SETTLEMENT_STORE_MARK_V1_BYTES: usize = 8 + 8 + 32 + 32;
const MAX_RECORDS: u64 = 10_000;

/// Exact independently retained rollback floor. It is not trustworthy when
/// copied from the store directory being opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementStoreMarkV1 {
    /// Snapshot generation; generation zero is the empty registry.
    pub generation: u64,
    /// Digest of the complete canonical record bytes.
    pub record_digest: B256,
    /// Registry state commitment in that record.
    pub state_commitment: B256,
}

impl SettlementStoreMarkV1 {
    /// Encode a fixed-width transport for independent retention. Encoding does
    /// not authenticate the mark or make storage independent.
    pub fn encode(self) -> [u8; SETTLEMENT_STORE_MARK_V1_BYTES] {
        let mut bytes = [0u8; SETTLEMENT_STORE_MARK_V1_BYTES];
        bytes[..8].copy_from_slice(MARK_TAG);
        bytes[8..16].copy_from_slice(&self.generation.to_le_bytes());
        bytes[16..48].copy_from_slice(self.record_digest.as_slice());
        bytes[48..].copy_from_slice(self.state_commitment.as_slice());
        bytes
    }

    /// Decode exactly one canonical external-floor transport.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementStoreErrorV1> {
        if bytes.len() != SETTLEMENT_STORE_MARK_V1_BYTES || &bytes[..8] != MARK_TAG {
            return Err(SettlementStoreErrorV1::Format);
        }
        Ok(Self {
            generation: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| SettlementStoreErrorV1::Format)?),
            record_digest: B256::from_slice(&bytes[16..48]),
            state_commitment: B256::from_slice(&bytes[48..]),
        })
    }
}

/// Deterministic refusal or uncertain durable publication.
#[derive(Debug)]
pub enum SettlementStoreErrorV1 {
    /// Filesystem operation failed before publication began.
    Io(io::Error),
    /// Another process owns this store.
    Locked,
    /// Noncanonical, partial, unexpected, or unsafe filesystem state.
    Format,
    /// A leftover private publication inode proves a prior commit did not
    /// finish cleanly. Operator reconciliation is required; it is not ignored.
    CrashEvidence,
    /// Local bounded-history limit was exceeded.
    Limit,
    /// The supplied policy does not exactly match the store policy.
    Policy,
    /// The external floor is absent or disagrees with retained history.
    Rollback,
    /// Caller CAS mark is stale or forged.
    Cas,
    /// Native settlement verification rejected the candidate.
    Settlement(SettlementError),
    /// A write, link, unlink, or fsync may have changed durable state. Close
    /// and reopen; blindly retrying is forbidden.
    CommitUncertain(io::Error),
    /// This handle observed an uncertain commit and cannot be used again.
    Poisoned,
}

impl From<io::Error> for SettlementStoreErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl core::fmt::Display for SettlementStoreErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "settlement store refused operation: {self:?}")
    }
}

impl std::error::Error for SettlementStoreErrorV1 {}

/// Exclusively locked local settlement registry and append-only snapshots.
pub struct SettlementStoreV1 {
    directory: PathBuf,
    lock: File,
    registry: SettlementRegistryV1,
    mark: SettlementStoreMarkV1,
    poisoned: bool,
}

impl Drop for SettlementStoreV1 {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

impl SettlementStoreV1 {
    /// Create an owner-only store without replacing any existing path. The
    /// returned generation-zero mark must be retained outside this directory.
    pub fn create(path: impl AsRef<Path>, policy: SettlementPolicyV1) -> Result<Self, SettlementStoreErrorV1> {
        let registry = SettlementRegistryV1::new(policy).map_err(SettlementStoreErrorV1::Settlement)?;
        fs::DirBuilder::new().mode(0o700).create(path.as_ref())?;
        let directory = fs::canonicalize(path)?;
        check_private_directory(&directory)?;
        let lock = create_file(&directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| SettlementStoreErrorV1::Locked)?;
        lock.sync_all()?;
        let mut policy_bytes = Vec::with_capacity(40);
        policy_bytes.extend_from_slice(POLICY_TAG);
        policy_bytes.extend_from_slice(
            policy
                .commitment()
                .map_err(SettlementStoreErrorV1::Settlement)?
                .as_slice(),
        );
        publish_create_once(&directory, "POLICY", &policy_bytes)?;
        let bytes = encode_record(0, policy, B256::ZERO, &registry)?;
        publish_create_once(&directory, &record_name(0), &bytes)?;
        directory_file(&directory)?.sync_all()?;
        directory_file(directory.parent().ok_or(SettlementStoreErrorV1::Format)?)?.sync_all()?;
        let mark = mark(0, &bytes, &registry);
        Ok(Self {
            directory,
            lock,
            registry,
            mark,
            poisoned: false,
        })
    }

    /// Replay all canonical records under the exact policy and require the
    /// independently supplied floor to occur unchanged in that history.
    pub fn open(
        path: impl AsRef<Path>,
        policy: SettlementPolicyV1,
        floor: SettlementStoreMarkV1,
    ) -> Result<Self, SettlementStoreErrorV1> {
        check_private_directory(path.as_ref())?;
        let directory = fs::canonicalize(path)?;
        regular_private(&directory.join("LOCK"))?;
        let lock = OpenOptions::new().read(true).write(true).open(directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| SettlementStoreErrorV1::Locked)?;
        let commitment = policy.commitment().map_err(SettlementStoreErrorV1::Settlement)?;
        let expected_policy = [POLICY_TAG.as_slice(), commitment.as_slice()].concat();
        if read_exact_bounded(&directory.join("POLICY"), 40)? != expected_policy {
            return Err(SettlementStoreErrorV1::Policy);
        }
        let generations = record_generations(&directory)?;
        if generations.is_empty() || generations.len() > MAX_RECORDS as usize + 1 {
            return Err(SettlementStoreErrorV1::Limit);
        }
        let mut registry = SettlementRegistryV1::new(policy).map_err(SettlementStoreErrorV1::Settlement)?;
        let mut previous_digest = B256::ZERO;
        let mut previous_head = None;
        let mut found_floor = false;
        let mut current_mark = None;
        for (index, generation) in generations.into_iter().enumerate() {
            if generation != index as u64 {
                return Err(SettlementStoreErrorV1::Format);
            }
            let bytes = read_exact_bounded(&directory.join(record_name(generation)), RECORD_BYTES)?;
            let decoded = decode_record(&bytes, generation, policy, previous_digest)?;
            validate_replayed_head(generation, policy, previous_head, decoded.head)?;
            registry.head = decoded.head;
            if registry.state_commitment() != decoded.state_commitment {
                return Err(SettlementStoreErrorV1::Format);
            }
            let observed = mark(generation, &bytes, &registry);
            if generation == floor.generation {
                if observed != floor {
                    return Err(SettlementStoreErrorV1::Rollback);
                }
                found_floor = true;
            }
            previous_digest = observed.record_digest;
            previous_head = decoded.head;
            current_mark = Some(observed);
        }
        if !found_floor {
            return Err(SettlementStoreErrorV1::Rollback);
        }
        directory_file(&directory)?.sync_all()?;
        Ok(Self {
            directory,
            lock,
            registry,
            mark: current_mark.ok_or(SettlementStoreErrorV1::Format)?,
            poisoned: false,
        })
    }

    /// Current externally retainable CAS/rollback mark.
    pub const fn mark(&self) -> SettlementStoreMarkV1 {
        self.mark
    }

    /// Current local registry. This value is not a finalized-L2 capability.
    pub const fn registry(&self) -> &SettlementRegistryV1 {
        &self.registry
    }

    /// Verify against a private clone, publish one create-once record, and only
    /// then expose the new local registry. Any uncertain I/O poisons the handle.
    pub fn verify_and_commit<V: SettlementProofVerifierV1>(
        &mut self,
        expected: SettlementStoreMarkV1,
        transaction_bytes: &[u8],
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1), SettlementStoreErrorV1> {
        if self.poisoned {
            return Err(SettlementStoreErrorV1::Poisoned);
        }
        if expected != self.mark {
            return Err(SettlementStoreErrorV1::Cas);
        }
        let generation = self
            .mark
            .generation
            .checked_add(1)
            .ok_or(SettlementStoreErrorV1::Limit)?;
        if generation > MAX_RECORDS {
            return Err(SettlementStoreErrorV1::Limit);
        }
        let mut next = self.registry.clone();
        let accepted = next
            .verify_and_apply(transaction_bytes, expectation, verifier)
            .map_err(SettlementStoreErrorV1::Settlement)?;
        let bytes = encode_record(generation, next.policy, self.mark.record_digest, &next)?;
        self.poisoned = true;
        if let Err(error) = publish_create_once(&self.directory, &record_name(generation), &bytes) {
            return Err(SettlementStoreErrorV1::CommitUncertain(error));
        }
        self.registry = next;
        self.mark = mark(generation, &bytes, &self.registry);
        self.poisoned = false;
        Ok((accepted, self.mark))
    }
}

struct DecodedRecord {
    state_commitment: B256,
    head: Option<AcceptedSettlementV1>,
}

fn encode_record(
    generation: u64,
    policy: SettlementPolicyV1,
    previous_digest: B256,
    registry: &SettlementRegistryV1,
) -> Result<Vec<u8>, SettlementStoreErrorV1> {
    let mut bytes = Vec::with_capacity(RECORD_BYTES);
    bytes.extend_from_slice(RECORD_TAG);
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(
        policy
            .commitment()
            .map_err(SettlementStoreErrorV1::Settlement)?
            .as_slice(),
    );
    bytes.extend_from_slice(previous_digest.as_slice());
    bytes.extend_from_slice(registry.state_commitment().as_slice());
    match registry.head {
        None => {
            bytes.push(0);
            bytes.resize(RECORD_BYTES, 0);
        }
        Some(head) => {
            bytes.push(1);
            for value in [
                head.commitment,
                head.l2_header_hash,
                head.l2_state_root,
                head.l1_block,
                head.source_commitment,
                head.inbox_root,
            ] {
                bytes.extend_from_slice(value.as_slice());
            }
            for value in [
                head.l2_number,
                head.l1_slot,
                head.l1_height,
                head.inbox_count,
                head.consumed_end,
            ] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    if bytes.len() != RECORD_BYTES {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
    expected_generation: u64,
    policy: SettlementPolicyV1,
    expected_previous: B256,
) -> Result<DecodedRecord, SettlementStoreErrorV1> {
    if bytes.len() != RECORD_BYTES || &bytes[..8] != RECORD_TAG {
        return Err(SettlementStoreErrorV1::Format);
    }
    let mut reader = Reader(&bytes[8..]);
    if reader.u64()? != expected_generation
        || reader.hash()? != policy.commitment().map_err(SettlementStoreErrorV1::Settlement)?
        || reader.hash()? != expected_previous
    {
        return Err(SettlementStoreErrorV1::Format);
    }
    let state_commitment = reader.hash()?;
    let present = reader.byte()?;
    let head = match present {
        0 => {
            if reader.remaining().iter().any(|byte| *byte != 0) {
                return Err(SettlementStoreErrorV1::Format);
            }
            let padding = reader.remaining().len();
            reader.take(padding)?;
            None
        }
        1 => Some(AcceptedSettlementV1 {
            commitment: reader.hash()?,
            l2_header_hash: reader.hash()?,
            l2_state_root: reader.hash()?,
            l1_block: reader.hash()?,
            source_commitment: reader.hash()?,
            inbox_root: reader.hash()?,
            l2_number: reader.u64()?,
            l1_slot: reader.u64()?,
            l1_height: reader.u64()?,
            inbox_count: reader.u64()?,
            consumed_end: reader.u64()?,
        }),
        _ => return Err(SettlementStoreErrorV1::Format),
    };
    if !reader.remaining().is_empty() {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(DecodedRecord { state_commitment, head })
}

fn validate_replayed_head(
    generation: u64,
    policy: SettlementPolicyV1,
    previous: Option<AcceptedSettlementV1>,
    current: Option<AcceptedSettlementV1>,
) -> Result<(), SettlementStoreErrorV1> {
    if generation == 0 {
        return if previous.is_none() && current.is_none() {
            Ok(())
        } else {
            Err(SettlementStoreErrorV1::Format)
        };
    }
    let head = current.ok_or(SettlementStoreErrorV1::Format)?;
    if [
        head.commitment,
        head.l2_header_hash,
        head.l2_state_root,
        head.l1_block,
        head.source_commitment,
        head.inbox_root,
    ]
    .contains(&B256::ZERO)
        || head.l1_height == 0
        || head.l1_slot < head.l1_height
        || head.consumed_end > head.inbox_count
        || head.l2_number
            != policy
                .first_l2_number
                .checked_add(generation - 1)
                .ok_or(SettlementStoreErrorV1::Limit)?
    {
        return Err(SettlementStoreErrorV1::Format);
    }
    if let Some(old) = previous {
        if head.l2_number != old.l2_number.checked_add(1).ok_or(SettlementStoreErrorV1::Format)?
            || head.consumed_end < old.consumed_end
            || head.inbox_count < old.inbox_count
            || head.l1_height < old.l1_height
            || head.l1_slot < old.l1_slot
            || (head.l1_height == old.l1_height && (head.l1_block != old.l1_block || head.l1_slot != old.l1_slot))
            || (head.l1_height > old.l1_height && head.l1_slot <= old.l1_slot)
            || (head.inbox_count == old.inbox_count && head.inbox_root != old.inbox_root)
        {
            return Err(SettlementStoreErrorV1::Format);
        }
    }
    Ok(())
}

fn mark(generation: u64, bytes: &[u8], registry: &SettlementRegistryV1) -> SettlementStoreMarkV1 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-STORE-RECORD:1");
    hasher.update(bytes);
    SettlementStoreMarkV1 {
        generation,
        record_digest: B256::from_slice(&hasher.finalize()),
        state_commitment: registry.state_commitment(),
    }
}

fn record_name(generation: u64) -> String {
    format!("{generation:020}.sst")
}

fn record_generations(directory: &Path) -> Result<Vec<u64>, SettlementStoreErrorV1> {
    let mut values = Vec::new();
    for item in fs::read_dir(directory)? {
        let name = item?
            .file_name()
            .into_string()
            .map_err(|_| SettlementStoreErrorV1::Format)?;
        if name == "LOCK" || name == "POLICY" {
            continue;
        }
        if name.starts_with(".pending-") {
            return Err(SettlementStoreErrorV1::CrashEvidence);
        }
        if name.len() != 24 || !name.ends_with(".sst") || !name.as_bytes()[..20].iter().all(u8::is_ascii_digit) {
            return Err(SettlementStoreErrorV1::Format);
        }
        values.push(name[..20].parse().map_err(|_| SettlementStoreErrorV1::Format)?);
    }
    values.sort_unstable();
    Ok(values)
}

fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn publish_create_once(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let destination = directory.join(name);
    if destination.try_exists()? {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "settlement record exists"));
    }
    let temp = directory.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::hard_link(&temp, &destination)?;
    fs::remove_file(&temp)?;
    directory_file(directory)?.sync_all()
}

fn check_private_directory(path: &Path) -> Result<(), SettlementStoreErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(())
}

fn regular_private(path: &Path) -> Result<(), SettlementStoreErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o077 != 0 {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(())
}

fn directory_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn read_exact_bounded(path: &Path, expected: usize) -> Result<Vec<u8>, SettlementStoreErrorV1> {
    regular_private(path)?;
    let file = File::open(path)?;
    if file.metadata()?.len() != expected as u64 {
        return Err(SettlementStoreErrorV1::Format);
    }
    let mut bytes = Vec::with_capacity(expected);
    file.take(expected as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(bytes)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SettlementStoreErrorV1> {
        if count > self.0.len() {
            return Err(SettlementStoreErrorV1::Format);
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, SettlementStoreErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, SettlementStoreErrorV1> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| SettlementStoreErrorV1::Format)?,
        ))
    }

    fn hash(&mut self) -> Result<B256, SettlementStoreErrorV1> {
        Ok(B256::from_slice(self.take(32)?))
    }

    const fn remaining(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests;
