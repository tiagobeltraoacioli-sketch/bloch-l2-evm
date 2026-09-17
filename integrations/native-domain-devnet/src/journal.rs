// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unix single-writer source journal with exact externally retained tip binding.
//! No repair or acceptance of an unacknowledged suffix is performed.
use crate::{Error, SourceAnchor, SourceBatch, SourceRegistry, MAX_LOCKS, MAX_SOURCE_BYTES};
use alloy_primitives::{keccak256, Address, Bytes, B256};
use bloch_l2_evm::{
    escrow::LockedDeposit,
    escrow_inbox::InboxProof,
    l1::{
        height::{HeightCursor, HeightPosition, MAX_HEIGHT_HEADERS},
        FinalizedCheckpoint,
    },
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

const FILE_TAG: &[u8; 8] = b"BLSRCJ01";
const FRAME_TAG: &[u8; 8] = b"BLSRCF01";
const MARK_TAG: &[u8] = b"BLOCH:SOURCE:MARK:1";
const FILE_HEADER: usize = 40;
const FRAME_OVERHEAD: usize = 8 + 4 + 32;
const MAX_PROOF_DEPTH: usize = 12; // ceil(log2(MAX_LOCKS)).
const PROOF_FIXED: usize = 32 + 32 + 20 + 8 + 8 + 8 + 1;
/// Largest accepted payload, before its fixed frame envelope.
pub const MAX_FRAME_BYTES: usize =
    4 + MAX_SOURCE_BYTES + 4 + MAX_HEIGHT_HEADERS * 304 + 4 + MAX_LOCKS * (PROOF_FIXED + MAX_PROOF_DEPTH * 32);
/// Hard local total-file budget; this is not a native consensus limit.
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS: u64 = 10_000;
pub const MARK_BYTES: usize = MARK_TAG.len() + 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    pub records: u64,
    /// Includes file header, frame envelopes and payloads.
    pub bytes: u64,
}
impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            records: MAX_RECORDS,
            bytes: MAX_JOURNAL_BYTES,
        }
    }
}
impl JournalLimits {
    fn validate(self) -> Result<(), JournalError> {
        if self.records == 0
            || self.records > MAX_RECORDS
            || self.bytes < FILE_HEADER as u64
            || self.bytes > MAX_JOURNAL_BYTES
        {
            return Err(JournalError::Limit);
        }
        Ok(())
    }
}

/// Exact independently retained source tip. Decoding this record does not make
/// it trusted; do not read the expected mark from the journal being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceMark {
    pub records: u64,
    pub commitment: B256,
    pub anchor: SourceAnchor,
    pub inbox_count: u64,
    pub inbox_root: B256,
}
impl SourceMark {
    fn of(registry: &SourceRegistry, records: u64) -> Self {
        Self {
            records,
            commitment: registry.commitment(),
            anchor: registry.anchor(),
            inbox_count: registry.count(),
            inbox_root: registry.inbox_root(),
        }
    }
    /// Exact tagged, fixed-width little-endian transport, not authentication.
    pub fn encode(self) -> [u8; MARK_BYTES] {
        let mut bytes = Vec::with_capacity(MARK_BYTES);
        bytes.extend_from_slice(MARK_TAG);
        bytes.extend_from_slice(&self.records.to_le_bytes());
        bytes.extend_from_slice(self.commitment.as_slice());
        bytes.extend_from_slice(self.anchor.block.as_slice());
        for n in [self.anchor.slot, self.anchor.height, self.inbox_count] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        bytes.extend_from_slice(self.inbox_root.as_slice());
        bytes.try_into().expect("fixed mark layout")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != MARK_BYTES || !bytes.starts_with(MARK_TAG) {
            return Err(JournalError::Format);
        }
        let mut reader = Reader(&bytes[MARK_TAG.len()..]);
        Ok(Self {
            records: reader.u64()?,
            commitment: reader.hash()?,
            anchor: SourceAnchor {
                block: reader.hash()?,
                slot: reader.u64()?,
                height: reader.u64()?,
            },
            inbox_count: reader.u64()?,
            inbox_root: reader.hash()?,
        })
    }
}

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    Locked,
    Format,
    Limit,
    WrongGenesis,
    Mark,
    Verification(Error),
    Height,
    /// Write or fsync may have changed disk. Close and recover; never retry.
    CommitUncertain(io::Error),
    Poisoned,
    StorageChanged,
}
impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source journal rejected: {self:?}")
    }
}
impl std::error::Error for JournalError {}
impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Private registry becomes visible only after complete replay and exact mark
/// validation. Files live in an exclusively controlled directory; hostile
/// concurrent filesystem replacement is outside this process-lock model.
pub struct SourceJournal {
    registry: SourceRegistry,
    file: File,
    lock: File,
    mark: SourceMark,
    bytes: u64,
    limits: JournalLimits,
    poisoned: bool,
}
impl Drop for SourceJournal {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}
impl SourceJournal {
    /// Create an entirely new directory, never overwrite or repair an old one.
    pub fn create(
        path: impl AsRef<Path>,
        network: B256,
        domain: B256,
        genesis: HeightCursor,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        limits.validate()?;
        let registry = SourceRegistry::new(network, domain, genesis).map_err(JournalError::Verification)?;
        fs::DirBuilder::new().mode(0o700).create(path.as_ref())?;
        let path = fs::canonicalize(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("LOCK"))?;
        lock.try_lock().map_err(|_| JournalError::Locked)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("SOURCE"))?;
        file.write_all(FILE_TAG)?;
        file.write_all(registry.commitment().as_slice())?;
        file.sync_all()?;
        lock.sync_all()?;
        directory(&path)?.sync_all()?;
        directory(path.parent().ok_or(JournalError::Format)?)?.sync_all()?;
        let mark = SourceMark::of(&registry, 0);
        Ok(Self {
            registry,
            file,
            lock,
            mark,
            bytes: FILE_HEADER as u64,
            limits,
            poisoned: false,
        })
    }

    /// Replay privately from genesis; EXACT expected tip is required. Hash
    /// chaining to that trusted source tip authenticates prior source batches.
    /// Native positions are re-derived from headers, never decoded as authority.
    pub fn open(
        path: impl AsRef<Path>,
        network: B256,
        domain: B256,
        genesis: HeightCursor,
        expected: SourceMark,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        limits.validate()?;
        if expected.records > limits.records || expected.inbox_count > MAX_LOCKS as u64 {
            return Err(JournalError::Limit);
        }
        let path = path.as_ref();
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(JournalError::Format);
        }
        for name in ["LOCK", "SOURCE"] {
            if !fs::symlink_metadata(path.join(name))?.is_file() {
                return Err(JournalError::Format);
            }
        }
        let _directory = directory(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("LOCK"))?;
        if !lock.metadata()?.is_file() {
            return Err(JournalError::Format);
        }
        lock.try_lock().map_err(|_| JournalError::Locked)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("SOURCE"))?;
        if !file.metadata()?.is_file() {
            return Err(JournalError::Format);
        }
        let bytes = file.metadata()?.len();
        if bytes < FILE_HEADER as u64 {
            return Err(JournalError::Format);
        }
        if bytes > limits.bytes {
            return Err(JournalError::Limit);
        }
        let mut registry = SourceRegistry::new(network, domain, genesis).map_err(JournalError::Verification)?;
        let mut header = [0u8; FILE_HEADER];
        file.read_exact(&mut header)?;
        if &header[..8] != FILE_TAG || &header[8..] != registry.commitment().as_slice() {
            return Err(JournalError::WrongGenesis);
        }
        let mut read = FILE_HEADER as u64;
        let mut records = 0;
        while read < bytes {
            if records >= limits.records || records >= expected.records {
                return Err(JournalError::Mark);
            }
            if bytes - read < FRAME_OVERHEAD as u64 {
                return Err(JournalError::Format);
            }
            let mut prefix = [0u8; 12];
            file.read_exact(&mut prefix)?;
            if &prefix[..8] != FRAME_TAG {
                return Err(JournalError::Format);
            }
            let length = u32::from_le_bytes(prefix[8..].try_into().map_err(|_| JournalError::Format)?) as usize;
            if length > MAX_FRAME_BYTES {
                return Err(JournalError::Limit);
            }
            let frame_bytes = length as u64 + FRAME_OVERHEAD as u64;
            if frame_bytes > bytes - read {
                return Err(JournalError::Format);
            }
            let mut payload = vec![0; length];
            file.read_exact(&mut payload)?;
            let mut digest = [0; 32];
            file.read_exact(&mut digest)?;
            if frame_digest(&prefix, &payload) != B256::from(digest) {
                return Err(JournalError::Format);
            }
            let record = decode_payload(&payload)?;
            let mut identified = registry.cursor.clone();
            let position = identified
                .advance(
                    FinalizedCheckpoint {
                        block: record.batch.anchor.block,
                        slot: record.batch.anchor.slot,
                    },
                    &record.headers,
                )
                .map_err(|_| JournalError::Height)?;
            let commitment = record.batch.commitment().map_err(JournalError::Verification)?;
            registry
                .apply(commitment, position, &record.headers, &record.batch, &record.proofs)
                .map_err(JournalError::Verification)?;
            records += 1;
            read += frame_bytes;
        }
        if file.metadata()?.len() != bytes {
            return Err(JournalError::StorageChanged);
        }
        let mark = SourceMark::of(&registry, records);
        if mark != expected {
            return Err(JournalError::Mark);
        }
        // No provisional registry or partially replayed mark escapes above.
        Ok(Self {
            registry,
            file,
            lock,
            mark,
            bytes,
            limits,
            poisoned: false,
        })
    }

    pub fn registry(&self) -> Result<&SourceRegistry, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        Ok(&self.registry)
    }
    pub fn mark(&self) -> Result<SourceMark, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        Ok(self.mark)
    }
    /// The returned mark must be durably retained independently. Failure to
    /// retain it can leave a valid but unacknowledged suffix which open rejects.
    pub fn append(
        &mut self,
        expected: B256,
        position: HeightPosition,
        headers: &[Bytes],
        batch: &SourceBatch,
        proofs: &[InboxProof],
    ) -> Result<SourceMark, JournalError> {
        self.append_with(expected, position, headers, batch, proofs, |file, bytes| {
            file.write_all(bytes)?;
            file.sync_all()
        })
    }
    fn check_length(&mut self) -> Result<(), JournalError> {
        match self.file.metadata() {
            Ok(metadata) if metadata.len() == self.bytes => Ok(()),
            Ok(_) => {
                self.poisoned = true;
                Err(JournalError::StorageChanged)
            }
            Err(error) => {
                self.poisoned = true;
                Err(JournalError::CommitUncertain(error))
            }
        }
    }
    fn append_with(
        &mut self,
        expected: B256,
        position: HeightPosition,
        headers: &[Bytes],
        batch: &SourceBatch,
        proofs: &[InboxProof],
        publish: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    ) -> Result<SourceMark, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        self.check_length()?;
        if self.mark.records >= self.limits.records {
            return Err(JournalError::Limit);
        }
        let frame = encode_frame(headers, batch, proofs)?;
        let bytes = self.bytes.checked_add(frame.len() as u64).ok_or(JournalError::Limit)?;
        if bytes > self.limits.bytes {
            return Err(JournalError::Limit);
        }
        let mut registry = self.registry.clone();
        registry
            .apply(expected, position, headers, batch, proofs)
            .map_err(JournalError::Verification)?;
        let mark = SourceMark::of(&registry, self.mark.records + 1);
        self.check_length()?;
        self.poisoned = true;
        publish(&mut self.file, &frame).map_err(JournalError::CommitUncertain)?;
        self.registry = registry;
        self.mark = mark;
        self.bytes = bytes;
        self.poisoned = false;
        Ok(mark)
    }
}

fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn frame_digest(prefix: &[u8], payload: &[u8]) -> B256 {
    let mut bytes = Vec::with_capacity(prefix.len() + payload.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(payload);
    keccak256(bytes)
}
fn encode_frame(headers: &[Bytes], batch: &SourceBatch, proofs: &[InboxProof]) -> Result<Vec<u8>, JournalError> {
    if headers.len() > MAX_HEIGHT_HEADERS
        || headers.iter().any(|header| header.len() != 304)
        || proofs.len() > MAX_LOCKS
        || proofs.iter().any(|proof| proof.siblings.len() > MAX_PROOF_DEPTH)
    {
        return Err(JournalError::Limit);
    }
    let source = batch.encode().map_err(JournalError::Verification)?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&(source.len() as u32).to_le_bytes());
    payload.extend_from_slice(&source);
    payload.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for header in headers {
        payload.extend_from_slice(header);
    }
    payload.extend_from_slice(&(proofs.len() as u32).to_le_bytes());
    for proof in proofs {
        let deposit = &proof.deposit;
        payload.extend_from_slice(deposit.id.as_slice());
        payload.extend_from_slice(deposit.domain.as_slice());
        payload.extend_from_slice(deposit.recipient.as_slice());
        for n in [deposit.amount, deposit.sequence, proof.count] {
            payload.extend_from_slice(&n.to_le_bytes());
        }
        payload.push(proof.siblings.len() as u8);
        for sibling in &proof.siblings {
            payload.extend_from_slice(sibling.as_slice());
        }
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(JournalError::Limit);
    }
    let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    frame.extend_from_slice(FRAME_TAG);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let digest = frame_digest(&frame, &payload);
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(digest.as_slice());
    Ok(frame)
}
struct Record {
    batch: SourceBatch,
    headers: Vec<Bytes>,
    proofs: Vec<InboxProof>,
}
fn decode_payload(payload: &[u8]) -> Result<Record, JournalError> {
    let mut reader = Reader(payload);
    let length = reader.u32()? as usize;
    if length > MAX_SOURCE_BYTES {
        return Err(JournalError::Limit);
    }
    let batch = SourceBatch::decode(reader.bytes(length)?).map_err(JournalError::Verification)?;
    let count = reader.u32()? as usize;
    if count > MAX_HEIGHT_HEADERS {
        return Err(JournalError::Limit);
    }
    if count * 304 > reader.0.len() {
        return Err(JournalError::Format);
    }
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        headers.push(Bytes::copy_from_slice(reader.bytes(304)?));
    }
    let count = reader.u32()? as usize;
    if count > MAX_LOCKS {
        return Err(JournalError::Limit);
    }
    if count * PROOF_FIXED > reader.0.len() {
        return Err(JournalError::Format);
    }
    if count as u64 != batch.count || batch.locations.len() != count {
        return Err(JournalError::Verification(Error::Incomplete));
    }
    let mut proofs = Vec::with_capacity(count);
    for sequence in 0..count {
        let deposit = LockedDeposit {
            id: reader.hash()?,
            domain: reader.hash()?,
            recipient: Address::from(reader.take::<20>()?),
            amount: reader.u64()?,
            sequence: reader.u64()?,
        };
        let count = reader.u64()?;
        if count != batch.count || deposit.sequence != sequence as u64 {
            return Err(JournalError::Verification(Error::Incomplete));
        }
        let depth = reader.take::<1>()?[0] as usize;
        if count > MAX_LOCKS as u64 || depth > MAX_PROOF_DEPTH {
            return Err(JournalError::Limit);
        }
        if depth * 32 > reader.0.len() {
            return Err(JournalError::Format);
        }
        let mut siblings = Vec::with_capacity(depth);
        for _ in 0..depth {
            siblings.push(reader.hash()?);
        }
        proofs.push(InboxProof {
            deposit,
            count,
            siblings,
        });
    }
    if !reader.0.is_empty() {
        return Err(JournalError::Format);
    }
    Ok(Record { batch, headers, proofs })
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], JournalError> {
        let result = self.0.get(..n).ok_or(JournalError::Format)?;
        self.0 = &self.0[n..];
        Ok(result)
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        self.bytes(N)?.try_into().map_err(|_| JournalError::Format)
    }
    fn u32(&mut self) -> Result<u32, JournalError> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn hash(&mut self) -> Result<B256, JournalError> {
        Ok(B256::from(self.take::<32>()?))
    }
}

#[cfg(test)]
mod tests;
