// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable, fail-closed process lifecycle records for a future node host.
//!
//! This records local process state only. It does not authenticate genesis,
//! select a fork, establish L1 finality or repair storage.
use crate::BlochNodeHeader;
use alloy_primitives::{keccak256, B256};
use reth_primitives_traits::SealedHeader;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAGIC: &str = "bloch-l2-runtime-v1";
const RECEIPT_MAGIC: &[u8] = b"BLOCH-L2-RUNTIME-RECEIPTS-V1\n";
const RECEIPT_DOMAIN: &[u8] = b"bloch-l2-runtime-receipt-v1\0";
const MAX_RECEIPT_RECORD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableHead {
    pub number: u64,
    pub hash: B256,
    pub state_root: B256,
    pub receipts_root: B256,
    /// Last settlement input the host says it consumed. This is consistency
    /// metadata only; this journal does not authenticate the L1 block.
    pub settlement: SettlementCursor,
}

impl DurableHead {
    /// Capture all execution commitments from an already verified sealed header,
    /// plus the separately observed settlement cursor.
    pub fn from_header(header: &SealedHeader<BlochNodeHeader>, settlement: SettlementCursor) -> Self {
        Self {
            number: header.0.number,
            hash: header.hash(),
            state_root: header.0.state_root,
            receipts_root: header.0.receipts_root,
            settlement,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementCursor {
    pub l1_height: u64,
    pub l1_block_hash: B256,
    pub event_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub chain_id: u64,
    pub genesis_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeStatus {
    Clean,
    Running,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeRecord {
    pub generation: u64,
    pub identity: RuntimeIdentity,
    pub head: DurableHead,
    pub status: RuntimeStatus,
}

/// Externally retained minimum receipt. Supplying this value authenticates
/// nothing by itself; the caller is responsible for the floor's provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeReceiptFloor {
    pub sequence: u64,
    pub digest: B256,
}

/// Exclusive lifecycle lease. Dropping it without [`Self::shutdown`] deliberately
/// leaves both a `running` record and the lock file as crash evidence.
pub struct RuntimeLease {
    path: PathBuf,
    lock_path: PathBuf,
    record: RuntimeRecord,
    closed: bool,
}

impl RuntimeLease {
    /// Acquire the sole-writer lease and durably mark the process running.
    ///
    /// The existing record must be clean and must exactly match the independently
    /// checked storage head. First use requires [`initialize_runtime_record`].
    pub fn acquire(path: impl AsRef<Path>, identity: RuntimeIdentity, head: DurableHead) -> io::Result<Self> {
        Self::acquire_inner(path.as_ref(), identity, head, None)
    }

    /// Acquire only if the complete local chain contains the externally retained
    /// floor at its exact sequence. The floor's authenticity remains a host input.
    pub fn acquire_with_floor(
        path: impl AsRef<Path>,
        identity: RuntimeIdentity,
        head: DurableHead,
        floor: RuntimeReceiptFloor,
    ) -> io::Result<Self> {
        Self::acquire_inner(path.as_ref(), identity, head, Some(floor))
    }

    fn acquire_inner(
        path: &Path,
        identity: RuntimeIdentity,
        head: DurableHead,
        floor: Option<RuntimeReceiptFloor>,
    ) -> io::Result<Self> {
        let path = path.to_path_buf();
        let (existing, _) = read_runtime_record_inner(&path, floor)?;
        verify_identity_and_head(existing, identity, head)?;
        if existing.status != RuntimeStatus::Clean {
            return Err(invalid("unclean runtime record requires explicit recovery"));
        }
        let lock_path = sidecar(&path, "lock")?;
        let mut lock_options = OpenOptions::new();
        lock_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let mut lock = lock_options.open(&lock_path)?;
        lock.write_all(b"bloch-l2-runtime-exclusive\n")?;
        lock.sync_all()?;
        verify_regular_single_link(&lock_path)?;
        sync_parent(&path)?;
        let record = RuntimeRecord {
            generation: existing
                .generation
                .checked_add(1)
                .ok_or_else(|| invalid("runtime generation overflow"))?,
            identity,
            head,
            status: RuntimeStatus::Running,
        };
        // Retain the lock on every error: once publication begins, an fsync error
        // cannot prove whether the old or new record will survive a power loss.
        write_record(&path, record)?;
        Ok(Self {
            path,
            lock_path,
            record,
            closed: false,
        })
    }

    pub fn record(&self) -> RuntimeRecord {
        self.record
    }

    /// Record a head only after the database commit has completed successfully.
    /// Heights must increase by exactly one; reorgs require a separate, qualified
    /// recovery protocol rather than rewriting this local process journal.
    pub fn checkpoint(&mut self, head: DurableHead) -> io::Result<()> {
        if self.closed || self.record.status != RuntimeStatus::Running {
            return Err(invalid("runtime lease is not active"));
        }
        if head.number
            != self
                .record
                .head
                .number
                .checked_add(1)
                .ok_or_else(|| invalid("head overflow"))?
        {
            return Err(invalid("runtime checkpoint must extend exactly one height"));
        }
        if head.settlement.l1_height < self.record.head.settlement.l1_height
            || (head.settlement.l1_height == self.record.head.settlement.l1_height
                && (head.settlement.l1_block_hash != self.record.head.settlement.l1_block_hash
                    || head.settlement.event_index < self.record.head.settlement.event_index))
        {
            return Err(invalid("runtime settlement cursor regressed or conflicted"));
        }
        let updated = RuntimeRecord {
            generation: self
                .record
                .generation
                .checked_add(1)
                .ok_or_else(|| invalid("runtime generation overflow"))?,
            head,
            ..self.record
        };
        write_record(&self.path, updated)?;
        self.record = updated;
        Ok(())
    }

    /// Mark a verified durable head clean, then release the exclusive lock.
    pub fn shutdown(mut self, observed: DurableHead) -> io::Result<()> {
        if observed != self.record.head {
            return Err(invalid("shutdown head disagrees with runtime checkpoint"));
        }
        let clean = RuntimeRecord {
            generation: self
                .record
                .generation
                .checked_add(1)
                .ok_or_else(|| invalid("runtime generation overflow"))?,
            status: RuntimeStatus::Clean,
            ..self.record
        };
        write_record(&self.path, clean)?;
        verify_regular_single_link(&self.lock_path)?;
        fs::remove_file(&self.lock_path)?;
        sync_parent(&self.path)?;
        self.record = clean;
        self.closed = true;
        Ok(())
    }
}

/// Create the initial clean record. This does not validate the supplied domain;
/// callers must do so independently before crossing this local lifecycle boundary.
pub fn initialize_runtime_record(
    path: impl AsRef<Path>,
    identity: RuntimeIdentity,
    head: DurableHead,
) -> io::Result<()> {
    let path = path.as_ref();
    verify_parent(path)?;
    let record = RuntimeRecord {
        generation: 0,
        identity,
        head,
        status: RuntimeStatus::Clean,
    };
    let bytes = encode_record(record);
    initialize_receipts(path, record, bytes.as_bytes())?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // Never remove a partial initial file: its presence blocks a racing initializer
    // and its invalid checksum blocks startup until investigated.
    file.write_all(bytes.as_bytes())?;
    file.sync_all()?;
    sync_parent(path)
}

/// Clear crash evidence only after the host has stopped all possible writers and
/// independently verified the exact durable database identity and head.
///
/// A mismatch is intentionally not repaired. A crash after a database commit but
/// before [`RuntimeLease::checkpoint`] therefore requires separate storage replay.
pub fn acknowledge_recovered_runtime(
    path: impl AsRef<Path>,
    identity: RuntimeIdentity,
    observed: DurableHead,
) -> io::Result<()> {
    let path = path.as_ref();
    let record = read_runtime_record(path)?;
    verify_identity_and_head(record, identity, observed)?;
    let lock_path = sidecar(path, "lock")?;
    if !lock_path.exists() {
        return Err(invalid("runtime crash lock is missing"));
    }
    verify_regular_single_link(&lock_path)?;
    if record.status == RuntimeStatus::Running {
        write_record(
            path,
            RuntimeRecord {
                generation: record
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| invalid("runtime generation overflow"))?,
                status: RuntimeStatus::Clean,
                ..record
            },
        )?;
    }
    fs::remove_file(lock_path)?;
    sync_parent(path)
}

pub fn read_runtime_record(path: impl AsRef<Path>) -> io::Result<RuntimeRecord> {
    read_runtime_record_inner(path.as_ref(), None).map(|(record, _)| record)
}

/// Read the current record and require the append-only receipt chain to include
/// the caller's externally retained floor at its exact sequence.
pub fn read_runtime_record_with_floor(path: impl AsRef<Path>, floor: RuntimeReceiptFloor) -> io::Result<RuntimeRecord> {
    read_runtime_record_inner(path.as_ref(), Some(floor)).map(|(record, _)| record)
}

/// Verify the snapshot and full local receipt chain, returning its current tip.
pub fn runtime_receipt_tip(
    path: impl AsRef<Path>,
    floor: Option<RuntimeReceiptFloor>,
) -> io::Result<RuntimeReceiptFloor> {
    read_runtime_record_inner(path.as_ref(), floor).map(|(_, tip)| tip)
}

fn read_runtime_record_inner(
    path: &Path,
    floor: Option<RuntimeReceiptFloor>,
) -> io::Result<(RuntimeRecord, RuntimeReceiptFloor)> {
    verify_parent(path)?;
    verify_regular_single_link(path)?;
    let bytes = fs::read(path)?;
    let record = parse_record(&bytes)?;
    let tip = verify_receipts(path, record, &bytes, floor)?;
    Ok((record, tip))
}

fn verify_identity_and_head(record: RuntimeRecord, identity: RuntimeIdentity, head: DurableHead) -> io::Result<()> {
    if record.identity != identity {
        return Err(invalid("runtime identity disagrees with configured domain"));
    }
    if record.head != head {
        return Err(invalid("runtime head disagrees with durable storage"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn sidecar(path: &Path, suffix: &str) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("runtime record path has no file name"))?;
    let mut sidecar = name.to_os_string();
    sidecar.push(format!(".{suffix}"));
    Ok(path.with_file_name(sidecar))
}

fn encode_payload(record: RuntimeRecord) -> String {
    let status = match record.status {
        RuntimeStatus::Clean => "clean",
        RuntimeStatus::Running => "running",
    };
    format!(
        "{MAGIC}\ngeneration={}\nchain_id={}\ngenesis_hash={:#x}\nhead_number={}\nhead_hash={:#x}\nstate_root={:#x}\nreceipts_root={:#x}\nsettlement_height={}\nsettlement_block_hash={:#x}\nsettlement_event_index={}\nstatus={}\n",
        record.generation,
        record.identity.chain_id,
        record.identity.genesis_hash,
        record.head.number,
        record.head.hash,
        record.head.state_root,
        record.head.receipts_root,
        record.head.settlement.l1_height,
        record.head.settlement.l1_block_hash,
        record.head.settlement.event_index,
        status
    )
}

fn write_record(path: &Path, record: RuntimeRecord) -> io::Result<()> {
    verify_parent(path)?;
    verify_regular_single_link(path)?;
    let bytes = encode_record(record);
    let current = read_runtime_record(path)?;
    if current.generation.checked_add(1) != Some(record.generation) {
        return Err(invalid("runtime receipt sequence must advance exactly once"));
    }
    append_receipt(path, record, bytes.as_bytes())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock predates Unix epoch"))?
        .as_nanos();
    let temporary = sidecar(path, &format!("new.{}.{nonce}", std::process::id()))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn receipt_path(path: &Path) -> io::Result<PathBuf> {
    sidecar(path, "receipts")
}

fn receipt_frame(record: RuntimeRecord, previous: B256, bytes: &[u8]) -> io::Result<(Vec<u8>, B256)> {
    let length: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| invalid("runtime receipt record is too large"))?;
    if bytes.len() > MAX_RECEIPT_RECORD_BYTES {
        return Err(invalid("runtime receipt record is too large"));
    }
    let mut body = Vec::with_capacity(8 + 32 + 4 + bytes.len());
    body.extend_from_slice(&record.generation.to_be_bytes());
    body.extend_from_slice(previous.as_slice());
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(bytes);
    let mut committed = Vec::with_capacity(RECEIPT_DOMAIN.len() + body.len());
    committed.extend_from_slice(RECEIPT_DOMAIN);
    committed.extend_from_slice(&body);
    let digest = keccak256(committed);
    body.extend_from_slice(digest.as_slice());
    Ok((body, digest))
}

fn initialize_receipts(path: &Path, record: RuntimeRecord, bytes: &[u8]) -> io::Result<()> {
    let receipts = receipt_path(path)?;
    let (frame, _) = receipt_frame(record, B256::ZERO, bytes)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&receipts)?;
    file.write_all(RECEIPT_MAGIC)?;
    file.write_all(&frame)?;
    file.sync_all()?;
    verify_regular_single_link(&receipts)?;
    sync_parent(path)
}

fn append_receipt(path: &Path, record: RuntimeRecord, bytes: &[u8]) -> io::Result<()> {
    let receipts = receipt_path(path)?;
    verify_regular_single_link(&receipts)?;
    let tip = runtime_receipt_tip(path, None)?;
    if tip.sequence.checked_add(1) != Some(record.generation) {
        return Err(invalid("runtime receipt tip does not precede new record"));
    }
    let (frame, _) = receipt_frame(record, tip.digest, bytes)?;
    let mut file = OpenOptions::new().append(true).open(receipts)?;
    file.write_all(&frame)?;
    file.sync_all()
}

fn verify_receipts(
    path: &Path,
    expected: RuntimeRecord,
    expected_bytes: &[u8],
    floor: Option<RuntimeReceiptFloor>,
) -> io::Result<RuntimeReceiptFloor> {
    let receipts = receipt_path(path)?;
    verify_regular_single_link(&receipts)?;
    let mut file = File::open(receipts)?;
    let mut magic = vec![0; RECEIPT_MAGIC.len()];
    file.read_exact(&mut magic)?;
    if magic != RECEIPT_MAGIC {
        return Err(invalid("runtime receipt log version disagrees"));
    }
    let mut previous = B256::ZERO;
    let mut expected_sequence = 0u64;
    let mut tip = None;
    let mut floor_seen = floor.is_none();
    loop {
        let mut sequence_bytes = [0u8; 8];
        match file.read(&mut sequence_bytes[..1])? {
            0 => break,
            1 => file.read_exact(&mut sequence_bytes[1..])?,
            _ => unreachable!(),
        }
        let sequence = u64::from_be_bytes(sequence_bytes);
        let mut previous_bytes = [0u8; 32];
        file.read_exact(&mut previous_bytes)?;
        let mut length_bytes = [0u8; 4];
        file.read_exact(&mut length_bytes)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length > MAX_RECEIPT_RECORD_BYTES {
            return Err(invalid("runtime receipt record is too large"));
        }
        let mut record_bytes = vec![0; length];
        file.read_exact(&mut record_bytes)?;
        let mut digest_bytes = [0u8; 32];
        file.read_exact(&mut digest_bytes)?;
        let digest = B256::from(digest_bytes);
        let linked_previous = B256::from(previous_bytes);
        if sequence != expected_sequence || linked_previous != previous {
            return Err(invalid("runtime receipt chain has a gap, reorder or fork"));
        }
        let record = parse_record(&record_bytes)?;
        if record.generation != sequence {
            return Err(invalid("runtime receipt sequence disagrees with exact record"));
        }
        if encode_record(record).as_bytes() != record_bytes {
            return Err(invalid("runtime receipt record encoding is not canonical"));
        }
        let (_, computed) = receipt_frame(record, linked_previous, &record_bytes)?;
        if computed != digest {
            return Err(invalid("runtime receipt digest disagrees"));
        }
        if let Some(required) = floor {
            if sequence == required.sequence {
                if digest != required.digest {
                    return Err(invalid("runtime receipt floor digest disagrees"));
                }
                floor_seen = true;
            }
        }
        tip = Some((RuntimeReceiptFloor { sequence, digest }, record, record_bytes));
        previous = digest;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("runtime receipt sequence overflow"))?;
    }
    let (tip, record, record_bytes) = tip.ok_or_else(|| invalid("runtime receipt log is empty"))?;
    if !floor_seen {
        return Err(invalid("runtime receipt chain is below external floor"));
    }
    if record != expected || record_bytes != expected_bytes {
        return Err(invalid("runtime snapshot disagrees with receipt tip"));
    }
    Ok(tip)
}

fn encode_record(record: RuntimeRecord) -> String {
    let payload = encode_payload(record);
    let checksum = keccak256(payload.as_bytes());
    format!("{payload}checksum={checksum:#x}\n")
}

fn verify_parent(path: &Path) -> io::Result<()> {
    let parent = parent_dir(path)?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid("runtime record parent must be a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime record parent must not be group/world writable",
            ));
        }
    }
    Ok(())
}

fn verify_regular_single_link(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("runtime record must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid("runtime record must have exactly one hard link"));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime record permissions must not grant group/world access",
            ));
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = parent_dir(path)?;
    File::open(parent)?.sync_all()
}

fn parent_dir(path: &Path) -> io::Result<&Path> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("runtime record path has no parent"))?;
    if parent.as_os_str().is_empty() {
        Ok(Path::new("."))
    } else {
        Ok(parent)
    }
}

fn parse_record(bytes: &[u8]) -> io::Result<RuntimeRecord> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("runtime record is not UTF-8"))?;
    let (payload, checksum_line) = text
        .rsplit_once("checksum=")
        .ok_or_else(|| invalid("runtime record checksum is missing"))?;
    let checksum_text = checksum_line
        .strip_suffix('\n')
        .ok_or_else(|| invalid("runtime record is not newline terminated"))?;
    let expected: B256 = checksum_text
        .parse()
        .map_err(|_| invalid("runtime record checksum is malformed"))?;
    if keccak256(payload.as_bytes()) != expected {
        return Err(invalid("runtime record checksum disagrees"));
    }
    let mut lines = payload.lines();
    if lines.next() != Some(MAGIC) {
        return Err(invalid("runtime record version disagrees"));
    }
    let generation = field(&mut lines, "generation=")?
        .parse()
        .map_err(|_| invalid("runtime generation is malformed"))?;
    let chain_id = field(&mut lines, "chain_id=")?
        .parse()
        .map_err(|_| invalid("runtime chain ID is malformed"))?;
    let genesis_hash = field(&mut lines, "genesis_hash=")?
        .parse()
        .map_err(|_| invalid("runtime genesis hash is malformed"))?;
    let number = field(&mut lines, "head_number=")?
        .parse()
        .map_err(|_| invalid("runtime head number is malformed"))?;
    let hash = field(&mut lines, "head_hash=")?
        .parse()
        .map_err(|_| invalid("runtime head hash is malformed"))?;
    let state_root = field(&mut lines, "state_root=")?
        .parse()
        .map_err(|_| invalid("runtime state root is malformed"))?;
    let receipts_root = field(&mut lines, "receipts_root=")?
        .parse()
        .map_err(|_| invalid("runtime receipts root is malformed"))?;
    let l1_height = field(&mut lines, "settlement_height=")?
        .parse()
        .map_err(|_| invalid("runtime settlement height is malformed"))?;
    let l1_block_hash = field(&mut lines, "settlement_block_hash=")?
        .parse()
        .map_err(|_| invalid("runtime settlement block hash is malformed"))?;
    let event_index = field(&mut lines, "settlement_event_index=")?
        .parse()
        .map_err(|_| invalid("runtime settlement event index is malformed"))?;
    let status = match field(&mut lines, "status=")? {
        "clean" => RuntimeStatus::Clean,
        "running" => RuntimeStatus::Running,
        _ => return Err(invalid("runtime status is malformed")),
    };
    if lines.next().is_some() {
        return Err(invalid("runtime record has unexpected fields"));
    }
    Ok(RuntimeRecord {
        generation,
        identity: RuntimeIdentity { chain_id, genesis_hash },
        head: DurableHead {
            number,
            hash,
            state_root,
            receipts_root,
            settlement: SettlementCursor {
                l1_height,
                l1_block_hash,
                event_index,
            },
        },
        status,
    })
}

fn field<'a>(lines: &mut impl Iterator<Item = &'a str>, prefix: &str) -> io::Result<&'a str> {
    lines
        .next()
        .and_then(|line| line.strip_prefix(prefix))
        .ok_or_else(|| invalid("runtime record field is missing or out of order"))
}
