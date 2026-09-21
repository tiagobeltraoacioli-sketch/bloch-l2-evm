// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable source-bound Groth16 settlement V2 coordination.
//!
//! This journal is deliberately distinct from the legacy Core-proof journal.
//! It persists local selection only; it does not establish native finality,
//! authorize a bridge release or enable DEX liquidity.
use crate::{
    invalid,
    settlement::{SettlementCursor, SettlementMark, MAX_JOURNAL_BYTES, MAX_JOURNAL_RECORDS},
    source_settlement::{
        expected_groth16_source_statement, prepare_groth16_source_advance, CheckedGroth16SettlementV2,
        SourceSettlementV2Mark, SourceSettlementV2State,
    },
    verification::{
        decode_groth16_settlement_v2_proof, ProgramIdentity, QualifiedGroth16SettlementV2, TrustedProgram,
        MAX_GROTH16_ARTIFACT_BYTES,
    },
    Result,
};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::{Decodable, Encodable};
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    node_primitives::{NodeBodyV2, NodeHeaderV2, MAX_NODE_BODY_BYTES},
    proof_statement::configuration_commitment,
    ChainSpec,
};
use bloch_native_domain_devnet::{
    journal::{SourceJournal, SourceMark, MARK_BYTES},
    SettlementPayloadV2, SourceRegistry, SETTLEMENT_PAYLOAD_V2_BYTES,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const TAG: &[u8] = b"BLOCH:LOCAL:SP1:SOURCE:SETTLEMENT:2";
const MARK_TAG: &[u8] = b"BLOCH:LOCAL:SP1:SOURCE:SETTLEMENT:MARK:2";
const MAX_HEADER_BYTES: usize = 2_048;
const RECORD_OVERHEAD: u64 = 36;
const MAX_FRAME_BYTES: usize =
    MARK_BYTES + 8 + MAX_HEADER_BYTES + MAX_NODE_BODY_BYTES + MAX_GROTH16_ARTIFACT_BYTES;
pub const SOURCE_SETTLEMENT_V2_FLOOR_BYTES: usize = MARK_TAG.len() + 80 + MARK_BYTES + 1 + 32;

/// Immutable, independently selected policy for one V2 journal.
#[derive(Clone)]
pub struct SourceSettlementPolicyV2 {
    spec: ChainSpec,
    network: B256,
    native_genesis: B256,
    domain: B256,
    program: ProgramIdentity,
    genesis: NodeHeaderV2,
    proof_policy: B256,
}

impl SourceSettlementPolicyV2 {
    pub fn new(
        spec: ChainSpec,
        network: B256,
        native_genesis: B256,
        domain: B256,
        program: ProgramIdentity,
        genesis: NodeHeaderV2,
        proof_policy: B256,
    ) -> Result<Self> {
        if network == B256::ZERO
            || native_genesis == B256::ZERO
            || domain == B256::ZERO
            || proof_policy == B256::ZERO
        {
            return Err(invalid("zero V2 source settlement policy identity"));
        }
        let mut state = genesis_v2(&spec, genesis.timestamp)?;
        state.commit_root();
        if genesis != node_head(&spec, domain, &state)? {
            return Err(invalid("V2 source journal requires canonical zero-funded genesis"));
        }
        Ok(Self {
            spec,
            network,
            native_genesis,
            domain,
            program,
            genesis,
            proof_policy,
        })
    }

    fn cursor(&self) -> Result<SettlementCursor> {
        SettlementCursor::from_trusted_anchor(
            self.spec.clone(),
            self.domain,
            self.program,
            self.genesis.clone(),
        )
    }

    fn check_source(&self, source: &SourceRegistry) -> Result<()> {
        if source.network() != self.network
            || source.genesis() != self.native_genesis
            || source.domain() != self.domain
        {
            return Err(invalid("V2 source journal policy identity mismatch"));
        }
        Ok(())
    }

    fn prefix(&self) -> Result<Vec<u8>> {
        let header = alloy_rlp::encode(&self.genesis);
        if header.is_empty() || header.len() > MAX_HEADER_BYTES {
            return Err(invalid("V2 source journal genesis header bound"));
        }
        let mut bytes = TAG.to_vec();
        for hash in [
            configuration_commitment(&self.spec)?,
            self.network,
            self.native_genesis,
            self.domain,
            self.program.elf_keccak(),
            self.program.verifying_key_hash(),
            self.program.verifying_key_bn254(),
            self.proof_policy,
        ] {
            bytes.extend_from_slice(hash.as_slice());
        }
        bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&header);
        Ok(bytes)
    }
}

/// Independently retained rollback floor. Decoding is transport only; `open`
/// must encounter the complete value while deriving trusted state from genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementJournalV2Floor {
    execution: SettlementMark,
    next_sequence: u64,
    last_source: SourceMark,
    settlement: Option<B256>,
}

impl SourceSettlementJournalV2Floor {
    pub fn execution(&self) -> SettlementMark {
        self.execution
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn last_source(&self) -> SourceMark {
        self.last_source
    }
    pub fn settlement(&self) -> Option<B256> {
        self.settlement
    }
    pub fn encode(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(SOURCE_SETTLEMENT_V2_FLOOR_BYTES);
        bytes.extend_from_slice(MARK_TAG);
        bytes.extend_from_slice(&self.execution.number.to_be_bytes());
        bytes.extend_from_slice(self.execution.header_hash.as_slice());
        bytes.extend_from_slice(self.execution.state_root.as_slice());
        bytes.extend_from_slice(&self.next_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.last_source.encode());
        match self.settlement {
            None => {
                bytes.push(0);
                bytes.extend_from_slice(B256::ZERO.as_slice());
            }
            Some(commitment) => {
                bytes.push(1);
                bytes.extend_from_slice(commitment.as_slice());
            }
        }
        debug_assert_eq!(bytes.len(), SOURCE_SETTLEMENT_V2_FLOOR_BYTES);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SOURCE_SETTLEMENT_V2_FLOOR_BYTES || !bytes.starts_with(MARK_TAG) {
            return Err(invalid("invalid V2 source settlement floor encoding"));
        }
        let fields = &bytes[MARK_TAG.len()..];
        let execution = SettlementMark {
            number: u64::from_be_bytes(fields[..8].try_into()?),
            header_hash: B256::from_slice(&fields[8..40]),
            state_root: B256::from_slice(&fields[40..72]),
        };
        let next_sequence = u64::from_be_bytes(fields[72..80].try_into()?);
        let last_source = SourceMark::decode(&fields[80..80 + MARK_BYTES])?;
        let option = 80 + MARK_BYTES;
        let commitment = B256::from_slice(&fields[option + 1..option + 33]);
        let settlement = match fields[option] {
            0 if commitment == B256::ZERO && execution.number == 0 && next_sequence == 0 => None,
            1 if commitment != B256::ZERO => Some(commitment),
            _ => return Err(invalid("invalid V2 settlement floor option")),
        };
        Ok(Self {
            execution,
            next_sequence,
            last_source,
            settlement,
        })
    }

    fn validate(self) -> Result<()> {
        match self.settlement {
            None if self.execution.number == 0 && self.next_sequence == 0 => Ok(()),
            Some(commitment) if commitment != B256::ZERO => Ok(()),
            _ => Err(invalid("invalid V2 settlement floor state")),
        }
    }
}

pub struct SourceSettlementJournalV2 {
    file: File,
    policy: SourceSettlementPolicyV2,
    cursor: SettlementCursor,
    next_sequence: u64,
    last_source: SourceMark,
    last_payload: Option<SettlementPayloadV2>,
    expected_len: u64,
    records: usize,
    poisoned: bool,
}

impl Drop for SourceSettlementJournalV2 {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl SourceSettlementJournalV2 {
    pub fn create(
        path: impl AsRef<Path>,
        policy: SourceSettlementPolicyV2,
        source: &mut SourceJournal,
    ) -> Result<Self> {
        let initial = source.mark()?;
        policy.check_source(&source.snapshot_at(initial)?)?;
        let cursor = policy.cursor()?;
        let mut file = create_private_regular(path.as_ref())?;
        file.try_lock()?;
        let mut bytes = policy.prefix()?;
        bytes.extend_from_slice(&initial.encode());
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_parent(path.as_ref())?;
        Ok(Self {
            file,
            policy,
            cursor,
            next_sequence: 0,
            last_source: initial,
            last_payload: None,
            expected_len: bytes.len() as u64,
            records: 0,
            poisoned: false,
        })
    }

    pub fn open(
        path: impl AsRef<Path>,
        policy: SourceSettlementPolicyV2,
        program: &TrustedProgram,
        source: &mut SourceJournal,
        floor: SourceSettlementJournalV2Floor,
    ) -> Result<Self> {
        if program.identity() != policy.program {
            return Err(invalid("V2 source journal verifier/program mismatch"));
        }
        policy.check_source(source.registry()?)?;
        let mut file = crate::open_regular(path.as_ref(), true)?;
        require_private_mode(&file)?;
        file.try_lock()?;
        let expected_len = file.metadata()?.len();
        if expected_len > MAX_JOURNAL_BYTES {
            return Err(invalid("V2 source settlement cumulative byte limit"));
        }
        let prefix = policy.prefix()?;
        let initial_len = prefix
            .len()
            .checked_add(MARK_BYTES)
            .ok_or_else(|| invalid("V2 source settlement prefix overflow"))?;
        if expected_len < initial_len as u64 {
            return Err(invalid("truncated V2 source settlement manifest"));
        }
        let mut stored = vec![0; prefix.len()];
        file.read_exact(&mut stored)?;
        if stored != prefix {
            return Err(invalid("V2 source settlement policy/genesis mismatch"));
        }
        let mut initial = [0u8; MARK_BYTES];
        file.read_exact(&mut initial)?;
        let initial = SourceMark::decode(&initial)?;
        policy.check_source(&source.snapshot_at(initial)?)?;

        let mut cursor = policy.cursor()?;
        let mut next_sequence = 0;
        let mut last_source = initial;
        let mut last_payload: Option<SettlementPayloadV2> = None;
        let mut current_floor = floor_of(&cursor, next_sequence, last_source, last_payload.as_ref())?;
        let mut floor_seen = current_floor == floor;
        let mut records = 0usize;
        let mut consumed = initial_len as u64;

        while consumed < expected_len {
            if records >= MAX_JOURNAL_RECORDS || expected_len - consumed < RECORD_OVERHEAD {
                return Err(invalid("V2 source settlement record bounds"));
            }
            let mut length = [0u8; 4];
            file.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            if !(MARK_BYTES + 8 + 4..=MAX_FRAME_BYTES).contains(&length)
                || (length as u64)
                    .checked_add(RECORD_OVERHEAD)
                    .is_none_or(|record| record > expected_len - consumed)
            {
                return Err(invalid("V2 source settlement frame bounds"));
            }
            let mut frame_bytes = vec![0u8; length];
            file.read_exact(&mut frame_bytes)?;
            let mut checksum = [0u8; 32];
            file.read_exact(&mut checksum)?;
            if keccak256(&frame_bytes) != B256::from(checksum) {
                return Err(invalid("V2 source settlement checksum mismatch"));
            }
            let frame = decode_frame(&frame_bytes)?;
            source_order(last_source, frame.source)?;
            // Authenticate both the prior exact snapshot and the candidate
            // snapshot through the independently opened source history.
            policy.check_source(&source.snapshot_at(last_source)?)?;
            let snapshot = source.snapshot_at(frame.source)?;
            policy.check_source(&snapshot)?;
            let state = SourceSettlementV2State::new(
                &policy.spec,
                &cursor,
                next_sequence,
                last_payload.as_ref(),
                &snapshot,
            )?;
            let expected = expected_groth16_source_statement(state, &frame.header, &frame.body)?;
            let verified = program.verify_groth16_settlement_v2(
                decode_groth16_settlement_v2_proof(frame.proof)?,
                &expected,
            )?;
            let checked = CheckedGroth16SettlementV2::from_capability(&verified)?;
            let (candidate, mark) =
                prepare_groth16_source_advance(state, &checked, &frame.header, &frame.body)?;
            check_payload_policy(&policy, &mark)?;
            cursor = candidate;
            next_sequence = mark.next_sequence();
            last_source = frame.source;
            last_payload = Some(mark.payload());
            current_floor = floor_of(&cursor, next_sequence, last_source, last_payload.as_ref())?;
            floor_seen |= current_floor == floor;
            records += 1;
            consumed = consumed
                .checked_add(length as u64 + RECORD_OVERHEAD)
                .ok_or_else(|| invalid("V2 source settlement byte overflow"))?;
        }
        if consumed != expected_len || file.metadata()?.len() != expected_len {
            return Err(invalid("V2 source settlement length changed during replay"));
        }
        if !floor_seen {
            return Err(invalid("complete retained V2 source settlement floor not found"));
        }
        Ok(Self {
            file,
            policy,
            cursor,
            next_sequence,
            last_source,
            last_payload,
            expected_len,
            records,
            poisoned: false,
        })
    }

    pub fn floor(&mut self) -> Result<SourceSettlementJournalV2Floor> {
        self.check_live()?;
        floor_of(
            &self.cursor,
            self.next_sequence,
            self.last_source,
            self.last_payload.as_ref(),
        )
    }
    pub fn cursor(&mut self) -> Result<&SettlementCursor> {
        self.check_live()?;
        Ok(&self.cursor)
    }
    pub fn last_payload(&mut self) -> Result<Option<SettlementPayloadV2>> {
        self.check_live()?;
        Ok(self.last_payload)
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn append(
        &mut self,
        source: &mut SourceJournal,
        proof: &QualifiedGroth16SettlementV2,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementJournalV2Floor> {
        self.ensure_healthy()?;
        self.check_length()?;
        if self.records >= MAX_JOURNAL_RECORDS {
            return Err(invalid("V2 source settlement record limit"));
        }
        self.policy.check_source(source.registry()?)?;
        let current = source.mark()?;
        source_order(self.last_source, current)?;
        self.policy.check_source(&source.snapshot_at(self.last_source)?)?;
        let snapshot = source.snapshot_at(current)?;
        self.policy.check_source(&snapshot)?;
        let checked = CheckedGroth16SettlementV2::from_capability(proof)?;
        let state = SourceSettlementV2State::new(
            &self.policy.spec,
            &self.cursor,
            self.next_sequence,
            self.last_payload.as_ref(),
            &snapshot,
        )?;
        let (cursor, mark) = prepare_groth16_source_advance(state, &checked, header, body)?;
        check_payload_policy(&self.policy, &mark)?;
        let frame = encode_frame(current, header, body, proof)?;
        let next_len = self
            .expected_len
            .checked_add(RECORD_OVERHEAD)
            .and_then(|length| length.checked_add(frame.len() as u64))
            .ok_or_else(|| invalid("V2 source settlement byte overflow"))?;
        if next_len > MAX_JOURNAL_BYTES {
            return Err(invalid("V2 source settlement cumulative byte limit"));
        }
        let next_floor = SourceSettlementJournalV2Floor {
            execution: mark.execution(),
            next_sequence: mark.next_sequence(),
            last_source: current,
            settlement: Some(mark.settlement_commitment()),
        };
        self.check_length()?;
        self.poisoned = true;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.file.write_all(&frame)?;
        self.file.write_all(keccak256(&frame).as_slice())?;
        self.file.sync_all()?;
        self.cursor = cursor;
        self.next_sequence = mark.next_sequence();
        self.last_source = current;
        self.last_payload = Some(mark.payload());
        self.expected_len = next_len;
        self.records += 1;
        self.poisoned = false;
        Ok(next_floor)
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(invalid("V2 source settlement journal is poisoned"));
        }
        Ok(())
    }
    fn check_live(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        self.check_length()
    }
    fn check_length(&mut self) -> Result<()> {
        match self.file.metadata() {
            Ok(metadata) if metadata.len() == self.expected_len => Ok(()),
            Ok(_) => {
                self.poisoned = true;
                Err(invalid("V2 source settlement journal length changed"))
            }
            Err(error) => {
                self.poisoned = true;
                Err(error.into())
            }
        }
    }
}

fn payload_commitment(payload: Option<&SettlementPayloadV2>) -> Result<Option<B256>> {
    match payload.map(SettlementPayloadV2::commitment).transpose()? {
        Some(commitment) if commitment == B256::ZERO => Err(invalid("zero V2 settlement payload commitment")),
        commitment => Ok(commitment),
    }
}

fn floor_of(
    cursor: &SettlementCursor,
    next_sequence: u64,
    last_source: SourceMark,
    last_payload: Option<&SettlementPayloadV2>,
) -> Result<SourceSettlementJournalV2Floor> {
    let floor = SourceSettlementJournalV2Floor {
        execution: cursor.mark(),
        next_sequence,
        last_source,
        settlement: payload_commitment(last_payload)?,
    };
    floor.validate()?;
    Ok(floor)
}

fn check_payload_policy(policy: &SourceSettlementPolicyV2, mark: &SourceSettlementV2Mark) -> Result<()> {
    let payload = mark.payload();
    if payload.proof_policy != policy.proof_policy {
        return Err(invalid("V2 settlement proof policy differs from journal policy"));
    }
    let encoded = payload.encode()?;
    if encoded.len() != SETTLEMENT_PAYLOAD_V2_BYTES || SettlementPayloadV2::decode(&encoded)? != payload {
        return Err(invalid("V2 settlement payload is not canonical"));
    }
    if payload.commitment()? != mark.settlement_commitment() {
        return Err(invalid("V2 settlement payload commitment mismatch"));
    }
    Ok(())
}

fn source_order(previous: SourceMark, next: SourceMark) -> Result<()> {
    if next.records < previous.records || (next.records == previous.records && next != previous) {
        return Err(invalid("V2 source settlement historical rollback/conflict"));
    }
    Ok(())
}

fn encode_frame(
    source: SourceMark,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
    proof: &QualifiedGroth16SettlementV2,
) -> Result<Vec<u8>> {
    let header_length = header.length();
    let body_length = body.length();
    if header_length == 0
        || header_length > MAX_HEADER_BYTES
        || body_length == 0
        || body_length > MAX_NODE_BODY_BYTES
    {
        return Err(invalid("V2 source settlement header/body size limit"));
    }
    let artifact = proof.artifact_bytes()?;
    if artifact.len() < 4 || artifact.len() > MAX_GROTH16_ARTIFACT_BYTES {
        return Err(invalid("V2 Groth16 artifact size limit"));
    }
    let capacity = MARK_BYTES
        .checked_add(8)
        .and_then(|n| n.checked_add(header_length))
        .and_then(|n| n.checked_add(body_length))
        .and_then(|n| n.checked_add(artifact.len()))
        .ok_or_else(|| invalid("V2 source settlement frame overflow"))?;
    if capacity > MAX_FRAME_BYTES {
        return Err(invalid("V2 source settlement frame size limit"));
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&source.encode());
    bytes.extend_from_slice(&(header_length as u32).to_be_bytes());
    bytes.extend_from_slice(&(body_length as u32).to_be_bytes());
    header.encode(&mut bytes);
    body.encode(&mut bytes);
    bytes.extend_from_slice(&artifact);
    Ok(bytes)
}

struct Frame<'a> {
    source: SourceMark,
    header: NodeHeaderV2,
    body: NodeBodyV2,
    proof: &'a [u8],
}

fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>> {
    if bytes.len() < MARK_BYTES + 8 + 4 || bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid("V2 source settlement frame truncated or oversized"));
    }
    let source = SourceMark::decode(&bytes[..MARK_BYTES])?;
    let header_len = u32::from_be_bytes(bytes[MARK_BYTES..MARK_BYTES + 4].try_into()?) as usize;
    let body_len = u32::from_be_bytes(bytes[MARK_BYTES + 4..MARK_BYTES + 8].try_into()?) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES || body_len == 0 || body_len > MAX_NODE_BODY_BYTES {
        return Err(invalid("V2 source settlement header/body length invalid"));
    }
    let offset = MARK_BYTES + 8;
    let body_start = offset
        .checked_add(header_len)
        .ok_or_else(|| invalid("V2 source settlement frame length overflow"))?;
    let proof_start = body_start
        .checked_add(body_len)
        .ok_or_else(|| invalid("V2 source settlement frame length overflow"))?;
    let proof_len = bytes
        .len()
        .checked_sub(proof_start)
        .ok_or_else(|| invalid("V2 source settlement frame truncated"))?;
    if !(4..=MAX_GROTH16_ARTIFACT_BYTES).contains(&proof_len) {
        return Err(invalid("V2 Groth16 artifact length invalid"));
    }
    let mut header_bytes = &bytes[offset..body_start];
    let header = NodeHeaderV2::decode(&mut header_bytes)?;
    let mut body_bytes = &bytes[body_start..proof_start];
    let body = NodeBodyV2::decode(&mut body_bytes)?;
    if !header_bytes.is_empty() || !body_bytes.is_empty() {
        return Err(invalid("V2 source settlement trailing header/body bytes"));
    }
    Ok(Frame {
        source,
        header,
        body,
        proof: &bytes[proof_start..],
    })
}

fn create_private_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("V2 source settlement path is not a regular file"));
    }
    require_private_mode(&file)?;
    Ok(file)
}

fn require_private_mode(file: &File) -> Result<()> {
    if file.metadata()?.mode() & 0o777 != 0o600 {
        return Err(invalid("V2 source settlement journal must have mode 0600"));
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_l2_evm::l1::height::HeightCursor;
    use bloch_native_domain_devnet::{journal::JournalLimits, SourceAnchor};
    use sha3::{Digest, Sha3_256};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bloch-source-settlement-v2-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn native_cursor() -> HeightCursor {
        let mut header = vec![0u8; 304];
        header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
        header[100..108].copy_from_slice(&100u64.to_le_bytes());
        let mut hash = Sha3_256::new();
        hash.update(b"BLCH4:BLOCK\0\0\0\0\0");
        hash.update(&header);
        HeightCursor::from_genesis(B256::from_slice(&hash.finalize()), &header).unwrap()
    }

    fn create_source(path: &Path) -> SourceJournal {
        SourceJournal::create(
            path,
            B256::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            native_cursor(),
            JournalLimits::default(),
        )
        .unwrap()
    }

    fn policy(source: &SourceJournal) -> SourceSettlementPolicyV2 {
        let spec = ChainSpec::testnet();
        let domain = source.registry().unwrap().domain();
        let mut state = genesis_v2(&spec, 100).unwrap();
        state.commit_root();
        let genesis = node_head(&spec, domain, &state).unwrap();
        SourceSettlementPolicyV2::new(
            spec,
            source.registry().unwrap().network(),
            source.registry().unwrap().genesis(),
            domain,
            ProgramIdentity::test_fixture(0x31),
            genesis,
            B256::repeat_byte(0x41),
        )
        .unwrap()
    }

    fn source_mark() -> SourceMark {
        SourceMark {
            records: 7,
            commitment: B256::repeat_byte(1),
            anchor: SourceAnchor {
                block: B256::repeat_byte(2),
                slot: 3,
                height: 4,
            },
            inbox_count: 5,
            inbox_root: B256::repeat_byte(6),
        }
    }

    fn floor(settlement: Option<B256>) -> SourceSettlementJournalV2Floor {
        SourceSettlementJournalV2Floor {
            execution: SettlementMark {
                number: u64::from(settlement.is_some()),
                header_hash: B256::repeat_byte(7),
                state_root: B256::repeat_byte(8),
            },
            next_sequence: u64::from(settlement.is_some()),
            last_source: source_mark(),
            settlement,
        }
    }

    // Framing fixture only. The four zero bytes are not a valid Groth16
    // artifact and never cross the verifier boundary.
    fn transport_frame() -> Vec<u8> {
        let header = alloy_rlp::encode(NodeHeaderV2::default());
        let body = alloy_rlp::encode(NodeBodyV2::default());
        let mut bytes = source_mark().encode().to_vec();
        bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }

    #[test]
    fn floor_codec_is_exact_and_option_is_canonical() {
        for value in [floor(None), floor(Some(B256::repeat_byte(9)))] {
            let encoded = value.encode().unwrap();
            assert_eq!(encoded.len(), SOURCE_SETTLEMENT_V2_FLOOR_BYTES);
            assert_eq!(SourceSettlementJournalV2Floor::decode(&encoded).unwrap(), value);
            for cut in 0..encoded.len() {
                assert!(SourceSettlementJournalV2Floor::decode(&encoded[..cut]).is_err());
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert!(SourceSettlementJournalV2Floor::decode(&trailing).is_err());
        }

        let mut bad = floor(None).encode().unwrap();
        let option = MARK_TAG.len() + 80 + MARK_BYTES;
        bad[option] = 2;
        assert!(SourceSettlementJournalV2Floor::decode(&bad).is_err());
        let mut bad = floor(None).encode().unwrap();
        bad[option + 1] = 1;
        assert!(SourceSettlementJournalV2Floor::decode(&bad).is_err());
        let mut bad = floor(Some(B256::repeat_byte(9))).encode().unwrap();
        bad[option + 1..option + 33].fill(0);
        assert!(SourceSettlementJournalV2Floor::decode(&bad).is_err());
        assert!(floor(Some(B256::ZERO)).encode().is_err());
    }

    #[test]
    fn source_order_rejects_rollback_and_same_height_conflict() {
        let previous = source_mark();
        let mut rollback = previous;
        rollback.records -= 1;
        assert!(source_order(previous, rollback).is_err());
        let mut conflict = previous;
        conflict.commitment = B256::repeat_byte(99);
        assert!(source_order(previous, conflict).is_err());
        assert!(source_order(previous, previous).is_ok());
    }

    #[test]
    fn frame_decoder_enforces_every_boundary_before_proof_verification() {
        let bytes = transport_frame();
        assert!(decode_frame(&bytes).is_ok());
        for cut in 0..bytes.len() {
            assert!(decode_frame(&bytes[..cut]).is_err(), "prefix {cut}");
        }

        let mut zero_header = bytes.clone();
        zero_header[MARK_BYTES..MARK_BYTES + 4].fill(0);
        assert!(decode_frame(&zero_header).is_err());
        let mut huge_body = bytes.clone();
        huge_body[MARK_BYTES + 4..MARK_BYTES + 8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_frame(&huge_body).is_err());

        let header_len = u32::from_be_bytes(bytes[MARK_BYTES..MARK_BYTES + 4].try_into().unwrap()) as usize;
        let mut trailing_header = bytes;
        trailing_header.insert(MARK_BYTES + 8 + header_len, 0);
        trailing_header[MARK_BYTES..MARK_BYTES + 4]
            .copy_from_slice(&((header_len + 1) as u32).to_be_bytes());
        assert!(decode_frame(&trailing_header).is_err());
    }

    #[test]
    fn create_is_private_locked_and_external_length_change_poisons_getters() {
        let temp = Temp::new();
        let mut source = create_source(&temp.0.join("source"));
        let journal_path = temp.0.join("settlement-v2");
        let policy = policy(&source);
        let mut journal = SourceSettlementJournalV2::create(&journal_path, policy.clone(), &mut source).unwrap();
        let floor = journal.floor().unwrap();
        assert_eq!(floor.execution().number, 0);
        assert_eq!(floor.next_sequence(), 0);
        assert_eq!(floor.settlement(), None);
        assert_eq!(fs::metadata(&journal_path).unwrap().mode() & 0o777, 0o600);

        let contender = OpenOptions::new().read(true).write(true).open(&journal_path).unwrap();
        assert!(contender.try_lock().is_err());
        assert!(SourceSettlementJournalV2::create(&journal_path, policy, &mut source).is_err());

        let mut external = OpenOptions::new().append(true).open(&journal_path).unwrap();
        external.write_all(&[0]).unwrap();
        external.sync_all().unwrap();
        assert!(journal.floor().is_err());
        assert!(journal.is_poisoned());
        assert!(journal.cursor().is_err());
        assert!(journal.last_payload().is_err());
    }

    #[test]
    fn create_rejects_a_symlink_final_component() {
        let temp = Temp::new();
        let mut source = create_source(&temp.0.join("source"));
        let target = temp.0.join("target");
        fs::write(&target, b"do not replace").unwrap();
        let link = temp.0.join("settlement-v2");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(SourceSettlementJournalV2::create(&link, policy(&source), &mut source).is_err());
        assert_eq!(fs::read(target).unwrap(), b"do not replace");
    }
}
