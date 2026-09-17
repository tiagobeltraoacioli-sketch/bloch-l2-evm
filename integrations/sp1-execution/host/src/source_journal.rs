// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable local SP1 execution plus authenticated experimental source selection.
//! Source trust is supplied by a separately opened exact-tip SourceJournal.
use crate::{
    invalid,
    settlement::{SettlementCursor, SettlementMark, MAX_JOURNAL_BYTES, MAX_JOURNAL_RECORDS},
    source_settlement::prepare_source_advance,
    verification::{decode_proof, ProgramIdentity, TrustedProgram, VerifiedExecutionStatement, MAX_PROOF_BYTES},
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
    SourceRegistry,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const TAG: &[u8] = b"BLOCH:LOCAL:SP1:SOURCE:1";
const MARK_TAG: &[u8] = b"BLOCH:LOCAL:SP1:SOURCE:MARK:1";
const MAX_HEADER_BYTES: usize = 2048;
const MAX_FRAME_BYTES: usize = MARK_BYTES + 8 + MAX_HEADER_BYTES + MAX_NODE_BODY_BYTES + MAX_PROOF_BYTES;
pub const SOURCE_SETTLEMENT_MARK_BYTES: usize = MARK_TAG.len() + 80 + MARK_BYTES;

/// Explicit independently trusted policy, fixed for the journal's lifetime.
#[derive(Clone)]
pub struct SourceSettlementPolicy {
    spec: ChainSpec,
    network: B256,
    native_genesis: B256,
    domain: B256,
    program: ProgramIdentity,
    genesis: NodeHeaderV2,
}
impl SourceSettlementPolicy {
    /// Consumption starts at zero only for the exact canonical zero-funded V2
    /// genesis, not an arbitrary header labeled block zero or an imported cursor.
    pub fn new(
        spec: ChainSpec,
        network: B256,
        native_genesis: B256,
        domain: B256,
        program: ProgramIdentity,
        genesis: NodeHeaderV2,
    ) -> Result<Self> {
        if network == B256::ZERO || native_genesis == B256::ZERO {
            return Err(invalid("zero native policy identity"));
        }
        let mut state = genesis_v2(&spec, genesis.timestamp)?;
        state.commit_root();
        if genesis != node_head(&spec, domain, &state)? {
            return Err(invalid("source journal requires canonical zero-funded V2 genesis"));
        }
        Ok(Self {
            spec,
            network,
            native_genesis,
            domain,
            program,
            genesis,
        })
    }
    fn cursor(&self) -> Result<SettlementCursor> {
        SettlementCursor::from_trusted_anchor(self.spec.clone(), self.domain, self.program, self.genesis.clone())
    }
    fn check_source(&self, registry: &SourceRegistry) -> Result<()> {
        if registry.network() != self.network
            || registry.genesis() != self.native_genesis
            || registry.domain() != self.domain
        {
            return Err(invalid("source journal policy identity mismatch"));
        }
        Ok(())
    }
    fn prefix(&self) -> Result<Vec<u8>> {
        let mut bytes = TAG.to_vec();
        for hash in [
            self.program.elf_keccak(),
            self.program.verifying_key_hash(),
            configuration_commitment(&self.spec)?,
            self.domain,
            self.network,
            self.native_genesis,
        ] {
            bytes.extend_from_slice(hash.as_slice());
        }
        let header = alloy_rlp::encode(&self.genesis);
        bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&header);
        Ok(bytes)
    }
}

/// Independently retained complete acknowledgment floor, never loaded as an
/// authoritative cursor. Recovery must encounter this exact derived mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementJournalMark {
    pub execution: SettlementMark,
    pub next_sequence: u64,
    pub last_source: SourceMark,
}
impl SourceSettlementJournalMark {
    /// Fixed-width tagged transport only, not authentication.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = MARK_TAG.to_vec();
        bytes.extend_from_slice(&self.execution.number.to_be_bytes());
        bytes.extend_from_slice(self.execution.header_hash.as_slice());
        bytes.extend_from_slice(self.execution.state_root.as_slice());
        bytes.extend_from_slice(&self.next_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.last_source.encode());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SOURCE_SETTLEMENT_MARK_BYTES || !bytes.starts_with(MARK_TAG) {
            return Err(invalid("invalid source settlement mark encoding"));
        }
        let bytes = &bytes[MARK_TAG.len()..];
        Ok(Self {
            execution: SettlementMark {
                number: u64::from_be_bytes(bytes[..8].try_into()?),
                header_hash: B256::from_slice(&bytes[8..40]),
                state_root: B256::from_slice(&bytes[40..72]),
            },
            next_sequence: u64::from_be_bytes(bytes[72..80].try_into()?),
            last_source: SourceMark::decode(&bytes[80..])?,
        })
    }
}

/// One durable frame publishes both the execution successor and derived source
/// consumption. The separate source journal can be ahead with unconsumed locks.
pub struct SourceSettlementJournal {
    file: File,
    policy: SourceSettlementPolicy,
    cursor: SettlementCursor,
    mark: SourceSettlementJournalMark,
    expected_len: u64,
    records: usize,
    poisoned: bool,
}
impl Drop for SourceSettlementJournal {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
impl SourceSettlementJournal {
    /// Create a new file, refusing overwrite. The source's current authenticated
    /// tip may contain pending locks; canonical EVM genesis still consumes zero.
    pub fn create(path: impl AsRef<Path>, policy: SourceSettlementPolicy, source: &mut SourceJournal) -> Result<Self> {
        let initial = source.mark()?;
        policy.check_source(&source.snapshot_at(initial)?)?;
        let cursor = policy.cursor()?;
        let mark = SourceSettlementJournalMark {
            execution: cursor.mark(),
            next_sequence: 0,
            last_source: initial,
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path.as_ref())?;
        file.try_lock()?;
        let mut bytes = policy.prefix()?;
        bytes.extend_from_slice(&initial.encode());
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(
            path.as_ref()
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self {
            file,
            policy,
            cursor,
            mark,
            expected_len: bytes.len() as u64,
            records: 0,
            poisoned: false,
        })
    }

    /// Reverify every real SP1 proof and its historical source snapshot. The
    /// source journal must already be authenticated against an INDEPENDENT exact
    /// current tip. Stored source marks cannot bootstrap or replace that trust.
    /// Valid execution successors after the complete floor may be recovered as
    /// local durable selection, not native finality or transaction DA authority.
    pub fn open(
        path: impl AsRef<Path>,
        policy: SourceSettlementPolicy,
        program: &TrustedProgram,
        source: &mut SourceJournal,
        floor: SourceSettlementJournalMark,
    ) -> Result<Self> {
        if program.identity() != policy.program {
            return Err(invalid("source journal verifier/program mismatch"));
        }
        policy.check_source(source.registry()?)?;
        let mut file = crate::open_regular(path.as_ref(), true)?;
        file.try_lock()?;
        let expected_len = file.metadata()?.len();
        if expected_len > MAX_JOURNAL_BYTES {
            return Err(invalid("source settlement cumulative byte limit"));
        }
        let prefix = policy.prefix()?;
        if expected_len < (prefix.len() + MARK_BYTES) as u64 {
            return Err(invalid("truncated source settlement manifest"));
        }
        let mut stored = vec![0; prefix.len()];
        file.read_exact(&mut stored)?;
        if stored != prefix {
            return Err(invalid("source settlement policy/genesis mismatch"));
        }
        let mut initial = [0u8; MARK_BYTES];
        file.read_exact(&mut initial)?;
        let initial = SourceMark::decode(&initial)?;
        policy.check_source(&source.snapshot_at(initial)?)?;
        let mut cursor = policy.cursor()?;
        let mut mark = SourceSettlementJournalMark {
            execution: cursor.mark(),
            next_sequence: 0,
            last_source: initial,
        };
        let mut floor_seen = mark == floor;
        let mut records = 0;
        let mut consumed = (prefix.len() + MARK_BYTES) as u64;
        while consumed < expected_len {
            if records >= MAX_JOURNAL_RECORDS || expected_len - consumed < 36 {
                return Err(invalid("source settlement record bounds"));
            }
            let mut length = [0; 4];
            file.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            if !(MARK_BYTES + 8 + 14..=MAX_FRAME_BYTES).contains(&length)
                || length as u64 + 36 > expected_len - consumed
            {
                return Err(invalid("source settlement frame bounds"));
            }
            let mut payload = vec![0; length];
            file.read_exact(&mut payload)?;
            let mut checksum = [0; 32];
            file.read_exact(&mut checksum)?;
            if keccak256(&payload) != B256::from(checksum) {
                return Err(invalid("source settlement checksum mismatch"));
            }
            let frame = decode_frame(&payload)?;
            source_order(mark.last_source, frame.source)?;
            let snapshot = source.snapshot_at(frame.source)?;
            policy.check_source(&snapshot)?;
            let selected = snapshot.validate_v2_prefix(&policy.spec, mark.next_sequence, &frame.header, &frame.body)?;
            let verified = program.verify(decode_proof(frame.proof)?, &selected.statement())?;
            let (candidate, accepted) = prepare_source_advance(
                &policy.spec,
                &cursor,
                mark.next_sequence,
                &snapshot,
                &verified,
                &frame.header,
                &frame.body,
            )?;
            mark = SourceSettlementJournalMark {
                execution: accepted.execution,
                next_sequence: accepted.next_sequence,
                last_source: frame.source,
            };
            cursor = candidate;
            records += 1;
            consumed += length as u64 + 36;
            floor_seen |= mark == floor;
        }
        if file.metadata()?.len() != expected_len {
            return Err(invalid("source settlement length changed during replay"));
        }
        if !floor_seen {
            return Err(invalid("complete retained source settlement floor not found"));
        }
        Ok(Self {
            file,
            policy,
            cursor,
            mark,
            expected_len,
            records,
            poisoned: false,
        })
    }

    pub fn mark(&self) -> Result<SourceSettlementJournalMark> {
        if self.poisoned {
            return Err(invalid("source settlement journal is poisoned"));
        }
        Ok(self.mark)
    }
    pub fn cursor(&self) -> Result<&SettlementCursor> {
        if self.poisoned {
            return Err(invalid("source settlement journal is poisoned"));
        }
        Ok(&self.cursor)
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn check_length(&mut self) -> Result<()> {
        match self.file.metadata() {
            Ok(metadata) if metadata.len() == self.expected_len => Ok(()),
            Ok(_) => {
                self.poisoned = true;
                Err(invalid("source settlement journal length changed"))
            }
            Err(error) => {
                self.poisoned = true;
                Err(error.into())
            }
        }
    }
    /// Source validation, proof/parent checks and encoding all finish before any
    /// write. An uncertain write/fsync poisons all state access and future writes.
    pub fn append(
        &mut self,
        source: &mut SourceJournal,
        proof: &VerifiedExecutionStatement,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementJournalMark> {
        if self.poisoned {
            return Err(invalid("source settlement journal is poisoned"));
        }
        self.check_length()?;
        if self.records >= MAX_JOURNAL_RECORDS {
            return Err(invalid("source settlement journal record limit"));
        }
        self.policy.check_source(source.registry()?)?;
        let current = source.mark()?;
        source_order(self.mark.last_source, current)?;
        // A different source handle cannot substitute a conflicting history with
        // the same network/genesis. The last used exact mark must also occur.
        self.policy.check_source(&source.snapshot_at(self.mark.last_source)?)?;
        let snapshot = source.snapshot_at(current)?;
        self.policy.check_source(&snapshot)?;
        let (cursor, accepted) = prepare_source_advance(
            &self.policy.spec,
            &self.cursor,
            self.mark.next_sequence,
            &snapshot,
            proof,
            header,
            body,
        )?;
        let mark = SourceSettlementJournalMark {
            execution: accepted.execution,
            next_sequence: accepted.next_sequence,
            last_source: current,
        };
        let payload = encode_frame(current, header, body, proof)?;
        let next_len = self
            .expected_len
            .checked_add(36 + payload.len() as u64)
            .ok_or_else(|| invalid("source settlement byte overflow"))?;
        if next_len > MAX_JOURNAL_BYTES {
            return Err(invalid("source settlement cumulative byte limit"));
        }
        self.check_length()?;
        self.poisoned = true;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&(payload.len() as u32).to_be_bytes())?;
        self.file.write_all(&payload)?;
        self.file.write_all(keccak256(&payload).as_slice())?;
        self.file.sync_all()?;
        self.cursor = cursor;
        self.mark = mark;
        self.expected_len = next_len;
        self.records += 1;
        self.poisoned = false;
        Ok(mark)
    }
}
fn source_order(previous: SourceMark, next: SourceMark) -> Result<()> {
    if next.records < previous.records || (next.records == previous.records && next != previous) {
        return Err(invalid("source settlement historical source rollback/conflict"));
    }
    Ok(())
}
fn encode_frame(
    source: SourceMark,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
    proof: &VerifiedExecutionStatement,
) -> Result<Vec<u8>> {
    let header_length = header.length();
    let body_length = body.length();
    if header_length > MAX_HEADER_BYTES || body_length > MAX_NODE_BODY_BYTES {
        return Err(invalid("source settlement header/body size limit"));
    }
    let proof = proof.proof_bytes()?;
    let mut bytes = Vec::with_capacity(MARK_BYTES + 8 + header_length + body_length + proof.len());
    bytes.extend_from_slice(&source.encode());
    bytes.extend_from_slice(&(header_length as u32).to_be_bytes());
    bytes.extend_from_slice(&(body_length as u32).to_be_bytes());
    header.encode(&mut bytes);
    body.encode(&mut bytes);
    bytes.extend_from_slice(&proof);
    Ok(bytes)
}
struct Frame<'a> {
    source: SourceMark,
    header: NodeHeaderV2,
    body: NodeBodyV2,
    proof: &'a [u8],
}
fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>> {
    if bytes.len() < MARK_BYTES + 8 {
        return Err(invalid("source settlement frame truncated"));
    }
    let source = SourceMark::decode(&bytes[..MARK_BYTES])?;
    let header_len = u32::from_be_bytes(bytes[MARK_BYTES..MARK_BYTES + 4].try_into()?) as usize;
    let body_len = u32::from_be_bytes(bytes[MARK_BYTES + 4..MARK_BYTES + 8].try_into()?) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES || body_len == 0 || body_len > MAX_NODE_BODY_BYTES {
        return Err(invalid("source settlement header/body length invalid"));
    }
    let offset = MARK_BYTES + 8;
    let proof_start = offset
        .checked_add(header_len)
        .and_then(|n| n.checked_add(body_len))
        .ok_or_else(|| invalid("source settlement frame length overflow"))?;
    if proof_start >= bytes.len() || !(12..=MAX_PROOF_BYTES).contains(&(bytes.len() - proof_start)) {
        return Err(invalid("source settlement proof length invalid"));
    }
    let mut header_bytes = &bytes[offset..offset + header_len];
    let header = NodeHeaderV2::decode(&mut header_bytes)?;
    let mut body_bytes = &bytes[offset + header_len..proof_start];
    let body = NodeBodyV2::decode(&mut body_bytes)?;
    if !header_bytes.is_empty() || !body_bytes.is_empty() {
        return Err(invalid("source settlement trailing header/body data"));
    }
    Ok(Frame {
        source,
        header,
        body,
        proof: &bytes[proof_start..],
    })
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use bloch_native_domain_devnet::SourceAnchor;

    // These tests exercise byte framing only. Twelve zero bytes are deliberately
    // NOT a verified SP1 proof and never enter the public verification boundary.
    fn transport_fixture() -> Vec<u8> {
        let source = SourceMark {
            records: 0,
            commitment: B256::ZERO,
            anchor: SourceAnchor {
                block: B256::ZERO,
                slot: 0,
                height: 0,
            },
            inbox_count: 0,
            inbox_root: B256::ZERO,
        };
        let header = alloy_rlp::encode(NodeHeaderV2::default());
        let body = alloy_rlp::encode(NodeBodyV2::default());
        let mut bytes = source.encode().to_vec();
        bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&[0; 12]);
        bytes
    }
    #[test]
    fn transport_bounds_and_trailing_rlp_are_checked_without_proof_acceptance() {
        let bytes = transport_fixture();
        assert!(decode_frame(&bytes).is_ok());
        for cut in 0..bytes.len() {
            assert!(decode_frame(&bytes[..cut]).is_err(), "prefix {cut}");
        }
        let mut bad = bytes.clone();
        bad[MARK_BYTES..MARK_BYTES + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_frame(&bad).is_err());
        let mut bad = bytes.clone();
        bad[MARK_BYTES + 4..MARK_BYTES + 8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_frame(&bad).is_err());
        let header_len = u32::from_be_bytes(bytes[MARK_BYTES..MARK_BYTES + 4].try_into().unwrap()) as usize;
        let mut trailing_header = bytes;
        trailing_header.insert(MARK_BYTES + 8 + header_len, 0);
        trailing_header[MARK_BYTES..MARK_BYTES + 4].copy_from_slice(&((header_len + 1) as u32).to_be_bytes());
        assert!(decode_frame(&trailing_header).is_err());
    }
}
