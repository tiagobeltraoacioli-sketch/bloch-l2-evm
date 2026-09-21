// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local V2 settlement cursor and append-only proof journal.
//! No native liabilities, native state component, finality or payouts are changed.
#[cfg(feature = "source-settlement")]
use crate::source_settlement::CheckedGroth16SettlementV2;
use crate::{
    invalid,
    verification::{decode_proof, ProgramIdentity, TrustedProgram, VerifiedExecutionStatement, MAX_PROOF_BYTES},
    Result,
};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Decodable;
#[cfg(feature = "source-settlement")]
use bloch_l2_evm::proof_statement::SettlementStatementV2;
use bloch_l2_evm::{
    node_primitives::NodeHeaderV2,
    proof_statement::{configuration_commitment, ExecutionStatement},
    ChainSpec,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const JOURNAL_TAG: &[u8] = b"BLOCH:LOCAL:SP1:SETTLEMENT:1";
const MAX_HEADER_BYTES: usize = 2048;
const MAX_FRAME_BYTES: usize = 4 + MAX_HEADER_BYTES + MAX_PROOF_BYTES;
/// Bounded local prototype history; reaching capacity refuses new entries.
pub const MAX_JOURNAL_RECORDS: usize = 256;
/// Cumulative byte bound, checked before reads/allocations and before append.
pub const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

/// An independently retained acknowledgment floor. This is trusted application
/// input, not a proof, signature or automatically authenticated saved checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementMark {
    pub number: u64,
    pub header_hash: B256,
    pub state_root: B256,
}

#[derive(Clone, Debug)]
pub struct SettlementCursor {
    spec: ChainSpec,
    configuration: B256,
    domain: B256,
    program: ProgramIdentity,
    head: NodeHeaderV2,
}

impl SettlementCursor {
    /// Bootstrap from an independently trusted V2 anchor. Header configuration
    /// checks do not establish that the anchor was executed or finalized.
    pub fn from_trusted_anchor(
        spec: ChainSpec,
        domain: B256,
        program: ProgramIdentity,
        anchor: NodeHeaderV2,
    ) -> Result<Self> {
        anchor.validate_configuration(&spec, domain)?;
        let configuration = configuration_commitment(&spec)?;
        Ok(Self {
            spec,
            configuration,
            domain,
            program,
            head: anchor,
        })
    }

    pub fn head(&self) -> &NodeHeaderV2 {
        &self.head
    }
    pub fn program(&self) -> ProgramIdentity {
        self.program
    }
    pub fn mark(&self) -> SettlementMark {
        SettlementMark {
            number: self.head.number,
            header_hash: self.head.hash(),
            state_root: self.head.state_root,
        }
    }

    /// The caller selects this header independently; this only derives expected
    /// public commitments from the configured cursor and checks continuity.
    pub fn expected_for_selected_header(&self, header: &NodeHeaderV2) -> Result<ExecutionStatement> {
        header.validate_configuration(&self.spec, self.domain)?;
        header.validate_parent(&self.spec, &self.head)?;
        Ok(ExecutionStatement {
            configuration: self.configuration,
            domain: self.domain,
            previous_state_root: self.head.state_root,
            header_hash: header.hash(),
        })
    }

    /// Publish exactly one verified successor, after every check succeeds.
    pub fn advance(&mut self, verified: &VerifiedExecutionStatement, header: &NodeHeaderV2) -> Result<SettlementMark> {
        if verified.program() != self.program {
            return Err(invalid("settlement proof belongs to another trusted program"));
        }
        let expected = self.expected_for_selected_header(header)?;
        if verified.statement() != expected {
            return Err(invalid("verified statement does not match settlement successor"));
        }
        self.head = header.clone();
        Ok(self.mark())
    }

    /// Internal transition after the source coordinator has extracted and
    /// checked an unforgeable verifier capability.
    #[cfg(feature = "source-settlement")]
    pub(crate) fn advance_checked_settlement_v2(
        &mut self,
        verified: &CheckedGroth16SettlementV2,
        expected: &SettlementStatementV2,
        header: &NodeHeaderV2,
    ) -> Result<SettlementMark> {
        if verified.program() != self.program {
            return Err(invalid(
                "Groth16 settlement V2 proof belongs to another trusted program",
            ));
        }
        self.check_settlement_v2_successor(expected, header)?;
        if verified.statement() != *expected {
            return Err(invalid(
                "verified Groth16 settlement V2 statement does not match successor",
            ));
        }
        self.head = header.clone();
        Ok(self.mark())
    }

    #[cfg(feature = "source-settlement")]
    fn check_settlement_v2_successor(&self, expected: &SettlementStatementV2, header: &NodeHeaderV2) -> Result<()> {
        self.expected_for_selected_header(header)?;
        if expected.configuration != self.configuration
            || expected.domain != self.domain
            || expected.chain_id != header.chain_id
            || expected.l2_number != header.number
            || expected.l2_parent_hash != header.parent_hash
            || expected.l2_previous_state_root != header.parent_state_root
            || expected.l2_header_hash != header.hash()
            || expected.l2_state_root != header.state_root
            || expected.l1_block != header.anchor_root
        {
            return Err(invalid("settlement V2 statement is not the selected L2 successor"));
        }
        Ok(())
    }

    fn journal_header(&self) -> Vec<u8> {
        let header = alloy_rlp::encode(&self.head);
        let mut bytes = JOURNAL_TAG.to_vec();
        for hash in [
            self.program.elf_keccak(),
            self.program.verifying_key_hash(),
            self.configuration,
            self.domain,
        ] {
            bytes.extend_from_slice(hash.as_slice());
        }
        bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&header);
        bytes
    }
}

/// Sole cooperating writer, with fail-closed recovery and no automatic tail
/// repair. Proofs are reverified when reopening; a serialized cursor is not trusted.
pub struct SettlementJournal {
    file: File,
    cursor: SettlementCursor,
    expected_len: u64,
    records: usize,
    poisoned: bool,
}

impl SettlementJournal {
    /// Create a new local journal without replacing any existing path.
    pub fn create(path: impl AsRef<Path>, anchor: SettlementCursor) -> Result<Self> {
        let path = path.as_ref();
        let mut file = OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
        file.try_lock()?;
        let bytes = anchor.journal_header();
        file.write_all(&bytes)?;
        file.sync_all()?;
        // Acknowledge the new directory entry as well as its contents.
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self {
            file,
            cursor: anchor,
            expected_len: bytes.len() as u64,
            records: 0,
            poisoned: false,
        })
    }

    /// Reverify the complete history under the externally supplied program,
    /// anchor and rollback floor. Never take the floor from this journal itself.
    /// Valid successors after the floor are recovered as local durable selection;
    /// this does not establish network consensus or native finality.
    pub fn open(
        path: impl AsRef<Path>,
        program: &TrustedProgram,
        mut anchor: SettlementCursor,
        floor: SettlementMark,
    ) -> Result<Self> {
        if program.identity() != anchor.program() {
            return Err(invalid("journal verifier and trusted anchor program differ"));
        }
        let mut file = crate::open_regular(path.as_ref(), true)?;
        file.try_lock()?;
        if file.metadata()?.len() > MAX_JOURNAL_BYTES {
            return Err(invalid("journal cumulative byte limit exceeded"));
        }
        let prefix = anchor.journal_header();
        let mut stored = vec![0; prefix.len()];
        file.read_exact(&mut stored)?;
        if stored != prefix {
            return Err(invalid("journal identity or trusted anchor mismatch"));
        }
        let mut floor_seen = anchor.mark() == floor;
        let mut records = 0;
        let mut consumed = prefix.len() as u64;
        loop {
            let mut length = [0; 4];
            if file.read(&mut length[..1])? == 0 {
                break;
            }
            file.read_exact(&mut length[1..])?;
            records += 1;
            let length = u32::from_be_bytes(length) as usize;
            if records > MAX_JOURNAL_RECORDS || !(5..=MAX_FRAME_BYTES).contains(&length) {
                return Err(invalid("journal record bounds exceeded"));
            }
            consumed += 4 + length as u64 + 32;
            if consumed > MAX_JOURNAL_BYTES {
                return Err(invalid("journal cumulative byte limit exceeded"));
            }
            let mut frame = vec![0; length];
            file.read_exact(&mut frame)?;
            let mut checksum = [0; 32];
            file.read_exact(&mut checksum)?;
            if keccak256(&frame).as_slice() != checksum {
                return Err(invalid("journal record checksum mismatch"));
            }
            let header_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            if header_len == 0 || header_len > MAX_HEADER_BYTES || 4 + header_len >= frame.len() {
                return Err(invalid("journal header bounds exceeded"));
            }
            let mut encoded_header = &frame[4..4 + header_len];
            let header = NodeHeaderV2::decode(&mut encoded_header)?;
            if !encoded_header.is_empty() {
                return Err(invalid("trailing journal header bytes"));
            }
            let expected = anchor.expected_for_selected_header(&header)?;
            let proof = decode_proof(&frame[4 + header_len..])?;
            let verified = program.verify(proof, &expected)?;
            anchor.advance(&verified, &header)?;
            floor_seen |= anchor.mark() == floor;
        }
        if !floor_seen {
            return Err(invalid(
                "journal does not contain independently retained settlement floor",
            ));
        }
        let expected_len = file.stream_position()?;
        Ok(Self {
            file,
            cursor: anchor,
            expected_len,
            records,
            poisoned: false,
        })
    }

    pub fn cursor(&self) -> &SettlementCursor {
        &self.cursor
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Validation failures leave disk and cursor unchanged. Any I/O failure after
    /// writing begins poisons this instance; reopen and reverify before continuing.
    pub fn append(&mut self, verified: &VerifiedExecutionStatement, header: &NodeHeaderV2) -> Result<SettlementMark> {
        if self.poisoned {
            return Err(invalid("settlement journal is poisoned"));
        }
        if self.records >= MAX_JOURNAL_RECORDS {
            return Err(invalid("settlement journal is full"));
        }
        let mut candidate = self.cursor.clone();
        let mark = candidate.advance(verified, header)?;
        let encoded_header = alloy_rlp::encode(header);
        if encoded_header.len() > MAX_HEADER_BYTES {
            return Err(invalid("journal header too large"));
        }
        let proof = verified.proof_bytes()?;
        let mut frame = (encoded_header.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&encoded_header);
        frame.extend_from_slice(&proof);
        if self.expected_len + 4 + frame.len() as u64 + 32 > MAX_JOURNAL_BYTES {
            return Err(invalid("journal cumulative byte limit exceeded"));
        }
        if self.file.metadata()?.len() != self.expected_len {
            self.poisoned = true;
            return Err(invalid("journal length changed outside its sole writer"));
        }
        self.poisoned = true;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.file.write_all(&frame)?;
        self.file.write_all(keccak256(&frame).as_slice())?;
        self.file.sync_all()?;
        self.expected_len += 4 + frame.len() as u64 + 32;
        self.records += 1;
        self.cursor = candidate;
        self.poisoned = false;
        Ok(mark)
    }
}
