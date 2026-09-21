// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory coordination of externally trusted source selection and SP1 execution.
//! This does not persist a combined cursor or activate native consensus rules.
use crate::{
    invalid,
    settlement::{SettlementCursor, SettlementMark},
    verification::{ProgramIdentity, QualifiedGroth16SettlementV2, VerifiedExecutionStatement},
    Result,
};
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    escrow_inbox::InboxProof,
    l1::height::HeightPosition,
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{configuration_commitment, SettlementContextV2, SettlementStatementV2},
    ChainSpec,
};
use bloch_native_domain_devnet::{proof_digest, SettlementPayloadV2, SourceBatch, SourceRegistry};

/// Published only after both execution and mandatory-prefix checks succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementMark {
    pub execution: SettlementMark,
    pub next_sequence: u64,
    pub source_commitment: B256,
}

/// Result of one fully checked local V2 transition. The payload remains inert:
/// this type does not activate a native transaction or finality rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementV2Mark {
    execution: SettlementMark,
    next_sequence: u64,
    source_commitment: B256,
    settlement_commitment: B256,
    payload: SettlementPayloadV2,
}

impl SourceSettlementV2Mark {
    pub fn execution(&self) -> SettlementMark {
        self.execution
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn source_commitment(&self) -> B256 {
        self.source_commitment
    }
    pub fn settlement_commitment(&self) -> B256 {
        self.settlement_commitment
    }
    pub fn payload(&self) -> SettlementPayloadV2 {
        self.payload
    }
}

/// Owns source history and consumed position; callers cannot replace either.
pub struct SourceSettlement {
    source: SourceRegistry,
    execution: SettlementCursor,
    spec: ChainSpec,
    next_sequence: u64,
    last_settlement: Option<B256>,
}
impl SourceSettlement {
    /// Independent policy pins native network/genesis and execution domain/program.
    /// Only a trusted EVM genesis with zero consumed deposits can bootstrap here.
    pub fn from_trusted_genesis(
        spec: ChainSpec,
        network: B256,
        genesis: B256,
        domain: B256,
        program: ProgramIdentity,
        anchor: NodeHeaderV2,
        source: SourceRegistry,
    ) -> Result<Self> {
        if anchor.number != 0
            || source.anchor().height != 0
            || source.count() != 0
            || source.network() != network
            || source.genesis() != genesis
            || source.domain() != domain
        {
            return Err(invalid("source settlement bootstrap identity mismatch"));
        }
        let mut state = bloch_l2_evm::node_execution::genesis_v2(&spec, anchor.timestamp)?;
        state.commit_root();
        let canonical = bloch_l2_evm::node_execution::node_head(&spec, domain, &state)?;
        if anchor != canonical {
            return Err(invalid("source settlement requires canonical unconsumed EVM genesis"));
        }
        let execution = SettlementCursor::from_trusted_anchor(spec.clone(), domain, program, anchor)?;
        Ok(Self {
            source,
            execution,
            spec,
            next_sequence: 0,
            last_settlement: None,
        })
    }
    pub fn execution(&self) -> &SettlementCursor {
        &self.execution
    }
    pub fn source(&self) -> &SourceRegistry {
        &self.source
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn last_settlement(&self) -> Option<B256> {
        self.last_settlement
    }

    /// Construct the exact V2 proof expectation from the independently retained
    /// source registry and execution cursor. This authenticates only the local
    /// experimental inputs; native consensus must enforce the same expectation.
    pub fn expected_statement_v2(&self, header: &NodeHeaderV2, body: &NodeBodyV2) -> Result<SettlementStatementV2> {
        self.execution.expected_for_selected_header(header)?;
        let selected = self
            .source
            .validate_v2_prefix(&self.spec, self.next_sequence, header, body)?;
        let anchor = selected.anchor();
        let range = selected.range();
        let program = self.execution.program();
        Ok(SettlementStatementV2::from_executed(
            configuration_commitment(&self.spec)?,
            header,
            body,
            SettlementContextV2 {
                network: selected.network(),
                genesis: selected.genesis(),
                program_elf_keccak: program.elf_keccak(),
                program_vkey_koalabear: program.verifying_key_hash(),
                program_vkey_bn254: program.verifying_key_bn254(),
                previous_settlement: expected_previous_settlement(self.last_settlement),
                l1_slot: anchor.slot,
                l1_height: anchor.height,
                source_commitment: selected.source_commitment(),
                inbox_root: selected.inbox_root(),
                inbox_count: selected.inbox_count(),
                consumed_start: range.start,
                consumed_end: range.end,
            },
        )?)
    }

    /// `expected` is independently trusted authority, not derived from proposer input.
    pub fn apply_source(
        &mut self,
        expected: B256,
        position: HeightPosition,
        headers: &[Bytes],
        batch: &SourceBatch,
        proofs: &[InboxProof],
    ) -> Result<()> {
        self.source.apply(expected, position, headers, batch, proofs)?;
        Ok(())
    }
    /// All fallible checks precede publication of either execution or consumption.
    pub fn advance(
        &mut self,
        proof: &VerifiedExecutionStatement,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementMark> {
        check_legacy_advance_allowed(self.last_settlement)?;
        let (execution, mark) = prepare_source_advance(
            &self.spec,
            &self.execution,
            self.next_sequence,
            &self.source,
            proof,
            header,
            body,
        )?;
        self.execution = execution;
        self.next_sequence = mark.next_sequence;
        Ok(mark)
    }

    /// Check and publish one Groth16 V2 successor as a single in-memory state
    /// change. The predecessor, source cursor and proof digest are not supplied
    /// by the caller. All fallible work completes before any field is changed.
    pub fn advance_groth16_settlement_v2(
        &mut self,
        proof: &QualifiedGroth16SettlementV2,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementV2Mark> {
        let expected = self.expected_statement_v2(header, body)?;
        check_previous_settlement(&expected, self.last_settlement)?;
        if proof.statement() != expected {
            return Err(invalid("verified Groth16 statement differs from retained source state"));
        }

        let selected = self
            .source
            .validate_v2_prefix(&self.spec, self.next_sequence, header, body)?;
        let canonical_proof = proof.canonical_proof_bytes()?;
        let digest = proof_digest(&canonical_proof)?;
        let proof_policy = proof.proof_policy_commitment()?;
        let payload = SettlementPayloadV2::from_unverified_statement_v2(expected, digest, proof_policy)?;
        let settlement_commitment = payload.commitment()?;

        let mut execution = self.execution.clone();
        let execution_mark = execution.advance_groth16_settlement_v2(proof, &expected, header)?;
        let mark = SourceSettlementV2Mark {
            execution: execution_mark,
            next_sequence: selected.range().end,
            source_commitment: selected.source_commitment(),
            settlement_commitment,
            payload,
        };

        self.execution = execution;
        self.next_sequence = mark.next_sequence;
        self.last_settlement = Some(mark.settlement_commitment);
        Ok(mark)
    }
}

fn expected_previous_settlement(last_settlement: Option<B256>) -> B256 {
    last_settlement.unwrap_or(B256::ZERO)
}

fn check_previous_settlement(statement: &SettlementStatementV2, last_settlement: Option<B256>) -> Result<()> {
    if statement.previous_settlement != expected_previous_settlement(last_settlement) {
        return Err(invalid("settlement V2 predecessor differs from retained tip"));
    }
    Ok(())
}

fn check_legacy_advance_allowed(last_settlement: Option<B256>) -> Result<()> {
    if last_settlement.is_some() {
        return Err(invalid("legacy settlement cannot advance after V2 tip publication"));
    }
    Ok(())
}

/// Shared checked transition; callers publish only after any required durable sync.
pub(crate) fn prepare_source_advance(
    spec: &ChainSpec,
    execution: &SettlementCursor,
    next_sequence: u64,
    source: &SourceRegistry,
    proof: &VerifiedExecutionStatement,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<(SettlementCursor, SourceSettlementMark)> {
    let selected = source.validate_v2_prefix(spec, next_sequence, header, body)?;
    if selected.statement() != proof.statement() {
        return Err(invalid("source selection differs from verified execution"));
    }
    let mut candidate = execution.clone();
    let mark = candidate.advance(proof, header)?;
    Ok((
        candidate,
        SourceSettlementMark {
            execution: mark,
            next_sequence: selected.range().end,
            source_commitment: selected.source_commitment(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_with_previous(previous_settlement: B256) -> SettlementStatementV2 {
        SettlementStatementV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            domain: B256::repeat_byte(3),
            configuration: B256::repeat_byte(4),
            program_elf_keccak: B256::repeat_byte(5),
            program_vkey_koalabear: B256::repeat_byte(6),
            program_vkey_bn254: B256::repeat_byte(7),
            previous_settlement,
            chain_id: 700_771,
            l2_number: 1,
            l2_parent_hash: B256::repeat_byte(8),
            l2_previous_state_root: B256::repeat_byte(9),
            l2_header_hash: B256::repeat_byte(10),
            l2_state_root: B256::repeat_byte(11),
            l1_block: B256::repeat_byte(12),
            l1_slot: 2,
            l1_height: 1,
            source_commitment: B256::repeat_byte(13),
            inbox_root: B256::repeat_byte(14),
            inbox_count: 0,
            consumed_start: 0,
            consumed_end: 0,
            body_commitment: B256::repeat_byte(15),
        }
    }

    #[test]
    fn predecessor_is_zero_only_before_the_first_settlement() {
        let first = statement_with_previous(B256::ZERO);
        assert!(check_previous_settlement(&first, None).is_ok());

        let tip = B256::repeat_byte(42);
        assert!(check_previous_settlement(&statement_with_previous(tip), Some(tip)).is_ok());
        assert!(check_previous_settlement(&first, Some(tip)).is_err());
    }

    #[test]
    fn stale_fork_and_replay_predecessors_fail_closed() {
        let tip = B256::repeat_byte(42);
        for stale in [B256::repeat_byte(41), B256::repeat_byte(43), B256::ZERO] {
            assert!(check_previous_settlement(&statement_with_previous(stale), Some(tip)).is_err());
        }
    }

    #[test]
    fn legacy_path_cannot_split_state_after_v2_publication() {
        assert!(check_legacy_advance_allowed(None).is_ok());
        assert!(check_legacy_advance_allowed(Some(B256::repeat_byte(42))).is_err());
    }
}
