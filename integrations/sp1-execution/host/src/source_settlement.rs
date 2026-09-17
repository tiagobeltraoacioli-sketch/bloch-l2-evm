// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory coordination of externally trusted source selection and SP1 execution.
//! This does not persist a combined cursor or activate native consensus rules.
use crate::{
    invalid,
    settlement::{SettlementCursor, SettlementMark},
    verification::{ProgramIdentity, VerifiedExecutionStatement},
    Result,
};
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    escrow_inbox::InboxProof,
    l1::height::HeightPosition,
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    ChainSpec,
};
use bloch_native_domain_devnet::{SourceBatch, SourceRegistry};

/// Published only after both execution and mandatory-prefix checks succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementMark {
    pub execution: SettlementMark,
    pub next_sequence: u64,
    pub source_commitment: B256,
}

/// Owns source history and consumed position; callers cannot replace either.
pub struct SourceSettlement {
    source: SourceRegistry,
    execution: SettlementCursor,
    spec: ChainSpec,
    next_sequence: u64,
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
