// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only source selection for V2 execution statements.
use crate::{Error, SourceAnchor, SourceRegistry, MAX_LOCKS};
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{configuration_commitment, ExecutionStatement},
    ChainSpec, DepositMint, DepositProvenance,
};
use std::ops::Range;

/// A checked selection under the registry's explicit external source authority.
/// This is neither an execution proof nor a consumed-deposit receipt. There is
/// no public constructor or serde decoder; a proof/settlement host must compare
/// the exact statement AND its retained consumption cursor before committing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedV2Prefix {
    network: B256,
    genesis: B256,
    source_commitment: B256,
    inbox_root: B256,
    inbox_count: u64,
    anchor: SourceAnchor,
    range: Range<u64>,
    body_commitment: B256,
    statement: ExecutionStatement,
}
impl ValidatedV2Prefix {
    pub fn network(&self) -> B256 {
        self.network
    }
    pub fn genesis(&self) -> B256 {
        self.genesis
    }
    pub fn domain(&self) -> B256 {
        self.statement.domain
    }
    pub fn source_commitment(&self) -> B256 {
        self.source_commitment
    }
    pub fn inbox_root(&self) -> B256 {
        self.inbox_root
    }
    pub fn inbox_count(&self) -> u64 {
        self.inbox_count
    }
    pub fn anchor(&self) -> SourceAnchor {
        self.anchor
    }
    pub fn range(&self) -> Range<u64> {
        self.range.clone()
    }
    /// Keccak over the existing canonical tagged V2 body RLP.
    pub fn body_commitment(&self) -> B256 {
        self.body_commitment
    }
    /// Exact public execution expectation, not authenticated proof output.
    pub fn statement(&self) -> ExecutionStatement {
        self.statement
    }
}

impl SourceRegistry {
    /// Validate the mandatory prefix beginning at an independently retained
    /// execution cursor. Caller-supplied `next_sequence` is not a replay guard;
    /// successful execution/proof and durable settlement must advance it once.
    /// This function never modifies the registry or fabricates a mint permit.
    pub fn validate_v2_prefix(
        &self,
        spec: &ChainSpec,
        next_sequence: u64,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<ValidatedV2Prefix, Error> {
        header
            .validate_configuration(spec, self.domain)
            .map_err(|_| Error::Configuration)?;
        if header.number == 0 || header.anchor_root != self.anchor.block {
            return Err(Error::Identity);
        }
        if next_sequence > self.count() {
            return Err(Error::Incomplete);
        }
        let take = (self.count() - next_sequence).min(spec.max_deposits_per_block().min(MAX_LOCKS as u64));
        if body.deposits.len() as u64 != take {
            return Err(Error::Incomplete);
        }
        body.validate(spec).map_err(|_| Error::Body)?;
        if header.transactions_root != body.transactions_root() || header.deposits_hash != body.deposits_hash() {
            return Err(Error::Body);
        }
        let deposit_gas = take.checked_mul(spec.deposit_gas).ok_or(Error::Configuration)?;
        if header.user_gas_used.checked_add(deposit_gas) != Some(header.gas_used) {
            return Err(Error::Body);
        }
        let end = next_sequence + take; // take <= count - next_sequence.
        for (index, mint) in (next_sequence as usize..end as usize).zip(&body.deposits) {
            let location = &self.locations[index];
            let deposit = &self.deposits[index];
            let expected = DepositMint {
                recipient: deposit.recipient,
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: location.position.l1_height,
                    l1_tx_index: location.position.l1_tx_index,
                    l1_txid: location.transaction.into(),
                    l1_vout: location.position.l1_vout,
                    l1_sats: deposit.amount,
                },
            };
            if *mint != expected {
                return Err(Error::Mapping);
            }
        }
        Ok(ValidatedV2Prefix {
            network: self.network,
            genesis: self.genesis,
            source_commitment: self.commitment,
            inbox_root: self.inbox_root,
            inbox_count: self.count(),
            anchor: self.anchor,
            range: next_sequence..end,
            body_commitment: keccak256(alloy_rlp::encode(body)),
            statement: ExecutionStatement {
                configuration: configuration_commitment(spec).map_err(|_| Error::Configuration)?,
                domain: self.domain,
                previous_state_root: header.parent_state_root,
                header_hash: header.hash(),
            },
        })
    }
}
