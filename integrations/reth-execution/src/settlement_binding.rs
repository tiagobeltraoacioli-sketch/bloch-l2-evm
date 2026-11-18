// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only correspondence between recovered settlements and persisted V2 blocks.
//! Local canonical selection is a host trust input, never native finality.

use crate::{BlochProviderFactory, ReplayFloor, ReplayLimits};
use alloy_eips::BlockNumHash;
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Encodable;
use bloch_l2_evm::{
    native_settlement::{SettlementPolicyV1, SettlementTransactionV1},
    node_primitives::NodeHeaderV2,
    proof_statement::configuration_commitment,
};
use reth_chainspec::EthChainSpec;
use reth_provider::{BlockNumReader, BlockReader, ChainSpecProvider, DatabaseProviderFactory, HeaderProvider};

/// Maximum cached prefix; callers must also supply an encoded-byte budget.
pub const MAX_SETTLEMENT_AUDIT_BLOCKS: u64 = 10_000;

/// Scoped, ordered audit over one bounded snapshot of acknowledged V2 blocks.
/// There is no constructor from RPC claims and no method that changes finality.
pub struct CanonicalSettlementAuditV1 {
    policy: SettlementPolicyV1,
    blocks: Vec<BlockBinding>,
    report: CanonicalSettlementAuditReportV1,
    poisoned: bool,
}

impl CanonicalSettlementAuditV1 {
    /// Exact correspondence only. The caller must authenticate native consensus
    /// separately; this method never creates native or Ethereum finality authority.
    pub fn audit_transaction(&mut self, transaction: &SettlementTransactionV1) -> Result<(), BlockExecutionError> {
        if self.poisoned {
            return Err(invalid("canonical settlement audit requires a fresh snapshot"));
        }
        self.poisoned = true;
        let generation = self
            .report
            .audited_records
            .checked_add(1)
            .ok_or_else(|| invalid("audit generation overflow"))?;
        let number = self
            .policy
            .first_l2_number
            .checked_add(self.report.audited_records)
            .ok_or_else(|| invalid("settlement block number overflow"))?;
        let block = usize::try_from(number)
            .ok()
            .and_then(|number| self.blocks.get(number))
            .ok_or_else(|| invalid("settlement is beyond the acknowledged canonical prefix"))?;
        let statement = transaction.statement();
        let header = &block.header;
        if statement.l2_number != number
            || transaction.proof_policy() != self.policy.proof_policy
            || statement.network != self.policy.network
            || statement.genesis != self.policy.genesis
            || statement.program_elf_keccak != self.policy.program_elf_keccak
            || statement.program_vkey_koalabear != self.policy.program_vkey_koalabear
            || statement.program_vkey_bn254 != self.policy.program_vkey_bn254
            || statement.domain != self.policy.domain
            || statement.configuration != self.policy.configuration
            || statement.chain_id != self.policy.chain_id
            || statement.l2_number != header.number
            || statement.l2_header_hash != block.hash
            || statement.l2_parent_hash != header.parent_hash
            || statement.l2_previous_state_root != header.parent_state_root
            || statement.l2_state_root != header.state_root
            || statement.l1_block != header.anchor_root
            || statement.body_commitment != block.body_commitment
            || statement.consumed_end.checked_sub(statement.consumed_start) != Some(block.deposits)
        {
            return Err(invalid(
                "settlement differs from the canonical V2 header or complete body",
            ));
        }
        self.report.audited_records = generation;
        self.report.last_settlement = Some(BlockNumHash::new(number, block.hash));
        self.poisoned = false;
        Ok(())
    }
}

/// Informational accounting, not a finalized-block capability or RPC instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSettlementAuditReportV1 {
    /// Selected settlement policy, including native network/program identities.
    pub policy_commitment: B256,
    /// Configured local L2 genesis, distinct from the native genesis in policy.
    pub genesis: B256,
    /// Highest locally acknowledged V2 block inspected, including unsettled tail.
    pub canonical_head: BlockNumHash,
    /// Total encoded non-genesis block bytes inspected under the byte budget.
    pub canonical_bytes: u64,
    /// Independently supplied minimum acknowledged local L2 block.
    pub l2_floor: ReplayFloor,
    /// Number of consecutive settlement records matched, starting at generation one.
    pub audited_records: u64,
    /// Last local block matched to a settlement; not an RPC finality assertion.
    pub last_settlement: Option<BlockNumHash>,
}

/// No consumer result escapes if the canonical snapshot or audit fails.
#[derive(Debug)]
pub enum CanonicalSettlementAuditErrorV1<E> {
    Canonical(BlockExecutionError),
    Consumer(E),
}

impl<E: std::fmt::Debug> std::fmt::Display for CanonicalSettlementAuditErrorV1<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical settlement audit refused: {self:?}")
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CanonicalSettlementAuditErrorV1<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Canonical(error) => error,
            Self::Consumer(error) => error,
        })
    }
}

struct BlockBinding {
    header: NodeHeaderV2,
    hash: B256,
    body_commitment: B256,
    deposits: u64,
}

/// Bind a recovery operation to a pinned canonical prefix and an independent
/// L2 rollback floor. The host must stop all source writers, including static
/// file writers, and select the chain configuration independently.
///
/// One MDBX view is retained while reading the complete prefix. Genesis,
/// parent/state linkage, configuration, complete signed bodies and budgets are
/// checked before invoking `recover`. Only bounded header/commitment data is
/// cached, not every body. A fresh reader checks the acknowledged tip again
/// before returning the consumer's result. A changed tip, ignored audit failure
/// or zero audited records discards that result.
///
/// The callback must only recover/validate; it must not publish intermediate
/// handles or heads. This read-only boundary neither verifies native authority
/// by itself nor calls Reth safe/finalized setters. It does not protect against
/// a compromised host or source writers violating the stopped-writer contract.
pub fn with_canonical_settlement_audit<T, E>(
    source: &BlochProviderFactory,
    policy: SettlementPolicyV1,
    floor: ReplayFloor,
    limits: ReplayLimits,
    recover: impl FnOnce(&mut CanonicalSettlementAuditV1) -> Result<T, E>,
) -> Result<(T, CanonicalSettlementAuditReportV1), CanonicalSettlementAuditErrorV1<E>> {
    let mut audit = load_snapshot(source, policy, floor, limits).map_err(CanonicalSettlementAuditErrorV1::Canonical)?;
    let result = recover(&mut audit).map_err(CanonicalSettlementAuditErrorV1::Consumer)?;
    if audit.poisoned || audit.report.audited_records == 0 {
        return Err(CanonicalSettlementAuditErrorV1::Canonical(invalid(
            "canonical settlement audit is incomplete",
        )));
    }
    let check = || -> Result<(), BlockExecutionError> {
        let current = source.database_provider_ro().map_err(BlockExecutionError::other)?;
        let number = audit.report.canonical_head.number;
        if current.best_block_number().map_err(BlockExecutionError::other)? != number {
            return Err(invalid("canonical head changed during settlement recovery"));
        }
        let header = current
            .sealed_header(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| invalid("canonical head disappeared during settlement recovery"))?;
        let expected = &audit.blocks[number as usize];
        if header.0 != expected.header || header.hash() != expected.hash || header.0.hash() != expected.hash {
            return Err(invalid("canonical head changed during settlement recovery"));
        }
        Ok(())
    };
    check().map_err(CanonicalSettlementAuditErrorV1::Canonical)?;
    Ok((result, audit.report))
}

fn load_snapshot(
    source: &BlochProviderFactory,
    policy: SettlementPolicyV1,
    floor: ReplayFloor,
    limits: ReplayLimits,
) -> Result<CanonicalSettlementAuditV1, BlockExecutionError> {
    let policy_commitment = policy.commitment().map_err(BlockExecutionError::other)?;
    let spec = source.chain_spec();
    if limits.blocks > MAX_SETTLEMENT_AUDIT_BLOCKS
        || policy.domain != spec.domain()
        || policy.chain_id != spec.execution().chain_id
        || policy.configuration != configuration_commitment(spec.execution()).map_err(BlockExecutionError::other)?
    {
        return Err(invalid(
            "settlement policy or canonical audit limit differs from the selected configuration",
        ));
    }
    let snapshot = source.database_provider_ro().map_err(BlockExecutionError::other)?;
    let height = snapshot.best_block_number().map_err(BlockExecutionError::other)?;
    if height > limits.blocks || floor.number > height || floor.hash.is_zero() || policy.first_l2_number - 1 > height {
        return Err(invalid(
            "canonical prefix is outside the audit budget, floor or settlement start",
        ));
    }
    let genesis = snapshot
        .sealed_header(0)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| invalid("canonical settlement audit genesis is missing"))?;
    if genesis.hash() != spec.genesis_hash()
        || genesis.0 != spec.genesis_header().0
        || genesis.0.hash() != genesis.hash()
    {
        return Err(invalid(
            "canonical settlement audit genesis differs from the selected configuration",
        ));
    }
    let mut blocks = Vec::with_capacity(height as usize + 1);
    blocks.push(BlockBinding {
        header: genesis.0.clone(),
        hash: genesis.hash(),
        body_commitment: B256::ZERO,
        deposits: 0,
    });
    let mut bytes = 0u64;
    for number in 1..=height {
        let block = snapshot
            .block_by_number(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| invalid("canonical settlement audit body is missing"))?;
        let canonical = snapshot
            .sealed_header(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| invalid("canonical settlement audit header is missing"))?;
        if block.header.0.number != number || block.header.0 != canonical.0 || block.header.0.hash() != canonical.hash()
        {
            return Err(invalid("canonical settlement audit block and header disagree"));
        }
        bytes = bytes
            .checked_add(block.length() as u64)
            .filter(|total| *total <= limits.bytes)
            .ok_or_else(|| invalid("canonical settlement audit byte budget exceeded"))?;
        spec.rules()
            .validate_link(&block.header.0, &blocks[number as usize - 1].header)
            .map_err(BlockExecutionError::other)?;
        let body = block.body.as_core();
        spec.rules()
            .validate_body(number, body)
            .map_err(BlockExecutionError::other)?;
        if body.transactions_root() != block.header.0.transactions_root
            || body.deposits_hash() != block.header.0.deposits_hash
        {
            return Err(invalid("canonical settlement audit body commitments disagree"));
        }
        blocks.push(BlockBinding {
            hash: canonical.hash(),
            body_commitment: keccak256(alloy_rlp::encode(body)),
            deposits: body.deposits.len() as u64,
            header: block.header.0,
        });
    }
    let initial = &blocks[(policy.first_l2_number - 1) as usize];
    if blocks[floor.number as usize].hash != floor.hash
        || initial.hash != policy.initial_l2_parent_hash
        || initial.header.state_root != policy.initial_l2_state_root
    {
        return Err(invalid(
            "canonical history conflicts with the independent floor or initial settlement parent",
        ));
    }
    let report = CanonicalSettlementAuditReportV1 {
        policy_commitment,
        genesis: genesis.hash(),
        canonical_head: BlockNumHash::new(height, blocks[height as usize].hash),
        canonical_bytes: bytes,
        l2_floor: floor,
        audited_records: 0,
        last_settlement: None,
    };
    Ok(CanonicalSettlementAuditV1 {
        policy,
        blocks,
        report,
        poisoned: false,
    })
}

fn invalid(message: &'static str) -> BlockExecutionError {
    BlockExecutionError::msg(message)
}
