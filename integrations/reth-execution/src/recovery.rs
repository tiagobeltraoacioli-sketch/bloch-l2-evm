// SPDX-License-Identifier: MIT OR Apache-2.0
//! Re-execute an acknowledged canonical prefix into separate fresh storage.
use crate::{
    prepare_genesis, validate_and_execute_block, BlochChainSpec, BlochNextBlockEnvCtx, BlochNodeBlock, BlochNodeHeader,
    BlochProviderFactory,
};
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use reth_chainspec::EthChainSpec;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use reth_provider::{
    providers::SaveBlocksMode, BlockNumReader, BlockReader, ChainSpecProvider, DBProvider, DatabaseProviderFactory,
    HeaderProvider,
};

/// An independently retained lower bound on acknowledged canonical history.
/// A copy obtained only from the source under inspection cannot detect rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayFloor {
    /// Minimum acknowledged height, including genesis when explicitly selected.
    pub number: u64,
    /// Exact V2 header hash at that height, not an RPC finality assertion.
    pub hash: B256,
}

/// Explicit bounds on the completed prefix, excluding genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayLimits {
    /// Maximum number of non-genesis blocks to re-execute.
    pub blocks: u64,
    /// Maximum sum of canonical V2 block RLP lengths, including headers/bodies.
    /// This is not a bound on decoded heap, backend I/O, or execution time.
    pub bytes: u64,
}
impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            blocks: 10_000,
            bytes: 256 * 1024 * 1024,
        }
    }
}

/// Structural and resource inspection of a source prefix, before execution.
/// This value is informational; replay performs its own inspection again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayInspection {
    /// Last completed source MDBX checkpoint.
    pub head: SealedHeader<BlochNodeHeader>,
    /// Non-genesis block count.
    pub blocks: u64,
    /// Cumulative canonical V2 block RLP bytes, excluding genesis.
    pub bytes: u64,
    /// Independently supplied minimum acknowledged head, if any.
    pub floor: Option<ReplayFloor>,
}

/// Completed local replay accounting; it does not authenticate source selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Exact completed MDBX checkpoint reconstructed into the target.
    pub head: SealedHeader<BlochNodeHeader>,
    /// Number of re-executed non-genesis blocks.
    pub blocks: u64,
    /// Exact cumulative canonical V2 block bytes, excluding genesis.
    pub bytes: u64,
    /// The external lower bound checked, if the caller supplied one.
    pub floor: Option<ReplayFloor>,
}

/// Rebuild the source's MDBX-acknowledged prefix by validating and re-executing
/// every block into a fresh target. No source writes or in-place repair occur.
///
/// The host must stop source writers and trust the source's canonical selection
/// and target configuration. Derivation attributes are recovered from recorded
/// blocks, not authenticated against L1: this is local recovery, not a new import
/// authorization. Open the source read-only for an enforced storage boundary.
///
/// An error leaves the separate target incomplete; it never publishes a running
/// node. Missing/corrupt source bodies fail closed. Only the last completed MDBX
/// checkpoint is replayed; static-file rows ahead of it are not acknowledged.
pub fn replay_canonical_prefix(
    source: &BlochProviderFactory,
    target: &BlochProviderFactory,
) -> Result<SealedHeader<BlochNodeHeader>, BlockExecutionError> {
    replay_canonical_prefix_with_limits(source, target, None, ReplayLimits::default()).map(|outcome| outcome.head)
}

/// Re-execute with an optional independently selected rollback floor and budget.
///
/// Height/floor, complete bodies, canonical linkage and cumulative encoded bytes
/// are checked before writing target genesis. A preflight limit refusal leaves
/// target genesis unwritten. Later source, execution or publication failures can
/// leave an incomplete target, which must not be served or automatically retried.
///
/// The floor is a minimum, permitting a complete extra commit after a lost
/// acknowledgement. Without it, deleting a valid source suffix is undetectable.
pub fn replay_canonical_prefix_with_limits(
    source: &BlochProviderFactory,
    target: &BlochProviderFactory,
    floor: Option<ReplayFloor>,
    limits: ReplayLimits,
) -> Result<ReplayOutcome, BlockExecutionError> {
    let spec = target.chain_spec();
    // Retain one completed MDBX view across preflight and replay. The source
    // must still be stopped: this does not lock external static-file writers.
    let source = source.database_provider_ro().map_err(BlockExecutionError::other)?;
    if target.sealed_header(0).map_err(BlockExecutionError::other)?.is_some()
        || target.best_block_number().map_err(BlockExecutionError::other)? != 0
        || target.last_block_number().map_err(BlockExecutionError::other)? != 0
    {
        return Err(BlockExecutionError::msg("recovery target must be fresh storage"));
    }
    let inspection = inspect_prefix(&source, &spec, floor, limits)?;
    let height = inspection.blocks;
    let expected_tip = inspection.head;
    let source_genesis = source
        .sealed_header(0)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| BlockExecutionError::msg("recovery source genesis is missing"))?;
    let genesis = prepare_genesis(&spec, target.latest().map_err(BlockExecutionError::other)?.as_ref())?;
    let writer = target.database_provider_rw().map_err(BlockExecutionError::other)?;
    writer
        .save_blocks(vec![genesis], SaveBlocksMode::Full)
        .map_err(BlockExecutionError::other)?;
    writer.commit().map_err(BlockExecutionError::other)?;
    let mut parent = source_genesis;
    let mut replayed_bytes = 0u64;
    for number in 1..=height {
        let block = source
            .block_by_number(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("recovery source block body is missing"))?;
        replayed_bytes = account_bytes(replayed_bytes, block.length() as u64, limits.bytes)?;
        let block = SealedBlock::seal_slow(block);
        let canonical = source
            .sealed_header(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("recovery source canonical header is missing"))?;
        if block.sealed_header() != &canonical {
            return Err(BlockExecutionError::msg(
                "recovery source block and canonical seal disagree",
            ));
        }
        let expected = BlochNextBlockEnvCtx {
            timestamp: block.header().0.timestamp,
            prevrandao: block.header().0.prevrandao,
            anchor_root: block.header().0.anchor_root,
            deposits: block.body().as_core().deposits.clone(),
        };
        let executed = validate_and_execute_block(
            &spec,
            target.latest().map_err(BlockExecutionError::other)?.as_ref(),
            &parent,
            &block,
            expected,
        )?;
        let writer = target.database_provider_rw().map_err(BlockExecutionError::other)?;
        writer
            .save_blocks(vec![executed], SaveBlocksMode::Full)
            .map_err(BlockExecutionError::other)?;
        writer.commit().map_err(BlockExecutionError::other)?;
        parent = canonical;
    }
    if parent != expected_tip || replayed_bytes != inspection.bytes {
        return Err(BlockExecutionError::msg(
            "recovery source canonical selection changed during replay",
        ));
    }
    Ok(ReplayOutcome {
        head: parent,
        blocks: height,
        bytes: replayed_bytes,
        floor,
    })
}

/// Inspect a stopped source before creating/opening any writable target.
/// This checks identity, floor, complete canonical bodies and budgets, not EVM
/// execution or native authorization. The caller must keep source writers stopped.
pub fn inspect_canonical_prefix(
    source: &BlochProviderFactory,
    spec: &BlochChainSpec,
    floor: Option<ReplayFloor>,
    limits: ReplayLimits,
) -> Result<ReplayInspection, BlockExecutionError> {
    let snapshot = source.database_provider_ro().map_err(BlockExecutionError::other)?;
    inspect_prefix(&snapshot, spec, floor, limits)
}

fn inspect_prefix(
    source: &impl BlockReader<Block = BlochNodeBlock, Header = BlochNodeHeader>,
    spec: &BlochChainSpec,
    floor: Option<ReplayFloor>,
    limits: ReplayLimits,
) -> Result<ReplayInspection, BlockExecutionError> {
    let source_genesis = source
        .sealed_header(0)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| BlockExecutionError::msg("recovery source genesis is missing"))?;
    if source_genesis.hash() != spec.genesis_hash() || source_genesis.0 != spec.genesis_header().0 {
        return Err(BlockExecutionError::msg(
            "recovery source genesis disagrees with target configuration",
        ));
    }
    let height = source.best_block_number().map_err(BlockExecutionError::other)?;
    if height > limits.blocks {
        return Err(BlockExecutionError::msg("recovery block budget exceeded"));
    }
    let expected_tip = source
        .sealed_header(height)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| BlockExecutionError::msg("recovery source checkpoint header is missing"))?;
    if expected_tip.hash() != expected_tip.0.hash() {
        return Err(BlockExecutionError::msg(
            "recovery source checkpoint seal is inconsistent",
        ));
    }
    if let Some(floor) = floor {
        if floor.hash.is_zero() || floor.number > height {
            return Err(BlockExecutionError::msg("recovery source is below the retained floor"));
        }
        let retained = source
            .sealed_header(floor.number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("recovery retained floor header is missing"))?;
        if retained.hash() != floor.hash || retained.0.hash() != floor.hash {
            return Err(BlockExecutionError::msg(
                "recovery source conflicts with retained floor",
            ));
        }
    }
    let mut bytes = 0u64;
    let mut previous = source_genesis.clone();
    for number in 1..=height {
        let block = source
            .block_by_number(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("recovery source block body is missing"))?;
        let canonical = source
            .sealed_header(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("recovery source canonical header is missing"))?;
        if block.header.0.number != number
            || block.header.0 != canonical.0
            || block.header.0.hash() != canonical.hash()
            || block.header.0.parent_hash != previous.hash()
        {
            return Err(BlockExecutionError::msg(
                "recovery source canonical prefix is inconsistent",
            ));
        }
        bytes = account_bytes(bytes, block.length() as u64, limits.bytes)?;
        previous = canonical;
    }
    if previous != expected_tip {
        return Err(BlockExecutionError::msg("recovery source preflight tip changed"));
    }
    Ok(ReplayInspection {
        head: expected_tip,
        blocks: height,
        bytes,
        floor,
    })
}

fn account_bytes(total: u64, next: u64, limit: u64) -> Result<u64, BlockExecutionError> {
    total
        .checked_add(next)
        .filter(|total| *total <= limit)
        .ok_or_else(|| BlockExecutionError::msg("recovery byte budget exceeded"))
}

#[cfg(test)]
mod tests {
    use super::account_bytes;

    #[test]
    fn byte_accounting_accepts_exact_limit_and_rejects_overflow() {
        assert_eq!(account_bytes(100, 200, 300).unwrap(), 300);
        assert_eq!(account_bytes(0, 0, 0).unwrap(), 0);
        assert_eq!(account_bytes(u64::MAX - 1, 1, u64::MAX).unwrap(), u64::MAX);
        assert!(account_bytes(100, 201, 300).is_err());
        assert!(account_bytes(u64::MAX, 1, u64::MAX).is_err());
    }
}
