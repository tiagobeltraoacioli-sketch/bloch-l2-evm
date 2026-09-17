// SPDX-License-Identifier: MIT OR Apache-2.0
//! Re-execute an acknowledged canonical prefix into separate fresh storage.
use crate::{prepare_genesis, validate_and_execute_block, BlochNextBlockEnvCtx, BlochNodeHeader, BlochProviderFactory};
use alloy_evm::block::BlockExecutionError;
use reth_chainspec::EthChainSpec;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use reth_provider::{
    providers::SaveBlocksMode, BlockNumReader, BlockReader, ChainSpecProvider, DBProvider, DatabaseProviderFactory,
    HeaderProvider,
};

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
    let spec = target.chain_spec();
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
    let expected_tip = source
        .sealed_header(height)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| BlockExecutionError::msg("recovery source checkpoint header is missing"))?;
    if expected_tip.hash() != expected_tip.0.hash() {
        return Err(BlockExecutionError::msg(
            "recovery source checkpoint seal is inconsistent",
        ));
    }
    if target.sealed_header(0).map_err(BlockExecutionError::other)?.is_some()
        || target.best_block_number().map_err(BlockExecutionError::other)? != 0
        || target.last_block_number().map_err(BlockExecutionError::other)? != 0
    {
        return Err(BlockExecutionError::msg("recovery target must be fresh storage"));
    }
    let genesis = prepare_genesis(&spec, target.latest().map_err(BlockExecutionError::other)?.as_ref())?;
    let writer = target.database_provider_rw().map_err(BlockExecutionError::other)?;
    writer
        .save_blocks(vec![genesis], SaveBlocksMode::Full)
        .map_err(BlockExecutionError::other)?;
    writer.commit().map_err(BlockExecutionError::other)?;
    let mut parent = source_genesis;
    for number in 1..=height {
        let block = source
            .block_by_number(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("recovery source block body is missing"))?;
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
    if parent != expected_tip {
        return Err(BlockExecutionError::msg(
            "recovery source canonical selection changed during replay",
        ));
    }
    Ok(parent)
}
