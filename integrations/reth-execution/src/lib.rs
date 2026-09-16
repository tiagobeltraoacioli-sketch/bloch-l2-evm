// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bloch execution through Reth state providers and the Alloy EVM factory.
//!
//! Includes custom primitives, provider types and deposit-body storage, but no
//! launched node, RPC, pool, canonical recovery service or finality.
//! The provider snapshot and roots are trusted host inputs. Signed Ethereum
//! bytes are authenticated by the existing Bloch kernel, not a sender cache.

use alloy_primitives::B256;
use bloch_l2_evm::{
    execute_signed_block_on_database, BlockContext, BlockExecutionError, ChainSpec, DatabaseBlockExecution,
    DepositMint, SignedBlockBuilder, SignedBlockInput, SignedInputError,
};
use reth_revm::database::{EvmStateProvider, StateProviderDatabase};

pub mod block;
pub mod chainspec;
pub mod config;
pub mod consensus;
pub use consensus::BlochConsensus;
pub mod execute;
pub use chainspec::BlochChainSpec;
pub use execute::{execute_next_block, prepare_genesis, validate_and_execute_block};
pub mod payload;
pub use payload::{BlochBuiltPayload, BlochExecutionPayload, BlochPayloadAttributes, BlochPayloadTypes};
/// Complete type selection for a provider; does not launch a node or Engine API.
#[derive(Clone, Debug, Default)]
pub struct BlochNodeTypes;

impl reth_node_types::NodeTypes for BlochNodeTypes {
    type Primitives = BlochNodePrimitives;
    type ChainSpec = BlochChainSpec;
    type Storage = BlochChainStorage;
    type Payload = BlochPayloadTypes;
}
pub mod node_factory;
pub mod primitives;
pub mod storage;
pub use block::{
    BlochBlockExecutionCtx, BlochBlockExecutor, BlochBlockExecutorFactory, BlochBlockFinish,
    BlochNodeBlockExecutorFactory, BlochNodeBlockFinish, BlochTxResult,
};
pub use config::{BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeBlockAssembler};
pub use node_factory::{BlochRethBlockExecutor, BlochRethBlockExecutorFactory, BlochRethBlockFinish};
pub use primitives::{
    BlochNodeBlock, BlochNodeBody, BlochNodeHeader, BlochNodePrimitives, BlochRethReceipt, BlochRethTransaction,
};
pub use storage::{BlochChainStorage, BlochTables, BlochV2Deposits, StoredBlochDeposits};

pub mod context;
pub mod factory;
pub use context::BlochContext;
pub use factory::{BlochEvm, BlochEvmFactory};

pub mod bundle;
pub use bundle::{execution_bundle, BundleError};

/// Run against a Reth state provider without committing its storage.
///
/// An actual Reth `StateProvider` implements `EvmStateProvider` via upstream's
/// blanket implementation. The caller supplies the snapshot's real MPT root
/// and independently authenticated deposit/anchor context. Compute the full
/// post-state root and persist the returned overlay separately. Neither roots
/// nor L1 trust are established by this adapter.
pub fn execute_on_provider<P: EvmStateProvider>(
    spec: &ChainSpec,
    provider: P,
    previous_root: B256,
    input: &SignedBlockInput,
) -> Result<DatabaseBlockExecution<StateProviderDatabase<P>>, SignedInputError<BlockExecutionError>> {
    execute_signed_block_on_database(spec, StateProviderDatabase::new(provider), previous_root, input)
}

/// Begin incremental signed construction against a consistent Reth snapshot.
///
/// Each candidate is authenticated from signed bytes and may be skipped without
/// publishing its state or accounting changes. The caller authenticates L1
/// context/deposits and supplies the snapshot's trusted root, just as for
/// [`execute_on_provider`]. Finishing yields an execution usable with
/// [`execution_bundle`]; it does not calculate a root or persist the block.
pub fn begin_on_provider<P: EvmStateProvider>(
    spec: &ChainSpec,
    provider: P,
    previous_root: B256,
    context: BlockContext,
    deposits: Vec<DepositMint>,
) -> Result<SignedBlockBuilder<StateProviderDatabase<P>>, SignedInputError<BlockExecutionError>> {
    SignedBlockBuilder::new(
        spec,
        StateProviderDatabase::new(provider),
        previous_root,
        context,
        deposits,
    )
}
