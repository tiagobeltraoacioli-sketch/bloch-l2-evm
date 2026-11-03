// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bloch execution through Reth state providers and the Alloy EVM factory.
//!
//! Includes custom primitives, provider types, deposit-body storage, pool
//! maintenance, RPC handlers and HTTP transport. Node orchestration, crash recovery and finality
//! remain separate integration work.
//! The provider snapshot and roots are trusted host inputs. Signed Ethereum
//! bytes are authenticated by the existing Bloch kernel, not a sender cache.

use alloy_primitives::B256;
use bloch_l2_evm::{
    execute_signed_block_on_database, BlockContext, BlockExecutionError, ChainSpec, DatabaseBlockExecution,
    DepositMint, SignedBlockBuilder, SignedBlockInput, SignedInputError,
};
use reth_revm::database::{EvmStateProvider, StateProviderDatabase};

pub mod async_finality_cursor;
pub mod block;
pub mod canonical;
pub mod chainspec;
pub use canonical::{BlochBlockchainProvider, BlochProviderFactory, CanonicalCoordinator};
pub mod config;
pub mod consensus;
pub use consensus::BlochConsensus;
pub mod execute;
pub use chainspec::BlochChainSpec;
pub use execute::{execute_next_block, prepare_genesis, validate_and_execute_block};
pub mod finality_cursor;
pub mod lifecycle;
pub mod maintenance;
pub mod network;
pub use network::{L2Network, DEVNET_DOMAIN};
pub mod payload;
pub mod pool;
pub mod proof_export;
pub mod recovery;
pub mod settlement_binding;
pub use recovery::{
    inspect_canonical_prefix, replay_canonical_prefix, replay_canonical_prefix_with_limits, ReplayFloor,
    ReplayInspection, ReplayLimits, ReplayOutcome,
};
pub mod rpc;
pub mod rpc_identity;
pub mod rpc_transport;
pub mod rpc_types;
pub use lifecycle::{
    acknowledge_recovered_runtime, initialize_runtime_record, read_runtime_record, read_runtime_record_with_floor,
    runtime_receipt_tip, DurableHead, RuntimeIdentity, RuntimeLease, RuntimeReceiptFloor, RuntimeRecord, RuntimeStatus,
    SettlementCursor,
};
pub use maintenance::{pool_maintenance, MaintenanceConfigError};
pub use payload::{BlochBuiltPayload, BlochExecutionPayload, BlochPayloadAttributes, BlochPayloadTypes};
pub use pool::{pooled_from_raw, BlochPoolError, BlochTransactionValidator};
pub use rpc::{
    build_eth_api, build_eth_api_capped, build_eth_api_with, rpc_converter, serve_pending_blocks_as_latest, BlochRpcComponents, BlochRpcConverter,
    LatestDerivedPending, NoDerivedPending, PendingPolicy,
};
pub use rpc_identity::{
    chain_identity_rpc, chain_status_rpc, BlochChainIdentity, BlochChainStatus, CHAIN_IDENTITY_FORMAT,
    CHAIN_STATUS_FORMAT, HEADER_FORMAT,
};
pub use rpc_transport::{
    start_http_rpc, start_ws_rpc, RPC_MAX_BATCH_CALLS, RPC_MAX_HTTP_CONNECTIONS, RPC_MAX_REQUEST_BYTES, RPC_MAX_RESPONSE_BYTES,
};
pub use rpc_types::{BlochHeaderConverter, BlochRpcHeader, BlochRpcTypes};
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
pub mod supervisor;
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
pub use supervisor::DurableCanonicalSupervisor;

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
