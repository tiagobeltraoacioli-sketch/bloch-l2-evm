// SPDX-License-Identifier: MIT OR Apache-2.0
//! Construct a fully executed V2 block against one consistent provider snapshot.
use crate::{
    BlochChainSpec, BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeBlock, BlochNodeBody, BlochNodeHeader,
    BlochNodePrimitives, BlochRethTransaction,
};
use alloy_consensus::transaction::Recovered;
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{BlockExecutionError, BlockExecutor, BlockExecutorFactory},
    Evm, EvmFactory,
};
use alloy_primitives::{Address, U256};
use bloch_l2_evm::node_primitives::NodeBodyV2;
use bloch_l2_evm::transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS};
use reth_chain_state::ExecutedBlock;
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, FullConsensus, HeaderValidator};
use reth_evm::{
    execute::{BlockAssembler, BlockAssemblerInput},
    ConfigureEvm,
};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{BlockBody, RecoveredBlock, SealedBlock, SealedHeader};
use reth_provider::StateProvider;
use reth_revm::{
    database::StateProviderDatabase,
    revm::{
        database::{states::bundle_state::BundleRetention, BundleState, State},
        state::{AccountInfo, Bytecode},
    },
};
use reth_trie_common::ComputedTrieData;
use std::sync::Arc;

/// Validate and re-execute a received block before handing it to persistence.
///
/// `expected` must come from the caller's authenticated derivation, not from the
/// received block. Matching it prevents an otherwise valid block from selecting
/// its own deposits, anchor, randomness or timestamp. This API does not perform
/// L1 finality verification itself. The configured domain/genesis and canonical
/// parent must also be trusted by the caller.
///
/// Header/body checks and actual execution receipts are validated through Reth's
/// custom consensus traits. Re-execution then compares the entire V2 header,
/// including the independently computed state root, which those traits cannot
/// check alone. No failed import commits state. Successful imports retain the
/// same snapshot/serialization requirements as [`execute_next_block`].
pub fn validate_and_execute_block(
    spec: &BlochChainSpec,
    provider: &dyn StateProvider,
    parent: &SealedHeader<BlochNodeHeader>,
    block: &SealedBlock<BlochNodeBlock>,
    expected: BlochNextBlockEnvCtx,
) -> Result<ExecutedBlock<BlochNodePrimitives>, BlockExecutionError> {
    let header = &block.header().0;
    if header.timestamp != expected.timestamp
        || header.prevrandao != expected.prevrandao
        || header.anchor_root != expected.anchor_root
        || block.body().as_core().deposits != expected.deposits
    {
        return Err(BlockExecutionError::msg(
            "V2 block disagrees with authenticated derivation inputs",
        ));
    }
    let consensus = crate::BlochConsensus::new(Arc::new(spec.clone()));
    consensus
        .validate_block_pre_execution(block)
        .map_err(BlockExecutionError::other)?;
    consensus
        .validate_header_against_parent(block.sealed_header(), parent)
        .map_err(BlockExecutionError::other)?;
    let config = BlochEvmConfig::new(spec.execution(), spec.domain());
    let executed = execute_next_block(
        &config,
        provider,
        parent,
        expected,
        block.body().transactions().to_vec(),
    )?;
    // Post-execution checks must use the received header rather than the one we built.
    let incoming = RecoveredBlock::try_recover_sealed(block.clone()).map_err(BlockExecutionError::other)?;
    consensus
        .validate_block_post_execution(&incoming, &executed.execution_output.result, None, None)
        .map_err(BlockExecutionError::other)?;
    if executed.recovered_block().header() != block.header() {
        return Err(BlockExecutionError::msg(
            "V2 imported header disagrees with re-execution",
        ));
    }
    Ok(executed)
}

/// Prepare the configured zero-issuance genesis on an empty state snapshot.
///
/// Persist with Reth `save_blocks(..., SaveBlocksMode::Full)` so even the empty
/// genesis establishes receipt/static-file boundaries and pipeline checkpoints.
/// The returned genesis reverts also initialize allocation history indices.
/// Existing databases initialized without those indices need separate repair
/// or replay; this constructor does not migrate an initialized database.
/// The caller must also ensure the chain database has no existing block history;
/// an empty state root alone does not prove an uninitialized database.
pub fn prepare_genesis(
    spec: &BlochChainSpec,
    provider: &dyn StateProvider,
) -> Result<ExecutedBlock<BlochNodePrimitives>, BlockExecutionError> {
    let before = provider
        .state_root(Default::default())
        .map_err(BlockExecutionError::other)?;
    if before != spec.genesis_header().0.parent_state_root {
        return Err(BlockExecutionError::msg("V2 genesis requires an empty state snapshot"));
    }
    let mut builder = BundleState::builder(0..=0);
    for (address, allocation) in &spec.genesis().alloc {
        let code = Bytecode::new_raw(allocation.code.clone().unwrap_or_default());
        let code_hash = code.hash_slow();
        builder = builder
            .state_address(*address)
            .state_present_account_info(
                *address,
                AccountInfo {
                    balance: allocation.balance,
                    nonce: allocation.nonce.unwrap_or_default(),
                    code_hash,
                    code: Some(code.clone()),
                    ..Default::default()
                },
            )
            .contract(code_hash, code)
            // Full persistence derives history indices from the reverts. The
            // allocation starts on empty state, so its prior account is absent.
            .revert_account_info(0, *address, Some(None));
        builder.set_state_storage(
            *address,
            allocation
                .storage
                .iter()
                .flatten()
                .map(|(key, value)| (U256::from_be_bytes(key.0), (U256::ZERO, U256::from_be_bytes(value.0))))
                .collect(),
        );
        builder.set_revert_storage(
            0,
            *address,
            allocation
                .storage
                .iter()
                .flatten()
                .map(|(key, _)| (U256::from_be_bytes(key.0), U256::ZERO))
                .collect(),
        );
    }
    let bundle = builder.build();
    let hashed = provider.hashed_post_state(&bundle);
    let (root, updates) = provider
        .state_root_with_updates(hashed.clone())
        .map_err(BlockExecutionError::other)?;
    if root != spec.genesis_header().0.state_root {
        return Err(BlockExecutionError::msg(
            "V2 genesis allocation root disagrees with header",
        ));
    }
    let block = BlochNodeBlock {
        header: spec.genesis_header().clone(),
        body: BlochNodeBody::try_from_core(NodeBodyV2::default()).map_err(BlockExecutionError::other)?,
    };
    Ok(ExecutedBlock::new(
        Arc::new(RecoveredBlock::try_recover(block).map_err(BlockExecutionError::other)?),
        Arc::new(BlockExecutionOutput {
            result: Default::default(),
            state: bundle,
        }),
        ComputedTrieData::new(Arc::new(hashed.into_sorted()), Arc::new(updates.into_sorted())),
    ))
}

/// Execute every supplied canonical signed transaction and calculate the actual
/// database trie root before assembling a V2 block ready for Reth `save_blocks`.
///
/// The caller authenticates the parent, domain and deposit/anchor inputs and must
/// supply a consistent snapshot. This verifies its root against the parent but
/// does not establish L1 finality. No storage is committed by this operation;
/// any error discards its provisional state. Persistence and fork choice remain
/// separate responsibilities. Reverted user transactions still produce receipts.
/// The result does not reserve the canonical tip: the persistence coordinator
/// must ensure this snapshot's parent is still current before saving the block.
pub fn execute_next_block(
    config: &BlochEvmConfig,
    provider: &dyn StateProvider,
    parent: &SealedHeader<BlochNodeHeader>,
    attributes: BlochNextBlockEnvCtx,
    transactions: Vec<BlochRethTransaction>,
) -> Result<ExecutedBlock<BlochNodePrimitives>, BlockExecutionError> {
    if transactions.len() > MAX_SIGNED_TRANSACTIONS {
        return Err(BlockExecutionError::msg("V2 transaction count limit exceeded"));
    }
    let mut bytes = 0usize;
    for transaction in &transactions {
        let length = transaction.encode_2718_len();
        if length > MAX_RAW_TRANSACTION_BYTES {
            return Err(BlockExecutionError::msg("V2 transaction size limit exceeded"));
        }
        bytes = bytes
            .checked_add(length)
            .filter(|bytes| *bytes <= MAX_SIGNED_BLOCK_BYTES)
            .ok_or_else(|| BlockExecutionError::msg("V2 transaction byte budget exceeded"))?;
    }
    let env = config.next_evm_env(parent, &attributes)?;
    let context = config.context_for_next_block(parent, attributes)?;
    if parent.hash() != parent.0.hash() {
        return Err(BlockExecutionError::msg("V2 parent seal disagrees with canonical hash"));
    }
    let before = provider
        .state_root(Default::default())
        .map_err(BlockExecutionError::other)?;
    if before != parent.0.state_root {
        return Err(BlockExecutionError::msg("V2 snapshot root disagrees with parent"));
    }
    let database = State::builder()
        .with_database(StateProviderDatabase::new(provider))
        .with_bundle_update()
        .build();
    let factory = config.block_executor_factory();
    let evm = factory.evm_factory().create_evm(database, env.clone());
    let mut executor = factory.create_executor(evm, context.clone());
    executor.apply_pre_execution_changes()?;
    for transaction in &transactions {
        // The executor authenticates signed bytes; this sender cache is ignored.
        let candidate = executor
            .execute_transaction_without_commit(Recovered::new_unchecked(transaction.clone(), Address::ZERO))?;
        executor.checked_commit_transaction(candidate)?;
    }
    let (evm, result, finished) = executor.finish_node()?;
    let mut database = evm.finish().0;
    database.merge_transitions(BundleRetention::Reverts);
    let bundle = database.take_bundle();
    let hashed = provider.hashed_post_state(&bundle);
    let (root, updates) = provider
        .state_root_with_updates(hashed.clone())
        .map_err(BlockExecutionError::other)?;
    let block = config.block_assembler().assemble_block(BlockAssemblerInput::new(
        env,
        context,
        parent,
        transactions,
        &result,
        &bundle,
        provider,
        root,
        None,
    ))?;
    if block.header.0 != finished.finalize(root).header {
        return Err(BlockExecutionError::msg(
            "V2 assembly disagrees with committed execution",
        ));
    }
    let recovered = RecoveredBlock::try_recover(block).map_err(BlockExecutionError::other)?;
    Ok(ExecutedBlock::new(
        Arc::new(recovered),
        Arc::new(BlockExecutionOutput { result, state: bundle }),
        ComputedTrieData::new(Arc::new(hashed.into_sorted()), Arc::new(updates.into_sorted())),
    ))
}
