// SPDX-License-Identifier: MIT OR Apache-2.0
//! Serialized canonical extension and publication after durable persistence.
use crate::{
    execute_next_block, BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeHeader, BlochNodeTypes, BlochRethTransaction,
};
use alloy_eips::{eip2718::Decodable2718, BlockNumHash};
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::{keccak256, B256, U256};
use bloch_l2_evm::node_execution::select::{select_node_transactions, BlockSelection, SelectionLimits};
use reth_chain_state::CanonStateNotification;
use reth_chainspec::EthChainSpec;
use reth_db::DatabaseEnv;
use reth_execution_types::{Chain, ExecutionOutcome};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    providers::{BlockchainProvider, SaveBlocksMode},
    BlockExecutionWriter, BlockNumReader, ChainSpecProvider, DBProvider, DatabaseProviderFactory, HeaderProvider,
    ProviderFactory,
};
use std::sync::Arc;

pub type BlochProviderFactory = ProviderFactory<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;
pub type BlochBlockchainProvider = BlockchainProvider<NodeTypesWithDBAdapter<BlochNodeTypes, Arc<DatabaseEnv>>>;

/// Remove the head block, an unsettled one the caller names by hash, from every
/// backend, and return its new head. Nothing else may write this database.
///
/// The one case that needs it: L1 replaced the program while the head was still
/// unsettled, so that block can no longer be proved under the rules it ran.
pub fn rewind_canonical_head(
    factory: &BlochProviderFactory,
    expected: B256,
) -> Result<SealedHeader<BlochNodeHeader>, BlockExecutionError> {
    let number = factory.best_block_number().map_err(BlockExecutionError::other)?;
    if number == 0 {
        return Err(BlockExecutionError::msg("the L2 genesis cannot be rewound"));
    }
    let head = factory
        .sealed_header(number)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| BlockExecutionError::msg("canonical head is missing"))?;
    if head.hash() != expected {
        return Err(BlockExecutionError::msg(
            "the canonical head is not the block to rewind",
        ));
    }
    let writer = factory.database_provider_rw().map_err(BlockExecutionError::other)?;
    writer
        .remove_block_and_execution_above(number - 1)
        .map_err(BlockExecutionError::other)?;
    writer.commit().map_err(BlockExecutionError::other)?;
    let parent = factory
        .sealed_header(number - 1)
        .map_err(BlockExecutionError::other)?
        .ok_or_else(|| BlockExecutionError::msg("parent of the rewound head is missing"))?;
    let root = factory
        .latest()
        .map_err(BlockExecutionError::other)?
        .state_root(Default::default())
        .map_err(BlockExecutionError::other)?;
    if factory.best_block_number().map_err(BlockExecutionError::other)? != number - 1 || root != parent.0.state_root {
        return Err(BlockExecutionError::msg(
            "the rewound database does not match its parent",
        ));
    }
    Ok(parent)
}

/// Own the sole canonical writer for an initialized database.
///
/// All external factory/provider clones must be used only for reads. Concurrent
/// direct writes and other coordinators are outside this ownership contract.
/// This component extends the selected head; it does not choose forks, verify L1
/// derivation, initialize genesis or repair a crashed database.
pub struct CanonicalCoordinator {
    factory: BlochProviderFactory,
    provider: BlochBlockchainProvider,
    head: SealedHeader<BlochNodeHeader>,
    poisoned: bool,
}

impl CanonicalCoordinator {
    /// Attach to a configured, initialized head after checking its identity and root.
    /// Checks every configured genesis allocation through historical reads, so
    /// databases missing genesis history indices fail closed. This requires an
    /// archival database; it does not repair indices or cross-backend crash damage.
    pub fn attach(factory: BlochProviderFactory) -> Result<Self, BlockExecutionError> {
        crate::finality_cursor::reject_unverified_finality_markers(&factory)?;
        let spec = factory.chain_spec();
        let number = factory.best_block_number().map_err(BlockExecutionError::other)?;
        if factory.last_block_number().map_err(BlockExecutionError::other)? != number {
            return Err(BlockExecutionError::msg(
                "canonical header and execution checkpoints disagree",
            ));
        }
        let genesis = factory
            .sealed_header(0)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("canonical genesis is missing"))?;
        if genesis.hash() != spec.genesis_hash() || genesis.0 != spec.genesis_header().0 {
            return Err(BlockExecutionError::msg(
                "canonical genesis disagrees with configured domain",
            ));
        }
        let head = factory
            .sealed_header(number)
            .map_err(BlockExecutionError::other)?
            .ok_or_else(|| BlockExecutionError::msg("canonical head is missing"))?;
        if head.hash() != head.0.hash() {
            return Err(BlockExecutionError::msg("canonical head seal disagrees with header"));
        }
        let state = factory.latest().map_err(BlockExecutionError::other)?;
        let root = state
            .state_root(Default::default())
            .map_err(BlockExecutionError::other)?;
        if root != head.0.state_root {
            return Err(BlockExecutionError::msg("canonical head and state root disagree"));
        }
        let recorded = bloch_l2_evm::node_execution::node_head_on_database(
            spec.execution(),
            spec.domain(),
            reth_revm::database::StateProviderDatabase::new(state.as_ref()),
            root,
        )
        .map_err(BlockExecutionError::other)?;
        if recorded != head.0 {
            return Err(BlockExecutionError::msg(
                "canonical head and committed metadata disagree",
            ));
        }
        drop(state);
        let historical = factory
            .history_by_block_hash(spec.genesis_hash())
            .map_err(BlockExecutionError::other)?;
        for (address, allocation) in &spec.genesis().alloc {
            let account = historical
                .basic_account(address)
                .map_err(BlockExecutionError::other)?
                .ok_or_else(|| BlockExecutionError::msg("historical genesis account is missing"))?;
            let code = allocation.code.clone().unwrap_or_default();
            let code_hash = keccak256(&code);
            if account.nonce != allocation.nonce.unwrap_or_default()
                || account.balance != allocation.balance
                || account.bytecode_hash.unwrap_or(alloy_primitives::KECCAK256_EMPTY) != code_hash
            {
                return Err(BlockExecutionError::msg(
                    "historical genesis account disagrees with allocation",
                ));
            }
            if !code.is_empty() {
                let stored = historical
                    .bytecode_by_hash(&code_hash)
                    .map_err(BlockExecutionError::other)?
                    .ok_or_else(|| BlockExecutionError::msg("historical genesis bytecode is missing"))?;
                if stored.original_bytes() != code {
                    return Err(BlockExecutionError::msg(
                        "historical genesis bytecode disagrees with allocation",
                    ));
                }
            }
            for (slot, value) in allocation.storage.iter().flatten() {
                let stored = historical
                    .storage(*address, *slot)
                    .map_err(BlockExecutionError::other)?
                    .unwrap_or_default();
                if stored != U256::from_be_bytes(value.0) {
                    return Err(BlockExecutionError::msg(
                        "historical genesis storage disagrees with allocation",
                    ));
                }
            }
        }
        drop(historical);
        let provider = BlockchainProvider::new(factory.clone()).map_err(BlockExecutionError::other)?;
        Ok(Self {
            factory,
            provider,
            head,
            poisoned: false,
        })
    }

    /// Read/query provider sharing the canonical notification channel.
    pub fn provider(&self) -> BlochBlockchainProvider {
        self.provider.clone()
    }

    pub fn head(&self) -> &SealedHeader<BlochNodeHeader> {
        &self.head
    }

    /// A persistence error can leave static files/RocksDB ahead of MDBX.
    /// A poisoned coordinator must be discarded and storage independently checked.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Deterministically select, from `candidates` (canonical signed bytes),
    /// the user transactions for the next block on the current head, after the
    /// block's `attributes.deposits` are minted. Reads the latest state only;
    /// nothing is executed into storage. See
    /// [`bloch_l2_evm::node_execution::select`] for order and reasons.
    pub fn select_pending(
        &self,
        attributes: &BlochNextBlockEnvCtx,
        candidates: &[alloy_primitives::Bytes],
        limits: SelectionLimits,
    ) -> Result<BlockSelection, BlockExecutionError> {
        let spec = self.factory.chain_spec();
        let config = BlochEvmConfig::for_chain(&spec);
        let context = config.next_context(self.head.header(), attributes)?;
        let state = self.factory.latest().map_err(BlockExecutionError::other)?;
        select_node_transactions(
            spec.execution_at(context.number),
            spec.domain(),
            reth_revm::database::StateProviderDatabase::new(state.as_ref()),
            self.head.0.state_root,
            &context,
            &attributes.deposits,
            candidates,
            limits,
        )
        .map_err(BlockExecutionError::other)
    }

    /// [`Self::select_pending_after_forced`] (or [`Self::select_pending`] when `forced` is empty) with the
    /// producer's write price judged inside the selection (review R308-3P-2): a transaction that would add
    /// storage slots it does not pay for is left out and reported; the block body is `forced.included` followed
    /// by the selection's transactions, in that order.
    pub fn select_pending_priced(
        &self,
        attributes: &BlochNextBlockEnvCtx,
        forced: &[bloch_l2_evm::forced_inclusion::ForcedTransaction],
        candidates: &[alloy_primitives::Bytes],
        limits: SelectionLimits,
        price: &bloch_l2_evm::node_execution::select::WritePrice,
    ) -> Result<
        (
            bloch_l2_evm::forced_inclusion::ForcedSelection,
            BlockSelection,
            bloch_l2_evm::node_execution::select::LeftUnpaid,
        ),
        BlockExecutionError,
    > {
        let spec = self.factory.chain_spec();
        let config = BlochEvmConfig::for_chain(&spec);
        let context = config.next_context(self.head.header(), attributes)?;
        let state = self.factory.latest().map_err(BlockExecutionError::other)?;
        bloch_l2_evm::node_execution::select::select_node_transactions_priced_after_forced(
            spec.execution_at(context.number),
            spec.domain(),
            reth_revm::database::StateProviderDatabase::new(state.as_ref()),
            self.head.0.state_root,
            &context,
            &attributes.deposits,
            forced,
            candidates,
            limits,
            price,
        )
        .map_err(BlockExecutionError::other)
    }

    /// CANDIDATE (forced inclusion): the forced envelopes L1 names for this
    /// block, by the rule of `bloch_l2_evm::forced_inclusion`, then
    /// [`Self::select_pending`] after them. The block body is
    /// `forced.included` followed by the selection's transactions.
    pub fn select_pending_after_forced(
        &self,
        attributes: &BlochNextBlockEnvCtx,
        forced: &[bloch_l2_evm::forced_inclusion::ForcedTransaction],
        candidates: &[alloy_primitives::Bytes],
        limits: SelectionLimits,
    ) -> Result<(bloch_l2_evm::forced_inclusion::ForcedSelection, BlockSelection), BlockExecutionError> {
        let spec = self.factory.chain_spec();
        let config = BlochEvmConfig::for_chain(&spec);
        let context = config.next_context(self.head.header(), attributes)?;
        let state = self.factory.latest().map_err(BlockExecutionError::other)?;
        bloch_l2_evm::node_execution::select::select_node_transactions_after_forced(
            spec.execution_at(context.number),
            spec.domain(),
            reth_revm::database::StateProviderDatabase::new(state.as_ref()),
            self.head.0.state_root,
            &context,
            &attributes.deposits,
            forced,
            candidates,
            limits,
        )
        .map_err(BlockExecutionError::other)
    }

    /// Select pending transactions ([`Self::select_pending`]) and extend the
    /// head with exactly that selection, deposits first.
    pub fn extend_with_pending(
        &mut self,
        expected_parent: B256,
        attributes: BlochNextBlockEnvCtx,
        candidates: &[alloy_primitives::Bytes],
        limits: SelectionLimits,
    ) -> Result<(SealedHeader<BlochNodeHeader>, BlockSelection), BlockExecutionError> {
        if expected_parent != self.head.hash() {
            return Err(BlockExecutionError::msg("stale canonical parent"));
        }
        let selection = self.select_pending(&attributes, candidates, limits)?;
        let tip = self.extend_raw(expected_parent, attributes, &selection.transactions)?;
        Ok((tip, selection))
    }

    /// Extend the head with exactly these canonical signed envelopes, in
    /// order (for example a batch re-read from L1 data availability). Each
    /// must decode exactly; execution validates them like any block.
    pub fn extend_raw(
        &mut self,
        expected_parent: B256,
        attributes: BlochNextBlockEnvCtx,
        raw: &[alloy_primitives::Bytes],
    ) -> Result<SealedHeader<BlochNodeHeader>, BlockExecutionError> {
        let transactions = raw
            .iter()
            .map(|raw| {
                let mut bytes = raw.as_ref();
                let tx = BlochRethTransaction::decode_2718(&mut bytes).map_err(BlockExecutionError::other)?;
                if !bytes.is_empty() {
                    return Err(BlockExecutionError::msg("selected transaction has trailing bytes"));
                }
                Ok(tx)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.extend(expected_parent, attributes, transactions)
    }

    /// Execute against the selected parent and publish only after commit.
    /// `attributes` must be authenticated by the host; no L1 proof is checked here.
    pub fn extend(
        &mut self,
        expected_parent: B256,
        attributes: BlochNextBlockEnvCtx,
        transactions: Vec<BlochRethTransaction>,
    ) -> Result<SealedHeader<BlochNodeHeader>, BlockExecutionError> {
        if self.poisoned {
            return Err(BlockExecutionError::msg(
                "canonical coordinator requires storage recovery",
            ));
        }
        if expected_parent != self.head.hash() {
            return Err(BlockExecutionError::msg("stale canonical parent"));
        }
        let spec = self.factory.chain_spec();
        let config = BlochEvmConfig::for_chain(&spec);
        let executed = {
            let state = self.factory.latest().map_err(BlockExecutionError::other)?;
            execute_next_block(&config, state.as_ref(), &self.head, attributes, transactions)?
        };
        let tip = executed.recovered_block().clone_sealed_header();
        let notification = Arc::new(Chain::from_block(
            executed.recovered_block().clone(),
            ExecutionOutcome::from((executed.execution_outcome().clone(), executed.block_number())),
            executed.trie_data_handle(),
        ));
        let writer = self
            .factory
            .database_provider_rw()
            .map_err(BlockExecutionError::other)?;
        let number = writer.best_block_number().map_err(BlockExecutionError::other)?;
        let durable = writer.sealed_header(number).map_err(BlockExecutionError::other)?;
        if number != self.head.0.number
            || writer.last_block_number().map_err(BlockExecutionError::other)? != number
            || durable.as_ref().map(|header| header.hash()) != Some(expected_parent)
        {
            return Err(BlockExecutionError::msg("canonical parent changed before persistence"));
        }
        // Full persistence crosses multiple backends. Even a save error must
        // prevent retrying this object as though the failed operation was atomic.
        self.poisoned = true;
        writer
            .save_blocks(vec![executed], SaveBlocksMode::Full)
            .map_err(BlockExecutionError::other)?;
        writer.commit().map_err(BlockExecutionError::other)?;
        self.provider
            .canonical_in_memory_state()
            .set_canonical_head(tip.clone());
        self.provider
            .canonical_in_memory_state()
            .set_persisted(BlockNumHash::new(tip.0.number, tip.hash()));
        self.provider
            .canonical_in_memory_state()
            .notify_canon_state(CanonStateNotification::Commit { new: notification });
        self.head = tip;
        self.poisoned = false;
        Ok(self.head.clone())
    }
}
