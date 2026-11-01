// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genuine Alloy block executor over the shared Bloch protocol lifecycle.
//!
//! User receipts count user gas only; the block result includes deposit gas.
//! This is a standalone executor, not Ethereum header/consensus compatibility.
use crate::{BlochContext, BlochEvm, BlochEvmFactory};
use alloy_consensus::{ReceiptEnvelope, TxEnvelope, TxType};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory, ExecutableTx, GasOutput,
        StateDB, TxResult,
    },
    eth::receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder, ReceiptBuilderCtx},
    precompiles::PrecompilesMap,
    Evm, RecoveredTx,
};
use alloy_primitives::{Bytes, B256, U256};
use bloch_l2_evm::{
    chainspec::BEACON_ROOTS_ADDRESS,
    decode_signed_transaction,
    executor::lifecycle::{
        prepare_block_start, prepare_node_block_start, ActiveBlock, FinishedBlock, FinishedNodeBlock,
    },
    node_primitives::NodeBodyV2,
    transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
    BlockContext, BlockInput, ChainSpec, DepositMint, PreparedTransaction,
};
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::{
        block::BlobExcessGasAndPrice,
        result::{HaltReason, ResultAndState},
    },
    precompile::{PrecompileSpecId, Precompiles},
    Inspector,
};
use std::sync::Arc;

/// Host-authenticated block context. Roots and L1 deposits remain caller trust.
#[derive(Clone, Debug)]
pub struct BlochBlockExecutionCtx {
    /// Trusted root of the supplied pre-block state.
    pub previous_root: B256,
    /// Bloch header fields for this block.
    pub context: BlockContext,
    /// Deposits independently authenticated by the host.
    pub deposits: Vec<DepositMint>,
}

/// A read-complete candidate bound to its executor's current generation.
/// Dropping or extracting the raw EVM result discards the protocol effects.
pub struct BlochTxResult {
    prepared: PreparedTransaction,
    tx_type: TxType,
    raw: Bytes,
    session: Arc<()>,
    generation: u64,
}
impl TxResult for BlochTxResult {
    type HaltReason = HaltReason;
    fn result(&self) -> &ResultAndState<HaltReason> {
        self.prepared.result_and_state()
    }
    fn into_result(self) -> ResultAndState<HaltReason> {
        self.prepared.into_result_and_state()
    }
}

/// The supplied EVM, SDK receipt/gas result, and root-pending Bloch outcome.
pub type BlochBlockFinish<DB, I> = (BlochEvm<DB, I>, BlockExecutionResult<ReceiptEnvelope>, FinishedBlock);

/// The supplied EVM, SDK result, and root-pending V2 outcome.
pub type BlochNodeBlockFinish<DB, I> = (
    BlochEvm<DB, I>,
    BlockExecutionResult<ReceiptEnvelope>,
    FinishedNodeBlock,
);

/// Block executor retaining the actual supplied EVM, database and inspector.
/// Any lifecycle failure requires discarding its provisional database.
pub struct BlochBlockExecutor<DB: StateDB, I: Inspector<BlochContext<DB>>> {
    evm: BlochEvm<DB, I>,
    spec: ChainSpec,
    context: BlochBlockExecutionCtx,
    active: Option<ActiveBlock>,
    node_domain: Option<B256>,
    accepted_transactions: Vec<Bytes>,
    block_hashes: Vec<(u64, B256)>,
    receipts: Vec<ReceiptEnvelope>,
    user_gas: u64,
    session: Arc<()>,
    generation: u64,
    attempted_transactions: usize,
    attempted_bytes: usize,
    poisoned: Option<&'static str>,
}
impl<DB: StateDB, I: Inspector<BlochContext<DB>>> BlochBlockExecutor<DB, I> {
    fn ready(&self) -> Result<(), BlockExecutionError> {
        if let Some(reason) = self.poisoned {
            return Err(BlockExecutionError::msg(reason));
        }
        Ok(())
    }
    fn invalidate(&mut self) {
        if let Some(next) = self.generation.checked_add(1) {
            self.generation = next;
        } else {
            self.poisoned = Some("candidate generation exhausted");
        }
    }
    fn reset_precompiles(&mut self) {
        // A caller may mutate the exposed map through evm_mut(). Bloch fixes
        // precompile semantics to its pinned fork, so reset the actual supplied
        // EVM's map before execution rather than accepting arbitrary overrides.
        *self.evm.components_mut().2 =
            PrecompilesMap::from_static(Precompiles::new(PrecompileSpecId::from_spec_id(self.spec.spec_id)));
    }
    fn validate_environment(&self) -> Result<(), BlockExecutionError> {
        let mut cfg = CfgEnv::new_with_spec(self.spec.spec_id);
        cfg.chain_id = self.spec.chain_id;
        let context = &self.context.context;
        let block = BlockEnv {
            number: U256::from(context.number),
            timestamp: U256::from(context.timestamp),
            gas_limit: self.spec.gas_limit,
            basefee: context.base_fee_per_gas,
            beneficiary: self.spec.coinbase(),
            prevrandao: Some(context.prevrandao),
            difficulty: U256::ZERO,
            blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new_with_spec(0, self.spec.spec_id)),
            ..Default::default()
        };
        if self.evm.cfg_env() != &cfg || self.evm.block() != &block || self.evm.block_info() != self.spec.block_info {
            return Err(BlockExecutionError::msg(
                "supplied EVM environment does not match the Bloch block",
            ));
        }
        Ok(())
    }
    /// Checked counterpart to Alloy's infallible commit method. Foreign or
    /// stale results poison this executor before any state or receipt changes.
    pub fn checked_commit_transaction(&mut self, output: BlochTxResult) -> Result<GasOutput, BlockExecutionError> {
        self.ready()?;
        if !Arc::ptr_eq(&self.session, &output.session) || self.generation != output.generation || self.active.is_none()
        {
            self.poisoned = Some("foreign or stale prepared transaction");
            return Err(BlockExecutionError::msg("foreign or stale prepared transaction"));
        }
        let Some(next_generation) = self.generation.checked_add(1) else {
            self.poisoned = Some("candidate generation exhausted");
            return Err(BlockExecutionError::msg("candidate generation exhausted"));
        };
        let gas = output.prepared.outcome().gas_used;
        let Some(cumulative) = self.user_gas.checked_add(gas) else {
            self.poisoned = Some("receipt gas overflow");
            return Err(BlockExecutionError::msg("receipt gas overflow"));
        };
        let receipt = AlloyReceiptBuilder::default().build_receipt(ReceiptBuilderCtx {
            tx_type: output.tx_type,
            evm: &self.evm,
            result: output.prepared.outcome().result.clone(),
            state: &output.prepared.result_and_state().state,
            cumulative_gas_used: cumulative,
        });
        self.active
            .as_mut()
            .expect("checked active block")
            .commit_prepared_transaction(output.prepared, self.evm.db_mut());
        self.generation = next_generation;
        self.user_gas = cumulative;
        self.receipts.push(receipt);
        if self.node_domain.is_some() {
            self.accepted_transactions.push(output.raw);
        }
        Ok(GasOutput::new(gas))
    }
    /// Commit final protocol effects and retain the core root-pending result.
    /// The caller calculates the complete post-state root before finalizing it.
    pub fn finish_bloch(mut self) -> Result<BlochBlockFinish<DB, I>, BlockExecutionError> {
        self.ready()?;
        if self.node_domain.is_some() {
            return Err(BlockExecutionError::msg("V2 executor requires finish_node"));
        }
        self.validate_environment()?;
        let active = self
            .active
            .take()
            .ok_or_else(|| BlockExecutionError::msg("block pre-execution has not completed"))?;
        let gas_used = active.gas_used();
        let finished = active
            .prepare_finish(self.evm.db_mut())
            .map_err(BlockExecutionError::other)?
            .commit(self.evm.db_mut());
        let result = BlockExecutionResult {
            receipts: self.receipts,
            requests: Default::default(),
            gas_used,
            blob_gas_used: 0,
        };
        Ok((self.evm, result, finished))
    }
    /// Commit V2 metadata and retain the actual root-pending V2 result.
    /// The caller independently computes the complete post-state root.
    pub fn finish_node(mut self) -> Result<BlochNodeBlockFinish<DB, I>, BlockExecutionError> {
        self.ready()?;
        if self.node_domain.is_none() {
            return Err(BlockExecutionError::msg("V1 executor requires finish_bloch"));
        }
        self.validate_environment()?;
        let active = self
            .active
            .take()
            .ok_or_else(|| BlockExecutionError::msg("block pre-execution has not completed"))?;
        let gas_used = active.gas_used();
        let body = NodeBodyV2 {
            deposits: self.context.deposits,
            transactions: self.accepted_transactions,
        };
        let prepared = active
            .prepare_node_finish(self.evm.db_mut(), &body)
            .map_err(BlockExecutionError::other)?;
        if prepared.receipts() != self.receipts {
            return Err(BlockExecutionError::msg(
                "SDK receipts disagree with shared V2 execution",
            ));
        }
        let finished = prepared.commit(self.evm.db_mut());
        let result = BlockExecutionResult {
            receipts: self.receipts,
            requests: Default::default(),
            gas_used,
            blob_gas_used: 0,
        };
        Ok((self.evm, result, finished))
    }
}
impl<DB: StateDB, I: Inspector<BlochContext<DB>>> BlockExecutor for BlochBlockExecutor<DB, I> {
    type Transaction = TxEnvelope;
    type Receipt = ReceiptEnvelope;
    type Evm = BlochEvm<DB, I>;
    type Result = BlochTxResult;
    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.ready()?;
        if self.active.is_some() {
            self.poisoned = Some("block prefix already applied");
            return Err(BlockExecutionError::msg("block prefix already applied"));
        }
        // Keep a failed lifecycle unusable even when earlier phases committed.
        self.poisoned = Some("block pre-execution failed; discard provisional database");
        self.validate_environment()?;
        self.reset_precompiles();
        let input = BlockInput {
            context: self.context.context.clone(),
            deposits: self.context.deposits.clone(),
            txs: Vec::new(),
        };
        let prepared = match self.node_domain {
            Some(domain) => prepare_node_block_start(
                &self.spec,
                domain,
                self.evm.db_mut(),
                self.context.previous_root,
                &input,
            ),
            None => prepare_block_start(&self.spec, self.evm.db_mut(), self.context.previous_root, &input),
        }
        .map_err(BlockExecutionError::other)?;
        let pending = prepared.commit(self.evm.db_mut());
        // Shared preparation captures the same pre-system-call window as the
        // portable executor. Contract writes cannot change BLOCKHASH mid-block.
        self.block_hashes = pending.block_hashes().to_vec();
        self.evm.install_block_hashes(&self.block_hashes);
        let result = self
            .evm
            .transact_system_call(
                reth_revm::revm::handler::system_call::SYSTEM_ADDRESS,
                BEACON_ROOTS_ADDRESS,
                Bytes::copy_from_slice(input.context.anchor_root.as_slice()),
            )
            .map_err(|error| BlockExecutionError::msg(format!("beacon system call failed: {error}")))?;
        self.active = Some(
            pending
                .complete(result, self.evm.db_mut())
                .map_err(BlockExecutionError::other)?,
        );
        self.poisoned = None;
        Ok(())
    }
    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<BlochTxResult, BlockExecutionError> {
        self.ready()?;
        self.validate_environment()?;
        self.reset_precompiles();
        self.evm.install_block_hashes(&self.block_hashes);
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| BlockExecutionError::msg("block pre-execution has not completed"))?;
        // Neither an externally supplied TxEnv nor a cached recovered sender is
        // an authentication source. Authenticate the canonical envelope anew.
        let (_, recovered) = tx.into_parts();
        let envelope = recovered.tx();
        let length = envelope.encode_2718_len();
        if length > MAX_RAW_TRANSACTION_BYTES {
            return Err(BlockExecutionError::msg("signed transaction too large"));
        }
        if self.attempted_transactions >= MAX_SIGNED_TRANSACTIONS {
            return Err(BlockExecutionError::msg("signed candidate attempt limit exceeded"));
        }
        let total = self
            .attempted_bytes
            .checked_add(length)
            .filter(|total| *total <= MAX_SIGNED_BLOCK_BYTES)
            .ok_or_else(|| BlockExecutionError::msg("signed candidate byte budget exceeded"))?;
        self.attempted_transactions += 1;
        self.attempted_bytes = total;
        let raw = envelope.encoded_2718();
        let authenticated = decode_signed_transaction(&self.spec, &raw).map_err(BlockExecutionError::other)?;
        let env = authenticated.environment();
        active.validate_transaction(env).map_err(BlockExecutionError::other)?;
        let result = self
            .evm
            .transact_raw(env.clone())
            .map_err(|error| BlockExecutionError::evm(error, authenticated.hash()))?;
        let prepared = active
            .prepare_owned_transaction(env, result, self.evm.db_mut())
            .map_err(BlockExecutionError::other)?;
        Ok(BlochTxResult {
            prepared,
            tx_type: envelope.tx_type(),
            raw: raw.into(),
            session: Arc::clone(&self.session),
            generation: self.generation,
        })
    }
    fn commit_transaction(&mut self, output: BlochTxResult) -> GasOutput {
        // Trait cannot return an error: poison and return no gas; finish must fail.
        self.checked_commit_transaction(output).unwrap_or_default()
    }
    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        if self.node_domain.is_some() {
            self.finish_node().map(|(evm, result, _pending_root)| (evm, result))
        } else {
            self.finish_bloch().map(|(evm, result, _pending_root)| (evm, result))
        }
    }
    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.invalidate();
        &mut self.evm
    }
    fn evm(&self) -> &Self::Evm {
        &self.evm
    }
    fn receipts(&self) -> &[ReceiptEnvelope] {
        &self.receipts
    }
}
/// Standalone Alloy factory using Bloch lifecycle and signed user envelopes.
/// It does not supply custom node primitives, consensus validation or RPC.
#[derive(Clone, Debug)]
pub struct BlochBlockExecutorFactory {
    spec: ChainSpec,
    rules: Option<crate::RuleSchedule>,
    evm_factory: BlochEvmFactory,
}
impl BlochBlockExecutorFactory {
    /// Configure execution for a fixed chain specification.
    pub fn new(spec: &ChainSpec) -> Self {
        let evm_factory = BlochEvmFactory::new(spec);
        Self {
            spec: spec.clone(),
            rules: None,
            evm_factory,
        }
    }
    /// Each block runs the rules the schedule gives for its number.
    pub fn with_rules(mut self, rules: crate::RuleSchedule) -> Self {
        self.rules = Some(rules);
        self
    }
}
impl BlockExecutorFactory for BlochBlockExecutorFactory {
    type EvmFactory = BlochEvmFactory;
    type TxExecutionResult = BlochTxResult;
    type ExecutionCtx<'a> = BlochBlockExecutionCtx;
    type Transaction = TxEnvelope;
    type Receipt = ReceiptEnvelope;
    type Executor<'a, DB: StateDB, I: Inspector<BlochContext<DB>>> = BlochBlockExecutor<DB, I>;
    fn evm_factory(&self) -> &BlochEvmFactory {
        &self.evm_factory
    }
    fn create_executor<DB: StateDB, I: Inspector<BlochContext<DB>>>(
        &self,
        evm: BlochEvm<DB, I>,
        context: BlochBlockExecutionCtx,
    ) -> BlochBlockExecutor<DB, I> {
        let spec = match &self.rules {
            Some(rules) => rules.at(context.context.number).clone(),
            None => self.spec.clone(),
        };
        BlochBlockExecutor {
            evm,
            spec,
            context,
            active: None,
            node_domain: None,
            accepted_transactions: Vec::new(),
            block_hashes: Vec::new(),
            receipts: Vec::new(),
            user_gas: 0,
            session: Arc::new(()),
            generation: 0,
            attempted_transactions: 0,
            attempted_bytes: 0,
            poisoned: None,
        }
    }
}

/// Explicit V2 standalone factory. Domain identity must come from trusted configuration.
/// This does not implement node consensus, custom Reth primitives, or RPC.
#[derive(Clone, Debug)]
pub struct BlochNodeBlockExecutorFactory {
    inner: BlochBlockExecutorFactory,
    domain: B256,
}
impl BlochNodeBlockExecutorFactory {
    /// Bind this factory to a trusted V2 domain; zero is rejected before prefix writes.
    pub fn new(spec: &ChainSpec, domain: B256) -> Self {
        Self {
            inner: BlochBlockExecutorFactory::new(spec),
            domain,
        }
    }
    /// Each block runs the rules the schedule gives for its number.
    pub fn with_rules(mut self, rules: crate::RuleSchedule) -> Self {
        self.inner = self.inner.with_rules(rules);
        self
    }
}
impl BlockExecutorFactory for BlochNodeBlockExecutorFactory {
    type EvmFactory = BlochEvmFactory;
    type TxExecutionResult = BlochTxResult;
    type ExecutionCtx<'a> = BlochBlockExecutionCtx;
    type Transaction = TxEnvelope;
    type Receipt = ReceiptEnvelope;
    type Executor<'a, DB: StateDB, I: Inspector<BlochContext<DB>>> = BlochBlockExecutor<DB, I>;
    fn evm_factory(&self) -> &BlochEvmFactory {
        self.inner.evm_factory()
    }
    fn create_executor<DB: StateDB, I: Inspector<BlochContext<DB>>>(
        &self,
        evm: BlochEvm<DB, I>,
        context: BlochBlockExecutionCtx,
    ) -> BlochBlockExecutor<DB, I> {
        let mut executor = self.inner.create_executor(evm, context);
        executor.node_domain = Some(self.domain);
        executor
    }
}
