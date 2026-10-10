// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reth configuration and assembly for the explicit tagged V2 domain.
use crate::{
    BlochBlockExecutionCtx, BlochNodeBlock, BlochNodeBody, BlochNodeHeader, BlochNodePrimitives,
    BlochRethBlockExecutorFactory,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{block::BlockExecutionError, Database, EvmEnv, EvmFactory};
use alloy_primitives::{Address, B256, U256};
use bloch_l2_evm::{
    node_execution::node_head_on_database, node_primitives::NodeBodyV2, BlockContext, ChainSpec, DepositMint,
};
use reth_evm::{
    execute::{BlockAssembler, BlockAssemblerInput},
    ConfigureEvm, EvmFor, InspectorFor,
};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use reth_revm::{
    database::StateProviderDatabase,
    revm::{
        context::{BlockEnv, CfgEnv},
        context_interface::block::BlobExcessGasAndPrice,
        database::BundleState,
        state::{AccountInfo, Bytecode},
        DatabaseRef,
    },
};

/// Explicit host-authenticated inputs which cannot be derived from the parent.
#[derive(Clone, Debug)]
pub struct BlochNextBlockEnvCtx {
    /// Sequencer timestamp; must not precede the parent.
    pub timestamp: u64,
    /// Host-authenticated randomness.
    pub prevrandao: B256,
    /// Host-authenticated anchor commitment.
    pub anchor_root: B256,
    /// Host-authenticated deposits, preserved in the tagged body.
    pub deposits: Vec<DepositMint>,
}
/// Reth configuration using Bloch primitives, execution and assembly.
#[derive(Clone, Debug)]
pub struct BlochEvmConfig {
    spec: ChainSpec,
    domain: B256,
    factory: BlochRethBlockExecutorFactory,
    assembler: BlochNodeBlockAssembler,
    rpc_block_hashes: bool,
}
impl BlochEvmConfig {
    /// Bind execution to a trusted specification and nonzero V2 domain.
    pub fn new(spec: &ChainSpec, domain: B256) -> Self {
        Self {
            spec: spec.clone(),
            domain,
            factory: BlochRethBlockExecutorFactory::new(spec, domain),
            assembler: BlochNodeBlockAssembler::new(spec, domain),
            rpc_block_hashes: false,
        }
    }
    /// Only RPC construction enables provider ancestry and explicit block overrides.
    /// Canonical block executors still install their shared-kernel snapshot.
    pub(crate) fn for_rpc(mut self) -> Self {
        self.rpc_block_hashes = true;
        self
    }
    pub(crate) fn next_context(
        &self,
        parent: &BlochNodeHeader,
        attributes: &BlochNextBlockEnvCtx,
    ) -> Result<BlockContext, BlockExecutionError> {
        parent
            .0
            .validate_configuration(&self.spec, self.domain)
            .map_err(BlockExecutionError::other)?;
        if attributes.timestamp < parent.0.timestamp {
            return Err(BlockExecutionError::msg("V2 timestamp precedes parent"));
        }
        Ok(BlockContext {
            number: parent
                .0
                .number
                .checked_add(1)
                .ok_or_else(|| BlockExecutionError::msg("V2 block number overflow"))?,
            timestamp: attributes.timestamp,
            base_fee_per_gas: self.spec.next_base_fee(parent.0.base_fee_per_gas, parent.0.gas_used),
            prevrandao: attributes.prevrandao,
            anchor_root: attributes.anchor_root,
        })
    }
}
fn block_context(header: &BlochNodeHeader) -> BlockContext {
    BlockContext {
        number: header.0.number,
        timestamp: header.0.timestamp,
        base_fee_per_gas: header.0.base_fee_per_gas,
        prevrandao: header.0.prevrandao,
        anchor_root: header.0.anchor_root,
    }
}
fn environment(spec: &ChainSpec, context: &BlockContext) -> EvmEnv {
    let mut cfg = CfgEnv::new_with_spec(spec.spec_id);
    cfg.chain_id = spec.chain_id;
    EvmEnv::new(
        cfg,
        BlockEnv {
            number: U256::from(context.number),
            timestamp: U256::from(context.timestamp),
            basefee: context.base_fee_per_gas,
            gas_limit: spec.gas_limit,
            beneficiary: spec.coinbase(),
            prevrandao: Some(context.prevrandao),
            blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new_with_spec(0, spec.spec_id)),
            ..Default::default()
        },
    )
}
impl ConfigureEvm for BlochEvmConfig {
    type Primitives = BlochNodePrimitives;
    type Error = BlockExecutionError;
    type NextBlockEnvCtx = BlochNextBlockEnvCtx;
    type BlockExecutorFactory = BlochRethBlockExecutorFactory;
    type BlockAssembler = BlochNodeBlockAssembler;
    fn evm_with_env<DB: Database>(&self, db: DB, env: EvmEnv) -> EvmFor<Self, DB> {
        let mut evm = self.evm_factory().create_evm(db, env);
        if self.rpc_block_hashes {
            evm.use_rpc_block_hashes();
        }
        evm
    }
    fn evm_with_env_and_inspector<DB, I>(&self, db: DB, env: EvmEnv, inspector: I) -> EvmFor<Self, DB, I>
    where
        DB: Database,
        I: InspectorFor<Self, DB>,
    {
        let mut evm = self.evm_factory().create_evm_with_inspector(db, env, inspector);
        if self.rpc_block_hashes {
            evm.use_rpc_block_hashes();
        }
        evm
    }
    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.factory
    }
    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.assembler
    }
    fn evm_env(&self, header: &BlochNodeHeader) -> Result<EvmEnv, Self::Error> {
        header
            .0
            .validate_configuration(&self.spec, self.domain)
            .map_err(BlockExecutionError::other)?;
        Ok(environment(&self.spec, &block_context(header)))
    }
    fn next_evm_env(
        &self,
        parent: &BlochNodeHeader,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv, Self::Error> {
        Ok(environment(&self.spec, &self.next_context(parent, attributes)?))
    }
    fn context_for_block(&self, block: &SealedBlock<BlochNodeBlock>) -> Result<BlochBlockExecutionCtx, Self::Error> {
        let header = block.header();
        header
            .0
            .validate_configuration(&self.spec, self.domain)
            .map_err(BlockExecutionError::other)?;
        let body = block.body().as_core();
        body.validate(&self.spec).map_err(BlockExecutionError::other)?;
        if header.0.transactions_root != body.transactions_root() || header.0.deposits_hash != body.deposits_hash() {
            return Err(BlockExecutionError::msg("V2 body commitments disagree with header"));
        }
        let deposit_gas = self.spec.deposit_gas.checked_mul(body.deposits.len() as u64);
        if deposit_gas != header.0.gas_used.checked_sub(header.0.user_gas_used) {
            return Err(BlockExecutionError::msg("V2 deposit gas disagrees with body"));
        }
        Ok(BlochBlockExecutionCtx {
            previous_root: header.0.parent_state_root,
            context: block_context(header),
            deposits: body.deposits.clone(),
        })
    }
    fn context_for_next_block(
        &self,
        parent: &SealedHeader<BlochNodeHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<BlochBlockExecutionCtx, Self::Error> {
        let context = self.next_context(parent, &attributes)?;
        NodeBodyV2 {
            deposits: attributes.deposits.clone(),
            transactions: vec![],
        }
        .validate(&self.spec)
        .map_err(BlockExecutionError::other)?;
        Ok(BlochBlockExecutionCtx {
            previous_root: parent.0.state_root,
            context,
            deposits: attributes.deposits,
        })
    }
}

/// Reconstructs metadata already committed by the V2 executor, without state writes.
/// The supplied root must already have been calculated from this post-state bundle.
#[derive(Clone, Debug)]
pub struct BlochNodeBlockAssembler {
    spec: ChainSpec,
    domain: B256,
}
impl BlochNodeBlockAssembler {
    /// Bind assembly to the same trusted configuration as execution.
    pub fn new(spec: &ChainSpec, domain: B256) -> Self {
        Self {
            spec: spec.clone(),
            domain,
        }
    }
}
/// Final bundle values shadow original provider state, including storage wipes.
struct BundleDatabase<'a, DB> {
    bundle: &'a BundleState,
    backing: DB,
}
impl<DB: DatabaseRef> DatabaseRef for BundleDatabase<'_, DB> {
    type Error = DB::Error;
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.bundle.state.get(&address) {
            Some(account) => Ok(account.account_info()),
            None => self.backing.basic_ref(address),
        }
    }
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(account) = self.bundle.state.get(&address) {
            if account.info.is_none() {
                return Ok(U256::ZERO);
            }
            if let Some(value) = account.storage_slot(index) {
                return Ok(value);
            }
        }
        self.backing.storage_ref(address, index)
    }
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        match self.bundle.contracts.get(&hash) {
            Some(code) => Ok(code.clone()),
            None => self.backing.code_by_hash_ref(hash),
        }
    }
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.backing.block_hash_ref(number)
    }
}
impl BlockAssembler<BlochRethBlockExecutorFactory> for BlochNodeBlockAssembler {
    type Block = BlochNodeBlock;
    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, BlochRethBlockExecutorFactory, BlochNodeHeader>,
    ) -> Result<Self::Block, BlockExecutionError> {
        if !input.output.requests.is_empty()
            || input.output.blob_gas_used != 0
            || input.block_access_list_hash.is_some()
        {
            return Err(BlockExecutionError::msg("unsupported V2 execution output extensions"));
        }
        let expected_env = environment(&self.spec, &input.execution_ctx.context);
        if input.evm_env.cfg_env != expected_env.cfg_env || input.evm_env.block_env != expected_env.block_env {
            return Err(BlockExecutionError::msg("V2 assembly environment mismatch"));
        }
        use bloch_l2_evm::{
            node_primitives::MAX_NODE_DEPOSITS,
            transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
        };
        if input.transactions.len() > MAX_SIGNED_TRANSACTIONS || input.execution_ctx.deposits.len() > MAX_NODE_DEPOSITS
        {
            return Err(BlockExecutionError::msg("V2 assembly body count limit exceeded"));
        }
        let mut total = 0usize;
        for transaction in &input.transactions {
            let length = transaction.encode_2718_len();
            if length > MAX_RAW_TRANSACTION_BYTES {
                return Err(BlockExecutionError::msg("V2 assembly transaction too large"));
            }
            total = total
                .checked_add(length)
                .filter(|value| *value <= MAX_SIGNED_BLOCK_BYTES)
                .ok_or_else(|| BlockExecutionError::msg("V2 assembly body byte limit exceeded"))?;
        }
        let body = NodeBodyV2 {
            deposits: input.execution_ctx.deposits,
            transactions: input.transactions.iter().map(|tx| tx.encoded_2718().into()).collect(),
        };
        let db = BundleDatabase {
            bundle: input.bundle_state,
            backing: StateProviderDatabase::new(input.state_provider),
        };
        let header =
            node_head_on_database(&self.spec, self.domain, db, input.state_root).map_err(BlockExecutionError::other)?;
        let context = &input.execution_ctx.context;
        if header.number != context.number
            || header.timestamp != context.timestamp
            || header.base_fee_per_gas != context.base_fee_per_gas
            || header.prevrandao != context.prevrandao
            || header.anchor_root != context.anchor_root
            || header.parent_state_root != input.execution_ctx.previous_root
            || header.gas_used != input.output.gas_used
        {
            return Err(BlockExecutionError::msg(
                "V2 committed head disagrees with execution context",
            ));
        }
        header
            .validate_parent(&self.spec, &input.parent.0)
            .map_err(BlockExecutionError::other)?;
        let receipts = input
            .output
            .receipts
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<alloy_consensus::ReceiptEnvelope>>();
        header
            .validate_commitments(&self.spec, self.domain, &body, &receipts)
            .map_err(BlockExecutionError::other)?;
        Ok(BlochNodeBlock {
            header: BlochNodeHeader(header),
            body: BlochNodeBody::try_from_core(body).map_err(BlockExecutionError::other)?,
        })
    }
}
