// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reth storage-compatible transaction and receipt wrappers over the same executor.
use crate::{
    BlochBlockExecutionCtx, BlochBlockExecutor, BlochContext, BlochEvm, BlochEvmFactory, BlochNodeBlockExecutorFactory,
    BlochRethReceipt, BlochRethTransaction, BlochTxResult,
};
use alloy_consensus::{transaction::Recovered, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory, ExecutableTx, GasOutput,
        StateDB,
    },
    RecoveredTx,
};
use alloy_primitives::{Address, B256};
use bloch_l2_evm::{executor::lifecycle::FinishedNodeBlock, ChainSpec};
use reth_revm::revm::Inspector;

/// The actual EVM, Reth-compatible receipts, and unchanged core finalization token.
pub type BlochRethBlockFinish<DB, I> = (
    BlochEvm<DB, I>,
    BlockExecutionResult<BlochRethReceipt>,
    FinishedNodeBlock,
);
/// A type adapter retaining the common executor's authentication and commit leases.
pub struct BlochRethBlockExecutor<DB: StateDB, I: Inspector<BlochContext<DB>>> {
    inner: BlochBlockExecutor<DB, I>,
    receipts: Vec<BlochRethReceipt>,
}
fn convert_result(
    result: BlockExecutionResult<alloy_consensus::ReceiptEnvelope>,
) -> BlockExecutionResult<BlochRethReceipt> {
    BlockExecutionResult {
        receipts: result.receipts.into_iter().map(Into::into).collect(),
        requests: result.requests,
        gas_used: result.gas_used,
        blob_gas_used: result.blob_gas_used,
    }
}
impl<DB: StateDB, I: Inspector<BlochContext<DB>>> BlochRethBlockExecutor<DB, I> {
    /// Delegate checked lease validation and commit, then mirror the accepted receipt.
    pub fn checked_commit_transaction(&mut self, result: BlochTxResult) -> Result<GasOutput, BlockExecutionError> {
        let gas = self.inner.checked_commit_transaction(result)?;
        self.receipts
            .push(self.inner.receipts().last().expect("committed receipt").clone().into());
        Ok(gas)
    }
    /// Finalize V2 effects without substituting the supplied EVM or state root.
    pub fn finish_node(self) -> Result<BlochRethBlockFinish<DB, I>, BlockExecutionError> {
        let (evm, result, finished) = self.inner.finish_node()?;
        Ok((evm, convert_result(result), finished))
    }
}
impl<DB: StateDB, I: Inspector<BlochContext<DB>>> BlockExecutor for BlochRethBlockExecutor<DB, I> {
    type Transaction = BlochRethTransaction;
    type Receipt = BlochRethReceipt;
    type Evm = BlochEvm<DB, I>;
    type Result = BlochTxResult;
    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }
    fn execute_transaction_without_commit(
        &mut self,
        transaction: impl ExecutableTx<Self>,
    ) -> Result<BlochTxResult, BlockExecutionError> {
        let (_, recovered) = transaction.into_parts();
        if recovered.tx().encode_2718_len() > bloch_l2_evm::transactions::MAX_RAW_TRANSACTION_BYTES {
            return Err(BlockExecutionError::msg("signed transaction too large"));
        }
        let transaction: TxEnvelope = recovered.tx().clone().into();
        self.inner
            .execute_transaction_without_commit(Recovered::new_unchecked(transaction, Address::ZERO))
    }
    fn commit_transaction(&mut self, result: BlochTxResult) -> GasOutput {
        self.checked_commit_transaction(result).unwrap_or_default()
    }
    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        self.finish_node().map(|(evm, result, _)| (evm, result))
    }
    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }
    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
    fn receipts(&self) -> &[Self::Receipt] {
        &self.receipts
    }
}
/// Actual Reth primitive types over the existing explicit V2 factory.
#[derive(Clone, Debug)]
pub struct BlochRethBlockExecutorFactory {
    inner: BlochNodeBlockExecutorFactory,
}
impl BlochRethBlockExecutorFactory {
    /// Bind the same trusted specification/domain as the shared V2 executor.
    pub fn new(spec: &ChainSpec, domain: B256) -> Self {
        Self {
            inner: BlochNodeBlockExecutorFactory::new(spec, domain),
        }
    }
}
impl BlockExecutorFactory for BlochRethBlockExecutorFactory {
    type EvmFactory = BlochEvmFactory;
    type TxExecutionResult = BlochTxResult;
    type ExecutionCtx<'a> = BlochBlockExecutionCtx;
    type Transaction = BlochRethTransaction;
    type Receipt = BlochRethReceipt;
    type Executor<'a, DB: StateDB, I: Inspector<BlochContext<DB>>> = BlochRethBlockExecutor<DB, I>;
    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }
    fn create_executor<DB: StateDB, I: Inspector<BlochContext<DB>>>(
        &self,
        evm: BlochEvm<DB, I>,
        context: BlochBlockExecutionCtx,
    ) -> Self::Executor<'_, DB, I> {
        BlochRethBlockExecutor {
            inner: self.inner.create_executor(evm, context),
            receipts: Vec::new(),
        }
    }
}
