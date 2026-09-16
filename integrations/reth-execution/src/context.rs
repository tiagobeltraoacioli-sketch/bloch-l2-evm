// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real revm context with Bloch's committed block-hash source.
use alloy_evm::eth::EthEvmContext;
use alloy_primitives::{Address, Log, B256, U256};
use bloch_l2_evm::state::{block_hash_slot, BLOCK_INFO_FLAG_SLOT};
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::{
        cfg::GasParams,
        context::{SStoreResult, SelfDestructResult, StateLoad},
        host::LoadError,
        journaled_state::AccountInfoLoad,
        ContextError, ContextSetters, ContextTr, Host,
    },
    Database,
};

/// Standard revm context with an explicit Bloch block-info address.
/// The original database and journal remain visible to inspectors and callers.
pub struct BlochContext<DB: Database> {
    pub(crate) inner: EthEvmContext<DB>,
    pub(crate) block_info: Address,
}
impl<DB: Database> ContextTr for BlochContext<DB> {
    type Block = BlockEnv;
    type Tx = TxEnv;
    type Cfg = CfgEnv;
    type Db = DB;
    type Journal = <EthEvmContext<DB> as ContextTr>::Journal;
    type Chain = ();
    type Local = <EthEvmContext<DB> as ContextTr>::Local;
    fn all(
        &self,
    ) -> (
        &Self::Block,
        &Self::Tx,
        &Self::Cfg,
        &DB,
        &Self::Journal,
        &(),
        &Self::Local,
    ) {
        self.inner.all()
    }
    fn all_mut(
        &mut self,
    ) -> (
        &Self::Block,
        &Self::Tx,
        &Self::Cfg,
        &mut Self::Journal,
        &mut (),
        &mut Self::Local,
    ) {
        self.inner.all_mut()
    }
    fn error(&mut self) -> &mut Result<(), ContextError<DB::Error>> {
        self.inner.error()
    }
}
impl<DB: Database> ContextSetters for BlochContext<DB> {
    fn set_tx(&mut self, tx: TxEnv) {
        self.inner.set_tx(tx)
    }
    fn set_block(&mut self, block: BlockEnv) {
        self.inner.set_block(block)
    }
}
impl<DB: Database> Host for BlochContext<DB> {
    fn block_hash(&mut self, number: u64) -> Option<B256> {
        // Window checks and opcode gas remain upstream interpreter behavior.
        // Raw database reads must not warm the block-info account or its slots.
        let address = self.block_info;
        let result = (|| {
            if self.inner.db_mut().storage(address, BLOCK_INFO_FLAG_SLOT)?.is_zero() {
                return Ok(B256::ZERO);
            }
            self.inner
                .db_mut()
                .storage(address, block_hash_slot(number))
                .map(|word| B256::from(word.to_be_bytes::<32>()))
        })();
        match result {
            Ok(hash) => Some(hash),
            Err(error) => {
                *self.inner.error() = Err(ContextError::Db(error));
                None
            }
        }
    }
    fn basefee(&self) -> U256 {
        self.inner.basefee()
    }
    fn blob_gasprice(&self) -> U256 {
        self.inner.blob_gasprice()
    }
    fn gas_limit(&self) -> U256 {
        self.inner.gas_limit()
    }
    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }
    fn prevrandao(&self) -> Option<U256> {
        self.inner.prevrandao()
    }
    fn block_number(&self) -> U256 {
        self.inner.block_number()
    }
    fn timestamp(&self) -> U256 {
        self.inner.timestamp()
    }
    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }
    fn slot_num(&self) -> U256 {
        self.inner.slot_num()
    }
    fn chain_id(&self) -> U256 {
        self.inner.chain_id()
    }
    fn effective_gas_price(&self) -> U256 {
        self.inner.effective_gas_price()
    }
    fn caller(&self) -> Address {
        self.inner.caller()
    }
    fn max_initcode_size(&self) -> usize {
        self.inner.max_initcode_size()
    }
    fn gas_params(&self) -> &GasParams {
        self.inner.gas_params()
    }
    fn is_amsterdam_eip8037_enabled(&self) -> bool {
        self.inner.is_amsterdam_eip8037_enabled()
    }
    fn blob_hash(&self, number: usize) -> Option<U256> {
        self.inner.blob_hash(number)
    }
    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, LoadError> {
        self.inner.selfdestruct(address, target, skip_cold_load)
    }
    fn log(&mut self, log: Log) {
        self.inner.log(log)
    }
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, LoadError> {
        self.inner.sstore_skip_cold_load(address, key, value, skip_cold_load)
    }
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, LoadError> {
        self.inner.sload_skip_cold_load(address, key, skip_cold_load)
    }
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.inner.tstore(address, key, value)
    }
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.inner.tload(address, key)
    }
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, LoadError> {
        self.inner
            .load_account_info_skip_cold_load(address, load_code, skip_cold_load)
    }
}

// Alloy's precompile provider is implemented for its standard Context. Forward
// through the wrapped context so builtin and dynamic precompiles stay upstream.
impl<DB: alloy_evm::Database> reth_revm::revm::handler::PrecompileProvider<BlochContext<DB>>
    for alloy_evm::precompiles::PrecompilesMap
{
    type Output = reth_revm::revm::interpreter::InterpreterResult;
    fn set_spec(&mut self, spec: reth_revm::revm::primitives::hardfork::SpecId) -> bool {
        <Self as reth_revm::revm::handler::PrecompileProvider<EthEvmContext<DB>>>::set_spec(self, spec)
    }
    fn run(
        &mut self,
        context: &mut BlochContext<DB>,
        inputs: &reth_revm::revm::interpreter::CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        <Self as reth_revm::revm::handler::PrecompileProvider<EthEvmContext<DB>>>::run(self, &mut context.inner, inputs)
    }
    fn warm_addresses(&self) -> &reth_revm::revm::primitives::AddressSet {
        <Self as reth_revm::revm::handler::PrecompileProvider<EthEvmContext<DB>>>::warm_addresses(self)
    }
    fn contains(&self, address: &Address) -> bool {
        <Self as reth_revm::revm::handler::PrecompileProvider<EthEvmContext<DB>>>::contains(self, address)
    }
}
