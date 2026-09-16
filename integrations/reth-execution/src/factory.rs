// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alloy EVM factory preserving Bloch BLOCKHASH without replacing the database.
use crate::context::BlochContext;
use alloy_evm::{precompiles::PrecompilesMap, Database, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, Bytes, B256};
use bloch_l2_evm::ChainSpec;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv, Evm as RevmEvm, TxEnv},
    context_interface::result::{EVMError, HaltReason, ResultAndState},
    handler::{instructions::EthInstructions, EthFrame},
    inspector::NoOpInspector,
    interpreter::interpreter::EthInterpreter,
    precompile::{PrecompileSpecId, Precompiles},
    primitives::hardfork::SpecId,
    Context, ExecuteEvm, InspectEvm, Inspector, MainContext, SystemCallEvm,
};

type Inner<DB, I> =
    RevmEvm<BlochContext<DB>, I, EthInstructions<EthInterpreter, BlochContext<DB>>, PrecompilesMap, EthFrame>;
/// Actual revm EVM with Bloch's host context and the caller's database/inspector.
pub struct BlochEvm<DB: Database, I> {
    inner: Inner<DB, I>,
    inspect: bool,
}
impl<DB: Database, I> BlochEvm<DB, I> {
    pub(crate) fn use_rpc_block_hashes(&mut self) {
        self.inner.ctx.rpc_block_hashes = true;
    }
    pub(crate) fn block_info(&self) -> Address {
        self.inner.ctx.block_info
    }
    /// Install the BLOCKHASH window captured by shared core preparation.
    ///
    /// Call with `PendingSystemCall::block_hashes()` before running its system
    /// call. This trusted host helper performs no reads or proof verification;
    /// arbitrary values change execution semantics. The block executor retains
    /// its own canonical copy and reinstalls it before each candidate.
    pub fn install_block_hashes(&mut self, window: &[(u64, B256)]) {
        self.inner.ctx.block_hashes = Some(window.to_vec());
    }
}

impl<DB: Database, I: Inspector<BlochContext<DB>>> Evm for BlochEvm<DB, I> {
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;
    fn block(&self) -> &BlockEnv {
        &self.inner.ctx.inner.block
    }
    fn cfg_env(&self) -> &CfgEnv {
        &self.inner.ctx.inner.cfg
    }
    fn chain_id(&self) -> u64 {
        self.inner.ctx.inner.cfg.chain_id
    }
    fn transact_raw(&mut self, tx: TxEnv) -> Result<ResultAndState<HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            self.inner.transact(tx)
        }
    }
    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<HaltReason>, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }
    fn finish(self) -> (DB, EvmEnv) {
        let context = self.inner.ctx.inner;
        (
            context.journaled_state.database,
            EvmEnv::new(context.cfg, context.block),
        )
    }
    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled
    }
    fn components(&self) -> (&DB, &I, &PrecompilesMap) {
        (
            &self.inner.ctx.inner.journaled_state.database,
            &self.inner.inspector,
            &self.inner.precompiles,
        )
    }
    fn components_mut(&mut self) -> (&mut DB, &mut I, &mut PrecompilesMap) {
        (
            &mut self.inner.ctx.inner.journaled_state.database,
            &mut self.inner.inspector,
            &mut self.inner.precompiles,
        )
    }
}
/// Factory for transaction execution with committed Bloch block-hash lookup.
/// The caller still supplies the matching environment and authenticates inputs;
/// this factory does not implement block lifecycle, receipts or node services.
#[derive(Clone, Debug)]
pub struct BlochEvmFactory {
    block_info: Address,
}
impl BlochEvmFactory {
    /// Select the block-info address from the chain specification.
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            block_info: spec.block_info,
        }
    }
    fn build<DB: Database, I: Inspector<BlochContext<DB>>>(
        &self,
        db: DB,
        env: EvmEnv,
        inspector: I,
        inspect: bool,
    ) -> BlochEvm<DB, I> {
        let spec = env.cfg_env.spec;
        let context = BlochContext {
            inner: Context::mainnet()
                .with_block(env.block_env)
                .with_cfg(env.cfg_env)
                .with_db(db),
            block_info: self.block_info,
            block_hashes: None,
            rpc_block_hashes: false,
        };
        let precompiles = PrecompilesMap::from_static(Precompiles::new(PrecompileSpecId::from_spec_id(spec)));
        BlochEvm {
            inner: RevmEvm::new_with_inspector(
                context,
                inspector,
                EthInstructions::new_mainnet_with_spec(spec),
                precompiles,
            ),
            inspect,
        }
    }
}
impl EvmFactory for BlochEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = BlochEvm<DB, I>;
    type Context<DB: Database> = BlochContext<DB>;
    type Tx = TxEnv;
    type Error<Error: reth_revm::revm::context::DBErrorMarker> = EVMError<Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    fn create_evm<DB: Database>(&self, db: DB, env: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        self.build(db, env, NoOpInspector {}, false)
    }
    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        env: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        self.build(db, env, inspector, true)
    }
}
