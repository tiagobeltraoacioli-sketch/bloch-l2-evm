// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fail-closed composition of canonical database commits and runtime receipts.
//!
//! The supplied settlement cursor is a host trust input. This module compares and
//! journals it; it does not authenticate L1 or make the database and journal one
//! atomic transaction.
use crate::{
    BlochNextBlockEnvCtx, BlochNodeHeader, BlochProviderFactory, BlochRethTransaction, CanonicalCoordinator,
    DurableHead, RuntimeIdentity, RuntimeLease, RuntimeReceiptFloor, SettlementCursor,
};
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::B256;
use reth_chainspec::EthChainSpec;
use reth_primitives_traits::SealedHeader;
use reth_provider::ChainSpecProvider;
use std::path::Path;

/// Sole canonical writer coupled to a durable lifecycle lease.
///
/// Every attempted extension poisons the supervisor until both the database
/// commit and the post-commit lifecycle checkpoint succeed. Discard a poisoned
/// instance and perform independent storage/journal recovery before restarting.
pub struct DurableCanonicalSupervisor {
    coordinator: CanonicalCoordinator,
    runtime: RuntimeLease,
    poisoned: bool,
}

impl DurableCanonicalSupervisor {
    pub fn attach(
        factory: BlochProviderFactory,
        runtime_path: impl AsRef<Path>,
        settlement: SettlementCursor,
    ) -> Result<Self, BlockExecutionError> {
        Self::attach_inner(factory, runtime_path.as_ref(), settlement, None)
    }

    pub fn attach_with_floor(
        factory: BlochProviderFactory,
        runtime_path: impl AsRef<Path>,
        settlement: SettlementCursor,
        floor: RuntimeReceiptFloor,
    ) -> Result<Self, BlockExecutionError> {
        Self::attach_inner(factory, runtime_path.as_ref(), settlement, Some(floor))
    }

    fn attach_inner(
        factory: BlochProviderFactory,
        runtime_path: &Path,
        settlement: SettlementCursor,
        floor: Option<RuntimeReceiptFloor>,
    ) -> Result<Self, BlockExecutionError> {
        let spec = factory.chain_spec();
        let identity = RuntimeIdentity {
            chain_id: spec.execution().chain_id,
            genesis_hash: spec.genesis_hash(),
        };
        let coordinator = CanonicalCoordinator::attach(factory)?;
        let head = DurableHead::from_header(coordinator.head(), settlement);
        let runtime = match floor {
            Some(floor) => RuntimeLease::acquire_with_floor(runtime_path, identity, head, floor),
            None => RuntimeLease::acquire(runtime_path, identity, head),
        }
        .map_err(BlockExecutionError::other)?;
        Ok(Self {
            coordinator,
            runtime,
            poisoned: false,
        })
    }

    pub fn head(&self) -> &SealedHeader<BlochNodeHeader> {
        self.coordinator.head()
    }

    pub fn durable_head(&self) -> DurableHead {
        self.runtime.record().head
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned || self.coordinator.is_poisoned()
    }

    /// Commit one canonical block, then append its exact lifecycle checkpoint.
    ///
    /// `settlement` must already have been authenticated by the host. A database
    /// success followed by journal failure returns an error and permanently poisons
    /// this object; it does not roll back, retry or claim cross-backend atomicity.
    pub fn extend(
        &mut self,
        expected_parent: B256,
        attributes: BlochNextBlockEnvCtx,
        transactions: Vec<BlochRethTransaction>,
        settlement: SettlementCursor,
    ) -> Result<SealedHeader<BlochNodeHeader>, BlockExecutionError> {
        if self.is_poisoned() {
            return Err(BlockExecutionError::msg(
                "durable canonical supervisor requires recovery",
            ));
        }
        // From this point every error requires a new attach/recovery decision.
        self.poisoned = true;
        if expected_parent != self.coordinator.head().hash() {
            return Err(BlockExecutionError::msg("stale supervised canonical parent"));
        }
        if !settlement_extends(self.runtime.record().head.settlement, settlement) {
            return Err(BlockExecutionError::msg(
                "stale or conflicting supervised settlement cursor",
            ));
        }
        let tip = self.coordinator.extend(expected_parent, attributes, transactions)?;
        let durable = DurableHead::from_header(&tip, settlement);
        self.runtime.checkpoint(durable).map_err(BlockExecutionError::other)?;
        self.poisoned = false;
        Ok(tip)
    }

    /// Mark the exact checkpoint clean. Poisoned instances deliberately cannot
    /// erase crash/ambiguity evidence.
    pub fn shutdown(self) -> Result<(), BlockExecutionError> {
        if self.is_poisoned() {
            return Err(BlockExecutionError::msg(
                "poisoned supervisor cannot mark a clean shutdown",
            ));
        }
        let observed = DurableHead::from_header(self.coordinator.head(), self.runtime.record().head.settlement);
        self.runtime.shutdown(observed).map_err(BlockExecutionError::other)
    }
}

fn settlement_extends(previous: SettlementCursor, next: SettlementCursor) -> bool {
    next.l1_height > previous.l1_height
        || (next.l1_height == previous.l1_height
            && next.l1_block_hash == previous.l1_block_hash
            && next.event_index >= previous.event_index)
}
