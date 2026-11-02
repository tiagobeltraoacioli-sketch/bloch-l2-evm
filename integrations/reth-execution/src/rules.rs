// SPDX-License-Identifier: MIT OR Apache-2.0
//! Which kernel rule set each L2 block of one chain runs.
//!
//! A chain starts on its base rules. A network with a next rule set switches at
//! the first block L1 settles under the next program. L1 does not fix that
//! number in advance: it replaces the program at an epoch boundary, and the block
//! number at that moment depends on how far settlement got. So the schedule holds
//! the number as a value learned from a source of authority:
//!
//! - a rebuild reads it from each settlement statement's configuration commitment,
//!   the field L1 compared with the policy of that moment;
//! - the settler reads it from the program L1 reports (`getl2settlement.program`);
//! - every reader of an existing database derives it from the database, because
//!   the next rules install the sweep code at the fee vaults in their first block
//!   and no earlier rule set can put it there.
//!
//! The two rule sets may differ only in what [`RuleSchedule::new`] allows, so
//! everything else in the stack (header layout, gas, fees, chain id) reads the
//! base rules and needs no block number. The genesis is the same under both.
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::Bytes;
use bloch_l2_evm::{chainspec::fee_vault_sweep_code, ChainSpec};
use reth_provider::{BlockNumReader, StateProvider};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const UNSET: u64 = u64::MAX;

/// The rule sets of one chain and the first block of the next one. Clones share
/// the switch, so a provider's configuration and its readers agree.
#[derive(Clone, Debug)]
pub struct RuleSchedule {
    base: ChainSpec,
    next: Option<ChainSpec>,
    next_from: Arc<AtomicU64>,
}

impl RuleSchedule {
    /// One rule set for the whole chain (the development networks).
    pub fn single(base: ChainSpec) -> Self {
        Self { base, next: None, next_from: Arc::new(AtomicU64::new(UNSET)) }
    }

    /// A base and a next rule set. Refused unless they differ only in the block
    /// derivation and the fee-vault sweep.
    pub fn new(base: ChainSpec, next: ChainSpec) -> Result<Self, BlockExecutionError> {
        // Forced inclusion (candidate) is part of the next rules when the core
        // crate is built with it; the base rules never have it.
        let comparable = ChainSpec {
            block_derivation: base.block_derivation,
            fee_vault_sweep: base.fee_vault_sweep,
            forced_inclusion: base.forced_inclusion,
            ..next.clone()
        };
        if comparable != base || next.fee_vault_sweep.is_none() || base.fee_vault_sweep.is_some() {
            return Err(BlockExecutionError::msg(
                "the next rule set may add only the block derivation and the fee-vault sweep",
            ));
        }
        next.validate().map_err(BlockExecutionError::other)?;
        Ok(Self { base, next: Some(next), next_from: Arc::new(AtomicU64::new(UNSET)) })
    }

    /// The rules of the chain's first blocks.
    pub fn base(&self) -> &ChainSpec {
        &self.base
    }

    /// The next rule set, on a network that has one.
    pub fn next(&self) -> Option<&ChainSpec> {
        self.next.as_ref()
    }

    /// The first block under the next rules, once known.
    pub fn next_from(&self) -> Option<u64> {
        match self.next_from.load(Ordering::Acquire) {
            UNSET => None,
            number => Some(number),
        }
    }

    /// The rules block `number` runs.
    pub fn at(&self, number: u64) -> &ChainSpec {
        match &self.next {
            Some(next) if number >= self.next_from.load(Ordering::Acquire) => next,
            _ => &self.base,
        }
    }

    /// Whether block `number` runs the next rules.
    pub fn is_next(&self, number: u64) -> bool {
        self.next.is_some() && number >= self.next_from.load(Ordering::Acquire)
    }

    /// Fix the first block of the next rules. Block 0 is refused, and so is any
    /// other block than the one already fixed: the switch happens once.
    pub fn switch_at(&self, number: u64) -> Result<(), BlockExecutionError> {
        if self.next.is_none() {
            return Err(BlockExecutionError::msg("this network has no next rule set"));
        }
        if number == 0 || number == UNSET {
            return Err(BlockExecutionError::msg("the next rules cannot start at this block"));
        }
        match self.next_from.compare_exchange(UNSET, number, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(current) if current == number => Ok(()),
            Err(current) => Err(BlockExecutionError::msg(format!(
                "the next rules already start at block {current}, not {number}"
            ))),
        }
    }

    /// Forget the switch: a rewind removed its block.
    pub fn clear_switch(&self) {
        self.next_from.store(UNSET, Ordering::Release);
    }

    fn sweep_installed(&self, state: &dyn StateProvider) -> Result<bool, BlockExecutionError> {
        let Some(recipient) = self.next.as_ref().and_then(|next| next.fee_vault_sweep) else {
            return Ok(false);
        };
        let code = state.account_code(&self.base.base_fee_vault).map_err(BlockExecutionError::other)?;
        Ok(code.is_some_and(|code| code.original_bytes() == Bytes::copy_from_slice(&fee_vault_sweep_code(recipient))))
    }

    /// Learn the switch from a database: the lowest block whose state holds the
    /// sweep code. Clears it when the database no longer holds any such block.
    /// Returns the first next-rule block, if any. Needs an archival database.
    pub fn discover(&self, provider: &crate::BlochProviderFactory) -> Result<Option<u64>, BlockExecutionError> {
        if self.next.is_none() {
            return Ok(None);
        }
        let head = provider.best_block_number().map_err(BlockExecutionError::other)?;
        let installed_at = |number: u64| -> Result<bool, BlockExecutionError> {
            let state = provider.history_by_block_number(number).map_err(BlockExecutionError::other)?;
            self.sweep_installed(state.as_ref())
        };
        if head == 0 || !installed_at(head)? {
            self.clear_switch();
            return Ok(None);
        }
        let (mut without, mut with) = (0, head);
        while with - without > 1 {
            let middle = without + (with - without) / 2;
            if installed_at(middle)? {
                with = middle;
            } else {
                without = middle;
            }
        }
        self.next_from.store(with, Ordering::Release);
        Ok(Some(with))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule() -> RuleSchedule {
        RuleSchedule::new(ChainSpec::mainnet_v1(), ChainSpec::mainnet()).unwrap()
    }

    #[test]
    fn blocks_run_the_base_rules_until_the_switch_and_the_next_rules_from_it() {
        let rules = schedule();
        assert_eq!(rules.at(1), &ChainSpec::mainnet_v1());
        assert_eq!(rules.next_from(), None);
        assert!(!rules.is_next(u64::MAX - 1));
        rules.switch_at(7).unwrap();
        assert_eq!(rules.at(6), &ChainSpec::mainnet_v1());
        assert!(!rules.is_next(6));
        assert_eq!(rules.at(7), &ChainSpec::mainnet());
        assert_eq!(rules.at(8), &ChainSpec::mainnet());
        assert!(rules.is_next(7));
    }

    #[test]
    fn the_switch_happens_once_and_never_at_genesis() {
        let rules = schedule();
        assert!(rules.switch_at(0).is_err());
        rules.switch_at(7).unwrap();
        rules.switch_at(7).unwrap();
        assert!(rules.switch_at(8).is_err());
        assert!(rules.switch_at(6).is_err());
        rules.clear_switch();
        rules.switch_at(6).unwrap();
    }

    #[test]
    fn clones_share_the_switch() {
        let rules = schedule();
        let reader = rules.clone();
        rules.switch_at(3).unwrap();
        assert_eq!(reader.next_from(), Some(3));
    }

    #[test]
    fn a_development_network_has_one_rule_set() {
        let rules = RuleSchedule::single(ChainSpec::testnet_v3());
        assert!(rules.switch_at(1).is_err());
        assert_eq!(rules.at(u64::MAX - 1), &ChainSpec::testnet_v3());
    }

    #[test]
    fn a_next_rule_set_may_change_nothing_else() {
        let mut other = ChainSpec::mainnet();
        other.deposit_gas += 1;
        assert!(RuleSchedule::new(ChainSpec::mainnet_v1(), other).is_err());
        let mut no_sweep = ChainSpec::mainnet();
        no_sweep.fee_vault_sweep = None;
        assert!(RuleSchedule::new(ChainSpec::mainnet_v1(), no_sweep).is_err());
        assert!(RuleSchedule::new(ChainSpec::mainnet(), ChainSpec::mainnet()).is_err());
        assert!(RuleSchedule::new(ChainSpec::testnet_v3(), ChainSpec::mainnet()).is_err());
    }
}
