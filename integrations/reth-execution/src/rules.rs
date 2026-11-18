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
//! everything else in the stack (header layout, gas limit, chain id) reads the
//! base rules and needs no block number. The genesis is the same under both.
//!
//! What they may differ in includes the base-fee floor (`min_base_fee`), so the
//! base fee of a block and the link of a block to its parent are NOT among the
//! things the base rules answer (F387-1: three fixes in a row each found one more
//! caller that asked the base rules). This module is the one place that answers
//! them: [`RuleSchedule::base_fee_after`], [`RuleSchedule::validate_link`] and
//! [`RuleSchedule::validate_body`] take the rules of the block in question, and
//! no other code of this crate or of the producer and follower calls the kernel's
//! `ChainSpec::next_base_fee` or `NodeHeaderV2::validate_parent` (the test
//! `no_caller_asks_a_rule_set_of_its_own_choice` reads the sources).
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::Bytes;
use bloch_l2_evm::{
    chainspec::fee_vault_sweep_code,
    node_primitives::{NodeBodyError, NodeBodyV2, NodeHeaderError, NodeHeaderV2},
    ChainSpec,
};
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
        Self {
            base,
            next: None,
            next_from: Arc::new(AtomicU64::new(UNSET)),
        }
    }

    /// A base and a next rule set. Refused unless they differ only in the block
    /// derivation and the fee-vault sweep.
    pub fn new(base: ChainSpec, next: ChainSpec) -> Result<Self, BlockExecutionError> {
        // Forced inclusion (candidate) is part of the next rules when the core
        // crate is built with it; the base rules never have it. The base-fee
        // floor (agent 197) is also a next-rules addition.
        let comparable = ChainSpec {
            block_derivation: base.block_derivation,
            fee_vault_sweep: base.fee_vault_sweep,
            forced_inclusion: base.forced_inclusion,
            min_base_fee: base.min_base_fee,
            ..next.clone()
        };
        if comparable != base || next.fee_vault_sweep.is_none() || base.fee_vault_sweep.is_some() {
            return Err(BlockExecutionError::msg(
                "the next rule set may add only the block derivation and the fee-vault sweep",
            ));
        }
        next.validate().map_err(BlockExecutionError::other)?;
        Ok(Self {
            base,
            next: Some(next),
            next_from: Arc::new(AtomicU64::new(UNSET)),
        })
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

    /// The base fee of the block after `parent`, under the rules of THAT block:
    /// the EIP-1559 step, raised to the floor where the block's rules have one.
    /// At the first block of the next rules the parent is a base-rules block and
    /// the result is still the next rules' (the floor applies from that block).
    pub fn base_fee_after(&self, parent: &NodeHeaderV2) -> u64 {
        self.at(parent.number.saturating_add(1))
            .next_base_fee(parent.base_fee_per_gas, parent.gas_used)
    }

    /// The base fee of the block after `parent` if that block is the FIRST of the
    /// next rules (the producer's `extend --rule-set next`). `None` on a network
    /// without a next rule set and once the switch is fixed, when
    /// [`Self::base_fee_after`] already answers.
    pub fn base_fee_after_switching(&self, parent: &NodeHeaderV2) -> Option<u64> {
        match (&self.next, self.next_from()) {
            (Some(next), None) => Some(next.next_base_fee(parent.base_fee_per_gas, parent.gas_used)),
            _ => None,
        }
    }

    /// What a fee QUOTE should assume for the block after `parent` (never a rule: blocks are built and judged
    /// with [`Self::base_fee_after`]). Before the switch nobody on the L2 knows whether the next block is the
    /// first of the next rules, and on a chain whose fee has fallen under the floor that block starts at the
    /// floor: a wallet that priced from the base rules' step would sign a fee cap the switch block leaves
    /// under the tip floor, and wait (F404-2, review R406-5). The quote is therefore the higher of the two
    /// until the switch is fixed, and [`Self::base_fee_after`] from then on and on a network with one rule set.
    pub fn base_fee_quote(&self, parent: &NodeHeaderV2) -> u64 {
        let next = self.base_fee_after(parent);
        self.base_fee_after_switching(parent).map_or(next, |switching| next.max(switching))
    }

    /// The link of `header` to its parent, judged on the rules of `header`'s
    /// block: what [`Self::base_fee_after`] builds, this accepts, and nothing else.
    pub fn validate_link(&self, header: &NodeHeaderV2, parent: &NodeHeaderV2) -> Result<(), NodeHeaderError> {
        header.validate_parent(self.at(header.number), parent)
    }

    /// The body of block `number`, on that block's rules.
    pub fn validate_body(&self, number: u64, body: &NodeBodyV2) -> Result<(), NodeBodyError> {
        body.validate(self.at(number))
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
        match self
            .next_from
            .compare_exchange(UNSET, number, Ordering::AcqRel, Ordering::Acquire)
        {
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
        let code = state
            .account_code(&self.base.base_fee_vault)
            .map_err(BlockExecutionError::other)?;
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
            let state = provider
                .history_by_block_number(number)
                .map_err(BlockExecutionError::other)?;
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
        RuleSchedule::new(ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal()).unwrap()
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
        assert_eq!(rules.at(7), &ChainSpec::mainnet_next_or_rehearsal());
        assert_eq!(rules.at(8), &ChainSpec::mainnet_next_or_rehearsal());
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
        let mut other = ChainSpec::mainnet_next_or_rehearsal();
        other.deposit_gas += 1;
        assert!(RuleSchedule::new(ChainSpec::mainnet_v1(), other).is_err());
        let mut no_sweep = ChainSpec::mainnet_next_or_rehearsal();
        no_sweep.fee_vault_sweep = None;
        assert!(RuleSchedule::new(ChainSpec::mainnet_v1(), no_sweep).is_err());
        assert!(RuleSchedule::new(
            ChainSpec::mainnet_next_or_rehearsal(),
            ChainSpec::mainnet_next_or_rehearsal()
        )
        .is_err());
        assert!(RuleSchedule::new(ChainSpec::testnet_v3(), ChainSpec::mainnet_next_or_rehearsal()).is_err());
    }

    /// The release gate (agent 163, B-1): without the owner's recipient there is
    /// no next rule set to schedule.
    #[test]
    fn no_next_rules_without_the_release_recipient() {
        let scheduled = RuleSchedule::new(ChainSpec::mainnet_v1(), ChainSpec::mainnet());
        assert_eq!(
            scheduled.is_ok(),
            bloch_l2_evm::chainspec::MAINNET_FEE_SWEEP_RECIPIENT.is_some()
        );
    }

    // ---- F387-1: one source of the per-block rules for the base fee and the parent link ----

    fn header(number: u64, base_fee: u64, gas_used: u64) -> NodeHeaderV2 {
        let spec = ChainSpec::mainnet_v1();
        NodeHeaderV2 {
            domain: alloy_primitives::B256::repeat_byte(0x70),
            chain_id: spec.chain_id,
            number,
            timestamp: 1_786_656_679 + number,
            base_fee_per_gas: base_fee,
            gas_limit: spec.gas_limit,
            gas_used,
            user_gas_used: 0,
            beneficiary: spec.coinbase(),
            ..NodeHeaderV2::default()
        }
    }

    fn child(rules: &RuleSchedule, parent: &NodeHeaderV2) -> NodeHeaderV2 {
        NodeHeaderV2 {
            parent_hash: parent.hash(),
            parent_state_root: parent.state_root,
            ..header(parent.number + 1, rules.base_fee_after(parent), 0)
        }
    }

    /// The property the three F387-1 fixes were after, stated once: for every parent
    /// and every position of the switch, the base fee the schedule gives the child is
    /// the one the child's own rules compute (what the executor and the guest of that
    /// block's program require), the link built from it is accepted, and a link built
    /// from the OTHER rule set's value is refused whenever the two differ.
    #[test]
    fn f387_1_the_base_fee_and_the_parent_link_are_the_rules_of_the_child_at_every_position() {
        let (base, next) = (ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal());
        let floor = next.min_base_fee;
        assert!(floor > 0 && base.min_base_fee == 0, "the floor is a next-rules addition");
        let target = base.gas_target();
        // Fees around the floor, far above it and at the bottom; empty, at target and full parents.
        let fees = [1, 7, floor / 2, floor - 1, floor, floor + 1, 100_134_788, 100_218_107, 100_401_761, 2 * floor, 1_000_000_000];
        let gas = [0, 21_000, target, base.gas_limit];
        let (mut differing, mut cases) = (0u32, 0u32);
        for switch in [None, Some(1u64), Some(575), Some(576), Some(577), Some(1_000)] {
            let rules = schedule();
            if let Some(number) = switch {
                rules.switch_at(number).unwrap();
            }
            for number in [1u64, 574, 575, 576, 999] {
                for fee in fees {
                    for used in gas {
                        let parent = header(number, fee, used);
                        let own = rules.at(number + 1);
                        let other = if rules.is_next(number + 1) { &base } else { &next };
                        let built = child(&rules, &parent);
                        let expected = own.next_base_fee(fee, used);
                        assert_eq!(built.base_fee_per_gas, expected, "switch {switch:?}, parent {number}, fee {fee}, gas {used}");
                        if rules.is_next(number + 1) {
                            assert!(built.base_fee_per_gas >= floor, "a next-rules block is never under the floor");
                        }
                        rules.validate_link(&built, &parent).expect("the link the schedule built");
                        let foreign = other.next_base_fee(fee, used);
                        cases += 1;
                        if foreign != expected {
                            differing += 1;
                            let wrong = NodeHeaderV2 { base_fee_per_gas: foreign, ..built.clone() };
                            assert!(
                                matches!(rules.validate_link(&wrong, &parent), Err(NodeHeaderError::Parent)),
                                "the other rule set's base fee: switch {switch:?}, parent {number}, fee {fee}, gas {used}"
                            );
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 6 * 5 * 11 * 4);
        assert!(differing > 200, "the cases reach under the floor: {differing}");
    }

    /// The launch chain runs the base rules first: its base fee falls under 0.1 gwei
    /// after about 575 quiet blocks (800 here: under half of it). The first block of the next rules then starts at
    /// the floor (a step up from its parent), and the blocks after it stay there.
    #[test]
    fn f387_1_the_first_next_block_after_a_base_fee_under_the_floor_starts_at_the_floor() {
        let next = ChainSpec::mainnet_next_or_rehearsal();
        let rules = schedule();
        let mut head = header(0, 1_000_000_000, 0);
        for _ in 0..800 {
            let parent = head.clone();
            head = child(&rules, &parent);
            rules.validate_link(&head, &parent).unwrap();
        }
        assert!(head.base_fee_per_gas < next.min_base_fee / 2, "800 quiet base blocks: {}", head.base_fee_per_gas);
        assert_eq!(rules.base_fee_after_switching(&head), Some(next.min_base_fee));
        assert!(rules.base_fee_after(&head) < head.base_fee_per_gas, "not switched: the base rules' step");
        rules.switch_at(801).unwrap();
        assert_eq!(rules.base_fee_after_switching(&head), None);
        assert_eq!(RuleSchedule::single(ChainSpec::testnet_v3()).base_fee_after_switching(&head), None);
        for _ in 0..3 {
            let parent = head.clone();
            head = child(&rules, &parent);
            assert_eq!(head.base_fee_per_gas, next.min_base_fee);
            rules.validate_link(&head, &parent).unwrap();
        }
        // The base-rules history before the switch still links on the base rules.
        let a = header(799, 61_000_000, 0);
        let b = child(&rules, &a);
        assert!(b.base_fee_per_gas < 61_000_000, "block 800 is a base-rules block: no floor");
        rules.validate_link(&b, &a).unwrap();
    }

    /// F404-2 (review R406-5): before the switch the quote covers the case that the next block is the
    /// switch block; it is never under what the next block will really carry, whichever rules it runs.
    #[test]
    fn f404_2_a_fee_quote_before_the_switch_is_not_under_the_floor_the_switch_block_starts_at() {
        let (base, next) = (ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal());
        let floor = next.min_base_fee;
        let rules = schedule();
        // Chain 2 of the end-to-end test: head 580 on the base rules at 97,817,550.
        let under = header(580, 97_817_550, 0);
        assert_eq!(rules.base_fee_after(&under), 97_426_280, "what a base-rules block 581 carries");
        assert_eq!(rules.base_fee_quote(&under), floor, "what a wallet must be able to pay if 581 is the switch");
        // Above the floor, and with a busy parent, the quote is the higher of the two rule sets' values.
        for (fee, used) in [(1_000_000_000, 0), (100_218_107, 0), (floor, base.gas_limit), (7, 0), (floor + 1, 21_000)] {
            let parent = header(9, fee, used);
            let (as_base, as_switch) = (base.next_base_fee(fee, used), next.next_base_fee(fee, used));
            assert_eq!(rules.base_fee_quote(&parent), as_base.max(as_switch), "fee {fee}, gas {used}");
            assert!(rules.base_fee_quote(&parent) >= rules.base_fee_after(&parent));
        }
        // Once the switch is fixed there is one answer, and the quote is it.
        rules.switch_at(581).unwrap();
        assert_eq!(rules.base_fee_quote(&under), rules.base_fee_after(&under));
        assert_eq!(rules.base_fee_quote(&under), floor);
        let earlier = header(400, 97_817_550, 0);
        assert_eq!(rules.base_fee_quote(&earlier), base.next_base_fee(97_817_550, 0), "a base-rules block before the switch");
        // One rule set: nothing to cover.
        let single = RuleSchedule::single(ChainSpec::testnet_v3());
        assert_eq!(single.base_fee_quote(&under), single.base_fee_after(&under));
    }

    /// Reads the sources: outside this module nothing in this crate, the producer or
    /// the follower calls the kernel's `next_base_fee` or `validate_parent`, because
    /// each such call names a rule set of the caller's choice (F387-1 was three of
    /// them). Test modules may (they state kernel expectations); everything after a
    /// file's first test module must be test modules only, so nothing hides there.
    #[test]
    fn no_caller_asks_a_rule_set_of_its_own_choice() {
        use std::path::{Path, PathBuf};
        fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&here.join("src"), &mut files);
        sources(&here.join("../settlement-recovery/src"), &mut files);
        files.sort();
        assert!(files.len() > 40, "the two crates were found: {}", files.len());
        let forbidden = ["validate_parent(", "next_base_fee("];
        let (mut offenders, mut scanned, mut seen_here) = (Vec::new(), 0usize, 0usize);
        for file in &files {
            let name = file.file_name().unwrap().to_str().unwrap();
            let text = std::fs::read_to_string(file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            if name.ends_with("_tests.rs") {
                // A whole-file test module: it must be included as one.
                continue;
            }
            // The first test module: `#[cfg(test)]`, an optional `#[path]`, then `mod`.
            let is_mod = |i: usize| lines.get(i).is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub mod "));
            let cut = (0..lines.len())
                .find(|&i| lines[i] == "#[cfg(test)]" && (is_mod(i + 1) || (lines[i + 1].starts_with("#[path") && is_mod(i + 2))))
                .unwrap_or(lines.len());
            for (index, line) in lines[cut..].iter().enumerate() {
                let test_only = line.is_empty()
                    || line.starts_with(' ')
                    || line.starts_with("//")
                    || line.starts_with("#[cfg(test)]")
                    || line.starts_with("#[cfg(all(test,")
                    || line.starts_with("#[path")
                    || line.starts_with("mod ")
                    || line.starts_with("pub mod ")
                    || *line == "}";
                assert!(test_only, "{}:{}: code after the first test module: {line}", file.display(), cut + index + 1);
            }
            for (index, line) in lines[..cut].iter().enumerate() {
                let code = line.split("//").next().unwrap();
                for token in forbidden {
                    for (at, _) in code.match_indices(token) {
                        let before = &code[..at];
                        if !(before.ends_with('.') || before.ends_with("::")) {
                            continue; // a definition or another name ending in the token
                        }
                        if name == "rules.rs" && file.starts_with(here) {
                            seen_here += 1;
                        } else {
                            offenders.push(format!("{}:{}: {}", file.display(), index + 1, line.trim()));
                        }
                    }
                }
            }
            scanned += cut;
        }
        assert!(offenders.is_empty(), "a rule set chosen by the caller:\n{}", offenders.join("\n"));
        // Not vacuous: the scan sees the two kernel calls this module makes, and real code.
        assert_eq!(seen_here, 3, "the scan finds this module's own three kernel calls");
        assert!(scanned > 8_000, "lines scanned: {scanned}");
    }
}
