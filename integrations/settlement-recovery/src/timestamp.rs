// SPDX-License-Identifier: AGPL-3.0-or-later
//! L2 block timestamps tied to L1 time, as Ethereum rollups do (OP Stack:
//! an L2 block's time follows its L1 origin). From `from_l2_number` on, a
//! block's timestamp is the start time of its anchored native slot, and never
//! less than the parent's timestamp plus one. Earlier blocks keep the
//! development rule `parent + 1`, so already settled history reproduces.
//!
//! The producer (`extend`) and every rebuilder (`reconstruct`, attestors)
//! derive the timestamp with the same rule; a block that breaks it does not
//! rebuild to its settled header hash and is refused.

/// `FROM_L2_NUMBER:L1_GENESIS_UNIX_SECS:L1_SLOT_MILLIS`, e.g. `220:1760300000:2000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimestampRule {
    pub from_l2_number: u64,
    pub l1_genesis_time: u64,
    pub l1_slot_millis: u64,
}

impl TimestampRule {
    pub fn parse(text: &str) -> Result<Self, String> {
        let parts: Vec<&str> = text.split(':').collect();
        let [from, genesis, slot] = parts.as_slice() else {
            return Err("--timestamp-rule must be FROM_L2_NUMBER:L1_GENESIS_UNIX_SECS:L1_SLOT_MILLIS".into());
        };
        let number = |value: &str, field: &str| -> Result<u64, String> {
            value
                .parse::<u64>()
                .map_err(|_| format!("--timestamp-rule {field} must be decimal"))
        };
        let rule = Self {
            from_l2_number: number(from, "FROM_L2_NUMBER")?,
            l1_genesis_time: number(genesis, "L1_GENESIS_UNIX_SECS")?,
            l1_slot_millis: number(slot, "L1_SLOT_MILLIS")?,
        };
        if rule.from_l2_number == 0 || rule.l1_slot_millis == 0 {
            return Err("--timestamp-rule needs a non-zero first L2 number and slot duration".into());
        }
        Ok(rule)
    }

    /// The mainnet rule: wall-clock L2 time from the first block after
    /// genesis (the genesis itself is stamped with wall-clock seconds by the
    /// network profile), so no block of the chain is ever stamped `parent + 1`
    /// by a development rule.
    pub fn from_genesis(l1_genesis_time: u64, l1_slot_millis: u64) -> Result<Self, String> {
        let rule = Self {
            from_l2_number: 1,
            l1_genesis_time,
            l1_slot_millis,
        };
        rule.require_from_genesis()?;
        Ok(rule)
    }

    /// Refuse a rule that leaves any block after genesis on `parent + 1`
    /// (devnet4 switched at block 228; mainnet must not).
    pub fn require_from_genesis(&self) -> Result<(), String> {
        if self.from_l2_number != 1 || self.l1_slot_millis == 0 {
            return Err(
                "the mainnet timestamp rule must apply from L2 block 1 (--timestamp-rule 1:GENESIS:SLOT_MS)".into(),
            );
        }
        Ok(())
    }

    /// Start time (unix seconds) of native slot `slot`.
    pub fn l1_time(&self, slot: u64) -> Option<u64> {
        self.l1_genesis_time
            .checked_add(slot.checked_mul(self.l1_slot_millis)? / 1000)
    }
}

/// Timestamp of L2 block `number` on a parent stamped `parent_timestamp`,
/// anchored to native slot `anchor_slot`. `None` on overflow, or when the rule
/// applies and the anchor slot is unknown.
pub fn next_timestamp(
    rule: Option<&TimestampRule>,
    number: u64,
    parent_timestamp: u64,
    anchor_slot: Option<u64>,
) -> Option<u64> {
    let successor = parent_timestamp.checked_add(1)?;
    match rule {
        Some(rule) if number >= rule.from_l2_number => Some(successor.max(rule.l1_time(anchor_slot?)?)),
        _ => Some(successor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: TimestampRule = TimestampRule {
        from_l2_number: 10,
        l1_genesis_time: 1_000,
        l1_slot_millis: 2_000,
    };

    #[test]
    fn history_before_activation_keeps_parent_plus_one() {
        assert_eq!(next_timestamp(None, 50, 7, Some(99)), Some(8));
        assert_eq!(next_timestamp(Some(&RULE), 9, 7, None), Some(8));
    }

    #[test]
    fn follows_the_anchored_slot_and_stays_strictly_increasing() {
        // Slot 30 starts at 1000 + 30 * 2 s.
        assert_eq!(next_timestamp(Some(&RULE), 10, 9, Some(30)), Some(1_060));
        // An anchor that lags the parent never moves time backwards.
        assert_eq!(next_timestamp(Some(&RULE), 11, 1_060, Some(30)), Some(1_061));
        assert_eq!(next_timestamp(Some(&RULE), 12, 1_061, Some(31)), Some(1_062));
        assert_eq!(next_timestamp(Some(&RULE), 13, 1_062, Some(40)), Some(1_080));
    }

    #[test]
    fn the_rule_needs_the_anchor_slot_and_refuses_overflow() {
        assert_eq!(next_timestamp(Some(&RULE), 10, 9, None), None);
        assert_eq!(next_timestamp(None, 1, u64::MAX, None), None);
        assert_eq!(next_timestamp(Some(&RULE), 10, 9, Some(u64::MAX)), None);
    }

    #[test]
    fn mainnet_rule_starts_at_block_one() {
        let rule = TimestampRule::from_genesis(1_000, 2_000).unwrap();
        assert_eq!(rule.from_l2_number, 1);
        assert_eq!(TimestampRule::parse("1:1000:2000").unwrap(), rule);
        assert!(TimestampRule::from_genesis(1_000, 0).is_err());
        assert!(
            RULE.require_from_genesis().is_err(),
            "a devnet-style switch at block 10"
        );
        // Block 1 already follows the anchored slot, even on a wall-clock genesis.
        assert_eq!(next_timestamp(Some(&rule), 1, 1_050, Some(30)), Some(1_060));
        assert_eq!(next_timestamp(Some(&rule), 1, 1_050, None), None);
    }

    #[test]
    fn parses_and_validates() {
        assert_eq!(TimestampRule::parse("10:1000:2000"), Ok(RULE));
        for bad in ["", "1:2", "0:1000:2000", "10:1000:0", "10:x:2000", "1:2:3:4"] {
            assert!(TimestampRule::parse(bad).is_err(), "{bad}");
        }
    }
}
