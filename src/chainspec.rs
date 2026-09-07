// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chain specification — the design's genesis knobs (BLOCH-L2-EVM-DESIGN §1).
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** These are the testnet /
//! zero-value parameters; chain id 700771 is a placeholder pending
//! ethereum-lists/chains registration.

use alloy_primitives::{address, hex, Address, U256};
use revm::primitives::hardfork::SpecId;

use crate::scale::SATS_PER_BLCH;

/// OP-Stack-convention predeploy address for the sequencer fee vault
/// (priority fees land here; it is also the block's COINBASE, per the design:
/// "COINBASE returns the fee-vault address").
pub const SEQUENCER_FEE_VAULT: Address = address!("4200000000000000000000000000000000000011");

/// OP-Stack-convention predeploy address for the base-fee vault. The EIP-1559
/// basefee is routed here instead of being destroyed — bridged BLCH is
/// **never burned by the protocol**, so the L1 escrow always balances and no
/// party operates a BLCH supply-reduction mechanism. (The EVM itself can still
/// destroy value via EIP-6780 SELFDESTRUCT-to-self in the creating
/// transaction; see the audit report, finding C11.)
pub const BASE_FEE_VAULT: Address = address!("4200000000000000000000000000000000000019");

/// System account holding the **committed supply ledger**: the cumulative
/// bridged-BLCH wei ever minted (storage slot 0) and the **deposit cursor**
/// (slot 1) — the canonical L1 position of the last consumed escrow output
/// (see [`crate::state::DepositPosition`]).
///
/// It is a plain storage-bearing account with `nonce = 1` and no code, created
/// lazily by the first deposit, so it is a leaf of the keccak-MPT state root:
/// the ledger is part of every state commitment, carried by the batch witness
/// like any other account (two slots, whatever the chain's history), and
/// re-checked by a stateless guest. The address is outside the OP-Stack
/// predeploy byte range (`0x4200…00xx`).
pub const SUPPLY_LEDGER: Address = address!("4200000000000000000000000000000000000100");

/// System account holding the **committed block-header record** of the head
/// block (number, timestamp, base fee, gas used, prevrandao, anchor root,
/// parent hash, deposits hash — slots `0..=8`, see `crate::state::BLOCK_INFO_*`)
/// and a 256-entry **ring buffer of L2 block hashes** (slot `0x100 + n % 256`
/// holds the hash of block `n`, EIP-2935 style). The executor validates every
/// block against the record (EIP-1559 rule, number, timestamp), writes the
/// parent's hash into the ring at block start and serves `BLOCKHASH` from it,
/// so header validity and block hashes are part of the state commitment and
/// re-checked by a stateless guest. Nonce 1, no code, created lazily.
pub const BLOCK_INFO: Address = address!("4200000000000000000000000000000000000101");

/// EIP-4788 beacon-roots contract address (Cancun). On this L2 the 32-byte
/// value written at each block start is the **Bloch anchor block hash**
/// ([`crate::executor::BlockContext::anchor_root`]) — the L1 value the design
/// exposes to contracts, in the slot Ethereum uses for the beacon root.
pub const BEACON_ROOTS_ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

/// Canonical EIP-4788 beacon-roots contract bytecode. Installed by the STF as a
/// system account (nonce 1) the first time a block executes, and by
/// [`crate::state::L2State::genesis`].
pub const BEACON_ROOTS_CODE: &[u8] = &hex!("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500");

/// Hard cap on the Bloch L1 supply, in sats, used to bound deposits:
/// **100 000 000 000 BLCH** (confirmed by the project) = 10^19 sats at 8
/// decimals = 10^29 wei on the L2. The L2 has no cap of its own: its native
/// supply is bridged BLCH with zero issuance, so this is also the maximum the
/// supply ledger can ever reach. 10^19 fits `u64` (max ≈ 1.8 × 10^19) but
/// **not** `i64`, so the L1's amount type must be unsigned 64-bit or wider.
/// A `ChainSpec` knob so a future L1 change never touches the executor.
pub const MAX_L1_SATS: u64 = 100_000_000_000 * SATS_PER_BLCH;

/// Genesis / consensus-parameter knobs for the Bloch EVM L2, mirroring
/// `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1's ChainSpec.
///
/// The EVM itself is UNMODIFIED revm at a named hardfork ([`SpecId::CANCUN`]).
/// The only deltas from mainline Ethereum are the enumerated, legal,
/// non-semantic knobs below (chain id, fee routing, zero issuance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSpec {
    /// EIP-155 chain id. 700771 = proposed Bloch L2 **testnet** id
    /// (placeholder pending ethereum-lists/chains registration).
    pub chain_id: u64,
    /// The pinned revm hardfork. CANCUN at genesis; Prague only via a
    /// coordinated, height-gated upgrade (out of scope for this scaffold).
    pub spec_id: SpecId,
    /// Block gas limit — Ethereum-mainnet parity (30M) so any
    /// mainnet-deployable contract deploys.
    pub gas_limit: u64,
    /// Target L2 block time in seconds (informational for this scaffold; no
    /// consensus loop exists here).
    pub block_time_secs: u64,
    /// EIP-1559 elasticity multiplier (gas target = gas_limit / elasticity).
    pub base_fee_elasticity: u64,
    /// EIP-1559 base-fee max-change denominator (raised toward the OP-Stack
    /// range so the basefee is stable at 2s blocks — a chain-config value
    /// Ethereum itself varies per network, not an EVM change).
    pub base_fee_denominator: u64,
    /// Base fee of the genesis block, in wei per gas (1 gwei).
    pub initial_base_fee: u64,
    /// Block reward. **Always zero**: the L2 never issues — native balance
    /// enters only via deposit mints of bridged BLCH.
    pub block_reward: U256,
    /// Where the EIP-1559 basefee is routed (never burned).
    pub base_fee_vault: Address,
    /// Where priority fees are routed; also the block beneficiary /
    /// COINBASE.
    pub sequencer_fee_vault: Address,
    /// The committed supply-ledger system account (see [`SUPPLY_LEDGER`]).
    pub supply_ledger: Address,
    /// The committed block-info system account (see [`BLOCK_INFO`]).
    pub block_info: Address,
    /// Hard cap on the L1 supply in sats: no single deposit may claim more,
    /// and the cumulative minted supply may never exceed it. See
    /// [`MAX_L1_SATS`].
    pub max_l1_sats: u64,
}

impl ChainSpec {
    /// The testnet / zero-value parameter set from the design.
    pub fn testnet() -> Self {
        Self {
            chain_id: 700_771,
            spec_id: SpecId::CANCUN,
            gas_limit: 30_000_000,
            block_time_secs: 2,
            base_fee_elasticity: 2,
            base_fee_denominator: 250,
            initial_base_fee: 1_000_000_000, // 1 gwei
            block_reward: U256::ZERO,
            base_fee_vault: BASE_FEE_VAULT,
            sequencer_fee_vault: SEQUENCER_FEE_VAULT,
            supply_ledger: SUPPLY_LEDGER,
            block_info: BLOCK_INFO,
            max_l1_sats: MAX_L1_SATS,
        }
    }

    /// The address the COINBASE opcode observes (the design routes it to the
    /// sequencer fee vault so priority fees land there via unmodified revm
    /// beneficiary payment).
    pub fn coinbase(&self) -> Address {
        self.sequencer_fee_vault
    }

    /// EIP-1559 gas target per block (`gas_limit / elasticity`).
    pub fn gas_target(&self) -> u64 {
        self.gas_limit / self.base_fee_elasticity
    }

    /// EIP-1559 next-base-fee computation with this chain's elasticity /
    /// denominator knobs. Pure integer math (u128 internally, no overflow for
    /// any realistic base fee), byte-identical to the Ethereum formula with
    /// retuned constants.
    pub fn next_base_fee(&self, parent_base_fee: u64, parent_gas_used: u64) -> u64 {
        let target = self.gas_target();
        if target == 0 {
            return parent_base_fee;
        }
        let parent = parent_base_fee as u128;
        let denom = self.base_fee_denominator as u128;
        match parent_gas_used.cmp(&target) {
            core::cmp::Ordering::Equal => parent_base_fee,
            core::cmp::Ordering::Greater => {
                let gas_delta = (parent_gas_used - target) as u128;
                let delta = core::cmp::max(1, parent * gas_delta / target as u128 / denom);
                u64::try_from(parent + delta).unwrap_or(u64::MAX)
            }
            core::cmp::Ordering::Less => {
                let gas_delta = (target - parent_gas_used) as u128;
                let delta = parent * gas_delta / target as u128 / denom;
                u64::try_from(parent - delta).unwrap_or(0)
            }
        }
    }
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self::testnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_knobs_match_design() {
        let spec = ChainSpec::testnet();
        assert_eq!(spec.chain_id, 700_771);
        assert_eq!(spec.spec_id, SpecId::CANCUN);
        assert_eq!(spec.gas_limit, 30_000_000);
        assert_eq!(spec.base_fee_elasticity, 2);
        assert_eq!(spec.base_fee_denominator, 250);
        assert_eq!(spec.initial_base_fee, 1_000_000_000);
        assert_eq!(spec.block_reward, U256::ZERO, "zero issuance, always");
        assert_eq!(spec.gas_target(), 15_000_000);
        assert_eq!(spec.coinbase(), SEQUENCER_FEE_VAULT);
        assert_ne!(spec.base_fee_vault, spec.sequencer_fee_vault);
        assert_ne!(spec.supply_ledger, spec.base_fee_vault);
        assert_ne!(spec.supply_ledger, spec.sequencer_fee_vault);
        assert_ne!(spec.block_info, spec.supply_ledger);
        assert_eq!(BEACON_ROOTS_CODE.len(), 97, "canonical EIP-4788 bytecode");
        assert_eq!(spec.max_l1_sats, 100_000_000_000 * SATS_PER_BLCH);
    }

    #[test]
    fn l1_cap_is_100_billion_blch_and_fits_the_amount_types() {
        assert_eq!(MAX_L1_SATS, 10_000_000_000_000_000_000u64, "10^19 sats");
        assert!(MAX_L1_SATS > i64::MAX as u64, "needs unsigned 64-bit sats on the L1");
        // 10^29 wei: the most the L2 supply ledger can ever hold.
        let cap_wei = crate::scale::sats_to_wei(MAX_L1_SATS);
        assert_eq!(cap_wei, U256::from(10u128.pow(29)));
        assert_eq!(cap_wei, U256::from(100_000_000_000u64) * U256::from(10u64).pow(U256::from(18)), "100 billion × 10^18 wei");
    }

    #[test]
    fn base_fee_constant_at_target() {
        let spec = ChainSpec::testnet();
        let bf = spec.initial_base_fee;
        assert_eq!(spec.next_base_fee(bf, spec.gas_target()), bf);
    }

    #[test]
    fn base_fee_rises_on_full_block() {
        let spec = ChainSpec::testnet();
        let bf = 1_000_000_000u64;
        // full block: gas_used = gas_limit = 2 * target → delta = bf / denominator
        let next = spec.next_base_fee(bf, spec.gas_limit);
        assert_eq!(next, bf + bf / 250);
        assert!(next > bf);
    }

    #[test]
    fn base_fee_falls_on_empty_block() {
        let spec = ChainSpec::testnet();
        let bf = 1_000_000_000u64;
        // empty block: gas_used = 0 → delta = bf / denominator
        let next = spec.next_base_fee(bf, 0);
        assert_eq!(next, bf - bf / 250);
        assert!(next < bf);
    }

    #[test]
    fn base_fee_increase_is_at_least_one_wei() {
        let spec = ChainSpec::testnet();
        // tiny parent base fee: integer division would give 0; EIP-1559
        // clamps the increase to at least 1 wei.
        let next = spec.next_base_fee(1, spec.gas_limit);
        assert_eq!(next, 2);
    }
}
