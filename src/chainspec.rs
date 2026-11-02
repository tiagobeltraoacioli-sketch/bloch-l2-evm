// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chain specification — the design's genesis knobs (BLOCH-L2-EVM-DESIGN §1).
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** These are the testnet /
//! zero-value parameters; chain id 700771 is the selected testnet identity but
//! remains blocked on public registration and a frozen production genesis.

use alloy_primitives::{address, hex, Address, B256, U256};
use revm::primitives::hardfork::SpecId;

use crate::scale::SATS_PER_BLCH;

/// Gas charged to the block budget for each deposit system-transaction
/// (the cost of a plain value transfer). Deposits pay no fee — the L1 escrow
/// paid on the L1 — but they consume block capacity like any transaction, so a
/// block carries at most `gas_limit / deposit_gas` of them and heavy deposit
/// traffic moves the EIP-1559 base fee exactly like user traffic does (the
/// OP-Stack precedent). Overflow is carried by the derivation layer into the
/// following blocks, in canonical order.
pub const DEPOSIT_GAS: u64 = 21_000;

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

/// EIP-155 chain id of the Bloch L2 development networks and the selected
/// testnet (devnet2..devnet4). Unchanged by the mainnet profile.
pub const TESTNET_CHAIN_ID: u64 = 700_771;

/// EIP-155 chain id decided for the Bloch L2 **mainnet** (2026-10-14). Only
/// [`ChainSpec::mainnet`] uses it; a transaction signed for 700771 never
/// authenticates under it and vice versa.
pub const MAINNET_CHAIN_ID: u64 = 700_770;

/// The Bloch L1 (Genesis-4) admission network domain: SHA3-256 of the
/// canonical encoding of `genesis/mainnet.manifest` (file SHA-256
/// `7eef82a7…b2dd`), pinned in the native node as the live admission domain.
/// It is the native policy's `identities[0]`; here it only seeds
/// [`MAINNET_DOMAIN`].
pub const GENESIS4_NETWORK_DOMAIN: B256 =
    B256::new(hex!("f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966"));

/// Domain tag of [`MAINNET_DOMAIN`].
pub const MAINNET_DOMAIN_TAG: &[u8] = b"BLOCH:L2:MAINNET-DOMAIN:1";

/// The V2 header domain of the Bloch L2 mainnet, compiled into its
/// settlement guest:
/// `keccak256("BLOCH:L2:MAINNET-DOMAIN:1" || MAINNET_CHAIN_ID (u64 BE) || GENESIS4_NETWORK_DOMAIN)`.
/// Derived from public values only (no ceremony secret): it binds the L2 to
/// its chain id and to the L1 network it settles on, and differs from the
/// development domain `0xd3…d3` and from zero.
pub const MAINNET_DOMAIN: B256 =
    B256::new(hex!("1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733"));

/// L2 mainnet genesis timestamp (unix seconds): the Genesis-4 slot-0 time
/// (`genesis_time_ms / 1000` of `genesis/mainnet.manifest`). A fixed public
/// value no later than any native slot an L2 block can anchor to, so the
/// wall-clock rule from L2 block 1 never has to move time backwards.
pub const MAINNET_GENESIS_TIMESTAMP: u64 = 1_786_656_679;

/// Genesis-4 slot duration in milliseconds (`slot_ms` of the manifest), the
/// third field of the mainnet timestamp rule `1:GENESIS:SLOT_MS`.
pub const GENESIS4_SLOT_MS: u64 = 30_000;

/// The constant prevrandao of every Bloch L2 block. L1 publishes nothing a
/// rebuilder could derive a varying value from.
pub const L2_BLOCK_PREVRANDAO: B256 = B256::repeat_byte(0x07);

/// CANDIDATE PLACEHOLDER, `TBD-owner`: the immutable recipient of the fee-vault
/// sweep, the Bloch Inc Safe's L2 address once the owner fixes it. This value
/// enters the configuration commitment, so the configuration, ELF and verifying
/// keys built with it are examples and change when it is set.
pub const MAINNET_FEE_SWEEP_RECIPIENT: Address = Address::new(hex!("00000000000000000000000000000000000fee01"));

/// How a settled block's timestamp and prevrandao follow from public L1 data.
///
/// The L2 header commits both values, and L1 publishes neither, so a block that
/// departs from this rule cannot be rebuilt from L1. A rule set that carries it
/// has the settlement statement refuse such a block. The rule depends only on
/// the block's parent and its L1-checked anchor slot, so it needs no activation
/// height and tolerates any earlier parent timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDerivation {
    /// Unix seconds of native slot 0.
    pub l1_genesis_time: u64,
    /// Native slot duration in milliseconds.
    pub l1_slot_millis: u64,
    /// The constant prevrandao of every block.
    pub prevrandao: B256,
}

impl BlockDerivation {
    /// `max(parent + 1, start of native slot l1_slot)`; `None` on overflow.
    pub fn timestamp(&self, parent_timestamp: u64, l1_slot: u64) -> Option<u64> {
        let slot_time = self.l1_genesis_time.checked_add(l1_slot.checked_mul(self.l1_slot_millis)? / 1000)?;
        Some(parent_timestamp.checked_add(1)?.max(slot_time))
    }
}

/// `CALL(gas, recipient, selfbalance, 0, 0, 0, 0)`, reverting if the call fails.
/// No owner, no storage and no selector: any call sends the whole balance to the
/// recipient compiled into the program.
pub fn fee_vault_sweep_code(recipient: Address) -> [u8; 37] {
    let mut code = [0u8; 37];
    code[..6].copy_from_slice(&[0x5f, 0x5f, 0x5f, 0x5f, 0x47, 0x73]);
    code[6..26].copy_from_slice(recipient.as_slice());
    code[26..].copy_from_slice(&[0x5a, 0xf1, 0x15, 0x60, 0x21, 0x57, 0x00, 0x5b, 0x5f, 0x5f, 0xfd]);
    code
}

/// Genesis / consensus-parameter knobs for the Bloch EVM L2, mirroring
/// `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1's ChainSpec.
///
/// The EVM itself is UNMODIFIED revm at a named hardfork ([`SpecId::CANCUN`]).
/// The only deltas from mainline Ethereum are the enumerated, legal,
/// non-semantic knobs below (chain id, fee routing, zero issuance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSpec {
    /// EIP-155 chain id. 700771 is the selected Bloch L2 **testnet** id.
    /// Selection does not establish public registration or production readiness.
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
    /// Block gas charged per deposit (see [`DEPOSIT_GAS`]); bounds the number
    /// of deposits per block to `gas_limit / deposit_gas`.
    pub deposit_gas: u64,
    /// The L2 → L1 withdrawal outbox predeploy
    /// ([`crate::withdrawal::L2_TO_L1_MESSAGE_PASSER`]), or `None` for a chain
    /// without withdrawals. Part of the execution rules: the executor installs
    /// the outbox code at block start and appends its withdrawals to the
    /// committed tree when the block finishes ([`crate::withdrawal`]).
    /// Settlement V3 requires it ([`ChainSpec::testnet_v3`]); the V2 testnet
    /// rules ([`ChainSpec::testnet`], devnet2/devnet3 history) have none.
    pub withdrawal_outbox: Option<Address>,
    /// See [`BlockDerivation`]. `None` on every earlier rule set.
    pub block_derivation: Option<BlockDerivation>,
    /// Immutable recipient of both fee vaults: each block executed under this
    /// rule set installs [`fee_vault_sweep_code`] at both vault addresses if it
    /// is not there yet, keeping their balances. `None` on every earlier rule set.
    pub fee_vault_sweep: Option<Address>,
}

/// Why a [`ChainSpec`] is not a valid configuration. The executor refuses to
/// run a block under an invalid spec ([`ChainSpec::validate`]), so no knob can
/// reach a division by zero or a silent misconfiguration at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSpecError {
    /// The execution rules are audited and wired only for Cancun. Other
    /// hardforks require an explicit protocol upgrade, not a runtime knob.
    UnsupportedHardfork(SpecId),
    /// `chain_id` is zero (no EIP-155 domain).
    ZeroChainId,
    /// `gas_limit` is zero.
    ZeroGasLimit,
    /// `base_fee_elasticity` is zero (the gas target would be undefined).
    ZeroElasticity,
    /// `gas_limit < base_fee_elasticity` (the gas target would be zero).
    GasLimitBelowElasticity,
    /// `base_fee_denominator` is zero.
    ZeroDenominator,
    /// `block_reward` is not zero: the L2 never issues.
    NonZeroBlockReward,
    /// `deposit_gas` is zero (deposits would be unmetered).
    ZeroDepositGas,
    /// `deposit_gas > gas_limit` (no deposit could ever be included).
    DepositGasAboveGasLimit,
    /// Two system addresses (vaults, ledger, block info, EIP-4788 predeploy,
    /// withdrawal outbox) coincide.
    SystemAddressCollision(Address),
    /// Block derivation and the fee-vault sweep ship together, on a chain with
    /// the withdrawal outbox.
    PartialNextRules,
}

impl core::fmt::Display for ChainSpecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainSpecError::UnsupportedHardfork(fork) => write!(f, "unsupported hardfork {fork:?}; expected CANCUN"),
            ChainSpecError::ZeroChainId => write!(f, "chain_id must not be zero"),
            ChainSpecError::ZeroGasLimit => write!(f, "gas_limit must not be zero"),
            ChainSpecError::ZeroElasticity => write!(f, "base_fee_elasticity must not be zero"),
            ChainSpecError::GasLimitBelowElasticity => write!(f, "gas_limit must be at least base_fee_elasticity"),
            ChainSpecError::ZeroDenominator => write!(f, "base_fee_denominator must not be zero"),
            ChainSpecError::NonZeroBlockReward => write!(f, "block_reward must be zero (the L2 never issues)"),
            ChainSpecError::ZeroDepositGas => write!(f, "deposit_gas must not be zero"),
            ChainSpecError::DepositGasAboveGasLimit => write!(f, "deposit_gas must not exceed gas_limit"),
            ChainSpecError::SystemAddressCollision(a) => write!(f, "system address {a} is used twice"),
            ChainSpecError::PartialNextRules => {
                write!(f, "block derivation and the fee-vault sweep ship together, with the outbox")
            }
        }
    }
}

impl core::error::Error for ChainSpecError {}

impl ChainSpec {
    /// The testnet / zero-value parameter set from the design.
    pub fn testnet() -> Self {
        Self {
            chain_id: TESTNET_CHAIN_ID,
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
            deposit_gas: DEPOSIT_GAS,
            withdrawal_outbox: None,
            block_derivation: None,
            fee_vault_sweep: None,
        }
    }

    /// The settlement V3 execution rules (devnet4): [`Self::testnet`] plus the
    /// withdrawal outbox at [`crate::withdrawal::L2_TO_L1_MESSAGE_PASSER`].
    /// Same genesis state (the outbox is installed by the first block, like the
    /// EIP-4788 predeploy), different configuration commitment.
    pub fn testnet_v3() -> Self {
        Self {
            withdrawal_outbox: Some(crate::withdrawal::L2_TO_L1_MESSAGE_PASSER),
            ..Self::testnet()
        }
    }

    /// The Bloch L2 **mainnet** execution rules: the settlement V3 rules
    /// ([`Self::testnet_v3`]: Cancun, 30M block gas, withdrawal outbox, the
    /// same vaults and fee knobs) under chain id [`MAINNET_CHAIN_ID`].
    ///
    /// The chain id is part of the configuration commitment, so this is a
    /// different program identity from every devnet: the SP1 settlement guest
    /// built for it has its own vkey (see `docs/MAINNET-RPC-READINESS.md`).
    /// The devnet constructors are unchanged.
    ///
    /// These are the rules of the program the epoch-5850 activation pinned
    /// (configuration `8ec1c804…`): every settlement accepted under that policy
    /// replays with them.
    pub fn mainnet_v1() -> Self {
        Self {
            chain_id: MAINNET_CHAIN_ID,
            ..Self::testnet_v3()
        }
    }

    /// The rules of the next mainnet program (candidate, not scheduled):
    /// [`Self::mainnet_v1`] plus the settlement-bound [`BlockDerivation`] and the
    /// fee-vault sweep. The genesis is unchanged, because neither rule touches it.
    pub fn mainnet() -> Self {
        Self {
            block_derivation: Some(BlockDerivation {
                l1_genesis_time: MAINNET_GENESIS_TIMESTAMP,
                l1_slot_millis: GENESIS4_SLOT_MS,
                prevrandao: L2_BLOCK_PREVRANDAO,
            }),
            fee_vault_sweep: Some(MAINNET_FEE_SWEEP_RECIPIENT),
            ..Self::mainnet_v1()
        }
    }

    /// The mainnet rule set of a settled statement, from its configuration
    /// commitment (the field L1 compares with the policy of that moment).
    /// `None` for a commitment that is neither of the two.
    pub fn mainnet_rules_for(configuration: B256) -> Option<Self> {
        [Self::mainnet_v1(), Self::mainnet()].into_iter().find(|rules| {
            crate::proof_statement::configuration_commitment(rules).is_ok_and(|c| c == configuration)
        })
    }

    /// Check every knob for consistency. The executor calls this before any
    /// block (`BlockExecutionError::InvalidChainSpec`), so an invalid spec can
    /// never execute a block, divide by zero or pay a block reward.
    pub fn validate(&self) -> Result<(), ChainSpecError> {
        if self.spec_id != SpecId::CANCUN {
            return Err(ChainSpecError::UnsupportedHardfork(self.spec_id));
        }
        if self.chain_id == 0 {
            return Err(ChainSpecError::ZeroChainId);
        }
        if self.gas_limit == 0 {
            return Err(ChainSpecError::ZeroGasLimit);
        }
        if self.base_fee_elasticity == 0 {
            return Err(ChainSpecError::ZeroElasticity);
        }
        if self.gas_limit < self.base_fee_elasticity {
            return Err(ChainSpecError::GasLimitBelowElasticity);
        }
        if self.base_fee_denominator == 0 {
            return Err(ChainSpecError::ZeroDenominator);
        }
        if self.block_reward != U256::ZERO {
            return Err(ChainSpecError::NonZeroBlockReward);
        }
        if self.deposit_gas == 0 {
            return Err(ChainSpecError::ZeroDepositGas);
        }
        if self.deposit_gas > self.gas_limit {
            return Err(ChainSpecError::DepositGasAboveGasLimit);
        }
        let system = [
            Some(self.base_fee_vault),
            Some(self.sequencer_fee_vault),
            Some(self.supply_ledger),
            Some(self.block_info),
            Some(BEACON_ROOTS_ADDRESS),
            self.withdrawal_outbox,
            self.fee_vault_sweep,
        ];
        for (i, a) in system.iter().enumerate() {
            let Some(a) = a else { continue };
            if system[..i].contains(&Some(*a)) {
                return Err(ChainSpecError::SystemAddressCollision(*a));
            }
        }
        Ok(())
    }

    /// The most deposits one block can carry: `gas_limit / deposit_gas`
    /// (zero for an invalid spec with `deposit_gas == 0`).
    pub fn max_deposits_per_block(&self) -> u64 {
        self.gas_limit.checked_div(self.deposit_gas).unwrap_or(0)
    }

    /// The address the COINBASE opcode observes (the design routes it to the
    /// sequencer fee vault so priority fees land there via unmodified revm
    /// beneficiary payment).
    pub fn coinbase(&self) -> Address {
        self.sequencer_fee_vault
    }

    /// EIP-1559 gas target per block (`gas_limit / elasticity`). Total: zero
    /// for the (invalid, see [`Self::validate`]) elasticity 0.
    pub fn gas_target(&self) -> u64 {
        self.gas_limit.checked_div(self.base_fee_elasticity).unwrap_or(0)
    }

    /// EIP-1559 next-base-fee computation with this chain's elasticity /
    /// denominator knobs. Pure integer math (u128 internally, no overflow for
    /// any realistic base fee), byte-identical to the Ethereum formula with
    /// retuned constants. Total: with a zero gas target or denominator (an
    /// invalid spec, see [`Self::validate`]) the base fee is left unchanged
    /// rather than dividing by zero.
    pub fn next_base_fee(&self, parent_base_fee: u64, parent_gas_used: u64) -> u64 {
        let target = self.gas_target();
        if target == 0 || self.base_fee_denominator == 0 {
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
        assert_eq!(spec.deposit_gas, 21_000);
        assert_eq!(spec.max_deposits_per_block(), 30_000_000 / 21_000);
        spec.validate().expect("the testnet spec is valid");
    }

    type Case = (fn(&mut ChainSpec), ChainSpecError);

    #[test]
    fn validate_rejects_every_degenerate_knob() {
        let base = ChainSpec::testnet();
        let cases: [Case; 9] = [
            (|s| s.chain_id = 0, ChainSpecError::ZeroChainId),
            (|s| s.gas_limit = 0, ChainSpecError::ZeroGasLimit),
            (|s| s.base_fee_elasticity = 0, ChainSpecError::ZeroElasticity),
            (
                |s| {
                    s.gas_limit = 1;
                    s.base_fee_elasticity = 2;
                    s.deposit_gas = 1;
                },
                ChainSpecError::GasLimitBelowElasticity,
            ),
            (|s| s.base_fee_denominator = 0, ChainSpecError::ZeroDenominator),
            (
                |s| s.block_reward = U256::from(1u64),
                ChainSpecError::NonZeroBlockReward,
            ),
            (|s| s.deposit_gas = 0, ChainSpecError::ZeroDepositGas),
            (
                |s| s.deposit_gas = s.gas_limit + 1,
                ChainSpecError::DepositGasAboveGasLimit,
            ),
            (
                |s| s.block_info = s.supply_ledger,
                ChainSpecError::SystemAddressCollision(SUPPLY_LEDGER),
            ),
        ];
        for (mutate, expected) in cases {
            let mut s = base.clone();
            mutate(&mut s);
            assert_eq!(s.validate(), Err(expected));
        }
        let mut s = base.clone();
        s.base_fee_vault = BEACON_ROOTS_ADDRESS;
        assert_eq!(
            s.validate(),
            Err(ChainSpecError::SystemAddressCollision(BEACON_ROOTS_ADDRESS))
        );
    }

    #[test]
    fn fee_helpers_are_total_for_zero_knobs() {
        let parent = 1_000_000_000u64;
        let mut s = ChainSpec::testnet();
        s.base_fee_elasticity = 0;
        assert_eq!(s.gas_target(), 0);
        for used in [0u64, 1, s.gas_limit / 2, s.gas_limit] {
            assert_eq!(s.next_base_fee(parent, used), parent);
        }
        let mut s = ChainSpec::testnet();
        s.base_fee_denominator = 0;
        for used in [
            0u64,
            s.gas_target() - 1,
            s.gas_target(),
            s.gas_target() + 1,
            s.gas_limit,
        ] {
            assert_eq!(s.next_base_fee(parent, used), parent);
        }
        let mut s = ChainSpec::testnet();
        s.gas_limit = 1;
        s.base_fee_elasticity = 2;
        assert_eq!(s.next_base_fee(parent, 0), parent);
        assert_eq!(s.next_base_fee(parent, 1), parent);
        let mut s = ChainSpec::testnet();
        s.deposit_gas = 0;
        assert_eq!(s.max_deposits_per_block(), 0);
    }

    #[test]
    fn l1_cap_is_100_billion_blch_and_fits_the_amount_types() {
        assert_eq!(MAX_L1_SATS, 10_000_000_000_000_000_000u64, "10^19 sats");
        assert!(MAX_L1_SATS > i64::MAX as u64, "needs unsigned 64-bit sats on the L1");
        // 10^29 wei: the most the L2 supply ledger can ever hold.
        let cap_wei = crate::scale::sats_to_wei(MAX_L1_SATS);
        assert_eq!(cap_wei, U256::from(10u128.pow(29)));
        assert_eq!(
            cap_wei,
            U256::from(100_000_000_000u64) * U256::from(10u64).pow(U256::from(18)),
            "100 billion × 10^18 wei"
        );
    }

    #[test]
    fn mainnet_domain_is_derived_from_the_chain_id_and_the_l1_network() {
        let mut preimage = MAINNET_DOMAIN_TAG.to_vec();
        preimage.extend_from_slice(&MAINNET_CHAIN_ID.to_be_bytes());
        preimage.extend_from_slice(GENESIS4_NETWORK_DOMAIN.as_slice());
        let derived = alloy_primitives::keccak256(&preimage);
        assert_eq!(MAINNET_DOMAIN, derived);
        assert!(!MAINNET_DOMAIN.is_zero());
        assert_ne!(MAINNET_DOMAIN, B256::repeat_byte(0xd3));
        // Genesis-4 clock (manifest genesis_time_ms 1786656679962, slot_ms
        // 30000): wall-clock seconds, after the 2020-01-01 floor.
        assert_eq!(MAINNET_GENESIS_TIMESTAMP, 1_786_656_679_962 / 1000);
        assert!(MAINNET_GENESIS_TIMESTAMP >= 1_577_836_800);
        assert_eq!(GENESIS4_SLOT_MS, 30_000);
    }

    #[test]
    fn next_mainnet_rules_add_only_block_derivation_and_the_sweep() {
        let next = ChainSpec::mainnet();
        next.validate().expect("the next mainnet spec is valid");
        assert!(next.block_derivation.is_some() && next.fee_vault_sweep.is_some());
        assert_eq!(
            ChainSpec { block_derivation: None, fee_vault_sweep: None, ..next.clone() },
            ChainSpec::mainnet_v1()
        );
    }

    #[test]
    fn mainnet_v1_is_the_v3_rules_under_its_own_chain_id() {
        let mainnet = ChainSpec::mainnet_v1();
        mainnet.validate().expect("the mainnet spec is valid");
        assert_eq!(mainnet.chain_id, 700_770);
        assert_eq!(MAINNET_CHAIN_ID, 700_770);
        // Only the chain id differs from the devnet4 settlement V3 rules.
        assert_eq!(
            ChainSpec {
                chain_id: TESTNET_CHAIN_ID,
                ..mainnet.clone()
            },
            ChainSpec::testnet_v3()
        );
        assert!(mainnet.withdrawal_outbox.is_some());
        // The DEX router creation needs ~3.9M gas: the block gas limit and the
        // deposit-free per-block budget must hold it with a wide margin.
        assert_eq!(mainnet.gas_limit, 30_000_000);
        assert!(mainnet.gas_limit >= 4_000_000);
        // The devnet identities are untouched.
        assert_eq!(ChainSpec::testnet().chain_id, 700_771);
        assert_eq!(ChainSpec::testnet_v3().chain_id, 700_771);
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
