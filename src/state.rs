// SPDX-License-Identifier: MIT OR Apache-2.0
//! L2 account/state layer over revm's `CacheDB`/`InMemoryDB`.
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** In-memory only: the real node
//! persists state behind a keccak-256 MPT (see [`crate::stateroot`]).
//!
//! Supply rule (BLOCH-L2-EVM-DESIGN §1): the native gas token is an L2
//! representation of **bridged BLCH** with **zero issuance** — balances enter
//! only via deposit mints (crediting exactly the escrowed L1 sats scaled by
//! [`crate::scale::ATOM_SCALE`]) and leave only via withdrawals (bridge
//! component, not this crate). Block reward is zero and fees are routed to
//! vaults, so **the protocol never burns**; the EVM itself can still destroy
//! native value through EIP-6780 (`SELFDESTRUCT` to self in the creating
//! transaction), so `total_native_wei <= total_minted_wei` is the invariant the
//! executor maintains, with equality whenever no such burn happened.
//!
//! The supply ledger — cumulative minted wei and the set of consumed L1 escrow
//! outpoints — lives in the storage of the [`crate::chainspec::SUPPLY_LEDGER`]
//! system account, so it is **committed in the state root**, carried by batch
//! witnesses and re-checked by a stateless guest. A deposit whose outpoint was
//! already consumed is rejected ([`DepositError::Replay`]); a deposit claiming
//! more than the L1 hard cap, or pushing the cumulative supply past it, is
//! rejected as well.
//!
//! **Trust boundary.** The STF cannot itself observe the Bloch L1: it trusts
//! the derivation layer to hand it deposits that were really escrowed in a
//! finalized L1 block. What it *does* enforce is exact scaling, uniqueness of
//! each outpoint, and the supply cap, all against committed state.

use alloy_primitives::{keccak256, Address, B256, U256};
use revm::database::{AccountState, CacheDB, DbAccount, InMemoryDB};
use revm::primitives::KECCAK_EMPTY;
use revm::{Database, DatabaseRef};

use crate::chainspec::{ChainSpec, SUPPLY_LEDGER};
use crate::scale::sats_to_wei;

/// Where a deposit mint's value came from, as reported by the derivation layer.
///
/// Deliberately a single-variant enum: **bridged BLCH is the only provenance
/// that can ever mint on this L2**. There is no admin mint, no reward mint,
/// no other asset. Adding a variant here would violate the design's zero-
/// issuance / not-a-security posture and must not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositProvenance {
    /// BLCH escrowed on the Bloch L1 (the deposit system-transaction's
    /// source, OP-style type-0x7E envelope in the full design).
    BridgedBlch {
        /// L1 escrow transaction id.
        l1_txid: [u8; 32],
        /// Output index of the escrow within that transaction.
        l1_vout: u32,
        /// Escrowed amount in L1 sats (u64, 8 decimals).
        l1_sats: u64,
    },
}

/// A deposit system-transaction's mint effect, applied at block start.
///
/// The credited amount is **derived** from the provenance
/// (`sats_to_wei(l1_sats)`, see [`DepositMint::mint_wei`]); there is no
/// separate caller-supplied amount to keep consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositMint {
    /// L2 recipient credited with the minted wei.
    pub recipient: Address,
    /// Where the value came from (bridged BLCH only).
    pub provenance: DepositProvenance,
}

impl DepositMint {
    /// Escrowed L1 sats carried by the provenance.
    pub fn l1_sats(&self) -> u64 {
        let DepositProvenance::BridgedBlch { l1_sats, .. } = self.provenance;
        l1_sats
    }

    /// The exact wei this deposit mints: `sats_to_wei(l1_sats)`.
    pub fn mint_wei(&self) -> U256 {
        sats_to_wei(self.l1_sats())
    }

    /// The L1 escrow outpoint `(l1_txid, l1_vout)` that uniquely identifies
    /// this deposit and may be minted at most once.
    pub fn outpoint(&self) -> ([u8; 32], u32) {
        let DepositProvenance::BridgedBlch { l1_txid, l1_vout, .. } = self.provenance;
        (l1_txid, l1_vout)
    }
}

/// Storage slot of the supply-ledger account holding the cumulative minted wei.
pub const SUPPLY_LEDGER_TOTAL_MINTED_SLOT: U256 = U256::ZERO;

/// Storage slot of the supply-ledger account that marks an L1 escrow outpoint
/// as consumed (value `1` once minted): `keccak256(0x01 ‖ l1_txid ‖ l1_vout_be)`.
pub fn consumed_deposit_slot(l1_txid: &[u8; 32], l1_vout: u32) -> U256 {
    let mut preimage = [0u8; 37];
    preimage[0] = 0x01;
    preimage[1..33].copy_from_slice(l1_txid);
    preimage[33..37].copy_from_slice(&l1_vout.to_be_bytes());
    U256::from_be_bytes(keccak256(preimage).0)
}

/// Errors from applying a deposit mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    /// The L1 escrow outpoint was already minted on this L2.
    Replay {
        /// L1 escrow transaction id.
        l1_txid: [u8; 32],
        /// Output index within that transaction.
        l1_vout: u32,
    },
    /// The deposit claims more sats than the L1 can ever hold.
    ExceedsL1Supply {
        /// The claimed sats.
        l1_sats: u64,
        /// The configured L1 hard cap (`ChainSpec::max_l1_sats`).
        max_l1_sats: u64,
    },
    /// Minting this deposit would push the cumulative L2 supply past the L1
    /// hard cap.
    CumulativeSupplyExceeded {
        /// The cumulative minted wei after this deposit.
        total_after_wei: U256,
        /// The cap in wei (`sats_to_wei(max_l1_sats)`).
        cap_wei: U256,
    },
}

impl core::fmt::Display for DepositError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DepositError::Replay { l1_txid, l1_vout } => {
                write!(f, "deposit outpoint {}:{l1_vout} was already minted", B256::from(*l1_txid))
            }
            DepositError::ExceedsL1Supply { l1_sats, max_l1_sats } => {
                write!(f, "deposit claims {l1_sats} sats, above the L1 hard cap of {max_l1_sats} sats")
            }
            DepositError::CumulativeSupplyExceeded { total_after_wei, cap_wei } => write!(
                f,
                "cumulative minted supply {total_after_wei} wei would exceed the L1 cap {cap_wei} wei"
            ),
        }
    }
}

impl core::error::Error for DepositError {}

/// Error from applying a deposit against a generic (possibly fallible) database.
#[derive(Debug)]
pub(crate) enum DepositApplyError<E> {
    /// The deposit itself is invalid.
    Deposit(DepositError),
    /// The backing database failed (e.g. a stateless guest reading an account
    /// the witness does not cover).
    Db(E),
}

/// Read-only view of one L2 account (standard Ethereum account model; the
/// storage root is computed by [`crate::stateroot`], not held in this view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Account {
    /// Native (bridged-BLCH) balance in wei.
    pub balance: U256,
    /// Transaction nonce.
    pub nonce: u64,
    /// keccak-256 of the account's code ([`KECCAK_EMPTY`] for EOAs).
    pub code_hash: B256,
}

/// The L2 execution state: revm's in-memory `CacheDB`. The zero-issuance
/// supply ledger is part of it, as storage of the [`SUPPLY_LEDGER`] account.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct L2State {
    /// The underlying revm database the EVM executes against.
    pub db: InMemoryDB,
}

impl L2State {
    /// Fresh, empty state (genesis alloc / predeploys are out of scope for
    /// this scaffold; see README).
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one deposit mint directly to this state (block-level callers use
    /// [`crate::executor::execute_block`], which is atomic and validates the
    /// whole block first). Credits **exactly** `sats_to_wei(l1_sats)` to the
    /// recipient after checking the L1 cap, the cumulative cap and that the
    /// outpoint was never minted; records the outpoint and the new total in
    /// the committed ledger. Returns the credited wei.
    pub fn deposit_mint(&mut self, spec: &ChainSpec, deposit: &DepositMint) -> Result<U256, DepositError> {
        match apply_deposit(&mut self.db, spec, deposit) {
            Ok(wei) => Ok(wei),
            Err(DepositApplyError::Deposit(e)) => Err(e),
            Err(DepositApplyError::Db(never)) => match never {},
        }
    }

    /// Total wei ever minted by deposits (the L2's entire authorized supply),
    /// read from the committed ledger at the default [`SUPPLY_LEDGER`] address.
    pub fn total_minted_wei(&self) -> U256 {
        self.total_minted_wei_at(SUPPLY_LEDGER)
    }

    /// [`Self::total_minted_wei`] for a custom ledger address
    /// (`ChainSpec::supply_ledger`).
    pub fn total_minted_wei_at(&self, ledger: Address) -> U256 {
        ledger_slot(&self.db, ledger, SUPPLY_LEDGER_TOTAL_MINTED_SLOT)
    }

    /// Whether the L1 escrow outpoint was already minted (default ledger).
    pub fn is_deposit_consumed(&self, l1_txid: &[u8; 32], l1_vout: u32) -> bool {
        !ledger_slot(&self.db, SUPPLY_LEDGER, consumed_deposit_slot(l1_txid, l1_vout)).is_zero()
    }

    /// Sum of every live account's native balance. With zero issuance and
    /// vault-routed fees this equals [`Self::total_minted_wei`] unless the EVM
    /// destroyed value via EIP-6780 (then it is strictly smaller) — asserted by
    /// the executor tests.
    pub fn total_native_wei(&self) -> U256 {
        self.db
            .cache
            .accounts
            .values()
            .filter(|acc| acc.account_state != AccountState::NotExisting)
            .fold(U256::ZERO, |sum, acc| {
                sum.checked_add(acc.info.balance)
                    .expect("summed balances cannot overflow U256")
            })
    }

    /// Read-only account view (`None` if the account does not exist).
    pub fn account(&self, address: &Address) -> Option<L2Account> {
        let acc: &DbAccount = self.db.cache.accounts.get(address)?;
        let info = acc.info()?;
        Some(L2Account {
            balance: info.balance,
            nonce: info.nonce,
            code_hash: if info.code_hash == B256::ZERO {
                KECCAK_EMPTY
            } else {
                info.code_hash
            },
        })
    }

    /// Native balance of `address` (zero if absent).
    pub fn balance_of(&self, address: &Address) -> U256 {
        self.account(address).map(|a| a.balance).unwrap_or(U256::ZERO)
    }

    /// Nonce of `address` (zero if absent).
    pub fn nonce_of(&self, address: &Address) -> u64 {
        self.account(address).map(|a| a.nonce).unwrap_or(0)
    }
}

/// Read a ledger slot straight from a complete (EmptyDB-backed) cache.
fn ledger_slot(db: &InMemoryDB, ledger: Address, slot: U256) -> U256 {
    db.cache
        .accounts
        .get(&ledger)
        .filter(|acc| acc.account_state != AccountState::NotExisting)
        .and_then(|acc| acc.storage.get(&slot).copied())
        .unwrap_or(U256::ZERO)
}

/// Credit `amount_wei` to `address` in the raw database (deposit mints and
/// vault fee routing — protocol-level accounting outside EVM opcode
/// semantics, the OP-Stack precedent). Must only be called between
/// transactions / at block boundaries, never mid-execution. A zero credit is a
/// no-op and never materializes an account (EIP-161 semantics).
pub(crate) fn credit_balance<ExtDB: DatabaseRef>(
    db: &mut CacheDB<ExtDB>,
    address: Address,
    amount_wei: U256,
) -> Result<(), ExtDB::Error> {
    if amount_wei.is_zero() {
        return Ok(());
    }
    let account = db.load_account(address)?;
    account.info.balance = account
        .info
        .balance
        .checked_add(amount_wei)
        .expect("balance cannot overflow U256");
    if account.account_state == AccountState::NotExisting {
        // A brand-new account has no storage anywhere: mark it StorageCleared so
        // slot reads never consult the backing database.
        account.account_state = AccountState::StorageCleared;
    }
    Ok(())
}

/// Apply one deposit against any `CacheDB`: cap checks, replay check against
/// the committed ledger, ledger update, recipient credit. All ledger reads go
/// through the [`Database`] trait so a recording or stateless backing observes
/// them. Returns the credited wei. On `Err` nothing has been written.
pub(crate) fn apply_deposit<ExtDB: DatabaseRef>(
    db: &mut CacheDB<ExtDB>,
    spec: &ChainSpec,
    deposit: &DepositMint,
) -> Result<U256, DepositApplyError<ExtDB::Error>> {
    let (l1_txid, l1_vout) = deposit.outpoint();
    let l1_sats = deposit.l1_sats();
    if l1_sats > spec.max_l1_sats {
        return Err(DepositApplyError::Deposit(DepositError::ExceedsL1Supply {
            l1_sats,
            max_l1_sats: spec.max_l1_sats,
        }));
    }
    let wei = sats_to_wei(l1_sats);
    let ledger = spec.supply_ledger;

    // Load (and record) the ledger account, then read the two slots we depend on.
    db.basic(ledger).map_err(DepositApplyError::Db)?;
    let marker_slot = consumed_deposit_slot(&l1_txid, l1_vout);
    if !db.storage(ledger, marker_slot).map_err(DepositApplyError::Db)?.is_zero() {
        return Err(DepositApplyError::Deposit(DepositError::Replay { l1_txid, l1_vout }));
    }
    let total = db
        .storage(ledger, SUPPLY_LEDGER_TOTAL_MINTED_SLOT)
        .map_err(DepositApplyError::Db)?;
    let total_after = total.checked_add(wei).expect("total minted wei cannot overflow U256");
    let cap_wei = sats_to_wei(spec.max_l1_sats);
    if total_after > cap_wei {
        return Err(DepositApplyError::Deposit(DepositError::CumulativeSupplyExceeded {
            total_after_wei: total_after,
            cap_wei,
        }));
    }

    // Materialize the ledger as a non-empty (nonce 1, code-less) system account
    // so EIP-161 never drops it — and its storage — from the state trie.
    {
        let acc = db.load_account(ledger).map_err(DepositApplyError::Db)?;
        if acc.account_state == AccountState::NotExisting {
            acc.account_state = AccountState::StorageCleared;
        }
        if acc.info.nonce == 0 {
            acc.info.nonce = 1;
        }
    }
    db.insert_account_storage(ledger, marker_slot, U256::from(1u64))
        .map_err(DepositApplyError::Db)?;
    db.insert_account_storage(ledger, SUPPLY_LEDGER_TOTAL_MINTED_SLOT, total_after)
        .map_err(DepositApplyError::Db)?;
    credit_balance(db, deposit.recipient, wei).map_err(DepositApplyError::Db)?;
    Ok(wei)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use core::sync::atomic::{AtomicU32, Ordering};

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");

    static NEXT_VOUT: AtomicU32 = AtomicU32::new(0);

    /// A deposit with a fresh, unique L1 outpoint.
    fn blch_deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_txid: [0x42; 32],
                l1_vout: NEXT_VOUT.fetch_add(1, Ordering::Relaxed),
                l1_sats,
            },
        }
    }

    #[test]
    fn deposit_mints_exactly_and_supply_equals_sum_of_mints() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        // 1.5 BLCH to alice, 0.00000001 BLCH (1 sat) to bob.
        state.deposit_mint(&spec, &blch_deposit(ALICE, 150_000_000)).unwrap();
        state.deposit_mint(&spec, &blch_deposit(BOB, 1)).unwrap();
        // A second deposit (distinct outpoint) to the same recipient accumulates.
        state.deposit_mint(&spec, &blch_deposit(ALICE, 50_000_000)).unwrap();

        assert_eq!(state.balance_of(&ALICE), sats_to_wei(200_000_000));
        assert_eq!(state.balance_of(&BOB), sats_to_wei(1));
        // Zero issuance: total supply == sum of mints, nothing else.
        assert_eq!(
            state.total_minted_wei(),
            sats_to_wei(200_000_000) + sats_to_wei(1)
        );
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
        // Nonces untouched by mints.
        assert_eq!(state.nonce_of(&ALICE), 0);
        // The ledger is a real, non-empty account (nonce 1, no code).
        let ledger = state.account(&SUPPLY_LEDGER).expect("ledger exists");
        assert_eq!(ledger.nonce, 1);
        assert_eq!(ledger.code_hash, KECCAK_EMPTY);
    }

    #[test]
    fn replayed_outpoint_is_rejected_and_is_a_noop() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let dep = blch_deposit(ALICE, 100);
        state.deposit_mint(&spec, &dep).unwrap();
        let (txid, vout) = dep.outpoint();
        assert!(state.is_deposit_consumed(&txid, vout));

        let before_root = crate::compute_keccak_mpt_state_root(&state);
        let err = state.deposit_mint(&spec, &dep).unwrap_err();
        assert_eq!(err, DepositError::Replay { l1_txid: txid, l1_vout: vout });
        // Same outpoint with a different recipient / amount is still a replay.
        let mut other = dep;
        other.recipient = BOB;
        other.provenance = DepositProvenance::BridgedBlch { l1_txid: txid, l1_vout: vout, l1_sats: 5 };
        assert!(matches!(state.deposit_mint(&spec, &other), Err(DepositError::Replay { .. })));
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(100));
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
        assert_eq!(state.total_minted_wei(), sats_to_wei(100));
        assert_eq!(crate::compute_keccak_mpt_state_root(&state), before_root, "rejected deposit is a no-op");
    }

    #[test]
    fn deposit_above_l1_cap_is_rejected() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let err = state.deposit_mint(&spec, &blch_deposit(ALICE, spec.max_l1_sats + 1)).unwrap_err();
        assert!(matches!(err, DepositError::ExceedsL1Supply { .. }));
        assert_eq!(state.total_minted_wei(), U256::ZERO);
        assert!(state.account(&SUPPLY_LEDGER).is_none(), "nothing written");
        // u64::MAX sats is far above any possible L1 supply and is rejected too.
        assert!(matches!(
            state.deposit_mint(&spec, &blch_deposit(ALICE, u64::MAX)),
            Err(DepositError::ExceedsL1Supply { .. })
        ));
    }

    #[test]
    fn cumulative_supply_cannot_exceed_l1_cap() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        // Exactly the cap is fine (the whole L1 supply bridged).
        state.deposit_mint(&spec, &blch_deposit(ALICE, spec.max_l1_sats)).unwrap();
        assert_eq!(state.total_minted_wei(), sats_to_wei(spec.max_l1_sats));
        // One more sat is not.
        let err = state.deposit_mint(&spec, &blch_deposit(BOB, 1)).unwrap_err();
        assert!(matches!(err, DepositError::CumulativeSupplyExceeded { .. }));
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
        assert_eq!(state.total_minted_wei(), sats_to_wei(spec.max_l1_sats));
    }

    #[test]
    fn absent_account_reads_as_zero() {
        let state = L2State::new();
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert_eq!(state.nonce_of(&ALICE), 0);
        assert!(state.account(&ALICE).is_none());
        assert_eq!(state.total_minted_wei(), U256::ZERO);
    }

    #[test]
    fn zero_sat_deposit_is_exact_mints_nothing_and_creates_no_recipient() {
        // A zero-value bridged deposit is exact (0 == 0), consumes its outpoint,
        // adds nothing to supply, and — per EIP-161 — does not materialize the
        // recipient account.
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let dep = blch_deposit(ALICE, 0);
        assert_eq!(state.deposit_mint(&spec, &dep).unwrap(), U256::ZERO);
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert!(state.account(&ALICE).is_none());
        assert_eq!(state.total_minted_wei(), U256::ZERO);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
        let (txid, vout) = dep.outpoint();
        assert!(state.is_deposit_consumed(&txid, vout));
    }

    #[test]
    fn ledger_is_committed_in_the_state_root() {
        // Two states with identical account balances but different mint
        // histories (different consumed outpoints) must hash differently, and a
        // ledger edit alone must move the root.
        let spec = ChainSpec::testnet();
        let mut a = L2State::new();
        a.deposit_mint(&spec, &blch_deposit(ALICE, 7)).unwrap();
        let mut b = L2State::new();
        b.deposit_mint(&spec, &blch_deposit(ALICE, 7)).unwrap(); // different vout
        assert_eq!(a.balance_of(&ALICE), b.balance_of(&ALICE));
        assert_ne!(
            crate::compute_keccak_mpt_state_root(&a),
            crate::compute_keccak_mpt_state_root(&b),
            "consumed-outpoint set is part of the commitment"
        );
        let root_a = crate::compute_keccak_mpt_state_root(&a);
        a.db.insert_account_storage(SUPPLY_LEDGER, SUPPLY_LEDGER_TOTAL_MINTED_SLOT, U256::from(1u64))
            .unwrap();
        assert_ne!(crate::compute_keccak_mpt_state_root(&a), root_a, "ledger total is committed");
    }
}
