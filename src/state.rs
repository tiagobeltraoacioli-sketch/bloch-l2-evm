// SPDX-License-Identifier: MIT OR Apache-2.0
//! L2 account/state layer over revm's `CacheDB`/`InMemoryDB`.
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** In-memory only: the real node
//! persists state behind a keccak-256 MPT (see [`crate::stateroot`]).
//!
//! Supply rule (BLOCH-L2-EVM-DESIGN §1): the native gas token is an L2
//! representation of **bridged BLCH** with **zero issuance** — balances enter
//! only via deposit mints (crediting exactly the escrowed L1 sats scaled by
//! [`crate::scale::ATOM_SCALE`]) and leave only via withdrawals (the outbox,
//! [`crate::withdrawal`], on chains that configure it). Block reward is zero and fees are routed to
//! vaults, so **the protocol never burns**; the EVM itself can still destroy
//! native value through EIP-6780 (`SELFDESTRUCT` to self in the creating
//! transaction). The executor measures that per transaction and accumulates it
//! in the ledger, as are outbox withdrawals, so the executor maintains
//! `total_native_wei == total_minted_wei - total_burned_wei - total_withdrawn_wei`.
//!
//! The supply ledger — cumulative minted wei, the **deposit cursor** and the
//! cumulative wei burned by the EVM — lives in the storage of the
//! [`crate::chainspec::SUPPLY_LEDGER`] system account (three slots, whatever
//! the chain's history), and the **head block record** plus a 256-entry ring of
//! L2 block hashes live in [`crate::chainspec::BLOCK_INFO`] ([`HeadRecord`],
//! `BLOCK_INFO_*_SLOT`, [`block_hash_slot`]). Both are **committed in the state
//! root**, carried by batch witnesses and re-checked by a stateless guest.
//!
//! **Replay protection is a monotonic cursor over canonical L1 positions**
//! (the OP-Stack / Arbitrum inbox model): every escrow output has a unique
//! [`DepositPosition`] `(l1_height, l1_tx_index, l1_vout)`, the derivation layer
//! must present deposits in strictly increasing position order, and the STF
//! accepts a deposit only if its position is strictly after the cursor, then
//! advances the cursor. A replayed, duplicated or out-of-order deposit is
//! [`DepositError::OutOfOrder`]. Compared with a set of consumed outpoints this
//! keeps state and witness size O(1) instead of O(total deposits). A deposit
//! claiming more than the L1 hard cap, or pushing the cumulative supply past
//! it, is rejected as well.
//!
//! **Trust boundary.** The STF cannot itself observe the Bloch L1: it trusts
//! the derivation layer to hand it deposits that were really escrowed at the
//! stated positions in finalized L1 blocks. What it *does* enforce is exact
//! scaling, canonical order (hence uniqueness), and the supply cap, all against
//! committed state.

use alloc::vec::Vec;

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::database::{AccountState, Cache, CacheDB, DbAccount, InMemoryDB};
use revm::primitives::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};
use revm::{Database, DatabaseRef};

use crate::chainspec::{ChainSpec, BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE, BLOCK_INFO, SUPPLY_LEDGER};
use crate::scale::sats_to_wei;
use crate::stateroot::{compute_keccak_mpt_state_root, StateTrie};

/// Where a deposit mint's value came from, as reported by the derivation layer.
///
/// Deliberately a single-variant enum: **bridged BLCH is the only provenance
/// that can ever mint on this L2**. There is no admin mint, no reward mint,
/// no other asset. Adding a variant here would violate the design's zero-
/// issuance / not-a-security posture and must not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DepositProvenance {
    /// BLCH escrowed on the Bloch L1 (the deposit system-transaction's
    /// source, OP-style type-0x7E envelope in the full design).
    BridgedBlch {
        /// Height of the Bloch block containing the escrow transaction.
        l1_height: u64,
        /// Index of the escrow transaction within that block.
        l1_tx_index: u32,
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// The L1 escrow outpoint `(l1_txid, l1_vout)` (auditability; the
    /// uniqueness rule is the [`DepositPosition`]).
    pub fn outpoint(&self) -> ([u8; 32], u32) {
        let DepositProvenance::BridgedBlch { l1_txid, l1_vout, .. } = self.provenance;
        (l1_txid, l1_vout)
    }

    /// The canonical L1 position of this deposit's escrow output.
    pub fn position(&self) -> DepositPosition {
        let DepositProvenance::BridgedBlch {
            l1_height,
            l1_tx_index,
            l1_vout,
            ..
        } = self.provenance;
        DepositPosition {
            l1_height,
            l1_tx_index,
            l1_vout,
        }
    }
}

/// Canonical position of an escrow output on the Bloch L1 — the order in which
/// the derivation layer must present deposits and the STF's replay cursor.
/// Ordering is lexicographic `(l1_height, l1_tx_index, l1_vout)`, identical to
/// the numeric order of [`Self::packed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DepositPosition {
    /// Height of the Bloch block containing the escrow transaction.
    pub l1_height: u64,
    /// Index of the escrow transaction within that block.
    pub l1_tx_index: u32,
    /// Output index within that transaction.
    pub l1_vout: u32,
}

impl DepositPosition {
    /// The cursor value before any deposit: nothing consumed. A real escrow
    /// output can never sit at `(0, 0, 0)` (the L1 genesis coinbase), so this
    /// sentinel excludes no valid deposit.
    pub const NONE: Self = Self {
        l1_height: 0,
        l1_tx_index: 0,
        l1_vout: 0,
    };

    /// Storage encoding: `height << 64 | tx_index << 32 | vout` (128 bits), so
    /// numeric comparison equals positional order.
    pub fn packed(&self) -> U256 {
        (U256::from(self.l1_height) << 64) | (U256::from(self.l1_tx_index) << 32) | U256::from(self.l1_vout)
    }

    /// Inverse of [`Self::packed`] (upper 128 bits ignored).
    pub fn from_packed(v: U256) -> Self {
        let limbs = v.as_limbs();
        Self {
            l1_height: limbs[1],
            l1_tx_index: (limbs[0] >> 32) as u32,
            l1_vout: limbs[0] as u32,
        }
    }
}

impl core::fmt::Display for DepositPosition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}:{}", self.l1_height, self.l1_tx_index, self.l1_vout)
    }
}

/// Storage slot of the supply-ledger account holding the cumulative minted wei.
pub const SUPPLY_LEDGER_TOTAL_MINTED_SLOT: U256 = U256::ZERO;

/// Storage slot of the supply-ledger account holding the deposit cursor: the
/// [`DepositPosition::packed`] position of the last consumed deposit
/// ([`DepositPosition::NONE`] when no deposit was ever minted).
pub const SUPPLY_LEDGER_CURSOR_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);

/// Storage slot of the supply-ledger account holding the cumulative wei the
/// EVM destroyed (EIP-6780 `SELFDESTRUCT` to self in the creating transaction),
/// as measured by the executor per transaction.
pub const SUPPLY_LEDGER_BURNED_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);

/// Storage slot of the supply-ledger account holding the cumulative wei
/// withdrawn to L1 through the outbox ([`crate::withdrawal`]): value that left
/// the L2 supply and is owed by the L1 escrow until claimed.
pub const SUPPLY_LEDGER_WITHDRAWN_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// `BLOCK_INFO` slot: non-zero once any block has executed (a head exists).
pub const BLOCK_INFO_FLAG_SLOT: U256 = U256::ZERO;
/// `BLOCK_INFO` slot: head block number.
pub const BLOCK_INFO_NUMBER_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block timestamp.
pub const BLOCK_INFO_TIMESTAMP_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block base fee per gas.
pub const BLOCK_INFO_BASE_FEE_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block gas used.
pub const BLOCK_INFO_GAS_USED_SLOT: U256 = U256::from_limbs([4, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block PREVRANDAO.
pub const BLOCK_INFO_PREVRANDAO_SLOT: U256 = U256::from_limbs([5, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block Bloch anchor root.
pub const BLOCK_INFO_ANCHOR_ROOT_SLOT: U256 = U256::from_limbs([6, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block's parent hash.
pub const BLOCK_INFO_PARENT_HASH_SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);
/// `BLOCK_INFO` slot: head block's deposits hash.
pub const BLOCK_INFO_DEPOSITS_HASH_SLOT: U256 = U256::from_limbs([8, 0, 0, 0]);

/// Size of the committed L2 block-hash ring buffer (the `BLOCKHASH` window).
pub const BLOCK_HASH_HISTORY: u64 = 256;

/// `BLOCK_INFO` slot holding the hash of L2 block `number`
/// (`0x100 + number % 256`, EIP-2935 style; valid only for the last 256
/// blocks before the head).
pub fn block_hash_slot(number: u64) -> U256 {
    U256::from(0x100u64 + number % BLOCK_HASH_HISTORY)
}

/// The committed record of the head (last executed) block, as read from the
/// [`BLOCK_INFO`] account. Together with the state root it is committed in, it
/// reconstructs the head's [`crate::executor::L2Header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRecord {
    /// Head block number.
    pub number: u64,
    /// Head block timestamp.
    pub timestamp: u64,
    /// Head block base fee per gas.
    pub base_fee_per_gas: u64,
    /// Gas used by the head block.
    pub gas_used: u64,
    /// Head block PREVRANDAO.
    pub prevrandao: B256,
    /// Head block Bloch anchor root.
    pub anchor_root: B256,
    /// Hash of the head block's parent.
    pub parent_hash: B256,
    /// Commitment to the head block's deposit list.
    pub deposits_hash: B256,
}

/// The canonical EIP-4788 beacon-roots contract as revm bytecode.
pub fn beacon_roots_bytecode() -> Bytecode {
    Bytecode::new_raw(Bytes::from_static(BEACON_ROOTS_CODE))
}

/// Errors from applying a deposit mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    /// The deposit's L1 position is not strictly after the ledger cursor: it
    /// was already minted (replay), is duplicated, or the derivation layer
    /// presented deposits out of canonical order.
    OutOfOrder {
        /// The offending deposit's position.
        position: DepositPosition,
        /// The ledger cursor (last consumed position).
        cursor: DepositPosition,
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
            DepositError::OutOfOrder { position, cursor } => {
                write!(f, "deposit at L1 position {position} is not after the ledger cursor {cursor} (replay or out of order)")
            }
            DepositError::ExceedsL1Supply { l1_sats, max_l1_sats } => {
                write!(
                    f,
                    "deposit claims {l1_sats} sats, above the L1 hard cap of {max_l1_sats} sats"
                )
            }
            DepositError::CumulativeSupplyExceeded {
                total_after_wei,
                cap_wei,
            } => write!(
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

/// The L2 execution state: revm's in-memory `CacheDB` plus a cached,
/// incrementally maintained keccak-MPT commitment over it. The zero-issuance
/// supply ledger and the head-block record are part of it, as storage of the
/// [`SUPPLY_LEDGER`] / [`BLOCK_INFO`] system accounts.
///
/// **Sealed database.** `db` is private: reads go through [`Self::db`], and
/// any direct mutation goes through [`Self::db_mut`], which invalidates the
/// cached commitment so a stale root can never be served. Blocks are applied
/// through the executor's overlay merge (`apply_overlay`), which updates the commitment for exactly
/// the accounts the block touched (audit finding C27) and prunes what the
/// state trie does not hold — EIP-161-empty accounts and zero-valued slots —
/// so the live state and the committed root agree account for account
/// (finding C26).
///
/// The database is `CacheDB<EmptyDB>`: everything the chain knows is in the
/// cache, so the from-scratch root over it is complete. The type is sealed to
/// keep that guarantee.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct L2State {
    db: InMemoryDB,
    /// Derived data (rebuilt from `db` when absent); never serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    trie: Option<StateTrie>,
}

/// Whether an account exists in the Ethereum state trie sense (EIP-161: not
/// all of nonce 0, balance 0, empty code). The **single** existence predicate
/// shared by the views, the state root, the witness generator and the pruning.
pub(crate) fn info_exists(info: &AccountInfo) -> bool {
    info.nonce != 0 || !info.balance.is_zero() || !(info.code_hash == KECCAK_EMPTY || info.code_hash == B256::ZERO)
}

/// [`info_exists`] for a cached database entry (`NotExisting` never exists).
pub(crate) fn account_exists(acc: &DbAccount) -> bool {
    acc.account_state != AccountState::NotExisting && info_exists(&acc.info)
}

/// The post-block form of one account: the overlay's entry merged over the
/// base entry it was loaded from, pruned as the state trie sees it. `None` if
/// the account does not exist after the block (destroyed, never created, or
/// EIP-161 empty). Pure; [`L2State::apply_overlay`] applies the same rules
/// in place.
pub(crate) fn merge_account(base: Option<&DbAccount>, overlay: &DbAccount) -> Option<DbAccount> {
    let mut merged = match overlay.account_state {
        AccountState::NotExisting => return None,
        // The overlay's storage is complete: nothing of the base survives.
        AccountState::StorageCleared => DbAccount {
            info: overlay.info.clone(),
            account_state: AccountState::StorageCleared,
            storage: overlay.storage.clone(),
        },
        AccountState::Touched | AccountState::None => {
            let mut storage = base
                .filter(|b| account_exists(b))
                .map(|b| b.storage.clone())
                .unwrap_or_default();
            storage.extend(overlay.storage.iter().map(|(k, v)| (*k, *v)));
            DbAccount {
                info: overlay.info.clone(),
                account_state: AccountState::Touched,
                storage,
            }
        }
    };
    if !info_exists(&merged.info) {
        return None;
    }
    if merged.info.code_hash == B256::ZERO {
        merged.info.code_hash = KECCAK_EMPTY;
    }
    merged.storage.retain(|_, v| !v.is_zero());
    Some(merged)
}

impl L2State {
    /// Fresh, empty state (genesis alloc / predeploys are out of scope for
    /// this scaffold; see README).
    pub fn new() -> Self {
        Self::default()
    }

    /// Read access to the revm database the EVM executes against.
    pub fn db(&self) -> &InMemoryDB {
        &self.db
    }

    /// Direct write access to the database (genesis construction, tests,
    /// snapshots). Invalidates the cached commitment: the next root is
    /// rebuilt from scratch, once. Block execution never needs this.
    pub fn db_mut(&mut self) -> &mut InMemoryDB {
        self.trie = None;
        &mut self.db
    }

    /// The keccak-MPT state root. O(1) while the cached commitment is warm
    /// (always, right after a block); otherwise computed from scratch without
    /// caching (see [`Self::commit_root`] to warm it).
    pub fn state_root(&self) -> B256 {
        match self.trie.as_ref().and_then(StateTrie::root_cached) {
            Some(root) => root,
            None => compute_keccak_mpt_state_root(self),
        }
    }

    /// The keccak-MPT state root, building the incremental commitment if it
    /// is absent (O(state), once) and re-hashing only what changed since the
    /// last call.
    pub fn commit_root(&mut self) -> B256 {
        self.commitment().root()
    }

    /// Whether the cached commitment is warm (root and proofs are O(touched)).
    pub fn is_warm(&self) -> bool {
        self.trie.as_ref().is_some_and(|t| t.root_cached().is_some())
    }

    /// The cached commitment, built from the database if absent.
    pub(crate) fn commitment(&mut self) -> &mut StateTrie {
        if self.trie.is_none() {
            self.trie = Some(StateTrie::build(&self.db));
        }
        self.trie.as_mut().expect("just built")
    }

    /// The warm commitment, if any.
    pub(crate) fn warm_commitment(&self) -> Option<&StateTrie> {
        self.trie.as_ref().filter(|t| t.root_cached().is_some())
    }

    /// Apply a block's overlay (a `CacheDB` layered over this state and now
    /// holding every account the block read or wrote) to the live state, and
    /// update the commitment for exactly those accounts. Returns the touched
    /// addresses.
    ///
    /// Merge rules per overlay entry: `NotExisting` (read while absent, or
    /// destroyed) removes any live entry; `StorageCleared` (created in-block)
    /// replaces the live entry, storage included; `Touched`/`None` updates the
    /// info and applies the written slots on top of the live storage. Then
    /// EIP-161-empty results and zero-valued slots are pruned, so the live
    /// state never holds a "ghost" the trie excludes. Reads that only hit
    /// absent addresses leave no trace.
    pub(crate) fn apply_overlay(&mut self, cache: Cache) -> Vec<Address> {
        self.commitment();
        let Self { db, trie } = self;
        let trie = trie.as_mut().expect("commitment built above");
        let Cache {
            accounts, contracts, ..
        } = cache;
        db.cache.contracts.extend(contracts);

        let mut touched = Vec::with_capacity(accounts.len());
        for (address, overlay) in accounts {
            touched.push(address);
            match overlay.account_state {
                AccountState::NotExisting => {
                    if db.cache.accounts.remove(&address).is_some() {
                        trie.remove_account(address);
                    }
                }
                AccountState::StorageCleared => {
                    if !info_exists(&overlay.info) {
                        if db.cache.accounts.remove(&address).is_some() {
                            trie.remove_account(address);
                        }
                        continue;
                    }
                    let mut acc = overlay;
                    db.insert_contract(&mut acc.info);
                    acc.storage.retain(|_, v| !v.is_zero());
                    trie.set_account(address, &acc);
                    db.cache.accounts.insert(address, acc);
                }
                AccountState::Touched | AccountState::None => {
                    if !info_exists(&overlay.info) {
                        if db.cache.accounts.remove(&address).is_some() {
                            trie.remove_account(address);
                        }
                        continue;
                    }
                    let mut info = overlay.info;
                    db.insert_contract(&mut info);
                    let entry = db.cache.accounts.entry(address).or_default();
                    if entry.account_state == AccountState::NotExisting {
                        entry.storage.clear();
                    }
                    if entry.account_state != AccountState::StorageCleared {
                        entry.account_state = AccountState::Touched;
                    }
                    entry.info = info;
                    let mut delta: Vec<(U256, U256)> = Vec::new();
                    for (slot, value) in overlay.storage {
                        let previous = entry.storage.get(&slot).copied().unwrap_or(U256::ZERO);
                        if previous == value {
                            continue;
                        }
                        delta.push((slot, value));
                        if value.is_zero() {
                            entry.storage.remove(&slot);
                        } else {
                            entry.storage.insert(slot, value);
                        }
                    }
                    trie.update_account(address, &entry.info, &delta);
                }
            }
        }
        // Re-hash the touched paths now, so the state is always warm (root and
        // proofs O(1) / O(targets)) after any mutation through an overlay.
        trie.root();
        touched
    }

    /// The genesis state this scaffold can produce: empty, with the EIP-4788
    /// beacon-roots predeploy installed (the executor installs it lazily
    /// anyway, so [`Self::new`] behaves identically after the first block).
    /// Genesis alloc / the vault contracts are out of scope for this scaffold.
    pub fn genesis(_spec: &ChainSpec) -> Self {
        let mut state = Self::default();
        match ensure_system_account(state.db_mut(), BEACON_ROOTS_ADDRESS, Some(&beacon_roots_bytecode())) {
            Ok(()) => state,
            Err(never) => match never {},
        }
    }

    /// Apply one deposit mint directly to this state (block-level callers use
    /// [`crate::executor::execute_block`], which is atomic and validates the
    /// whole block first). Credits **exactly** `sats_to_wei(l1_sats)` to the
    /// recipient after checking the L1 cap, the cumulative cap and that the
    /// deposit's position is strictly after the cursor; advances the cursor
    /// and the total in the committed ledger. Returns the credited wei.
    pub fn deposit_mint(&mut self, spec: &ChainSpec, deposit: &DepositMint) -> Result<U256, DepositError> {
        let mut overlay = CacheDB::new(&self.db);
        let wei = match apply_deposit(&mut overlay, spec, deposit) {
            Ok(wei) => wei,
            Err(DepositApplyError::Deposit(e)) => return Err(e),
            Err(DepositApplyError::Db(never)) => match never {},
        };
        let CacheDB { cache, .. } = overlay;
        self.apply_overlay(cache);
        Ok(wei)
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

    /// Total wei the EVM destroyed (EIP-6780), read from the committed ledger
    /// at the default [`SUPPLY_LEDGER`] address.
    pub fn total_burned_wei(&self) -> U256 {
        ledger_slot(&self.db, SUPPLY_LEDGER, SUPPLY_LEDGER_BURNED_SLOT)
    }

    /// Total wei withdrawn to L1 through the outbox, read from the committed
    /// ledger at the default [`SUPPLY_LEDGER`] address.
    pub fn total_withdrawn_wei(&self) -> U256 {
        ledger_slot(&self.db, SUPPLY_LEDGER, SUPPLY_LEDGER_WITHDRAWN_SLOT)
    }

    /// The outbox commitment in this state (`None` without an outbox account):
    /// the root and count the next settlement V3 statement would publish.
    pub fn withdrawal_commitment(&self, outbox: Address) -> Option<crate::withdrawal::WithdrawalCommitment> {
        self.account(&outbox)?;
        let count = ledger_slot(&self.db, outbox, crate::withdrawal::OUTBOX_NONCE_SLOT).as_limbs()[0];
        let root = if count == 0 {
            crate::withdrawal::empty_withdrawal_root()
        } else {
            B256::from(ledger_slot(&self.db, outbox, crate::withdrawal::OUTBOX_ROOT_SLOT))
        };
        Some(crate::withdrawal::WithdrawalCommitment { root, count })
    }

    /// The committed head-block record at the default [`BLOCK_INFO`] address
    /// (`None` before any block executed).
    pub fn head(&self) -> Option<HeadRecord> {
        self.head_at(BLOCK_INFO)
    }

    /// The committed head at a custom block-info address. Execution helpers
    /// must use `ChainSpec::block_info`, matching the executor's read/write path.
    pub fn head_at(&self, block_info: Address) -> Option<HeadRecord> {
        let slot = |s: U256| ledger_slot(&self.db, block_info, s);
        if slot(BLOCK_INFO_FLAG_SLOT).is_zero() {
            return None;
        }
        let word = |s: U256| slot(s).as_limbs()[0];
        Some(HeadRecord {
            number: word(BLOCK_INFO_NUMBER_SLOT),
            timestamp: word(BLOCK_INFO_TIMESTAMP_SLOT),
            base_fee_per_gas: word(BLOCK_INFO_BASE_FEE_SLOT),
            gas_used: word(BLOCK_INFO_GAS_USED_SLOT),
            prevrandao: B256::from(slot(BLOCK_INFO_PREVRANDAO_SLOT)),
            anchor_root: B256::from(slot(BLOCK_INFO_ANCHOR_ROOT_SLOT)),
            parent_hash: B256::from(slot(BLOCK_INFO_PARENT_HASH_SLOT)),
            deposits_hash: B256::from(slot(BLOCK_INFO_DEPOSITS_HASH_SLOT)),
        })
    }

    /// The committed hash of L2 block `number`, if it is one of the 256 blocks
    /// before the head (the `BLOCKHASH` window; the head's own hash is only
    /// committed when the next block executes).
    pub fn block_hash(&self, number: u64) -> Option<B256> {
        let head = self.head()?;
        if number >= head.number || head.number - number > BLOCK_HASH_HISTORY {
            return None;
        }
        let v = ledger_slot(&self.db, BLOCK_INFO, block_hash_slot(number));
        (!v.is_zero()).then(|| B256::from(v))
    }

    /// The deposit cursor: position of the last consumed deposit (default ledger).
    pub fn deposit_cursor(&self) -> DepositPosition {
        DepositPosition::from_packed(ledger_slot(&self.db, SUPPLY_LEDGER, SUPPLY_LEDGER_CURSOR_SLOT))
    }

    /// Whether a deposit at `position` can no longer be minted (it is at or
    /// before the cursor — default ledger).
    pub fn is_deposit_consumed(&self, position: DepositPosition) -> bool {
        position <= self.deposit_cursor()
    }

    /// Sum of every live account's native balance. With zero issuance,
    /// vault-routed fees and the executor's burn and withdrawal accounting this
    /// equals [`Self::total_minted_wei`]` - `[`Self::total_burned_wei`]` -
    /// `[`Self::total_withdrawn_wei`] — asserted by the executor tests.
    pub fn total_native_wei(&self) -> U256 {
        self.db
            .cache
            .accounts
            .values()
            .filter(|acc| account_exists(acc))
            .fold(U256::ZERO, |sum, acc| {
                sum.checked_add(acc.info.balance)
                    .expect("summed balances cannot overflow U256")
            })
    }

    /// Read-only account view (`None` if the account does not exist — in the
    /// EIP-161 sense the state root uses: nonce 0, balance 0 and no code is
    /// "absent").
    pub fn account(&self, address: &Address) -> Option<L2Account> {
        let acc: &DbAccount = self.db.cache.accounts.get(address).filter(|acc| account_exists(acc))?;
        let info = &acc.info;
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

    /// Storage `slot` of `address` (zero if absent or unset).
    pub fn storage_of(&self, address: &Address, slot: U256) -> U256 {
        ledger_slot(&self.db, *address, slot)
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

/// Materialize `address` as a **system account**: non-empty (nonce 1) so
/// EIP-161 never drops it — and its storage — from the state trie, with `code`
/// installed if given and the account has none yet. Existing balances, nonces
/// and code are never overwritten. Idempotent.
pub(crate) fn ensure_system_account<ExtDB: DatabaseRef>(
    db: &mut CacheDB<ExtDB>,
    address: Address,
    code: Option<&Bytecode>,
) -> Result<(), ExtDB::Error> {
    let code_hash = code.map(|c| c.hash_slow());
    let acc = db.load_account(address)?;
    if acc.account_state == AccountState::NotExisting {
        // A brand-new account has no storage anywhere: mark it StorageCleared
        // so slot reads never consult the backing database.
        acc.account_state = AccountState::StorageCleared;
    }
    if acc.info.nonce == 0 {
        acc.info.nonce = 1;
    }
    let mut install = false;
    if let (Some(c), Some(h)) = (code, code_hash) {
        if acc.info.code_hash == KECCAK_EMPTY || acc.info.code_hash == B256::ZERO {
            acc.info.code_hash = h;
            acc.info.code = Some(c.clone());
            install = true;
        }
    }
    if install {
        if let (Some(c), Some(h)) = (code, code_hash) {
            db.cache.contracts.entry(h).or_insert_with(|| c.clone());
        }
    }
    Ok(())
}

/// Add `amount` to storage `slot` of the system account `account` (reads go
/// through the [`Database`] trait so recording / stateless backings observe
/// them). Returns the new value.
pub(crate) fn ledger_add<ExtDB: DatabaseRef>(
    db: &mut CacheDB<ExtDB>,
    account: Address,
    slot: U256,
    amount: U256,
) -> Result<U256, ExtDB::Error> {
    db.basic(account)?;
    let current = db.storage(account, slot)?;
    let next = current.checked_add(amount).expect("ledger slot cannot overflow U256");
    ensure_system_account(db, account, None)?;
    db.insert_account_storage(account, slot, next)?;
    Ok(next)
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

/// Apply one deposit against any `CacheDB`: cap checks, cursor check against
/// the committed ledger, ledger update, recipient credit. All ledger reads go
/// through the [`Database`] trait so a recording or stateless backing observes
/// them. Returns the credited wei. On `Err` nothing has been written.
pub(crate) fn apply_deposit<ExtDB: DatabaseRef>(
    db: &mut CacheDB<ExtDB>,
    spec: &ChainSpec,
    deposit: &DepositMint,
) -> Result<U256, DepositApplyError<ExtDB::Error>> {
    let position = deposit.position();
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
    let cursor = DepositPosition::from_packed(
        db.storage(ledger, SUPPLY_LEDGER_CURSOR_SLOT)
            .map_err(DepositApplyError::Db)?,
    );
    if position <= cursor {
        return Err(DepositApplyError::Deposit(DepositError::OutOfOrder {
            position,
            cursor,
        }));
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
    ensure_system_account(db, ledger, None).map_err(DepositApplyError::Db)?;
    db.insert_account_storage(ledger, SUPPLY_LEDGER_CURSOR_SLOT, position.packed())
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

    static NEXT_HEIGHT: AtomicU32 = AtomicU32::new(1);

    /// A deposit at a fresh, strictly increasing L1 position.
    fn blch_deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: NEXT_HEIGHT.fetch_add(1, Ordering::Relaxed) as u64,
                l1_tx_index: 0,
                l1_txid: [0x42; 32],
                l1_vout: 0,
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
        assert_eq!(state.total_minted_wei(), sats_to_wei(200_000_000) + sats_to_wei(1));
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
        assert_eq!(state.total_burned_wei(), U256::ZERO);
        assert!(state.head().is_none(), "no block executed yet");
        assert!(state.block_hash(0).is_none());
        // Nonces untouched by mints.
        assert_eq!(state.nonce_of(&ALICE), 0);
        // The ledger is a real, non-empty account (nonce 1, no code).
        let ledger = state.account(&SUPPLY_LEDGER).expect("ledger exists");
        assert_eq!(ledger.nonce, 1);
        assert_eq!(ledger.code_hash, KECCAK_EMPTY);
    }

    #[test]
    fn replayed_or_out_of_order_deposit_is_rejected_and_is_a_noop() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        assert_eq!(state.deposit_cursor(), DepositPosition::NONE);
        let dep = blch_deposit(ALICE, 100);
        state.deposit_mint(&spec, &dep).unwrap();
        assert_eq!(state.deposit_cursor(), dep.position());
        assert!(state.is_deposit_consumed(dep.position()));

        let before_root = crate::compute_keccak_mpt_state_root(&state);
        // Replay of the very same deposit.
        let err = state.deposit_mint(&spec, &dep).unwrap_err();
        assert_eq!(
            err,
            DepositError::OutOfOrder {
                position: dep.position(),
                cursor: dep.position()
            }
        );
        // Same position with a different recipient / amount is still rejected.
        let mut other = dep;
        other.recipient = BOB;
        let DepositProvenance::BridgedBlch {
            l1_height,
            l1_tx_index,
            l1_vout,
            ..
        } = dep.provenance;
        other.provenance = DepositProvenance::BridgedBlch {
            l1_height,
            l1_tx_index,
            l1_txid: [9; 32],
            l1_vout,
            l1_sats: 5,
        };
        assert!(matches!(
            state.deposit_mint(&spec, &other),
            Err(DepositError::OutOfOrder { .. })
        ));
        // An earlier position (out-of-order derivation) is rejected too.
        let earlier = DepositMint {
            recipient: BOB,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 0,
                l1_tx_index: 1,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 5,
            },
        };
        assert!(earlier.position() < dep.position());
        assert!(matches!(
            state.deposit_mint(&spec, &earlier),
            Err(DepositError::OutOfOrder { .. })
        ));
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(100));
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
        assert_eq!(state.total_minted_wei(), sats_to_wei(100));
        assert_eq!(state.deposit_cursor(), dep.position());
        assert_eq!(
            crate::compute_keccak_mpt_state_root(&state),
            before_root,
            "rejected deposit is a no-op"
        );

        // Positions order lexicographically and round-trip through the packing.
        let a = DepositPosition {
            l1_height: 5,
            l1_tx_index: 7,
            l1_vout: 9,
        };
        let b = DepositPosition {
            l1_height: 5,
            l1_tx_index: 8,
            l1_vout: 0,
        };
        let c = DepositPosition {
            l1_height: 6,
            l1_tx_index: 0,
            l1_vout: 0,
        };
        assert!(a < b && b < c);
        assert!(a.packed() < b.packed() && b.packed() < c.packed());
        for p in [
            a,
            b,
            c,
            DepositPosition::NONE,
            DepositPosition {
                l1_height: u64::MAX,
                l1_tx_index: u32::MAX,
                l1_vout: u32::MAX,
            },
        ] {
            assert_eq!(DepositPosition::from_packed(p.packed()), p);
        }
    }

    #[test]
    fn deposit_above_l1_cap_is_rejected() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let err = state
            .deposit_mint(&spec, &blch_deposit(ALICE, spec.max_l1_sats + 1))
            .unwrap_err();
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
        state
            .deposit_mint(&spec, &blch_deposit(ALICE, spec.max_l1_sats))
            .unwrap();
        assert_eq!(state.total_minted_wei(), sats_to_wei(spec.max_l1_sats));
        // One more sat is not.
        let err = state.deposit_mint(&spec, &blch_deposit(BOB, 1)).unwrap_err();
        assert!(matches!(err, DepositError::CumulativeSupplyExceeded { .. }));
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
        assert_eq!(state.total_minted_wei(), sats_to_wei(spec.max_l1_sats));
    }

    #[test]
    fn genesis_installs_the_beacon_roots_predeploy_idempotently() {
        let spec = ChainSpec::testnet();
        let state = L2State::genesis(&spec);
        let acc = state.account(&BEACON_ROOTS_ADDRESS).expect("predeploy exists");
        assert_eq!(acc.nonce, 1);
        assert_eq!(acc.code_hash, beacon_roots_bytecode().hash_slow());
        assert_eq!(state.total_native_wei(), U256::ZERO);
        // Re-ensuring never changes anything (root-stable).
        let root = crate::compute_keccak_mpt_state_root(&state);
        let mut again = state.clone();
        ensure_system_account(again.db_mut(), BEACON_ROOTS_ADDRESS, Some(&beacon_roots_bytecode())).unwrap();
        assert_eq!(crate::compute_keccak_mpt_state_root(&again), root);
        // System accounts without code stay code-less; a non-zero nonce is kept.
        let mut s2 = L2State::new();
        s2.db_mut().insert_account_info(
            ALICE,
            revm::state::AccountInfo {
                nonce: 7,
                ..Default::default()
            },
        );
        ensure_system_account(s2.db_mut(), ALICE, None).unwrap();
        assert_eq!(s2.nonce_of(&ALICE), 7);
        assert_eq!(s2.account(&ALICE).unwrap().code_hash, KECCAK_EMPTY);
        // ledger_add accumulates.
        assert_eq!(
            ledger_add(s2.db_mut(), SUPPLY_LEDGER, SUPPLY_LEDGER_BURNED_SLOT, U256::from(5u64)).unwrap(),
            U256::from(5u64)
        );
        assert_eq!(
            ledger_add(s2.db_mut(), SUPPLY_LEDGER, SUPPLY_LEDGER_BURNED_SLOT, U256::from(6u64)).unwrap(),
            U256::from(11u64)
        );
        assert_eq!(s2.total_burned_wei(), U256::from(11u64));
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
        assert!(state.is_deposit_consumed(dep.position()));
    }

    #[test]
    fn ledger_is_committed_in_the_state_root() {
        // Two states with identical account balances but different mint
        // histories (different cursor positions) must hash differently, and a
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
            "the deposit cursor is part of the commitment"
        );
        let root_a = crate::compute_keccak_mpt_state_root(&a);
        assert_eq!(
            a.state_root(),
            root_a,
            "incremental root agrees with the from-scratch root"
        );
        a.db_mut()
            .insert_account_storage(SUPPLY_LEDGER, SUPPLY_LEDGER_TOTAL_MINTED_SLOT, U256::from(1u64))
            .unwrap();
        assert_ne!(
            crate::compute_keccak_mpt_state_root(&a),
            root_a,
            "ledger total is committed"
        );
        assert_eq!(
            a.state_root(),
            crate::compute_keccak_mpt_state_root(&a),
            "db_mut invalidated the cache"
        );
    }

    #[test]
    fn views_and_root_share_one_existence_predicate_and_ghosts_are_pruned() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        // A touched-empty account planted directly in the database is a ghost:
        // the root excludes it, so the views must too.
        state.db_mut().insert_account_info(BOB, AccountInfo::default());
        assert!(state.db().cache.accounts.contains_key(&BOB));
        assert!(
            state.account(&BOB).is_none(),
            "EIP-161-empty account is reported as absent"
        );
        assert_eq!(state.total_native_wei(), U256::ZERO);
        // Applying an overlay that touches the ghost (a zero-value read) prunes it.
        let mut overlay = CacheDB::new(state.db());
        overlay.basic(BOB).unwrap();
        let CacheDB { cache, .. } = overlay;
        let touched = state.apply_overlay(cache);
        assert_eq!(touched, alloc::vec![BOB]);
        assert!(
            !state.db().cache.accounts.contains_key(&BOB),
            "ghost pruned from the live state"
        );
        // A deposit through the overlay path creates a real account and keeps
        // the incremental root equal to the from-scratch root.
        state.deposit_mint(&spec, &blch_deposit(ALICE, 5)).unwrap();
        assert!(state.is_warm());
        assert_eq!(state.state_root(), crate::compute_keccak_mpt_state_root(&state));
        assert_eq!(state.commit_root(), crate::compute_keccak_mpt_state_root(&state));
        // Zero-valued slots written through an overlay are not kept.
        let mut overlay = CacheDB::new(state.db());
        overlay
            .insert_account_storage(SUPPLY_LEDGER, U256::from(9u64), U256::ZERO)
            .unwrap();
        overlay
            .insert_account_storage(SUPPLY_LEDGER, U256::from(10u64), U256::from(1u64))
            .unwrap();
        let CacheDB { cache, .. } = overlay;
        state.apply_overlay(cache);
        let ledger = &state.db().cache.accounts[&SUPPLY_LEDGER];
        assert!(!ledger.storage.contains_key(&U256::from(9u64)));
        assert_eq!(ledger.storage[&U256::from(10u64)], U256::from(1u64));
        assert_eq!(state.state_root(), crate::compute_keccak_mpt_state_root(&state));
        // merge_account agrees with the applied state.
        let merged = merge_account(
            None,
            &DbAccount {
                info: AccountInfo::default(),
                account_state: AccountState::Touched,
                storage: Default::default(),
            },
        );
        assert!(merged.is_none(), "touched-empty merges to non-existence");
    }
}
