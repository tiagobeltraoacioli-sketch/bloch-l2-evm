// SPDX-License-Identifier: MIT OR Apache-2.0
//! CANDIDATE, inert: a sparse settlement witness. Nothing in a release builds or
//! selects this module. The pinned program is unchanged.
//!
//! [`crate::proving::BatchWitness`] carries the complete non-zero storage of every
//! touched account, and its guest re-hashes all of it. Every block touches the
//! EIP-4788 predeploy, whose ring holds 16,380 slots after 8,191 blocks, and any
//! contract with a large storage is charged the same way by every block that calls it.
//!
//! This witness carries, per account, its storage root and a multiproof of only the
//! slots the block touches. The state transition is the same: same revm, same rules,
//! same roots, same statement bytes.
//!
//! # The soundness property
//!
//! **A slot the witness does not cover is never read as zero.** The guest's backing
//! database is the authenticated proof itself, and it answers in three ways only:
//!
//! * the key is an exposed leaf hash-linked to the storage root: its value;
//! * the key's position is exposed and empty, which proves exclusion: zero;
//! * the key lies under an opaque subtree: an **error**, which fails the whole block.
//!
//! The account's `StorageCleared` marker, which the complete witness uses to make a
//! missing slot read as zero, is never set by hydration. It arises only inside
//! revm's own commit, for an account created in the block, whose old storage is gone
//! by the rules. A database error inside a call frame is not a revert: revm returns
//! it as a fatal `EVMError::Database`, and `BlockSession::try_transaction` fails the
//! block with it. So an omitted slot cannot be turned into a caught failure either.
//!
//! The chain of trust is `prev_state_root` -> account multiproof -> account leaf
//! (which fixes nonce, balance, code hash and storage root) -> storage multiproof.
//! `prev_state_root` itself is bound by the settlement statement, as today.
//!
//! # Code
//!
//! An account leaf fixes the account's code hash, and the witness carries that hash,
//! not the code. Code travels in a separate list, [`SparseBatchWitness::codes`],
//! which holds only the code the block loads. The guest hashes each entry once and
//! keys it by the hash it computed, so an entry can only ever be served for its own
//! hash. A code the block loads and the list does not hold is a database error, which
//! fails the block like an unwitnessed slot. An entry the block never loads is
//! unused. So a deposit to a contract, or a `BALANCE` of one, costs no code.
//!
//! The post-state root is derived from the same views. A write under an opaque
//! subtree is an error, and so is a zero write there, because it could be a deletion.
//!
//! # BLOCKHASH
//!
//! The canonical path reads the whole 256-slot block-hash ring of the block-info
//! account for every block. [`BlockHashes::Lazy`] reads a ring slot only when a
//! `BLOCKHASH` asks for it, through the same authenticated lookup. The value served
//! is the one the eager path would cache, and the generator rejects any difference.

#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};
use alloc::collections::{BTreeMap, BTreeSet};
use core::cell::RefCell;
use core::ops::Range;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::Nibbles;
use revm::database::{AccountState, CacheDB, InMemoryDB};
use revm::database_interface::DBErrorMarker;
use revm::primitives::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};
use revm::DatabaseRef;

use crate::executor::{BlockExecutionError, BlockSession};
use crate::node_execution::{head, outcome_record, prepare_parent, NodeExecutionError, NodeExecutionOutcome, PendingOutcome};
use crate::node_execution::{generate_node_batch_witness, NodeWitnessError};
use crate::node_primitives::NodeBodyV2;
use crate::proof_statement::{configuration_commitment, SettlementContextV2, SettlementStatementV2Error, SettlementStatementV3};
use crate::state::{account_exists, block_hash_slot, info_exists, BLOCK_HASH_HISTORY};
use crate::stateroot::{account_key, account_leaf, account_leaf_with_root, storage_key, IndexedTrieView, WitnessError};
use crate::{BlockContext, ChainSpec, L2State};

#[cfg(feature = "serde")]
const MAX_WITNESS_TRIE_NODE_BYTES: usize = 1024;
/// Allocation guard for [`SparseBatchWitness::codes`]: entries. Not a rule: far
/// above what a block's gas can load, as each load of a cold account costs 2,600 gas.
#[cfg(feature = "serde")]
const MAX_WITNESS_CODES: usize = 1 << 16;
/// Allocation guard for [`SparseBatchWitness::codes`]: bytes over all entries.
#[cfg(feature = "serde")]
const MAX_WITNESS_CODE_BYTES: usize = 1 << 30;

/// A settlement witness with sparse storage. All vectors are sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseBatchWitness {
    /// State root before the block.
    pub prev_state_root: B256,
    /// State root after the block as claimed by the host; the guest derives its own.
    pub new_state_root: B256,
    /// Account-trie multiproof against `prev_state_root`.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_proof"))]
    pub proof: BTreeMap<Nibbles, Bytes>,
    /// Touched accounts that exist in the pre-state.
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "crate::serde_bounded::streaming_vector")
    )]
    pub pre_accounts: Vec<SparseWitnessAccount>,
    /// Touched addresses that do not exist in the pre-state; each is proved absent.
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "crate::serde_bounded::streaming_vector")
    )]
    pub absent_accounts: Vec<Address>,
    /// Code the block loads, sorted by hash, each entry once. The guest hashes every
    /// entry and serves it only for that hash; see the module documentation.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_codes"))]
    pub codes: Vec<Bytes>,
}

/// A touched pre-state account. It carries no slot values: every value is a leaf of
/// `storage_proof`, so nothing here can state a value the trie does not hold. It
/// carries no code either: `code_hash` is bound by the account leaf, and the code
/// itself, when the block loads it, comes from [`SparseBatchWitness::codes`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseWitnessAccount {
    /// Account address.
    pub address: Address,
    /// Balance.
    pub balance: U256,
    /// Nonce.
    pub nonce: u64,
    /// Code hash, `KECCAK_EMPTY` for an account without code; authenticated by the
    /// account leaf.
    pub code_hash: B256,
    /// Storage root; authenticated by the account leaf.
    pub storage_root: B256,
    /// Storage multiproof against `storage_root`.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_proof"))]
    pub storage_proof: BTreeMap<Nibbles, Bytes>,
}

#[cfg(feature = "serde")]
fn deserialize_proof<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<BTreeMap<Nibbles, Bytes>, D::Error> {
    crate::serde_bounded::nibble_byte_map::<_, MAX_WITNESS_TRIE_NODE_BYTES>(deserializer)
}

#[cfg(feature = "serde")]
fn deserialize_codes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Bytes>, D::Error> {
    crate::serde_bounded::byte_vectors::<
        _,
        MAX_WITNESS_CODES,
        { revm::primitives::eip170::MAX_CODE_SIZE },
        MAX_WITNESS_CODE_BYTES,
    >(deserializer)
}

/// How `BLOCKHASH` reaches the block-hash ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockHashes {
    /// Read the whole window before any transaction, as the canonical path does.
    Eager,
    /// Read a ring slot only when `BLOCKHASH` asks for it.
    Lazy,
}

/// A read the sparse witness does not answer. Each fails the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparseAccessError {
    /// An account neither hydrated nor proven absent.
    UnwitnessedAccount(Address),
    /// Code no hydrated account carries.
    UnwitnessedCode(B256),
    /// A slot whose trie position the proof leaves opaque.
    UnwitnessedStorage(Address, U256),
    /// A slot of an account that has no authenticated view.
    UnknownStorageAccount(Address, U256),
    /// A trie leaf that is not a canonical non-zero word.
    MalformedStorageValue(Address, U256),
    /// `BLOCKHASH` outside the window this block may read.
    UnwitnessedBlockHash(u64),
}

impl core::fmt::Display for SparseAccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnwitnessedAccount(a) => write!(f, "account {a} is not covered by the witness"),
            Self::UnwitnessedCode(h) => write!(f, "code {h} is not covered by the witness"),
            Self::UnwitnessedStorage(a, s) => write!(f, "slot {s} of {a} is not covered by the witness"),
            Self::UnknownStorageAccount(a, s) => write!(f, "slot {s} of {a}: account has no storage view"),
            Self::MalformedStorageValue(a, s) => write!(f, "slot {s} of {a}: malformed value in the trie"),
            Self::UnwitnessedBlockHash(n) => write!(f, "block hash of block {n} is not covered by the witness"),
        }
    }
}

impl core::error::Error for SparseAccessError {}
impl DBErrorMarker for SparseAccessError {}

/// Read one slot from an authenticated view. Exclusion is the only source of zero.
fn read_slot(view: &IndexedTrieView, address: Address, slot: U256) -> Result<U256, SparseAccessError> {
    match view.lookup(&storage_key(&slot)) {
        Err(_) => Err(SparseAccessError::UnwitnessedStorage(address, slot)),
        Ok(None) => Ok(U256::ZERO),
        Ok(Some(leaf)) => {
            let mut bytes = leaf;
            match U256::decode(&mut bytes) {
                Ok(value) if bytes.is_empty() && !value.is_zero() => Ok(value),
                _ => Err(SparseAccessError::MalformedStorageValue(address, slot)),
            }
        }
    }
}

/// The guest's database: proven-absent addresses and one authenticated view per
/// hydrated account. Hydrated account records sit in the `CacheDB` above it with no
/// storage and without `StorageCleared`, so every first slot read arrives here.
#[derive(Debug, Clone, Default)]
pub struct SparseBacking {
    absent: BTreeSet<Address>,
    storage: BTreeMap<Address, IndexedTrieView>,
    block_info: Address,
    block_hash_window: Range<u64>,
}

impl DatabaseRef for SparseBacking {
    type Error = SparseAccessError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if self.absent.contains(&address) {
            Ok(None)
        } else {
            Err(SparseAccessError::UnwitnessedAccount(address))
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Err(SparseAccessError::UnwitnessedCode(code_hash))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(view) = self.storage.get(&address) {
            return read_slot(view, address, index);
        }
        if self.absent.contains(&address) {
            // Proven absent from the state trie: it has no storage trie at all.
            return Ok(U256::ZERO);
        }
        Err(SparseAccessError::UnknownStorageAccount(address, index))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        if !self.block_hash_window.contains(&number) {
            return Err(SparseAccessError::UnwitnessedBlockHash(number));
        }
        let view = self
            .storage
            .get(&self.block_info)
            .ok_or(SparseAccessError::UnwitnessedBlockHash(number))?;
        let word = read_slot(view, self.block_info, block_hash_slot(number))
            .map_err(|_| SparseAccessError::UnwitnessedBlockHash(number))?;
        Ok(B256::from(word))
    }
}

/// Why a sparse witness is rejected.
#[derive(Debug)]
pub enum SparseVerifyError {
    /// The account multiproof failed.
    Witness(WitnessError),
    /// A storage multiproof failed.
    Storage(Address, WitnessError),
    /// An address appears twice.
    DuplicateAccount(Address),
    /// A witness account is EIP-161 empty.
    EmptyAccount(Address),
    /// An entry of `codes` is empty or does not decode; its index.
    InvalidCode(usize),
    /// Two entries of `codes` have the same hash.
    DuplicateCode(B256),
    /// A witness account states the zero code hash, which no account leaf holds.
    ZeroCodeHash(Address),
    /// A witness account does not open against `prev_state_root` with these fields.
    AccountNotProven(Address),
    /// An address listed as absent is not proved absent.
    AccountNotProvenAbsent(Address),
    /// The cached account has no authenticated origin.
    UnknownAccount(Address),
    /// A storage value in the cache has no authenticated pre-state.
    Slot(SparseAccessError),
    /// The derived root differs from the claim.
    ClaimedRootMismatch {
        /// The claim.
        claimed: B256,
        /// The guest's root.
        derived: B256,
    },
}

impl core::fmt::Display for SparseVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Witness(e) => write!(f, "account proof: {e}"),
            Self::Storage(a, e) => write!(f, "storage proof of {a}: {e}"),
            Self::DuplicateAccount(a) => write!(f, "address {a} listed twice"),
            Self::EmptyAccount(a) => write!(f, "pre-account {a} is EIP-161 empty"),
            Self::InvalidCode(i) => write!(f, "code entry {i} is empty or invalid"),
            Self::DuplicateCode(h) => write!(f, "code {h} listed twice"),
            Self::ZeroCodeHash(a) => write!(f, "pre-account {a} states the zero code hash"),
            Self::AccountNotProven(a) => write!(f, "pre-account {a} does not open against prev_state_root"),
            Self::AccountNotProvenAbsent(a) => write!(f, "address {a} is not proved absent"),
            Self::UnknownAccount(a) => write!(f, "account {a} has no authenticated origin"),
            Self::Slot(e) => write!(f, "{e}"),
            Self::ClaimedRootMismatch { claimed, derived } => write!(f, "derived root {derived} != claimed {claimed}"),
        }
    }
}

impl core::error::Error for SparseVerifyError {}

/// A verified, hydrated pre-state ready for re-execution.
#[derive(Debug)]
pub struct HydratedSparse {
    /// Accounts in the cache, storage behind the authenticated backing.
    pub state: CacheDB<SparseBacking>,
    account_view: IndexedTrieView,
    pre_leaves: BTreeMap<Nibbles, Vec<u8>>,
    pre_storage_roots: BTreeMap<Address, B256>,
}

/// Authenticate the witness and build the guest database for block `number`.
pub fn hydrate_sparse(
    spec: &ChainSpec,
    witness: &SparseBatchWitness,
    number: u64,
) -> Result<HydratedSparse, SparseVerifyError> {
    let account_view =
        IndexedTrieView::from_proof(witness.prev_state_root, &witness.proof).map_err(SparseVerifyError::Witness)?;

    let mut seen: BTreeSet<Address> = BTreeSet::new();
    for address in witness
        .pre_accounts
        .iter()
        .map(|account| &account.address)
        .chain(&witness.absent_accounts)
    {
        if !seen.insert(*address) {
            return Err(SparseVerifyError::DuplicateAccount(*address));
        }
    }

    // Each code entry is keyed by the hash computed here, never by a claim.
    let mut codes: BTreeMap<B256, Bytecode> = BTreeMap::new();
    for (index, code) in witness.codes.iter().enumerate() {
        if code.is_empty() {
            return Err(SparseVerifyError::InvalidCode(index));
        }
        let bytecode = Bytecode::new_raw_checked(code.clone()).map_err(|_| SparseVerifyError::InvalidCode(index))?;
        let hash = bytecode.hash_slow();
        if codes.insert(hash, bytecode).is_some() {
            return Err(SparseVerifyError::DuplicateCode(hash));
        }
    }

    let mut storage = BTreeMap::new();
    let mut pre_leaves = BTreeMap::new();
    let mut pre_storage_roots = BTreeMap::new();
    let mut infos = Vec::with_capacity(witness.pre_accounts.len());
    for account in &witness.pre_accounts {
        if account.code_hash == B256::ZERO {
            return Err(SparseVerifyError::ZeroCodeHash(account.address));
        }
        // No code here: revm loads it by hash, from `codes` or not at all.
        let info = AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            code: None,
            ..Default::default()
        };
        if !info_exists(&info) {
            return Err(SparseVerifyError::EmptyAccount(account.address));
        }
        // The leaf fixes nonce, balance, code hash and storage root at once.
        let path = account_key(&account.address);
        let leaf = account_leaf_with_root(&info, account.storage_root);
        match account_view.lookup(&path).map_err(SparseVerifyError::Witness)? {
            Some(proven) if proven == leaf.as_slice() => {}
            _ => return Err(SparseVerifyError::AccountNotProven(account.address)),
        }
        let view = IndexedTrieView::from_proof(account.storage_root, &account.storage_proof)
            .map_err(|error| SparseVerifyError::Storage(account.address, error))?;
        storage.insert(account.address, view);
        pre_leaves.insert(path, leaf);
        pre_storage_roots.insert(account.address, account.storage_root);
        infos.push((account.address, info));
    }
    for address in &witness.absent_accounts {
        match account_view.lookup(&account_key(address)) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(SparseVerifyError::AccountNotProvenAbsent(*address)),
            Err(error) => return Err(SparseVerifyError::Witness(error)),
        }
    }

    let mut state = CacheDB::new(SparseBacking {
        absent: witness.absent_accounts.iter().copied().collect(),
        storage,
        block_info: spec.block_info,
        block_hash_window: number.saturating_sub(BLOCK_HASH_HISTORY)..number,
    });
    for (address, info) in infos {
        // `insert_account_info` leaves the account state `None`: slot reads go down
        // to the backing. Never mark these accounts `StorageCleared`. With `code`
        // unset it adds nothing to the contract cache.
        state.insert_account_info(address, info);
    }
    // A code load finds its entry here; a load of any other hash falls through to
    // `SparseBacking::code_by_hash_ref`, which fails the block.
    state.cache.contracts.extend(codes);
    Ok(HydratedSparse {
        state,
        account_view,
        pre_leaves,
        pre_storage_roots,
    })
}

/// Derive the new storage root of one account that was not wiped in this block.
fn post_storage_root(
    address: Address,
    view: &IndexedTrieView,
    pre_root: B256,
    written: impl Iterator<Item = (U256, U256)>,
) -> Result<B256, SparseVerifyError> {
    let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
    for (slot, value) in written {
        let key = storage_key(&slot);
        // Every slot in the cache must have an authenticated pre-state, including
        // one written without a read and a zero write: under an opaque subtree it
        // could be a deletion the root would not show.
        let pre = view
            .lookup(&key)
            .map_err(|_| SparseVerifyError::Slot(SparseAccessError::UnwitnessedStorage(address, slot)))?;
        if value.is_zero() {
            if pre.is_some() {
                changes.insert(key, None);
            }
        } else {
            let encoded = alloy_rlp::encode(value);
            if pre != Some(encoded.as_slice()) {
                changes.insert(key, Some(encoded));
            }
        }
    }
    if changes.is_empty() {
        return Ok(pre_root);
    }
    view.apply(&changes)
        .map_err(|error| SparseVerifyError::Storage(address, error))
}

/// Derive the post-state root from the executed cache and the authenticated views.
fn derive_post_root(
    witness: &SparseBatchWitness,
    account_view: &IndexedTrieView,
    pre_leaves: &BTreeMap<Nibbles, Vec<u8>>,
    pre_storage_roots: &BTreeMap<Address, B256>,
    db: &CacheDB<SparseBacking>,
) -> Result<B256, SparseVerifyError> {
    let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
    for (address, account) in db.cache.accounts.iter() {
        let path = account_key(address);
        let pre = pre_leaves.get(&path);
        if !account_exists(account) {
            if pre.is_some() {
                changes.insert(path, None);
            }
            continue;
        }
        let leaf = match account.account_state {
            // Created or wiped in this block: by revm's commit, or by a protocol
            // write to an account that did not exist (`ensure_system_account`,
            // `credit_balance`). The cached storage is all the account has.
            AccountState::StorageCleared => account_leaf(account),
            // `account_exists` is false for this state, so the loop has already
            // continued. Refuse rather than derive a leaf if that ever changes.
            AccountState::NotExisting => return Err(SparseVerifyError::UnknownAccount(*address)),
            AccountState::None | AccountState::Touched => {
                let written = account.storage.iter().map(|(slot, value)| (*slot, *value));
                let root = match (db.db.storage.get(address), pre_storage_roots.get(address)) {
                    (Some(view), Some(pre_root)) => post_storage_root(*address, view, *pre_root, written)?,
                    _ if db.db.absent.contains(address) => {
                        post_storage_root(*address, &IndexedTrieView::empty(), alloy_trie::EMPTY_ROOT_HASH, written)?
                    }
                    _ => return Err(SparseVerifyError::UnknownAccount(*address)),
                };
                account_leaf_with_root(&account.info, root)
            }
        };
        if pre != Some(&leaf) {
            changes.insert(path, Some(leaf));
        }
    }
    let derived = account_view.apply(&changes).map_err(SparseVerifyError::Witness)?;
    if derived != witness.new_state_root {
        return Err(SparseVerifyError::ClaimedRootMismatch {
            claimed: witness.new_state_root,
            derived,
        });
    }
    Ok(derived)
}

/// `prepare_parent` without the eager read of the window. The parent's hash is the
/// only ring entry that must be written first; a later entry of the window is the
/// committed one. No number in `[N - 256, N - 2]` shares a ring slot with `N - 1`.
fn prepare_parent_lazy<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: &mut CacheDB<DB>,
    previous_root: B256,
    context: &BlockContext,
) -> Result<B256, BlockExecutionError> {
    let parent = head::read_head_v2(db, spec.block_info)?.header(spec, domain, previous_root);
    parent
        .validate_configuration(spec, domain)
        .map_err(|e| BlockExecutionError::HeaderState { detail: format!("{e}") })?;
    let expected = parent
        .number
        .checked_add(1)
        .ok_or(BlockExecutionError::InvalidBlockNumber {
            expected: u64::MAX,
            got: context.number,
        })?;
    if context.number != expected {
        return Err(BlockExecutionError::InvalidBlockNumber {
            expected,
            got: context.number,
        });
    }
    if context.timestamp < parent.timestamp {
        return Err(BlockExecutionError::InvalidTimestamp {
            parent: parent.timestamp,
            got: context.timestamp,
        });
    }
    let expected = spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used);
    if context.base_fee_per_gas != expected {
        return Err(BlockExecutionError::InvalidBaseFee {
            expected,
            got: context.base_fee_per_gas,
        });
    }
    let hash = parent.hash();
    db.insert_account_storage(spec.block_info, block_hash_slot(parent.number), hash.into())
        .map_err(|e| BlockExecutionError::Database {
            detail: format!("{e:?}"),
        })?;
    db.cache.block_hashes.insert(U256::from(parent.number), hash);
    Ok(hash)
}

/// `run_node_block` with a choice of how the ring is read.
fn run_sparse_block<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: CacheDB<DB>,
    previous_root: B256,
    context: &BlockContext,
    body: &NodeBodyV2,
    block_hashes: BlockHashes,
) -> Result<(CacheDB<DB>, PendingOutcome), NodeExecutionError> {
    let input = body.authenticated_input(spec).map_err(NodeExecutionError::Body)?;
    let mut parent_timestamp = 0;
    let mut session = BlockSession::begin_with_header(spec, db, context, &body.deposits, |db| {
        parent_timestamp = head::read_head_v2(db, spec.block_info)?.base.timestamp;
        match block_hashes {
            BlockHashes::Eager => prepare_parent(spec, domain, db, previous_root, context),
            BlockHashes::Lazy => prepare_parent_lazy(spec, domain, db, previous_root, context),
        }
    })?;
    for tx in &input.txs {
        session.try_transaction(tx, |_| true)?;
    }
    let (db, run, (record, receipts)) = session.finish_with_header(|db, run| {
        let (record, receipts) = outcome_record(context, previous_root, run, body, &input.txs)?;
        head::write_head_v2(db, spec.block_info, &record)?;
        Ok((record, receipts))
    })?;
    Ok((
        db,
        PendingOutcome {
            record,
            receipts,
            transactions: run.tx_outcomes,
            withdrawals: run.withdrawals,
            parent_timestamp,
        },
    ))
}

/// Failure of the sparse verifier on the V2 path.
#[derive(Debug)]
pub enum SparseNodeError {
    /// The block does not execute, including any read the witness does not cover.
    Execution(NodeExecutionError),
    /// The witness failed authentication or does not derive the claimed root.
    Verify(SparseVerifyError),
    /// The independent canonical path failed (host only).
    Canonical(NodeWitnessError),
    /// The commitment is cold (host only).
    ColdCommitment,
    /// A proof could not be built (host only).
    ProofBuild(Address),
    /// The block loaded a code the pre-state does not hold (host only).
    MissingCode(B256),
    /// The sparse path did not reproduce the canonical outcome (host only).
    OutcomeMismatch,
}

impl core::fmt::Display for SparseNodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Execution(e) => e.fmt(f),
            Self::Verify(e) => e.fmt(f),
            Self::Canonical(e) => e.fmt(f),
            Self::ColdCommitment => f.write_str("sparse witness generation needs a warm commitment"),
            Self::ProofBuild(a) => write!(f, "could not build a proof for {a}"),
            Self::MissingCode(h) => write!(f, "the pre-state holds no code {h}"),
            Self::OutcomeMismatch => f.write_str("sparse path differs from the canonical outcome"),
        }
    }
}

impl core::error::Error for SparseNodeError {}

/// The stateless verifier: authenticate, re-execute, derive the root.
pub fn verify_node_batch_sparse(
    spec: &ChainSpec,
    domain: B256,
    witness: &SparseBatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    block_hashes: BlockHashes,
) -> Result<NodeExecutionOutcome, SparseNodeError> {
    let hydrated = hydrate_sparse(spec, witness, context.number).map_err(SparseNodeError::Verify)?;
    let HydratedSparse {
        state,
        account_view,
        pre_leaves,
        pre_storage_roots,
    } = hydrated;
    let (db, pending) = run_sparse_block(spec, domain, state, witness.prev_state_root, context, body, block_hashes)
        .map_err(SparseNodeError::Execution)?;
    let root = derive_post_root(witness, &account_view, &pre_leaves, &pre_storage_roots, &db)
        .map_err(SparseNodeError::Verify)?;
    Ok(pending.finalize(spec, domain, root))
}

/// Failure of the sparse settlement statement.
#[derive(Debug)]
pub enum SparseStatementError {
    /// The witness or execution failed.
    Node(SparseNodeError),
    /// The statement rules failed, on the same terms as the complete witness.
    Statement(SettlementStatementV2Error),
}

impl core::fmt::Display for SparseStatementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Node(e) => e.fmt(f),
            Self::Statement(e) => write!(f, "{e:?}"),
        }
    }
}

impl core::error::Error for SparseStatementError {}

/// [`crate::proof_statement::execute_settlement_statement_v3`] over a sparse
/// witness. The statement bytes are those of the complete witness for the same block.
pub fn execute_settlement_statement_v3_sparse(
    spec: &ChainSpec,
    domain: B256,
    witness: &SparseBatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    settlement: SettlementContextV2,
    block_hashes: BlockHashes,
) -> Result<SettlementStatementV3, SparseStatementError> {
    let outcome =
        verify_node_batch_sparse(spec, domain, witness, context, body, block_hashes).map_err(SparseStatementError::Node)?;
    if let Some(rule) = spec.block_derivation {
        if rule.timestamp(outcome.parent_timestamp, settlement.l1_slot) != Some(context.timestamp)
            || context.prevrandao != rule.prevrandao
        {
            return Err(SparseStatementError::Statement(SettlementStatementV2Error::BlockDerivation));
        }
    }
    let configuration = configuration_commitment(spec).map_err(|error| {
        SparseStatementError::Node(SparseNodeError::Execution(NodeExecutionError::Execution(
            BlockExecutionError::InvalidChainSpec(error),
        )))
    })?;
    let withdrawals = outcome
        .withdrawals
        .as_ref()
        .map(|summary| summary.commitment)
        .ok_or(SparseStatementError::Statement(SettlementStatementV2Error::Withdrawals))?;
    SettlementStatementV3::from_executed(configuration, &outcome.header, body, settlement, withdrawals)
        .map_err(SparseStatementError::Statement)
}

/// The host's recording database: every read that reaches the pre-state.
struct RecordingDb<'a> {
    inner: &'a InMemoryDB,
    block_info: Address,
    accounts: RefCell<BTreeSet<Address>>,
    slots: RefCell<BTreeMap<Address, BTreeSet<U256>>>,
    codes: RefCell<BTreeSet<B256>>,
}

/// The pre-state code of `hash`: from the contract cache, or from an account that
/// holds it inline.
fn pre_state_code(db: &InMemoryDB, hash: B256) -> Option<Bytecode> {
    db.cache.contracts.get(&hash).cloned().or_else(|| {
        db.cache
            .accounts
            .values()
            .find(|account| account.info.code_hash == hash)
            .and_then(|account| account.info.code.clone())
    })
}

impl RecordingDb<'_> {
    fn record_slot(&self, address: Address, slot: U256) {
        self.slots.borrow_mut().entry(address).or_default().insert(slot);
    }
}

impl DatabaseRef for RecordingDb<'_> {
    type Error = <InMemoryDB as DatabaseRef>::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.accounts.borrow_mut().insert(address);
        // Without its code, as the guest hydrates it, so that every code load reaches
        // `code_by_hash_ref` and is recorded.
        Ok(self.inner.basic_ref(address)?.map(|mut info| {
            info.code = None;
            info
        }))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.codes.borrow_mut().insert(code_hash);
        match pre_state_code(self.inner, code_hash) {
            Some(code) => Ok(code),
            None => self.inner.code_by_hash_ref(code_hash),
        }
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.accounts.borrow_mut().insert(address);
        self.record_slot(address, index);
        self.inner.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let slot = block_hash_slot(number);
        self.accounts.borrow_mut().insert(self.block_info);
        self.record_slot(self.block_info, slot);
        Ok(B256::from(self.inner.storage_ref(self.block_info, slot)?))
    }
}

/// Generate a sparse witness and accept it only if the stateless verifier reproduces
/// the outcome of the independent canonical path. The pre-state is not cloned; the
/// canonical path costs what witness generation costs today.
pub fn generate_sparse_node_witness(
    pre: &L2State,
    spec: &ChainSpec,
    domain: B256,
    context: &BlockContext,
    body: &NodeBodyV2,
    block_hashes: BlockHashes,
) -> Result<(SparseBatchWitness, NodeExecutionOutcome), SparseNodeError> {
    let (_, canonical) = generate_node_batch_witness(pre, spec, domain, context, body).map_err(SparseNodeError::Canonical)?;
    let trie = pre.warm_commitment().ok_or(SparseNodeError::ColdCommitment)?;
    let previous_root = pre.state_root();

    let recording = RecordingDb {
        inner: pre.db(),
        block_info: spec.block_info,
        accounts: RefCell::new(BTreeSet::new()),
        slots: RefCell::new(BTreeMap::new()),
        codes: RefCell::new(BTreeSet::new()),
    };
    let (db, _) = run_sparse_block(spec, domain, CacheDB::new(recording), previous_root, context, body, block_hashes)
        .map_err(SparseNodeError::Execution)?;

    let mut addresses: BTreeSet<Address> = db.cache.accounts.keys().copied().collect();
    addresses.extend(db.db.accounts.borrow().iter().copied());
    let slots = db.db.slots.borrow();

    let mut pre_accounts = Vec::new();
    let mut absent_accounts = Vec::new();
    let mut targets: BTreeSet<Nibbles> = BTreeSet::new();
    let mut restructured: Vec<Nibbles> = Vec::new();
    for address in &addresses {
        let base = pre.db().cache.accounts.get(address).filter(|account| account_exists(account));
        let overlay = db.cache.accounts.get(address);
        let exists_after = match overlay {
            Some(entry) => entry.account_state != AccountState::NotExisting && info_exists(&entry.info),
            None => base.is_some(),
        };
        let key = account_key(address);
        targets.insert(key);
        if base.is_some() != exists_after {
            restructured.push(key);
        }
        let Some(account) = base else {
            absent_accounts.push(*address);
            continue;
        };
        let mut storage_targets: BTreeSet<Nibbles> = BTreeSet::new();
        if let Some(read) = slots.get(address) {
            storage_targets.extend(read.iter().map(storage_key));
        }
        if let Some(entry) = overlay {
            for (slot, value) in entry.storage.iter() {
                let slot_path = storage_key(slot);
                storage_targets.insert(slot_path);
                // A deletion can collapse a branch onto a sibling, which the proof
                // must then expose so its compact path can be merged.
                if value.is_zero() && account.storage.get(slot).is_some_and(|old| !old.is_zero()) {
                    let (before, after) = trie.storage_neighbours(address, &slot_path);
                    storage_targets.extend(before);
                    storage_targets.extend(after);
                }
            }
        }
        let storage_root = trie
            .storage_root_cached(address)
            .ok_or(SparseNodeError::ProofBuild(*address))?;
        let storage_proof = trie
            .storage_proof(address, storage_targets)
            .ok_or(SparseNodeError::ProofBuild(*address))?;
        let code_hash = if account.info.code_hash == B256::ZERO {
            KECCAK_EMPTY
        } else {
            account.info.code_hash
        };
        pre_accounts.push(SparseWitnessAccount {
            address: *address,
            balance: account.info.balance,
            nonce: account.info.nonce,
            code_hash,
            storage_root,
            storage_proof,
        });
    }
    for key in &restructured {
        let (before, after) = trie.neighbours(key);
        targets.extend(before);
        targets.extend(after);
    }
    let proof = trie
        .proof(targets.iter().copied())
        .ok_or(SparseNodeError::ColdCommitment)?;
    // Only the code the block loaded, in hash order (`codes` is a sorted set).
    let mut codes = Vec::new();
    for hash in db.db.codes.borrow().iter() {
        if *hash == KECCAK_EMPTY || *hash == B256::ZERO {
            continue;
        }
        let code = pre_state_code(pre.db(), *hash).ok_or(SparseNodeError::MissingCode(*hash))?;
        codes.push(code.original_bytes());
    }

    let witness = SparseBatchWitness {
        prev_state_root: previous_root,
        new_state_root: canonical.header.state_root,
        proof,
        pre_accounts,
        absent_accounts,
        codes,
    };
    let verified = verify_node_batch_sparse(spec, domain, &witness, context, body, block_hashes)?;
    if verified.header != canonical.header
        || verified.receipts != canonical.receipts
        || verified.withdrawals != canonical.withdrawals
        || verified.transactions.len() != canonical.transactions.len()
        || !verified.transactions.iter().zip(&canonical.transactions).all(|(a, b)| {
            a.success == b.success
                && a.gas_used == b.gas_used
                && a.created_address == b.created_address
                && a.burned_wei == b.burned_wei
                && a.result == b.result
        })
    {
        return Err(SparseNodeError::OutcomeMismatch);
    }
    Ok((witness, canonical))
}

/// What a witness holds, for reports. The guest does not use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseWitnessSize {
    /// Accounts hydrated.
    pub accounts: usize,
    /// Account proof nodes.
    pub account_nodes: usize,
    /// Storage proof nodes over all accounts.
    pub storage_nodes: usize,
    /// Bytes of all proof nodes.
    pub node_bytes: usize,
}

impl SparseBatchWitness {
    /// Count the witness's parts.
    pub fn size(&self) -> SparseWitnessSize {
        let storage = self.pre_accounts.iter().flat_map(|account| account.storage_proof.values());
        SparseWitnessSize {
            accounts: self.pre_accounts.len(),
            account_nodes: self.proof.len(),
            storage_nodes: self.pre_accounts.iter().map(|account| account.storage_proof.len()).sum(),
            node_bytes: self.proof.values().chain(storage).map(|node| node.len()).sum(),
        }
    }
}

/// Benchmark and test contract. Calldata is three words: `op`, `start`, `count`.
/// For each slot `i` in `start..start + count`: op 0 writes `i + 1`, op 1 reads,
/// op 2 writes `sload(i) + 1`, any other op writes zero. Synthetic only.
pub fn storage_ops_runtime() -> Vec<u8> {
    enum I {
        B(&'static [u8]),
        L(&'static str),
        J(&'static str),
    }
    use I::*;
    let program = [
        B(&[0x60, 0x20, 0x35, 0x60, 0x40, 0x35, 0x81, 0x01]), // i end
        L("loop"),
        B(&[0x80, 0x82, 0x10, 0x15]), // i end !(i < end)
        J("done"),
        B(&[0x57, 0x60, 0x00, 0x35]), // JUMPI; i end op
        B(&[0x80, 0x15]),
        J("write"),
        B(&[0x57, 0x80, 0x60, 0x01, 0x14]),
        J("read"),
        B(&[0x57, 0x80, 0x60, 0x02, 0x14]),
        J("update"),
        B(&[0x57, 0x50, 0x60, 0x00, 0x82, 0x55]), // POP; sstore(i, 0)
        J("next"),
        B(&[0x56]),
        L("write"),
        B(&[0x50, 0x81, 0x60, 0x01, 0x01, 0x82, 0x55]), // POP; sstore(i, i + 1)
        J("next"),
        B(&[0x56]),
        L("read"),
        B(&[0x50, 0x81, 0x54, 0x50]), // POP; pop(sload(i))
        J("next"),
        B(&[0x56]),
        L("update"),
        B(&[0x50, 0x81, 0x54, 0x60, 0x01, 0x01, 0x82, 0x55]), // POP; sstore(i, sload(i) + 1)
        L("next"),
        B(&[0x90, 0x60, 0x01, 0x01, 0x90]), // i + 1, end
        J("loop"),
        B(&[0x56]),
        L("done"),
        B(&[0x00]),
    ];
    let mut labels: BTreeMap<&str, usize> = BTreeMap::new();
    let mut offset = 0;
    for item in &program {
        match item {
            B(bytes) => offset += bytes.len(),
            L(name) => {
                labels.insert(name, offset);
                offset += 1;
            }
            J(_) => offset += 3,
        }
    }
    let mut code = Vec::with_capacity(offset);
    for item in &program {
        match item {
            B(bytes) => code.extend_from_slice(bytes),
            L(_) => code.push(0x5b),
            J(name) => {
                let target = labels[name];
                code.extend_from_slice(&[0x61, (target >> 8) as u8, target as u8]);
            }
        }
    }
    code
}

/// Initcode that deploys `runtime` unchanged.
pub fn deploy_code(runtime: &[u8]) -> Vec<u8> {
    let len = runtime.len();
    assert!(len <= 0xffff, "benchmark runtime fits PUSH2");
    let mut code = vec_prefix(len);
    code.extend_from_slice(runtime);
    code
}

fn vec_prefix(len: usize) -> Vec<u8> {
    let (high, low) = ((len >> 8) as u8, len as u8);
    // PUSH2 len; PUSH1 14; PUSH1 0; CODECOPY; PUSH2 len; PUSH1 0; RETURN
    let mut prefix = Vec::with_capacity(14);
    prefix.extend_from_slice(&[0x61, high, low, 0x60, 14, 0x60, 0x00, 0x39, 0x61, high, low, 0x60, 0x00, 0xf3]);
    prefix
}

/// Benchmark tamper support: the trie key of a slot.
pub fn slot_trie_key(slot: u64) -> Nibbles {
    storage_key(&U256::from(slot))
}

/// Benchmark tamper support: a storage leaf node holding `value` at path `rest`.
pub fn forged_storage_leaf(rest: Nibbles, value: U256) -> Bytes {
    alloy_rlp::encode(&alloy_trie::nodes::LeafNode::new(rest, alloy_rlp::encode(value))).into()
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod review;
#[cfg(test)]
mod review_a;
