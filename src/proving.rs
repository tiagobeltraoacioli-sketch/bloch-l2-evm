// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stateless proving path (RSP pattern): host-side batch witness generation and
//! the guest-side verification it must satisfy (BLOCH-L2-PROVER-SCOPE W1/P1).
//!
//! **SCAFFOLD, UNAUDITED.** The SP1 guest itself is still a stub
//! ([`crate::stubs::sp1_guest`]); this module provides the primitives it will
//! call and demonstrates their intended composition in [`verify_batch`].
//!
//! Soundness model — everything the guest consumes is either *authenticated
//! against `prev_state_root`* or *derived by the guest itself*:
//!
//! * the multiproof is opened with [`SparseTrieView::from_proof`], which checks
//!   the root node's hash and hash-links every descended node;
//! * every hydrated pre-account must be an **exposed leaf** of that view with
//!   exactly the hydrated RLP (inclusion), and every address the batch reads
//!   without finding must be **provably absent** (its position exposed and
//!   empty). Reads of anything else fail the execution — the guest database
//!   ([`WitnessBacking`]) errors instead of reading "empty";
//! * the change set is **derived by the guest** from the proven pre-leaves and
//!   its own re-execution, never taken from the host; the post-state root is
//!   [`SparseTrieView::apply`] over it, which refuses changes the proof does not
//!   cover.
//!
//! The host generator records the batch's full **read set** with a recording
//! overlay, emits it (existing accounts with their complete non-zero storage,
//! plus the absent addresses), builds the multiproof over that set, and finally
//! runs the exact guest procedure on its own witness: generation is
//! *correct-or-error* because the witness is accepted only if the guest
//! reproduces the host's outcome and post-state root.

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec::Vec};

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use revm::database::{AccountState, CacheDB, DbAccount};
use revm::database_interface::DBErrorMarker;
use revm::primitives::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};
use revm::DatabaseRef;

use crate::chainspec::ChainSpec;
use crate::executor::{deposits_hash, execute_block, run_block, BlockExecutionError, BlockInput, ExecutionOutcome, TxOutcome};
use crate::state::L2State;
use crate::stateroot::{account_leaves, account_leaves_of, compute_keccak_mpt_state_root, sorted_unique_keys, SparseTrieView, WitnessError};

/// Everything a guest needs to re-derive a batch's post-state root without the
/// full state. All vectors are sorted (canonical form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchWitness {
    /// keccak-MPT state root before the batch.
    pub prev_state_root: B256,
    /// keccak-MPT state root after the batch, as **claimed** by the host. The
    /// guest derives its own and compares.
    pub new_state_root: B256,
    /// Multiproof (trie-node path → RLP) against `prev_state_root`, exposing
    /// every pre-account, every absent address' position, every changed key
    /// and the key-order neighbours a restructure can touch.
    pub proof: BTreeMap<Nibbles, Bytes>,
    /// Every pre-state account the batch READS or WRITES that existed before it,
    /// keyed by address (the trie stores only `keccak(address)`), with its
    /// complete non-zero storage. Sorted by address.
    pub pre_accounts: Vec<WitnessAccount>,
    /// Every address the batch touches that did NOT exist in the pre-state
    /// (recipients created in-block, cold precompiles, ...). Each must be
    /// provably absent from `prev_state_root`. Sorted.
    pub absent_accounts: Vec<Address>,
}

/// A touched pre-state account (the fields a revm `AccountInfo` + its storage
/// need to round-trip to the guest). Storage is sorted by slot and holds only
/// non-zero values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessAccount {
    /// Account address (trie-key preimage).
    pub address: Address,
    /// Native balance (wei).
    pub balance: U256,
    /// Nonce.
    pub nonce: u64,
    /// Contract code (empty for EOAs).
    pub code: Vec<u8>,
    /// Non-zero storage slots, sorted by slot.
    pub storage: Vec<(U256, U256)>,
}

/// A read that the witness does not cover. Raised by [`WitnessBacking`] so the
/// guest execution fails instead of silently reading "empty".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessAccessError {
    /// An account neither hydrated nor proven absent was read.
    UnwitnessedAccount(Address),
    /// Code that no hydrated account carries was requested.
    UnwitnessedCode(B256),
    /// A storage slot of a non-hydrated account was read.
    UnwitnessedStorage(Address, U256),
}

impl core::fmt::Display for WitnessAccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WitnessAccessError::UnwitnessedAccount(a) => write!(f, "account {a} is not covered by the witness"),
            WitnessAccessError::UnwitnessedCode(h) => write!(f, "code {h} is not covered by the witness"),
            WitnessAccessError::UnwitnessedStorage(a, s) => {
                write!(f, "storage slot {s} of {a} is not covered by the witness")
            }
        }
    }
}

impl core::error::Error for WitnessAccessError {}
impl DBErrorMarker for WitnessAccessError {}

/// The guest's backing database: it knows nothing except which addresses were
/// **proven absent**. Hydrated accounts live entirely in the `CacheDB` layer
/// above it (marked `StorageCleared`, so their missing slots read as zero
/// without consulting this layer). Any other read is an error.
#[derive(Debug, Clone, Default)]
pub struct WitnessBacking {
    absent: BTreeSet<Address>,
}

impl DatabaseRef for WitnessBacking {
    type Error = WitnessAccessError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if self.absent.contains(&address) {
            Ok(None)
        } else {
            Err(WitnessAccessError::UnwitnessedAccount(address))
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Err(WitnessAccessError::UnwitnessedCode(code_hash))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if self.absent.contains(&address) {
            Ok(U256::ZERO)
        } else {
            Err(WitnessAccessError::UnwitnessedStorage(address, index))
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // Parity with the host's `EmptyDB` placeholder (no L2 block hashes are
        // supplied to the EVM yet — audit finding C16).
        Ok(keccak256(number.to_string().as_bytes()))
    }
}

/// The stateless guest's state: revm's `CacheDB` over a [`WitnessBacking`].
pub type GuestState = CacheDB<WitnessBacking>;

/// A verified, hydrated pre-state ready for re-execution.
#[derive(Debug)]
pub struct HydratedPreState {
    /// The guest state (hydrated accounts + proven-absent set).
    pub state: GuestState,
    /// The authenticated sparse view of the pre-state trie.
    pub view: SparseTrieView,
    /// The proven pre-leaves (`keccak(address)` path → RLP) of every hydrated
    /// account — the "before" side of the guest-derived change set.
    pub pre_leaves: BTreeMap<Nibbles, Vec<u8>>,
}

/// Why a witness is rejected by the guest procedure.
#[derive(Debug)]
pub enum VerifyError {
    /// The multiproof failed authentication or cannot cover the change set.
    Witness(WitnessError),
    /// An address appears twice in `pre_accounts` / `absent_accounts`.
    DuplicateAccount(Address),
    /// A `WitnessAccount` is EIP-161 empty (nonce 0, balance 0, no code); such
    /// an account is not in the trie and must be listed as absent instead.
    EmptyAccount(Address),
    /// A `WitnessAccount` carries a zero-valued or duplicate storage slot.
    InvalidStorage(Address, U256),
    /// A `WitnessAccount`'s code does not decode as bytecode.
    InvalidCode(Address),
    /// A hydrated account is not an exposed leaf of the proof with exactly the
    /// hydrated value.
    AccountNotProven(Address),
    /// An address listed as absent is not proven absent (it exists, or lies
    /// in an opaque subtree).
    AccountNotProvenAbsent(Address),
    /// Re-execution failed (including reads the witness does not cover).
    Execution(BlockExecutionError),
    /// The guest-derived post-state root differs from the host's claim.
    ClaimedRootMismatch {
        /// `BatchWitness::new_state_root`.
        claimed: B256,
        /// The root the guest derived.
        derived: B256,
    },
    /// Host self-check: the guest procedure did not reproduce the host's
    /// execution outcome.
    OutcomeMismatch,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Witness(e) => write!(f, "witness: {e}"),
            VerifyError::DuplicateAccount(a) => write!(f, "address {a} listed twice in the witness"),
            VerifyError::EmptyAccount(a) => write!(f, "pre-account {a} is EIP-161 empty (list it as absent)"),
            VerifyError::InvalidStorage(a, s) => write!(f, "pre-account {a}: invalid storage entry for slot {s}"),
            VerifyError::InvalidCode(a) => write!(f, "pre-account {a}: invalid bytecode"),
            VerifyError::AccountNotProven(a) => write!(f, "pre-account {a} does not open against prev_state_root"),
            VerifyError::AccountNotProvenAbsent(a) => write!(f, "address {a} is not proven absent from prev_state_root"),
            VerifyError::Execution(e) => write!(f, "re-execution failed: {e}"),
            VerifyError::ClaimedRootMismatch { claimed, derived } => {
                write!(f, "derived post-state root {derived} != claimed {claimed}")
            }
            VerifyError::OutcomeMismatch => write!(f, "guest outcome differs from the host outcome"),
        }
    }
}

impl core::error::Error for VerifyError {}

impl From<WitnessError> for VerifyError {
    fn from(e: WitnessError) -> Self {
        VerifyError::Witness(e)
    }
}

/// Guest step 3(a): open the multiproof against `prev_state_root`, hydrate a
/// guest state from the witness's pre-accounts and VERIFY each one is an
/// exposed leaf with exactly that value, and check that every listed absent
/// address is provably absent. Rejects duplicates, EIP-161-empty pre-accounts
/// and malformed storage/code. Nothing the host supplied is trusted by
/// structure.
pub fn hydrate_and_verify(witness: &BatchWitness) -> Result<HydratedPreState, VerifyError> {
    let view = SparseTrieView::from_proof(witness.prev_state_root, &witness.proof)?;

    let mut seen: BTreeSet<Address> = BTreeSet::new();
    for wa in &witness.pre_accounts {
        if !seen.insert(wa.address) {
            return Err(VerifyError::DuplicateAccount(wa.address));
        }
    }
    for a in &witness.absent_accounts {
        if !seen.insert(*a) {
            return Err(VerifyError::DuplicateAccount(*a));
        }
    }

    let mut state: GuestState = CacheDB::new(WitnessBacking { absent: witness.absent_accounts.iter().copied().collect() });
    let mut address_of_key: BTreeMap<B256, Address> = BTreeMap::new();
    for wa in &witness.pre_accounts {
        if wa.nonce == 0 && wa.balance.is_zero() && wa.code.is_empty() {
            return Err(VerifyError::EmptyAccount(wa.address));
        }
        let code = if wa.code.is_empty() {
            None
        } else {
            Some(Bytecode::new_raw_checked(wa.code.clone().into()).map_err(|_| VerifyError::InvalidCode(wa.address))?)
        };
        let code_hash = code.as_ref().map(|c| c.hash_slow()).unwrap_or(KECCAK_EMPTY);
        state.insert_account_info(
            wa.address,
            AccountInfo { balance: wa.balance, nonce: wa.nonce, code_hash, code, ..Default::default() },
        );
        let mut last_slot: Option<U256> = None;
        for (slot, val) in &wa.storage {
            if val.is_zero() || last_slot.is_some_and(|prev| prev >= *slot) {
                return Err(VerifyError::InvalidStorage(wa.address, *slot));
            }
            last_slot = Some(*slot);
            state
                .insert_account_storage(wa.address, *slot, *val)
                .map_err(|e| VerifyError::Execution(BlockExecutionError::Database { detail: e.to_string() }))?;
        }
        // The complete storage is known: missing slots are zero, never a lookup.
        if let Some(acc) = state.cache.accounts.get_mut(&wa.address) {
            acc.account_state = AccountState::StorageCleared;
        }
        address_of_key.insert(keccak256(wa.address), wa.address);
    }

    // Bind every hydrated leaf to prev_state_root: it must be exposed with
    // exactly the hydrated RLP.
    let mut pre_leaves: BTreeMap<Nibbles, Vec<u8>> = BTreeMap::new();
    for (key, value) in account_leaves_of(&state) {
        let address = address_of_key[&key];
        let path = Nibbles::unpack(key);
        if view.leaf(&path) != Some(&value) {
            return Err(VerifyError::AccountNotProven(address));
        }
        pre_leaves.insert(path, value);
    }
    if pre_leaves.len() != witness.pre_accounts.len() {
        // Cannot happen (empties were rejected), but never let an unproven
        // account through.
        return Err(VerifyError::AccountNotProven(witness.pre_accounts[0].address));
    }

    // Every absent address must be provably absent (exposed, empty position).
    for a in &witness.absent_accounts {
        match view.contains_key(&Nibbles::unpack(keccak256(a))) {
            Ok(false) => {}
            Ok(true) => return Err(VerifyError::AccountNotProvenAbsent(*a)),
            Err(e) => return Err(VerifyError::Witness(e)),
        }
    }

    Ok(HydratedPreState { state, view, pre_leaves })
}

/// What the guest attests to after verifying a batch.
#[derive(Debug)]
pub struct VerifiedBatch {
    /// The post-state root the guest derived from its own re-execution.
    pub new_state_root: B256,
    /// Commitment to the deposit list that was minted.
    pub deposits_hash: B256,
    /// Total gas used by the batch.
    pub gas_used: u64,
    /// Wei minted by deposits.
    pub minted_wei: U256,
    /// Wei routed to the `BaseFeeVault`.
    pub base_fee_routed_wei: U256,
    /// Wei routed to the `SequencerFeeVault`.
    pub priority_fee_routed_wei: U256,
    /// Per-transaction outcomes.
    pub tx_outcomes: Vec<TxOutcome>,
}

/// The complete guest procedure: hydrate and verify the pre-state, re-execute
/// `input` against it (any read outside the witness fails), derive the change
/// set from the proven pre-leaves and the re-executed post-leaves, and compute
/// the post-state root statelessly. Fails if the derived root differs from the
/// host's claim.
pub fn verify_batch(spec: &ChainSpec, witness: &BatchWitness, input: &BlockInput) -> Result<VerifiedBatch, VerifyError> {
    let hydrated = hydrate_and_verify(witness)?;
    let (db, run) = run_block(spec, hydrated.state, input).map_err(VerifyError::Execution)?;

    let post_leaves: BTreeMap<Nibbles, Vec<u8>> =
        account_leaves_of(&db).into_iter().map(|(k, v)| (Nibbles::unpack(k), v)).collect();
    let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
    for (k, v) in &post_leaves {
        if hydrated.pre_leaves.get(k) != Some(v) {
            changes.insert(*k, Some(v.clone()));
        }
    }
    for k in hydrated.pre_leaves.keys() {
        if !post_leaves.contains_key(k) {
            changes.insert(*k, None);
        }
    }
    let derived = hydrated.view.apply(&changes)?;
    if derived != witness.new_state_root {
        return Err(VerifyError::ClaimedRootMismatch { claimed: witness.new_state_root, derived });
    }
    Ok(VerifiedBatch {
        new_state_root: derived,
        deposits_hash: deposits_hash(&input.deposits),
        gas_used: run.gas_used,
        minted_wei: run.minted_wei,
        base_fee_routed_wei: run.base_fee_routed_wei,
        priority_fee_routed_wei: run.priority_fee_routed_wei,
        tx_outcomes: run.tx_outcomes,
    })
}

/// Why the host could not produce a witness.
#[derive(Debug)]
pub enum GenerateError {
    /// The batch itself does not execute.
    Execution(BlockExecutionError),
    /// The retained trie build did not reproduce `prev_state_root`.
    RetainedRootMismatch,
    /// The generated witness fails the guest procedure (the host refuses to
    /// hand out a witness the guest could not verify).
    SelfCheck(VerifyError),
}

impl core::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenerateError::Execution(e) => write!(f, "batch execution failed: {e}"),
            GenerateError::RetainedRootMismatch => write!(f, "witness build: retained root != prev_state_root"),
            GenerateError::SelfCheck(e) => write!(f, "witness self-check failed: {e}"),
        }
    }
}

impl core::error::Error for GenerateError {}

/// Whether a pre-state account is in the state trie (exists and is not EIP-161
/// empty).
fn in_trie(acc: &DbAccount) -> bool {
    acc.account_state != AccountState::NotExisting
        && !(acc.info.nonce == 0
            && acc.info.balance.is_zero()
            && (acc.info.code_hash == KECCAK_EMPTY || acc.info.code_hash == B256::ZERO))
}

/// Generate (and self-verify) the witness for executing `input` against `pre`.
///
/// 1. Executes the batch for real (atomic, on a copy) to obtain the post-state
///    and outcome.
/// 2. Re-runs it on a recording overlay of `pre` to capture the exact set of
///    accounts revm and the protocol accounting read or wrote; existing ones
///    become `pre_accounts` (with complete non-zero storage and code), the rest
///    `absent_accounts`.
/// 3. Builds a multiproof against `prev_state_root` targeting every read key,
///    every changed key and its key-order neighbours (so a leaf split or branch
///    collapse exposes the sibling it restructures).
/// 4. Runs [`verify_batch`] on the result and refuses to return a witness the
///    guest would reject or that does not reproduce the host's outcome.
pub fn generate_batch_witness(
    pre: &L2State,
    spec: &ChainSpec,
    input: BlockInput,
) -> Result<(BatchWitness, ExecutionOutcome), GenerateError> {
    let prev_state_root = compute_keccak_mpt_state_root(pre);

    // 1. The real run.
    let mut post = pre.clone();
    let outcome = execute_block(spec, &mut post, input.clone()).map_err(GenerateError::Execution)?;
    let new_state_root = outcome.state_root;

    // 2. The recording run: every account the batch loads lands in the overlay.
    let (probe, _) = run_block(spec, CacheDB::new(&pre.db), &input).map_err(GenerateError::Execution)?;
    let mut pre_accounts: Vec<WitnessAccount> = Vec::new();
    let mut absent_accounts: Vec<Address> = Vec::new();
    for addr in probe.cache.accounts.keys() {
        match pre.db.cache.accounts.get(addr).filter(|acc| in_trie(acc)) {
            Some(acc) => {
                let code_hash = if acc.info.code_hash == B256::ZERO { KECCAK_EMPTY } else { acc.info.code_hash };
                let code = if code_hash == KECCAK_EMPTY {
                    Vec::new()
                } else {
                    acc.info
                        .code
                        .as_ref()
                        .or_else(|| pre.db.cache.contracts.get(&code_hash))
                        .map(|c| c.original_bytes().to_vec())
                        .unwrap_or_default()
                };
                let mut storage: Vec<(U256, U256)> =
                    acc.storage.iter().filter(|(_, v)| !v.is_zero()).map(|(k, v)| (*k, *v)).collect();
                storage.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                pre_accounts.push(WitnessAccount { address: *addr, balance: acc.info.balance, nonce: acc.info.nonce, code, storage });
            }
            None => absent_accounts.push(*addr),
        }
    }
    pre_accounts.sort_unstable_by(|a, b| a.address.cmp(&b.address));
    absent_accounts.sort_unstable();

    // 3. Proof targets: read set ∪ changed keys ∪ neighbours of changed keys.
    let pre_leaves: BTreeMap<B256, Vec<u8>> = account_leaves(pre).into_iter().collect();
    let post_leaves: BTreeMap<B256, Vec<u8>> = account_leaves(&post).into_iter().collect();
    let mut changed: BTreeSet<B256> = BTreeSet::new();
    for (k, v) in &post_leaves {
        if pre_leaves.get(k) != Some(v) {
            changed.insert(*k);
        }
    }
    for k in pre_leaves.keys() {
        if !post_leaves.contains_key(k) {
            changed.insert(*k);
        }
    }
    let all_keys = sorted_unique_keys(pre_leaves.keys().chain(post_leaves.keys()).copied());
    let mut targets: BTreeSet<Nibbles> = changed.iter().map(Nibbles::unpack).collect();
    for (i, k) in all_keys.iter().enumerate() {
        if changed.contains(k) {
            if i > 0 {
                targets.insert(Nibbles::unpack(all_keys[i - 1]));
            }
            if i + 1 < all_keys.len() {
                targets.insert(Nibbles::unpack(all_keys[i + 1]));
            }
        }
    }
    for wa in &pre_accounts {
        targets.insert(Nibbles::unpack(keccak256(wa.address)));
    }
    for a in &absent_accounts {
        targets.insert(Nibbles::unpack(keccak256(a)));
    }

    let mut leaves: Vec<(B256, Vec<u8>)> = pre_leaves.into_iter().collect();
    leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets));
    for (k, v) in &leaves {
        hb.add_leaf(Nibbles::unpack(k), v);
    }
    if hb.root() != prev_state_root {
        return Err(GenerateError::RetainedRootMismatch);
    }
    let proof: BTreeMap<Nibbles, Bytes> = hb.take_proof_nodes().into_nodes_sorted().into_iter().collect();

    let witness = BatchWitness { prev_state_root, new_state_root, proof, pre_accounts, absent_accounts };

    // 4. Self-check: the guest procedure must accept the witness and reproduce
    //    the host's outcome exactly.
    let verified = verify_batch(spec, &witness, &input).map_err(GenerateError::SelfCheck)?;
    let same_outcome = verified.gas_used == outcome.gas_used
        && verified.minted_wei == outcome.minted_wei
        && verified.base_fee_routed_wei == outcome.base_fee_routed_wei
        && verified.priority_fee_routed_wei == outcome.priority_fee_routed_wei
        && verified.tx_outcomes.len() == outcome.tx_outcomes.len()
        && verified
            .tx_outcomes
            .iter()
            .zip(&outcome.tx_outcomes)
            .all(|(g, h)| g.success == h.success && g.gas_used == h.gas_used && g.result == h.result);
    if !same_outcome {
        return Err(GenerateError::SelfCheck(VerifyError::OutcomeMismatch));
    }

    Ok((witness, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::BlockContext;
    use crate::scale::{sats_to_wei, SATS_PER_BLCH};
    use crate::state::{DepositMint, DepositProvenance};
    use alloy_primitives::{address, bytes, Address, TxKind};
    use core::sync::atomic::{AtomicU32, Ordering};
    use revm::context::TxEnv;

    static NEXT_HEIGHT: AtomicU32 = AtomicU32::new(1);

    fn deposit(to: Address, sats: u64) -> DepositMint {
        DepositMint {
            recipient: to,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: NEXT_HEIGHT.fetch_add(1, Ordering::Relaxed) as u64,
                l1_tx_index: 0,
                l1_txid: [0u8; 32],
                l1_vout: 0,
                l1_sats: sats,
            },
        }
    }

    fn addr(i: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = i;
        Address::from(b)
    }

    /// Pre-state with `n` funded accounts 0x..01 ..= 0x..n (5 BLCH each).
    fn funded_pre_state(spec: &ChainSpec, n: u8) -> L2State {
        let mut pre = L2State::new();
        execute_block(
            spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 0, ..Default::default() },
                deposits: (1..=n).map(|i| deposit(addr(i), 5 * SATS_PER_BLCH)).collect(),
                txs: vec![],
            },
        )
        .unwrap();
        pre
    }

    fn tx(spec: &ChainSpec, from: Address, kind: TxKind, value: U256, data: Bytes, nonce: u64, gas_limit: u64) -> TxEnv {
        TxEnv::builder()
            .caller(from)
            .kind(kind)
            .value(value)
            .data(data)
            .gas_limit(gas_limit)
            .max_fee_per_gas(spec.initial_base_fee as u128 + 1_000_000_000)
            .gas_priority_fee(Some(1_000_000_000))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap()
    }

    fn transfer_batch(spec: &ChainSpec, from: Address, to: Address) -> BlockInput {
        BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(spec, from, TxKind::Call(to), sats_to_wei(SATS_PER_BLCH), Bytes::new(), 0, 21_000)],
        }
    }

    /// End-to-end host witness generation for a REAL transfer batch: the guest
    /// procedure reproduces the post-state root from the witness alone.
    #[test]
    fn host_generates_self_verifying_witness_for_a_transfer_batch() {
        let spec = ChainSpec::testnet();
        let pre = funded_pre_state(&spec, 8);
        let alice = addr(1);
        let bob = address!("00000000000000000000000000000000000000bb"); // a NEW recipient (insert)
        let batch = transfer_batch(&spec, alice, bob);

        let (witness, outcome) = generate_batch_witness(&pre, &spec, batch.clone()).expect("witness generates and self-verifies");
        assert!(outcome.tx_outcomes[0].success);
        assert_ne!(witness.new_state_root, witness.prev_state_root);

        // The witness is sparse: only Alice pre-existed among the touched
        // accounts; Bob and the two vaults are absent (created in-block).
        assert_eq!(witness.pre_accounts.iter().map(|a| a.address).collect::<Vec<_>>(), vec![alice]);
        assert_eq!(witness.absent_accounts.len(), 3);
        assert!(witness.absent_accounts.contains(&bob));
        assert!(witness.absent_accounts.contains(&spec.base_fee_vault));
        assert!(witness.absent_accounts.contains(&spec.sequencer_fee_vault));

        // The full guest procedure agrees with the full rebuild.
        let mut full = pre.clone();
        execute_block(&spec, &mut full, batch.clone()).unwrap();
        let verified = verify_batch(&spec, &witness, &batch).expect("guest verifies");
        assert_eq!(verified.new_state_root, compute_keccak_mpt_state_root(&full));
        assert_eq!(verified.new_state_root, witness.new_state_root);
        assert_eq!(verified.tx_outcomes[0].gas_used, outcome.tx_outcomes[0].gas_used);
        assert_eq!(verified.deposits_hash, outcome.deposits_hash);
    }

    /// Tampering with the pre-state, the proof, the absent set or the claimed
    /// root is rejected by the guest.
    #[test]
    fn guest_rejects_tampered_witnesses() {
        let spec = ChainSpec::testnet();
        let pre = funded_pre_state(&spec, 8);
        let alice = addr(1);
        let bob = addr(7); // an EXISTING recipient
        let batch = transfer_batch(&spec, alice, bob);
        let (w, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        assert_eq!(w.pre_accounts.len(), 2, "sender and recipient pre-exist");
        verify_batch(&spec, &w, &batch).expect("honest witness verifies");

        // (a) A tampered pre-account balance does not open.
        let mut bad = w.clone();
        bad.pre_accounts[0].balance += U256::from(1u64);
        assert!(matches!(hydrate_and_verify(&bad), Err(VerifyError::AccountNotProven(_))));

        // (b) Omitting an existing, touched account: it is neither hydrated nor
        //     proven absent, so the guest's read fails instead of reading zero.
        let mut omitted = w.clone();
        omitted.pre_accounts.retain(|a| a.address != bob);
        match verify_batch(&spec, &omitted, &batch) {
            Err(VerifyError::Execution(BlockExecutionError::Evm { .. }))
            | Err(VerifyError::Execution(BlockExecutionError::Database { .. })) => {}
            other => panic!("omitted account must fail the guest read, got {other:?}"),
        }
        // Listing it as absent instead is caught: the proof proves it present.
        let mut lied = omitted.clone();
        lied.absent_accounts.push(bob);
        lied.absent_accounts.sort();
        assert!(matches!(hydrate_and_verify(&lied), Err(VerifyError::AccountNotProvenAbsent(a)) if a == bob));

        // (c) A wrong claimed root is rejected even though everything else is
        //     honest: the guest derives its own root.
        let mut claim = w.clone();
        claim.new_state_root = B256::repeat_byte(0x42);
        assert!(matches!(verify_batch(&spec, &claim, &batch), Err(VerifyError::ClaimedRootMismatch { .. })));

        // (d) An injected node at an opaque frontier path breaks authentication.
        let view = SparseTrieView::from_proof(w.prev_state_root, &w.proof).unwrap();
        if let Some((frontier_path, _)) = view.frontier().first().copied() {
            let mut injected = w.clone();
            let rest = Nibbles::from_nibbles(vec![0u8; 64 - frontier_path.len()]);
            let fake = alloy_trie::nodes::LeafNode::new(rest, vec![0xc0]);
            injected.proof.insert(frontier_path, alloy_rlp::encode(&fake).into());
            assert!(matches!(
                hydrate_and_verify(&injected),
                Err(VerifyError::Witness(WitnessError::UnanchoredNode { .. }))
            ));
        }

        // (e) Stripping the proof nodes under the recipient's subtree: the
        //     recipient can no longer be proven, so the witness is rejected.
        let bob_path = Nibbles::unpack(keccak256(bob));
        let mut stripped = w.clone();
        stripped.proof.retain(|p, _| p.is_empty() || !bob_path.starts_with(p));
        assert!(stripped.proof.len() < w.proof.len());
        assert!(hydrate_and_verify(&stripped).is_err());

        // (f) An EIP-161-empty pre-account with planted storage is rejected.
        let mut ghost = w.clone();
        ghost.pre_accounts.push(WitnessAccount {
            address: address!("00000000000000000000000000000000deadbeef"),
            balance: U256::ZERO,
            nonce: 0,
            code: vec![],
            storage: vec![(U256::from(1u64), U256::from(0xdead_u64))],
        });
        ghost.pre_accounts.sort_by(|a, b| a.address.cmp(&b.address));
        assert!(matches!(hydrate_and_verify(&ghost), Err(VerifyError::EmptyAccount(_))));

        // (g) Duplicate addresses are rejected.
        let mut dup = w.clone();
        dup.pre_accounts.push(dup.pre_accounts[0].clone());
        assert!(matches!(hydrate_and_verify(&dup), Err(VerifyError::DuplicateAccount(_))));

        // (h) An empty witness only opens the empty root.
        let empty = BatchWitness {
            prev_state_root: w.prev_state_root,
            new_state_root: w.new_state_root,
            proof: BTreeMap::new(),
            pre_accounts: vec![],
            absent_accounts: vec![],
        };
        assert!(matches!(
            hydrate_and_verify(&empty),
            Err(VerifyError::Witness(WitnessError::EmptyProofForNonEmptyRoot { .. }))
        ));
    }

    /// Read-only accounts (BALANCE target), contracts whose storage is merely
    /// read, and zero-slot reads are all in the witness, so the guest replays
    /// them exactly (C06/C07).
    #[test]
    fn witness_covers_read_only_accounts_and_contract_storage_reads() {
        let spec = ChainSpec::testnet();
        let mut pre = funded_pre_state(&spec, 60);
        let alice = addr(1);
        let d = addr(9); // read-only BALANCE target
        // Contract C: runtime  PUSH1 0 SLOAD  ADDRESS-independent BALANCE(D) store:
        //   runtime: 73<D> 31 60 00 55  60 00 54 00
        //   = PUSH20 D, BALANCE, PUSH1 0, SSTORE, PUSH1 0, SLOAD, STOP
        let mut runtime = vec![0x73u8];
        runtime.extend_from_slice(d.as_slice());
        runtime.extend_from_slice(&[0x31, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54, 0x00]);
        // initcode: PUSH<len> runtime; PUSH1 0; MSTORE-free CODECOPY variant:
        //   PUSH1 len PUSH1 offset PUSH1 0 CODECOPY PUSH1 len PUSH1 0 RETURN <runtime>
        let len = runtime.len() as u8;
        let mut initcode = vec![0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3];
        initcode.extend_from_slice(&runtime);
        let deploy = BlockInput {
            context: BlockContext { number: 1, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(&spec, alice, TxKind::Create, U256::ZERO, initcode.into(), 0, 200_000)],
        };
        let out = execute_block(&spec, &mut pre, deploy).unwrap();
        let contract = out.tx_outcomes[0].created_address.expect("deployed");
        assert!(out.tx_outcomes[0].success);

        // Batch: call C (zero value). C reads D's balance (read-only account),
        // stores it, then SLOADs slot 0 back.
        let batch = BlockInput {
            context: BlockContext { number: 2, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(&spec, alice, TxKind::Call(contract), U256::ZERO, Bytes::new(), 1, 100_000)],
        };
        let (w, outcome) = generate_batch_witness(&pre, &spec, batch.clone()).expect("generates");
        assert!(outcome.tx_outcomes[0].success);
        let addrs: Vec<Address> = w.pre_accounts.iter().map(|a| a.address).collect();
        assert!(addrs.contains(&d), "read-only BALANCE target is in the witness");
        assert!(addrs.contains(&contract), "called contract is in the witness");
        assert!(addrs.contains(&alice));
        let verified = verify_batch(&spec, &w, &batch).expect("guest verifies");
        let mut full = pre.clone();
        execute_block(&spec, &mut full, batch.clone()).unwrap();
        assert_eq!(verified.new_state_root, compute_keccak_mpt_state_root(&full));
        assert_eq!(full.db.cache.accounts[&contract].storage[&U256::ZERO], sats_to_wei(5 * SATS_PER_BLCH));

        // A second batch that only SLOADs the (now non-zero) slot: the contract
        // is read-only again and still covered.
        let mut pre2 = full.clone();
        let out2 = execute_block(
            &spec,
            &mut pre2,
            BlockInput {
                context: BlockContext { number: 3, ..Default::default() },
                deposits: vec![],
                txs: vec![tx(&spec, alice, TxKind::Call(contract), U256::ZERO, Bytes::new(), 2, 100_000)],
            },
        );
        assert!(out2.is_ok());
        let batch3 = BlockInput {
            context: BlockContext { number: 3, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(&spec, alice, TxKind::Call(contract), U256::ZERO, Bytes::new(), 2, 100_000)],
        };
        let (w3, _) = generate_batch_witness(&full, &spec, batch3.clone()).expect("generates");
        assert!(w3.pre_accounts.iter().any(|a| a.address == contract && a.storage.len() == 1));
        verify_batch(&spec, &w3, &batch3).expect("guest verifies");
    }

    /// Deposits go through the committed ledger (total + cursor) inside the
    /// guest too: the ledger account is part of the witness, and a replay is
    /// rejected by the guest exactly as by the host.
    #[test]
    fn deposits_and_ledger_are_provable_and_replay_is_rejected_in_the_guest() {
        let spec = ChainSpec::testnet();
        let pre = funded_pre_state(&spec, 4);
        let dep = deposit(address!("00000000000000000000000000000000000000cc"), 3 * SATS_PER_BLCH);
        let batch = BlockInput { context: BlockContext { number: 1, ..Default::default() }, deposits: vec![dep], txs: vec![] };
        let (w, outcome) = generate_batch_witness(&pre, &spec, batch.clone()).expect("generates");
        assert!(w.pre_accounts.iter().any(|a| a.address == spec.supply_ledger), "ledger is hydrated");
        assert_eq!(outcome.minted_wei, sats_to_wei(3 * SATS_PER_BLCH));
        let verified = verify_batch(&spec, &w, &batch).expect("guest verifies");
        assert_eq!(verified.minted_wei, outcome.minted_wei);
        assert_eq!(verified.deposits_hash, deposits_hash(&[dep]));

        // Replaying the same deposit in the next batch: the host refuses to
        // execute it, and a guest handed the previous witness rejects it too.
        let mut post = pre.clone();
        execute_block(&spec, &mut post, batch.clone()).unwrap();
        let replay = BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![dep], txs: vec![] };
        assert!(matches!(generate_batch_witness(&post, &spec, replay.clone()), Err(GenerateError::Execution(_))));

        // First deposit ever on an empty chain: ledger absent, then created.
        let empty = L2State::new();
        let first = BlockInput { context: BlockContext { number: 0, ..Default::default() }, deposits: vec![deposit(addr(1), 1)], txs: vec![] };
        let (w0, _) = generate_batch_witness(&empty, &spec, first.clone()).expect("generates from empty");
        assert!(w0.proof.is_empty() || w0.proof.len() == 1);
        assert!(w0.absent_accounts.contains(&spec.supply_ledger));
        verify_batch(&spec, &w0, &first).expect("guest verifies genesis deposit");
    }

    #[test]
    fn witness_is_canonical_across_independent_generations() {
        let spec = ChainSpec::testnet();
        let mut pre = funded_pre_state(&spec, 14);
        // A contract with several storage slots so per-account storage order matters.
        let alice = addr(1);
        let store8: Bytes = bytes!("600160015560026002556003600355600460045560056005556006600655600760075560086008556000600055");
        let mut runtime = store8.to_vec();
        runtime.push(0x00);
        let len = runtime.len() as u8;
        let mut initcode = vec![0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3];
        initcode.extend_from_slice(&runtime);
        let out = execute_block(
            &spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 1, ..Default::default() },
                deposits: vec![],
                txs: vec![tx(&spec, alice, TxKind::Create, U256::ZERO, initcode.into(), 0, 400_000)],
            },
        )
        .unwrap();
        let contract = out.tx_outcomes[0].created_address.unwrap();
        assert!(out.tx_outcomes[0].success);
        // Populate the 8 slots BEFORE the batch under test, so they are
        // pre-state storage the witness must carry.
        let fill = execute_block(
            &spec,
            &mut pre,
            BlockInput {
                context: BlockContext { number: 2, ..Default::default() },
                deposits: vec![],
                txs: vec![tx(&spec, alice, TxKind::Call(contract), U256::ZERO, Bytes::new(), 1, 400_000)],
            },
        )
        .unwrap();
        assert!(fill.tx_outcomes[0].success);

        let batch = BlockInput {
            context: BlockContext { number: 3, ..Default::default() },
            deposits: vec![],
            txs: vec![tx(&spec, alice, TxKind::Call(contract), U256::ZERO, Bytes::new(), 2, 400_000)],
        };
        let (w1, _) = generate_batch_witness(&pre, &spec, batch.clone()).unwrap();
        let (w2, _) = generate_batch_witness(&pre.clone(), &spec, batch).unwrap();
        assert_eq!(w1.prev_state_root, w2.prev_state_root, "prev root");
        assert_eq!(w1.new_state_root, w2.new_state_root, "new root");
        assert_eq!(w1.absent_accounts, w2.absent_accounts, "absent set");
        assert_eq!(w1.proof.len(), w2.proof.len(), "proof size");
        assert_eq!(w1.proof, w2.proof, "proof nodes");
        for (a, b) in w1.pre_accounts.iter().zip(&w2.pre_accounts) {
            assert_eq!(a.address, b.address, "account order");
            assert_eq!((a.balance, a.nonce), (b.balance, b.nonce), "info of {}", a.address);
            assert_eq!(a.code, b.code, "code of {}", a.address);
            assert_eq!(a.storage, b.storage, "storage of {}", a.address);
        }
        assert_eq!(w1, w2, "identical inputs give byte-identical witnesses");
        let c = w1.pre_accounts.iter().find(|a| a.address == contract).unwrap();
        assert_eq!(c.storage.len(), 8);
        assert!(c.storage.windows(2).all(|p| p[0].0 < p[1].0), "storage sorted by slot");
        assert!(w1.pre_accounts.windows(2).all(|p| p[0].address < p[1].address), "accounts sorted");
    }
}
