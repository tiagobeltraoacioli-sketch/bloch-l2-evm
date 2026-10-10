// SPDX-License-Identifier: MIT OR Apache-2.0
//! L2 → L1 withdrawals: the `L2ToL1MessagePasser` outbox (milestone M4).
//!
//! **SCAFFOLD, UNAUDITED.** A withdrawal is an ordinary EVM call to the outbox
//! predeploy at [`L2_TO_L1_MESSAGE_PASSER`]:
//!
//! ```text
//! initiateWithdrawal(bytes32 l1Recipient) payable
//! ```
//!
//! `l1Recipient` is the native owner identity: the 32-byte script hash
//! (SHA3-256 of the owner's hybrid PQ public key) that native outputs lock to
//! (`TransferOutput::script_hash` in the native repository). The call value is
//! the withdrawn amount in wei; it must be a multiple of
//! [`crate::scale::ATOM_SCALE`] (`10^10`, one L1 sat), at least
//! [`MIN_WITHDRAWAL_SATS`] and below `2^64` sats.
//!
//! ## Two halves
//!
//! * **EVM half** ([`OUTBOX_CODE`], 132 bytes, hand-assembled — the repository
//!   has no Solidity toolchain, and the canonical EIP-4788 contract is installed
//!   the same way). It validates the call, assigns the next nonce (storage slot
//!   [`OUTBOX_NONCE_SLOT`]) and emits
//!   `WithdrawalInitiated(uint256 indexed nonce, bytes32 indexed l1Recipient,
//!   address sender, uint256 amountWei)`. It makes no external call (no
//!   reentrancy surface), has no `SELFDESTRUCT` and no other entry point: plain
//!   value transfers, unknown selectors and malformed calldata revert, so the
//!   value is refunded. The value stays in the outbox balance until the block
//!   ends.
//! * **Protocol half** ([`apply_withdrawals`], run by the executor when the
//!   block finishes, beside the EIP-6780 burn accounting): it reads the
//!   outbox's `WithdrawalInitiated` logs from the block's successful
//!   transactions in order, appends one leaf per log to an append-only,
//!   fixed-depth ([`WITHDRAWAL_TREE_DEPTH`]) keccak Merkle tree kept as an
//!   incremental frontier in the outbox's storage, writes the new root, then
//!   **removes exactly the withdrawn wei from the outbox balance** and adds it
//!   to the committed ledger ([`crate::state::SUPPLY_LEDGER_WITHDRAWN_SLOT`]).
//!   Afterwards `total_native_wei == minted - burned - withdrawn`: withdrawn
//!   value has left the L2 supply and is owed by the L1 escrow until claimed.
//!
//! Only code running *at* the outbox address can emit a log with that address
//! (`DELEGATECALL`/`CALLCODE` emit under the caller's address and are ignored;
//! `STATICCALL` cannot write the nonce), and a reverted frame discards both
//! its logs and its nonce increment, so the log list and the nonce counter
//! always agree; the executor re-checks that every block (consecutive nonces
//! ending at the post-block counter) and refuses the block otherwise.
//!
//! ## Commitment
//!
//! * leaf `i`: `keccak256("BLOCH:L2:WITHDRAW:1" || chain_id (u64 BE) ||
//!   nonce (u64 BE, = i) || l1_recipient (32) || sats (u64 BE))`
//!   ([`withdrawal_leaf`]);
//! * node: `keccak256(left || right)`; empty leaf: 32 zero bytes;
//! * root: the depth-32 tree over leaves `0..count`, padded with empty leaves
//!   (the eth2 deposit-contract construction without a length mix-in — the
//!   count is published separately). The empty tree's root is
//!   [`empty_withdrawal_root`], not zero.
//!
//! Settlement V3 publishes `(withdrawal_root, withdrawal_count)` of the
//! post-state ([`WithdrawalCommitment`]); the guest obtains them by executing
//! the block over the witness, whose MPT proofs cover the outbox account and
//! the storage slots read here. Shared vectors: `tests/fixtures/l2-withdrawal-v1`.
//!
//! Stray value that reaches the outbox without a call (a `SELFDESTRUCT`
//! beneficiary) is never burned: it stays locked in the outbox balance and
//! remains part of the L2 supply, so conservation still holds.

#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

use alloy_primitives::{address, b256, hex, keccak256, Address, Log, B256, U256};
use revm::database::CacheDB;
use revm::state::Bytecode;
use revm::{Database, DatabaseRef};

use crate::scale::{sats_to_wei, ATOM_SCALE};

/// The outbox predeploy, next to the supply ledger (`0x4200…0100`) and the
/// block-info record (`0x4200…0101`).
pub const L2_TO_L1_MESSAGE_PASSER: Address = address!("4200000000000000000000000000000000000102");

/// Domain tag of every withdrawal leaf.
pub const WITHDRAWAL_LEAF_DOMAIN: &[u8] = b"BLOCH:L2:WITHDRAW:1";

/// Fixed tree depth: at most `2^32` withdrawals per chain.
pub const WITHDRAWAL_TREE_DEPTH: usize = 32;

/// Smallest withdrawal: 0.01 BLCH, the native `MIN_L2_DEPOSIT_SAT`. Dust
/// leaves would only cost claim verification on L1.
pub const MIN_WITHDRAWAL_SATS: u64 = 1_000_000;

/// Outbox storage: the nonce of the next withdrawal (= leaves appended), written
/// by the EVM code.
pub const OUTBOX_NONCE_SLOT: U256 = U256::ZERO;
/// Outbox storage: the tree root after the last block that appended leaves,
/// written by the protocol (zero until the first withdrawal).
pub const OUTBOX_ROOT_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);
/// Outbox storage: frontier node `h` of the incremental tree lives in slot
/// `0x100 + h`, written by the protocol.
pub const OUTBOX_BRANCH_SLOT_BASE: u64 = 0x100;

/// `bytes4(keccak256("initiateWithdrawal(bytes32)"))`.
pub const INITIATE_WITHDRAWAL_SELECTOR: [u8; 4] = hex!("b769844a");

/// `keccak256("WithdrawalInitiated(uint256,bytes32,address,uint256)")`.
pub const WITHDRAWAL_INITIATED_TOPIC: B256 = b256!("ce2e3b3c3607f63db6a4e9c3d50ce0b37e10456bce8dcb9b5d9cecd1c28a69d2");

/// The outbox runtime code. Listing (stack shown top-right; every failed check
/// jumps to `0x7f`, which reverts with empty data):
///
/// ```text
/// 00 PUSH1 0x24 CALLDATASIZE EQ ISZERO PUSH1 0x7f JUMPI        calldata is exactly 36 bytes
/// 08 PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR PUSH4 b769844a EQ
///    ISZERO PUSH1 0x7f JUMPI                                    selector initiateWithdrawal(bytes32)
/// 18 PUSH1 4 CALLDATALOAD DUP1 ISZERO PUSH1 0x7f JUMPI          [r]  l1Recipient != 0
/// 20 PUSH5 10^10 CALLVALUE MOD PUSH1 0x7f JUMPI                 value % 10^10 == 0
/// 2b PUSH7 10^16 CALLVALUE LT PUSH1 0x7f JUMPI                  value >= MIN_WITHDRAWAL_SATS * 10^10
/// 38 PUSH5 10^10 CALLVALUE DIV PUSH1 0x40 SHR PUSH1 0x7f JUMPI  value / 10^10 < 2^64
/// 46 PUSH1 0 SLOAD DUP1 PUSH1 1 ADD PUSH1 0 SSTORE              [r n]  nonce++ (slot 0)
/// 50 CALLER PUSH1 0 MSTORE CALLVALUE PUSH1 0x20 MSTORE          data = (sender, value)
/// 58 PUSH32 topic PUSH1 0x40 PUSH1 0 LOG3 STOP                  topics = (topic, n, r)
/// 7f JUMPDEST PUSH1 0 DUP1 REVERT
/// ```
pub const OUTBOX_CODE: &[u8] = &hex!(
    "6024361415607f57"
    "60003560e01c63b769844a1415607f57"
    "6004358015607f57"
    "6402540be4003406607f57"
    "662386f26fc100003410607f57"
    "6402540be400340460401c607f57"
    "60005480600101600055"
    "3360005234602052"
    "7fce2e3b3c3607f63db6a4e9c3d50ce0b37e10456bce8dcb9b5d9cecd1c28a69d2"
    "60406000a300"
    "5b600080fd"
);

/// The outbox code as a revm [`Bytecode`].
pub fn outbox_bytecode() -> Bytecode {
    Bytecode::new_raw(alloy_primitives::Bytes::from_static(OUTBOX_CODE))
}

/// One withdrawal initiated on L2 (one tree leaf).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Withdrawal {
    /// Leaf index (the outbox nonce).
    pub nonce: u64,
    /// Native owner script hash credited by the L1 claim.
    pub l1_recipient: B256,
    /// Withdrawn amount in L1 sats (`value / 10^10`, exact).
    pub sats: u64,
    /// The L2 account that called the outbox (informational, not in the leaf).
    pub sender: Address,
}

impl Withdrawal {
    /// This withdrawal's tree leaf on chain `chain_id`.
    pub fn leaf(&self, chain_id: u64) -> B256 {
        withdrawal_leaf(chain_id, self.nonce, self.l1_recipient, self.sats)
    }

    /// The burned wei (`sats * 10^10`).
    pub fn wei(&self) -> U256 {
        sats_to_wei(self.sats)
    }

    /// Decode one outbox log. `None` for a log of another contract or event;
    /// `Some(Err)` for an outbox event that does not have the exact shape the
    /// outbox code emits (unreachable with [`OUTBOX_CODE`]).
    pub fn from_log(outbox: Address, log: &Log) -> Option<Result<Self, WithdrawalError>> {
        let topics = log.data.topics();
        if log.address != outbox || topics.first() != Some(&WITHDRAWAL_INITIATED_TOPIC) {
            return None;
        }
        Some(Self::decode(topics, &log.data.data))
    }

    fn decode(topics: &[B256], data: &[u8]) -> Result<Self, WithdrawalError> {
        if topics.len() != 3 || data.len() != 64 || data[..12] != [0u8; 12] {
            return Err(WithdrawalError::MalformedLog);
        }
        let nonce = u64::try_from(U256::from_be_bytes(topics[1].0)).map_err(|_| WithdrawalError::MalformedLog)?;
        let value = U256::from_be_slice(&data[32..64]);
        let (sats, remainder) = value.div_rem(U256::from(ATOM_SCALE));
        let sats = u64::try_from(sats).map_err(|_| WithdrawalError::MalformedLog)?;
        if !remainder.is_zero() || sats < MIN_WITHDRAWAL_SATS || topics[2].is_zero() {
            return Err(WithdrawalError::MalformedLog);
        }
        Ok(Self {
            nonce,
            l1_recipient: topics[2],
            sats,
            sender: Address::from_slice(&data[12..32]),
        })
    }
}

/// `keccak256("BLOCH:L2:WITHDRAW:1" || chain_id BE8 || nonce BE8 ||
/// l1_recipient || sats BE8)`.
pub fn withdrawal_leaf(chain_id: u64, nonce: u64, l1_recipient: B256, sats: u64) -> B256 {
    let mut preimage = [0u8; 19 + 8 + 8 + 32 + 8];
    preimage[..19].copy_from_slice(WITHDRAWAL_LEAF_DOMAIN);
    preimage[19..27].copy_from_slice(&chain_id.to_be_bytes());
    preimage[27..35].copy_from_slice(&nonce.to_be_bytes());
    preimage[35..67].copy_from_slice(l1_recipient.as_slice());
    preimage[67..75].copy_from_slice(&sats.to_be_bytes());
    keccak256(preimage)
}

fn node(left: B256, right: B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_slice());
    buf[32..].copy_from_slice(right.as_slice());
    keccak256(buf)
}

/// Roots of empty subtrees: `zero[0]` is the empty leaf (zero),
/// `zero[h + 1] = keccak256(zero[h] || zero[h])`.
pub fn zero_hashes() -> [B256; WITHDRAWAL_TREE_DEPTH + 1] {
    let mut zero = [B256::ZERO; WITHDRAWAL_TREE_DEPTH + 1];
    for h in 0..WITHDRAWAL_TREE_DEPTH {
        zero[h + 1] = node(zero[h], zero[h]);
    }
    zero
}

/// Root of the tree without leaves.
pub fn empty_withdrawal_root() -> B256 {
    zero_hashes()[WITHDRAWAL_TREE_DEPTH]
}

/// What settlement V3 publishes about the outbox after a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WithdrawalCommitment {
    /// Root of the tree over every withdrawal so far.
    pub root: B256,
    /// Number of withdrawals so far (the next nonce).
    pub count: u64,
}

impl WithdrawalCommitment {
    /// The commitment of a chain without withdrawals.
    pub fn empty() -> Self {
        Self {
            root: empty_withdrawal_root(),
            count: 0,
        }
    }
}

/// The outbox effect of one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalSummary {
    /// Post-block root and count.
    pub commitment: WithdrawalCommitment,
    /// Withdrawals initiated in this block, in nonce order.
    pub withdrawals: Vec<Withdrawal>,
    /// Wei removed from the L2 supply by this block (`Σ sats × 10^10`).
    pub withdrawn_wei: U256,
}

/// Why the protocol half refused a block. Unreachable with [`OUTBOX_CODE`];
/// a hard stop rather than a silently wrong tree or ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalError {
    /// An outbox `WithdrawalInitiated` log has an unexpected shape or value.
    MalformedLog,
    /// The logged nonces are not consecutive up to the outbox counter.
    NonceMismatch,
    /// The tree is full (`2^32` leaves).
    TreeFull,
    /// The outbox balance does not cover the withdrawn wei.
    Balance,
}

impl core::fmt::Display for WithdrawalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MalformedLog => "malformed outbox withdrawal log",
            Self::NonceMismatch => "outbox withdrawal nonces do not match the outbox counter",
            Self::TreeFull => "withdrawal tree is full",
            Self::Balance => "outbox balance does not cover the withdrawn value",
        })
    }
}

impl core::error::Error for WithdrawalError {}

/// The full tree over an explicit leaf list: tooling and tests (claim proofs,
/// shared vectors). Execution uses the O(depth) frontier in the outbox storage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WithdrawalTree {
    leaves: Vec<B256>,
}

impl WithdrawalTree {
    /// A tree over `leaves` (at most `2^32`).
    pub fn new(leaves: Vec<B256>) -> Result<Self, WithdrawalError> {
        if leaves.len() as u128 > 1u128 << WITHDRAWAL_TREE_DEPTH {
            return Err(WithdrawalError::TreeFull);
        }
        Ok(Self { leaves })
    }

    /// The leaves, in nonce order.
    pub fn leaves(&self) -> &[B256] {
        &self.leaves
    }

    /// Number of leaves.
    pub fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Root and count.
    pub fn commitment(&self) -> WithdrawalCommitment {
        WithdrawalCommitment {
            root: self.root(),
            count: self.count(),
        }
    }

    /// The root (only non-empty subtrees are hashed).
    pub fn root(&self) -> B256 {
        let zero = zero_hashes();
        let mut level = self.leaves.clone();
        for z in zero.iter().take(WITHDRAWAL_TREE_DEPTH) {
            if level.is_empty() {
                break;
            }
            level = level
                .chunks(2)
                .map(|pair| node(pair[0], pair.get(1).copied().unwrap_or(*z)))
                .collect();
        }
        level.first().copied().unwrap_or(zero[WITHDRAWAL_TREE_DEPTH])
    }

    /// The 32 siblings of leaf `index`, bottom-up, or `None` past the end.
    pub fn proof(&self, index: u64) -> Option<[B256; WITHDRAWAL_TREE_DEPTH]> {
        let mut position = usize::try_from(index).ok().filter(|i| *i < self.leaves.len())?;
        let zero = zero_hashes();
        let mut siblings = [B256::ZERO; WITHDRAWAL_TREE_DEPTH];
        let mut level = self.leaves.clone();
        for (h, sibling) in siblings.iter_mut().enumerate() {
            *sibling = level.get(position ^ 1).copied().unwrap_or(zero[h]);
            level = level
                .chunks(2)
                .map(|pair| node(pair[0], pair.get(1).copied().unwrap_or(zero[h])))
                .collect();
            position /= 2;
        }
        Some(siblings)
    }
}

/// Recompute the root from a leaf, its index and its 32 siblings (bottom-up).
pub fn withdrawal_root_from_proof(leaf: B256, index: u64, siblings: &[B256; WITHDRAWAL_TREE_DEPTH]) -> Option<B256> {
    if index >> WITHDRAWAL_TREE_DEPTH != 0 {
        return None;
    }
    let mut acc = leaf;
    for (h, sibling) in siblings.iter().enumerate() {
        acc = if (index >> h) & 1 == 1 {
            node(*sibling, acc)
        } else {
            node(acc, *sibling)
        };
    }
    Some(acc)
}

/// Whether `siblings` prove `leaf` at `index` under `root`. A valid proof does
/// not by itself show `index < count`; the claim checks that separately.
pub fn verify_withdrawal_proof(leaf: B256, index: u64, siblings: &[B256; WITHDRAWAL_TREE_DEPTH], root: B256) -> bool {
    withdrawal_root_from_proof(leaf, index, siblings) == Some(root)
}

fn branch_slot(height: usize) -> U256 {
    U256::from(OUTBOX_BRANCH_SLOT_BASE + height as u64)
}

/// Protocol half: append this block's withdrawals (decoded from `logs`, the
/// logs of the block's successful transactions in order) to the outbox tree,
/// write the new root, debit the withdrawn wei from the outbox balance and
/// return the post-block commitment. Every storage read goes through the
/// [`Database`] trait, so a recording or stateless (witness) backing observes
/// it — in particular the guest reads the post-block root and count from the
/// authenticated outbox storage even when the block has no withdrawal.
/// On `Err` the caller discards the block.
pub(crate) fn apply_withdrawals<'a, DB: DatabaseRef>(
    db: &mut CacheDB<DB>,
    outbox: Address,
    chain_id: u64,
    logs: impl IntoIterator<Item = &'a Log>,
) -> Result<WithdrawalSummary, ApplyWithdrawalError<DB::Error>> {
    let mut withdrawals = Vec::new();
    for log in logs {
        if let Some(withdrawal) = Withdrawal::from_log(outbox, log) {
            withdrawals.push(withdrawal.map_err(ApplyWithdrawalError::Withdrawal)?);
        }
    }
    db.basic(outbox).map_err(ApplyWithdrawalError::Db)?;
    let counter = db
        .storage(outbox, OUTBOX_NONCE_SLOT)
        .map_err(ApplyWithdrawalError::Db)?;
    let count = u64::try_from(counter).map_err(|_| ApplyWithdrawalError::Withdrawal(WithdrawalError::TreeFull))?;
    if count >> WITHDRAWAL_TREE_DEPTH != 0 {
        return Err(ApplyWithdrawalError::Withdrawal(WithdrawalError::TreeFull));
    }
    let first = count
        .checked_sub(withdrawals.len() as u64)
        .ok_or(ApplyWithdrawalError::Withdrawal(WithdrawalError::NonceMismatch))?;
    if withdrawals.iter().zip(first..).any(|(w, nonce)| w.nonce != nonce) {
        return Err(ApplyWithdrawalError::Withdrawal(WithdrawalError::NonceMismatch));
    }
    if withdrawals.is_empty() {
        let stored = B256::from(db.storage(outbox, OUTBOX_ROOT_SLOT).map_err(ApplyWithdrawalError::Db)?);
        let root = if count == 0 { empty_withdrawal_root() } else { stored };
        return Ok(WithdrawalSummary {
            commitment: WithdrawalCommitment { root, count },
            withdrawals,
            withdrawn_wei: U256::ZERO,
        });
    }

    // Incremental append over the stored frontier (eth2 deposit contract):
    // each leaf rewrites exactly one frontier slot.
    let zero = zero_hashes();
    let read = |db: &mut CacheDB<DB>, h: usize| {
        db.storage(outbox, branch_slot(h))
            .map(B256::from)
            .map_err(ApplyWithdrawalError::Db)
    };
    let mut size = first;
    for withdrawal in &withdrawals {
        let mut acc = withdrawal.leaf(chain_id);
        size += 1;
        let mut height = 0;
        while (size >> height) & 1 == 0 {
            acc = node(read(db, height)?, acc);
            height += 1;
        }
        db.insert_account_storage(outbox, branch_slot(height), acc.into())
            .map_err(ApplyWithdrawalError::Db)?;
    }
    let mut root = B256::ZERO;
    for (h, z) in zero.iter().enumerate().take(WITHDRAWAL_TREE_DEPTH) {
        root = if (count >> h) & 1 == 1 {
            node(read(db, h)?, root)
        } else {
            node(root, *z)
        };
    }
    db.insert_account_storage(outbox, OUTBOX_ROOT_SLOT, root.into())
        .map_err(ApplyWithdrawalError::Db)?;

    let withdrawn_wei = withdrawals.iter().fold(U256::ZERO, |sum, w| {
        sum.checked_add(w.wei()).expect("withdrawn wei cannot overflow U256")
    });
    let account = db.load_account(outbox).map_err(ApplyWithdrawalError::Db)?;
    account.info.balance = account
        .info
        .balance
        .checked_sub(withdrawn_wei)
        .ok_or(ApplyWithdrawalError::Withdrawal(WithdrawalError::Balance))?;
    Ok(WithdrawalSummary {
        commitment: WithdrawalCommitment { root, count },
        withdrawals,
        withdrawn_wei,
    })
}

/// [`apply_withdrawals`] failure: a protocol violation or a database error.
#[derive(Debug)]
pub(crate) enum ApplyWithdrawalError<E> {
    Withdrawal(WithdrawalError),
    Db(E),
}

impl<E: core::fmt::Debug> ApplyWithdrawalError<E> {
    pub(crate) fn into_block_error(self) -> crate::BlockExecutionError {
        match self {
            Self::Withdrawal(error) => crate::BlockExecutionError::Withdrawal(error),
            Self::Db(error) => crate::BlockExecutionError::Database {
                detail: format!("{error:?}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_code_matches_its_listing() {
        assert_eq!(OUTBOX_CODE.len(), 0x84);
        assert_eq!(
            INITIATE_WITHDRAWAL_SELECTOR,
            keccak256("initiateWithdrawal(bytes32)")[..4]
        );
        assert_eq!(
            WITHDRAWAL_INITIATED_TOPIC,
            keccak256("WithdrawalInitiated(uint256,bytes32,address,uint256)")
        );
        assert_eq!(&OUTBOX_CODE[0x0f..0x13], &INITIATE_WITHDRAWAL_SELECTOR);
        assert_eq!(&OUTBOX_CODE[0x59..0x79], WITHDRAWAL_INITIATED_TOPIC.as_slice());
        assert_eq!(&OUTBOX_CODE[0x21..0x26], &ATOM_SCALE.to_be_bytes()[3..]);
        assert_eq!(
            &OUTBOX_CODE[0x2c..0x33],
            &(MIN_WITHDRAWAL_SATS * ATOM_SCALE).to_be_bytes()[1..]
        );
        // Every jump goes to the single JUMPDEST.
        assert_eq!(OUTBOX_CODE[0x7f], 0x5b);
        for at in [0x05, 0x15, 0x1d, 0x28, 0x35, 0x43] {
            assert_eq!(&OUTBOX_CODE[at..at + 3], &[0x60, 0x7f, 0x57]);
        }
    }

    fn outbox_log(nonce: u64, recipient: B256, sats: u64) -> Log {
        let mut data = [0u8; 64];
        data[12..32].copy_from_slice(&[0x77; 20]);
        data[32..].copy_from_slice(&sats_to_wei(sats).to_be_bytes::<32>());
        Log::new_unchecked(
            L2_TO_L1_MESSAGE_PASSER,
            alloc::vec![WITHDRAWAL_INITIATED_TOPIC, B256::from(U256::from(nonce)), recipient],
            alloy_primitives::Bytes::copy_from_slice(&data),
        )
    }

    /// The storage frontier, appended in blocks of varying size, always has
    /// the root of the full tree over the same leaves.
    #[test]
    fn frontier_appends_match_the_full_tree() {
        use revm::database::EmptyDB;
        let mut db = CacheDB::new(EmptyDB::default());
        let mut leaves = Vec::new();
        let mut nonce = 0u64;
        for batch in [1usize, 1, 2, 3, 5, 8, 13, 0, 21, 34, 1] {
            let logs: Vec<Log> = (0..batch)
                .map(|k| {
                    outbox_log(
                        nonce + k as u64,
                        B256::repeat_byte(k as u8 + 1),
                        MIN_WITHDRAWAL_SATS + k as u64,
                    )
                })
                .collect();
            for log in &logs {
                let w = Withdrawal::from_log(L2_TO_L1_MESSAGE_PASSER, log).unwrap().unwrap();
                leaves.push(w.leaf(700_771));
            }
            nonce += batch as u64;
            // What the EVM half leaves behind: the counter and the value.
            db.insert_account_storage(L2_TO_L1_MESSAGE_PASSER, OUTBOX_NONCE_SLOT, U256::from(nonce))
                .unwrap();
            let value = logs
                .iter()
                .fold(U256::ZERO, |sum, log| sum + U256::from_be_slice(&log.data.data[32..]));
            db.load_account(L2_TO_L1_MESSAGE_PASSER).unwrap().info.balance += value;
            let summary = apply_withdrawals(&mut db, L2_TO_L1_MESSAGE_PASSER, 700_771, &logs).unwrap();
            let tree = WithdrawalTree::new(leaves.clone()).unwrap();
            assert_eq!(summary.commitment, tree.commitment());
            assert_eq!(summary.withdrawn_wei, value);
            assert_eq!(
                db.load_account(L2_TO_L1_MESSAGE_PASSER).unwrap().info.balance,
                U256::ZERO
            );
        }
        // A counter that disagrees with the logs is refused.
        db.insert_account_storage(L2_TO_L1_MESSAGE_PASSER, OUTBOX_NONCE_SLOT, U256::from(nonce + 2))
            .unwrap();
        let log = outbox_log(nonce, B256::repeat_byte(1), MIN_WITHDRAWAL_SATS);
        assert!(matches!(
            apply_withdrawals(&mut db, L2_TO_L1_MESSAGE_PASSER, 700_771, [&log]),
            Err(ApplyWithdrawalError::Withdrawal(WithdrawalError::NonceMismatch))
        ));
        // Logs of other contracts or events are not withdrawals.
        let mut other = log.clone();
        other.address = Address::repeat_byte(1);
        assert!(Withdrawal::from_log(L2_TO_L1_MESSAGE_PASSER, &other).is_none());
        // A malformed outbox event is refused, never skipped.
        let mut malformed = log.clone();
        malformed.data =
            alloy_primitives::LogData::new_unchecked(log.data.topics().to_vec(), alloy_primitives::Bytes::new());
        assert_eq!(
            Withdrawal::from_log(L2_TO_L1_MESSAGE_PASSER, &malformed),
            Some(Err(WithdrawalError::MalformedLog))
        );
        let unaligned = outbox_log(0, B256::repeat_byte(1), MIN_WITHDRAWAL_SATS);
        let mut data = unaligned.data.data.to_vec();
        data[63] ^= 1;
        let unaligned = Log::new_unchecked(L2_TO_L1_MESSAGE_PASSER, unaligned.data.topics().to_vec(), data.into());
        assert_eq!(
            Withdrawal::from_log(L2_TO_L1_MESSAGE_PASSER, &unaligned),
            Some(Err(WithdrawalError::MalformedLog))
        );
    }

    #[test]
    fn proofs_verify_and_bind_index_and_leaf() {
        let leaves: Vec<B256> = (0..5)
            .map(|i| withdrawal_leaf(700_771, i, B256::repeat_byte(9), 1_000_000 + i))
            .collect();
        let tree = WithdrawalTree::new(leaves.clone()).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i as u64).unwrap();
            assert!(verify_withdrawal_proof(*leaf, i as u64, &proof, tree.root()));
            assert!(!verify_withdrawal_proof(*leaf, i as u64 ^ 1, &proof, tree.root()));
            assert!(!verify_withdrawal_proof(
                B256::repeat_byte(1),
                i as u64,
                &proof,
                tree.root()
            ));
        }
        assert!(tree.proof(5).is_none());
        assert!(withdrawal_root_from_proof(leaves[0], 1 << 32, &[B256::ZERO; 32]).is_none());
        assert_eq!(WithdrawalTree::default().root(), empty_withdrawal_root());
    }
}
