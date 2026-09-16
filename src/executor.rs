// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block executor: UNMODIFIED revm at `SpecId::CANCUN` over [`L2State`].
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** This is the state-transition
//! core only: no consensus, no txpool, no RPC. Per BLOCH-L2-EVM-DESIGN §1:
//!
//! * the block header is validated against the **committed head record**
//!   (`BLOCK_INFO` system account): `number == head + 1`, non-decreasing
//!   timestamp, `base_fee == ChainSpec::next_base_fee(head)`; a chain's first
//!   block must carry `ChainSpec::initial_base_fee`;
//! * the parent block's hash — an [`L2Header`] hash over the committed record
//!   plus the pre-state root — is written into a 256-entry ring buffer in the
//!   same account, and `BLOCKHASH` is served from that ring (real, committed
//!   L2 block hashes, never a placeholder);
//! * the EIP-4788 system call runs at block start against the canonical
//!   beacon-roots predeploy, storing the block's **Bloch anchor root**
//!   ([`BlockContext::anchor_root`]) under the block timestamp;
//! * deposit mints (bridged BLCH only) are applied at block start, against the
//!   committed supply ledger (exact scaling, strictly increasing L1 position —
//!   the replay cursor — and the L1 cap);
//! * the EVM itself is unmodified revm at the pinned CANCUN hardfork;
//! * COINBASE / block beneficiary is the sequencer fee vault, so priority
//!   fees are paid there by revm's own (unmodified) beneficiary payment;
//! * the EIP-1559 basefee is NOT destroyed: the part of the effective gas
//!   price that revm actually charged up to the basefee is routed to the
//!   `BaseFeeVault` as protocol-level accounting between transactions
//!   (outside EVM opcode semantics — the OP-Stack precedent). The protocol
//!   never burns bridged BLCH; the wei the EVM itself destroys (EIP-6780
//!   `SELFDESTRUCT` to self in the creating transaction) is measured per
//!   transaction and accumulated in the committed ledger, so
//!   `total_native_wei == total_minted_wei - total_burned_wei` always holds;
//! * only EIP-155-protected transactions of types 0, 1 and 2 are accepted at
//!   CANCUN; type 3 (blob), every other type byte and `chain_id != spec` are
//!   rejected at this boundary.
//!
//! **Role and atomicity.** [`execute_block`] is the *verifier* state-transition
//! function: a block containing an invalid transaction is an invalid block
//! (Ethereum / OP-Stack semantics, and what a stateless guest must enforce).
//! Rejection is **non-destructive**: the whole block is validated, then applied
//! to a working copy, and the caller's state is replaced only on success — on
//! any `Err` it is byte-identical to the pre-block state, so a sequencer can
//! drop the offending transaction (identified by `tx_index`) and rebuild.
//! The authenticated incremental builder shares this kernel, staging each
//! candidate separately before accepting its effects into the working block.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use revm::context::result::{ExecutionResult, HaltReason, ResultAndState};
use revm::context::TxEnv;
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::context_interface::Transaction;
use revm::database::CacheDB;
use revm::handler::{ExecuteEvm, SystemCallCommitEvm};
use revm::state::{Account, EvmState};
use revm::{Context, Database, DatabaseCommit, DatabaseRef, MainBuilder, MainContext};

use crate::chainspec::{ChainSpec, ChainSpecError, BEACON_ROOTS_ADDRESS};

pub mod lifecycle;
use crate::state::{
    apply_deposit, beacon_roots_bytecode, block_hash_slot, ensure_system_account, ledger_add, DepositApplyError,
    DepositError, DepositMint, HeadRecord, L2State, BLOCK_HASH_HISTORY, BLOCK_INFO_ANCHOR_ROOT_SLOT,
    BLOCK_INFO_BASE_FEE_SLOT, BLOCK_INFO_DEPOSITS_HASH_SLOT, BLOCK_INFO_FLAG_SLOT, BLOCK_INFO_GAS_USED_SLOT,
    BLOCK_INFO_NUMBER_SLOT, BLOCK_INFO_PARENT_HASH_SLOT, BLOCK_INFO_PREVRANDAO_SLOT, BLOCK_INFO_TIMESTAMP_SLOT,
    SUPPLY_LEDGER_BURNED_SLOT,
};

/// Per-block environment chosen by the sequencer and **validated** by the
/// executor against the committed head record (number, timestamp, base fee).
/// `prevrandao` and `anchor_root` come from the (stubbed) anchor reader and are
/// committed in the block header but not derived here.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockContext {
    /// L2 block number (must be `head.number + 1`; any value for a chain's
    /// first block).
    pub number: u64,
    /// Sequencer timestamp (must not decrease; the drift bound against the
    /// Bloch anchor is the node's job).
    pub timestamp: u64,
    /// This block's EIP-1559 base fee per gas, in wei: must equal
    /// [`ChainSpec::next_base_fee`] of the head (or
    /// `ChainSpec::initial_base_fee` for the first block).
    pub base_fee_per_gas: u64,
    /// PREVRANDAO. In the full design this is
    /// `keccak256(parent_l2_block_hash ‖ bloch_anchor_block_hash)` and is
    /// documented as WEAK randomness, exactly as on every L2.
    pub prevrandao: B256,
    /// The 32-byte value the EIP-4788 system call stores for this block: the
    /// Bloch anchor block hash this L2 block is derived from (zero until the
    /// anchor reader exists).
    pub anchor_root: B256,
}

impl BlockContext {
    /// The rule-conforming context for the block after `state`'s head:
    /// `number + 1`, the head's timestamp (non-decreasing), the EIP-1559 base
    /// fee derived from the head, zero prevrandao / anchor root. Before any
    /// block: [`BlockContext::default`] (number 1, initial base fee). Reads the
    /// configured `spec.block_info` account. At `u64::MAX` the number saturates
    /// and execution rejects the exhausted chain. Callers override timestamp /
    /// randomness / anchor as needed.
    pub fn next(spec: &ChainSpec, state: &L2State) -> Self {
        match state.head_at(spec.block_info) {
            Some(h) => Self {
                number: h.number.saturating_add(1),
                timestamp: h.timestamp,
                base_fee_per_gas: spec.next_base_fee(h.base_fee_per_gas, h.gas_used),
                prevrandao: B256::ZERO,
                anchor_root: B256::ZERO,
            },
            None => Self {
                base_fee_per_gas: spec.initial_base_fee,
                ..Self::default()
            },
        }
    }
}

/// Everything the executor consumes for one block.
#[derive(Debug, Clone, Default)]
pub struct BlockInput {
    /// Block environment.
    pub context: BlockContext,
    /// Deposit system-transactions, applied (minted) at block start, before
    /// any user transaction — they cannot be dropped once anchored. They MUST
    /// be in strictly increasing canonical L1 position order
    /// ([`DepositMint::position`]), and all after the ledger's cursor. Each
    /// consumes `ChainSpec::deposit_gas` of the block's gas budget (no fee),
    /// so a block carries at most `ChainSpec::max_deposits_per_block`; the
    /// derivation layer carries the overflow into the following blocks.
    ///
    /// **Trust boundary:** the derivation layer must only hand over deposits
    /// that were really escrowed at the stated positions in finalized Bloch
    /// blocks; the STF enforces exact scaling, canonical order (hence one mint
    /// per escrow output, via the committed cursor) and the L1 cap, and
    /// commits the list via [`ExecutionOutcome::deposits_hash`].
    pub deposits: Vec<DepositMint>,
    /// User transactions in sequencer order. `TxEnv` is revm's transaction
    /// environment and its caller is TRUSTED at this low-level interface. Network
    /// and guest inputs must use [`crate::transactions::SignedBlockInput`] and
    /// the signed execution/verification entry points. A block with an invalid transaction is
    /// an invalid block (verifier semantics, see the module docs).
    pub txs: Vec<TxEnv>,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self {
            number: 1,
            timestamp: 0,
            base_fee_per_gas: ChainSpec::testnet().initial_base_fee,
            prevrandao: B256::ZERO,
            anchor_root: B256::ZERO,
        }
    }
}

/// The L2 block header this scaffold commits to. Its hash is the L2 block
/// hash (`BLOCKHASH`, parent linkage, anchoring). This header does not commit
/// transaction or receipt roots; `deposits_hash` commits the deposit list.
/// Adding those roots requires a versioned execution-domain change, including
/// the committed head record and its reconstruction, not just RPC fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Header {
    /// EIP-155 chain id (domain separation).
    pub chain_id: u64,
    /// Block number.
    pub number: u64,
    /// Block timestamp.
    pub timestamp: u64,
    /// EIP-1559 base fee per gas.
    pub base_fee_per_gas: u64,
    /// Gas used by the block.
    pub gas_used: u64,
    /// PREVRANDAO.
    pub prevrandao: B256,
    /// Bloch anchor root written by the EIP-4788 system call.
    pub anchor_root: B256,
    /// Hash of the parent L2 block (zero for a chain's first block).
    pub parent_hash: B256,
    /// Commitment to the block's deposit list ([`deposits_hash`]).
    pub deposits_hash: B256,
    /// keccak-MPT state root after the block.
    pub state_root: B256,
}

impl L2Header {
    /// The block hash: `keccak256` over the fixed-width concatenation of every
    /// field in declaration order (`u64`s big-endian).
    pub fn hash(&self) -> B256 {
        let mut buf = [0u8; 8 * 5 + 32 * 5];
        buf[0..8].copy_from_slice(&self.chain_id.to_be_bytes());
        buf[8..16].copy_from_slice(&self.number.to_be_bytes());
        buf[16..24].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[24..32].copy_from_slice(&self.base_fee_per_gas.to_be_bytes());
        buf[32..40].copy_from_slice(&self.gas_used.to_be_bytes());
        buf[40..72].copy_from_slice(self.prevrandao.as_slice());
        buf[72..104].copy_from_slice(self.anchor_root.as_slice());
        buf[104..136].copy_from_slice(self.parent_hash.as_slice());
        buf[136..168].copy_from_slice(self.deposits_hash.as_slice());
        buf[168..200].copy_from_slice(self.state_root.as_slice());
        keccak256(buf)
    }

    /// Rebuild the header of the head block recorded in state, given the root
    /// that record is committed in.
    pub fn from_head(chain_id: u64, head: &HeadRecord, state_root: B256) -> Self {
        Self {
            chain_id,
            number: head.number,
            timestamp: head.timestamp,
            base_fee_per_gas: head.base_fee_per_gas,
            gas_used: head.gas_used,
            prevrandao: head.prevrandao,
            anchor_root: head.anchor_root,
            parent_hash: head.parent_hash,
            deposits_hash: head.deposits_hash,
            state_root,
        }
    }
}

/// Outcome of one applied transaction.
#[derive(Debug, Clone)]
pub struct TxOutcome {
    /// Whether execution succeeded (revert/halt still consume gas and pay
    /// fees; they are valid, included transactions).
    pub success: bool,
    /// Gas actually used (post-refund), as revm reports it.
    pub gas_used: u64,
    /// For CREATE transactions, the deployed contract address.
    pub created_address: Option<Address>,
    /// Wei the EVM destroyed in this transaction (EIP-6780 self-destruct to
    /// self of an account created in the same transaction).
    pub burned_wei: U256,
    /// Raw revm execution result (logs, output, halt reason...).
    pub result: ExecutionResult<HaltReason>,
}

/// Outcome of executing one block against [`L2State`].
#[derive(Debug)]
pub struct ExecutionOutcome {
    /// The block number executed.
    pub block_number: u64,
    /// Total gas used by the block: `deposits × ChainSpec::deposit_gas` plus
    /// every transaction's gas (what the EIP-1559 rule sees).
    pub gas_used: u64,
    /// The base fee this block executed under.
    pub base_fee_per_gas: u64,
    /// Wei minted by deposits at block start.
    pub minted_wei: U256,
    /// Wei destroyed by the EVM in this block (EIP-6780), now recorded in the
    /// committed ledger.
    pub burned_wei: U256,
    /// Commitment to the block's deposit list (see [`deposits_hash`]).
    pub deposits_hash: B256,
    /// Wei routed to the `BaseFeeVault` (the basefee part of what revm
    /// charged, per tx). Never burned.
    pub base_fee_routed_wei: U256,
    /// Wei routed to the `SequencerFeeVault` (priority fee × gas, per tx,
    /// paid by unmodified revm to the block beneficiary).
    pub priority_fee_routed_wei: U256,
    /// Per-transaction outcomes, in block order.
    pub tx_outcomes: Vec<TxOutcome>,
    /// The keccak-256 hexary Merkle-Patricia state root over the post-execution
    /// account + storage tries (Ethereum-compatible; see [`crate::stateroot`]).
    pub state_root: B256,
    /// The block's header (committed as the next head record).
    pub header: L2Header,
    /// `header.hash()` — the L2 block hash.
    pub block_hash: B256,
}

/// Errors that abort block execution. The caller's [`L2State`] is left
/// **unchanged** on every variant.
#[derive(Debug)]
pub enum BlockExecutionError {
    /// A deposit mint violated the ledger rules (cursor, L1 cap).
    Deposit(DepositError),
    /// The block's deposits are not in strictly increasing L1 position order
    /// (a duplicate, or an out-of-order derivation).
    DepositsOutOfOrder {
        /// Index of the deposit that precedes the offending one.
        first_index: usize,
        /// Index of the deposit whose position is not after the previous one.
        second_index: usize,
    },
    /// `context.number` is not `head.number + 1`.
    InvalidBlockNumber {
        /// The required number.
        expected: u64,
        /// The supplied number.
        got: u64,
    },
    /// `context.timestamp` is below the head's timestamp.
    InvalidTimestamp {
        /// The head block's timestamp.
        parent: u64,
        /// The supplied timestamp.
        got: u64,
    },
    /// `context.base_fee_per_gas` is not the EIP-1559 value derived from the
    /// head (or the initial base fee for a chain's first block).
    InvalidBaseFee {
        /// The required base fee.
        expected: u64,
        /// The supplied base fee.
        got: u64,
    },
    /// A type-3 (EIP-4844 blob) transaction was submitted; the sequencer
    /// rejects blob transactions exactly as on OP-Stack L2s.
    BlobTxRejected {
        /// Index of the offending transaction within the block.
        tx_index: usize,
    },
    /// A transaction type outside [`SUPPORTED_TX_TYPES`] was submitted
    /// (e.g. type 4 before Prague, or the reserved deposit envelope 0x7E,
    /// which must never arrive as a user `TxEnv`).
    UnsupportedTxType {
        /// Index of the offending transaction within the block.
        tx_index: usize,
        /// The rejected type byte.
        tx_type: u8,
    },
    /// The `TxEnv`'s fields are inconsistent with its `tx_type` (a legacy /
    /// EIP-2930 env carrying a priority fee, an EIP-1559 env without one,
    /// legacy env carrying an access list, or any supported env carrying
    /// EIP-7702 authorizations).
    InconsistentTxEnv {
        /// Index of the offending transaction within the block.
        tx_index: usize,
    },
    /// The transaction is not EIP-155-protected for this chain
    /// (`chain_id != Some(spec.chain_id)`): unprotected legacy transactions
    /// and transactions for other chains are consensus-invalid here.
    ChainIdMismatch {
        /// Index of the offending transaction within the block.
        tx_index: usize,
        /// The transaction's chain id (`None` = pre-EIP-155).
        got: Option<u64>,
    },
    /// A single transaction's gas limit exceeds the block gas limit.
    TxGasLimitExceedsBlock {
        /// Index of the offending transaction within the block.
        tx_index: usize,
    },
    /// Including this transaction would exceed the block gas limit.
    BlockGasLimitExceeded {
        /// Index of the offending transaction within the block.
        tx_index: usize,
    },
    /// revm rejected or failed the transaction pre-execution (invalid nonce,
    /// insufficient max-fee balance, ...). Debug-printed revm error, since the
    /// concrete error type is generic over the DB.
    Evm {
        /// Index of the offending transaction within the block.
        tx_index: usize,
        /// Debug rendering of the revm error.
        detail: String,
    },
    /// The EIP-4788 system call failed.
    SystemCall {
        /// Debug rendering of the failure.
        detail: String,
    },
    /// The transaction's balance accounting does not reconcile: the touched
    /// accounts lost less than the basefee revm must have collected. Never
    /// reachable with the supported transaction types; a hard stop rather than
    /// a silently wrong ledger.
    Conservation {
        /// Index of the offending transaction within the block.
        tx_index: usize,
        /// Net wei lost by the touched accounts.
        lost_wei: U256,
        /// Basefee wei revm must have collected.
        base_fee_wei: U256,
    },
    /// The backing database failed while applying protocol-level accounting
    /// (deposits, fee routing) — e.g. a stateless guest touching an account
    /// its witness does not cover.
    Database {
        /// Debug rendering of the database error.
        detail: String,
    },
    /// The [`ChainSpec`] itself is invalid (see [`ChainSpec::validate`]); no
    /// block executes under it.
    InvalidChainSpec(ChainSpecError),
    /// The block's deposits alone exceed the block gas budget
    /// (`deposits × deposit_gas > gas_limit`).
    DepositGasExceedsBlock {
        /// Number of deposits in the block.
        deposits: usize,
        /// The most this chain admits per block.
        max_deposits: u64,
    },
}

impl core::fmt::Display for BlockExecutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockExecutionError::Deposit(e) => write!(f, "deposit failed: {e}"),
            BlockExecutionError::DepositsOutOfOrder {
                first_index,
                second_index,
            } => {
                write!(
                    f,
                    "deposit {second_index} is not after deposit {first_index} in L1 position order"
                )
            }
            BlockExecutionError::InvalidBlockNumber { expected, got } => {
                write!(f, "block number {got}, expected {expected}")
            }
            BlockExecutionError::InvalidTimestamp { parent, got } => {
                write!(f, "block timestamp {got} is below the parent's {parent}")
            }
            BlockExecutionError::InvalidBaseFee { expected, got } => {
                write!(f, "block base fee {got}, EIP-1559 rule requires {expected}")
            }
            BlockExecutionError::BlobTxRejected { tx_index } => {
                write!(
                    f,
                    "tx {tx_index}: blob (type-3) transactions are rejected at the sequencer"
                )
            }
            BlockExecutionError::UnsupportedTxType { tx_index, tx_type } => {
                write!(
                    f,
                    "tx {tx_index}: transaction type {tx_type:#04x} is not supported at this hardfork"
                )
            }
            BlockExecutionError::InconsistentTxEnv { tx_index } => {
                write!(f, "tx {tx_index}: TxEnv fields are inconsistent with its tx_type")
            }
            BlockExecutionError::ChainIdMismatch { tx_index, got } => {
                write!(
                    f,
                    "tx {tx_index}: chain id {got:?} is not this chain's (EIP-155 required)"
                )
            }
            BlockExecutionError::TxGasLimitExceedsBlock { tx_index } => {
                write!(f, "tx {tx_index}: gas limit exceeds the block gas limit")
            }
            BlockExecutionError::BlockGasLimitExceeded { tx_index } => {
                write!(f, "tx {tx_index}: block gas limit exceeded")
            }
            BlockExecutionError::Evm { tx_index, detail } => {
                write!(f, "tx {tx_index}: evm error: {detail}")
            }
            BlockExecutionError::SystemCall { detail } => write!(f, "EIP-4788 system call failed: {detail}"),
            BlockExecutionError::Conservation {
                tx_index,
                lost_wei,
                base_fee_wei,
            } => write!(
                f,
                "tx {tx_index}: accounts lost {lost_wei} wei, less than the {base_fee_wei} wei basefee revm charges"
            ),
            BlockExecutionError::Database { detail } => write!(f, "database error: {detail}"),
            BlockExecutionError::InvalidChainSpec(e) => write!(f, "invalid chain spec: {e}"),
            BlockExecutionError::DepositGasExceedsBlock { deposits, max_deposits } => {
                write!(
                    f,
                    "{deposits} deposits exceed the block gas budget (at most {max_deposits} per block)"
                )
            }
        }
    }
}

impl core::error::Error for BlockExecutionError {}

impl From<DepositError> for BlockExecutionError {
    fn from(e: DepositError) -> Self {
        BlockExecutionError::Deposit(e)
    }
}

/// EIP-4844 blob transaction type byte.
const BLOB_TX_TYPE: u8 = 3;

/// Transaction types this L2 accepts at CANCUN: legacy (0), EIP-2930 (1) and
/// EIP-1559 (2). Everything else — blob (3), EIP-7702 (4, Prague), the
/// reserved OP-style deposit envelope (0x7E) and any unknown byte — is
/// rejected before it reaches revm, whose fee validation does not cover
/// unknown ("custom") types.
pub const SUPPORTED_TX_TYPES: [u8; 3] = [0, 1, 2];

/// Commitment to a block's deposit list: `keccak256` over the concatenation of
/// `recipient ‖ l1_height (BE u64) ‖ l1_tx_index (BE u32) ‖ l1_txid ‖
/// l1_vout (BE u32) ‖ l1_sats (BE u64)` for each deposit in order
/// (`keccak256("")` for no deposits). Binds a proof over the block to the exact
/// L1-derived deposits it minted.
pub fn deposits_hash(deposits: &[DepositMint]) -> B256 {
    let mut buf = Vec::with_capacity(deposits.len() * 76);
    for d in deposits {
        let pos = d.position();
        let (txid, vout) = d.outpoint();
        buf.extend_from_slice(d.recipient.as_slice());
        buf.extend_from_slice(&pos.l1_height.to_be_bytes());
        buf.extend_from_slice(&pos.l1_tx_index.to_be_bytes());
        buf.extend_from_slice(&txid);
        buf.extend_from_slice(&vout.to_be_bytes());
        buf.extend_from_slice(&d.l1_sats().to_be_bytes());
    }
    keccak256(&buf)
}

/// Pure, state-independent validation of a [`BlockInput`] against the
/// [`ChainSpec`]: it depends on nothing but the input, so it runs before any
/// state is touched. Checks the spec itself ([`ChainSpec::validate`]), the
/// deposits' gas budget, every deposit's L1 cap and the strictly increasing
/// L1 position order of the deposit list (which also excludes duplicates), and
/// every transaction's type, blob fields, `TxEnv` consistency, EIP-155 chain
/// id and gas limit. Stateful rules (header validity against the head, the
/// deposit cursor, the cumulative cap, revm's own validation) are enforced
/// during execution on the working copy.
pub fn validate_block_input(spec: &ChainSpec, input: &BlockInput) -> Result<(), BlockExecutionError> {
    spec.validate().map_err(BlockExecutionError::InvalidChainSpec)?;
    deposits_gas(spec, input)?;
    for (i, d) in input.deposits.iter().enumerate() {
        if d.l1_sats() > spec.max_l1_sats {
            return Err(DepositError::ExceedsL1Supply {
                l1_sats: d.l1_sats(),
                max_l1_sats: spec.max_l1_sats,
            }
            .into());
        }
        if i > 0 && d.position() <= input.deposits[i - 1].position() {
            return Err(BlockExecutionError::DepositsOutOfOrder {
                first_index: i - 1,
                second_index: i,
            });
        }
    }
    for (i, tx) in input.txs.iter().enumerate() {
        validate_transaction(spec, tx, i)?;
    }
    Ok(())
}

fn validate_transaction(spec: &ChainSpec, tx: &TxEnv, i: usize) -> Result<(), BlockExecutionError> {
    if tx.tx_type == BLOB_TX_TYPE || !tx.blob_hashes.is_empty() || tx.max_fee_per_blob_gas != 0 {
        return Err(BlockExecutionError::BlobTxRejected { tx_index: i });
    }
    if !SUPPORTED_TX_TYPES.contains(&tx.tx_type) {
        return Err(BlockExecutionError::UnsupportedTxType {
            tx_index: i,
            tx_type: tx.tx_type,
        });
    }
    let is_1559 = tx.tx_type == 2;
    if is_1559 != tx.gas_priority_fee.is_some()
        || (tx.tx_type == 0 && !tx.access_list.0.is_empty())
        || !tx.authorization_list.is_empty()
    {
        return Err(BlockExecutionError::InconsistentTxEnv { tx_index: i });
    }
    if tx.chain_id != Some(spec.chain_id) {
        return Err(BlockExecutionError::ChainIdMismatch {
            tx_index: i,
            got: tx.chain_id,
        });
    }
    if tx.gas_limit > spec.gas_limit {
        return Err(BlockExecutionError::TxGasLimitExceedsBlock { tx_index: i });
    }
    Ok(())
}

/// Block gas consumed by the block's deposits (`deposits × deposit_gas`), or
/// the error if they alone exceed the block gas limit.
fn deposits_gas(spec: &ChainSpec, input: &BlockInput) -> Result<u64, BlockExecutionError> {
    let too_many = || BlockExecutionError::DepositGasExceedsBlock {
        deposits: input.deposits.len(),
        max_deposits: spec.max_deposits_per_block(),
    };
    let count = u64::try_from(input.deposits.len()).map_err(|_| too_many())?;
    let gas = spec.deposit_gas.checked_mul(count).ok_or_else(too_many)?;
    if gas > spec.gas_limit {
        return Err(too_many());
    }
    Ok(gas)
}

/// The per-block accounting a run produces (everything in [`ExecutionOutcome`]
/// except the state root, which needs the full post-state).
#[derive(Debug)]
pub(crate) struct BlockRun {
    pub(crate) gas_used: u64,
    pub(crate) minted_wei: U256,
    pub(crate) burned_wei: U256,
    pub(crate) deposits_hash: B256,
    pub(crate) parent_hash: B256,
    pub(crate) base_fee_routed_wei: U256,
    pub(crate) priority_fee_routed_wei: U256,
    pub(crate) tx_outcomes: Vec<TxOutcome>,
}

impl BlockRun {
    fn record(&mut self, committed: CommittedTransaction) {
        let outcome = committed.outcome;
        self.gas_used += outcome.gas_used;
        self.burned_wei = self
            .burned_wei
            .checked_add(outcome.burned_wei)
            .expect("burned wei cannot overflow U256");
        self.base_fee_routed_wei = self
            .base_fee_routed_wei
            .checked_add(committed.base_fee_routed_wei)
            .expect("routed wei cannot overflow U256");
        self.priority_fee_routed_wei = self
            .priority_fee_routed_wei
            .checked_add(committed.priority_fee_routed_wei)
            .expect("routed wei cannot overflow U256");
        self.tx_outcomes.push(outcome);
    }

    /// The full outcome, given the post-state root.
    pub(crate) fn into_outcome(self, chain_id: u64, context: &BlockContext, state_root: B256) -> ExecutionOutcome {
        let header = self.header(chain_id, context, state_root);
        ExecutionOutcome {
            block_number: context.number,
            gas_used: self.gas_used,
            base_fee_per_gas: context.base_fee_per_gas,
            minted_wei: self.minted_wei,
            burned_wei: self.burned_wei,
            deposits_hash: self.deposits_hash,
            base_fee_routed_wei: self.base_fee_routed_wei,
            priority_fee_routed_wei: self.priority_fee_routed_wei,
            tx_outcomes: self.tx_outcomes,
            state_root,
            block_hash: header.hash(),
            header,
        }
    }

    /// The header of the executed block, given its post-state root.
    pub(crate) fn header(&self, chain_id: u64, context: &BlockContext, state_root: B256) -> L2Header {
        L2Header {
            chain_id,
            number: context.number,
            timestamp: context.timestamp,
            base_fee_per_gas: context.base_fee_per_gas,
            gas_used: self.gas_used,
            prevrandao: context.prevrandao,
            anchor_root: context.anchor_root,
            parent_hash: self.parent_hash,
            deposits_hash: self.deposits_hash,
            state_root,
        }
    }
}

fn db_error<E: core::fmt::Debug>(e: E) -> BlockExecutionError {
    BlockExecutionError::Database {
        detail: format!("{e:?}"),
    }
}

fn word_u64(v: U256) -> u64 {
    v.as_limbs()[0]
}

/// Read the committed head record through the [`Database`] trait (so recording
/// and stateless backings observe the reads).
fn read_head<ExtDB: DatabaseRef>(db: &mut CacheDB<ExtDB>, info: Address) -> Result<Option<HeadRecord>, ExtDB::Error> {
    db.basic(info)?;
    if db.storage(info, BLOCK_INFO_FLAG_SLOT)?.is_zero() {
        return Ok(None);
    }
    Ok(Some(HeadRecord {
        number: word_u64(db.storage(info, BLOCK_INFO_NUMBER_SLOT)?),
        timestamp: word_u64(db.storage(info, BLOCK_INFO_TIMESTAMP_SLOT)?),
        base_fee_per_gas: word_u64(db.storage(info, BLOCK_INFO_BASE_FEE_SLOT)?),
        gas_used: word_u64(db.storage(info, BLOCK_INFO_GAS_USED_SLOT)?),
        prevrandao: B256::from(db.storage(info, BLOCK_INFO_PREVRANDAO_SLOT)?),
        anchor_root: B256::from(db.storage(info, BLOCK_INFO_ANCHOR_ROOT_SLOT)?),
        parent_hash: B256::from(db.storage(info, BLOCK_INFO_PARENT_HASH_SLOT)?),
        deposits_hash: B256::from(db.storage(info, BLOCK_INFO_DEPOSITS_HASH_SLOT)?),
    }))
}

/// Write the head record for the block just executed.
fn write_head<ExtDB: DatabaseRef>(
    db: &mut CacheDB<ExtDB>,
    info: Address,
    rec: &HeadRecord,
) -> Result<(), ExtDB::Error> {
    ensure_system_account(db, info, None)?;
    db.insert_account_storage(info, BLOCK_INFO_FLAG_SLOT, U256::from(1u64))?;
    db.insert_account_storage(info, BLOCK_INFO_NUMBER_SLOT, U256::from(rec.number))?;
    db.insert_account_storage(info, BLOCK_INFO_TIMESTAMP_SLOT, U256::from(rec.timestamp))?;
    db.insert_account_storage(info, BLOCK_INFO_BASE_FEE_SLOT, U256::from(rec.base_fee_per_gas))?;
    db.insert_account_storage(info, BLOCK_INFO_GAS_USED_SLOT, U256::from(rec.gas_used))?;
    db.insert_account_storage(info, BLOCK_INFO_PREVRANDAO_SLOT, rec.prevrandao.into())?;
    db.insert_account_storage(info, BLOCK_INFO_ANCHOR_ROOT_SLOT, rec.anchor_root.into())?;
    db.insert_account_storage(info, BLOCK_INFO_PARENT_HASH_SLOT, rec.parent_hash.into())?;
    db.insert_account_storage(info, BLOCK_INFO_DEPOSITS_HASH_SLOT, rec.deposits_hash.into())?;
    Ok(())
}

/// Validate the block context against the head record and return the parent
/// block's hash (writing it into the ring buffer), plus whether a committed
/// head exists. Portable cache population is separate from this protocol update.
fn apply_header_update<ExtDB: DatabaseRef>(
    spec: &ChainSpec,
    db: &mut CacheDB<ExtDB>,
    prev_state_root: B256,
    ctx: &BlockContext,
) -> Result<(B256, bool), BlockExecutionError> {
    let info = spec.block_info;
    let head = read_head(db, info).map_err(db_error)?;
    let parent_hash = match head {
        Some(h) => {
            let expected = h.number.checked_add(1).ok_or(BlockExecutionError::InvalidBlockNumber {
                expected: u64::MAX,
                got: ctx.number,
            })?;
            if ctx.number != expected {
                return Err(BlockExecutionError::InvalidBlockNumber {
                    expected,
                    got: ctx.number,
                });
            }
            if ctx.timestamp < h.timestamp {
                return Err(BlockExecutionError::InvalidTimestamp {
                    parent: h.timestamp,
                    got: ctx.timestamp,
                });
            }
            let expected_fee = spec.next_base_fee(h.base_fee_per_gas, h.gas_used);
            if ctx.base_fee_per_gas != expected_fee {
                return Err(BlockExecutionError::InvalidBaseFee {
                    expected: expected_fee,
                    got: ctx.base_fee_per_gas,
                });
            }
            // The parent's header is the committed record plus the root it is
            // committed in; its hash enters the ring buffer now.
            let parent_hash = L2Header::from_head(spec.chain_id, &h, prev_state_root).hash();
            ensure_system_account(db, info, None).map_err(db_error)?;
            db.insert_account_storage(info, block_hash_slot(h.number), parent_hash.into())
                .map_err(db_error)?;
            parent_hash
        }
        None => {
            if ctx.base_fee_per_gas != spec.initial_base_fee {
                return Err(BlockExecutionError::InvalidBaseFee {
                    expected: spec.initial_base_fee,
                    got: ctx.base_fee_per_gas,
                });
            }
            B256::ZERO
        }
    };

    Ok((parent_hash, head.is_some()))
}

fn apply_header_rules<ExtDB: DatabaseRef>(
    spec: &ChainSpec,
    db: &mut CacheDB<ExtDB>,
    prev_state_root: B256,
    ctx: &BlockContext,
) -> Result<B256, BlockExecutionError> {
    let (parent_hash, has_head) = apply_header_update(spec, db, prev_state_root, ctx)?;
    let info = spec.block_info;
    // BLOCKHASH window: every number in [N-256, N-1] is served from the ring
    // (zero for blocks before the chain started), never from a backing DB.
    let start = ctx.number.saturating_sub(BLOCK_HASH_HISTORY);
    for n in start..ctx.number {
        let v = if has_head {
            db.storage(info, block_hash_slot(n)).map_err(db_error)?
        } else {
            U256::ZERO
        };
        db.cache.block_hashes.insert(U256::from(n), B256::from(v));
    }
    Ok(parent_hash)
}

/// Execute one block against any `CacheDB`: validate the input and the header,
/// run the EIP-4788 system call, apply deposit mints, then run every
/// transaction through unmodified revm at the spec's pinned hardfork, routing
/// fees to the vaults and accounting EVM burns, and finally commit the new head
/// record. Consumes the database and returns it only on success; the caller
/// decides what the database was (a working copy of the live state, a
/// recording overlay, or a stateless guest state). `prev_state_root` is the
/// root of `db` before this block (the host computes it, the guest takes it
/// from the authenticated witness).
pub(crate) fn run_block<DB: DatabaseRef>(
    spec: &ChainSpec,
    db: CacheDB<DB>,
    prev_state_root: B256,
    input: &BlockInput,
) -> Result<(CacheDB<DB>, BlockRun), BlockExecutionError> {
    // Keep verifier-wide preflight ahead of every database read.
    validate_block_input(spec, input)?;
    let mut session = BlockSession::begin(spec, db, prev_state_root, &input.context, &input.deposits)?;
    for tx in &input.txs {
        session.try_transaction(tx, |_| true)?;
    }
    session.finish()
}

fn block_context<DB: Database>(
    spec: &ChainSpec,
    context: &BlockContext,
    db: DB,
) -> Context<revm::context::BlockEnv, TxEnv, revm::context::CfgEnv, DB> {
    Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = spec.chain_id;
            // Sets both the spec and its mainnet gas params (CANCUN here).
            cfg.set_spec_and_mainnet_gas_params(spec.spec_id);
        })
        .modify_block_chained(|b| {
            b.number = U256::from(context.number);
            b.timestamp = U256::from(context.timestamp);
            b.gas_limit = spec.gas_limit;
            b.basefee = context.base_fee_per_gas;
            // COINBASE = fee-vault address (design §1): priority fees are
            // paid to the beneficiary by revm's unmodified handler.
            b.beneficiary = spec.coinbase();
            b.prevrandao = Some(context.prevrandao);
            b.difficulty = U256::ZERO;
            // Blobless blocks: BLOBHASH / blob-basefee opcodes still return
            // spec-correct values (zero excess gas) for Cancun.
            b.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::new_with_spec(0, spec.spec_id));
        })
}

/// Fully prepared effects from a trusted, matching revm execution result.
/// Dropping this value discards all writes. It is not an authentication or proof boundary.
#[must_use = "commit prepared effects or drop them to discard the candidate"]
#[derive(Debug)]
pub struct PreparedTransaction {
    state: EvmState,
    fee_credit: EvmState,
    committed: CommittedTransaction,
}

/// Accounting produced when a prepared transaction is committed.
#[derive(Debug)]
pub struct CommittedTransaction {
    /// EVM execution outcome, including separately accounted destruction.
    pub outcome: TxOutcome,
    /// Base fee credited by the protocol to the configured vault.
    pub base_fee_routed_wei: U256,
    /// Priority fee already credited by revm to the beneficiary.
    pub priority_fee_routed_wei: U256,
}

impl PreparedTransaction {
    /// Inspect the execution outcome before choosing whether to commit.
    pub fn outcome(&self) -> &TxOutcome {
        &self.committed.outcome
    }

    /// Commit to the same logical pre-state used for preparation, without database reads.
    ///
    /// No other transition may change that pre-state between preparation and commit.
    /// The two commits preserve deletion followed by protocol-level vault recreation.
    pub fn commit(self, db: &mut impl DatabaseCommit) -> CommittedTransaction {
        db.commit(self.state);
        if !self.fee_credit.is_empty() {
            db.commit(self.fee_credit);
        }
        self.committed
    }
}

/// Reconcile a matching revm result and prepare all fee effects without committing.
///
/// The caller must supply the actual result of executing `tx` against `db` at the
/// given base fee. This function does not authenticate transactions, validate an
/// arbitrary result, enforce block gas limits, or prove the backing state. Reads
/// may populate database caches; errors never call `DatabaseCommit::commit`.
pub fn prepare_transaction_effects<DB: Database>(
    spec: &ChainSpec,
    base_fee: u64,
    tx: &TxEnv,
    tx_index: usize,
    result: ResultAndState<HaltReason>,
    db: &mut DB,
) -> Result<PreparedTransaction, BlockExecutionError> {
    let ResultAndState { result, state } = result;
    let gas_used = result.tx_gas_used();
    let effective = Transaction::effective_gas_price(tx, base_fee as u128);
    let base_fee_wei = U256::from(core::cmp::min(effective, base_fee as u128))
        .checked_mul(U256::from(gas_used))
        .expect("fee cannot overflow U256");
    let priority_fee_routed_wei = U256::from(effective.saturating_sub(base_fee as u128))
        .checked_mul(U256::from(gas_used))
        .expect("fee cannot overflow U256");
    let mut pre_sum = U256::ZERO;
    let mut post_sum = U256::ZERO;
    for (address, account) in &state {
        let pre = db
            .basic(*address)
            .map_err(db_error)?
            .map(|info| info.balance)
            .unwrap_or_default();
        let post = if account.is_selfdestructed() {
            U256::ZERO
        } else {
            account.info.balance
        };
        pre_sum = pre_sum.checked_add(pre).expect("balances cannot overflow U256");
        post_sum = post_sum.checked_add(post).expect("balances cannot overflow U256");
    }
    let lost = pre_sum.saturating_sub(post_sum);
    let burned = lost
        .checked_sub(base_fee_wei)
        .ok_or(BlockExecutionError::Conservation {
            tx_index,
            lost_wei: lost,
            base_fee_wei,
        })?;
    let mut fee_credit = EvmState::default();
    if !base_fee_wei.is_zero() {
        // DatabaseCommit ignores untouched entries. Model the state after the
        // original EVM commit before preparing the independent protocol credit.
        let info = match state.get(&spec.base_fee_vault).filter(|account| account.is_touched()) {
            Some(account) if account.is_selfdestructed() => None,
            Some(account) => Some(account.info.clone()),
            None => db.basic(spec.base_fee_vault).map_err(db_error)?,
        };
        let absent = info.is_none();
        let mut account = Account::from(info.unwrap_or_default());
        account.info.balance = account
            .info
            .balance
            .checked_add(base_fee_wei)
            .expect("balance cannot overflow U256");
        account.mark_touch();
        if absent {
            account.mark_created();
        }
        fee_credit.insert(spec.base_fee_vault, account);
    }
    Ok(PreparedTransaction {
        state,
        fee_credit,
        committed: CommittedTransaction {
            outcome: TxOutcome {
                success: result.is_success(),
                gas_used,
                created_address: result.created_address(),
                burned_wei: burned,
                result,
            },
            base_fee_routed_wei: base_fee_wei,
            priority_fee_routed_wei,
        },
    })
}

/// Incremental execution with a sparse, disposable overlay for each candidate.
/// Only accepted candidates modify the session; protocol transitions run once.
pub(crate) struct BlockSession<DB> {
    spec: ChainSpec,
    context: BlockContext,
    db: CacheDB<DB>,
    run: BlockRun,
}

impl<DB: DatabaseRef> BlockSession<DB> {
    pub(crate) fn begin(
        spec: &ChainSpec,
        mut db: CacheDB<DB>,
        previous_root: B256,
        context: &BlockContext,
        deposits: &[DepositMint],
    ) -> Result<Self, BlockExecutionError> {
        let input = BlockInput {
            context: context.clone(),
            deposits: deposits.to_vec(),
            txs: Vec::new(),
        };
        validate_block_input(spec, &input)?;
        let parent_hash = apply_header_rules(spec, &mut db, previous_root, context)?;
        let mut evm = block_context(spec, context, db).build_mainnet();
        // 3. EIP-4788 system call: store this block's anchor root under its
        //    timestamp in the canonical beacon-roots predeploy (materialized if
        //    absent), before any transaction.
        ensure_system_account(
            &mut evm.ctx.journaled_state.database,
            BEACON_ROOTS_ADDRESS,
            Some(&beacon_roots_bytecode()),
        )
        .map_err(db_error)?;
        let sys = evm
            .system_call_commit(
                BEACON_ROOTS_ADDRESS,
                Bytes::copy_from_slice(context.anchor_root.as_slice()),
            )
            .map_err(|e| BlockExecutionError::SystemCall {
                detail: format!("{e:?}"),
            })?;
        if !sys.is_success() {
            return Err(BlockExecutionError::SystemCall {
                detail: format!("{sys:?}"),
            });
        }

        // 4. Deposit mints (before any user tx). This is the ONLY place native
        //    balance is created; provenance is bridged BLCH only and positions must
        //    advance the committed cursor (one mint per escrow).
        let minted_wei = apply_deposits(&mut evm.ctx.journaled_state.database, spec, deposits)?;

        Ok(Self {
            spec: spec.clone(),
            context: context.clone(),
            db: evm.ctx.journaled_state.database,
            run: BlockRun {
                gas_used: deposits_gas(spec, &input)?,
                minted_wei,
                burned_wei: U256::ZERO,
                deposits_hash: deposits_hash(deposits),
                parent_hash,
                base_fee_routed_wei: U256::ZERO,
                priority_fee_routed_wei: U256::ZERO,
                tx_outcomes: Vec::new(),
            },
        })
    }

    pub(crate) fn try_transaction(
        &mut self,
        tx: &TxEnv,
        commit: impl FnOnce(&TxOutcome) -> bool,
    ) -> Result<Option<&TxOutcome>, BlockExecutionError> {
        let spec = &self.spec;
        let i = self.run.tx_outcomes.len();
        validate_transaction(spec, tx, i)?;
        let base_fee = self.context.base_fee_per_gas;
        let mut evm = block_context(spec, &self.context, CacheDB::new(&self.db)).build_mainnet();
        if self.run.gas_used.saturating_add(tx.gas_limit) > spec.gas_limit {
            return Err(BlockExecutionError::BlockGasLimitExceeded { tx_index: i });
        }
        // Execute without committing, so the balance deltas of every touched
        // account can be reconciled against the pre-state before they land.
        let res = evm.transact(tx.clone()).map_err(|e| BlockExecutionError::Evm {
            tx_index: i,
            detail: format!("{e:?}"),
        })?;
        let prepared = prepare_transaction_effects(spec, base_fee, tx, i, res, &mut evm.ctx.journaled_state.database)?;
        if !commit(prepared.outcome()) {
            return Ok(None);
        }
        let committed = prepared.commit(&mut evm.ctx.journaled_state.database);
        let cache = evm.ctx.journaled_state.database.cache;
        merge_candidate(&mut self.db, cache);
        self.run.record(committed);
        Ok(self.run.tx_outcomes.last())
    }

    pub(crate) fn finish(self) -> Result<(CacheDB<DB>, BlockRun), BlockExecutionError> {
        let mut db = self.db;
        finish_protocol(&mut db, &self.spec, &self.context, &self.run)?;

        Ok((db, self.run))
    }
}

fn apply_deposits<DB: DatabaseRef>(
    db: &mut CacheDB<DB>,
    spec: &ChainSpec,
    deposits: &[DepositMint],
) -> Result<U256, BlockExecutionError> {
    let mut minted = U256::ZERO;
    for deposit in deposits {
        let wei = apply_deposit(db, spec, deposit).map_err(|error| match error {
            DepositApplyError::Deposit(error) => BlockExecutionError::Deposit(error),
            DepositApplyError::Db(error) => db_error(error),
        })?;
        minted = minted.checked_add(wei).expect("minted wei cannot overflow U256");
    }
    Ok(minted)
}

fn finish_protocol<DB: DatabaseRef>(
    db: &mut CacheDB<DB>,
    spec: &ChainSpec,
    context: &BlockContext,
    run: &BlockRun,
) -> Result<(), BlockExecutionError> {
    if !run.burned_wei.is_zero() {
        ledger_add(db, spec.supply_ledger, SUPPLY_LEDGER_BURNED_SLOT, run.burned_wei).map_err(db_error)?;
    }
    write_head(
        db,
        spec.block_info,
        &HeadRecord {
            number: context.number,
            timestamp: context.timestamp,
            base_fee_per_gas: context.base_fee_per_gas,
            gas_used: run.gas_used,
            prevrandao: context.prevrandao,
            anchor_root: context.anchor_root,
            parent_hash: run.parent_hash,
            deposits_hash: run.deposits_hash,
        },
    )
    .map_err(db_error)?;
    Ok(())
}

/// Merge sparse reads/writes without replacing an account's untouched storage.
/// Deletion and clear markers remain until the block overlay reaches its backing.
fn merge_candidate<DB>(db: &mut CacheDB<DB>, candidate: revm::database::Cache) {
    use revm::database::AccountState;
    for (address, mut account) in candidate.accounts {
        match account.account_state {
            AccountState::NotExisting | AccountState::StorageCleared => {
                db.cache.accounts.insert(address, account);
            }
            AccountState::None | AccountState::Touched => {
                if let Some(previous) = db.cache.accounts.get_mut(&address) {
                    previous.info = account.info;
                    if previous.account_state == AccountState::StorageCleared
                        || previous.account_state == AccountState::NotExisting
                    {
                        previous.account_state = AccountState::StorageCleared;
                    } else if account.account_state == AccountState::Touched {
                        previous.account_state = AccountState::Touched;
                    }
                    previous.storage.extend(account.storage.drain());
                } else {
                    db.cache.accounts.insert(address, account);
                }
            }
        }
    }
    db.cache.contracts.extend(candidate.contracts);
    db.cache.logs.extend(candidate.logs);
    db.cache.block_hashes.extend(candidate.block_hashes);
}

/// Execute one block: validate it (input and header), run the EIP-4788 system
/// call, apply deposit mints, then run every transaction through unmodified
/// revm at the spec's pinned hardfork, routing fees to the vaults and
/// accounting EVM burns; commit the new head record.
///
/// **Atomic and O(touched):** the block runs on an overlay (`CacheDB`) of
/// `state` that holds only the accounts it reads or writes; `state` is merged
/// with the overlay only when the whole block succeeded and is left
/// byte-identical to the pre-block state on every `Err`. The state root is
/// maintained incrementally (only the touched accounts are re-hashed), so an
/// empty block costs the same against 1k or 1M accounts. Returns the
/// [`ExecutionOutcome`].
pub fn execute_block(
    spec: &ChainSpec,
    state: &mut L2State,
    input: BlockInput,
) -> Result<ExecutionOutcome, BlockExecutionError> {
    // The pre-state root: O(1) once the commitment is warm (built once otherwise).
    let prev_state_root = state.commit_root();
    let overlay = CacheDB::new(state.db());
    let (overlay, run) = run_block(spec, overlay, prev_state_root, &input)?;
    let CacheDB { cache, .. } = overlay;
    state.apply_overlay(cache);

    // Real keccak-256 MPT state root over the post-execution state, re-hashing
    // only what this block touched.
    let state_root = state.commit_root();
    Ok(run.into_outcome(spec.chain_id, &input.context, state_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::{sats_to_wei, SATS_PER_BLCH};
    use crate::state::DepositProvenance;
    use crate::stateroot::compute_keccak_mpt_state_root;
    use alloy_primitives::{address, bytes, Bytes, TxKind};
    use alloy_trie::EMPTY_ROOT_HASH;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn sparse_candidate_merge_preserves_slots_and_storage_wipes() {
        use revm::database::{AccountState, Cache, DbAccount, EmptyDB};
        let mut db = CacheDB::new(EmptyDB::default());
        let mut original = DbAccount::default();
        original.info.balance = U256::from(1);
        original.storage.insert(U256::from(1), U256::from(11));
        original.storage.insert(U256::from(2), U256::from(22));
        db.cache.accounts.insert(ALICE, original.clone());
        let mut delta = original.clone();
        delta.account_state = AccountState::Touched;
        delta.storage.clear();
        delta.storage.insert(U256::from(1), U256::ZERO);
        let mut cache = Cache::default();
        cache.accounts.insert(ALICE, delta);
        merge_candidate(&mut db, cache);
        assert_eq!(db.storage(ALICE, U256::from(1)).unwrap(), U256::ZERO);
        assert_eq!(db.storage(ALICE, U256::from(2)).unwrap(), U256::from(22));

        let mut cache = Cache::default();
        cache.accounts.insert(ALICE, DbAccount::new_not_existing());
        merge_candidate(&mut db, cache);
        let mut cache = Cache::default();
        original.storage.clear();
        cache.accounts.insert(ALICE, original);
        merge_candidate(&mut db, cache);
        assert_eq!(db.cache.accounts[&ALICE].account_state, AccountState::StorageCleared);
        assert_eq!(db.storage(ALICE, U256::from(2)).unwrap(), U256::ZERO);

        let mut cache = Cache::default();
        let mut delta = DbAccount::default();
        delta.info.balance = U256::from(1);
        delta.account_state = AccountState::Touched;
        delta.storage.insert(U256::from(3), U256::from(33));
        cache.accounts.insert(ALICE, delta);
        merge_candidate(&mut db, cache);
        assert_eq!(db.cache.accounts[&ALICE].account_state, AccountState::StorageCleared);
        assert_eq!(db.storage(ALICE, U256::from(3)).unwrap(), U256::from(33));
        assert_eq!(db.storage(ALICE, U256::from(2)).unwrap(), U256::ZERO);
    }

    #[test]
    fn late_vault_read_failure_does_not_commit_candidate() {
        use core::cell::Cell;
        use revm::state::{AccountInfo, Bytecode};
        #[derive(Debug)]
        struct Unavailable;
        impl core::fmt::Display for Unavailable {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("vault unavailable")
            }
        }
        impl core::error::Error for Unavailable {}
        impl revm::database_interface::DBErrorMarker for Unavailable {}
        struct Provider {
            vault: Address,
            fail: Cell<bool>,
            vault_reads: Cell<usize>,
        }
        impl DatabaseRef for Provider {
            type Error = Unavailable;
            fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
                if address == self.vault {
                    self.vault_reads.set(self.vault_reads.get() + 1);
                    if self.fail.get() {
                        return Err(Unavailable);
                    }
                }
                Ok(None)
            }
            fn code_by_hash_ref(&self, _: B256) -> Result<Bytecode, Self::Error> {
                Ok(Bytecode::default())
            }
            fn storage_ref(&self, _: Address, _: U256) -> Result<U256, Self::Error> {
                Ok(U256::ZERO)
            }
            fn block_hash_ref(&self, _: u64) -> Result<B256, Self::Error> {
                Ok(B256::ZERO)
            }
        }
        let spec = ChainSpec::testnet();
        let provider = Provider {
            vault: spec.base_fee_vault,
            fail: Cell::new(true),
            vault_reads: Cell::new(0),
        };
        let mut session = BlockSession::begin(
            &spec,
            CacheDB::new(provider),
            EMPTY_ROOT_HASH,
            &BlockContext::default(),
            &[deposit(ALICE, SATS_PER_BLCH)],
        )
        .unwrap();
        let before = format!("{:?}", session.db.cache);
        let gas = session.run.gas_used;
        let tx = transfer(ALICE, BOB, 0, U256::from(7), 21_000);
        let condition_called = Cell::new(false);
        let error = session
            .try_transaction(&tx, |_| {
                condition_called.set(true);
                true
            })
            .unwrap_err();
        assert!(matches!(error, BlockExecutionError::Database { .. }));
        assert_eq!(session.db.db.vault_reads.get(), 1);
        assert!(!condition_called.get());
        assert_eq!(format!("{:?}", session.db.cache), before);
        assert_eq!(session.run.gas_used, gas);
        assert!(session.run.tx_outcomes.is_empty());
        assert!(session.run.burned_wei.is_zero());
        assert!(session.run.base_fee_routed_wei.is_zero());
        assert!(session.run.priority_fee_routed_wei.is_zero());
        session.db.db.fail.set(false);
        assert!(session.try_transaction(&tx, |_| true).unwrap().unwrap().success);
        assert_eq!(session.db.basic_ref(ALICE).unwrap().unwrap().nonce, 1);
        assert_eq!(session.db.basic_ref(BOB).unwrap().unwrap().balance, U256::from(7));
        session.finish().unwrap();
    }

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");

    const GWEI: u128 = 1_000_000_000;

    static NEXT_HEIGHT: AtomicU32 = AtomicU32::new(1);

    /// A deposit at a fresh, strictly increasing L1 position.
    fn deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: NEXT_HEIGHT.fetch_add(1, Ordering::Relaxed) as u64,
                l1_tx_index: 0,
                l1_txid: [7; 32],
                l1_vout: 0,
                l1_sats,
            },
        }
    }

    fn transfer(from: Address, to: Address, nonce: u64, value: U256, gas_limit: u64) -> TxEnv {
        tx_at_fee(from, to, nonce, value, gas_limit, ChainSpec::testnet().initial_base_fee)
    }

    /// EIP-1559 transfer paying `base_fee + 1 gwei`.
    fn tx_at_fee(from: Address, to: Address, nonce: u64, value: U256, gas_limit: u64, base_fee: u64) -> TxEnv {
        let spec = ChainSpec::testnet();
        TxEnv::builder()
            .caller(from)
            .kind(TxKind::Call(to))
            .value(value)
            .gas_limit(gas_limit)
            .max_fee_per_gas(base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx env")
    }

    /// A genesis block input (first block: number 1, initial base fee).
    fn genesis(deposits: Vec<DepositMint>, txs: Vec<TxEnv>) -> BlockInput {
        BlockInput {
            context: BlockContext::default(),
            deposits,
            txs,
        }
    }

    /// The rule-conforming next block after `state`.
    fn next(spec: &ChainSpec, state: &L2State, deposits: Vec<DepositMint>, txs: Vec<TxEnv>) -> BlockInput {
        BlockInput {
            context: BlockContext::next(spec, state),
            deposits,
            txs,
        }
    }

    /// Execute the rule-conforming next block after `state` (context computed
    /// before the mutable borrow).
    fn exec_next(
        spec: &ChainSpec,
        state: &mut L2State,
        deposits: Vec<DepositMint>,
        txs: Vec<TxEnv>,
    ) -> Result<ExecutionOutcome, BlockExecutionError> {
        let input = next(spec, state, deposits, txs);
        execute_block(spec, state, input)
    }

    /// Init code that deploys a 10-byte runtime returning uint256(42) on any
    /// call:
    ///   runtime: 602a60005260206000f3
    ///     PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    ///   initcode: PUSH10 <runtime> PUSH1 0 MSTORE PUSH1 10 PUSH1 22 RETURN
    fn return42_initcode() -> Bytes {
        bytes!("69602a60005260206000f3600052600a6016f3")
    }

    /// Initcode that deploys `runtime` verbatim (CODECOPY + RETURN).
    fn deployer(runtime: &[u8]) -> Bytes {
        let len = runtime.len() as u8;
        let mut initcode = vec![0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3];
        initcode.extend_from_slice(runtime);
        initcode.into()
    }

    /// Snapshot of everything an error must leave untouched.
    fn fingerprint(state: &L2State) -> (B256, U256, U256, U256, usize) {
        (
            compute_keccak_mpt_state_root(state),
            state.total_native_wei(),
            state.total_minted_wei(),
            state.total_burned_wei(),
            state.db().cache.accounts.len(),
        )
    }

    fn conserved(state: &L2State) -> bool {
        state.total_native_wei() == state.total_minted_wei() - state.total_burned_wei()
    }

    #[test]
    fn value_transfer_state_transition() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei
        let tip: u128 = GWEI; // 1 gwei priority fee

        // Fund alice with 10 BLCH via a bridged deposit.
        let funding_sats = 10 * SATS_PER_BLCH;
        let transfer_wei = sats_to_wei(SATS_PER_BLCH); // 1 BLCH

        let tx = transfer(ALICE, BOB, 0, transfer_wei, 21_000);
        let deposits = vec![deposit(ALICE, funding_sats)];
        let outcome = execute_block(&spec, &mut state, genesis(deposits.clone(), vec![tx])).expect("block executes");

        // Tx-level assertions.
        assert_eq!(outcome.tx_outcomes.len(), 1);
        assert!(outcome.tx_outcomes[0].success);
        assert_eq!(outcome.tx_outcomes[0].gas_used, 21_000);
        assert_eq!(outcome.tx_outcomes[0].burned_wei, U256::ZERO);
        assert_eq!(
            outcome.gas_used,
            21_000 + spec.deposit_gas,
            "tx gas plus the metered deposit"
        );
        assert_eq!(outcome.deposits_hash, deposits_hash(&deposits));
        assert_eq!(outcome.state_root, compute_keccak_mpt_state_root(&state));
        assert_eq!(outcome.block_hash, outcome.header.hash());
        assert_eq!(outcome.header.parent_hash, B256::ZERO, "first block has no parent");
        assert_eq!(outcome.header.state_root, outcome.state_root);

        // Post balances / nonces.
        let effective_price = base_fee as u128 + tip; // max fee covers both
        let gas_cost = U256::from(effective_price) * U256::from(21_000u64);
        assert_eq!(
            state.balance_of(&ALICE),
            sats_to_wei(funding_sats) - transfer_wei - gas_cost
        );
        assert_eq!(state.balance_of(&BOB), transfer_wei);
        assert_eq!(state.nonce_of(&ALICE), 1);
        assert_eq!(state.nonce_of(&BOB), 0);

        // Fee routing: basefee → BaseFeeVault, priority → SequencerFeeVault.
        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(tip) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);

        // Zero issuance, never burn: supply is exactly the deposits.
        assert_eq!(outcome.minted_wei, sats_to_wei(funding_sats));
        assert_eq!(state.total_burned_wei(), U256::ZERO);
        assert!(conserved(&state));
        assert_eq!(state.total_minted_wei(), sats_to_wei(funding_sats));

        // The head record is committed.
        let head = state.head().expect("head after first block");
        assert_eq!(
            (head.number, head.gas_used, head.base_fee_per_gas),
            (1, 21_000 + spec.deposit_gas, base_fee)
        );
        assert_eq!(head.deposits_hash, outcome.deposits_hash);
    }

    #[test]
    fn contract_deploy_and_call() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee;
        let tip: u128 = GWEI;
        let funding_sats = 10 * SATS_PER_BLCH;

        let deploy = TxEnv::builder()
            .caller(ALICE)
            .create()
            .data(return42_initcode())
            .gas_limit(300_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid deploy tx");

        // CREATE address is deterministic: keccak(rlp([sender, nonce])).
        let expected_contract = ALICE.create(0);

        let call = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(expected_contract))
            .gas_limit(100_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(1)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid call tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, funding_sats)], vec![deploy, call]),
        )
        .expect("block executes");

        assert_eq!(outcome.tx_outcomes.len(), 2);

        // Deploy landed at the CREATE address; deployment costs more than a
        // bare transfer (21k intrinsic + initcode + code deposit).
        let deploy_out = &outcome.tx_outcomes[0];
        assert!(deploy_out.success);
        assert_eq!(deploy_out.created_address, Some(expected_contract));
        assert!(deploy_out.gas_used > 21_000);
        let contract = state.account(&expected_contract).expect("contract exists");
        assert_ne!(contract.code_hash, revm::primitives::KECCAK_EMPTY);

        // The call returned uint256(42).
        let call_out = &outcome.tx_outcomes[1];
        assert!(call_out.success);
        let output = call_out.result.output().expect("call has output");
        assert_eq!(output.len(), 32);
        assert_eq!(U256::from_be_slice(output), U256::from(42));
        assert!(call_out.gas_used >= 21_000);

        // Nonce accounting: two txs from alice (CREATE bumps to 1, call to 2).
        assert_eq!(state.nonce_of(&ALICE), 2);
        // Contract accounts are created with nonce 1 (EIP-161).
        assert_eq!(contract.nonce, 1);

        // Gas accounting: block gas = sum of tx gas; payer balance reflects
        // exactly value(0) + gas at the effective price; fees all in vaults.
        let total_gas = deploy_out.gas_used + call_out.gas_used;
        assert_eq!(
            outcome.gas_used,
            total_gas + spec.deposit_gas,
            "tx gas plus the metered deposit"
        );
        let effective_price = base_fee as u128 + tip;
        assert_eq!(
            state.balance_of(&ALICE),
            sats_to_wei(funding_sats) - U256::from(effective_price) * U256::from(total_gas)
        );
        assert_eq!(
            state.balance_of(&spec.base_fee_vault),
            U256::from(base_fee) * U256::from(total_gas)
        );
        assert_eq!(
            state.balance_of(&spec.sequencer_fee_vault),
            U256::from(tip) * U256::from(total_gas)
        );

        // Conservation: zero issuance, never burn.
        assert!(conserved(&state));
    }

    #[test]
    fn deposit_mint_total_supply_is_sum_of_mints() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // Two deposit-only blocks, no user txs: pure mint accounting.
        for (i, sats) in [5_000u64, 123_456_789u64].into_iter().enumerate() {
            let input = if i == 0 {
                genesis(vec![deposit(ALICE, sats), deposit(BOB, sats / 2 + 1)], vec![])
            } else {
                next(
                    &spec,
                    &state,
                    vec![deposit(ALICE, sats), deposit(BOB, sats / 2 + 1)],
                    vec![],
                )
            };
            let outcome = execute_block(&spec, &mut state, input).expect("deposit-only block executes");
            assert_eq!(
                outcome.gas_used,
                2 * spec.deposit_gas,
                "deposits consume block gas, fee-less"
            );
            assert_eq!(outcome.minted_wei, sats_to_wei(sats) + sats_to_wei(sats / 2 + 1));
        }

        let expected = sats_to_wei(5_000) + sats_to_wei(2_501) + sats_to_wei(123_456_789) + sats_to_wei(61_728_395);
        // total supply == sum of mints (zero issuance).
        assert_eq!(state.total_minted_wei(), expected);
        assert_eq!(state.total_native_wei(), expected);
        assert_eq!(state.head().unwrap().number, 2);
    }

    #[test]
    fn blob_transactions_are_rejected_at_the_sequencer_without_touching_state() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(&spec, &mut state, genesis(vec![deposit(ALICE, 1_000_000)], vec![])).unwrap();
        let before = fingerprint(&state);

        let blob_tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(2 * GWEI)
            .gas_priority_fee(Some(GWEI))
            .blob_hashes(vec![B256::repeat_byte(1)])
            .max_fee_per_blob_gas(1)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build_fill();

        let err = exec_next(&spec, &mut state, vec![deposit(BOB, 1_000_000)], vec![blob_tx]).unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlobTxRejected { tx_index: 0 }));
        // The rejected block's deposit was NOT applied: state is untouched.
        assert_eq!(fingerprint(&state), before);
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
    }

    #[test]
    fn reverting_tx_still_consumes_gas_and_routes_fees() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee;
        let tip: u128 = GWEI;
        let funding_sats = 10 * SATS_PER_BLCH;

        // A CREATE whose initcode reverts immediately: PUSH1 0 PUSH1 0 REVERT.
        // The transaction is valid and included; it just fails.
        let revert_deploy = TxEnv::builder()
            .caller(ALICE)
            .create()
            .data(bytes!("60006000fd"))
            .gas_limit(100_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid deploy tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, funding_sats)], vec![revert_deploy]),
        )
        .expect("block executes even though the tx reverts");

        let out = &outcome.tx_outcomes[0];
        assert!(!out.success, "the deploy reverted");
        assert_eq!(out.created_address, None, "no contract is created on revert");
        assert!(
            out.gas_used > 21_000,
            "a revert still consumes intrinsic + execution gas"
        );

        // Fees are routed even for a failed-but-included transaction: a revert
        // is never free, and bridged BLCH is never burned.
        let base_part = U256::from(base_fee) * U256::from(out.gas_used);
        let tip_part = U256::from(tip) * U256::from(out.gas_used);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);

        // The nonce still advanced, and supply is conserved.
        assert_eq!(state.nonce_of(&ALICE), 1);
        assert!(conserved(&state));
    }

    #[test]
    fn priority_fee_is_capped_by_max_fee_per_gas() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei (first block)
        let funding_sats = 10 * SATS_PER_BLCH;

        // The caller asks for a 2 gwei tip but caps total at 2 gwei per gas.
        // Effective price = min(max_fee, base_fee + priority) = 2 gwei, so only
        // 1 gwei of tip can actually be realized above the 1 gwei base fee.
        let requested_tip: u128 = 2 * GWEI;
        let max_fee: u128 = 2 * GWEI;
        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(max_fee)
            .gas_priority_fee(Some(requested_tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx");

        let outcome = execute_block(&spec, &mut state, genesis(vec![deposit(ALICE, funding_sats)], vec![tx]))
            .expect("block executes");

        let realized_tip: u128 = GWEI; // capped down from the requested 2 gwei
        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(realized_tip) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        // The realized tip is strictly less than the requested tip — the cap
        // (the `min` in revm's effective-price calc) actually bit.
        assert!(U256::from(requested_tip) * U256::from(21_000u64) > tip_part);
        assert!(conserved(&state));
    }

    #[test]
    fn legacy_tx_routes_gas_price_minus_basefee_as_tip() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei
        let funding_sats = 10 * SATS_PER_BLCH;

        // A legacy (type-0) transaction carries no priority-fee field; it pays
        // its full gas price and the executor routes (gas_price - base_fee) to
        // the sequencer vault.
        let gas_price: u128 = 3 * GWEI;
        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .gas_price(gas_price)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid legacy tx");
        assert_eq!(tx.tx_type, 0, "derived as a legacy transaction");
        assert!(tx.gas_priority_fee.is_none());

        let outcome = execute_block(&spec, &mut state, genesis(vec![deposit(ALICE, funding_sats)], vec![tx]))
            .expect("block executes");

        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(gas_price - base_fee as u128) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        assert!(conserved(&state));
    }

    /// C13 regression: the block environment is validated against the committed
    /// head — base fee rule, number continuity, timestamp monotonicity — and a
    /// chain's first block must carry the initial base fee.
    #[test]
    fn block_header_is_validated_against_the_head() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // A first block with a zero base fee (the old test blessed it) is rejected.
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext {
                    base_fee_per_gas: 0,
                    ..BlockContext::default()
                },
                deposits: vec![deposit(ALICE, 10 * SATS_PER_BLCH)],
                txs: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::InvalidBaseFee { got: 0, .. }));
        assert_eq!(fingerprint(&state), fingerprint(&L2State::new()));

        // Genesis: block 0, timestamp 1000 (its one deposit is metered gas).
        let genesis = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext {
                    number: 0,
                    timestamp: 1_000,
                    ..BlockContext::default()
                },
                deposits: vec![deposit(ALICE, 10 * SATS_PER_BLCH)],
                txs: vec![],
            },
        )
        .unwrap();
        assert_eq!(genesis.gas_used, spec.deposit_gas);
        let before = fingerprint(&state);
        let expected_bf = spec.next_base_fee(spec.initial_base_fee, genesis.gas_used);
        assert_ne!(expected_bf, spec.initial_base_fee);
        let good = BlockContext {
            number: 1,
            timestamp: 1_002,
            base_fee_per_gas: expected_bf,
            ..BlockContext::default()
        };
        assert_eq!(BlockContext::next(&spec, &state).base_fee_per_gas, expected_bf);
        assert_eq!(BlockContext::next(&spec, &state).number, 1);

        for bad_bf in [0u64, spec.initial_base_fee, 5 * GWEI as u64] {
            let ctx = BlockContext {
                base_fee_per_gas: bad_bf,
                ..good.clone()
            };
            let err = execute_block(
                &spec,
                &mut state,
                BlockInput {
                    context: ctx,
                    deposits: vec![],
                    txs: vec![tx_at_fee(ALICE, BOB, 0, U256::from(1u64), 21_000, bad_bf)],
                },
            )
            .unwrap_err();
            assert!(
                matches!(err, BlockExecutionError::InvalidBaseFee { expected, got } if expected == expected_bf && got == bad_bf),
                "{err}"
            );
            assert_eq!(fingerprint(&state), before);
        }
        for bad_number in [0u64, 2, 7] {
            let ctx = BlockContext {
                number: bad_number,
                ..good.clone()
            };
            let err = execute_block(
                &spec,
                &mut state,
                BlockInput {
                    context: ctx,
                    deposits: vec![],
                    txs: vec![],
                },
            )
            .unwrap_err();
            assert!(
                matches!(err, BlockExecutionError::InvalidBlockNumber { expected: 1, got } if got == bad_number),
                "{err}"
            );
            assert_eq!(fingerprint(&state), before);
        }
        let ctx = BlockContext {
            timestamp: 999,
            ..good.clone()
        };
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: ctx,
                deposits: vec![],
                txs: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::InvalidTimestamp {
                parent: 1_000,
                got: 999
            }
        ));
        assert_eq!(fingerprint(&state), before);

        // The conforming header is accepted and routes fees per the 1559 split.
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: good.clone(),
                deposits: vec![],
                txs: vec![tx_at_fee(ALICE, BOB, 0, U256::from(1u64), 21_000, expected_bf)],
            },
        )
        .expect("conforming header executes");
        assert_eq!(out.base_fee_per_gas, expected_bf);
        assert_eq!(out.base_fee_routed_wei, U256::from(expected_bf) * U256::from(21_000u64));
        assert_eq!(
            state.balance_of(&spec.base_fee_vault),
            U256::from(expected_bf) * U256::from(21_000u64)
        );
        let head = state.head().unwrap();
        assert_eq!(
            (head.number, head.timestamp, head.base_fee_per_gas, head.gas_used),
            (1, 1_002, expected_bf, 21_000)
        );
        // Equal timestamps are allowed (non-decreasing).
        exec_next(&spec, &mut state, vec![], vec![]).unwrap();
        assert_eq!(state.head().unwrap().timestamp, 1_002);
    }

    /// C16 regression: BLOCKHASH returns committed L2 block hashes (header
    /// hashes chained through the ring buffer), never a placeholder.
    #[test]
    fn blockhash_serves_committed_l2_block_hashes() {
        let spec = ChainSpec::testnet();
        // Probe contract: PUSH1 0 BLOCKHASH PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN,
        // parameterized on the queried number via calldata: CALLDATALOAD(0).
        //   runtime: 60 00 35 40 60 00 52 60 20 60 00 f3
        let runtime = [0x60, 0x00, 0x35, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let mut state = L2State::new();
        let out0 = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext {
                    number: 0,
                    ..BlockContext::default()
                },
                deposits: vec![deposit(ALICE, 10 * SATS_PER_BLCH)],
                txs: vec![],
            },
        )
        .unwrap();
        let bf1 = BlockContext::next(&spec, &state).base_fee_per_gas;
        let deploy = TxEnv::builder()
            .caller(ALICE)
            .create()
            .data(deployer(&runtime))
            .gas_limit(200_000)
            .max_fee_per_gas(bf1 as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();
        let out1 = exec_next(&spec, &mut state, vec![], vec![deploy]).unwrap();
        let probe = out1.tx_outcomes[0].created_address.unwrap();
        assert!(out1.tx_outcomes[0].success);
        assert_eq!(out1.header.parent_hash, out0.block_hash, "block 1 links to block 0");
        assert_eq!(
            state.block_hash(0),
            Some(out0.block_hash),
            "ring holds hash(0) after block 1"
        );
        assert_eq!(state.block_hash(1), None, "hash(1) is only known after block 2 starts");

        // Block 2: query BLOCKHASH(0), BLOCKHASH(1), BLOCKHASH(2) (self), BLOCKHASH(9).
        let query = |n: u64, nonce: u64, bf: u64| {
            TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(probe))
                .data(Bytes::from(U256::from(n).to_be_bytes::<32>().to_vec()))
                .gas_limit(100_000)
                .max_fee_per_gas(bf as u128 + GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(nonce)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap()
        };
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;
        let out2 = exec_next(
            &spec,
            &mut state,
            vec![],
            vec![query(0, 1, bf), query(1, 2, bf), query(2, 3, bf), query(9, 4, bf)],
        )
        .unwrap();
        let word = |i: usize| B256::from_slice(out2.tx_outcomes[i].result.output().unwrap());
        assert_eq!(word(0), out0.block_hash, "BLOCKHASH(0) is block 0's header hash");
        assert_eq!(word(1), out1.block_hash, "BLOCKHASH(1) is block 1's header hash");
        assert_eq!(word(2), B256::ZERO, "the current block has no hash yet");
        assert_eq!(
            word(3),
            B256::ZERO,
            "future / nonexistent blocks are zero, never a placeholder"
        );
        assert_ne!(word(0), keccak256(b"0"), "never revm's EmptyDB placeholder");
        assert_eq!(out2.header.parent_hash, out1.block_hash);
        assert_eq!(state.block_hash(1), Some(out1.block_hash));

        // Two chains whose block 0 differs have different block hashes.
        let mut other = L2State::new();
        let o0 = execute_block(
            &spec,
            &mut other,
            BlockInput {
                context: BlockContext {
                    number: 0,
                    ..BlockContext::default()
                },
                deposits: vec![deposit(ALICE, 11 * SATS_PER_BLCH)],
                txs: vec![],
            },
        )
        .unwrap();
        assert_ne!(o0.block_hash, out0.block_hash);
    }

    /// C17 regression: the EIP-4788 system call runs at block start against the
    /// canonical predeploy with the block's anchor root.
    #[test]
    fn eip4788_system_call_stores_the_anchor_root() {
        let spec = ChainSpec::testnet();
        const T: u64 = 1_700_000_000;
        let anchor = B256::repeat_byte(0xA7);

        // The predeploy is visible at genesis via L2State::genesis, and is
        // materialized by the STF for a bare L2State::new() as well.
        let g = L2State::genesis(&spec);
        let acct = g.account(&BEACON_ROOTS_ADDRESS).expect("predeploy at genesis");
        assert_eq!(acct.code_hash, keccak256(crate::chainspec::BEACON_ROOTS_CODE));
        assert_eq!(acct.nonce, 1);

        let get = |nonce: u64, ts: u64| {
            TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(BEACON_ROOTS_ADDRESS))
                .gas_limit(100_000)
                .data(Bytes::from(U256::from(ts).to_be_bytes::<32>().to_vec()))
                .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
                .gas_priority_fee(Some(GWEI))
                .nonce(nonce)
                .chain_id(Some(spec.chain_id))
                .build()
                .unwrap()
        };
        let mut state = L2State::new();
        let out = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext {
                    number: 1,
                    timestamp: T,
                    anchor_root: anchor,
                    ..BlockContext::default()
                },
                deposits: vec![deposit(ALICE, 10 * SATS_PER_BLCH)],
                txs: vec![get(0, T), get(1, T + 1)],
            },
        )
        .expect("block executes");
        // get(block.timestamp) returns the anchor root stored by the system call.
        let same_ts = &out.tx_outcomes[0];
        assert!(same_ts.success);
        assert_eq!(same_ts.result.output().unwrap().as_ref(), anchor.as_slice());
        // get(unknown timestamp) reverts, per EIP-4788.
        assert!(!out.tx_outcomes[1].success);
        // Ring-buffer slots as the spec lays them out.
        let slots = &state.db().cache.accounts[&BEACON_ROOTS_ADDRESS].storage;
        assert_eq!(slots[&U256::from(T % 8191)], U256::from(T));
        assert_eq!(slots[&U256::from(T % 8191 + 8191)], U256::from_be_bytes(anchor.0));
        assert_eq!(
            state.account(&BEACON_ROOTS_ADDRESS).unwrap().code_hash,
            keccak256(crate::chainspec::BEACON_ROOTS_CODE)
        );
        assert_eq!(out.header.anchor_root, anchor);
        assert!(conserved(&state), "the system call mints and burns nothing");
    }

    /// C15 regression: only EIP-155-protected transactions for this chain are
    /// accepted; unprotected legacy transactions are rejected at the boundary.
    #[test]
    fn unprotected_or_foreign_chain_id_transactions_are_rejected() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, 10 * SATS_PER_BLCH)], vec![]),
        )
        .unwrap();
        let before = fingerprint(&state);
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;
        for chain_id in [None, Some(1u64), Some(10), Some(spec.chain_id + 1)] {
            let t = TxEnv::builder()
                .caller(ALICE)
                .kind(TxKind::Call(BOB))
                .value(U256::from(1u64))
                .gas_limit(21_000)
                .gas_price(bf as u128 + GWEI)
                .nonce(0)
                .chain_id(chain_id)
                .build()
                .unwrap();
            assert_eq!(t.tx_type, 0);
            let err = exec_next(&spec, &mut state, vec![], vec![t]).unwrap_err();
            assert!(
                matches!(err, BlockExecutionError::ChainIdMismatch { tx_index: 0, got } if got == chain_id),
                "{err}"
            );
            assert_eq!(fingerprint(&state), before);
        }
        // The protected legacy tx for this chain executes.
        let ok = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .value(U256::from(1u64))
            .gas_limit(21_000)
            .gas_price(bf as u128 + GWEI)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();
        exec_next(&spec, &mut state, vec![], vec![ok]).unwrap();
        assert_eq!(state.balance_of(&BOB), U256::from(1u64));
    }

    /// C11 regression: an EIP-6780 self-destruct-to-self burn is measured and
    /// recorded in the committed ledger; the invariant is
    /// `native == minted - burned`, and fees still route correctly.
    #[test]
    fn eip6780_burn_is_accounted_in_the_ledger() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, 10 * SATS_PER_BLCH)], vec![]),
        )
        .unwrap();
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;
        let value = sats_to_wei(SATS_PER_BLCH);
        // CREATE with initcode `ADDRESS SELFDESTRUCT` (0x30ff) and 1 BLCH of value.
        let burn_tx = TxEnv::builder()
            .caller(ALICE)
            .create()
            .value(value)
            .data(bytes!("30ff"))
            .gas_limit(100_000)
            .max_fee_per_gas(bf as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();
        // Control: SELFDESTRUCT to BOB in the creating tx moves value, burns nothing.
        let mut to_bob = vec![0x73u8];
        to_bob.extend_from_slice(BOB.as_slice());
        to_bob.push(0xff);
        let move_tx = TxEnv::builder()
            .caller(ALICE)
            .create()
            .value(value)
            .data(Bytes::from(to_bob))
            .gas_limit(100_000)
            .max_fee_per_gas(bf as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(1)
            .chain_id(Some(spec.chain_id))
            .build()
            .unwrap();
        let out = exec_next(&spec, &mut state, vec![], vec![burn_tx, move_tx]).unwrap();
        assert!(out.tx_outcomes[0].success && out.tx_outcomes[1].success);
        assert_eq!(
            out.tx_outcomes[0].burned_wei, value,
            "the self-destructed value is measured"
        );
        assert_eq!(out.tx_outcomes[1].burned_wei, U256::ZERO);
        assert_eq!(out.burned_wei, value);
        assert_eq!(state.total_burned_wei(), value, "committed in the ledger");
        assert_eq!(state.balance_of(&BOB), value);
        assert!(state.account(&ALICE.create(0)).is_none(), "EIP-6780: destroyed");
        assert_eq!(
            state.total_native_wei(),
            state.total_minted_wei() - state.total_burned_wei()
        );
        // Fees of both txs are fully routed.
        let gas = U256::from(out.gas_used);
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::from(bf) * gas);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), U256::from(GWEI) * gas);
        // The burn total is committed: it moves the root.
        let root = compute_keccak_mpt_state_root(&state);
        state
            .db_mut()
            .insert_account_storage(spec.supply_ledger, SUPPLY_LEDGER_BURNED_SLOT, U256::ZERO)
            .unwrap();
        assert_ne!(compute_keccak_mpt_state_root(&state), root);
    }

    #[test]
    fn block_gas_limit_exceeded_is_rejected_without_touching_state() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, 10 * SATS_PER_BLCH)], vec![]),
        )
        .unwrap();
        let before = fingerprint(&state);
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;

        // A single transaction whose gas limit alone exceeds the 30M block
        // limit is rejected by input validation, before anything runs.
        let err = exec_next(
            &spec,
            &mut state,
            vec![],
            vec![tx_at_fee(ALICE, BOB, 0, U256::ZERO, spec.gas_limit + 1, bf)],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::TxGasLimitExceedsBlock { tx_index: 0 }
        ));
        assert_eq!(fingerprint(&state), before);

        // Cumulative overflow at index 1 (after a valid, committed tx 0) is
        // rejected too — and tx 0 is rolled back with the block.
        let err = exec_next(
            &spec,
            &mut state,
            vec![deposit(BOB, 1)],
            vec![
                tx_at_fee(ALICE, BOB, 0, sats_to_wei(1), 21_000, bf),
                tx_at_fee(ALICE, BOB, 1, U256::ZERO, spec.gas_limit, bf),
            ],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::BlockGasLimitExceeded { tx_index: 1 }
        ));
        assert_eq!(
            fingerprint(&state),
            before,
            "the whole block (tx 0 and the deposit) is rolled back"
        );
        assert_eq!(state.nonce_of(&ALICE), 0);
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
    }

    /// C01 regression: any rejection leaves the caller's state byte-identical
    /// to the pre-block state (no wipe, no partial advance).
    #[test]
    fn evm_errors_leave_state_unchanged() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            genesis(
                vec![deposit(ALICE, 10 * SATS_PER_BLCH), deposit(BOB, 5 * SATS_PER_BLCH)],
                vec![],
            ),
        )
        .unwrap();
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;
        exec_next(
            &spec,
            &mut state,
            vec![],
            vec![tx_at_fee(ALICE, BOB, 0, sats_to_wei(SATS_PER_BLCH), 21_000, bf)],
        )
        .unwrap();
        let before = fingerprint(&state);
        assert_ne!(before.0, EMPTY_ROOT_HASH);
        assert_eq!(state.nonce_of(&ALICE), 1);
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;

        // (a) stale / future nonce at index 1, after a valid tx 0 and a deposit.
        let err = exec_next(
            &spec,
            &mut state,
            vec![deposit(BOB, 1)],
            vec![
                tx_at_fee(ALICE, BOB, 1, U256::ZERO, 21_000, bf),
                tx_at_fee(ALICE, BOB, 7, U256::ZERO, 21_000, bf),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 1, .. }));
        assert_eq!(fingerprint(&state), before);
        assert_eq!(state.nonce_of(&ALICE), 1, "tx 0 of the failed block is rolled back");

        // (b) insufficient balance for max fee.
        let err = exec_next(
            &spec,
            &mut state,
            vec![],
            vec![tx_at_fee(ALICE, BOB, 1, sats_to_wei(100 * SATS_PER_BLCH), 21_000, bf)],
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 0, .. }));
        assert_eq!(fingerprint(&state), before);

        // (c) chain-id mismatch is caught by input validation.
        let mut t = tx_at_fee(ALICE, BOB, 1, U256::ZERO, 21_000, bf);
        t.chain_id = Some(1);
        let err = exec_next(&spec, &mut state, vec![], vec![t]).unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::ChainIdMismatch {
                tx_index: 0,
                got: Some(1)
            }
        ));
        assert_eq!(fingerprint(&state), before);

        // (d) a replayed deposit fails the block and rolls back everything.
        let dep = deposit(BOB, 1);
        exec_next(&spec, &mut state, vec![dep], vec![]).unwrap();
        let after_dep = fingerprint(&state);
        let fresh = deposit(ALICE, 1);
        // [replayed, fresh] is in position order, so it reaches the ledger check
        // and fails there; [fresh, replayed] is rejected by pure validation.
        let err = exec_next(&spec, &mut state, vec![dep, fresh], vec![]).unwrap_err();
        assert!(
            matches!(err, BlockExecutionError::Deposit(DepositError::OutOfOrder { .. })),
            "{err}"
        );
        assert_eq!(fingerprint(&state), after_dep);
        let err = exec_next(&spec, &mut state, vec![fresh, dep], vec![]).unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::DepositsOutOfOrder {
                first_index: 0,
                second_index: 1
            }
        ));
        assert_eq!(
            fingerprint(&state),
            after_dep,
            "the fresh deposit of the failed block is rolled back too"
        );

        // The state is still fully usable afterwards.
        let bf = BlockContext::next(&spec, &state).base_fee_per_gas;
        exec_next(
            &spec,
            &mut state,
            vec![],
            vec![tx_at_fee(ALICE, BOB, 1, U256::ZERO, 21_000, bf)],
        )
        .unwrap();
        assert_eq!(state.nonce_of(&ALICE), 2);
        assert!(conserved(&state));
    }

    /// C10 regression: the same L1 escrow cannot mint twice, within a block or
    /// across blocks, and deposits must advance the committed cursor.
    #[test]
    fn deposit_outpoint_mints_at_most_once() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let dep = deposit(ALICE, SATS_PER_BLCH);

        let err = execute_block(&spec, &mut state, genesis(vec![dep, dep], vec![])).unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::DepositsOutOfOrder {
                first_index: 0,
                second_index: 1
            }
        ));
        assert_eq!(state.total_minted_wei(), U256::ZERO);

        execute_block(&spec, &mut state, genesis(vec![dep], vec![])).unwrap();
        assert_eq!(state.deposit_cursor(), dep.position());
        let before = fingerprint(&state);
        for _ in 0..3 {
            let err = exec_next(&spec, &mut state, vec![dep], vec![]).unwrap_err();
            assert!(matches!(
                err,
                BlockExecutionError::Deposit(DepositError::OutOfOrder { .. })
            ));
            assert_eq!(fingerprint(&state), before);
        }
        // Two deposits in the same L1 block: tx index / vout order is enforced.
        let a = DepositMint {
            recipient: BOB,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1_000_000,
                l1_tx_index: 3,
                l1_txid: [1; 32],
                l1_vout: 1,
                l1_sats: 5,
            },
        };
        let b = DepositMint {
            recipient: BOB,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1_000_000,
                l1_tx_index: 3,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 5,
            },
        };
        assert!(matches!(
            exec_next(&spec, &mut state, vec![a, b], vec![]),
            Err(BlockExecutionError::DepositsOutOfOrder {
                first_index: 0,
                second_index: 1
            })
        ));
        exec_next(&spec, &mut state, vec![b, a], vec![]).unwrap();
        assert_eq!(state.deposit_cursor(), a.position());
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(SATS_PER_BLCH));
        assert_eq!(state.balance_of(&BOB), sats_to_wei(10));
        assert_eq!(state.total_minted_wei(), sats_to_wei(SATS_PER_BLCH + 10));
    }

    /// C03 regression: only types 0/1/2 reach revm; a zero-priced custom type
    /// can neither execute nor inflate the supply.
    #[test]
    fn unsupported_tx_types_are_rejected_and_never_inflate_supply() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, 10 * SATS_PER_BLCH)], vec![]),
        )
        .unwrap();
        let before = fingerprint(&state);

        for tx_type in [4u8, 5, 0x10, 0x7E, 0xFF] {
            let mut t = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
            t.tx_type = tx_type;
            t.gas_price = 0;
            t.gas_priority_fee = None;
            let err = exec_next(&spec, &mut state, vec![], vec![t]).unwrap_err();
            assert!(
                matches!(err, BlockExecutionError::UnsupportedTxType { tx_index: 0, tx_type: t } if t == tx_type),
                "type {tx_type:#x}: {err}"
            );
            assert_eq!(fingerprint(&state), before);
        }
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::ZERO);
        assert!(conserved(&state));

        // Inconsistent envs are rejected too (a legacy env carrying a tip, a
        // 1559 env without one).
        let mut legacy_with_tip = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
        legacy_with_tip.tx_type = 0;
        let err = exec_next(&spec, &mut state, vec![], vec![legacy_with_tip]).unwrap_err();
        assert!(matches!(err, BlockExecutionError::InconsistentTxEnv { tx_index: 0 }));
        let mut eip1559_without_tip = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
        eip1559_without_tip.gas_priority_fee = None;
        let err = exec_next(&spec, &mut state, vec![], vec![eip1559_without_tip]).unwrap_err();
        assert!(matches!(err, BlockExecutionError::InconsistentTxEnv { tx_index: 0 }));
        assert_eq!(fingerprint(&state), before);
    }

    /// C19 regression: a deposit above the L1 hard cap is rejected at input
    /// validation; the cumulative cap holds across blocks.
    #[test]
    fn deposits_above_the_l1_cap_are_rejected() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let err = execute_block(&spec, &mut state, genesis(vec![deposit(ALICE, u64::MAX)], vec![])).unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::Deposit(DepositError::ExceedsL1Supply { .. })
        ));
        assert_eq!(fingerprint(&state), fingerprint(&L2State::new()));

        execute_block(
            &spec,
            &mut state,
            genesis(vec![deposit(ALICE, spec.max_l1_sats)], vec![]),
        )
        .unwrap();
        let err = exec_next(&spec, &mut state, vec![deposit(BOB, 1)], vec![]).unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::Deposit(DepositError::CumulativeSupplyExceeded { .. })
        ));
        assert_eq!(state.total_minted_wei(), sats_to_wei(spec.max_l1_sats));
    }

    #[test]
    fn deposits_hash_and_header_hash_are_canonical() {
        let a = deposit(ALICE, 5);
        let b = deposit(BOB, 6);
        assert_eq!(deposits_hash(&[]), keccak256([]));
        assert_eq!(deposits_hash(&[a, b]), deposits_hash(&[a, b]));
        assert_ne!(deposits_hash(&[a, b]), deposits_hash(&[b, a]), "order is committed");
        assert_ne!(deposits_hash(&[a]), deposits_hash(&[a, b]));

        let h = L2Header {
            chain_id: 700_771,
            number: 7,
            timestamp: 1_700_000_000,
            base_fee_per_gas: 1_000_000_000,
            gas_used: 21_000,
            prevrandao: B256::repeat_byte(1),
            anchor_root: B256::repeat_byte(2),
            parent_hash: B256::repeat_byte(3),
            deposits_hash: B256::repeat_byte(4),
            state_root: B256::repeat_byte(5),
        };
        assert_eq!(h.hash(), h.hash());
        let mut h2 = h;
        h2.state_root = B256::repeat_byte(6);
        assert_ne!(h.hash(), h2.hash());
        let mut h3 = h;
        h3.chain_id += 1;
        assert_ne!(h.hash(), h3.hash(), "chain id is part of the domain");
    }
}
