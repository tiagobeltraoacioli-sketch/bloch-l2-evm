// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block executor: UNMODIFIED revm at `SpecId::CANCUN` over [`L2State`].
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** This is the state-transition
//! core only: no consensus, no txpool, no RPC. Per BLOCH-L2-EVM-DESIGN §1:
//!
//! * deposit mints (bridged BLCH only) are applied at block start, against the
//!   committed supply ledger (exact scaling, one mint per L1 outpoint, L1 cap);
//! * the EVM itself is unmodified revm at the pinned CANCUN hardfork;
//! * COINBASE / block beneficiary is the sequencer fee vault, so priority
//!   fees are paid there by revm's own (unmodified) beneficiary payment;
//! * the EIP-1559 basefee is NOT destroyed: the part of the effective gas
//!   price that revm actually charged up to the basefee is routed to the
//!   `BaseFeeVault` as protocol-level accounting between transactions
//!   (outside EVM opcode semantics — the OP-Stack precedent). The protocol
//!   never burns bridged BLCH;
//! * only transaction types 0, 1 and 2 are accepted at CANCUN; type 3 (blob)
//!   and every other type byte are rejected at this boundary.
//!
//! **Role and atomicity.** [`execute_block`] is the *verifier* state-transition
//! function: a block containing an invalid transaction is an invalid block
//! (Ethereum / OP-Stack semantics, and what a stateless guest must enforce).
//! Rejection is **non-destructive**: the whole block is validated, then applied
//! to a working copy, and the caller's state is replaced only on success — on
//! any `Err` it is byte-identical to the pre-block state, so a sequencer can
//! drop the offending transaction (identified by `tx_index`) and rebuild.
//! A separate block-*builder* entry point (skip invalid candidates, stop at the
//! gas limit) is not part of this scaffold.

use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use alloy_primitives::{keccak256, Address, B256, U256};
use revm::context::result::{ExecutionResult, HaltReason};
use revm::context::TxEnv;
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::context_interface::Transaction;
use revm::database::CacheDB;
use revm::{Context, DatabaseRef, ExecuteCommitEvm, MainBuilder, MainContext};

use crate::chainspec::ChainSpec;
use crate::state::{apply_deposit, credit_balance, DepositApplyError, DepositError, DepositMint, L2State};
use crate::stateroot::compute_keccak_mpt_state_root;

/// Per-block environment chosen by the sequencer (this scaffold has no
/// sequencer; tests supply it directly). **Not validated** against a parent
/// header by this scaffold (base fee rule, number/timestamp monotonicity) —
/// see the audit report, finding C13.
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// L2 block number.
    pub number: u64,
    /// Sequencer timestamp (monotonic, drift-bounded against the Bloch
    /// anchor in the full design; unchecked here).
    pub timestamp: u64,
    /// This block's EIP-1559 base fee per gas, in wei
    /// (see [`ChainSpec::next_base_fee`] for the update rule).
    pub base_fee_per_gas: u64,
    /// PREVRANDAO. In the full design this is
    /// `keccak256(parent_l2_block_hash ‖ bloch_anchor_block_hash)` and is
    /// documented as WEAK randomness, exactly as on every L2.
    pub prevrandao: B256,
}

/// Everything the executor consumes for one block.
#[derive(Debug, Clone, Default)]
pub struct BlockInput {
    /// Block environment.
    pub context: BlockContext,
    /// Deposit system-transactions, applied (minted) at block start, before
    /// any user transaction — they cannot be dropped once anchored.
    ///
    /// **Trust boundary:** the derivation layer must only hand over deposits
    /// that were really escrowed in a finalized Bloch block; the STF enforces
    /// exact scaling, one mint per outpoint (committed ledger) and the L1 cap,
    /// and commits the list via [`ExecutionOutcome::deposits_hash`].
    pub deposits: Vec<DepositMint>,
    /// User transactions in sequencer order. `TxEnv` is revm's transaction
    /// environment; signature recovery / RLP decoding belong to the (stubbed)
    /// node layer, not this scaffold. A block with an invalid transaction is
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
    /// Raw revm execution result (logs, output, halt reason...).
    pub result: ExecutionResult<HaltReason>,
}

/// Outcome of executing one block against [`L2State`].
#[derive(Debug)]
pub struct ExecutionOutcome {
    /// The block number executed.
    pub block_number: u64,
    /// Total gas used by all transactions in the block.
    pub gas_used: u64,
    /// The base fee this block executed under.
    pub base_fee_per_gas: u64,
    /// Wei minted by deposits at block start.
    pub minted_wei: U256,
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
}

/// Errors that abort block execution. The caller's [`L2State`] is left
/// **unchanged** on every variant.
#[derive(Debug)]
pub enum BlockExecutionError {
    /// A deposit mint violated the ledger rules (replay, L1 cap).
    Deposit(DepositError),
    /// The same L1 escrow outpoint appears twice in the block.
    DuplicateDeposit {
        /// Index of the first occurrence.
        first_index: usize,
        /// Index of the duplicate.
        second_index: usize,
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
    /// EIP-2930 env carrying a priority fee, or an EIP-1559 env without one).
    InconsistentTxEnv {
        /// Index of the offending transaction within the block.
        tx_index: usize,
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
    /// insufficient max-fee balance, chain-id mismatch, ...). Debug-printed
    /// revm error, since the concrete error type is generic over the DB.
    Evm {
        /// Index of the offending transaction within the block.
        tx_index: usize,
        /// Debug rendering of the revm error.
        detail: String,
    },
    /// The backing database failed while applying protocol-level accounting
    /// (deposits, fee routing) — e.g. a stateless guest touching an account
    /// its witness does not cover.
    Database {
        /// Debug rendering of the database error.
        detail: String,
    },
    /// `ChainSpec::block_reward` is not zero. The L2 never issues; a non-zero
    /// reward is a misconfiguration, not a payment.
    NonZeroBlockReward,
}

impl core::fmt::Display for BlockExecutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockExecutionError::Deposit(e) => write!(f, "deposit failed: {e}"),
            BlockExecutionError::DuplicateDeposit { first_index, second_index } => {
                write!(f, "deposits {first_index} and {second_index} share the same L1 outpoint")
            }
            BlockExecutionError::BlobTxRejected { tx_index } => {
                write!(f, "tx {tx_index}: blob (type-3) transactions are rejected at the sequencer")
            }
            BlockExecutionError::UnsupportedTxType { tx_index, tx_type } => {
                write!(f, "tx {tx_index}: transaction type {tx_type:#04x} is not supported at this hardfork")
            }
            BlockExecutionError::InconsistentTxEnv { tx_index } => {
                write!(f, "tx {tx_index}: TxEnv fields are inconsistent with its tx_type")
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
            BlockExecutionError::Database { detail } => write!(f, "database error: {detail}"),
            BlockExecutionError::NonZeroBlockReward => {
                write!(f, "ChainSpec::block_reward must be zero (the L2 never issues)")
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
/// `recipient ‖ l1_txid ‖ l1_vout (BE u32) ‖ l1_sats (BE u64)` for each deposit
/// in order (`keccak256("")` for no deposits). Binds a proof over the block to
/// the exact L1-derived deposits it minted.
pub fn deposits_hash(deposits: &[DepositMint]) -> B256 {
    let mut buf = Vec::with_capacity(deposits.len() * 64);
    for d in deposits {
        let (txid, vout) = d.outpoint();
        buf.extend_from_slice(d.recipient.as_slice());
        buf.extend_from_slice(&txid);
        buf.extend_from_slice(&vout.to_be_bytes());
        buf.extend_from_slice(&d.l1_sats().to_be_bytes());
    }
    keccak256(&buf)
}

/// Pure, state-independent validation of a [`BlockInput`] against the
/// [`ChainSpec`]: it depends on nothing but the input, so it runs before any
/// state is touched. Checks every deposit's L1 cap and intra-block uniqueness,
/// and every transaction's type, blob fields, `TxEnv` consistency and gas
/// limit. Stateful rules (deposit replay against the ledger, cumulative cap,
/// revm's own validation) are enforced during execution on the working copy.
pub fn validate_block_input(spec: &ChainSpec, input: &BlockInput) -> Result<(), BlockExecutionError> {
    if spec.block_reward != U256::ZERO {
        return Err(BlockExecutionError::NonZeroBlockReward);
    }
    let mut seen: BTreeSet<([u8; 32], u32)> = BTreeSet::new();
    let mut first_index_of: alloc::collections::BTreeMap<([u8; 32], u32), usize> = Default::default();
    for (i, d) in input.deposits.iter().enumerate() {
        if d.l1_sats() > spec.max_l1_sats {
            return Err(DepositError::ExceedsL1Supply { l1_sats: d.l1_sats(), max_l1_sats: spec.max_l1_sats }.into());
        }
        let op = d.outpoint();
        if !seen.insert(op) {
            return Err(BlockExecutionError::DuplicateDeposit { first_index: first_index_of[&op], second_index: i });
        }
        first_index_of.insert(op, i);
    }
    for (i, tx) in input.txs.iter().enumerate() {
        if tx.tx_type == BLOB_TX_TYPE || !tx.blob_hashes.is_empty() || tx.max_fee_per_blob_gas != 0 {
            return Err(BlockExecutionError::BlobTxRejected { tx_index: i });
        }
        if !SUPPORTED_TX_TYPES.contains(&tx.tx_type) {
            return Err(BlockExecutionError::UnsupportedTxType { tx_index: i, tx_type: tx.tx_type });
        }
        let is_1559 = tx.tx_type == 2;
        if is_1559 != tx.gas_priority_fee.is_some() {
            return Err(BlockExecutionError::InconsistentTxEnv { tx_index: i });
        }
        if tx.gas_limit > spec.gas_limit {
            return Err(BlockExecutionError::TxGasLimitExceedsBlock { tx_index: i });
        }
    }
    Ok(())
}

/// The per-block accounting a run produces (everything in [`ExecutionOutcome`]
/// except the state root, which needs the full post-state).
#[derive(Debug)]
pub(crate) struct BlockRun {
    pub(crate) gas_used: u64,
    pub(crate) minted_wei: U256,
    pub(crate) base_fee_routed_wei: U256,
    pub(crate) priority_fee_routed_wei: U256,
    pub(crate) tx_outcomes: Vec<TxOutcome>,
}

fn db_error<E: core::fmt::Debug>(e: E) -> BlockExecutionError {
    BlockExecutionError::Database { detail: format!("{e:?}") }
}

/// Execute one block against any `CacheDB`: validate the input, apply deposit
/// mints, then run every transaction through unmodified revm at the spec's
/// pinned hardfork, routing fees to the vaults. Consumes the database and
/// returns it only on success; the caller decides what the database was (a
/// working copy of the live state, a recording overlay, or a stateless guest
/// state).
pub(crate) fn run_block<ExtDB: DatabaseRef>(
    spec: &ChainSpec,
    mut db: CacheDB<ExtDB>,
    input: &BlockInput,
) -> Result<(CacheDB<ExtDB>, BlockRun), BlockExecutionError> {
    // 0. Input-only validation, before anything is touched.
    validate_block_input(spec, input)?;

    // 1. Deposit mints at block start (before any user tx). This is the ONLY
    //    place native balance is created; provenance is bridged BLCH only and
    //    every outpoint mints at most once (committed ledger).
    let mut minted_wei = U256::ZERO;
    for deposit in &input.deposits {
        let wei = apply_deposit(&mut db, spec, deposit).map_err(|e| match e {
            DepositApplyError::Deposit(d) => BlockExecutionError::Deposit(d),
            DepositApplyError::Db(e) => db_error(e),
        })?;
        minted_wei = minted_wei.checked_add(wei).expect("minted wei cannot overflow U256");
    }

    // 2. Build the EVM: UNMODIFIED revm, mainnet handler, pinned hardfork.
    //    The database is moved into the EVM context and recovered afterwards.
    let base_fee = input.context.base_fee_per_gas;
    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = spec.chain_id;
            // Sets both the spec and its mainnet gas params (CANCUN here).
            cfg.set_spec_and_mainnet_gas_params(spec.spec_id);
        })
        .modify_block_chained(|b| {
            b.number = U256::from(input.context.number);
            b.timestamp = U256::from(input.context.timestamp);
            b.gas_limit = spec.gas_limit;
            b.basefee = base_fee;
            // COINBASE = fee-vault address (design §1): priority fees are
            // paid to the beneficiary by revm's unmodified handler.
            b.beneficiary = spec.coinbase();
            b.prevrandao = Some(input.context.prevrandao);
            b.difficulty = U256::ZERO;
            // Blobless blocks: BLOBHASH / blob-basefee opcodes still return
            // spec-correct values (zero excess gas) for Cancun.
            b.blob_excess_gas_and_price =
                Some(BlobExcessGasAndPrice::new_with_spec(0, spec.spec_id));
        })
        .build_mainnet();

    // 3. Execute transactions in order, routing fees per tx.
    let mut tx_outcomes = Vec::with_capacity(input.txs.len());
    let mut block_gas_used: u64 = 0;
    let mut base_fee_routed = U256::ZERO;
    let mut priority_fee_routed = U256::ZERO;

    for (i, tx) in input.txs.iter().enumerate() {
        if block_gas_used.saturating_add(tx.gas_limit) > spec.gas_limit {
            return Err(BlockExecutionError::BlockGasLimitExceeded { tx_index: i });
        }
        // The effective gas price exactly as revm's handler computes it for this
        // TxEnv (type-aware): what the caller is charged per gas. revm pays
        // `effective - basefee` to the beneficiary and leaves the rest
        // uncredited; that rest — never more than the basefee — is routed here.
        let effective_gas_price = Transaction::effective_gas_price(tx, base_fee as u128);
        let base_fee_paid_per_gas = core::cmp::min(effective_gas_price, base_fee as u128);
        let priority_per_gas = effective_gas_price.saturating_sub(base_fee as u128);

        let result = evm
            .transact_commit(tx.clone())
            .map_err(|e| BlockExecutionError::Evm { tx_index: i, detail: format!("{e:?}") })?;

        // Receipt-level gas used (post-refund; unambiguous name after revm's
        // EIP-8037 state-gas split).
        let gas_used = result.tx_gas_used();
        block_gas_used += gas_used;

        // Route the basefee portion to the BaseFeeVault (never burn).
        // Protocol-level accounting between transactions, outside EVM opcode
        // semantics — the journal is empty here (transact_commit finalized),
        // so direct DB credit is safe.
        let base_fee_wei = U256::from(base_fee_paid_per_gas) * U256::from(gas_used);
        credit_balance(&mut evm.ctx.journaled_state.database, spec.base_fee_vault, base_fee_wei)
            .map_err(db_error)?;
        base_fee_routed = base_fee_routed.checked_add(base_fee_wei).expect("routed wei cannot overflow U256");
        // The priority portion was already paid to the beneficiary
        // (= SequencerFeeVault) by revm itself; track it for the outcome.
        priority_fee_routed = priority_fee_routed
            .checked_add(U256::from(priority_per_gas) * U256::from(gas_used))
            .expect("routed wei cannot overflow U256");

        tx_outcomes.push(TxOutcome {
            success: result.is_success(),
            gas_used,
            created_address: result.created_address(),
            result,
        });
    }

    // 4. Recover the database (block reward is ZERO by design — checked in
    //    validate_block_input; issuance is deposits only).
    let db = evm.ctx.journaled_state.database;
    Ok((
        db,
        BlockRun {
            gas_used: block_gas_used,
            minted_wei,
            base_fee_routed_wei: base_fee_routed,
            priority_fee_routed_wei: priority_fee_routed,
            tx_outcomes,
        },
    ))
}

/// Execute one block: validate it, apply deposit mints, then run every
/// transaction through unmodified revm at the spec's pinned hardfork, routing
/// fees to the vaults.
///
/// **Atomic:** the block is applied to a working copy of `state`; `state` is
/// replaced only when the whole block succeeded and is left byte-identical to
/// the pre-block state on every `Err`. Returns the [`ExecutionOutcome`].
pub fn execute_block(
    spec: &ChainSpec,
    state: &mut L2State,
    input: BlockInput,
) -> Result<ExecutionOutcome, BlockExecutionError> {
    let work = state.db.clone();
    let (db, run) = run_block(spec, work, &input)?;
    state.db = db;

    Ok(ExecutionOutcome {
        block_number: input.context.number,
        gas_used: run.gas_used,
        base_fee_per_gas: input.context.base_fee_per_gas,
        minted_wei: run.minted_wei,
        deposits_hash: deposits_hash(&input.deposits),
        base_fee_routed_wei: run.base_fee_routed_wei,
        priority_fee_routed_wei: run.priority_fee_routed_wei,
        tx_outcomes: run.tx_outcomes,
        // Real keccak-256 MPT state root over the post-execution state.
        state_root: compute_keccak_mpt_state_root(state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::sats_to_wei;
    use crate::state::DepositProvenance;
    use alloy_primitives::{address, bytes, Bytes, TxKind};
    use alloy_trie::EMPTY_ROOT_HASH;
    use core::sync::atomic::{AtomicU32, Ordering};

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");

    const GWEI: u128 = 1_000_000_000;

    static NEXT_VOUT: AtomicU32 = AtomicU32::new(0);

    /// A deposit with a fresh, unique L1 outpoint.
    fn deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_txid: [7; 32],
                l1_vout: NEXT_VOUT.fetch_add(1, Ordering::Relaxed),
                l1_sats,
            },
        }
    }

    fn transfer(from: Address, to: Address, nonce: u64, value: U256, gas_limit: u64) -> TxEnv {
        let spec = ChainSpec::testnet();
        TxEnv::builder()
            .caller(from)
            .kind(TxKind::Call(to))
            .value(value)
            .gas_limit(gas_limit)
            .max_fee_per_gas(spec.initial_base_fee as u128 + GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(nonce)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx env")
    }

    /// Init code that deploys a 10-byte runtime returning uint256(42) on any
    /// call:
    ///   runtime: 602a60005260206000f3
    ///     PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    ///   initcode: PUSH10 <runtime> PUSH1 0 MSTORE PUSH1 10 PUSH1 22 RETURN
    fn return42_initcode() -> Bytes {
        bytes!("69602a60005260206000f3600052600a6016f3")
    }

    /// Snapshot of everything an error must leave untouched.
    fn fingerprint(state: &L2State) -> (B256, U256, U256, usize) {
        (
            compute_keccak_mpt_state_root(state),
            state.total_native_wei(),
            state.total_minted_wei(),
            state.db.cache.accounts.len(),
        )
    }

    #[test]
    fn value_transfer_state_transition() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei
        let tip: u128 = GWEI; // 1 gwei priority fee

        // Fund alice with 10 BLCH via a bridged deposit.
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;
        let transfer_wei = sats_to_wei(crate::scale::SATS_PER_BLCH); // 1 BLCH

        let tx = transfer(ALICE, BOB, 0, transfer_wei, 21_000);
        let deposits = vec![deposit(ALICE, funding_sats)];
        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: deposits.clone(), txs: vec![tx] },
        )
        .expect("block executes");

        // Tx-level assertions.
        assert_eq!(outcome.tx_outcomes.len(), 1);
        assert!(outcome.tx_outcomes[0].success);
        assert_eq!(outcome.tx_outcomes[0].gas_used, 21_000);
        assert_eq!(outcome.gas_used, 21_000);
        assert_eq!(outcome.deposits_hash, deposits_hash(&deposits));
        assert_eq!(outcome.state_root, compute_keccak_mpt_state_root(&state));

        // Post balances / nonces.
        let effective_price = base_fee as u128 + tip; // max fee covers both
        let gas_cost = U256::from(effective_price) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(funding_sats) - transfer_wei - gas_cost);
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
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
        assert_eq!(state.total_minted_wei(), sats_to_wei(funding_sats));
    }

    /// Stateless READ property (the guest re-executes from touched accounts
    /// only): a batch re-executes IDENTICALLY when the state is hydrated with
    /// ONLY the accounts it touches. The naive full-rebuild root over that
    /// partial state is of course different — the stateless root comes from
    /// [`crate::stateroot::stateless_new_root`] instead (see `proving.rs`).
    #[test]
    fn p0_stateless_read_reproduces_full_execution_but_root_needs_untouched_leaves() {
        let spec = ChainSpec::testnet();

        // Pre-state: fund ALICE plus five UNTOUCHED "noise" accounts (a setup
        // block with deposits only). These stand in for the rest of L2 state.
        let noise: Vec<Address> = (1u8..=5).map(|i| Address::from([i; 20])).collect();
        let mut s0 = L2State::new();
        let mut setup_deposits = vec![deposit(ALICE, 10 * crate::scale::SATS_PER_BLCH)];
        for n in &noise {
            setup_deposits.push(deposit(*n, 3 * crate::scale::SATS_PER_BLCH));
        }
        execute_block(
            &spec,
            &mut s0,
            BlockInput { context: BlockContext::default(), deposits: setup_deposits, txs: vec![] },
        )
        .expect("setup block executes");
        // 6 funded accounts + the supply-ledger system account.
        assert_eq!(s0.db.cache.accounts.len(), 2 + noise.len(), "7 accounts in pre-state");

        // The batch under test: ALICE -> BOB (touches ALICE, BOB, both vaults).
        let transfer_wei = sats_to_wei(crate::scale::SATS_PER_BLCH);
        let make_batch = || BlockInput {
            context: BlockContext { number: 2, ..BlockContext::default() },
            deposits: vec![],
            txs: vec![transfer(ALICE, BOB, 0, transfer_wei, 21_000)],
        };

        // FULL run (all accounts present).
        let mut full = s0.clone();
        let out_full = execute_block(&spec, &mut full, make_batch()).expect("full executes");

        // WITNESS run: hydrate a fresh state with ONLY the touched PRE-state —
        // here that is just ALICE (BOB and the vaults are created in-block).
        let mut witness = L2State::new();
        let alice_info = s0.db.cache.accounts.get(&ALICE).expect("alice in pre-state").info.clone();
        witness.db.insert_account_info(ALICE, alice_info);
        assert_eq!(witness.db.cache.accounts.len(), 1, "witness holds ONLY the touched account");
        let out_wit = execute_block(&spec, &mut witness, make_batch()).expect("witness executes");

        // (1) Stateless READ: identical execution from the touched subset alone.
        assert_eq!(out_full.tx_outcomes[0].success, out_wit.tx_outcomes[0].success);
        assert_eq!(out_full.tx_outcomes[0].gas_used, out_wit.tx_outcomes[0].gas_used);
        assert_eq!(full.balance_of(&ALICE), witness.balance_of(&ALICE));
        assert_eq!(full.balance_of(&BOB), witness.balance_of(&BOB));
        assert_eq!(full.balance_of(&spec.base_fee_vault), witness.balance_of(&spec.base_fee_vault));
        assert_eq!(full.nonce_of(&ALICE), witness.nonce_of(&ALICE));
        for n in &noise {
            assert!(!witness.db.cache.accounts.contains_key(n), "noise account never loaded");
        }

        // (2) The naive full rebuild over the partial state is not the real root.
        assert_ne!(
            crate::compute_keccak_mpt_state_root(&full),
            crate::compute_keccak_mpt_state_root(&witness),
            "witness-only naive root differs — the stateless root needs the untouched sibling hashes"
        );
    }

    #[test]
    fn contract_deploy_and_call() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee;
        let tip: u128 = GWEI;
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

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
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![deploy, call],
            },
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
        assert_eq!(outcome.gas_used, total_gas);
        let effective_price = base_fee as u128 + tip;
        assert_eq!(
            state.balance_of(&ALICE),
            sats_to_wei(funding_sats) - U256::from(effective_price) * U256::from(total_gas)
        );
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::from(base_fee) * U256::from(total_gas));
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), U256::from(tip) * U256::from(total_gas));

        // Conservation: zero issuance, never burn.
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn deposit_mint_total_supply_is_sum_of_mints() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // Two deposit-only blocks, no user txs: pure mint accounting.
        for (block, sats) in [(1u64, 5_000u64), (2u64, 123_456_789u64)] {
            let outcome = execute_block(
                &spec,
                &mut state,
                BlockInput {
                    context: BlockContext { number: block, ..BlockContext::default() },
                    deposits: vec![deposit(ALICE, sats), deposit(BOB, sats / 2 + 1)],
                    txs: vec![],
                },
            )
            .expect("deposit-only block executes");
            assert_eq!(outcome.gas_used, 0);
            assert_eq!(outcome.minted_wei, sats_to_wei(sats) + sats_to_wei(sats / 2 + 1));
        }

        let expected = sats_to_wei(5_000) + sats_to_wei(2_501) + sats_to_wei(123_456_789) + sats_to_wei(61_728_395);
        // total supply == sum of mints (zero issuance).
        assert_eq!(state.total_minted_wei(), expected);
        assert_eq!(state.total_native_wei(), expected);
    }

    #[test]
    fn blob_transactions_are_rejected_at_the_sequencer_without_touching_state() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, 1_000_000)], txs: vec![] },
        )
        .unwrap();
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

        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 2, ..Default::default() },
                deposits: vec![deposit(BOB, 1_000_000)],
                txs: vec![blob_tx],
            },
        )
        .unwrap_err();
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
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

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
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![revert_deploy],
            },
        )
        .expect("block executes even though the tx reverts");

        let out = &outcome.tx_outcomes[0];
        assert!(!out.success, "the deploy reverted");
        assert_eq!(out.created_address, None, "no contract is created on revert");
        assert!(out.gas_used > 21_000, "a revert still consumes intrinsic + execution gas");

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
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn priority_fee_is_capped_by_max_fee_per_gas() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei (BlockContext::default)
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

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

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, funding_sats)], txs: vec![tx] },
        )
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
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn legacy_tx_routes_gas_price_minus_basefee_as_tip() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

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

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, funding_sats)], txs: vec![tx] },
        )
        .expect("block executes");

        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(gas_price - base_fee as u128) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn zero_basefee_routes_nothing_to_the_base_fee_vault() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let tip: u128 = GWEI;
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(tip) // base fee 0 + up to 1 gwei tip
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { base_fee_per_gas: 0, ..BlockContext::default() },
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![tx],
            },
        )
        .expect("block executes at zero base fee");

        // Zero base fee routes nothing to the BaseFeeVault; the whole effective
        // price is priority and lands in the SequencerFeeVault.
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::ZERO);
        assert_eq!(outcome.base_fee_routed_wei, U256::ZERO);
        let tip_part = U256::from(tip) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn block_gas_limit_exceeded_is_rejected_without_touching_state() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, 10 * crate::scale::SATS_PER_BLCH)], txs: vec![] },
        )
        .unwrap();
        let before = fingerprint(&state);

        // A single transaction whose gas limit alone exceeds the 30M block
        // limit is rejected by input validation, before anything runs.
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 2, ..Default::default() },
                deposits: vec![],
                txs: vec![transfer(ALICE, BOB, 0, U256::ZERO, spec.gas_limit + 1)],
            },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::TxGasLimitExceedsBlock { tx_index: 0 }));
        assert_eq!(fingerprint(&state), before);

        // Cumulative overflow at index 1 (after a valid, committed tx 0) is
        // rejected too — and tx 0 is rolled back with the block.
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 2, ..Default::default() },
                deposits: vec![deposit(BOB, 1)],
                txs: vec![
                    transfer(ALICE, BOB, 0, sats_to_wei(1), 21_000),
                    transfer(ALICE, BOB, 1, U256::ZERO, spec.gas_limit),
                ],
            },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::BlockGasLimitExceeded { tx_index: 1 }));
        assert_eq!(fingerprint(&state), before, "the whole block (tx 0 and the deposit) is rolled back");
        assert_eq!(state.nonce_of(&ALICE), 0);
        assert_eq!(state.balance_of(&BOB), U256::ZERO);
    }

    /// C01 regression: any revm-level rejection leaves the caller's state
    /// byte-identical to the pre-block state (no wipe, no partial advance).
    #[test]
    fn evm_errors_leave_state_unchanged() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, 10 * crate::scale::SATS_PER_BLCH), deposit(BOB, 5 * crate::scale::SATS_PER_BLCH)],
                txs: vec![],
            },
        )
        .unwrap();
        execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 2, ..Default::default() },
                deposits: vec![],
                txs: vec![transfer(ALICE, BOB, 0, sats_to_wei(crate::scale::SATS_PER_BLCH), 21_000)],
            },
        )
        .unwrap();
        let before = fingerprint(&state);
        assert_ne!(before.0, EMPTY_ROOT_HASH);
        assert_eq!(state.nonce_of(&ALICE), 1);

        // (a) stale / future nonce at index 1, after a valid tx 0.
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 3, ..Default::default() },
                deposits: vec![deposit(BOB, 1)],
                txs: vec![transfer(ALICE, BOB, 1, U256::ZERO, 21_000), transfer(ALICE, BOB, 7, U256::ZERO, 21_000)],
            },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 1, .. }));
        assert_eq!(fingerprint(&state), before);
        assert_eq!(state.nonce_of(&ALICE), 1, "tx 0 of the failed block is rolled back");

        // (b) insufficient balance for max fee.
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 3, ..Default::default() },
                deposits: vec![],
                txs: vec![transfer(ALICE, BOB, 1, sats_to_wei(100 * crate::scale::SATS_PER_BLCH), 21_000)],
            },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 0, .. }));
        assert_eq!(fingerprint(&state), before);

        // (c) chain-id mismatch.
        let mut t = transfer(ALICE, BOB, 1, U256::ZERO, 21_000);
        t.chain_id = Some(1);
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext { number: 3, ..Default::default() }, deposits: vec![], txs: vec![t] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Evm { tx_index: 0, .. }));
        assert_eq!(fingerprint(&state), before);

        // (d) a replayed deposit fails the block and rolls back everything.
        let dep = deposit(BOB, 1);
        execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext { number: 3, ..Default::default() }, deposits: vec![dep], txs: vec![] },
        )
        .unwrap();
        let after_dep = fingerprint(&state);
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 4, ..Default::default() },
                deposits: vec![deposit(ALICE, 1), dep],
                txs: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Deposit(DepositError::Replay { .. })));
        assert_eq!(fingerprint(&state), after_dep, "the first deposit of the failed block is rolled back too");

        // The state is still fully usable afterwards.
        execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext { number: 4, ..Default::default() },
                deposits: vec![],
                txs: vec![transfer(ALICE, BOB, 1, U256::ZERO, 21_000)],
            },
        )
        .unwrap();
        assert_eq!(state.nonce_of(&ALICE), 2);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    /// C10 regression: the same L1 outpoint cannot mint twice, within a block
    /// or across blocks.
    #[test]
    fn deposit_outpoint_mints_at_most_once() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let dep = deposit(ALICE, crate::scale::SATS_PER_BLCH);

        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![dep, dep], txs: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::DuplicateDeposit { first_index: 0, second_index: 1 }));
        assert_eq!(state.total_minted_wei(), U256::ZERO);

        execute_block(&spec, &mut state, BlockInput { context: BlockContext::default(), deposits: vec![dep], txs: vec![] })
            .unwrap();
        let before = fingerprint(&state);
        for n in 2..5u64 {
            let err = execute_block(
                &spec,
                &mut state,
                BlockInput { context: BlockContext { number: n, ..Default::default() }, deposits: vec![dep], txs: vec![] },
            )
            .unwrap_err();
            assert!(matches!(err, BlockExecutionError::Deposit(DepositError::Replay { .. })));
            assert_eq!(fingerprint(&state), before);
        }
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(crate::scale::SATS_PER_BLCH));
        assert_eq!(state.total_minted_wei(), sats_to_wei(crate::scale::SATS_PER_BLCH));
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
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, 10 * crate::scale::SATS_PER_BLCH)], txs: vec![] },
        )
        .unwrap();
        let before = fingerprint(&state);

        for tx_type in [4u8, 5, 0x10, 0x7E, 0xFF] {
            let mut t = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
            t.tx_type = tx_type;
            t.gas_price = 0;
            t.gas_priority_fee = None;
            let err = execute_block(
                &spec,
                &mut state,
                BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![], txs: vec![t] },
            )
            .unwrap_err();
            assert!(
                matches!(err, BlockExecutionError::UnsupportedTxType { tx_index: 0, tx_type: t } if t == tx_type),
                "type {tx_type:#x}: {err}"
            );
            assert_eq!(fingerprint(&state), before);
        }
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::ZERO);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());

        // Inconsistent envs are rejected too (a legacy env carrying a tip, a
        // 1559 env without one).
        let mut legacy_with_tip = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
        legacy_with_tip.tx_type = 0;
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![], txs: vec![legacy_with_tip] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::InconsistentTxEnv { tx_index: 0 }));
        let mut eip1559_without_tip = transfer(ALICE, BOB, 0, U256::ZERO, 21_000);
        eip1559_without_tip.gas_priority_fee = None;
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![], txs: vec![eip1559_without_tip] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::InconsistentTxEnv { tx_index: 0 }));
        assert_eq!(fingerprint(&state), before);
    }

    /// C19 regression: a deposit above the L1 hard cap is rejected at input
    /// validation; the cumulative cap holds across blocks.
    #[test]
    fn deposits_above_the_l1_cap_are_rejected() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, u64::MAX)], txs: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Deposit(DepositError::ExceedsL1Supply { .. })));
        assert_eq!(fingerprint(&state), fingerprint(&L2State::new()));

        execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext::default(), deposits: vec![deposit(ALICE, spec.max_l1_sats)], txs: vec![] },
        )
        .unwrap();
        let err = execute_block(
            &spec,
            &mut state,
            BlockInput { context: BlockContext { number: 2, ..Default::default() }, deposits: vec![deposit(BOB, 1)], txs: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, BlockExecutionError::Deposit(DepositError::CumulativeSupplyExceeded { .. })));
        assert_eq!(state.total_minted_wei(), sats_to_wei(spec.max_l1_sats));
    }

    #[test]
    fn deposits_hash_is_canonical() {
        let a = deposit(ALICE, 5);
        let b = deposit(BOB, 6);
        assert_eq!(deposits_hash(&[]), keccak256([]));
        assert_eq!(deposits_hash(&[a, b]), deposits_hash(&[a, b]));
        assert_ne!(deposits_hash(&[a, b]), deposits_hash(&[b, a]), "order is committed");
        assert_ne!(deposits_hash(&[a]), deposits_hash(&[a, b]));
    }
}
