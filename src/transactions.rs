// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicitly classical L2 wallet boundary. Native Bloch L1 authorization is PQ.
//!
//! Network input is canonical signed Ethereum bytes, never a caller supplied in
//! a `TxEnv`. The same recovery runs in execution and witness verification. This
//! module provides no RPC, pool, L1 escrow authentication or proof-system binding.

use alloc::vec::Vec;
use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::{
    eip2718::{Decodable2718, Encodable2718},
    Typed2718,
};
use alloy_primitives::{Address, Bytes, B256};
use revm::context::TxEnv;
use revm::{database::CacheDB, DatabaseRef};

use crate::executor::{run_block, BlockRun};

use crate::{
    execute_block, generate_batch_witness, verify_batch, BatchWitness, BlockContext, BlockExecutionError, BlockInput,
    ChainSpec, DepositMint, ExecutionOutcome, GenerateError, L2State, VerifiedBatch, VerifyError,
};

/// Maximum encoded user transaction size, checked before RLP decoding.
pub const MAX_RAW_TRANSACTION_BYTES: usize = 128 * 1024;
/// Maximum encoded user bytes per block, checked before recovery/allocation.
pub const MAX_SIGNED_BLOCK_BYTES: usize = 16 * 1024 * 1024;
/// Independent bound on signature recoveries per block; EVM gas limits also apply.
pub const MAX_SIGNED_TRANSACTIONS: usize = 4096;

/// Rejection at the signed L2 input boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionAuthError {
    /// Chain parameters failed validation.
    InvalidChainSpec,
    /// No transaction bytes were supplied.
    Empty,
    /// The raw transaction exceeds the decoding budget.
    TooLarge,
    /// Only protected legacy, EIP-2930 and EIP-1559 are supported at Cancun.
    UnsupportedType,
    /// The upstream Ethereum envelope decoder rejected the bytes.
    InvalidEncoding,
    /// Trailing data or a noncanonical envelope was supplied.
    NonCanonical,
    /// Unprotected legacy signatures have no EIP-155 replay domain.
    UnprotectedLegacy,
    /// The signed chain ID does not match this L2.
    WrongChain,
    /// EIP-2 requires low-S signatures; normalization is not acceptance.
    HighS,
    /// The signature cannot recover an Ethereum sender.
    InvalidSignature,
    /// The block exceeds the independent transaction-count bound.
    TooManyTransactions,
    /// Aggregate raw transaction bytes exceed the block decoding budget.
    BlockTooLarge,
    /// The trusted derivation list exceeds the configured deposit-count bound.
    TooManyDeposits,
}

impl core::fmt::Display for TransactionAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "L2 signed input rejected: {self:?}")
    }
}
impl core::error::Error for TransactionAuthError {}

/// A sender recovered from canonical, domain-checked ECDSA bytes.
///
/// Fields are private and this type cannot be deserialized. A read-only `TxEnv`
/// is available for pool validation; cloning/mutating that environment loses the
/// authentication guarantee and must never replace the original signed bytes.
#[derive(Clone, Debug)]
pub struct AuthenticatedTransaction {
    env: TxEnv,
    hash: B256,
    raw: Bytes,
}

impl AuthenticatedTransaction {
    /// Recovered Ethereum sender (classical secp256k1 security).
    pub fn sender(&self) -> Address {
        self.env.caller
    }
    /// Canonical Ethereum transaction hash, suitable for RPC/pool identity.
    pub fn hash(&self) -> B256 {
        self.hash
    }
    /// Original canonical signed transaction bytes.
    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
    /// Authenticated execution fields for read-only pool inspection.
    pub fn environment(&self) -> &TxEnv {
        &self.env
    }
}

/// Authenticate a raw Ethereum transaction for this L2, using pinned Alloy/k256.
///
/// This verifies encoding, replay domain and signature, not state-dependent
/// validity. Nonce, balance, intrinsic gas and fees are checked by the executor.
pub fn decode_signed_transaction(
    spec: &ChainSpec,
    raw: &[u8],
) -> Result<AuthenticatedTransaction, TransactionAuthError> {
    spec.validate().map_err(|_| TransactionAuthError::InvalidChainSpec)?;
    if raw.len() > MAX_RAW_TRANSACTION_BYTES {
        return Err(TransactionAuthError::TooLarge);
    }
    let first = *raw.first().ok_or(TransactionAuthError::Empty)?;
    if first != 1 && first != 2 && first < 0xc0 {
        return Err(TransactionAuthError::UnsupportedType);
    }
    let mut rest = raw;
    let envelope = TxEnvelope::decode_2718(&mut rest).map_err(|_| TransactionAuthError::InvalidEncoding)?;
    if !rest.is_empty() || envelope.encoded_2718() != raw {
        return Err(TransactionAuthError::NonCanonical);
    }
    let chain_id = envelope.chain_id().ok_or(TransactionAuthError::UnprotectedLegacy)?;
    if chain_id != spec.chain_id {
        return Err(TransactionAuthError::WrongChain);
    }
    if envelope.signature().normalize_s().is_some() {
        return Err(TransactionAuthError::HighS);
    }
    let caller = envelope
        .recover_signer()
        .map_err(|_| TransactionAuthError::InvalidSignature)?;
    let env = TxEnv {
        tx_type: envelope.ty(),
        caller,
        gas_limit: envelope.gas_limit(),
        gas_price: envelope.max_fee_per_gas(),
        kind: envelope.kind(),
        value: envelope.value(),
        data: envelope.input().clone(),
        nonce: envelope.nonce(),
        chain_id: Some(chain_id),
        access_list: envelope.access_list().cloned().unwrap_or_default(),
        gas_priority_fee: envelope.max_priority_fee_per_gas(),
        ..TxEnv::default()
    };
    Ok(AuthenticatedTransaction {
        env,
        hash: *envelope.tx_hash(),
        raw: Bytes::copy_from_slice(raw),
    })
}

/// Node/guest input preserving signatures instead of trusting `TxEnv::caller`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedBlockInput {
    /// Header context, validated against committed state by the executor.
    pub context: BlockContext,
    /// Trusted finalized-L1 derivation input; NEVER accepted from a wallet RPC.
    /// Signature recovery does not authenticate escrow provenance.
    pub deposits: Vec<DepositMint>,
    /// Canonical signed Ethereum envelopes in sequencer order.
    pub transactions: Vec<Bytes>,
}

/// Authentication failure or the existing executor/proving error.
#[derive(Debug)]
pub enum SignedInputError<E> {
    /// Rejected before any execution/state mutation.
    Authentication {
        /// The zero-based transaction index, or `None` for a block-wide bound.
        transaction_index: Option<usize>,
        /// Why the signed input failed validation.
        reason: TransactionAuthError,
    },
    /// State-dependent execution or witness verification failed.
    Execution(E),
}
impl<E: core::fmt::Display> core::fmt::Display for SignedInputError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Authentication {
                transaction_index,
                reason,
            } => write!(f, "{reason} (index {transaction_index:?})"),
            Self::Execution(error) => error.fmt(f),
        }
    }
}
impl<E: core::error::Error + 'static> core::error::Error for SignedInputError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(match self {
            Self::Authentication { reason, .. } => reason,
            Self::Execution(error) => error,
        })
    }
}

impl SignedBlockInput {
    // Private: callers cannot authenticate once, mutate a TxEnv, then submit it
    // through the signed execution/proving boundary.
    fn authenticate<E>(&self, spec: &ChainSpec) -> Result<BlockInput, SignedInputError<E>> {
        let block_error = |reason| SignedInputError::Authentication {
            transaction_index: None,
            reason,
        };
        spec.validate()
            .map_err(|_| block_error(TransactionAuthError::InvalidChainSpec))?;
        if self.transactions.len() > MAX_SIGNED_TRANSACTIONS {
            return Err(block_error(TransactionAuthError::TooManyTransactions));
        }
        if self.deposits.len() as u64 > spec.max_deposits_per_block() {
            return Err(block_error(TransactionAuthError::TooManyDeposits));
        }
        let total = self
            .transactions
            .iter()
            .try_fold(0usize, |total, raw| total.checked_add(raw.len()));
        if total.is_none_or(|total| total > MAX_SIGNED_BLOCK_BYTES) {
            return Err(block_error(TransactionAuthError::BlockTooLarge));
        }
        // Preflight every per-transaction size before doing any cryptography.
        for (index, raw) in self.transactions.iter().enumerate() {
            if raw.len() > MAX_RAW_TRANSACTION_BYTES {
                return Err(SignedInputError::Authentication {
                    transaction_index: Some(index),
                    reason: TransactionAuthError::TooLarge,
                });
            }
        }
        let mut txs = Vec::with_capacity(self.transactions.len());
        for (index, raw) in self.transactions.iter().enumerate() {
            let tx = decode_signed_transaction(spec, raw).map_err(|reason| SignedInputError::Authentication {
                transaction_index: Some(index),
                reason,
            })?;
            txs.push(tx.env);
        }
        Ok(BlockInput {
            context: self.context.clone(),
            deposits: self.deposits.clone(),
            txs,
        })
    }
}

/// Authenticate every sender and execute atomically. Use for signed node input.
pub fn execute_signed_block(
    spec: &ChainSpec,
    state: &mut L2State,
    input: &SignedBlockInput,
) -> Result<ExecutionOutcome, SignedInputError<BlockExecutionError>> {
    let authenticated = input.authenticate(spec)?;
    execute_block(spec, state, authenticated).map_err(SignedInputError::Execution)
}

/// A successfully executed block over a read-only host database.
///
/// The private overlay contains only loaded/changed accounts, not the complete
/// post-state. No state has been persisted, and no post-state root has been
/// calculated or authenticated. Drop this value to discard the candidate.
#[must_use = "execution is provisional until the host computes and commits its state root"]
pub struct DatabaseBlockExecution<DB> {
    overlay: CacheDB<DB>,
    run: BlockRun,
    chain_id: u64,
    context: BlockContext,
}

impl<DB> DatabaseBlockExecution<DB> {
    /// Read the successful overlay before calculating the full post-state root.
    ///
    /// Use the backing database for untouched state. Loaded accounts are not
    /// necessarily changed accounts; cleared storage and deleted/empty accounts
    /// must follow revm/EIP-161 semantics when translating to host persistence.
    pub fn overlay(&self) -> &CacheDB<DB> {
        &self.overlay
    }

    /// Attach a host-calculated root and return the overlay and execution result.
    ///
    /// `post_state_root` is a trusted host input: this method does not verify it.
    /// The host must compute the complete MPT root from the unchanged backing
    /// snapshot plus this overlay and atomically persist the matching changes.
    /// The returned header retains Bloch's existing hash format; it is not an
    /// Ethereum RLP header, a proof, or an authenticated execution-domain receipt.
    pub fn finalize(self, post_state_root: B256) -> (CacheDB<DB>, ExecutionOutcome) {
        let outcome = self.run.into_outcome(self.chain_id, &self.context, post_state_root);
        (self.overlay, outcome)
    }
}

/// Authenticate signed envelopes and execute against an arbitrary host database.
///
/// This uses the same block kernel as [`execute_signed_block`], including
/// deposit gas/cursors, vault fee routing, supply accounting, EIP-4788 and the
/// committed Bloch block-hash ring. It creates a fresh overlay and never invokes
/// a write/commit method on `database`. Errors return no candidate overlay.
/// Database implementations may still perform interior read-cache bookkeeping.
///
/// The host must provide an immutable, consistent pre-state snapshot and its
/// correct `previous_root`; the root is not authenticated here. In particular,
/// supplying a wrong root can change parent/BLOCKHASH commitments without a
/// database read error. Deposits and L1 context likewise require independent
/// authentication. Use [`verify_signed_batch`] or an execution domain when an
/// untrusted proposal requires authenticated witness/root verification.
///
/// This is a whole-block execution adapter, not a transaction pool, incremental
/// payload builder, persistent database or Reth node.
pub fn execute_signed_block_on_database<DB: DatabaseRef>(
    spec: &ChainSpec,
    database: DB,
    previous_root: B256,
    input: &SignedBlockInput,
) -> Result<DatabaseBlockExecution<DB>, SignedInputError<BlockExecutionError>> {
    let authenticated = input.authenticate(spec)?;
    let (overlay, run) =
        run_block(spec, CacheDB::new(database), previous_root, &authenticated).map_err(SignedInputError::Execution)?;
    Ok(DatabaseBlockExecution {
        overlay,
        run,
        chain_id: spec.chain_id,
        context: input.context.clone(),
    })
}

/// Generate a witness from original signed bytes on the host.
pub fn generate_signed_batch_witness(
    pre: &L2State,
    spec: &ChainSpec,
    input: &SignedBlockInput,
) -> Result<(BatchWitness, ExecutionOutcome), SignedInputError<GenerateError>> {
    let authenticated = input.authenticate(spec)?;
    generate_batch_witness(pre, spec, authenticated).map_err(SignedInputError::Execution)
}

/// Recheck signatures INSIDE the guest procedure, then verify/re-execute state.
///
/// A real prover must also bind the expected pre-root, chain/program identity,
/// ordered transaction commitment and finalized-L1 derivation as public inputs.
/// This wrapper alone is not a rollup proof or a transaction-root commitment.
pub fn verify_signed_batch(
    spec: &ChainSpec,
    witness: &BatchWitness,
    input: &SignedBlockInput,
) -> Result<VerifiedBatch, SignedInputError<VerifyError>> {
    let authenticated = input.authenticate(spec)?;
    verify_batch(spec, witness, &authenticated).map_err(SignedInputError::Execution)
}
