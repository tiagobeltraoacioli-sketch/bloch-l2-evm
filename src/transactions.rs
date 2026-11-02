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

use crate::executor::{run_block, BlockRun, BlockSession};

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

/// Authenticate a raw Ethereum transaction using the pinned Alloy implementation.
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
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_deposits"))]
    pub deposits: Vec<DepositMint>,
    /// Canonical signed Ethereum envelopes in sequencer order.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_transactions"))]
    pub transactions: Vec<Bytes>,
}

#[cfg(feature = "serde")]
fn deserialize_deposits<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<DepositMint>, D::Error> {
    crate::serde_bounded::vector::<_, _, { crate::node_primitives::MAX_NODE_DEPOSITS }>(deserializer)
}

#[cfg(feature = "serde")]
fn deserialize_transactions<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Bytes>, D::Error> {
    crate::serde_bounded::byte_vectors::<_, MAX_SIGNED_TRANSACTIONS, MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES>(
        deserializer,
    )
}

/// Authentication failure or the existing executor/proving error.
#[derive(Debug)]
pub enum SignedInputError<E> {
    /// Rejected before executing the candidate. Whole-block authentication
    /// happens before any block execution; a builder may have earlier candidates.
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
    // Crate-private: network callers cannot authenticate once, mutate a TxEnv,
    // then submit it through the signed execution/proving boundary.
    pub(crate) fn authenticate<E>(&self, spec: &ChainSpec) -> Result<BlockInput, SignedInputError<E>> {
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

/// Incremental signed block construction over an immutable host snapshot.
///
/// Header rules, system calls and authenticated-by-host deposits run once at
/// construction. Each candidate is reauthenticated from its original bytes.
/// Rejected or conditionally skipped transactions publish no state, gas or fee
/// changes. A reverted EVM transaction remains valid and may be included.
///
/// Attempt budgets include rejected and skipped candidates, bounding recovery
/// work for this builder's lifetime. Pool scheduling and network rate limiting
/// remain the caller's responsibility. This is not a pool or Reth node.
#[must_use = "finish the builder or drop it to discard the provisional block"]
pub struct SignedBlockBuilder<DB> {
    session: BlockSession<DB>,
    spec: ChainSpec,
    input: SignedBlockInput,
    attempted_transactions: usize,
    attempted_bytes: usize,
}

impl<DB: DatabaseRef> SignedBlockBuilder<DB> {
    /// Begin a block using a consistent snapshot and its trusted root.
    ///
    /// The caller must independently authenticate deposits and L1 context.
    /// Neither this constructor nor finishing verifies the supplied state root.
    pub fn new(
        spec: &ChainSpec,
        database: DB,
        previous_root: B256,
        context: BlockContext,
        deposits: Vec<DepositMint>,
    ) -> Result<Self, SignedInputError<BlockExecutionError>> {
        let input = SignedBlockInput {
            context,
            deposits,
            transactions: Vec::new(),
        };
        // Apply the same spec/deposit limits before any provider access.
        input.authenticate::<BlockExecutionError>(spec)?;
        let session = BlockSession::begin(
            spec,
            CacheDB::new(database),
            previous_root,
            &input.context,
            &input.deposits,
        )
        .map_err(SignedInputError::Execution)?;
        Ok(Self {
            session,
            spec: spec.clone(),
            input,
            attempted_transactions: 0,
            attempted_bytes: 0,
        })
    }

    /// The accepted signed input so far. Context and deposits cannot be changed.
    pub fn input(&self) -> &SignedBlockInput {
        &self.input
    }

    /// Number of candidates charged to this builder's authentication budget.
    pub fn attempted_transactions(&self) -> usize {
        self.attempted_transactions
    }

    /// Authenticate and include a candidate if it executes as a valid transaction.
    pub fn try_push(&mut self, raw: &[u8]) -> Result<&crate::TxOutcome, SignedInputError<BlockExecutionError>> {
        self.try_push_with_condition(raw, |_| true)
            .map(|outcome| outcome.expect("unconditional inclusion"))
    }

    /// Inspect execution and include its effects only when `include` returns true.
    ///
    /// `Ok(None)` means the candidate was skipped. Errors and skips preserve the
    /// accepted block. Candidates sent to decoding consume authentication budget;
    /// cheap size/budget preflight failures do not. Error indices
    /// identify the next accepted transaction position, not the attempt count.
    pub fn try_push_with_condition(
        &mut self,
        raw: &[u8],
        include: impl FnOnce(&crate::TxOutcome) -> bool,
    ) -> Result<Option<&crate::TxOutcome>, SignedInputError<BlockExecutionError>> {
        let index = self.input.transactions.len();
        let auth_error = |reason| SignedInputError::Authentication {
            transaction_index: Some(index),
            reason,
        };
        if raw.len() > MAX_RAW_TRANSACTION_BYTES {
            return Err(auth_error(TransactionAuthError::TooLarge));
        }
        if self.attempted_transactions >= MAX_SIGNED_TRANSACTIONS {
            return Err(auth_error(TransactionAuthError::TooManyTransactions));
        }
        let bytes = self.attempted_bytes.checked_add(raw.len());
        if bytes.is_none_or(|bytes| bytes > MAX_SIGNED_BLOCK_BYTES) {
            return Err(auth_error(TransactionAuthError::BlockTooLarge));
        }
        self.attempted_transactions += 1;
        self.attempted_bytes = bytes.expect("checked authentication byte budget");
        let tx = decode_signed_transaction(&self.spec, raw).map_err(auth_error)?;
        let outcome = self
            .session
            .try_transaction(&tx.env, include)
            .map_err(SignedInputError::Execution)?;
        if outcome.is_some() {
            self.input.transactions.push(tx.raw);
        }
        Ok(outcome)
    }

    /// CANDIDATE (forced inclusion): run one forced envelope by the rule of
    /// [`crate::forced_inclusion`]; `Ok(None)` when it was included.
    #[cfg(feature = "forced-inclusion")]
    pub(crate) fn push_forced_one(
        &mut self,
        spec: &ChainSpec,
        forced: &crate::forced_inclusion::ForcedTransaction,
    ) -> Result<Option<crate::forced_inclusion::ForcedSkip>, BlockExecutionError> {
        let skip = crate::forced_inclusion::forced_step(spec, &mut self.session, forced)?;
        if skip.is_none() {
            self.attempted_transactions += 1;
            self.attempted_bytes = self.attempted_bytes.saturating_add(forced.envelope.len());
            self.input.transactions.push(forced.envelope.clone());
        }
        Ok(skip)
    }

    /// Finalize ledger/head changes and return the exact accepted signed input.
    ///
    /// Compute the complete post-state root from the returned execution overlay
    /// before its host finalization and atomic persistence. No backing write is
    /// performed here. A failure discards the entire provisional block.
    pub fn finish(
        self,
    ) -> Result<(SignedBlockInput, DatabaseBlockExecution<DB>), SignedInputError<BlockExecutionError>> {
        let (overlay, run) = self.session.finish().map_err(SignedInputError::Execution)?;
        let execution = DatabaseBlockExecution {
            overlay,
            run,
            chain_id: self.spec.chain_id,
            context: self.input.context.clone(),
        };
        Ok((self.input, execution))
    }
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
