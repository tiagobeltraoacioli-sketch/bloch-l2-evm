// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol phases for a caller-owned EVM and provisional mutable database.
//!
//! Each preparation finishes all reads before its commit. A whole block is NOT
//! atomic on arbitrary `DatabaseCommit`: discard the provisional database on
//! any later failure. The caller supplies a matching EVM environment, authentic
//! signed transactions and system-call results, authenticated deposits/anchors,
//! and the independently calculated roots. These are trusted backend interfaces.
use super::*;
use crate::protocol_overlay::{stage_protocol, PreparedProtocolChanges};

/// Header/ring and beacon-account changes, not yet committed.
#[must_use = "commit to begin the system-call phase, or drop to discard"]
pub struct PreparedBlockStart {
    changes: PreparedProtocolChanges,
    next: PendingSystemCall,
}

/// The header prefix is committed; the supplied EVM must now run EIP-4788.
#[must_use = "execute the system call or discard the provisional block database"]
pub struct PendingSystemCall {
    active: ActiveBlock,
    deposits: Vec<DepositMint>,
}

/// Protocol bookkeeping after the system call and deposits have committed.
/// Dropping this object does not undo changes to the caller's database.
pub struct ActiveBlock {
    spec: ChainSpec,
    context: BlockContext,
    run: BlockRun,
}

/// A prepared candidate borrowing its originating block's accounting.
/// Dropping it leaves accounting and database state unchanged.
#[must_use = "commit the candidate or drop it to skip"]
pub struct PreparedBlockTransaction<'a> {
    block: &'a mut ActiveBlock,
    transaction: PreparedTransaction,
}

/// Final ledger/head changes, with all reads and validation completed.
#[must_use = "commit final protocol changes or discard the block"]
pub struct PreparedBlockFinish {
    changes: PreparedProtocolChanges,
    block: ActiveBlock,
}

/// A committed block awaiting the independently computed post-state root.
#[must_use = "compute the post-state root and finalize the outcome"]
pub struct FinishedBlock(ActiveBlock);

/// Validate the complete supplied input and prepare the header/beacon prefix.
///
/// No writes occur on error or when the returned value is dropped. Commit to
/// the same logical pre-state before executing the supplied EVM's system call.
/// For incremental construction, pass an empty transaction list; validate each
/// later candidate through [`ActiveBlock::validate_transaction`].
pub fn prepare_block_start<DB: Database>(
    spec: &ChainSpec,
    db: &mut DB,
    previous_root: B256,
    input: &BlockInput,
) -> Result<PreparedBlockStart, BlockExecutionError> {
    validate_block_input(spec, input)?;
    let (changes, parent_hash) = stage_protocol(db, |overlay| {
        let (parent_hash, _) = apply_header_update(spec, overlay, previous_root, &input.context)?;
        ensure_system_account(overlay, BEACON_ROOTS_ADDRESS, Some(&beacon_roots_bytecode())).map_err(db_error)?;
        Ok(parent_hash)
    })?;
    Ok(PreparedBlockStart {
        changes,
        next: PendingSystemCall {
            active: ActiveBlock {
                spec: spec.clone(),
                context: input.context.clone(),
                run: BlockRun {
                    gas_used: deposits_gas(spec, input)?,
                    minted_wei: U256::ZERO,
                    burned_wei: U256::ZERO,
                    deposits_hash: deposits_hash(&input.deposits),
                    parent_hash,
                    base_fee_routed_wei: U256::ZERO,
                    priority_fee_routed_wei: U256::ZERO,
                    tx_outcomes: Vec::new(),
                },
            },
            deposits: input.deposits.clone(),
        },
    })
}

impl PreparedBlockStart {
    /// Commit to the same provisional database used for preparation.
    pub fn commit(self, db: &mut impl DatabaseCommit) -> PendingSystemCall {
        self.changes.commit(db);
        self.next
    }
}

impl PendingSystemCall {
    /// Commit a successful, matching EIP-4788 result, then prepare and commit
    /// the entire deposit batch. On any error discard the provisional block
    /// database: the earlier header prefix may already have committed.
    pub fn complete<DB: Database + DatabaseCommit>(
        mut self,
        result: ResultAndState<HaltReason>,
        db: &mut DB,
    ) -> Result<ActiveBlock, BlockExecutionError> {
        if !result.result.is_success() {
            return Err(BlockExecutionError::SystemCall {
                detail: format!("{:?}", result.result),
            });
        }
        db.commit(result.state);
        let (changes, minted) =
            stage_protocol(db, |overlay| apply_deposits(overlay, &self.active.spec, &self.deposits))?;
        changes.commit(db);
        self.active.run.minted_wei = minted;
        Ok(self.active)
    }
}

impl ActiveBlock {
    /// Validate type, chain, environment shape and remaining block gas before
    /// executing a candidate. Signature authentication is the caller's job.
    pub fn validate_transaction(&self, tx: &TxEnv) -> Result<(), BlockExecutionError> {
        let index = self.run.tx_outcomes.len();
        validate_transaction(&self.spec, tx, index)?;
        if self.run.gas_used.saturating_add(tx.gas_limit) > self.spec.gas_limit {
            return Err(BlockExecutionError::BlockGasLimitExceeded { tx_index: index });
        }
        Ok(())
    }

    /// Reconcile a matching, uncommitted EVM result and borrow its originating
    /// block until the candidate is committed or discarded. The caller must
    /// preserve the database pre-state between execution, preparation and commit.
    pub fn prepare_transaction<'a, DB: Database>(
        &'a mut self,
        tx: &TxEnv,
        result: ResultAndState<HaltReason>,
        db: &mut DB,
    ) -> Result<PreparedBlockTransaction<'a>, BlockExecutionError> {
        self.validate_transaction(tx)?;
        let transaction = prepare_transaction_effects(
            &self.spec,
            self.context.base_fee_per_gas,
            tx,
            self.run.tx_outcomes.len(),
            result,
            db,
        )?;
        Ok(PreparedBlockTransaction {
            block: self,
            transaction,
        })
    }

    /// Prepare the burned-supply ledger and committed head together.
    pub fn prepare_finish<DB: Database>(self, db: &mut DB) -> Result<PreparedBlockFinish, BlockExecutionError> {
        let (changes, ()) = stage_protocol(db, |overlay| {
            finish_protocol(overlay, &self.spec, &self.context, &self.run)
        })?;
        Ok(PreparedBlockFinish { changes, block: self })
    }
}

impl PreparedBlockTransaction<'_> {
    /// Inspect the outcome when deciding whether to include this candidate.
    pub fn outcome(&self) -> &TxOutcome {
        self.transaction.outcome()
    }

    /// Commit effects and advance the originating block's accounting once.
    pub fn commit(self, db: &mut impl DatabaseCommit) {
        self.block.run.record(self.transaction.commit(db));
    }
}

impl PreparedBlockFinish {
    /// Commit the final protocol phase to its unchanged provisional pre-state.
    pub fn commit(self, db: &mut impl DatabaseCommit) -> FinishedBlock {
        self.changes.commit(db);
        FinishedBlock(self.block)
    }
}

impl FinishedBlock {
    /// Attach the caller's independently computed full post-state root.
    /// This method trusts that root; it neither calculates nor authenticates it.
    pub fn finalize(self, state_root: B256) -> ExecutionOutcome {
        self.0
            .run
            .into_outcome(self.0.spec.chain_id, &self.0.context, state_root)
    }
}
