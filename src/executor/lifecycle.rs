// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol phases for a caller-owned EVM and provisional mutable database.
//!
//! Each preparation finishes all reads before its commit. A whole block is NOT
//! atomic on arbitrary `DatabaseCommit`: discard the provisional database on
//! any later failure. The caller supplies a matching EVM environment, authentic
//! signed transactions and system-call results, authenticated deposits/anchors,
//! and the independently calculated roots. These are trusted backend interfaces.
use super::*;
use crate::node_execution::{NodeExecutionError, NodeExecutionOutcome, PendingOutcome};
use crate::node_primitives::NodeBodyV2;
use crate::protocol_overlay::{stage_protocol, PreparedProtocolChanges};

#[derive(Clone, Copy)]
enum HeaderPolicy {
    V1,
    Node { domain: B256, previous_root: B256 },
}

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
    block_hashes: Vec<(u64, B256)>,
}

/// Protocol bookkeeping after the system call and deposits have committed.
/// Dropping this object does not undo changes to the caller's database.
pub struct ActiveBlock {
    spec: ChainSpec,
    context: BlockContext,
    run: BlockRun,
    header_policy: HeaderPolicy,
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

/// Read-complete V2 ledger/head writes and actual user receipts.
#[must_use = "commit V2 final effects or discard the provisional block"]
pub struct PreparedNodeBlockFinish {
    changes: PreparedProtocolChanges,
    finished: FinishedNodeBlock,
}

/// Committed V2 metadata awaiting the independently calculated state root.
#[must_use = "calculate the post-state root and finalize the V2 outcome"]
pub struct FinishedNodeBlock {
    spec: ChainSpec,
    domain: B256,
    pending: PendingOutcome,
}

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
    prepare_start(spec, db, previous_root, input, HeaderPolicy::V1)
}

/// Prepare the explicit V2 header/beacon prefix on a provisional database.
/// Domain and previous root must be trusted. As with the V1 backend interface,
/// callers authenticate signed transactions and L1 provenance independently.
pub fn prepare_node_block_start<DB: Database>(
    spec: &ChainSpec,
    domain: B256,
    db: &mut DB,
    previous_root: B256,
    input: &BlockInput,
) -> Result<PreparedBlockStart, BlockExecutionError> {
    if input.deposits.len() > crate::node_primitives::MAX_NODE_DEPOSITS {
        return Err(BlockExecutionError::HeaderState {
            detail: "V2 deposit count limit exceeded".into(),
        });
    }
    prepare_start(
        spec,
        db,
        previous_root,
        input,
        HeaderPolicy::Node { domain, previous_root },
    )
}

fn prepare_start<DB: Database>(
    spec: &ChainSpec,
    db: &mut DB,
    previous_root: B256,
    input: &BlockInput,
    header_policy: HeaderPolicy,
) -> Result<PreparedBlockStart, BlockExecutionError> {
    validate_block_input(spec, input)?;
    let (changes, (parent_hash, block_hashes)) = stage_protocol(db, |overlay| {
        let parent_hash = match header_policy {
            HeaderPolicy::V1 => apply_header_rules(spec, overlay, previous_root, &input.context)?,
            HeaderPolicy::Node { domain, previous_root } => {
                crate::node_execution::prepare_parent(spec, domain, overlay, previous_root, &input.context)?
            }
        };
        let start = input.context.number.saturating_sub(BLOCK_HASH_HISTORY);
        let block_hashes = (start..input.context.number)
            .map(|number| (number, overlay.cache.block_hashes[&U256::from(number)]))
            .collect();
        ensure_system_account(overlay, BEACON_ROOTS_ADDRESS, Some(&beacon_roots_bytecode())).map_err(db_error)?;
        Ok((parent_hash, block_hashes))
    })?;
    Ok(PreparedBlockStart {
        changes,
        next: PendingSystemCall {
            active: ActiveBlock {
                header_policy,
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
            block_hashes,
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
    /// Immutable BLOCKHASH window captured at the same point as the portable
    /// kernel: after the header update, before beacon/deposit/user execution.
    /// Install this in the supplied EVM before its system call. Reading the live
    /// ring during later transactions can diverge when contracts mutate it.
    pub fn block_hashes(&self) -> &[(u64, B256)] {
        &self.block_hashes
    }

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
        let transaction = self.prepare_owned_transaction(tx, result, db)?;
        Ok(PreparedBlockTransaction {
            block: self,
            transaction,
        })
    }

    /// Prepare an owned result for adapters requiring `Send + 'static` tokens.
    ///
    /// Unlike the borrowed variant this does not bind the result to this block.
    /// The adapter must bind session and database generation, invalidate tokens
    /// on mutable EVM access, and reject stale/foreign results before commit.
    pub fn prepare_owned_transaction<DB: Database>(
        &self,
        tx: &TxEnv,
        result: ResultAndState<HaltReason>,
        db: &mut DB,
    ) -> Result<PreparedTransaction, BlockExecutionError> {
        self.validate_transaction(tx)?;
        prepare_transaction_effects(
            &self.spec,
            self.context.base_fee_per_gas,
            tx,
            self.run.tx_outcomes.len(),
            result,
            db,
        )
    }

    /// Commit an owned result that the adapter has bound to this exact block
    /// and unchanged database pre-state. This trusted method does not repeat
    /// session/generation or signature checks; those must precede the commit.
    pub fn commit_prepared_transaction(
        &mut self,
        prepared: PreparedTransaction,
        db: &mut impl DatabaseCommit,
    ) -> &TxOutcome {
        self.run.record(prepared.commit(db));
        self.run.tx_outcomes.last().expect("just recorded a transaction")
    }

    /// Total gas used by deposits and committed user transactions.
    pub fn gas_used(&self) -> u64 {
        self.run.gas_used
    }

    /// Number of committed user transactions, excluding protocol deposits.
    pub fn transaction_count(&self) -> usize {
        self.run.tx_outcomes.len()
    }

    /// Prepare the burned-supply ledger and committed head together.
    pub fn prepare_finish<DB: Database>(self, db: &mut DB) -> Result<PreparedBlockFinish, BlockExecutionError> {
        if !matches!(self.header_policy, HeaderPolicy::V1) {
            return Err(BlockExecutionError::HeaderState {
                detail: "V2 block requires V2 finalization".into(),
            });
        }
        let (changes, ()) = stage_protocol(db, |overlay| {
            finish_protocol(overlay, &self.spec, &self.context, &self.run)
        })?;
        Ok(PreparedBlockFinish { changes, block: self })
    }

    /// Authenticate the exact accepted body and prepare V2 metadata before root
    /// calculation. This is a trusted backend interface: the caller must retain
    /// the exact signed bytes corresponding to each committed EVM result.
    /// Dropped or skipped candidates must not appear in `body`.
    pub fn prepare_node_finish<DB: Database>(
        self,
        db: &mut DB,
        body: &NodeBodyV2,
    ) -> Result<PreparedNodeBlockFinish, NodeExecutionError> {
        let HeaderPolicy::Node { domain, previous_root } = self.header_policy else {
            return Err(BlockExecutionError::HeaderState {
                detail: "V1 block cannot use V2 finalization".into(),
            }
            .into());
        };
        let input = body.authenticated_input(&self.spec).map_err(NodeExecutionError::Body)?;
        let (record, receipts) =
            crate::node_execution::outcome_record(&self.context, previous_root, &self.run, body, &input.txs)?;
        let (changes, ()) = stage_protocol(db, |overlay| {
            finish_burns(overlay, &self.spec, &self.run)?;
            crate::node_execution::head::write_head_v2(overlay, self.spec.block_info, &record)
        })?;
        Ok(PreparedNodeBlockFinish {
            changes,
            finished: FinishedNodeBlock {
                spec: self.spec,
                domain,
                pending: PendingOutcome {
                    record,
                    receipts,
                    transactions: self.run.tx_outcomes,
                },
            },
        })
    }
}

impl PreparedNodeBlockFinish {
    /// Receipts derived from committed execution results, before publishing writes.
    pub fn receipts(&self) -> &[alloy_consensus::ReceiptEnvelope] {
        &self.finished.pending.receipts
    }

    /// Commit to the unchanged provisional database used for preparation.
    pub fn commit(self, db: &mut impl DatabaseCommit) -> FinishedNodeBlock {
        self.changes.commit(db);
        self.finished
    }
}
impl FinishedNodeBlock {
    /// Attach the independently calculated full post-state root. This trusted
    /// method neither calculates nor authenticates the supplied root.
    pub fn finalize(self, state_root: B256) -> NodeExecutionOutcome {
        self.pending.finalize(&self.spec, self.domain, state_root)
    }
}

impl PreparedBlockTransaction<'_> {
    /// Inspect the outcome when deciding whether to include this candidate.
    pub fn outcome(&self) -> &TxOutcome {
        self.transaction.outcome()
    }

    /// Commit effects and advance the originating block's accounting once.
    pub fn commit(self, db: &mut impl DatabaseCommit) {
        self.block.commit_prepared_transaction(self.transaction, db);
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
