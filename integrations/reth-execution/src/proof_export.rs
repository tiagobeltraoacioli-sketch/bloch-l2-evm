// SPDX-License-Identifier: MIT OR Apache-2.0
//! A selected persisted block's sparse witness, from the database's state before that block. The state is
//! accepted only if it hashes to the parent's committed state root, so the cost depends on the state, not the height.
//! Local selection is trusted; this is not native deposit/finality authentication.
use crate::BlochProviderFactory;
use alloy_primitives::{Address, B256, U256};
use bloch_execution_artifact::{ExecutionArtifact, Result, SparseExecutionArtifact};
use bloch_l2_evm::{
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    sparse_witness::{generate_sparse_node_witness, generate_sparse_node_witness_forced, BlockHashes},
    BlockContext, ChainSpec, L2State,
};
use reth_chainspec::EthChainSpec;
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
use reth_primitives_traits::Account;
use reth_provider::{
    BlockNumReader, BlockReader, ChainSpecProvider, ChangeSetReader, HeaderProvider, StorageChangeSetReader,
    StorageSettingsCache,
};
use reth_revm::revm::{primitives::KECCAK_EMPTY, state::AccountInfo};
use std::collections::HashMap;

/// How far below the database tip a block can be exported. Each block between costs reading its changesets.
pub const MAX_BLOCKS_BEHIND_TIP: u64 = 4096;
/// Accounts plus storage slots an export loads into memory: refused above this, before memory runs out. The
/// settlement worker's unit caps it far lower than a chain's history would, so the bound is on state, not height.
pub const MAX_STATE_ENTRIES: u64 = 100_000_000;
/// The old bound on a replay from genesis, kept for [`export_by_replay`].
pub const MAX_REPLAY_BLOCKS: u64 = 4096;

fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

/// An export and what it cost.
pub struct ExportReport {
    pub artifact: ExecutionArtifact,
    /// Accounts plus storage slots of the pre-state.
    pub state_entries: u64,
}

/// The state before block `number`: the plain state at `tip`, with the changesets of `number..=tip` undone.
fn state_before(source: &BlochProviderFactory, number: u64, tip: u64) -> Result<(L2State, u64)> {
    let provider = source.provider()?;
    if provider.cached_storage_settings().use_hashed_state() {
        return Err(invalid("proof export needs the plain state tables"));
    }
    let mut accounts: HashMap<Address, Option<Account>> = HashMap::new();
    let mut slots: HashMap<(Address, B256), U256> = HashMap::new();
    // Newest first, so the entry of the oldest block is the value before `number`.
    for height in (number..=tip).rev() {
        for change in provider.account_block_changeset(height)? {
            accounts.insert(change.address, change.info);
        }
        for (key, entry) in provider.storage_changeset(height)? {
            slots.insert((key.address(), entry.key), entry.value);
        }
    }
    let mut state = L2State::new();
    let mut entries = 0u64;
    let count = |entries: &mut u64| -> Result<()> {
        *entries += 1;
        if *entries > MAX_STATE_ENTRIES {
            return Err(invalid("proof export state above MAX_STATE_ENTRIES"));
        }
        Ok(())
    };
    let tx = provider.tx_ref();
    let put = |state: &mut L2State, address: Address, account: Account| -> Result<()> {
        let hash = account.bytecode_hash.unwrap_or(KECCAK_EMPTY);
        let code = if hash == KECCAK_EMPTY {
            None
        } else {
            let code = tx
                .get::<tables::Bytecodes>(hash)?
                .ok_or_else(|| invalid("missing contract code"))?;
            Some(code.0)
        };
        let info = AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: hash,
            code,
            ..Default::default()
        };
        state.db_mut().insert_account_info(address, info);
        Ok(())
    };
    let mut cursor = tx.cursor_read::<tables::PlainAccountState>()?;
    let mut row = cursor.first()?;
    while let Some((address, account)) = row {
        if !accounts.contains_key(&address) {
            count(&mut entries)?;
            put(&mut state, address, account)?;
        }
        row = cursor.next()?;
    }
    for (address, account) in &accounts {
        if let Some(account) = account {
            count(&mut entries)?;
            put(&mut state, *address, *account)?;
        }
    }
    let mut cursor = tx.cursor_dup_read::<tables::PlainStorageState>()?;
    let mut row = cursor.first()?;
    while let Some((address, entry)) = row {
        if !slots.contains_key(&(address, entry.key)) && !entry.value.is_zero() {
            count(&mut entries)?;
            state
                .db_mut()
                .insert_account_storage(address, entry.key.into(), entry.value)
                .map_err(|_| invalid("storage insert"))?;
        }
        row = cursor.next()?;
    }
    for ((address, key), value) in &slots {
        if !value.is_zero() {
            count(&mut entries)?;
            state
                .db_mut()
                .insert_account_storage(*address, (*key).into(), *value)
                .map_err(|_| invalid("storage insert"))?;
        }
    }
    Ok((state, entries))
}

/// Export a non-genesis block from the database's state before it, at most [`MAX_BLOCKS_BEHIND_TIP`] below
/// the tip. Independently checked: the state must hash to the parent's committed root, and executing the
/// block must reproduce its stored header. The caller must stop source writers and open storage read-only.
pub fn export_canonical_witness(source: &BlochProviderFactory, number: u64) -> Result<ExecutionArtifact> {
    Ok(export_with_report(source, number)?.artifact)
}

/// [`export_canonical_witness`], reporting the size of the pre-state.
pub fn export_with_report(source: &BlochProviderFactory, number: u64) -> Result<ExportReport> {
    let (artifact, state_entries) = export_from_state(source, number, complete_artifact)?;
    Ok(ExportReport {
        artifact,
        state_entries,
    })
}

/// CANDIDATE: [`export_canonical_witness`] for the sparse-witness guest (lazy
/// `BLOCKHASH`). The same pre-state and checks; only the witness differs. The
/// generator also runs the complete-witness path and refuses any difference.
pub fn export_canonical_sparse_witness(source: &BlochProviderFactory, number: u64) -> Result<SparseExecutionArtifact> {
    Ok(export_sparse_with_report(source, number)?.0)
}

/// [`export_canonical_sparse_witness`], with the number of pre-state entries (accounts plus slots) loaded.
pub fn export_sparse_with_report(source: &BlochProviderFactory, number: u64) -> Result<(SparseExecutionArtifact, u64)> {
    export_from_state(source, number, sparse_artifact)
}

/// CANDIDATE (forced inclusion): [`export_sparse_with_report`] for a block that consumed these forced records.
/// The witness carries them, and the generator re-runs the forced rule, so a body that does not start with
/// exactly the forced selection is refused here.
pub fn export_sparse_forced_with_report(
    source: &BlochProviderFactory,
    number: u64,
    forced: &[bloch_l2_evm::forced_inclusion::ForcedTransaction],
) -> Result<(SparseExecutionArtifact, u64)> {
    export_from_state(source, number, |state, rules, domain, context, parent, header, body| {
        let (witness, recorded) =
            generate_sparse_node_witness_forced(state, rules, domain, context, body, BlockHashes::Lazy, forced)?;
        if recorded.header != *header {
            return Err(invalid("exported witness execution differs from stored block"));
        }
        SparseExecutionArtifact::new(rules, domain, parent, header, body, witness)
    })
}

/// CANDIDATE (forced inclusion): [`export_with_report`] for a block that consumed these forced records, for the
/// complete-witness fallback guest. The witness covers the forced rule's reads (skipped senders included) and the
/// artifact carries the records; a body that does not start with exactly the forced selection is refused here.
pub fn export_forced_with_report(
    source: &BlochProviderFactory,
    number: u64,
    forced: &[bloch_l2_evm::forced_inclusion::ForcedTransaction],
) -> Result<ExportReport> {
    let (artifact, state_entries) =
        export_from_state(source, number, |state, rules, domain, context, parent, header, body| {
            let (witness, recorded) = bloch_l2_evm::forced_complete::generate_node_batch_witness_forced(
                state, rules, domain, context, body, forced,
            )?;
            if recorded.header != *header {
                return Err(invalid("exported witness execution differs from stored block"));
            }
            ExecutionArtifact::new_forced(rules, domain, parent, header, body, witness, forced.to_vec())
        })?;
    Ok(ExportReport {
        artifact,
        state_entries,
    })
}

fn complete_artifact(
    state: &L2State,
    rules: &ChainSpec,
    domain: B256,
    context: &BlockContext,
    parent: &NodeHeaderV2,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<ExecutionArtifact> {
    let (witness, recorded) = generate_node_batch_witness(state, rules, domain, context, body)?;
    if recorded.header != *header {
        return Err(invalid("exported witness execution differs from stored block"));
    }
    ExecutionArtifact::new(rules, domain, parent, header, body, witness)
}

fn sparse_artifact(
    state: &L2State,
    rules: &ChainSpec,
    domain: B256,
    context: &BlockContext,
    parent: &NodeHeaderV2,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<SparseExecutionArtifact> {
    let (witness, recorded) = generate_sparse_node_witness(state, rules, domain, context, body, BlockHashes::Lazy)?;
    if recorded.header != *header {
        return Err(invalid("exported witness execution differs from stored block"));
    }
    SparseExecutionArtifact::new(rules, domain, parent, header, body, witness)
}

/// The block's rules are those of its height (`execution_at`), so a block past a rule switch is exported
/// under the next rules and one below it under the base rules.
#[allow(clippy::type_complexity)]
fn export_from_state<T>(
    source: &BlochProviderFactory,
    number: u64,
    make: impl Fn(&L2State, &ChainSpec, B256, &BlockContext, &NodeHeaderV2, &NodeHeaderV2, &NodeBodyV2) -> Result<T>,
) -> Result<(T, u64)> {
    if number == 0 {
        return Err(invalid("proof export height outside the non-genesis chain"));
    }
    let spec = source.chain_spec();
    let domain = spec.domain();
    let tip_number = source.best_block_number()?;
    if number > tip_number {
        return Err(invalid("proof export block is not acknowledged by MDBX"));
    }
    if tip_number - number > MAX_BLOCKS_BEHIND_TIP {
        return Err(invalid("proof export block is too far below the tip"));
    }
    let tip = source
        .sealed_header(tip_number)?
        .ok_or_else(|| invalid("missing acknowledged tip"))?;
    let selected = source
        .sealed_header(number)?
        .ok_or_else(|| invalid("missing selected export header"))?;
    let parent = source
        .sealed_header(number - 1)?
        .ok_or_else(|| invalid("missing parent header"))?;
    let genesis = source
        .sealed_header(0)?
        .ok_or_else(|| invalid("missing canonical genesis"))?;
    if genesis.header() != spec.genesis_header() || genesis.hash() != spec.genesis_hash() {
        return Err(invalid("proof export genesis differs from trusted configuration"));
    }
    let block = source
        .block_by_number(number)?
        .ok_or_else(|| invalid("missing canonical block body"))?;
    if &block.header != selected.header() || selected.hash() != block.header.0.hash() {
        return Err(invalid("proof export body/header canonical selection mismatch"));
    }
    let (mut state, state_entries) = state_before(source, number, tip_number)?;
    if state.commit_root() != parent.0.state_root {
        return Err(invalid("proof export state does not hash to the parent's state root"));
    }
    let header = &block.header.0;
    let rules = spec.execution_at(number);
    header.validate_parent(rules, &parent.0)?;
    let body = block.body.as_core();
    let context = BlockContext {
        number: header.number,
        timestamp: header.timestamp,
        base_fee_per_gas: header.base_fee_per_gas,
        prevrandao: header.prevrandao,
        anchor_root: header.anchor_root,
    };
    let artifact = make(&state, rules, domain, &context, &parent.0, header, body)?;
    if source.best_block_number()? != tip_number || source.sealed_header(tip_number)?.as_ref() != Some(&tip) {
        return Err(invalid("canonical selection changed during proof export"));
    }
    if source.sealed_header(number)?.as_ref() != Some(&selected) {
        return Err(invalid("selected export header changed before publication"));
    }
    Ok((artifact, state_entries))
}

/// The former export: re-execute the whole prefix from genesis. Kept as the reference that tests and audits
/// compare [`export_canonical_witness`] with, byte for byte. Bounded, and not used by the settlement path.
pub fn export_by_replay(source: &BlochProviderFactory, number: u64) -> Result<ExecutionArtifact> {
    export_by_replay_with(source, number, complete_artifact)
}

/// [`export_by_replay`] for the sparse-witness guest: the reference for [`export_canonical_sparse_witness`].
pub fn export_sparse_by_replay(source: &BlochProviderFactory, number: u64) -> Result<SparseExecutionArtifact> {
    export_by_replay_with(source, number, sparse_artifact)
}

#[allow(clippy::type_complexity)]
fn export_by_replay_with<T>(
    source: &BlochProviderFactory,
    number: u64,
    make: fn(&L2State, &ChainSpec, B256, &BlockContext, &NodeHeaderV2, &NodeHeaderV2, &NodeBodyV2) -> Result<T>,
) -> Result<T> {
    if number == 0 || number > MAX_REPLAY_BLOCKS {
        return Err(invalid("proof export height outside bounded non-genesis prefix"));
    }
    let spec = source.chain_spec();
    // The genesis and every parent check are the same under each rule set.
    let kernel = spec.execution();
    let domain = spec.domain();
    let tip_number = source.best_block_number()?;
    if number > tip_number {
        return Err(invalid("proof export block is not acknowledged by MDBX"));
    }
    let tip = source
        .sealed_header(tip_number)?
        .ok_or_else(|| invalid("missing acknowledged tip"))?;
    let expected_selected = source
        .sealed_header(number)?
        .ok_or_else(|| invalid("missing selected export header"))?;
    let genesis = source
        .sealed_header(0)?
        .ok_or_else(|| invalid("missing canonical genesis"))?;
    if genesis.header() != spec.genesis_header() || genesis.hash() != spec.genesis_hash() {
        return Err(invalid("proof export genesis differs from trusted configuration"));
    }
    let mut state = genesis_v2(kernel, genesis.0.timestamp)?;
    state.commit_root();
    let mut parent = node_head(kernel, domain, &state)?;
    if parent != genesis.0 {
        return Err(invalid("proof export reconstruction genesis mismatch"));
    }
    let mut exported = None;
    for height in 1..=number {
        let block = source
            .block_by_number(height)?
            .ok_or_else(|| invalid("missing canonical block body"))?;
        let selected = source
            .sealed_header(height)?
            .ok_or_else(|| invalid("missing canonical block header"))?;
        if &block.header != selected.header() || selected.hash() != block.header.0.hash() {
            return Err(invalid("proof export body/header canonical selection mismatch"));
        }
        let header = &block.header.0;
        let rules = spec.execution_at(height);
        header.validate_parent(rules, &parent)?;
        let body = block.body.as_core();
        let context = BlockContext {
            number: header.number,
            timestamp: header.timestamp,
            base_fee_per_gas: header.base_fee_per_gas,
            prevrandao: header.prevrandao,
            anchor_root: header.anchor_root,
        };
        if height == number {
            if selected != expected_selected {
                return Err(invalid("selected export header changed during reconstruction"));
            }
            exported = Some(make(&state, rules, domain, &context, &parent, header, body)?);
        }
        let outcome = execute_node_block(rules, domain, &mut state, &context, body)?;
        if outcome.header != *header {
            return Err(invalid("canonical prefix execution differs from stored block"));
        }
        parent = outcome.header;
    }
    if source.best_block_number()? != tip_number || source.sealed_header(tip_number)?.as_ref() != Some(&tip) {
        return Err(invalid("canonical selection changed during proof export"));
    }
    if source.sealed_header(number)?.as_ref() != Some(&expected_selected) {
        return Err(invalid("selected export header changed before publication"));
    }
    exported.ok_or_else(|| invalid("proof export produced no witness"))
}
