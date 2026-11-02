// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reconstruct a selected persisted block's sparse witness from canonical genesis.
//! Local selection is trusted; this is not native deposit/finality authentication.
use crate::BlochProviderFactory;
use alloy_primitives::B256;
use bloch_execution_artifact::{ExecutionArtifact, Result, SparseExecutionArtifact};
use bloch_l2_evm::{
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    sparse_witness::{generate_sparse_node_witness, BlockHashes},
    BlockContext, ChainSpec, L2State,
};
use reth_chainspec::EthChainSpec;
use reth_provider::{BlockNumReader, BlockReader, ChainSpecProvider, HeaderProvider};

/// Full-prefix reconstruction is deliberately bounded for this local prototype.
pub const MAX_REPLAY_BLOCKS: u64 = 4096;

fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

/// Export a non-genesis block after independently re-executing its complete
/// prefix. The caller must stop source writers and open storage read-only.
/// No database writes, partial target or arbitrary starting state are accepted.
/// Complexity includes all transactions/state in at most 4096 selected blocks;
/// this is not a hostile-input CPU or accumulated-state memory sandbox.
pub fn export_canonical_witness(source: &BlochProviderFactory, number: u64) -> Result<ExecutionArtifact> {
    export_with(source, number, |state, rules, domain, context, parent, header, body| {
        let (witness, recorded) = generate_node_batch_witness(state, rules, domain, context, body)?;
        if recorded.header != *header {
            return Err(invalid("exported witness execution differs from stored block"));
        }
        ExecutionArtifact::new(rules, domain, parent, header, body, witness)
    })
}

/// CANDIDATE: [`export_canonical_witness`] for the sparse-witness guest (lazy
/// `BLOCKHASH`). The same replay and checks; only the witness differs. The
/// generator also runs the complete-witness path and refuses any difference.
pub fn export_canonical_sparse_witness(source: &BlochProviderFactory, number: u64) -> Result<SparseExecutionArtifact> {
    export_with(source, number, |state, rules, domain, context, parent, header, body| {
        let (witness, recorded) =
            generate_sparse_node_witness(state, rules, domain, context, body, BlockHashes::Lazy)?;
        if recorded.header != *header {
            return Err(invalid("exported witness execution differs from stored block"));
        }
        SparseExecutionArtifact::new(rules, domain, parent, header, body, witness)
    })
}

#[allow(clippy::type_complexity)]
fn export_with<T>(
    source: &BlochProviderFactory,
    number: u64,
    make: impl FnOnce(&L2State, &ChainSpec, B256, &BlockContext, &NodeHeaderV2, &NodeHeaderV2, &NodeBodyV2) -> Result<T>,
) -> Result<T> {
    let mut make = Some(make);
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
            let make = make.take().ok_or_else(|| invalid("proof export selected twice"))?;
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
