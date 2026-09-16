// SPDX-License-Identifier: MIT OR Apache-2.0
//! Whole-block Bloch execution using Reth's state-provider database adapter.
//!
//! This module does not implement a node, RPC, pool, persistence or finality.
//! The provider snapshot and roots are trusted host inputs. Signed Ethereum
//! bytes are authenticated by the existing Bloch kernel, not a sender cache.

use alloy_primitives::B256;
use bloch_l2_evm::{
    execute_signed_block_on_database, BlockExecutionError, ChainSpec, DatabaseBlockExecution, SignedBlockInput,
    SignedInputError,
};
use reth_revm::database::{EvmStateProvider, StateProviderDatabase};

/// Run against a Reth state provider without committing its storage.
///
/// An actual Reth `StateProvider` implements `EvmStateProvider` via upstream's
/// blanket implementation. The caller supplies the snapshot's real MPT root
/// and independently authenticated deposit/anchor context. Compute the full
/// post-state root and persist the returned overlay separately. Neither roots
/// nor L1 trust are established by this adapter.
pub fn execute_on_provider<P: EvmStateProvider>(
    spec: &ChainSpec,
    provider: P,
    previous_root: B256,
    input: &SignedBlockInput,
) -> Result<DatabaseBlockExecution<StateProviderDatabase<P>>, SignedInputError<BlockExecutionError>> {
    execute_signed_block_on_database(spec, StateProviderDatabase::new(provider), previous_root, input)
}
