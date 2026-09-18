// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independently selected local block transport for the unchanged developer guest.
use crate::{invalid, Result};
use alloy_primitives::B256;
use bloch_execution_artifact::{ExecutionArtifact, MAX_ARTIFACT_BYTES};
use bloch_l2_evm::ChainSpec;
use std::{io::Read, path::Path};

/// Selection of this local artifact and its parent remains application trust.
/// Decoding re-executes the sparse witness; it is not a proof or native authority.
pub fn load_selected_artifact(path: impl AsRef<Path>) -> Result<ExecutionArtifact> {
    let mut file = crate::open_regular(path.as_ref(), false)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_ARTIFACT_BYTES as u64 {
        return Err(invalid("execution artifact file outside 64 MiB bound"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.by_ref()
        .take(MAX_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != length as usize {
        return Err(invalid("execution artifact length changed while reading"));
    }
    // The guest embeds exactly this policy. A transport cannot choose another.
    ExecutionArtifact::decode(&bytes, &ChainSpec::testnet(), B256::repeat_byte(0xd3))
}
