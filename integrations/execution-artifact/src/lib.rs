// SPDX-License-Identifier: MIT OR Apache-2.0
//! Portable transport between isolated Reth and SP1 host dependency graphs.
//! Validation re-executes a witness; it neither verifies a cryptographic proof
//! nor authenticates canonical block selection or native deposit authority.
use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, Encodable};
use bloch_l2_evm::{
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{configuration_commitment, execute_statement, ExecutionStatement},
    proving::BatchWitness,
    sparse_witness::{verify_node_batch_sparse, BlockHashes, SparseBatchWitness},
    BlockContext, ChainSpec,
};
use serde::{Deserialize, Serialize};
use std::io::Write;

const FORMAT: &str = "BLOCH:EVM:EXECUTION-ARTIFACT:1";
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format: String,
    configuration: B256,
    domain: B256,
    parent_rlp: Bytes,
    header_rlp: Bytes,
    body_rlp: Bytes,
    witness: BatchWitness,
}

/// Checked execution input, NOT a proof-verification or native funding token.
/// The caller independently chooses the trusted configuration/domain and the
/// local canonical artifact; an arbitrary received artifact establishes neither.
pub struct ExecutionArtifact {
    wire: Wire,
    parent: NodeHeaderV2,
    header: NodeHeaderV2,
    body: NodeBodyV2,
    context: BlockContext,
    expected: ExecutionStatement,
}

impl ExecutionArtifact {
    pub fn new(
        spec: &ChainSpec,
        domain: B256,
        parent: &NodeHeaderV2,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
        witness: BatchWitness,
    ) -> Result<Self> {
        body.validate(spec)?;
        Self::validate(
            spec,
            domain,
            Wire {
                format: FORMAT.into(),
                configuration: configuration_commitment(spec)?,
                domain,
                parent_rlp: alloy_rlp::encode(parent).into(),
                header_rlp: alloy_rlp::encode(header).into(),
                body_rlp: alloy_rlp::encode(body).into(),
                witness,
            },
        )
    }

    pub fn decode(bytes: &[u8], spec: &ChainSpec, domain: B256) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(invalid("execution artifact byte limit exceeded"));
        }
        // serde_json rejects non-whitespace trailing input and unknown envelope fields.
        Self::validate(spec, domain, serde_json::from_slice(bytes)?)
    }

    fn validate(spec: &ChainSpec, domain: B256, wire: Wire) -> Result<Self> {
        if wire.format != FORMAT || wire.domain != domain || wire.configuration != configuration_commitment(spec)? {
            return Err(invalid("execution artifact identity/configuration mismatch"));
        }
        if wire.parent_rlp.len() > 2048 || wire.header_rlp.len() > 2048 {
            return Err(invalid("execution artifact header byte limit exceeded"));
        }
        let parent: NodeHeaderV2 = exact(&wire.parent_rlp)?;
        let header: NodeHeaderV2 = exact(&wire.header_rlp)?;
        let body: NodeBodyV2 = exact(&wire.body_rlp)?;
        parent.validate_configuration(spec, domain)?;
        header.validate_configuration(spec, domain)?;
        header.validate_parent(spec, &parent)?;
        if wire.witness.prev_state_root != parent.state_root || wire.witness.new_state_root != header.state_root {
            return Err(invalid("execution artifact witness/selected roots disagree"));
        }
        let context = BlockContext {
            number: header.number,
            timestamp: header.timestamp,
            base_fee_per_gas: header.base_fee_per_gas,
            prevrandao: header.prevrandao,
            anchor_root: header.anchor_root,
        };
        let expected = execute_statement(spec, domain, &wire.witness, &context, &body)?;
        if expected.header_hash != header.hash() {
            return Err(invalid("execution artifact re-execution differs from selected header"));
        }
        Ok(Self {
            wire,
            parent,
            header,
            body,
            context,
            expected,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = BoundedOutput(Vec::new());
        serde_json::to_writer(&mut output, &self.wire)?;
        Ok(output.0)
    }
    pub fn expected(&self) -> ExecutionStatement {
        self.expected
    }
    pub fn parent(&self) -> &NodeHeaderV2 {
        &self.parent
    }
    pub fn header(&self) -> &NodeHeaderV2 {
        &self.header
    }
    pub fn body(&self) -> &NodeBodyV2 {
        &self.body
    }
    pub fn context(&self) -> &BlockContext {
        &self.context
    }
    pub fn witness(&self) -> &BatchWitness {
        &self.wire.witness
    }
}

const SPARSE_FORMAT: &str = "BLOCH:EVM:EXECUTION-ARTIFACT:SPARSE:2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SparseWire {
    format: String,
    configuration: B256,
    domain: B256,
    parent_rlp: Bytes,
    header_rlp: Bytes,
    body_rlp: Bytes,
    witness: SparseBatchWitness,
}

/// CANDIDATE: [`ExecutionArtifact`] for the sparse-witness guest. Its own format
/// string, so neither decoder accepts the other's file. It carries no complete
/// witness, whose size grows with the touched accounts' storage. Validation runs
/// the stateless sparse verifier with lazy `BLOCKHASH`, as the guest does.
pub struct SparseExecutionArtifact {
    wire: SparseWire,
    parent: NodeHeaderV2,
    header: NodeHeaderV2,
    body: NodeBodyV2,
    context: BlockContext,
    expected: ExecutionStatement,
}

impl SparseExecutionArtifact {
    pub fn new(
        spec: &ChainSpec,
        domain: B256,
        parent: &NodeHeaderV2,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
        witness: SparseBatchWitness,
    ) -> Result<Self> {
        body.validate(spec)?;
        Self::validate(
            spec,
            domain,
            SparseWire {
                format: SPARSE_FORMAT.into(),
                configuration: configuration_commitment(spec)?,
                domain,
                parent_rlp: alloy_rlp::encode(parent).into(),
                header_rlp: alloy_rlp::encode(header).into(),
                body_rlp: alloy_rlp::encode(body).into(),
                witness,
            },
        )
    }

    pub fn decode(bytes: &[u8], spec: &ChainSpec, domain: B256) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(invalid("execution artifact byte limit exceeded"));
        }
        Self::validate(spec, domain, serde_json::from_slice(bytes)?)
    }

    fn validate(spec: &ChainSpec, domain: B256, wire: SparseWire) -> Result<Self> {
        if wire.format != SPARSE_FORMAT || wire.domain != domain || wire.configuration != configuration_commitment(spec)? {
            return Err(invalid("sparse execution artifact identity/configuration mismatch"));
        }
        if wire.parent_rlp.len() > 2048 || wire.header_rlp.len() > 2048 {
            return Err(invalid("execution artifact header byte limit exceeded"));
        }
        let parent: NodeHeaderV2 = exact(&wire.parent_rlp)?;
        let header: NodeHeaderV2 = exact(&wire.header_rlp)?;
        let body: NodeBodyV2 = exact(&wire.body_rlp)?;
        parent.validate_configuration(spec, domain)?;
        header.validate_configuration(spec, domain)?;
        header.validate_parent(spec, &parent)?;
        if wire.witness.prev_state_root != parent.state_root || wire.witness.new_state_root != header.state_root {
            return Err(invalid("execution artifact witness/selected roots disagree"));
        }
        let context = BlockContext {
            number: header.number,
            timestamp: header.timestamp,
            base_fee_per_gas: header.base_fee_per_gas,
            prevrandao: header.prevrandao,
            anchor_root: header.anchor_root,
        };
        let outcome = verify_node_batch_sparse(spec, domain, &wire.witness, &context, &body, BlockHashes::Lazy)?;
        if outcome.header.hash() != header.hash() {
            return Err(invalid("execution artifact re-execution differs from selected header"));
        }
        let expected = ExecutionStatement {
            configuration: wire.configuration,
            domain,
            previous_state_root: wire.witness.prev_state_root,
            header_hash: outcome.header.hash(),
        };
        Ok(Self {
            wire,
            parent,
            header,
            body,
            context,
            expected,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = BoundedOutput(Vec::new());
        serde_json::to_writer(&mut output, &self.wire)?;
        Ok(output.0)
    }
    pub fn expected(&self) -> ExecutionStatement {
        self.expected
    }
    pub fn parent(&self) -> &NodeHeaderV2 {
        &self.parent
    }
    pub fn header(&self) -> &NodeHeaderV2 {
        &self.header
    }
    pub fn body(&self) -> &NodeBodyV2 {
        &self.body
    }
    pub fn context(&self) -> &BlockContext {
        &self.context
    }
    pub fn witness(&self) -> &SparseBatchWitness {
        &self.wire.witness
    }
}

fn exact<T: Decodable + Encodable>(bytes: &[u8]) -> Result<T> {
    let mut remaining = bytes;
    let value = T::decode(&mut remaining)?;
    if !remaining.is_empty() || alloy_rlp::encode(&value) != bytes {
        return Err(invalid("noncanonical or trailing execution artifact RLP"));
    }
    Ok(value)
}

struct BoundedOutput(Vec<u8>);
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_ARTIFACT_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("execution artifact output byte limit exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
