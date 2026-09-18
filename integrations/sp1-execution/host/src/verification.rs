// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-backend verification capabilities; no injectable mock verifier.
use crate::{invalid, Result};
use alloy_primitives::{keccak256, B256};
use bincode::Options;
use bloch_l2_evm::proof_statement::{ExecutionStatement, STATEMENT_LEN};
use sp1_sdk::{Elf, HashableKey, LightProver, Prover, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1VerifyingKey};
use std::{io::Read, path::Path};

/// Local file admission bound, not a network-proof protocol parameter.
pub const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CORE_SHARDS: usize = 256;

/// Identity of the exact operator-selected ELF and its SP1 verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramIdentity {
    elf_keccak: B256,
    verifying_key_hash: B256,
}

impl ProgramIdentity {
    pub fn elf_keccak(&self) -> B256 {
        self.elf_keccak
    }
    /// SDK `HashableKey::hash_bytes`, not the BN254/on-chain projection.
    pub fn verifying_key_hash(&self) -> B256 {
        self.verifying_key_hash
    }
}

/// An operator-selected program. The concrete LightProver always performs real
/// cryptographic verification; callers cannot supply a `MockProver` or closure.
pub struct TrustedProgram {
    client: LightProver,
    key: SP1VerifyingKey,
    identity: ProgramIdentity,
}

impl TrustedProgram {
    /// The caller must authenticate this ELF independently of an incoming proof.
    pub async fn from_trusted_elf(elf: Elf) -> Result<Self> {
        let elf_keccak = keccak256(&*elf);
        let client = LightProver::new().await;
        let key = client.setup(elf).await?.verifying_key().clone();
        let identity = ProgramIdentity {
            elf_keccak,
            verifying_key_hash: B256::from(key.hash_bytes()),
        };
        Ok(Self { client, key, identity })
    }

    pub fn identity(&self) -> ProgramIdentity {
        self.identity
    }

    /// `expected` is independently trusted selection, never decoded from the
    /// proof itself. The returned capability retains the exact verified proof.
    pub fn verify(
        &self,
        proof: SP1ProofWithPublicValues,
        expected: &ExecutionStatement,
    ) -> Result<VerifiedExecutionStatement> {
        if !matches!(proof.proof, SP1Proof::Core(_)) {
            return Err(invalid("only SP1 core proofs are permitted"));
        }
        if let SP1Proof::Core(shards) = &proof.proof {
            if shards.is_empty() || shards.len() > MAX_CORE_SHARDS {
                return Err(invalid("core proof shard count outside local bounds"));
            }
        }
        if proof.public_values.as_slice().len() != STATEMENT_LEN {
            return Err(invalid("wrong execution statement length"));
        }
        // None requires a successful guest exit. Proof version, commitments and
        // core proof validity are checked by the pinned SDK before expectations.
        self.client.verify(&proof, &self.key, None)?;
        expected.check_expected(proof.public_values.as_slice())?;
        Ok(VerifiedExecutionStatement {
            statement: *expected,
            program: self.identity,
            proof,
        })
    }

    pub fn verify_file(
        &self,
        path: impl AsRef<Path>,
        expected: &ExecutionStatement,
    ) -> Result<VerifiedExecutionStatement> {
        self.verify(load_proof(path)?, expected)
    }
}

/// Capability created only after successful SP1 verification and expectation
/// binding. No public constructor, deserializer or mutable proof accessor exists.
pub struct VerifiedExecutionStatement {
    statement: ExecutionStatement,
    program: ProgramIdentity,
    proof: SP1ProofWithPublicValues,
}

impl VerifiedExecutionStatement {
    pub fn statement(&self) -> ExecutionStatement {
        self.statement
    }
    pub fn program(&self) -> ProgramIdentity {
        self.program
    }
    pub(crate) fn proof_bytes(&self) -> Result<Vec<u8>> {
        let size = bincode::serialized_size(&self.proof)?;
        if size > MAX_PROOF_BYTES as u64 {
            return Err(invalid("proof exceeds local byte limit"));
        }
        Ok(bincode::serialize(&self.proof)?)
    }
}

/// Strict local SDK 6.8.0 encoding. No network-format fallback or trailing data.
pub fn decode_proof(bytes: &[u8]) -> Result<SP1ProofWithPublicValues> {
    if bytes.len() < 12 || bytes.len() > MAX_PROOF_BYTES {
        return Err(invalid("proof file length outside local bounds"));
    }
    // SDK 6.8.0 fixint format starts with SP1Proof enum u32 followed by
    // Core's Vec length u64, both little-endian. Bound before serde reserves it.
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != 0 {
        return Err(invalid("encoded proof is not SP1 core"));
    }
    let shards = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    if shards == 0 || shards > MAX_CORE_SHARDS as u64 {
        return Err(invalid("encoded core shard count outside local bounds"));
    }
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

/// Check the regular-file length before allocation and cap the actual read too.
/// This is a byte bound, not a complete hostile-proof memory/CPU sandbox.
pub fn load_proof(path: impl AsRef<Path>) -> Result<SP1ProofWithPublicValues> {
    let file = crate::open_regular(path.as_ref(), false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PROOF_BYTES as u64 {
        return Err(invalid("proof must be a bounded nonempty regular file"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PROOF_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    decode_proof(&bytes)
}
