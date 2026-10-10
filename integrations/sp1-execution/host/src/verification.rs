// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-backend verification capabilities; no injectable mock verifier.
use crate::{invalid, Result};
use alloy_primitives::{keccak256, B256};
use bincode::Options;
use bloch_l2_evm::proof_statement::{
    ExecutionStatement, SettlementStatementV2, SettlementStatementV3, SETTLEMENT_STATEMENT_V2_LEN,
    SETTLEMENT_STATEMENT_V3_LEN, STATEMENT_LEN,
};
use sp1_sdk::{Elf, HashableKey, LightProver, Prover, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1VerifyingKey};
use std::{io::Read, path::Path};
#[cfg(feature = "source-settlement")]
use {
    bloch_native_domain_devnet::{
        settlement_v2_groth16_proof_policy_commitment, settlement_v3_groth16_proof_policy_commitment,
    },
    sha2::{Digest, Sha256},
    sp1_verifier::GROTH16_VK_BYTES,
};

/// Local file admission bound, not a network-proof protocol parameter.
pub const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CORE_SHARDS: usize = 256;
/// Deliberately narrow admission bound for the dormant Groth16 qualification
/// path. This is not a consensus block-size decision.
pub const MAX_GROTH16_ARTIFACT_BYTES: usize = 64 * 1024;
const GROTH16_ENCODED_HEX_LEN: usize = 352 * 2;
/// Exact SP1 6.8.0 Groth16 byte string accepted by the minimal verifier.
pub const GROTH16_CONSENSUS_PROOF_BYTES: usize = 4 + 352;

/// Identity of the exact operator-selected ELF and its SP1 verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramIdentity {
    elf_keccak: B256,
    verifying_key_hash: B256,
    verifying_key_bn254: B256,
}

impl ProgramIdentity {
    pub fn elf_keccak(&self) -> B256 {
        self.elf_keccak
    }
    /// SDK `HashableKey::hash_bytes`, not the BN254/on-chain projection.
    pub fn verifying_key_hash(&self) -> B256 {
        self.verifying_key_hash
    }
    /// SDK `HashableKey::bytes32_raw`, the BN254/on-chain projection.
    /// This is deliberately distinct from `hash_bytes` above.
    pub fn verifying_key_bn254(&self) -> B256 {
        self.verifying_key_bn254
    }

    /// Unit-test identity only. Production identities remain obtainable solely
    /// from `TrustedProgram::from_trusted_elf`.
    #[cfg(all(test, feature = "source-settlement"))]
    pub(crate) fn test_fixture(byte: u8) -> Self {
        Self {
            elf_keccak: B256::repeat_byte(byte),
            verifying_key_hash: B256::repeat_byte(byte.wrapping_add(1)),
            verifying_key_bn254: B256::repeat_byte(byte.wrapping_add(2)),
        }
    }
}

/// An operator-selected program. The concrete LightProver always performs real
/// cryptographic verification; callers cannot supply a `MockProver` or closure.
pub struct TrustedProgram {
    client: LightProver,
    key: SP1VerifyingKey,
    identity: ProgramIdentity,
}

fn statement_program_matches(statement: &SettlementStatementV2, identity: ProgramIdentity) -> bool {
    statement.program_elf_keccak == identity.elf_keccak
        && statement.program_vkey_koalabear == identity.verifying_key_hash
        && statement.program_vkey_bn254 == identity.verifying_key_bn254
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
            verifying_key_bn254: B256::from(key.bytes32_raw()),
        };
        Ok(Self { client, key, identity })
    }

    pub fn identity(&self) -> ProgramIdentity {
        self.identity
    }

    pub(crate) fn verifying_key_bn254_string(&self) -> String {
        self.key.bytes32()
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

    /// Verify the settlement-specific guest and bind every public settlement
    /// field to an independently constructed expectation. This is deliberately
    /// a separate capability from the legacy execution statement.
    pub fn verify_settlement_v2(
        &self,
        proof: SP1ProofWithPublicValues,
        expected: &SettlementStatementV2,
    ) -> Result<VerifiedSettlementStatementV2> {
        if !statement_program_matches(expected, self.identity) {
            return Err(invalid(
                "settlement statement program identity differs from trusted ELF",
            ));
        }
        if !matches!(proof.proof, SP1Proof::Core(_)) {
            return Err(invalid("only SP1 core proofs are permitted for settlement V2"));
        }
        if let SP1Proof::Core(shards) = &proof.proof {
            if shards.is_empty() || shards.len() > MAX_CORE_SHARDS {
                return Err(invalid("core proof shard count outside local bounds"));
            }
        }
        if proof.public_values.as_slice().len() != SETTLEMENT_STATEMENT_V2_LEN {
            return Err(invalid("wrong settlement V2 statement length"));
        }
        self.client.verify(&proof, &self.key, None)?;
        expected.check_expected(proof.public_values.as_slice())?;
        Ok(VerifiedSettlementStatementV2 {
            statement: *expected,
            program: self.identity,
            proof,
        })
    }

    pub fn verify_settlement_v2_file(
        &self,
        path: impl AsRef<Path>,
        expected: &SettlementStatementV2,
    ) -> Result<VerifiedSettlementStatementV2> {
        self.verify_settlement_v2(load_proof(path)?, expected)
    }

    /// Verify a genuine Groth16 wrapper for the V2 settlement guest. The
    /// returned capability is distinct from both legacy qualification and Core
    /// settlement proof capabilities and has no conversion into either.
    pub fn verify_groth16_settlement_v2(
        &self,
        proof: SP1ProofWithPublicValues,
        expected: &SettlementStatementV2,
    ) -> Result<QualifiedGroth16SettlementV2> {
        if !statement_program_matches(expected, self.identity) {
            return Err(invalid(
                "settlement statement program identity differs from trusted ELF",
            ));
        }
        validate_groth16_envelope(&proof, SETTLEMENT_STATEMENT_V2_LEN)?;
        // The source-settlement capability commits to the complete wrapper
        // key, not merely the SDK verification key derived from the guest.
        // Reject mismatched wrapper metadata before emitting the capability so
        // no caller can accidentally treat a later policy check as optional.
        #[cfg(feature = "source-settlement")]
        validate_settlement_v2_groth16_wrapper_key(&proof)?;
        self.client.verify(&proof, &self.key, None)?;
        expected.check_expected(proof.public_values.as_slice())?;
        Ok(QualifiedGroth16SettlementV2 {
            statement: *expected,
            program: self.identity,
            proof,
        })
    }

    pub fn verify_groth16_settlement_v2_file(
        &self,
        path: impl AsRef<Path>,
        expected: &SettlementStatementV2,
    ) -> Result<QualifiedGroth16SettlementV2> {
        self.verify_groth16_settlement_v2(
            load_groth16_proof_for_public_len(path, SETTLEMENT_STATEMENT_V2_LEN)?,
            expected,
        )
    }

    /// Verify a genuine Groth16 wrapper for the V3 settlement guest. V3 public
    /// values are 766 bytes, so a V2 proof can never satisfy this check.
    pub fn verify_groth16_settlement_v3(
        &self,
        proof: SP1ProofWithPublicValues,
        expected: &SettlementStatementV3,
    ) -> Result<QualifiedGroth16SettlementV3> {
        if !statement_program_matches(&expected.base, self.identity) {
            return Err(invalid(
                "settlement statement program identity differs from trusted ELF",
            ));
        }
        validate_groth16_envelope(&proof, SETTLEMENT_STATEMENT_V3_LEN)?;
        #[cfg(feature = "source-settlement")]
        validate_settlement_v2_groth16_wrapper_key(&proof)?;
        self.client.verify(&proof, &self.key, None)?;
        expected.check_expected(proof.public_values.as_slice())?;
        Ok(QualifiedGroth16SettlementV3 {
            statement: *expected,
            program: self.identity,
            proof,
        })
    }

    pub fn verify_groth16_settlement_v3_file(
        &self,
        path: impl AsRef<Path>,
        expected: &SettlementStatementV3,
    ) -> Result<QualifiedGroth16SettlementV3> {
        self.verify_groth16_settlement_v3(
            load_groth16_proof_for_public_len(path, SETTLEMENT_STATEMENT_V3_LEN)?,
            expected,
        )
    }

    /// Verify a real SP1 Groth16 wrapper for offline qualification only.
    ///
    /// This intentionally returns a different capability from the Core-proof
    /// settlement path. Nothing accepting `VerifiedExecutionStatement` can
    /// consume it, so merely producing a wrapper cannot activate settlement.
    pub fn verify_groth16_qualification(
        &self,
        proof: SP1ProofWithPublicValues,
        expected: &ExecutionStatement,
    ) -> Result<QualifiedGroth16Execution> {
        validate_groth16_envelope(&proof, STATEMENT_LEN)?;
        self.client.verify(&proof, &self.key, None)?;
        expected.check_expected(proof.public_values.as_slice())?;
        Ok(QualifiedGroth16Execution {
            statement: *expected,
            program: self.identity,
            proof,
        })
    }

    pub fn verify_groth16_qualification_file(
        &self,
        path: impl AsRef<Path>,
        expected: &ExecutionStatement,
    ) -> Result<QualifiedGroth16Execution> {
        self.verify_groth16_qualification(load_groth16_proof(path)?, expected)
    }
}

/// Offline evidence that the pinned SDK verified a genuine Groth16 wrapper.
/// This type has no conversion into the active Core settlement capability.
pub struct QualifiedGroth16Execution {
    statement: ExecutionStatement,
    program: ProgramIdentity,
    proof: SP1ProofWithPublicValues,
}

/// Evidence that a real SP1 Groth16 wrapper authenticated the complete V2
/// settlement statement under the exact trusted ELF and verifying key.
pub struct QualifiedGroth16SettlementV2 {
    statement: SettlementStatementV2,
    program: ProgramIdentity,
    proof: SP1ProofWithPublicValues,
}

impl QualifiedGroth16SettlementV2 {
    /// Exact authenticated public statement.
    pub fn statement(&self) -> SettlementStatementV2 {
        self.statement
    }
    /// Exact ELF and SP1 key identity used for verification.
    pub fn program(&self) -> ProgramIdentity {
        self.program
    }
    /// Exact SDK artifact retained after cryptographic verification.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>> {
        let bytes = bincode::serialize(&self.proof)?;
        if bytes.is_empty() || bytes.len() > MAX_GROTH16_ARTIFACT_BYTES {
            return Err(invalid("Groth16 artifact outside qualification bound"));
        }
        Ok(bytes)
    }
    /// Canonical 356-byte proof consumed by `sp1-verifier`, excluding public
    /// values which are transported as the fixed V2 statement separately.
    pub fn canonical_proof_bytes(&self) -> Result<Vec<u8>> {
        let bytes = self.proof.bytes();
        if bytes.len() != GROTH16_CONSENSUS_PROOF_BYTES {
            return Err(invalid("unexpected canonical Groth16 proof length"));
        }
        Ok(bytes)
    }

    /// Commitment to the exact SDK proof policy used by this verified
    /// capability. The full wrapper VK is read from the pinned verifier crate.
    #[cfg(feature = "source-settlement")]
    pub fn proof_policy_commitment(&self) -> Result<B256> {
        let full_vk_sha256: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
        validate_settlement_v2_groth16_wrapper_key(&self.proof)?;
        Ok(settlement_v2_groth16_proof_policy_commitment(
            sp1_sdk::SP1_CIRCUIT_VERSION,
            B256::from(full_vk_sha256),
        )?)
    }
}

/// Evidence that a real SP1 Groth16 wrapper authenticated the complete V3
/// settlement statement under the exact trusted ELF and verifying key.
pub struct QualifiedGroth16SettlementV3 {
    statement: SettlementStatementV3,
    program: ProgramIdentity,
    proof: SP1ProofWithPublicValues,
}

impl QualifiedGroth16SettlementV3 {
    /// Exact authenticated public statement.
    pub fn statement(&self) -> SettlementStatementV3 {
        self.statement
    }
    /// Exact ELF and SP1 key identity used for verification.
    pub fn program(&self) -> ProgramIdentity {
        self.program
    }
    /// Exact SDK artifact retained after cryptographic verification.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>> {
        let bytes = bincode::serialize(&self.proof)?;
        if bytes.is_empty() || bytes.len() > MAX_GROTH16_ARTIFACT_BYTES {
            return Err(invalid("Groth16 artifact outside qualification bound"));
        }
        Ok(bytes)
    }
    /// Canonical 356-byte proof consumed by `sp1-verifier`.
    pub fn canonical_proof_bytes(&self) -> Result<Vec<u8>> {
        let bytes = self.proof.bytes();
        if bytes.len() != GROTH16_CONSENSUS_PROOF_BYTES {
            return Err(invalid("unexpected canonical Groth16 proof length"));
        }
        Ok(bytes)
    }
    /// Commitment to the exact V3 SDK proof policy used by this capability.
    #[cfg(feature = "source-settlement")]
    pub fn proof_policy_commitment(&self) -> Result<B256> {
        let full_vk_sha256: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
        validate_settlement_v2_groth16_wrapper_key(&self.proof)?;
        Ok(settlement_v3_groth16_proof_policy_commitment(
            sp1_sdk::SP1_CIRCUIT_VERSION,
            B256::from(full_vk_sha256),
        )?)
    }
}

#[cfg(feature = "source-settlement")]
fn validate_settlement_v2_groth16_wrapper_key(proof: &SP1ProofWithPublicValues) -> Result<()> {
    let expected: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
    let SP1Proof::Groth16(inner) = &proof.proof else {
        return Err(invalid("settlement proof-policy capability is not Groth16"));
    };
    if inner.groth16_vkey_hash != expected {
        return Err(invalid(
            "settlement Groth16 proof wrapper key differs from pinned full key",
        ));
    }
    Ok(())
}

impl QualifiedGroth16Execution {
    pub fn statement(&self) -> ExecutionStatement {
        self.statement
    }

    pub fn program(&self) -> ProgramIdentity {
        self.program
    }

    /// Exact SDK 6.8.0 bincode artifact that was cryptographically verified.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>> {
        let bytes = bincode::serialize(&self.proof)?;
        if bytes.is_empty() || bytes.len() > MAX_GROTH16_ARTIFACT_BYTES {
            return Err(invalid("Groth16 artifact outside qualification bound"));
        }
        Ok(bytes)
    }
}

/// Capability created only after successful SP1 verification and expectation
/// binding. No public constructor, deserializer or mutable proof accessor exists.
pub struct VerifiedExecutionStatement {
    statement: ExecutionStatement,
    program: ProgramIdentity,
    proof: SP1ProofWithPublicValues,
}

/// Capability obtainable only from the V2 guest, the trusted program identity,
/// real SP1 verification, and exact expectation comparison.
pub struct VerifiedSettlementStatementV2 {
    statement: SettlementStatementV2,
    program: ProgramIdentity,
    proof: SP1ProofWithPublicValues,
}

impl VerifiedSettlementStatementV2 {
    /// Exact authenticated public statement.
    pub fn statement(&self) -> SettlementStatementV2 {
        self.statement
    }
    /// Exact ELF and SP1 key identity used for verification.
    pub fn program(&self) -> ProgramIdentity {
        self.program
    }
    /// Exact bounded SDK artifact, suitable for deriving the transport digest.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>> {
        let size = bincode::serialized_size(&self.proof)?;
        if size > MAX_PROOF_BYTES as u64 {
            return Err(invalid("proof exceeds local byte limit"));
        }
        Ok(bincode::serialize(&self.proof)?)
    }
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

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 78
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn validate_groth16_envelope(proof: &SP1ProofWithPublicValues, public_len: usize) -> Result<()> {
    let SP1Proof::Groth16(inner) = &proof.proof else {
        return Err(invalid("only SP1 Groth16 proofs are permitted"));
    };
    if proof.tee_proof.is_some() {
        return Err(invalid("TEE attachments are not permitted in Groth16 qualification"));
    }
    if proof.sp1_version != sp1_sdk::SP1_CIRCUIT_VERSION {
        return Err(invalid("Groth16 proof circuit version differs from pinned SDK"));
    }
    if proof.public_values.as_slice().len() != public_len {
        return Err(invalid("wrong public statement length"));
    }
    if !inner.public_inputs.iter().all(|value| canonical_decimal(value)) {
        return Err(invalid("Groth16 public inputs are not canonical bounded decimals"));
    }
    if inner.encoded_proof.len() != GROTH16_ENCODED_HEX_LEN
        || !inner
            .encoded_proof
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("Groth16 encoded proof must be exactly 352 hexadecimal bytes"));
    }
    if inner.raw_proof.is_empty() || inner.raw_proof.len() > 16 * 1024 {
        return Err(invalid("Groth16 raw proof outside qualification bound"));
    }
    Ok(())
}

/// Strict SDK 6.8.0 fixed-integer bincode decoder for the opt-in Groth16
/// qualification artifact. Other proof modes and trailing bytes are rejected.
pub fn decode_groth16_proof(bytes: &[u8]) -> Result<SP1ProofWithPublicValues> {
    decode_groth16_proof_for_public_len(bytes, STATEMENT_LEN)
}

fn decode_groth16_proof_for_public_len(bytes: &[u8], public_len: usize) -> Result<SP1ProofWithPublicValues> {
    if bytes.len() < 4 || bytes.len() > MAX_GROTH16_ARTIFACT_BYTES {
        return Err(invalid("Groth16 artifact length outside qualification bound"));
    }
    // SP1Proof enum variant 3 is Groth16 in the pinned SDK 6.8.0 format.
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != 3 {
        return Err(invalid("encoded proof is not SP1 Groth16"));
    }
    let proof: SP1ProofWithPublicValues = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?;
    validate_groth16_envelope(&proof, public_len)?;
    Ok(proof)
}

/// Fixed V2 journal decoder. Callers cannot choose a shorter public-values
/// schema or reuse the legacy execution-statement decoder.
#[cfg(feature = "source-settlement")]
pub(crate) fn decode_groth16_settlement_v2_proof(bytes: &[u8]) -> Result<SP1ProofWithPublicValues> {
    decode_groth16_proof_for_public_len(bytes, SETTLEMENT_STATEMENT_V2_LEN)
}

pub fn load_groth16_proof(path: impl AsRef<Path>) -> Result<SP1ProofWithPublicValues> {
    load_groth16_proof_for_public_len(path, STATEMENT_LEN)
}

fn load_groth16_proof_for_public_len(path: impl AsRef<Path>, public_len: usize) -> Result<SP1ProofWithPublicValues> {
    let file = crate::open_regular(path.as_ref(), false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_GROTH16_ARTIFACT_BYTES as u64 {
        return Err(invalid("Groth16 proof must be a bounded nonempty regular file"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_GROTH16_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    decode_groth16_proof_for_public_len(&bytes, public_len)
}

#[cfg(test)]
mod groth16_tests {
    use super::*;
    use sp1_sdk::{SP1PublicValues, SP1_CIRCUIT_VERSION};
    use sp1_verifier::Groth16Bn254Proof;

    fn fake_envelope_len(public_len: usize) -> SP1ProofWithPublicValues {
        SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(Groth16Bn254Proof {
                public_inputs: std::array::from_fn(|_| "0".to_owned()),
                encoded_proof: "00".repeat(352),
                raw_proof: "not-a-proof".to_owned(),
                groth16_vkey_hash: [0; 32],
            }),
            public_values: SP1PublicValues::from(vec![0; public_len].as_slice()),
            sp1_version: SP1_CIRCUIT_VERSION.to_owned(),
            tee_proof: None,
        }
    }

    #[test]
    fn groth16_decoder_is_fail_closed_before_deserialization() {
        assert!(decode_groth16_proof(&[]).is_err());
        assert!(decode_groth16_proof(&0_u32.to_le_bytes()).is_err());
        assert!(decode_groth16_proof(&3_u32.to_le_bytes()).is_err());
        assert!(decode_groth16_proof(&vec![0; MAX_GROTH16_ARTIFACT_BYTES + 1]).is_err());
    }

    #[test]
    fn decimal_admission_is_canonical_and_bounded() {
        assert!(canonical_decimal("0"));
        assert!(canonical_decimal("123456789"));
        assert!(!canonical_decimal(""));
        assert!(!canonical_decimal("00"));
        assert!(!canonical_decimal("+1"));
        assert!(!canonical_decimal(&"9".repeat(79)));
    }

    #[test]
    fn groth16_decoder_accepts_only_the_bounded_canonical_envelope() {
        let proof = fake_envelope_len(STATEMENT_LEN);
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(decode_groth16_proof(&bytes).is_ok());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_groth16_proof(&trailing).is_err());

        let mut tee = fake_envelope_len(STATEMENT_LEN);
        tee.tee_proof = Some(vec![1]);
        assert!(decode_groth16_proof(&bincode::serialize(&tee).unwrap()).is_err());

        let SP1Proof::Groth16(inner) = &mut tee.proof else {
            unreachable!();
        };
        tee.tee_proof = None;
        inner.public_inputs[0] = "00".to_owned();
        assert!(decode_groth16_proof(&bincode::serialize(&tee).unwrap()).is_err());

        let mut uppercase = fake_envelope_len(STATEMENT_LEN);
        let SP1Proof::Groth16(inner) = &mut uppercase.proof else {
            unreachable!();
        };
        inner.encoded_proof = "AA".repeat(352);
        assert!(decode_groth16_proof(&bincode::serialize(&uppercase).unwrap()).is_err());
    }

    #[test]
    fn groth16_v2_envelope_is_length_separated_from_v1() {
        let proof = fake_envelope_len(SETTLEMENT_STATEMENT_V2_LEN);
        assert_eq!(proof.bytes().len(), GROTH16_CONSENSUS_PROOF_BYTES);
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(decode_groth16_proof(&bytes).is_err());
        assert!(decode_groth16_proof_for_public_len(&bytes, SETTLEMENT_STATEMENT_V2_LEN).is_ok());
    }

    #[test]
    fn groth16_v3_envelope_is_length_separated_from_v2() {
        let v3 = bincode::serialize(&fake_envelope_len(SETTLEMENT_STATEMENT_V3_LEN)).unwrap();
        let v2 = bincode::serialize(&fake_envelope_len(SETTLEMENT_STATEMENT_V2_LEN)).unwrap();
        assert!(decode_groth16_proof_for_public_len(&v3, SETTLEMENT_STATEMENT_V3_LEN).is_ok());
        assert!(decode_groth16_proof_for_public_len(&v3, SETTLEMENT_STATEMENT_V2_LEN).is_err());
        assert!(decode_groth16_proof_for_public_len(&v2, SETTLEMENT_STATEMENT_V3_LEN).is_err());
    }

    #[test]
    fn groth16_envelope_binds_the_pinned_circuit_version() {
        let mut proof = fake_envelope_len(SETTLEMENT_STATEMENT_V2_LEN);
        proof.sp1_version = "v0.0.0".to_owned();
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(decode_groth16_proof_for_public_len(&bytes, SETTLEMENT_STATEMENT_V2_LEN).is_err());
    }

    #[cfg(feature = "source-settlement")]
    #[test]
    fn proof_policy_uses_the_complete_sdk_wrapper_key() {
        let full_vk_sha256: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
        assert_eq!(GROTH16_VK_BYTES.len(), 492);
        assert_ne!(full_vk_sha256[..4], [0; 4]);
        assert!(settlement_v2_groth16_proof_policy_commitment(
            sp1_sdk::SP1_CIRCUIT_VERSION,
            B256::from(full_vk_sha256),
        )
        .is_ok());
    }

    #[cfg(feature = "source-settlement")]
    #[test]
    fn capability_admission_rejects_claimed_wrapper_key_mismatch() {
        let mut statement_bytes = vec![0; SETTLEMENT_STATEMENT_V2_LEN];
        statement_bytes[..bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG.len()]
            .copy_from_slice(bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG);
        let statement = SettlementStatementV2::decode(&statement_bytes).unwrap();
        let mut capability = QualifiedGroth16SettlementV2 {
            statement,
            program: ProgramIdentity {
                elf_keccak: B256::repeat_byte(1),
                verifying_key_hash: B256::repeat_byte(2),
                verifying_key_bn254: B256::repeat_byte(3),
            },
            proof: fake_envelope_len(SETTLEMENT_STATEMENT_V2_LEN),
        };
        assert!(validate_settlement_v2_groth16_wrapper_key(&capability.proof).is_err());
        assert!(capability.proof_policy_commitment().is_err());
        let SP1Proof::Groth16(inner) = &mut capability.proof.proof else {
            unreachable!();
        };
        inner.groth16_vkey_hash = Sha256::digest(*GROTH16_VK_BYTES).into();
        assert!(validate_settlement_v2_groth16_wrapper_key(&capability.proof).is_ok());
        assert!(capability.proof_policy_commitment().is_ok());
        capability.proof.proof = SP1Proof::Core(Vec::new());
        assert!(validate_settlement_v2_groth16_wrapper_key(&capability.proof).is_err());
        assert!(capability.proof_policy_commitment().is_err());
    }

    #[test]
    fn settlement_program_identity_binds_all_three_values() {
        let identity = ProgramIdentity {
            elf_keccak: B256::repeat_byte(1),
            verifying_key_hash: B256::repeat_byte(2),
            verifying_key_bn254: B256::repeat_byte(3),
        };
        let mut bytes = vec![0; SETTLEMENT_STATEMENT_V2_LEN];
        bytes[..bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG.len()]
            .copy_from_slice(bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG);
        let mut statement = SettlementStatementV2::decode(&bytes).unwrap();
        statement.program_elf_keccak = identity.elf_keccak;
        statement.program_vkey_koalabear = identity.verifying_key_hash;
        statement.program_vkey_bn254 = identity.verifying_key_bn254;
        assert!(statement_program_matches(&statement, identity));
        statement.program_elf_keccak[0] ^= 1;
        assert!(!statement_program_matches(&statement, identity));
        statement.program_elf_keccak = identity.elf_keccak;
        statement.program_vkey_koalabear[0] ^= 1;
        assert!(!statement_program_matches(&statement, identity));
        statement.program_vkey_koalabear = identity.verifying_key_hash;
        statement.program_vkey_bn254[0] ^= 1;
        assert!(!statement_program_matches(&statement, identity));
    }
}
