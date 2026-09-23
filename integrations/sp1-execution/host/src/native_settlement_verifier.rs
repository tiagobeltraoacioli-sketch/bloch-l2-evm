// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real, dormant SP1 Groth16 verifier for the native-settlement V1 boundary.
//!
//! This module implements only deterministic proof verification. It does not
//! assign a native transaction tag, authenticate a settlement expectation,
//! persist state, expose RPC, or activate consensus.

use crate::{
    verification::{ProgramIdentity, TrustedProgram, GROTH16_CONSENSUS_PROOF_BYTES},
    Result,
};
use alloy_primitives::B256;
use bloch_l2_evm::{
    native_settlement::SettlementProofVerifierV1,
    proof_statement::{SettlementStatementV2, SETTLEMENT_STATEMENT_V2_LEN},
};
use bloch_native_domain_devnet::settlement_v2_groth16_proof_policy_commitment;
use sha2::{Digest, Sha256};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

/// Derive the only proof-policy identity this build can verify.
///
/// The commitment pins the SP1 circuit version, exact 356-byte Groth16
/// transport, complete wrapper verification key, settlement statement schema,
/// and exact-public-values comparison rule.
pub fn native_settlement_proof_policy() -> Result<B256> {
    let full_vk_sha256: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
    Ok(settlement_v2_groth16_proof_policy_commitment(
        sp1_sdk::SP1_CIRCUIT_VERSION,
        B256::from(full_vk_sha256),
    )?)
}

/// A verifier tied to one independently selected guest ELF and the SP1 6.8.0
/// Groth16 wrapper key compiled into this binary.
///
/// Construction from [`TrustedProgram`] prevents callers from supplying a
/// free-form program hash. The native registry must separately pin the same
/// program identity and proof-policy commitment in its consensus policy.
pub struct Sp1SettlementProofVerifierV1<'a> {
    program: &'a TrustedProgram,
    proof_policy: B256,
}

impl<'a> Sp1SettlementProofVerifierV1<'a> {
    /// Bind the adapter to an operator-authenticated ELF already set up by the
    /// fixed `LightProver` backend.
    pub fn new(program: &'a TrustedProgram) -> Result<Self> {
        Ok(Self {
            program,
            proof_policy: native_settlement_proof_policy()?,
        })
    }

    /// Exact commitment which the dormant native policy must pin.
    pub const fn proof_policy(&self) -> B256 {
        self.proof_policy
    }

    /// Exact program identity derived from the trusted ELF.
    pub fn program_identity(&self) -> ProgramIdentity {
        self.program.identity()
    }
}

impl SettlementProofVerifierV1 for Sp1SettlementProofVerifierV1<'_> {
    fn verify(&self, proof_policy: B256, public_values: &[u8], proof: &[u8]) -> bool {
        verify_canonical_groth16(
            self.proof_policy,
            self.program.identity(),
            &self.program.verifying_key_bn254_string(),
            proof_policy,
            public_values,
            proof,
        )
    }
}

fn verify_canonical_groth16(
    expected_policy: B256,
    expected_program: ProgramIdentity,
    program_vkey_bn254: &str,
    proof_policy: B256,
    public_values: &[u8],
    proof: &[u8],
) -> bool {
    if proof_policy != expected_policy
        || expected_policy == B256::ZERO
        || public_values.len() != SETTLEMENT_STATEMENT_V2_LEN
        || proof.len() != GROTH16_CONSENSUS_PROOF_BYTES
    {
        return false;
    }

    let Ok(statement) = SettlementStatementV2::decode(public_values) else {
        return false;
    };
    if statement.encode().as_slice() != public_values
        || statement.program_elf_keccak != expected_program.elf_keccak()
        || statement.program_vkey_koalabear != expected_program.verifying_key_hash()
        || statement.program_vkey_bn254 != expected_program.verifying_key_bn254()
    {
        return false;
    }

    // Make the canonical wrapper-key selector check explicit at this boundary;
    // `Groth16Verifier::verify` repeats it before parsing the proof.
    let wrapper_vk_sha256: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
    if proof[..4] != wrapper_vk_sha256[..4] {
        return false;
    }

    Groth16Verifier::verify(proof, public_values, program_vkey_bn254, &GROTH16_VK_BYTES).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(identity: ProgramIdentity) -> Vec<u8> {
        let mut bytes = vec![0; SETTLEMENT_STATEMENT_V2_LEN];
        bytes[..bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG.len()]
            .copy_from_slice(bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG);
        let mut statement = SettlementStatementV2::decode(&bytes).unwrap();
        statement.program_elf_keccak = identity.elf_keccak();
        statement.program_vkey_koalabear = identity.verifying_key_hash();
        statement.program_vkey_bn254 = identity.verifying_key_bn254();
        statement.encode().to_vec()
    }

    #[test]
    fn proof_policy_pins_the_complete_nonzero_wrapper_key() {
        assert_eq!(GROTH16_VK_BYTES.len(), 492);
        assert_ne!(native_settlement_proof_policy().unwrap(), B256::ZERO);
    }

    #[test]
    fn malformed_inputs_fail_before_cryptographic_acceptance() {
        let identity = ProgramIdentity::test_fixture(1);
        let policy = native_settlement_proof_policy().unwrap();
        let public_values = statement(identity);
        let mut proof = vec![0; GROTH16_CONSENSUS_PROOF_BYTES];
        proof[..4].copy_from_slice(&Sha256::digest(*GROTH16_VK_BYTES)[..4]);

        assert!(!verify_canonical_groth16(
            policy,
            identity,
            "0x01",
            B256::repeat_byte(9),
            &public_values,
            &proof,
        ));
        assert!(!verify_canonical_groth16(
            policy,
            identity,
            "0x01",
            policy,
            &public_values[..public_values.len() - 1],
            &proof,
        ));
        assert!(!verify_canonical_groth16(
            policy,
            identity,
            "0x01",
            policy,
            &public_values,
            &proof[..proof.len() - 1],
        ));

        let other_identity = ProgramIdentity::test_fixture(8);
        assert!(!verify_canonical_groth16(
            policy,
            other_identity,
            "0x01",
            policy,
            &public_values,
            &proof,
        ));

        proof[0] ^= 1;
        assert!(!verify_canonical_groth16(
            policy,
            identity,
            "0x01",
            policy,
            &public_values,
            &proof,
        ));
    }

    #[test]
    fn correctly_framed_but_invalid_proof_is_rejected_cryptographically() {
        let identity = ProgramIdentity::test_fixture(1);
        let policy = native_settlement_proof_policy().unwrap();
        let public_values = statement(identity);
        let mut proof = vec![0; GROTH16_CONSENSUS_PROOF_BYTES];
        proof[..4].copy_from_slice(&Sha256::digest(*GROTH16_VK_BYTES)[..4]);

        assert!(!verify_canonical_groth16(
            policy,
            identity,
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            policy,
            &public_values,
            &proof,
        ));
    }
}
