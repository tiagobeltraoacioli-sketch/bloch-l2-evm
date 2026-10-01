// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real CPU verification under the same full-key policy as native consensus.
use alloy_primitives::B256;
use bloch_l2_evm::native_settlement::{SettlementPolicyV1, SettlementProofVerifierV1};

/// Guest identity comes from the independently trusted recovery policy, never
/// from the proof or recovered record. The registry checks all other identities.
pub struct NativeGroth16Verifier {
    program: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidProofPolicy;

impl NativeGroth16Verifier {
    pub fn from_policy(policy: &SettlementPolicyV1) -> Result<Self, InvalidProofPolicy> {
        if policy.commitment().is_err() || policy.proof_policy.as_slice() != bloch_l2_proof::policy_commitment() {
            return Err(InvalidProofPolicy);
        }
        Ok(Self {
            program: policy.program_vkey_bn254.0,
        })
    }
}

impl SettlementProofVerifierV1 for NativeGroth16Verifier {
    fn verify(&self, policy: B256, values: &[u8], proof: &[u8]) -> bool {
        bloch_l2_proof::verify(&policy.0, &self.program, values, proof)
    }
}
