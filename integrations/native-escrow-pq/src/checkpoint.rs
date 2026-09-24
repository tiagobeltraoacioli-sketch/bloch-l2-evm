// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real PQ quorum authentication of an externally trusted signer arrangement.
//! A signed weak-subjectivity anchor is not an independently proven FFG history.
use alloy_primitives::B256;
use bloch_l2_evm::l1::FinalizedCheckpoint;
use bloch_pos_committee::{
    header::{BlockHeaderV4, BlockId},
    staking::HybridKeyVerifier,
    ws::{self, CheckpointEnvelope, EnvelopeReject, SignerSet, WeakSubjectivityCheckpoint},
};

/// Explicit release policy, never inferred from an envelope's claimed threshold.
#[derive(Debug, Clone, Copy)]
pub enum Phase {
    A,
    B,
}
impl Phase {
    fn shape(self) -> (usize, usize, usize) {
        match self {
            Self::A => (
                ws::WS_PHASE_A_THRESHOLD,
                ws::WS_PHASE_A_SIGNERS,
                ws::WS_PHASE_A_MIN_EXTERNAL,
            ),
            Self::B => (
                ws::WS_PHASE_B_THRESHOLD,
                ws::WS_PHASE_B_SIGNERS,
                ws::WS_PHASE_B_MIN_EXTERNAL,
            ),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointError {
    Arrangement,
    Limit,
    Future,
    Stale,
    AdoptionWindow,
    Envelope(EnvelopeReject),
    Header,
    Rollback,
    Conflict,
}

struct NativeVerifier;
impl HybridKeyVerifier for NativeVerifier {
    fn verify_mldsa65(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify_mldsa65_raw(key, root, signature)
    }
    fn verify_falcon1024(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::falcon::verify(key, root, signature)
    }
}

/// Immutable operator/release-authenticated policy. Signer identity and external
/// independence are out-of-band trust inputs; cryptography cannot establish them.
pub struct CheckpointPolicy {
    network: u32,
    genesis: [u8; 32],
    set: SignerSet,
    phase: Phase,
}
/// Private verified provenance, obtained only after real hybrid/quorum/header checks.
#[derive(Debug, Clone)]
pub struct VerifiedCheckpoint {
    checkpoint: WeakSubjectivityCheckpoint,
    anchor: FinalizedCheckpoint,
    policy_identity: B256,
    checked_at_epoch: u64,
    review_due: bool,
}
impl VerifiedCheckpoint {
    /// Anchor accepted by the existing header/body verifier. Its slot comes from
    /// the authenticated canonical header, not an epoch-to-height conversion.
    pub fn anchor(&self) -> FinalizedCheckpoint {
        self.anchor
    }
    pub fn digest(&self) -> B256 {
        B256::from(self.checkpoint.ws_digest())
    }
    pub fn epoch(&self) -> u64 {
        self.checkpoint.epoch
    }
    pub fn state_root(&self) -> B256 {
        B256::from(self.checkpoint.state_root)
    }
    pub fn arrangement_review_due(&self) -> bool {
        self.review_due
    }
    /// Exact immutable signer/chain policy that authenticated this checkpoint.
    pub fn policy_identity(&self) -> B256 {
        self.policy_identity
    }
    /// Independently supplied epoch at which freshness was last checked.
    pub fn checked_at_epoch(&self) -> u64 {
        self.checked_at_epoch
    }
}
impl CheckpointPolicy {
    /// Storage identity for this exact out-of-band policy, including key order.
    pub(crate) fn storage_identity(&self) -> B256 {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"BLOCH:EXPERIMENTAL:WS:POLICY:1");
        h.update(self.network.to_le_bytes());
        h.update(self.genesis);
        h.update(self.set.id.to_le_bytes());
        h.update(self.set.adopted_epoch.to_le_bytes());
        let (threshold, count, external) = self.phase.shape();
        for n in [threshold, count, external] {
            h.update((n as u64).to_le_bytes());
        }
        for signer in &self.set.signers {
            h.update(signer.pubkey);
            h.update([u8::from(signer.external)]);
        }
        B256::from_slice(&h.finalize())
    }
    /// Bind independently authenticated keys and chain identity. Duplicate keys,
    /// self-declared weaker thresholds and overflowing review clocks are refused.
    pub fn new(network: u32, genesis: [u8; 32], set: SignerSet, phase: Phase) -> Result<Self, CheckpointError> {
        let (threshold, count, external) = phase.shape();
        if genesis == [0; 32]
            || set.id == ws::WS_GENESIS_SIGNER_SET_ID
            || !set.matches_policy(threshold, count, external)
            || set
                .adopted_epoch
                .checked_add(ws::WS_ARRANGEMENT_REVIEW_EPOCHS)
                .and_then(|e| e.checked_add(ws::WS_ARRANGEMENT_GRACE_EPOCHS))
                .is_none()
            || set
                .signers
                .iter()
                .enumerate()
                .any(|(i, signer)| set.signers[..i].iter().any(|other| other.pubkey == signer.pubkey))
        {
            return Err(CheckpointError::Arrangement);
        }
        Ok(Self {
            network,
            genesis,
            set,
            phase,
        })
    }

    /// Authenticate a bootstrap anchor. `current_epoch` must come from a trusted
    /// local clock/chain schedule, never the envelope's issued_at or an RPC claim.
    /// Persist/reverify the last accepted checkpoint separately to retain rollback
    /// protection across restarts. This does not override a running node's finality.
    pub fn verify(
        &self,
        envelope: &CheckpointEnvelope,
        header: &[u8],
        current_epoch: u64,
        previous: Option<&VerifiedCheckpoint>,
    ) -> Result<VerifiedCheckpoint, CheckpointError> {
        if header.len() != 304
            || envelope.signatures.len() > self.set.signers.len()
            || envelope.signatures.iter().any(|(_, signature)| signature.len() > 8192)
        {
            return Err(CheckpointError::Limit);
        }
        let cp = &envelope.checkpoint;
        let age = current_epoch.checked_sub(cp.epoch).ok_or(CheckpointError::Future)?;
        if age >= ws::WS_PERIOD_EPOCHS {
            return Err(CheckpointError::Stale);
        }
        if cp.epoch < self.set.adopted_epoch {
            return Err(CheckpointError::AdoptionWindow);
        }
        let (threshold, count, external) = self.phase.shape();
        let verified = ws::verify_envelope_with_shape_policy(
            envelope,
            &self.set,
            self.network,
            &self.genesis,
            &NativeVerifier,
            threshold,
            count,
            external,
        )
        .map_err(CheckpointError::Envelope)?;
        let native = BlockHeaderV4::canonical_deserialize(header).map_err(|_| CheckpointError::Header)?;
        if native.version != 0xb10c_0005
            || BlockId::of(&native).as_bytes() != &cp.block_root
            || native.state_root != cp.state_root
        {
            return Err(CheckpointError::Header);
        }
        if let Some(old) = previous {
            if old.checkpoint.network_id != self.network || old.checkpoint.genesis_root != self.genesis {
                return Err(CheckpointError::Arrangement);
            }
            if cp.epoch < old.epoch() {
                return Err(CheckpointError::Rollback);
            }
            if cp.epoch == old.epoch() && cp.ws_digest() != old.checkpoint.ws_digest() {
                return Err(CheckpointError::Conflict);
            }
        }
        Ok(VerifiedCheckpoint {
            checkpoint: *cp,
            anchor: FinalizedCheckpoint {
                block: B256::from(cp.block_root),
                slot: native.slot,
            },
            policy_identity: self.storage_identity(),
            checked_at_epoch: current_epoch,
            review_due: verified.arrangement_past_review,
        })
    }
}
