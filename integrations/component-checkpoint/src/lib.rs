// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached component review checkpoints. These do not establish consensus
//! finality, upgrade contracts, or authorize custody transfers.
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_DOCUMENT: usize = 1_048_576;
pub const MAX_LIFETIME: u64 = 456 * 86400;
const HYBRID: [u8; 4] = [0xb1, 0x0c, 0x01, 0x00];
fn check(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}
fn digest<T: Serialize>(domain: &[u8], value: &T) -> String {
    let mut h = Sha3_256::new();
    h.update(domain);
    h.update(serde_json::to_vec(value).expect("typed checkpoint serialization"));
    hex::encode(h.finalize())
}
fn decode(value: &str, size: usize) -> Result<Vec<u8>> {
    check(
        value.len() == size * 2 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical lowercase hex required",
    )?;
    hex::decode(value).map_err(|_| "invalid hex".into())
}
fn pin(value: &str, zero_allowed: bool) -> Result<()> {
    let bytes = decode(value, 32)?;
    check(zero_allowed || bytes.iter().any(|b| *b != 0), "zero commitment")
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    L2,
    Dex,
    Bridge,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub id: String,
    pub external: bool,
    /// Exact suite-enveloped ML-DSA-65 AND Falcon-1024 public key.
    pub public_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub version: u32,
    pub id: String,
    pub threshold: u8,
    pub min_external: u8,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signers: Vec<Signer>,
}
impl Registry {
    pub fn validate(&self) -> Result<()> {
        check(self.version == 1 && id(&self.id), "invalid registry version/id")?;
        check(
            self.signers.len() == 3
                && (2..=3).contains(&self.threshold)
                && self.min_external >= 1
                && self.min_external <= self.threshold,
            "three-holder quorum required",
        )?;
        check(
            self.valid_until > self.valid_from && self.valid_until - self.valid_from <= MAX_LIFETIME,
            "invalid registry lifetime",
        )?;
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut external = 0;
        for s in &self.signers {
            check(id(&s.id) && ids.insert(&s.id), "invalid/duplicate signer id")?;
            let key = decode(&s.public_key, 3749)?;
            check(
                key[..4] == HYBRID && keys.insert(key),
                "invalid suite/duplicate signer key",
            )?;
            external += u8::from(s.external);
        }
        check(external >= self.min_external, "missing external holders")
    }
    pub fn commitment(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(b"BLOCH-COMPONENT-SIGNERS-v1\0", self))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub component: Component,
    pub chain_id: String,
    pub genesis: String,
    pub sequence: u64,
    pub previous: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub state_root: String,
    /// SHA3-256 of the exact reviewed deployment/policy bytes.
    pub configuration_sha3: String,
    /// SHA3-256 of the exact reviewed artifact/evidence manifest bytes.
    pub artifacts_sha3: String,
    pub registry_sha3: String,
}
impl Checkpoint {
    pub fn validate(&self, registry: &Registry) -> Result<()> {
        check(self.version == 1 && id(&self.chain_id), "invalid checkpoint identity")?;
        check(
            self.sequence > 0 && self.finalized_height > 0,
            "positive sequence/finalized height required",
        )?;
        pin(&self.previous, self.sequence == 1)?;
        check(
            self.sequence != 1 || self.previous == "00".repeat(32),
            "first checkpoint must have zero predecessor",
        )?;
        for p in [
            &self.genesis,
            &self.finalized_hash,
            &self.state_root,
            &self.configuration_sha3,
            &self.artifacts_sha3,
        ] {
            pin(p, false)?;
        }
        check(
            self.registry_sha3 == registry.commitment()?,
            "registry commitment mismatch",
        )?;
        check(
            self.issued_at >= registry.valid_from
                && self.expires_at <= registry.valid_until
                && self.expires_at > self.issued_at
                && self.expires_at - self.issued_at <= MAX_LIFETIME,
            "invalid checkpoint lifetime",
        )
    }
    pub fn commitment(&self, registry: &Registry) -> Result<String> {
        self.validate(registry)?;
        Ok(digest(b"BLOCH-COMPONENT-CHECKPOINT-v1\0", self))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub signer: String,
    pub checkpoint_sha3: String,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub checkpoint: Checkpoint,
    pub signatures: Vec<DetachedSignature>,
}
/// Pinned independently of the downloaded envelope/registry. Rotation requires a
/// newly reviewed trust file; an envelope cannot change its own trust policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub version: u32,
    pub component: Component,
    pub chain_id: String,
    pub genesis: String,
    pub registry_sha3: String,
    pub configuration_sha3: String,
    pub artifacts_sha3: String,
    pub next_sequence: u64,
    pub previous: String,
    pub minimum_finalized_height: u64,
    pub maximum_age_seconds: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verified {
    pub component: Component,
    pub checkpoint_sha3: String,
    pub sequence: u64,
    pub finalized_height: u64,
    pub signer_ids: Vec<String>,
    pub external_signatures: u8,
    pub configuration_sha3: String,
    pub artifacts_sha3: String,
    pub consensus_finality_verified: bool,
    pub activation_authorized: bool,
}

pub fn sign(registry: &Registry, checkpoint: &Checkpoint, signer: &str, secret: &[u8]) -> Result<DetachedSignature> {
    let root = checkpoint.commitment(registry)?;
    check(
        secret.len() > 4 && secret[..4] == HYBRID,
        "hybrid secret envelope required",
    )?;
    let holder = registry
        .signers
        .iter()
        .find(|s| s.id == signer)
        .ok_or("unknown signer")?;
    let sig = bloch_crypto::crypto::sign(secret, &decode(&root, 32)?).map_err(|_| "signing failed")?;
    check(
        bloch_crypto::crypto::verify(&decode(&holder.public_key, 3749)?, &decode(&root, 32)?, &sig),
        "secret does not match registered public key",
    )?;
    Ok(DetachedSignature {
        signer: signer.into(),
        checkpoint_sha3: root,
        signature: hex::encode(sig),
    })
}

pub fn verify(registry: &Registry, envelope: &Envelope, trust: &Trust, now: u64) -> Result<Verified> {
    let cp = &envelope.checkpoint;
    let root = cp.commitment(registry)?;
    check(
        trust.version == 1
            && trust.component == cp.component
            && trust.chain_id == cp.chain_id
            && trust.genesis == cp.genesis
            && trust.registry_sha3 == cp.registry_sha3,
        "component/network/registry trust mismatch",
    )?;
    check(
        trust.configuration_sha3 == cp.configuration_sha3 && trust.artifacts_sha3 == cp.artifacts_sha3,
        "reviewed configuration/artifacts mismatch",
    )?;
    check(
        trust.next_sequence == cp.sequence
            && trust.previous == cp.previous
            && cp.finalized_height >= trust.minimum_finalized_height,
        "checkpoint sequence/predecessor/height rollback",
    )?;
    check(
        trust.maximum_age_seconds > 0
            && trust.maximum_age_seconds <= MAX_LIFETIME
            && cp.issued_at <= now
            && now < cp.expires_at
            && now - cp.issued_at <= trust.maximum_age_seconds,
        "checkpoint expired, stale or from the future",
    )?;
    check(
        envelope.signatures.len() >= registry.threshold as usize && envelope.signatures.len() <= 3,
        "signature quorum not met",
    )?;
    let mut seen = BTreeSet::new();
    let mut external = 0;
    for sig in &envelope.signatures {
        check(
            seen.insert(sig.signer.clone()) && sig.checkpoint_sha3 == root,
            "duplicate signer or detached digest mismatch",
        )?;
        let holder = registry
            .signers
            .iter()
            .find(|s| s.id == sig.signer)
            .ok_or("unknown signer")?;
        check(
            sig.signature.len() <= 16_384 && sig.signature.len() >= 8 && sig.signature.len() % 2 == 0,
            "signature size limit",
        )?;
        let raw = decode(&sig.signature, sig.signature.len() / 2)?;
        check(raw[..4] == HYBRID, "hybrid signature suite required")?;
        check(
            bloch_crypto::crypto::verify(&decode(&holder.public_key, 3749)?, &decode(&root, 32)?, &raw),
            "invalid hybrid signature",
        )?;
        external += u8::from(holder.external);
    }
    check(external >= registry.min_external, "external signature quorum not met")?;
    Ok(Verified {
        component: cp.component,
        checkpoint_sha3: root,
        sequence: cp.sequence,
        finalized_height: cp.finalized_height,
        signer_ids: seen.into_iter().collect(),
        external_signatures: external,
        configuration_sha3: cp.configuration_sha3.clone(),
        artifacts_sha3: cp.artifacts_sha3.clone(),
        consensus_finality_verified: false,
        activation_authorized: false,
    })
}
