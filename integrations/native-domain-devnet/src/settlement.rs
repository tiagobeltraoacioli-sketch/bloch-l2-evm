// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant settlement payload; no native tag, transition or finality claim.
use crate::{Error, Reader, ValidatedV2Prefix};
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{node_primitives::NodeHeaderV2, proof_statement::SettlementStatementV2};

// This is a codec discriminator, not an assigned native transaction or state tag.
const CODEC_TAG: &[u8] = b"BLOCH:EXPERIMENTAL:SETTLEMENT-PAYLOAD:1";
const CODEC_V2_TAG: &[u8] = b"BLOCH:EXPERIMENTAL:SETTLEMENT-PAYLOAD:2";
const PROOF_POLICY_TAG: &[u8] = b"BLOCH:EXPERIMENTAL:SETTLEMENT-PROOF-POLICY:1";
const PROOF_SCHEME: &[u8] = b"SP1_GROTH16";
const FULL_WRAPPER_VK_HASH_POLICY: &[u8] = b"SHA256:FULL-WRAPPER-VK";
const PUBLIC_VALUES_POLICY: &[u8] = b"PUBLIC-VALUES:EXACT-SETTLEMENT-V2-BYTES";
const PUBLIC_VALUES_POLICY_V3: &[u8] = b"PUBLIC-VALUES:EXACT-SETTLEMENT-V3-BYTES";
const MAX_SP1_CIRCUIT_VERSION_BYTES: usize = 64;
const HASH_FIELDS: usize = 17;
const INTEGER_FIELDS: usize = 7;
/// Exact size of the only supported settlement payload version.
pub const SETTLEMENT_PAYLOAD_BYTES: usize = CODEC_TAG.len() + HASH_FIELDS * 32 + INTEGER_FIELDS * 8;
/// Exact canonical SP1 Groth16 verifier input: four-byte full-VK selector and
/// the 352-byte encoded proof. Public values remain in the statement.
pub const SP1_GROTH16_TRANSPORT_BYTES: u64 = 356;
/// Exact size of [`SettlementPayloadV2`]. V1 remains byte-for-byte unchanged.
pub const SETTLEMENT_PAYLOAD_V2_BYTES: usize = CODEC_V2_TAG.len() + 32 + (SETTLEMENT_PAYLOAD_BYTES - CODEC_TAG.len());
/// Host proof-file admission bound. Proof bytes are not embedded in this payload.
pub const MAX_SETTLEMENT_PROOF_BYTES: usize = 32 * 1024 * 1024;

fn read_hash(reader: &mut Reader<'_>) -> Result<B256, Error> {
    reader.take::<32>().map(B256::from)
}

/// Keccak-256 of exact canonical proof bytes after their external verification.
///
/// This function only enforces the shared host byte bound and nonempty input. It
/// does not parse, canonicalize or verify a proof, and does not make its bytes fit
/// in a native transaction or block.
pub fn proof_digest(canonical_proof_bytes: &[u8]) -> Result<B256, Error> {
    if canonical_proof_bytes.is_empty() {
        return Err(Error::Codec);
    }
    if canonical_proof_bytes.len() > MAX_SETTLEMENT_PROOF_BYTES {
        return Err(Error::Limit);
    }
    Ok(keccak256(canonical_proof_bytes))
}

/// Commitment to the complete proof policy selected by a verifier-facing host.
///
/// The scheme, canonical transport length, settlement statement tag and exact
/// public-values comparison policy are fixed here. The host must supply the exact
/// pinned SDK circuit version and SHA-256 of the complete Groth16 wrapper
/// verifying key, not the four-byte selector carried in a proof.
///
/// This proof-policy commitment is distinct from [`SettlementPayloadV2::commitment`],
/// which is Keccak-256 of the complete canonical PAYLOAD:2 encoding.
pub fn settlement_v2_groth16_proof_policy_commitment(
    sp1_circuit_version: &str,
    full_wrapper_vk_sha256: B256,
) -> Result<B256, Error> {
    groth16_proof_policy_commitment(
        sp1_circuit_version,
        full_wrapper_vk_sha256,
        bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V2_TAG,
        PUBLIC_VALUES_POLICY,
    )
}

/// Proof-policy commitment for the settlement V3 program. Same construction as
/// [`settlement_v2_groth16_proof_policy_commitment`] with the V3 statement tag
/// and `PUBLIC-VALUES:EXACT-SETTLEMENT-V3-BYTES`, so a V2 policy can never
/// admit V3 public values or the reverse. The native `bloch-l2-proof` crate
/// computes the same value independently (shared golden vector).
pub fn settlement_v3_groth16_proof_policy_commitment(
    sp1_circuit_version: &str,
    full_wrapper_vk_sha256: B256,
) -> Result<B256, Error> {
    groth16_proof_policy_commitment(
        sp1_circuit_version,
        full_wrapper_vk_sha256,
        bloch_l2_evm::proof_statement::SETTLEMENT_STATEMENT_V3_TAG,
        PUBLIC_VALUES_POLICY_V3,
    )
}

fn groth16_proof_policy_commitment(
    sp1_circuit_version: &str,
    full_wrapper_vk_sha256: B256,
    statement_tag: &[u8],
    public_values_policy: &[u8],
) -> Result<B256, Error> {
    let version = sp1_circuit_version.as_bytes();
    if version.is_empty()
        || version.len() > MAX_SP1_CIRCUIT_VERSION_BYTES
        || !version.iter().all(|byte| byte.is_ascii_graphic())
        || full_wrapper_vk_sha256 == B256::ZERO
    {
        return Err(Error::Configuration);
    }
    let mut encoded = Vec::with_capacity(
        PROOF_POLICY_TAG.len()
            + PROOF_SCHEME.len()
            + 8
            + 2
            + version.len()
            + FULL_WRAPPER_VK_HASH_POLICY.len()
            + 32
            + 2
            + statement_tag.len()
            + public_values_policy.len(),
    );
    encoded.extend_from_slice(PROOF_POLICY_TAG);
    encoded.extend_from_slice(PROOF_SCHEME);
    encoded.extend_from_slice(&SP1_GROTH16_TRANSPORT_BYTES.to_le_bytes());
    encoded.extend_from_slice(&(version.len() as u16).to_le_bytes());
    encoded.extend_from_slice(version);
    encoded.extend_from_slice(FULL_WRAPPER_VK_HASH_POLICY);
    encoded.extend_from_slice(full_wrapper_vk_sha256.as_slice());
    encoded.extend_from_slice(&(statement_tag.len() as u16).to_le_bytes());
    encoded.extend_from_slice(statement_tag);
    encoded.extend_from_slice(public_values_policy);
    Ok(keccak256(encoded))
}

/// Canonical candidate input to a future native settlement transition.
///
/// This value is inert. Construction, decoding and hashing do not verify a
/// proof, authenticate native state, advance a cursor or finalize an L2 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementPayload {
    pub network: B256,
    pub genesis: B256,
    pub domain: B256,
    pub configuration: B256,
    pub program_elf_keccak: B256,
    pub program_vkey_koalabear: B256,
    pub program_vkey_bn254: B256,
    pub proof_digest: B256,
    pub previous_settlement: B256,
    pub chain_id: u64,
    pub l2_number: u64,
    pub l2_parent_hash: B256,
    pub l2_previous_state_root: B256,
    pub l2_header_hash: B256,
    pub l2_state_root: B256,
    pub l1_block: B256,
    pub l1_slot: u64,
    pub l1_height: u64,
    pub source_commitment: B256,
    pub inbox_root: B256,
    pub inbox_count: u64,
    pub consumed_start: u64,
    pub consumed_end: u64,
    pub body_commitment: B256,
}

impl SettlementPayload {
    fn check(&self) -> Result<(), Error> {
        let identities = [
            self.network,
            self.genesis,
            self.domain,
            self.configuration,
            self.program_elf_keccak,
            self.program_vkey_koalabear,
            self.program_vkey_bn254,
            self.proof_digest,
            self.l2_parent_hash,
            self.l2_previous_state_root,
            self.l2_header_hash,
            self.l2_state_root,
            self.l1_block,
            self.source_commitment,
            self.inbox_root,
            self.body_commitment,
        ];
        if identities.contains(&B256::ZERO)
            || self.chain_id == 0
            || self.l2_number == 0
            || self.l1_height == 0
            || self.l1_slot < self.l1_height
        {
            return Err(Error::Configuration);
        }
        if self.consumed_start > self.consumed_end || self.consumed_end > self.inbox_count {
            return Err(Error::Mapping);
        }
        Ok(())
    }

    /// Copy the complete read-only selection into an inert candidate payload.
    ///
    /// Both program hashes and `proof_digest` must already have been established
    /// by a future proof verifier. This method only binds them to the selection;
    /// it deliberately accepts no proof bytes and performs no proof verification.
    pub fn from_validated_prefix(
        selected: &ValidatedV2Prefix,
        header: &NodeHeaderV2,
        program_elf_keccak: B256,
        program_vkey_koalabear: B256,
        program_vkey_bn254: B256,
        proof_digest: B256,
        previous_settlement: B256,
    ) -> Result<Self, Error> {
        let statement = selected.statement();
        let anchor = selected.anchor();
        let range = selected.range();
        if statement.header_hash != header.hash()
            || statement.domain != header.domain
            || statement.previous_state_root != header.parent_state_root
            || header.anchor_root != anchor.block
        {
            return Err(Error::Identity);
        }
        let payload = Self {
            network: selected.network(),
            genesis: selected.genesis(),
            domain: statement.domain,
            configuration: statement.configuration,
            program_elf_keccak,
            program_vkey_koalabear,
            program_vkey_bn254,
            proof_digest,
            previous_settlement,
            chain_id: header.chain_id,
            l2_number: header.number,
            l2_parent_hash: header.parent_hash,
            l2_previous_state_root: header.parent_state_root,
            l2_header_hash: statement.header_hash,
            l2_state_root: header.state_root,
            l1_block: anchor.block,
            l1_slot: anchor.slot,
            l1_height: anchor.height,
            source_commitment: selected.source_commitment(),
            inbox_root: selected.inbox_root(),
            inbox_count: selected.inbox_count(),
            consumed_start: range.start,
            consumed_end: range.end,
            body_commitment: selected.body_commitment(),
        };
        payload.check()?;
        Ok(payload)
    }

    /// Low-level value conversion from a V2 statement plus a claimed proof
    /// digest. This function does not establish that either input was verified.
    /// A verifier-facing crate must restrict its safe API to a private proof
    /// capability and derive `proof_digest` from canonical verified bytes.
    pub fn from_unverified_statement_v2(statement: SettlementStatementV2, proof_digest: B256) -> Result<Self, Error> {
        let payload = Self {
            network: statement.network,
            genesis: statement.genesis,
            domain: statement.domain,
            configuration: statement.configuration,
            program_elf_keccak: statement.program_elf_keccak,
            program_vkey_koalabear: statement.program_vkey_koalabear,
            program_vkey_bn254: statement.program_vkey_bn254,
            proof_digest,
            previous_settlement: statement.previous_settlement,
            chain_id: statement.chain_id,
            l2_number: statement.l2_number,
            l2_parent_hash: statement.l2_parent_hash,
            l2_previous_state_root: statement.l2_previous_state_root,
            l2_header_hash: statement.l2_header_hash,
            l2_state_root: statement.l2_state_root,
            l1_block: statement.l1_block,
            l1_slot: statement.l1_slot,
            l1_height: statement.l1_height,
            source_commitment: statement.source_commitment,
            inbox_root: statement.inbox_root,
            inbox_count: statement.inbox_count,
            consumed_start: statement.consumed_start,
            consumed_end: statement.consumed_end,
            body_commitment: statement.body_commitment,
        };
        payload.check()?;
        Ok(payload)
    }

    /// Exact fixed-width little-endian transport encoding.
    pub fn encode(&self) -> Result<[u8; SETTLEMENT_PAYLOAD_BYTES], Error> {
        self.check()?;
        let mut out = [0u8; SETTLEMENT_PAYLOAD_BYTES];
        let mut offset = 0;
        let mut write = |bytes: &[u8]| {
            let end = offset + bytes.len();
            out[offset..end].copy_from_slice(bytes);
            offset = end;
        };
        write(CODEC_TAG);
        for value in [
            self.network,
            self.genesis,
            self.domain,
            self.configuration,
            self.program_elf_keccak,
            self.program_vkey_koalabear,
            self.program_vkey_bn254,
            self.proof_digest,
            self.previous_settlement,
        ] {
            write(value.as_slice());
        }
        write(&self.chain_id.to_le_bytes());
        write(&self.l2_number.to_le_bytes());
        for value in [
            self.l2_parent_hash,
            self.l2_previous_state_root,
            self.l2_header_hash,
            self.l2_state_root,
            self.l1_block,
        ] {
            write(value.as_slice());
        }
        for value in [self.l1_slot, self.l1_height] {
            write(&value.to_le_bytes());
        }
        for value in [self.source_commitment, self.inbox_root] {
            write(value.as_slice());
        }
        for value in [self.inbox_count, self.consumed_start, self.consumed_end] {
            write(&value.to_le_bytes());
        }
        write(self.body_commitment.as_slice());
        debug_assert_eq!(offset, SETTLEMENT_PAYLOAD_BYTES);
        Ok(out)
    }

    /// Strict decoder: one known version, exact length and no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SETTLEMENT_PAYLOAD_BYTES || !bytes.starts_with(CODEC_TAG) {
            return Err(Error::Codec);
        }
        let mut reader = Reader(&bytes[CODEC_TAG.len()..]);
        let network = read_hash(&mut reader)?;
        let genesis = read_hash(&mut reader)?;
        let domain = read_hash(&mut reader)?;
        let configuration = read_hash(&mut reader)?;
        let program_elf_keccak = read_hash(&mut reader)?;
        let program_vkey_koalabear = read_hash(&mut reader)?;
        let program_vkey_bn254 = read_hash(&mut reader)?;
        let proof_digest = read_hash(&mut reader)?;
        let previous_settlement = read_hash(&mut reader)?;
        let chain_id = u64::from_le_bytes(reader.take()?);
        let l2_number = u64::from_le_bytes(reader.take()?);
        let l2_parent_hash = B256::from(reader.take::<32>()?);
        let l2_previous_state_root = B256::from(reader.take::<32>()?);
        let l2_header_hash = B256::from(reader.take::<32>()?);
        let l2_state_root = B256::from(reader.take::<32>()?);
        let l1_block = B256::from(reader.take::<32>()?);
        let l1_slot = u64::from_le_bytes(reader.take()?);
        let l1_height = u64::from_le_bytes(reader.take()?);
        let source_commitment = B256::from(reader.take::<32>()?);
        let inbox_root = B256::from(reader.take::<32>()?);
        let inbox_count = u64::from_le_bytes(reader.take()?);
        let consumed_start = u64::from_le_bytes(reader.take()?);
        let consumed_end = u64::from_le_bytes(reader.take()?);
        let body_commitment = B256::from(reader.take::<32>()?);
        if !reader.0.is_empty() {
            return Err(Error::Codec);
        }
        let payload = Self {
            network,
            genesis,
            domain,
            configuration,
            program_elf_keccak,
            program_vkey_koalabear,
            program_vkey_bn254,
            proof_digest,
            previous_settlement,
            chain_id,
            l2_number,
            l2_parent_hash,
            l2_previous_state_root,
            l2_header_hash,
            l2_state_root,
            l1_block,
            l1_slot,
            l1_height,
            source_commitment,
            inbox_root,
            inbox_count,
            consumed_start,
            consumed_end,
            body_commitment,
        };
        payload.check()?;
        Ok(payload)
    }

    /// Candidate payload commitment only; not a native transaction or receipt.
    pub fn commitment(&self) -> Result<B256, Error> {
        Ok(keccak256(self.encode()?))
    }
}

/// Version-2 settlement transport. It preserves every V1 field and adds the
/// independently derived proof-policy commitment under a distinct wire tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementPayloadV2 {
    pub payload: SettlementPayload,
    pub proof_policy: B256,
}

impl SettlementPayloadV2 {
    /// Low-level conversion only. The verifier-facing host is responsible for
    /// deriving both digests from its private verified capability and pinned SDK.
    pub fn from_unverified_statement_v2(
        statement: SettlementStatementV2,
        proof_digest: B256,
        proof_policy: B256,
    ) -> Result<Self, Error> {
        let value = Self {
            payload: SettlementPayload::from_unverified_statement_v2(statement, proof_digest)?,
            proof_policy,
        };
        value.check()?;
        Ok(value)
    }

    fn check(&self) -> Result<(), Error> {
        self.payload.check()?;
        if self.proof_policy == B256::ZERO {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; SETTLEMENT_PAYLOAD_V2_BYTES], Error> {
        self.check()?;
        let v1 = self.payload.encode()?;
        let mut out = [0u8; SETTLEMENT_PAYLOAD_V2_BYTES];
        let mut offset = 0;
        let mut write = |bytes: &[u8]| {
            let end = offset + bytes.len();
            out[offset..end].copy_from_slice(bytes);
            offset = end;
        };
        write(CODEC_V2_TAG);
        write(self.proof_policy.as_slice());
        write(&v1[CODEC_TAG.len()..]);
        debug_assert_eq!(offset, SETTLEMENT_PAYLOAD_V2_BYTES);
        Ok(out)
    }

    /// Decode the canonical structure and require a nonzero proof-policy field.
    ///
    /// This low-level codec cannot authenticate that policy. A verifier-facing
    /// boundary must recompute the policy from its pinned Groth16 proof and full
    /// wrapper key, then require exact equality before accepting this value.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SETTLEMENT_PAYLOAD_V2_BYTES || !bytes.starts_with(CODEC_V2_TAG) {
            return Err(Error::Codec);
        }
        let mut reader = Reader(&bytes[CODEC_V2_TAG.len()..]);
        let proof_policy = read_hash(&mut reader)?;
        let mut v1 = Vec::with_capacity(SETTLEMENT_PAYLOAD_BYTES);
        v1.extend_from_slice(CODEC_TAG);
        v1.extend_from_slice(reader.0);
        let value = Self {
            payload: SettlementPayload::decode(&v1)?,
            proof_policy,
        };
        value.check()?;
        Ok(value)
    }

    /// Keccak-256 of the complete canonical PAYLOAD:2 encoding. This is a
    /// candidate payload commitment only, not a native transaction or receipt.
    pub fn commitment(&self) -> Result<B256, Error> {
        Ok(keccak256(self.encode()?))
    }
}

#[cfg(test)]
mod tests;
