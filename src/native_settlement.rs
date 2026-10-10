// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant, versioned native-settlement transition kernel.
//!
//! This module deliberately assigns no Genesis-4 transaction tag, state key,
//! activation height, proof implementation or RPC finality rule.  It models the
//! deterministic checks a future native consensus adapter must perform after it
//! has independently authenticated the source snapshot and selected the exact
//! L2 successor.  [`SettlementExpectationV1`] is plain data, not an
//! authentication capability; consensus must derive it from committed native
//! state rather than from the transaction proposer.

use crate::proof_statement::{SettlementStatementV2, SettlementStatementV2Error, SETTLEMENT_STATEMENT_V2_LEN};
use alloc::vec::Vec;
use alloy_primitives::B256;
use sha3::{Digest, Sha3_256};

#[cfg(feature = "std")]
pub mod store;

/// Experimental wire discriminator. It is not an assigned native transaction tag.
pub const EXPERIMENTAL_SETTLEMENT_TX_V1_TAG: &[u8] = b"BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-TX:1";
/// The only proof transport admitted by this version: SP1 Groth16's canonical
/// four-byte verifier-key selector followed by its 352-byte encoded proof.
pub const SETTLEMENT_PROOF_V1_BYTES: usize = 356;
/// Exact V1 transaction length. Fixed width prevents ambiguous framing and
/// allocation controlled by untrusted length fields.
pub const SETTLEMENT_TX_V1_BYTES: usize =
    EXPERIMENTAL_SETTLEMENT_TX_V1_TAG.len() + 32 + SETTLEMENT_STATEMENT_V2_LEN + SETTLEMENT_PROOF_V1_BYTES;
/// Native development format assigned by the separately pinned consensus implementation.
///
/// HISTORICAL: this is the pre-2026-10-10 synchronous settlement byte, kept so
/// recorded development history (and the real fixtures under
/// `tests/fixtures/native-settlement/`) still decodes. The native branch
/// `codex/native-l2-v3-m1-20261010` moved its L2 tags past the mainnet
/// transaction space (mainnet assigns 0x0E-0x11 to funded delegation):
/// settlement 0x12, async settlement 0x13, L2 deposit 0x14. A tool targeting a
/// network built from that branch must use [`NATIVE_SETTLEMENT_TAG_V2`].
pub const NATIVE_SETTLEMENT_TAG: u8 = 0x0e;
/// Renumbered native synchronous settlement tag (see [`NATIVE_SETTLEMENT_TAG`]).
pub const NATIVE_SETTLEMENT_TAG_V2: u8 = 0x12;
/// Renumbered native asynchronous settlement tag (was 0x0F).
pub const NATIVE_ASYNC_SETTLEMENT_TAG_V2: u8 = 0x13;
/// Renumbered native L2 deposit tag (was 0x10).
pub const NATIVE_L2_DEPOSIT_TAG_V2: u8 = 0x14;
/// Exact native envelope size, with no user-controlled length fields.
pub const NATIVE_SETTLEMENT_BYTES: usize = 1 + 32 + SETTLEMENT_STATEMENT_V2_LEN + SETTLEMENT_PROOF_V1_BYTES;

/// Versioned native wire-tag sets. A tool selects the set of the network it
/// targets; it never mixes bytes from two sets.
///
/// * [`NativeWireTags::V1`] — development history before 2026-10-10 (devnet1..3):
///   0x0E settlement, 0x0F async settlement, 0x10 deposit. These collide with
///   the mainnet funded-delegation tags and are kept only so recorded history
///   and the real V2 fixtures still decode.
/// * [`NativeWireTags::V2`] — every network built from the renumbered native
///   branch (devnet4 onward): 0x12, 0x13, 0x14. The settlement V3 frame
///   ([`NativeSettlementFrameV3`]) exists only under this set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeWireTags {
    /// Synchronous settlement transaction tag.
    pub settlement: u8,
    /// Asynchronous settlement transaction tag.
    pub settlement_async: u8,
    /// Native L2 deposit transaction tag.
    pub deposit: u8,
}
impl NativeWireTags {
    /// Historical development tag set (devnet3 and earlier).
    pub const V1: Self = Self {
        settlement: NATIVE_SETTLEMENT_TAG,
        settlement_async: 0x0f,
        deposit: 0x10,
    };
    /// Renumbered tag set, past the mainnet transaction space (0x00..=0x11).
    pub const V2: Self = Self {
        settlement: NATIVE_SETTLEMENT_TAG_V2,
        settlement_async: NATIVE_ASYNC_SETTLEMENT_TAG_V2,
        deposit: NATIVE_L2_DEPOSIT_TAG_V2,
    };
}

/// Exact native settlement V3 transaction length: tag, proof-policy hash,
/// 766-byte V3 statement, 356-byte Groth16 proof (1155 bytes).
pub const NATIVE_SETTLEMENT_V3_BYTES: usize =
    1 + 32 + crate::proof_statement::SETTLEMENT_STATEMENT_V3_LEN + SETTLEMENT_PROOF_V1_BYTES;

/// Which native settlement transaction carries a V3 statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSettlementModeV3 {
    /// `L2Settlement` (0x12).
    Synchronous,
    /// `L2SettlementAsync` (0x13), used by the asynchronous development genesis.
    Asynchronous,
}
impl NativeSettlementModeV3 {
    /// Wire tag under the renumbered tag set. V3 is never framed with V1 tags.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Synchronous => NativeWireTags::V2.settlement,
            Self::Asynchronous => NativeWireTags::V2.settlement_async,
        }
    }
}

/// Native settlement transaction carrying a [`SettlementStatementV3`]:
/// `tag || proof_policy || statement (766) || proof (356)`. This is the exact
/// byte layout the native `l2_settlement::Transaction` decodes at 1155 bytes.
/// The shared golden vector in `tests/native_settlement_v3_frame.rs` is
/// reproduced independently by the native crate.
///
/// [`SettlementStatementV3`]: crate::proof_statement::SettlementStatementV3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSettlementFrameV3 {
    /// Synchronous or asynchronous settlement.
    pub mode: NativeSettlementModeV3,
    /// Pinned proof-policy commitment (`bloch_l2_proof::policy_commitment_v3`).
    pub proof_policy: B256,
    /// Exact proven public values.
    pub statement: crate::proof_statement::SettlementStatementV3,
    /// SP1 Groth16 selector plus encoded proof.
    pub proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
}
impl NativeSettlementFrameV3 {
    /// Encode the exact 1155-byte native transaction.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NATIVE_SETTLEMENT_V3_BYTES);
        bytes.push(self.mode.tag());
        bytes.extend_from_slice(self.proof_policy.as_slice());
        bytes.extend_from_slice(&self.statement.encode());
        bytes.extend_from_slice(&self.proof);
        debug_assert_eq!(bytes.len(), NATIVE_SETTLEMENT_V3_BYTES);
        bytes
    }

    /// Decode exactly one V3 frame. Historical V1 tags (0x0E/0x0F), the V2
    /// statement length, prefixes and suffixes are all refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementError> {
        if bytes.len() != NATIVE_SETTLEMENT_V3_BYTES {
            return Err(SettlementError::Encoding);
        }
        let mode = match bytes[0] {
            tag if tag == NativeSettlementModeV3::Synchronous.tag() => NativeSettlementModeV3::Synchronous,
            tag if tag == NativeSettlementModeV3::Asynchronous.tag() => NativeSettlementModeV3::Asynchronous,
            _ => return Err(SettlementError::Encoding),
        };
        let end = 33 + crate::proof_statement::SETTLEMENT_STATEMENT_V3_LEN;
        let statement = crate::proof_statement::SettlementStatementV3::decode(&bytes[33..end])
            .map_err(SettlementError::Statement)?;
        Ok(Self {
            mode,
            proof_policy: B256::from_slice(&bytes[1..33]),
            statement,
            proof: bytes[end..].try_into().map_err(|_| SettlementError::Encoding)?,
        })
    }
}

/// Explicit framing; exact native bytes must never be replaced inside inclusion evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementWireFormat {
    /// Original unassigned tagged transport; historical encodings remain unchanged.
    ExperimentalV1,
    /// Assigned 0x0E native development transport with an empty inbox.
    NativeV1,
}

// Independent implementation of the native empty-source rule, checked on both
// admission and historical replay. The containing header separately binds parent.
fn check_native_source(statement: &SettlementStatementV2, previous: B256) -> Result<(), SettlementError> {
    let mut hash = Sha3_256::new();
    hash.update(b"BLOCH:NATIVE:L2:EMPTY-SOURCE:1");
    for value in [
        statement.network,
        statement.genesis,
        statement.domain,
        previous,
        statement.l1_block,
    ] {
        hash.update(value);
    }
    hash.update(statement.l1_slot.to_le_bytes());
    hash.update(statement.l1_height.to_le_bytes());
    hash.update(statement.inbox_root);
    if B256::from_slice(&hash.finalize()) != statement.source_commitment {
        return Err(SettlementError::Transition);
    }
    Ok(())
}

/// Consensus-pinned identities for the dormant V1 transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementPolicyV1 {
    /// Native network identity.
    pub network: B256,
    /// Native genesis identity.
    pub genesis: B256,
    /// L2 execution domain.
    pub domain: B256,
    /// Commitment to the complete L2 configuration.
    pub configuration: B256,
    /// Keccak-256 of the selected guest ELF.
    pub program_elf_keccak: B256,
    /// SP1 KoalaBear verification-key digest.
    pub program_vkey_koalabear: B256,
    /// SP1 BN254 verification-key projection.
    pub program_vkey_bn254: B256,
    /// Commitment to the complete deterministic proof policy.
    pub proof_policy: B256,
    /// EVM replay-protection chain ID.
    pub chain_id: u64,
    /// First L2 block number this fresh registry may accept.
    pub first_l2_number: u64,
    /// Canonical L2 head which the first accepted block must extend.
    pub initial_l2_parent_hash: B256,
    /// Canonical state root before the first accepted block.
    pub initial_l2_state_root: B256,
}

impl SettlementPolicyV1 {
    fn check(&self) -> Result<(), SettlementError> {
        if [
            self.network,
            self.genesis,
            self.domain,
            self.configuration,
            self.program_elf_keccak,
            self.program_vkey_koalabear,
            self.program_vkey_bn254,
            self.proof_policy,
            self.initial_l2_parent_hash,
            self.initial_l2_state_root,
        ]
        .contains(&B256::ZERO)
            || self.chain_id == 0
            || self.first_l2_number == 0
        {
            return Err(SettlementError::Policy);
        }
        Ok(())
    }

    /// Domain-separated SHA3-256 commitment to every policy field. Integers
    /// are little-endian, matching the dormant native payload conventions.
    pub fn commitment(&self) -> Result<B256, SettlementError> {
        self.check()?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-POLICY:1");
        for value in [
            self.network,
            self.genesis,
            self.domain,
            self.configuration,
            self.program_elf_keccak,
            self.program_vkey_koalabear,
            self.program_vkey_bn254,
            self.proof_policy,
            self.initial_l2_parent_hash,
            self.initial_l2_state_root,
        ] {
            hasher.update(value);
        }
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.first_l2_number.to_le_bytes());
        Ok(B256::from_slice(&hasher.finalize()))
    }
}

/// Canonical fixed-width V1 transaction candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementTransactionV1 {
    proof_policy: B256,
    statement: SettlementStatementV2,
    proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
}

impl SettlementTransactionV1 {
    /// Decode exactly one of the two bounded envelopes. The legacy decoder
    /// remains strict; this entry point is reserved for envelope-aware adapters.
    pub fn decode_wire(bytes: &[u8]) -> Result<(Self, SettlementWireFormat), SettlementError> {
        if bytes.len() == NATIVE_SETTLEMENT_BYTES && bytes.first() == Some(&NATIVE_SETTLEMENT_TAG) {
            let statement = SettlementStatementV2::decode(&bytes[33..33 + SETTLEMENT_STATEMENT_V2_LEN])
                .map_err(SettlementError::Statement)?;
            if statement.inbox_count != 0
                || statement.consumed_start != 0
                || statement.consumed_end != 0
                || statement.inbox_root != B256::from_slice(&Sha3_256::digest(b"BLOCH:NATIVE:L2:EMPTY-INBOX:1"))
            {
                return Err(SettlementError::Transition);
            }
            let tx = Self::new(
                B256::from_slice(&bytes[1..33]),
                statement,
                bytes[33 + SETTLEMENT_STATEMENT_V2_LEN..]
                    .try_into()
                    .map_err(|_| SettlementError::Encoding)?,
            )?;
            Ok((tx, SettlementWireFormat::NativeV1))
        } else {
            Self::decode(bytes).map(|tx| (tx, SettlementWireFormat::ExperimentalV1))
        }
    }

    /// Encode the selected complete envelope. The predecessor commitment is
    /// unchanged; admission commitments separately bind these exact wire bytes.
    pub fn encode_wire(&self, format: SettlementWireFormat) -> Vec<u8> {
        let legacy = self.encode();
        match format {
            SettlementWireFormat::ExperimentalV1 => legacy.to_vec(),
            SettlementWireFormat::NativeV1 => {
                let mut bytes = Vec::with_capacity(NATIVE_SETTLEMENT_BYTES);
                bytes.push(NATIVE_SETTLEMENT_TAG);
                bytes.extend_from_slice(&legacy[EXPERIMENTAL_SETTLEMENT_TX_V1_TAG.len()..]);
                bytes
            }
        }
    }
    /// Construct after the caller has obtained canonical proof bytes. This does
    /// not verify the proof; [`SettlementRegistryV1::verify_and_apply`] does.
    pub fn new(
        proof_policy: B256,
        statement: SettlementStatementV2,
        proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
    ) -> Result<Self, SettlementError> {
        if proof_policy == B256::ZERO || proof.iter().all(|byte| *byte == 0) {
            return Err(SettlementError::Encoding);
        }
        // Round-trip through the statement decoder to apply its structural
        // checks at the boundary rather than accepting an arbitrary struct.
        let statement = SettlementStatementV2::decode(&statement.encode()).map_err(SettlementError::Statement)?;
        Ok(Self {
            proof_policy,
            statement,
            proof,
        })
    }

    /// Decode exactly one V1 transaction; prefixes, suffixes and other versions fail.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementError> {
        if bytes.len() != SETTLEMENT_TX_V1_BYTES || !bytes.starts_with(EXPERIMENTAL_SETTLEMENT_TX_V1_TAG) {
            return Err(SettlementError::Encoding);
        }
        let mut offset = EXPERIMENTAL_SETTLEMENT_TX_V1_TAG.len();
        let proof_policy = B256::from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        let statement = SettlementStatementV2::decode(&bytes[offset..offset + SETTLEMENT_STATEMENT_V2_LEN])
            .map_err(SettlementError::Statement)?;
        offset += SETTLEMENT_STATEMENT_V2_LEN;
        let proof = bytes[offset..].try_into().map_err(|_| SettlementError::Encoding)?;
        Self::new(proof_policy, statement, proof)
    }

    /// Canonical fixed-width encoding.
    pub fn encode(&self) -> [u8; SETTLEMENT_TX_V1_BYTES] {
        let mut bytes = [0u8; SETTLEMENT_TX_V1_BYTES];
        let mut offset = 0usize;
        for part in [
            EXPERIMENTAL_SETTLEMENT_TX_V1_TAG,
            self.proof_policy.as_slice(),
            self.statement.encode().as_slice(),
            self.proof.as_slice(),
        ] {
            let end = offset + part.len();
            bytes[offset..end].copy_from_slice(part);
            offset = end;
        }
        debug_assert_eq!(offset, SETTLEMENT_TX_V1_BYTES);
        bytes
    }

    /// Candidate transition identity, domain-separated with SHA3-256. This is
    /// not a native transaction ID and must not be exposed as one.
    pub fn commitment(&self) -> B256 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-COMMITMENT:1");
        hasher.update(self.encode());
        B256::from_slice(&hasher.finalize())
    }

    /// Proof-authenticated public statement claimed by this candidate.
    pub const fn statement(&self) -> &SettlementStatementV2 {
        &self.statement
    }

    /// Claimed proof-policy identity; this accessor performs no verification.
    pub const fn proof_policy(&self) -> B256 {
        self.proof_policy
    }
}

/// Source and L2 successor selected independently by native consensus.
///
/// `source_predecessor` must be the registry's previous source commitment.
/// This makes extension explicit, but the embedding native implementation must
/// still verify that `statement.source_commitment` really preserves every old
/// leaf. Merely constructing this value proves nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementExpectationV1 {
    /// Exact expected proof public values.
    pub statement: SettlementStatementV2,
    /// Prior accepted source commitment, or zero before the first settlement.
    pub source_predecessor: B256,
}

/// Deterministic proof verification boundary supplied by native consensus.
/// Implementations must be pure for a fixed policy, statement and proof and
/// must reject noncanonical encodings. Network calls or mutable local policy do
/// not satisfy this contract.
pub trait SettlementProofVerifierV1 {
    /// Verify the proof against exactly these public bytes and proof-policy pin.
    fn verify(&self, proof_policy: B256, public_values: &[u8], proof: &[u8]) -> bool;
}

/// Accepted settlement head retained by native state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedSettlementV1 {
    /// Commitment of the exact accepted transaction candidate.
    pub commitment: B256,
    /// L2 block number.
    pub l2_number: u64,
    /// Full V2 L2 header hash.
    pub l2_header_hash: B256,
    /// Post-state root.
    pub l2_state_root: B256,
    /// Accepted native anchor block.
    pub l1_block: B256,
    /// Accepted native anchor slot.
    pub l1_slot: u64,
    /// Independently derived native anchor height.
    pub l1_height: u64,
    /// Complete accepted source commitment.
    pub source_commitment: B256,
    /// Accepted inbox root and count.
    pub inbox_root: B256,
    /// Number of leaves committed by `inbox_root`.
    pub inbox_count: u64,
    /// Exclusive consumed inbox cursor.
    pub consumed_end: u64,
}

/// Dormant native registry state. It owns only settlement/head consumption;
/// escrow liabilities, fees and spendable outputs remain separate components
/// and cannot be changed through this API.
#[derive(Clone, Debug)]
pub struct SettlementRegistryV1 {
    policy: SettlementPolicyV1,
    policy_commitment: B256,
    head: Option<AcceptedSettlementV1>,
}

impl SettlementRegistryV1 {
    /// Create an empty registry under one immutable policy.
    pub fn new(policy: SettlementPolicyV1) -> Result<Self, SettlementError> {
        let policy_commitment = policy.commitment()?;
        Ok(Self {
            policy,
            policy_commitment,
            head: None,
        })
    }

    /// Current accepted head, if any.
    pub const fn head(&self) -> Option<&AcceptedSettlementV1> {
        self.head.as_ref()
    }

    /// Immutable policy identity pinned when this registry was created.
    pub const fn policy_commitment(&self) -> B256 {
        self.policy_commitment
    }

    /// Canonical commitment to this registry component. This does not assign a
    /// native state key or prove inclusion under a native state root.
    pub fn state_commitment(&self) -> B256 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-STATE:1");
        hasher.update(self.policy_commitment);
        match self.head {
            None => hasher.update([0]),
            Some(head) => {
                hasher.update([1]);
                for value in [
                    head.commitment,
                    head.l2_header_hash,
                    head.l2_state_root,
                    head.l1_block,
                    head.source_commitment,
                    head.inbox_root,
                ] {
                    hasher.update(value);
                }
                for value in [
                    head.l2_number,
                    head.l1_slot,
                    head.l1_height,
                    head.inbox_count,
                    head.consumed_end,
                ] {
                    hasher.update(value.to_le_bytes());
                }
            }
        }
        B256::from_slice(&hasher.finalize())
    }

    /// Verify every fallible condition, then atomically publish head and cursor.
    /// On every error `self` remains byte-for-byte logically unchanged.
    pub fn verify_and_apply<V: SettlementProofVerifierV1>(
        &mut self,
        transaction_bytes: &[u8],
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<AcceptedSettlementV1, SettlementError> {
        let (transaction, format) = SettlementTransactionV1::decode_wire(transaction_bytes)?;
        let statement = transaction.statement;
        if statement != expectation.statement {
            return Err(SettlementError::Expectation);
        }
        self.check_policy(&transaction)?;
        self.check_successor(&statement, expectation.source_predecessor)?;
        if format == SettlementWireFormat::NativeV1 {
            check_native_source(&statement, self.head.map_or(B256::ZERO, |head| head.source_commitment))?;
        }
        if !verifier.verify(transaction.proof_policy, &statement.encode(), &transaction.proof) {
            return Err(SettlementError::Proof);
        }

        let accepted = AcceptedSettlementV1 {
            commitment: transaction.commitment(),
            l2_number: statement.l2_number,
            l2_header_hash: statement.l2_header_hash,
            l2_state_root: statement.l2_state_root,
            l1_block: statement.l1_block,
            l1_slot: statement.l1_slot,
            l1_height: statement.l1_height,
            source_commitment: statement.source_commitment,
            inbox_root: statement.inbox_root,
            inbox_count: statement.inbox_count,
            consumed_end: statement.consumed_end,
        };
        // No fallible operation follows publication.
        self.head = Some(accepted);
        Ok(accepted)
    }

    fn check_policy(&self, transaction: &SettlementTransactionV1) -> Result<(), SettlementError> {
        let statement = transaction.statement;
        if transaction.proof_policy != self.policy.proof_policy
            || statement.network != self.policy.network
            || statement.genesis != self.policy.genesis
            || statement.domain != self.policy.domain
            || statement.configuration != self.policy.configuration
            || statement.program_elf_keccak != self.policy.program_elf_keccak
            || statement.program_vkey_koalabear != self.policy.program_vkey_koalabear
            || statement.program_vkey_bn254 != self.policy.program_vkey_bn254
            || statement.chain_id != self.policy.chain_id
        {
            return Err(SettlementError::Policy);
        }
        Ok(())
    }

    fn check_successor(
        &self,
        statement: &SettlementStatementV2,
        source_predecessor: B256,
    ) -> Result<(), SettlementError> {
        if [
            statement.l2_parent_hash,
            statement.l2_previous_state_root,
            statement.l2_header_hash,
            statement.l2_state_root,
            statement.l1_block,
            statement.source_commitment,
            statement.inbox_root,
            statement.body_commitment,
        ]
        .contains(&B256::ZERO)
            || statement.l1_height == 0
            || statement.l1_slot < statement.l1_height
            || statement.consumed_start > statement.consumed_end
            || statement.consumed_end > statement.inbox_count
        {
            return Err(SettlementError::Transition);
        }
        match self.head {
            None => {
                if statement.previous_settlement != B256::ZERO
                    || source_predecessor != B256::ZERO
                    || statement.l2_number != self.policy.first_l2_number
                    || statement.l2_parent_hash != self.policy.initial_l2_parent_hash
                    || statement.l2_previous_state_root != self.policy.initial_l2_state_root
                    || statement.consumed_start != 0
                {
                    return Err(SettlementError::Transition);
                }
            }
            Some(head) => {
                if statement.previous_settlement != head.commitment
                    || source_predecessor != head.source_commitment
                    || statement.l2_number != head.l2_number.checked_add(1).ok_or(SettlementError::Transition)?
                    || statement.l2_parent_hash != head.l2_header_hash
                    || statement.l2_previous_state_root != head.l2_state_root
                    || statement.consumed_start != head.consumed_end
                    || statement.inbox_count < head.inbox_count
                    || statement.l1_height < head.l1_height
                    || statement.l1_slot < head.l1_slot
                    || (statement.l1_height == head.l1_height
                        && (statement.l1_block != head.l1_block || statement.l1_slot != head.l1_slot))
                    || (statement.l1_height > head.l1_height && statement.l1_slot <= head.l1_slot)
                    || (statement.inbox_count == head.inbox_count && statement.inbox_root != head.inbox_root)
                {
                    return Err(SettlementError::Transition);
                }
            }
        }
        Ok(())
    }
}

/// Deterministic rejection. Registry state is unchanged for every variant.
#[derive(Debug)]
pub enum SettlementError {
    /// Invalid immutable policy or policy mismatch.
    Policy,
    /// Wrong version, length or canonical proof framing.
    Encoding,
    /// Malformed public statement.
    Statement(SettlementStatementV2Error),
    /// Proposer bytes differ from independently selected values.
    Expectation,
    /// Invalid predecessor, head, cursor, source or anchor transition.
    Transition,
    /// The pinned deterministic proof verifier rejected the candidate.
    Proof,
}

impl core::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy => f.write_str("invalid or mismatched settlement policy"),
            Self::Encoding => f.write_str("invalid native settlement V1 encoding"),
            Self::Statement(error) => write!(f, "invalid settlement statement: {error}"),
            Self::Expectation => f.write_str("settlement differs from consensus-selected expectation"),
            Self::Transition => f.write_str("invalid settlement state transition"),
            Self::Proof => f.write_str("settlement proof rejected"),
        }
    }
}

impl core::error::Error for SettlementError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Statement(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
