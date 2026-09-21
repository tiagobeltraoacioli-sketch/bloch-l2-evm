// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical public statement for V2 stateless execution.
//!
//! This module supplies neither a cryptographic proof nor L1 authentication.
//! A proof backend must authenticate its pinned guest/program identity before
//! passing authenticated public bytes to [`ExecutionStatement::check_expected`].
//! The expected statement must come from independently trusted configuration,
//! parent state and canonical block selection, never from the prover's claims.
//!
//! The guest commits [`execute_statement`]'s exact [`ExecutionStatement::encode`]
//! bytes. A host verifier first checks a cryptographic proof against a trusted
//! guest verification key, then compares its public bytes to the independently
//! expected statement. Neither deserialization nor successful re-execution
//! replaces that proof check. The header commitment covers context, ordered
//! deposits, transactions, receipts and post-state through the full V2 format.
//! Whether those deposits are authorized by finalized L1 remains a separate
//! derivation/consensus check outside this execution statement.

use crate::{
    node_execution::{verify_node_batch, NodeWitnessError},
    node_primitives::NodeBodyV2,
    proving::BatchWitness,
    BlockContext, ChainSpec, ChainSpecError,
};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256};

/// Domain separator and wire version; independent of the V2 header version.
pub const STATEMENT_TAG: &[u8] = b"BLOCH:EVM:EXECUTION:1";
/// Exact byte length: tag followed by four 32-byte commitments in field order.
pub const STATEMENT_LEN: usize = STATEMENT_TAG.len() + 128;

/// Domain separator for the settlement-specific public statement. V1 remains
/// supported above; the two encodings cannot be confused by length or tag.
pub const SETTLEMENT_STATEMENT_V2_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:2";
const SETTLEMENT_V2_HASH_FIELDS: usize = 16;
const SETTLEMENT_V2_INTEGER_FIELDS: usize = 7;
/// Exact byte length of [`SettlementStatementV2`]. Hashes are raw bytes and
/// integers are big-endian, matching the execution statement's convention.
pub const SETTLEMENT_STATEMENT_V2_LEN: usize =
    SETTLEMENT_STATEMENT_V2_TAG.len() + SETTLEMENT_V2_HASH_FIELDS * 32 + SETTLEMENT_V2_INTEGER_FIELDS * 8;

/// Native/source values which execution cannot derive. The guest commits these
/// values but does not authenticate native consensus; the verifier must compare
/// them with an independently authorized expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SettlementContextV2 {
    /// Native network identity selected outside the guest.
    pub network: B256,
    /// Native genesis block identity.
    pub genesis: B256,
    /// Keccak-256 of the exact settlement guest ELF.
    pub program_elf_keccak: B256,
    /// SP1 KoalaBear verifying-key digest.
    pub program_vkey_koalabear: B256,
    /// SP1 BN254 verifying-key projection used by Groth16 verification.
    pub program_vkey_bn254: B256,
    /// Zero is permitted only for the first settlement; continuity is enforced
    /// by the native transition, not by the stateless guest.
    pub previous_settlement: B256,
    /// Slot of the native anchor.
    pub l1_slot: u64,
    /// Independently derived native height of the anchor.
    pub l1_height: u64,
    /// Commitment to the authenticated source snapshot.
    pub source_commitment: B256,
    /// Root of the complete source inbox.
    pub inbox_root: B256,
    /// Number of records in that inbox.
    pub inbox_count: u64,
    /// First inbox sequence consumed by this L2 block.
    pub consumed_start: u64,
    /// Exclusive end of the consumed inbox range.
    pub consumed_end: u64,
}

impl SettlementContextV2 {
    fn check(&self, deposit_count: usize) -> Result<(), SettlementStatementV2Error> {
        if [
            self.network,
            self.genesis,
            self.program_elf_keccak,
            self.program_vkey_koalabear,
            self.program_vkey_bn254,
            self.source_commitment,
            self.inbox_root,
        ]
        .contains(&B256::ZERO)
            || self.l1_height == 0
            || self.l1_slot < self.l1_height
            || self.consumed_start > self.consumed_end
            || self.consumed_end > self.inbox_count
            || self.consumed_end.checked_sub(self.consumed_start) != u64::try_from(deposit_count).ok()
        {
            return Err(SettlementStatementV2Error::Context);
        }
        Ok(())
    }
}

/// Public proof statement for native settlement. `proof_digest` is deliberately
/// absent: including a digest of the proof inside that proof would be circular.
/// Transport binds the resulting proof bytes separately after verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementStatementV2 {
    /// Native network identity.
    pub network: B256,
    /// Native genesis identity.
    pub genesis: B256,
    /// L2 execution domain.
    pub domain: B256,
    /// Commitment to the complete validated L2 configuration.
    pub configuration: B256,
    /// Keccak-256 of the exact guest ELF.
    pub program_elf_keccak: B256,
    /// SP1 KoalaBear verifying-key digest.
    pub program_vkey_koalabear: B256,
    /// SP1 BN254 verifying-key projection.
    pub program_vkey_bn254: B256,
    /// Commitment of the preceding accepted settlement, or zero initially.
    pub previous_settlement: B256,
    /// EVM replay-protection chain ID.
    pub chain_id: u64,
    /// Executed L2 block number.
    pub l2_number: u64,
    /// Parent L2 header hash.
    pub l2_parent_hash: B256,
    /// State root before execution.
    pub l2_previous_state_root: B256,
    /// Hash of the complete executed L2 header.
    pub l2_header_hash: B256,
    /// State root after execution.
    pub l2_state_root: B256,
    /// Native block anchoring the executed header.
    pub l1_block: B256,
    /// Native anchor slot.
    pub l1_slot: u64,
    /// Independently derived native anchor height.
    pub l1_height: u64,
    /// Commitment to the authenticated source snapshot.
    pub source_commitment: B256,
    /// Root of the complete source inbox.
    pub inbox_root: B256,
    /// Number of records in the source inbox.
    pub inbox_count: u64,
    /// First inbox sequence consumed by this block.
    pub consumed_start: u64,
    /// Exclusive end of the consumed inbox range.
    pub consumed_end: u64,
    /// Keccak-256 of the canonical tagged V2 body RLP.
    pub body_commitment: B256,
}

/// Invalid V2 context, encoding, expectation, or executed transition.
#[derive(Debug)]
pub enum SettlementStatementV2Error {
    /// A zero identity, invalid anchor, or inconsistent cursor was supplied.
    Context,
    /// Bytes have the wrong version, length, or framing.
    Encoding,
    /// Authenticated public bytes differ from the trusted expectation.
    Mismatch,
    /// Stateless execution rejected the witness or body.
    Execution(NodeWitnessError),
}

impl core::fmt::Display for SettlementStatementV2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Context => f.write_str("invalid settlement V2 context"),
            Self::Encoding => f.write_str("invalid settlement V2 encoding"),
            Self::Mismatch => f.write_str("settlement V2 statement differs from trusted expectation"),
            Self::Execution(error) => write!(f, "settlement V2 execution failed: {error}"),
        }
    }
}

impl core::error::Error for SettlementStatementV2Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }
}

fn settlement_v2_take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], SettlementStatementV2Error> {
    let end = offset.checked_add(N).ok_or(SettlementStatementV2Error::Encoding)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(SettlementStatementV2Error::Encoding)?
        .try_into()
        .map_err(|_| SettlementStatementV2Error::Encoding)?;
    *offset = end;
    Ok(value)
}

impl SettlementStatementV2 {
    /// Build the statement from an already verified execution result. Native
    /// source authority remains an independent host/consensus responsibility.
    pub fn from_executed(
        configuration: B256,
        header: &crate::node_primitives::NodeHeaderV2,
        body: &NodeBodyV2,
        context: SettlementContextV2,
    ) -> Result<Self, SettlementStatementV2Error> {
        context.check(body.deposits.len())?;
        if configuration == B256::ZERO
            || header.domain == B256::ZERO
            || header.chain_id == 0
            || header.number == 0
            || header.parent_hash == B256::ZERO
            || header.parent_state_root == B256::ZERO
            || header.state_root == B256::ZERO
            || header.anchor_root == B256::ZERO
        {
            return Err(SettlementStatementV2Error::Context);
        }
        Ok(Self {
            network: context.network,
            genesis: context.genesis,
            domain: header.domain,
            configuration,
            program_elf_keccak: context.program_elf_keccak,
            program_vkey_koalabear: context.program_vkey_koalabear,
            program_vkey_bn254: context.program_vkey_bn254,
            previous_settlement: context.previous_settlement,
            chain_id: header.chain_id,
            l2_number: header.number,
            l2_parent_hash: header.parent_hash,
            l2_previous_state_root: header.parent_state_root,
            l2_header_hash: header.hash(),
            l2_state_root: header.state_root,
            l1_block: header.anchor_root,
            l1_slot: context.l1_slot,
            l1_height: context.l1_height,
            source_commitment: context.source_commitment,
            inbox_root: context.inbox_root,
            inbox_count: context.inbox_count,
            consumed_start: context.consumed_start,
            consumed_end: context.consumed_end,
            body_commitment: keccak256(alloy_rlp::encode(body)),
        })
    }

    /// Encode the exact fixed-width, version-tagged statement.
    pub fn encode(&self) -> [u8; SETTLEMENT_STATEMENT_V2_LEN] {
        let mut bytes = [0u8; SETTLEMENT_STATEMENT_V2_LEN];
        let mut offset = 0;
        let mut write = |value: &[u8]| {
            let end = offset + value.len();
            bytes[offset..end].copy_from_slice(value);
            offset = end;
        };
        write(SETTLEMENT_STATEMENT_V2_TAG);
        for value in [
            self.network,
            self.genesis,
            self.domain,
            self.configuration,
            self.program_elf_keccak,
            self.program_vkey_koalabear,
            self.program_vkey_bn254,
            self.previous_settlement,
        ] {
            write(value.as_slice());
        }
        write(&self.chain_id.to_be_bytes());
        write(&self.l2_number.to_be_bytes());
        for value in [
            self.l2_parent_hash,
            self.l2_previous_state_root,
            self.l2_header_hash,
            self.l2_state_root,
            self.l1_block,
        ] {
            write(value.as_slice());
        }
        write(&self.l1_slot.to_be_bytes());
        write(&self.l1_height.to_be_bytes());
        for value in [self.source_commitment, self.inbox_root] {
            write(value.as_slice());
        }
        for value in [self.inbox_count, self.consumed_start, self.consumed_end] {
            write(&value.to_be_bytes());
        }
        write(self.body_commitment.as_slice());
        debug_assert_eq!(offset, SETTLEMENT_STATEMENT_V2_LEN);
        bytes
    }

    /// Decode exactly one V2 statement, rejecting prefixes and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementStatementV2Error> {
        if bytes.len() != SETTLEMENT_STATEMENT_V2_LEN || !bytes.starts_with(SETTLEMENT_STATEMENT_V2_TAG) {
            return Err(SettlementStatementV2Error::Encoding);
        }
        let mut offset = SETTLEMENT_STATEMENT_V2_TAG.len();
        let hash = |offset: &mut usize| settlement_v2_take::<32>(bytes, offset).map(B256::from);
        let integer = |offset: &mut usize| settlement_v2_take::<8>(bytes, offset).map(u64::from_be_bytes);
        let network = hash(&mut offset)?;
        let genesis = hash(&mut offset)?;
        let domain = hash(&mut offset)?;
        let configuration = hash(&mut offset)?;
        let program_elf_keccak = hash(&mut offset)?;
        let program_vkey_koalabear = hash(&mut offset)?;
        let program_vkey_bn254 = hash(&mut offset)?;
        let previous_settlement = hash(&mut offset)?;
        let chain_id = integer(&mut offset)?;
        let l2_number = integer(&mut offset)?;
        let l2_parent_hash = hash(&mut offset)?;
        let l2_previous_state_root = hash(&mut offset)?;
        let l2_header_hash = hash(&mut offset)?;
        let l2_state_root = hash(&mut offset)?;
        let l1_block = hash(&mut offset)?;
        let l1_slot = integer(&mut offset)?;
        let l1_height = integer(&mut offset)?;
        let source_commitment = hash(&mut offset)?;
        let inbox_root = hash(&mut offset)?;
        let inbox_count = integer(&mut offset)?;
        let consumed_start = integer(&mut offset)?;
        let consumed_end = integer(&mut offset)?;
        let body_commitment = hash(&mut offset)?;
        debug_assert_eq!(offset, SETTLEMENT_STATEMENT_V2_LEN);
        Ok(Self {
            network,
            genesis,
            domain,
            configuration,
            program_elf_keccak,
            program_vkey_koalabear,
            program_vkey_bn254,
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
        })
    }

    /// Compare proof-authenticated public bytes with a trusted expectation.
    pub fn check_expected(&self, authenticated_public_bytes: &[u8]) -> Result<(), SettlementStatementV2Error> {
        if Self::decode(authenticated_public_bytes)? != *self {
            return Err(SettlementStatementV2Error::Mismatch);
        }
        Ok(())
    }
}

/// Hash every validated configuration field using a fixed-width, tagged layout.
/// Integers are big-endian, addresses are raw 20 bytes, reward is 32 bytes.
/// Cancun is named explicitly, never encoded using a dependency's enum ordinal.
/// The layout is ASCII `BLOCH:EVM:CONFIG:1:CANCUN`, then chain ID, gas limit,
/// block time, elasticity, denominator, initial base fee (six u64s), reward,
/// base-fee vault, sequencer vault, supply ledger, block-info address, maximum
/// L1 sats and deposit gas (two u64s). Changing this layout requires a new tag.
pub fn configuration_commitment(spec: &ChainSpec) -> Result<B256, ChainSpecError> {
    spec.validate()?;
    // Exhaustive destructuring makes new configuration fields a compile error.
    let ChainSpec {
        chain_id,
        spec_id: _,
        gas_limit,
        block_time_secs,
        base_fee_elasticity,
        base_fee_denominator,
        initial_base_fee,
        block_reward,
        base_fee_vault,
        sequencer_fee_vault,
        supply_ledger,
        block_info,
        max_l1_sats,
        deposit_gas,
    } = spec;
    let mut bytes = Vec::from(&b"BLOCH:EVM:CONFIG:1:CANCUN"[..]);
    for value in [
        chain_id,
        gas_limit,
        block_time_secs,
        base_fee_elasticity,
        base_fee_denominator,
        initial_base_fee,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&block_reward.to_be_bytes::<32>());
    for address in [base_fee_vault, sequencer_fee_vault, supply_ledger, block_info] {
        bytes.extend_from_slice(address.as_slice());
    }
    for value in [max_l1_sats, deposit_gas] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Ok(keccak256(bytes))
}

/// Public commitments to the complete configuration and executed transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionStatement {
    /// Tagged commitment to all validated chain parameters.
    pub configuration: B256,
    /// Separately configured V2 execution domain.
    pub domain: B256,
    /// Authenticated pre-state root.
    pub previous_state_root: B256,
    /// Full tagged V2 header hash, including post-state, body and receipt roots.
    pub header_hash: B256,
}

/// Invalid public encoding or mismatch with an independently expected statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementError {
    /// Wrong length, tag or version, including any trailing bytes.
    Encoding,
    /// At least one commitment differs from the trusted expectation.
    Mismatch,
}
impl core::fmt::Display for StatementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Encoding => "invalid execution statement encoding",
            Self::Mismatch => "execution statement differs from trusted expectation",
        })
    }
}
impl core::error::Error for StatementError {}

impl ExecutionStatement {
    /// Encode exactly the tagged, fixed-width public statement.
    pub fn encode(&self) -> [u8; STATEMENT_LEN] {
        let mut bytes = [0; STATEMENT_LEN];
        bytes[..STATEMENT_TAG.len()].copy_from_slice(STATEMENT_TAG);
        for (chunk, value) in bytes[STATEMENT_TAG.len()..].chunks_exact_mut(32).zip([
            self.configuration,
            self.domain,
            self.previous_state_root,
            self.header_hash,
        ]) {
            chunk.copy_from_slice(value.as_slice());
        }
        bytes
    }

    /// Strict decoding; this checks syntax only, not proof or execution validity.
    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() != STATEMENT_LEN || !bytes.starts_with(STATEMENT_TAG) {
            return Err(StatementError::Encoding);
        }
        let field = |index: usize| {
            B256::from_slice(&bytes[STATEMENT_TAG.len() + index * 32..STATEMENT_TAG.len() + (index + 1) * 32])
        };
        Ok(Self {
            configuration: field(0),
            domain: field(1),
            previous_state_root: field(2),
            header_hash: field(3),
        })
    }

    /// Compare proof-authenticated public bytes with this trusted expectation.
    /// Calling this on unauthenticated bytes does not verify a proof.
    pub fn check_expected(&self, authenticated_public_bytes: &[u8]) -> Result<(), StatementError> {
        if Self::decode(authenticated_public_bytes)? != *self {
            return Err(StatementError::Mismatch);
        }
        Ok(())
    }
}

/// Run the actual sparse-witness V2 verifier and derive its public statement.
/// Witness roots are checked by execution; no caller-supplied outcome is used.
pub fn execute_statement(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<ExecutionStatement, NodeWitnessError> {
    let outcome = verify_node_batch(spec, domain, witness, context, body)?;
    // Execution already validated the configuration; propagate its error shape.
    let configuration = configuration_commitment(spec).map_err(|error| {
        NodeWitnessError::Execution(crate::node_execution::NodeExecutionError::Execution(
            crate::BlockExecutionError::InvalidChainSpec(error),
        ))
    })?;
    Ok(ExecutionStatement {
        configuration,
        domain,
        previous_state_root: witness.prev_state_root,
        header_hash: outcome.header.hash(),
    })
}

/// Execute the V2 block and derive the settlement-specific public statement.
/// The external context is committed verbatim only after its bounded structural
/// relationship to the executed body and header has been checked.
pub fn execute_settlement_statement_v2(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    settlement: SettlementContextV2,
) -> Result<SettlementStatementV2, SettlementStatementV2Error> {
    let outcome =
        verify_node_batch(spec, domain, witness, context, body).map_err(SettlementStatementV2Error::Execution)?;
    let configuration = configuration_commitment(spec).map_err(|error| {
        SettlementStatementV2Error::Execution(NodeWitnessError::Execution(
            crate::node_execution::NodeExecutionError::Execution(crate::BlockExecutionError::InvalidChainSpec(error)),
        ))
    })?;
    SettlementStatementV2::from_executed(configuration, &outcome.header, body, settlement)
}

#[cfg(test)]
mod settlement_v2_tests {
    use super::*;
    use crate::node_primitives::NodeHeaderV2;
    use alloy_primitives::Address;

    fn context() -> SettlementContextV2 {
        SettlementContextV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            program_elf_keccak: B256::repeat_byte(3),
            program_vkey_koalabear: B256::repeat_byte(4),
            program_vkey_bn254: B256::repeat_byte(5),
            previous_settlement: B256::ZERO,
            l1_slot: 12,
            l1_height: 11,
            source_commitment: B256::repeat_byte(6),
            inbox_root: B256::repeat_byte(7),
            inbox_count: 0,
            consumed_start: 0,
            consumed_end: 0,
        }
    }

    fn statement() -> SettlementStatementV2 {
        let header = NodeHeaderV2 {
            domain: B256::repeat_byte(8),
            chain_id: 700_771,
            number: 1,
            beneficiary: Address::repeat_byte(9),
            anchor_root: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(11),
            parent_state_root: B256::repeat_byte(12),
            state_root: B256::repeat_byte(13),
            ..Default::default()
        };
        SettlementStatementV2::from_executed(B256::repeat_byte(14), &header, &NodeBodyV2::default(), context()).unwrap()
    }

    #[test]
    fn settlement_v2_is_exact_and_distinct_from_execution_v1() {
        let expected = statement();
        let bytes = expected.encode();
        assert_eq!(bytes.len(), SETTLEMENT_STATEMENT_V2_LEN);
        assert_ne!(bytes.len(), STATEMENT_LEN);
        assert_eq!(SettlementStatementV2::decode(&bytes).unwrap(), expected);
        assert!(ExecutionStatement::decode(&bytes).is_err());
        assert!(SettlementStatementV2::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(SettlementStatementV2::decode(&trailing).is_err());
        let mut wrong_tag = bytes;
        wrong_tag[0] ^= 1;
        assert!(SettlementStatementV2::decode(&wrong_tag).is_err());
    }

    #[test]
    fn every_settlement_v2_byte_is_expectation_bound() {
        let expected = statement();
        let bytes = expected.encode();
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(expected.check_expected(&changed).is_err(), "byte {index} was not bound");
        }
    }

    #[test]
    fn settlement_v2_rejects_bad_cursor_anchor_and_identity_context() {
        let header = NodeHeaderV2 {
            domain: B256::repeat_byte(8),
            chain_id: 700_771,
            number: 1,
            beneficiary: Address::repeat_byte(9),
            anchor_root: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(11),
            parent_state_root: B256::repeat_byte(12),
            state_root: B256::repeat_byte(13),
            ..Default::default()
        };
        for bad in [
            SettlementContextV2 {
                network: B256::ZERO,
                ..context()
            },
            SettlementContextV2 {
                l1_slot: 10,
                ..context()
            },
            SettlementContextV2 {
                consumed_end: 1,
                ..context()
            },
            SettlementContextV2 {
                consumed_start: 1,
                ..context()
            },
        ] {
            assert!(
                SettlementStatementV2::from_executed(B256::repeat_byte(14), &header, &NodeBodyV2::default(), bad,)
                    .is_err()
            );
        }
    }

    #[test]
    fn settlement_v2_binds_cursor_head_chain_and_parent() {
        let expected = statement();
        assert_eq!(expected.chain_id, 700_771);
        assert_eq!(expected.l2_number, 1);
        assert_eq!(expected.l2_parent_hash, B256::repeat_byte(11));
        assert_eq!(expected.l2_previous_state_root, B256::repeat_byte(12));
        assert_eq!(expected.l2_state_root, B256::repeat_byte(13));
        assert_eq!(expected.consumed_start, 0);
        assert_eq!(expected.consumed_end, 0);

        let mut header = NodeHeaderV2 {
            domain: B256::repeat_byte(8),
            chain_id: 700_771,
            number: 1,
            beneficiary: Address::repeat_byte(9),
            anchor_root: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(11),
            parent_state_root: B256::repeat_byte(12),
            state_root: B256::repeat_byte(13),
            ..Default::default()
        };
        assert_eq!(
            SettlementStatementV2::from_executed(B256::repeat_byte(14), &header, &NodeBodyV2::default(), context(),)
                .unwrap(),
            expected
        );
        let mutations: [fn(&mut NodeHeaderV2); 5] = [
            |h: &mut NodeHeaderV2| h.chain_id += 1,
            |h: &mut NodeHeaderV2| h.number += 1,
            |h: &mut NodeHeaderV2| h.parent_hash[0] ^= 1,
            |h: &mut NodeHeaderV2| h.parent_state_root[0] ^= 1,
            |h: &mut NodeHeaderV2| h.state_root[0] ^= 1,
        ];
        for mutate in mutations {
            let original = header.clone();
            mutate(&mut header);
            let changed =
                SettlementStatementV2::from_executed(B256::repeat_byte(14), &header, &NodeBodyV2::default(), context())
                    .unwrap();
            assert_ne!(changed, expected);
            header = original;
        }
    }
}
