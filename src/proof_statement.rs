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

/// Domain separator for the settlement V3 public statement. It has the same
/// length as the V2 tag, so every V2 field keeps its V2 offset after the tag.
pub const SETTLEMENT_STATEMENT_V3_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:3";
const SETTLEMENT_V3_EXTRA_HASH_FIELDS: usize = 5;
const SETTLEMENT_V3_EXTRA_INTEGER_FIELDS: usize = 2;
/// Exact byte length of [`SettlementStatementV3`]: the V3 tag, the 568 V2
/// field bytes in V2 order, then 5 hashes and 2 big-endian `u64`s (766 bytes).
pub const SETTLEMENT_STATEMENT_V3_LEN: usize = SETTLEMENT_STATEMENT_V3_TAG.len()
    + (SETTLEMENT_STATEMENT_V2_LEN - SETTLEMENT_STATEMENT_V2_TAG.len())
    + SETTLEMENT_V3_EXTRA_HASH_FIELDS * 32
    + SETTLEMENT_V3_EXTRA_INTEGER_FIELDS * 8;

/// Byte offsets of the V3-only fields, relative to the end of the 22-byte tag.
/// Offsets `0..568` are exactly the V2 layout (`body_commitment` at 536). The
/// native verifier parses these offsets independently; conformance tests on
/// both sides pin them.
pub mod settlement_v3_layout {
    /// Keccak-256 of the ordered deposit list ([`crate::executor::deposits_hash`]).
    pub const DEPOSITS_HASH: usize = 568;
    /// Ordered MPT root of the signed user transaction envelopes.
    pub const TRANSACTIONS_ROOT: usize = 600;
    /// Ordered MPT root of the user receipts.
    pub const RECEIPTS_ROOT: usize = 632;
    /// Number of user transactions (big-endian `u64`).
    pub const USER_TX_COUNT: usize = 664;
    /// L2 to L1 withdrawal root (M1: reserved, zero).
    pub const WITHDRAWAL_ROOT: usize = 672;
    /// Number of withdrawals (big-endian `u64`; M1: reserved, zero).
    pub const WITHDRAWAL_COUNT: usize = 704;
    /// Data-availability commitment (M1: reserved, zero).
    pub const DA_COMMITMENT: usize = 712;
    /// End of the statement after the tag.
    pub const END: usize = 744;
}

/// M1 placeholder for [`SettlementStatementV3::withdrawal_root`]. Milestone M4
/// (L2 outbox predeploy) defines the real root; until then the guest commits
/// zero and the native verifier refuses anything else.
pub const SETTLEMENT_V3_RESERVED_WITHDRAWAL_ROOT: B256 = B256::ZERO;
/// M1 placeholder for [`SettlementStatementV3::da_commitment`]. Milestone M3
/// (L1 data availability) defines it; until then it is zero and enforced zero.
pub const SETTLEMENT_V3_RESERVED_DA_COMMITMENT: B256 = B256::ZERO;

/// Settlement statement that admits user transactions.
///
/// V2 forced the native chain to recompute `body_commitment` with an empty
/// transaction list, so no user transaction could ever settle. V3 keeps every
/// V2 field (still including `body_commitment`, which binds the exact body
/// inside the proof) and additionally exposes the commitments the native chain
/// can check WITHOUT seeing the transactions:
///
/// * `deposits_hash` lets L1 bind the minted deposits to its own inbox
///   records, replacing the "empty body" recomputation;
/// * `transactions_root`, `receipts_root`, `user_tx_count` publish what was
///   executed (the header hash already commits to them; exposing them lets L1
///   and observers reference them without the full header);
/// * `withdrawal_root`, `withdrawal_count`, `da_commitment` are RESERVED in M1:
///   always zero here and refused if non-zero by the native verifier. M3 (data
///   availability) and M4 (outbox) give them meaning under a new program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementStatementV3 {
    /// All V2 fields, encoded at their V2 offsets after the V3 tag.
    pub base: SettlementStatementV2,
    /// Keccak-256 of the ordered deposit list minted by this block.
    pub deposits_hash: B256,
    /// Ordered MPT root of the signed user transaction envelopes.
    pub transactions_root: B256,
    /// Ordered MPT root of the typed user receipts.
    pub receipts_root: B256,
    /// Number of user transactions executed by this block.
    pub user_tx_count: u64,
    /// Reserved (M4): root of L2 to L1 withdrawals. Zero in M1.
    pub withdrawal_root: B256,
    /// Reserved (M4): number of withdrawals. Zero in M1.
    pub withdrawal_count: u64,
    /// Reserved (M3): data-availability commitment. Zero in M1.
    pub da_commitment: B256,
}

impl SettlementStatementV3 {
    /// Build the V3 statement from an already verified execution result.
    /// Fails if the header's body commitments disagree with `body`.
    pub fn from_executed(
        configuration: B256,
        header: &crate::node_primitives::NodeHeaderV2,
        body: &NodeBodyV2,
        context: SettlementContextV2,
    ) -> Result<Self, SettlementStatementV2Error> {
        let base = SettlementStatementV2::from_executed(configuration, header, body, context)?;
        let deposits_hash = body.deposits_hash();
        if header.deposits_hash != deposits_hash
            || header.transactions_root != body.transactions_root()
            || header.receipts_root == B256::ZERO
        {
            return Err(SettlementStatementV2Error::Context);
        }
        Ok(Self {
            base,
            deposits_hash,
            transactions_root: header.transactions_root,
            receipts_root: header.receipts_root,
            user_tx_count: u64::try_from(body.transactions.len()).map_err(|_| SettlementStatementV2Error::Context)?,
            withdrawal_root: SETTLEMENT_V3_RESERVED_WITHDRAWAL_ROOT,
            withdrawal_count: 0,
            da_commitment: SETTLEMENT_V3_RESERVED_DA_COMMITMENT,
        })
    }

    /// Encode the exact fixed-width, version-tagged statement.
    pub fn encode(&self) -> [u8; SETTLEMENT_STATEMENT_V3_LEN] {
        let mut bytes = [0u8; SETTLEMENT_STATEMENT_V3_LEN];
        let v2 = self.base.encode();
        let tag = SETTLEMENT_STATEMENT_V3_TAG.len();
        bytes[..tag].copy_from_slice(SETTLEMENT_STATEMENT_V3_TAG);
        bytes[tag..tag + settlement_v3_layout::DEPOSITS_HASH].copy_from_slice(&v2[SETTLEMENT_STATEMENT_V2_TAG.len()..]);
        let mut offset = tag + settlement_v3_layout::DEPOSITS_HASH;
        let mut write = |value: &[u8]| {
            let end = offset + value.len();
            bytes[offset..end].copy_from_slice(value);
            offset = end;
        };
        write(self.deposits_hash.as_slice());
        write(self.transactions_root.as_slice());
        write(self.receipts_root.as_slice());
        write(&self.user_tx_count.to_be_bytes());
        write(self.withdrawal_root.as_slice());
        write(&self.withdrawal_count.to_be_bytes());
        write(self.da_commitment.as_slice());
        debug_assert_eq!(offset, SETTLEMENT_STATEMENT_V3_LEN);
        bytes
    }

    /// Decode exactly one V3 statement, rejecting prefixes, trailing bytes and
    /// V2 (or any other) tags.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementStatementV2Error> {
        if bytes.len() != SETTLEMENT_STATEMENT_V3_LEN || !bytes.starts_with(SETTLEMENT_STATEMENT_V3_TAG) {
            return Err(SettlementStatementV2Error::Encoding);
        }
        let tag = SETTLEMENT_STATEMENT_V3_TAG.len();
        let mut v2 = [0u8; SETTLEMENT_STATEMENT_V2_LEN];
        v2[..SETTLEMENT_STATEMENT_V2_TAG.len()].copy_from_slice(SETTLEMENT_STATEMENT_V2_TAG);
        v2[SETTLEMENT_STATEMENT_V2_TAG.len()..].copy_from_slice(&bytes[tag..tag + settlement_v3_layout::DEPOSITS_HASH]);
        let base = SettlementStatementV2::decode(&v2)?;
        let mut offset = tag + settlement_v3_layout::DEPOSITS_HASH;
        let hash = |offset: &mut usize| settlement_v2_take::<32>(bytes, offset).map(B256::from);
        let integer = |offset: &mut usize| settlement_v2_take::<8>(bytes, offset).map(u64::from_be_bytes);
        let deposits_hash = hash(&mut offset)?;
        let transactions_root = hash(&mut offset)?;
        let receipts_root = hash(&mut offset)?;
        let user_tx_count = integer(&mut offset)?;
        let withdrawal_root = hash(&mut offset)?;
        let withdrawal_count = integer(&mut offset)?;
        let da_commitment = hash(&mut offset)?;
        debug_assert_eq!(offset, SETTLEMENT_STATEMENT_V3_LEN);
        Ok(Self {
            base,
            deposits_hash,
            transactions_root,
            receipts_root,
            user_tx_count,
            withdrawal_root,
            withdrawal_count,
            da_commitment,
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

/// Execute the V2 block and derive the V3 settlement statement. Unlike the V2
/// settlement path, nothing here requires the body to be deposit-only.
pub fn execute_settlement_statement_v3(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    settlement: SettlementContextV2,
) -> Result<SettlementStatementV3, SettlementStatementV2Error> {
    let outcome =
        verify_node_batch(spec, domain, witness, context, body).map_err(SettlementStatementV2Error::Execution)?;
    let configuration = configuration_commitment(spec).map_err(|error| {
        SettlementStatementV2Error::Execution(NodeWitnessError::Execution(
            crate::node_execution::NodeExecutionError::Execution(crate::BlockExecutionError::InvalidChainSpec(error)),
        ))
    })?;
    SettlementStatementV3::from_executed(configuration, &outcome.header, body, settlement)
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

#[cfg(test)]
mod settlement_v3_tests {
    use super::*;
    use crate::node_primitives::NodeHeaderV2;
    use alloy_primitives::{Address, Bytes};

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

    /// A body with two opaque user transaction envelopes. `from_executed` only
    /// binds commitments; signature validity is execution's job.
    fn body() -> NodeBodyV2 {
        NodeBodyV2 {
            deposits: Vec::new(),
            transactions: alloc::vec![Bytes::from_static(&[0x02, 0xaa]), Bytes::from_static(&[0x02, 0xbb])],
        }
    }

    fn header(body: &NodeBodyV2) -> NodeHeaderV2 {
        NodeHeaderV2 {
            domain: B256::repeat_byte(8),
            chain_id: 700_771,
            number: 1,
            beneficiary: Address::repeat_byte(9),
            anchor_root: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(11),
            parent_state_root: B256::repeat_byte(12),
            state_root: B256::repeat_byte(13),
            transactions_root: body.transactions_root(),
            receipts_root: B256::repeat_byte(15),
            deposits_hash: body.deposits_hash(),
            ..Default::default()
        }
    }

    fn statement() -> SettlementStatementV3 {
        let body = body();
        SettlementStatementV3::from_executed(B256::repeat_byte(14), &header(&body), &body, context()).unwrap()
    }

    #[test]
    fn settlement_v3_layout_is_exact_and_extends_v2_in_place() {
        assert_eq!(SETTLEMENT_STATEMENT_V3_TAG.len(), SETTLEMENT_STATEMENT_V2_TAG.len());
        assert_eq!(SETTLEMENT_STATEMENT_V3_LEN, 766);
        assert_eq!(
            SETTLEMENT_STATEMENT_V3_LEN,
            SETTLEMENT_STATEMENT_V3_TAG.len() + settlement_v3_layout::END
        );
        let expected = statement();
        let bytes = expected.encode();
        let v2 = expected.base.encode();
        let t = SETTLEMENT_STATEMENT_V3_TAG.len();
        assert_eq!(&bytes[..t], SETTLEMENT_STATEMENT_V3_TAG);
        // Every V2 field sits at its V2 offset.
        assert_eq!(&bytes[t..t + settlement_v3_layout::DEPOSITS_HASH], &v2[t..]);
        let at = |o: usize| B256::from_slice(&bytes[t + o..t + o + 32]);
        let int = |o: usize| u64::from_be_bytes(bytes[t + o..t + o + 8].try_into().unwrap());
        assert_eq!(at(536), expected.base.body_commitment);
        assert_eq!(at(settlement_v3_layout::DEPOSITS_HASH), expected.deposits_hash);
        assert_eq!(at(settlement_v3_layout::TRANSACTIONS_ROOT), expected.transactions_root);
        assert_eq!(at(settlement_v3_layout::RECEIPTS_ROOT), expected.receipts_root);
        assert_eq!(int(settlement_v3_layout::USER_TX_COUNT), 2);
        assert_eq!(at(settlement_v3_layout::WITHDRAWAL_ROOT), B256::ZERO);
        assert_eq!(int(settlement_v3_layout::WITHDRAWAL_COUNT), 0);
        assert_eq!(at(settlement_v3_layout::DA_COMMITMENT), B256::ZERO);
    }

    #[test]
    fn settlement_v3_round_trips_and_is_distinct_from_v2() {
        let expected = statement();
        let bytes = expected.encode();
        assert_eq!(SettlementStatementV3::decode(&bytes).unwrap(), expected);
        assert!(SettlementStatementV2::decode(&bytes).is_err());
        assert!(SettlementStatementV3::decode(&expected.base.encode()).is_err());
        assert!(SettlementStatementV3::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(SettlementStatementV3::decode(&trailing).is_err());
        // A V2 tag on V3-length bytes is refused (version is the tag).
        let mut v2_tag = bytes;
        v2_tag[..SETTLEMENT_STATEMENT_V2_TAG.len()].copy_from_slice(SETTLEMENT_STATEMENT_V2_TAG);
        assert!(SettlementStatementV3::decode(&v2_tag).is_err());
        let mut wrong_tag = bytes;
        wrong_tag[0] ^= 1;
        assert!(SettlementStatementV3::decode(&wrong_tag).is_err());
    }

    #[test]
    fn every_settlement_v3_byte_is_expectation_bound() {
        let expected = statement();
        let bytes = expected.encode();
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(expected.check_expected(&changed).is_err(), "byte {index} was not bound");
        }
    }

    #[test]
    fn settlement_v3_admits_user_transactions_and_binds_body_commitments() {
        let body = body();
        let statement = statement();
        assert_eq!(statement.user_tx_count, 2);
        assert_eq!(statement.transactions_root, body.transactions_root());
        assert_ne!(statement.transactions_root, alloy_trie::EMPTY_ROOT_HASH);
        assert_eq!(statement.deposits_hash, keccak256([]));
        assert_eq!(statement.base.body_commitment, keccak256(alloy_rlp::encode(&body)));
        // Header commitments that disagree with the body are refused.
        let mut wrong_txs = header(&body);
        wrong_txs.transactions_root = alloy_trie::EMPTY_ROOT_HASH;
        let mut wrong_deposits = header(&body);
        wrong_deposits.deposits_hash = B256::repeat_byte(1);
        let mut zero_receipts = header(&body);
        zero_receipts.receipts_root = B256::ZERO;
        for bad in [wrong_txs, wrong_deposits, zero_receipts] {
            assert!(SettlementStatementV3::from_executed(B256::repeat_byte(14), &bad, &body, context()).is_err());
        }
        // The V2 context rules still apply.
        let bad_context = SettlementContextV2 {
            consumed_end: 1,
            ..context()
        };
        assert!(
            SettlementStatementV3::from_executed(B256::repeat_byte(14), &header(&body), &body, bad_context).is_err()
        );
    }

    /// Golden vector: pins the complete V3 byte layout. Any change to field
    /// order, width or endianness changes this digest and needs a new tag.
    #[test]
    fn settlement_v3_golden_vector() {
        let statement = SettlementStatementV3 {
            base: SettlementStatementV2 {
                network: B256::repeat_byte(0x01),
                genesis: B256::repeat_byte(0x02),
                domain: B256::repeat_byte(0x03),
                configuration: B256::repeat_byte(0x04),
                program_elf_keccak: B256::repeat_byte(0x05),
                program_vkey_koalabear: B256::repeat_byte(0x06),
                program_vkey_bn254: B256::repeat_byte(0x07),
                previous_settlement: B256::repeat_byte(0x08),
                chain_id: 0x0102_0304_0506_0708,
                l2_number: 0x1112_1314_1516_1718,
                l2_parent_hash: B256::repeat_byte(0x09),
                l2_previous_state_root: B256::repeat_byte(0x0a),
                l2_header_hash: B256::repeat_byte(0x0b),
                l2_state_root: B256::repeat_byte(0x0c),
                l1_block: B256::repeat_byte(0x0d),
                l1_slot: 0x2122_2324_2526_2728,
                l1_height: 0x3132_3334_3536_3738,
                source_commitment: B256::repeat_byte(0x0e),
                inbox_root: B256::repeat_byte(0x0f),
                inbox_count: 0x4142_4344_4546_4748,
                consumed_start: 0x5152_5354_5556_5758,
                consumed_end: 0x6162_6364_6566_6768,
                body_commitment: B256::repeat_byte(0x10),
            },
            deposits_hash: B256::repeat_byte(0x11),
            transactions_root: B256::repeat_byte(0x12),
            receipts_root: B256::repeat_byte(0x13),
            user_tx_count: 0x7172_7374_7576_7778,
            withdrawal_root: B256::repeat_byte(0x14),
            withdrawal_count: 0x8182_8384_8586_8788,
            da_commitment: B256::repeat_byte(0x15),
        };
        let bytes = statement.encode();
        let t = SETTLEMENT_STATEMENT_V3_TAG.len();
        assert_eq!(
            &bytes[t + 664..t + 672],
            &[0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78]
        );
        assert_eq!(
            &bytes[t + 704..t + 712],
            &[0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88]
        );
        assert_eq!(bytes[t + 712], 0x15);
        assert_eq!(SettlementStatementV3::decode(&bytes).unwrap(), statement);
        assert_eq!(
            alloc::format!("{:x}", keccak256(bytes)),
            "66469230128b9e871eb65c938c300ce51b4e42136468145f7e54c211ade696d4"
        );
    }
}
