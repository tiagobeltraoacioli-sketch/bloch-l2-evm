// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local execution-domain verification. This is not an L1 verifier or a ZK proof.
//!
//! The host must authenticate `TrustedL1Batch` through a finalized L1 reader and
//! an inbox/DA derivation rule. Constructing that value does not establish finality.
//! This boundary re-executes signed EVM transactions; it never accepts a prover's
//! success flag. No bridge funds are released and no mainnet state is modified.

use crate::{deposits_hash, verify_signed_batch, BatchWitness, ChainSpec, SignedBlockInput};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256};

/// Host-authenticated L1 batch context, supplied separately from a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedL1Batch {
    /// Finalized L1 height. The host must prove canonicality, not trust an RPC flag.
    pub height: u64,
    /// Canonical L1 block commitment at that height.
    pub block: B256,
    /// Expected execution-domain identity from the L1 module registry.
    pub domain: B256,
    /// Commitment to the complete ordered input obtained through inbox/DA derivation.
    pub input: B256,
}

/// Verified local receipt; NOT a succinct proof or a withdrawal authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceipt {
    /// Network, module, runtime and configuration binding.
    pub domain: B256,
    /// Sequential L2 block number.
    pub number: u64,
    /// Accepted L1 context.
    pub anchor: TrustedL1Batch,
    /// Root before execution.
    pub previous_root: B256,
    /// Re-executed root after execution.
    pub new_root: B256,
    /// Re-executed L2 block hash.
    pub block_hash: B256,
}

impl ExecutionReceipt {
    /// Canonical, domain-separated receipt commitment for local transport/tests.
    pub fn commitment(&self) -> B256 {
        let mut bytes = Vec::from(&b"BLOCH:EXECUTION:RECEIPT:1"[..]);
        bytes.extend_from_slice(self.domain.as_slice());
        bytes.extend_from_slice(&self.number.to_le_bytes());
        bytes.extend_from_slice(&self.anchor.height.to_le_bytes());
        for value in [
            self.anchor.block,
            self.anchor.domain,
            self.anchor.input,
            self.previous_root,
            self.new_root,
            self.block_hash,
        ] {
            bytes.extend_from_slice(value.as_slice());
        }
        keccak256(bytes)
    }
}

/// Fail-closed rejection; domain state is unchanged on every error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    /// Zero identity or invalid execution parameters.
    Configuration,
    /// Wrong domain, input commitment or anchor in the trusted derivation.
    Derivation,
    /// Rollback or a conflicting block at an already accepted L1 height.
    AnchorRegression,
    /// The proposal does not extend the accepted state/sequence.
    Continuity,
    /// Input exceeds the transaction or deposit budget.
    InputLimit,
    /// Witness exceeds the local resource budget.
    WitnessLimit,
    /// Signature, execution or authenticated-witness verification failed.
    Execution,
}

/// Immutable EVM runtime configuration with an atomic local commitment cursor.
/// A runtime upgrade requires a new domain and an explicit state migration.
#[derive(Debug)]
pub struct EvmDomain {
    id: B256,
    spec: ChainSpec,
    root: B256,
    next: u64,
    anchor: Option<(u64, B256)>,
    witness_limit: usize,
}

impl EvmDomain {
    /// Create a domain from a trusted genesis root and pinned runtime artifact ID.
    /// `runtime` is an identifier, not proof that a particular binary is running.
    pub fn new(
        network: B256,
        module: B256,
        runtime: B256,
        spec: ChainSpec,
        genesis_root: B256,
        witness_limit: usize,
    ) -> Result<Self, DomainError> {
        if [network, module, runtime].contains(&B256::ZERO) || witness_limit == 0 || spec.validate().is_err() {
            return Err(DomainError::Configuration);
        }
        // validate() admits only Cancun. Encode every ChainSpec field explicitly;
        // Debug/JSON encodings must never define a consensus commitment.
        let mut bytes = Vec::from(&b"BLOCH:EXECUTION:DOMAIN:1:EVM:CANCUN"[..]);
        for value in [network, module, runtime, genesis_root] {
            bytes.extend_from_slice(value.as_slice());
        }
        for value in [
            spec.chain_id,
            spec.gas_limit,
            spec.block_time_secs,
            spec.base_fee_elasticity,
            spec.base_fee_denominator,
            spec.initial_base_fee,
            spec.max_l1_sats,
            spec.deposit_gas,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&spec.block_reward.to_be_bytes::<32>());
        for value in [
            spec.base_fee_vault,
            spec.sequencer_fee_vault,
            spec.supply_ledger,
            spec.block_info,
        ] {
            bytes.extend_from_slice(value.as_slice());
        }
        Ok(Self {
            id: keccak256(bytes),
            spec,
            root: genesis_root,
            next: 1,
            anchor: None,
            witness_limit,
        })
    }

    /// Immutable domain identity.
    pub fn id(&self) -> B256 {
        self.id
    }
    /// Last locally verified state commitment.
    pub fn state_root(&self) -> B256 {
        self.root
    }
    /// Next expected block number.
    pub fn next_block(&self) -> u64 {
        self.next
    }

    /// Authenticate and re-execute one block before atomically advancing the cursor.
    /// Availability and L1 finality authentication remain the caller's obligation.
    pub fn verify_and_advance(
        &mut self,
        trusted: &TrustedL1Batch,
        input: &SignedBlockInput,
        witness: &BatchWitness,
    ) -> Result<ExecutionReceipt, DomainError> {
        use crate::transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS};
        let total = input
            .transactions
            .iter()
            .fold(0usize, |n, tx| n.saturating_add(tx.len()));
        if input.transactions.len() > MAX_SIGNED_TRANSACTIONS
            || input.transactions.iter().any(|tx| tx.len() > MAX_RAW_TRANSACTION_BYTES)
            || total > MAX_SIGNED_BLOCK_BYTES
            || input.deposits.len() as u64 > self.spec.gas_limit / self.spec.deposit_gas
        {
            return Err(DomainError::InputLimit);
        }
        if trusted.domain != self.id
            || trusted.block == B256::ZERO
            || input.context.anchor_root != trusted.block
            || input_commitment(input) != trusted.input
        {
            return Err(DomainError::Derivation);
        }
        if let Some((height, block)) = self.anchor {
            if trusted.height < height || (trusted.height == height && trusted.block != block) {
                return Err(DomainError::AnchorRegression);
            }
        }
        let next = self.next.checked_add(1).ok_or(DomainError::Continuity)?;
        if input.context.number != self.next || witness.prev_state_root != self.root {
            return Err(DomainError::Continuity);
        }
        let mut size = 64usize;
        for (key, value) in &witness.proof {
            size = size
                .saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(16);
        }
        for account in &witness.pre_accounts {
            size = size
                .saturating_add(60)
                .saturating_add(account.code.len())
                .saturating_add(account.storage.len().saturating_mul(64));
        }
        size = size.saturating_add(witness.absent_accounts.len().saturating_mul(20));
        if size > self.witness_limit {
            return Err(DomainError::WitnessLimit);
        }
        let verified = verify_signed_batch(&self.spec, witness, input).map_err(|_| DomainError::Execution)?;
        let receipt = ExecutionReceipt {
            domain: self.id,
            number: self.next,
            anchor: trusted.clone(),
            previous_root: self.root,
            new_root: verified.new_state_root,
            block_hash: verified.block_hash,
        };
        self.root = verified.new_state_root;
        self.next = next;
        self.anchor = Some((trusted.height, trusted.block));
        Ok(receipt)
    }
}

/// Bind header context, deposit list and exact ordered signed envelopes.
/// Length prefixes distinguish empty elements, boundaries and order.
/// The host must bound decoding BEFORE allocating an untrusted input.
pub fn input_commitment(input: &SignedBlockInput) -> B256 {
    let mut bytes = Vec::from(&b"BLOCH:EXECUTION:INPUT:1"[..]);
    for value in [
        input.context.number,
        input.context.timestamp,
        input.context.base_fee_per_gas,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [
        input.context.prevrandao,
        input.context.anchor_root,
        deposits_hash(&input.deposits),
    ] {
        bytes.extend_from_slice(value.as_slice());
    }
    bytes.extend_from_slice(&(input.transactions.len() as u64).to_le_bytes());
    for tx in &input.transactions {
        bytes.extend_from_slice(&(tx.len() as u64).to_le_bytes());
        bytes.extend_from_slice(tx);
    }
    keccak256(bytes)
}
