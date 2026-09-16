// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental atomic inbox consumption and EVM re-execution.
//! Trusted host inputs below are NOT independently verified L1 certificates.
use crate::{
    domain::{DomainError, EvmDomain, ExecutionReceipt, TrustedL1Batch},
    escrow_inbox::InboxProof,
    BatchWitness, ChainSpec, DepositMint, DepositPosition, DepositProvenance, SignedBlockInput,
};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256};

/// Host-authenticated mapping from an inbox lock to its actual L1 provenance.
/// Never substitute an inbox sequence or a slot for `position.l1_height`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLockLocation {
    /// Zero-based inbox sequence.
    pub sequence: u64,
    /// Escrow intent identity, not necessarily the native transaction ID.
    pub intent: B256,
    /// Actual finalized escrow output position.
    pub position: DepositPosition,
    /// Actual native escrow transaction ID.
    pub transaction: B256,
}

/// Trusted finalized derivation supplied by the embedding host, not by a proposer.
/// Host must authenticate root/count, every location and append-only ancestry.
#[derive(Debug, Clone)]
pub struct TrustedEscrowBatch {
    /// Independently authenticated ordered execution input and L1 anchor.
    pub execution: TrustedL1Batch,
    /// Finalized inbox commitment for this network/domain at the anchor.
    pub inbox_root: B256,
    /// Exact total inbox length at the anchor, including previously consumed locks.
    pub count: u64,
    /// Actual L1 locations of this block's mandatory contiguous deposit prefix.
    pub locations: Vec<TrustedLockLocation>,
}

/// Rejection before any cursor advances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowExecutionError {
    /// Invalid initial configuration.
    Configuration,
    /// Changed snapshot at the same anchor or a shrinking inbox.
    Snapshot,
    /// Missing, extra, replayed or reordered deposits.
    Sequence,
    /// Invalid inclusion or mismatch with independently authenticated L1 mapping.
    Inclusion,
    /// Re-execution or the underlying domain boundary rejected the block.
    Execution(DomainError),
}

/// Local execution receipt binding inbox consumption; NOT a withdrawal proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowExecutionReceipt {
    /// Verified EVM execution.
    pub execution: ExecutionReceipt,
    /// Accepted finalized inbox root, authenticated externally by the host.
    pub inbox_root: B256,
    /// Accepted inbox length.
    pub inbox_count: u64,
    /// First consumed sequence (inclusive).
    pub start: u64,
    /// Next unconsumed sequence (exclusive).
    pub end: u64,
}
impl EscrowExecutionReceipt {
    /// Canonical local receipt identity binding execution and the consumed range.
    pub fn commitment(&self) -> B256 {
        let mut bytes = Vec::from(&b"BLOCH:EXPERIMENTAL:ESCROW:EXECUTION:1"[..]);
        bytes.extend_from_slice(self.execution.commitment().as_slice());
        bytes.extend_from_slice(self.inbox_root.as_slice());
        for n in [self.inbox_count, self.start, self.end] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        keccak256(bytes)
    }
}

/// Private domain and inbox cursors advance together after successful verification.
/// In-memory atomicity only; persistent recovery and L1 authentication are external.
#[derive(Debug, Clone)]
pub struct EscrowEvmDomain {
    network: B256,
    execution: EvmDomain,
    next_deposit: u64,
    batch_limit: u64,
    snapshot: Option<(u64, B256, B256, u64)>,
}
impl EscrowEvmDomain {
    /// Start a fresh domain with no consumed inbox deposits. The initial EVM root
    /// is trusted; the host must ensure it does not already credit these deposits.
    /// Pin this derivation policy in a new runtime artifact identity.
    pub fn new(
        network: B256,
        module: B256,
        runtime: B256,
        spec: ChainSpec,
        genesis_root: B256,
        witness_limit: usize,
    ) -> Result<Self, EscrowExecutionError> {
        spec.validate().map_err(|_| EscrowExecutionError::Configuration)?;
        let batch_limit = (spec.gas_limit / spec.deposit_gas).min(4096);
        if batch_limit == 0 {
            return Err(EscrowExecutionError::Configuration);
        }
        let execution = EvmDomain::new(network, module, runtime, spec, genesis_root, witness_limit)
            .map_err(|_| EscrowExecutionError::Configuration)?;
        Ok(Self {
            network,
            execution,
            next_deposit: 0,
            batch_limit,
            snapshot: None,
        })
    }
    /// Immutable execution domain identity.
    pub fn id(&self) -> B256 {
        self.execution.id()
    }
    /// Last locally accepted EVM state root.
    pub fn state_root(&self) -> B256 {
        self.execution.state_root()
    }
    /// Next expected EVM block.
    pub fn next_block(&self) -> u64 {
        self.execution.next_block()
    }
    /// First inbox position not yet consumed.
    pub fn next_deposit(&self) -> u64 {
        self.next_deposit
    }

    /// Preview the exact mandatory prefix using the verifier's gas-derived limit.
    /// This does not authenticate a snapshot/root or reserve/consume deposits.
    pub fn required_deposit_range(&self, count: u64) -> Result<core::ops::Range<u64>, EscrowExecutionError> {
        if count < self.next_deposit || self.snapshot.is_some_and(|(_, _, _, prior)| count < prior) {
            return Err(EscrowExecutionError::Snapshot);
        }
        let take = (count - self.next_deposit).min(self.batch_limit);
        Ok(self.next_deposit..self.next_deposit + take)
    }

    /// Consume exactly the available prefix up to the gas-derived/4096 limit.
    /// All validation precedes EVM mutation; no fallible step follows that mutation.
    pub fn verify_and_advance(
        &mut self,
        trusted: &TrustedEscrowBatch,
        proofs: &[InboxProof],
        input: &SignedBlockInput,
        witness: &BatchWitness,
    ) -> Result<EscrowExecutionReceipt, EscrowExecutionError> {
        if trusted.inbox_root == B256::ZERO || trusted.count < self.next_deposit {
            return Err(EscrowExecutionError::Snapshot);
        }
        if let Some((height, block, root, count)) = self.snapshot {
            if trusted.count < count
                || (trusted.count == count && trusted.inbox_root != root)
                || (trusted.execution.height == height
                    && (trusted.execution.block != block || trusted.inbox_root != root || trusted.count != count))
            {
                return Err(EscrowExecutionError::Snapshot);
            }
        }
        let range = self.required_deposit_range(trusted.count)?;
        let take = range.end - range.start;
        if proofs.len() as u64 != take || input.deposits.len() as u64 != take || trusted.locations.len() as u64 != take
        {
            return Err(EscrowExecutionError::Sequence);
        }
        // Sum cannot overflow: take <= count - next_deposit.
        let end = range.end;
        for (offset, ((proof, location), mint)) in
            proofs.iter().zip(&trusted.locations).zip(&input.deposits).enumerate()
        {
            let sequence = self.next_deposit + offset as u64;
            if proof.deposit.sequence != sequence || location.sequence != sequence {
                return Err(EscrowExecutionError::Sequence);
            }
            if proof.count != trusted.count
                || !proof.verify(self.network, self.id(), trusted.inbox_root)
                || location.intent != proof.deposit.id
                || location.transaction == B256::ZERO
                || location.position.l1_height > trusted.execution.height
            {
                return Err(EscrowExecutionError::Inclusion);
            }
            let expected = DepositMint {
                recipient: proof.deposit.recipient,
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: location.position.l1_height,
                    l1_tx_index: location.position.l1_tx_index,
                    l1_txid: location.transaction.into(),
                    l1_vout: location.position.l1_vout,
                    l1_sats: proof.deposit.amount,
                },
            };
            if *mint != expected {
                return Err(EscrowExecutionError::Inclusion);
            }
        }
        let execution = self
            .execution
            .verify_and_advance(&trusted.execution, input, witness)
            .map_err(EscrowExecutionError::Execution)?;
        let receipt = EscrowExecutionReceipt {
            execution,
            inbox_root: trusted.inbox_root,
            inbox_count: trusted.count,
            start: self.next_deposit,
            end,
        };
        self.next_deposit = end;
        self.snapshot = Some((
            trusted.execution.height,
            trusted.execution.block,
            trusted.inbox_root,
            trusted.count,
        ));
        Ok(receipt)
    }
}
