// SPDX-License-Identifier: AGPL-3.0-or-later
//! Experimental native escrow adapter using Bloch's real hybrid PQ verifier.
//! No network, wallet unlock, signing endpoint, mainnet transition or release.
use alloy_primitives::B256;
use bloch_l2_evm::escrow::{Coin, EscrowError, EscrowLedger, LockIntent, LockedDeposit, Outpoint};
use sha3::{Digest, Sha3_256};

pub mod checkpoint;
#[cfg(unix)]
pub mod checkpoint_store;

/// Authentication or state-transition rejection. All errors preserve ledger state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    /// Only the exact enveloped ML-DSA-65 AND Falcon-1024 suite is accepted.
    Suite,
    /// Native script hash does not commit the supplied funding public key.
    Owner,
    /// Hybrid signature is invalid for this complete intent.
    Signature,
    /// Input work exceeds the adapter's budget.
    Limit,
    /// Authenticated intent failed the native transition.
    Transition(EscrowError),
}
/// Borrowed authorization; each complete intent needs its own hybrid signature.
pub struct SignedLock<'a> {
    pub intent: &'a LockIntent,
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}
/// Bound cryptographic work per call independently of the ledger capacity.
pub const MAX_LOCK_BATCH: usize = 64;
/// Authenticated facade; the unchecked transition kernel is never exposed mutably.
/// Constructor allocations remain trusted local genesis inputs.
#[derive(Debug)]
pub struct PqEscrow {
    ledger: EscrowLedger,
}
impl PqEscrow {
    /// Apply an ordered batch atomically on a private candidate state. Later
    /// intents may spend earlier change, but cannot spend consumed inputs again.
    /// All request limits are checked before cloning or signature verification.
    /// This local operation does not persist state or establish L1 finality.
    pub fn submit_batch(&mut self, requests: &[SignedLock<'_>]) -> Result<Vec<LockedDeposit>, AuthorizationError> {
        if requests.is_empty()
            || requests.len() > MAX_LOCK_BATCH
            || requests
                .iter()
                .any(|r| r.signature.len() > 8192 || r.public_key.len() > 3749)
            || requests
                .iter()
                .fold(0usize, |n, r| n.saturating_add(r.intent.inputs.len()))
                > 4096
        {
            return Err(AuthorizationError::Limit);
        }
        let mut candidate = Self {
            ledger: self.ledger.clone(),
        };
        let records = requests
            .iter()
            .map(|r| candidate.submit(r.intent, r.public_key, r.signature))
            .collect::<Result<Vec<_>, _>>()?;
        self.ledger = candidate.ledger;
        Ok(records)
    }
    /// Create a local ledger from trusted genesis allocations, not an RPC balance.
    pub fn new(
        network: B256,
        domain: B256,
        coins: Vec<(Outpoint, Coin)>,
        capacity: usize,
    ) -> Result<Self, EscrowError> {
        Ok(Self {
            ledger: EscrowLedger::new(network, domain, coins, capacity)?,
        })
    }
    /// Authenticate both PQ signature components before applying an atomic lock.
    /// No legacy key fallback, algorithm downgrade or caller-supplied verifier exists.
    pub fn submit(
        &mut self,
        intent: &LockIntent,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<LockedDeposit, AuthorizationError> {
        if intent.inputs.len() > 4096 || signature.len() > 8192 {
            return Err(AuthorizationError::Limit);
        }
        let suite = [0xb1, 0x0c, 0x01, 0x00];
        if public_key.len() != 3749 || public_key[..4] != suite || signature.len() < 4 || signature[..4] != suite {
            return Err(AuthorizationError::Suite);
        }
        let owner = B256::from_slice(&Sha3_256::digest(public_key));
        if owner != intent.owner {
            return Err(AuthorizationError::Owner);
        }
        let root = intent.signing_root();
        if !bloch_crypto::crypto::verify(public_key, root.as_slice(), signature) {
            return Err(AuthorizationError::Signature);
        }
        self.ledger
            .apply_authorized_lock(intent)
            .map_err(AuthorizationError::Transition)
    }
    /// Current experimental state commitment, not a live Genesis-4 state root.
    pub fn commitment(&self) -> B256 {
        self.ledger.commitment()
    }
    /// Read-only native coin lookup.
    pub fn coin(&self, id: Outpoint) -> Option<Coin> {
        self.ledger.coin(id)
    }
    /// Native amount locked by successfully authenticated requests.
    pub fn locked_sat(&self) -> u128 {
        self.ledger.locked_sat()
    }
    /// Assert the accounting conservation invariant.
    pub fn conserved(&self) -> bool {
        self.ledger.conserved()
    }
    /// Snapshot of authenticated local locks; external finality is still required.
    pub fn inbox(&self) -> bloch_l2_evm::escrow_inbox::InboxSnapshot {
        self.ledger.inbox()
    }
    /// No withdrawal-proof backend is installed; funds cannot be released here.
    pub fn release(&mut self) -> Result<(), EscrowError> {
        self.ledger.release()
    }
}
