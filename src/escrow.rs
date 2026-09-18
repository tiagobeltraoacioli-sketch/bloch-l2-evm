// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental native escrow transition kernel, NOT wired into Genesis-4.
//!
//! `apply_authorized_lock` is a TRUSTED consensus-host boundary: the host MUST
//! authenticate the funding authority's PQ signature over `LockIntent::signing_root`
//! before calling it. No signature verifier, finality proof or bridge release is
//! supplied by this kernel. Genesis allocations are trusted local inputs.
use alloc::{collections::BTreeMap, vec::Vec};
use alloy_primitives::{Address, B256};
use sha3::{Digest, Sha3_256};

const MAX_LOCK_INPUTS: usize = 4096;

/// Native output identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Outpoint {
    /// Native transaction ID.
    pub txid: B256,
    /// Output index.
    pub vout: u32,
}
/// Spendable native coin in the experimental host state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coin {
    /// Exact native satoshis.
    pub value: u64,
    /// Funding public-key script hash.
    pub owner: B256,
}
/// Explicit native lock intent; not an assigned mainnet transaction wire tag.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LockIntent {
    /// Genesis/network identity.
    pub network: B256,
    /// Immutable execution domain identity.
    pub domain: B256,
    /// Authority the consensus host must authenticate.
    pub owner: B256,
    /// Canonically sorted, unique funding outpoints.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_lock_inputs"))]
    pub inputs: Vec<Outpoint>,
    /// Runtime-specific EVM recipient.
    pub recipient: Address,
    /// Native amount to lock.
    pub amount: u64,
    /// Fee explicitly authorized by the funder, accounted separately.
    pub fee: u64,
    /// Authority receiving change.
    pub change_owner: B256,
    /// Explicit authorization nonce.
    pub nonce: u64,
}

#[cfg(feature = "serde")]
fn deserialize_lock_inputs<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Outpoint>, D::Error> {
    crate::serde_bounded::vector::<_, _, MAX_LOCK_INPUTS>(deserializer)
}
impl LockIntent {
    /// Domain-separated signing root binding every authorization field.
    pub fn signing_root(&self) -> B256 {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH:EXPERIMENTAL:ESCROW:LOCK:1");
        for v in [self.network, self.domain, self.owner, self.change_owner] {
            h.update(v);
        }
        h.update(self.recipient);
        h.update(self.amount.to_le_bytes());
        h.update(self.fee.to_le_bytes());
        h.update(self.nonce.to_le_bytes());
        h.update((self.inputs.len() as u64).to_le_bytes());
        for p in &self.inputs {
            h.update(p.txid);
            h.update(p.vout.to_le_bytes());
        }
        B256::from_slice(&h.finalize())
    }
}
/// Recorded liability; not a mint authorization or finality certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LockedDeposit {
    /// Unique intent commitment.
    pub id: B256,
    /// Domain receiving the future verified credit.
    pub domain: B256,
    /// EVM recipient bound by funding authorization.
    pub recipient: Address,
    /// Locked native amount.
    pub amount: u64,
    /// Experimental append-only inbox sequence, starting at zero.
    pub sequence: u64,
}
/// Deterministic rejection; all errors preserve the previous state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    /// Wrong domain/network or malformed intent/genesis configuration.
    Configuration,
    /// Inputs missing, unsorted, repeated or owned by another authority.
    Funding,
    /// Insufficient input value, change overflow or counter overflow.
    Amount,
    /// Duplicate intent or generated change identity collision.
    Replay,
    /// Bounded lock journal is full; caller must not discard replay protection.
    Capacity,
    /// No real withdrawal proof verifier is integrated. All releases are refused.
    ReleaseUnavailable,
}
/// Experimental native ledger. No authority/admin mint or release bypass exists.
#[derive(Debug, Clone)]
pub struct EscrowLedger {
    network: B256,
    domain: B256,
    coins: BTreeMap<Outpoint, Coin>,
    deposits: BTreeMap<B256, LockedDeposit>,
    sequence: u64,
    initial: u128,
    locked: u128,
    fees: u128,
    capacity: usize,
}
impl EscrowLedger {
    /// Construct from a trusted local genesis allocation, never wallet/RPC claims.
    pub fn new(
        network: B256,
        domain: B256,
        coins: Vec<(Outpoint, Coin)>,
        capacity: usize,
    ) -> Result<Self, EscrowError> {
        if network == B256::ZERO || domain == B256::ZERO || capacity == 0 {
            return Err(EscrowError::Configuration);
        }
        let mut state = BTreeMap::new();
        let mut initial = 0u128;
        for (id, coin) in coins {
            if coin.value == 0 || coin.owner == B256::ZERO || state.insert(id, coin).is_some() {
                return Err(EscrowError::Configuration);
            }
            initial = initial.checked_add(coin.value as u128).ok_or(EscrowError::Amount)?;
        }
        Ok(Self {
            network,
            domain,
            coins: state,
            deposits: BTreeMap::new(),
            sequence: 0,
            initial,
            locked: 0,
            fees: 0,
            capacity,
        })
    }
    /// Apply only AFTER the consensus host verified the funder's PQ authorization.
    /// The kernel validates ownership/conservation, not possession of a private key.
    /// A locked deposit cannot be credited to EVM by merely calling this method.
    pub fn apply_authorized_lock(&mut self, intent: &LockIntent) -> Result<LockedDeposit, EscrowError> {
        if intent.network != self.network
            || intent.domain != self.domain
            || intent.amount == 0
            || intent.recipient == Address::ZERO
            || intent.owner == B256::ZERO
            || intent.change_owner == B256::ZERO
            || intent.inputs.is_empty()
            || intent.inputs.len() > MAX_LOCK_INPUTS
        {
            return Err(EscrowError::Configuration);
        }
        if intent.inputs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(EscrowError::Funding);
        }
        let id = intent.signing_root();
        if self.deposits.contains_key(&id) {
            return Err(EscrowError::Replay);
        }
        if self.deposits.len() >= self.capacity {
            return Err(EscrowError::Capacity);
        }
        let next = self.sequence.checked_add(1).ok_or(EscrowError::Amount)?;
        let mut total = 0u128;
        for p in &intent.inputs {
            let coin = self.coins.get(p).ok_or(EscrowError::Funding)?;
            if coin.owner != intent.owner {
                return Err(EscrowError::Funding);
            }
            total = total.checked_add(coin.value as u128).ok_or(EscrowError::Amount)?;
        }
        let cost = intent.amount as u128 + intent.fee as u128;
        let change = total.checked_sub(cost).ok_or(EscrowError::Amount)?;
        let change = u64::try_from(change).map_err(|_| EscrowError::Amount)?;
        let change_id = Outpoint { txid: id, vout: 0 };
        if self.coins.contains_key(&change_id) {
            return Err(EscrowError::Replay);
        }
        let locked = self
            .locked
            .checked_add(intent.amount as u128)
            .ok_or(EscrowError::Amount)?;
        let fees = self.fees.checked_add(intent.fee as u128).ok_or(EscrowError::Amount)?;
        let record = LockedDeposit {
            id,
            domain: self.domain,
            recipient: intent.recipient,
            amount: intent.amount,
            sequence: self.sequence,
        };
        // No fallible validation below this line: consume and commit atomically.
        for p in &intent.inputs {
            self.coins.remove(p);
        }
        if change > 0 {
            self.coins.insert(
                change_id,
                Coin {
                    value: change,
                    owner: intent.change_owner,
                },
            );
        }
        self.deposits.insert(id, record.clone());
        self.sequence = next;
        self.locked = locked;
        self.fees = fees;
        Ok(record)
    }
    /// Spendable balance + locked liabilities + accounted fees equals genesis.
    pub fn conserved(&self) -> bool {
        self.coins.values().map(|c| c.value as u128).sum::<u128>() + self.locked + self.fees == self.initial
    }
    /// Read a spendable native coin; locked principal is absent from this set.
    pub fn coin(&self, id: Outpoint) -> Option<Coin> {
        self.coins.get(&id).copied()
    }
    /// Total native liabilities in satoshis.
    pub fn locked_sat(&self) -> u128 {
        self.locked
    }
    /// Total explicitly charged native fees.
    pub fn fee_sat(&self) -> u128 {
        self.fees
    }
    /// Current append-only lock count.
    pub fn lock_count(&self) -> u64 {
        self.sequence
    }
    /// Ordered inclusion snapshot; its root is not a finalized L1 commitment.
    pub fn inbox(&self) -> crate::escrow_inbox::InboxSnapshot {
        crate::escrow_inbox::InboxSnapshot::new(self.network, self.domain, self.deposits.values().cloned().collect())
    }
    /// Fail closed until real withdrawal verification and nullifiers are implemented.
    pub fn release(&mut self) -> Result<(), EscrowError> {
        Err(EscrowError::ReleaseUnavailable)
    }
    /// Canonical commitment covering every mutable ledger field and configuration.
    /// This experimental root is NOT the Genesis-4 consensus state root.
    pub fn commitment(&self) -> B256 {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH:EXPERIMENTAL:ESCROW:STATE:1");
        h.update(self.network);
        h.update(self.domain);
        h.update((self.capacity as u64).to_le_bytes());
        h.update(self.sequence.to_le_bytes());
        for value in [self.initial, self.locked, self.fees] {
            h.update(value.to_le_bytes());
        }
        h.update((self.coins.len() as u64).to_le_bytes());
        for (id, coin) in &self.coins {
            h.update(id.txid);
            h.update(id.vout.to_le_bytes());
            h.update(coin.value.to_le_bytes());
            h.update(coin.owner);
        }
        h.update((self.deposits.len() as u64).to_le_bytes());
        for (id, d) in &self.deposits {
            h.update(id);
            h.update(d.domain);
            h.update(d.recipient);
            h.update(d.amount.to_le_bytes());
            h.update(d.sequence.to_le_bytes());
        }
        B256::from_slice(&h.finalize())
    }
}
