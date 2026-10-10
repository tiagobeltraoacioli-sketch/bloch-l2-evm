// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded full native replay from independently pinned genesis state.
//! This does not activate a network or publish an Ethereum finality tag.
use alloy_primitives::B256;
use bloch_l2_evm::{
    l1::FinalizedCheckpoint,
    native_settlement::{store::SettlementReplayRecordV1, SettlementPolicyV1},
};
use bloch_pos_committee::{
    attestation::{Attestation, SignatureVerifier},
    epoch_of,
    header::BlockId,
    interfaces::{ProposalEnvelope, StateReader, StateTransition},
    l2_settlement::Policy,
    params::SLOTS_PER_EPOCH,
    transition::{CommittedState, PosTransaction, Transition},
};
use std::collections::BTreeMap;

/// Independently authenticated genesis state root, not a value copied from the
/// submitted history. Settlement policy also pins the native network/genesis.
#[derive(Clone, Copy, Debug)]
pub struct NativeGenesisTrustV1 {
    pub state_root: B256,
    pub settlement_policy: SettlementPolicyV1,
}

/// Already decoded envelope/attestations and bounded canonical transaction bytes.
/// Network/file decoding and its allocation limits remain the host's responsibility.
#[derive(Clone, Debug)]
pub struct NativeReplayBlockV1 {
    pub envelope: ProposalEnvelope,
    pub attestations: Vec<Attestation>,
    pub transactions: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeReplayLimitsV1 {
    pub blocks: usize,
    pub epochs: u64,
    pub attestations: usize,
    pub transactions: usize,
    pub proofs: usize,
    pub bytes: usize,
}
impl Default for NativeReplayLimitsV1 {
    fn default() -> Self {
        Self {
            blocks: 64,
            epochs: 8,
            attestations: 256,
            transactions: 64,
            proofs: 8,
            bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFinalityErrorV1 {
    Trust,
    Limit,
    Encoding,
    Ancestry,
    VoteBranch,
    Transition { block: usize, reason: String },
    NotFinalized,
    Settlement,
}
impl std::fmt::Display for NativeFinalityErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native finality replay refused: {self:?}")
    }
}
impl std::error::Error for NativeFinalityErrorV1 {}

/// The same real signature/proof operations used by the native node. No caller
/// verifier injection exists at the finality replay boundary.
pub struct NativeConsensusVerifierV1;
impl SignatureVerifier for NativeConsensusVerifierV1 {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify(key, root, signature)
    }
    fn verify_l2_settlement(&self, policy: &[u8; 32], program: &[u8; 32], values: &[u8], proof: &[u8]) -> bool {
        bloch_l2_proof::verify(policy, program, values, proof)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFinalityReportV1 {
    pub genesis_state_root: B256,
    pub settlement_policy: B256,
    pub replayed_tip: B256,
    pub replayed_state_root: B256,
    pub replayed_blocks: usize,
    pub replayed_slot: u64,
    pub finalized: FinalizedCheckpoint,
    pub finalized_epoch: u64,
}

/// Private-constructor replay result. It owns the exact accepted bytes and
/// canonical ancestry used to audit settlements; a report alone is not authority.
pub struct VerifiedNativeFinalityV1 {
    report: NativeFinalityReportV1,
    chain: Vec<(u64, B256)>,
    positions: BTreeMap<B256, (u64, usize)>,
    finalized_index: usize,
    settlements: BTreeMap<B256, Vec<u8>>,
}
impl VerifiedNativeFinalityV1 {
    pub const fn report(&self) -> &NativeFinalityReportV1 {
        &self.report
    }

    /// Exact accepted bytes in native order, restricted to the finalized prefix.
    /// This borrowed view is available only after complete consensus replay.
    pub fn finalized_settlements(&self) -> impl Iterator<Item = (u64, B256, &[u8])> {
        self.chain
            .iter()
            .take(self.finalized_index + 1)
            .filter_map(|(slot, id)| self.settlements.get(id).map(|bytes| (*slot, *id, bytes.as_slice())))
    }

    pub(crate) fn check_checkpoint(
        &self,
        anchor: FinalizedCheckpoint,
        epoch: u64,
    ) -> Result<(), NativeFinalityErrorV1> {
        if epoch > self.report.finalized_epoch
            || checkpoint(&self.chain, epoch) != Some(anchor.block)
            || !self
                .positions
                .get(&anchor.block)
                .is_some_and(|(slot, index)| *slot == anchor.slot && *index <= self.finalized_index)
        {
            return Err(NativeFinalityErrorV1::NotFinalized);
        }
        Ok(())
    }

    pub(crate) fn audit_record(&self, record: &SettlementReplayRecordV1<'_>) -> Result<(), NativeFinalityErrorV1> {
        let admission = record.admission.ok_or(NativeFinalityErrorV1::Settlement)?;
        let checkpoint = admission.checkpoint();
        let receipt = bloch_native_escrow_pq::settlement_authority::CheckpointAuthorityReceiptV1::decode(
            record.authority_audit.ok_or(NativeFinalityErrorV1::Settlement)?,
        )
        .map_err(|_| NativeFinalityErrorV1::Settlement)?;
        self.check_checkpoint(checkpoint, receipt.checkpoint_epoch())?;
        if !self
            .positions
            .get(&admission.block())
            .is_some_and(|(slot, index)| *slot == admission.slot() && *index <= self.finalized_index)
            || self.settlements.get(&admission.block()).map(Vec::as_slice) != Some(record.transaction)
        {
            return Err(NativeFinalityErrorV1::Settlement);
        }
        Ok(())
    }
}

fn native_policy(p: SettlementPolicyV1) -> Policy {
    Policy {
        identities: [
            p.network.0,
            p.genesis.0,
            p.domain.0,
            p.configuration.0,
            p.program_elf_keccak.0,
            p.program_vkey_koalabear.0,
            p.program_vkey_bn254.0,
        ],
        proof_policy: p.proof_policy.0,
        chain_id: p.chain_id,
        initial_l2_parent: p.initial_l2_parent_hash.0,
        initial_l2_state: p.initial_l2_state_root.0,
    }
}

fn checkpoint(chain: &[(u64, B256)], epoch: u64) -> Option<B256> {
    let boundary = epoch.checked_mul(SLOTS_PER_EPOCH)?;
    // Slots are strictly increasing. Avoid scanning a whole prefix per vote.
    let next = chain.partition_point(|(slot, _)| *slot < boundary);
    Some(chain[next.saturating_sub(1)].1)
}

/// Replay all native blocks, with real proposer/attester signatures, committed
/// state transitions and Groth16 checks. The complete prior state is reconstructed;
/// no WS snapshot resets the leak ledger or skips epoch accounting.
///
/// This deliberately supports a single complete branch from genesis. It does not
/// implement network fork choice or a state-sync shortcut. All limits are checked
/// before signature/proof work. Branch checks follow the node's checkpoint rule:
/// the last block strictly before the epoch boundary, including empty slots.
pub fn verify_native_finality(
    genesis: &CommittedState,
    trust: NativeGenesisTrustV1,
    blocks: &[NativeReplayBlockV1],
    limits: NativeReplayLimitsV1,
) -> Result<VerifiedNativeFinalityV1, NativeFinalityErrorV1> {
    use NativeFinalityErrorV1 as E;
    if limits.blocks > 10_000
        || limits.epochs > 4_096
        || limits.attestations > 100_000
        || limits.transactions > 100_000
        || limits.proofs > 1_024
        || limits.bytes > 64 * 1_048_576
        || blocks.is_empty()
        || blocks.len() > limits.blocks
        || genesis.validator_count() > 4_096
    {
        return Err(E::Limit);
    }
    check_trust(genesis, trust)?;
    let mut byte_count = 0usize;
    let mut atts = 0usize;
    let mut txs = 0usize;
    let mut proofs = 0usize;
    let mut last_slot = 0;
    for block in blocks {
        let slot = block.envelope.header.slot;
        if slot <= last_slot || epoch_of(slot) > limits.epochs {
            return Err(E::Limit);
        }
        last_slot = slot;
        byte_count = byte_count
            .checked_add(304 + block.envelope.proposer_sig.len())
            .ok_or(E::Limit)?;
        if block.envelope.proposer_sig.len() > 8_192 {
            return Err(E::Limit);
        }
        atts = atts.checked_add(block.attestations.len()).ok_or(E::Limit)?;
        txs = txs.checked_add(block.transactions.len()).ok_or(E::Limit)?;
        if byte_count > limits.bytes || atts > limits.attestations || txs > limits.transactions {
            return Err(E::Limit);
        }
        for att in &block.attestations {
            if att.signature.len() > 8_192 {
                return Err(E::Limit);
            }
            byte_count = byte_count.checked_add(132 + att.signature.len()).ok_or(E::Limit)?;
            if byte_count > limits.bytes {
                return Err(E::Limit);
            }
        }
        for tx in &block.transactions {
            byte_count = byte_count.checked_add(tx.len()).ok_or(E::Limit)?;
            if matches!(
                tx.first(),
                Some(&bloch_pos_committee::l2_settlement::WIRE_TAG)
                    | Some(&bloch_pos_committee::l2_settlement::ASYNC_WIRE_TAG)
            ) {
                proofs = proofs.checked_add(1).ok_or(E::Limit)?;
            }
            if byte_count > limits.bytes || proofs > limits.proofs {
                return Err(E::Limit);
            }
        }
        if byte_count > limits.bytes
            || atts > limits.attestations
            || txs > limits.transactions
            || proofs > limits.proofs
        {
            return Err(E::Limit);
        }
    }
    let mut verifier = IncrementalNativeVerifierV1::new(genesis, trust, blocks.len())?;
    for block in blocks {
        verifier.apply_checked(block)?;
    }
    verifier.snapshot()
}

fn check_trust(genesis: &CommittedState, trust: NativeGenesisTrustV1) -> Result<B256, NativeFinalityErrorV1> {
    use NativeFinalityErrorV1 as E;
    let p = trust.settlement_policy;
    let policy_commitment = p.commitment().map_err(|_| E::Trust)?;
    let state = genesis.l2_settlement().ok_or(E::Trust)?;
    if trust.state_root == B256::ZERO
        || genesis.slot() != 0
        || genesis.head().as_bytes() != &p.genesis.0
        || genesis.state_root() != trust.state_root.0
        || state.height() != 0
        || state.head().is_some()
        || state.policy() != &native_policy(p)
        || p.first_l2_number != 1
        || p.proof_policy.0 != bloch_l2_proof::policy_commitment()
    {
        return Err(E::Trust);
    }
    Ok(policy_commitment)
}

/// Per-block bounds for continuous verification, where no whole-history budget
/// applies. All are checked before any signature or proof work on that block.
#[derive(Clone, Copy, Debug)]
pub struct NativeBlockLimitsV1 {
    pub signature_bytes: usize,
    pub attestations: usize,
    pub transactions: usize,
    pub proofs: usize,
    pub bytes: usize,
}
impl Default for NativeBlockLimitsV1 {
    fn default() -> Self {
        Self {
            signature_bytes: 8_192,
            attestations: 4_096,
            transactions: 4_096,
            proofs: 64,
            bytes: 4 * 1_048_576,
        }
    }
}

/// Real native replay that advances one block at a time and can be queried
/// between blocks. It holds the complete committed state from the pinned
/// genesis; nothing is restored from a stored snapshot. Any refusal poisons the
/// verifier: no partially applied state is ever reported or extended.
pub struct IncrementalNativeVerifierV1 {
    transition: Transition<NativeConsensusVerifierV1>,
    trust: NativeGenesisTrustV1,
    policy_commitment: B256,
    state: CommittedState,
    chain: Vec<(u64, B256)>,
    positions: BTreeMap<B256, (u64, usize)>,
    settlements: BTreeMap<B256, Vec<u8>>,
    final_epoch: u64,
    final_index: usize,
    applied: usize,
    max_blocks: usize,
    poisoned: bool,
}

impl IncrementalNativeVerifierV1 {
    pub fn new(genesis: &CommittedState, trust: NativeGenesisTrustV1, max_blocks: usize) -> Result<Self, NativeFinalityErrorV1> {
        if genesis.validator_count() > 4_096 || max_blocks == 0 {
            return Err(NativeFinalityErrorV1::Limit);
        }
        let policy_commitment = check_trust(genesis, trust)?;
        let p = trust.settlement_policy;
        Ok(Self {
            transition: Transition::new(NativeConsensusVerifierV1),
            trust,
            policy_commitment,
            state: genesis.clone(),
            chain: vec![(0, p.genesis)],
            positions: BTreeMap::from([(p.genesis, (0, 0))]),
            settlements: BTreeMap::new(),
            final_epoch: 0,
            final_index: 0,
            applied: 0,
            max_blocks,
            poisoned: false,
        })
    }

    /// Head of the verified branch (the pinned genesis before any block).
    pub fn head(&self) -> B256 {
        B256::from(*self.state.head().as_bytes())
    }

    pub const fn applied(&self) -> usize {
        self.applied
    }

    /// Apply one block after enforcing [`NativeBlockLimitsV1`].
    pub fn apply(&mut self, block: &NativeReplayBlockV1, limits: NativeBlockLimitsV1) -> Result<(), NativeFinalityErrorV1> {
        use NativeFinalityErrorV1 as E;
        let sizes_ok = block.envelope.proposer_sig.len() <= limits.signature_bytes
            && block.attestations.len() <= limits.attestations
            && block.transactions.len() <= limits.transactions
            && block.attestations.iter().all(|a| a.signature.len() <= limits.signature_bytes);
        let bytes = 304usize
            .saturating_add(block.envelope.proposer_sig.len())
            .saturating_add(block.attestations.iter().map(|a| 132 + a.signature.len()).sum::<usize>())
            .saturating_add(block.transactions.iter().map(Vec::len).sum::<usize>());
        let proofs = block
            .transactions
            .iter()
            .filter(|tx| {
                matches!(
                    tx.first(),
                    Some(&bloch_pos_committee::l2_settlement::WIRE_TAG)
                        | Some(&bloch_pos_committee::l2_settlement::ASYNC_WIRE_TAG)
                )
            })
            .count();
        if !sizes_ok || bytes > limits.bytes || proofs > limits.proofs {
            self.poisoned = true;
            return Err(E::Limit);
        }
        self.apply_checked(block)
    }

    /// Callers must already have bounded this block's sizes.
    fn apply_checked(&mut self, block: &NativeReplayBlockV1) -> Result<(), NativeFinalityErrorV1> {
        use NativeFinalityErrorV1 as E;
        if self.poisoned {
            return Err(E::Ancestry);
        }
        if self.applied >= self.max_blocks || block.envelope.header.slot <= self.state.slot() {
            self.poisoned = true;
            return Err(E::Limit);
        }
        // Poison until every check below has passed and the block is published.
        self.poisoned = true;
        let index = self.applied;
        if block.envelope.header.parent != self.state.head().as_bytes()[..] {
            return Err(E::Ancestry);
        }
        for att in &block.attestations {
            let a = &att.data;
            if checkpoint(&self.chain, a.source_epoch).map(|h| h.0) != Some(a.source_root)
                || checkpoint(&self.chain, a.target_epoch).map(|h| h.0) != Some(a.target_root)
                || !self
                    .positions
                    .get(&B256::from(a.head))
                    .is_some_and(|(slot, _)| *slot <= a.slot)
            {
                return Err(E::VoteBranch);
            }
        }
        let transactions = block
            .transactions
            .iter()
            .map(|bytes| {
                let tx = PosTransaction::from_canonical_bytes(bytes).map_err(|_| E::Encoding)?;
                if tx.canonical_bytes() != *bytes {
                    return Err(E::Encoding);
                }
                Ok(tx)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.state = self
            .transition
            .apply_block(&self.state, &block.envelope, &block.attestations, &transactions)
            .map_err(|e| E::Transition {
                block: index,
                reason: format!("{e:?}"),
            })?;
        let id = B256::from(*BlockId::of(&block.envelope.header).as_bytes());
        if self
            .positions
            .insert(id, (block.envelope.header.slot, self.chain.len()))
            .is_some()
        {
            return Err(E::Ancestry);
        }
        self.chain.push((block.envelope.header.slot, id));
        for (tx, bytes) in transactions.iter().zip(&block.transactions) {
            if matches!(
                tx,
                PosTransaction::L2Settlement(_) | PosTransaction::L2SettlementAsync(_)
            ) {
                self.settlements.insert(id, bytes.clone());
            }
        }
        let finalized = self.state.finality().finalized;
        if finalized.epoch < self.final_epoch
            || checkpoint(&self.chain, finalized.epoch).map(|h| h.0) != Some(finalized.root)
        {
            return Err(E::Ancestry);
        }
        let position = self.positions.get(&B256::from(finalized.root)).ok_or(E::Ancestry)?.1;
        if position < self.final_index {
            return Err(E::Ancestry);
        }
        self.final_epoch = finalized.epoch;
        self.final_index = position;
        self.applied += 1;
        self.poisoned = false;
        Ok(())
    }

    /// The verified finality capability at the current branch tip.
    pub fn snapshot(&self) -> Result<VerifiedNativeFinalityV1, NativeFinalityErrorV1> {
        use NativeFinalityErrorV1 as E;
        if self.poisoned {
            return Err(E::Ancestry);
        }
        if self.final_epoch == 0 || self.final_index == 0 {
            return Err(E::NotFinalized);
        }
        Ok(VerifiedNativeFinalityV1 {
            report: NativeFinalityReportV1 {
                genesis_state_root: self.trust.state_root,
                settlement_policy: self.policy_commitment,
                replayed_tip: self.head(),
                replayed_state_root: B256::from(self.state.state_root()),
                replayed_blocks: self.applied,
                replayed_slot: self.state.slot(),
                finalized: FinalizedCheckpoint {
                    block: self.chain[self.final_index].1,
                    slot: self.chain[self.final_index].0,
                },
                finalized_epoch: self.final_epoch,
            },
            chain: self.chain.clone(),
            positions: self.positions.clone(),
            finalized_index: self.final_index,
            settlements: self.settlements.clone(),
        })
    }
}

/// Bind every finalized asynchronous settlement, in native order, to a bounded
/// stopped-writer canonical L2 snapshot. Only full real-cryptography replay can
/// construct `verified`; caller-supplied RPC heights are never authority.
/// Existing 0x0E/WS stores retain their strict immediate-parent admission rule.
pub fn audit_finalized_async_settlements(
    verified: &VerifiedNativeFinalityV1,
    source: &bloch_reth_execution::BlochProviderFactory,
    policy: SettlementPolicyV1,
    floor: bloch_reth_execution::ReplayFloor,
    limits: bloch_reth_execution::ReplayLimits,
) -> Result<
    bloch_reth_execution::settlement_binding::CanonicalSettlementAuditReportV1,
    bloch_reth_execution::settlement_binding::CanonicalSettlementAuditErrorV1<NativeFinalityErrorV1>,
> {
    use bloch_l2_evm::{native_settlement::SettlementTransactionV1, proof_statement::SettlementStatementV2};
    use bloch_reth_execution::settlement_binding::{with_canonical_settlement_audit, CanonicalSettlementAuditErrorV1};
    if policy.commitment().ok() != Some(verified.report.settlement_policy) {
        return Err(CanonicalSettlementAuditErrorV1::Consumer(NativeFinalityErrorV1::Trust));
    }
    let (_, report) = with_canonical_settlement_audit(source, policy, floor, limits, |audit| {
        for (_, _, bytes) in verified.finalized_settlements() {
            let tx = bloch_pos_committee::l2_settlement::Transaction::decode_async(bytes)
                .ok_or(NativeFinalityErrorV1::Encoding)?;
            let statement =
                SettlementStatementV2::decode(&tx.statement).map_err(|_| NativeFinalityErrorV1::Encoding)?;
            let tx = SettlementTransactionV1::new(tx.proof_policy.into(), statement, tx.proof)
                .map_err(|_| NativeFinalityErrorV1::Encoding)?;
            audit
                .audit_transaction(&tx)
                .map_err(|_| NativeFinalityErrorV1::Settlement)?;
        }
        Ok(())
    })?;
    Ok(report)
}

#[cfg(test)]
#[path = "async_cursor_tests.rs"]
mod async_cursor_tests;

#[cfg(test)]
mod deposit_conformance {
    use bloch_l2_evm::{node_primitives::NodeBodyV2, DepositMint, DepositProvenance};
    use bloch_pos_committee::l2_settlement::{expected_body_commitment, InboxRecord};

    /// The native consensus recomputes the L2 body commitment from inbox
    /// records with its own minimal RLP; it must equal the L2 codec exactly.
    #[test]
    fn native_inbox_body_commitment_matches_the_l2_body_codec() {
        let records: Vec<InboxRecord> = (0..70u32)
            .map(|i| InboxRecord {
                height: [1, 127, 128, 255, 256, 65_535, u64::MAX][i as usize % 7].wrapping_add(u64::from(i / 7)),
                tx_index: i,
                txid: [i as u8; 32],
                vout: [0, 1, 127, 128, u32::MAX][i as usize % 5],
                sats: [1, 0x7f, 0x80, 1_000_000, u64::MAX / 3][i as usize % 5],
                recipient: [(i as u8).wrapping_mul(3); 20],
            })
            .collect();
        for n in [0usize, 1, 2, 3, 64, 70] {
            let body = NodeBodyV2 {
                deposits: records[..n]
                    .iter()
                    .map(|r| DepositMint {
                        recipient: r.recipient.into(),
                        provenance: DepositProvenance::BridgedBlch {
                            l1_height: r.height,
                            l1_tx_index: r.tx_index,
                            l1_txid: r.txid,
                            l1_vout: r.vout,
                            l1_sats: r.sats,
                        },
                    })
                    .collect(),
                transactions: vec![],
            };
            let l2 = alloy_primitives::keccak256(alloy_rlp::encode(&body));
            assert_eq!(expected_body_commitment(&records[..n]), l2.0, "{n} deposits");
        }
    }
}
