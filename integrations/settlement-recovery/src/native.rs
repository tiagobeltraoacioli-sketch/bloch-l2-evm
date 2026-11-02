// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded full native replay from independently pinned genesis state.
//! This does not activate a network or publish an Ethereum finality tag.
use alloy_primitives::B256;
use bloch_l2_evm::{
    l1::FinalizedCheckpoint,
    native_settlement::SettlementPolicyV1,
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
    /// L1 hard fork SIG_CANONICAL (audit e9b52781): the transition wraps this
    /// verifier in its epoch's `PolicyVerifier`, which calls this method. The
    /// trait default ignores the policy, which after the fork would refuse
    /// every v2 proposer/vote signature and halt the replay. Same mapping as
    /// the node's `HybridVerifier`. Compiled when the native checkout has the
    /// method (see build.rs).
    #[cfg(bloch_native_sig_policy)]
    fn verify_with_key_under(
        &self,
        policy: bloch_pos_committee::attestation::SignaturePolicy,
        key: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        use bloch_crypto::crypto::SignaturePolicy as C;
        use bloch_pos_committee::attestation::SignaturePolicy as P;
        let policy = match policy {
            P::Compatible => C::Compatible,
            // L1 MLDSA_PIN_ACTIVATION_EPOCH: historical byte forms, ML-DSA half
            // judged by the pinned FIPS 204 verifier (`SignaturePolicy::consensus`
            // and `::transaction` select it). Same as the node's `crypto_policy`.
            #[cfg(bloch_native_mldsa_pin)]
            P::CompatiblePinned => C::CompatiblePinned,
            P::CanonicalUnbound => C::CanonicalUnbound,
            P::Bound => C::Bound,
        };
        bloch_crypto::crypto::verify_with_policy(policy, key, root, signature)
    }
    /// L1 hard fork HF3_SLH_SUITE_EPOCH: eUTXO spend witnesses may use suite
    /// 0x0003 from the fork. The trait default answers the pre-fork verdict
    /// and would halt the replay at the first such spend. Same mapping as the
    /// node's `HybridVerifier` (bloch-pos-node `keys.rs`): `verify_spend` with
    /// the gate decided by the ONE HF3 constant in bloch-pos-committee
    /// (`params::hf3_slh_suite_active`); bloch-crypto holds no activation
    /// epoch of its own. Composition with the transaction policy is the
    /// native `PolicyVerifier`'s job (it routes only suite-0x0003 keys here).
    /// Compiled when the native checkout has the method (see build.rs).
    #[cfg(bloch_native_spend_at_epoch)]
    fn verify_spend_at_epoch(&self, key: &[u8], root: &[u8; 32], signature: &[u8], epoch: u64) -> bool {
        bloch_crypto::crypto::verify_spend(
            key,
            root,
            signature,
            bloch_pos_committee::params::hf3_slh_suite_active(epoch),
        )
    }
    /// KES leaves are signed in the canonical, suite-bound v2 form from the
    /// first KES signature, independent of any signature-policy flag day
    /// (native review F-1). `kes::verify` calls this after the Merkle path
    /// checks out. The trait default is the v1 `verify_with_key`, which
    /// refuses every v2 leaf: the follower would halt at the first
    /// KES-signed proposal or vote. Same mapping as the node's
    /// `HybridVerifier`. Compiled when the native trait has it (build.rs).
    #[cfg(bloch_native_kes_leaf)]
    fn verify_kes_leaf(&self, leaf_pk: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify_bound(leaf_pk, message, signature)
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
    /// Chain index of the block whose post-state first holds the L2
    /// settlement registry (0 = configured at genesis); `None` before a
    /// flag-day activation.
    l2_activation_index: Option<usize>,
}
impl VerifiedNativeFinalityV1 {
    pub const fn report(&self) -> &NativeFinalityReportV1 {
        &self.report
    }

    /// The native block that installed the L2 settlement registry with the
    /// pinned policy (the genesis block when the manifest configured it) and
    /// whether it lies inside the verified FFG-finalized prefix. Once it does,
    /// the L2 genesis (`initial_l2_parent`) is final.
    pub fn l2_activation(&self) -> Option<(FinalizedCheckpoint, bool)> {
        let index = self.l2_activation_index?;
        let (slot, block) = *self.chain.get(index)?;
        Some((FinalizedCheckpoint { block, slot }, index <= self.finalized_index))
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
        // The V1 trust carries no M6 withdrawal attestor set; check_trust
        // takes it from the pinned genesis.
        attestor_set: [0; 32],
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
        if block.envelope.proposer_sig.len() > MAX_CONSENSUS_SIGNATURE_BYTES {
            return Err(E::Limit);
        }
        atts = atts.checked_add(block.attestations.len()).ok_or(E::Limit)?;
        txs = txs.checked_add(block.transactions.len()).ok_or(E::Limit)?;
        if byte_count > limits.bytes || atts > limits.attestations || txs > limits.transactions {
            return Err(E::Limit);
        }
        for att in &block.attestations {
            if att.signature.len() > MAX_CONSENSUS_SIGNATURE_BYTES {
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
        // The M6 attestor set is not part of the V1 policy: it is taken from
        // the pinned genesis itself (whose state root is checked above).
        || state.policy() != &(Policy { attestor_set: state.policy().attestor_set, ..native_policy(p) })
        || p.first_l2_number != 1
        || (p.proof_policy.0 != bloch_l2_proof::policy_commitment()
            && p.proof_policy.0 != bloch_l2_proof::policy_commitment_v3())
    {
        return Err(E::Trust);
    }
    Ok(policy_commitment)
}

/// Trust for a genesis without an L2 registry (flag-day activation): the same
/// anchors as [`check_trust`] except the registry, which must be absent here.
/// The policy's genesis identity must be this genesis block, unless the policy
/// is exactly the one the linked native consensus installs for this network
/// (`l2_settlement::activation_for`): a qualification build
/// (`l2-activation-rehearsal-mainnet-policy`) binds identities 0..1 to the
/// private network with derived labels, so its genesis identity is not a block id.
fn check_flag_day_trust(genesis: &CommittedState, trust: NativeGenesisTrustV1) -> Result<B256, NativeFinalityErrorV1> {
    use NativeFinalityErrorV1 as E;
    let p = trust.settlement_policy;
    let policy_commitment = p.commitment().map_err(|_| E::Trust)?;
    let installed_natively = bloch_pos_committee::l2_settlement::activation_for(Some(p.network.0))
        .is_some_and(|a| a.policy == Policy { attestor_set: a.policy.attestor_set, ..native_policy(p) });
    if trust.state_root == B256::ZERO
        || genesis.l2_settlement().is_some()
        || genesis.slot() != 0
        || (genesis.head().as_bytes() != &p.genesis.0 && !installed_natively)
        || genesis.state_root() != trust.state_root.0
        || p.first_l2_number != 1
        || p.proof_policy.0 != bloch_l2_proof::policy_commitment_v3()
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
            signature_bytes: MAX_CONSENSUS_SIGNATURE_BYTES,
            attestations: 4_096,
            transactions: 4_096,
            proofs: 64,
            bytes: 4 * 1_048_576,
        }
    }
}

/// Largest proposer or vote signature replayed: a hybrid signature (at most
/// 4,593 bytes) or, from native KES activation on, a forward-secure KES
/// signature (`bloch_pos_committee::kes::MAX_SIGNATURE_LEN` = 9,053 bytes in
/// native 78d4921c: leaf key, leaf signature and up to a 16-level path;
/// pinned by the test `kes_signature_fits_the_replay_bound`).
pub const MAX_CONSENSUS_SIGNATURE_BYTES: usize = 9_216;

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
    /// Chain index of the block that installed the L2 registry; `None` while a
    /// flag-day network has not activated it yet.
    l2_activation: Option<usize>,
    /// The withdrawal attestor-set hash a flag-day activation must install
    /// (not part of the V1 policy). Unused when genesis configures the L2.
    expected_attestor_set: [u8; 32],
}

impl IncrementalNativeVerifierV1 {
    pub fn new(genesis: &CommittedState, trust: NativeGenesisTrustV1, max_blocks: usize) -> Result<Self, NativeFinalityErrorV1> {
        if genesis.validator_count() > 4_096 || max_blocks == 0 {
            return Err(NativeFinalityErrorV1::Limit);
        }
        let policy_commitment = check_trust(genesis, trust)?;
        Self::start(genesis, trust, policy_commitment, max_blocks, Some(0), [0; 32])
    }

    /// A network whose genesis carries no L2 registry and whose native
    /// transition installs it at a flag day (Bloch mainnet: Genesis-4, epoch
    /// 5850). The pinned policy and attestor-set hash must be exactly what the
    /// replayed transition installs; any other installation halts the replay.
    /// Before activation no settlement can be accepted natively, so the
    /// verified finality simply carries no settlements.
    pub fn new_flag_day(
        genesis: &CommittedState,
        trust: NativeGenesisTrustV1,
        attestor_set: B256,
        max_blocks: usize,
    ) -> Result<Self, NativeFinalityErrorV1> {
        if genesis.validator_count() > 4_096 || max_blocks == 0 || attestor_set.is_zero() {
            return Err(NativeFinalityErrorV1::Limit);
        }
        let policy_commitment = check_flag_day_trust(genesis, trust)?;
        Self::start(genesis, trust, policy_commitment, max_blocks, None, attestor_set.0)
    }

    fn start(
        genesis: &CommittedState,
        trust: NativeGenesisTrustV1,
        policy_commitment: B256,
        max_blocks: usize,
        l2_activation: Option<usize>,
        expected_attestor_set: [u8; 32],
    ) -> Result<Self, NativeFinalityErrorV1> {
        // The native genesis block id: equal to the policy's genesis identity
        // (checked by check_trust / check_flag_day_trust) except on a
        // qualification flag-day network, whose identity 1 is a derived label.
        let id = B256::from(*genesis.head().as_bytes());
        Ok(Self {
            transition: Transition::new(NativeConsensusVerifierV1),
            trust,
            policy_commitment,
            state: genesis.clone(),
            chain: vec![(0, id)],
            positions: BTreeMap::from([(id, (0, 0))]),
            settlements: BTreeMap::new(),
            final_epoch: 0,
            final_index: 0,
            applied: 0,
            max_blocks,
            poisoned: false,
            l2_activation,
            expected_attestor_set,
        })
    }

    /// Chain index of the block that installed the L2 registry, if any yet.
    pub const fn l2_activation_index(&self) -> Option<usize> {
        self.l2_activation
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
        // Votes for another branch are valid native blocks: the transition keeps
        // only votes linking from its justified checkpoint and tallies by target,
        // so a foreign vote cannot move finality. Refusing the block here halted
        // on a chain every node accepts (devnet4 slot 186817, after a fork). The
        // finalized-on-this-branch check below is what binds finality.
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
        if self.l2_activation.is_none() {
            if let Some(registry) = self.state.l2_settlement() {
                let pinned = Policy {
                    attestor_set: self.expected_attestor_set,
                    ..native_policy(self.trust.settlement_policy)
                };
                if registry.policy() != &pinned {
                    return Err(E::Trust);
                }
                self.l2_activation = Some(self.chain.len() - 1);
            }
        }
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

    /// The L2 policy in the replayed state: the program the next settlement must
    /// prove, which moves at the native gate. `None` before the L2 is installed.
    pub fn l2_policy(&self) -> Option<&Policy> {
        self.state.l2_settlement().map(|registry| registry.policy())
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
            l2_activation_index: self.l2_activation,
        })
    }
}

/// Bind every finalized asynchronous settlement, in native order, to a bounded
/// stopped-writer canonical L2 snapshot. Only full real-cryptography replay can
/// construct `verified`; caller-supplied RPC heights are never authority.
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

#[cfg(all(test, bloch_native_sig_policy))]
mod sig_policy {
    use super::NativeConsensusVerifierV1;
    use bloch_pos_committee::attestation::SignatureVerifier;

    /// The replay verifier applies each L1 signature policy exactly as the
    /// node does, so a follower built against a SIG_CANONICAL release keeps
    /// following across the activation epoch.
    #[test]
    fn replay_verifier_honours_the_native_signature_policy() {
        use bloch_pos_committee::attestation::{PolicyVerifier, SignaturePolicy::*};
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let root = [0x5B; 32];
        let v1 = bloch_crypto::crypto::sign(&sk, &root).unwrap();
        let v2 = bloch_crypto::crypto::sign_bound(&sk, &root).unwrap();
        let under = |p| PolicyVerifier::new(&NativeConsensusVerifierV1, p);
        assert!(under(Compatible).verify_with_key(&pk, &root, &v1));
        assert!(!under(Compatible).verify_with_key(&pk, &root, &v2));
        assert!(under(CanonicalUnbound).verify_with_key(&pk, &root, &v1));
        assert!(under(Bound).verify_with_key(&pk, &root, &v2));
        assert!(!under(Bound).verify_with_key(&pk, &root, &v1));
    }
}

/// Parity of [`NativeConsensusVerifierV1`] with the native node's
/// `HybridVerifier` (bloch-pos-node `src/keys.rs`, not exported by that crate,
/// so each test states the node's mapping as the `bloch_crypto` call it makes
/// and checks the replay verifier against it). Every test goes through the
/// same wrapper the native transition uses (`PolicyVerifier`) where the
/// transition does.
#[cfg(test)]
mod node_parity {
    use super::NativeConsensusVerifierV1;
    use bloch_pos_committee::attestation::SignatureVerifier;

    /// The replay verifier as it was before the trait grew a method: only the
    /// required `verify_with_key`, every other method on the trait default.
    /// A test double for "the default would have answered".
    struct TraitDefaults;
    impl SignatureVerifier for TraitDefaults {
        fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
            bloch_crypto::crypto::verify(key, root, signature)
        }
    }

    /// KES signatures can be as large as the native decoder admits; the replay
    /// size bound must not refuse a valid one before the transition sees it.
    #[cfg(bloch_native_kes_leaf)]
    #[test]
    fn kes_signature_fits_the_replay_bound() {
        assert!(bloch_pos_committee::kes::MAX_SIGNATURE_LEN <= super::MAX_CONSENSUS_SIGNATURE_BYTES);
    }

    /// (a) KES leaves: node `verify_kes_leaf` = `bloch_crypto::crypto::verify_bound`.
    #[cfg(bloch_native_kes_leaf)]
    #[test]
    fn kes_leaf_is_judged_in_the_bound_form_like_the_node() {
        use bloch_pos_committee::attestation::{PolicyVerifier, SignaturePolicy::*};
        use bloch_pos_committee::kes::{self, KesPublic, KesSignature};
        let leaves_kp: Vec<_> = (0..2).map(|_| bloch_crypto::crypto::generate_keypair()).collect();
        let leaves: Vec<[u8; 32]> = leaves_kp.iter().map(|(pk, _)| kes::leaf_hash(pk)).collect();
        let start = 40;
        let public = KesPublic::new(1, kes::merkle_root(&leaves), start);
        let (pk, sk) = &leaves_kp[1];
        let message = [0xC3; 32];
        let bound = bloch_crypto::crypto::sign_bound(sk, &message).unwrap();
        let v1 = bloch_crypto::crypto::sign(sk, &message).unwrap();
        let encode = |sig: &[u8]| {
            KesSignature { index: 1, leaf_pk: pk.clone(), sig: sig.to_vec(), path: kes::auth_path(&leaves, 1) }.encode()
        };
        let (kes_bound, kes_v1) = (encode(&bound), encode(&v1));

        // The leaf check itself: exactly the node's verdicts.
        let v = NativeConsensusVerifierV1;
        assert_eq!(v.verify_kes_leaf(pk, &message, &bound), bloch_crypto::crypto::verify_bound(pk, &message, &bound));
        assert_eq!(v.verify_kes_leaf(pk, &message, &v1), bloch_crypto::crypto::verify_bound(pk, &message, &v1));
        assert!(v.verify_kes_leaf(pk, &message, &bound));
        assert!(!v.verify_kes_leaf(pk, &message, &v1), "a v1 leaf is not a KES leaf");
        // The trait default (what the follower at 0044697 ran) refuses the
        // honest bound leaf: the follower would halt at the first KES block.
        assert!(!TraitDefaults.verify_kes_leaf(pk, &message, &bound));
        assert!(!TraitDefaults.verify_kes(&public, start + 1, &message, &kes_bound));

        // The whole KES check (path + leaf), bare and through every policy
        // wrapper the transition can put around it: forwarded unchanged.
        let period = start + 1;
        assert!(v.verify_kes(&public, period, &message, &kes_bound));
        assert!(!v.verify_kes(&public, period, &message, &kes_v1));
        assert!(!v.verify_kes(&public, start, &message, &kes_bound), "wrong period / leaf index");
        assert!(!v.verify_kes(&public, period, &[0xC4; 32], &kes_bound), "other message");
        let mut policies = vec![Compatible, CanonicalUnbound, Bound];
        #[cfg(bloch_native_mldsa_pin)]
        policies.push(CompatiblePinned);
        for p in policies {
            let w = PolicyVerifier::new(&v, p);
            assert!(w.verify_kes(&public, period, &message, &kes_bound), "{p:?}");
            assert!(!w.verify_kes(&public, period, &message, &kes_v1), "{p:?}");
            assert!(!PolicyVerifier::new(&TraitDefaults, p).verify_kes(&public, period, &message, &kes_bound), "{p:?}");
        }
    }

    /// (b) The node's `crypto_policy`: every committee policy maps to the
    /// bloch-crypto policy of the same name, including `CompatiblePinned`.
    /// An honest signature cannot tell the pinned ML-DSA backend from the
    /// CPU-dispatching one (they disagree only on crafted edge cases, for which
    /// no fixture exists in the native crates), so the mapping is pinned by
    /// equality with the exact bloch-crypto entry point the node calls, on
    /// both signature forms, and by the epochs that select the policy.
    #[cfg(bloch_native_sig_policy)]
    #[test]
    fn every_signature_policy_maps_like_the_node() {
        use bloch_crypto::crypto::SignaturePolicy as C;
        use bloch_pos_committee::attestation::{PolicyVerifier, SignaturePolicy as P};
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let root = [0x6D; 32];
        let v1 = bloch_crypto::crypto::sign(&sk, &root).unwrap();
        let v2 = bloch_crypto::crypto::sign_bound(&sk, &root).unwrap();
        let mut table = vec![(P::Compatible, C::Compatible), (P::CanonicalUnbound, C::CanonicalUnbound), (P::Bound, C::Bound)];
        #[cfg(bloch_native_mldsa_pin)]
        table.push((P::CompatiblePinned, C::CompatiblePinned));
        for (p, c) in table {
            for sig in [&v1, &v2] {
                let node = bloch_crypto::crypto::verify_with_policy(c, &pk, &root, sig);
                assert_eq!(NativeConsensusVerifierV1.verify_with_key_under(p, &pk, &root, sig), node, "{p:?}");
                assert_eq!(PolicyVerifier::new(&NativeConsensusVerifierV1, p).verify_with_key(&pk, &root, sig), node, "{p:?}");
            }
        }
        #[cfg(bloch_native_mldsa_pin)]
        {
            use bloch_pos_committee::params::{MLDSA_PIN_ACTIVATION_EPOCH as PIN, SIG_CANONICAL_ACTIVATION_EPOCH as CANON};
            let pinned = |sig: &[u8]| bloch_crypto::crypto::verify_pinned(&pk, &root, sig);
            assert!(NativeConsensusVerifierV1.verify_with_key_under(P::CompatiblePinned, &pk, &root, &v1));
            assert!(!NativeConsensusVerifierV1.verify_with_key_under(P::CompatiblePinned, &pk, &root, &v2));
            assert_eq!(NativeConsensusVerifierV1.verify_with_key_under(P::CompatiblePinned, &pk, &root, &v1), pinned(&v1));
            if PIN != u64::MAX {
                // Transactions are judged under CompatiblePinned from the pin
                // epoch on (and never under a canonical policy).
                assert_eq!(P::transaction(PIN), P::CompatiblePinned);
                for e in [PIN, PIN + 1, CANON.max(PIN).saturating_add(1_000)] {
                    assert_eq!(P::transaction(e), P::CompatiblePinned, "epoch {e}");
                    let w = PolicyVerifier::new(&NativeConsensusVerifierV1, P::transaction(e));
                    assert!(w.verify_with_key(&pk, &root, &v1), "epoch {e}: v1 transaction witness");
                    assert_eq!(w.verify_with_key(&pk, &root, &v1), pinned(&v1));
                }
                if PIN < CANON {
                    assert_eq!(P::consensus(PIN), P::CompatiblePinned);
                }
            }
        }
    }

    /// (c) HF3 spends: node `verify_spend_at_epoch` =
    /// `bloch_crypto::crypto::verify_spend(.., params::hf3_slh_suite_active(epoch))`.
    #[cfg(bloch_native_spend_at_epoch)]
    #[test]
    fn spend_at_epoch_uses_the_hf3_gate_like_the_node() {
        use bloch_pos_committee::attestation::{PolicyVerifier, SignaturePolicy};
        use bloch_pos_committee::params::{hf3_slh_suite_active, HF3_SLH_SUITE_EPOCH as GATE};
        let (slh_pk, slh_sk) = bloch_crypto::crypto::slhdsa_suite::generate_keypair();
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let root = [0x3A; 32];
        let slh_sig = bloch_crypto::crypto::sign(&slh_sk, &root).unwrap();
        let mut forged = slh_sig.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let sig = bloch_crypto::crypto::sign(&sk, &root).unwrap();
        let v = NativeConsensusVerifierV1;
        let mut epochs = vec![0, 5_850, 7_359, 7_360, 8_620, u64::MAX - 1];
        if GATE != u64::MAX {
            epochs.extend([GATE.saturating_sub(1), GATE, GATE + 1]);
        }
        for e in epochs {
            let gate = hf3_slh_suite_active(e);
            let node = |k: &[u8], s: &[u8]| bloch_crypto::crypto::verify_spend(k, &root, s, gate);
            assert_eq!(v.verify_spend_at_epoch(&slh_pk, &root, &slh_sig, e), node(&slh_pk, &slh_sig), "epoch {e}");
            assert_eq!(v.verify_spend_at_epoch(&slh_pk, &root, &slh_sig, e), gate, "epoch {e}");
            assert!(!v.verify_spend_at_epoch(&slh_pk, &root, &forged, e), "epoch {e}");
            assert!(v.verify_spend_at_epoch(&pk, &root, &sig, e), "epoch {e}: 0x0001 spends unchanged");
            assert_eq!(v.verify_spend_at_epoch(&pk, &root, &sig, e), node(&pk, &sig), "epoch {e}");
            // Through the transaction-policy wrapper, as the transition calls it.
            #[cfg(bloch_native_sig_policy)]
            {
                let w = PolicyVerifier::new(&v, SignaturePolicy::transaction(e));
                assert_eq!(w.verify_spend_at_epoch(&slh_pk, &root, &slh_sig, e), gate, "epoch {e}");
                assert!(w.verify_spend_at_epoch(&pk, &root, &sig, e), "epoch {e}");
            }
            // The trait default never accepts the new suite.
            assert!(!TraitDefaults.verify_spend_at_epoch(&slh_pk, &root, &slh_sig, e), "epoch {e}");
        }
        if GATE != u64::MAX {
            assert!(!v.verify_spend_at_epoch(&slh_pk, &root, &slh_sig, GATE - 1));
            assert!(v.verify_spend_at_epoch(&slh_pk, &root, &slh_sig, GATE));
        }
    }
}
