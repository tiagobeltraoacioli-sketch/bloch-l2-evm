// SPDX-License-Identifier: AGPL-3.0-or-later
//! Foreign-branch votes after the VoteBranch removal (b4470a8).
//!
//! The follower no longer refuses a block that carries a vote whose source,
//! target or head is off its branch, because native consensus accepts such
//! blocks. These tests generate a fresh chain with genuine hybrid signatures
//! (disposable keys, no settlement proof needed) and check that:
//! - validly signed foreign votes are accepted and do not move finality;
//! - a supermajority for a foreign target, which the native transition does
//!   justify and finalize, makes the follower fail closed instead of reporting
//!   a finalized checkpoint that is not on its branch.
#![cfg(unix)]
#[path = "support/native_ffg.rs"]
mod fixture;
use alloy_primitives::B256;
use bloch_pos_committee::{
    attestation::{Attestation, AttestationData},
    beacon::{self, RandaoChain},
    committees, epoch_of,
    header::BlockHeaderV4,
    interfaces::{ProposalEnvelope, StateReader, StateTransition},
    transition::{CommittedState, PosTransaction, Transition},
};
use bloch_settlement_recovery::native::{
    verify_native_finality, NativeBlockLimitsV1, NativeConsensusVerifierV1, NativeFinalityErrorV1,
    NativeGenesisTrustV1, NativeReplayBlockV1, NativeReplayLimitsV1, IncrementalNativeVerifierV1,
};
use std::sync::OnceLock;

type Keys = Vec<(Vec<u8>, Vec<u8>)>;

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}
fn genesis() -> CommittedState {
    fixture::genesis(&keys().iter().map(|k| k.0.clone()).collect::<Vec<_>>())
}
fn trust(g: &CommittedState) -> NativeGenesisTrustV1 {
    NativeGenesisTrustV1 {
        settlement_policy: fixture::policy(),
        state_root: B256::from(g.state_root()),
    }
}

/// Same block builder as `examples/qualify_native_ffg.rs`.
fn build(
    pre: &CommittedState,
    slot: u64,
    atts: Vec<Attestation>,
    chains: &mut [RandaoChain],
) -> (NativeReplayBlockV1, CommittedState) {
    let keys = keys();
    let tr = Transition::new(NativeConsensusVerifierV1);
    let mut ctx = pre.clone();
    for _ in epoch_of(pre.slot())..epoch_of(slot) {
        ctx = tr.process_epoch(&ctx).unwrap();
    }
    let proposer =
        bloch_pos_committee::proposer(&ctx.seed_for_epoch(epoch_of(slot)), slot, &ctx.active_validators()).unwrap();
    let reveal = chains[proposer as usize].next_reveal().unwrap();
    let txs: Vec<PosTransaction> = vec![];
    let fin = ctx.finality();
    let mut header = BlockHeaderV4 {
        version: 0xb10c_0005,
        parent: *pre.head().as_bytes(),
        state_root: [0; 32],
        body_root: bloch_pos_committee::derive::body_root(&[]),
        slot,
        proposer_index: proposer,
        randao_reveal: reveal,
        randao_mix: beacon::mix_in(&ctx.randao_mix(), &reveal),
        justified_root: fin.justified.root,
        finalized_root: fin.finalized.root,
        attestation_root: bloch_pos_committee::derive::attestation_root(&atts),
        coherence_root: pre.coherence_root(),
    };
    let sign =
        |h: &BlockHeaderV4| bloch_crypto::crypto::sign(&keys[proposer as usize].1, &h.proposal_signing_root()).unwrap();
    let probe = ProposalEnvelope { header, proposer_sig: sign(&header) };
    header.state_root = tr.compute_post_state(pre, &probe, &atts, &txs).unwrap().state_root();
    let envelope = ProposalEnvelope { header, proposer_sig: sign(&header) };
    // The native transition itself must accept every block built here.
    let post = tr.apply_block(pre, &envelope, &atts, &txs).unwrap();
    (NativeReplayBlockV1 { envelope, attestations: atts, transactions: vec![] }, post)
}

fn sign(v: u32, data: AttestationData) -> Attestation {
    Attestation {
        validator: v,
        signature: bloch_crypto::crypto::sign(&keys()[v as usize].1, &data.signing_root()).unwrap(),
        data,
    }
}

const FOREIGN: [u8; 32] = [0xf0; 32];

/// Vote shapes cast by each committee member in an epoch.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Every validator votes for this branch.
    Honest,
    /// Validators 0,1 vote for this branch; validator 2 casts only validly
    /// signed votes for another branch (foreign target, head and source).
    MinorityForeign,
    /// Every validator votes for a foreign target (another branch has the
    /// supermajority; this branch only carries its votes).
    SupermajorityForeign,
}

/// Blocks at slots 1, 32, 63, 64, 95, 96: epoch 1 is finalized by the honest
/// links 0→1 and 1→2.
fn chain(mode: Mode) -> (Vec<NativeReplayBlockV1>, Vec<CommittedState>) {
    let mut chains = fixture::chains();
    let (first, mut state) = build(&genesis(), 1, vec![], &mut chains);
    let mut blocks = vec![first];
    let mut states = vec![state.clone()];
    for epoch in 1..=2u64 {
        let target = *state.head().as_bytes();
        let (block, post) = build(&state, epoch * 32, vec![], &mut chains);
        blocks.push(block);
        states.push(post.clone());
        state = post;
        let partition = committees::epoch_committees(&state.seed_for_epoch(epoch), epoch, &state.active_validators());
        let mut atts = Vec::new();
        for (offset, members) in partition.iter().enumerate() {
            for &v in members {
                let honest = AttestationData {
                    slot: epoch * 32 + offset as u64,
                    head: *state.head().as_bytes(),
                    source_epoch: state.finality().justified.epoch,
                    source_root: state.finality().justified.root,
                    target_epoch: epoch,
                    target_root: target,
                };
                let mut foreign = honest;
                foreign.head = FOREIGN;
                foreign.target_root = [0xf0 ^ epoch as u8; 32];
                match (mode, v) {
                    (Mode::Honest, _) | (Mode::MinorityForeign, 0 | 1) => atts.push(sign(v, honest)),
                    (Mode::MinorityForeign, _) => {
                        // Foreign head and target from this branch's justified
                        // source, validly signed. Validator 2 casts no honest
                        // vote, so it is not an equivocator.
                        atts.push(sign(v, foreign));
                    }
                    (Mode::SupermajorityForeign, _) => {
                        // Foreign link: source is the foreign justified root.
                        atts.push(sign(v, foreign));
                    }
                }
            }
        }
        let (block, post) = build(&state, epoch * 32 + 31, atts, &mut chains);
        blocks.push(block);
        states.push(post.clone());
        state = post;
    }
    let (block, post) = build(&state, 96, vec![], &mut chains);
    blocks.push(block);
    states.push(post);
    (blocks, states)
}

fn checkpoint_root(blocks: &[NativeReplayBlockV1], epoch: u64) -> [u8; 32] {
    *blocks
        .iter()
        .filter(|b| b.envelope.header.slot < epoch * 32)
        .next_back()
        .unwrap()
        .envelope
        .header
        .id()
        .as_bytes()
}

#[test]
fn honest_chain_finalizes_epoch_one() {
    let g = genesis();
    let (blocks, _) = chain(Mode::Honest);
    let native = verify_native_finality(&g, trust(&g), &blocks, NativeReplayLimitsV1::default()).unwrap();
    assert_eq!(native.report().finalized_epoch, 1);
    assert_eq!(native.report().finalized.block.0, checkpoint_root(&blocks, 1));
}

#[test]
fn validly_signed_foreign_branch_votes_are_accepted_and_do_not_move_finality() {
    let g = genesis();
    let (honest, _) = chain(Mode::Honest);
    let (blocks, states) = chain(Mode::MinorityForeign);
    // The foreign votes really are in the blocks and validly signed (the
    // native transition accepted them in `build`).
    assert!(blocks
        .iter()
        .flat_map(|b| &b.attestations)
        .any(|a| a.data.head == FOREIGN && a.data.target_root != checkpoint_root(&blocks, a.data.target_epoch)));
    // The native state never justified a foreign root.
    for s in &states {
        for cp in [s.finality().justified, s.finality().finalized] {
            assert!(cp.epoch == 0 || cp.root == checkpoint_root(&blocks, cp.epoch));
        }
    }
    // Incremental follower: accepts every block, finality identical in shape
    // to the honest chain (epoch 1 at this branch's checkpoint).
    let mut f = IncrementalNativeVerifierV1::new(&g, trust(&g), 64).unwrap();
    for b in &blocks {
        f.apply(b, NativeBlockLimitsV1::default()).unwrap();
    }
    let snap = f.snapshot().unwrap();
    assert_eq!(snap.report().finalized_epoch, 1);
    assert_eq!(snap.report().finalized.block.0, checkpoint_root(&blocks, 1));
    let native = verify_native_finality(&g, trust(&g), &blocks, NativeReplayLimitsV1::default()).unwrap();
    assert_eq!(native.report().finalized_epoch, 1);
    // A single foreign vote cannot make 2-of-3 honest weight insufficient, and
    // the honest chain reaches the same finalized epoch.
    let h = verify_native_finality(&g, trust(&g), &honest, NativeReplayLimitsV1::default()).unwrap();
    assert_eq!(h.report().finalized_epoch, native.report().finalized_epoch);
}

#[test]
fn a_foreign_supermajority_is_finalized_natively_but_the_follower_fails_closed() {
    let g = genesis();
    let (blocks, states) = chain(Mode::SupermajorityForeign);
    // The native transition accepts the blocks AND justifies/finalizes a root
    // that is not on the branch it is applied to: it does not bind FFG
    // checkpoints to the block's own ancestry.
    let last = states.last().unwrap().finality();
    assert_eq!(last.finalized.epoch, 1);
    assert_eq!(last.finalized.root, [0xf0 ^ 1; 32]);
    assert_ne!(last.finalized.root, checkpoint_root(&blocks, 1));
    // The follower must not report it: it fails closed with Ancestry at the
    // first block whose post-state names a foreign finalized checkpoint.
    let mut f = IncrementalNativeVerifierV1::new(&g, trust(&g), 64).unwrap();
    let mut refused = None;
    for (i, b) in blocks.iter().enumerate() {
        if let Err(e) = f.apply(b, NativeBlockLimitsV1::default()) {
            refused = Some((i, e));
            break;
        }
    }
    let (i, e) = refused.expect("follower accepted a foreign finalized checkpoint");
    assert!(matches!(e, NativeFinalityErrorV1::Ancestry), "{e:?}");
    assert_eq!(states[i].finality().finalized.root, [0xf0 ^ 1; 32]);
    assert!(f.snapshot().is_err());
    assert!(verify_native_finality(&g, trust(&g), &blocks, NativeReplayLimitsV1::default()).is_err());
}
