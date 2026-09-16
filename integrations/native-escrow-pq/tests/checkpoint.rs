// SPDX-License-Identifier: AGPL-3.0-or-later
use bloch_native_escrow_pq::checkpoint::{CheckpointError as Error, CheckpointPolicy, Phase};
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
    ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint},
};
use std::sync::OnceLock;

fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| (0..5).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}
fn set(phase_b: bool) -> SignerSet {
    let n = if phase_b { 5 } else { 3 };
    SignerSet {
        id: 1,
        signers: keys()[..n]
            .iter()
            .enumerate()
            .map(|(i, k)| Signer {
                pubkey: k.0[4..].try_into().unwrap(),
                external: i >= if phase_b { 3 } else { 2 },
            })
            .collect(),
        threshold: if phase_b { 3 } else { 2 },
        min_external: if phase_b { 2 } else { 1 },
        adopted_epoch: 50,
    }
}
fn signed(cp: WeakSubjectivityCheckpoint, indices: &[u8]) -> CheckpointEnvelope {
    let digest = cp.ws_digest();
    CheckpointEnvelope {
        checkpoint: cp,
        signatures: indices
            .iter()
            .map(|i| {
                let signature = bloch_crypto::crypto::sign(&keys()[*i as usize].1, &digest).unwrap();
                (*i, signature[4..].to_vec())
            })
            .collect(),
    }
}
fn fixture(epoch: u64) -> (CheckpointEnvelope, Vec<u8>) {
    let mut header = vec![0; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].fill(11);
    header[68..100].copy_from_slice(&body_root(&[]));
    header[100..108].copy_from_slice(&(epoch * 120).to_le_bytes());
    let native = BlockHeaderV4::canonical_deserialize(&header).unwrap();
    let cp = WeakSubjectivityCheckpoint {
        version: ws::WS_FORMAT_VERSION,
        network_id: 7,
        genesis_root: [9; 32],
        epoch,
        block_root: *BlockId::of(&native).as_bytes(),
        state_root: native.state_root,
        validator_set_root: [12; 32],
        issued_at: 12345,
        signer_set_id: 1,
    };
    (signed(cp, &[0, 2]), header)
}
fn policy() -> CheckpointPolicy {
    CheckpointPolicy::new(7, [9; 32], set(false), Phase::A).unwrap()
}

#[test]
fn real_phase_a_and_b_quorums_feed_header_authentication() {
    let (env, header) = fixture(100);
    for phase_b in [false, true] {
        let p = CheckpointPolicy::new(7, [9; 32], set(phase_b), if phase_b { Phase::B } else { Phase::A }).unwrap();
        let env = if phase_b {
            signed(env.checkpoint, &[0, 3, 4])
        } else {
            env.clone()
        };
        let verified = p.verify(&env, &header, 101, None).unwrap();
        assert_eq!(verified.epoch(), 100);
        assert!(!verified.arrangement_review_due());
        let body = bloch_l2_evm::l1::authenticate_body(verified.anchor(), &[header.clone().into()], &[]).unwrap();
        assert_eq!(body.state_root(), verified.state_root());
        assert_eq!(body.slot(), 12000);
    }
}
#[test]
fn both_signature_halves_are_required() {
    let (env, header) = fixture(100);
    let p = policy();
    for offset in [0, 3309] {
        let mut broken = env.clone();
        broken.signatures[0].1[offset] ^= 1;
        assert!(matches!(p.verify(&broken, &header, 101, None), Err(Error::Envelope(_))));
    }
    let mut broken = env.clone();
    broken.signatures[0].1.truncate(3309);
    assert!(p.verify(&broken, &header, 101, None).is_err());
    let mut changed = env;
    changed.checkpoint.validator_set_root[0] ^= 1;
    assert!(p.verify(&changed, &header, 101, None).is_err());
}
#[test]
fn weak_duplicate_and_nonexternal_arrangements_or_envelopes_fail() {
    let mut duplicate = set(false);
    duplicate.signers[2].pubkey = duplicate.signers[0].pubkey;
    assert!(matches!(
        CheckpointPolicy::new(7, [9; 32], duplicate, Phase::A),
        Err(Error::Arrangement)
    ));
    let mut weak = set(false);
    weak.threshold = 1;
    weak.min_external = 0;
    assert!(CheckpointPolicy::new(7, [9; 32], weak, Phase::A).is_err());
    let mut overflow = set(false);
    overflow.adopted_epoch = u64::MAX;
    assert!(CheckpointPolicy::new(7, [9; 32], overflow, Phase::A).is_err());
    let (env, header) = fixture(100);
    let p = policy();
    for indices in [&[0, 1][..], &[0][..], &[0, 0, 2][..]] {
        assert!(p.verify(&signed(env.checkpoint, indices), &header, 101, None).is_err());
    }
}
#[test]
fn freshness_and_arrangement_windows_are_enforced() {
    let p = policy();
    let (env, header) = fixture(100);
    assert_eq!(p.verify(&env, &header, 99, None).unwrap_err(), Error::Future);
    assert_eq!(
        p.verify(&env, &header, 100 + ws::WS_PERIOD_EPOCHS, None).unwrap_err(),
        Error::Stale
    );
    assert!(p.verify(&env, &header, 99 + ws::WS_PERIOD_EPOCHS, None).is_ok());
    let (early, header) = fixture(49);
    assert_eq!(p.verify(&early, &header, 100, None).unwrap_err(), Error::AdoptionWindow);
    let epoch = set(false).review_deadline() + 1;
    let (review, header) = fixture(epoch);
    assert!(p
        .verify(&review, &header, epoch, None)
        .unwrap()
        .arrangement_review_due());
    let epoch = set(false).hard_stop() + 1;
    let (expired, header) = fixture(epoch);
    assert!(p.verify(&expired, &header, epoch, None).is_err());
}
#[test]
fn chain_identity_header_state_and_version_are_bound() {
    let p = policy();
    let (env, header) = fixture(100);
    for field in 0..3 {
        let mut cp = env.checkpoint;
        match field {
            0 => cp.network_id += 1,
            1 => cp.genesis_root[0] ^= 1,
            _ => cp.state_root[0] ^= 1,
        }
        assert!(p.verify(&signed(cp, &[0, 2]), &header, 101, None).is_err());
    }
    let mut altered = header.clone();
    altered[200] ^= 1;
    assert_eq!(p.verify(&env, &altered, 101, None).unwrap_err(), Error::Header);
    altered = header;
    altered[..4].fill(0);
    let mut cp = env.checkpoint;
    cp.block_root = *BlockId::of(&BlockHeaderV4::canonical_deserialize(&altered).unwrap()).as_bytes();
    assert_eq!(
        p.verify(&signed(cp, &[0, 2]), &altered, 101, None).unwrap_err(),
        Error::Header
    );
}
#[test]
fn rollback_and_same_epoch_conflicts_are_refused_but_identical_retry_is_valid() {
    let p = policy();
    let (env, header) = fixture(100);
    let old = p.verify(&env, &header, 101, None).unwrap();
    assert_eq!(p.verify(&env, &header, 101, Some(&old)).unwrap().digest(), old.digest());
    let mut changed = env.checkpoint;
    changed.issued_at += 1;
    assert_eq!(
        p.verify(&signed(changed, &[0, 2]), &header, 101, Some(&old))
            .unwrap_err(),
        Error::Conflict
    );
    let (new, new_header) = fixture(101);
    let latest = p.verify(&new, &new_header, 101, Some(&old)).unwrap();
    assert_eq!(
        p.verify(&env, &header, 101, Some(&latest)).unwrap_err(),
        Error::Rollback
    );
}
#[test]
fn envelope_and_header_work_are_bounded() {
    let (mut env, header) = fixture(100);
    let p = policy();
    assert_eq!(p.verify(&env, &header[..303], 101, None).unwrap_err(), Error::Limit);
    env.signatures[0].1 = vec![0; 8193];
    assert_eq!(p.verify(&env, &header, 101, None).unwrap_err(), Error::Limit);
}
