// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public fixture generation only. Disposable private keys remain in this process.
#[path = "../tests/support/native_ffg.rs"]
mod fixture;
use bloch_pos_committee::{
    attestation::{Attestation, AttestationData},
    beacon::{self, RandaoChain},
    committees, epoch_of,
    header::BlockHeaderV4,
    interfaces::{ProposalEnvelope, StateReader, StateTransition},
    transition::{CommittedState, PosTransaction, Transition},
};
use bloch_settlement_recovery::native::{NativeConsensusVerifierV1, NativeReplayBlockV1};
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

fn save(root: &Path, name: &str, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn build(
    pre: &CommittedState,
    slot: u64,
    atts: Vec<Attestation>,
    txs: Vec<PosTransaction>,
    chains: &mut [RandaoChain],
    keys: &[(Vec<u8>, Vec<u8>)],
) -> (NativeReplayBlockV1, CommittedState) {
    let tr = Transition::new(NativeConsensusVerifierV1);
    let mut ctx = pre.clone();
    for _ in epoch_of(pre.slot())..epoch_of(slot) {
        ctx = tr.process_epoch(&ctx).unwrap();
    }
    let proposer =
        bloch_pos_committee::proposer(&ctx.seed_for_epoch(epoch_of(slot)), slot, &ctx.active_validators()).unwrap();
    let reveal = chains[proposer as usize].next_reveal().unwrap();
    let transactions = txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>();
    let fin = ctx.finality();
    let mut header = BlockHeaderV4 {
        version: 0xb10c_0005,
        parent: *pre.head().as_bytes(),
        state_root: [0; 32],
        body_root: bloch_pos_committee::derive::body_root(&transactions),
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
    let probe = ProposalEnvelope {
        header,
        proposer_sig: sign(&header),
    };
    header.state_root = tr.compute_post_state(pre, &probe, &atts, &txs).unwrap().state_root();
    let envelope = ProposalEnvelope {
        header,
        proposer_sig: sign(&header),
    };
    let post = tr.apply_block(pre, &envelope, &atts, &txs).unwrap();
    (
        NativeReplayBlockV1 {
            envelope,
            attestations: atts,
            transactions,
        },
        post,
    )
}
fn tail(
    pre: &CommittedState,
    prefix: &[NativeReplayBlockV1],
    keys: &[(Vec<u8>, Vec<u8>)],
    mode: &str,
) -> Vec<NativeReplayBlockV1> {
    let mut chains = fixture::chains();
    for block in prefix {
        chains[block.envelope.header.proposer_index as usize]
            .next_reveal()
            .unwrap();
    }
    let mut state = pre.clone();
    let mut blocks = prefix.to_vec();
    for epoch in 1..=2 {
        let target = *state.head().as_bytes(); // last block strictly before the epoch
        let (block, post) = build(&state, epoch * 32, vec![], vec![], &mut chains, keys);
        blocks.push(block);
        state = post;
        let partition = committees::epoch_committees(&state.seed_for_epoch(epoch), epoch, &state.active_validators());
        let mut atts = Vec::new();
        for (offset, members) in partition.iter().enumerate() {
            for &v in members {
                let include = match mode {
                    "full" => true,
                    "two" | "conflict" => v < 2,
                    _ => v == 0,
                };
                if !include {
                    continue;
                }
                let data = AttestationData {
                    slot: epoch * 32 + offset as u64,
                    head: *state.head().as_bytes(),
                    source_epoch: state.finality().justified.epoch,
                    source_root: state.finality().justified.root,
                    target_epoch: epoch,
                    target_root: target,
                };
                let att = Attestation {
                    validator: v,
                    signature: bloch_crypto::crypto::sign(&keys[v as usize].1, &data.signing_root()).unwrap(),
                    data,
                };
                atts.push(att.clone());
                if mode == "duplicates" {
                    atts.extend([att.clone(), att]);
                }
                if mode == "conflict" && v == 0 {
                    let mut data = data;
                    data.head = target;
                    atts.push(Attestation {
                        validator: v,
                        signature: bloch_crypto::crypto::sign(&keys[v as usize].1, &data.signing_root()).unwrap(),
                        data,
                    });
                }
            }
        }
        let (block, post) = build(&state, epoch * 32 + 31, atts, vec![], &mut chains, keys);
        blocks.push(block);
        state = post;
    }
    let (block, post) = build(&state, 96, vec![], vec![], &mut chains, keys);
    blocks.push(block);
    if matches!(mode, "full" | "two") {
        assert_eq!(post.finality().finalized.epoch, 1);
    } else {
        assert_eq!(post.finality().finalized.epoch, 0);
    }
    blocks
}
fn main() {
    let path = std::env::args_os().nth(1).expect("fresh output directory required");
    let root = Path::new(&path);
    fs::create_dir(root).unwrap();
    let keys = (0..3)
        .map(|_| bloch_crypto::crypto::generate_keypair())
        .collect::<Vec<_>>();
    let public = keys.iter().map(|k| k.0.clone()).collect::<Vec<_>>();
    let genesis = fixture::genesis(&public);
    let mut chains = fixture::chains();
    let (first, pre) = build(&genesis, 1, vec![], vec![], &mut chains, &keys);
    let source = pre.l2_settlement().unwrap().source(*pre.head().as_bytes(), pre.slot());
    let p = fixture::policy();
    let request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        hex::encode(p.network),
        hex::encode(p.genesis),
        hex::encode(source.block),
        source.slot,
        source.height,
        hex::encode(source.commitment),
        hex::encode(source.inbox_root)
    );
    save(root, "native-request.txt", request.as_bytes());
    let metadata = json!({"classification":"disposable-native-pq-ffg-rehearsal","operational_authority":false,
        "public_keys":public.iter().map(hex::encode).collect::<Vec<_>>(),"genesis_state_root":hex::encode(genesis.state_root()),
        "first_block":fixture::encode_block(&first)});
    save(
        root,
        "bootstrap.json",
        serde_json::to_string_pretty(&metadata).unwrap().as_bytes(),
    );
    println!("Public request ready. Waiting for canonical.proof, canonical.values and proof-ready; no private keys exported.");
    let deadline = Instant::now() + Duration::from_secs(3600);
    while !root.join("proof-ready").exists() {
        assert!(Instant::now() < deadline, "proof wait expired");
        std::thread::sleep(Duration::from_millis(500));
    }
    // The statement is a byte vector in this native tree and was a fixed array in earlier ones: the conversion
    // is kept so that the example builds against both.
    #[allow(clippy::useless_conversion)]
    let tx = bloch_pos_committee::l2_settlement::Transaction {
        proof_policy: p.proof_policy.0,
        statement: fs::read(root.join("canonical.values")).unwrap().try_into().unwrap(),
        proof: fs::read(root.join("canonical.proof")).unwrap().try_into().unwrap(),
    };
    let (settlement, pre) = build(
        &pre,
        2,
        vec![],
        vec![PosTransaction::L2Settlement(Box::new(tx))],
        &mut chains,
        &keys,
    );
    let prefix = vec![first, settlement];
    for mode in ["full", "two", "insufficient", "duplicates", "conflict"] {
        let blocks = tail(&pre, &prefix, &keys, mode);
        save(
            root,
            &format!("{mode}.json"),
            serde_json::to_string_pretty(&blocks.iter().map(fixture::encode_block).collect::<Vec<_>>())
                .unwrap()
                .as_bytes(),
        );
    }
    println!("Native blocks and FFG attestations generated and reverified with real hybrid signatures and real Groth16. Private keys now discarded.");
}
