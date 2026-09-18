// SPDX-License-Identifier: AGPL-3.0-or-later
//! Full local pipeline, with explicitly synthetic host-trusted L1 provenance.
#![cfg(unix)]
use alloy_primitives::{Address, B256};
use bloch_escrow_journal::Journal;
use bloch_l2_evm::{
    domain::{input_commitment, TrustedL1Batch},
    escrow::{Coin, LockIntent, Outpoint},
    escrow_execution::{EscrowEvmDomain, TrustedEscrowBatch, TrustedLockLocation},
    execute_signed_block, generate_signed_batch_witness,
    scale::sats_to_wei,
    BlockContext, ChainSpec, DepositMint, DepositPosition, DepositProvenance, L2State, SignedBlockInput,
};
use bloch_native_escrow_pq::{lock_store::LockStore, PqEscrow, SignedLock};
use sha3::{Digest, Sha3_256};
use std::{fs, io, path::PathBuf};
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn recovered_pq_locks_feed_durable_evm_without_recredit_after_restart() {
    let path = std::env::temp_dir().join(format!(
        "bloch-durable-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let temp = Temp(path);
    let spec = ChainSpec::default();
    let mut state = L2State::genesis(&spec);
    let root = state.commit_root();
    let network = B256::repeat_byte(1);
    let fresh_domain = || {
        EscrowEvmDomain::new(
            network,
            B256::repeat_byte(2),
            B256::repeat_byte(3),
            spec.clone(),
            root,
            16 * 1024 * 1024,
        )
        .unwrap()
    };
    let domain = fresh_domain();
    let domain_id = domain.id();
    let (public, secret) = bloch_crypto::crypto::generate_keypair();
    let owner = B256::from_slice(&Sha3_256::digest(&public));
    let source = Outpoint {
        txid: B256::repeat_byte(4),
        vout: 0,
    };
    let baseline = || PqEscrow::new(network, domain_id, vec![(source, Coin { value: 1000, owner })], 100).unwrap();
    let first = LockIntent {
        network,
        domain: domain_id,
        owner,
        inputs: vec![source],
        recipient: Address::repeat_byte(7),
        amount: 600,
        fee: 10,
        change_owner: owner,
        nonce: 0,
    };
    let mut second = first.clone();
    second.inputs = vec![Outpoint {
        txid: first.signing_root(),
        vout: 0,
    }];
    second.amount = 300;
    second.nonce = 1;
    let signatures: Vec<_> = [&first, &second]
        .iter()
        .map(|intent| bloch_crypto::crypto::sign(&secret, intent.signing_root().as_slice()).unwrap())
        .collect();
    let requests = [
        SignedLock {
            intent: &first,
            public_key: &public,
            signature: &signatures[0],
        },
        SignedLock {
            intent: &second,
            public_key: &public,
            signature: &signatures[1],
        },
    ];
    let escrow_path = temp.0.join("escrow");
    let mut escrow = LockStore::create(&escrow_path, baseline()).unwrap();
    escrow.submit_batch(&requests).unwrap();
    let mark = escrow.mark().unwrap();
    drop(escrow);
    // Restart after L1-side local commit but before any EVM credit.
    let escrow = LockStore::open(&escrow_path, baseline(), mark).unwrap();
    assert_eq!(escrow.escrow().unwrap().locked_sat(), 900);
    let snapshot = escrow.escrow().unwrap().inbox();
    let proofs = snapshot
        .proofs(domain.required_deposit_range(snapshot.len() as u64).unwrap())
        .unwrap();
    // This test supplies a synthetic trusted host mapping. Local inclusion alone
    // must never be described as native finality or a mainnet mint authorization.
    let locations: Vec<_> = proofs
        .iter()
        .map(|p| TrustedLockLocation {
            sequence: p.deposit.sequence,
            intent: p.deposit.id,
            position: DepositPosition {
                l1_height: 50,
                l1_tx_index: p.deposit.sequence as u32,
                l1_vout: 0,
            },
            transaction: B256::repeat_byte(10 + p.deposit.sequence as u8),
        })
        .collect();
    let mut context = BlockContext::next(&spec, &state);
    context.anchor_root = B256::repeat_byte(20);
    let input = SignedBlockInput {
        context,
        deposits: proofs
            .iter()
            .zip(&locations)
            .map(|(p, l)| DepositMint {
                recipient: p.deposit.recipient,
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: l.position.l1_height,
                    l1_tx_index: l.position.l1_tx_index,
                    l1_vout: l.position.l1_vout,
                    l1_txid: l.transaction.into(),
                    l1_sats: p.deposit.amount,
                },
            })
            .collect(),
        ..Default::default()
    };
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
    let trusted = TrustedEscrowBatch {
        execution: TrustedL1Batch {
            height: 100,
            block: input.context.anchor_root,
            domain: domain_id,
            input: input_commitment(&input),
        },
        inbox_root: snapshot.root(),
        count: snapshot.len() as u64,
        locations,
    };
    let execution_path = temp.0.join("execution");
    let mut journal = Journal::create(&execution_path, domain).unwrap();
    let before = journal.head();
    let mut tampered = proofs.clone();
    tampered[1].deposit.amount += 1;
    assert!(journal.commit(&trusted, &tampered, &input, &witness).is_err());
    assert_eq!(journal.head(), before);
    let receipt = journal.commit(&trusted, &proofs, &input, &witness).unwrap();
    let head = journal.head();
    let outcome = execute_signed_block(&spec, &mut state, &input).unwrap();
    assert_eq!(receipt.execution.new_root, outcome.state_root);
    assert_eq!(state.balance_of(&first.recipient), sats_to_wei(900));
    assert_eq!(state.total_minted_wei(), sats_to_wei(900));
    drop(journal);
    drop(escrow);
    // Independent derivation remains required on recovery, even for valid files.
    assert!(
        Journal::open(&execution_path, fresh_domain(), head, |_| Err(io::Error::other(
            "L1 unavailable"
        )))
        .is_err()
    );
    let mut changed = trusted.clone();
    changed.inbox_root = B256::repeat_byte(99);
    assert!(Journal::open(&execution_path, fresh_domain(), head, |_| Ok(changed.clone())).is_err());
    let mut journal = Journal::open(&execution_path, fresh_domain(), head, |number| {
        assert_eq!(number, 1);
        Ok(trusted.clone())
    })
    .unwrap();
    assert_eq!(journal.head(), head);
    assert!(journal.commit(&trusted, &proofs, &input, &witness).is_err());
    assert_eq!(journal.head(), head);
    let mut escrow = LockStore::open(&escrow_path, baseline(), mark).unwrap();
    assert!(escrow.submit_batch(&requests).is_err());
    assert_eq!(escrow.mark().unwrap(), mark);
    assert_eq!(escrow.escrow().unwrap().inbox().root(), snapshot.root());
    assert!(escrow.escrow().unwrap().conserved());
    let config = serde_json::json!({
        "version": 1, "profile": "bloch-local-escrow-v1",
        "network": network, "domain": domain_id, "capacity": 100,
        "expected_commitment": baseline().commitment(),
        "allocations": [{"outpoint": source, "value": 1000, "owner": owner}]
    });
    let config_path = temp.0.join("baseline.json");
    let minimum_path = temp.0.join("minimum.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::write(
        &minimum_path,
        serde_json::to_vec(&serde_json::json!({
            "batches": mark.batches, "digest": mark.digest
        }))
        .unwrap(),
    )
    .unwrap();
    let audit = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_bloch-escrow-audit"))
            .arg(&config_path)
            .arg(&escrow_path)
            .arg(&minimum_path)
            .output()
            .unwrap()
    };
    // A concurrent writer prevents reporting a stale or unlocked snapshot.
    assert_eq!(audit().status.code(), Some(1));
    let expected_state = escrow.escrow().unwrap().commitment();
    drop(escrow);
    let output = audit();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["locked_sat"], "900");
    assert_eq!(report["history_usage"]["batches"], 1);
    assert_eq!(
        report["history_usage"]["bytes"],
        fs::metadata(escrow_path.join("00000000000000000001.locks"))
            .unwrap()
            .len()
            .to_string()
    );
    assert_eq!(
        report["state_commitment"],
        serde_json::to_value(expected_state).unwrap()
    );
    assert_eq!(report["inbox"]["root"], serde_json::to_value(snapshot.root()).unwrap());
    assert_eq!(report["inbox"]["count"], 2);
    assert_eq!(report["native_finality_verified"], false);
    assert_eq!(report["mark"]["digest"], serde_json::to_value(mark.digest).unwrap());
    let export = |start: &str, end: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_bloch-escrow-audit"))
            .arg(&config_path)
            .arg(&escrow_path)
            .arg(&minimum_path)
            .args(["--proofs", start, end])
            .output()
            .unwrap()
    };
    let output = export("0", "2");
    assert!(output.status.success());
    let exported: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(exported["mark"], report["mark"]);
    assert_eq!(exported["inbox"], report["inbox"]);
    let decoded: Vec<bloch_l2_evm::escrow_inbox::InboxProof> =
        serde_json::from_value(exported["proof_batch"]["proofs"].clone()).unwrap();
    assert_eq!(decoded, proofs);
    let verified = bloch_l2_evm::escrow_inbox::verify_proof_range(
        network,
        domain_id,
        snapshot.root(),
        snapshot.len() as u64,
        0..2,
        &decoded,
    )
    .unwrap();
    assert_eq!(verified.total_sat(), 900);
    for proof in &decoded {
        assert!(proof.verify(network, domain_id, snapshot.root()));
        assert!(!proof.verify(network, domain_id, B256::ZERO));
    }
    assert_eq!(exported["proof_batch"]["start"], 0);
    assert_eq!(exported["proof_batch"]["end"], 2);
    let empty = export("2", "2");
    assert!(empty.status.success());
    let empty: serde_json::Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert!(empty["proof_batch"]["proofs"].as_array().unwrap().is_empty());
    for (start, end) in [
        ("2", "1"),
        ("0", "3"),
        ("3", "3"),
        ("0", "4097"),
        ("-1", "2"),
        ("+1", "2"),
        ("0", "18446744073709551616"),
    ] {
        let output = export(start, end);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    let size = fs::metadata(escrow_path.join("00000000000000000001.locks"))
        .unwrap()
        .len();
    for limits in [
        serde_json::json!({"max_batches": 0, "max_bytes": size}),
        serde_json::json!({"max_batches": 1, "max_bytes": size - 1}),
    ] {
        let mut limited = config.clone();
        limited["recovery"] = limits;
        fs::write(&config_path, serde_json::to_vec(&limited).unwrap()).unwrap();
        let output = audit();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Limit"));
        assert_eq!(export("0", "2").status.code(), Some(1));
    }
    let mut limited = config.clone();
    limited["recovery"] = serde_json::json!({"max_batches": 1, "max_bytes": size});
    fs::write(&config_path, serde_json::to_vec(&limited).unwrap()).unwrap();
    assert!(audit().status.success());
    let mut wrong = config.clone();
    wrong["allocations"][0]["value"] = 1001.into();
    fs::write(&config_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
    let output = audit();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::write(
        &minimum_path,
        serde_json::to_vec(&serde_json::json!({
            "batches": mark.batches + 1, "digest": mark.digest
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(audit().status.code(), Some(1));
}
