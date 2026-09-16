// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable local inputs for bloch-domain. All L1 trust and funding are synthetic.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_escrow_journal::JournalHead;
use bloch_l2_evm::{
    domain::{input_commitment, TrustedL1Batch},
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::{EscrowEvmDomain, TrustedEscrowBatch, TrustedLockLocation},
    execute_signed_block, generate_signed_batch_witness, BlockContext, ChainSpec, DepositMint, DepositPosition,
    DepositProvenance, L2State, SignedBlockInput,
};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn sign(key: &SigningKey, chain_id: u64, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to,
        input,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .expect("fixture signature")
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let output = args.next().ok_or("usage: developer_fixture NEW_DIRECTORY")?;
    if args.next().is_some() {
        return Err("usage: developer_fixture NEW_DIRECTORY".into());
    }
    let output = Path::new(&output);
    // Never reuse an existing destination, including an existing symlink.
    fs::DirBuilder::new().mode(0o700).create(output)?;
    for child in ["trust", "proposals"] {
        fs::DirBuilder::new().mode(0o700).create(output.join(child))?;
    }
    let mut warning = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output.join("SYNTHETIC-TRUST.txt"))?;
    warning.write_all(b"LOCAL DEVELOPMENT ONLY. Every trust file, L1 location, checkpoint and funding allocation in this directory is synthetic. The fixture author controls both proposals and trust: this demonstrates local verification, not L1 authentication. No real BLCH, PQ authorization, finalized native deposit, production mint authority, RPC service or withdrawal proof is supplied. The public signing key is disposable. minimum-head.json is a genesis watermark retained outside the journal; retain each successful CLI head separately to detect loss of acknowledged records. Keeping a watermark here does not protect rollback of this entire directory. Files are created exclusively; incomplete output after an error must be inspected and a new destination chosen.\n")?;
    warning.sync_all()?;

    let spec = ChainSpec::default();
    let mut state = L2State::genesis(&spec);
    let network = B256::repeat_byte(1);
    let module = B256::repeat_byte(2);
    let runtime = B256::repeat_byte(3);
    let mut domain = EscrowEvmDomain::new(
        network,
        module,
        runtime,
        spec.clone(),
        state.commit_root(),
        16 * 1024 * 1024,
    )
    .expect("local domain");
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("public fixture key");
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    let owner = B256::repeat_byte(6);
    let source = Outpoint {
        txid: B256::repeat_byte(8),
        vout: 0,
    };
    let mut escrow = EscrowLedger::new(
        network,
        domain.id(),
        vec![(
            source,
            Coin {
                value: 100_000_010,
                owner,
            },
        )],
        10,
    )
    .expect("synthetic allocation");
    // This API assumes authorization by its caller. No native PQ signature is asserted.
    let record = escrow
        .apply_authorized_lock(&LockIntent {
            network,
            domain: domain.id(),
            owner,
            inputs: vec![source],
            recipient: sender,
            amount: 100_000_000,
            fee: 10,
            change_owner: owner,
            nonce: 0,
        })
        .expect("synthetic authorized lock");
    let inbox = escrow.inbox();
    let proof = inbox.proof(0).expect("real local inbox proof");
    let initial_head = JournalHead::genesis(domain.id());
    write_json(
        &output.join("config.json"),
        &json!({
            "version": 1, "profile": "bloch-evm-cancun-local-v1", "network": network,
            "module": module, "runtime": runtime, "expected_domain": domain.id(),
            "witness_limit": 16777216
        }),
    )?;
    write_json(
        &output.join("minimum-head.json"),
        &json!({
            "blocks": initial_head.blocks, "digest": initial_head.digest
        }),
    )?;

    // Runtime stores calldata word 0 in slot 0 and returns that word.
    let runtime_code = [
        0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 0, 0x54, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3,
    ];
    let length = u8::try_from(runtime_code.len()).expect("short runtime");
    let mut initcode = vec![0x60, length, 0x60, 12, 0x60, 0, 0x39, 0x60, length, 0x60, 0, 0xf3];
    initcode.extend_from_slice(&runtime_code);
    let transactions = [
        sign(&key, spec.chain_id, 0, TxKind::Create, initcode.into()),
        sign(
            &key,
            spec.chain_id,
            1,
            TxKind::Call(contract),
            U256::from(42).to_be_bytes::<32>().to_vec().into(),
        ),
    ];
    let mut roots = Vec::new();
    for (index, transaction) in transactions.into_iter().enumerate() {
        let first = index == 0;
        let mut context = BlockContext::next(&spec, &state);
        context.anchor_root = B256::repeat_byte(4);
        context.timestamp = 100 + index as u64;
        let input = SignedBlockInput {
            context,
            transactions: vec![transaction],
            deposits: if first {
                vec![DepositMint {
                    recipient: sender,
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 50,
                        l1_tx_index: 3,
                        l1_vout: 0,
                        l1_txid: [9; 32],
                        l1_sats: record.amount,
                    },
                }]
            } else {
                vec![]
            },
        };
        let proofs = if first { vec![proof.clone()] } else { vec![] };
        let trusted = TrustedEscrowBatch {
            execution: TrustedL1Batch {
                height: 100,
                block: input.context.anchor_root,
                domain: domain.id(),
                input: input_commitment(&input),
            },
            inbox_root: inbox.root(),
            count: 1,
            locations: if first {
                vec![TrustedLockLocation {
                    sequence: 0,
                    intent: record.id,
                    position: DepositPosition {
                        l1_height: 50,
                        l1_tx_index: 3,
                        l1_vout: 0,
                    },
                    transaction: B256::repeat_byte(9),
                }]
            } else {
                vec![]
            },
        };
        let (witness, generated) = generate_signed_batch_witness(&state, &spec, &input).expect("witness");
        domain
            .verify_and_advance(&trusted, &proofs, &input, &witness)
            .expect("escrow and EVM verification");
        let outcome = execute_signed_block(&spec, &mut state, &input).expect("signed execution");
        assert!(outcome.tx_outcomes[0].success);
        assert_eq!(outcome.state_root, generated.state_root);
        assert_eq!(outcome.state_root, domain.state_root());
        if first {
            assert_eq!(outcome.tx_outcomes[0].created_address, Some(contract));
        }
        let locations: Vec<_> = trusted
            .locations
            .iter()
            .map(|location| {
                json!({
                    "sequence": location.sequence, "intent": location.intent, "height": location.position.l1_height,
                    "transaction_index": location.position.l1_tx_index, "output_index": location.position.l1_vout,
                    "transaction": location.transaction
                })
            })
            .collect();
        let filename = format!("{:020}.json", input.context.number);
        write_json(
            &output.join("trust").join(&filename),
            &json!({
                "version": 1, "height": trusted.execution.height, "block": trusted.execution.block,
                "domain": trusted.execution.domain, "input": trusted.execution.input,
                "inbox_root": trusted.inbox_root, "count": trusted.count, "locations": locations
            }),
        )?;
        write_json(
            &output.join("proposals").join(filename),
            &json!({
                "version": 1, "proofs": proofs, "input": input, "witness": witness
            }),
        )?;
        roots.push(outcome.state_root);
    }
    assert_eq!(
        state.db().cache.accounts[&contract].storage[&U256::ZERO],
        U256::from(42)
    );
    assert_eq!(state.nonce_of(&sender), 2);
    assert_eq!(domain.next_deposit(), 1);
    write_json(
        &output.join("expected.json"),
        &json!({
            "version": 1, "synthetic": true, "domain": domain.id(), "sender": sender,
            "contract": contract, "state_root": state.commit_root(), "block_roots": roots,
            "next_block": domain.next_block(), "next_deposit": domain.next_deposit(),
            "sender_nonce": 2, "storage_slot": "0", "storage_value": "42"
        }),
    )?;
    for path in [output.join("trust"), output.join("proposals"), output.to_path_buf()] {
        fs::File::open(path)?.sync_all()?;
    }
    println!("Synthetic local developer fixture created: {}", output.display());
    println!("Signed deployment and call verified; storage[0] = 42. No journal created.");
    Ok(())
}
