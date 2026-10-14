// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mainnet execution profile (chain id 700770) on the V2 node path:
//! chain-id separation from the devnets, BLOCKHASH over the last 256 L2
//! blocks, and a block gas budget that holds a ~3.9M-gas contract creation
//! (the DEX router).
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    decode_signed_transaction,
    node_execution::{execute_node_block, genesis_v2, node_head},
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID,
};
use k256::ecdsa::SigningKey;

fn domain() -> B256 {
    B256::repeat_byte(0x70)
}

fn key() -> SigningKey {
    SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap()
}

fn sign(chain_id: u64, nonce: u64, to: TxKind, input: Bytes, gas_limit: u64) -> Bytes {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        to,
        input,
        gas_limit,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}

fn next(spec: &ChainSpec, parent: &NodeHeaderV2) -> BlockContext {
    BlockContext {
        number: parent.number + 1,
        timestamp: parent.timestamp + 12,
        base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
        prevrandao: B256::repeat_byte(7),
        anchor_root: B256::repeat_byte(8),
    }
}

#[test]
fn chain_ids_do_not_cross_between_mainnet_and_devnets() {
    let mainnet = ChainSpec::mainnet();
    let devnet = ChainSpec::testnet_v3();
    assert_eq!(mainnet.chain_id, MAINNET_CHAIN_ID);
    assert_eq!(devnet.chain_id, TESTNET_CHAIN_ID);
    let to = TxKind::Call(Address::repeat_byte(1));
    let for_mainnet = sign(MAINNET_CHAIN_ID, 0, to, Bytes::new(), 21_000);
    let for_devnet = sign(TESTNET_CHAIN_ID, 0, to, Bytes::new(), 21_000);
    assert!(decode_signed_transaction(&mainnet, &for_mainnet).is_ok());
    assert!(decode_signed_transaction(&devnet, &for_devnet).is_ok());
    assert!(decode_signed_transaction(&mainnet, &for_devnet).is_err(), "700771 replayed on mainnet");
    assert!(decode_signed_transaction(&devnet, &for_mainnet).is_err(), "700770 replayed on a devnet");
}

/// Runtime: `n = calldataload(0); sstore(n, blockhash(n))`.
const PROBE_RUNTIME: [u8; 8] = [0x60, 0x00, 0x35, 0x80, 0x40, 0x90, 0x55, 0x00];

fn probe_init() -> Bytes {
    // CODECOPY(0, 12, 8); RETURN(0, 8); runtime follows the 12-byte prefix.
    let mut code = vec![0x60, 0x08, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x08, 0x60, 0x00, 0xf3];
    code.extend_from_slice(&PROBE_RUNTIME);
    code.into()
}

/// Init code returning 18,000 zero bytes: 3.6M gas of code deposit alone,
/// the size class of the DEX router creation (~3.9M gas).
fn heavy_init() -> Bytes {
    Bytes::from_static(&[0x61, 0x46, 0x50, 0x60, 0x00, 0xf3])
}

#[test]
fn blockhash_serves_exactly_the_last_256_blocks_and_a_router_sized_create_fits() {
    let spec = ChainSpec::mainnet();
    let sender = Address::from_public_key(key().verifying_key());
    let mut state = genesis_v2(&spec, 1_760_000_000).unwrap();
    let mut parent = node_head(&spec, domain(), &state).unwrap();
    let mut hashes = vec![parent.hash()];

    // Block 1: fund the sender, deploy the probe and a router-sized contract.
    let body = NodeBodyV2 {
        deposits: vec![DepositMint {
            recipient: sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
        transactions: vec![
            sign(MAINNET_CHAIN_ID, 0, TxKind::Create, probe_init(), 200_000),
            sign(MAINNET_CHAIN_ID, 1, TxKind::Create, heavy_init(), 4_000_000),
        ],
    };
    let result = execute_node_block(&spec, domain(), &mut state, &next(&spec, &parent), &body).unwrap();
    let probe = result.transactions[0].created_address.expect("probe deployed");
    let heavy = &result.transactions[1];
    assert!(heavy.success, "a 4M-gas creation fits the mainnet block");
    assert!(heavy.gas_used > 3_600_000, "gas used {}", heavy.gas_used);
    assert!(state.account(&heavy.created_address.unwrap()).is_some());
    parent = result.header;
    hashes.push(parent.hash());

    // Blocks 2..=299 are empty.
    while parent.number < 299 {
        let result =
            execute_node_block(&spec, domain(), &mut state, &next(&spec, &parent), &NodeBodyV2::default()).unwrap();
        parent = result.header;
        hashes.push(parent.hash());
    }

    // Block 300 asks BLOCKHASH for the window edges.
    let numbers = [299u64, 200, 44, 43, 300, 0];
    let transactions = numbers
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let input = Bytes::from(U256::from(*n).to_be_bytes::<32>().to_vec());
            sign(MAINNET_CHAIN_ID, 2 + i as u64, TxKind::Call(probe), input, 100_000)
        })
        .collect();
    let body = NodeBodyV2 {
        deposits: vec![],
        transactions,
    };
    let result = execute_node_block(&spec, domain(), &mut state, &next(&spec, &parent), &body).unwrap();
    assert_eq!(result.header.number, 300);
    assert!(result.transactions.iter().all(|t| t.success));
    let seen = |n: u64| B256::from(state.storage_of(&probe, U256::from(n)).to_be_bytes::<32>());
    // In the window [N-256, N-1]: the real committed L2 header hashes.
    for n in [299u64, 200, 44] {
        assert_eq!(seen(n), hashes[n as usize], "BLOCKHASH({n}) at block 300");
        assert_ne!(seen(n), B256::ZERO);
    }
    // Outside it (older than 256, the current block, genesis): zero.
    for n in [43u64, 300, 0] {
        assert_eq!(seen(n), B256::ZERO, "BLOCKHASH({n}) at block 300");
    }
}
