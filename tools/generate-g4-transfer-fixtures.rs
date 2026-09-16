// Synthetic codec vectors from the authoritative Genesis-4 consensus crate.
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
    transition::{PosTransaction, TransferInput, TransferInputV2, TransferOutput, WitnessKey},
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let outputs = vec![
        TransferOutput {
            value: u64::MAX,
            script_hash: [11; 32],
        },
        TransferOutput {
            value: 5,
            script_hash: [22; 32],
        },
        TransferOutput {
            value: u64::MAX,
            script_hash: [11; 32],
        },
    ];
    let txs = vec![
        PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: [7; 32],
                vout: 3,
                pubkey: vec![1, 2],
                signature: vec![3, 4],
            }],
            outputs: outputs.clone(),
            tx_bytes: 10000,
            tip_millisat_per_gas: 5,
        },
        PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: vec![1, 2],
                signature: vec![3, 4],
            }],
            inputs: vec![TransferInputV2 {
                txid: [7; 32],
                vout: 3,
                key_index: 0,
            }],
            outputs,
            tx_bytes: 10000,
            tip_millisat_per_gas: 5,
        },
    ];
    println!("[");
    for (i, tx) in txs.iter().enumerate() {
        let raw = tx.canonical_bytes();
        assert_eq!(PosTransaction::from_canonical_bytes(&raw).unwrap().txid(), tx.txid());
        let mut bytes = [0u8; 304];
        bytes[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
        bytes[68..100].copy_from_slice(&body_root(&[raw.clone()]));
        bytes[100..108].copy_from_slice(&100u64.to_le_bytes());
        let h = BlockHeaderV4::canonical_deserialize(&bytes).unwrap();
        println!(
            "{}{{\"header\":\"{}\",\"checkpoint\":\"{}\",\"transaction\":\"{}\",\"txid\":\"{}\"}}",
            if i == 0 { "" } else { "," },
            hex(&h.canonical_serialize()),
            hex(BlockId::of(&h).as_bytes()),
            hex(&raw),
            hex(&tx.txid())
        );
    }
    println!("]");
}
