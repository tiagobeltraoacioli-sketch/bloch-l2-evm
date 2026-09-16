// Fixture generator linked against the authoritative Genesis-4 consensus crate.
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    println!("[");
    for (case, count) in [0usize, 1, 2, 3, 5, 17, 32].into_iter().enumerate() {
        let txs: Vec<Vec<u8>> = (0..count).map(|i| vec![(i + 1) as u8; i + 1]).collect();
        let root = body_root(&txs);
        let mut header = vec![0u8; 304];
        header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
        header[36..68].fill(11);
        header[68..100].copy_from_slice(&root);
        header[100..108].copy_from_slice(&100u64.to_le_bytes());
        let target = BlockHeaderV4::canonical_deserialize(&header).unwrap();
        let first = BlockId::of(&target);
        let mut path = vec![hex(&target.canonical_serialize())];
        let mut previous = first;
        for slot in [103u64, 109] {
            header[4..36].copy_from_slice(previous.as_bytes());
            header[100..108].copy_from_slice(&slot.to_le_bytes());
            let h = BlockHeaderV4::canonical_deserialize(&header).unwrap();
            previous = BlockId::of(&h);
            path.push(hex(&h.canonical_serialize()));
        }
        println!("{}{{\"body_root\":\"{}\",\"target\":\"{}\",\"checkpoint\":\"{}\",\"checkpoint_slot\":109,\"headers\":{:?},\"transactions\":{:?}}}",
            if case == 0 { "" } else { "," }, hex(&root), hex(first.as_bytes()), hex(previous.as_bytes()), path, txs.iter().map(|t|hex(t)).collect::<Vec<_>>());
    }
    println!("]");
}
