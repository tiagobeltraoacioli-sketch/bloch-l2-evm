// SPDX-License-Identifier: MIT OR Apache-2.0
//! Synthetic canonical headers for tests; no native finality or escrow authority.
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{
    height::{HeightCursor, HeightPosition},
    FinalizedCheckpoint,
};
use sha3::{Digest, Sha3_256};

pub fn id(header: &[u8]) -> B256 {
    let mut digest = Sha3_256::new();
    digest.update(b"BLCH4:BLOCK\0\0\0\0\0");
    digest.update(header);
    B256::from_slice(&digest.finalize())
}
pub fn headers(height: u64) -> Vec<Bytes> {
    let mut headers = Vec::new();
    let mut parent = B256::ZERO;
    for index in 0..=height {
        let mut bytes = vec![0u8; 304];
        bytes[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
        bytes[4..36].copy_from_slice(parent.as_slice());
        bytes[100..108].copy_from_slice(&(100 + index * 50).to_le_bytes());
        parent = id(&bytes);
        headers.push(Bytes::from(bytes));
    }
    headers
}
pub fn cursor() -> HeightCursor {
    let headers = headers(0);
    HeightCursor::from_genesis(id(&headers[0]), &headers[0]).unwrap()
}
pub fn position(height: u64) -> HeightPosition {
    let headers = headers(height);
    let mut cursor = cursor();
    if height != 0 {
        cursor
            .advance(
                FinalizedCheckpoint {
                    block: id(&headers[height as usize]),
                    slot: 100 + height * 50,
                },
                &headers,
            )
            .unwrap();
    }
    cursor.position()
}
