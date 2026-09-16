// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only Genesis-4 transfer observations from an authenticated block body.
//! A payment to a script hash is NOT a bridge escrow or a mint authorization.
use crate::l1::AuthenticatedBody;
use alloc::vec::Vec;
use alloy_primitives::B256;
use sha3::{Digest, Sha3_256};

/// Decoded fixed-width native output. There is no memo or EVM recipient field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeOutput {
    /// Native satoshis, without decimal conversion.
    pub value_sat: u64,
    /// Genesis-4 spend-authority commitment; not arbitrary script bytecode.
    pub script_hash: B256,
}

/// An authenticated observation, never a bridge credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTransfer {
    block: B256,
    slot: u64,
    index: u32,
    txid: B256,
    outputs: Vec<NativeOutput>,
}
impl ObservedTransfer {
    /// Canonical containing block ID.
    pub fn block(&self) -> B256 {
        self.block
    }
    /// Consensus slot, not block height.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// Position in the complete block body.
    pub fn transaction_index(&self) -> u32 {
        self.index
    }
    /// Consensus transaction ID, not the hash of signed transport bytes.
    pub fn txid(&self) -> B256 {
        self.txid
    }
    /// Outputs in original order; output indices remain stable.
    pub fn outputs(&self) -> &[NativeOutput] {
        &self.outputs
    }
    /// Exact sum paid to a script. It proves neither custody nor current unspentness.
    pub fn paid_to(&self, script: B256) -> u128 {
        self.outputs
            .iter()
            .filter(|o| o.script_hash == script)
            .map(|o| o.value_sat as u128)
            .sum()
    }
}

/// Transfer decoding error; no observation or mint is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferObservationError {
    /// Transaction index outside the authenticated body.
    Position,
    /// Only native Transfer (0x01) and TransferV2 (0x06) are supported.
    Unsupported,
    /// Truncation, trailing bytes, invalid counts or witness-table references.
    Encoding,
    /// Local transaction/count work budget exceeded.
    Limit,
}
use TransferObservationError as Error;
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(n).ok_or(Error::Encoding)?;
        let data = self.bytes.get(self.offset..end).ok_or(Error::Encoding)?;
        self.offset = end;
        Ok(data)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
    fn count(&mut self) -> Result<u32, Error> {
        let n = self.u32()?;
        if n > 4096 {
            Err(Error::Limit)
        } else if n == 0 {
            Err(Error::Encoding)
        } else {
            Ok(n)
        }
    }
    fn blob(&mut self) -> Result<(), Error> {
        let n = self.u32()? as usize;
        self.take(n)?;
        Ok(())
    }
}

/// Decode one authenticated transfer, with strict boundaries and consensus txid.
/// The finalized checkpoint's external validator establishes transaction validity;
/// this reader does not independently verify signatures or input ownership.
/// No EVM recipient can be inferred from the native output's script hash.
pub fn observe_transfer(body: &AuthenticatedBody, index: usize) -> Result<ObservedTransfer, Error> {
    let bytes = body.transactions().get(index).ok_or(Error::Position)?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Limit);
    }
    let mut reader = Reader { bytes, offset: 0 };
    let tag = reader.take(1)?[0];
    if tag != 1 && tag != 6 {
        return Err(Error::Unsupported);
    }
    let keys = if tag == 6 {
        let count = reader.count()?;
        for _ in 0..count {
            reader.blob()?;
            reader.blob()?;
        }
        count
    } else {
        0
    };
    let count = reader.count()?;
    let mut spend = Sha3_256::new();
    spend.update(b"BLCH4:SPEND\0\0\0\0\0");
    spend.update(count.to_le_bytes());
    for _ in 0..count {
        spend.update(reader.take(36)?);
        if tag == 1 {
            reader.blob()?;
            reader.blob()?;
        } else if reader.u32()? >= keys {
            return Err(Error::Encoding);
        }
    }
    let count = reader.count()?;
    spend.update(count.to_le_bytes());
    let mut outputs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let raw = reader.take(40)?;
        spend.update(raw);
        outputs.push(NativeOutput {
            value_sat: u64::from_le_bytes(raw[..8].try_into().map_err(|_| Error::Encoding)?),
            script_hash: B256::from_slice(&raw[8..]),
        });
    }
    spend.update(reader.take(24)?); // tx_bytes u64 and priority fee rate u128.
    if reader.offset != bytes.len() {
        return Err(Error::Encoding);
    }
    let mut id = Sha3_256::new();
    id.update(b"BLCH4:TXID\0\0\0\0\0\0");
    id.update(spend.finalize());
    Ok(ObservedTransfer {
        block: body.block(),
        slot: body.slot(),
        index: index as u32,
        txid: B256::from_slice(&id.finalize()),
        outputs,
    })
}
