// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded internal serde representation as canonical RLP bytes.
use alloy_rlp::{Decodable, Error};
use serde::de::{Error as _, SeqAccess, Visitor};
use std::marker::PhantomData;

pub(super) fn decode_exact<T: Decodable>(mut bytes: &[u8]) -> alloy_rlp::Result<T> {
    let value = T::decode(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(Error::Custom("trailing Bloch V2 encoding bytes"));
    }
    Ok(value)
}
pub(super) struct RlpVisitor<T, const LIMIT: usize>(pub PhantomData<T>);
impl<'de, T: Decodable, const LIMIT: usize> Visitor<'de> for RlpVisitor<T, LIMIT> {
    type Value = T;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical Bloch V2 RLP bytes (at most {LIMIT})")
    }
    fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<T, E> {
        if bytes.len() > LIMIT {
            return Err(E::custom("Bloch V2 serde byte limit exceeded"));
        }
        decode_exact(bytes).map_err(E::custom)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
        if seq.size_hint().is_some_and(|len| len > LIMIT) {
            return Err(A::Error::custom("Bloch V2 serde byte limit exceeded"));
        }
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(LIMIT));
        while let Some(byte) = seq.next_element::<u8>()? {
            if bytes.len() == LIMIT {
                return Err(A::Error::custom("Bloch V2 serde byte limit exceeded"));
            }
            bytes.push(byte);
        }
        self.visit_bytes(&bytes)
    }
}
macro_rules! impl_serde_rlp {
    ($ty:ty, $limit:expr) => {
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&alloy_rlp::encode(self))
            }
        }
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_bytes($crate::primitives::serde_rlp::RlpVisitor::<Self, { $limit }>(
                    std::marker::PhantomData,
                ))
            }
        }
    };
}
pub(super) use impl_serde_rlp;
