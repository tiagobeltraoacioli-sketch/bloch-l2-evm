// SPDX-License-Identifier: MIT OR Apache-2.0
//! Allocation-bounded sequence decoding shared by experimental integrations.
use alloc::vec::Vec;
use alloy_primitives::Bytes;
use core::{fmt, marker::PhantomData};
use serde::{
    de::{self, DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

struct BoundedBytes<const N: usize>;
impl<'de, const N: usize> DeserializeSeed<'de> for BoundedBytes<N> {
    type Value = Bytes;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Bytes, D::Error> {
        struct BytesVisitor<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = Bytes;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "at most {N} bytes")
            }
            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Bytes, E> {
                if value.len() > N {
                    return Err(E::custom("byte sequence exceeds allocation limit"));
                }
                Ok(Bytes::copy_from_slice(value))
            }
            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Bytes, E> {
                if value.len() > N {
                    return Err(E::custom("byte sequence exceeds allocation limit"));
                }
                Ok(value.into())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bytes, A::Error> {
                if seq.size_hint().is_some_and(|size| size > N) {
                    return Err(de::Error::custom("byte sequence exceeds allocation limit"));
                }
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
                while bytes.len() < N {
                    match seq.next_element()? {
                        Some(byte) => bytes.push(byte),
                        None => return Ok(bytes.into()),
                    }
                }
                seq.next_element_seed(Reject)?;
                Ok(bytes.into())
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Bytes, E> {
                if value.len() > N.saturating_mul(2).saturating_add(2) {
                    return Err(E::custom("hex byte sequence exceeds allocation limit"));
                }
                value.parse().map_err(|_| E::custom("invalid hex byte sequence"))
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(BytesVisitor::<N>)
        } else {
            deserializer.deserialize_byte_buf(BytesVisitor::<N>)
        }
    }
}

struct Reject;
impl<'de> DeserializeSeed<'de> for Reject {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(de::Error::custom("sequence exceeds allocation limit"))
    }
}

/// Decode at most N elements, rejecting an excess element before decoding it.
/// Nested element types must impose their own bounds; this is not a byte budget.
pub fn vector<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(PhantomData<T>);
    // Reject the first excess element without deserializing it. In particular,
    // an excess lock must not allocate its nested public key/signature/inputs.
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a sequence with at most {N} entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if seq.size_hint().is_some_and(|size| size > N) {
                return Err(de::Error::custom("sequence exceeds allocation limit"));
            }
            let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
            while items.len() < N {
                match seq.next_element()? {
                    Some(value) => items.push(value),
                    None => return Ok(items),
                }
            }
            seq.next_element_seed(Reject)?;
            Ok(items)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, N>(PhantomData))
}

/// Decode a vector of bounded byte strings with count, per-item and aggregate limits.
pub fn byte_vectors<'de, D, const COUNT: usize, const ITEM: usize, const TOTAL: usize>(
    deserializer: D,
) -> Result<Vec<Bytes>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Bounded<const COUNT: usize, const ITEM: usize, const TOTAL: usize>;
    impl<'de, const COUNT: usize, const ITEM: usize, const TOTAL: usize> Visitor<'de> for Bounded<COUNT, ITEM, TOTAL> {
        type Value = Vec<Bytes>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "at most {COUNT} byte strings totaling at most {TOTAL} bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Bytes>, A::Error> {
            if seq.size_hint().is_some_and(|size| size > COUNT) {
                return Err(de::Error::custom("sequence exceeds allocation limit"));
            }
            let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(COUNT));
            let mut total = 0usize;
            while items.len() < COUNT {
                let Some(value) = seq.next_element_seed(BoundedBytes::<ITEM>)? else {
                    return Ok(items);
                };
                total = total
                    .checked_add(value.len())
                    .filter(|total| *total <= TOTAL)
                    .ok_or_else(|| de::Error::custom("byte sequence total exceeds allocation limit"))?;
                items.push(value);
            }
            seq.next_element_seed(Reject)?;
            Ok(items)
        }
    }
    deserializer.deserialize_seq(Bounded::<COUNT, ITEM, TOTAL>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Wire {
        #[serde(deserialize_with = "byte_vectors::<_, 2, 2, 3>")]
        values: Vec<Bytes>,
    }

    #[test]
    fn byte_vectors_preserve_format_and_enforce_every_budget() {
        let wire: Wire = serde_json::from_str(r#"{"values":["0x01","0x0203"]}"#).unwrap();
        assert_eq!(wire.values, [Bytes::from_static(&[1]), Bytes::from_static(&[2, 3])]);

        for json in [
            r#"{"values":["0x00","0x01","0x02"]}"#,
            r#"{"values":["0x000102"]}"#,
            r#"{"values":["0x0001","0x0203"]}"#,
        ] {
            assert!(serde_json::from_str::<Wire>(json).is_err(), "accepted {json}");
        }
    }
}
