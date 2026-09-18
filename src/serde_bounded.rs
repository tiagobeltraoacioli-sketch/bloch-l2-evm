// SPDX-License-Identifier: MIT OR Apache-2.0
//! Allocation-bounded sequence decoding shared by experimental integrations.
use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};
use serde::{
    de::{self, DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

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
    struct Reject;
    impl<'de> DeserializeSeed<'de> for Reject {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
            Err(de::Error::custom("sequence exceeds allocation limit"))
        }
    }
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
